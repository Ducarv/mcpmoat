package inspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Secrets that must never appear in any error text.
const (
	testRawURL      = "https://user:pw@mcp.example.com/mcp?token=QSECRET42" //nolint:gosec // G101: fake test credentials
	testQuerySecret = "QSECRET42"
	testAuthValue   = "Bearer HSECRET99"
	testAuthSecret  = "HSECRET99"
	testKeyValue    = "KSECRET77"
)

// testSecrets are the substrings that no error text may hold.
var testSecrets = []string{testQuerySecret, testAuthSecret, testKeyValue, "pw@"}

// testServer returns a remote server whose URL and headers hold secrets.
func testServer(transport discover.Transport) discover.Server {
	return discover.Server{
		Name:      "remote",
		Transport: transport,
		URL:       discover.NewURL(testRawURL),
		Headers: discover.SecretMap{
			"Authorization": discover.NewSecret(testAuthValue),
			"X-Api-Key":     discover.NewSecret(testKeyValue),
		},
	}
}

// testHeaderValues returns the header values of srv, as classify expects.
func testHeaderValues(srv discover.Server) []string {
	values := make([]string, 0, len(srv.Headers))
	for _, name := range srv.Headers.Keys() {
		values = append(values, srv.Headers[name].Reveal())
	}
	return values
}

// leakyError is an error whose text is fixed and whose cause is err. It
// models a wrapper that prints a secret next to a typed cause.
type leakyError struct {
	text string
	err  error
}

func (e *leakyError) Error() string { return e.text }
func (e *leakyError) Unwrap() error { return e.err }

// fakeEvents is a transportEvents with fixed answers.
type fakeEvents struct {
	status    int
	blocked   error
	sessionUp bool
}

func (f *fakeEvents) lastStatus() int   { return f.status }
func (f *fakeEvents) blockedErr() error { return f.blocked }
func (f *fakeEvents) connected() bool   { return f.sessionUp }

// fakeNetError is a net.Error with a fixed answer for Timeout.
type fakeNetError struct {
	text    string
	timeout bool
}

func (e *fakeNetError) Error() string   { return e.text }
func (e *fakeNetError) Timeout() bool   { return e.timeout }
func (e *fakeNetError) Temporary() bool { return false }

// urlErr wraps err in a *url.Error that holds the raw URL, as net/http does.
func urlErr(op string, err error) error {
	return &url.Error{Op: op, URL: testRawURL, Err: err}
}

func TestClassify(t *testing.T) {
	t.Parallel()

	leakText := fmt.Sprintf("failed %s with %s and %s", testRawURL, testAuthValue, testKeyValue)

	tests := []struct {
		name       string
		err        error
		transport  discover.Transport // zero value means TransportHTTP
		ev         transportEvents    // nil means no transport events
		wantKind   ConnectKind
		wantStatus int
		// wantReason holds substrings that Reason must contain.
		wantReason []string
		// noReason holds substrings that Reason must not contain.
		noReason []string
		// wantIs holds errors that errors.Is must find in the cause.
		wantIs []error
		// notIs holds errors that errors.Is must not find in the cause.
		notIs []error
		// check runs extra assertions, for example errors.As.
		check func(t *testing.T, ce *ConnectError)
	}{
		{
			name: "tls unknown authority",
			err: urlErr("Post", &tls.CertificateVerificationError{
				Err: x509.UnknownAuthorityError{},
			}),
			wantKind:   KindTLS,
			wantReason: []string{"not trusted", "unknown authority"},
			check: func(t *testing.T, ce *ConnectError) {
				t.Helper()
				var ua x509.UnknownAuthorityError
				if !errors.As(ce, &ua) {
					t.Error("errors.As(x509.UnknownAuthorityError) = false, want true")
				}
				var cv *tls.CertificateVerificationError
				if !errors.As(ce, &cv) {
					t.Error("errors.As(*tls.CertificateVerificationError) = false, want true")
				}
			},
		},
		{
			name:       "tls unknown authority without wrapper",
			err:        x509.UnknownAuthorityError{},
			wantKind:   KindTLS,
			wantReason: []string{"unknown authority"},
		},
		{
			name: "tls hostname mismatch",
			err: urlErr("Get", &tls.CertificateVerificationError{
				// Error() of a HostnameError reads Certificate, as in a
				// real handshake, so it must not be nil.
				Err: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "h"},
			}),
			wantKind:   KindTLS,
			wantReason: []string{"not valid for this host"},
			check: func(t *testing.T, ce *ConnectError) {
				t.Helper()
				var he x509.HostnameError
				if !errors.As(ce, &he) {
					t.Fatal("errors.As(x509.HostnameError) = false, want true")
				}
				if he.Host != "h" {
					t.Errorf("HostnameError.Host = %q, want %q", he.Host, "h")
				}
			},
		},
		{
			name: "tls certificate expired",
			err: urlErr("Post", &tls.CertificateVerificationError{
				Err: x509.CertificateInvalidError{Reason: x509.Expired},
			}),
			wantKind:   KindTLS,
			wantReason: []string{"expired or not yet valid"},
			check: func(t *testing.T, ce *ConnectError) {
				t.Helper()
				var ci x509.CertificateInvalidError
				if !errors.As(ce, &ci) {
					t.Fatal("errors.As(x509.CertificateInvalidError) = false, want true")
				}
				if ci.Reason != x509.Expired {
					t.Errorf("Reason = %v, want Expired", ci.Reason)
				}
			},
		},
		{
			name: "tls certificate invalid other reason",
			err: urlErr("Post", &tls.CertificateVerificationError{
				Err: x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign},
			}),
			wantKind:   KindTLS,
			wantReason: []string{"TLS certificate invalid"},
			noReason:   []string{"expired"},
		},
		{
			name:       "tls generic verification failure",
			err:        urlErr("Post", &tls.CertificateVerificationError{Err: errors.New("boom")}),
			wantKind:   KindTLS,
			wantReason: []string{"verification failed"},
			check: func(t *testing.T, ce *ConnectError) {
				t.Helper()
				var cv *tls.CertificateVerificationError
				if !errors.As(ce, &cv) {
					t.Error("errors.As(*tls.CertificateVerificationError) = false, want true")
				}
			},
		},
		{
			name:       "tls record header error",
			err:        urlErr("Post", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}),
			wantKind:   KindTLS,
			wantReason: []string{"did not answer with TLS"},
			check: func(t *testing.T, ce *ConnectError) {
				t.Helper()
				var rh tls.RecordHeaderError
				if !errors.As(ce, &rh) {
					t.Error("errors.As(tls.RecordHeaderError) = false, want true")
				}
			},
		},
		{
			name:       "scheme mismatch wrapped",
			err:        urlErr("Post", fmt.Errorf("transport: %w", http.ErrSchemeMismatch)),
			wantKind:   KindTLS,
			wantReason: []string{"plain HTTP", "http://"},
			wantIs:     []error{http.ErrSchemeMismatch},
		},
		{
			name:       "tls wins over http status",
			err:        urlErr("Post", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}),
			ev:         &fakeEvents{status: http.StatusUnauthorized},
			wantKind:   KindTLS,
			wantReason: []string{"unknown authority"},
		},
		{
			name:       "tls never suggests skipping verification",
			err:        urlErr("Post", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}),
			wantKind:   KindTLS,
			wantReason: []string{"TLS"},
			noReason:   []string{"insecure", "skip", "verify=false", "InsecureSkipVerify"},
		},
		{
			name: "deadline exceeded through url error",
			err: fmt.Errorf("connect: %w", &url.Error{
				Op: "Post", URL: testRawURL, Err: context.DeadlineExceeded,
			}),
			wantKind:   KindTimeout,
			wantReason: []string{"timed out"},
			wantIs:     []error{context.DeadlineExceeded},
		},
		{
			name:       "deadline exceeded bare",
			err:        context.DeadlineExceeded,
			wantKind:   KindTimeout,
			wantReason: []string{"timed out"},
			wantIs:     []error{context.DeadlineExceeded},
		},
		{
			name:       "canceled",
			err:        urlErr("Post", context.Canceled),
			wantKind:   KindTimeout,
			wantReason: []string{"canceled"},
			wantIs:     []error{context.Canceled},
		},
		{
			name:       "timeout wins over http status",
			err:        urlErr("Post", context.DeadlineExceeded),
			ev:         &fakeEvents{status: http.StatusInternalServerError},
			wantKind:   KindTimeout,
			wantReason: []string{"timed out"},
		},
		{
			name: "network connection refused",
			err: urlErr("Post", &net.OpError{
				Op: "dial", Net: "tcp", Err: errors.New("connection refused"),
			}),
			wantKind:   KindNetwork,
			wantReason: []string{"network error:", "connection refused"},
			check: func(t *testing.T, ce *ConnectError) {
				t.Helper()
				var ne net.Error
				if !errors.As(ce, &ne) {
					t.Error("errors.As(net.Error) = false, want true")
				}
			},
		},
		{
			name: "network error with secrets in text",
			err: urlErr("Post", &net.OpError{
				Op: "dial", Net: "tcp", Err: errors.New(leakText),
			}),
			wantKind:   KindNetwork,
			wantReason: []string{"network error:", "failed", discover.Mask},
		},
		{
			// Not context.DeadlineExceeded: the http.Transport TLS handshake
			// timeout is an error of its own that only has Timeout() true.
			name:       "net error with Timeout true is a timeout",
			err:        urlErr("Post", &fakeNetError{text: "net/http: TLS handshake timeout", timeout: true}),
			wantKind:   KindTimeout,
			wantReason: []string{"timed out"},
			noReason:   []string{"network error", "handshake"},
			check: func(t *testing.T, ce *ConnectError) {
				t.Helper()
				if errors.Is(ce, context.DeadlineExceeded) {
					t.Error("errors.Is(DeadlineExceeded) = true; the test needs an error that does not wrap it")
				}
				var ne net.Error
				if !errors.As(ce, &ne) || !ne.Timeout() {
					t.Error("cause is not a net.Error with Timeout() true")
				}
			},
		},
		{
			name:       "net error with Timeout false is a network error",
			err:        urlErr("Post", &fakeNetError{text: "connection reset by peer", timeout: false}),
			wantKind:   KindNetwork,
			wantReason: []string{"network error:", "connection reset by peer"},
			noReason:   []string{"timed out"},
		},
		{
			name:       "wrapped net.OpError with Timeout true is a timeout",
			err:        urlErr("Post", &net.OpError{Op: "read", Net: "tcp", Err: &fakeNetError{text: "i/o timeout", timeout: true}}),
			wantKind:   KindTimeout,
			wantReason: []string{"timed out"},
		},
		{
			name: "timeout net error with secrets in text keeps them out",
			err: urlErr("Post", &fakeNetError{
				text: leakText, timeout: true,
			}),
			wantKind:   KindTimeout,
			wantReason: []string{"timed out"},
			noReason:   []string{"failed"},
		},
		{
			name:       "http status wins over a timeout net error",
			err:        urlErr("Post", &fakeNetError{text: "timeout", timeout: true}),
			ev:         &fakeEvents{status: http.StatusBadGateway},
			wantKind:   KindHTTP,
			wantStatus: http.StatusBadGateway,
		},
		{
			name: "tls certificate error wins over a timeout net error",
			err: urlErr("Post", errors.Join(
				&fakeNetError{text: "timeout", timeout: true},
				&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
			)),
			wantKind:   KindTLS,
			wantReason: []string{"unknown authority"},
		},
		{
			name:       "network error is not an http status",
			err:        urlErr("Post", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("reset")}),
			ev:         &fakeEvents{status: 0},
			wantKind:   KindNetwork,
			wantReason: []string{"reset"},
		},
		{
			name:       "other origin",
			err:        urlErr("Post", fmt.Errorf("%w: %s", errOtherOrigin, testRawURL)),
			wantKind:   KindOrigin,
			wantReason: []string{"another origin", "refused"},
			// The cause text held the raw URL, so safeCause replaced the
			// chain with a scrubbed plain error: errors.Is cannot match.
		},
		{
			name:       "other origin clean cause keeps chain",
			err:        urlErr("Post", errOtherOrigin),
			wantKind:   KindOrigin,
			wantReason: []string{"another origin", "refused"},
			wantIs:     []error{errOtherOrigin},
		},
		{
			name:       "cross origin redirect",
			err:        urlErr("Post", errCrossOriginRedirect),
			wantKind:   KindRedirect,
			wantReason: []string{"another origin", "final URL"},
			wantIs:     []error{errCrossOriginRedirect},
		},
		{
			name:       "too many redirects",
			err:        urlErr("Post", errTooManyRedirects),
			wantKind:   KindRedirect,
			wantReason: []string{"too many redirects"},
			wantIs:     []error{errTooManyRedirects},
		},
		{
			name:       "body too large",
			err:        urlErr("Post", errBodyTooLarge),
			wantKind:   KindTooLarge,
			wantReason: []string{"too large"},
			wantIs:     []error{errBodyTooLarge},
		},
		{
			name:       "sentinel wins over http status",
			err:        errCrossOriginRedirect,
			ev:         &fakeEvents{status: http.StatusFound},
			wantKind:   KindRedirect,
			wantReason: []string{"another origin"},
		},
		{
			name:       "401 names header keys only",
			err:        errors.New("sending \"initialize\": Unauthorized: " + leakText),
			ev:         &fakeEvents{status: http.StatusUnauthorized},
			wantKind:   KindHTTP,
			wantStatus: http.StatusUnauthorized,
			wantReason: []string{"HTTP 401", "headers sent: Authorization, X-Api-Key"},
			noReason:   []string{"Bearer", "failed"},
		},
		{
			name:       "403 names header keys only",
			err:        errors.New("forbidden"),
			ev:         &fakeEvents{status: http.StatusForbidden},
			wantKind:   KindHTTP,
			wantStatus: http.StatusForbidden,
			wantReason: []string{"HTTP 403", "headers sent: Authorization, X-Api-Key"},
		},
		{
			name:       "404 with http transport hints sse",
			err:        errors.New("not found"),
			transport:  discover.TransportHTTP,
			ev:         &fakeEvents{status: http.StatusNotFound},
			wantKind:   KindHTTP,
			wantStatus: http.StatusNotFound,
			wantReason: []string{"HTTP 404", "legacy SSE", "type = sse"},
		},
		{
			name:       "400 with http transport hints sse",
			err:        errors.New("bad request"),
			transport:  discover.TransportHTTP,
			ev:         &fakeEvents{status: http.StatusBadRequest},
			wantKind:   KindHTTP,
			wantStatus: http.StatusBadRequest,
			wantReason: []string{"HTTP 400", "legacy SSE"},
		},
		{
			name:       "405 with http transport hints sse",
			err:        errors.New("method not allowed"),
			transport:  discover.TransportHTTP,
			ev:         &fakeEvents{status: http.StatusMethodNotAllowed},
			wantKind:   KindHTTP,
			wantStatus: http.StatusMethodNotAllowed,
			wantReason: []string{"HTTP 405", "legacy SSE"},
		},
		{
			name:       "404 with sse transport has no hint",
			err:        errors.New("not found"),
			transport:  discover.TransportSSE,
			ev:         &fakeEvents{status: http.StatusNotFound},
			wantKind:   KindHTTP,
			wantStatus: http.StatusNotFound,
			wantReason: []string{"HTTP 404 Not Found"},
			noReason:   []string{"SSE", "type = sse"},
		},
		{
			name:       "404 with http transport after connect has no hint",
			err:        errors.New("not found"),
			transport:  discover.TransportHTTP,
			ev:         &fakeEvents{status: http.StatusNotFound, sessionUp: true},
			wantKind:   KindHTTP,
			wantStatus: http.StatusNotFound,
			wantReason: []string{"HTTP 404 Not Found"},
			noReason:   []string{"SSE", "type = sse"},
		},
		{
			name:       "401 after connect still names the headers",
			err:        errors.New("unauthorized"),
			ev:         &fakeEvents{status: http.StatusUnauthorized, sessionUp: true},
			wantKind:   KindHTTP,
			wantStatus: http.StatusUnauthorized,
			wantReason: []string{"HTTP 401", "headers sent: Authorization, X-Api-Key"},
		},
		{
			name:       "500",
			err:        errors.New("server exploded " + leakText),
			ev:         &fakeEvents{status: http.StatusInternalServerError},
			wantKind:   KindHTTP,
			wantStatus: http.StatusInternalServerError,
			wantReason: []string{"HTTP 500 Internal Server Error"},
			noReason:   []string{"exploded", "failed"},
		},
		{
			name:       "unknown status has no status text",
			err:        errors.New("odd"),
			ev:         &fakeEvents{status: 599},
			wantKind:   KindHTTP,
			wantStatus: 599,
			wantReason: []string{"HTTP 599"},
		},
		{
			name:       "protocol fallback",
			err:        errors.New("invalid MCP answer: unexpected end of JSON input"),
			wantKind:   KindProtocol,
			wantReason: []string{"invalid MCP answer"},
		},
		{
			name:       "protocol fallback with secrets in text",
			err:        errors.New(leakText),
			wantKind:   KindProtocol,
			wantReason: []string{"failed", discover.Mask},
		},
		{
			name:       "protocol fallback through url error",
			err:        urlErr("Post", errors.New("EOF")),
			wantKind:   KindProtocol,
			wantReason: []string{"EOF"},
		},
		{
			name: "typed tls cause with secret text keeps kind",
			err: urlErr("Post", &leakyError{
				text: leakText,
				err:  &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
			}),
			wantKind:   KindTLS,
			wantReason: []string{"unknown authority"},
		},
		{
			name:       "ev blocked other origin wins over flattened text",
			err:        errors.New("client is closing: Post x: request to another origin refused"),
			ev:         &fakeEvents{blocked: urlErr("Post", errOtherOrigin)},
			wantKind:   KindOrigin,
			wantReason: []string{"another origin", "refused"},
			wantIs:     []error{errOtherOrigin},
		},
		{
			name:       "ev blocked cross origin redirect wins over flattened text",
			err:        errors.New("client is closing: Post x: request to another origin refused"),
			ev:         &fakeEvents{blocked: errCrossOriginRedirect},
			wantKind:   KindRedirect,
			wantReason: []string{"final URL"},
			wantIs:     []error{errCrossOriginRedirect},
		},
		{
			name:       "ev blocked too many redirects wins over flattened text",
			err:        errors.New("client is closing: Post x: request to another origin refused"),
			ev:         &fakeEvents{blocked: urlErr("Get", errTooManyRedirects)},
			wantKind:   KindRedirect,
			wantReason: []string{"too many redirects"},
			wantIs:     []error{errTooManyRedirects},
		},
		{
			name:       "ev blocked body too large wins over flattened text",
			err:        errors.New("client is closing: Post x: request to another origin refused"),
			ev:         &fakeEvents{blocked: errBodyTooLarge},
			wantKind:   KindTooLarge,
			wantReason: []string{"too large"},
			wantIs:     []error{errBodyTooLarge},
		},
		{
			name:       "ev blocked wins over typed timeout in err",
			err:        urlErr("Post", context.DeadlineExceeded),
			ev:         &fakeEvents{blocked: errBodyTooLarge, status: http.StatusInternalServerError},
			wantKind:   KindTooLarge,
			wantReason: []string{"too large"},
			wantIs:     []error{errBodyTooLarge},
		},
		// When a blocked error decides the kind, a context error of err stays
		// in the chain, so errors.Is(err, context.DeadlineExceeded) still
		// works, as Remote promises.
		{
			name:       "ev blocked redirect keeps the deadline of err",
			err:        fmt.Errorf("calling initialize: %w", context.DeadlineExceeded),
			ev:         &fakeEvents{blocked: errCrossOriginRedirect},
			wantKind:   KindRedirect,
			wantReason: []string{"final URL"},
			wantIs:     []error{errCrossOriginRedirect, context.DeadlineExceeded},
			noReason:   []string{"timed out"},
		},
		{
			name:       "ev blocked body too large keeps the cancel of err",
			err:        urlErr("Post", fmt.Errorf("read: %w", context.Canceled)),
			ev:         &fakeEvents{blocked: urlErr("Get", errBodyTooLarge)},
			wantKind:   KindTooLarge,
			wantReason: []string{"too large"},
			wantIs:     []error{errBodyTooLarge, context.Canceled},
			notIs:      []error{context.DeadlineExceeded},
		},
		{
			name:       "ev blocked without a context error in err adds none",
			err:        errors.New("client is closing: EOF"),
			ev:         &fakeEvents{blocked: errCrossOriginRedirect},
			wantKind:   KindRedirect,
			wantReason: []string{"final URL"},
			wantIs:     []error{errCrossOriginRedirect},
			notIs:      []error{context.DeadlineExceeded, context.Canceled},
		},
		{
			name:       "ev blocked error that is not a sentinel is ignored",
			err:        errors.New("invalid MCP answer"),
			ev:         &fakeEvents{blocked: errors.New("something else")},
			wantKind:   KindProtocol,
			wantReason: []string{"invalid MCP answer"},
		},
		{
			name:       "ev with nothing set keeps the err kind",
			err:        urlErr("Post", context.DeadlineExceeded),
			ev:         &fakeEvents{},
			wantKind:   KindTimeout,
			wantReason: []string{"timed out"},
		},
		{
			name:       "status 0 after 2xx with later protocol error has no sse hint",
			err:        errors.New("calling \"tools/list\": invalid JSON-RPC response"),
			ev:         &fakeEvents{status: 0},
			transport:  discover.TransportHTTP,
			wantKind:   KindProtocol,
			wantReason: []string{"invalid JSON-RPC response"},
			noReason:   []string{"SSE", "type = sse", "HTTP"},
		},
		{
			name:       "nil ev works",
			err:        errors.New("boom"),
			ev:         nil,
			wantKind:   KindProtocol,
			wantReason: []string{"boom"},
		},
		{
			name:     "invalid proxy setting is a config error with a fixed reason",
			err:      urlErr("Post", fmt.Errorf("proxyconnect: %w", errInvalidProxy)),
			wantKind: KindConfig,
			wantIs:   []error{errInvalidProxy},
			check: func(t *testing.T, ce *ConnectError) {
				t.Helper()
				if ce.Reason != errInvalidProxy.Error() {
					t.Errorf("Reason = %q, want %q", ce.Reason, errInvalidProxy.Error())
				}
			},
		},
		{
			// The SDK can wrap the transport error in text of its own; the
			// reason is still the fixed text, so no other text gets in.
			// safeCause drops the chain of a cause whose text holds a secret,
			// so errors.Is is not checked here.
			name:     "invalid proxy in a leaky wrapper keeps the fixed reason",
			err:      &leakyError{text: "connect: " + leakText, err: errInvalidProxy},
			wantKind: KindConfig,
			check: func(t *testing.T, ce *ConnectError) {
				t.Helper()
				if ce.Reason != errInvalidProxy.Error() {
					t.Errorf("Reason = %q, want %q", ce.Reason, errInvalidProxy.Error())
				}
			},
		},
		{
			name: "nested url errors",
			err: urlErr("Post", &url.Error{
				Op: "Get", URL: testRawURL, Err: context.DeadlineExceeded,
			}),
			wantKind:   KindTimeout,
			wantReason: []string{"timed out"},
			wantIs:     []error{context.DeadlineExceeded},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			transport := tt.transport
			if transport == "" {
				transport = discover.TransportHTTP
			}
			srv := testServer(transport)

			ce := classify(tt.err, srv, tt.ev, testHeaderValues(srv))
			if ce == nil {
				t.Fatal("classify() = nil")
			}
			if ce.Kind != tt.wantKind {
				t.Errorf("Kind = %q, want %q (reason %q)", ce.Kind, tt.wantKind, ce.Reason)
			}
			if ce.Status != tt.wantStatus {
				t.Errorf("Status = %d, want %d", ce.Status, tt.wantStatus)
			}
			if ce.Server != srv.Name {
				t.Errorf("Server = %q, want %q", ce.Server, srv.Name)
			}
			for _, want := range tt.wantReason {
				if !strings.Contains(ce.Reason, want) {
					t.Errorf("Reason = %q, want it to contain %q", ce.Reason, want)
				}
			}
			for _, bad := range tt.noReason {
				if strings.Contains(ce.Reason, bad) {
					t.Errorf("Reason = %q, must not contain %q", ce.Reason, bad)
				}
			}
			for _, target := range tt.wantIs {
				if !errors.Is(ce, target) {
					t.Errorf("errors.Is(ce, %v) = false, want true", target)
				}
			}
			for _, target := range tt.notIs {
				if errors.Is(ce, target) {
					t.Errorf("errors.Is(ce, %v) = true, want false", target)
				}
			}
			if tt.check != nil {
				tt.check(t, ce)
			}

			assertNoSecrets(t, ce, testSecrets...)
			assertHasServerAndURL(t, ce, srv)
		})
	}
}

// assertHasServerAndURL fails if ce.Error() lacks the server name or the
// redacted URL.
func assertHasServerAndURL(t *testing.T, ce *ConnectError, srv discover.Server) {
	t.Helper()
	text := ce.Error()
	if !strings.Contains(text, srv.Name) {
		t.Errorf("Error() = %q, want it to contain server name %q", text, srv.Name)
	}
	if !strings.Contains(text, srv.URL.String()) {
		t.Errorf("Error() = %q, want it to contain redacted URL %q", text, srv.URL.String())
	}
}

// TestClassifyRealNetworkTimeout checks the errors that the net package
// produces for an expired context, and not only hand-made ones.
// TestContextErr checks that contextErr finds a context error anywhere in the
// chain and returns the bare sentinel, and nil for any other error.
func TestContextErr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "nil", err: nil, want: nil},
		{name: "plain error", err: errors.New("EOF"), want: nil},
		{name: "blocked sentinel", err: errCrossOriginRedirect, want: nil},
		{name: "deadline", err: context.DeadlineExceeded, want: context.DeadlineExceeded},
		{name: "wrapped deadline", err: fmt.Errorf("calling initialize: %w", context.DeadlineExceeded), want: context.DeadlineExceeded},
		{name: "deadline in url error", err: urlErr("Post", context.DeadlineExceeded), want: context.DeadlineExceeded},
		{name: "canceled", err: context.Canceled, want: context.Canceled},
		{name: "wrapped canceled", err: fmt.Errorf("read: %w", context.Canceled), want: context.Canceled},
		{name: "canceled in a join", err: errors.Join(errors.New("EOF"), context.Canceled), want: context.Canceled},
		{name: "deadline wins over canceled", err: errors.Join(context.Canceled, context.DeadlineExceeded), want: context.DeadlineExceeded},
		// The text alone is not enough: the SDK can flatten the chain.
		{name: "flattened deadline text", err: errors.New(context.DeadlineExceeded.Error()), want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := contextErr(tt.err); got != tt.want { //nolint:errorlint // contextErr returns the bare sentinel, so == is the check
				t.Errorf("contextErr(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestClassifyRealNetworkTimeout(t *testing.T) {
	t.Parallel()

	srv := testServer(discover.TransportHTTP)

	t.Run("expired deadline", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithDeadline(t.Context(), time.Unix(0, 0))
		t.Cleanup(cancel)

		var d net.Dialer
		_, err := d.DialContext(ctx, "tcp", "127.0.0.1:1")
		if err == nil {
			t.Fatal("DialContext() error = nil, want error")
		}
		ce := classify(urlErr("Post", err), srv, nil, testHeaderValues(srv))
		if ce.Kind != KindTimeout {
			t.Errorf("Kind = %q, want %q (reason %q)", ce.Kind, KindTimeout, ce.Reason)
		}
		if !errors.Is(ce, context.DeadlineExceeded) {
			t.Errorf("errors.Is(ce, context.DeadlineExceeded) = false; cause = %v", errors.Unwrap(ce))
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		var d net.Dialer
		_, err := d.DialContext(ctx, "tcp", "127.0.0.1:1")
		if err == nil {
			t.Fatal("DialContext() error = nil, want error")
		}
		ce := classify(urlErr("Post", err), srv, nil, testHeaderValues(srv))
		if ce.Kind != KindTimeout {
			t.Errorf("Kind = %q, want %q (reason %q)", ce.Kind, KindTimeout, ce.Reason)
		}
		if !errors.Is(ce, context.Canceled) {
			t.Errorf("errors.Is(ce, context.Canceled) = false; cause = %v", errors.Unwrap(ce))
		}
	})
}

// TestClassifyRealTLSHandshakeTimeout runs a real TLS handshake against a
// listener that accepts and never answers. The http.Transport gives up with
// "net/http: TLS handshake timeout", which does not wrap
// context.DeadlineExceeded. classify must still report a timeout.
func TestClassifyRealTLSHandshakeTimeout(t *testing.T) {
	t.Parallel()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// Accept connections and keep them open without a reply. The goroutine
	// ends when the listener closes (Accept then returns an error).
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		for _, c := range conns {
			_ = c.Close()
		}
	})

	tr := &http.Transport{TLSHandshakeTimeout: 50 * time.Millisecond}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+ln.Addr().String()+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("client.Do() error = nil, want a TLS handshake timeout")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error %v wraps context.DeadlineExceeded; the test needs the plain handshake timeout", err)
	}

	srv := testServer(discover.TransportHTTP)
	// Replace the dialed URL by the secret URL: classify strips the *url.Error.
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Fatalf("error %T is not a *url.Error", err)
	}
	wrapped := urlErr("Post", ue.Err)
	ce := classify(wrapped, srv, nil, testHeaderValues(srv))
	if ce.Kind != KindTimeout {
		t.Errorf("Kind = %q, want %q (reason %q)", ce.Kind, KindTimeout, ce.Reason)
	}
	if ce.Reason != "timed out" {
		t.Errorf("Reason = %q, want %q", ce.Reason, "timed out")
	}
	assertNoSecrets(t, ce, testSecrets...)
	assertHasServerAndURL(t, ce, srv)
}

// TestClassifyEmptyURL checks a server without a URL: no secret, no
// parentheses.
func TestClassifyEmptyURL(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "remote", Transport: discover.TransportHTTP}
	ce := classify(errors.New("boom"), srv, nil, nil)
	if ce.Kind != KindProtocol {
		t.Errorf("Kind = %q, want %q", ce.Kind, KindProtocol)
	}
	if got, want := ce.Error(), "remote: boom"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestClassifyCauseKept checks that a clean cause is returned as is, and a
// leaky cause is replaced.
func TestClassifyCauseKept(t *testing.T) {
	t.Parallel()

	srv := testServer(discover.TransportHTTP)
	values := testHeaderValues(srv)

	clean := errors.New("clean")
	ce := classify(urlErr("Post", clean), srv, nil, values)
	if got := errors.Unwrap(ce); got != clean { //nolint:errorlint // identity check: the cause must be returned unchanged
		t.Errorf("Unwrap() = %v, want the original clean cause", got)
	}

	leaky := errors.New("leak " + testAuthValue)
	ce = classify(leaky, srv, nil, values)
	got := errors.Unwrap(ce)
	if got == nil {
		t.Fatal("Unwrap() = nil, want a scrubbed cause")
	}
	if got == leaky { //nolint:errorlint // identity check: the leaky cause must be replaced, not returned
		t.Error("Unwrap() returned the leaky cause, want a scrubbed copy")
	}
	if strings.Contains(got.Error(), testAuthSecret) {
		t.Errorf("Unwrap().Error() = %q, must not contain %q", got.Error(), testAuthSecret)
	}
}

// TestClassifyLongReasonTruncated checks the cut of long cause text.
func TestClassifyLongReasonTruncated(t *testing.T) {
	t.Parallel()

	srv := testServer(discover.TransportHTTP)
	long := strings.Repeat("x", 500)
	ce := classify(errors.New(long), srv, nil, nil)
	if ce.Kind != KindProtocol {
		t.Fatalf("Kind = %q, want %q", ce.Kind, KindProtocol)
	}
	if got, want := len([]rune(ce.Reason)), maxReasonRunes+1; got != want {
		t.Errorf("rune count of Reason = %d, want %d", got, want)
	}
	if !strings.HasSuffix(ce.Reason, "…") {
		t.Errorf("Reason = %q, want suffix %q", ce.Reason, "…")
	}
}

func TestHTTPReasonNoHeaders(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "remote", Transport: discover.TransportHTTP}
	got := httpReason(srv, http.StatusUnauthorized, false)
	if !strings.Contains(got, "headers sent: none") {
		t.Errorf("httpReason() = %q, want it to contain %q", got, "headers sent: none")
	}
}

// TestHTTPReasonSSEHint checks when the reason for a 400, 404 or 405 tells
// the user to try the legacy SSE transport: only for TransportHTTP, and only
// before the session connected. After the connect, the server has shown that
// it speaks streamable HTTP, so the hint would be wrong.
func TestHTTPReasonSSEHint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		transport discover.Transport
		connected bool
		hint      bool
	}{
		{transport: discover.TransportHTTP, connected: false, hint: true},
		{transport: discover.TransportHTTP, connected: true, hint: false},
		{transport: discover.TransportSSE, connected: false, hint: false},
		{transport: discover.TransportSSE, connected: true, hint: false},
	}
	for _, tt := range tests {
		for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed} {
			t.Run(fmt.Sprintf("%s/connected=%t/%d", tt.transport, tt.connected, status), func(t *testing.T) {
				t.Parallel()
				srv := discover.Server{Name: "remote", Transport: tt.transport}
				want := fmt.Sprintf("HTTP %d %s", status, http.StatusText(status))
				if tt.hint {
					want = fmt.Sprintf("HTTP %d; the server may use the legacy SSE transport; set type = sse", status)
				}
				if got := httpReason(srv, status, tt.connected); got != want {
					t.Errorf("httpReason(%d, connected=%t) = %q, want %q", status, tt.connected, got, want)
				}
			})
		}
	}
}

func TestScrub(t *testing.T) {
	t.Parallel()

	redacted := discover.NewURL(testRawURL).String()
	const (
		m = discover.Mask
		// quoteURL holds a quote and a backslash in its query value.
		quoteURL   = `https://h.example/p?t=ab"c\d`
		rawNoQuery = "https://user:pw@mcp.example.com/mcp" //nolint:gosec // G101: fake test credentials
		// net/http prints this variant: no password, no query.
		printedNoQuery = "https://mcp.example.com/mcp"
	)

	tests := []struct {
		name     string
		text     string
		rawURL   string
		redacted string
		headers  []string
		want     string
		// wantHas and wantNot hold substrings, for rows where the exact
		// text depends on the redaction rules.
		wantHas []string
		wantNot []string
	}{
		{
			name:     "raw url replaced",
			text:     "Post " + testRawURL + ": EOF",
			rawURL:   testRawURL,
			redacted: redacted,
			want:     "Post " + redacted + ": EOF",
		},
		{
			name:     "raw url replaced twice",
			text:     testRawURL + " and " + testRawURL,
			rawURL:   testRawURL,
			redacted: redacted,
			want:     redacted + " and " + redacted,
		},
		{
			name:     "query after question mark masked",
			text:     "bad request: ?token=QSECRET42 rejected",
			rawURL:   testRawURL,
			redacted: redacted,
			want:     "bad request: ?" + m + " rejected",
		},
		{
			name:     "short query does not garble other words",
			text:     "a bad apple",
			rawURL:   "https://h.example/p?a",
			redacted: discover.NewURL("https://h.example/p?a").String(),
			want:     "a bad apple",
		},
		{
			name:     "short query masked after question mark",
			text:     "bad request: ?a rejected",
			rawURL:   "https://h.example/p?a",
			redacted: discover.NewURL("https://h.example/p?a").String(),
			want:     "bad request: ?" + m + " rejected",
		},
		{
			name:     "base url variant",
			text:     "Post " + printedNoQuery + ": EOF",
			rawURL:   testRawURL,
			redacted: redacted,
			wantHas:  []string{"mcp.example.com/mcp", ": EOF"},
			wantNot:  []string{"pw@"},
		},
		{
			name:     "base url with user info variant",
			text:     "Post " + rawNoQuery + ": EOF",
			rawURL:   testRawURL,
			redacted: redacted,
			wantNot:  []string{"pw@", "pw"},
			wantHas:  []string{"mcp.example.com/mcp"},
		},
		{
			name:     "password masked between colon and at sign",
			text:     "auth failed for host:pw@mcp",
			rawURL:   testRawURL,
			redacted: redacted,
			want:     "auth failed for host:" + m + "@mcp",
		},
		{
			name:     "password outside the authority is not masked",
			text:     "auth failed for pw",
			rawURL:   testRawURL,
			redacted: redacted,
			want:     "auth failed for pw",
		},
		{
			name:     "user name outside the authority is not masked",
			text:     "the user said no",
			rawURL:   testRawURL,
			redacted: redacted,
			want:     "the user said no",
		},
		{
			name:     "user name masked before at sign",
			text:     "Post http://user@mcp.example.com/mcp: EOF",
			rawURL:   testRawURL,
			redacted: redacted,
			want:     "Post http://" + m + "@mcp.example.com/mcp: EOF",
		},
		{ //nolint:gosec // G101: fake test credentials
			name:     "user name masked before colon",
			text:     "Post http://user:other@mcp.example.com/mcp: EOF",
			rawURL:   testRawURL,
			redacted: redacted,
			want:     "Post http://" + m + ":other@mcp.example.com/mcp: EOF",
		},
		{
			name:     "escaped user name masked",
			text:     `Post "http://ghp_TOK%40EN%2F123@h:1/p?x=1": EOF`,
			rawURL:   "http://ghp_TOK%40EN%2F123@h:1/p?tok=QQ",
			redacted: discover.NewURL("http://ghp_TOK%40EN%2F123@h:1/p?tok=QQ").String(),
			wantNot:  []string{"ghp_TOK", "EN%2F123", "EN/123"},
			wantHas:  []string{"@h:1/p", ": EOF"},
		},
		{
			name:     "decoded user name masked",
			text:     "Post http://ghp_TOK@EN/123@h:1/p: EOF",
			rawURL:   "http://ghp_TOK%40EN%2F123@h:1/p?tok=QQ",
			redacted: discover.NewURL("http://ghp_TOK%40EN%2F123@h:1/p?tok=QQ").String(),
			wantNot:  []string{"ghp_TOK"},
		},
		{ //nolint:gosec // G101: fake test credentials
			name:     "short user name does not garble dial tcp or host",
			text:     "dial tcp: lookup example.invalid: no such host",
			rawURL:   "http://a:pw@example.invalid:1/p?q=1",
			redacted: discover.NewURL("http://a:pw@example.invalid:1/p?q=1").String(),
			want:     "dial tcp: lookup example.invalid: no such host",
		},
		{ //nolint:gosec // G101: fake test credentials
			name:     "short user name masked in authority only",
			text:     `Post "http://a@example.invalid:1/p": dial tcp: lookup example.invalid: no such host`,
			rawURL:   "http://a:pw@example.invalid:1/p?q=1",
			redacted: discover.NewURL("http://a:pw@example.invalid:1/p?q=1").String(),
			want:     `Post "http://` + m + `@example.invalid:1/p": dial tcp: lookup example.invalid: no such host`,
		},
		{ //nolint:gosec // G101: fake test credentials
			name:     "short password does not garble other words",
			text:     "dial tcp: connection refused by pw-host",
			rawURL:   "http://a:pw@example.invalid:1/p?q=1",
			redacted: discover.NewURL("http://a:pw@example.invalid:1/p?q=1").String(),
			want:     "dial tcp: connection refused by pw-host",
		},
		{
			name:     "percent-q escaped url with quote and backslash in query",
			text:     fmt.Sprintf("%q", "Post "+quoteURL+": EOF"),
			rawURL:   quoteURL,
			redacted: discover.NewURL(quoteURL).String(),
			wantNot:  []string{`ab\"c\\d`, `ab"c`, "ab", "c\\d"},
			wantHas:  []string{"EOF"},
		},
		{
			name:     "percent-q escaped query alone with quote and backslash",
			text:     fmt.Sprintf("%q", "bad ?t=ab\"c\\d end"),
			rawURL:   quoteURL,
			redacted: discover.NewURL(quoteURL).String(),
			want:     fmt.Sprintf("%q", "bad ?"+m+" end"),
		},
		{
			// A legacy SSE server announces its message endpoint under the
			// same path prefix, so the token segment stands in a URL that is
			// not the configured one.
			name:     "secret path segment in another URL on the same origin",
			text:     "Post https://host.example/ghp_NOTREAL0123/messages?sessionId=abc: EOF",
			rawURL:   "https://host.example/ghp_NOTREAL0123/sse",
			redacted: discover.NewURL("https://host.example/ghp_NOTREAL0123/sse").String(),
			want:     "Post https://host.example/" + m + "/messages?sessionId=abc: EOF",
		},
		{
			name:     "escaped secret path segment masked in both forms",
			text:     "Post https://host.example/ghp_NOTREAL0123/messages and /%67hp_NOTREAL0123/x",
			rawURL:   "https://host.example/%67hp_NOTREAL0123/sse",
			redacted: discover.NewURL("https://host.example/%67hp_NOTREAL0123/sse").String(),
			want:     "Post https://host.example/" + m + "/messages and /" + m + "/x",
		},
		{
			name:     "path segment that is no secret is kept",
			text:     "Post https://host.example/v1/messages: EOF",
			rawURL:   "https://host.example/v1/sse",
			redacted: discover.NewURL("https://host.example/v1/sse").String(),
			want:     "Post https://host.example/v1/messages: EOF",
		},
		{
			name:    "header value with quote masked in plain form",
			text:    `sent Bearer a"b ok`,
			headers: []string{`Bearer a"b`},
			want:    "sent " + m + " ok",
		},
		{
			name:    "header value with quote masked in quoted form",
			text:    fmt.Sprintf("%q", `sent Bearer a"b ok`),
			headers: []string{`Bearer a"b`},
			want:    fmt.Sprintf("%q", "sent "+m+" ok"),
			wantNot: []string{`a\"b`, `a"b`},
		},
		{
			name:     "header value masked",
			text:     "sent " + testAuthValue + " ok",
			headers:  []string{testAuthValue},
			want:     "sent " + m + " ok",
			wantNot:  []string{testAuthSecret},
			rawURL:   "",
			redacted: "",
		},
		{
			name:    "longest header value first",
			text:    "got abcdef and abc",
			headers: []string{"abc", "abcdef"},
			want:    "got " + m + " and " + m,
		},
		{
			name:    "longest header value first reverse order",
			text:    "got abcdef and abc",
			headers: []string{"abcdef", "abc"},
			want:    "got " + m + " and " + m,
		},
		{
			name:    "empty header values ignored",
			text:    "nothing to hide",
			headers: []string{"", ""},
			want:    "nothing to hide",
		},
		{
			name:    "empty header value among real ones",
			text:    "key KSECRET77 end",
			headers: []string{"", testKeyValue},
			want:    "key " + m + " end",
		},
		{
			name:     "empty raw url",
			text:     "plain error text",
			rawURL:   "",
			redacted: "",
			want:     "plain error text",
		},
		{
			name:     "empty raw url leaves url-like text alone",
			text:     "see https://other.example.com/x",
			rawURL:   "",
			redacted: "",
			want:     "see https://other.example.com/x",
		},
		{
			name: "empty text",
			text: "",
			want: "",
		},
		{
			// The base URL must not take the redacted fragment with it: the
			// full URL already got one, and another URL on the same origin
			// must not get "#********" in the middle of its path.
			name:     "fragment of the configured URL is not doubled or spread",
			text:     "Post https://host.example/mcp#frag-NOTREAL: EOF; endpoint https://host.example/mcp/messages",
			rawURL:   "https://host.example/mcp#frag-NOTREAL",
			redacted: discover.NewURL("https://host.example/mcp#frag-NOTREAL").String(),
			want:     "Post https://host.example/mcp#" + m + ": EOF; endpoint https://host.example/mcp/messages",
			wantNot:  []string{"frag-NOTREAL", "#" + m + "#" + m, "#" + m + "/messages"},
		},
		{
			name:     "fragment and query of the configured URL",
			text:     "Post https://host.example/mcp?t=QSECRET42#frag-NOTREAL: EOF; endpoint https://host.example/mcp/messages",
			rawURL:   "https://host.example/mcp?t=QSECRET42#frag-NOTREAL",
			redacted: discover.NewURL("https://host.example/mcp?t=QSECRET42#frag-NOTREAL").String(),
			want:     "Post https://host.example/mcp?t=" + m + "#" + m + ": EOF; endpoint https://host.example/mcp/messages",
			wantNot:  []string{"frag-NOTREAL", "QSECRET42", "#" + m + "#" + m, "#" + m + "/messages"},
		},
		{
			name:     "unparsable raw url still replaced as a whole",
			text:     "bad ://%zz here",
			rawURL:   "://%zz",
			redacted: m,
			want:     "bad " + m + " here",
		},
		{
			name: "exactly 200 runes not truncated",
			text: strings.Repeat("a", 200),
			want: strings.Repeat("a", 200),
		},
		{
			name: "201 runes truncated",
			text: strings.Repeat("a", 201),
			want: strings.Repeat("a", 200) + "…",
		},
		{
			name: "truncation counts runes not bytes",
			text: strings.Repeat("é", 250),
			want: strings.Repeat("é", 200) + "…",
		},
		{
			name:    "truncation after replacement",
			text:    strings.Repeat("a", 190) + " " + testAuthValue + " tail tail tail",
			headers: []string{testAuthValue},
			wantNot: []string{testAuthSecret},
			wantHas: []string{"…"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := scrub(tt.text, tt.rawURL, tt.redacted, tt.headers)
			if tt.want != "" || (len(tt.wantHas) == 0 && len(tt.wantNot) == 0) {
				if got != tt.want {
					t.Errorf("scrub() = %q, want %q", got, tt.want)
				}
			}
			for _, has := range tt.wantHas {
				if !strings.Contains(got, has) {
					t.Errorf("scrub() = %q, want it to contain %q", got, has)
				}
			}
			for _, not := range tt.wantNot {
				if strings.Contains(got, not) {
					t.Errorf("scrub() = %q, must not contain %q", got, not)
				}
			}
			if n := len([]rune(got)); n > maxReasonRunes+1 {
				t.Errorf("rune count = %d, want at most %d", n, maxReasonRunes+1)
			}
		})
	}
}

func TestConnectErrorError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *ConnectError
		want string
	}{
		{
			name: "with url",
			err:  &ConnectError{Server: "s", Reason: "timed out", URL: "https://h/mcp"},
			want: "s: timed out (https://h/mcp)",
		},
		{
			name: "without url",
			err:  &ConnectError{Server: "s", Reason: "timed out"},
			want: "s: timed out",
		},
		{
			name: "empty server",
			err:  &ConnectError{Reason: "boom", URL: "u"},
			want: ": boom (u)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConnectErrorUnwrap(t *testing.T) {
	t.Parallel()

	if got := (&ConnectError{}).Unwrap(); got != nil {
		t.Errorf("Unwrap() = %v, want nil", got)
	}
	cause := context.DeadlineExceeded
	ce := &ConnectError{err: cause}
	if !errors.Is(ce, context.DeadlineExceeded) {
		t.Error("errors.Is(ce, DeadlineExceeded) = false, want true")
	}
	var target *ConnectError
	if !errors.As(fmt.Errorf("wrap: %w", ce), &target) || target != ce {
		t.Error("errors.As(*ConnectError) did not find ce")
	}
}

func TestConfigError(t *testing.T) {
	t.Parallel()

	srv := testServer(discover.TransportHTTP)
	ce := configError(srv, `header name not allowed: "X-Key"`)
	if ce.Kind != KindConfig {
		t.Errorf("Kind = %q, want %q", ce.Kind, KindConfig)
	}
	if ce.Server != srv.Name || ce.URL != srv.URL.String() {
		t.Errorf("Server/URL = %q/%q, want %q/%q", ce.Server, ce.URL, srv.Name, srv.URL.String())
	}
	if errors.Unwrap(ce) != nil {
		t.Errorf("Unwrap() = %v, want nil", errors.Unwrap(ce))
	}
	assertNoSecrets(t, ce, testSecrets...)
	assertHasServerAndURL(t, ce, srv)
}

// TestHTTPReasonHeadersSent checks the header names that the 401 and 403
// reasons list. URL user info goes out as a Basic Authorization header, so
// the reason names it when the config sets no Authorization header. The
// reason never holds a value.
func TestHTTPReasonHeadersSent(t *testing.T) {
	t.Parallel()

	const (
		plainURL    = "https://mcp.example.com/mcp"
		userinfoURL = "https://user:pw@mcp.example.com/mcp" //nolint:gosec // G101: fake test credentials
		fromURL     = "Authorization (from URL user info)"
	)
	tests := []struct {
		name    string
		rawURL  string
		headers map[string]string
		want    string // the list after "headers sent: "
	}{
		{name: "no user info and no headers", rawURL: plainURL, want: "none"},
		{name: "user info and no headers", rawURL: userinfoURL, want: fromURL},
		{name: "user name only", rawURL: "https://user@mcp.example.com/mcp", want: fromURL},
		{name: "user info and other headers", rawURL: userinfoURL, headers: map[string]string{"X-Api-Key": testKeyValue}, want: "X-Api-Key, " + fromURL},
		{name: "user info and config Authorization", rawURL: userinfoURL, headers: map[string]string{"Authorization": testAuthValue}, want: "Authorization"},
		{name: "user info and lower-case config authorization", rawURL: userinfoURL, headers: map[string]string{"authorization": testAuthValue}, want: "authorization"},
		{name: "user info and upper-case config AUTHORIZATION", rawURL: userinfoURL, headers: map[string]string{"AUTHORIZATION": testAuthValue, "X-Api-Key": testKeyValue}, want: "AUTHORIZATION, X-Api-Key"},
		{name: "plain config headers", rawURL: plainURL, headers: map[string]string{"X-Api-Key": testKeyValue, "Authorization": testAuthValue}, want: "Authorization, X-Api-Key"},
		{name: "unparsable url", rawURL: "https://user:pw@[bad/mcp", want: "none"},
		// Keys that differ only in case go out as one header (buildHeader), so
		// the list names it once, in the form of the first sorted key.
		{name: "keys that differ only in case are named once", rawURL: plainURL, headers: map[string]string{"x-key": testKeyValue, "X-Key": testKeyValue}, want: "X-Key"},
		{name: "case duplicates among other keys", rawURL: plainURL, headers: map[string]string{"x-key": testKeyValue, "Accept-Language": "en", "X-KEY": testKeyValue}, want: "Accept-Language, X-KEY"},
		{name: "authorization keys that differ only in case with user info", rawURL: userinfoURL, headers: map[string]string{"authorization": testAuthValue, "Authorization": testAuthValue}, want: "Authorization"},
		// An empty config Authorization counts as absent: the Basic header
		// from the user info replaces it, so the config key is not named.
		{name: "user info and empty config authorization", rawURL: userinfoURL, headers: map[string]string{"authorization": ""}, want: fromURL},
		{name: "user info, empty config Authorization and other headers", rawURL: userinfoURL, headers: map[string]string{"Authorization": "", "X-Api-Key": testKeyValue}, want: "X-Api-Key, " + fromURL},
		{name: "empty config Authorization without user info", rawURL: plainURL, headers: map[string]string{"Authorization": ""}, want: "Authorization"},
		{name: "empty config Authorization with unparsable url", rawURL: "https://user:pw@[bad/mcp", headers: map[string]string{"Authorization": ""}, want: "Authorization"},
		// Sorted byte order puts "authorization" after "Authorization", so the
		// lower-case key gives the value (buildHeader: last key wins).
		{name: "user info, last authorization key empty", rawURL: userinfoURL, headers: map[string]string{"Authorization": testAuthValue, "authorization": ""}, want: fromURL},
		{name: "user info, last authorization key non-empty", rawURL: userinfoURL, headers: map[string]string{"Authorization": "", "authorization": testAuthValue}, want: "Authorization"},
	}
	for _, tt := range tests {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
			t.Run(fmt.Sprintf("%s/%d", tt.name, status), func(t *testing.T) {
				t.Parallel()
				headers := make(discover.SecretMap, len(tt.headers))
				for key, value := range tt.headers {
					headers[key] = discover.NewSecret(value)
				}
				srv := discover.Server{
					Name:      "remote",
					Transport: discover.TransportHTTP,
					URL:       discover.NewURL(tt.rawURL),
					Headers:   headers,
				}
				got := httpReason(srv, status, false)
				want := fmt.Sprintf("server needs authentication (HTTP %d); headers sent: %s", status, tt.want)
				if got != want {
					t.Errorf("httpReason() = %q, want %q", got, want)
				}
				for _, secret := range []string{"pw", testKeyValue, testAuthSecret} {
					if strings.Contains(got, secret) {
						t.Errorf("httpReason() = %q holds the secret %q", got, secret)
					}
				}
			})
		}
	}
}

// TestSentHeaderNamesMatchesRoundTrip ties sentHeaderNames to what
// headerTransport.RoundTrip really sends. The reason names the Basic header
// from the URL user info exactly when the request carries it, and it names a
// config Authorization key exactly when the request carries the config value.
func TestSentHeaderNamesMatchesRoundTrip(t *testing.T) {
	t.Parallel()

	const (
		rawURL  = "http://user:pw@example.com/mcp" //nolint:gosec // G101: fake test credentials
		fromURL = "Authorization (from URL user info)"
	)
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{name: "no headers"},
		{name: "empty Authorization", headers: map[string]string{"Authorization": ""}},
		{name: "empty lower-case authorization", headers: map[string]string{"authorization": ""}},
		{name: "non-empty Authorization", headers: map[string]string{"Authorization": "Bearer x"}},
		{name: "non-empty then empty", headers: map[string]string{"Authorization": "Bearer x", "authorization": ""}},
		{name: "empty then non-empty", headers: map[string]string{"Authorization": "", "authorization": "Bearer x"}},
		{name: "upper-case empty first", headers: map[string]string{"AUTHORIZATION": "", "Authorization": "Bearer x"}},
		{name: "upper-case non-empty first", headers: map[string]string{"AUTHORIZATION": "Bearer x", "authorization": ""}},
		{name: "other header only", headers: map[string]string{"X-Api-Key": "k"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(rawURL)
			if err != nil {
				t.Fatal(err)
			}
			endpoint, user := splitUserinfo(u)
			stub := &hcStub{}
			client, _, err := newHTTPClient(httpClientConfig{Endpoint: &endpoint, User: user, Headers: tt.headers, Base: stub})
			if err != nil {
				t.Fatalf("newHTTPClient() error = %v", err)
			}
			resp := hcGet(t, client, endpoint.String())
			_ = resp.Body.Close()
			sent := stub.header(0).Get("Authorization")
			basicSent := strings.HasPrefix(sent, "Basic ")

			cfg := make(discover.SecretMap, len(tt.headers))
			for key, value := range tt.headers {
				cfg[key] = discover.NewSecret(value)
			}
			names := sentHeaderNames(discover.Server{
				Name:      "remote",
				Transport: discover.TransportHTTP,
				URL:       discover.NewURL(rawURL),
				Headers:   cfg,
			})
			namesBasic := slices.Contains(names, fromURL)
			namesConfig := slices.ContainsFunc(names, func(n string) bool { return http.CanonicalHeaderKey(n) == "Authorization" })

			if namesBasic != basicSent {
				t.Errorf("sentHeaderNames() = %q names the user info header: %t; the request carries Authorization %q", names, namesBasic, sent)
			}
			if want := sent != "" && !basicSent; namesConfig != want {
				t.Errorf("sentHeaderNames() = %q names a config Authorization key: %t, want %t; the request carries Authorization %q", names, namesConfig, want, sent)
			}
		})
	}
}

// TestClassifyShortUserName checks that a short URL user name does not garble
// other words in the error text, while the password, the Basic token and the
// user name in a URL authority are still masked.
func TestClassifyShortUserName(t *testing.T) {
	t.Parallel()

	const (
		rawURL   = "https://in:s3cr3t@host.example/mcp" //nolint:gosec // G101: fake test credentials
		password = "s3cr3t"
		token    = "aW46czNjcjN0" //nolint:gosec // G101: fake test credentials, base64 of "in:s3cr3t"
	)
	srv := discover.Server{
		Name:      "remote",
		Transport: discover.TransportHTTP,
		URL:       discover.NewURL(rawURL),
	}
	user := url.UserPassword("in", password)
	// Remote passes the user info secrets to classify the same way.
	secrets := userinfoSecrets(user)

	text := "initialize server in session: got " + password +
		" from //in@host.example and //in:x@other, header Basic " + token
	ce := classify(errors.New(text), srv, nil, secrets)

	for _, has := range []string{
		"initialize server in session",
		"//" + discover.Mask + "@host.example",
		"//" + discover.Mask + ":",
	} {
		if !strings.Contains(ce.Reason, has) {
			t.Errorf("Reason = %q, want it to contain %q", ce.Reason, has)
		}
	}
	for _, not := range []string{password, token, "//in@", "//in:"} {
		if strings.Contains(ce.Error(), not) {
			t.Errorf("Error() = %q, must not contain %q", ce.Error(), not)
		}
	}
}
