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
	"strconv"
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

// fakeEvents is a transportEvents with fixed answers. stateFor gives the same
// status and blocked error for every err.
type fakeEvents struct {
	status    int
	blocked   error
	sessionUp bool
}

func (f *fakeEvents) stateFor(error) (int, error) { return f.status, f.blocked }
func (f *fakeEvents) connected() bool             { return f.sessionUp }

// fakeNetError is a net.Error with a fixed answer for Timeout.
type fakeNetError struct {
	text    string
	timeout bool
}

func (e *fakeNetError) Error() string   { return e.text }
func (e *fakeNetError) Timeout() bool   { return e.timeout }
func (e *fakeNetError) Temporary() bool { return false }

// jsonTooComplexReason is the fixed reason for errJSONTooComplex. It is
// written out here, not read from blockedKinds, so a change of the text
// fails a test.
const jsonTooComplexReason = "response JSON too large: too deep, too many values or a too long string"

// addrRefusedReason is the fixed reason for errAddrRefused (issue #106). It
// is written out here, not read from blockedKinds, so a change of the text
// fails a test. It names no address and no host.
const addrRefusedReason = "server name resolves only to loopback, unspecified, link-local or multicast addresses; mcpmoat did not connect"

// wantExactReason returns a TestClassify check that Reason is exactly want.
func wantExactReason(want string) func(t *testing.T, ce *ConnectError) {
	return func(t *testing.T, ce *ConnectError) {
		t.Helper()
		if ce.Reason != want {
			t.Errorf("Reason = %q, want %q", ce.Reason, want)
		}
	}
}

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
		// errJSONTooComplex (issue #101) is a size limit too, so it gets
		// KindTooLarge. The reason is the fixed text from blockedKinds: the
		// detail that a wrapper adds (here "more than 5 values") never
		// reaches the reason.
		{
			name:     "json too complex bare",
			err:      errJSONTooComplex,
			wantKind: KindTooLarge,
			wantIs:   []error{errJSONTooComplex},
			notIs:    []error{errBodyTooLarge},
			check:    wantExactReason(jsonTooComplexReason),
		},
		{
			name:     "json too complex wrapped with detail",
			err:      fmt.Errorf("%w (more than 5 values)", errJSONTooComplex),
			wantKind: KindTooLarge,
			wantIs:   []error{errJSONTooComplex},
			noReason: []string{"more than 5"},
			check:    wantExactReason(jsonTooComplexReason),
		},
		{
			name:     "json too complex inside a url error",
			err:      urlErr("Post", fmt.Errorf("%w (more than 5 values)", errJSONTooComplex)),
			wantKind: KindTooLarge,
			wantIs:   []error{errJSONTooComplex},
			check:    wantExactReason(jsonTooComplexReason),
		},
		{
			name:     "json too complex wins over http status",
			err:      fmt.Errorf("%w (more than 5 values)", errJSONTooComplex),
			ev:       &fakeEvents{status: http.StatusInternalServerError},
			wantKind: KindTooLarge,
			wantIs:   []error{errJSONTooComplex},
			check:    wantExactReason(jsonTooComplexReason),
		},
		{
			name:     "ev blocked json too complex wins over flattened text",
			err:      errors.New("client is closing: unexpected EOF"),
			ev:       &fakeEvents{blocked: fmt.Errorf("%w (more than 5 values)", errJSONTooComplex)},
			wantKind: KindTooLarge,
			wantIs:   []error{errJSONTooComplex},
			check:    wantExactReason(jsonTooComplexReason),
		},
		{
			name:     "ev blocked json too complex keeps the deadline of err",
			err:      fmt.Errorf("calling tools/list: %w", context.DeadlineExceeded),
			ev:       &fakeEvents{blocked: errJSONTooComplex},
			wantKind: KindTooLarge,
			wantIs:   []error{errJSONTooComplex, context.DeadlineExceeded},
			noReason: []string{"timed out"},
			check:    wantExactReason(jsonTooComplexReason),
		},
		// errAddrRefused (issue #106): the dialer refused the DNS answer for
		// the server name. It is a network error with a fixed reason. The
		// net.OpError around it must not turn it into the generic
		// "network error: <text>" reason.
		{
			name:     "addr refused bare",
			err:      errAddrRefused,
			wantKind: KindNetwork,
			wantIs:   []error{errAddrRefused},
			check:    wantExactReason(addrRefusedReason),
		},
		{
			name:     "addr refused in a dial error",
			err:      urlErr("Post", &net.OpError{Op: "dial", Net: "tcp", Err: errAddrRefused}),
			wantKind: KindNetwork,
			wantIs:   []error{errAddrRefused},
			noReason: []string{"network error:", "dial"},
			check:    wantExactReason(addrRefusedReason),
		},
		{
			name:     "addr refused wins over http status",
			err:      fmt.Errorf("dial: %w", errAddrRefused),
			ev:       &fakeEvents{status: http.StatusBadGateway},
			wantKind: KindNetwork,
			wantIs:   []error{errAddrRefused},
			check:    wantExactReason(addrRefusedReason),
		},
		{
			// The SDK flattens the transport error into text. The record of
			// headerTransport keeps the label.
			name:     "ev blocked addr refused wins over flattened text",
			err:      errors.New("calling initialize: Post x: " + errAddrRefused.Error()),
			ev:       &fakeEvents{blocked: urlErr("Post", errAddrRefused)},
			wantKind: KindNetwork,
			wantIs:   []error{errAddrRefused},
			notIs:    []error{errOtherOrigin, errBodyTooLarge},
			check:    wantExactReason(addrRefusedReason),
		},
		{
			name:     "ev blocked addr refused keeps the deadline of err",
			err:      fmt.Errorf("calling initialize: %w", context.DeadlineExceeded),
			ev:       &fakeEvents{blocked: errAddrRefused},
			wantKind: KindNetwork,
			wantIs:   []error{errAddrRefused, context.DeadlineExceeded},
			noReason: []string{"timed out"},
			check:    wantExactReason(addrRefusedReason),
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
			// safeCause replaces a cause whose text holds a secret, but the
			// new cause still matches the sentinel (see withText).
			name:     "invalid proxy in a leaky wrapper keeps the fixed reason",
			err:      &leakyError{text: "connect: " + leakText, err: errInvalidProxy},
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

			ce := classify(tt.err, srv, tt.ev, secretLists{long: testHeaderValues(srv)})
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

// TestClassifyRealNetworkTimeout checks the errors that the net package
// produces for an expired context, and not only hand-made ones.
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
		ce := classify(urlErr("Post", err), srv, nil, secretLists{long: testHeaderValues(srv)})
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
		ce := classify(urlErr("Post", err), srv, nil, secretLists{long: testHeaderValues(srv)})
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
	ce := classify(wrapped, srv, nil, secretLists{long: testHeaderValues(srv)})
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
	ce := classify(errors.New("boom"), srv, nil, secretLists{})
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
	ce := classify(urlErr("Post", clean), srv, nil, secretLists{long: values})
	if got := errors.Unwrap(ce); got != clean { //nolint:errorlint // identity check: the cause must be returned unchanged
		t.Errorf("Unwrap() = %v, want the original clean cause", got)
	}

	leaky := errors.New("leak " + testAuthValue)
	ce = classify(leaky, srv, nil, secretLists{long: values})
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
	ce := classify(errors.New(long), srv, nil, secretLists{})
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

			got := scrub(tt.text, tt.rawURL, tt.redacted, secretLists{long: tt.headers})
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
	ce := classify(errors.New(text), srv, nil, secretLists{long: secrets})

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

// TestSentHeaders checks the keys and the Basic flag that sentHeaders gives,
// and that sentHeaderNames keeps its old output: the same keys, plus
// "Authorization (from URL user info)" at the end when basic is true. The
// result never holds a header value or a password.
func TestSentHeaders(t *testing.T) {
	t.Parallel()

	const (
		plainURL    = "http://mcp.example.com/mcp"
		userinfoURL = "http://user:pa55-SECRET@mcp.example.com/mcp" //nolint:gosec // G101: fake test credentials
		password    = "pa55-SECRET"
		value       = "VAL-SECRET-1"
		fromURL     = "Authorization (from URL user info)"
	)
	tests := []struct {
		name    string
		rawURL  string
		headers map[string]string // nil gives a nil SecretMap
		// wantNames and wantBasic are the results of sentHeaders.
		wantNames []string
		wantBasic bool
		// wantList is the result of sentHeaderNames.
		wantList []string
	}{
		{name: "no headers, nil map", rawURL: plainURL},
		{name: "no headers, empty map", rawURL: plainURL, headers: map[string]string{}},
		{
			name: "one header", rawURL: plainURL,
			headers:   map[string]string{"X-Api-Key": value},
			wantNames: []string{"X-Api-Key"},
			wantList:  []string{"X-Api-Key"},
		},
		{
			name: "two headers in sorted key order", rawURL: plainURL,
			headers:   map[string]string{"X-Api-Key": value, "Authorization": "Bearer " + value},
			wantNames: []string{"Authorization", "X-Api-Key"},
			wantList:  []string{"Authorization", "X-Api-Key"},
		},
		// Keys that differ only in case go out as one header (buildHeader).
		// sentHeaders names it once, in the form of the first key in sorted
		// byte order: upper case sorts before lower case.
		{
			name: "mixed-case duplicates are named once", rawURL: plainURL,
			headers:   map[string]string{"x-api-key": value, "X-Api-Key": value, "X-API-KEY": value},
			wantNames: []string{"X-API-KEY"},
			wantList:  []string{"X-API-KEY"},
		},
		{
			name: "mixed-case duplicates among other keys", rawURL: plainURL,
			headers:   map[string]string{"accept-language": "en", "x-key": value, "X-Key": value, "Accept-Language": "en"},
			wantNames: []string{"Accept-Language", "X-Key"},
			wantList:  []string{"Accept-Language", "X-Key"},
		},
		{
			name: "user info only", rawURL: userinfoURL,
			wantBasic: true,
			wantList:  []string{fromURL},
		},
		{
			name: "user name only", rawURL: "http://user@mcp.example.com/mcp",
			wantBasic: true,
			wantList:  []string{fromURL},
		},
		{
			name: "user info and a header", rawURL: userinfoURL,
			headers:   map[string]string{"X-Api-Key": value},
			wantNames: []string{"X-Api-Key"},
			wantBasic: true,
			wantList:  []string{"X-Api-Key", fromURL},
		},
		{
			name: "user info and a config Authorization", rawURL: userinfoURL,
			headers:   map[string]string{"Authorization": "Bearer " + value},
			wantNames: []string{"Authorization"},
			wantList:  []string{"Authorization"},
		},
		// An empty config Authorization counts as absent: the Basic header
		// from the user info replaces it, so its key is not named.
		{
			name: "user info, empty Authorization and a header", rawURL: userinfoURL,
			headers:   map[string]string{"Authorization": "", "X-Api-Key": value},
			wantNames: []string{"X-Api-Key"},
			wantBasic: true,
			wantList:  []string{"X-Api-Key", fromURL},
		},
		// "authorization" sorts after "Authorization", so its non-empty value
		// wins and no Basic header goes out.
		{
			name: "user info and mixed-case Authorization, last non-empty", rawURL: userinfoURL,
			headers:   map[string]string{"Authorization": "", "authorization": "Bearer " + value},
			wantNames: []string{"Authorization"},
			wantList:  []string{"Authorization"},
		},
		// The client cannot parse such a URL, so there is no user info.
		{
			name: "unparsable URL", rawURL: "http://user:pa55-SECRET@[bad/mcp",
			headers:   map[string]string{"X-Api-Key": value},
			wantNames: []string{"X-Api-Key"},
			wantList:  []string{"X-Api-Key"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var cfg discover.SecretMap
			if tt.headers != nil {
				cfg = make(discover.SecretMap, len(tt.headers))
				for key, v := range tt.headers {
					cfg[key] = discover.NewSecret(v)
				}
			}
			srv := discover.Server{
				Name:      "remote",
				Transport: discover.TransportHTTP,
				URL:       discover.NewURL(tt.rawURL),
				Headers:   cfg,
			}

			names, basic := sentHeaders(srv)
			if !slices.Equal(names, tt.wantNames) || basic != tt.wantBasic {
				t.Errorf("sentHeaders() = %q, %t; want %q, %t", names, basic, tt.wantNames, tt.wantBasic)
			}
			list := sentHeaderNames(srv)
			if !slices.Equal(list, tt.wantList) {
				t.Errorf("sentHeaderNames() = %q, want %q", list, tt.wantList)
			}
			// A second call gives the same result: sentHeaderNames must not
			// change the slice of a later sentHeaders call.
			if again, againBasic := sentHeaders(srv); !slices.Equal(again, names) || againBasic != basic {
				t.Errorf("second sentHeaders() = %q, %t; want %q, %t", again, againBasic, names, basic)
			}

			text := fmt.Sprintf("%#v %#v", names, list)
			for _, secret := range []string{value, password, "Bearer"} {
				if strings.Contains(text, secret) {
					t.Errorf("sentHeaders output %s holds the secret %q", text, secret)
				}
			}
		})
	}
}

// TestScrubShortWords checks how scrub treats short, the values under
// discover.MinSecretBytes bytes (issue #180): they go only where they stand
// as whole words, in the raw and the %q form, while secrets go wherever they
// stand. Whole words cannot stop a hostile server that glues a letter to the
// value; the "inside a word" cases pin that known limit, they do not claim a
// fix.
func TestScrubShortWords(t *testing.T) {
	t.Parallel()

	// A text over maxReasonRunes runes whose cut ends right after "12345":
	// replaceWords keeps "12345x" (glued), but the cut alone would show
	// " 12345…" as a whole word. cutWords must drop it.
	cutPrefix := strings.Repeat("a", maxReasonRunes-len(" PIN ")-len("12345")) + " PIN "
	cutText := cutPrefix + "12345x" + strings.Repeat("b", 50)

	tests := []struct {
		name    string
		text    string
		secrets []string
		short   []string
		want    string
	}{
		{name: "short value as a word", text: "bad PIN 123456 given", short: []string{"123456"}, want: "bad PIN ******** given"},
		{name: "short value at both text edges", text: "123456", short: []string{"123456"}, want: discover.Mask},
		{name: "short value after punctuation", text: "pin=123456, retry", short: []string{"123456"}, want: "pin=********, retry"},
		{name: "short value after a multi-byte rune", text: "é123456", short: []string{"123456"}, want: "é********"},
		{
			name:  "short value inside a word stays (known limit)",
			text:  "a123456 123456x x_123456 9123456",
			short: []string{"123456"},
			want:  "a123456 123456x x_123456 9123456",
		},
		{
			// The cost of the whole-word rule: a common word that is also a
			// value goes too. "10" holds a "1" glued to a digit, so it stays.
			name:  "value 1 masks exit status 1 but not line 10",
			text:  "exit status 1 at line 10",
			short: []string{"1"},
			want:  "exit status ******** at line 10",
		},
		{
			// The cut ends with a Mask. The value "*" must not eat the stars
			// of the Mask one by one.
			name:  "cut that ends with a Mask and the value star",
			text:  strings.Repeat("a", maxReasonRunes-len(discover.Mask)) + discover.Mask + "tail",
			short: []string{"*"},
			want:  strings.Repeat("a", maxReasonRunes-len(discover.Mask)) + discover.Mask + "…",
		},
		{
			// replaceWords reads the text as it was: "pw!" is glued to "abc"
			// there, so it stays when "abc" goes (known limit).
			name:  "value glued to a masked value stays (known limit)",
			text:  "pw!abc",
			short: []string{"pw!", "abc"},
			want:  "pw!" + discover.Mask,
		},
		{
			// %q prints `a"b` as `a\"b`; the raw form is not in the text.
			name:  "quoted form of a value with a quote",
			text:  `got "a\"b" from server`,
			short: []string{`a"b`},
			want:  `got "********" from server`,
		},
		{
			name:  "quoted form of a value with a backslash",
			text:  `path "c:\\d" not found`,
			short: []string{`c:\d`},
			want:  `path "********" not found`,
		},
		{
			// The "n" before the value is a word byte, but it ends the
			// escape \n, so it counts as a boundary.
			name:  "newline escape before the value",
			text:  `line\n123456`,
			short: []string{"123456"},
			want:  `line\n********`,
		},
		{name: "hex escape before the value", text: `\x01123456`, short: []string{"123456"}, want: `\x01********`},
		{name: "unicode escape before the value", text: `\u00e9123456`, short: []string{"123456"}, want: `\u00e9********`},
		{
			// `\\n` is an escaped backslash and a plain "n": no escape.
			name:  "escaped backslash then n is not a boundary",
			text:  `line\\n123456`,
			short: []string{"123456"},
			want:  `line\\n123456`,
		},
		{
			// Without the longest-first rule "ab" would go and leave "-c".
			name:  "overlapping values longest wins",
			text:  "x ab-c y ab z",
			short: []string{"ab", "ab-c"},
			want:  "x ******** y ******** z",
		},
		{
			name:  "overlapping values longest wins in any order",
			text:  "x ab-c y ab z",
			short: []string{"ab-c", "ab"},
			want:  "x ******** y ******** z",
		},
		{
			// The stars of an existing mask must not be masked one by one.
			name:  "existing mask is copied with value star",
			text:  "token ******** and * here",
			short: []string{"*"},
			want:  "token ******** and ******** here",
		},
		{
			name:    "mask from a long secret is copied with value star",
			text:    "got longsecret8 and *",
			secrets: []string{"longsecret8"},
			short:   []string{"*"},
			want:    "got ******** and ********",
		},
		{
			// The last "*" of the stars is the first byte of the value: the
			// copy of the Mask must not take it and leave "1234".
			name:  "value with a leading star after seven stars",
			text:  "*******" + "*1234",
			short: []string{"*1234"},
			want:  "*******" + discover.Mask,
		},
		{
			name:  "value with a leading star inside a mask in a sentence",
			text:  "pin ********1234 end",
			short: []string{"*1234"},
			want:  "pin *******" + discover.Mask + " end",
		},
		{
			name:  "value with a leading star right after a mask",
			text:  discover.Mask + "*1234",
			short: []string{"*1234"},
			want:  discover.Mask + discover.Mask,
		},
		{
			name:  "value with a leading star glued to a letter stays",
			text:  discover.Mask + "1234x",
			short: []string{"*1234"},
			want:  discover.Mask + "1234x",
		},
		{
			// The longer form "*1234" wins over "1234" at the same text.
			name:  "value with a leading star and its tail as values",
			text:  discover.Mask + "1234",
			short: []string{"1234", "*1234"},
			want:  "*******" + discover.Mask,
		},
		{
			// A match that ends inside the mask is only stars: the mask is
			// copied once, then the star after it goes.
			name:  "value star after a mask is masked once",
			text:  discover.Mask + "*",
			short: []string{"*"},
			want:  discover.Mask + discover.Mask,
		},
		{
			// "**" starts at the last star of the mask and ends after it.
			name:  "value of two stars across the mask end",
			text:  discover.Mask + "*",
			short: []string{"**"},
			want:  "*******" + discover.Mask,
		},
		{
			name:  "value star in a run of masks does not blow up",
			text:  strings.Repeat(discover.Mask, 3),
			short: []string{"*"},
			want:  strings.Repeat(discover.Mask, 3),
		},
		{name: "cut after replace drops a value at the cut edge", text: cutText, short: []string{"12345"}, want: cutPrefix + "…"},
		{name: "cut without the value in short keeps it", text: cutText, want: cutPrefix + "12345…"},
		{name: "nil short changes nothing", text: "exit status 1", want: "exit status 1"},
		{name: "empty value in short changes nothing", text: "exit status 1", short: []string{""}, want: "exit status 1"},
		{name: "short value not in text changes nothing", text: "exit status 1", short: []string{"2"}, want: "exit status 1"},
		{
			name:    "long secret goes inside a word",
			text:    "xlongsecret8y",
			secrets: []string{"longsecret8"},
			want:    "x********y",
		},
		{
			// Header values stay removed anywhere, even when short.
			name:    "short header value goes inside a word",
			text:    "xabcx",
			secrets: []string{"abc"},
			want:    "x********x",
		},
		{
			// The long one goes as a whole first, then the short one as a word.
			name:    "short value that is part of a long secret",
			text:    "key abcdefgh12 and 12",
			secrets: []string{"abcdefgh12"},
			short:   []string{"12"},
			want:    "key ******** and ********",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// The values are fake, so the messages show them.
			if got := scrub(tt.text, "", "", secretLists{long: tt.secrets, short: tt.short}); got != tt.want {
				t.Errorf("scrub(%q, short %q) = %q, want %q", tt.text, tt.short, got, tt.want)
			}
		})
	}
}

// TestClassifyShortValue checks that classify passes short to the scrub of
// both the reason and the cause, so ConnectError.Error and errors.Unwrap do
// not show a short value that a server echoed as a word.
func TestClassifyShortValue(t *testing.T) {
	t.Parallel()

	srv := testServer(discover.TransportHTTP)
	ce := classify(errors.New("bad PIN 123456 and tok-42"), srv, nil, secretLists{short: []string{"123456", "tok-42"}})
	cause := errors.Unwrap(ce)
	if cause == nil {
		t.Fatal("Unwrap() = nil, want a scrubbed cause")
	}
	for _, text := range []string{ce.Error(), ce.Reason, cause.Error()} {
		if strings.Contains(text, "123456") || strings.Contains(text, "tok-42") {
			t.Errorf("error text %q holds a short value", text)
		}
		if !strings.Contains(text, "bad PIN "+discover.Mask) {
			t.Errorf("error text %q, want it to hold %q", text, "bad PIN "+discover.Mask)
		}
	}
}

// testRand is a small linear congruential generator for repeatable test
// inputs (the constants are the ones of Knuth's MMIX). The inputs are not
// secrets, so a generator for security is not needed, and the fixed seed
// gives the same inputs on every run.
type testRand struct {
	state int64
}

// IntN returns a number in [0, n), or 0 when n is 0 or less. The small bias
// of the modulo does not matter for test inputs.
func (r *testRand) IntN(n int) int {
	if n <= 0 {
		return 0
	}
	// Go integers wrap around on overflow, which the generator needs.
	r.state = r.state*6364136223846793005 + 1442695040888963407
	// The high bits of the state are the most random ones. The mask keeps
	// 30 of them, so the number is not negative and fits in any int.
	return int(r.state>>33&(1<<30-1)) % n
}

// shortWordsInput returns a text of about size bytes and n short values,
// for the benchmark and the differential test of replaceWords. The text is
// words of 1 to 7 bytes from [a-z0-9], split by spaces, with each value in it
// one time as a whole word. The values are 3 to 7 bytes from the same
// alphabet, so many bytes of the text start a value. The fixed seed makes the
// input the same on every run.
func shortWordsInput(size, n int) (string, []string) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	r := &testRand{state: 1}
	word := func(minLen, maxLen int) string {
		b := make([]byte, minLen+r.IntN(maxLen-minLen+1))
		for i := range b {
			b[i] = alphabet[r.IntN(len(alphabet))]
		}
		return string(b)
	}
	values := make([]string, n)
	for i := range values {
		values[i] = word(3, 7)
	}
	var b strings.Builder
	for b.Len() < size {
		// About one value in every size/n bytes.
		if r.IntN(size/n/4) == 0 && len(values) > 0 {
			b.WriteString(values[r.IntN(len(values))])
		} else {
			b.WriteString(word(1, 7))
		}
		b.WriteByte(' ')
	}
	return b.String(), values
}

// BenchmarkScrubShortWords measures the whole-word scrub on a JSON-RPC error
// message at the 4 MiB size class with 200 short values (NFR-03: a hostile
// server must not make the scrub slow).
func BenchmarkScrubShortWords(b *testing.B) {
	text, short := shortWordsInput(4<<20, 200)
	b.Run("replaceWords", func(b *testing.B) {
		b.SetBytes(int64(len(text)))
		for b.Loop() {
			replaceWords(text, short)
		}
	})
	b.Run("scrub", func(b *testing.B) {
		b.SetBytes(int64(len(text)))
		for b.Loop() {
			scrub(text, "", "", secretLists{short: short})
		}
	})
}

// TestClassifyContextErrorWithShortValue checks that the cause keeps the
// context error when the scrub changes its text (see safeCause). With the
// short value "1" (as in DEBUG=1), the text "exit status 1" changes, so the
// cause becomes a new error; errors.Is must still find the context error,
// as Remote and Inspect promise, and the new text must not show the value.
func TestClassifyContextErrorWithShortValue(t *testing.T) {
	t.Parallel()

	short := secretLists{short: []string{"1"}}
	tests := []struct {
		name     string
		ctxErr   error
		wantText string
	}{
		{name: "deadline", ctxErr: context.DeadlineExceeded, wantText: "timed out"},
		{name: "canceled", ctxErr: context.Canceled, wantText: "canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := fmt.Errorf("%w: calling initialize: exit status 1", tt.ctxErr)
			checks := []struct {
				name string
				ce   *ConnectError
			}{
				{name: "classify", ce: classify(err, testServer(discover.TransportHTTP), nil, short)},
				{name: "stdioFailure", ce: stdioFailure(stdioServer("/bin/true"), err, short, false)},
			}
			for _, c := range checks {
				if c.ce.Kind != KindTimeout || c.ce.Reason != tt.wantText {
					t.Errorf("%s: Kind %q, Reason %q, want %q, %q", c.name, c.ce.Kind, c.ce.Reason, KindTimeout, tt.wantText)
				}
				if !errors.Is(c.ce, tt.ctxErr) {
					t.Errorf("%s: errors.Is(err, %v) = false, want true", c.name, tt.ctxErr)
				}
				cause := errors.Unwrap(c.ce)
				if cause == nil {
					t.Fatalf("%s: Unwrap() = nil, want the scrubbed cause", c.name)
				}
				if want := "exit status " + discover.Mask; !strings.HasSuffix(cause.Error(), want) {
					t.Errorf("%s: cause text %q, want it to end with %q", c.name, cause.Error(), want)
				}
			}
		})
	}
}

// refReplaceWords is replaceWords as it was before the prefix tree
// (wordTrie): it tries every form at every byte. TestReplaceWordsDifferential
// compares the two, so the faster code must give the same text. The reference
// shares no helper with the code under test (see refWordForms and
// refWordStart), so a bug in a shared helper cannot change both sides the
// same way.
func refReplaceWords(text string, short []string) string {
	forms := refWordForms(text, short)
	if len(forms) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	for i := 0; i < len(text); {
		if strings.HasPrefix(text[i:], discover.Mask) {
			j, n := refMaskedWordAt(text, i, forms)
			if n == 0 {
				b.WriteString(discover.Mask)
				i += len(discover.Mask)
				continue
			}
			b.WriteString(text[i:j])
			b.WriteString(discover.Mask)
			i = j + n
			continue
		}
		if n := refWordAt(text, i, forms); n > 0 {
			b.WriteString(discover.Mask)
			i += n
			continue
		}
		b.WriteByte(text[i])
		i++
	}
	return b.String()
}

// refWordAt is wordAt before the prefix tree (see refReplaceWords).
func refWordAt(text string, i int, forms []string) int {
	for _, f := range forms {
		if !strings.HasPrefix(text[i:], f) {
			continue
		}
		if !refWordStart(text, i) {
			return 0
		}
		end := i + len(f)
		if end == len(text) || !refIsWordByte(text[end]) {
			return len(f)
		}
	}
	return 0
}

// refMaskedWordAt is maskedWordAt before the prefix tree (see
// refReplaceWords).
func refMaskedWordAt(text string, i int, forms []string) (start, n int) {
	maskEnd := i + len(discover.Mask)
	for j := i; j < maskEnd; j++ {
		if m := refWordAt(text, j, forms); j+m > maskEnd {
			return j, m
		}
	}
	return 0, 0
}

// refWordForms is the old wordForms (see refReplaceWords): the forms of the
// values in short that occur in text, each non-empty value and its %q form,
// each one time, longest first and then by bytes.
func refWordForms(text string, short []string) []string {
	var forms []string
	for _, v := range short {
		if v == "" {
			continue
		}
		q := strconv.Quote(v)
		for _, f := range []string{v, q[1 : len(q)-1]} {
			if strings.Contains(text, f) {
				forms = append(forms, f)
			}
		}
	}
	slices.SortFunc(forms, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	return slices.Compact(forms)
}

// refWordStart is the old wordStart (see refReplaceWords).
func refWordStart(text string, i int) bool {
	return i == 0 || !refIsWordByte(text[i-1]) || refEndsWithEscape(text[:i])
}

// refIsWordByte is the old isWordByte (see refReplaceWords).
func refIsWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// refEndsWithEscape is the old endsWithEscape (see refReplaceWords): s ends
// with \a, \b, \f, \n, \r, \t, \v, \xHH, \uHHHH or \UHHHHHHHH after an odd
// number of backslashes.
func refEndsWithEscape(s string) bool {
	isHex := func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
	}
	for _, n := range []int{1, 3, 5, 9} {
		if len(s) < n+1 {
			continue
		}
		body := s[len(s)-n:]
		ok := false
		switch {
		case n == 1:
			ok = strings.IndexByte("abfnrtv", body[0]) >= 0
		case body[0] == 'x' && n == 3, body[0] == 'u' && n == 5, body[0] == 'U' && n == 9:
			ok = true
			for i := 1; i < n; i++ {
				ok = ok && isHex(body[i])
			}
		}
		if !ok {
			continue
		}
		before := s[:len(s)-n]
		if (len(before)-len(strings.TrimRight(before, `\`)))%2 == 1 {
			return true
		}
	}
	return false
}

// TestReplaceWordsDifferential compares replaceWords with refReplaceWords on
// 3000 random texts and value lists. The alphabet is small and holds the
// bytes that the rules treat in a special way: "*" (the Mask), digits and
// letters (word bytes, hex digits, escape letters), "\" and quotes (escapes
// and %q forms), "_" and a two-byte rune. Whole Masks are mixed in too. The
// fixed seed makes every run check the same cases.
func TestReplaceWordsDifferential(t *testing.T) {
	t.Parallel()

	pieces := []string{"*", "*", "1", "2", "0", "a", "x", "n", "u", "_", " ", `\`, `"`, "-", "é", "\n", discover.Mask}
	r := &testRand{state: 3}
	randomText := func(maxPieces int) string {
		var b strings.Builder
		for range r.IntN(maxPieces + 1) {
			b.WriteString(pieces[r.IntN(len(pieces))])
		}
		return b.String()
	}
	// changed counts the cases in which the text changed.
	changed := 0
	for n := range 3000 {
		text := randomText(40)
		short := make([]string, r.IntN(6))
		for i := range short {
			// Values of 0 to 3 pieces, without the Mask piece: a value is
			// shorter than discover.MinSecretBytes. An empty value is
			// allowed; replaceWords must skip it.
			var b strings.Builder
			for range r.IntN(4) {
				b.WriteString(pieces[r.IntN(len(pieces)-1)])
			}
			short[i] = b.String()
		}
		// Half of the cases take a value from the text, so that most cases
		// have a match.
		if len(text) > 0 && len(short) > 0 && r.IntN(2) == 0 {
			i := r.IntN(len(text))
			short[0] = text[i:min(len(text), i+1+r.IntN(4))]
		}
		got, want := replaceWords(text, short), refReplaceWords(text, short)
		if got != want {
			t.Fatalf("case %d: replaceWords(%q, %q) = %q, want %q (reference)", n, text, short, got, want)
		}
		if got != text {
			changed++
		}
	}
	// Guard against a test that checks nothing: many cases must mask.
	if changed < 500 {
		t.Errorf("only %d of 3000 cases masked a value, want at least 500", changed)
	}
}

// TestShowDiscoveredURLHeaderShortValue checks that showDiscoveredURL removes
// the short credentials inside the header values too, as classify did in
// Remote (see remoteShortSecrets). The hostname "h1" comes from a short
// variable. In "h1pw" classify kept both values, because they are glued.
// showDiscoveredURL replaces the hostname with the discovered one, and that
// puts "pw", the short password of the X-Db header, after a non-word byte. So
// "pw" now stands as a whole word and must go.
func TestShowDiscoveredURLHeaderShortValue(t *testing.T) {
	t.Parallel()

	expanded := discover.Server{
		Name:      "remote",
		Transport: discover.TransportHTTP,
		URL:       discover.NewURL("http://h1:8080/mcp"),
		Headers:   discover.SecretMap{"X-Db": discover.NewSecret("postgres://app:pw@db/app")},
	}
	discovered := discover.NewURL("http://${MCP_HOST}:8080/mcp")
	lookedUp := secretLists{short: []string{"h1"}}
	short := remoteShortSecrets(expanded, lookedUp)
	if !slices.Contains(short, "h1") || !slices.Contains(short, "pw") {
		t.Fatalf("remoteShortSecrets() = %q, want it to hold the expanded value and the header password", short)
	}

	// All of reason is text of the cause (see ConnectError.serverText).
	reason := "lookup h1pw: no such host"
	ce := &ConnectError{Kind: KindNetwork, Server: "remote", Reason: reason, serverText: reason}
	showDiscoveredURL(ce, expanded.URL, discovered, short)
	if strings.Contains(ce.Reason, "pw") || strings.Contains(ce.Reason, "h1") {
		t.Errorf("Reason = %q, want no short value in it", ce.Reason)
	}

	// The expanded short values alone, the list before the fix, leave the
	// password as a whole word. This shows that the case tests the fix.
	old := &ConnectError{Kind: KindNetwork, Server: "remote", Reason: reason, serverText: reason}
	showDiscoveredURL(old, expanded.URL, discovered, lookedUp.short)
	if !strings.Contains(old.Reason, "pw") {
		t.Errorf("Reason with the expanded values only = %q, want the case to show %q", old.Reason, "pw")
	}
}
