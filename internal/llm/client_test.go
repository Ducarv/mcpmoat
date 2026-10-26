package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Canaries of the client tests. No error text may hold one of them.
const (
	// llmTestKey is the API key of every test client.
	llmTestKey = "sk-KEYCANARY-7f3a9c"
	// llmBodyCanary is put in response bodies and response headers.
	llmBodyCanary = "BODYCANARY-91c2e"
	// llmTestModel is the model name of the test clients.
	llmTestModel = "test-model-1"
)

// capturedRequest is what a test server saw of one request.
type capturedRequest struct {
	Method     string
	Path       string
	RawQuery   string
	RequestURI string
	Host       string
	Header     http.Header
	Body       []byte
}

// testServer is a loopback httptest server that counts requests and keeps
// the last one. Its URL is an http URL, and the client never uses a proxy
// for http, so the tests that use it do not depend on HTTP_PROXY of the
// machine (the "httpnoproxy" mode of TestClassifyProxySettings checks this).
type testServer struct {
	*httptest.Server
	hits atomic.Int32
	mu   sync.Mutex
	last capturedRequest
}

// startServer starts a testServer that calls h after it records the request.
func startServer(t *testing.T, h http.HandlerFunc) *testServer {
	t.Helper()
	s := &testServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("server: read request body: %v", err)
		}
		s.hits.Add(1)
		s.mu.Lock()
		s.last = capturedRequest{
			Method:     r.Method,
			Path:       r.URL.Path,
			RawQuery:   r.URL.RawQuery,
			RequestURI: r.RequestURI,
			Host:       r.Host,
			Header:     r.Header.Clone(),
			Body:       body,
		}
		s.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// lastRequest returns the last request that s saw.
func (s *testServer) lastRequest() capturedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// reply returns a handler that answers with status and body, and puts
// llmBodyCanary in a response header.
func reply(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Debug", llmBodyCanary)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// testSecret returns llmTestKey as a secret.
func testSecret() discover.Secret { return discover.NewSecret(llmTestKey) }

// newTestClient returns a client for provider p at base, with llmTestKey and
// llmTestModel.
func newTestClient(t *testing.T, p Provider, base string) *Client {
	t.Helper()
	c, err := New(Config{Provider: p, Model: llmTestModel, BaseURL: base, APIKey: testSecret()})
	if err != nil {
		t.Fatalf("New(%s) error = %v", p, err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// validReply returns a 2xx response body of provider p with the verdict
// risk and category.
func validReply(p Provider, risk Risk, category Category) string {
	if p == ProviderOpenAI {
		return openAIReply(risk, category)
	}
	return anthropicReply(risk, category)
}

// assertNoLeak fails when the error text holds the key, a body canary, a
// loopback address, a URL or one of extra.
func assertNoLeak(t *testing.T, err error, extra ...string) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	for _, s := range append([]string{llmTestKey, llmBodyCanary, "127.0.0.1", "://", "Bearer"}, extra...) {
		if s != "" && strings.Contains(msg, s) {
			t.Errorf("error %q holds %q", msg, s)
		}
	}
}

// bothProviders lists the providers for tests that run against each one.
var bothProviders = []Provider{ProviderAnthropic, ProviderOpenAI}

func TestNewRefusesBadConfigAndSendsNothing(t *testing.T) {
	t.Parallel()
	srv := startServer(t, reply(http.StatusOK, ""))
	tests := []struct {
		name    string
		cfg     Config
		wantErr error
	}{
		{
			name:    "missing key",
			cfg:     Config{Provider: ProviderAnthropic, BaseURL: srv.URL},
			wantErr: ErrMissingKey,
		},
		{
			name:    "key with a line break",
			cfg:     Config{Provider: ProviderAnthropic, BaseURL: srv.URL, APIKey: discover.NewSecret(llmTestKey + "\r\nX: y")},
			wantErr: ErrInvalidKey,
		},
		{
			name:    "openai without model",
			cfg:     Config{Provider: ProviderOpenAI, BaseURL: srv.URL, APIKey: testSecret()},
			wantErr: ErrInvalidModel,
		},
		{
			name:    "unknown provider",
			cfg:     Config{Provider: "gemini", BaseURL: srv.URL, APIKey: testSecret()},
			wantErr: ErrUnknownProvider,
		},
		{
			name:    "http to a non-loopback host",
			cfg:     Config{Provider: ProviderAnthropic, BaseURL: "http://api.example.com", APIKey: testSecret()},
			wantErr: ErrInvalidBaseURL,
		},
		{
			name:    "user info in the base URL",
			cfg:     Config{Provider: ProviderOpenAI, Model: llmTestModel, BaseURL: strings.Replace(srv.URL, "://", "://user:pw@", 1), APIKey: testSecret()},
			wantErr: ErrInvalidBaseURL,
		},
		{
			name:    "query in the base URL",
			cfg:     Config{Provider: ProviderAnthropic, BaseURL: srv.URL + "/?k=v", APIKey: testSecret()},
			wantErr: ErrInvalidBaseURL,
		},
		{
			name:    "not a URL",
			cfg:     Config{Provider: ProviderAnthropic, BaseURL: "https://exa mple.com", APIKey: testSecret()},
			wantErr: ErrInvalidBaseURL,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(tt.cfg)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("New() error = %v, want %v", err, tt.wantErr)
			}
			if c != nil {
				t.Errorf("New() client = %v, want nil", c)
			}
			assertNoLeak(t, err, srv.URL, "user:pw", "example.com")
		})
	}
	// New must never send a request. Each subtest above is parallel, so
	// check after they finish.
	t.Cleanup(func() {
		if n := srv.hits.Load(); n != 0 {
			t.Errorf("server requests after New = %d, want 0", n)
		}
	})
}

func TestNewSendsNoRequest(t *testing.T) {
	t.Parallel()
	for _, p := range bothProviders {
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, reply(http.StatusOK, ""))
			c := newTestClient(t, p, srv.URL)
			c.CloseIdleConnections()
			if n := srv.hits.Load(); n != 0 {
				t.Errorf("server requests after New = %d, want 0", n)
			}
		})
	}
}

func TestClassifyKeyOnlyInAuthHeader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		provider   Provider
		authHeader string
		authValue  string
	}{
		{provider: ProviderAnthropic, authHeader: "X-Api-Key", authValue: llmTestKey},
		{provider: ProviderOpenAI, authHeader: "Authorization", authValue: "Bearer " + llmTestKey},
	}
	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, reply(http.StatusOK, validReply(tt.provider, RiskLow, CategoryOther)))
			c := newTestClient(t, tt.provider, srv.URL)
			if _, err := c.Classify(t.Context(), Input{ToolName: "t", Description: "d"}); err != nil {
				t.Fatalf("Classify() error = %v", err)
			}
			req := srv.lastRequest()

			if got := req.Header.Values(tt.authHeader); len(got) != 1 || got[0] != tt.authValue {
				t.Errorf("%s header = %q, want exactly one %q", tt.authHeader, got, tt.authValue)
			}
			found := 0
			for name, values := range req.Header {
				for _, v := range values {
					if strings.Contains(name, llmTestKey) || strings.Contains(v, llmTestKey) {
						found++
						if name != tt.authHeader {
							t.Errorf("header %s holds the key", name)
						}
					}
				}
			}
			if found != 1 {
				t.Errorf("headers with the key = %d, want 1", found)
			}
			for what, s := range map[string]string{
				"request URI": req.RequestURI,
				"query":       req.RawQuery,
				"host":        req.Host,
				"body":        string(req.Body),
			} {
				if strings.Contains(s, llmTestKey) {
					t.Errorf("%s holds the key", what)
				}
			}
		})
	}
}

func TestClassifyRefusesRedirect(t *testing.T) {
	t.Parallel()
	codes := []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	}
	for _, p := range bothProviders {
		for _, code := range codes {
			t.Run(fmt.Sprintf("%s/%d", p, code), func(t *testing.T) {
				t.Parallel()
				target := startServer(t, reply(http.StatusOK, validReply(p, RiskNone, CategoryOther)))
				origin := startServer(t, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Location", target.URL+r.URL.Path+"?leak="+llmBodyCanary)
					w.WriteHeader(code)
					_, _ = io.WriteString(w, llmBodyCanary)
				})
				c := newTestClient(t, p, origin.URL)

				v, err := c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})
				var se *StatusError
				if !errors.As(err, &se) || se.Code != code {
					t.Fatalf("Classify() error = %v, want *StatusError{Code: %d}", err, code)
				}
				if !errors.Is(err, ErrProvider) || errors.Is(err, ErrAuth) || errors.Is(err, ErrInvalidOutput) {
					t.Errorf("Classify() error = %v, want ErrProvider only", err)
				}
				if !strings.Contains(err.Error(), "redirect refused") {
					t.Errorf("Classify() error = %q, want it to say redirect refused", err)
				}
				if v != (Verdict{}) {
					t.Errorf("Classify() verdict = %+v, want zero", v)
				}
				if n := origin.hits.Load(); n != 1 {
					t.Errorf("origin requests = %d, want 1", n)
				}
				if n := target.hits.Load(); n != 0 {
					t.Errorf("redirect target requests = %d, want 0", n)
				}
				assertNoLeak(t, err, origin.URL, target.URL)
			})
		}
	}
}

func TestClassifyStatusErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code     int
		wantAuth bool
	}{
		{code: http.StatusBadRequest},
		{code: http.StatusUnauthorized, wantAuth: true},
		{code: http.StatusForbidden, wantAuth: true},
		{code: http.StatusNotFound},
		{code: http.StatusTooManyRequests},
		{code: http.StatusInternalServerError},
		{code: http.StatusServiceUnavailable},
	}
	for _, p := range bothProviders {
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s/%d", p, tt.code), func(t *testing.T) {
				t.Parallel()
				// A valid verdict in the body must be ignored.
				srv := startServer(t, reply(tt.code, validReply(p, RiskNone, CategoryOther)+llmBodyCanary))
				c := newTestClient(t, p, srv.URL)

				v, err := c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})
				var se *StatusError
				if !errors.As(err, &se) || se.Code != tt.code {
					t.Fatalf("Classify() error = %v, want *StatusError{Code: %d}", err, tt.code)
				}
				if got := errors.Is(err, ErrAuth); got != tt.wantAuth {
					t.Errorf("errors.Is(err, ErrAuth) = %v, want %v", got, tt.wantAuth)
				}
				if !errors.Is(err, ErrProvider) || errors.Is(err, ErrInvalidOutput) {
					t.Errorf("Classify() error = %v, want ErrProvider and not ErrInvalidOutput", err)
				}
				if want := fmt.Sprintf("LLM provider request failed: HTTP %d", tt.code); err.Error() != want {
					t.Errorf("Classify() error = %q, want %q", err, want)
				}
				if v != (Verdict{}) {
					t.Errorf("Classify() verdict = %+v, want zero", v)
				}
				assertNoLeak(t, err, srv.URL)
			})
		}
	}
}

func TestStatusError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code       int
		wantText   string
		wantUnwrap error
	}{
		{code: 301, wantText: "LLM provider request failed: HTTP 301 (redirect refused)", wantUnwrap: ErrProvider},
		{code: 399, wantText: "LLM provider request failed: HTTP 399 (redirect refused)", wantUnwrap: ErrProvider},
		{code: 400, wantText: "LLM provider request failed: HTTP 400", wantUnwrap: ErrProvider},
		{code: 401, wantText: "LLM provider request failed: HTTP 401", wantUnwrap: ErrAuth},
		{code: 403, wantText: "LLM provider request failed: HTTP 403", wantUnwrap: ErrAuth},
		{code: 407, wantText: "LLM provider request failed: HTTP 407", wantUnwrap: ErrProvider},
		{code: 500, wantText: "LLM provider request failed: HTTP 500", wantUnwrap: ErrProvider},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.code), func(t *testing.T) {
			t.Parallel()
			err := &StatusError{Code: tt.code}
			if got := err.Error(); got != tt.wantText {
				t.Errorf("Error() = %q, want %q", got, tt.wantText)
			}
			if got := err.Unwrap(); !errors.Is(got, tt.wantUnwrap) || got.Error() != tt.wantUnwrap.Error() {
				t.Errorf("Unwrap() = %v, want %v", got, tt.wantUnwrap)
			}
			if !errors.Is(err, ErrProvider) {
				t.Error("errors.Is(err, ErrProvider) = false, want true")
			}
		})
	}
}

// paddedReply returns a valid response body of provider p padded with
// trailing spaces to exactly size bytes.
func paddedReply(t *testing.T, p Provider, size int) string {
	t.Helper()
	body := validReply(p, RiskMedium, CategoryToolShadowing)
	if len(body) > size {
		t.Fatalf("reply has %d bytes, more than %d", len(body), size)
	}
	return body + strings.Repeat(" ", size-len(body))
}

func TestClassifyResponseBodyCap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		size          int
		contentLength bool
		wantTooLarge  bool
	}{
		{name: "at cap with Content-Length", size: MaxResponseBodyBytes, contentLength: true},
		{name: "at cap chunked", size: MaxResponseBodyBytes},
		{name: "cap plus one with Content-Length", size: MaxResponseBodyBytes + 1, contentLength: true, wantTooLarge: true},
		{name: "cap plus one chunked", size: MaxResponseBodyBytes + 1, wantTooLarge: true},
		{name: "much larger chunked", size: 4 * MaxResponseBodyBytes, wantTooLarge: true},
	}
	for _, p := range bothProviders {
		for _, tt := range tests {
			t.Run(string(p)+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				body := paddedReply(t, p, tt.size)
				srv := startServer(t, func(w http.ResponseWriter, _ *http.Request) {
					if tt.contentLength {
						w.Header().Set("Content-Length", fmt.Sprint(len(body)))
					} else {
						// A flush before the body makes the response chunked,
						// so it has no Content-Length.
						w.WriteHeader(http.StatusOK)
						w.(http.Flusher).Flush()
					}
					_, _ = io.WriteString(w, body)
				})
				c := newTestClient(t, p, srv.URL)

				v, err := c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})
				if tt.wantTooLarge {
					if !errors.Is(err, ErrTooLarge) || !errors.Is(err, ErrProvider) {
						t.Fatalf("Classify() error = %v, want ErrTooLarge", err)
					}
					assertNoLeak(t, err, srv.URL)
					return
				}
				if err != nil {
					t.Fatalf("Classify() error = %v, want nil", err)
				}
				if want := (Verdict{Risk: RiskMedium, Category: CategoryToolShadowing}); v != want {
					t.Errorf("Classify() = %+v, want %+v", v, want)
				}
			})
		}
	}
}

// TestClassifyDeclaredLengthTooLarge checks that a Content-Length above the
// cap is refused before the body is read: the body here is short, so a read
// would end in a transport error, not ErrTooLarge.
func TestClassifyDeclaredLengthTooLarge(t *testing.T) {
	t.Parallel()
	body := anthropicReply(RiskLow, CategoryOther)
	srv := startServer(t, func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("Hijack() error = %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", MaxResponseBodyBytes+1, body)
		_ = rw.Flush()
	})
	c := newTestClient(t, ProviderAnthropic, srv.URL)
	_, err := c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Classify() error = %v, want ErrTooLarge", err)
	}
}

func TestClassifyRequestBodyStaysUnderCap(t *testing.T) {
	t.Parallel()
	// Each input is far above the caps of toolMessage, and made of the
	// characters that JSON escapes grow the most.
	inputs := []struct {
		name string
		in   Input
	}{
		{name: "quotes", in: Input{ToolName: strings.Repeat(`\`, 1000), Description: strings.Repeat(`"`, 100000)}},
		{name: "backslashes", in: Input{ToolName: strings.Repeat(`"`, 1000), Description: strings.Repeat(`\`, 100000)}},
		{name: "control characters", in: Input{ToolName: strings.Repeat("\x01", 1000), Description: strings.Repeat("\x01", 100000)}},
		{name: "html characters", in: Input{ToolName: strings.Repeat("<", 1000), Description: strings.Repeat("<>&", 40000)}},
		{name: "line separators", in: Input{ToolName: "t", Description: strings.Repeat(string(rune(0x2028)), 40000)}},
		{name: "invalid UTF-8", in: Input{ToolName: "t", Description: strings.Repeat("\xff", 100000)}},
	}
	for _, p := range bothProviders {
		for _, tt := range inputs {
			t.Run(string(p)+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				srv := startServer(t, reply(http.StatusOK, validReply(p, RiskHigh, CategoryOther)))
				c := newTestClient(t, p, srv.URL)
				if _, err := c.Classify(t.Context(), tt.in); err != nil {
					t.Fatalf("Classify() error = %v, want nil", err)
				}
				if n := srv.hits.Load(); n != 1 {
					t.Fatalf("server requests = %d, want 1", n)
				}
				if n := len(srv.lastRequest().Body); n > MaxRequestBodyBytes {
					t.Errorf("request body = %d bytes, want at most %d", n, MaxRequestBodyBytes)
				}
			})
		}
	}
}

// TestClassifyTruncated checks that Classify sets Verdict.Truncated when the
// tool name or description was cut, and only then. The model answers risk
// none: Classify keeps the model risk, and the caller applies the floor.
func TestClassifyTruncated(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   Input
		want bool
	}{
		{name: "short tool", in: Input{ToolName: "read_file", Description: "Reads a file."}, want: false},
		{name: "description at limit", in: Input{ToolName: "t", Description: strings.Repeat("d", MaxDescriptionBytes)}, want: false},
		{name: "description over limit", in: Input{ToolName: "t", Description: strings.Repeat("d", MaxDescriptionBytes+1)}, want: true},
		{name: "name over limit", in: Input{ToolName: strings.Repeat("n", MaxToolNameBytes+1), Description: "d"}, want: true},
		// The description is not over MaxDescriptionBytes, but each control
		// character grows to six bytes in JSON, so only the message cap cuts it.
		{name: "cut by message cap", in: Input{ToolName: "t", Description: strings.Repeat("\x01", MaxDescriptionBytes)}, want: true},
	}
	for _, p := range bothProviders {
		for _, tt := range tests {
			t.Run(string(p)+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				srv := startServer(t, reply(http.StatusOK, validReply(p, RiskNone, CategoryOther)))
				c := newTestClient(t, p, srv.URL)
				v, err := c.Classify(t.Context(), tt.in)
				if err != nil {
					t.Fatalf("Classify() error = %v, want nil", err)
				}
				want := Verdict{Risk: RiskNone, Category: CategoryOther, Truncated: tt.want}
				if v != want {
					t.Errorf("Classify() = %+v, want %+v", v, want)
				}
			})
		}
	}
}

// TestClassifyTruncatedError checks that a failed Classify returns only
// Truncated in the Verdict: true for a cut description, false for a tool that
// was not cut. Risk and Category stay zero. The caller needs Truncated with
// an unusable answer (ErrInvalidOutput) to rate a cut tool medium.
func TestClassifyTruncatedError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		desc    string
		status  int
		wantErr error
		want    Verdict
	}{
		{name: "cut and unusable", desc: strings.Repeat("d", MaxDescriptionBytes+1), status: http.StatusOK, wantErr: ErrInvalidOutput, want: Verdict{Truncated: true}},
		{name: "not cut and unusable", desc: "d", status: http.StatusOK, wantErr: ErrInvalidOutput, want: Verdict{}},
		{name: "cut and provider failure", desc: strings.Repeat("d", MaxDescriptionBytes+1), status: http.StatusServiceUnavailable, wantErr: ErrProvider, want: Verdict{Truncated: true}},
	}
	for _, p := range bothProviders {
		for _, tt := range tests {
			t.Run(string(p)+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				srv := startServer(t, reply(tt.status, validReply(p, "critical", CategoryOther)))
				c := newTestClient(t, p, srv.URL)
				v, err := c.Classify(t.Context(), Input{ToolName: "t", Description: tt.desc})
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Classify() error = %v, want %v", err, tt.wantErr)
				}
				if v != tt.want {
					t.Errorf("Classify() = %+v, want %+v on error", v, tt.want)
				}
			})
		}
	}
}

// sizedAPI is the Anthropic API with a request body that is one JSON string
// of exactly size bytes. No real Input can pass the request cap, so the
// guard is tested with this fake.
type sizedAPI struct {
	anthropicAPI
	size int
}

func (a sizedAPI) requestBody(string, string) any {
	// The JSON string adds two quotes.
	return strings.Repeat("a", a.size-2)
}

func TestClassifyRequestBodyCapGuard(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		size     int
		wantSent bool
	}{
		{name: "at cap", size: MaxRequestBodyBytes, wantSent: true},
		{name: "cap plus one", size: MaxRequestBodyBytes + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, reply(http.StatusOK, anthropicReply(RiskNone, CategoryOther)))
			c := newTestClient(t, ProviderAnthropic, srv.URL)
			c.api = sizedAPI{size: tt.size}

			_, err := c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})
			if tt.wantSent {
				if err != nil {
					t.Fatalf("Classify() error = %v, want nil", err)
				}
				if n := len(srv.lastRequest().Body); n != tt.size {
					t.Errorf("request body = %d bytes, want %d", n, tt.size)
				}
			} else if !errors.Is(err, errRequestTooLarge) || errors.Is(err, ErrProvider) {
				t.Errorf("Classify() error = %v, want errRequestTooLarge", err)
			}
			if got, want := srv.hits.Load() == 1, tt.wantSent; got != want {
				t.Errorf("request sent = %v, want %v", got, want)
			}
		})
	}
}

func TestClassifyDialHook(t *testing.T) {
	t.Parallel()
	for _, p := range bothProviders {
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, reply(http.StatusOK, validReply(p, RiskLow, CategoryDataExfiltration)))
			var (
				mu    sync.Mutex
				dials []string
			)
			c, err := New(Config{
				Provider: p,
				Model:    llmTestModel,
				BaseURL:  srv.URL,
				APIKey:   testSecret(),
				Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					mu.Lock()
					dials = append(dials, network+" "+addr)
					mu.Unlock()
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				},
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			t.Cleanup(c.CloseIdleConnections)

			if _, err := c.Classify(t.Context(), Input{ToolName: "t", Description: "d"}); err != nil {
				t.Fatalf("Classify() error = %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if want := []string{"tcp " + srv.Listener.Addr().String()}; !slices.Equal(dials, want) {
				t.Errorf("dials = %q, want %q", dials, want)
			}
		})
	}
}

func TestClassifyDialFailure(t *testing.T) {
	t.Parallel()
	const dialCanary = "DIALCANARY-blocked"
	for _, p := range bothProviders {
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, reply(http.StatusOK, validReply(p, RiskNone, CategoryOther)))
			var dials atomic.Int32
			c, err := New(Config{
				Provider: p,
				Model:    llmTestModel,
				BaseURL:  srv.URL,
				APIKey:   testSecret(),
				Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
					dials.Add(1)
					return nil, errors.New(dialCanary + " " + addr)
				},
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			_, err = c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})
			if !errors.Is(err, ErrTransport) || !errors.Is(err, ErrProvider) {
				t.Fatalf("Classify() error = %v, want ErrTransport", err)
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, ErrInvalidOutput) {
				t.Errorf("Classify() error = %v, want only ErrTransport", err)
			}
			if n := dials.Load(); n != 1 {
				t.Errorf("dials = %d, want 1 (no retry)", n)
			}
			if n := srv.hits.Load(); n != 0 {
				t.Errorf("server requests = %d, want 0", n)
			}
			assertNoLeak(t, err, dialCanary, srv.URL)
		})
	}
}

func TestClassifyParentContextEnds(t *testing.T) {
	t.Parallel()

	t.Run("canceled during the request", func(t *testing.T) {
		t.Parallel()
		started := make(chan struct{})
		var once sync.Once
		srv := startServer(t, func(_ http.ResponseWriter, r *http.Request) {
			once.Do(func() { close(started) })
			<-r.Context().Done()
		})
		c := newTestClient(t, ProviderOpenAI, srv.URL)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() {
			<-started
			cancel()
		}()

		_, err := c.Classify(ctx, Input{ToolName: "t", Description: "d"})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Classify() error = %v, want context.Canceled", err)
		}
		if errors.Is(err, ErrProvider) || errors.Is(err, ErrInvalidOutput) {
			t.Errorf("Classify() error = %v, want not ErrProvider or ErrInvalidOutput", err)
		}
		assertNoLeak(t, err, srv.URL)
	})

	tests := []struct {
		name    string
		ctx     func(context.Context) (context.Context, context.CancelFunc)
		wantErr error
	}{
		{
			name: "canceled before the call",
			ctx: func(parent context.Context) (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(parent)
				cancel()
				return ctx, cancel
			},
			wantErr: context.Canceled,
		},
		{
			name: "deadline passed before the call",
			ctx: func(parent context.Context) (context.Context, context.CancelFunc) {
				return context.WithDeadline(parent, time.Unix(0, 0))
			},
			wantErr: context.DeadlineExceeded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, reply(http.StatusOK, anthropicReply(RiskNone, CategoryOther)))
			c := newTestClient(t, ProviderAnthropic, srv.URL)
			ctx, cancel := tt.ctx(t.Context())
			defer cancel()

			_, err := c.Classify(ctx, Input{ToolName: "t", Description: "d"})
			if !errors.Is(err, tt.wantErr) || errors.Is(err, ErrProvider) {
				t.Errorf("Classify() error = %v, want %v and not ErrProvider", err, tt.wantErr)
			}
			if n := srv.hits.Load(); n != 0 {
				t.Errorf("server requests = %d, want 0", n)
			}
		})
	}
}

// timeoutError is a net.Error that reports a timeout.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout " + llmBodyCanary }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestTransportError checks the error mapping of transportError directly.
// requestTimeout is a constant (30 s), so the timeout of a real request is
// not tested end to end; the expired request context stands in for it.
func TestTransportError(t *testing.T) {
	t.Parallel()
	leakyURL := "http://127.0.0.1:1/v1/messages?" + llmTestKey
	urlErr := func(err error) error { return &url.Error{Op: "Post", URL: leakyURL, Err: err} }

	live := t.Context()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, cancelExpired := context.WithDeadline(t.Context(), time.Unix(0, 0))
	defer cancelExpired()

	tests := []struct {
		name     string
		parent   context.Context
		reqCtx   context.Context
		err      error
		wantText string
		wantIs   []error
		wantNot  []error
	}{
		{
			name:     "parent canceled",
			parent:   canceled,
			reqCtx:   canceled,
			err:      urlErr(context.Canceled),
			wantText: "LLM request stopped: context canceled",
			wantIs:   []error{context.Canceled},
			wantNot:  []error{ErrProvider},
		},
		{
			name:     "parent deadline",
			parent:   expired,
			reqCtx:   expired,
			err:      urlErr(context.DeadlineExceeded),
			wantText: "LLM request stopped: context deadline exceeded",
			wantIs:   []error{context.DeadlineExceeded},
			wantNot:  []error{ErrProvider},
		},
		{
			name:     "own timeout",
			parent:   live,
			reqCtx:   expired,
			err:      urlErr(context.DeadlineExceeded),
			wantText: "LLM provider request failed: network error: timed out after 30s",
			wantIs:   []error{ErrTransport, ErrProvider},
			wantNot:  []error{context.DeadlineExceeded},
		},
		{
			name:     "net timeout",
			parent:   live,
			reqCtx:   live,
			err:      urlErr(timeoutError{}),
			wantText: "LLM provider request failed: network error: timed out after 30s",
			wantIs:   []error{ErrTransport},
		},
		{
			name:     "proxy",
			parent:   live,
			reqCtx:   live,
			err:      urlErr(errProxy),
			wantText: "LLM provider request failed: network error: proxy setting from HTTP_PROXY or HTTPS_PROXY refused",
			wantIs:   []error{ErrTransport, errProxy},
		},
		{
			name:     "untrusted certificate",
			parent:   live,
			reqCtx:   live,
			err:      urlErr(&tls.CertificateVerificationError{Err: errors.New("x509: " + llmBodyCanary)}),
			wantText: "LLM provider request failed: network error: TLS certificate not trusted",
			wantIs:   []error{ErrTransport},
		},
		{
			name:     "other",
			parent:   live,
			reqCtx:   live,
			err:      urlErr(errors.New("dial tcp 127.0.0.1:1: connection refused " + llmBodyCanary)),
			wantText: "LLM provider request failed: network error",
			wantIs:   []error{ErrTransport},
		},
		{
			name:     "body read error",
			parent:   live,
			reqCtx:   live,
			err:      io.ErrUnexpectedEOF,
			wantText: "LLM provider request failed: network error",
			wantIs:   []error{ErrTransport},
			wantNot:  []error{io.ErrUnexpectedEOF},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := transportError(tt.parent, tt.reqCtx, tt.err)
			if err == nil {
				t.Fatal("transportError() = nil, want error")
			}
			if got := err.Error(); got != tt.wantText {
				t.Errorf("transportError() = %q, want %q", got, tt.wantText)
			}
			for _, want := range tt.wantIs {
				if !errors.Is(err, want) {
					t.Errorf("errors.Is(err, %v) = false, want true", want)
				}
			}
			for _, not := range tt.wantNot {
				if errors.Is(err, not) {
					t.Errorf("errors.Is(err, %v) = true, want false", not)
				}
			}
			var ue *url.Error
			if errors.As(err, &ue) {
				t.Errorf("transportError() wraps the *url.Error %v", ue)
			}
			assertNoLeak(t, err)
		})
	}
}

func TestClassifyConcurrent(t *testing.T) {
	t.Parallel()
	const calls = 16
	for _, p := range bothProviders {
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, reply(http.StatusOK, validReply(p, RiskHigh, CategoryConcealFromUser)))
			c := newTestClient(t, p, srv.URL)
			want := Verdict{Risk: RiskHigh, Category: CategoryConcealFromUser}

			var wg sync.WaitGroup
			for i := range calls {
				wg.Go(func() {
					v, err := c.Classify(t.Context(), Input{ToolName: fmt.Sprint("tool", i), Description: "d"})
					if err != nil || v != want {
						t.Errorf("Classify() = %+v, %v, want %+v, nil", v, err, want)
					}
				})
			}
			wg.Wait()
			if n := srv.hits.Load(); n != calls {
				t.Errorf("server requests = %d, want %d", n, calls)
			}
		})
	}
}

func TestClassifyUntrustedCertificate(t *testing.T) {
	t.Parallel()
	for _, p := range bothProviders {
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()
			var hits atomic.Int32
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				_, _ = io.WriteString(w, validReply(p, RiskNone, CategoryOther))
			}))
			// The failed handshake is expected: keep its log out of the
			// test output.
			srv.Config.ErrorLog = log.New(io.Discard, "", 0)
			srv.StartTLS()
			t.Cleanup(srv.Close)
			c := newTestClient(t, p, srv.URL)

			_, err := c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})
			if !errors.Is(err, ErrTransport) {
				t.Fatalf("Classify() error = %v, want ErrTransport", err)
			}
			if want := "LLM provider request failed: network error: TLS certificate not trusted"; err.Error() != want {
				t.Errorf("Classify() error = %q, want %q", err, want)
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("handler calls = %d, want 0", n)
			}
			assertNoLeak(t, err, srv.URL)
		})
	}
}

func TestClassifyNilClient(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]*Client{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := c.Classify(t.Context(), Input{ToolName: "t"})
			if !errors.Is(err, errNilClient) {
				t.Errorf("Classify() error = %v, want errNilClient", err)
			}
			c.CloseIdleConnections() // must not panic
		})
	}
}

func TestEncodeJSONNoHTMLEscape(t *testing.T) {
	t.Parallel()
	got, err := encodeJSON(map[string]string{"k": "<IMPORTANT>&</IMPORTANT>"})
	if err != nil {
		t.Fatalf("encodeJSON() error = %v", err)
	}
	if want := `{"k":"<IMPORTANT>&</IMPORTANT>"}`; string(got) != want {
		t.Errorf("encodeJSON() = %q, want %q", got, want)
	}
	if _, err := encodeJSON(func() {}); !errors.Is(err, errBuildRequest) {
		t.Errorf("encodeJSON(func) error = %v, want errBuildRequest", err)
	}
}

// fakeResolver answers every lookup with addrs and err, and records the
// lookups.
type fakeResolver struct {
	addrs []netip.Addr
	err   error

	mu       sync.Mutex
	lookups  []string
	networks []string
}

func (r *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups = append(r.lookups, host)
	r.networks = append(r.networks, network)
	return slices.Clone(r.addrs), r.err
}

// calls returns the hosts and networks of the lookups so far.
func (r *fakeResolver) calls() (hosts, networks []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.lookups), slices.Clone(r.networks)
}

// addrs parses each of ips as a netip.Addr.
func addrs(ips ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, netip.MustParseAddr(ip))
	}
	return out
}

// TestClassifyHTTPLoopbackOnly checks the dialer of an http base URL: the
// host must resolve to loopback addresses only, and the client dials those
// addresses, never the name. Otherwise no connection is opened, so the key
// never goes in clear text to another machine.
func TestClassifyHTTPLoopbackOnly(t *testing.T) {
	t.Parallel()
	const (
		nonLoopback = "192.0.2.10" // TEST-NET-1, never routed
		lookupLeak  = "lookup localhost on 10.0.0.53:53: no such host"
	)
	wantRefused := "LLM provider request failed: network error: host does not resolve to a loopback address"
	errNoLookup := errors.New("lookup not expected")

	tests := []struct {
		name string
		// host is the host of the base URL; the port of the server is added.
		host string
		// answer and lookupErr are the answer of the resolver for a name.
		answer    []netip.Addr
		lookupErr error
		// wantLookups is the hosts that the resolver must see.
		wantLookups []string
		// wantDials is the addresses that Config.Dial must see, without
		// the port. Nil means no dial and a refused request.
		wantDials []string
	}{
		{
			name:        "localhost resolves to IPv4 loopback",
			host:        "localhost",
			answer:      addrs("127.0.0.1"),
			wantLookups: []string{"localhost"},
			wantDials:   []string{"127.0.0.1"},
		},
		{
			// The test dialer refuses ::1, so the client tries the next
			// address.
			name:        "localhost resolves to IPv6 and IPv4 loopback",
			host:        "localhost",
			answer:      addrs("::1", "127.0.0.1"),
			wantLookups: []string{"localhost"},
			wantDials:   []string{"[::1]", "127.0.0.1"},
		},
		{
			name:      "IPv4 loopback literal",
			host:      "127.0.0.1",
			lookupErr: errNoLookup,
			wantDials: []string{"127.0.0.1"},
		},
		{
			name:      "IPv4-mapped loopback literal",
			host:      "[::ffff:127.0.0.1]",
			lookupErr: errNoLookup,
			wantDials: []string{"127.0.0.1"},
		},
		{
			name:        "localhost resolves to a non-loopback address",
			host:        "localhost",
			answer:      addrs(nonLoopback),
			wantLookups: []string{"localhost"},
		},
		{
			name:        "loopback and non-loopback answers",
			host:        "localhost",
			answer:      addrs("127.0.0.1", nonLoopback),
			wantLookups: []string{"localhost"},
		},
		{
			name:        "non-loopback answer first",
			host:        "localhost",
			answer:      addrs(nonLoopback, "::1"),
			wantLookups: []string{"localhost"},
		},
		{
			name:        "IPv4-mapped non-loopback answer",
			host:        "localhost",
			answer:      addrs("::ffff:" + nonLoopback),
			wantLookups: []string{"localhost"},
		},
		{
			name:        "unspecified address",
			host:        "localhost",
			answer:      addrs("0.0.0.0"),
			wantLookups: []string{"localhost"},
		},
		{
			name:        "no answer",
			host:        "localhost",
			wantLookups: []string{"localhost"},
		},
		{
			name:        "lookup error",
			host:        "localhost",
			lookupErr:   errors.New(lookupLeak + " " + llmBodyCanary),
			wantLookups: []string{"localhost"},
		},
	}
	for _, p := range bothProviders {
		for _, tt := range tests {
			t.Run(string(p)+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				r := &fakeResolver{addrs: tt.answer, err: tt.lookupErr}
				srv := startServer(t, reply(http.StatusOK, validReply(p, RiskLow, CategoryOther)))
				_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
				if err != nil {
					t.Fatalf("server address: %v", err)
				}
				var (
					mu    sync.Mutex
					dials []string
				)
				dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
					mu.Lock()
					dials = append(dials, addr)
					mu.Unlock()
					// The test server listens on IPv4 only.
					if strings.HasPrefix(addr, "[::1]") {
						return nil, errors.New("connection refused")
					}
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				}
				c, err := newClient(Config{
					Provider: p,
					Model:    llmTestModel,
					BaseURL:  "http://" + net.JoinHostPort(strings.Trim(tt.host, "[]"), port),
					APIKey:   testSecret(),
					Dial:     dial,
				}, r)
				if err != nil {
					t.Fatalf("newClient() error = %v", err)
				}
				t.Cleanup(c.CloseIdleConnections)

				v, err := c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})

				hosts, networks := r.calls()
				if !slices.Equal(hosts, tt.wantLookups) {
					t.Errorf("lookups = %q, want %q", hosts, tt.wantLookups)
				}
				for _, n := range networks {
					if n != "ip" {
						t.Errorf("lookup network = %q, want ip", n)
					}
				}
				mu.Lock()
				gotDials := slices.Clone(dials)
				mu.Unlock()

				if tt.wantDials == nil {
					if err == nil || err.Error() != wantRefused {
						t.Fatalf("Classify() = %+v, %v; want error %q", v, err, wantRefused)
					}
					if !errors.Is(err, ErrTransport) || !errors.Is(err, ErrProvider) {
						t.Errorf("Classify() error = %v, want ErrTransport", err)
					}
					if len(gotDials) != 0 {
						t.Errorf("dials = %q, want none", gotDials)
					}
					if n := srv.hits.Load(); n != 0 {
						t.Errorf("server requests = %d, want 0", n)
					}
					assertNoLeak(t, err, "localhost", nonLoopback, "::", "10.0.0.53", "no such host", port, srv.URL)
					return
				}

				if err != nil {
					t.Fatalf("Classify() error = %v", err)
				}
				if want := (Verdict{Risk: RiskLow, Category: CategoryOther}); v != want {
					t.Errorf("Classify() = %+v, want %+v", v, want)
				}
				wantDials := make([]string, len(tt.wantDials))
				for i, d := range tt.wantDials {
					wantDials[i] = d + ":" + port
				}
				if !slices.Equal(gotDials, wantDials) {
					t.Errorf("dials = %q, want %q", gotDials, wantDials)
				}
				if n := srv.hits.Load(); n != 1 {
					t.Errorf("server requests = %d, want 1", n)
				}
			})
		}
	}
}

// TestClassifyHTTPSNoLoopbackCheck checks that an https base URL does not use
// the loopback check: the resolver of the client is never asked. TLS
// protects the key on any network.
func TestClassifyHTTPSNoLoopbackCheck(t *testing.T) {
	t.Parallel()
	r := &fakeResolver{addrs: addrs("192.0.2.10")}
	c, err := newClient(Config{
		Provider: ProviderAnthropic,
		BaseURL:  "https://api.example.invalid",
		APIKey:   testSecret(),
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("blocked")
		},
	}, r)
	if err != nil {
		t.Fatalf("newClient() error = %v", err)
	}
	t.Cleanup(c.CloseIdleConnections)

	_, err = c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})
	if !errors.Is(err, ErrTransport) || errors.Is(err, errNotLoopback) {
		t.Errorf("Classify() error = %v, want ErrTransport and not errNotLoopback", err)
	}
	if hosts, _ := r.calls(); len(hosts) != 0 {
		t.Errorf("lookups = %q, want none", hosts)
	}
}

func TestLoopbackDialBadInput(t *testing.T) {
	t.Parallel()
	var dials atomic.Int32
	dial := loopbackDial(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("dial not expected")
	}, &fakeResolver{addrs: addrs("127.0.0.1")}, loopbackAddrTimeout)

	// An address without a port is refused before any lookup or dial.
	if _, err := dial(t.Context(), "tcp", "localhost"); !errors.Is(err, errNotLoopback) {
		t.Errorf("dial(no port) error = %v, want errNotLoopback", err)
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("dials = %d, want 0", n)
	}

	for network, want := range map[string]string{"tcp": "ip", "tcp4": "ip4", "tcp6": "ip6", "": "ip"} {
		if got := lookupNetwork(network); got != want {
			t.Errorf("lookupNetwork(%q) = %q, want %q", network, got, want)
		}
	}
}

// TestLoopbackDialAddrTimeout checks that an address that does not answer
// gets only the short timeout of one address, so the next address is tried
// long before the full dial timeout.
func TestLoopbackDialAddrTimeout(t *testing.T) {
	t.Parallel()
	// addrTimeout is small so that the test is fast. The client uses
	// loopbackAddrTimeout.
	const addrTimeout = 50 * time.Millisecond

	t.Run("first address does not answer", func(t *testing.T) {
		t.Parallel()
		// The parent context has the full dial timeout. If the first address
		// waited for it, the parent would end before the second dial.
		parent, cancel := context.WithTimeout(t.Context(), dialTimeout)
		defer cancel()
		parentDeadline, _ := parent.Deadline()
		var (
			mu        sync.Mutex
			dials     []string
			deadlines []time.Time
		)
		dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
			deadline, _ := ctx.Deadline()
			mu.Lock()
			dials = append(dials, addr)
			deadlines = append(deadlines, deadline)
			mu.Unlock()
			if strings.HasPrefix(addr, "[::1]") {
				// Like a firewall that drops the packets: wait until the
				// context ends.
				<-ctx.Done()
				return nil, ctx.Err()
			}
			client, server := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			return client, nil
		}
		d := loopbackDial(dial, &fakeResolver{addrs: addrs("::1", "127.0.0.1")}, addrTimeout)

		before := time.Now()
		conn, err := d(parent, "tcp", "localhost:11434")
		after := time.Now()
		if err != nil || conn == nil {
			t.Fatalf("dial() = %v, %v; want a connection", conn, err)
		}
		if parent.Err() != nil {
			t.Fatalf("parent context ended (%v): the first address used the full dial timeout", parent.Err())
		}
		mu.Lock()
		defer mu.Unlock()
		if want := []string{"[::1]:11434", "127.0.0.1:11434"}; !slices.Equal(dials, want) {
			t.Fatalf("dials = %q, want %q", dials, want)
		}
		// The first address had addrTimeout from the start of its dial.
		if first := deadlines[0]; first.Before(before.Add(addrTimeout)) || first.After(after.Add(addrTimeout)) {
			t.Errorf("first dial deadline = %v after the start, want %v", first.Sub(before), addrTimeout)
		}
		// The last address gets the time that is left of the parent.
		if last := deadlines[1]; !last.Equal(parentDeadline) {
			t.Errorf("last dial deadline = %v, want the parent deadline %v", last, parentDeadline)
		}
	})

	t.Run("caller gives up", func(t *testing.T) {
		t.Parallel()
		parent, cancel := context.WithCancel(t.Context())
		defer cancel()
		var dials atomic.Int32
		dial := func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			cancel()
			return nil, context.Canceled
		}
		d := loopbackDial(dial, &fakeResolver{addrs: addrs("::1", "127.0.0.1")}, addrTimeout)
		if _, err := d(parent, "tcp", "localhost:11434"); err == nil {
			t.Fatal("dial() error = nil, want an error")
		}
		if n := dials.Load(); n != 1 {
			t.Errorf("dials = %d, want 1 (no next address after the caller gave up)", n)
		}
	})

	t.Run("every address fails", func(t *testing.T) {
		t.Parallel()
		const dialCanary = "DIALCANARY-every"
		c, err := newClient(Config{
			Provider: ProviderAnthropic,
			BaseURL:  "http://localhost:11434",
			APIKey:   testSecret(),
			Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
				return nil, errors.New(dialCanary + " " + addr)
			},
		}, &fakeResolver{addrs: addrs("::1", "127.0.0.1")})
		if err != nil {
			t.Fatalf("newClient() error = %v", err)
		}
		t.Cleanup(c.CloseIdleConnections)
		_, err = c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})
		if err == nil || err.Error() != ErrTransport.Error() {
			t.Fatalf("Classify() error = %v, want %q", err, ErrTransport)
		}
		assertNoLeak(t, err, dialCanary, "::1", "11434", "localhost")
	})
}

// TestNewProxyOnlyForHTTPS checks the proxy setting of the transport: an
// http base URL (always a loopback host) never uses a proxy, and an https
// base URL uses the proxy settings of the environment.
func TestNewProxyOnlyForHTTPS(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		"http://127.0.0.1:8080":       false,
		"http://localhost:11434/v1":   false,
		"http://[::1%25lo0]:8080":     false,
		"https://api.example.invalid": true,
	}
	for base, wantProxy := range tests {
		t.Run(base, func(t *testing.T) {
			t.Parallel()
			c, err := New(Config{Provider: ProviderOpenAI, Model: llmTestModel, BaseURL: base, APIKey: testSecret()})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			tr, ok := c.http.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("transport type = %T, want *http.Transport", c.http.Transport)
			}
			if got := tr.Proxy != nil; got != wantProxy {
				t.Errorf("transport has a proxy func = %t, want %t", got, wantProxy)
			}
		})
	}
}

// proxyHelperEnv names the mode of TestProxyHelperProcess. Only
// TestClassifyProxySettings sets it, in a child process.
const proxyHelperEnv = "MCPMOAT_LLM_TEST_PROXY_HELPER"

// proxyCanary is the password in the proxy setting of the "cgi" mode.
const proxyCanary = "PROXYCANARY"

// proxyEnvNames are the variables that net/http reads for the proxy.
// REQUEST_METHOD is there because net/http ignores HTTP_PROXY when it is
// set (CGI).
var proxyEnvNames = []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "REQUEST_METHOD"}

// TestClassifyProxySettings runs TestProxyHelperProcess in a child process
// for each proxy setting. net/http reads the proxy variables only one time
// for each process, so t.Setenv cannot change them in this process. The child
// does not get the proxy variables of this process.
func TestClassifyProxySettings(t *testing.T) {
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}
	base := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(proxyEnvNames, strings.ToUpper(name))
	})
	// recorder is a real proxy address for the "httpnoproxy" mode. It must
	// get no connection.
	recorder := startProxyRecorder(t)
	recorderURL := "http://" + recorder.ln.Addr().String()
	tests := []struct {
		mode string
		env  []string
		// proxy, when it is not nil, must get no connection.
		proxy *proxyRecorder
	}{
		// net/http refuses HTTP_PROXY in a CGI process (REQUEST_METHOD set)
		// for every http URL, even a loopback one. The client uses no proxy
		// for http, so the request still goes to the loopback server.
		{mode: "cgi", env: []string{"REQUEST_METHOD=GET", "HTTP_PROXY=http://user:" + proxyCanary + "@proxy.test:3128"}},
		{mode: "proxy", env: []string{"HTTPS_PROXY=http://proxy.test:3128"}},
		{mode: "noproxy", env: []string{"HTTPS_PROXY=http://proxy.test:3128", "NO_PROXY=api.example.invalid"}},
		{mode: "loopback", env: []string{"HTTP_PROXY=http://proxy.test:3128", "HTTPS_PROXY=http://proxy.test:3128"}},
		// Over http the key is in clear text, so a request to an http base
		// URL never goes through a proxy, whatever the proxy variables say.
		{
			mode:  "httpnoproxy",
			env:   []string{"HTTP_PROXY=" + recorderURL, "http_proxy=" + recorderURL, "HTTPS_PROXY=" + recorderURL},
			proxy: recorder,
		},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			t.Parallel()
			cmd := exec.CommandContext(t.Context(), exe, "-test.run=^TestProxyHelperProcess$", "-test.v", "-test.count=1")
			cmd.Env = append(slices.Clone(base), append(tt.env, proxyHelperEnv+"="+tt.mode)...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("helper process error = %v, output:\n%s", err, out)
			}
			if !bytes.Contains(out, []byte("--- PASS: TestProxyHelperProcess")) {
				t.Fatalf("helper process did not pass, output:\n%s", out)
			}
			if tt.proxy != nil {
				if n := tt.proxy.connections(t); n != 0 {
					t.Errorf("proxy connections = %d, want 0", n)
				}
			}
		})
	}
}

// proxyRecorder is a TCP listener in place of a proxy. It closes each
// connection that it accepts and records its remote address.
type proxyRecorder struct {
	ln   net.Listener
	seen chan string
	done chan struct{}
}

// startProxyRecorder starts a proxyRecorder on a loopback port. The cleanup
// of t stops it.
func startProxyRecorder(t *testing.T) *proxyRecorder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &proxyRecorder{ln: ln, seen: make(chan string), done: make(chan struct{})}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // the listener is closed
			}
			remote := conn.RemoteAddr().String()
			_ = conn.Close()
			select {
			case p.seen <- remote:
			case <-p.done:
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(p.done)
		_ = ln.Close()
	})
	return p
}

// connections returns the number of connections that p accepted before this
// call. It opens one marker connection and counts the connections that come
// before it. The listener accepts connections in order, so no wait is
// needed.
func (p *proxyRecorder) connections(t *testing.T) int {
	t.Helper()
	marker, err := net.Dial("tcp", p.ln.Addr().String())
	if err != nil {
		t.Fatalf("dial the proxy recorder: %v", err)
	}
	defer func() { _ = marker.Close() }()
	want := marker.LocalAddr().String()
	n := 0
	for {
		if remote := <-p.seen; remote == want {
			return n
		}
		n++
	}
}

// TestProxyHelperProcess is the child process of TestClassifyProxySettings.
// It skips when proxyHelperEnv is not set.
func TestProxyHelperProcess(t *testing.T) {
	mode := os.Getenv(proxyHelperEnv)
	if mode == "" {
		t.Skip("helper process of TestClassifyProxySettings")
	}
	var (
		mu    sync.Mutex
		dials []string
	)
	record := func(addr string) {
		mu.Lock()
		defer mu.Unlock()
		dials = append(dials, addr)
	}
	dialed := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(dials)
	}
	blocked := func(_ context.Context, _, addr string) (net.Conn, error) {
		record(addr)
		return nil, errors.New("blocked")
	}
	direct := func(ctx context.Context, network, addr string) (net.Conn, error) {
		record(addr)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	classify := func(base string, dial func(context.Context, string, string) (net.Conn, error)) (Verdict, error) {
		c, err := New(Config{Provider: ProviderAnthropic, BaseURL: base, APIKey: testSecret(), Dial: dial})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		defer c.CloseIdleConnections()
		return c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})
	}

	switch mode {
	case "cgi":
		srv := startServer(t, reply(http.StatusOK, anthropicReply(RiskLow, CategoryOther)))
		_, err := classify(srv.URL, direct)
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil (no proxy for http)", err)
		}
		assertNoLeak(t, err, proxyCanary)
		if got, want := dialed(), []string{srv.Listener.Addr().String()}; !slices.Equal(got, want) {
			t.Errorf("dials = %q, want %q", got, want)
		}
		if n := srv.hits.Load(); n != 1 {
			t.Errorf("server requests = %d, want 1", n)
		}
	case "proxy", "noproxy":
		_, err := classify("https://api.example.invalid", blocked)
		if !errors.Is(err, ErrTransport) {
			t.Errorf("Classify() error = %v, want ErrTransport", err)
		}
		want := []string{"proxy.test:3128"}
		if mode == "noproxy" {
			want = []string{"api.example.invalid:443"}
		}
		if got := dialed(); !slices.Equal(got, want) {
			t.Errorf("dials = %q, want %q", got, want)
		}
	case "loopback":
		srv := startServer(t, reply(http.StatusOK, anthropicReply(RiskLow, CategoryOther)))
		if _, err := classify(srv.URL, direct); err != nil {
			t.Fatalf("Classify() error = %v", err)
		}
		if got, want := dialed(), []string{srv.Listener.Addr().String()}; !slices.Equal(got, want) {
			t.Errorf("dials = %q, want %q (loopback is never proxied)", got, want)
		}
	case "httpnoproxy":
		proxyAddr := strings.TrimPrefix(os.Getenv("HTTP_PROXY"), "http://")
		srv := startServer(t, reply(http.StatusOK, anthropicReply(RiskLow, CategoryOther)))
		srvAddr := srv.Listener.Addr().String()
		_, port, err := net.SplitHostPort(srvAddr)
		if err != nil {
			t.Fatalf("server address: %v", err)
		}
		// toServer dials an address with a zone at the test server, so the
		// test does not need IPv6. It dials every other address as it is,
		// so a request through the proxy would reach the proxy recorder.
		toServer := func(ctx context.Context, network, addr string) (net.Conn, error) {
			if host, _, err := net.SplitHostPort(addr); err == nil && strings.Contains(host, "%") {
				record(addr)
				var d net.Dialer
				return d.DialContext(ctx, network, srvAddr)
			}
			return direct(ctx, network, addr)
		}
		// ValidateBaseURL accepts "::1%lo0" as loopback. The client must
		// not send it through the proxy, whatever net/http thinks of a
		// zone.
		for _, base := range []string{srv.URL, "http://[::1%25lo0]:" + port} {
			if _, err := classify(base, toServer); err != nil {
				t.Errorf("Classify(%s) error = %v", base, err)
			}
		}
		if got := dialed(); slices.Contains(got, proxyAddr) {
			t.Errorf("dials = %q, want no dial to the proxy %s", got, proxyAddr)
		}
		if n := srv.hits.Load(); n != 2 {
			t.Errorf("server requests = %d, want 2", n)
		}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

// TestJSONNullAndAbsent checks the two helpers for a JSON value: jsonNull is
// true for a missing field and for null, and jsonAbsent also for an empty
// JSON string. White space around the value does not count.
func TestJSONNullAndAbsent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw        string
		wantNull   bool
		wantAbsent bool
	}{
		{raw: "", wantNull: true, wantAbsent: true},
		{raw: " \t\r\n", wantNull: true, wantAbsent: true},
		{raw: "null", wantNull: true, wantAbsent: true},
		{raw: " null\n", wantNull: true, wantAbsent: true},
		{raw: `""`, wantAbsent: true},
		{raw: ` "" `, wantAbsent: true},
		{raw: `"no"`},
		{raw: "{}"},
		{raw: "false"},
		{raw: "0"},
		{raw: `"null"`},
		{raw: "nul"},
	}
	for _, tt := range tests {
		raw := json.RawMessage(tt.raw)
		if got := jsonNull(raw); got != tt.wantNull {
			t.Errorf("jsonNull(%q) = %v, want %v", tt.raw, got, tt.wantNull)
		}
		if got := jsonAbsent(raw); got != tt.wantAbsent {
			t.Errorf("jsonAbsent(%q) = %v, want %v", tt.raw, got, tt.wantAbsent)
		}
	}
	if !jsonNull(nil) || !jsonAbsent(nil) {
		t.Error("jsonNull(nil) or jsonAbsent(nil) = false, want true")
	}
}
