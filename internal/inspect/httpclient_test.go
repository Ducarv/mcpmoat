package inspect

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// hcSecret is a fake header value. Tests assert that it never shows up in an
// error text.
const hcSecret = "VSECRET1"

// hcNew calls newHTTPClient with the common fields. The tests that need User or
// MaxTotal build the httpClientConfig themselves.
func hcNew(origin *url.URL, headers map[string]string, base http.RoundTripper, ua string, maxBody int64) (*http.Client, *requestRecorder, error) {
	return newHTTPClient(httpClientConfig{
		Origin:    origin,
		Headers:   headers,
		Base:      base,
		UserAgent: ua,
		MaxBody:   maxBody,
	})
}

// hcURL parses s or stops the test. It is for fixed test URLs.
func hcURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("url.Parse(%q) = %v", s, err)
	}
	return u
}

// hcResponse builds a response for req with the given status and body text.
// resp.Request is set, because http.Client needs it to resolve a Location.
func hcResponse(req *http.Request, status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// hcStub is a fake base RoundTripper. It records every request it gets, with a
// snapshot of the request headers, and answers with respond (a 200 with the
// body "ok" if respond is nil).
type hcStub struct {
	respond func(req *http.Request) *http.Response

	mu      sync.Mutex
	reqs    []*http.Request
	headers []http.Header
}

func (s *hcStub) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.reqs = append(s.reqs, req)
	s.headers = append(s.headers, req.Header.Clone())
	s.mu.Unlock()
	if s.respond != nil {
		return s.respond(req), nil
	}
	return hcResponse(req, http.StatusOK, "ok", nil), nil
}

// count returns the number of requests that the stub got.
func (s *hcStub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

// header returns the header snapshot of request i.
func (s *hcStub) header(i int) http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headers[i]
}

// hcRoundTripFunc turns a function into an http.RoundTripper.
type hcRoundTripFunc func(req *http.Request) (*http.Response, error)

func (f hcRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// hcBody is a request body that notes when it is closed.
type hcBody struct {
	r      io.Reader
	closed atomic.Bool
}

func (b *hcBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *hcBody) Close() error               { b.closed.Store(true); return nil }

func TestSameOrigin(t *testing.T) {
	t.Parallel()

	u := func(s string) *url.URL {
		parsed, err := url.Parse(s)
		if err != nil {
			t.Fatalf("url.Parse(%q) = %v", s, err)
		}
		return parsed
	}

	tests := []struct {
		name string
		a, b *url.URL
		want bool
	}{
		{name: "identical", a: u("http://example.com/x"), b: u("http://example.com/y"), want: true},
		{name: "scheme case", a: &url.URL{Scheme: "HTTP", Host: "example.com"}, b: u("http://example.com"), want: true},
		{name: "scheme case, both upper", a: &url.URL{Scheme: "HTTPS", Host: "example.com"}, b: &url.URL{Scheme: "Https", Host: "example.com"}, want: true},
		{name: "host case", a: u("http://EXAMPLE.com"), b: u("http://example.com"), want: true},
		{name: "http default port 80", a: u("http://h"), b: u("http://h:80"), want: true},
		{name: "http default port 80, reversed", a: u("http://h:80"), b: u("http://h"), want: true},
		{name: "https default port 443", a: u("https://h"), b: u("https://h:443"), want: true},
		{name: "https default port 443, reversed", a: u("https://h:443"), b: u("https://h"), want: true},
		{name: "http on 443 is not https", a: u("http://h:443"), b: u("https://h"), want: false},
		{name: "http on 443 vs https on 443", a: u("http://h:443"), b: u("https://h:443"), want: false},
		{name: "https on 80 is not http", a: u("https://h:80"), b: u("http://h"), want: false},
		{name: "different port", a: u("http://h:8080"), b: u("http://h:8081"), want: false},
		{name: "explicit port vs default", a: u("http://h:8080"), b: u("http://h"), want: false},
		{name: "different host", a: u("http://a.example.com"), b: u("http://b.example.com"), want: false},
		{name: "subdomain", a: u("http://sub.example.com"), b: u("http://example.com"), want: false},
		{name: "host suffix", a: u("http://example.com.evil.test"), b: u("http://example.com"), want: false},
		{name: "userinfo trick", a: u("http://example.com@evil.test/"), b: u("http://example.com"), want: false},
		{name: "same host, user info differs", a: u("http://user@example.com"), b: u("http://example.com"), want: true},
		{name: "trailing dot host", a: u("http://example.com."), b: u("http://example.com"), want: false},
		{name: "different scheme", a: u("http://h"), b: u("https://h"), want: false},
		{name: "scheme without default port", a: u("ftp://h"), b: u("ftp://h"), want: true},
		{name: "scheme without default port, different scheme", a: u("ftp://h"), b: u("http://h"), want: false},
		{name: "ipv6 same", a: u("http://[::1]:8080"), b: u("http://[::1]:8080"), want: true},
		{name: "ipv6 port differs", a: u("http://[::1]:8080"), b: u("http://[::1]:9090"), want: false},
		{name: "ipv6 default port", a: u("http://[::1]:80"), b: u("http://[::1]"), want: true},
		{name: "ipv6 explicit vs default", a: u("http://[::1]:8080"), b: u("http://[::1]"), want: false},
		{name: "ipv6 other address", a: u("http://[::1]:8080"), b: u("http://[::2]:8080"), want: false},
		{name: "ipv6 vs ipv4 loopback", a: u("http://[::1]:8080"), b: u("http://127.0.0.1:8080"), want: false},
		{name: "nil u", a: nil, b: u("http://h"), want: false},
		{name: "nil origin", a: u("http://h"), b: nil, want: false},
		{name: "both nil", a: nil, b: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sameOrigin(tt.a, tt.b); got != tt.want {
				t.Errorf("sameOrigin(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestNewHTTPClientHeaders(t *testing.T) {
	t.Parallel()

	const origin = "http://example.com:8080"

	t.Run("config headers are set with canonical keys", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{}
		client, _, err := hcNew(hcURL(t, origin), map[string]string{
			"x-api-key":     hcSecret,
			"AUTHORIZATION": "Bearer VSECRET2",
		}, stub, "mcpmoat", 0)
		if err != nil {
			t.Fatalf("hcNew() error = %v", err)
		}
		resp := hcGet(t, client, origin+"/mcp")
		_ = resp.Body.Close()

		if stub.count() != 1 {
			t.Fatalf("base got %d requests, want 1", stub.count())
		}
		got := stub.header(0)
		if v := got["X-Api-Key"]; !reflect.DeepEqual(v, []string{hcSecret}) {
			t.Errorf(`header["X-Api-Key"] = %q, want [%q]`, v, hcSecret)
		}
		if v := got["Authorization"]; !reflect.DeepEqual(v, []string{"Bearer VSECRET2"}) {
			t.Errorf(`header["Authorization"] = %q, want [Bearer VSECRET2]`, v)
		}
		for key := range got {
			if key != http.CanonicalHeaderKey(key) {
				t.Errorf("header key %q is not canonical", key)
			}
		}
	})

	t.Run("caller request is not modified", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{}
		client, _, err := hcNew(hcURL(t, origin), map[string]string{"X-Api-Key": hcSecret}, stub, "mcpmoat", 0)
		if err != nil {
			t.Fatalf("hcNew() error = %v", err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin+"/mcp", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Caller", "keep")
		before := req.Header.Clone()

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("client.Do() error = %v", err)
		}
		_ = resp.Body.Close()

		if !reflect.DeepEqual(req.Header, before) {
			t.Errorf("caller request header changed: got %v, want %v", req.Header, before)
		}
		if stub.count() != 1 {
			t.Fatalf("base got %d requests, want 1", stub.count())
		}
		seen := stub.reqs[0]
		if seen == req {
			t.Error("base got the caller's *http.Request, want a clone")
		}
		if got := stub.header(0).Get("X-Caller"); got != "keep" {
			t.Errorf("X-Caller on the sent request = %q, want %q", got, "keep")
		}
	})

	t.Run("config header wins over a caller header of the same name", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{}
		client, _, err := hcNew(hcURL(t, origin), map[string]string{"X-Api-Key": hcSecret}, stub, "mcpmoat", 0)
		if err != nil {
			t.Fatalf("hcNew() error = %v", err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Api-Key", "from-caller")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("client.Do() error = %v", err)
		}
		_ = resp.Body.Close()
		if got := stub.header(0)["X-Api-Key"]; !reflect.DeepEqual(got, []string{hcSecret}) {
			t.Errorf(`header["X-Api-Key"] = %q, want [%q]`, got, hcSecret)
		}
	})

	uaTests := []struct {
		name    string
		headers map[string]string
		ua      string
		want    string
	}{
		{name: "default when absent", headers: nil, ua: "mcpmoat", want: "mcpmoat"},
		{name: "given ua when absent", headers: map[string]string{"X-Other": "v"}, ua: "mcpmoat/9.9", want: "mcpmoat/9.9"},
		{name: "config wins, canonical", headers: map[string]string{"User-Agent": "custom/1"}, ua: "mcpmoat", want: "custom/1"},
		{name: "config wins, lower case", headers: map[string]string{"user-agent": "custom/2"}, ua: "mcpmoat", want: "custom/2"},
		{name: "config wins, upper case", headers: map[string]string{"USER-AGENT": "custom/3"}, ua: "mcpmoat", want: "custom/3"},
		{name: "config wins, mixed case", headers: map[string]string{"uSeR-aGeNt": "custom/4"}, ua: "mcpmoat", want: "custom/4"},
	}
	for _, tt := range uaTests {
		t.Run("user agent "+tt.name, func(t *testing.T) {
			t.Parallel()
			stub := &hcStub{}
			client, _, err := hcNew(hcURL(t, origin), tt.headers, stub, tt.ua, 0)
			if err != nil {
				t.Fatalf("hcNew() error = %v", err)
			}
			resp := hcGet(t, client, origin)
			_ = resp.Body.Close()
			got := stub.header(0)["User-Agent"]
			if !reflect.DeepEqual(got, []string{tt.want}) {
				t.Errorf(`header["User-Agent"] = %q, want [%q]`, got, tt.want)
			}
		})
	}

	t.Run("keys that differ only in case give a stable result", func(t *testing.T) {
		t.Parallel()
		// The keys are set in sorted order, so "X-Key" comes first and "x-key"
		// wins. The result must not depend on the map iteration order.
		for range 20 {
			stub := &hcStub{}
			client, _, err := hcNew(hcURL(t, origin), map[string]string{"x-key": "lower", "X-Key": "upper"}, stub, "mcpmoat", 0)
			if err != nil {
				t.Fatalf("hcNew() error = %v", err)
			}
			resp := hcGet(t, client, origin)
			_ = resp.Body.Close()
			if got := stub.header(0)["X-Key"]; !reflect.DeepEqual(got, []string{"lower"}) {
				t.Fatalf(`header["X-Key"] = %q, want ["lower"]`, got)
			}
		}
	})

	reserved := []string{
		"Content-Type", "Content-Length", "Accept", "Mcp-Session-Id",
		"Mcp-Protocol-Version", "Host", "Last-Event-Id", "Connection",
		"Transfer-Encoding", "Accept-Encoding", "Upgrade", "Expect", "Te", "Trailer",
		// Every name with the prefix "Mcp-".
		"Mcp-Custom", "mcp-custom", "MCP-CUSTOM", "Mcp-X", "mcp-", "Mcp-Session-Id-2",
		// Variants in other case.
		"content-type", "content-length", "accept", "mcp-session-id",
		"mcp-protocol-version", "host", "HOST", "MCP-SESSION-ID", "aCcEpT",
		"accept-encoding", "ACCEPT-ENCODING", "upgrade", "expect", "te", "TE",
		"trailer", "TRAILER",
		// A proxy credential must not go to the origin.
		"Proxy-Authorization", "proxy-authorization", "PROXY-AUTHORIZATION",
	}
	for _, key := range reserved {
		t.Run("reserved "+key, func(t *testing.T) {
			t.Parallel()
			client, rec, err := hcNew(hcURL(t, origin), map[string]string{
				"X-Fine": "ok",
				key:      hcSecret,
			}, &hcStub{}, "mcpmoat", 0)
			if err == nil {
				t.Fatal("hcNew() error = nil, want errReservedHeader")
			}
			if !errors.Is(err, errReservedHeader) {
				t.Errorf("errors.Is(err, errReservedHeader) = false; err = %v", err)
			}
			if client != nil || rec != nil {
				t.Errorf("hcNew() returned client=%v rec=%v with an error, want nil", client, rec)
			}
			text := err.Error()
			if !strings.Contains(text, key) {
				t.Errorf("error text %q does not hold the header key %q", text, key)
			}
			if strings.Contains(text, hcSecret) {
				t.Errorf("error text %q holds the header value", text)
			}
		})
	}

	allowed := []string{"X-Mcp-Thing", "Mcpfoo", "Accept-Language", "Authorization", "Cookie", "Tex"}
	for _, key := range allowed {
		t.Run("allowed "+key, func(t *testing.T) {
			t.Parallel()
			stub := &hcStub{}
			client, _, err := hcNew(hcURL(t, origin), map[string]string{key: hcSecret}, stub, "mcpmoat", 0)
			if err != nil {
				t.Fatalf("newHTTPClient() error = %v, want nil", err)
			}
			resp := hcGet(t, client, origin)
			_ = resp.Body.Close()
			got := stub.header(0)[http.CanonicalHeaderKey(key)]
			if !reflect.DeepEqual(got, []string{hcSecret}) {
				t.Errorf("header %q = %q, want [%q]", key, got, hcSecret)
			}
		})
	}

	t.Run("empty name refused", func(t *testing.T) {
		t.Parallel()
		_, _, err := hcNew(hcURL(t, origin), map[string]string{"": hcSecret}, &hcStub{}, "mcpmoat", 0)
		if !errors.Is(err, errReservedHeader) {
			t.Fatalf("hcNew() error = %v, want errReservedHeader", err)
		}
		if strings.Contains(err.Error(), hcSecret) {
			t.Errorf("error text %q holds the header value", err)
		}
	})

	t.Run("nil origin refused", func(t *testing.T) {
		t.Parallel()
		client, rec, err := hcNew(nil, nil, &hcStub{}, "mcpmoat", 0)
		if err == nil {
			t.Fatal("hcNew(nil origin) error = nil, want error")
		}
		if client != nil || rec != nil {
			t.Errorf("got client=%v rec=%v with an error, want nil", client, rec)
		}
	})
}

// hcGet sends a GET with client and stops the test on error. The caller closes
// the body.
func hcGet(t *testing.T, client *http.Client, rawURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	return resp
}

func TestOriginPin(t *testing.T) {
	t.Parallel()

	const origin = "http://example.com:8080"

	tests := []struct {
		name string
		url  string
	}{
		{name: "other host", url: "http://evil.test:8080/mcp"},
		{name: "subdomain", url: "http://sub.example.com:8080/mcp"},
		{name: "other port", url: "http://example.com:9090/mcp"},
		{name: "default port instead of the configured one", url: "http://example.com/mcp"},
		{name: "other scheme", url: "https://example.com:8080/mcp"},
		{name: "userinfo trick", url: "http://example.com:8080@evil.test/mcp"}, //nolint:gosec // G101: fake test credentials
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stub := &hcStub{}
			client, rec, err := hcNew(hcURL(t, origin), map[string]string{"X-Api-Key": hcSecret}, stub, "mcpmoat", 0)
			if err != nil {
				t.Fatalf("hcNew() error = %v", err)
			}

			body := &hcBody{r: strings.NewReader(`{"jsonrpc":"2.0"}`)}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tt.url, body)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("client.Do() error = nil, want errOtherOrigin")
			}
			if !errors.Is(err, errOtherOrigin) {
				t.Errorf("errors.Is(err, errOtherOrigin) = false; err = %v", err)
			}
			var urlErr *url.Error
			if !errors.As(err, &urlErr) {
				t.Errorf("error %T is not a *url.Error: client.Do wraps the RoundTrip error", err)
			}
			if stub.count() != 0 {
				t.Errorf("base got %d requests, want 0: nothing may go out to another origin", stub.count())
			}
			if !body.closed.Load() {
				t.Error("request body was not closed")
			}
			if rec.lastStatus() != 0 {
				t.Errorf("recorder status = %d, want 0", rec.lastStatus())
			}
			if strings.Contains(err.Error(), hcSecret) {
				t.Errorf("error text %q holds the header value", err)
			}
		})
	}

	t.Run("same origin is allowed", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{}
		client, _, err := hcNew(hcURL(t, origin), nil, stub, "mcpmoat", 0)
		if err != nil {
			t.Fatal(err)
		}
		// Host in other case.
		resp := hcGet(t, client, "http://EXAMPLE.com:8080/mcp")
		_ = resp.Body.Close()
		if stub.count() != 1 {
			t.Errorf("base got %d requests, want 1", stub.count())
		}
	})
}

func TestBodyCap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		maxBody  int64
		bodyLen  int
		wantLen  int // bytes that ReadAll returns
		wantLarg bool
	}{
		{name: "one byte over", maxBody: 10, bodyLen: 11, wantLen: 10, wantLarg: true},
		{name: "far over", maxBody: 10, bodyLen: 1000, wantLen: 10, wantLarg: true},
		{name: "exactly the cap", maxBody: 10, bodyLen: 10, wantLen: 10},
		{name: "under the cap", maxBody: 10, bodyLen: 3, wantLen: 3},
		{name: "empty body", maxBody: 10, bodyLen: 0, wantLen: 0},
		{name: "cap of one, exact", maxBody: 1, bodyLen: 1, wantLen: 1},
		{name: "cap of one, over", maxBody: 1, bodyLen: 2, wantLen: 1, wantLarg: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			payload := strings.Repeat("a", tt.bodyLen)
			stub := &hcStub{respond: func(req *http.Request) *http.Response {
				return hcResponse(req, http.StatusOK, payload, nil)
			}}
			client, _, err := hcNew(hcURL(t, "http://example.com"), nil, stub, "mcpmoat", tt.maxBody)
			if err != nil {
				t.Fatal(err)
			}
			resp := hcGet(t, client, "http://example.com/")
			defer func() { _ = resp.Body.Close() }()

			data, err := io.ReadAll(resp.Body)
			if tt.wantLarg {
				if !errors.Is(err, errBodyTooLarge) {
					t.Errorf("io.ReadAll() error = %v, want errBodyTooLarge", err)
				}
			} else if err != nil {
				t.Errorf("io.ReadAll() error = %v, want nil", err)
			}
			if len(data) != tt.wantLen {
				t.Errorf("io.ReadAll() returned %d bytes, want %d", len(data), tt.wantLen)
			}
			if int64(len(data)) > tt.maxBody {
				t.Errorf("io.ReadAll() returned %d bytes, more than the cap %d", len(data), tt.maxBody)
			}
		})
	}

	t.Run("error repeats on later reads", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			return hcResponse(req, http.StatusOK, strings.Repeat("a", 50), nil)
		}}
		client, _, err := hcNew(hcURL(t, "http://example.com"), nil, stub, "mcpmoat", 5)
		if err != nil {
			t.Fatal(err)
		}
		resp := hcGet(t, client, "http://example.com/")
		defer func() { _ = resp.Body.Close() }()
		if _, err := io.ReadAll(resp.Body); !errors.Is(err, errBodyTooLarge) {
			t.Fatalf("first io.ReadAll() error = %v, want errBodyTooLarge", err)
		}
		n, err := resp.Body.Read(make([]byte, 8))
		if n != 0 || !errors.Is(err, errBodyTooLarge) {
			t.Errorf("later Read() = (%d, %v), want (0, errBodyTooLarge)", n, err)
		}
	})

	t.Run("small reads count together", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			return hcResponse(req, http.StatusOK, "0123456789AB", nil) // 12 bytes
		}}
		client, _, err := hcNew(hcURL(t, "http://example.com"), nil, stub, "mcpmoat", 10)
		if err != nil {
			t.Fatal(err)
		}
		resp := hcGet(t, client, "http://example.com/")
		defer func() { _ = resp.Body.Close() }()
		var total int
		buf := make([]byte, 3)
		var readErr error
		for readErr == nil {
			var n int
			n, readErr = resp.Body.Read(buf)
			total += n
		}
		if !errors.Is(readErr, errBodyTooLarge) {
			t.Errorf("read error = %v, want errBodyTooLarge", readErr)
		}
		if total != 10 {
			t.Errorf("read %d bytes before the error, want 10", total)
		}
	})

	capTests := []struct {
		name    string
		maxBody int64
		want    int64
	}{
		{name: "zero uses the default", maxBody: 0, want: defaultMaxResponseBytes},
		{name: "negative uses the default", maxBody: -5, want: defaultMaxResponseBytes},
		{name: "positive is kept", maxBody: 123, want: 123},
	}
	for _, tt := range capTests {
		t.Run("cap value: "+tt.name, func(t *testing.T) {
			t.Parallel()
			client, _, err := hcNew(hcURL(t, "http://example.com"), nil, &hcStub{}, "mcpmoat", tt.maxBody)
			if err != nil {
				t.Fatal(err)
			}
			ht, ok := client.Transport.(*headerTransport)
			if !ok {
				t.Fatalf("client.Transport is %T, want *headerTransport", client.Transport)
			}
			if ht.maxBody != tt.want {
				t.Errorf("maxBody = %d, want %d", ht.maxBody, tt.want)
			}
		})
	}

	t.Run("default cap is 8 MiB", func(t *testing.T) {
		t.Parallel()
		if defaultMaxResponseBytes != 8<<20 {
			t.Errorf("defaultMaxResponseBytes = %d, want %d", defaultMaxResponseBytes, 8<<20)
		}
	})
}

// hcRecordResp is a response with only a status and a header, for tests that
// call recordResponse or isFollowedRedirect directly.
func hcRecordResp(status int, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header}
}

func TestStatusRecorder(t *testing.T) {
	t.Parallel()

	loc := http.Header{"Location": {"/next"}}

	t.Run("zero value", func(t *testing.T) {
		t.Parallel()
		var rec requestRecorder
		if got := rec.lastStatus(); got != 0 {
			t.Errorf("lastStatus() = %d, want 0", got)
		}
	})

	// recordResponse called directly: the latest response that is not a followed
	// redirect wins; a 2xx stores 0.
	direct := []struct {
		name string
		resp []*http.Response
		want int
	}{
		{name: "404 then 200", resp: []*http.Response{hcRecordResp(404, nil), hcRecordResp(200, nil)}, want: 0},
		{name: "200 then 401", resp: []*http.Response{hcRecordResp(200, nil), hcRecordResp(401, nil)}, want: 401},
		{name: "401 then 500: latest wins", resp: []*http.Response{hcRecordResp(401, nil), hcRecordResp(500, nil)}, want: 500},
		{name: "500 then 401: latest wins", resp: []*http.Response{hcRecordResp(500, nil), hcRecordResp(401, nil)}, want: 401},
		{name: "401 then 204 clears", resp: []*http.Response{hcRecordResp(401, nil), hcRecordResp(204, nil)}, want: 0},
		{name: "299 is 2xx", resp: []*http.Response{hcRecordResp(401, nil), hcRecordResp(299, nil)}, want: 0},
		{name: "300 is not 2xx", resp: []*http.Response{hcRecordResp(200, nil), hcRecordResp(300, nil)}, want: 300},
		{name: "199 is not 2xx", resp: []*http.Response{hcRecordResp(199, nil)}, want: 199},
		{name: "followed redirect keeps a failure", resp: []*http.Response{hcRecordResp(401, nil), hcRecordResp(302, loc)}, want: 401},
		{name: "followed redirect keeps a success", resp: []*http.Response{hcRecordResp(200, nil), hcRecordResp(307, loc)}, want: 0},
		{name: "redirect without Location is a failure", resp: []*http.Response{hcRecordResp(200, nil), hcRecordResp(302, nil)}, want: 302},
	}
	for _, tt := range direct {
		t.Run("direct: "+tt.name, func(t *testing.T) {
			t.Parallel()
			var rec requestRecorder
			for _, resp := range tt.resp {
				rec.recordResponse(resp)
			}
			if got := rec.lastStatus(); got != tt.want {
				t.Errorf("lastStatus() = %d, want %d", got, tt.want)
			}
		})
	}

	t.Run("concurrent records keep a recorded value", func(t *testing.T) {
		t.Parallel()
		var rec requestRecorder
		var wg sync.WaitGroup
		for i := range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rec.recordResponse(hcRecordResp(400+i, nil))
			}()
		}
		wg.Wait()
		if got := rec.lastStatus(); got < 400 || got >= 450 {
			t.Fatalf("lastStatus() = %d, want a value in [400, 450)", got)
		}
	})

	// Through the client, with a base that answers with a fixed list of
	// statuses, one per request.
	viaClient := []struct {
		name     string
		statuses []int
		header   http.Header
		want     int
	}{
		{name: "404 then 200", statuses: []int{404, 200}, want: 0},
		{name: "200 then 401", statuses: []int{200, 401}, want: 401},
		{name: "401 then 500", statuses: []int{401, 500}, want: 500},
		{name: "500 then 401", statuses: []int{500, 401}, want: 401},
		{name: "401 then 200", statuses: []int{401, 200}, want: 0},
		{name: "2xx only", statuses: []int{200, 202, 204}, want: 0},
		{name: "2xx then 404", statuses: []int{200, 404}, want: 404},
		{name: "3xx without Location is recorded", statuses: []int{307}, want: 307},
		{name: "304 with Location is recorded", statuses: []int{304}, header: http.Header{"Location": {"http://example.com/other"}}, want: 304},
		{name: "300 without Location is recorded", statuses: []int{300}, want: 300},
	}
	for _, tt := range viaClient {
		t.Run("via client: "+tt.name, func(t *testing.T) {
			t.Parallel()
			var n atomic.Int32
			stub := &hcStub{respond: func(req *http.Request) *http.Response {
				i := int(n.Add(1)) - 1
				return hcResponse(req, tt.statuses[i], "x", tt.header.Clone())
			}}
			client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, stub, "mcpmoat", 0)
			if err != nil {
				t.Fatal(err)
			}
			for range tt.statuses {
				resp := hcGet(t, client, "http://example.com/")
				_ = resp.Body.Close()
			}
			if got := rec.lastStatus(); got != tt.want {
				t.Errorf("lastStatus() = %d, want %d", got, tt.want)
			}
		})
	}

	// recordNoResponse: a request that gets no response clears an older status.
	t.Run("recordNoResponse clears the status", func(t *testing.T) {
		t.Parallel()
		var rec requestRecorder
		rec.recordResponse(hcRecordResp(404, nil))
		if got := rec.lastStatus(); got != 404 {
			t.Fatalf("lastStatus() = %d after a 404, want 404", got)
		}
		rec.recordNoResponse()
		if got := rec.lastStatus(); got != 0 {
			t.Errorf("lastStatus() = %d after recordNoResponse, want 0", got)
		}
	})

	t.Run("transport error after a 404 clears the status", func(t *testing.T) {
		t.Parallel()
		var n atomic.Int32
		base := hcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if n.Add(1) == 1 {
				return hcResponse(req, http.StatusNotFound, "nope", nil), nil
			}
			return nil, errors.New("boom")
		})
		client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, base, "mcpmoat", 0)
		if err != nil {
			t.Fatal(err)
		}
		resp := hcGet(t, client, "http://example.com/")
		_ = resp.Body.Close()
		if got := rec.lastStatus(); got != 404 {
			t.Fatalf("lastStatus() = %d after the 404, want 404", got)
		}

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err = client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Fatal("client.Do() error = nil, want the transport error")
		}
		if got := rec.lastStatus(); got != 0 {
			t.Errorf("lastStatus() = %d after a transport error, want 0", got)
		}
	})

	t.Run("classify: transport error after a 404 is a network error", func(t *testing.T) {
		t.Parallel()
		var n atomic.Int32
		base := hcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if n.Add(1) == 1 {
				return hcResponse(req, http.StatusNotFound, "nope", nil), nil
			}
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
		})
		client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, base, "mcpmoat", 0)
		if err != nil {
			t.Fatal(err)
		}
		resp := hcGet(t, client, "http://example.com/")
		_ = resp.Body.Close()

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, doErr := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if doErr == nil {
			t.Fatal("client.Do() error = nil, want the transport error")
		}

		srv := discover.Server{
			Name:      "remote",
			Transport: discover.TransportHTTP,
			URL:       discover.NewURL("http://example.com/"),
		}
		ce := classify(doErr, srv, rec, nil)
		if ce.Kind != KindNetwork {
			t.Errorf("Kind = %q, want %q (error: %v)", ce.Kind, KindNetwork, ce)
		}
		if ce.Status != 0 {
			t.Errorf("Status = %d, want 0", ce.Status)
		}
		if strings.Contains(ce.Reason, "404") {
			t.Errorf("Reason = %q, want no stale 404", ce.Reason)
		}
	})

	t.Run("followed redirect is not recorded", func(t *testing.T) {
		t.Parallel()
		// The first response is a 307 with a Location on the same origin: the
		// client follows it, and the second response is a 200.
		var n atomic.Int32
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			if n.Add(1) == 1 {
				return hcResponse(req, http.StatusTemporaryRedirect, "", http.Header{"Location": {"/next"}})
			}
			return hcResponse(req, http.StatusOK, "ok", nil)
		}}
		client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, stub, "mcpmoat", 0)
		if err != nil {
			t.Fatal(err)
		}
		resp := hcGet(t, client, "http://example.com/start")
		_ = resp.Body.Close()
		if stub.count() != 2 {
			t.Fatalf("base got %d requests, want 2", stub.count())
		}
		if got := rec.lastStatus(); got != 0 {
			t.Errorf("lastStatus() = %d, want 0: a followed redirect is not a failure", got)
		}
	})

	refused := []struct {
		name string
		prev int // status of an earlier request, 0 for none
	}{
		{name: "refused redirect is not recorded either", prev: 0},
		{name: "refused redirect keeps an earlier failure", prev: 401},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var n atomic.Int32
			stub := &hcStub{respond: func(req *http.Request) *http.Response {
				if tt.prev != 0 && n.Add(1) == 1 {
					return hcResponse(req, tt.prev, "", nil)
				}
				return hcResponse(req, http.StatusFound, "", http.Header{"Location": {"http://evil.test/"}})
			}}
			client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, stub, "mcpmoat", 0)
			if err != nil {
				t.Fatal(err)
			}
			if tt.prev != 0 {
				resp := hcGet(t, client, "http://example.com/")
				_ = resp.Body.Close()
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !errors.Is(err, errCrossOriginRedirect) {
				t.Fatalf("client.Do() error = %v, want errCrossOriginRedirect", err)
			}
			if got := rec.lastStatus(); got != tt.prev {
				t.Errorf("lastStatus() = %d, want %d", got, tt.prev)
			}
			wantReqs := 1
			if tt.prev != 0 {
				wantReqs = 2
			}
			if stub.count() != wantReqs {
				t.Errorf("base got %d requests, want %d: the redirect target must not be requested", stub.count(), wantReqs)
			}
		})
	}
}

func TestRequestRecorder(t *testing.T) {
	t.Parallel()

	t.Run("zero value has no blocked error", func(t *testing.T) {
		t.Parallel()
		var rec requestRecorder
		if err := rec.blockedErr(); err != nil {
			t.Errorf("blockedErr() = %v, want nil", err)
		}
	})

	t.Run("recordBlocked returns its argument", func(t *testing.T) {
		t.Parallel()
		var rec requestRecorder
		if got := rec.recordBlocked(errOtherOrigin); got != errOtherOrigin { //nolint:errorlint // identity check: recordBlocked must return its argument unchanged
			t.Errorf("recordBlocked() = %v, want errOtherOrigin", got)
		}
		// A later call returns its own argument, not the stored error.
		if got := rec.recordBlocked(errBodyTooLarge); got != errBodyTooLarge { //nolint:errorlint // identity check: recordBlocked must return its argument unchanged
			t.Errorf("recordBlocked() = %v, want errBodyTooLarge", got)
		}
	})

	t.Run("first recorded error wins", func(t *testing.T) {
		t.Parallel()
		var rec requestRecorder
		_ = rec.recordBlocked(errCrossOriginRedirect)
		_ = rec.recordBlocked(errTooManyRedirects)
		_ = rec.recordBlocked(errBodyTooLarge)
		if got := rec.blockedErr(); got != errCrossOriginRedirect { //nolint:errorlint // identity check: the first recorded error must be returned unchanged
			t.Errorf("blockedErr() = %v, want errCrossOriginRedirect", got)
		}
	})

	t.Run("status and blocked are independent", func(t *testing.T) {
		t.Parallel()
		var rec requestRecorder
		rec.recordResponse(hcRecordResp(401, nil))
		if err := rec.blockedErr(); err != nil {
			t.Errorf("blockedErr() = %v after a 401, want nil", err)
		}
		_ = rec.recordBlocked(errOtherOrigin)
		if got := rec.lastStatus(); got != 401 {
			t.Errorf("lastStatus() = %d after recordBlocked, want 401", got)
		}
	})

	t.Run("concurrent recordBlocked keeps one error", func(t *testing.T) {
		t.Parallel()
		var rec requestRecorder
		errs := []error{errOtherOrigin, errCrossOriginRedirect, errTooManyRedirects, errBodyTooLarge}
		var wg sync.WaitGroup
		for _, e := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = rec.recordBlocked(e)
			}()
		}
		wg.Wait()
		got := rec.blockedErr()
		if !slices.Contains(errs, got) {
			t.Fatalf("blockedErr() = %v, want one of the recorded errors", got)
		}
		_ = rec.recordBlocked(errors.New("later"))
		if rec.blockedErr() != got { //nolint:errorlint // identity check: the stored error must not change
			t.Errorf("blockedErr() changed after a later record")
		}
	})

	const origin = "http://example.com"

	// Each case runs an action on a client and then checks blockedErr.
	cases := []struct {
		name     string
		maxBody  int64
		maxTotal int64
		respond  func(n int, req *http.Request) *http.Response
		act      func(t *testing.T, client *http.Client)
		want     error   // nil means blockedErr must be nil
		others   []error // sentinels that must not match
	}{
		{
			name: "other origin",
			act: func(t *testing.T, client *http.Client) {
				hcMustFail(t, client, "http://evil.test/", errOtherOrigin)
			},
			want:   errOtherOrigin,
			others: []error{errCrossOriginRedirect, errTooManyRedirects, errBodyTooLarge},
		},
		{
			name: "cross-origin redirect",
			respond: func(_ int, req *http.Request) *http.Response {
				return hcResponse(req, 302, "", http.Header{"Location": {"http://evil.test/"}})
			},
			act: func(t *testing.T, client *http.Client) {
				hcMustFail(t, client, origin+"/", errCrossOriginRedirect)
			},
			want:   errCrossOriginRedirect,
			others: []error{errOtherOrigin, errTooManyRedirects, errBodyTooLarge},
		},
		{
			name: "too many redirects",
			respond: func(_ int, req *http.Request) *http.Response {
				return hcResponse(req, 302, "", http.Header{"Location": {"/next"}})
			},
			act: func(t *testing.T, client *http.Client) {
				hcMustFail(t, client, origin+"/", errTooManyRedirects)
			},
			want:   errTooManyRedirects,
			others: []error{errOtherOrigin, errCrossOriginRedirect, errBodyTooLarge},
		},
		{
			name:    "body cap",
			maxBody: 4,
			respond: func(_ int, req *http.Request) *http.Response {
				return hcResponse(req, 200, "0123456789", nil)
			},
			act: func(t *testing.T, client *http.Client) {
				hcReadAll(t, client, origin+"/", errBodyTooLarge)
			},
			want:   errBodyTooLarge,
			others: []error{errOtherOrigin, errCrossOriginRedirect, errTooManyRedirects},
		},
		{
			name:     "total budget",
			maxBody:  10,
			maxTotal: 12,
			respond: func(_ int, req *http.Request) *http.Response {
				return hcResponse(req, 200, "01234567", nil)
			},
			act: func(t *testing.T, client *http.Client) {
				hcReadAll(t, client, origin+"/", nil)
				hcReadAll(t, client, origin+"/", errBodyTooLarge)
			},
			want:   errBodyTooLarge,
			others: []error{errOtherOrigin, errCrossOriginRedirect, errTooManyRedirects},
		},
		{
			name:    "first wins: origin before body cap",
			maxBody: 4,
			respond: func(_ int, req *http.Request) *http.Response {
				return hcResponse(req, 200, "0123456789", nil)
			},
			act: func(t *testing.T, client *http.Client) {
				hcMustFail(t, client, "http://evil.test/", errOtherOrigin)
				hcReadAll(t, client, origin+"/", errBodyTooLarge)
			},
			want:   errOtherOrigin,
			others: []error{errBodyTooLarge},
		},
		{
			name:    "first wins: body cap before origin",
			maxBody: 4,
			respond: func(_ int, req *http.Request) *http.Response {
				return hcResponse(req, 200, "0123456789", nil)
			},
			act: func(t *testing.T, client *http.Client) {
				hcReadAll(t, client, origin+"/", errBodyTooLarge)
				hcMustFail(t, client, "http://evil.test/", errOtherOrigin)
			},
			want:   errBodyTooLarge,
			others: []error{errOtherOrigin},
		},
		{
			name: "nothing blocked: 200",
			act: func(t *testing.T, client *http.Client) {
				hcReadAll(t, client, origin+"/", nil)
			},
		},
		{
			name: "nothing blocked: 404 and 500 are not blocked errors",
			respond: func(n int, req *http.Request) *http.Response {
				return hcResponse(req, 404+n*96, "nope", nil) // 404, then 500
			},
			act: func(t *testing.T, client *http.Client) {
				hcReadAll(t, client, origin+"/", nil)
				hcReadAll(t, client, origin+"/", nil)
			},
		},
		{
			name: "nothing blocked: followed redirect",
			respond: func(n int, req *http.Request) *http.Response {
				if n == 0 {
					return hcResponse(req, 302, "", http.Header{"Location": {"/next"}})
				}
				return hcResponse(req, 200, "ok", nil)
			},
			act: func(t *testing.T, client *http.Client) {
				hcReadAll(t, client, origin+"/", nil)
			},
		},
		{
			name:    "nothing blocked: body exactly at the cap",
			maxBody: 5,
			respond: func(_ int, req *http.Request) *http.Response {
				return hcResponse(req, 200, "01234", nil)
			},
			act: func(t *testing.T, client *http.Client) {
				hcReadAll(t, client, origin+"/", nil)
			},
		},
	}
	for _, tt := range cases {
		t.Run("blockedErr: "+tt.name, func(t *testing.T) {
			t.Parallel()
			var n atomic.Int32
			stub := &hcStub{respond: func(req *http.Request) *http.Response {
				i := int(n.Add(1)) - 1
				if tt.respond == nil {
					return hcResponse(req, 200, "ok", nil)
				}
				return tt.respond(i, req)
			}}
			client, rec, err := newHTTPClient(httpClientConfig{
				Origin:    hcURL(t, origin),
				Base:      stub,
				UserAgent: "mcpmoat",
				MaxBody:   tt.maxBody,
				MaxTotal:  tt.maxTotal,
			})
			if err != nil {
				t.Fatal(err)
			}
			tt.act(t, client)

			got := rec.blockedErr()
			if tt.want == nil {
				if got != nil {
					t.Fatalf("blockedErr() = %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, tt.want) {
				t.Fatalf("blockedErr() = %v, want %v", got, tt.want)
			}
			for _, other := range tt.others {
				if errors.Is(got, other) {
					t.Errorf("blockedErr() = %v also matches %v", got, other)
				}
			}
		})
	}
}

// hcMustFail sends a GET and expects an error that wraps want.
func hcMustFail(t *testing.T, client *http.Client, rawURL string, want error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, want) {
		t.Fatalf("GET %s: error = %v, want %v", rawURL, err, want)
	}
}

// hcReadAll sends a GET and reads the whole body. want is the expected read
// error (nil for none) and the returned bytes are those that ReadAll got.
func hcReadAll(t *testing.T, client *http.Client, rawURL string, want error) []byte {
	t.Helper()
	resp := hcGet(t, client, rawURL)
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if want == nil {
		if err != nil {
			t.Fatalf("read body of %s: error = %v, want nil", rawURL, err)
		}
		return data
	}
	if !errors.Is(err, want) {
		t.Fatalf("read body of %s: error = %v, want %v", rawURL, err, want)
	}
	return data
}

func TestBudgetTotal(t *testing.T) {
	t.Parallel()

	const origin = "http://example.com"

	t.Run("two bodies under the body cap but over the total", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			return hcResponse(req, 200, "01234567", nil) // 8 bytes
		}}
		client, rec, err := newHTTPClient(httpClientConfig{
			Origin: hcURL(t, origin), Base: stub, UserAgent: "mcpmoat", MaxBody: 10, MaxTotal: 12,
		})
		if err != nil {
			t.Fatal(err)
		}
		first := hcReadAll(t, client, origin+"/", nil)
		if len(first) != 8 {
			t.Errorf("first body: %d bytes, want 8", len(first))
		}
		if err := rec.blockedErr(); err != nil {
			t.Fatalf("blockedErr() = %v after the first body, want nil", err)
		}
		second := hcReadAll(t, client, origin+"/", errBodyTooLarge)
		// 12 - 8 = 4 bytes of budget are left for the second body.
		if len(second) != 4 {
			t.Errorf("second body: %d bytes, want 4 (the rest of the budget)", len(second))
		}
		if !errors.Is(rec.blockedErr(), errBodyTooLarge) {
			t.Errorf("blockedErr() = %v, want errBodyTooLarge", rec.blockedErr())
		}
		// The budget is spent: a third body fails at once, with no bytes.
		third := hcReadAll(t, client, origin+"/", errBodyTooLarge)
		if len(third) != 0 {
			t.Errorf("third body: %d bytes, want 0", len(third))
		}
	})

	t.Run("bodies that fill the budget exactly are allowed", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			return hcResponse(req, 200, "0123456", nil) // 7 bytes
		}}
		client, rec, err := newHTTPClient(httpClientConfig{
			Origin: hcURL(t, origin), Base: stub, UserAgent: "mcpmoat", MaxBody: 7, MaxTotal: 14,
		})
		if err != nil {
			t.Fatal(err)
		}
		hcReadAll(t, client, origin+"/", nil)
		hcReadAll(t, client, origin+"/", nil)
		if err := rec.blockedErr(); err != nil {
			t.Errorf("blockedErr() = %v, want nil: 14 of 14 bytes is within the budget", err)
		}
		// One more byte is over.
		hcReadAll(t, client, origin+"/", errBodyTooLarge)
	})

	t.Run("body cap and total budget are separate", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			return hcResponse(req, 200, "0123456789", nil) // 10 bytes
		}}
		client, _, err := newHTTPClient(httpClientConfig{
			Origin: hcURL(t, origin), Base: stub, UserAgent: "mcpmoat", MaxBody: 5, MaxTotal: 1000,
		})
		if err != nil {
			t.Fatal(err)
		}
		got := hcReadAll(t, client, origin+"/", errBodyTooLarge)
		if len(got) != 5 {
			t.Errorf("body: %d bytes, want 5 (the per-body cap)", len(got))
		}
	})

	t.Run("bodies read in parallel share one budget", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			return hcResponse(req, 200, strings.Repeat("a", 100), nil)
		}}
		client, rec, err := newHTTPClient(httpClientConfig{
			Origin: hcURL(t, origin), Base: stub, UserAgent: "mcpmoat", MaxBody: 100, MaxTotal: 500,
		})
		if err != nil {
			t.Fatal(err)
		}
		var total atomic.Int64
		var wg sync.WaitGroup
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get(origin + "/")
				if err != nil {
					t.Errorf("client.Get() error = %v", err)
					return
				}
				defer func() { _ = resp.Body.Close() }()
				data, _ := io.ReadAll(resp.Body)
				total.Add(int64(len(data)))
			}()
		}
		wg.Wait()
		if got := total.Load(); got != 500 {
			t.Errorf("bodies handed out %d bytes together, want exactly the budget of 500", got)
		}
		if !errors.Is(rec.blockedErr(), errBodyTooLarge) {
			t.Errorf("blockedErr() = %v, want errBodyTooLarge", rec.blockedErr())
		}
	})

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		if defaultMaxResponseBytes != 8<<20 {
			t.Errorf("defaultMaxResponseBytes = %d, want %d", defaultMaxResponseBytes, 8<<20)
		}
		if defaultMaxTotalBytes != 64<<20 {
			t.Errorf("defaultMaxTotalBytes = %d, want %d", defaultMaxTotalBytes, 64<<20)
		}
		tests := []struct {
			name      string
			maxBody   int64
			maxTotal  int64
			wantBody  int64
			wantTotal int64
		}{
			{name: "zero values", wantBody: defaultMaxResponseBytes, wantTotal: defaultMaxTotalBytes},
			{name: "negative values", maxBody: -1, maxTotal: -7, wantBody: defaultMaxResponseBytes, wantTotal: defaultMaxTotalBytes},
			{name: "only total default", maxBody: 11, wantBody: 11, wantTotal: defaultMaxTotalBytes},
			// The default body cap (8 MiB) is clamped to a small total.
			{name: "only body default", maxTotal: 22, wantBody: 22, wantTotal: 22},
			{name: "both given", maxBody: 11, maxTotal: 22, wantBody: 11, wantTotal: 22},
			{name: "body equals total", maxBody: 22, maxTotal: 22, wantBody: 22, wantTotal: 22},
			{name: "body above total is clamped to total", maxBody: 100, maxTotal: 22, wantBody: 22, wantTotal: 22},
			{name: "body above default total is clamped to it", maxBody: defaultMaxTotalBytes + 1, wantBody: defaultMaxTotalBytes, wantTotal: defaultMaxTotalBytes},
			{name: "total at MaxInt64 is clamped", maxBody: 11, maxTotal: math.MaxInt64, wantBody: 11, wantTotal: math.MaxInt64 - 1},
			{name: "total at MaxInt64-1 is kept", maxBody: 11, maxTotal: math.MaxInt64 - 1, wantBody: 11, wantTotal: math.MaxInt64 - 1},
			{name: "body and total at MaxInt64", maxBody: math.MaxInt64, maxTotal: math.MaxInt64, wantBody: math.MaxInt64 - 1, wantTotal: math.MaxInt64 - 1},
			{name: "body at MaxInt64, default total", maxBody: math.MaxInt64, wantBody: defaultMaxTotalBytes, wantTotal: defaultMaxTotalBytes},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				client, _, err := newHTTPClient(httpClientConfig{
					Origin: hcURL(t, origin), Base: &hcStub{}, UserAgent: "mcpmoat",
					MaxBody: tt.maxBody, MaxTotal: tt.maxTotal,
				})
				if err != nil {
					t.Fatal(err)
				}
				ht, ok := client.Transport.(*headerTransport)
				if !ok {
					t.Fatalf("client.Transport is %T, want *headerTransport", client.Transport)
				}
				if ht.maxBody != tt.wantBody {
					t.Errorf("maxBody = %d, want %d", ht.maxBody, tt.wantBody)
				}
				if ht.maxTotal != tt.wantTotal {
					t.Errorf("maxTotal = %d, want %d", ht.maxTotal, tt.wantTotal)
				}
			})
		}
	})
}

// TestBudgetHugeLimits checks that limits near math.MaxInt64 are safe. The body
// reader asks for remaining+1 bytes, which would overflow and panic without
// the clamp in newHTTPClient.
func TestBudgetHugeLimits(t *testing.T) {
	t.Parallel()

	const origin = "http://example.com"

	tests := []struct {
		name     string
		maxBody  int64
		maxTotal int64
	}{
		{name: "both at MaxInt64", maxBody: math.MaxInt64, maxTotal: math.MaxInt64},
		{name: "both at MaxInt64-1", maxBody: math.MaxInt64 - 1, maxTotal: math.MaxInt64 - 1},
		{name: "only total at MaxInt64", maxBody: 16, maxTotal: math.MaxInt64},
		{name: "only body at MaxInt64", maxBody: math.MaxInt64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stub := &hcStub{respond: func(req *http.Request) *http.Response {
				return hcResponse(req, 200, "small body", nil)
			}}
			client, rec, err := newHTTPClient(httpClientConfig{
				Origin: hcURL(t, origin), Base: stub, UserAgent: "mcpmoat",
				MaxBody: tt.maxBody, MaxTotal: tt.maxTotal,
			})
			if err != nil {
				t.Fatal(err)
			}
			ht, ok := client.Transport.(*headerTransport)
			if !ok {
				t.Fatalf("client.Transport is %T, want *headerTransport", client.Transport)
			}
			if ht.maxTotal > math.MaxInt64-1 {
				t.Errorf("maxTotal = %d, want at most %d", ht.maxTotal, int64(math.MaxInt64-1))
			}
			if ht.maxBody > ht.maxTotal {
				t.Errorf("maxBody = %d is above maxTotal = %d", ht.maxBody, ht.maxTotal)
			}
			// Two reads: the second one runs with a used counter above 0.
			for i := range 2 {
				got := hcReadAll(t, client, origin+"/", nil)
				if string(got) != "small body" {
					t.Errorf("read %d: body = %q, want %q", i, got, "small body")
				}
			}
			if err := rec.blockedErr(); err != nil {
				t.Errorf("blockedErr() = %v, want nil", err)
			}
		})
	}

	t.Run("body above total is cut at the total", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			return hcResponse(req, 200, "0123456789", nil) // 10 bytes
		}}
		client, rec, err := newHTTPClient(httpClientConfig{
			Origin: hcURL(t, origin), Base: stub, UserAgent: "mcpmoat", MaxBody: 1000, MaxTotal: 4,
		})
		if err != nil {
			t.Fatal(err)
		}
		got := hcReadAll(t, client, origin+"/", errBodyTooLarge)
		if string(got) != "0123" {
			t.Errorf("body = %q, want %q (the total budget)", got, "0123")
		}
		if !errors.Is(rec.blockedErr(), errBodyTooLarge) {
			t.Errorf("blockedErr() = %v, want errBodyTooLarge", rec.blockedErr())
		}
	})
}

func TestBasicAuth(t *testing.T) {
	t.Parallel()

	const origin = "http://example.com"
	const pass = "PWSECRET9"

	send := func(t *testing.T, cfg httpClientConfig, rawURL string) *hcStub {
		t.Helper()
		stub := &hcStub{}
		cfg.Origin = hcURL(t, origin)
		cfg.Base = stub
		cfg.UserAgent = "mcpmoat"
		client, _, err := newHTTPClient(cfg)
		if err != nil {
			t.Fatalf("newHTTPClient() error = %v", err)
		}
		resp := hcGet(t, client, rawURL)
		_ = resp.Body.Close()
		return stub
	}

	tests := []struct {
		name    string
		user    *url.Userinfo
		headers map[string]string
		want    []string // wanted Authorization values; nil for none
	}{
		{name: "user and password", user: url.UserPassword("u", "p"), want: []string{"Basic dTpw"}},
		{name: "user without password", user: url.User("u"), want: []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("u:"))}},
		{name: "colon and space in the values", user: url.UserPassword("us er", "p:w"), want: []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("us er:p:w"))}},
		{name: "config header wins", user: url.UserPassword("u", "p"), headers: map[string]string{"Authorization": "Bearer VTOKEN"}, want: []string{"Bearer VTOKEN"}},
		{name: "config header wins, lower case key", user: url.UserPassword("u", "p"), headers: map[string]string{"authorization": "Bearer VTOKEN"}, want: []string{"Bearer VTOKEN"}},
		{name: "config header wins, user without password", user: url.User("u"), headers: map[string]string{"AUTHORIZATION": "Token x"}, want: []string{"Token x"}},
		{name: "config header only", headers: map[string]string{"Authorization": "Bearer VTOKEN"}, want: []string{"Bearer VTOKEN"}},
		{name: "other config headers do not block it", user: url.UserPassword("u", "p"), headers: map[string]string{"X-Api-Key": "k"}, want: []string{"Basic dTpw"}},
		{name: "no user and no header", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stub := send(t, httpClientConfig{User: tt.user, Headers: tt.headers}, origin+"/mcp")
			got := stub.header(0)["Authorization"]
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf(`header["Authorization"] = %q, want %q`, got, tt.want)
			}
		})
	}

	t.Run("caller request is not modified", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{}
		client, _, err := newHTTPClient(httpClientConfig{
			Origin: hcURL(t, origin), User: url.UserPassword("u", "p"), Base: stub, UserAgent: "mcpmoat",
		})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("caller request got Authorization %q, want none", got)
		}
		if got := stub.header(0).Get("Authorization"); got != "Basic dTpw" {
			t.Errorf("sent Authorization = %q, want %q", got, "Basic dTpw")
		}
	})

	t.Run("a caller Authorization header is kept and not doubled", func(t *testing.T) {
		t.Parallel()
		// The user info is added only when the request has no Authorization yet,
		// so one request never carries two values.
		stub := &hcStub{}
		client, _, err := newHTTPClient(httpClientConfig{
			Origin: hcURL(t, origin), User: url.UserPassword("u", "p"), Base: stub, UserAgent: "mcpmoat",
		})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer from-caller")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if got := stub.header(0)["Authorization"]; !reflect.DeepEqual(got, []string{"Bearer from-caller"}) {
			t.Errorf(`header["Authorization"] = %q, want only the caller value`, got)
		}
	})

	t.Run("redirected request on the same origin carries it too", func(t *testing.T) {
		t.Parallel()
		var n atomic.Int32
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			if n.Add(1) == 1 {
				return hcResponse(req, 302, "", http.Header{"Location": {"/next"}})
			}
			return hcResponse(req, 200, "ok", nil)
		}}
		client, _, err := newHTTPClient(httpClientConfig{
			Origin: hcURL(t, origin), User: url.UserPassword("u", "p"), Base: stub, UserAgent: "mcpmoat",
		})
		if err != nil {
			t.Fatal(err)
		}
		resp := hcGet(t, client, origin+"/start")
		_ = resp.Body.Close()
		if stub.count() != 2 {
			t.Fatalf("base got %d requests, want 2", stub.count())
		}
		for i := range 2 {
			if got := stub.header(i).Get("Authorization"); got != "Basic dTpw" {
				t.Errorf("request %d: Authorization = %q, want %q", i, got, "Basic dTpw")
			}
		}
	})

	t.Run("request to another origin sends nothing and leaks nothing", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{}
		client, _, err := newHTTPClient(httpClientConfig{
			Origin: hcURL(t, origin), User: url.UserPassword("u", pass), Base: stub, UserAgent: "mcpmoat",
		})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://evil.test/", nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Do(req)
		if !errors.Is(err, errOtherOrigin) {
			t.Fatalf("client.Do() error = %v, want errOtherOrigin", err)
		}
		if stub.count() != 0 {
			t.Errorf("base got %d requests, want 0", stub.count())
		}
		basic := base64.StdEncoding.EncodeToString([]byte("u:" + pass))
		for _, secret := range []string{pass, basic} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error text %q holds the credential", err)
			}
		}
	})

	t.Run("password is not in the reserved header error", func(t *testing.T) {
		t.Parallel()
		_, _, err := newHTTPClient(httpClientConfig{
			Origin: hcURL(t, origin), User: url.UserPassword("u", pass),
			Headers: map[string]string{"Accept-Encoding": hcSecret}, Base: &hcStub{},
		})
		if !errors.Is(err, errReservedHeader) {
			t.Fatalf("newHTTPClient() error = %v, want errReservedHeader", err)
		}
		if strings.Contains(err.Error(), pass) || strings.Contains(err.Error(), hcSecret) {
			t.Errorf("error text %q holds a secret", err)
		}
	})
}

func TestNewHTTPClientBaseTransport(t *testing.T) {
	t.Parallel()

	t.Run("response header limit is 64 KiB", func(t *testing.T) {
		t.Parallel()
		if got := newBaseTransport().MaxResponseHeaderBytes; got != 64<<10 {
			t.Errorf("MaxResponseHeaderBytes = %d, want %d", got, 64<<10)
		}
	})

	t.Run("nil base uses the limited transport", func(t *testing.T) {
		t.Parallel()
		client, _, err := newHTTPClient(httpClientConfig{Origin: hcURL(t, "http://example.com"), UserAgent: "mcpmoat"})
		if err != nil {
			t.Fatal(err)
		}
		ht, ok := client.Transport.(*headerTransport)
		if !ok {
			t.Fatalf("client.Transport is %T, want *headerTransport", client.Transport)
		}
		base, ok := ht.base.(*http.Transport)
		if !ok {
			t.Fatalf("base is %T, want *http.Transport", ht.base)
		}
		if base.MaxResponseHeaderBytes != 64<<10 {
			t.Errorf("MaxResponseHeaderBytes = %d, want %d", base.MaxResponseHeaderBytes, 64<<10)
		}
	})

	t.Run("client has no overall timeout", func(t *testing.T) {
		t.Parallel()
		client, _, err := newHTTPClient(httpClientConfig{Origin: hcURL(t, "http://example.com"), UserAgent: "mcpmoat"})
		if err != nil {
			t.Fatal(err)
		}
		if client.Timeout != 0 {
			t.Errorf("Client.Timeout = %v, want 0: it would end long SSE streams", client.Timeout)
		}
	})

	t.Run("a huge response header is refused with a real server", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/big" {
				w.Header().Set("X-Big", strings.Repeat("a", 100<<10))
			}
			_, _ = io.WriteString(w, "ok")
		}))
		t.Cleanup(ts.Close)

		client, _, err := newHTTPClient(httpClientConfig{Origin: hcURL(t, ts.URL), UserAgent: "mcpmoat"})
		if err != nil {
			t.Fatal(err)
		}
		// A small header block still works.
		resp := hcGet(t, client, ts.URL+"/small")
		_ = resp.Body.Close()

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/big", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err = client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("client.Do() error = nil, want an error for 100 KiB of response headers")
		}
	})
}

func TestIsFollowedRedirect(t *testing.T) {
	t.Parallel()

	loc := http.Header{"Location": {"/x"}}
	tests := []struct {
		name   string
		status int
		header http.Header
		want   bool
	}{
		{name: "301 with Location", status: 301, header: loc, want: true},
		{name: "302 with Location", status: 302, header: loc, want: true},
		{name: "303 with Location", status: 303, header: loc, want: true},
		{name: "307 with Location", status: 307, header: loc, want: true},
		{name: "308 with Location", status: 308, header: loc, want: true},
		{name: "307 without Location", status: 307, header: http.Header{}, want: false},
		{name: "307 with empty Location", status: 307, header: http.Header{"Location": {""}}, want: false},
		{name: "300 with Location", status: 300, header: loc, want: false},
		{name: "304 with Location", status: 304, header: loc, want: false},
		{name: "200 with Location", status: 200, header: loc, want: false},
		{name: "401", status: 401, header: http.Header{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := &http.Response{StatusCode: tt.status, Header: tt.header}
			if got := isFollowedRedirect(resp); got != tt.want {
				t.Errorf("isFollowedRedirect(%d) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

// hcSeen is what a test server saw: one value per request.
type hcSeen struct {
	mu   sync.Mutex
	keys []string // value of the X-Api-Key header, per request
	uas  []string
}

func (s *hcSeen) add(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, r.Header.Get("X-Api-Key"))
	s.uas = append(s.uas, r.Header.Get("User-Agent"))
}

func (s *hcSeen) snapshot() (keys, uas []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.keys...), append([]string(nil), s.uas...)
}

// hcChainServer starts a server where /hop/N redirects to /hop/N+1 until N is
// hops, and /hop/hops answers 200. Every request is recorded in the returned
// hcSeen.
func hcChainServer(t *testing.T, status, hops int) (*httptest.Server, *hcSeen) {
	t.Helper()
	seen := &hcSeen{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.add(r)
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/hop/%d", &n); err != nil {
			http.NotFound(w, r)
			return
		}
		if n >= hops {
			_, _ = io.WriteString(w, "done")
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/hop/%d", n+1), status)
	}))
	t.Cleanup(ts.Close)
	return ts, seen
}

func TestRedirects(t *testing.T) {
	t.Parallel()

	headers := map[string]string{"X-Api-Key": hcSecret}

	// Each case runs with a nil base (the client builds its own transport) and
	// with the base of the test server.
	baseKinds := []struct {
		name string
		base func(ts *httptest.Server) http.RoundTripper
	}{
		{name: "nil base", base: func(*httptest.Server) http.RoundTripper { return nil }},
		{name: "explicit base", base: func(ts *httptest.Server) http.RoundTripper { return ts.Client().Transport }},
	}

	for _, bk := range baseKinds {
		t.Run(bk.name, func(t *testing.T) {
			t.Parallel()

			for _, status := range []int{301, 302, 303, 307, 308} {
				t.Run("same origin "+strconv.Itoa(status), func(t *testing.T) {
					t.Parallel()
					ts, seen := hcChainServer(t, status, 1)
					client, rec, err := hcNew(hcURL(t, ts.URL), headers, bk.base(ts), "mcpmoat", 0)
					if err != nil {
						t.Fatal(err)
					}
					resp := hcGet(t, client, ts.URL+"/hop/0")
					body, err := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if err != nil {
						t.Fatalf("io.ReadAll() error = %v", err)
					}
					if resp.StatusCode != http.StatusOK || string(body) != "done" {
						t.Errorf("final response = %d %q, want 200 \"done\"", resp.StatusCode, body)
					}
					keys, uas := seen.snapshot()
					if len(keys) != 2 {
						t.Fatalf("server saw %d requests, want 2 (original and redirected)", len(keys))
					}
					for i, k := range keys {
						if k != hcSecret {
							t.Errorf("request %d: X-Api-Key = %q, want %q: the redirected request must carry the config header", i, k, hcSecret)
						}
						if uas[i] != "mcpmoat" {
							t.Errorf("request %d: User-Agent = %q, want %q", i, uas[i], "mcpmoat")
						}
					}
					if got := rec.lastStatus(); got != 0 {
						t.Errorf("recorder status = %d, want 0: followed redirects are not failures", got)
					}
				})
			}

			t.Run("three redirects are followed", func(t *testing.T) {
				t.Parallel()
				ts, seen := hcChainServer(t, http.StatusFound, 3)
				client, _, err := hcNew(hcURL(t, ts.URL), headers, bk.base(ts), "mcpmoat", 0)
				if err != nil {
					t.Fatal(err)
				}
				resp := hcGet(t, client, ts.URL+"/hop/0")
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK || string(body) != "done" {
					t.Errorf("final response = %d %q, want 200 \"done\"", resp.StatusCode, body)
				}
				keys, _ := seen.snapshot()
				if len(keys) != 4 {
					t.Errorf("server saw %d requests, want 4 (1 + 3 redirects)", len(keys))
				}
				for i, k := range keys {
					if k != hcSecret {
						t.Errorf("request %d: X-Api-Key = %q, want %q", i, k, hcSecret)
					}
				}
			})

			t.Run("four redirects are refused", func(t *testing.T) {
				t.Parallel()
				ts, seen := hcChainServer(t, http.StatusFound, 4)
				client, rec, err := hcNew(hcURL(t, ts.URL), headers, bk.base(ts), "mcpmoat", 0)
				if err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/hop/0", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if !errors.Is(err, errTooManyRedirects) {
					t.Fatalf("client.Do() error = %v, want errTooManyRedirects", err)
				}
				if errors.Is(err, errCrossOriginRedirect) {
					t.Errorf("error also matches errCrossOriginRedirect: %v", err)
				}
				keys, _ := seen.snapshot()
				if len(keys) != 4 {
					t.Errorf("server saw %d requests, want 4 (1 + 3 followed redirects; the 4th is refused)", len(keys))
				}
				if got := rec.lastStatus(); got != 0 {
					t.Errorf("recorder status = %d, want 0", got)
				}
			})

			t.Run("redirect to another origin is refused", func(t *testing.T) {
				t.Parallel()
				var otherCount atomic.Int32
				var otherSawSecret atomic.Bool
				other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					otherCount.Add(1)
					for _, values := range r.Header {
						for _, v := range values {
							if strings.Contains(v, hcSecret) {
								otherSawSecret.Store(true)
							}
						}
					}
					_, _ = io.WriteString(w, "stolen")
				}))
				t.Cleanup(other.Close)

				seen := &hcSeen{}
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen.add(r)
					http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
				}))
				t.Cleanup(ts.Close)

				if hcURL(t, ts.URL).Host == hcURL(t, other.URL).Host {
					t.Fatal("test servers share a host and port")
				}

				client, rec, err := hcNew(hcURL(t, ts.URL), headers, bk.base(ts), "mcpmoat", 0)
				if err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/mcp", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if !errors.Is(err, errCrossOriginRedirect) {
					t.Fatalf("client.Do() error = %v, want errCrossOriginRedirect", err)
				}
				if strings.Contains(err.Error(), hcSecret) {
					t.Errorf("error text %q holds the header value", err)
				}
				if n := otherCount.Load(); n != 0 {
					t.Errorf("other origin got %d requests, want 0", n)
				}
				if otherSawSecret.Load() {
					t.Error("other origin saw the secret header")
				}
				keys, _ := seen.snapshot()
				if len(keys) != 1 {
					t.Errorf("configured origin got %d requests, want 1", len(keys))
				}
				if got := rec.lastStatus(); got != 0 {
					t.Errorf("recorder status = %d, want 0", got)
				}
			})

			t.Run("redirect to another host name on the same port is refused", func(t *testing.T) {
				t.Parallel()
				// 127.0.0.1 and localhost reach the same server, but they are
				// different origins for the header pin.
				seen := &hcSeen{}
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen.add(r)
					_, port, _ := strings.Cut(strings.TrimPrefix(hcOrigin(r), "http://"), ":")
					http.Redirect(w, r, "http://localhost:"+port+"/mcp", http.StatusFound) //nolint:gosec // G710: test server redirect to a fixed local target
				}))
				t.Cleanup(ts.Close)

				client, _, err := hcNew(hcURL(t, ts.URL), headers, bk.base(ts), "mcpmoat", 0)
				if err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/mcp", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if !errors.Is(err, errCrossOriginRedirect) {
					t.Fatalf("client.Do() error = %v, want errCrossOriginRedirect", err)
				}
				keys, _ := seen.snapshot()
				if len(keys) != 1 {
					t.Errorf("server got %d requests, want 1: the redirect must not be followed", len(keys))
				}
			})
		})
	}
}

// hcOrigin returns the "http://host:port" part of the URL that r was sent to.
func hcOrigin(r *http.Request) string {
	return "http://" + r.Host
}
