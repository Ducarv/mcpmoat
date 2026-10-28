package inspect

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// hcSecret is a fake header value. Tests assert that it never shows up in an
// error text.
const hcSecret = "VSECRET1"

// hcUA is the User-Agent that most tests give to newHTTPClient. Remote gives
// an empty one by default (see TestNewHTTPClientHeaders).
const hcUA = "test-agent/1"

// hcNew calls newHTTPClient with the common fields. The tests that need User or
// MaxTotal build the httpClientConfig themselves.
func hcNew(endpoint *url.URL, headers map[string]string, base http.RoundTripper, ua string, maxBody int64) (*http.Client, *httpEvents, error) {
	return newHTTPClient(httpClientConfig{
		Endpoint:  endpoint,
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
		{name: "host case, mixed both sides", a: u("http://ExAmPlE.CoM:8080"), b: u("http://eXaMpLe.cOm:8080"), want: true},
		// Go skips HTTP_PROXY for "localhost" only, so the case of this
		// name changes the network path.
		{name: "LOCALHOST is not localhost", a: u("http://LOCALHOST:8080"), b: u("http://localhost:8080"), want: false},
		{name: "localhost is not LOCALHOST", a: u("http://localhost:8080"), b: u("http://LOCALHOST:8080"), want: false},
		{name: "LOCALHOST and LocalHost", a: u("http://LOCALHOST:8080"), b: u("http://LocalHost:8080"), want: true},
		// strings.EqualFold folds these Unicode letters to ASCII ones, but
		// IDNA keeps them apart, so they are other hosts.
		{name: "Kelvin sign is not K", a: &url.URL{Scheme: "http", Host: "\u212aey.example"}, b: u("http://key.example"), want: false},
		{name: "long s is not s", a: &url.URL{Scheme: "https", Host: "example\u017f.com"}, b: u("https://examples.com"), want: false},
		{name: "same non-ASCII host", a: &url.URL{Scheme: "http", Host: "b\u00fccher.example"}, b: &url.URL{Scheme: "http", Host: "b\u00fccher.example"}, want: true},
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

// TestEqualFoldASCII checks that equalFoldASCII ignores the case of ASCII
// letters only, and compares every other byte exactly.
func TestEqualFoldASCII(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{name: "both empty", a: "", b: "", want: true},
		{name: "identical", a: "example.com", b: "example.com", want: true},
		{name: "upper and lower case", a: "EXAMPLE.COM", b: "example.com", want: true},
		{name: "mixed case", a: "ExAmPlE", b: "eXaMpLe", want: true},
		{name: "first and last letter", a: "Az", b: "aZ", want: true},
		{name: "digits and punctuation", a: "a-1.b_2:80", b: "A-1.B_2:80", want: true},
		{name: "different letter", a: "example.com", b: "examplf.com", want: false},
		{name: "different length", a: "example.com", b: "example.co", want: false},
		{name: "empty and not empty", a: "", b: "a", want: false},
		// The bytes next to the letter ranges must not fold: "@" is "A"-1,
		// "[" is "Z"+1, "`" is "a"-1 and "{" is "z"+1.
		{name: "at sign and backtick", a: "@", b: "`", want: false},
		{name: "brackets and braces", a: "[", b: "{", want: false},
		{name: "Z and brace", a: "Z", b: "{", want: false},
		{name: "A and backtick", a: "A", b: "`", want: false},
		// Unicode case folding must not apply.
		{name: "Kelvin sign and k", a: "\u212a", b: "k", want: false},
		{name: "Kelvin sign and K", a: "\u212a", b: "K", want: false},
		{name: "Greek final sigma and sigma", a: "\u03c2", b: "\u03c3", want: false},
		{name: "Greek capital and small sigma", a: "\u03a3", b: "\u03c3", want: false},
		{name: "long s and s", a: "\u017f", b: "s", want: false},
		{name: "identical non-ASCII", a: "b\u00fccher", b: "b\u00fccher", want: true},
		{name: "non-ASCII with ASCII case", a: "B\u00fcCHER", b: "b\u00fccher", want: true},
		{name: "upper and lower u umlaut", a: "\u00dc", b: "\u00fc", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := equalFoldASCII(tt.a, tt.b); got != tt.want {
				t.Errorf("equalFoldASCII(%q, %q) = %t, want %t", tt.a, tt.b, got, tt.want)
			}
			if got := equalFoldASCII(tt.b, tt.a); got != tt.want {
				t.Errorf("equalFoldASCII(%q, %q) = %t, want %t", tt.b, tt.a, got, tt.want)
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
		}, stub, hcUA, 0)
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
		client, _, err := hcNew(hcURL(t, origin), map[string]string{"X-Api-Key": hcSecret}, stub, hcUA, 0)
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
		client, _, err := hcNew(hcURL(t, origin), map[string]string{"X-Api-Key": hcSecret}, stub, hcUA, 0)
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
		{name: "given ua when absent", headers: nil, ua: hcUA, want: hcUA},
		{name: "given ua with other headers", headers: map[string]string{"X-Other": "v"}, ua: "agent/9.9", want: "agent/9.9"},
		// An empty ua sets no User-Agent, so net/http sends its default.
		{name: "none when ua is empty", headers: nil, ua: "", want: ""},
		{name: "none when ua is empty with other headers", headers: map[string]string{"X-Other": "v"}, ua: "", want: ""},
		{name: "config wins over empty ua", headers: map[string]string{"user-agent": "custom/0"}, ua: "", want: "custom/0"},
		{name: "config wins, canonical", headers: map[string]string{"User-Agent": "custom/1"}, ua: hcUA, want: "custom/1"},
		{name: "config wins, lower case", headers: map[string]string{"user-agent": "custom/2"}, ua: hcUA, want: "custom/2"},
		{name: "config wins, upper case", headers: map[string]string{"USER-AGENT": "custom/3"}, ua: hcUA, want: "custom/3"},
		{name: "config wins, mixed case", headers: map[string]string{"uSeR-aGeNt": "custom/4"}, ua: hcUA, want: "custom/4"},
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
			if tt.want == "" {
				if got != nil {
					t.Errorf(`header["User-Agent"] = %q, want no User-Agent key`, got)
				}
				return
			}
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
			client, _, err := hcNew(hcURL(t, origin), map[string]string{"x-key": "lower", "X-Key": "upper"}, stub, hcUA, 0)
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
			}, &hcStub{}, hcUA, 0)
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
			client, _, err := hcNew(hcURL(t, origin), map[string]string{key: hcSecret}, stub, hcUA, 0)
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
		_, _, err := hcNew(hcURL(t, origin), map[string]string{"": hcSecret}, &hcStub{}, hcUA, 0)
		if !errors.Is(err, errReservedHeader) {
			t.Fatalf("hcNew() error = %v, want errReservedHeader", err)
		}
		if strings.Contains(err.Error(), hcSecret) {
			t.Errorf("error text %q holds the header value", err)
		}
	})

	t.Run("nil origin refused", func(t *testing.T) {
		t.Parallel()
		client, rec, err := hcNew(nil, nil, &hcStub{}, hcUA, 0)
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
			client, rec, err := hcNew(hcURL(t, origin), map[string]string{"X-Api-Key": hcSecret}, stub, hcUA, 0)
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
			if rec.fallback.lastStatus() != 0 {
				t.Errorf("recorder status = %d, want 0", rec.fallback.lastStatus())
			}
			if strings.Contains(err.Error(), hcSecret) {
				t.Errorf("error text %q holds the header value", err)
			}
		})
	}

	t.Run("same origin is allowed", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{}
		client, _, err := hcNew(hcURL(t, origin), nil, stub, hcUA, 0)
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
			client, _, err := hcNew(hcURL(t, "http://example.com"), nil, stub, hcUA, tt.maxBody)
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
		client, _, err := hcNew(hcURL(t, "http://example.com"), nil, stub, hcUA, 5)
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
		client, _, err := hcNew(hcURL(t, "http://example.com"), nil, stub, hcUA, 10)
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
}

// hcRecordResp is a response with only a status and a header, for tests that
// call recordResponse or isFollowedRedirect directly.
func hcRecordResp(status int, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header}
}

// TestRequestRecorderStatus checks which HTTP status the requestRecorder keeps
// as the last failure, both when called directly and through the client.
func TestRequestRecorderStatus(t *testing.T) {
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
		{name: "redirect with unparsable Location is a failure", resp: []*http.Response{hcRecordResp(200, nil), hcRecordResp(302, http.Header{"Location": {"http://[::1"}})}, want: 302},
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
			wg.Go(func() {
				rec.recordResponse(hcRecordResp(400+i, nil))
			})
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
			client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, stub, hcUA, 0)
			if err != nil {
				t.Fatal(err)
			}
			for range tt.statuses {
				resp := hcGet(t, client, "http://example.com/")
				_ = resp.Body.Close()
			}
			if got := rec.fallback.lastStatus(); got != tt.want {
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
		client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, base, hcUA, 0)
		if err != nil {
			t.Fatal(err)
		}
		resp := hcGet(t, client, "http://example.com/")
		_ = resp.Body.Close()
		if got := rec.fallback.lastStatus(); got != 404 {
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
		if got := rec.fallback.lastStatus(); got != 0 {
			t.Errorf("lastStatus() = %d after a transport error, want 0", got)
		}
	})

	// The SDK sends DELETE only to close the session. Its outcome, an answer
	// or a transport error, must not change the recorded status.
	t.Run("session-close DELETE does not change the status", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name       string
			firstCode  int   // status of the GET before the DELETE
			deleteErr  error // non-nil: the DELETE gets no response
			deleteCode int
			want       int
		}{
			{name: "404 after a 2xx", firstCode: http.StatusOK, deleteCode: http.StatusNotFound, want: 0},
			{name: "404 after a 401", firstCode: http.StatusUnauthorized, deleteCode: http.StatusNotFound, want: 401},
			{name: "2xx after a 401", firstCode: http.StatusUnauthorized, deleteCode: http.StatusOK, want: 401},
			{name: "transport error after a 401", firstCode: http.StatusUnauthorized, deleteErr: errors.New("boom"), want: 401},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				base := hcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.Method != http.MethodDelete {
						return hcResponse(req, tt.firstCode, "body", nil), nil
					}
					if tt.deleteErr != nil {
						return nil, tt.deleteErr
					}
					return hcResponse(req, tt.deleteCode, "body", nil), nil
				})
				client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, base, hcUA, 0)
				if err != nil {
					t.Fatal(err)
				}
				resp := hcGet(t, client, "http://example.com/")
				_ = resp.Body.Close()

				req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, "http://example.com/", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err = client.Do(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if (err != nil) != (tt.deleteErr != nil) {
					t.Fatalf("client.Do(DELETE) error = %v, want error: %t", err, tt.deleteErr != nil)
				}
				if got := rec.fallback.lastStatus(); got != tt.want {
					t.Errorf("lastStatus() = %d after the DELETE, want %d", got, tt.want)
				}
			})
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
		client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, base, hcUA, 0)
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
		ce := classify(doErr, srv, rec, secretLists{})
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

	// The http.Client refuses a redirect whose Location does not parse and
	// returns an error. The redirect response is then the last answer of the
	// server, so the recorder must keep its status.
	t.Run("redirect with unparsable Location is recorded", func(t *testing.T) {
		t.Parallel()
		for _, loc := range []string{"http://[::1", "%zz"} {
			stub := &hcStub{respond: func(req *http.Request) *http.Response {
				return hcResponse(req, http.StatusFound, "", http.Header{"Location": {loc}})
			}}
			client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, stub, hcUA, 0)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if err == nil {
				t.Fatalf("Location %q: client.Do() error = nil, want the Location parse error", loc)
			}
			if stub.count() != 1 {
				t.Errorf("Location %q: base got %d requests, want 1", loc, stub.count())
			}
			if got := rec.fallback.lastStatus(); got != http.StatusFound {
				t.Errorf("Location %q: lastStatus() = %d, want %d", loc, got, http.StatusFound)
			}
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
		client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, stub, hcUA, 0)
		if err != nil {
			t.Fatal(err)
		}
		resp := hcGet(t, client, "http://example.com/start")
		_ = resp.Body.Close()
		if stub.count() != 2 {
			t.Fatalf("base got %d requests, want 2", stub.count())
		}
		if got := rec.fallback.lastStatus(); got != 0 {
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
			client, rec, err := hcNew(hcURL(t, "http://example.com"), nil, stub, hcUA, 0)
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
			if got := rec.fallback.lastStatus(); got != tt.prev {
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

// TestCheckRedirectSessionDelete checks that a refused redirect of the
// session DELETE fails, but leaves no blocked error in the fallback record.
// The SDK closes the session when Connect fails, before Remote classifies the
// error, so a recorded DELETE redirect would change the label of the real
// failure. A refused GET redirect without a call record still goes to the
// fallback record.
func TestCheckRedirectSessionDelete(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		method      string
		location    string // Location of every redirect
		wantErr     error
		wantBlocked error // blocked error of the fallback record afterwards
	}{
		{name: "DELETE to another origin", method: http.MethodDelete, location: "http://evil.test/", wantErr: errCrossOriginRedirect},
		{name: "DELETE redirect loop", method: http.MethodDelete, location: "http://example.com/again", wantErr: errTooManyRedirects},
		{name: "GET to another origin", method: http.MethodGet, location: "http://evil.test/", wantErr: errCrossOriginRedirect, wantBlocked: errCrossOriginRedirect},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// 307 keeps the method, so a redirected DELETE stays a DELETE.
			stub := &hcStub{respond: func(req *http.Request) *http.Response {
				return hcResponse(req, http.StatusTemporaryRedirect, "", http.Header{"Location": {tt.location}})
			}}
			client, ev, err := hcNew(hcURL(t, "http://example.com"), nil, stub, hcUA, 0)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(t.Context(), tt.method, "http://example.com/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("client.Do(%s) error = %v, want %v", tt.method, err, tt.wantErr)
			}
			if got := ev.fallback.blockedErr(); !errors.Is(got, tt.wantBlocked) || (got == nil) != (tt.wantBlocked == nil) {
				t.Errorf("fallback blockedErr() = %v, want %v", got, tt.wantBlocked)
			}
		})
	}
}

// TestRoundTripSessionDeleteBody checks that the body limits of a session
// DELETE answer write to no record either. A GET answer with the same body
// still records errBodyTooLarge in the fallback record.
func TestRoundTripSessionDeleteBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method      string
		wantBlocked error
	}{
		{method: http.MethodDelete},
		{method: http.MethodGet, wantBlocked: errBodyTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()
			base := hcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				return hcResponse(req, http.StatusOK, strings.Repeat("x", 64), nil), nil
			})
			client, ev, err := hcNew(hcURL(t, "http://example.com"), nil, base, hcUA, 8)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(t.Context(), tt.method, "http://example.com/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("client.Do(%s) error = %v", tt.method, err)
			}
			_, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if !errors.Is(readErr, errBodyTooLarge) {
				t.Fatalf("read body error = %v, want errBodyTooLarge", readErr)
			}
			if got := ev.fallback.blockedErr(); !errors.Is(got, tt.wantBlocked) || (got == nil) != (tt.wantBlocked == nil) {
				t.Errorf("fallback blockedErr() = %v, want %v", got, tt.wantBlocked)
			}
		})
	}
}

// TestCheckRedirectLocalhostCase checks that a redirect from a localhost
// endpoint to LOCALHOST is refused. Go sends LOCALHOST through HTTP_PROXY,
// so the redirected request could carry the secrets to a proxy, and the
// endpoint got no cleartext warning.
func TestCheckRedirectLocalhostCase(t *testing.T) {
	t.Parallel()
	stub := &hcStub{respond: func(req *http.Request) *http.Response {
		return hcResponse(req, http.StatusTemporaryRedirect, "", http.Header{"Location": {"http://LOCALHOST:8080/x"}})
	}}
	client, _, err := hcNew(hcURL(t, "http://localhost:8080"), map[string]string{"X-Api-Key": "k"}, stub, hcUA, 0)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://localhost:8080/mcp", nil)
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
	if stub.count() != 1 {
		t.Errorf("base got %d requests, want 1: the LOCALHOST target must not be requested", stub.count())
	}
}

// TestRoundTripRedirectedSessionDelete checks that a session DELETE keeps
// out of the record after a same-origin 302. http.Client follows the 302
// with a GET, and that GET is still part of the session DELETE: its status
// must not replace the status of the earlier failure.
func TestRoundTripRedirectedSessionDelete(t *testing.T) {
	t.Parallel()
	base := hcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodDelete:
			return hcResponse(req, http.StatusFound, "", http.Header{"Location": {"http://example.com/closed"}}), nil
		case req.URL.Path == "/closed":
			return hcResponse(req, http.StatusNotFound, "", nil), nil
		}
		return hcResponse(req, http.StatusUnauthorized, "", nil), nil
	})
	client, ev, err := hcNew(hcURL(t, "http://example.com"), nil, base, hcUA, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp := hcGet(t, client, "http://example.com/")
	_ = resp.Body.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("client.Do(DELETE) error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.Request.Method != http.MethodGet {
		t.Fatalf("redirected method = %s, want GET: the test needs the 302 method change", resp.Request.Method)
	}
	if got := ev.fallback.lastStatus(); got != http.StatusUnauthorized {
		t.Errorf("lastStatus() = %d after the redirected DELETE, want %d", got, http.StatusUnauthorized)
	}
}

// TestRequestRecorderBlocked checks how the requestRecorder stores the first
// blocked error and the connected flag.
func TestRequestRecorderBlocked(t *testing.T) {
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

	t.Run("zero value is not connected", func(t *testing.T) {
		t.Parallel()
		var ev httpEvents
		if ev.connected() {
			t.Error("connected() = true on the zero value, want false")
		}
	})

	// markConnected only marks the session up. A blocked error in the
	// fallback record (for example a legacy SSE stream over the size cap)
	// must still label later failures.
	t.Run("markConnected sets connected and keeps the blocked error", func(t *testing.T) {
		t.Parallel()
		var ev httpEvents
		ev.fallback.recordResponse(hcRecordResp(404, nil))
		_ = ev.fallback.recordBlocked(errCrossOriginRedirect)
		ev.markConnected()
		if !ev.connected() {
			t.Error("connected() = false after markConnected, want true")
		}
		if got := ev.fallback.blockedErr(); !errors.Is(got, errCrossOriginRedirect) {
			t.Errorf("blockedErr() = %v after markConnected, want errCrossOriginRedirect", got)
		}
		if got := ev.fallback.lastStatus(); got != 404 {
			t.Errorf("lastStatus() = %d after markConnected, want 404", got)
		}
	})

	t.Run("markHandshake sets connected and keeps the blocked error", func(t *testing.T) {
		t.Parallel()
		var ev httpEvents
		ev.fallback.recordResponse(hcRecordResp(404, nil))
		_ = ev.fallback.recordBlocked(errCrossOriginRedirect)
		ev.markHandshake()
		if !ev.connected() {
			t.Error("connected() = false after markHandshake, want true")
		}
		if got := ev.fallback.blockedErr(); got != errCrossOriginRedirect { //nolint:errorlint // identity check: markHandshake must keep the stored error unchanged
			t.Errorf("blockedErr() = %v after markHandshake, want errCrossOriginRedirect", got)
		}
		if got := ev.fallback.lastStatus(); got != 404 {
			t.Errorf("lastStatus() = %d after markHandshake, want 404", got)
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
			wg.Go(func() {
				_ = rec.recordBlocked(e)
			})
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
				Endpoint:  hcURL(t, origin),
				Base:      stub,
				UserAgent: hcUA,
				MaxBody:   tt.maxBody,
				MaxTotal:  tt.maxTotal,
			})
			if err != nil {
				t.Fatal(err)
			}
			tt.act(t, client)

			got := rec.fallback.blockedErr()
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
			Endpoint: hcURL(t, origin), Base: stub, UserAgent: hcUA, MaxBody: 10, MaxTotal: 12,
		})
		if err != nil {
			t.Fatal(err)
		}
		first := hcReadAll(t, client, origin+"/", nil)
		if len(first) != 8 {
			t.Errorf("first body: %d bytes, want 8", len(first))
		}
		if err := rec.fallback.blockedErr(); err != nil {
			t.Fatalf("blockedErr() = %v after the first body, want nil", err)
		}
		second := hcReadAll(t, client, origin+"/", errBodyTooLarge)
		// 12 - 8 = 4 bytes of budget are left for the second body.
		if len(second) != 4 {
			t.Errorf("second body: %d bytes, want 4 (the rest of the budget)", len(second))
		}
		if !errors.Is(rec.fallback.blockedErr(), errBodyTooLarge) {
			t.Errorf("blockedErr() = %v, want errBodyTooLarge", rec.fallback.blockedErr())
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
			Endpoint: hcURL(t, origin), Base: stub, UserAgent: hcUA, MaxBody: 7, MaxTotal: 14,
		})
		if err != nil {
			t.Fatal(err)
		}
		hcReadAll(t, client, origin+"/", nil)
		hcReadAll(t, client, origin+"/", nil)
		if err := rec.fallback.blockedErr(); err != nil {
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
			Endpoint: hcURL(t, origin), Base: stub, UserAgent: hcUA, MaxBody: 5, MaxTotal: 1000,
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
			Endpoint: hcURL(t, origin), Base: stub, UserAgent: hcUA, MaxBody: 100, MaxTotal: 500,
		})
		if err != nil {
			t.Fatal(err)
		}
		var total atomic.Int64
		var wg sync.WaitGroup
		for range 10 {
			wg.Go(func() {
				resp, err := client.Get(origin + "/")
				if err != nil {
					t.Errorf("client.Get() error = %v", err)
					return
				}
				defer func() { _ = resp.Body.Close() }()
				data, _ := io.ReadAll(resp.Body)
				total.Add(int64(len(data)))
			})
		}
		wg.Wait()
		if got := total.Load(); got != 500 {
			t.Errorf("bodies handed out %d bytes together, want exactly the budget of 500", got)
		}
		if !errors.Is(rec.fallback.blockedErr(), errBodyTooLarge) {
			t.Errorf("blockedErr() = %v, want errBodyTooLarge", rec.fallback.blockedErr())
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
					Endpoint: hcURL(t, origin), Base: &hcStub{}, UserAgent: hcUA,
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
				Endpoint: hcURL(t, origin), Base: stub, UserAgent: hcUA,
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
			if err := rec.fallback.blockedErr(); err != nil {
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
			Endpoint: hcURL(t, origin), Base: stub, UserAgent: hcUA, MaxBody: 1000, MaxTotal: 4,
		})
		if err != nil {
			t.Fatal(err)
		}
		got := hcReadAll(t, client, origin+"/", errBodyTooLarge)
		if string(got) != "0123" {
			t.Errorf("body = %q, want %q (the total budget)", got, "0123")
		}
		if !errors.Is(rec.fallback.blockedErr(), errBodyTooLarge) {
			t.Errorf("blockedErr() = %v, want errBodyTooLarge", rec.fallback.blockedErr())
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
		cfg.Endpoint = hcURL(t, origin)
		cfg.Base = stub
		cfg.UserAgent = hcUA
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
		// An empty config value counts as absent, as in net/http: the Basic
		// header from the user info replaces it.
		{name: "empty config header gives way", user: url.UserPassword("u", "p"), headers: map[string]string{"Authorization": ""}, want: []string{"Basic dTpw"}},
		{name: "empty config header gives way, lower case key", user: url.UserPassword("u", "p"), headers: map[string]string{"authorization": ""}, want: []string{"Basic dTpw"}},
		// buildHeader sets the keys in sorted (byte) order, so the last key
		// wins: "authorization" sorts after "Authorization".
		{name: "last key empty gives way", user: url.UserPassword("u", "p"), headers: map[string]string{"Authorization": "Bearer VTOKEN", "authorization": ""}, want: []string{"Basic dTpw"}},
		{name: "last key non-empty wins", user: url.UserPassword("u", "p"), headers: map[string]string{"Authorization": "", "authorization": "Bearer VTOKEN"}, want: []string{"Bearer VTOKEN"}},
		{name: "empty config header without user info is sent as is", headers: map[string]string{"Authorization": ""}, want: []string{""}},
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
			Endpoint: hcURL(t, origin), User: url.UserPassword("u", "p"), Base: stub, UserAgent: hcUA,
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
			Endpoint: hcURL(t, origin), User: url.UserPassword("u", "p"), Base: stub, UserAgent: hcUA,
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
			Endpoint: hcURL(t, origin), User: url.UserPassword("u", "p"), Base: stub, UserAgent: hcUA,
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
			Endpoint: hcURL(t, origin), User: url.UserPassword("u", pass), Base: stub, UserAgent: hcUA,
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
			Endpoint: hcURL(t, origin), User: url.UserPassword("u", pass),
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
		if got := newBaseTransport(nil, "").MaxResponseHeaderBytes; got != 64<<10 {
			t.Errorf("MaxResponseHeaderBytes = %d, want %d", got, 64<<10)
		}
	})

	t.Run("nil base uses the limited transport", func(t *testing.T) {
		t.Parallel()
		client, _, err := newHTTPClient(httpClientConfig{Endpoint: hcURL(t, "http://example.com"), UserAgent: hcUA})
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
		client, _, err := newHTTPClient(httpClientConfig{Endpoint: hcURL(t, "http://example.com"), UserAgent: hcUA})
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

		client, _, err := newHTTPClient(httpClientConfig{Endpoint: hcURL(t, ts.URL), UserAgent: hcUA})
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
	// at returns a header with the given Location value.
	at := func(v string) http.Header { return http.Header{"Location": {v}} }
	tests := []struct {
		name   string
		status int
		header http.Header
		// reqURL, when set, is the URL of resp.Request. resp.Location
		// resolves a relative Location against it.
		reqURL string
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
		{name: "302 with absolute Location", status: 302, header: at("http://example.com/next"), want: true},
		{name: "302 with absolute Location on another origin", status: 302, header: at("https://evil.test/steal"), want: true},
		{name: "302 with relative Location and a request URL", status: 302, header: at("next?x=1"), reqURL: "http://example.com/a/b", want: true},
		{name: "302 with scheme-relative Location", status: 302, header: at("//evil.test/steal"), reqURL: "http://example.com/", want: true},
		// The http.Client does not follow a Location that does not parse; it
		// returns an error. So the response is the final answer.
		{name: "302 with unclosed IPv6 host", status: 302, header: at("http://[::1"), want: false},
		{name: "307 with bad percent escape", status: 307, header: at("%zz"), want: false},
		{name: "308 with control character", status: 308, header: at("http://example.com/\x7f"), want: false},
		{name: "301 with unparsable Location and a request URL", status: 301, header: at("http://[::1"), reqURL: "http://example.com/", want: false},
		{name: "500 with unparsable Location", status: 500, header: at("http://[::1"), want: false},
		{name: "200 with absolute Location", status: 200, header: at("http://example.com/next"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := &http.Response{StatusCode: tt.status, Header: tt.header}
			if tt.reqURL != "" {
				resp.Request = &http.Request{URL: hcURL(t, tt.reqURL)}
			}
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
	return slices.Clone(s.keys), slices.Clone(s.uas)
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
					client, rec, err := hcNew(hcURL(t, ts.URL), headers, bk.base(ts), hcUA, 0)
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
						if uas[i] != hcUA {
							t.Errorf("request %d: User-Agent = %q, want %q", i, uas[i], hcUA)
						}
					}
					if got := rec.fallback.lastStatus(); got != 0 {
						t.Errorf("recorder status = %d, want 0: followed redirects are not failures", got)
					}
				})
			}

			t.Run("three redirects are followed", func(t *testing.T) {
				t.Parallel()
				ts, seen := hcChainServer(t, http.StatusFound, 3)
				client, _, err := hcNew(hcURL(t, ts.URL), headers, bk.base(ts), hcUA, 0)
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
				client, rec, err := hcNew(hcURL(t, ts.URL), headers, bk.base(ts), hcUA, 0)
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
				if got := rec.fallback.lastStatus(); got != 0 {
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

				client, rec, err := hcNew(hcURL(t, ts.URL), headers, bk.base(ts), hcUA, 0)
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
				if got := rec.fallback.lastStatus(); got != 0 {
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

				client, _, err := hcNew(hcURL(t, ts.URL), headers, bk.base(ts), hcUA, 0)
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

func TestBuildHeaderUserAgent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers map[string]string
		ua      string
		want    []string // nil: no User-Agent key
	}{
		{name: "empty ua and no config ua sets none", headers: nil, ua: "", want: nil},
		{name: "empty ua with other headers sets none", headers: map[string]string{"X-Api-Key": hcSecret}, ua: "", want: nil},
		{name: "ua used when the config has none", headers: nil, ua: hcUA, want: []string{hcUA}},
		{name: "config ua wins over ua", headers: map[string]string{"user-agent": "custom/1"}, ua: hcUA, want: []string{"custom/1"}},
		{name: "config ua kept with empty ua", headers: map[string]string{"User-Agent": "custom/2"}, ua: "", want: []string{"custom/2"}},
		// The config User-Agent wins, so a bad default is never used and not
		// checked.
		{name: "config ua wins over a ua with CR LF", headers: map[string]string{"User-Agent": "custom/3"}, ua: "a\r\nX: y", want: []string{"custom/3"}},
		{name: "config ua in lower case wins over a ua with NUL", headers: map[string]string{"user-agent": "custom/4"}, ua: "ua\x00", want: []string{"custom/4"}},
		// A tab and obs-text are valid in a header value.
		{name: "ua with a tab and UTF-8 is kept", headers: nil, ua: "client\t/é", want: []string{"client\t/é"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			header, err := buildHeader(tt.headers, tt.ua)
			if err != nil {
				t.Fatalf("buildHeader() error = %v", err)
			}
			got, ok := header["User-Agent"]
			if tt.want == nil {
				if ok {
					t.Errorf(`header["User-Agent"] = %q, want no User-Agent key`, got)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf(`header["User-Agent"] = %q, want %q`, got, tt.want)
			}
		})
	}
}

// hcNotTokenErr is the fixed error text for a header key that is not an HTTP
// token. It does not show the key: a key can hold a pasted header line with a
// value in it.
const hcNotTokenErr = "header name not allowed: a key is not a valid HTTP token (the key is not shown, it may hold a value)"

// TestBuildHeaderErrors checks the exact text of the errors for a header that
// the config must not set. The text holds a reserved key, quoted with %q so
// that a control character in it cannot change the terminal. It never holds
// a value, and never a key that is not an HTTP token.
func TestBuildHeaderErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers map[string]string
		// ua is the User-Agent default; empty means hcUA.
		ua   string
		want string
		// wantErr is the sentinel that the error wraps; nil means
		// errReservedHeader.
		wantErr error
		// secrets are extra strings that the error must not hold.
		secrets []string
	}{
		{name: "empty name", headers: map[string]string{"": hcSecret}, want: "header name not allowed: empty"},
		// A name that is not an HTTP token. net/http would refuse to send it,
		// and a space or a colon could split the header line. The text does
		// not show the key.
		{name: "space in name", headers: map[string]string{"X Key": hcSecret}, want: hcNotTokenErr, secrets: []string{"X Key"}},
		{name: "colon in name", headers: map[string]string{"X-Key:": hcSecret}, want: hcNotTokenErr, secrets: []string{"X-Key:"}},
		{name: "non-ASCII name", headers: map[string]string{"X-Clé": hcSecret}, want: hcNotTokenErr, secrets: []string{"X-Cl"}},
		{name: "CR LF in name", headers: map[string]string{"X-A\r\nX-B": hcSecret}, want: hcNotTokenErr, secrets: []string{"X-A", "X-B"}},
		// A pasted header line as the key: its value is in the key, so the
		// key must not be shown.
		{
			name:    "pasted Authorization line as the key",
			headers: map[string]string{"Authorization: Bearer tok-NOTREAL-pasted-123": ""},
			want:    hcNotTokenErr,
			secrets: []string{"tok-NOTREAL-pasted-123", "Bearer"},
		},
		{name: "pasted key and value as the key", headers: map[string]string{"sk-NOTREAL: x": ""}, want: hcNotTokenErr, secrets: []string{"sk-NOTREAL"}},
		// A token key that is reserved is still named, so the user can find
		// it, even when another key is not a token: "Accept" sorts first.
		{name: "reserved token key sorts before a bad key", headers: map[string]string{"Accept": "x", "X Key": hcSecret}, want: `header name not allowed: "Accept"`},
		{name: "bad key sorts before a reserved key", headers: map[string]string{"Host": "x", "Authorization: Bearer tok-NOTREAL-pasted-123": ""}, want: hcNotTokenErr, secrets: []string{"tok-NOTREAL-pasted-123"}},
		// A value with a control character. The text names the key, never
		// the value.
		{name: "CR LF in value", headers: map[string]string{"X-Inject": "a\r\nInjected: " + hcSecret}, want: `header value not allowed: control character: "X-Inject"`, wantErr: errInvalidHeaderValue},
		{name: "LF in value", headers: map[string]string{"X-Inject": hcSecret + "\n"}, want: `header value not allowed: control character: "X-Inject"`, wantErr: errInvalidHeaderValue},
		{name: "NUL in value", headers: map[string]string{"X-Key": hcSecret + "\x00"}, want: `header value not allowed: control character: "X-Key"`, wantErr: errInvalidHeaderValue},
		{name: "DEL in value", headers: map[string]string{"X-Key": "\x7f" + hcSecret}, want: `header value not allowed: control character: "X-Key"`, wantErr: errInvalidHeaderValue},
		{name: "bad value keeps the config case of the key", headers: map[string]string{"x-key": hcSecret + "\r"}, want: `header value not allowed: control character: "x-key"`, wantErr: errInvalidHeaderValue},
		{name: "reserved name", headers: map[string]string{"X-Key": "ok", "Host": hcSecret}, want: `header name not allowed: "Host"`},
		{name: "reserved name keeps the config case", headers: map[string]string{"mcp-session-id": hcSecret}, want: `header name not allowed: "mcp-session-id"`},
		{name: "control character in name is not shown", headers: map[string]string{"Mcp-\x1b[31m": hcSecret}, want: hcNotTokenErr, secrets: []string{"\x1b", "Mcp-"}},
		// The User-Agent default from RemoteOptions is checked like a config
		// value when the config sets no User-Agent.
		{name: "CR LF in the default User-Agent", headers: map[string]string{"X-Key": "ok"}, ua: "a\r\nInjected: 1", want: `header value not allowed: control character: "User-Agent"`, wantErr: errInvalidHeaderValue, secrets: []string{"a\r\n"}},
		{name: "NUL in the default User-Agent, no config headers", headers: nil, ua: "ua\x00", want: `header value not allowed: control character: "User-Agent"`, wantErr: errInvalidHeaderValue, secrets: []string{"ua\x00"}},
		{name: "DEL in the default User-Agent", headers: nil, ua: "ua\x7f", want: `header value not allowed: control character: "User-Agent"`, wantErr: errInvalidHeaderValue},
		// A bad config User-Agent is named with the config case of its key.
		{name: "bad config User-Agent", headers: map[string]string{"user-agent": "a\nb"}, want: `header value not allowed: control character: "user-agent"`, wantErr: errInvalidHeaderValue},
		// The keys are checked in sorted order, so the error is stable.
		{name: "first sorted key is named", headers: map[string]string{"Host": hcSecret, "Accept": hcSecret}, want: `header name not allowed: "Accept"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ua := tt.ua
			if ua == "" {
				ua = hcUA
			}
			header, err := buildHeader(tt.headers, ua)
			if err == nil {
				t.Fatalf("buildHeader() = %v, want an error", header)
			}
			wantErr := tt.wantErr
			if wantErr == nil {
				wantErr = errReservedHeader
			}
			if !errors.Is(err, wantErr) {
				t.Errorf("errors.Is(err, %v) = false; err = %v", wantErr, err)
			}
			if got := err.Error(); got != tt.want {
				t.Errorf("buildHeader() error = %q, want %q", got, tt.want)
			}
			if strings.Contains(err.Error(), hcSecret) || strings.Contains(err.Error(), "Injected") {
				t.Errorf("error text %q holds the header value", err)
			}
			assertNoSecrets(t, err, tt.secrets...)
		})
	}
}

// TestBuildHeaderAcceptsValidBytes checks that buildHeader keeps a name with
// every token punctuation byte, and a value with a tab and bytes of 0x80 and
// up (obs-text, for example UTF-8), exactly as configured.
func TestBuildHeaderAcceptsValidBytes(t *testing.T) {
	t.Parallel()

	const (
		name  = "X-a1!#$%&'*+.^_`|~"
		value = "a\tb \x80\xff é ~"
	)
	header, err := buildHeader(map[string]string{name: value}, "")
	if err != nil {
		t.Fatalf("buildHeader() error = %v, want nil", err)
	}
	if got := header.Get(name); got != value {
		t.Errorf("header %q = %q, want %q", name, got, value)
	}
}

// TestIsHTTPToken checks the HTTP token rule (RFC 9110, section 5.6.2).
func TestIsHTTPToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "plain", in: "X-Api-Key", want: true},
		{name: "letters and digits", in: "abcXYZ019", want: true},
		{name: "every punctuation byte of a token", in: "!#$%&'*+-.^_`|~", want: true},
		{name: "one byte", in: "x", want: true},
		{name: "empty", in: "", want: false},
		{name: "space", in: "X Key", want: false},
		{name: "colon", in: "X-Key:", want: false},
		{name: "tab", in: "X\tKey", want: false},
		{name: "CR", in: "X\rKey", want: false},
		{name: "LF", in: "X\nKey", want: false},
		{name: "NUL", in: "X\x00", want: false},
		{name: "DEL", in: "X\x7f", want: false},
		{name: "non-ASCII", in: "X-Clé", want: false},
		{name: "byte 0x80", in: "X\x80", want: false},
		{name: "quote", in: `X"Key`, want: false},
		{name: "slash", in: "X/Key", want: false},
		{name: "brackets and separators", in: "(),/;<=>?@[\\]{}", want: false},
		{name: "bad byte last", in: "X-Key ", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isHTTPToken(tt.in); got != tt.want {
				t.Errorf("isHTTPToken(%q) = %t, want %t", tt.in, got, tt.want)
			}
		})
	}
	// Each separator alone, so that one byte that slips through is found.
	for _, c := range "\"(),/:;<=>?@[\\]{} \t" {
		if isHTTPToken("X" + string(c)) {
			t.Errorf("isHTTPToken(%q) = true, want false", "X"+string(c))
		}
	}
}

// TestValidHeaderValue checks that a value may hold no control byte other
// than a horizontal tab, and no DEL. Bytes of 0x80 and up (obs-text) are
// allowed, as net/http allows them.
func TestValidHeaderValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "empty", in: "", want: true},
		{name: "plain", in: "Bearer tok-NOTREAL", want: true},
		{name: "tab", in: "a\tb", want: true},
		{name: "space and visible ASCII", in: " !~", want: true},
		{name: "obs-text 0x80", in: "a\x80", want: true},
		{name: "obs-text 0xff", in: "\xff", want: true},
		{name: "UTF-8", in: "café", want: true},
		{name: "CR", in: "a\rb", want: false},
		{name: "LF", in: "a\nb", want: false},
		{name: "CR LF header injection", in: "a\r\nInjected: 1", want: false},
		{name: "NUL", in: "a\x00", want: false},
		{name: "unit separator 0x1f", in: "\x1f", want: false},
		{name: "DEL", in: "a\x7f", want: false},
		{name: "bad byte first", in: "\x01abc", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := validHeaderValue(tt.in); got != tt.want {
				t.Errorf("validHeaderValue(%q) = %t, want %t", tt.in, got, tt.want)
			}
		})
	}
	// Every control byte but the tab, one by one.
	for c := range byte(0x20) {
		if want := c == '\t'; validHeaderValue("a"+string(c)) != want {
			t.Errorf("validHeaderValue(%q) = %t, want %t", "a"+string(c), !want, want)
		}
	}
}

// TestSendsBasicAuth checks the rule that RoundTrip and sentHeaderNames share:
// the URL user info gives a Basic header unless the config set a non-empty
// Authorization header.
func TestSendsBasicAuth(t *testing.T) {
	t.Parallel()

	user := url.UserPassword("user", "pw-NOTREAL")
	tests := []struct {
		name   string
		header http.Header
		user   *url.Userinfo
		want   bool
	}{
		{name: "nil user and nil header", header: nil, user: nil, want: false},
		{name: "nil user and empty Authorization", header: http.Header{"Authorization": {""}}, user: nil, want: false},
		{name: "nil user and no Authorization", header: http.Header{"X-Api-Key": {"k"}}, user: nil, want: false},
		{name: "user and nil header", header: nil, user: user, want: true},
		{name: "user name only", header: http.Header{}, user: url.User("user"), want: true},
		{name: "user and other header only", header: http.Header{"X-Api-Key": {"k"}}, user: user, want: true},
		{name: "user and empty Authorization", header: http.Header{"Authorization": {""}}, user: user, want: true},
		{name: "user and non-empty Authorization", header: http.Header{"Authorization": {"Bearer x"}}, user: user, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sendsBasicAuth(tt.header, tt.user); got != tt.want {
				t.Errorf("sendsBasicAuth(%v, %v) = %t, want %t", tt.header, tt.user, got, tt.want)
			}
		})
	}
}

// proxyHelperEnv marks the child process of TestProxyFromEnvironmentEnv.
const proxyHelperEnv = "MCPMOAT_TEST_PROXY_HELPER"

// proxyHelperPassword is the fake password in the proxy setting of the child
// process. It must never show up in an error text.
const proxyHelperPassword = "s3cr3t-NOTREAL-proxy"

// TestProxyFromEnvironmentEnv runs TestProxyFromEnvironmentChild in a child
// process with proxy variables that make http.ProxyFromEnvironment fail.
// net/http reads the variables only once per process (a sync.Once), so
// t.Setenv cannot change them inside this test binary.
//
// With the toolchain of go.mod, x/net/http/httpproxy drops a proxy value that
// does not parse, so the error that the child can trigger is the refusal of
// HTTP_PROXY in a CGI environment (REQUEST_METHOD set).
func TestProxyFromEnvironmentEnv(t *testing.T) {
	t.Parallel()
	if os.Getenv(proxyHelperEnv) != "" {
		t.Skip("this is the child process")
	}

	// os.Args[0] is this test binary; the arguments are fixed.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestProxyFromEnvironmentChild$", "-test.count=1", "-test.v") //nolint:gosec // G204: re-runs this test binary with fixed arguments
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "REQUEST_METHOD":
			return true
		}
		return false
	})
	cmd.Env = append(env,
		proxyHelperEnv+"=1",
		"REQUEST_METHOD=GET",
		"HTTP_PROXY=http://alice:"+proxyHelperPassword+"@proxy.invalid:8080",
		"HTTPS_PROXY=http://proxy.invalid:3128",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child process failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: TestProxyFromEnvironmentChild") {
		t.Fatalf("child process did not run TestProxyFromEnvironmentChild:\n%s", out)
	}
}

// TestProxyFromEnvironmentChild is the child of TestProxyFromEnvironmentEnv.
// It skips unless that test started it.
func TestProxyFromEnvironmentChild(t *testing.T) {
	if os.Getenv(proxyHelperEnv) == "" {
		t.Skip("runs only as the child of TestProxyFromEnvironmentEnv")
	}
	plainReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:1/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, goErr := http.ProxyFromEnvironment(plainReq); goErr == nil {
		t.Fatal("http.ProxyFromEnvironment() error = nil; the environment does not trigger the error, so the test checks nothing")
	}

	t.Run("error is the fixed sentinel", func(t *testing.T) {
		proxy, err := proxyFromEnvironment(plainReq)
		if err != errInvalidProxy { //nolint:errorlint // the function returns the bare sentinel
			t.Errorf("proxyFromEnvironment() error = %v, want errInvalidProxy", err)
		}
		if proxy != nil {
			t.Errorf("proxyFromEnvironment() proxy = %v, want nil", proxy)
		}
	})

	t.Run("a proxy without an error passes through", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://mcp.example.com/mcp", nil)
		if err != nil {
			t.Fatal(err)
		}
		proxy, err := proxyFromEnvironment(req)
		if err != nil {
			t.Fatalf("proxyFromEnvironment() error = %v, want nil", err)
		}
		if proxy == nil || proxy.String() != "http://proxy.invalid:3128" {
			t.Errorf("proxyFromEnvironment() proxy = %v, want http://proxy.invalid:3128", proxy)
		}
	})

	// Remote with the real base transport: the proxy error is a config error
	// with a fixed reason, no request reaches the server, and no secret of
	// the proxy setting or of the server entry is in the error.
	for _, sse := range []bool{false, true} {
		t.Run("Remote/"+string(rmKind(sse)), func(t *testing.T) {
			ts, rec := startFixture(t, fixtureOpts{SSE: sse})
			srv := rmServer(rmKind(sse), rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
			_, err := Remote(t.Context(), srv, RemoteOptions{})
			ce := rmRequireConnectError(t, err, KindConfig)
			if ce.Reason != errInvalidProxy.Error() {
				t.Errorf("Reason = %q, want %q", ce.Reason, errInvalidProxy.Error())
			}
			assertNoSecrets(t, err, proxyHelperPassword, "alice", "proxy.invalid", "cgihttpproxy")
			if n := len(rec.requests()); n != 0 {
				t.Errorf("server got %d request(s), want 0", n)
			}
		})
	}
}

// TestHeaderTransportNilHeader calls RoundTrip directly with a request that
// has no Header map. http.Client always sets one, but a RoundTripper must not
// panic on a request that a direct caller built.
func TestHeaderTransportNilHeader(t *testing.T) {
	t.Parallel()

	const pass = "nilhdr-pw" //nolint:gosec // G101: fake test credential
	tests := []struct {
		name string
		user *url.Userinfo
		want http.Header
	}{
		{
			name: "config headers",
			want: http.Header{"X-Api-Key": {hcSecret}, "User-Agent": {hcUA}},
		},
		{
			name: "config headers and user info",
			user: url.UserPassword("u", pass),
			want: http.Header{
				"X-Api-Key":     {hcSecret},
				"User-Agent":    {hcUA},
				"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("u:"+pass))},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stub := &hcStub{}
			client, _, err := newHTTPClient(httpClientConfig{
				Endpoint:  hcURL(t, "http://example.com"),
				Headers:   map[string]string{"x-api-key": hcSecret},
				User:      tt.user,
				Base:      stub,
				UserAgent: hcUA,
			})
			if err != nil {
				t.Fatal(err)
			}
			ht, ok := client.Transport.(*headerTransport)
			if !ok {
				t.Fatalf("client.Transport is %T, want *headerTransport", client.Transport)
			}

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/mcp", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header = nil
			resp, err := ht.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip() error = %v", err)
			}
			_ = resp.Body.Close()

			if stub.count() != 1 {
				t.Fatalf("base got %d request(s), want 1", stub.count())
			}
			if got := stub.header(0); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("base saw header %v, want %v", got, tt.want)
			}
			if req.Header != nil {
				t.Errorf("caller request Header = %v, want it left nil", req.Header)
			}
		})
	}
}

// hcIdleCloser is a base RoundTripper that counts CloseIdleConnections calls.
type hcIdleCloser struct {
	hcStub
	closed atomic.Int32
}

func (c *hcIdleCloser) CloseIdleConnections() { c.closed.Add(1) }

func TestHeaderTransportCloseIdleConnections(t *testing.T) {
	t.Parallel()

	t.Run("reaches the base transport", func(t *testing.T) {
		t.Parallel()
		base := &hcIdleCloser{}
		client, _, err := hcNew(hcURL(t, "http://example.com"), nil, base, hcUA, 0)
		if err != nil {
			t.Fatal(err)
		}
		// http.Client.CloseIdleConnections calls the method only if the
		// client transport (the headerTransport) has it.
		client.CloseIdleConnections()
		if got := base.closed.Load(); got != 1 {
			t.Errorf("base CloseIdleConnections calls = %d, want 1", got)
		}
		client.CloseIdleConnections()
		if got := base.closed.Load(); got != 2 {
			t.Errorf("base CloseIdleConnections calls = %d, want 2", got)
		}
	})

	t.Run("base without the method does not panic", func(t *testing.T) {
		t.Parallel()
		base := &hcStub{}
		client, _, err := hcNew(hcURL(t, "http://example.com"), nil, base, hcUA, 0)
		if err != nil {
			t.Fatal(err)
		}
		client.CloseIdleConnections()
		// The client still works afterwards.
		resp := hcGet(t, client, "http://example.com/")
		_ = resp.Body.Close()
		if got := base.count(); got != 1 {
			t.Errorf("base got %d request(s), want 1", got)
		}
	})

	t.Run("closes the idle connections of the default base", func(t *testing.T) {
		t.Parallel()
		closed := make(chan struct{})
		var once sync.Once
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "ok")
		}))
		ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				once.Do(func() { close(closed) })
			}
		}
		ts.Start()
		t.Cleanup(ts.Close)

		client, _, err := hcNew(hcURL(t, ts.URL), nil, nil, hcUA, 0)
		if err != nil {
			t.Fatal(err)
		}
		resp := hcGet(t, client, ts.URL+"/")
		// Read the body to the end, so the connection goes back to the pool.
		if _, err := io.ReadAll(resp.Body); err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()

		client.CloseIdleConnections()
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Fatal("the idle connection is still open, want it closed")
		}
	})
}

func TestCappedBodySharedBudgetOnOverflow(t *testing.T) {
	t.Parallel()

	const maxTotal = 1000

	tests := []struct {
		name      string
		remaining int64
		used      int64 // bytes of the shared budget already used
		bodyLen   int
		want      int // bytes that the first Read returns
	}{
		// The read gets remaining+1 = 101 bytes: over the body cap. Only 10
		// bytes of the shared budget are left, so only 10 come back.
		{name: "budget smaller than the body cap", remaining: 100, used: maxTotal - 10, bodyLen: 200, want: 10},
		{name: "budget used up", remaining: 100, used: maxTotal, bodyLen: 200, want: 0},
		{name: "budget exactly the body cap", remaining: 100, used: maxTotal - 100, bodyLen: 200, want: 100},
		{name: "budget larger than the body cap", remaining: 100, used: 0, bodyLen: 200, want: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var used atomic.Int64
			used.Store(tt.used)
			rec := &requestRecorder{}
			body := &cappedBody{
				r:         io.NopCloser(strings.NewReader(strings.Repeat("a", tt.bodyLen))),
				remaining: tt.remaining,
				used:      &used,
				maxTotal:  maxTotal,
				rec:       rec,
			}

			p := make([]byte, tt.bodyLen)
			n, err := body.Read(p)
			if n != tt.want {
				t.Errorf("Read() n = %d, want %d", n, tt.want)
			}
			if !errors.Is(err, errBodyTooLarge) {
				t.Errorf("Read() error = %v, want errBodyTooLarge", err)
			}
			if !errors.Is(rec.blockedErr(), errBodyTooLarge) {
				t.Errorf("blockedErr() = %v, want errBodyTooLarge", rec.blockedErr())
			}
			// Later reads return the same error and no bytes.
			for range 2 {
				n, err := body.Read(p)
				if n != 0 || !errors.Is(err, errBodyTooLarge) {
					t.Errorf("later Read() = %d, %v; want 0, errBodyTooLarge", n, err)
				}
			}
		})
	}
}

// hcDo sends a request with method to rawURL, reads the whole body and
// closes it. A non-nil rec goes on the request context (withRecorder); a nil
// rec sends the request without a record. It returns the bytes that were
// read and the read error. A request error stops the test.
func hcDo(t *testing.T, client *http.Client, rec *requestRecorder, method, rawURL string) ([]byte, error) {
	t.Helper()
	ctx := t.Context()
	if rec != nil {
		ctx = withRecorder(ctx, rec)
	}
	var body io.Reader
	if method == http.MethodPost {
		// A strings.Reader lets http.NewRequest set GetBody, so a 307
		// redirect can send the body again.
		body = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}

// hcWaitBoth returns a function that blocks until it was called twice, so
// that two requests in a base RoundTripper overlap. It gives up after a
// timeout, so a broken test fails instead of hanging.
func hcWaitBoth() func() {
	var n atomic.Int32
	both := make(chan struct{})
	return func() {
		if n.Add(1) == 2 {
			close(both)
		}
		select {
		case <-both:
		case <-time.After(5 * time.Second):
		}
	}
}

// TestHeaderTransportPerRequestRecords checks that each request writes its
// status and its blocked error into the record on its context (issue #100),
// and that a request without a record writes into the fallback record of
// httpEvents.
func TestHeaderTransportPerRequestRecords(t *testing.T) {
	t.Parallel()

	const origin = "http://example.com"

	t.Run("overlapping requests keep their own status", func(t *testing.T) {
		t.Parallel()
		wait := hcWaitBoth()
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			// Both requests are in the base at the same time. With one
			// shared record, the status of the request that ends last
			// would show in both.
			wait()
			if req.URL.Path == "/fail" {
				return hcResponse(req, http.StatusInternalServerError, "boom", nil)
			}
			return hcResponse(req, http.StatusOK, "ok", nil)
		}}
		client, ev, err := hcNew(hcURL(t, origin), nil, stub, hcUA, 0)
		if err != nil {
			t.Fatal(err)
		}

		recFail, recOK := &requestRecorder{}, &requestRecorder{}
		var wg sync.WaitGroup
		for _, c := range []struct {
			rec  *requestRecorder
			path string
		}{{recFail, "/fail"}, {recOK, "/ok"}} {
			wg.Go(func() {
				req, err := http.NewRequestWithContext(withRecorder(t.Context(), c.rec), http.MethodGet, origin+c.path, nil)
				if err != nil {
					t.Error(err)
					return
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Errorf("GET %s: %v", c.path, err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			})
		}
		wg.Wait()

		if got := recFail.lastStatus(); got != http.StatusInternalServerError {
			t.Errorf("record of /fail: lastStatus() = %d, want 500", got)
		}
		if got := recOK.lastStatus(); got != 0 {
			t.Errorf("record of /ok: lastStatus() = %d, want 0", got)
		}
		if got := ev.fallback.lastStatus(); got != 0 {
			t.Errorf("fallback lastStatus() = %d, want 0: both requests had a record", got)
		}
	})

	t.Run("overlapping requests keep their own blocked error", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			return hcResponse(req, http.StatusFound, "", http.Header{"Location": {"http://evil.test/"}})
		}}
		client, ev, err := hcNew(hcURL(t, origin), nil, stub, hcUA, 0)
		if err != nil {
			t.Fatal(err)
		}

		recOrigin, recRedirect := &requestRecorder{}, &requestRecorder{}
		var wg sync.WaitGroup
		wg.Go(func() {
			// The request goes to another origin: RoundTrip refuses it.
			req, err := http.NewRequestWithContext(withRecorder(t.Context(), recOrigin), http.MethodGet, "http://evil.test/", nil)
			if err != nil {
				t.Error(err)
				return
			}
			if resp, err := client.Do(req); !errors.Is(err, errOtherOrigin) {
				if resp != nil {
					_ = resp.Body.Close()
				}
				t.Errorf("GET evil.test: error = %v, want errOtherOrigin", err)
			}
		})
		wg.Go(func() {
			// The request goes to the origin, which redirects elsewhere:
			// CheckRedirect refuses it.
			req, err := http.NewRequestWithContext(withRecorder(t.Context(), recRedirect), http.MethodGet, origin+"/", nil)
			if err != nil {
				t.Error(err)
				return
			}
			if resp, err := client.Do(req); !errors.Is(err, errCrossOriginRedirect) {
				if resp != nil {
					_ = resp.Body.Close()
				}
				t.Errorf("GET origin: error = %v, want errCrossOriginRedirect", err)
			}
		})
		wg.Wait()

		if got := recOrigin.blockedErr(); !errors.Is(got, errOtherOrigin) || errors.Is(got, errCrossOriginRedirect) {
			t.Errorf("record of the other-origin request: blockedErr() = %v, want errOtherOrigin only", got)
		}
		if got := recRedirect.blockedErr(); !errors.Is(got, errCrossOriginRedirect) || errors.Is(got, errOtherOrigin) {
			t.Errorf("record of the redirected request: blockedErr() = %v, want errCrossOriginRedirect only", got)
		}
		if got := ev.fallback.blockedErr(); got != nil {
			t.Errorf("fallback blockedErr() = %v, want nil: both requests had a record", got)
		}
	})

	t.Run("request without a record uses the fallback", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			if req.URL.Path == "/fail" {
				return hcResponse(req, http.StatusInternalServerError, "boom", nil)
			}
			return hcResponse(req, http.StatusOK, "ok", nil)
		}}
		client, ev, err := hcNew(hcURL(t, origin), nil, stub, hcUA, 0)
		if err != nil {
			t.Fatal(err)
		}

		// t.Context() carries no record.
		if _, err := hcDo(t, client, nil, http.MethodGet, origin+"/fail"); err != nil {
			t.Fatal(err)
		}
		hcMustFail(t, client, "http://evil.test/", errOtherOrigin)
		if got := ev.fallback.lastStatus(); got != http.StatusInternalServerError {
			t.Errorf("fallback lastStatus() = %d, want 500", got)
		}
		if got := ev.fallback.blockedErr(); !errors.Is(got, errOtherOrigin) {
			t.Errorf("fallback blockedErr() = %v, want errOtherOrigin", got)
		}

		// A later request with a record must not touch the fallback.
		rec := &requestRecorder{}
		if _, err := hcDo(t, client, rec, http.MethodGet, origin+"/ok"); err != nil {
			t.Fatal(err)
		}
		if got := ev.fallback.lastStatus(); got != http.StatusInternalServerError {
			t.Errorf("fallback lastStatus() = %d after a request with a record, want 500", got)
		}
		if got := rec.lastStatus(); got != 0 {
			t.Errorf("record lastStatus() = %d, want 0", got)
		}
		if got := rec.blockedErr(); got != nil {
			t.Errorf("record blockedErr() = %v, want nil", got)
		}
	})

	t.Run("redirects write into the record of the first request", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name     string
			location string // Location of every 302; empty: 302 once, then 500
			want     error
			status   int
		}{
			{name: "cross-origin redirect", location: "http://evil.test/", want: errCrossOriginRedirect},
			{name: "too many redirects", location: "/again", want: errTooManyRedirects},
			{name: "same-origin redirect to a 500", status: http.StatusInternalServerError},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				stub := &hcStub{respond: func(req *http.Request) *http.Response {
					switch {
					case tt.location != "":
						return hcResponse(req, http.StatusFound, "", http.Header{"Location": {tt.location}})
					case req.URL.Path == "/":
						return hcResponse(req, http.StatusFound, "", http.Header{"Location": {"/next"}})
					}
					return hcResponse(req, http.StatusInternalServerError, "boom", nil)
				}}
				client, ev, err := hcNew(hcURL(t, origin), nil, stub, hcUA, 0)
				if err != nil {
					t.Fatal(err)
				}
				rec := &requestRecorder{}
				req, err := http.NewRequestWithContext(withRecorder(t.Context(), rec), http.MethodGet, origin+"/", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if tt.want != nil && !errors.Is(err, tt.want) {
					t.Fatalf("client.Do() error = %v, want %v", err, tt.want)
				}
				if got := rec.blockedErr(); !errors.Is(got, tt.want) || (tt.want == nil && got != nil) {
					t.Errorf("record blockedErr() = %v, want %v", got, tt.want)
				}
				if got := rec.lastStatus(); got != tt.status {
					t.Errorf("record lastStatus() = %d, want %d", got, tt.status)
				}
				if got := ev.fallback.blockedErr(); got != nil {
					t.Errorf("fallback blockedErr() = %v, want nil", got)
				}
				if got := ev.fallback.lastStatus(); got != 0 {
					t.Errorf("fallback lastStatus() = %d, want 0", got)
				}
			})
		}
	})

	t.Run("body cap writes into the record of the request", func(t *testing.T) {
		t.Parallel()
		stub := &hcStub{respond: func(req *http.Request) *http.Response {
			return hcResponse(req, http.StatusOK, "0123456789", nil)
		}}
		client, ev, err := hcNew(hcURL(t, origin), nil, stub, hcUA, 4)
		if err != nil {
			t.Fatal(err)
		}
		rec, other := &requestRecorder{}, &requestRecorder{}
		if _, err := hcDo(t, client, rec, http.MethodGet, origin+"/"); !errors.Is(err, errBodyTooLarge) {
			t.Fatalf("read body: error = %v, want errBodyTooLarge", err)
		}
		if got := rec.blockedErr(); !errors.Is(got, errBodyTooLarge) {
			t.Errorf("record blockedErr() = %v, want errBodyTooLarge", got)
		}
		if got := other.blockedErr(); got != nil {
			t.Errorf("unused record blockedErr() = %v, want nil", got)
		}
		if got := ev.fallback.blockedErr(); got != nil {
			t.Errorf("fallback blockedErr() = %v, want nil", got)
		}
	})
}

// hcRedirectChain returns the last request of a redirect chain whose
// requests have the given methods, oldest first. It links the requests the
// way http.Client does: each redirected request has Response set to the
// redirect response, and the Request of that response is the request before.
func hcRedirectChain(t *testing.T, methods ...string) *http.Request {
	t.Helper()
	var prev *http.Request
	for _, method := range methods {
		req, err := http.NewRequestWithContext(t.Context(), method, "http://example.com/mcp", nil)
		if err != nil {
			t.Fatal(err)
		}
		if prev != nil {
			req.Response = &http.Response{StatusCode: http.StatusSeeOther, Request: prev}
		}
		prev = req
	}
	return prev
}

func TestShapeFor(t *testing.T) {
	t.Parallel()

	const noCT = "\x00none" // marker: the response has no Content-Type header

	tests := []struct {
		name     string
		methods  []string // methods of the redirect chain, oldest first
		status   int
		ct       string
		location string // Location header, for a redirect status
		want     bodyShape
	}{
		{name: "POST json", methods: []string{"POST"}, status: 200, ct: "application/json", want: bodyShapeJSON},
		{name: "POST json with charset", methods: []string{"POST"}, status: 200, ct: "application/json; charset=utf-8", want: bodyShapeJSON},
		{name: "POST json in mixed case", methods: []string{"POST"}, status: 200, ct: "Application/JSON", want: bodyShapeJSON},
		{name: "POST event-stream", methods: []string{"POST"}, status: 200, ct: "text/event-stream", want: bodyShapeSSE},
		{name: "POST event-stream in upper case with charset", methods: []string{"POST"}, status: 200, ct: "TEXT/EVENT-STREAM; charset=utf-8", want: bodyShapeSSE},
		{name: "POST text/plain", methods: []string{"POST"}, status: 200, ct: "text/plain", want: bodyShapeNone},
		{name: "POST problem+json", methods: []string{"POST"}, status: 200, ct: "application/problem+json", want: bodyShapeNone},
		{name: "POST json-seq", methods: []string{"POST"}, status: 200, ct: "application/json-seq", want: bodyShapeNone},
		{name: "POST unparsable: no type", methods: []string{"POST"}, status: 200, ct: "/json", want: bodyShapeNone},
		{name: "POST unparsable: bad parameter", methods: []string{"POST"}, status: 200, ct: "application/json; charset", want: bodyShapeNone},
		{name: "POST empty Content-Type", methods: []string{"POST"}, status: 200, ct: "", want: bodyShapeNone},
		{name: "POST missing Content-Type", methods: []string{"POST"}, status: 200, ct: noCT, want: bodyShapeNone},

		// Status 2xx: the body is decoded as messages, by Content-Type.
		{name: "POST 204 json", methods: []string{"POST"}, status: 204, ct: "application/json", want: bodyShapeJSON},
		{name: "POST 299 json", methods: []string{"POST"}, status: 299, ct: "application/json", want: bodyShapeJSON},

		// Non-2xx: checkResponse in the SDK reads the body and decodes it as
		// one JSON-RPC message, whatever the Content-Type and the method
		// (security case: a deep "id" decodes to a huge amount of memory).
		{name: "POST 199 json", methods: []string{"POST"}, status: 199, ct: "application/json", want: bodyShapeJSON},
		{name: "POST 300 without Location", methods: []string{"POST"}, status: 300, ct: "application/json", want: bodyShapeJSON},
		{name: "POST 400 json", methods: []string{"POST"}, status: 400, ct: "application/json", want: bodyShapeJSON},
		{name: "POST 400 text/plain", methods: []string{"POST"}, status: 400, ct: "text/plain", want: bodyShapeJSON},
		{name: "POST 400 event-stream", methods: []string{"POST"}, status: 400, ct: "text/event-stream", want: bodyShapeJSON},
		{name: "POST 401 json", methods: []string{"POST"}, status: 401, ct: "application/json", want: bodyShapeJSON},
		{name: "POST 401 missing Content-Type", methods: []string{"POST"}, status: 401, ct: noCT, want: bodyShapeJSON},
		{name: "POST 404 json", methods: []string{"POST"}, status: 404, ct: "application/json", want: bodyShapeJSON},
		{name: "POST 404 unparsable Content-Type", methods: []string{"POST"}, status: 404, ct: "/json", want: bodyShapeJSON},
		{name: "POST 405 text/html", methods: []string{"POST"}, status: 405, ct: "text/html", want: bodyShapeJSON},
		{name: "POST 501 json", methods: []string{"POST"}, status: 501, ct: "application/json", want: bodyShapeJSON},
		{name: "GET 400 event-stream", methods: []string{"GET"}, status: 400, ct: "text/event-stream", want: bodyShapeJSON},
		{name: "GET 401 json", methods: []string{"GET"}, status: 401, ct: "application/json", want: bodyShapeJSON},
		{name: "GET 404 event-stream", methods: []string{"GET"}, status: 404, ct: "text/event-stream", want: bodyShapeJSON},
		{name: "GET 404 missing Content-Type", methods: []string{"GET"}, status: 404, ct: noCT, want: bodyShapeJSON},
		{name: "303 POST to GET 404 text/plain", methods: []string{"POST", "GET"}, status: 404, ct: "text/plain", want: bodyShapeJSON},

		// Non-2xx that the SDK never reads: the transient statuses of
		// checkResponse (isTransientHTTPStatus in go-sdk v1.8.0).
		{name: "POST 429 json", methods: []string{"POST"}, status: 429, ct: "application/json", want: bodyShapeNone},
		{name: "POST 500 json", methods: []string{"POST"}, status: 500, ct: "application/json", want: bodyShapeNone},
		{name: "POST 500 event-stream", methods: []string{"POST"}, status: 500, ct: "text/event-stream", want: bodyShapeNone},
		{name: "POST 502 json", methods: []string{"POST"}, status: 502, ct: "application/json", want: bodyShapeNone},
		{name: "POST 503 json", methods: []string{"POST"}, status: 503, ct: "application/json", want: bodyShapeNone},
		{name: "POST 504 json", methods: []string{"POST"}, status: 504, ct: "application/json", want: bodyShapeNone},
		{name: "GET 429", methods: []string{"GET"}, status: 429, ct: "text/event-stream", want: bodyShapeNone},
		{name: "GET 500", methods: []string{"GET"}, status: 500, ct: "text/event-stream", want: bodyShapeNone},
		{name: "GET 503", methods: []string{"GET"}, status: 503, ct: "text/event-stream", want: bodyShapeNone},
		{name: "303 POST to GET 500", methods: []string{"POST", "GET"}, status: 500, ct: "application/json", want: bodyShapeNone},

		// Non-2xx to a DELETE: the SDK closes that body without reading it.
		// The method of the first request decides.
		{name: "DELETE 400 json", methods: []string{"DELETE"}, status: 400, ct: "application/json", want: bodyShapeNone},
		{name: "DELETE 404 text/plain", methods: []string{"DELETE"}, status: 404, ct: "text/plain", want: bodyShapeNone},
		{name: "307 DELETE to DELETE 404 json", methods: []string{"DELETE", "DELETE"}, status: 404, ct: "application/json", want: bodyShapeNone},
		{name: "303 DELETE to GET 404 json", methods: []string{"DELETE", "GET"}, status: 404, ct: "application/json", want: bodyShapeNone},

		// A redirect that the http.Client follows: the SDK never gets the
		// body.
		{name: "POST 302 with Location", methods: []string{"POST"}, status: 302, ct: "application/json", location: "/next", want: bodyShapeNone},
		{name: "GET 307 with Location", methods: []string{"GET"}, status: 307, ct: "application/json", location: "/next", want: bodyShapeNone},
		{name: "POST 302 without Location", methods: []string{"POST"}, status: 302, ct: "application/json", want: bodyShapeJSON},

		// 2xx DELETE: unchanged, by Content-Type.
		{name: "DELETE 200 json", methods: []string{"DELETE"}, status: 200, ct: "application/json", want: bodyShapeJSON},

		// GET: the legacy SSE transport parses its GET stream as SSE whatever
		// the Content-Type.
		{name: "GET event-stream", methods: []string{"GET"}, status: 200, ct: "text/event-stream", want: bodyShapeSSE},
		{name: "legacy GET with json Content-Type", methods: []string{"GET"}, status: 200, ct: "application/json", want: bodyShapeSSE},
		{name: "GET text/plain", methods: []string{"GET"}, status: 200, ct: "text/plain", want: bodyShapeSSE},
		{name: "GET missing Content-Type", methods: []string{"GET"}, status: 200, ct: noCT, want: bodyShapeSSE},

		// Redirects: the method of the first request decides. A 303 turns a
		// POST into a GET, but the SDK still picks its parser by the
		// Content-Type, so the JSON check must stay (security case).
		{name: "303 POST to GET json", methods: []string{"POST", "GET"}, status: 200, ct: "application/json", want: bodyShapeJSON},
		{name: "303 POST to GET event-stream", methods: []string{"POST", "GET"}, status: 200, ct: "text/event-stream", want: bodyShapeSSE},
		{name: "303 POST to GET text/plain", methods: []string{"POST", "GET"}, status: 200, ct: "text/plain", want: bodyShapeNone},
		{name: "303 POST to GET 500", methods: []string{"POST", "GET"}, status: 500, ct: "application/json", want: bodyShapeNone},
		{name: "two hops POST to GET json", methods: []string{"POST", "GET", "GET"}, status: 200, ct: "application/json", want: bodyShapeJSON},
		{name: "most hops the client follows", methods: []string{"POST", "GET", "GET", "GET"}, status: 200, ct: "application/json", want: bodyShapeJSON},
		{name: "307 POST to POST json", methods: []string{"POST", "POST"}, status: 200, ct: "application/json", want: bodyShapeJSON},
		{name: "redirected GET with json Content-Type", methods: []string{"GET", "GET"}, status: 200, ct: "application/json", want: bodyShapeSSE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := hcRedirectChain(t, tt.methods...)
			header := http.Header{}
			if tt.ct != noCT {
				header.Set("Content-Type", tt.ct)
			}
			if tt.location != "" {
				header.Set("Location", tt.location)
			}
			resp := &http.Response{StatusCode: tt.status, Header: header, Request: req}
			if got := shapeFor(req, resp); got != tt.want {
				t.Errorf("shapeFor(%v, %d, %q) = %d, want %d", tt.methods, tt.status, tt.ct, got, tt.want)
			}
		})
	}
}

func TestShapeForFirstRequest(t *testing.T) {
	t.Parallel()

	t.Run("no redirect", func(t *testing.T) {
		t.Parallel()
		req := hcRedirectChain(t, "POST")
		if got := firstRequest(req); got != req {
			t.Errorf("firstRequest() = %p, want the request itself %p", got, req)
		}
	})

	t.Run("response without a request", func(t *testing.T) {
		t.Parallel()
		req := hcRedirectChain(t, "GET")
		req.Response = &http.Response{StatusCode: http.StatusSeeOther}
		if got := firstRequest(req); got != req {
			t.Errorf("firstRequest() = %p, want the request itself %p", got, req)
		}
	})

	t.Run("chain of the most redirects the client follows", func(t *testing.T) {
		t.Parallel()
		// maxRedirects redirects give maxRedirects+1 requests.
		methods := make([]string, maxRedirects+1)
		for i := range methods {
			methods[i] = http.MethodGet
		}
		methods[0] = http.MethodPost
		if got := firstRequest(hcRedirectChain(t, methods...)); got.Method != http.MethodPost {
			t.Errorf("firstRequest().Method = %s, want POST (the first request)", got.Method)
		}
	})

	t.Run("a cycle ends", func(t *testing.T) {
		t.Parallel()
		// A chain built by hand can point back to itself. firstRequest must
		// stop anyway.
		req := hcRedirectChain(t, "POST")
		req.Response = &http.Response{StatusCode: http.StatusSeeOther, Request: req}
		if got := firstRequest(req); got != req {
			t.Errorf("firstRequest() = %p, want %p", got, req)
		}
	})
}

// hcEnvelopeValues is the number of JSON values in the envelope that
// hcRPCList writes around its array: the outer object, the keys jsonrpc, id,
// result and tools, the values "2.0" and 1, the result object and the array.
const hcEnvelopeValues = 9

// hcRPCList returns a JSON-RPC response whose result.tools array has n empty
// objects. The whole message has hcEnvelopeValues+n JSON values, about 3
// bytes on the wire for each object.
func hcRPCList(n int) string {
	var b strings.Builder
	b.WriteString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[`)
	if n > 0 {
		b.WriteString(strings.Repeat("{},", n-1))
		b.WriteString("{}")
	}
	b.WriteString("]}}")
	return b.String()
}

// hcDeepIDEnvelopeValues is the number of JSON values in the envelope that
// hcRPCDeepID writes around its array: the outer object, the keys jsonrpc
// and id, the value "2.0" and the array.
const hcDeepIDEnvelopeValues = 5

// hcRPCDeepID returns a JSON-RPC message whose id is an array of n empty
// objects: the attack body of a non-2xx answer, which the SDK decodes into a
// struct with an "ID any" field. The whole message has
// hcDeepIDEnvelopeValues+n JSON values.
func hcRPCDeepID(n int) string {
	var b strings.Builder
	b.WriteString(`{"jsonrpc":"2.0","id":[`)
	if n > 0 {
		b.WriteString(strings.Repeat("{},", n-1))
		b.WriteString("{}")
	}
	b.WriteString("]}")
	return b.String()
}

// hcRPCUnauthorized is a small, normal JSON-RPC error body of a 401 answer.
const hcRPCUnauthorized = `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"unauthorized"}}`

// hcServed is one answer of the test server in TestShapeBodyEndToEnd.
type hcServed struct {
	status   int
	ct       string
	body     string
	location string // for a redirect status
}

// TestShapeBodyEndToEnd runs the shape check through newHTTPClient, the real
// base transport and an httptest server, with the real limits of jsonshape.go.
func TestShapeBodyEndToEnd(t *testing.T) {
	t.Parallel()

	// overLimit has one value more than MaxJSONValues, atLimit has exactly
	// MaxJSONValues. Both are about 300 KB, far below the 8 MiB body cap, so
	// only the shape check can refuse them.
	overLimit := hcRPCList(MaxJSONValues - hcEnvelopeValues + 1)
	atLimit := hcRPCList(MaxJSONValues - hcEnvelopeValues)
	deepOver := hcRPCDeepID(MaxJSONValues - hcDeepIDEnvelopeValues + 1)
	deepAt := hcRPCDeepID(MaxJSONValues - hcDeepIDEnvelopeValues)

	served := map[string]hcServed{
		"/json-over":         {status: 200, ct: "application/json", body: overLimit},
		"/json-at":           {status: 200, ct: "application/json", body: atLimit},
		"/json-charset-over": {status: 200, ct: "application/json; charset=utf-8", body: overLimit},
		"/sse-over":          {status: 200, ct: "text/event-stream", body: sseMessageEvent(overLimit)},
		"/sse-at":            {status: 200, ct: "text/event-stream", body: sseMessageEvent(atLimit)},
		"/sse-two-at":        {status: 200, ct: "text/event-stream", body: sseMessageEvent(atLimit) + sseMessageEvent(atLimit)},
		"/json-500-over":     {status: 500, ct: "application/json", body: overLimit},
		"/json-404-over":     {status: 404, ct: "application/json", body: overLimit},
		"/deep-400-over":     {status: 400, ct: "application/json", body: deepOver},
		"/deep-400-at":       {status: 400, ct: "application/json", body: deepAt},
		"/deep-400-plain":    {status: 400, ct: "text/plain", body: deepOver},
		"/deep-400-no-ct":    {status: 400, body: deepOver},
		"/deep-404-sse":      {status: 404, ct: "text/event-stream", body: deepOver},
		"/deep-429-over":     {status: 429, ct: "application/json", body: deepOver},
		"/deep-503-over":     {status: 503, ct: "application/json", body: deepOver},
		"/unauthorized":      {status: 401, ct: "application/json", body: hcRPCUnauthorized},
		"/plain-over":        {status: 200, ct: "text/plain", body: overLimit},
		"/get-json-raw":      {status: 200, ct: "application/json", body: overLimit},
		"/get-json-sse":      {status: 200, ct: "application/json", body: sseMessageEvent(overLimit)},
		"/see-other-json":    {status: 303, location: "/json-over"},
		"/see-other-sse":     {status: 303, location: "/sse-over"},
		"/see-other-at":      {status: 303, location: "/json-at"},
		"/temporary-json":    {status: 307, location: "/json-over"},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := served[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		if s.location != "" {
			w.Header().Set("Location", s.location)
		}
		if s.ct != "" {
			w.Header().Set("Content-Type", s.ct)
		}
		w.WriteHeader(s.status)
		_, _ = io.WriteString(w, s.body)
	}))
	t.Cleanup(ts.Close)

	srv := discover.Server{Name: "remote", Transport: discover.TransportHTTP, URL: discover.NewURL(ts.URL)}

	tests := []struct {
		name    string
		method  string
		path    string
		wantErr bool   // the read must fail with errJSONTooComplex
		body    string // the full body when wantErr is false
		status  int    // lastStatus of the record
	}{
		{name: "POST json over the limit", method: "POST", path: "/json-over", wantErr: true},
		{name: "POST json with charset over the limit", method: "POST", path: "/json-charset-over", wantErr: true},
		{name: "POST json at the limit", method: "POST", path: "/json-at", body: atLimit},
		{name: "POST SSE over the limit", method: "POST", path: "/sse-over", wantErr: true},
		{name: "POST SSE at the limit", method: "POST", path: "/sse-at", body: sseMessageEvent(atLimit)},
		{name: "POST SSE: the limit is per event", method: "POST", path: "/sse-two-at", body: sseMessageEvent(atLimit) + sseMessageEvent(atLimit)},
		{name: "GET SSE over the limit", method: "GET", path: "/sse-over", wantErr: true},
		{name: "legacy GET with json Content-Type is checked as SSE", method: "GET", path: "/get-json-sse", wantErr: true},
		// Not a message for the SDK: the legacy GET stream has no data
		// field, so nothing is decoded and nothing is counted.
		{name: "legacy GET with raw json is not a message", method: "GET", path: "/get-json-raw", body: overLimit},
		// Security case: the SDK decodes a non-2xx body as one JSON-RPC
		// message, whatever the Content-Type, so the check must stay. A
		// deep "id" would decode to a huge amount of memory.
		{name: "POST 400 deep id over the limit", method: "POST", path: "/deep-400-over", wantErr: true, status: 400},
		{name: "POST 400 deep id at the limit", method: "POST", path: "/deep-400-at", body: deepAt, status: 400},
		{name: "POST 400 text/plain deep id over the limit", method: "POST", path: "/deep-400-plain", wantErr: true, status: 400},
		{name: "POST 400 deep id without Content-Type", method: "POST", path: "/deep-400-no-ct", wantErr: true, status: 400},
		{name: "POST 404 json over the limit", method: "POST", path: "/json-404-over", wantErr: true, status: 404},
		{name: "GET 404 event-stream deep id over the limit", method: "GET", path: "/deep-404-sse", wantErr: true, status: 404},
		{name: "POST 401 small JSON-RPC error", method: "POST", path: "/unauthorized", body: hcRPCUnauthorized, status: 401},
		// The SDK never reads these bodies: transient statuses and DELETE.
		{name: "POST 500 is not checked", method: "POST", path: "/json-500-over", body: overLimit, status: 500},
		{name: "POST 429 is not checked", method: "POST", path: "/deep-429-over", body: deepOver, status: 429},
		{name: "POST 503 is not checked", method: "POST", path: "/deep-503-over", body: deepOver, status: 503},
		// A DELETE has no record of its status (see RoundTrip).
		{name: "DELETE 400 is not checked", method: "DELETE", path: "/deep-400-over", body: deepOver},
		{name: "POST text/plain is not checked", method: "POST", path: "/plain-over", body: overLimit},
		// Security case: a 303 turns the POST into a GET. The SDK still
		// decodes the application/json body, so the check must stay.
		{name: "303 POST to GET json over the limit", method: "POST", path: "/see-other-json", wantErr: true},
		{name: "303 POST to GET SSE over the limit", method: "POST", path: "/see-other-sse", wantErr: true},
		{name: "303 POST to GET json at the limit", method: "POST", path: "/see-other-at", body: atLimit},
		{name: "307 POST to POST json over the limit", method: "POST", path: "/temporary-json", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// A nil Base gives the real base transport.
			client, ev, err := newHTTPClient(httpClientConfig{Endpoint: hcURL(t, ts.URL), UserAgent: hcUA})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.CloseIdleConnections)
			rec := &requestRecorder{}
			data, readErr := hcDo(t, client, rec, tt.method, ts.URL+tt.path)

			if got := ev.fallback.blockedErr(); got != nil {
				t.Errorf("fallback blockedErr() = %v, want nil: the request had a record", got)
			}
			if !tt.wantErr {
				if readErr != nil {
					t.Fatalf("read body: error = %v, want nil", readErr)
				}
				if string(data) != tt.body {
					t.Errorf("read %d bytes, want the whole body of %d bytes", len(data), len(tt.body))
				}
				if got := rec.blockedErr(); got != nil {
					t.Errorf("record blockedErr() = %v, want nil", got)
				}
				if got := rec.lastStatus(); got != tt.status {
					t.Errorf("record lastStatus() = %d, want %d", got, tt.status)
				}
				return
			}

			if !errors.Is(readErr, errJSONTooComplex) {
				t.Fatalf("read body: error = %v, want errJSONTooComplex", readErr)
			}
			// The chunk that went over the limit never reaches the reader,
			// so the decoder never gets the whole message.
			// For a redirect, the message is the body at its Location.
			final := served[tt.path]
			if final.location != "" {
				final = served[final.location]
			}
			if len(data) >= len(final.body) {
				t.Errorf("read %d bytes before the error, want fewer than the %d bytes of the message", len(data), len(final.body))
			}
			if got := rec.blockedErr(); !errors.Is(got, errJSONTooComplex) {
				t.Errorf("record blockedErr() = %v, want errJSONTooComplex", got)
			}
			if got := rec.lastStatus(); got != tt.status {
				t.Errorf("record lastStatus() = %d, want %d", got, tt.status)
			}

			// The SDK can flatten the error to text. callRecords links it to
			// the record with a recordedError, and classify finds the blocked
			// error there.
			flat := &recordedError{err: errors.New(readErr.Error()), rec: rec}
			ce := classify(flat, srv, ev, secretLists{})
			if ce.Kind != KindTooLarge {
				t.Errorf("classify().Kind = %q, want %q (reason %q)", ce.Kind, KindTooLarge, ce.Reason)
			}
			if !errors.Is(ce, errJSONTooComplex) {
				t.Errorf("errors.Is(classify(), errJSONTooComplex) = false, want true")
			}
		})
	}

	// No regression: a normal JSON-RPC error body of a non-2xx answer passes
	// the check, so classify still reports the HTTP status.
	t.Run("small 401 JSON-RPC error classifies as HTTP 401", func(t *testing.T) {
		t.Parallel()
		client, ev, err := newHTTPClient(httpClientConfig{Endpoint: hcURL(t, ts.URL), UserAgent: hcUA})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.CloseIdleConnections)
		rec := &requestRecorder{}
		if _, err := hcDo(t, client, rec, http.MethodPost, ts.URL+"/unauthorized"); err != nil {
			t.Fatalf("read body: error = %v, want nil", err)
		}
		flat := &recordedError{err: errors.New("Unauthorized"), rec: rec}
		ce := classify(flat, srv, ev, secretLists{})
		if ce.Kind != KindHTTP || ce.Status != http.StatusUnauthorized {
			t.Errorf("classify() = kind %q, status %d, want %q, %d (reason %q)", ce.Kind, ce.Status, KindHTTP, http.StatusUnauthorized, ce.Reason)
		}
	})

	t.Run("request without a record blocks into the fallback", func(t *testing.T) {
		t.Parallel()
		client, ev, err := newHTTPClient(httpClientConfig{Endpoint: hcURL(t, ts.URL), UserAgent: hcUA})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.CloseIdleConnections)
		_, readErr := hcDo(t, client, nil, http.MethodGet, ts.URL+"/sse-over")
		if !errors.Is(readErr, errJSONTooComplex) {
			t.Fatalf("read body: error = %v, want errJSONTooComplex", readErr)
		}
		if got := ev.fallback.blockedErr(); !errors.Is(got, errJSONTooComplex) {
			t.Errorf("fallback blockedErr() = %v, want errJSONTooComplex", got)
		}
		ce := classify(errors.New("flattened by the SDK"), srv, ev, secretLists{})
		if ce.Kind != KindTooLarge {
			t.Errorf("classify().Kind = %q, want %q (reason %q)", ce.Kind, KindTooLarge, ce.Reason)
		}
	})
}

// TestShapeBodyWrap checks which bodies RoundTrip wraps in a shapeReader, and
// that Close on the wrapped body closes the real body, also after a shape
// violation.
func TestShapeBodyWrap(t *testing.T) {
	t.Parallel()

	const origin = "http://example.com"
	overLimit := hcRPCList(MaxJSONValues - hcEnvelopeValues + 1)

	tests := []struct {
		name    string
		method  string
		status  int
		ct      string
		body    string
		wrapped bool // the body must be a *shapeReader
		readErr bool // reading must fail with errJSONTooComplex
	}{
		{name: "POST json", method: "POST", status: 200, ct: "application/json", body: `{"jsonrpc":"2.0","id":1,"result":{}}`, wrapped: true},
		{name: "POST SSE", method: "POST", status: 200, ct: "text/event-stream", body: sseMessageEvent(`{}`), wrapped: true},
		{name: "GET", method: "GET", status: 200, ct: "text/event-stream", body: sseMessageEvent(`{}`), wrapped: true},
		{name: "POST text/plain", method: "POST", status: 200, ct: "text/plain", body: "ok"},
		{name: "POST 500 json", method: "POST", status: 500, ct: "application/json", body: overLimit},
		{name: "POST json after a violation", method: "POST", status: 200, ct: "application/json", body: overLimit, wrapped: true, readErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			realBody := &hcBody{r: strings.NewReader(tt.body)}
			stub := &hcStub{respond: func(req *http.Request) *http.Response {
				resp := hcResponse(req, tt.status, "", http.Header{"Content-Type": {tt.ct}})
				resp.Body = realBody
				return resp
			}}
			client, _, err := hcNew(hcURL(t, origin), nil, stub, hcUA, 0)
			if err != nil {
				t.Fatal(err)
			}
			ht, ok := client.Transport.(*headerTransport)
			if !ok {
				t.Fatalf("client.Transport is %T, want *headerTransport", client.Transport)
			}
			rec := &requestRecorder{}
			req, err := http.NewRequestWithContext(withRecorder(t.Context(), rec), tt.method, origin+"/mcp", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := ht.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip() error = %v", err)
			}

			switch b := resp.Body.(type) {
			case *shapeReader:
				if !tt.wrapped {
					t.Errorf("body is a *shapeReader, want no shape check")
				}
				// The shape check sees only bytes within the size caps.
				if _, ok := b.rc.(*cappedBody); !ok {
					t.Errorf("shapeReader wraps %T, want *cappedBody", b.rc)
				}
			case *cappedBody:
				if tt.wrapped {
					t.Errorf("body is a *cappedBody, want a *shapeReader")
				}
			default:
				t.Errorf("body is %T, want *shapeReader or *cappedBody", resp.Body)
			}

			data, err := io.ReadAll(resp.Body)
			if tt.readErr {
				if !errors.Is(err, errJSONTooComplex) {
					t.Errorf("read body: error = %v, want errJSONTooComplex", err)
				}
				if !strings.HasPrefix(err.Error(), "read response body: ") {
					t.Errorf("read body: error = %q, want the prefix %q", err, "read response body: ")
				}
				if got := rec.blockedErr(); got != err { //nolint:errorlint // identity check: the record must hold the error that Read returned
					t.Errorf("record blockedErr() = %v, want the read error %v", got, err)
				}
			} else {
				if err != nil {
					t.Errorf("read body: error = %v, want nil", err)
				}
				if string(data) != tt.body {
					t.Errorf("read %q, want %q", data, tt.body)
				}
				if got := rec.blockedErr(); got != nil {
					t.Errorf("record blockedErr() = %v, want nil", got)
				}
			}

			if realBody.closed.Load() {
				t.Fatal("the real body is closed before Close")
			}
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Close() = %v, want nil", err)
			}
			if !realBody.closed.Load() {
				t.Error("Close on the wrapped body did not close the real body")
			}
		})
	}
}

// TestNewBaseTransportSettings checks that newBaseTransport with the pinned
// dialer (issue #102) keeps the settings that it had before.
func TestNewBaseTransportSettings(t *testing.T) {
	t.Parallel()

	tr := newBaseTransport(nil, "")
	if tr.Proxy == nil {
		t.Error("Proxy = nil, want proxyFromEnvironment")
	}
	if tr.DialContext == nil {
		t.Error("DialContext = nil, want the pinned dialer")
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want 10s", tr.TLSHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != 0 {
		t.Errorf("ResponseHeaderTimeout = %v, want 0: an SSE server can wait long before the first byte", tr.ResponseHeaderTimeout)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLSClientConfig = %+v, want MinVersion TLS 1.2", tr.TLSClientConfig)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 = false, want true")
	}
	if tr.MaxIdleConns != 4 {
		t.Errorf("MaxIdleConns = %d, want 4", tr.MaxIdleConns)
	}
	if tr.IdleConnTimeout != 30*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 30s", tr.IdleConnTimeout)
	}
	if tr.MaxResponseHeaderBytes != 64<<10 {
		t.Errorf("MaxResponseHeaderBytes = %d, want %d", tr.MaxResponseHeaderBytes, 64<<10)
	}
	if tr.DisableCompression {
		t.Error("DisableCompression = true, want false: net/http must decompress, so the size cap counts decoded bytes")
	}

	// Each transport has its own TLS config, so no caller can change the
	// config of another one.
	if other := newBaseTransport(nil, ""); other.TLSClientConfig == tr.TLSClientConfig {
		t.Error("two transports share one TLSClientConfig, want one each")
	}

	// Go never uses a proxy for a loopback address.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if proxy, err := tr.Proxy(req); proxy != nil || err != nil {
		t.Errorf("Proxy(127.0.0.1) = %v, %v; want nil, nil", proxy, err)
	}

	// The dialer of a nil lookup dials an IP literal as is.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	conn, err := tr.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext(%s) error = %v", ln.Addr(), err)
	}
	_ = conn.Close()
}

// TestRoundTripRecordsAddrRefused checks that headerTransport.RoundTrip
// records an errAddrRefused from the base transport as the blocked error of
// the request (issue #106), so the label survives when the SDK flattens the
// error into text. Other transport errors are not blocked errors. The
// request without a response also clears an older status of its record.
func TestRoundTripRecordsAddrRefused(t *testing.T) {
	t.Parallel()

	const origin = "http://guarded.test"

	tests := []struct {
		name        string
		baseErr     error
		wantBlocked bool
	}{
		{name: "bare", baseErr: errAddrRefused, wantBlocked: true},
		{name: "wrapped", baseErr: fmt.Errorf("dial: %w", errAddrRefused), wantBlocked: true},
		{name: "in a net.OpError", baseErr: &net.OpError{Op: "dial", Net: "tcp", Err: errAddrRefused}, wantBlocked: true},
		{name: "other dial error", baseErr: errors.New("dial tcp: connection refused")},
		{name: "DNS error", baseErr: &net.DNSError{Err: "no such host", Name: "guarded.test", IsNotFound: true}},
	}
	for _, tt := range tests {
		for _, withRec := range []bool{false, true} {
			name := tt.name + "/fallback record"
			if withRec {
				name = tt.name + "/call record"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				// /first answers 500, so the record has an old status that
				// the refused request must clear. Every other request fails
				// with the base error.
				base := hcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.Path == "/first" {
						return hcResponse(req, http.StatusInternalServerError, "boom", nil), nil
					}
					return nil, tt.baseErr
				})
				client, ev, err := hcNew(hcURL(t, origin), nil, base, hcUA, 0)
				if err != nil {
					t.Fatal(err)
				}

				var rec *requestRecorder
				target := &ev.fallback
				if withRec {
					rec = &requestRecorder{}
					target = rec
				}
				if _, err := hcDo(t, client, rec, http.MethodGet, origin+"/first"); err != nil {
					t.Fatal(err)
				}
				if s := target.lastStatus(); s != http.StatusInternalServerError {
					t.Fatalf("lastStatus() after /first = %d, want 500", s)
				}

				ctx := t.Context()
				if rec != nil {
					ctx = withRecorder(ctx, rec)
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/mcp", strings.NewReader("{}"))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if !errors.Is(err, tt.baseErr) {
					t.Fatalf("client.Do() error = %v, want the base error", err)
				}

				got := target.blockedErr()
				if tt.wantBlocked {
					if !errors.Is(got, errAddrRefused) {
						t.Errorf("blockedErr() = %v, want errAddrRefused", got)
					}
				} else if got != nil {
					t.Errorf("blockedErr() = %v, want nil for a plain transport error", got)
				}
				if s := target.lastStatus(); s != 0 {
					t.Errorf("lastStatus() = %d after a request without a response, want 0", s)
				}
				if withRec {
					if fb := ev.fallback.blockedErr(); fb != nil {
						t.Errorf("fallback blockedErr() = %v, want nil: the request had a record", fb)
					}
				}

				// stateFor gives the label for a flattened error too.
				status, blocked := ev.stateFor(errors.New("flattened"))
				if !withRec {
					if tt.wantBlocked != errors.Is(blocked, errAddrRefused) || status != 0 {
						t.Errorf("stateFor() = %d, %v; want 0 and blocked %v", status, blocked, tt.wantBlocked)
					}
				}
			})
		}
	}
}

// TestAddrRefusedSurvivesFlattening runs the real chain: newBaseTransport
// with a stub lookup that points the guarded name at 127.0.0.1, behind
// newHTTPClient. The dial is refused before any connection, the refusal is
// recorded, and classify still gives KindNetwork with the fixed reason when
// the error that reaches it is only text, as the SDK can make it.
func TestAddrRefusedSurvivesFlattening(t *testing.T) {
	t.Parallel()

	lookup := func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	base := newBaseTransport(lookup, "guarded.test")
	// No proxy: the test must not depend on HTTP_PROXY of the machine.
	base.Proxy = nil
	t.Cleanup(base.CloseIdleConnections)

	const endpoint = "http://guarded.test:1/mcp"
	client, ev, err := hcNew(hcURL(t, endpoint), nil, base, hcUA, 0)
	if err != nil {
		t.Fatal(err)
	}
	hcMustFail(t, client, endpoint, errAddrRefused)

	if got := ev.fallback.blockedErr(); !errors.Is(got, errAddrRefused) {
		t.Fatalf("fallback blockedErr() = %v, want errAddrRefused", got)
	}

	srv := discover.Server{Name: "remote", Transport: discover.TransportHTTP, URL: discover.NewURL(endpoint)}
	flat := errors.New("calling initialize: Post " + endpoint + ": " + errAddrRefused.Error())
	ce := classify(flat, srv, ev, secretLists{})
	if ce.Kind != KindNetwork {
		t.Errorf("classify().Kind = %q, want %q", ce.Kind, KindNetwork)
	}
	if ce.Reason != addrRefusedReason {
		t.Errorf("classify().Reason = %q, want %q", ce.Reason, addrRefusedReason)
	}
	if !errors.Is(ce, errAddrRefused) {
		t.Errorf("errors.Is(classify(), errAddrRefused) = false, want true")
	}
	if strings.Contains(ce.Reason, "127.0.0.1") || strings.Contains(ce.Reason, "guarded.test") {
		t.Errorf("classify().Reason = %q, must hold no address and no host name", ce.Reason)
	}
}
