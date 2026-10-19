package inspect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// These tests cover the warning about secrets sent over plain http:// to a
// host that is not loopback (issue #98).

// Fake secrets of the warning tests. No warning and no error text may hold
// them.
const (
	wnHeaderValue = "s3cret-value"
	wnUser        = "wn-user"
	wnPassword    = "pa55word-SECRET"
	wnQueryValue  = "qu3ry-tok-SECRET"
	wnPathSegment = "9f1c2b7e-0a4d-4e8b-b3c6-5d7e8f901234" // a UUID segment is a secret
	// wnShortValue is shorter than minBareSecretLen. classify keeps such a
	// value in error text, but the warning must still count it.
	wnShortValue = "hunt3r"
)

func TestIsLoopbackHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		host string
		want bool
	}{
		{host: "localhost", want: true},
		// Go sends these through HTTP_PROXY: its bypass is case sensitive.
		{host: "LOCALHOST", want: false},
		{host: "LocalHost", want: false},
		{host: "127.0.0.1", want: true},
		{host: "127.0.0.2", want: true},
		{host: "127.255.255.254", want: true},
		{host: "::1", want: true},
		{host: "0:0:0:0:0:0:0:1", want: true},
		{host: "::ffff:127.0.0.1", want: true},
		{host: "::1%lo0", want: true},

		// Not loopback.
		{host: "fe80::1%en0", want: false},
		{host: "10.0.0.1", want: false},
		{host: "128.0.0.1", want: false},
		{host: "126.255.255.255", want: false},
		{host: "0.0.0.0", want: false},
		{host: "::", want: false},
		{host: "::ffff:10.0.0.1", want: false},
		{host: "example.com", want: false},
		// DNS names can point anywhere, even when they look local.
		{host: "localhost.example.com", want: false},
		{host: "127.0.0.1.nip.io", want: false},
		{host: "localhost.", want: false},
		{host: " localhost", want: false},
		// Short IPv4 forms do not parse as an address, so they get the
		// warning. That is the safe side.
		{host: "127.1", want: false},
		// The caller passes url.URL.Hostname, which has no brackets.
		{host: "[::1]", want: false},
		{host: "", want: false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.host), func(t *testing.T) {
			t.Parallel()
			if got := isLoopbackHost(tt.host); got != tt.want {
				t.Errorf("isLoopbackHost(%q) = %t, want %t", tt.host, got, tt.want)
			}
		})
	}
}

// wnServer returns a remote server entry for rawURL with headers.
func wnServer(rawURL string, headers map[string]string) discover.Server {
	cfg := make(discover.SecretMap, len(headers))
	for key, value := range headers {
		cfg[key] = discover.NewSecret(value)
	}
	return discover.Server{
		Name:      "remote",
		Transport: discover.TransportHTTP,
		URL:       discover.NewURL(rawURL),
		Headers:   cfg,
	}
}

// wnEqual reports whether got and want are the same warnings. A nil and an
// empty HeaderKeys count as equal. It compares whole values, so a new field
// of Warning is compared too.
func wnEqual(got, want []Warning) bool {
	norm := func(w Warning) Warning {
		if len(w.HeaderKeys) == 0 {
			w.HeaderKeys = nil
		}
		return w
	}
	return slices.EqualFunc(got, want, func(a, b Warning) bool {
		return reflect.DeepEqual(norm(a), norm(b))
	})
}

// wnAssertNoSecrets fails if the %#v form of v holds a secret of the
// warning tests.
func wnAssertNoSecrets(t *testing.T, what string, v any) {
	t.Helper()
	text := fmt.Sprintf("%#v", v)
	for _, secret := range []string{wnHeaderValue, wnPassword, wnUser, wnQueryValue, wnPathSegment, wnShortValue} {
		if strings.Contains(text, secret) {
			t.Errorf("%s holds the secret %q: %s", what, secret, text)
		}
	}
}

func TestCleartextWarnings(t *testing.T) {
	t.Parallel()

	userinfo := wnUser + ":" + wnPassword + "@"
	header := map[string]string{"X-Api-Key": wnHeaderValue}
	tests := []struct {
		name    string
		rawURL  string
		u       *url.URL // when set, used instead of url.Parse(rawURL)
		nilURL  bool     // pass a nil URL
		headers map[string]string
		want    []Warning
	}{
		{
			name:    "http non-loopback with a header",
			rawURL:  "http://mcp.example.com/mcp",
			headers: header,
			want:    []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}}},
		},
		{
			name:    "http private address with a header",
			rawURL:  "http://10.0.0.1:8080/mcp",
			headers: header,
			want:    []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}}},
		},
		{
			name:    "http look-alike localhost name with a header",
			rawURL:  "http://localhost.example.com/mcp",
			headers: header,
			want:    []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}}},
		},
		{
			name:    "http non-loopback with two headers",
			rawURL:  "http://mcp.example.com/mcp",
			headers: map[string]string{"X-Api-Key": wnHeaderValue, "Authorization": "Bearer " + wnHeaderValue},
			want:    []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"Authorization", "X-Api-Key"}}},
		},
		{
			name:    "http non-loopback with mixed-case duplicate keys",
			rawURL:  "http://mcp.example.com/mcp",
			headers: map[string]string{"x-api-key": wnHeaderValue, "X-Api-Key": wnHeaderValue},
			want:    []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}}},
		},
		{
			// Go sends LOCALHOST through HTTP_PROXY, so it is not loopback.
			name:    "http LOCALHOST with a header",
			rawURL:  "http://LOCALHOST/mcp",
			headers: header,
			want:    []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}}},
		},
		{
			name:   "http non-loopback with user info",
			rawURL: "http://" + userinfo + "mcp.example.com/mcp",
			want:   []Warning{{Kind: WarnCleartextSecrets, URLUserInfo: true}},
		},
		{
			name:    "http non-loopback with user info and a header",
			rawURL:  "http://" + userinfo + "mcp.example.com/mcp",
			headers: header,
			want:    []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}, URLUserInfo: true}},
		},
		{
			name:    "http non-loopback with user info and empty Authorization",
			rawURL:  "http://" + userinfo + "mcp.example.com/mcp",
			headers: map[string]string{"Authorization": ""},
			want:    []Warning{{Kind: WarnCleartextSecrets, URLUserInfo: true}},
		},
		{
			name:   "http non-loopback with a secret api_key query",
			rawURL: "http://mcp.example.com/mcp?api_key=" + wnQueryValue,
			want:   []Warning{{Kind: WarnCleartextSecrets, URLSecrets: true}},
		},
		{
			name:   "http non-loopback with a secret token query among others",
			rawURL: "http://mcp.example.com/mcp?debug=&token=" + wnQueryValue,
			want:   []Warning{{Kind: WarnCleartextSecrets, URLSecrets: true}},
		},
		{
			// urlSecrets drops values shorter than minBareSecretLen; the
			// warning must not.
			name:   "http non-loopback with a short query value",
			rawURL: "http://mcp.example.com/mcp?pw=" + wnShortValue,
			want:   []Warning{{Kind: WarnCleartextSecrets, URLSecrets: true}},
		},
		{
			name:   "http non-loopback with a bare query part",
			rawURL: "http://mcp.example.com/mcp?" + wnQueryValue,
			want:   []Warning{{Kind: WarnCleartextSecrets, URLSecrets: true}},
		},
		{
			name:   "http non-loopback with a token path segment",
			rawURL: "http://mcp.example.com/mcp/" + wnPathSegment + "/sse",
			want:   []Warning{{Kind: WarnCleartextSecrets, URLSecrets: true}},
		},
		{
			name:   "http non-loopback with a key=value path segment",
			rawURL: "http://mcp.example.com/key=" + wnShortValue + "/mcp",
			want:   []Warning{{Kind: WarnCleartextSecrets, URLSecrets: true}},
		},
		{
			name:    "http non-loopback with a secret query, user info and a header",
			rawURL:  "http://" + userinfo + "mcp.example.com/mcp?api_key=" + wnQueryValue,
			headers: header,
			want:    []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}, URLUserInfo: true, URLSecrets: true}},
		},
		{
			// url.Parse lowercases the scheme, so build the URL by hand.
			name:    "upper-case HTTP scheme",
			rawURL:  "http://mcp.example.com/mcp",
			u:       &url.URL{Scheme: "HTTP", Host: "mcp.example.com", Path: "/mcp"},
			headers: header,
			want:    []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}}},
		},
		{
			name:    "upper-case scheme parsed",
			rawURL:  "HTTP://mcp.example.com/mcp",
			headers: header,
			want:    []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}}},
		},

		// No warning.
		{name: "https with a header", rawURL: "https://mcp.example.com/mcp", headers: header},
		{name: "https with user info", rawURL: "https://" + userinfo + "mcp.example.com/mcp", headers: header},
		{
			name:    "upper-case HTTPS scheme",
			rawURL:  "https://mcp.example.com/mcp",
			u:       &url.URL{Scheme: "HTTPS", Host: "mcp.example.com", Path: "/mcp"},
			headers: header,
		},
		{name: "http 127.0.0.1 with a header", rawURL: "http://127.0.0.1:8080/mcp", headers: header},
		{name: "http 127.0.0.1 with user info", rawURL: "http://" + userinfo + "127.0.0.1:8080/mcp", headers: header},
		{name: "http localhost with a header", rawURL: "http://localhost:8080/mcp", headers: header},
		{name: "http [::1] with a header", rawURL: "http://[::1]:8080/mcp", headers: header},
		{name: "http non-loopback without secrets", rawURL: "http://mcp.example.com/mcp"},
		{name: "http non-loopback with empty header map", rawURL: "http://mcp.example.com/mcp", headers: map[string]string{}},
		{name: "nil URL", rawURL: "http://mcp.example.com/mcp", nilURL: true, headers: header},
		{name: "http non-loopback with an empty query value", rawURL: "http://mcp.example.com/mcp?debug="},
		{name: "http non-loopback with an empty query", rawURL: "http://mcp.example.com/mcp?"},
		{name: "http non-loopback with a plain path", rawURL: "http://mcp.example.com/v1/mcp/sse"},
		{name: "https with a secret query", rawURL: "https://mcp.example.com/mcp?api_key=" + wnQueryValue},
		{name: "https with a secret path segment", rawURL: "https://mcp.example.com/mcp/" + wnPathSegment},
		{name: "http 127.0.0.1 with a secret query", rawURL: "http://127.0.0.1:8080/mcp?api_key=" + wnQueryValue},
		{name: "http localhost with a secret query", rawURL: "http://localhost:8080/mcp?token=" + wnQueryValue},
		{name: "http [::1] with a secret path segment", rawURL: "http://[::1]:8080/mcp/" + wnPathSegment},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := wnServer(tt.rawURL, tt.headers)
			u := tt.u
			if u == nil && !tt.nilURL {
				var err error
				u, err = url.Parse(tt.rawURL)
				if err != nil {
					t.Fatalf("url.Parse(%q) error = %v", tt.rawURL, err)
				}
			}

			got := cleartextWarnings(srv, u)
			if !wnEqual(got, tt.want) {
				t.Errorf("cleartextWarnings() = %#v, want %#v", got, tt.want)
			}
			if tt.want == nil && got != nil {
				t.Errorf("cleartextWarnings() = %#v, want nil", got)
			}
			wnAssertNoSecrets(t, "cleartextWarnings()", got)
		})
	}
}

// wnStubLookup is a lookupFunc that resolves only the names in hosts, to
// 127.0.0.1, so no test uses real DNS. It records every other name that it
// gets.
type wnStubLookup struct {
	hosts map[string]bool

	mu      sync.Mutex
	unknown []string
}

func (s *wnStubLookup) lookup(_ context.Context, _, host string) ([]netip.Addr, error) {
	if s.hosts[host] {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	s.mu.Lock()
	s.unknown = append(s.unknown, host)
	s.mu.Unlock()
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (s *wnStubLookup) assertKnownOnly(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.unknown) > 0 {
		t.Errorf("lookups of unexpected hosts: %q", s.unknown)
	}
}

// wnBaseTransport returns a base transport with the pinned dialer of
// newBaseTransport and a stub lookup that maps mcp.example.test and localhost
// to 127.0.0.1. It uses no proxy, so the test does not depend on the
// HTTP_PROXY of the machine.
func wnBaseTransport(t *testing.T) (*http.Transport, *wnStubLookup) {
	t.Helper()
	stub := &wnStubLookup{hosts: map[string]bool{"mcp.example.test": true, "localhost": true}}
	tr := newBaseTransport(stub.lookup)
	tr.Proxy = nil
	t.Cleanup(tr.CloseIdleConnections)
	return tr, stub
}

// wnStartServer starts a plain HTTP server on 127.0.0.1 with the fixture MCP
// server at "/mcp". The SDK handlers refuse a request to a loopback listener
// whose Host header is not loopback (DNS rebinding protection). The test
// sends Host: mcp.example.test to 127.0.0.1 on purpose, so the protection is
// off here. wrap, when not nil, wraps the MCP handler. The recorder is the
// outermost handler, so it sees every request, even one that wrap refuses.
func wnStartServer(t *testing.T, sse bool, wrap func(http.Handler) http.Handler) (*httptest.Server, *recorder) {
	t.Helper()
	mcpSrv := newFixtureMCPServer()
	getServer := func(*http.Request) *mcp.Server { return mcpSrv }
	var h http.Handler
	if sse {
		h = mcp.NewSSEHandler(getServer, &mcp.SSEOptions{DisableLocalhostProtection: true})
	} else {
		h = mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: true})
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", h)

	var root http.Handler = mux
	if wrap != nil {
		root = wrap(root)
	}
	rec := &recorder{}
	ts := httptest.NewServer(rec.record(root))
	t.Cleanup(ts.Close)
	return ts, rec
}

// wnQueries records the raw query of each request that reaches a test
// server. The shared recorder keeps the path only. It is safe for concurrent
// use.
type wnQueries struct {
	mu      sync.Mutex
	queries []string
}

// wrap returns a handler that records the raw query of each request and
// then calls next.
func (q *wnQueries) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q.mu.Lock()
		q.queries = append(q.queries, req.URL.RawQuery)
		q.mu.Unlock()
		next.ServeHTTP(w, req)
	})
}

// first returns the raw query of the first request, or "" if there was none.
func (q *wnQueries) first() string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.queries) == 0 {
		return ""
	}
	return q.queries[0]
}

// wnPort returns the port of the test server.
func wnPort(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", ts.URL, err)
	}
	return u.Port()
}

// TestRemoteCleartextWarning is the acceptance test of issue #98: Remote
// over http:// to a host that is not loopback, with a config header, gives
// one warning that names the header key and holds no value. The same server
// at a loopback address gives no warning.
func TestRemoteCleartextWarning(t *testing.T) {
	t.Parallel()

	const secretQuery = "?api_key=" + wnQueryValue
	tests := []struct {
		name  string
		sse   bool
		host  string // host of the URL; the stub lookup maps names to 127.0.0.1
		query string // query of the URL, with "?"
		want  []Warning
	}{
		{name: "http non-loopback name", host: "mcp.example.test", want: []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}}}},
		{name: "sse non-loopback name", sse: true, host: "mcp.example.test", want: []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}}}},
		{
			name: "http non-loopback name with a secret query", host: "mcp.example.test", query: secretQuery,
			want: []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}, URLSecrets: true}},
		},
		{
			name: "sse non-loopback name with a secret query", sse: true, host: "mcp.example.test", query: secretQuery,
			want: []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}, URLSecrets: true}},
		},
		{name: "http 127.0.0.1", host: "127.0.0.1"},
		{name: "sse 127.0.0.1", sse: true, host: "127.0.0.1"},
		{name: "http localhost", host: "localhost"},
		{name: "http 127.0.0.1 with a secret query", host: "127.0.0.1", query: secretQuery},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			queries := &wnQueries{}
			ts, rec := wnStartServer(t, tt.sse, queries.wrap)
			base, stub := wnBaseTransport(t)

			rawURL := "http://" + tt.host + ":" + wnPort(t, ts) + "/mcp" + tt.query
			srv := wnServer(rawURL, map[string]string{"X-Api-Key": wnHeaderValue})
			srv.Name = rmServerName
			if tt.sse {
				srv.Transport = discover.TransportSSE
			}

			got, err := Remote(t.Context(), srv, RemoteOptions{baseTransport: base})
			if err != nil {
				t.Fatalf("Remote() error = %v", err)
			}
			if !wnEqual(got.Warnings, tt.want) {
				t.Errorf("Result.Warnings = %#v, want %#v", got.Warnings, tt.want)
			}
			if tt.want == nil && got.Warnings != nil {
				t.Errorf("Result.Warnings = %#v, want nil", got.Warnings)
			}
			if len(got.Tools) == 0 {
				t.Error("Result.Tools is empty; the inspection did not list the fixture tools")
			}
			wnAssertNoSecrets(t, "Result", got)

			// The header really went out, so the warning tells the truth.
			reqs := rec.requests()
			if len(reqs) == 0 {
				t.Fatal("the server got no request")
			}
			for i, req := range reqs {
				if v := req.Header.Get("X-Api-Key"); v != wnHeaderValue {
					t.Errorf("request %d (%s) X-Api-Key = %q, want the config value", i, req.Method, v)
				}
			}
			// The query really went out with the first request. (A legacy
			// SSE server picks the URL of later requests itself.)
			if want := strings.TrimPrefix(tt.query, "?"); queries.first() != want {
				t.Errorf("first request query = %q, want %q", queries.first(), want)
			}
			stub.assertKnownOnly(t)
		})
	}
}

// TestRemoteCleartextWarningOnFailure checks decision A of issue #98: when
// the inspection fails after the secrets went out, the *ConnectError still
// carries the warning, and its text holds no secret.
func TestRemoteCleartextWarningOnFailure(t *testing.T) {
	t.Parallel()

	unauthorized := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}
	tests := []struct {
		name     string
		sse      bool
		host     string
		userinfo bool
		query    string // query of the URL, with "?"
		want     []Warning
	}{
		{
			name: "http 401 non-loopback", host: "mcp.example.test",
			want: []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}}},
		},
		{
			name: "sse 401 non-loopback", sse: true, host: "mcp.example.test",
			want: []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}}},
		},
		{
			name: "http 401 non-loopback with user info", host: "mcp.example.test", userinfo: true,
			want: []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}, URLUserInfo: true}},
		},
		{
			name: "http 401 non-loopback with a secret query", host: "mcp.example.test", query: "?api_key=" + wnQueryValue,
			want: []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}, URLSecrets: true}},
		},
		{
			name: "sse 401 non-loopback with a secret query", sse: true, host: "mcp.example.test", query: "?token=" + wnQueryValue,
			want: []Warning{{Kind: WarnCleartextSecrets, HeaderKeys: []string{"X-Api-Key"}, URLSecrets: true}},
		},
		{name: "http 401 loopback", host: "127.0.0.1"},
		{name: "http 401 loopback with a secret query", host: "127.0.0.1", query: "?api_key=" + wnQueryValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			queries := &wnQueries{}
			ts, rec := wnStartServer(t, tt.sse, func(h http.Handler) http.Handler {
				return queries.wrap(unauthorized(h))
			})
			base, stub := wnBaseTransport(t)

			authority := tt.host + ":" + wnPort(t, ts)
			if tt.userinfo {
				authority = wnUser + ":" + wnPassword + "@" + authority
			}
			srv := wnServer("http://"+authority+"/mcp"+tt.query, map[string]string{"X-Api-Key": wnHeaderValue})
			srv.Name = rmServerName
			if tt.sse {
				srv.Transport = discover.TransportSSE
			}

			got, err := Remote(t.Context(), srv, RemoteOptions{baseTransport: base})
			if err == nil {
				t.Fatal("Remote() error = nil, want an HTTP 401 error")
			}
			var ce *ConnectError
			if !errors.As(err, &ce) {
				t.Fatalf("Remote() error = %T (%v), want *ConnectError", err, err)
			}
			if ce.Kind != KindHTTP || ce.Status != http.StatusUnauthorized {
				t.Errorf("Kind, Status = %q, %d; want %q, %d (error: %v)", ce.Kind, ce.Status, KindHTTP, http.StatusUnauthorized, err)
			}
			if !wnEqual(ce.Warnings, tt.want) {
				t.Errorf("ConnectError.Warnings = %#v, want %#v", ce.Warnings, tt.want)
			}
			if tt.want == nil && ce.Warnings != nil {
				t.Errorf("ConnectError.Warnings = %#v, want nil", ce.Warnings)
			}
			if got.Warnings != nil {
				t.Errorf("Result.Warnings on failure = %#v, want nil (the warning is on the error)", got.Warnings)
			}
			// The 401 reason names the header key, but no value, and Error
			// does not print the warnings.
			if !strings.Contains(ce.Error(), "X-Api-Key") {
				t.Errorf("Error() = %q, want it to name the header key X-Api-Key", ce.Error())
			}
			if strings.Contains(ce.Error(), string(WarnCleartextSecrets)) {
				t.Errorf("Error() = %q prints the warning kind; Error must not print warnings", ce.Error())
			}
			assertNoSecrets(t, err, wnHeaderValue, wnPassword, "pa55", wnQueryValue)
			wnAssertNoSecrets(t, "ConnectError", *ce)

			// The header really went out before the failure.
			reqs := rec.requests()
			if len(reqs) == 0 {
				t.Fatal("the server got no request; the test does not prove that the secrets went out")
			}
			if v := reqs[0].Header.Get("X-Api-Key"); v != wnHeaderValue {
				t.Errorf("first request X-Api-Key = %q, want the config value", v)
			}
			if want := strings.TrimPrefix(tt.query, "?"); queries.first() != want {
				t.Errorf("first request query = %q, want %q", queries.first(), want)
			}
			stub.assertKnownOnly(t)
		})
	}
}

// TestRemoteCleartextWarningNotOnConfigError checks that a config error that
// Remote finds before any request carries no warning: no secret went out.
func TestRemoteCleartextWarningNotOnConfigError(t *testing.T) {
	t.Parallel()

	const rawURL = "http://mcp.example.test:8080/mcp"
	tests := []struct {
		name    string
		srv     func() discover.Server
		wantMsg string
	}{
		{
			name: "untrusted project server",
			srv: func() discover.Server {
				srv := wnServer(rawURL, map[string]string{"X-Api-Key": wnHeaderValue})
				srv.Untrusted = true
				return srv
			},
			wantMsg: "untrusted",
		},
		{
			name: "reserved header",
			srv: func() discover.Server {
				return wnServer(rawURL, map[string]string{"X-Api-Key": wnHeaderValue, "Host": "evil.example"})
			},
			wantMsg: "Host",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := &rmNoRequests{t: t}
			_, err := Remote(t.Context(), tt.srv(), RemoteOptions{baseTransport: base})
			var ce *ConnectError
			if !errors.As(err, &ce) {
				t.Fatalf("Remote() error = %T (%v), want *ConnectError", err, err)
			}
			if ce.Kind != KindConfig || !strings.Contains(ce.Reason, tt.wantMsg) {
				t.Errorf("Kind, Reason = %q, %q; want %q and a reason with %q", ce.Kind, ce.Reason, KindConfig, tt.wantMsg)
			}
			if ce.Warnings != nil {
				t.Errorf("ConnectError.Warnings = %#v, want nil: no request went out", ce.Warnings)
			}
			if n := base.calls.Load(); n != 0 {
				t.Errorf("base transport calls = %d, want 0", n)
			}
			assertNoSecrets(t, err, wnHeaderValue)
		})
	}
}
