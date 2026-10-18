package inspect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// These tests run Remote against real httptest servers. They prove the
// acceptance criteria of issue #26: both transports work, the config headers
// are sent, TLS errors are clear, and no secret reaches an error text.

// Fake secrets. Every error test asserts that none of them shows up in an
// error text.
const (
	rmQuerySecret  = "QSECRET42"
	rmBearerSecret = "HSECRET99"
	rmAPIKeySecret = "KSECRET77"
	// rmFragmentSecret goes in the URL fragment. A fragment is never sent over
	// HTTP, but a client that keeps it could print it in an error text.
	rmFragmentSecret = "FSECRET55"
)

// rmServerName is the server name in the config of every test server.
const rmServerName = "remote-fixture"

// rmDefaultUA is the User-Agent that net/http sends over HTTP/1.1 when the
// request sets none. The httptest servers speak HTTP/1.1 only, so it is the
// User-Agent that they see when neither RemoteOptions nor the config sets
// one.
const rmDefaultUA = "Go-http-client/1.1"

// rmHeaders returns the config headers of the tests.
func rmHeaders() map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + rmBearerSecret,
		"X-Api-Key":     rmAPIKeySecret,
	}
}

// rmServer builds a discover.Server for a remote transport. rawURL gets a
// query with a secret, so every error test also checks that the query stays
// out of the error text.
func rmServer(kind discover.Transport, rawURL string, headers map[string]string) discover.Server {
	secrets := make(discover.SecretMap, len(headers))
	for key, value := range headers {
		secrets[key] = discover.NewSecret(value)
	}
	return discover.Server{
		Name:      rmServerName,
		Transport: kind,
		URL:       discover.NewURL(rawURL),
		Headers:   secrets,
	}
}

// rmWithSecretQuery adds the secret query to rawURL.
func rmWithSecretQuery(rawURL string) string {
	return rawURL + "?token=" + rmQuerySecret
}

// rmWithSecretQueryAndFragment adds the secret query and the secret fragment
// to rawURL.
func rmWithSecretQueryAndFragment(rawURL string) string {
	return rmWithSecretQuery(rawURL) + "#" + rmFragmentSecret
}

// rmKind returns the transport kind for the sse flag.
func rmKind(sse bool) discover.Transport {
	if sse {
		return discover.TransportSSE
	}
	return discover.TransportHTTP
}

// rmSecrets are the secrets of the test configs. Every error test asserts
// with assertNoSecrets that none of them shows up in an error text.
var rmSecrets = []string{rmQuerySecret, rmBearerSecret, rmAPIKeySecret, rmFragmentSecret, "pw@", "dXNlcjpwdw", "user:pw"}

// rmRequireConnectError checks that err is a *ConnectError of the wanted
// kind for the test server, that its text names the server and holds no
// secret, and returns it.
func rmRequireConnectError(t *testing.T, err error, kind ConnectKind) *ConnectError {
	t.Helper()
	if err == nil {
		t.Fatalf("Remote error = nil, want a %s error", kind)
	}
	var ce *ConnectError
	if !errors.As(err, &ce) {
		t.Fatalf("Remote error = %T (%v), want *ConnectError", err, err)
	}
	if ce.Kind != kind {
		t.Fatalf("Kind = %q, want %q (error: %v)", ce.Kind, kind, err)
	}
	if ce.Server != rmServerName || !strings.Contains(err.Error(), rmServerName) {
		t.Errorf("error %q does not name the server %q", err.Error(), rmServerName)
	}
	assertNoSecrets(t, err, rmSecrets...)
	return ce
}

// rmVictim is a second server. A request that reaches it is a leak of the
// config headers to another origin. It counts the requests and the requests
// that carry a config header.
type rmVictim struct {
	*httptest.Server
	requests atomic.Int32
	leaked   atomic.Int32
}

// startVictim starts a plain HTTP server that counts every request.
func startVictim(t *testing.T) *rmVictim {
	t.Helper()
	v := &rmVictim{}
	v.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v.requests.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Api-Key") != "" {
			v.leaked.Add(1)
		}
		http.Error(w, "victim", http.StatusTeapot)
	}))
	t.Cleanup(v.Close)
	return v
}

// assertUntouched fails the test when the victim got a request.
func (v *rmVictim) assertUntouched(t *testing.T) {
	t.Helper()
	if n := v.requests.Load(); n != 0 {
		t.Errorf("victim server got %d request(s), want 0", n)
	}
	if n := v.leaked.Load(); n != 0 {
		t.Errorf("victim server got %d request(s) with config headers, want 0", n)
	}
}

// rmCheckResult compares got with fixtureWant, the way the fixture comment
// asks: the protocol version must be set, and the schemas are compared by
// their property names.
func rmCheckResult(t *testing.T, got Result) {
	t.Helper()
	if got.ProtocolVersion == "" {
		t.Error("ProtocolVersion is empty, want the negotiated version")
	}
	got.ProtocolVersion = ""

	wantProps := map[string][]string{"add": {"a", "b"}, "echo": {"text"}}
	if len(got.Tools) != len(wantProps) {
		t.Fatalf("got %d tools, want %d: %+v", len(got.Tools), len(wantProps), got.Tools)
	}
	tools := slices.Clone(got.Tools)
	for i := range tools {
		want, ok := wantProps[tools[i].Name]
		if !ok {
			t.Fatalf("unexpected tool %q", tools[i].Name)
		}
		if props := schemaProps(t, tools[i].InputSchema); !reflect.DeepEqual(props, want) {
			t.Errorf("tool %q input properties = %v, want %v", tools[i].Name, props, want)
		}
		tools[i].InputSchema = nil
		tools[i].OutputSchema = nil
	}
	got.Tools = tools

	if want := fixtureWant(); !reflect.DeepEqual(got, want) {
		t.Errorf("Result mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

// rmCheckHeaders asserts that every recorded request carries every config
// header and the wanted User-Agent, that no header value names mcpmoat, and
// that the request methods are the ones that the transport must use.
func rmCheckHeaders(t *testing.T, reqs []recordedRequest, headers map[string]string, wantUA string, sse bool) {
	t.Helper()
	if len(reqs) == 0 {
		t.Fatal("the fixture server saw no request")
	}
	methods := map[string]int{}
	for _, req := range reqs {
		methods[req.Method]++
		for key, want := range headers {
			if got := req.Header.Get(key); got != want {
				t.Errorf("%s %s: header %s = %q, want %q", req.Method, req.Path, key, got, want)
			}
		}
		if got := req.Header.Get("User-Agent"); got != wantUA {
			t.Errorf("%s %s: User-Agent = %q, want %q", req.Method, req.Path, got, wantUA)
		}
		rmCheckNeutral(t, req)
	}
	if methods[http.MethodPost] == 0 {
		t.Errorf("methods seen = %v, want at least one POST", methods)
	}
	if sse && methods[http.MethodGet] == 0 {
		t.Errorf("SSE methods seen = %v, want a GET for the event stream", methods)
	}
	if !sse && methods[http.MethodGet] != 0 {
		// DisableStandaloneSSE is set, so listing opens no GET stream.
		t.Errorf("streamable HTTP methods seen = %v, want no GET", methods)
	}
}

func TestRemote(t *testing.T) {
	t.Parallel()

	const cfgUA = "cfg-agent/1"
	tests := []struct {
		name      string
		sse       bool
		tls       bool
		optUA     string            // RemoteOptions.UserAgent
		cfgUA     bool              // the config sets User-Agent
		wantUA    string            // User-Agent that the server must see
		extraHdrs map[string]string // headers added to the config
	}{
		{name: "http plain", wantUA: rmDefaultUA},
		{name: "http tls", tls: true, wantUA: rmDefaultUA},
		{name: "sse plain", sse: true, wantUA: rmDefaultUA},
		{name: "sse tls", sse: true, tls: true, wantUA: rmDefaultUA},
		{name: "http custom user agent", optUA: "scanner/9", wantUA: "scanner/9"},
		{name: "sse custom user agent", sse: true, optUA: "scanner/9", wantUA: "scanner/9"},
		{name: "http config user agent wins", optUA: "scanner/9", cfgUA: true, wantUA: cfgUA},
		{name: "sse tls config user agent wins", sse: true, tls: true, cfgUA: true, wantUA: cfgUA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ts, rec := startFixture(t, fixtureOpts{TLS: tt.tls, SSE: tt.sse})

			headers := rmHeaders()
			if tt.cfgUA {
				// A lower-case key must still win over the default.
				headers["user-agent"] = cfgUA
			}
			opts := RemoteOptions{UserAgent: tt.optUA}
			if tt.tls {
				opts.baseTransport = ts.Client().Transport
			}

			srv := rmServer(rmKind(tt.sse), rmWithSecretQuery(fixtureURL(ts)), headers)
			got, err := Remote(t.Context(), srv, opts)
			if err != nil {
				t.Fatalf("Remote() error = %v", err)
			}
			rmCheckResult(t, got)

			// The query is part of the configured URL, so the server sees it.
			delete(headers, "user-agent")
			rmCheckHeaders(t, rec.requests(), headers, tt.wantUA, tt.sse)
		})
	}
}

// TestRemoteNoPlaceholderExpansion proves that ${VAR} in a header goes
// to the server as written (issue #88 will add expansion on purpose). No
// t.Setenv here: the variable is unset, and an expansion would give "Bearer ".
func TestRemoteNoPlaceholderExpansion(t *testing.T) {
	t.Parallel()
	for _, sse := range []bool{false, true} {
		t.Run(string(rmKind(sse)), func(t *testing.T) {
			t.Parallel()
			ts, rec := startFixture(t, fixtureOpts{SSE: sse})
			headers := map[string]string{"Authorization": "Bearer ${TOKEN}", "X-Env": "$HOME"}
			srv := rmServer(rmKind(sse), fixtureURL(ts), headers)
			if _, err := Remote(t.Context(), srv, RemoteOptions{}); err != nil {
				t.Fatalf("Remote() error = %v", err)
			}
			rmCheckHeaders(t, rec.requests(), headers, rmDefaultUA, sse)
		})
	}
}

func TestRemoteTLSErrors(t *testing.T) {
	t.Parallel()

	okHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	tests := []struct {
		name       string
		start      func(t *testing.T) (rawURL string, opts RemoteOptions)
		wantReason string
	}{
		{
			name: "untrusted CA",
			start: func(t *testing.T) (string, RemoteOptions) {
				// The httptest certificate is not in the system roots, and the
				// transport is the default one.
				ts, _ := startFixture(t, fixtureOpts{TLS: true})
				return fixtureURL(ts), RemoteOptions{}
			},
			wantReason: "unknown authority",
		},
		{
			name: "hostname mismatch",
			start: func(t *testing.T) (string, RemoteOptions) {
				now := time.Now()
				cert, pool := genCert(t, now.Add(-time.Hour), now.Add(time.Hour), "example.invalid")
				ts := startTLSWithCert(t, okHandler, cert)
				return ts.URL + "/mcp", RemoteOptions{baseTransport: clientTransport(pool)}
			},
			wantReason: "not valid for this host",
		},
		{
			name: "expired certificate",
			start: func(t *testing.T) (string, RemoteOptions) {
				now := time.Now()
				cert, pool := genCert(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour), "127.0.0.1")
				ts := startTLSWithCert(t, okHandler, cert)
				return ts.URL + "/mcp", RemoteOptions{baseTransport: clientTransport(pool)}
			},
			wantReason: "expired",
		},
		{
			name: "not yet valid certificate",
			start: func(t *testing.T) (string, RemoteOptions) {
				now := time.Now()
				cert, pool := genCert(t, now.Add(24*time.Hour), now.Add(48*time.Hour), "127.0.0.1")
				ts := startTLSWithCert(t, okHandler, cert)
				return ts.URL + "/mcp", RemoteOptions{baseTransport: clientTransport(pool)}
			},
			wantReason: "expired or not yet valid",
		},
		{
			name: "https URL to a plain HTTP server",
			start: func(t *testing.T) (string, RemoteOptions) {
				ts, _ := startFixture(t, fixtureOpts{})
				return "https://" + strings.TrimPrefix(ts.URL, "http://") + "/mcp", RemoteOptions{}
			},
			wantReason: "plain HTTP",
		},
	}
	for _, tt := range tests {
		for _, sse := range []bool{false, true} {
			t.Run(tt.name+"/"+string(rmKind(sse)), func(t *testing.T) {
				t.Parallel()
				rawURL, opts := tt.start(t)
				srv := rmServer(rmKind(sse), rmWithSecretQuery(rawURL), rmHeaders())

				_, err := Remote(t.Context(), srv, opts)
				ce := rmRequireConnectError(t, err, KindTLS)
				if !strings.Contains(ce.Reason, tt.wantReason) {
					t.Errorf("Reason = %q, want it to contain %q", ce.Reason, tt.wantReason)
				}
				// The message must not tell the user to skip verification.
				lower := strings.ToLower(err.Error())
				for _, bad := range []string{"insecure", "skip verif", "skip-verif"} {
					if strings.Contains(lower, bad) {
						t.Errorf("error %q suggests to skip verification (%q)", err, bad)
					}
				}
			})
		}
	}
}

// sseEndpointHandler returns an SSE handler that announces endpoint as the
// POST endpoint and then holds the stream open until the request ends or
// stop closes.
func sseEndpointHandler(endpoint string, stop <-chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpoint)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-stop:
		}
	})
}

func TestRemoteHostileOrigin(t *testing.T) {
	t.Parallel()

	t.Run("sse endpoint on another origin", func(t *testing.T) {
		t.Parallel()
		victim := startVictim(t)

		stop := make(chan struct{})
		ts := httptest.NewServer(sseEndpointHandler(victim.URL+"/steal", stop))
		t.Cleanup(ts.Close)
		// Cleanups run last in, first out: stop closes before ts.Close waits
		// for the handler.
		t.Cleanup(func() { close(stop) })

		srv := rmServer(discover.TransportSSE, rmWithSecretQuery(ts.URL+"/sse"), rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		victim.assertUntouched(t)
		_ = rmRequireConnectError(t, err, KindOrigin)
	})

	t.Run("sse endpoint on another port of the same host", func(t *testing.T) {
		t.Parallel()
		victim := startVictim(t)

		stop := make(chan struct{})
		ts := httptest.NewServer(sseEndpointHandler(victim.URL, stop))
		t.Cleanup(ts.Close)
		t.Cleanup(func() { close(stop) })

		srv := rmServer(discover.TransportSSE, ts.URL+"/sse", rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		victim.assertUntouched(t)
		_ = rmRequireConnectError(t, err, KindOrigin)
	})

	t.Run("cross-origin redirect", func(t *testing.T) {
		t.Parallel()
		victim := startVictim(t)

		// Every POST goes to the victim. The SDK may try more than one request
		// (a discover call, then initialize), so a redirect on the first POST
		// only would not stop the connection.
		wrap := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					http.Redirect(w, r, victim.URL+"/steal", http.StatusTemporaryRedirect)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
		ts, _ := startFixture(t, fixtureOpts{Wrap: wrap})

		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		victim.assertUntouched(t)
		_ = rmRequireConnectError(t, err, KindRedirect)
	})

	t.Run("cross-origin redirect on the first POST only", func(t *testing.T) {
		t.Parallel()
		victim := startVictim(t)

		var once sync.Once
		wrap := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected := false
				if r.Method == http.MethodPost {
					once.Do(func() {
						redirected = true
						http.Redirect(w, r, victim.URL+"/steal", http.StatusTemporaryRedirect)
					})
				}
				if !redirected {
					next.ServeHTTP(w, r)
				}
			})
		}
		ts, _ := startFixture(t, fixtureOpts{Wrap: wrap})

		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
		// The SDK can retry after the refused redirect, so the call may succeed
		// or fail. Either way, nothing must reach the victim, and an error must
		// be safe to print.
		if _, err := Remote(t.Context(), srv, RemoteOptions{}); err != nil {
			assertNoSecrets(t, err, rmSecrets...)
		}
		victim.assertUntouched(t)
	})

	t.Run("cross-origin redirect on the SSE GET", func(t *testing.T) {
		t.Parallel()
		victim := startVictim(t)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, victim.URL+"/steal", http.StatusFound)
		}))
		t.Cleanup(ts.Close)

		srv := rmServer(discover.TransportSSE, rmWithSecretQuery(ts.URL+"/sse"), rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		victim.assertUntouched(t)
		_ = rmRequireConnectError(t, err, KindRedirect)
	})

	t.Run("too many redirects", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, r.URL.Path+"x", http.StatusTemporaryRedirect) //nolint:gosec // G710: test server redirect to a fixed local target
		}))
		t.Cleanup(ts.Close)

		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(ts.URL+"/mcp"), rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		_ = rmRequireConnectError(t, err, KindRedirect)
	})
}

func TestRemoteSameOriginRedirect(t *testing.T) {
	t.Parallel()

	// The wrapper sends each POST to /mcp on to /mcp2 with a 307, and serves
	// /mcp2 with the fixture at /mcp. It records what arrives at /mcp2.
	var (
		mu       sync.Mutex
		redirect []http.Header
	)
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/mcp" && r.Method == http.MethodPost:
				http.Redirect(w, r, "/mcp2", http.StatusTemporaryRedirect)
			case r.URL.Path == "/mcp2":
				mu.Lock()
				redirect = append(redirect, r.Header.Clone())
				mu.Unlock()
				r2 := r.Clone(r.Context())
				r2.URL.Path = "/mcp"
				next.ServeHTTP(w, r2)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
	ts, _ := startFixture(t, fixtureOpts{Wrap: wrap})

	headers := rmHeaders()
	srv := rmServer(discover.TransportHTTP, fixtureURL(ts), headers)
	got, err := Remote(t.Context(), srv, RemoteOptions{})
	if err != nil {
		t.Fatalf("Remote() error = %v", err)
	}
	rmCheckResult(t, got)

	mu.Lock()
	defer mu.Unlock()
	if len(redirect) == 0 {
		t.Fatal("no request reached /mcp2: the redirect was not followed")
	}
	for i, h := range redirect {
		for key, want := range headers {
			if got := h.Get(key); got != want {
				t.Errorf("redirected request %d: header %s = %q, want %q", i, key, got, want)
			}
		}
	}
}

func TestRemoteLimitsAndErrors(t *testing.T) {
	t.Parallel()

	t.Run("oversized body", func(t *testing.T) {
		t.Parallel()
		for _, sse := range []bool{false, true} {
			t.Run(string(rmKind(sse)), func(t *testing.T) {
				t.Parallel()
				ts, _ := startFixture(t, fixtureOpts{SSE: sse})
				srv := rmServer(rmKind(sse), rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
				_, err := Remote(t.Context(), srv, RemoteOptions{MaxResponseBytes: 64})
				_ = rmRequireConnectError(t, err, KindTooLarge)
			})
		}
	})

	t.Run("hanging server", func(t *testing.T) {
		t.Parallel()
		for _, sse := range []bool{false, true} {
			t.Run(string(rmKind(sse)), func(t *testing.T) {
				t.Parallel()
				stop := make(chan struct{})
				ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					select {
					case <-r.Context().Done():
					case <-stop:
					}
				}))
				t.Cleanup(ts.Close)
				t.Cleanup(func() { close(stop) })

				ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
				defer cancel()
				srv := rmServer(rmKind(sse), rmWithSecretQuery(ts.URL+"/mcp"), rmHeaders())
				_, err := Remote(ctx, srv, RemoteOptions{})
				_ = rmRequireConnectError(t, err, KindTimeout)
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("errors.Is(err, context.DeadlineExceeded) = false, error: %v", err)
				}
			})
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		ts, _ := startFixture(t, fixtureOpts{})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
		_, err := Remote(ctx, srv, RemoteOptions{})
		_ = rmRequireConnectError(t, err, KindTimeout)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("errors.Is(err, context.Canceled) = false, error: %v", err)
		}
	})

	t.Run("401 names header keys only", func(t *testing.T) {
		t.Parallel()
		for _, sse := range []bool{false, true} {
			t.Run(string(rmKind(sse)), func(t *testing.T) {
				t.Parallel()
				wrap := func(http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						// A hostile server can echo secrets. The error must not
						// repeat the body.
						http.Error(w, "bad token "+rmBearerSecret, http.StatusUnauthorized)
					})
				}
				ts, _ := startFixture(t, fixtureOpts{SSE: sse, Wrap: wrap})
				srv := rmServer(rmKind(sse), rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
				_, err := Remote(t.Context(), srv, RemoteOptions{})
				ce := rmRequireConnectError(t, err, KindHTTP)
				if ce.Status != http.StatusUnauthorized {
					t.Errorf("Status = %d, want 401", ce.Status)
				}
				for _, key := range []string{"Authorization", "X-Api-Key"} {
					if !strings.Contains(ce.Reason, key) {
						t.Errorf("Reason = %q, want it to name the header %s", ce.Reason, key)
					}
				}
			})
		}
	})

	t.Run("403 names header keys only", func(t *testing.T) {
		t.Parallel()
		wrap := func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			})
		}
		ts, _ := startFixture(t, fixtureOpts{Wrap: wrap})
		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		ce := rmRequireConnectError(t, err, KindHTTP)
		if ce.Status != http.StatusForbidden {
			t.Errorf("Status = %d, want 403", ce.Status)
		}
	})

	t.Run("500 gives no SSE hint", func(t *testing.T) {
		t.Parallel()
		wrap := func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
		}
		ts, _ := startFixture(t, fixtureOpts{Wrap: wrap})
		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		ce := rmRequireConnectError(t, err, KindHTTP)
		if ce.Status != http.StatusInternalServerError {
			t.Errorf("Status = %d, want 500", ce.Status)
		}
		if strings.Contains(ce.Reason, "type = sse") {
			t.Errorf("Reason = %q, want no SSE hint for a 500", ce.Reason)
		}
	})

	t.Run("wrong transport: http against an SSE server", func(t *testing.T) {
		t.Parallel()
		ts, _ := startFixture(t, fixtureOpts{SSE: true})
		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		ce := rmRequireConnectError(t, err, KindHTTP)
		if !strings.Contains(ce.Reason, "type = sse") {
			t.Errorf("Reason = %q, want the SSE hint", ce.Reason)
		}
	})

	t.Run("wrong transport: http against 405", func(t *testing.T) {
		t.Parallel()
		wrap := func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusMethodNotAllowed)
			})
		}
		ts, _ := startFixture(t, fixtureOpts{Wrap: wrap})
		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		ce := rmRequireConnectError(t, err, KindHTTP)
		if !strings.Contains(ce.Reason, "type = sse") {
			t.Errorf("Reason = %q, want the SSE hint", ce.Reason)
		}
	})

	t.Run("wrong transport: sse against a streamable server", func(t *testing.T) {
		t.Parallel()
		ts, _ := startFixture(t, fixtureOpts{})
		srv := rmServer(discover.TransportSSE, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		if err == nil {
			t.Fatal("Remote() error = nil, want an error")
		}
		var ce *ConnectError
		if !errors.As(err, &ce) {
			t.Fatalf("error = %T, want *ConnectError", err)
		}
		assertNoSecrets(t, err, rmSecrets...)
	})

	t.Run("connection refused", func(t *testing.T) {
		t.Parallel()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatalf("close listener: %v", err)
		}
		for _, sse := range []bool{false, true} {
			srv := rmServer(rmKind(sse), rmWithSecretQuery("http://"+addr+"/mcp"), rmHeaders())
			_, err := Remote(t.Context(), srv, RemoteOptions{})
			_ = rmRequireConnectError(t, err, KindNetwork)
		}
	})
}

// rmURLRecorder is a base transport that notes the URL of every request and
// then sends the request over a plain transport.
type rmURLRecorder struct {
	base http.RoundTripper

	mu   sync.Mutex
	urls []string
	frag []string
}

func (r *rmURLRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.urls = append(r.urls, req.URL.String())
	r.frag = append(r.frag, req.URL.Fragment+req.URL.RawFragment)
	r.mu.Unlock()
	return r.base.RoundTrip(req)
}

// TestRemoteFragment proves that Remote drops the URL fragment before it gives
// the endpoint to the SDK, so that no fragment secret can reach an error text.
func TestRemoteFragment(t *testing.T) {
	t.Parallel()

	t.Run("success: the fragment is not on any request", func(t *testing.T) {
		t.Parallel()
		for _, sse := range []bool{false, true} {
			t.Run(string(rmKind(sse)), func(t *testing.T) {
				t.Parallel()
				ts, rec := startFixture(t, fixtureOpts{SSE: sse})
				base := &http.Transport{}
				t.Cleanup(base.CloseIdleConnections)
				urls := &rmURLRecorder{base: base}

				headers := rmHeaders()
				srv := rmServer(rmKind(sse), rmWithSecretQueryAndFragment(fixtureURL(ts)), headers)
				got, err := Remote(t.Context(), srv, RemoteOptions{baseTransport: urls})
				if err != nil {
					t.Fatalf("Remote() error = %v", err)
				}
				rmCheckResult(t, got)
				rmCheckHeaders(t, rec.requests(), headers, rmDefaultUA, sse)

				urls.mu.Lock()
				defer urls.mu.Unlock()
				if len(urls.urls) == 0 {
					t.Fatal("the transport saw no request")
				}
				for i, u := range urls.urls {
					if urls.frag[i] != "" || strings.Contains(u, rmFragmentSecret) || strings.Contains(u, "#") {
						t.Errorf("request %d URL %q holds the fragment", i, u)
					}
				}
				// Only the fragment goes: the query is part of the endpoint. Only
				// the first request is checked, because an SSE server sends the
				// POST endpoint of the later requests itself.
				if first := urls.urls[0]; !strings.Contains(first, "token="+rmQuerySecret) {
					t.Errorf("first request URL %q lost the query", first)
				}
				for _, req := range rec.requests() {
					if strings.Contains(req.Path, "#") || strings.Contains(req.Path, rmFragmentSecret) {
						t.Errorf("%s %s: path holds the fragment", req.Method, req.Path)
					}
				}
			})
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		t.Parallel()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatalf("close listener: %v", err)
		}
		for _, sse := range []bool{false, true} {
			srv := rmServer(rmKind(sse), rmWithSecretQueryAndFragment("http://"+addr+"/mcp"), rmHeaders())
			_, err := Remote(t.Context(), srv, RemoteOptions{})
			_ = rmRequireConnectError(t, err, KindNetwork)
		}
	})

	failures := []struct {
		name     string
		wrap     func(http.Handler) http.Handler
		wantKind ConnectKind // empty: any ConnectError
	}{
		{
			name: "500",
			wrap: func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				})
			},
			wantKind: KindHTTP,
		},
		{
			name: "401 that echoes the request URI",
			wrap: func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "bad "+r.RequestURI, http.StatusUnauthorized)
				})
			},
			wantKind: KindHTTP,
		},
		{
			name: "200 with a body that is not JSON",
			wrap: func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte("not json"))
				})
			},
		},
	}
	for _, tt := range failures {
		for _, sse := range []bool{false, true} {
			t.Run(tt.name+"/"+string(rmKind(sse)), func(t *testing.T) {
				t.Parallel()
				ts, _ := startFixture(t, fixtureOpts{SSE: sse, Wrap: tt.wrap})
				srv := rmServer(rmKind(sse), rmWithSecretQueryAndFragment(fixtureURL(ts)), rmHeaders())

				_, err := Remote(t.Context(), srv, RemoteOptions{})
				if tt.wantKind != "" {
					_ = rmRequireConnectError(t, err, tt.wantKind)
					return
				}
				var ce *ConnectError
				if !errors.As(err, &ce) {
					t.Fatalf("Remote() error = %v (%T), want *ConnectError", err, err)
				}
				assertNoSecrets(t, err, rmSecrets...)
			})
		}
	}
}

func TestRemoteConfigErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		srv        discover.Server
		wantReason string
	}{
		{
			name:       "bad scheme",
			srv:        rmServer(discover.TransportHTTP, rmWithSecretQuery("ftp://example.invalid/mcp"), rmHeaders()),
			wantReason: "scheme",
		},
		{
			name:       "file scheme",
			srv:        rmServer(discover.TransportSSE, "file:///etc/passwd?x="+rmQuerySecret, rmHeaders()),
			wantReason: "scheme",
		},
		{
			name:       "no scheme",
			srv:        rmServer(discover.TransportHTTP, "example.invalid/mcp?token="+rmQuerySecret, rmHeaders()),
			wantReason: "scheme",
		},
		{
			name:       "invalid URL",
			srv:        rmServer(discover.TransportHTTP, "http://[::1?token="+rmQuerySecret, rmHeaders()),
			wantReason: "does not parse",
		},
		{
			name:       "no host",
			srv:        rmServer(discover.TransportHTTP, "http:///mcp?token="+rmQuerySecret, rmHeaders()),
			wantReason: "no host",
		},
		{
			name:       "empty URL",
			srv:        rmServer(discover.TransportSSE, "", rmHeaders()),
			wantReason: "scheme",
		},
		{
			name: "reserved header Accept",
			srv: rmServer(discover.TransportHTTP, rmWithSecretQuery("http://127.0.0.1:1/mcp"),
				map[string]string{"Authorization": "Bearer " + rmBearerSecret, "accept": "text/x-" + rmAPIKeySecret}),
			wantReason: `header name not allowed: "accept"`,
		},
		{
			name: "empty header name",
			srv: rmServer(discover.TransportHTTP, rmWithSecretQuery("http://127.0.0.1:1/mcp"),
				map[string]string{"": rmAPIKeySecret}),
			wantReason: "header name not allowed: empty",
		},
		{
			name: "stdio server",
			srv: discover.Server{
				Name:      rmServerName,
				Transport: discover.TransportStdio,
				Command:   "echo",
			},
			wantReason: "not a remote server",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Remote(t.Context(), tt.srv, RemoteOptions{})
			ce := rmRequireConnectError(t, err, KindConfig)
			if !strings.Contains(ce.Reason, tt.wantReason) {
				t.Errorf("Reason = %q, want it to contain %q", ce.Reason, tt.wantReason)
			}
		})
	}
}

func TestRemoteUntrusted(t *testing.T) {
	t.Parallel()

	for _, sse := range []bool{false, true} {
		t.Run(string(rmKind(sse)), func(t *testing.T) {
			t.Parallel()

			t.Run("refused by default", func(t *testing.T) {
				t.Parallel()
				ts, rec := startFixture(t, fixtureOpts{SSE: sse})
				srv := rmServer(rmKind(sse), rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
				srv.Untrusted = true

				_, err := Remote(t.Context(), srv, RemoteOptions{})
				ce := rmRequireConnectError(t, err, KindConfig)
				if !strings.Contains(ce.Reason, "untrusted project server") {
					t.Errorf("Reason = %q, want it to say that the server is untrusted", ce.Reason)
				}
				if n := len(rec.requests()); n != 0 {
					t.Errorf("fixture got %d request(s), want 0: %+v", n, rec.requests())
				}
			})

			t.Run("allowed with AllowUntrusted", func(t *testing.T) {
				t.Parallel()
				ts, rec := startFixture(t, fixtureOpts{SSE: sse})
				headers := rmHeaders()
				srv := rmServer(rmKind(sse), rmWithSecretQuery(fixtureURL(ts)), headers)
				srv.Untrusted = true

				got, err := Remote(t.Context(), srv, RemoteOptions{AllowUntrusted: true})
				if err != nil {
					t.Fatalf("Remote() error = %v", err)
				}
				rmCheckResult(t, got)
				rmCheckHeaders(t, rec.requests(), headers, rmDefaultUA, sse)
			})
		})
	}

	t.Run("refused before the transport check", func(t *testing.T) {
		t.Parallel()
		// An untrusted stdio server is not a remote server, but the answer must
		// still be the same refusal path and must start nothing.
		srv := discover.Server{
			Name:      rmServerName,
			Transport: discover.TransportStdio,
			Command:   "echo",
			Untrusted: true,
		}
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		ce := rmRequireConnectError(t, err, KindConfig)
		if !strings.Contains(ce.Reason, "untrusted project server") {
			t.Errorf("Reason = %q, want it to say that the server is untrusted", ce.Reason)
		}
	})
}

// rmUserinfoURL returns the fixture URL with "user:pw@" user info and the
// secret query.
func rmUserinfoURL(ts *httptest.Server) string {
	return "http://user:pw@" + strings.TrimPrefix(ts.URL, "http://") + "/mcp?token=" + rmQuerySecret
}

func TestRemoteUserinfo(t *testing.T) {
	t.Parallel()

	const wantAuth = "Basic dXNlcjpwdw=="

	for _, sse := range []bool{false, true} {
		t.Run(string(rmKind(sse))+"/sent as Basic auth", func(t *testing.T) {
			t.Parallel()
			ts, rec := startFixture(t, fixtureOpts{SSE: sse})
			srv := rmServer(rmKind(sse), rmUserinfoURL(ts), nil)

			got, err := Remote(t.Context(), srv, RemoteOptions{})
			if err != nil {
				t.Fatalf("Remote() error = %v", err)
			}
			rmCheckResult(t, got)
			rmCheckHeaders(t, rec.requests(), map[string]string{"Authorization": wantAuth}, rmDefaultUA, sse)
		})

		for _, key := range []string{"Authorization", "authorization"} {
			t.Run(string(rmKind(sse))+"/config "+key+" wins", func(t *testing.T) {
				t.Parallel()
				ts, rec := startFixture(t, fixtureOpts{SSE: sse})
				headers := map[string]string{key: "Bearer " + rmBearerSecret}
				srv := rmServer(rmKind(sse), rmUserinfoURL(ts), headers)

				got, err := Remote(t.Context(), srv, RemoteOptions{})
				if err != nil {
					t.Fatalf("Remote() error = %v", err)
				}
				rmCheckResult(t, got)
				rmCheckHeaders(t, rec.requests(), headers, rmDefaultUA, sse)
				for _, req := range rec.requests() {
					if got := req.Header.Values("Authorization"); len(got) != 1 {
						t.Errorf("%s %s: got %d Authorization values %q, want exactly the config one", req.Method, req.Path, len(got), got)
					}
				}
			})
		}
	}

	t.Run("no userinfo leaks in errors", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name     string
			sse      bool
			wrap     func(http.Handler) http.Handler
			wantKind ConnectKind // empty: any ConnectError
		}{
			{
				name: "401 that echoes the credentials",
				wrap: func(http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						// A hostile server can repeat what it received.
						http.Error(w, "bad "+r.Header.Get("Authorization")+" user:pw pw@host dXNlcjpwdw", http.StatusUnauthorized)
					})
				},
				wantKind: KindHTTP,
			},
			{
				name: "200 with a text body that echoes the credentials",
				wrap: func(http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						_, _ = fmt.Fprintf(w, "not json %s user:pw pw@host dXNlcjpwdw", r.Header.Get("Authorization")) //nolint:gosec // G705: test server echoes a request header to check that the client scrubs it
					})
				},
			},
			{
				name: "sse 401 that echoes the credentials",
				sse:  true,
				wrap: func(http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						http.Error(w, "bad "+r.Header.Get("Authorization")+" user:pw pw@host", http.StatusUnauthorized)
					})
				},
				wantKind: KindHTTP,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				ts, _ := startFixture(t, fixtureOpts{SSE: tt.sse, Wrap: tt.wrap})
				srv := rmServer(rmKind(tt.sse), rmUserinfoURL(ts), nil)

				_, err := Remote(t.Context(), srv, RemoteOptions{})
				if tt.wantKind != "" {
					_ = rmRequireConnectError(t, err, tt.wantKind)
					return
				}
				var ce *ConnectError
				if !errors.As(err, &ce) {
					t.Fatalf("Remote() error = %v (%T), want *ConnectError", err, err)
				}
				assertNoSecrets(t, err, rmSecrets...)
			})
		}
	})

	t.Run("no userinfo leaks when the connection is refused", func(t *testing.T) {
		t.Parallel()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatalf("close listener: %v", err)
		}
		for _, sse := range []bool{false, true} {
			srv := rmServer(rmKind(sse), "http://user:pw@"+addr+"/mcp?token="+rmQuerySecret, nil)
			_, err := Remote(t.Context(), srv, RemoteOptions{})
			_ = rmRequireConnectError(t, err, KindNetwork)
		}
	})

	t.Run("no userinfo leaks on a cross-origin redirect", func(t *testing.T) {
		t.Parallel()
		victim := startVictim(t)
		wrap := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					http.Redirect(w, r, victim.URL+"/steal", http.StatusTemporaryRedirect)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
		ts, _ := startFixture(t, fixtureOpts{Wrap: wrap})
		srv := rmServer(discover.TransportHTTP, rmUserinfoURL(ts), nil)

		_, err := Remote(t.Context(), srv, RemoteOptions{})
		if n := victim.requests.Load(); n != 0 {
			t.Errorf("victim got %d request(s), want 0", n)
		}
		_ = rmRequireConnectError(t, err, KindRedirect)
	})
}

// TestRemoteInvalidHeaderAnnotationToolIsReturned is the end-to-end proof of
// the hidden-tool fix. The SDK drops a tool with an invalid "x-mcp-header"
// annotation from ListTools, and a hostile server could use that to hide a
// tool from the scanner. Remote must return the tool anyway.
func TestRemoteInvalidHeaderAnnotationToolIsReturned(t *testing.T) {
	t.Parallel()

	const hiddenName = "hidden_exfil"

	for _, sse := range []bool{false, true} {
		t.Run(string(rmKind(sse)), func(t *testing.T) {
			t.Parallel()
			// AddTool panics on the hostile schema, so rmHostileFixture adds
			// the tool to the tools/list result on the wire.
			ts, _ := startFixture(t, fixtureOpts{SSE: sse, Server: rmHostileFixture(hiddenName)})

			// Control: a plain SDK client does not see the tool. Without this
			// check the test would pass even if the SDK did not filter.
			var transport mcp.Transport = &mcp.StreamableClientTransport{Endpoint: fixtureURL(ts), DisableStandaloneSSE: true}
			if sse {
				transport = &mcp.SSEClientTransport{Endpoint: fixtureURL(ts)}
			}
			cs, err := mcp.NewClient(&mcp.Implementation{Name: "control", Version: "1"}, nil).Connect(t.Context(), transport, nil)
			if err != nil {
				t.Fatalf("control client: connect: %v", err)
			}
			listed, err := cs.ListTools(t.Context(), nil)
			_ = cs.Close()
			if err != nil {
				t.Fatalf("control client: ListTools: %v", err)
			}
			for _, tool := range listed.Tools {
				if tool.Name == hiddenName {
					t.Fatalf("control: the SDK returned %q; the test no longer proves the fix", hiddenName)
				}
			}

			srv := rmServer(rmKind(sse), fixtureURL(ts), nil)
			got, err := Remote(t.Context(), srv, RemoteOptions{})
			if err != nil {
				t.Fatalf("Remote() error = %v", err)
			}
			var names []string
			for _, tool := range got.Tools {
				names = append(names, tool.Name)
			}
			slices.Sort(names)
			if want := []string{"add", "echo", hiddenName}; !reflect.DeepEqual(names, want) {
				t.Fatalf("tool names = %v, want %v", names, want)
			}
			for _, tool := range got.Tools {
				if tool.Name != hiddenName {
					continue
				}
				if tool.Description != hiddenToolDescription {
					t.Errorf("Description = %q, want the text from the server", tool.Description)
				}
				if !strings.Contains(string(tool.InputSchema), "Bad Header!") {
					t.Errorf("InputSchema = %s, want the annotation kept", tool.InputSchema)
				}
			}
		})
	}
}

// newProtocolVersion is the MCP protocol version that NFR-06 requires.
const newProtocolVersion = "2026-07-28"

// rmHostileFixture returns the fixture MCP server with a middleware that adds
// the hostile tool name (hostileHeaderTool) to every tools/list result on the
// wire.
func rmHostileFixture(name string) *mcp.Server {
	srv := newFixtureMCPServer()
	appendToolsOnList(srv, nil, func() []*mcp.Tool {
		return []*mcp.Tool{hostileHeaderTool(name)}
	})
	return srv
}

// rmBodyHas reports whether the body of r holds sub. It puts the body back,
// so the next handler can read it.
func rmBodyHas(t *testing.T, r *http.Request, sub string) bool {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("read request body: %v", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return bytes.Contains(body, []byte(sub))
}

// TestRemoteNewProtocol runs Remote against a stateless Streamable HTTP
// server. Only a stateless server negotiates protocol 2026-07-28 (the SDK
// falls back to an older version with a stateful one), so this is the test
// for the newest protocol (NFR-06).
func TestRemoteNewProtocol(t *testing.T) {
	t.Parallel()

	const hiddenName = "hidden_exfil"

	t.Run("lists everything", func(t *testing.T) {
		t.Parallel()
		for _, useTLS := range []bool{false, true} {
			name := "plain"
			if useTLS {
				name = "tls"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				ts, rec := startFixture(t, fixtureOpts{TLS: useTLS, Stateless: true, Server: rmHostileFixture(hiddenName)})

				opts := RemoteOptions{}
				if useTLS {
					opts.baseTransport = ts.Client().Transport
				}
				headers := rmHeaders()
				srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), headers)
				got, err := Remote(t.Context(), srv, opts)
				if err != nil {
					t.Fatalf("Remote() error = %v", err)
				}
				if got.ProtocolVersion != newProtocolVersion {
					t.Fatalf("ProtocolVersion = %q, want %q", got.ProtocolVersion, newProtocolVersion)
				}

				// The hostile tool must be there although the SDK hides it.
				var hidden *Tool
				var rest []Tool
				for i := range got.Tools {
					if got.Tools[i].Name == hiddenName {
						hidden = &got.Tools[i]
						continue
					}
					rest = append(rest, got.Tools[i])
				}
				if hidden == nil {
					t.Fatalf("tool %q is missing; tools = %v", hiddenName, toolNames(got.Tools))
				}
				if hidden.Description != hiddenToolDescription {
					t.Errorf("Description = %q, want the text from the server", hidden.Description)
				}
				if !strings.Contains(string(hidden.InputSchema), "Bad Header!") {
					t.Errorf("InputSchema = %s, want the annotation kept", hidden.InputSchema)
				}
				got.Tools = rest
				rmCheckResult(t, got)

				reqs := rec.requests()
				rmCheckHeaders(t, reqs, headers, rmDefaultUA, false)
				// A request count of 1 would mean that the headers were checked
				// on too few requests: discover and each list are separate.
				if len(reqs) < 4 {
					t.Errorf("server saw %d requests, want at least 4 (discover and three lists)", len(reqs))
				}
			})
		}
	})

	// The next cases fail after the server negotiated the new protocol, so
	// the failing request is a list request and not the handshake.
	t.Run("401 on a list request", func(t *testing.T) {
		t.Parallel()
		var discovered atomic.Bool
		wrap := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					if rmBodyHas(t, r, "server/discover") {
						discovered.Store(true)
					}
					if rmBodyHas(t, r, methodListTools) {
						http.Error(w, "bad token "+rmBearerSecret+" "+rmAPIKeySecret, http.StatusUnauthorized)
						return
					}
				}
				next.ServeHTTP(w, r)
			})
		}
		ts, _ := startFixture(t, fixtureOpts{Stateless: true, Wrap: wrap})
		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		ce := rmRequireConnectError(t, err, KindHTTP)
		if ce.Status != http.StatusUnauthorized {
			t.Errorf("Status = %d, want 401", ce.Status)
		}
		for _, key := range []string{"Authorization", "X-Api-Key"} {
			if !strings.Contains(ce.Reason, key) {
				t.Errorf("Reason = %q, want it to name the header %s", ce.Reason, key)
			}
		}
		if !discovered.Load() {
			t.Error("the client sent no server/discover request, so the test did not use the new protocol")
		}
	})

	t.Run("cross-origin redirect on a list request", func(t *testing.T) {
		t.Parallel()
		victim := startVictim(t)
		var discovered atomic.Bool
		wrap := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					if rmBodyHas(t, r, "server/discover") {
						discovered.Store(true)
					}
					if rmBodyHas(t, r, methodListTools) {
						http.Redirect(w, r, victim.URL+"/steal", http.StatusTemporaryRedirect)
						return
					}
				}
				next.ServeHTTP(w, r)
			})
		}
		ts, _ := startFixture(t, fixtureOpts{Stateless: true, Wrap: wrap})
		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
		_, err := Remote(t.Context(), srv, RemoteOptions{})
		victim.assertUntouched(t)
		_ = rmRequireConnectError(t, err, KindRedirect)
		if !discovered.Load() {
			t.Error("the client sent no server/discover request, so the test did not use the new protocol")
		}
	})
}

// TestRemoteStaleStatus proves that a 404 answer to the first request (the
// SDK probes with server/discover first, and a server without it can answer
// 404) does not stay as the HTTP status of a later, different failure.
func TestRemoteStaleStatus(t *testing.T) {
	t.Parallel()

	// newProbe404 returns a wrapper that answers the first POST with 404 and
	// passes all other requests on. It reports the body of the first POST and
	// the number of 404 answers.
	type probe struct {
		firstBody atomic.Value // string
		answered  atomic.Int32
	}
	newProbe404 := func() (*probe, func(http.Handler) http.Handler) {
		p := &probe{}
		var first atomic.Bool
		return p, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && first.CompareAndSwap(false, true) {
					body, _ := io.ReadAll(r.Body)
					p.firstBody.Store(string(body))
					p.answered.Add(1)
					http.NotFound(w, r)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	}
	requireProbe := func(t *testing.T, p *probe) {
		t.Helper()
		body, _ := p.firstBody.Load().(string)
		if !strings.Contains(body, "server/discover") {
			t.Fatalf("first POST body = %q, want the SDK server/discover probe; the test no longer covers a stale status", body)
		}
		if n := p.answered.Load(); n != 1 {
			t.Fatalf("404 answers = %d, want 1", n)
		}
	}

	t.Run("fallback after 404 succeeds", func(t *testing.T) {
		t.Parallel()
		p, wrap := newProbe404()
		ts, rec := startFixture(t, fixtureOpts{Wrap: wrap})
		headers := rmHeaders()
		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), headers)

		got, err := Remote(t.Context(), srv, RemoteOptions{})
		if err != nil {
			t.Fatalf("Remote() error = %v", err)
		}
		requireProbe(t, p)
		rmCheckResult(t, got)
		// The recorder sits inside the wrapper, so it never saw the 404 POST.
		rmCheckHeaders(t, rec.requests(), headers, rmDefaultUA, false)
	})

	t.Run("later failure is not labelled 404", func(t *testing.T) {
		t.Parallel()
		p, wrap := newProbe404()

		var failed atomic.Int32
		mcpSrv := newFixtureMCPServer()
		mcpSrv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
				if method == methodListTools {
					failed.Add(1)
					return nil, errors.New("tools backend broke")
				}
				return next(ctx, method, req)
			}
		})
		ts, _ := startFixture(t, fixtureOpts{Server: mcpSrv, Wrap: wrap})
		srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())

		_, err := Remote(t.Context(), srv, RemoteOptions{})
		requireProbe(t, p)
		if failed.Load() == 0 {
			t.Fatal("the tools/list failure never happened; the test checks nothing")
		}
		if err == nil {
			t.Fatal("Remote() error = nil, want an error")
		}
		var ce *ConnectError
		if !errors.As(err, &ce) {
			t.Fatalf("Remote() error = %T (%v), want *ConnectError", err, err)
		}
		assertNoSecrets(t, err, rmSecrets...)
		if ce.Kind == KindHTTP || ce.Status != 0 {
			t.Errorf("Kind = %q, Status = %d, want a non-HTTP failure (the 404 is stale): %v", ce.Kind, ce.Status, err)
		}
		if strings.Contains(err.Error(), "404") {
			t.Errorf("error %q mentions the stale 404", err)
		}
	})
}

// rmCheckNeutral fails the test when a header value or the body of req
// names mcpmoat. A server that recognises the scanner could show it a clean
// tool list and show the real clients a poisoned one.
func rmCheckNeutral(t *testing.T, req recordedRequest) {
	t.Helper()
	for key, values := range req.Header {
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), "mcpmoat") {
				t.Errorf("%s %s: header %s = %q names mcpmoat", req.Method, req.Path, key, value)
			}
		}
	}
	if bytes.Contains(bytes.ToLower(req.Body), []byte("mcpmoat")) {
		t.Errorf("%s %s: body %s names mcpmoat", req.Method, req.Path, req.Body)
	}
}

// rmClientInfo returns the method of the JSON-RPC request in body, and the
// client info that it carries, if any. The initialize request has the client
// info in params.clientInfo; the requests of protocol 2026-07-28 have it in
// params._meta.
func rmClientInfo(t *testing.T, body []byte) (method string, info *mcp.Implementation) {
	t.Helper()
	var msg struct {
		Method string `json:"method"`
		Params struct {
			ClientInfo *mcp.Implementation        `json:"clientInfo"`
			Meta       map[string]json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("decode request body %s: %v", body, err)
	}
	if msg.Params.ClientInfo != nil {
		return msg.Method, msg.Params.ClientInfo
	}
	raw, ok := msg.Params.Meta[mcp.MetaKeyClientInfo]
	if !ok {
		return msg.Method, nil
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("decode %s in %s: %v", mcp.MetaKeyClientInfo, body, err)
	}
	return msg.Method, info
}

// TestRemoteClientIdentity proves that Remote does not tell the server that
// the client is mcpmoat: the User-Agent is the net/http default, and the
// client info in the MCP handshake is the generic clientName and
// clientVersion.
func TestRemoteClientIdentity(t *testing.T) {
	t.Parallel()

	for _, s := range []string{clientName, clientVersion} {
		if strings.Contains(strings.ToLower(s), "mcpmoat") {
			t.Errorf("client identity %q names mcpmoat", s)
		}
	}

	tests := []struct {
		name      string
		sse       bool
		stateless bool
		// wantFrom is a method whose request must carry the client info.
		wantFrom string
	}{
		{name: "http initialize", wantFrom: "initialize"},
		{name: "http new protocol", stateless: true, wantFrom: "server/discover"},
		{name: "sse initialize", sse: true, wantFrom: "initialize"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ts, rec := startFixture(t, fixtureOpts{SSE: tt.sse, Stateless: tt.stateless})
			srv := rmServer(rmKind(tt.sse), fixtureURL(ts), nil)
			got, err := Remote(t.Context(), srv, RemoteOptions{})
			if err != nil {
				t.Fatalf("Remote() error = %v", err)
			}
			rmCheckResult(t, got)

			reqs := rec.requests()
			// The User-Agent check and rmCheckNeutral run on every request.
			rmCheckHeaders(t, reqs, nil, rmDefaultUA, tt.sse)

			var from []string
			for _, req := range reqs {
				if req.Method != http.MethodPost {
					continue
				}
				method, info := rmClientInfo(t, req.Body)
				if info == nil {
					continue
				}
				from = append(from, method)
				if info.Name != clientName || info.Version != clientVersion {
					t.Errorf("%s: client info = %q %q, want %q %q", method, info.Name, info.Version, clientName, clientVersion)
				}
			}
			if !slices.Contains(from, tt.wantFrom) {
				t.Errorf("requests with client info = %v, want %q among them", from, tt.wantFrom)
			}
		})
	}
}

// TestRemoteBlockedConnectRequestIsForgotten proves that a request that the
// HTTP layer blocked during the connect does not label a later, unrelated
// listing error. The SDK first sends server/discover and falls back to
// initialize after any error, so a refused redirect on server/discover
// leaves a working session behind.
func TestRemoteBlockedConnectRequestIsForgotten(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// failList answers the tools/list request. It returns when the
		// request is done.
		failList func(w http.ResponseWriter, r *http.Request, stop <-chan struct{})
		// timeout is the deadline of the Remote call; zero means none.
		timeout    time.Duration
		wantKind   ConnectKind
		wantStatus int
	}{
		{
			name: "listing gets HTTP 500",
			failList: func(w http.ResponseWriter, _ *http.Request, _ <-chan struct{}) {
				http.Error(w, "tools backend broke", http.StatusInternalServerError)
			},
			wantKind:   KindHTTP,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "listing times out",
			failList: func(_ http.ResponseWriter, r *http.Request, stop <-chan struct{}) {
				// Hang until the client gives up (or the test ends).
				select {
				case <-r.Context().Done():
				case <-stop:
				}
			},
			timeout:  time.Second,
			wantKind: KindTimeout,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			victim := startVictim(t)
			stop := make(chan struct{})
			var discovered, listed atomic.Int32
			wrap := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						switch {
						case rmBodyHas(t, r, `"method":"server/discover"`):
							discovered.Add(1)
							http.Redirect(w, r, victim.URL+"/steal", http.StatusTemporaryRedirect)
							return
						case rmBodyHas(t, r, `"method":"`+methodListTools+`"`):
							listed.Add(1)
							tt.failList(w, r, stop)
							return
						}
					}
					next.ServeHTTP(w, r)
				})
			}
			ts, _ := startFixture(t, fixtureOpts{Wrap: wrap})
			// Cleanups run last-in, first-out, so this unblocks a hanging
			// handler before ts.Close waits for it.
			t.Cleanup(func() { close(stop) })

			ctx := t.Context()
			if tt.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.timeout)
				defer cancel()
			}
			srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())
			_, err := Remote(ctx, srv, RemoteOptions{})

			victim.assertUntouched(t)
			if discovered.Load() == 0 {
				t.Fatal("the client sent no server/discover request; the test blocks nothing during the connect")
			}
			if listed.Load() == 0 {
				t.Fatalf("the client never listed tools, so the connect failed: %v", err)
			}
			ce := rmRequireConnectError(t, err, tt.wantKind)
			if ce.Status != tt.wantStatus {
				t.Errorf("Status = %d, want %d", ce.Status, tt.wantStatus)
			}
		})
	}
}

// TestRemoteClosesIdleConnections proves that Remote closes its idle
// connections before it returns. Before headerTransport had a
// CloseIdleConnections method, http.Client.CloseIdleConnections did nothing,
// and the connections stayed open until the idle timeout (30 seconds).
func TestRemoteClosesIdleConnections(t *testing.T) {
	t.Parallel()

	for _, sse := range []bool{false, true} {
		t.Run(string(rmKind(sse)), func(t *testing.T) {
			t.Parallel()
			var (
				mu     sync.Mutex
				open   = map[net.Conn]bool{}
				opened int
			)
			changed := make(chan struct{}, 1)
			connState := func(c net.Conn, state http.ConnState) {
				mu.Lock()
				switch state {
				case http.StateNew:
					open[c] = true
					opened++
				case http.StateClosed, http.StateHijacked:
					delete(open, c)
				}
				mu.Unlock()
				select {
				case changed <- struct{}{}:
				default:
				}
			}
			ts, _ := startFixture(t, fixtureOpts{SSE: sse, ConnState: connState})
			srv := rmServer(rmKind(sse), fixtureURL(ts), nil)
			got, err := Remote(t.Context(), srv, RemoteOptions{})
			if err != nil {
				t.Fatalf("Remote() error = %v", err)
			}
			rmCheckResult(t, got)

			// The server sees a close a moment after the client closes. Wait
			// for it, but far less than the 30 second idle timeout.
			deadline := time.After(2 * time.Second)
			for {
				mu.Lock()
				left, total := len(open), opened
				mu.Unlock()
				if total == 0 {
					t.Fatal("the server saw no connection")
				}
				if left == 0 {
					return
				}
				select {
				case <-changed:
				case <-deadline:
					t.Fatalf("%d of %d connection(s) still open after Remote returned, want 0", left, total)
				}
			}
		})
	}
}

func TestUserinfoSecrets(t *testing.T) {
	t.Parallel()

	const (
		longName  = "tok-NOTREAL-4b1d"
		eightName = "abcdefgh" // exactly minBareSecretLen bytes
		sevenName = "abcdefg"  // one byte short
	)
	basic := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	tests := []struct {
		name string
		user *url.Userinfo
		want []string
		// nameIsSecret tells whether the bare user name must be in the list.
		nameIsSecret bool
	}{
		{name: "nil user", user: nil, want: nil},
		{
			name: "name and password",
			user: url.UserPassword("in", "pw7"),
			want: []string{basic("in:pw7"), "Basic " + basic("in:pw7"), "pw7"},
		},
		{
			// A short name alone is no secret in the list: replaceUserinfo
			// masks it only in a URL authority.
			name: "short name only",
			user: url.User("in"),
			want: []string{basic("in:"), "Basic " + basic("in:")},
		},
		{
			name: "short name and empty password",
			user: url.UserPassword("in", ""),
			want: []string{basic("in:"), "Basic " + basic("in:")},
		},
		{
			name: "password only",
			user: url.UserPassword("", "pw7"),
			want: []string{basic(":pw7"), "Basic " + basic(":pw7"), "pw7"},
		},
		{
			// https://<token>@host/: the name is the credential.
			name:         "long name only is the token",
			user:         url.User(longName),
			want:         []string{basic(longName + ":"), "Basic " + basic(longName+":"), longName},
			nameIsSecret: true,
		},
		{
			name:         "long name and empty password is the token",
			user:         url.UserPassword(longName, ""),
			want:         []string{basic(longName + ":"), "Basic " + basic(longName+":"), longName},
			nameIsSecret: true,
		},
		{
			name:         "name of exactly minBareSecretLen bytes is the token",
			user:         url.User(eightName),
			want:         []string{basic(eightName + ":"), "Basic " + basic(eightName+":"), eightName},
			nameIsSecret: true,
		},
		{
			name: "name one byte under minBareSecretLen is not",
			user: url.User(sevenName),
			want: []string{basic(sevenName + ":"), "Basic " + basic(sevenName+":")},
		},
		{
			// With a password, the name is a user name and not the credential.
			name: "long name with password",
			user: url.UserPassword(longName, "pw7"),
			want: []string{basic(longName + ":pw7"), "Basic " + basic(longName+":pw7"), "pw7"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := userinfoSecrets(tt.user)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("userinfoSecrets() = %q, want %q", got, tt.want)
			}
			if tt.user == nil || tt.user.Username() == "" {
				return
			}
			if has := slices.Contains(got, tt.user.Username()); has != tt.nameIsSecret {
				t.Errorf("userinfoSecrets() = %q; holds the bare user name = %t, want %t", got, has, tt.nameIsSecret)
			}
		})
	}
}

func TestIsAuthScheme(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want bool
	}{
		{in: "Bearer", want: true},
		{in: "Token", want: true},
		{in: "bearer", want: true},
		{in: "Basic", want: true},
		{in: "AWS4-HMAC-SHA256", want: true},
		{in: "x_custom.v2", want: true},
		{in: "0", want: true},
		{in: "", want: false},
		{in: "Bearer:", want: false},
		{in: "Bearer=", want: false},
		{in: "Bea rer", want: false},
		{in: "Bearer\t", want: false},
		{in: "Bear/er", want: false},
		{in: "Bearé", want: false},
		{in: "Вearer", want: false}, // Cyrillic capital Ve, not the Latin B
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.in), func(t *testing.T) {
			t.Parallel()
			if got := isAuthScheme(tt.in); got != tt.want {
				t.Errorf("isAuthScheme(%q) = %t, want %t", tt.in, got, tt.want)
			}
		})
	}
}

func TestCredentialPart(t *testing.T) {
	t.Parallel()

	const tok = "tok-NOTREAL-9c2e"
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "bearer token", value: "Bearer " + tok, want: tok},
		{name: "token scheme", value: "Token " + tok, want: tok},
		{name: "lower-case scheme", value: "bearer " + tok, want: tok},
		{name: "credential of exactly minBareSecretLen bytes", value: "Bearer abcdefgh", want: "abcdefgh"},
		{name: "credential one byte short", value: "Bearer abcdefg", want: ""},
		{name: "extra spaces are trimmed", value: "Bearer   " + tok + "  ", want: tok},
		{name: "spaces do not count toward the length", value: "Bearer   abcdefg   ", want: ""},
		{name: "credential with inner space is kept whole", value: "Digest user=a, realm=b", want: "user=a, realm=b"},
		{name: "no space", value: "Bearer" + tok, want: ""},
		{name: "bare token with no scheme", value: tok, want: ""},
		{name: "empty", value: "", want: ""},
		{name: "space only", value: " ", want: ""},
		{name: "leading space means an empty scheme", value: " Bearer " + tok, want: ""},
		{name: "scheme with colon", value: "Bearer: " + tok, want: ""},
		{name: "scheme with non-ASCII letter", value: "Bearé " + tok, want: ""},
		{name: "scheme only and a space", value: "Bearer ", want: ""},
		{name: "tab is not the separator", value: "Bearer\t" + tok, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := credentialPart(tt.value); got != tt.want {
				t.Errorf("credentialPart(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// TestSplitHeaders checks that splitHeaders gives the raw values to the HTTP
// client and, for classify, each value and the credential part of a value
// with an auth scheme.
func TestSplitHeaders(t *testing.T) {
	t.Parallel()

	const tok = "tok-NOTREAL-1a7f"
	cfg := discover.SecretMap{
		"Authorization": discover.NewSecret("Bearer " + tok),
		"X-Api-Key":     discover.NewSecret(rmAPIKeySecret),
		"X-Short":       discover.NewSecret("Bearer short"),
		"X-Empty":       discover.NewSecret(""),
	}
	headers, values := splitHeaders(cfg)

	wantHeaders := map[string]string{
		"Authorization": "Bearer " + tok,
		"X-Api-Key":     rmAPIKeySecret,
		"X-Short":       "Bearer short",
		"X-Empty":       "",
	}
	if !reflect.DeepEqual(headers, wantHeaders) {
		t.Errorf("headers = %q, want %q", headers, wantHeaders)
	}
	slices.Sort(values)
	wantValues := []string{"Bearer " + tok, "Bearer short", rmAPIKeySecret, tok}
	slices.Sort(wantValues)
	if !reflect.DeepEqual(values, wantValues) {
		t.Errorf("values = %q, want %q", values, wantValues)
	}
}

// TestRemoteBareSecretEcho proves that a server cannot leak a credential by
// echoing it without its frame: the token of "Bearer <token>" without
// "Bearer ", or the token that the URL holds as its user name
// (https://<token>@host/) without the URL around it. The server answers with
// HTTP 200 and a JSON-RPC error whose message holds the bare token, so the
// SDK puts the text in its error.
func TestRemoteBareSecretEcho(t *testing.T) {
	t.Parallel()

	const (
		bearerTok = "tok-NOTREAL-bearer-5e8d"
		userTok   = "tok-NOTREAL-user-3c6b"
	)
	for _, method := range []string{"initialize", methodListTools} {
		for _, sse := range []bool{false, true} {
			for _, userinfo := range []bool{false, true} {
				where := "header"
				secret := bearerTok
				if userinfo {
					where, secret = "userinfo", userTok
				}
				t.Run(method+"/"+string(rmKind(sse))+"/"+where, func(t *testing.T) {
					t.Parallel()
					var echoed atomic.Int32
					mcpSrv := newFixtureMCPServer()
					mcpSrv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
						return func(ctx context.Context, m string, req mcp.Request) (mcp.Result, error) {
							if m == method {
								echoed.Add(1)
								return nil, fmt.Errorf("invalid token %s", secret)
							}
							return next(ctx, m, req)
						}
					})
					ts, _ := startFixture(t, fixtureOpts{SSE: sse, Server: mcpSrv})

					srv := rmServer(rmKind(sse), rmWithSecretQuery(fixtureURL(ts)),
						map[string]string{"Authorization": "Bearer " + bearerTok})
					if userinfo {
						host := strings.TrimPrefix(ts.URL, "http://")
						srv = rmServer(rmKind(sse), "http://"+userTok+"@"+host+"/mcp", nil)
					}

					_, err := Remote(t.Context(), srv, RemoteOptions{})
					if echoed.Load() == 0 {
						t.Fatalf("the server never echoed the token; the test checks nothing (error: %v)", err)
					}
					var ce *ConnectError
					if !errors.As(err, &ce) {
						t.Fatalf("Remote() error = %v (%T), want *ConnectError", err, err)
					}
					// On streamable HTTP, a failed initialize is followed by a
					// session-close DELETE that gets a 404 here. Its status
					// must not turn the JSON-RPC error into KindHTTP.
					if ce.Kind != KindProtocol {
						t.Errorf("Kind = %q (reason %q), want %q", ce.Kind, ce.Reason, KindProtocol)
					}
					assertNoSecrets(t, err, append(slices.Clone(rmSecrets), secret)...)
					// The echo must reach the reason or the cause, masked; else
					// the test would pass on an error that dropped the server
					// text.
					text := ce.Reason
					if cause := errors.Unwrap(ce); cause != nil {
						text += " | " + cause.Error()
					}
					if want := "invalid token " + discover.Mask; !strings.Contains(text, want) {
						t.Errorf("Reason and cause = %q, want them to contain %q", text, want)
					}
				})
			}
		}
	}
}

// TestRemoteContextErrorFirst proves that a timeout is KindTimeout and wraps
// context.DeadlineExceeded also when the SDK formats the context error with
// %v. The legacy SSE transport does that when the server opens the event
// stream and never sends the endpoint event.
func TestRemoteContextErrorFirst(t *testing.T) {
	t.Parallel()

	// openAndHang returns a handler that answers each request of method with
	// HTTP 200 and an open event stream that stays silent until the request
	// ends or stop closes. Other requests get 405.
	openAndHang := func(method string, stop <-chan struct{}) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			select {
			case <-r.Context().Done():
			case <-stop:
			}
		})
	}

	tests := []struct {
		name   string
		kind   discover.Transport
		method string
	}{
		{name: "sse stream without endpoint event", kind: discover.TransportSSE, method: http.MethodGet},
		{name: "streamable POST with a silent stream", kind: discover.TransportHTTP, method: http.MethodPost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stop := make(chan struct{})
			ts := httptest.NewServer(openAndHang(tt.method, stop))
			t.Cleanup(ts.Close)
			// Cleanups run last in, first out: stop closes before ts.Close
			// waits for the handler.
			t.Cleanup(func() { close(stop) })

			ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
			defer cancel()
			srv := rmServer(tt.kind, rmWithSecretQuery(ts.URL+"/mcp"), rmHeaders())
			_, err := Remote(ctx, srv, RemoteOptions{})
			ce := rmRequireConnectError(t, err, KindTimeout)
			if ce.Reason != "timed out" {
				t.Errorf("Reason = %q, want %q", ce.Reason, "timed out")
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("errors.Is(err, context.DeadlineExceeded) = false, error: %v", err)
			}
		})
	}
}

// TestRemoteNoSSEHintAfterConnect proves that a 404 after the session
// connected does not tell the user to switch to the legacy SSE transport:
// the server has already shown that it speaks streamable HTTP.
func TestRemoteNoSSEHintAfterConnect(t *testing.T) {
	t.Parallel()

	var listed atomic.Int32
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && rmBodyHas(t, r, `"method":"`+methodListTools+`"`) {
				listed.Add(1)
				http.NotFound(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	ts, _ := startFixture(t, fixtureOpts{Wrap: wrap})
	srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(fixtureURL(ts)), rmHeaders())

	_, err := Remote(t.Context(), srv, RemoteOptions{})
	if listed.Load() == 0 {
		t.Fatalf("the client never listed tools, so the connect failed: %v", err)
	}
	ce := rmRequireConnectError(t, err, KindHTTP)
	if ce.Status != http.StatusNotFound {
		t.Errorf("Status = %d, want 404", ce.Status)
	}
	if want := "HTTP 404 Not Found"; ce.Reason != want {
		t.Errorf("Reason = %q, want %q (no SSE hint after the connect)", ce.Reason, want)
	}
}
