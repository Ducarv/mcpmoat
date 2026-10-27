package inspect

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// The tests in this file cover the dial hook: SDKOptions.Dial, which goes
// to RemoteOptions.dial and to newBaseTransportDial. The hook replaces only
// the last dial step of the pinned dialer, so it must see the pinned address
// and never an address that the guard refuses (NFR-01, issue #77).

// errHookCalled is the error of a dial hook that must not be called.
var errHookCalled = errors.New("stub: dial hook called")

// dialRecorder is a dial hook that records every address it gets. If err is
// set, it returns err. Else it connects to target, or to the address it got
// when target is empty. It is safe for concurrent use.
type dialRecorder struct {
	target string
	err    error

	mu    sync.Mutex
	addrs []string
}

// dial has the DialFunc signature.
func (r *dialRecorder) dial(ctx context.Context, network, address string) (net.Conn, error) {
	r.mu.Lock()
	r.addrs = append(r.addrs, address)
	r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	to := address
	if r.target != "" {
		to = r.target
	}
	var d net.Dialer
	return d.DialContext(ctx, network, to)
}

// dials returns a copy of the addresses so far.
func (r *dialRecorder) dials() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.addrs)
}

// connStateCounter returns an http.Server.ConnState hook that adds 1 to n for
// each new connection.
func connStateCounter(n *atomic.Int32) func(net.Conn, http.ConnState) {
	return func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			n.Add(1)
		}
	}
}

// dhServer starts a loopback server that answers "ok" and counts its new
// connections. It returns the server and its port.
func dhServer(t *testing.T) (srv *httptest.Server, port string, newConns *atomic.Int32) {
	t.Helper()
	newConns = &atomic.Int32{}
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = connStateCounter(newConns)
	srv.Start()
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", srv.URL, err)
	}
	return srv, u.Port(), newConns
}

// dhGet sends a GET to target with tr and checks that the answer is 200 "ok".
func dhGet(t *testing.T, tr *http.Transport, target string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest(%q) error = %v", target, err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: error = %v", target, err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("GET %s: status %d body %q error %v, want 200 \"ok\"", target, resp.StatusCode, body, err)
	}
}

// TestDialHookSeesPinnedAddress checks that the hook gets the pinned IP
// address and port of the guarded server name, not the name, and only the
// addresses that the guard lets through. The hook then connects to a
// loopback server, so the requests succeed. The second request needs a new
// dial and uses the pin: no new lookup, the same address.
func TestDialHookSeesPinnedAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		urlHost  string
		answer   []string
		wantAddr string // without the port
	}{
		{name: "ipv4", urlHost: "remote.test", answer: []string{"203.0.113.7"}, wantAddr: "203.0.113.7"},
		{name: "ipv6", urlHost: "remote.test", answer: []string{"2001:db8::7"}, wantAddr: "[2001:db8::7]"},
		{name: "refused address dropped", urlHost: "remote.test", answer: []string{"127.0.0.1", "169.254.169.254", "203.0.113.7"}, wantAddr: "203.0.113.7"},
		{name: "ipv4-mapped answer unmapped", urlHost: "remote.test", answer: []string{"::ffff:203.0.113.7"}, wantAddr: "203.0.113.7"},
		{name: "mixed case host", urlHost: "Remote.TEST", answer: []string{"203.0.113.7"}, wantAddr: "203.0.113.7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv, port, newConns := dhServer(t)

			var lookups atomic.Int32
			lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
				if strings.ToLower(host) != "remote.test" {
					return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
				}
				lookups.Add(1)
				var addrs []netip.Addr
				for _, a := range tt.answer {
					addrs = append(addrs, netip.MustParseAddr(a))
				}
				return addrs, nil
			}
			rec := &dialRecorder{target: srv.Listener.Addr().String()}

			tr := newBaseTransportDial(lookup, rec.dial, "remote.test")
			// No proxy: the test must not depend on HTTP_PROXY of the machine.
			tr.Proxy = nil
			t.Cleanup(tr.CloseIdleConnections)

			target := "http://" + tt.urlHost + ":" + port + "/"
			for range 2 {
				dhGet(t, tr, target)
				// Drop the idle connection, so the next request needs a
				// new dial.
				tr.CloseIdleConnections()
			}

			want := tt.wantAddr + ":" + port
			if got := rec.dials(); !slices.Equal(got, []string{want, want}) {
				t.Errorf("hook dials = %q, want %q twice", got, want)
			}
			if n := lookups.Load(); n != 1 {
				t.Errorf("lookups = %d, want 1 (the second dial uses the pin)", n)
			}
			if n := newConns.Load(); n != 2 {
				t.Errorf("server connections = %d, want 2 (both through the hook)", n)
			}
		})
	}
}

// TestDialHookNotCalledForRefusedAddress checks that the guard runs before
// the hook: when the guarded name resolves only to refused addresses (see
// refusedAddr), the dial of the base transport fails with errAddrRefused
// itself and the hook is never called.
func TestDialHookNotCalledForRefusedAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		answer []string
	}{
		{name: "loopback", answer: []string{"127.0.0.1"}},
		{name: "ipv6 loopback", answer: []string{"::1"}},
		{name: "ipv4-mapped loopback", answer: []string{"::ffff:127.0.0.1"}},
		{name: "unspecified", answer: []string{"0.0.0.0"}},
		{name: "this network", answer: []string{"0.1.2.3"}},
		{name: "cloud metadata", answer: []string{"169.254.169.254"}},
		{name: "alibaba metadata", answer: []string{"100.100.100.200"}},
		{name: "aws ipv6 metadata", answer: []string{"fd00:ec2::254"}},
		{name: "azure wireserver", answer: []string{"168.63.129.16"}},
		{name: "nat64 metadata", answer: []string{"64:ff9b::a9fe:a9fe"}},
		{name: "multicast", answer: []string{"ff02::1"}},
		{name: "all refused", answer: []string{"127.0.0.1", "::1", "169.254.169.254"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lookup := func(context.Context, string, string) ([]netip.Addr, error) {
				var addrs []netip.Addr
				for _, a := range tt.answer {
					addrs = append(addrs, netip.MustParseAddr(a))
				}
				return addrs, nil
			}
			rec := &dialRecorder{err: errHookCalled}
			tr := newBaseTransportDial(lookup, rec.dial, "Guarded.TEST")

			for _, address := range []string{"guarded.test:443", "GUARDED.test:443"} {
				conn, err := tr.DialContext(t.Context(), "tcp", address)
				if conn != nil {
					_ = conn.Close()
				}
				// The text is exactly the fixed text: no address, no name.
				if !errors.Is(err, errAddrRefused) || err.Error() != errAddrRefused.Error() {
					t.Errorf("DialContext(%q) error = %v, want exactly errAddrRefused", address, err)
				}
			}
			if got := rec.dials(); len(got) != 0 {
				t.Errorf("hook dials = %q, want none", got)
			}
		})
	}
}

// TestDialHookNil checks that a nil hook keeps the default dialer:
// newBaseTransport and newBaseTransportDial with a nil dial both connect to
// a loopback server.
func TestDialHookNil(t *testing.T) {
	t.Parallel()

	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host != "local.test" {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	tests := []struct {
		name string
		make func() *http.Transport
	}{
		{name: "newBaseTransport", make: func() *http.Transport { return newBaseTransport(lookup, "") }},
		{name: "newBaseTransportDial nil", make: func() *http.Transport { return newBaseTransportDial(lookup, nil, "") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, port, newConns := dhServer(t)
			tr := tt.make()
			tr.Proxy = nil
			t.Cleanup(tr.CloseIdleConnections)

			dhGet(t, tr, "http://local.test:"+port+"/")
			if n := newConns.Load(); n != 1 {
				t.Errorf("server connections = %d, want 1", n)
			}
		})
	}
}

// TestDialHookSeesProxyAddress checks the documented proxy case: with a
// proxy, the hook gets the pinned address of the proxy, and the server name
// is never resolved (the proxy resolves it).
func TestDialHookSeesProxyAddress(t *testing.T) {
	t.Parallel()

	var proxied atomic.Value
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Store(r.URL.Host)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(proxy.Close)
	pu, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", proxy.URL, err)
	}

	var serverLookups atomic.Int32
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host == "proxy.test" {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		serverLookups.Add(1)
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	rec := &dialRecorder{}
	tr := newBaseTransportDial(lookup, rec.dial, "remote.test")
	tr.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: "proxy.test:" + pu.Port()})
	t.Cleanup(tr.CloseIdleConnections)

	dhGet(t, tr, "http://remote.test:9/")

	if got, want := rec.dials(), []string{"127.0.0.1:" + pu.Port()}; !slices.Equal(got, want) {
		t.Errorf("hook dials = %q, want %q (the proxy)", got, want)
	}
	if n := serverLookups.Load(); n != 0 {
		t.Errorf("lookups of the server name = %d, want 0", n)
	}
	if got := proxied.Load(); got != "remote.test:9" {
		t.Errorf("proxy got host %v, want remote.test:9", got)
	}
}

// TestDialHookSDKInspect checks the exported path: SDKOptions.Dial reaches
// the base transport of Remote. Every connection of a full inspection of a
// loopback MCP server goes through the hook, to the address of the server.
func TestDialHookSDKInspect(t *testing.T) {
	t.Parallel()

	for _, sse := range []bool{false, true} {
		t.Run(string(rmKind(sse)), func(t *testing.T) {
			t.Parallel()
			var newConns atomic.Int32
			ts, _ := startFixture(t, fixtureOpts{SSE: sse, ConnState: connStateCounter(&newConns)})

			rec := &dialRecorder{}
			inspector := New(SDKOptions{Dial: rec.dial})
			// Never read the real environment.
			inspector.environ = func() []string { return nil }
			srv := rmServer(rmKind(sse), fixtureURL(ts), rmHeaders())
			srv.Client = discover.ClientClaudeCode

			got, err := inspector.Inspect(t.Context(), srv)
			if err != nil {
				t.Fatalf("Inspect() error = %v", err)
			}
			rmCheckResult(t, got, rmHeaderSecrets...)

			dials := rec.dials()
			if len(dials) == 0 {
				t.Fatal("hook dials = none, want at least one")
			}
			want := ts.Listener.Addr().String()
			for _, d := range dials {
				if d != want {
					t.Errorf("hook dial = %q, want %q", d, want)
				}
			}
			// Each server connection came from a dial of the client. The
			// transport can dial a connection that it then does not use, so
			// the server can see fewer, never more.
			if n := int(newConns.Load()); n == 0 || n > len(dials) {
				t.Errorf("server connections = %d, want 1 to %d (the hook dials)", n, len(dials))
			}
		})
	}
}
