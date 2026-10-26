package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/llm"
)

// This file is the in-process proof of NFR-01 (issue #77): scan opens no
// network connection and looks up no name other than the configured servers,
// and, only with --llm, the LLM provider. --no-connect opens none at all
// (FR-05).
//
// The tests run the real SDK inspector. They see the network in three places:
//   - the dial hook of the inspector (inspect.SDKOptions.Dial) and of the LLM
//     client (llm.Config.Dial). Both hooks get the address after the DNS pin
//     and the address guard, and they connect only to an allowed address;
//   - net.DefaultResolver, swapped for a Go resolver whose Dial reads the DNS
//     query, records the name and fails. The pinned dialer of the inspector
//     resolves names with it;
//   - http.DefaultTransport, swapped for a RoundTripper that records each
//     request and fails. Code that falls back to http.DefaultClient (the MCP
//     SDK does when it gets no client) ends there.
//
// The tests swap globals and set environment variables, so they never call
// t.Parallel. Go runs the parallel tests only after all the tests that are
// not parallel, so no other test sees the swapped globals.

// errNetBlocked is the error of every connection that the recorder refuses.
var errNetBlocked = errors.New("test: connection refused by the network recorder")

// netRecorder records the network use of one scan. It is safe for
// concurrent use.
type netRecorder struct {
	mu sync.Mutex
	// allow holds the dial addresses ("host:port") that may connect.
	allow map[string]bool
	// dials are the addresses that the dial hooks got, in order.
	dials []string
	// lookups are the names of the DNS queries, in lower case.
	lookups []string
	// roundTrips are the hosts of the requests to http.DefaultTransport.
	roundTrips []string
}

// allowAddr lets the dial hooks connect to addr.
func (r *netRecorder) allowAddr(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.allow == nil {
		r.allow = make(map[string]bool)
	}
	r.allow[addr] = true
}

// dial is the dial hook of the inspector and of the LLM client. It records
// address, and connects only when address is allowed.
func (r *netRecorder) dial(ctx context.Context, network, address string) (net.Conn, error) {
	r.mu.Lock()
	r.dials = append(r.dials, address)
	ok := r.allow[address]
	r.mu.Unlock()
	if !ok {
		return nil, errNetBlocked
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// resolverDial is the Dial of the swapped net.DefaultResolver. It never
// connects. It returns one end of an in-memory pipe, reads the DNS query from
// the other end, records its name and closes the pipe, so the lookup fails.
// A net.Pipe is not a net.PacketConn, so the resolver sends the query in TCP
// framing (a 2-byte length first).
func (r *netRecorder) resolverDial(_ context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		name, err := netReadQueryName(server)
		switch {
		case errors.Is(err, io.EOF):
			// The resolver closed the pipe before it sent a byte: no query.
			return
		case err != nil:
			name = "<unreadable DNS query>"
		}
		r.mu.Lock()
		r.lookups = append(r.lookups, strings.ToLower(name))
		r.mu.Unlock()
	}()
	return client, nil
}

// RoundTrip records the host of req and fails. It replaces
// http.DefaultTransport.
func (r *netRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.roundTrips = append(r.roundTrips, req.URL.Host)
	r.mu.Unlock()
	if req.Body != nil {
		_ = req.Body.Close()
	}
	return nil, errNetBlocked
}

// snapshot returns copies of the records.
func (r *netRecorder) snapshot() (dials, lookups, roundTrips []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.dials), slices.Clone(r.lookups), slices.Clone(r.roundTrips)
}

// errBadDNSQuery means that a DNS query cannot be read.
var errBadDNSQuery = errors.New("test: bad DNS query")

// netReadQueryName reads one DNS query in TCP framing from conn and returns
// the name of its first question. It returns io.EOF when conn ends before the
// first byte.
func netReadQueryName(conn net.Conn) (string, error) {
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return "", err
	}
	msg := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return "", err
	}
	return netQuestionName(msg)
}

// netQuestionName returns the name of the first question of the DNS message
// msg (RFC 1035, section 4.1), without the final dot. A query has no
// compression pointers, so a pointer is an error.
func netQuestionName(msg []byte) (string, error) {
	const headerLen = 12
	if len(msg) < headerLen || binary.BigEndian.Uint16(msg[4:6]) == 0 {
		return "", errBadDNSQuery
	}
	var labels []string
	for i := headerLen; i < len(msg); {
		n := int(msg[i])
		switch {
		case n == 0:
			if len(labels) == 0 {
				return "", errBadDNSQuery
			}
			return strings.Join(labels, "."), nil
		case n&0xc0 != 0 || i+1+n > len(msg):
			return "", errBadDNSQuery
		}
		labels = append(labels, string(msg[i+1:i+1+n]))
		i += 1 + n
	}
	return "", errBadDNSQuery
}

// netViolations returns one line for each use of the network that NFR-01
// does not allow: a dial to an address that is not in allowDials, a lookup of
// a name that is not in allowHosts, and any request to http.DefaultTransport.
// DNS names are not case sensitive, so the names compare in lower case.
func netViolations(dials, lookups, roundTrips, allowDials, allowHosts []string) []string {
	var out []string
	for _, d := range dials {
		if !slices.Contains(allowDials, d) {
			out = append(out, "dial "+d)
		}
	}
	for _, name := range lookups {
		if !slices.ContainsFunc(allowHosts, func(h string) bool { return strings.EqualFold(h, name) }) {
			out = append(out, "lookup "+name)
		}
	}
	for _, h := range roundTrips {
		out = append(out, "http.DefaultTransport request to "+h)
	}
	return out
}

// TestNetViolations checks the assertion of the network tests itself (the
// negative control): a dial or a lookup of something that is not configured,
// and any request to http.DefaultTransport, is a violation.
func TestNetViolations(t *testing.T) {
	t.Parallel()

	allowDials := []string{"127.0.0.1:4000"}
	allowHosts := []string{"mcp.fixture.invalid"}
	tests := []struct {
		name                       string
		dials, lookups, roundTrips []string
		want                       []string
	}{
		{name: "nothing"},
		{name: "configured only", dials: []string{"127.0.0.1:4000", "127.0.0.1:4000"}, lookups: []string{"mcp.fixture.invalid"}},
		{name: "name in another case", lookups: []string{"MCP.Fixture.Invalid"}},
		{name: "unconfigured address", dials: []string{"127.0.0.1:4000", "203.0.113.9:443"}, want: []string{"dial 203.0.113.9:443"}},
		{name: "configured host on another port", dials: []string{"127.0.0.1:4001"}, want: []string{"dial 127.0.0.1:4001"}},
		{name: "unconfigured name", lookups: []string{"api.example.com"}, want: []string{"lookup api.example.com"}},
		{name: "configured name as a prefix", lookups: []string{"mcp.fixture.invalid.example.com"}, want: []string{"lookup mcp.fixture.invalid.example.com"}},
		{name: "unreadable query", lookups: []string{"<unreadable DNS query>"}, want: []string{"lookup <unreadable DNS query>"}},
		{name: "default transport", roundTrips: []string{"127.0.0.1:4000"}, want: []string{"http.DefaultTransport request to 127.0.0.1:4000"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := netViolations(tt.dials, tt.lookups, tt.roundTrips, allowDials, allowHosts)
			if !slices.Equal(got, tt.want) {
				t.Errorf("netViolations() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNetQuestionName checks the DNS query reader of the recorder.
func TestNetQuestionName(t *testing.T) {
	t.Parallel()

	header := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	query := func(qname ...byte) []byte {
		msg := append(slices.Clone(header), qname...)
		return append(msg, 0x00, 0x01, 0x00, 0x01) // type A, class IN
	}
	tests := []struct {
		name    string
		msg     []byte
		want    string
		wantErr bool
	}{
		{name: "three labels", msg: query(3, 'm', 'c', 'p', 7, 'f', 'i', 'x', 't', 'u', 'r', 'e', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0), want: "mcp.fixture.invalid"},
		{name: "short header", msg: header[:6], wantErr: true},
		{name: "no question", msg: append([]byte{0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}, 1, 'a', 0), wantErr: true},
		{name: "root name", msg: query(0), wantErr: true},
		{name: "label past the end", msg: append(slices.Clone(header), 9, 'a', 'b'), wantErr: true},
		{name: "compression pointer", msg: query(0xc0, 0x0c), wantErr: true},
		{name: "no end", msg: append(slices.Clone(header), 1, 'a'), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := netQuestionName(tt.msg)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("netQuestionName() = %q, %v; want %q, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

// netCountingInspector counts the calls to its inner inspector.
type netCountingInspector struct {
	inner inspect.Inspector
	calls atomic.Int32
}

// Inspect implements inspect.Inspector.
func (i *netCountingInspector) Inspect(ctx context.Context, s discover.Server) (inspect.Result, error) {
	i.calls.Add(1)
	return i.inner.Inspect(ctx, s)
}

// netInvalidHost is the configured remote server whose name cannot be
// resolved. The URL has the root form (a final dot), so the resolver looks up
// only this name and never adds the search domains of the system: a search
// domain would give a name that the allow list does not hold.
const netInvalidHost = "mcp.fixture.invalid"

// netWorld is the world of one network test.
type netWorld struct {
	rec  *netRecorder
	home string
	work string
	xdg  string
	// mcpAddr is the address of the configured loopback HTTP server, and
	// mcpConns counts its connections. It is not an MCP server: the dial and
	// the connection still count.
	mcpAddr  string
	mcpConns *atomic.Int32
	// envFile is the file where the benign stdio server writes its
	// environment.
	envFile string
	// marker is the file that the marker script creates when it runs. It is
	// "" when the config has no marker script.
	marker string
}

// netProxyVars are the proxy variables that skipIfProxyEnv checks, in upper
// case. It checks the lower-case names too.
var netProxyVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}

// skipIfProxyEnv skips the test when the real process environment sets a
// proxy variable (netProxyVars, in upper or lower case) to a value that is
// not empty.
//
// net/http reads the proxy variables only once in each process
// (http.ProxyFromEnvironment caches them with a sync.Once). When a variable
// is set, a request can go to the proxy whatever the test does later, and
// t.Setenv(name, "") cannot clear the cached value. Then the test cannot
// prove that scan connects only to the configured servers, so it skips. CI
// sets no proxy, so the tests run there.
func skipIfProxyEnv(t *testing.T) {
	t.Helper()
	for _, upper := range netProxyVars {
		for _, name := range []string{upper, strings.ToLower(upper)} {
			if os.Getenv(name) != "" {
				t.Skipf("the environment sets %s: net/http caches the proxy settings once per process, "+
					"so this test cannot prove that scan connects only to the configured servers (CI sets no proxy)", name)
			}
		}
	}
}

// newNetWorld installs the recorder and builds the world: a private home
// with a trusted global config that has the benign stdio fixture, a remote
// server on a loopback httptest server and a remote server whose name cannot
// be resolved. With marker, the config also has a stdio server that is a
// marker script. The process gets a fake HOME and cache directory, no proxy
// variables and the LLM key, so the tests also see that the stdio child does
// not get the key.
func newNetWorld(t *testing.T, marker bool) *netWorld {
	t.Helper()
	skipIfProxyEnv(t)
	w := &netWorld{rec: &netRecorder{}, home: t.TempDir(), work: t.TempDir(), xdg: t.TempDir()}
	requirePrivateChain(t, w.home)
	benign := inspecttest.Fixture(t, "benign")

	// The real inspector reads the process environment: the parent of the
	// stdio child environment, and the run root below the cache directory
	// (os.UserCacheDir reads HOME on macOS and XDG_CACHE_HOME on Linux).
	t.Setenv("HOME", w.home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(w.home, ".cache"))
	t.Setenv("XDG_CONFIG_HOME", w.xdg)
	t.Setenv(llm.KeyEnv, llmTestKey)
	// skipIfProxyEnv found no proxy variable, so this clearing changes nothing
	// that is cached. It keeps the child environment and any code that reads
	// the variables again free of a proxy.
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		t.Setenv(name, "")
		t.Setenv(strings.ToLower(name), "")
	}

	oldTransport, oldResolver := http.DefaultTransport, net.DefaultResolver
	http.DefaultTransport = w.rec
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: w.rec.resolverDial}
	t.Cleanup(func() {
		http.DefaultTransport = oldTransport
		net.DefaultResolver = oldResolver
	})

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		http.Error(rw, "not an MCP server", http.StatusNotFound)
	}))
	w.mcpConns = countNewConns(srv)
	srv.Start()
	t.Cleanup(srv.Close)
	w.mcpAddr = srv.Listener.Addr().String()
	w.rec.allowAddr(w.mcpAddr)

	w.envFile = filepath.Join(t.TempDir(), "env.txt")
	servers := map[string]any{
		"net-stdio":   map[string]any{"command": benign, "args": []string{"-envfile", w.envFile}},
		"net-local":   map[string]any{"type": "http", "url": "http://" + w.mcpAddr + "/mcp"},
		"net-invalid": map[string]any{"type": "http", "url": "https://" + netInvalidHost + "./mcp"},
	}
	if marker {
		var script string
		script, w.marker = writeMarkerScript(t, t.TempDir())
		servers["net-marker"] = map[string]any{"command": script}
	}
	writeServers(t, w.home, ".claude.json", servers)
	return w
}

// cli builds a cli for the world with the real SDK inspector, whose dial hook
// is the recorder. newClassifier is the classifier factory; nil means an
// llmFactory without a client, which fails the test when it is called.
func (w *netWorld) cli(t *testing.T, newClassifier func(llm.Config) (toolClassifier, error)) (*cli, *netCountingInspector, func() (stdout, stderr string)) {
	t.Helper()
	c, stdout, stderr := dirsCLI(t, w.home, w.work)
	c.getenv = fakeGetenv(map[string]string{"HOME": w.home, "XDG_CONFIG_HOME": w.xdg, llm.KeyEnv: llmTestKey})
	insp := &netCountingInspector{inner: inspect.New(inspect.SDKOptions{Dial: w.rec.dial})}
	c.inspector = insp
	if newClassifier == nil {
		newClassifier = (&llmFactory{t: t}).newClassifier
	}
	c.newClassifier = newClassifier
	return c, insp, func() (string, string) { return stdout.String(), stderr.String() }
}

// assertNetAllowed fails the test for each use of the network that is not
// in allowDials and allowHosts (see netViolations).
func (w *netWorld) assertNetAllowed(t *testing.T, allowDials, allowHosts []string) {
	t.Helper()
	dials, lookups, roundTrips := w.rec.snapshot()
	for _, v := range netViolations(dials, lookups, roundTrips, allowDials, allowHosts) {
		t.Errorf("network use outside the configured servers: %s", v)
	}
}

// dialsTo returns the number of recorded dials to addr.
func (w *netWorld) dialsTo(addr string) int {
	dials, _, _ := w.rec.snapshot()
	n := 0
	for _, d := range dials {
		if d == addr {
			n++
		}
	}
	return n
}

// assertChildEnv checks the environment that the benign stdio server wrote:
// the file exists, and it holds neither the name nor the value of the LLM
// key variable (NFR-04).
func (w *netWorld) assertChildEnv(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(w.envFile)
	if err != nil {
		t.Fatalf("the benign server wrote no environment file: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("the environment file of the benign server is empty")
	}
	if strings.Contains(string(data), llm.KeyEnv) {
		t.Errorf("the stdio server got %s in its environment", llm.KeyEnv)
	}
	llmAssertNoKey(t, llmTestKey, string(data))
}

// assertNetSummary checks the summary statuses of the three servers: the
// stdio fixture is inspected, and the two remote servers failed.
func assertNetSummary(t *testing.T, stdout string) {
	t.Helper()
	want := map[string]string{"net-stdio": "ok", "net-local": "failed", "net-invalid": "failed"}
	for name, status := range want {
		if row := summaryRowOf(t, stdout, name); row.Status != status {
			t.Errorf("summary of %s: status %q, want %q (reason %q)", name, row.Status, status, row.Reason)
		}
	}
}

// TestScanNetworkOnlyConfiguredServers runs a full scan with the real
// inspector (NFR-01): it dials only the configured loopback server, looks up
// only the configured name, sends nothing through http.DefaultTransport and
// builds no LLM client, although the LLM key is set. The stdio child does not
// get the key.
func TestScanNetworkOnlyConfiguredServers(t *testing.T) {
	tests := []struct {
		name    string
		jsonOut bool
	}{
		{"terminal", false},
		{"json", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newNetWorld(t, false)
			c, insp, out := w.cli(t, nil)
			args := []string{"scan"}
			if tt.jsonOut {
				args = append(args, "--json")
			}

			code := c.dispatch(args)

			stdout, stderr := out()
			if code != exitOK {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, stdout, stderr)
			}
			w.assertNetAllowed(t, []string{w.mcpAddr}, []string{netInvalidHost})
			if n := w.dialsTo(w.mcpAddr); n == 0 {
				t.Errorf("no dial to the configured server %s: the dial hook saw nothing", w.mcpAddr)
			} else if c := int(w.mcpConns.Load()); c > n {
				t.Errorf("the configured server got %d connections, the dial hook saw %d: a connection went around the hook", c, n)
			}
			if _, lookups, _ := w.rec.snapshot(); !slices.Contains(lookups, netInvalidHost) {
				t.Errorf("lookups = %q, want a lookup of %s: the resolver hook saw nothing", lookups, netInvalidHost)
			}
			if n := insp.calls.Load(); n != 3 {
				t.Errorf("Inspect calls = %d, want 3", n)
			}
			w.assertChildEnv(t)
			if tt.jsonOut {
				doc := decodeScanJSON(t, stdout)
				got := inspectionByName(doc)
				for name, want := range map[string]string{"net-stdio": "ok", "net-local": "failed", "net-invalid": "failed"} {
					if string(got[name]) != want {
						t.Errorf("inspection of %s = %q, want %q", name, got[name], want)
					}
				}
			} else {
				assertNetSummary(t, stdout)
			}
			llmAssertNoKey(t, llmTestKey, stdout, stderr)
			assertContainsNone(t, "stderr", stderr, []string{"--llm", "LLM"})
		})
	}
}

// TestScanNetworkNoConnect checks --no-connect (FR-05, NFR-01): no dial, no
// lookup, no request, no call to the inspector, no connection to the
// configured server and no process (the marker script does not run).
func TestScanNetworkNoConnect(t *testing.T) {
	w := newNetWorld(t, true)
	c, insp, out := w.cli(t, nil)

	code := c.dispatch([]string{"scan", "--no-connect"})

	stdout, stderr := out()
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, stdout, stderr)
	}
	dials, lookups, roundTrips := w.rec.snapshot()
	if len(dials)+len(lookups)+len(roundTrips) != 0 {
		t.Errorf("--no-connect used the network: dials %q, lookups %q, requests %q", dials, lookups, roundTrips)
	}
	if n := insp.calls.Load(); n != 0 {
		t.Errorf("Inspect calls = %d, want 0", n)
	}
	if n := w.mcpConns.Load(); n != 0 {
		t.Errorf("the configured server got %d connections, want 0", n)
	}
	if _, err := os.Stat(w.marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("marker file exists or cannot be checked (err = %v): a server process ran", err)
	}
	if _, err := os.Stat(w.envFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the benign server wrote its environment (err = %v): it ran", err)
	}
	for _, name := range []string{"net-stdio", "net-local", "net-invalid", "net-marker"} {
		if !strings.Contains(stdout, name) {
			t.Errorf("stdout does not list %s:\n%s", name, stdout)
		}
	}
}

// TestScanNetworkWithLLM checks that --llm adds exactly one host to the
// network use of a scan: the LLM provider at --llm-base-url (NFR-01). The
// LLM client dials through the same recorder (llm.Config.Dial, set in the
// factory). The provider gets one request for each tool of the benign
// fixture, and the stdio child still does not get the key.
func TestScanNetworkWithLLM(t *testing.T) {
	w := newNetWorld(t, false)
	api := newLLMAPI(t)
	w.rec.allowAddr(api.host)
	var builds atomic.Int32
	c, _, out := w.cli(t, func(cfg llm.Config) (toolClassifier, error) {
		builds.Add(1)
		cfg.Dial = w.rec.dial
		return newLLMClassifier(cfg)
	})

	code := c.dispatch([]string{"scan", "--llm", "--llm-base-url", api.srv.URL})

	stdout, stderr := out()
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, stdout, stderr)
	}
	if n := builds.Load(); n != 1 {
		t.Errorf("newClassifier calls = %d, want 1", n)
	}
	w.assertNetAllowed(t, []string{w.mcpAddr, api.host}, []string{netInvalidHost})
	if n := w.dialsTo(api.host); n == 0 {
		t.Errorf("no dial to the LLM provider %s: the LLM dial hook saw nothing", api.host)
	} else if c := int(api.newConns.Load()); c > n {
		t.Errorf("the LLM provider got %d connections, the dial hook saw %d: a connection went around the hook", c, n)
	}
	if n := w.dialsTo(w.mcpAddr); n == 0 {
		t.Errorf("no dial to the configured server %s", w.mcpAddr)
	}
	// The benign fixture has two tools, add and echo.
	if n := api.requests.Load(); n != 2 {
		t.Errorf("the LLM provider got %d requests, want 2", n)
	}
	assertNetSummary(t, stdout)
	w.assertChildEnv(t)
	assertContainsAll(t, "stderr", stderr, []string{llmWarning("anthropic", api.host) + "\n"})
	llmAssertNoKey(t, llmTestKey, stdout, stderr)
}
