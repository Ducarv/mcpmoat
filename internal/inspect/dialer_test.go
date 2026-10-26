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
	"time"
)

// The tests in this file never use real DNS. pdLookup stands in for the
// resolver and pdDialer for the network: it hands out in-memory connections
// from net.Pipe and records each address that it gets.

// pdAnswer is the answer of pdLookup to one lookup call.
type pdAnswer struct {
	addrs []netip.Addr
	err   error
}

// pdLookupCall is one call that pdLookup got.
type pdLookupCall struct {
	network string
	host    string
}

// pdLookup is a stub lookupFunc. Call i gets answers[i]; calls after the last
// answer get the last answer again. It is safe for concurrent use.
type pdLookup struct {
	answers []pdAnswer

	mu    sync.Mutex
	calls []pdLookupCall
}

// lookup has the lookupFunc signature.
func (l *pdLookup) lookup(_ context.Context, network, host string) ([]netip.Addr, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, pdLookupCall{network: network, host: host})
	if len(l.answers) == 0 {
		return nil, nil
	}
	a := l.answers[min(len(l.calls), len(l.answers))-1]
	// A copy, so the dialer cannot change the table of the test.
	return slices.Clone(a.addrs), a.err
}

// lookups returns a copy of the calls so far.
func (l *pdLookup) lookups() []pdLookupCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.calls)
}

// pdConn is a connection from pdDialer. It knows the address that it was
// dialled with and whether it was closed.
type pdConn struct {
	net.Conn
	addr   string
	closed atomic.Bool
}

// Close records the close and closes the pipe.
func (c *pdConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// pdDialer is a stub dialFunc. A dial to an address in fail returns that
// error; every other dial returns a new pdConn. It is safe for concurrent
// use.
type pdDialer struct {
	mu    sync.Mutex
	fail  map[string]error
	dials []string
	conns []*pdConn
}

func newPDDialer(t *testing.T) *pdDialer {
	t.Helper()
	d := &pdDialer{fail: map[string]error{}}
	t.Cleanup(func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, c := range d.conns {
			_ = c.Close()
		}
	})
	return d
}

// dial has the dialFunc signature.
func (d *pdDialer) dial(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials = append(d.dials, address)
	if err, ok := d.fail[address]; ok {
		return nil, err
	}
	client, server := net.Pipe()
	// The server end is not used. Close it now: a Close of the client end
	// still works, and a test that reads would get io.EOF, not a hang.
	_ = server.Close()
	c := &pdConn{Conn: client, addr: address}
	d.conns = append(d.conns, c)
	return c, nil
}

// setFail makes dials to the addresses fail with errPDRefused, and all other
// dials succeed.
func (d *pdDialer) setFail(addrs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fail = map[string]error{}
	for _, a := range addrs {
		d.fail[a] = errPDRefused
	}
}

// takeDials returns the dial addresses since the last call and forgets them.
func (d *pdDialer) takeDials() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	dials := d.dials
	d.dials = nil
	return dials
}

// errPDRefused is the error of a stub dial that fails.
var errPDRefused = errors.New("stub: connection refused")

// errPDLookup is the error of a stub lookup that fails.
var errPDLookup = errors.New("stub: lookup failed")

func pdAddrs(t *testing.T, s ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(s))
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// pdStep is one DialContext call of a pdCase.
type pdStep struct {
	// network is the dial network. Empty means "tcp".
	network string
	address string
	// fail are the addresses whose dial fails during this step.
	fail []string

	// wantDials are the addresses that the stub dial gets in this step, in
	// order.
	wantDials []string
	// wantConn is the address of the returned connection. Empty means that
	// the step must fail.
	wantConn string
	// wantErr, when set, must match the error with errors.Is.
	wantErr error
	// wantNotFound means the error must be a *net.DNSError with IsNotFound.
	wantNotFound bool
}

func TestPinnedDialerDialContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		answers []pdAnswer
		steps   []pdStep
		// wantLookups are the networks of the lookup calls, in order.
		wantLookups []string
	}{
		{
			// The core of #102: the second answer points at localhost, but
			// the second dial still goes to the first address.
			name: "rebind to localhost is ignored after the pin",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "203.0.113.10")},
				{addrs: pdAddrs(t, "127.0.0.1")},
			},
			steps: []pdStep{
				{address: "rebind.test:443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
				{address: "rebind.test:443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
			},
			wantLookups: []string{"ip"},
		},
		{
			name: "pin keeps the port of each dial",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "203.0.113.10")},
				{addrs: pdAddrs(t, "127.0.0.1")},
			},
			steps: []pdStep{
				{address: "rebind.test:443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
				{address: "rebind.test:8080", wantDials: []string{"203.0.113.10:8080"}, wantConn: "203.0.113.10:8080"},
			},
			wantLookups: []string{"ip"},
		},
		{
			name: "host name case does not matter for the pin",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "203.0.113.10")},
				{addrs: pdAddrs(t, "127.0.0.1")},
			},
			steps: []pdStep{
				{address: "Rebind.TEST:443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
				{address: "rebind.test:443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
				{address: "REBIND.test:443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
			},
			wantLookups: []string{"ip"},
		},
		{
			name: "different hosts get their own pins",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "203.0.113.10")},
				{addrs: pdAddrs(t, "203.0.113.20")},
				{addrs: pdAddrs(t, "127.0.0.1")},
			},
			steps: []pdStep{
				{address: "a.test:443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
				{address: "b.test:443", wantDials: []string{"203.0.113.20:443"}, wantConn: "203.0.113.20:443"},
				{address: "a.test:443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
				{address: "b.test:443", wantDials: []string{"203.0.113.20:443"}, wantConn: "203.0.113.20:443"},
			},
			wantLookups: []string{"ip", "ip"},
		},
		{
			// localhost counts as loopback by its name (no cleartext
			// warning), so only its loopback addresses are dialled.
			name: "localhost dials loopback addresses only",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "192.0.2.7", "127.0.0.1")},
			},
			steps: []pdStep{
				{address: "localhost:8080", wantDials: []string{"127.0.0.1:8080"}, wantConn: "127.0.0.1:8080"},
			},
			wantLookups: []string{"ip"},
		},
		{
			// LOCALHOST shares the pin of localhost (the key folds the
			// case), so it must dial loopback addresses only too. Otherwise
			// a later localhost dial would reuse a non-loopback pin.
			name: "LOCALHOST dials loopback only and shares the pin",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "192.0.2.7", "127.0.0.1")},
			},
			steps: []pdStep{
				{address: "LOCALHOST:8080", wantDials: []string{"127.0.0.1:8080"}, wantConn: "127.0.0.1:8080"},
				{address: "localhost:8080", wantDials: []string{"127.0.0.1:8080"}, wantConn: "127.0.0.1:8080"},
			},
			wantLookups: []string{"ip"},
		},
		{
			name: "localhost without a loopback address is not found",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "192.0.2.7", "2001:db8::7")},
			},
			steps: []pdStep{
				{address: "localhost:8080", wantNotFound: true},
			},
			wantLookups: []string{"ip"},
		},
		{
			name: "IPv4 literal skips the lookup",
			steps: []pdStep{
				{address: "127.0.0.1:8080", wantDials: []string{"127.0.0.1:8080"}, wantConn: "127.0.0.1:8080"},
				{address: "127.0.0.1:8080", wantDials: []string{"127.0.0.1:8080"}, wantConn: "127.0.0.1:8080"},
			},
		},
		{
			name: "IPv6 literal skips the lookup",
			steps: []pdStep{
				{address: "[::1]:8080", wantDials: []string{"[::1]:8080"}, wantConn: "[::1]:8080"},
			},
		},
		{
			name: "IPv6 literal with zone skips the lookup",
			steps: []pdStep{
				{address: "[fe80::1%en0]:8080", wantDials: []string{"[fe80::1%en0]:8080"}, wantConn: "[fe80::1%en0]:8080"},
			},
		},
		{
			name: "first address fails, second is pinned and reused",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "203.0.113.1", "203.0.113.2")},
				{addrs: pdAddrs(t, "127.0.0.1")},
			},
			steps: []pdStep{
				{
					address:   "multi.test:443",
					fail:      []string{"203.0.113.1:443"},
					wantDials: []string{"203.0.113.1:443", "203.0.113.2:443"},
					wantConn:  "203.0.113.2:443",
				},
				// The first address works again, but the pin is the second.
				{address: "multi.test:443", wantDials: []string{"203.0.113.2:443"}, wantConn: "203.0.113.2:443"},
			},
			wantLookups: []string{"ip"},
		},
		{
			name: "IPv4-mapped IPv6 address is unmapped",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "::ffff:203.0.113.5")},
				{addrs: pdAddrs(t, "127.0.0.1")},
			},
			steps: []pdStep{
				{address: "mapped.test:443", wantDials: []string{"203.0.113.5:443"}, wantConn: "203.0.113.5:443"},
				{address: "mapped.test:443", wantDials: []string{"203.0.113.5:443"}, wantConn: "203.0.113.5:443"},
			},
			wantLookups: []string{"ip"},
		},
		{
			name: "IPv6 answer is dialled with brackets",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "2001:db8::1")},
			},
			steps: []pdStep{
				{address: "v6.test:443", wantDials: []string{"[2001:db8::1]:443"}, wantConn: "[2001:db8::1]:443"},
			},
			wantLookups: []string{"ip"},
		},
		{
			name:    "empty answer is not found",
			answers: []pdAnswer{{}},
			steps: []pdStep{
				{address: "empty.test:443", wantNotFound: true},
			},
			wantLookups: []string{"ip"},
		},
		{
			name:    "answer with only invalid addresses is not found",
			answers: []pdAnswer{{addrs: []netip.Addr{{}, {}}}},
			steps: []pdStep{
				{address: "invalid.test:443", wantNotFound: true},
			},
			wantLookups: []string{"ip"},
		},
		{
			name:    "lookup error passes through",
			answers: []pdAnswer{{err: errPDLookup}},
			steps: []pdStep{
				{address: "broken.test:443", wantErr: errPDLookup},
			},
			wantLookups: []string{"ip"},
		},
		{
			name: "failed lookup pins nothing",
			answers: []pdAnswer{
				{err: errPDLookup},
				{addrs: pdAddrs(t, "203.0.113.10")},
			},
			steps: []pdStep{
				{address: "flaky.test:443", wantErr: errPDLookup},
				{address: "flaky.test:443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
			},
			wantLookups: []string{"ip", "ip"},
		},
		{
			name: "all addresses fail: first error, nothing pinned",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "203.0.113.1", "203.0.113.2")},
				{addrs: pdAddrs(t, "203.0.113.3")},
			},
			steps: []pdStep{
				{
					address:   "down.test:443",
					fail:      []string{"203.0.113.1:443", "203.0.113.2:443"},
					wantDials: []string{"203.0.113.1:443", "203.0.113.2:443"},
					wantErr:   errPDRefused,
				},
				// No pin, so the next dial resolves again.
				{address: "down.test:443", wantDials: []string{"203.0.113.3:443"}, wantConn: "203.0.113.3:443"},
			},
			wantLookups: []string{"ip", "ip"},
		},
		{
			name: "pinned host whose dial fails does not resolve again",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "203.0.113.10")},
				{addrs: pdAddrs(t, "127.0.0.1")},
			},
			steps: []pdStep{
				{address: "pinned.test:443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
				{
					address:   "pinned.test:443",
					fail:      []string{"203.0.113.10:443"},
					wantDials: []string{"203.0.113.10:443"},
					wantErr:   errPDRefused,
				},
			},
			wantLookups: []string{"ip"},
		},
		{
			name:    "tcp4 resolves ip4",
			answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10")}},
			steps: []pdStep{
				{network: "tcp4", address: "four.test:443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
			},
			wantLookups: []string{"ip4"},
		},
		{
			name:    "tcp6 resolves ip6",
			answers: []pdAnswer{{addrs: pdAddrs(t, "2001:db8::1")}},
			steps: []pdStep{
				{network: "tcp6", address: "six.test:443", wantDials: []string{"[2001:db8::1]:443"}, wantConn: "[2001:db8::1]:443"},
			},
			wantLookups: []string{"ip6"},
		},
		{
			name:    "udp is refused",
			answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10")}},
			steps: []pdStep{
				{network: "udp", address: "dns.test:53", wantErr: errDialNetwork},
			},
		},
		{
			name:    "unix is refused",
			answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10")}},
			steps: []pdStep{
				{network: "unix", address: "sock.test:1", wantErr: errDialNetwork},
			},
		},
		{
			name:    "port above 65535 is refused",
			answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10")}},
			steps: []pdStep{
				{address: "port.test:65536", wantErr: errDialPort},
			},
		},
		{
			name:    "named port is refused",
			answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10")}},
			steps: []pdStep{
				{address: "port.test:https", wantErr: errDialPort},
			},
		},
		{
			name:    "negative port is refused",
			answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10")}},
			steps: []pdStep{
				{address: "port.test:-1", wantErr: errDialPort},
			},
		},
		{
			name:    "IP literal with bad port is refused",
			answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10")}},
			steps: []pdStep{
				{address: "127.0.0.1:99999", wantErr: errDialPort},
			},
		},
		{
			name:    "address without port fails",
			answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10")}},
			steps: []pdStep{
				// net.SplitHostPort fails; any error is fine, but no
				// lookup and no dial may occur.
				{address: "noport.test"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lk := &pdLookup{answers: tt.answers}
			dl := newPDDialer(t)
			d := newPinnedDialer(lk.lookup, dl.dial)

			for i, st := range tt.steps {
				network := st.network
				if network == "" {
					network = "tcp"
				}
				dl.setFail(st.fail)

				conn, err := d.DialContext(t.Context(), network, st.address)
				dials := dl.takeDials()

				if !slices.Equal(dials, st.wantDials) {
					t.Errorf("step %d: DialContext(%q, %q) dials = %q, want %q", i, network, st.address, dials, st.wantDials)
				}
				if st.wantConn != "" {
					if err != nil {
						t.Fatalf("step %d: DialContext(%q, %q) error = %v, want nil", i, network, st.address, err)
					}
					pc, ok := conn.(*pdConn)
					if !ok {
						t.Fatalf("step %d: DialContext() conn = %T, want *pdConn", i, conn)
					}
					if pc.addr != st.wantConn {
						t.Errorf("step %d: DialContext() conn address = %q, want %q", i, pc.addr, st.wantConn)
					}
					if pc.closed.Load() {
						t.Errorf("step %d: DialContext() returned a closed conn", i)
					}
					continue
				}

				if err == nil {
					t.Fatalf("step %d: DialContext(%q, %q) error = nil, want an error", i, network, st.address)
				}
				if conn != nil {
					t.Errorf("step %d: DialContext() conn = %v, want nil with an error", i, conn)
				}
				if st.wantErr != nil && !errors.Is(err, st.wantErr) {
					t.Errorf("step %d: DialContext() error = %v, want errors.Is %v", i, err, st.wantErr)
				}
				if st.wantNotFound {
					var dnsErr *net.DNSError
					if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
						t.Errorf("step %d: DialContext() error = %#v, want *net.DNSError with IsNotFound", i, err)
					}
				}
			}

			var networks []string
			for _, c := range lk.lookups() {
				networks = append(networks, c.network)
			}
			if !slices.Equal(networks, tt.wantLookups) {
				t.Errorf("lookup networks = %q, want %q", networks, tt.wantLookups)
			}
		})
	}
}

// TestPinnedDialerLookupGetsHost checks that the lookup gets the host name
// without the port.
func TestPinnedDialerLookupGetsHost(t *testing.T) {
	t.Parallel()

	lk := &pdLookup{answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10")}}}
	d := newPinnedDialer(lk.lookup, newPDDialer(t).dial)
	if _, err := d.DialContext(t.Context(), "tcp", "mcp.example.test:8443"); err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	want := []pdLookupCall{{network: "ip", host: "mcp.example.test"}}
	if got := lk.lookups(); !slices.Equal(got, want) {
		t.Errorf("lookups = %+v, want %+v", got, want)
	}
}

// TestPinnedDialerContextCancelled checks that DialContext stops trying the
// next addresses when the context ends during a failed dial.
func TestPinnedDialerContextCancelled(t *testing.T) {
	t.Parallel()

	lk := &pdLookup{answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.1", "203.0.113.2", "203.0.113.3")}}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var dials []string
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		dials = append(dials, address)
		// The caller gives up while the first dial runs.
		cancel()
		return nil, context.Canceled
	}
	d := newPinnedDialer(lk.lookup, dial)

	conn, err := d.DialContext(ctx, "tcp", "slow.test:443")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("DialContext() error = %v, want context.Canceled", err)
	}
	if conn != nil {
		t.Errorf("DialContext() conn = %v, want nil", conn)
	}
	if want := []string{"203.0.113.1:443"}; !slices.Equal(dials, want) {
		t.Errorf("dials = %q, want %q (no dial after the cancel)", dials, want)
	}
}

// TestPinnedDialerParallelFirstDial checks that two first dials to one host,
// whose lookups give different addresses, end with both connections at one
// pinned address. Run it with -race.
func TestPinnedDialerParallelFirstDial(t *testing.T) {
	t.Parallel()

	// Both lookups wait here until both have started, so neither dial can
	// pin before the other one has its own answer. This makes the redial
	// path of pinOrRedial run every time.
	arrived := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	lookup := func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		n := calls.Add(1)
		select {
		case arrived <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if n == 1 {
			return pdAddrs(t, "203.0.113.1"), nil
		}
		return pdAddrs(t, "203.0.113.2"), nil
	}
	dl := newPDDialer(t)
	d := newPinnedDialer(lookup, dl.dial)

	type outcome struct {
		conn net.Conn
		err  error
	}
	results := make(chan outcome, 2)
	for range 2 {
		go func() {
			conn, err := d.DialContext(t.Context(), "tcp", "race.test:443")
			results <- outcome{conn, err}
		}()
	}
	<-arrived
	<-arrived
	close(release)

	var got []*pdConn
	for range 2 {
		r := <-results
		if r.err != nil {
			t.Fatalf("DialContext() error = %v", r.err)
		}
		got = append(got, r.conn.(*pdConn))
	}

	if got[0].addr != got[1].addr {
		t.Errorf("parallel first dials went to %q and %q, want one pinned address", got[0].addr, got[1].addr)
	}
	for i, c := range got {
		if c.closed.Load() {
			t.Errorf("conn %d (%s) is closed, want open", i, c.addr)
		}
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("lookups = %d, want 2", n)
	}

	// Three dials: one per lookup answer, then the redial of the loser to
	// the pinned address. The loser's first connection must be closed.
	dl.mu.Lock()
	conns := slices.Clone(dl.conns)
	dl.mu.Unlock()
	if len(conns) != 3 {
		t.Fatalf("stub dials = %d, want 3", len(conns))
	}
	var closed int
	for _, c := range conns {
		if c.closed.Load() {
			closed++
			if c.addr == got[0].addr {
				t.Errorf("closed conn has the pinned address %q, want the other one", c.addr)
			}
		}
	}
	if closed != 1 {
		t.Errorf("closed conns = %d, want 1 (the loser's first conn)", closed)
	}

	// A later dial uses the pin and does not resolve again.
	conn, err := d.DialContext(t.Context(), "tcp", "race.test:443")
	if err != nil {
		t.Fatalf("third DialContext() error = %v", err)
	}
	if pc := conn.(*pdConn); pc.addr != got[0].addr {
		t.Errorf("third dial went to %q, want the pin %q", pc.addr, got[0].addr)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("lookups after the third dial = %d, want 2", n)
	}
}

// TestNewPinnedDialerDefaults checks that nil arguments give the real
// resolver and dialer, not nil functions.
func TestNewPinnedDialerDefaults(t *testing.T) {
	t.Parallel()

	d := newPinnedDialer(nil, nil)
	if d.lookup == nil || d.dial == nil || d.pinned == nil {
		t.Errorf("newPinnedDialer(nil, nil) = lookup %v, dial %v, pinned %v; want all set",
			d.lookup != nil, d.dial != nil, d.pinned != nil)
	}
}

// TestBaseTransportPinsAcrossConnections checks newBaseTransport with a stub
// lookup against a real local server: a host name that resolves to
// 127.0.0.1 keeps working (localhost servers are allowed), and a second
// connection after CloseIdleConnections uses the pin, not a new lookup.
func TestBaseTransportPinsAcrossConnections(t *testing.T) {
	t.Parallel()

	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = connStateCounter(&newConns)
	srv.Start()
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", srv.URL, err)
	}
	target := "http://rebind.test:" + u.Port() + "/"

	// The first answer is the test server. A second lookup fails, so a
	// missing pin fails the second request at once.
	var lookups atomic.Int32
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host != "rebind.test" {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		if lookups.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, errPDLookup
	}

	tr := newBaseTransport(lookup, "")
	// No proxy: the test must not depend on HTTP_PROXY of the machine.
	tr.Proxy = nil
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr}

	for i := range 2 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: error = %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d: read body error = %v", i, err)
		}
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Errorf("request %d: status %d body %q, want 200 \"ok\"", i, resp.StatusCode, body)
		}
		// Drop the idle connection, so the next request needs a new dial.
		tr.CloseIdleConnections()
	}

	if n := newConns.Load(); n != 2 {
		t.Errorf("server connections = %d, want 2 (one new dial per request)", n)
	}
	if n := lookups.Load(); n != 1 {
		t.Errorf("lookups = %d, want 1 (the second dial uses the pin)", n)
	}
}

// The tests below cover the first dial to a host name with IPv4 and IPv6
// addresses (Happy Eyeballs) and the time share of each attempt. They use
// heDialer, a stub dial whose behaviour is set for each address, and sync
// only with channels and contexts: no test waits a fixed time.

// heAttempt is one call that heDialer got.
type heAttempt struct {
	addr        string
	deadline    time.Time
	hasDeadline bool
}

// heConn is a connection from heDialer. Close reports its address on the
// closed channel of the dialer, once.
type heConn struct {
	net.Conn
	addr   string
	closes atomic.Int32
	report chan<- string
}

// Close records the close and closes the pipe.
func (c *heConn) Close() error {
	if c.closes.Add(1) == 1 {
		c.report <- c.addr
	}
	return c.Conn.Close()
}

// heDialer is a stub dialFunc. Before it makes a connection to an address,
// it runs the behaviour of that address, if there is one: a non-nil error
// fails the dial. The behaviour gets the dial context, so it can block until
// the context ends. heDialer is safe for concurrent use.
type heDialer struct {
	// behave is set before the first dial and only read after that.
	behave map[string]func(ctx context.Context) error
	// closed gets the address of each connection on its first Close.
	closed chan string

	mu       sync.Mutex
	attempts []heAttempt
	conns    []*heConn
}

func newHEDialer(t *testing.T, behave map[string]func(ctx context.Context) error) *heDialer {
	t.Helper()
	// Large enough that Close never blocks in these tests.
	d := &heDialer{behave: behave, closed: make(chan string, 64)}
	t.Cleanup(func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, c := range d.conns {
			_ = c.Conn.Close()
		}
	})
	return d
}

// dial has the dialFunc signature.
func (d *heDialer) dial(ctx context.Context, _, address string) (net.Conn, error) {
	deadline, ok := ctx.Deadline()
	d.mu.Lock()
	d.attempts = append(d.attempts, heAttempt{addr: address, deadline: deadline, hasDeadline: ok})
	d.mu.Unlock()

	if fn := d.behave[address]; fn != nil {
		if err := fn(ctx); err != nil {
			return nil, err
		}
	}
	client, server := net.Pipe()
	_ = server.Close()
	c := &heConn{Conn: client, addr: address, report: d.closed}
	d.mu.Lock()
	d.conns = append(d.conns, c)
	d.mu.Unlock()
	return c, nil
}

// takeAttempts returns the attempts since the last call and forgets them.
func (d *heDialer) takeAttempts() []heAttempt {
	d.mu.Lock()
	defer d.mu.Unlock()
	a := d.attempts
	d.attempts = nil
	return a
}

// attemptAddrs returns the addresses of attempts, in order.
func attemptAddrs(attempts []heAttempt) []string {
	out := make([]string, 0, len(attempts))
	for _, a := range attempts {
		out = append(out, a.addr)
	}
	return out
}

// sortedAttemptAddrs returns the addresses of attempts, sorted. The two
// racers run in parallel, so the order of their first dials is not fixed.
func sortedAttemptAddrs(attempts []heAttempt) []string {
	out := attemptAddrs(attempts)
	slices.Sort(out)
	return out
}

// waitFor receives one value from ch, or fails the test when the safety
// limit passes first. The limit only stops a broken test from hanging; it
// does not synchronise anything.
func waitFor[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(dialTimeout):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

const (
	heV6 = "[2001:db8::1]:443"
	heV4 = "203.0.113.10:443"
)

// heAnswer is a lookup answer with an IPv6 address first, so IPv6 is the
// primary family and IPv4 the fallback.
func heAnswer(t *testing.T) *pdLookup {
	t.Helper()
	return &pdLookup{answers: []pdAnswer{
		{addrs: pdAddrs(t, "2001:db8::1", "203.0.113.10")},
		{addrs: pdAddrs(t, "127.0.0.1")},
	}}
}

// TestPinnedDialerFallbackWinsWhenPrimaryHangs is the regression test for a
// broken IPv6 path: the IPv6 dial hangs until its context ends, and the IPv4
// fallback must connect, be pinned, and return long before the dial timeout.
func TestPinnedDialerFallbackWinsWhenPrimaryHangs(t *testing.T) {
	t.Parallel()

	primaryErr := make(chan error, 1)
	dl := newHEDialer(t, map[string]func(context.Context) error{
		heV6: func(ctx context.Context) error {
			<-ctx.Done()
			primaryErr <- ctx.Err()
			return ctx.Err()
		},
	})
	lk := heAnswer(t)
	d := newPinnedDialer(lk.lookup, dl.dial)
	d.fallbackDelay = time.Millisecond

	start := time.Now()
	conn, err := d.DialContext(t.Context(), "tcp", "dual.test:443")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("DialContext() error = %v, want nil", err)
	}
	if got := conn.(*heConn).addr; got != heV4 {
		t.Errorf("DialContext() conn address = %q, want the IPv4 fallback %q", got, heV4)
	}
	if elapsed >= dialTimeout/2 {
		t.Errorf("DialContext() took %v, want well below the dial timeout %v", elapsed, dialTimeout)
	}

	// The hanging IPv6 dial must end because the winner cancelled it, not
	// because its deadline passed.
	if err := waitFor(t, primaryErr, "the IPv6 dial to end"); !errors.Is(err, context.Canceled) {
		t.Errorf("IPv6 dial context error = %v, want context.Canceled", err)
	}
	if got, want := sortedAttemptAddrs(dl.takeAttempts()), []string{heV4, heV6}; !slices.Equal(got, want) {
		t.Errorf("dials = %q, want %q", got, want)
	}

	// The IPv4 address is pinned: no new lookup, no IPv6 dial.
	conn, err = d.DialContext(t.Context(), "tcp", "dual.test:443")
	if err != nil {
		t.Fatalf("second DialContext() error = %v", err)
	}
	if got := conn.(*heConn).addr; got != heV4 {
		t.Errorf("second DialContext() conn address = %q, want the pin %q", got, heV4)
	}
	if got, want := attemptAddrs(dl.takeAttempts()), []string{heV4}; !slices.Equal(got, want) {
		t.Errorf("second dials = %q, want %q", got, want)
	}
	if n := len(lk.lookups()); n != 1 {
		t.Errorf("lookups = %d, want 1", n)
	}
}

// TestPinnedDialerPrimaryFastSkipsFallback checks that a primary address that
// connects before the fallback delay is the only dial.
func TestPinnedDialerPrimaryFastSkipsFallback(t *testing.T) {
	t.Parallel()

	dl := newHEDialer(t, nil)
	d := newPinnedDialer(heAnswer(t).lookup, dl.dial)
	// The fallback can only start if the primary fails.
	d.fallbackDelay = time.Hour

	conn, err := d.DialContext(t.Context(), "tcp", "dual.test:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if got := conn.(*heConn).addr; got != heV6 {
		t.Errorf("DialContext() conn address = %q, want the primary %q", got, heV6)
	}
	if got, want := attemptAddrs(dl.takeAttempts()), []string{heV6}; !slices.Equal(got, want) {
		t.Errorf("dials = %q, want %q (no fallback dial)", got, want)
	}
	if pinned, ok := d.pinnedAddr("dual.test"); !ok || pinned != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("pin = %v, %v; want 2001:db8::1", pinned, ok)
	}
}

// TestPinnedDialerLoserConnIsClosed checks that when both racers connect, the
// connection of the loser is closed, the winner's is not, and the loser's
// dial context is cancelled.
func TestPinnedDialerLoserConnIsClosed(t *testing.T) {
	t.Parallel()

	fallbackStarted := make(chan struct{})
	releasePrimary := make(chan struct{})
	releaseFallback := make(chan struct{})
	fallbackCtxErr := make(chan error, 1)
	// freeFallback closes releaseFallback once. The cleanup calls it too,
	// so a failed test does not leave the fallback goroutine blocked.
	freeFallback := sync.OnceFunc(func() { close(releaseFallback) })
	t.Cleanup(freeFallback)

	dl := newHEDialer(t, map[string]func(context.Context) error{
		heV6: func(ctx context.Context) error {
			select {
			case <-releasePrimary:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		heV4: func(ctx context.Context) error {
			close(fallbackStarted)
			// This dial ignores ctx on purpose: it connects even after
			// the race is lost, so the racer must close the connection.
			<-releaseFallback
			fallbackCtxErr <- ctx.Err()
			return nil
		},
	})
	d := newPinnedDialer(heAnswer(t).lookup, dl.dial)
	d.fallbackDelay = time.Millisecond

	type outcome struct {
		conn net.Conn
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		conn, err := d.DialContext(t.Context(), "tcp", "dual.test:443")
		done <- outcome{conn, err}
	}()

	waitFor(t, fallbackStarted, "the fallback dial to start")
	close(releasePrimary)
	res := waitFor(t, done, "DialContext to return")
	if res.err != nil {
		t.Fatalf("DialContext() error = %v", res.err)
	}
	winner := res.conn.(*heConn)
	if winner.addr != heV6 {
		t.Errorf("DialContext() conn address = %q, want the primary %q", winner.addr, heV6)
	}

	// Now the fallback connects too, after the race is over.
	freeFallback()
	if err := waitFor(t, fallbackCtxErr, "the fallback dial to end"); !errors.Is(err, context.Canceled) {
		t.Errorf("fallback dial context error = %v, want context.Canceled", err)
	}
	if got := waitFor(t, dl.closed, "the loser's conn to close"); got != heV4 {
		t.Errorf("closed conn = %q, want the loser %q", got, heV4)
	}
	if n := winner.closes.Load(); n != 0 {
		t.Errorf("winner conn closes = %d, want 0", n)
	}
	if pinned, ok := d.pinnedAddr("dual.test"); !ok || pinned != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("pin = %v, %v; want 2001:db8::1", pinned, ok)
	}
}

// TestPinnedDialerBothFamiliesFail checks that when both racers fail, the
// error of the primary is returned and nothing is pinned, whichever racer
// fails first.
func TestPinnedDialerBothFamiliesFail(t *testing.T) {
	t.Parallel()

	errPrimary := errors.New("stub: IPv6 unreachable")
	errFallback := errors.New("stub: IPv4 refused")

	tests := []struct {
		name          string
		fallbackDelay time.Duration
		// behave builds the stub behaviours. The channel lets one racer
		// wait for the other.
		behave func(ch chan struct{}) map[string]func(context.Context) error
		// wantDials are the dial addresses, sorted.
		wantDials []string
	}{
		{
			// The primary fails at once, so the fallback starts at once
			// although its delay is long.
			name:          "primary fails first",
			fallbackDelay: time.Hour,
			behave: func(chan struct{}) map[string]func(context.Context) error {
				return map[string]func(context.Context) error{
					heV6: func(context.Context) error { return errPrimary },
					heV4: func(context.Context) error { return errFallback },
				}
			},
			wantDials: []string{heV4, heV6},
		},
		{
			name:          "fallback fails first",
			fallbackDelay: time.Millisecond,
			behave: func(fallbackFailed chan struct{}) map[string]func(context.Context) error {
				return map[string]func(context.Context) error{
					heV6: func(ctx context.Context) error {
						select {
						case <-fallbackFailed:
						case <-ctx.Done():
						}
						return errPrimary
					},
					heV4: func(context.Context) error {
						close(fallbackFailed)
						return errFallback
					},
				}
			},
			wantDials: []string{heV4, heV6},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dl := newHEDialer(t, tt.behave(make(chan struct{})))
			lk := heAnswer(t)
			d := newPinnedDialer(lk.lookup, dl.dial)
			d.fallbackDelay = tt.fallbackDelay

			conn, err := d.DialContext(t.Context(), "tcp", "dual.test:443")
			if !errors.Is(err, errPrimary) {
				t.Errorf("DialContext() error = %v, want the primary error %v", err, errPrimary)
			}
			if conn != nil {
				t.Errorf("DialContext() conn = %v, want nil", conn)
			}
			if got := sortedAttemptAddrs(dl.takeAttempts()); !slices.Equal(got, tt.wantDials) {
				t.Errorf("dials = %q, want %q", got, tt.wantDials)
			}
			if pinned, ok := d.pinnedAddr("dual.test"); ok {
				t.Errorf("pin = %v, want none", pinned)
			}
			// No pin, so the next dial resolves again.
			if _, err := d.DialContext(t.Context(), "tcp", "dual.test:443"); err != nil {
				t.Fatalf("second DialContext() error = %v", err)
			}
			if n := len(lk.lookups()); n != 2 {
				t.Errorf("lookups = %d, want 2", n)
			}
		})
	}
}

// TestPinnedDialerAttemptDeadlines checks the deadline that each attempt of
// one family gets: a share of the remaining time, as in net.
func TestPinnedDialerAttemptDeadlines(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// ctxTimeout is the timeout of the caller's context; 0 means none.
		ctxTimeout time.Duration
		// timeout is pinnedDialer.timeout.
		timeout time.Duration
		// wantFirst and wantSecond are the deadlines of the two attempts,
		// as offsets from the start; 0 means no deadline.
		wantFirst  time.Duration
		wantSecond time.Duration
	}{
		{name: "dial timeout split over two addresses", timeout: 10 * time.Second, wantFirst: 5 * time.Second, wantSecond: 10 * time.Second},
		{name: "earlier context deadline wins", ctxTimeout: 6 * time.Second, timeout: 10 * time.Second, wantFirst: 3 * time.Second, wantSecond: 6 * time.Second},
		{name: "share is at least 2 s", ctxTimeout: 3 * time.Second, timeout: 10 * time.Second, wantFirst: 2 * time.Second, wantSecond: 3 * time.Second},
		{name: "no timeout and no context deadline", wantFirst: 0, wantSecond: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dl := newHEDialer(t, map[string]func(context.Context) error{
				"203.0.113.1:443": func(context.Context) error { return errPDRefused },
			})
			lk := &pdLookup{answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.1", "203.0.113.2")}}}
			d := newPinnedDialer(lk.lookup, dl.dial)
			d.timeout = tt.timeout

			before := time.Now()
			ctx := t.Context()
			if tt.ctxTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.ctxTimeout)
				defer cancel()
			}
			conn, err := d.DialContext(ctx, "tcp", "serial.test:443")
			after := time.Now()
			if err != nil {
				t.Fatalf("DialContext() error = %v", err)
			}
			if got := conn.(*heConn).addr; got != "203.0.113.2:443" {
				t.Errorf("DialContext() conn address = %q, want 203.0.113.2:443", got)
			}

			attempts := dl.takeAttempts()
			if len(attempts) != 2 {
				t.Fatalf("attempts = %d, want 2", len(attempts))
			}
			// A small slack for the integer division of durations.
			const slack = time.Millisecond
			for i, want := range []time.Duration{tt.wantFirst, tt.wantSecond} {
				a := attempts[i]
				if want == 0 {
					if a.hasDeadline {
						t.Errorf("attempt %d deadline = %v, want none", i, a.deadline)
					}
					continue
				}
				lo, hi := before.Add(want-slack), after.Add(want+slack)
				if !a.hasDeadline || a.deadline.Before(lo) || a.deadline.After(hi) {
					t.Errorf("attempt %d deadline = start + %v (set %v), want start + %v",
						i, a.deadline.Sub(before), a.hasDeadline, want)
				}
			}
		})
	}
}

func TestPartialDeadline(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name      string
		remaining time.Duration
		addrsLeft int
		want      time.Duration
	}{
		{name: "equal share", remaining: 10 * time.Second, addrsLeft: 2, want: 5 * time.Second},
		{name: "last address gets all", remaining: 10 * time.Second, addrsLeft: 1, want: 10 * time.Second},
		{name: "share raised to the minimum", remaining: 3 * time.Second, addrsLeft: 2, want: 2 * time.Second},
		{name: "never past the deadline", remaining: time.Second, addrsLeft: 3, want: time.Second},
		{name: "deadline passed", remaining: -time.Second, addrsLeft: 2, want: -time.Second},
		{name: "deadline now", remaining: 0, addrsLeft: 2, want: 0},
		{name: "zero addresses counts as one", remaining: 10 * time.Second, addrsLeft: 0, want: 10 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := partialDeadline(now, now.Add(tt.remaining), tt.addrsLeft)
			if want := now.Add(tt.want); !got.Equal(want) {
				t.Errorf("partialDeadline(now, now+%v, %d) = now+%v, want now+%v",
					tt.remaining, tt.addrsLeft, got.Sub(now), tt.want)
			}
		})
	}
}

func TestSplitByFamily(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		addrs         []string
		wantPrimaries []string
		wantFallbacks []string
	}{
		{name: "IPv6 first", addrs: []string{"2001:db8::1", "203.0.113.1", "2001:db8::2", "203.0.113.2"},
			wantPrimaries: []string{"2001:db8::1", "2001:db8::2"}, wantFallbacks: []string{"203.0.113.1", "203.0.113.2"}},
		{name: "IPv4 first", addrs: []string{"203.0.113.1", "2001:db8::1"},
			wantPrimaries: []string{"203.0.113.1"}, wantFallbacks: []string{"2001:db8::1"}},
		{name: "one family", addrs: []string{"203.0.113.1", "203.0.113.2"},
			wantPrimaries: []string{"203.0.113.1", "203.0.113.2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			primaries, fallbacks := splitByFamily(pdAddrs(t, tt.addrs...))
			if want := pdAddrs(t, tt.wantPrimaries...); !slices.Equal(primaries, want) {
				t.Errorf("primaries = %v, want %v", primaries, want)
			}
			if want := pdAddrs(t, tt.wantFallbacks...); len(fallbacks)+len(want) > 0 && !slices.Equal(fallbacks, want) {
				t.Errorf("fallbacks = %v, want %v", fallbacks, want)
			}
		})
	}
}

// TestUsableAddrsUnmapsBeforeSplit checks that an IPv4-mapped IPv6 address
// counts as IPv4, so it is not raced against the IPv4 addresses as a
// separate family.
func TestUsableAddrsUnmapsBeforeSplit(t *testing.T) {
	t.Parallel()

	addrs := usableAddrs([]netip.Addr{
		netip.MustParseAddr("::ffff:203.0.113.1"),
		{},
		netip.MustParseAddr("203.0.113.2"),
	})
	primaries, fallbacks := splitByFamily(addrs)
	if want := pdAddrs(t, "203.0.113.1", "203.0.113.2"); !slices.Equal(primaries, want) {
		t.Errorf("primaries = %v, want %v", primaries, want)
	}
	if len(fallbacks) != 0 {
		t.Errorf("fallbacks = %v, want none", fallbacks)
	}
}

// TestPinnedDialerGuard checks the address guard of the configured server
// name (issue #106): for guardHost, DialContext drops loopback, unspecified,
// link-local and multicast addresses and fails with errAddrRefused when none
// are left. It never dials a refused address. Other names, IP literals and
// "localhost" keep their old rules.
func TestPinnedDialerGuard(t *testing.T) {
	t.Parallel()

	const guard = "guarded.test"

	type guardCase struct {
		name    string
		guard   string // "" means guard
		answers []pdAnswer
		steps   []pdStep
		// wantLookups is the number of lookup calls.
		wantLookups int
	}

	refused := func(addr string) guardCase {
		return guardCase{
			name:        "refused " + addr,
			answers:     []pdAnswer{{addrs: pdAddrs(t, addr)}},
			steps:       []pdStep{{address: guard + ":443", wantErr: errAddrRefused}},
			wantLookups: 1,
		}
	}
	allowed := func(addr, dialed string) guardCase {
		return guardCase{
			name:        "allowed " + addr,
			answers:     []pdAnswer{{addrs: pdAddrs(t, addr)}},
			steps:       []pdStep{{address: guard + ":443", wantDials: []string{dialed}, wantConn: dialed}},
			wantLookups: 1,
		}
	}

	tests := []guardCase{
		// Loopback, also in the IPv4-mapped IPv6 form.
		refused("127.0.0.1"),
		refused("127.255.255.254"),
		refused("::1"),
		refused("::ffff:127.0.0.1"),
		// Unspecified and all of 0.0.0.0/8.
		refused("0.0.0.0"),
		refused("0.1.2.3"),
		refused("0.255.255.255"),
		refused("::"),
		refused("::ffff:0.0.0.0"),
		// Link-local unicast, with the cloud metadata address.
		refused("169.254.169.254"),
		refused("169.254.0.1"),
		refused("::ffff:169.254.169.254"),
		refused("fe80::1"),
		refused("fe80::1%lo0"),
		refused("febf::1"),
		// Multicast: link-local, interface-local and the rest.
		refused("224.0.0.1"),
		refused("239.255.255.250"),
		refused("ff02::1"),
		refused("ff01::1"),
		refused("ff05::1"),
		refused("ff0e::1"),
		// The Alibaba Cloud metadata address, also in the IPv4-mapped form.
		refused("100.100.100.200"),
		refused("::ffff:100.100.100.200"),

		// Private and unique local addresses are a normal company network.
		allowed("10.0.0.1", "10.0.0.1:443"),
		allowed("172.16.0.1", "172.16.0.1:443"),
		allowed("192.168.1.1", "192.168.1.1:443"),
		allowed("fd00::1", "[fd00::1]:443"),
		allowed("::ffff:10.0.0.1", "10.0.0.1:443"),
		// Public addresses, also next to the edges of the refused ranges.
		allowed("203.0.113.10", "203.0.113.10:443"),
		allowed("2001:db8::1", "[2001:db8::1]:443"),
		allowed("1.0.0.1", "1.0.0.1:443"),
		allowed("126.255.255.255", "126.255.255.255:443"),
		allowed("128.0.0.1", "128.0.0.1:443"),
		allowed("169.253.255.255", "169.253.255.255:443"),
		allowed("169.255.0.1", "169.255.0.1:443"),
		allowed("223.255.255.255", "223.255.255.255:443"),
		// The rest of 100.64.0.0/10 is a Tailscale or carrier-grade NAT
		// network, with real servers.
		allowed("100.64.0.1", "100.64.0.1:443"),
		allowed("100.100.100.100", "100.100.100.100:443"),

		{
			name: "mixed answer keeps only the public address",
			answers: []pdAnswer{{addrs: pdAddrs(t,
				"127.0.0.1", "169.254.169.254", "203.0.113.10", "::1", "fe80::1", "224.0.0.1")}},
			steps: []pdStep{
				{address: guard + ":443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
			},
			wantLookups: 1,
		},
		{
			// The refused address must not become a fallback when the
			// allowed one fails.
			name:    "failed public address does not fall back to a refused one",
			answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10", "127.0.0.1", "10.0.0.1")}},
			steps: []pdStep{
				{
					address:   guard + ":443",
					fail:      []string{"203.0.113.10:443", "10.0.0.1:443"},
					wantDials: []string{"203.0.113.10:443", "10.0.0.1:443"},
					wantErr:   errPDRefused,
				},
			},
			wantLookups: 1,
		},
		{
			// The pin holds the allowed address. A later answer with a
			// refused address is never asked.
			name: "pin holds the allowed address",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "127.0.0.1", "203.0.113.10")},
				{addrs: pdAddrs(t, "127.0.0.1")},
			},
			steps: []pdStep{
				{address: guard + ":443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
				{address: guard + ":8443", wantDials: []string{"203.0.113.10:8443"}, wantConn: "203.0.113.10:8443"},
			},
			wantLookups: 1,
		},
		{
			// A refused answer pins nothing: the next dial asks again.
			name: "refused answer pins nothing",
			answers: []pdAnswer{
				{addrs: pdAddrs(t, "127.0.0.1")},
				{addrs: pdAddrs(t, "203.0.113.10")},
			},
			steps: []pdStep{
				{address: guard + ":443", wantErr: errAddrRefused},
				{address: guard + ":443", wantDials: []string{"203.0.113.10:443"}, wantConn: "203.0.113.10:443"},
			},
			wantLookups: 2,
		},
		{
			// DNS names are not case sensitive: the key of the dialer is
			// lower case, and so is guardHost.
			name:        "host name case does not matter",
			answers:     []pdAnswer{{addrs: pdAddrs(t, "127.0.0.1")}},
			steps:       []pdStep{{address: "Guarded.TEST:443", wantErr: errAddrRefused}},
			wantLookups: 1,
		},
		{
			name:        "trailing dot name is guarded when configured so",
			guard:       guard + ".",
			answers:     []pdAnswer{{addrs: pdAddrs(t, "127.0.0.1")}},
			steps:       []pdStep{{address: guard + ".:443", wantErr: errAddrRefused}},
			wantLookups: 1,
		},
		{
			// The proxy host and any other name are not guarded: a local
			// proxy is a normal case.
			name:    "unguarded host keeps loopback",
			answers: []pdAnswer{{addrs: pdAddrs(t, "127.0.0.1")}},
			steps: []pdStep{
				{address: "proxy.test:3128", wantDials: []string{"127.0.0.1:3128"}, wantConn: "127.0.0.1:3128"},
			},
			wantLookups: 1,
		},
		{
			name:    "sub-domain of the guarded name is not guarded",
			answers: []pdAnswer{{addrs: pdAddrs(t, "127.0.0.1")}},
			steps: []pdStep{
				{address: "api." + guard + ":443", wantDials: []string{"127.0.0.1:443"}, wantConn: "127.0.0.1:443"},
			},
			wantLookups: 1,
		},
		{
			// An IP literal is never resolved, so it is dialled as is.
			name:  "IP literal guard host is not checked",
			guard: "127.0.0.1",
			steps: []pdStep{
				{address: "127.0.0.1:8080", wantDials: []string{"127.0.0.1:8080"}, wantConn: "127.0.0.1:8080"},
			},
		},
		{
			name: "IP literal dial with a guarded name",
			steps: []pdStep{
				{address: "[::1]:443", wantDials: []string{"[::1]:443"}, wantConn: "[::1]:443"},
				{address: "169.254.169.254:80", wantDials: []string{"169.254.169.254:80"}, wantConn: "169.254.169.254:80"},
			},
		},
		{
			// localhost has its own rule: loopback only. The guard does not
			// refuse it.
			name:    "localhost guard keeps loopback",
			guard:   "localhost",
			answers: []pdAnswer{{addrs: pdAddrs(t, "127.0.0.1")}},
			steps: []pdStep{
				{address: "localhost:8080", wantDials: []string{"127.0.0.1:8080"}, wantConn: "127.0.0.1:8080"},
			},
			wantLookups: 1,
		},
		{
			name:    "LocalHost guard keeps loopback",
			guard:   "localhost",
			answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10", "::1")}},
			steps: []pdStep{
				{address: "LocalHost:8080", wantDials: []string{"[::1]:8080"}, wantConn: "[::1]:8080"},
			},
			wantLookups: 1,
		},
		{
			// The other localhost names (RFC 6761) get the localhost rule,
			// not the guard: a local server at app.localhost works.
			name:    "app.localhost guard keeps loopback",
			guard:   "app.localhost",
			answers: []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10", "127.0.0.1")}},
			steps: []pdStep{
				{address: "app.localhost:3000", wantDials: []string{"127.0.0.1:3000"}, wantConn: "127.0.0.1:3000"},
			},
			wantLookups: 1,
		},
		{
			name:    "localhost. guard keeps loopback",
			guard:   "localhost.",
			answers: []pdAnswer{{addrs: pdAddrs(t, "::1")}},
			steps: []pdStep{
				{address: "localhost.:8080", wantDials: []string{"[::1]:8080"}, wantConn: "[::1]:8080"},
			},
			wantLookups: 1,
		},
		{
			name:        "app.localhost without loopback stays a DNS error",
			guard:       "app.localhost",
			answers:     []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10")}},
			steps:       []pdStep{{address: "app.localhost:3000", wantNotFound: true}},
			wantLookups: 1,
		},
		{
			// A name that only ends in "localhost" is not a localhost name.
			name:        "notlocalhost guard refuses loopback",
			guard:       "notlocalhost",
			answers:     []pdAnswer{{addrs: pdAddrs(t, "127.0.0.1")}},
			steps:       []pdStep{{address: "notlocalhost:443", wantErr: errAddrRefused}},
			wantLookups: 1,
		},
		{
			name:        "localhost without loopback stays a DNS error",
			guard:       "localhost",
			answers:     []pdAnswer{{addrs: pdAddrs(t, "203.0.113.10")}},
			steps:       []pdStep{{address: "localhost:8080", wantNotFound: true}},
			wantLookups: 1,
		},
		{
			name:        "empty answer stays a DNS error",
			answers:     []pdAnswer{{}},
			steps:       []pdStep{{address: guard + ":443", wantNotFound: true}},
			wantLookups: 1,
		},
		{
			name:        "answer of invalid addresses stays a DNS error",
			answers:     []pdAnswer{{addrs: []netip.Addr{{}, {}}}},
			steps:       []pdStep{{address: guard + ":443", wantNotFound: true}},
			wantLookups: 1,
		},
		{
			name:        "lookup error is kept",
			answers:     []pdAnswer{{err: errPDLookup}},
			steps:       []pdStep{{address: guard + ":443", wantErr: errPDLookup}},
			wantLookups: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lk := &pdLookup{answers: tt.answers}
			dl := newPDDialer(t)
			d := newPinnedDialer(lk.lookup, dl.dial)
			d.guardHost = guard
			if tt.guard != "" {
				d.guardHost = tt.guard
			}

			for i, st := range tt.steps {
				dl.setFail(st.fail)
				conn, err := d.DialContext(t.Context(), "tcp", st.address)
				dials := dl.takeDials()

				if !slices.Equal(dials, st.wantDials) {
					t.Errorf("step %d: DialContext(%q) dials = %q, want %q", i, st.address, dials, st.wantDials)
				}
				if st.wantConn != "" {
					if err != nil {
						t.Fatalf("step %d: DialContext(%q) error = %v, want nil", i, st.address, err)
					}
					pc, ok := conn.(*pdConn)
					if !ok {
						t.Fatalf("step %d: DialContext() conn = %T, want *pdConn", i, conn)
					}
					if pc.addr != st.wantConn {
						t.Errorf("step %d: conn address = %q, want %q", i, pc.addr, st.wantConn)
					}
					continue
				}

				if err == nil {
					t.Fatalf("step %d: DialContext(%q) error = nil, want an error", i, st.address)
				}
				if conn != nil {
					t.Errorf("step %d: DialContext() conn = %v, want nil with an error", i, conn)
				}
				if st.wantErr != nil && !errors.Is(err, st.wantErr) {
					t.Errorf("step %d: DialContext() error = %v, want errors.Is %v", i, err, st.wantErr)
				}
				if errors.Is(st.wantErr, errAddrRefused) {
					// Fixed text: no address and no host name.
					if err.Error() != errAddrRefused.Error() {
						t.Errorf("step %d: error text = %q, want exactly %q", i, err.Error(), errAddrRefused.Error())
					}
				} else if errors.Is(err, errAddrRefused) {
					t.Errorf("step %d: DialContext() error = %v, want no errAddrRefused", i, err)
				}
				if st.wantNotFound {
					var dnsErr *net.DNSError
					if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
						t.Errorf("step %d: DialContext() error = %#v, want *net.DNSError with IsNotFound", i, err)
					}
				}
			}

			if n := len(lk.lookups()); n != tt.wantLookups {
				t.Errorf("lookups = %d, want %d", n, tt.wantLookups)
			}
		})
	}
}

// TestRefusedAddr checks the address classes of refusedAddr directly. The
// input is unmapped, as DialContext gives it.
func TestRefusedAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.1.2.3", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"0.0.0.1", true},
		{"0.255.255.255", true},
		{"::", true},
		{"169.254.169.254", true},
		{"fe80::1", true},
		{"ff02::1", true},
		{"ff01::1", true},
		{"ff0e::1", true},
		{"224.0.0.1", true},
		{"239.255.255.255", true},
		{"100.100.100.200", true},
		{"fd00:ec2::254", true},
		// IPv6 forms that hold a refused IPv4 address: NAT64,
		// IPv4-compatible and 6to4.
		{"64:ff9b::a9fe:a9fe", true},
		{"64:ff9b::7f00:1", true},
		{"64:ff9b::6464:64c8", true},
		{"::7f00:1", true},
		{"::a9fe:a9fe", true},
		{"2002:7f00:1::", true},
		{"2002:a9fe:a9fe::1", true},
		{"::ffff:0:a9fe:a9fe", true},
		{"::ffff:0:7f00:1", true},
		// Other cloud host services and special ranges.
		{"168.63.129.16", true},
		{"192.0.0.192", true},
		{"192.0.0.1", true},
		{"fec0::1", true},
		{"feff::1", true},

		{"1.0.0.0", false},
		{"fd00:ec2::253", false},
		// The same forms with an allowed IPv4 address.
		{"64:ff9b::cb00:710a", false},
		{"64:ff9b::a00:1", false},
		{"::cb00:710a", false},
		{"2002:cb00:710a::1", false},
		{"::ffff:0:cb00:710a", false},
		{"168.63.129.17", false},
		{"192.0.1.1", false},
		{"fc00::1:2", false},
		// Teredo is not covered.
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", false},
		// NAT64 with the local-use prefix is not covered.
		{"64:ff9b:1::a9fe:a9fe", false},
		{"10.0.0.1", false},
		{"172.31.255.255", false},
		{"192.168.0.1", false},
		{"fc00::1", false},
		{"fd00::1", false},
		{"203.0.113.10", false},
		{"2001:db8::1", false},
		{"128.0.0.0", false},
		{"223.255.255.255", false},
		{"240.0.0.1", false},
		{"100.64.0.1", false},
		{"100.100.100.100", false},
		{"100.100.100.201", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			t.Parallel()
			if got := refusedAddr(netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Errorf("refusedAddr(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}

	t.Run("allowedAddrs keeps the order", func(t *testing.T) {
		t.Parallel()
		in := pdAddrs(t, "203.0.113.2", "127.0.0.1", "10.0.0.1", "fe80::1", "2001:db8::1")
		want := pdAddrs(t, "203.0.113.2", "10.0.0.1", "2001:db8::1")
		if got := allowedAddrs(in); !slices.Equal(got, want) {
			t.Errorf("allowedAddrs() = %v, want %v", got, want)
		}
		if got := allowedAddrs(pdAddrs(t, "127.0.0.1", "::")); len(got) != 0 {
			t.Errorf("allowedAddrs(refused only) = %v, want none", got)
		}
	})
}

// TestBaseTransportGuard checks that newBaseTransport guards its host name
// (in any letter case) against a real local server: a request to the guarded
// name that resolves to 127.0.0.1 fails with errAddrRefused and never reaches
// the server, and another name (a proxy, for example) that resolves to
// 127.0.0.1 still works.
func TestBaseTransportGuard(t *testing.T) {
	t.Parallel()

	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = connStateCounter(&newConns)
	srv.Start()
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", srv.URL, err)
	}

	// The lookup gets the host as the URL has it, so it folds the case.
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch strings.ToLower(host) {
		case "guarded.test", "proxy.test":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	// The guard is given in mixed case: newBaseTransport folds it.
	tr := newBaseTransport(lookup, "Guarded.TEST")
	// No proxy: the test must not depend on HTTP_PROXY of the machine.
	tr.Proxy = nil
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr}

	get := func(target string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		return client.Do(req)
	}

	for _, host := range []string{"guarded.test", "GUARDED.test"} {
		resp, err := get("http://" + host + ":" + u.Port() + "/")
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("GET %s: error = nil, want errAddrRefused", host)
		}
		if !errors.Is(err, errAddrRefused) {
			t.Errorf("GET %s: error = %v, want errAddrRefused", host, err)
		}
	}
	if n := newConns.Load(); n != 0 {
		t.Errorf("server connections after the refused requests = %d, want 0", n)
	}

	resp, err := get("http://proxy.test:" + u.Port() + "/")
	if err != nil {
		t.Fatalf("GET proxy.test: error = %v, want nil", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Errorf("GET proxy.test: status %d body %q error %v, want 200 \"ok\"", resp.StatusCode, body, err)
	}
}
