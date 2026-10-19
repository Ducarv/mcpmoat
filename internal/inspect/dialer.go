package inspect

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Timing of the first dial to a host name. The values are the ones of
// net.Dialer, so the pinned dialer connects as fast as the dialer that it
// replaces.
const (
	// defaultFallbackDelay is the time that the first address family gets
	// before the other family starts in parallel (RFC 6555, "Happy
	// Eyeballs"). net.Dialer uses 300 ms too.
	defaultFallbackDelay = 300 * time.Millisecond

	// minAttemptTimeout is the smallest share of the remaining time that one
	// address gets when the addresses of one family are tried one after the
	// other. net uses 2 s too.
	minAttemptTimeout = 2 * time.Second
)

// Errors of the pinned dialer. Their texts hold no address, so they can reach
// a report as they are. The other errors of DialContext can hold the host
// name or the dial address: the error of net.SplitHostPort, the
// *net.DNSError of a lookup and the errors of a failed connection.
var (
	// errDialPort means the dial address has a port that is not a decimal
	// number from 0 to 65535. http.Transport always gives a numeric port, so
	// this is a programmer bug, not bad input from a server.
	errDialPort = errors.New("invalid port in dial address")
	// errDialNetwork means the dial network is not tcp, tcp4 or tcp6.
	errDialNetwork = errors.New("unsupported dial network")
	// errAddrRefused means the DNS answer for the guarded host name held only
	// refused addresses (see refusedAddr). The text names the classes of
	// addresses, never an address or the host name. It does not name the
	// cloud metadata addresses outside these classes, or the IPv6 forms of
	// refused IPv4 addresses, which refusedAddr also refuses.
	errAddrRefused = errors.New("server name resolves only to loopback, unspecified, link-local or multicast addresses")
)

// lookupFunc resolves a host name to IP addresses. It has the signature of
// (*net.Resolver).LookupNetIP, so a method value such as
// net.DefaultResolver.LookupNetIP is a lookupFunc. Tests give a stub.
// network is "ip", "ip4" or "ip6".
type lookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// dialFunc opens a connection to an address. It has the signature of
// (*net.Dialer).DialContext and of http.Transport.DialContext. Tests give a
// stub that records the address it gets.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// pinnedDialer is a dialer that keeps the first IP address that it connects
// to for each host name, and uses only that address for all later
// connections to the same host name.
//
// Why: a hostile remote MCP server controls the DNS answers for its own name
// (DNS rebinding). It can answer the first lookup with its real address and a
// later lookup with 127.0.0.1 or an internal address. http.Transport opens a
// new connection (and so a new lookup) when its idle pool is empty, so
// without the pin a later POST or the session DELETE, with the config
// headers, could go to a local service on the configured port. With the pin,
// the later lookups do not occur.
//
// Scope: one pinnedDialer lives for one inspection. Remote makes a new
// transport, and so a new pinnedDialer, for each call, so a pin never passes
// from one server or one scan to the next.
//
// TLS: http.Transport does the TLS handshake over the connection that
// DialContext returns, with the host name of the URL for SNI and for the
// certificate check. The pin changes only the IP address, so TLS still
// verifies the URL host.
//
// Guard: the pin alone does not stop a name that points to a local address
// from the first lookup. So for one host name, guardHost (the host of the
// configured endpoint), DialContext also drops the addresses that a remote
// server must not have: loopback, unspecified, link-local, multicast and the
// Alibaba Cloud metadata address 100.100.100.200 (see refusedAddr). Private
// (RFC 1918) and unique local (ULA) addresses stay allowed: a server on the
// company network is a normal case. The rest of 100.64.0.0/10 (shared
// address space, RFC 6598) also stays allowed, because Tailscale and other
// carrier-grade NAT networks use it for real servers. The guard does
// not cover other host names. The proxy host is one of them: the user sets
// it in the environment, and a local proxy is a normal case.
//
// Known limit: with HTTP_PROXY or HTTPS_PROXY, http.Transport dials the proxy,
// so the pinned address is the address of the proxy. The proxy resolves the
// server name itself, and neither the pin nor the guard covers that lookup.
//
// The zero value is not ready to use; use newPinnedDialer. A pinnedDialer is
// safe for concurrent use: http.Transport can dial from many goroutines.
type pinnedDialer struct {
	// lookup resolves a host name that is not pinned yet.
	lookup lookupFunc
	// dial opens the connection to one IP address and port.
	dial dialFunc
	// timeout bounds the lookup and all the connection attempts of a first
	// dial to a host name, the same as net.Dialer.Timeout. Zero means no
	// limit other than the context.
	timeout time.Duration
	// fallbackDelay is the time that the first address family gets before
	// the other family starts. Tests set a small value.
	fallbackDelay time.Duration
	// guardHost is the host name, in ASCII lower case, whose DNS answers
	// must not hold refused addresses (see refusedAddr). Empty means no host
	// is guarded. newBaseTransport sets it; newPinnedDialer leaves it empty.
	guardHost string

	// mu protects pinned. It is never held during a lookup or a dial, so one
	// slow dial does not block the others.
	mu sync.Mutex
	// pinned maps a host name in ASCII lower case to the address that the
	// first successful connection used.
	pinned map[string]netip.Addr
}

// newPinnedDialer returns a pinnedDialer with no pins. A nil lookup uses the
// system resolver (net.DefaultResolver). A nil dial uses a net.Dialer with
// the timeouts of the base transport.
func newPinnedDialer(lookup lookupFunc, dial dialFunc) *pinnedDialer {
	if lookup == nil {
		// A method value: it binds the method to net.DefaultResolver, and
		// the result is a plain function with the lookupFunc signature.
		lookup = net.DefaultResolver.LookupNetIP
	}
	if dial == nil {
		dial = (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: dialKeepAlive,
		}).DialContext
	}
	return &pinnedDialer{
		lookup:        lookup,
		dial:          dial,
		timeout:       dialTimeout,
		fallbackDelay: defaultFallbackDelay,
		pinned:        make(map[string]netip.Addr),
	}
}

// DialContext connects to address ("host:port") on network. It has the
// signature of http.Transport.DialContext.
//
//   - An IP literal host is dialled as it is. No lookup occurs, so there is
//     nothing to pin.
//   - A pinned host name is dialled at its pinned address only. If that
//     connection fails, DialContext returns the error and does not resolve
//     the name again.
//   - Otherwise DialContext resolves the name and connects the way
//     net.Dialer does (see dialParallel), and pins the address of the
//     connection that it returns.
//   - For the guarded host (guardHost), it first drops the refused addresses
//     of the answer (see refusedAddr) and uses only the others. When none
//     are left, it returns errAddrRefused and dials nothing. The name
//     "localhost" is never guarded: it has its own rule below.
func (d *pinnedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	// ParseUint with bitSize 16 refuses values above 65535, so the
	// conversion to uint16 below cannot overflow.
	port64, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, errDialPort
	}
	port := uint16(port64)

	// netip.ParseAddr also accepts an IPv6 zone, such as "fe80::1%en0".
	if _, err := netip.ParseAddr(host); err == nil {
		return d.dial(ctx, network, address)
	}

	lookupNetwork, err := lookupNetworkFor(network)
	if err != nil {
		return nil, err
	}

	// DNS names are not case sensitive, so "Example.COM" and "example.com"
	// share one pin.
	key := strings.ToLower(host)
	if addr, ok := d.pinnedAddr(key); ok {
		return d.dial(ctx, network, netip.AddrPortFrom(addr, port).String())
	}

	// Like net.Dialer.Timeout, one limit covers the lookup and all the
	// connection attempts. context.WithTimeout keeps the deadline of ctx when
	// it is earlier. The deferred cancel frees the timer of the context; it
	// does not close the connection that DialContext returns.
	firstCtx := ctx
	if d.timeout > 0 {
		var cancel context.CancelFunc
		firstCtx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}

	addrs, err := d.lookup(firstCtx, lookupNetwork, host)
	if err != nil {
		// Unchanged, so classify still sees the *net.DNSError.
		return nil, err
	}
	addrs = usableAddrs(addrs)
	if isLoopbackHost(key) || isLocalhostName(key) {
		// The name "localhost" counts as loopback without a lookup, so a
		// plain http:// URL to it gets no cleartext warning (see
		// cleartextWarnings), and Go sends it past HTTP_PROXY. Make that
		// true whatever the resolver answers, for example from a changed
		// /etc/hosts: dial loopback addresses only. The check uses key, so
		// it covers every case of the name: "LOCALHOST" shares the pin of
		// "localhost", and that pin must be a loopback address too. The
		// other localhost names (see isLocalhostName) are loopback names
		// too, so they get the same rule, not the guard below, which would
		// refuse their loopback answers.
		addrs = loopbackAddrs(addrs)
	} else if d.guardHost != "" && key == d.guardHost && len(addrs) > 0 {
		// The configured server name. A hostile server controls the DNS
		// answers for its own name, so it can point the name at a local
		// service from the first lookup on. Keep only the addresses that a
		// remote server can have. The pin below then holds one of them. An
		// empty answer skips this step and stays a "no such host" error.
		addrs = allowedAddrs(addrs)
		if len(addrs) == 0 {
			// Fixed text: no address and no host name.
			return nil, errAddrRefused
		}
	}
	if len(addrs) == 0 {
		// The answer was empty or held only invalid addresses, or, for
		// localhost, no loopback address.
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	primaries, fallbacks := splitByFamily(addrs)
	conn, addr, err := d.dialParallel(firstCtx, network, port, primaries, fallbacks)
	if err != nil {
		return nil, err
	}
	// The caller's ctx, not firstCtx: a redial is a new dial, and the dial
	// function has its own timeout.
	return d.pinOrRedial(ctx, network, key, addr, port, conn)
}

// usableAddrs returns the valid addresses of a lookup answer, in the order of
// the answer. Unmap turns an IPv4-mapped IPv6 address (::ffff:1.2.3.4) into
// the IPv4 address, so the pin, the dial address and the family split use
// one form.
func usableAddrs(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		addr = addr.Unmap()
		if addr.IsValid() {
			out = append(out, addr)
		}
	}
	return out
}

// loopbackAddrs returns the loopback addresses of addrs, in the order of
// addrs. addrs must be unmapped (see usableAddrs).
func loopbackAddrs(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, addr := range addrs {
		if addr.IsLoopback() {
			out = append(out, addr)
		}
	}
	return out
}

// allowedAddrs returns the addresses of addrs that are not refused (see
// refusedAddr), in the order of addrs. addrs must be unmapped (see
// usableAddrs).
func allowedAddrs(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, addr := range addrs {
		if !refusedAddr(addr) {
			out = append(out, addr)
		}
	}
	return out
}

// isLocalhostName reports whether host, in lower case, is a localhost name
// other than "localhost" itself: "localhost." or a name under the localhost
// domain, such as "app.localhost" (RFC 6761 section 6.3). Resolvers answer
// such names with loopback addresses, so a local development server can use
// one. isLoopbackHost does not count them, so they keep the cleartext
// warning, and Go sends them through a proxy.
func isLocalhostName(host string) bool {
	host = strings.TrimSuffix(host, ".")
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// Addresses and prefixes that refusedAddr checks.
var (
	// alibabaMetadataAddr is the Alibaba Cloud metadata address. It is in
	// 100.64.0.0/10, not in a link-local range.
	alibabaMetadataAddr = netip.AddrFrom4([4]byte{100, 100, 100, 200})
	// awsIPv6MetadataAddr is the IPv6 address of the AWS metadata service.
	// It is in the unique local range fc00::/7, which is not refused.
	awsIPv6MetadataAddr = netip.MustParseAddr("fd00:ec2::254")
	// nat64Prefix is the well-known NAT64 prefix (RFC 6052). The last 32
	// bits are an IPv4 address that a NAT64 gateway connects to.
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	// ipv4CompatPrefix holds the IPv4-compatible IPv6 addresses (RFC 4291,
	// deprecated). The last 32 bits are an IPv4 address.
	ipv4CompatPrefix = netip.MustParsePrefix("::/96")
	// sixToFourPrefix is the 6to4 prefix (RFC 3056). Bits 16 to 47 are an
	// IPv4 address.
	sixToFourPrefix = netip.MustParsePrefix("2002::/16")
)

// embeddedIPv4 returns the IPv4 address in addr, and true, when addr is a
// NAT64, IPv4-compatible or 6to4 IPv6 address (see the prefixes above). Else
// it returns false.
func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	switch {
	case nat64Prefix.Contains(addr), ipv4CompatPrefix.Contains(addr):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixToFourPrefix.Contains(addr):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

// refusedAddr reports whether addr is an address that the configured server
// name must not resolve to. addr must be unmapped (see usableAddrs), so that
// ::ffff:127.0.0.1 counts as 127.0.0.1. The refused classes are:
//
//   - loopback (127.0.0.0/8, ::1): a service on this machine;
//   - unspecified (::) and all of 0.0.0.0/8: many systems send a
//     connection to 0.0.0.0 to this machine;
//   - link-local unicast (169.254.0.0/16, fe80::/10): this holds the cloud
//     metadata address 169.254.169.254;
//   - multicast (224.0.0.0/4, ff00::/8), with link-local and
//     interface-local multicast: not an address of one server;
//   - the cloud metadata addresses that the classes above do not cover: the
//     Alibaba Cloud address 100.100.100.200 and the AWS IPv6 address
//     fd00:ec2::254;
//   - a NAT64, IPv4-compatible or 6to4 IPv6 address whose IPv4 address is
//     refused (see embeddedIPv4): on a NAT64 network, 64:ff9b::a9fe:a9fe
//     reaches 169.254.169.254. NAT64 with another prefix (for example the
//     local-use prefix 64:ff9b:1::/48) is not covered.
//
// Private (RFC 1918) and unique local (fc00::/7) addresses are not refused.
// The rest of 100.64.0.0/10 (shared address space, RFC 6598) is not refused
// either: Tailscale and other carrier-grade NAT networks use it for real
// servers.
func refusedAddr(addr netip.Addr) bool {
	if addr.Is4() && addr.As4()[0] == 0 {
		// 0.0.0.0/8, "this network" (RFC 1122). IsUnspecified covers only
		// 0.0.0.0 itself.
		return true
	}
	if addr == alibabaMetadataAddr || addr == awsIPv6MetadataAddr {
		return true
	}
	if v4, ok := embeddedIPv4(addr); ok && refusedAddr(v4) {
		return true
	}
	// IsMulticast covers link-local and interface-local multicast too.
	return addr.IsLoopback() ||
		addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsMulticast()
}

// splitByFamily splits addrs, which must not be empty, the way net.Dialer
// does: primaries are the addresses of the family of the first address (IPv4
// or IPv6), fallbacks are the addresses of the other family. Both keep the
// order of addrs.
func splitByFamily(addrs []netip.Addr) (primaries, fallbacks []netip.Addr) {
	firstIs4 := addrs[0].Is4()
	for _, addr := range addrs {
		if addr.Is4() == firstIs4 {
			primaries = append(primaries, addr)
		} else {
			fallbacks = append(fallbacks, addr)
		}
	}
	return primaries, fallbacks
}

// dialParallel connects to one of the addresses, the way net.Dialer does for
// a host name with IPv4 and IPv6 addresses (RFC 6555, "Happy Eyeballs"). It
// returns the connection and the address that it is connected to.
//
// Two racers run, each in its own goroutine, and each tries its list one
// address after the other (dialSerial). The primary racer starts at once.
// The fallback racer starts after fallbackDelay, or at once when the primary
// racer fails first. The first connection wins. Without the race, a host with
// a broken IPv6 path would spend the whole timeout on the IPv6 address and
// never try the IPv4 address that works.
//
// When both racers fail, the error of the primary racer is returned, as in
// net. With no fallbacks, there is no race and no goroutine.
func (d *pinnedDialer) dialParallel(ctx context.Context, network string, port uint16, primaries, fallbacks []netip.Addr) (net.Conn, netip.Addr, error) {
	if len(fallbacks) == 0 {
		return d.dialSerial(ctx, network, port, primaries)
	}

	// result is what one racer reports when its list is done.
	type result struct {
		conn    net.Conn
		addr    netip.Addr
		err     error
		primary bool
	}
	// results is unbuffered: a racer can hand over its result only while
	// dialParallel waits in the select below.
	results := make(chan result)
	// returned is closed when dialParallel returns. A closed channel is
	// always ready to receive, so a racer that finishes later sees it in its
	// select, closes its connection (nobody will use it) and ends. This is
	// how the losing racer never leaks a goroutine or a connection.
	returned := make(chan struct{})
	defer close(returned)

	// Each racer gets its own child context. The deferred cancels run when
	// dialParallel returns, so the losing racer stops its dial at once and
	// does not wait for its timeout.
	primaryCtx, primaryCancel := context.WithCancel(ctx)
	defer primaryCancel()
	fallbackCtx, fallbackCancel := context.WithCancel(ctx)
	defer fallbackCancel()

	race := func(ctx context.Context, primary bool) {
		addrs := primaries
		if !primary {
			addrs = fallbacks
		}
		conn, addr, err := d.dialSerial(ctx, network, port, addrs)
		select {
		case results <- result{conn: conn, addr: addr, err: err, primary: primary}:
		case <-returned:
			if conn != nil {
				// The close error does not matter: the connection is
				// not used.
				_ = conn.Close()
			}
		}
	}

	go race(primaryCtx, true)

	fallbackTimer := time.NewTimer(d.fallbackDelay)
	defer fallbackTimer.Stop()

	var primaryErr error
	var primaryDone, fallbackDone bool
	// The loop ends with a return: on the first connection, or when both
	// racers have failed. Every racer that started sends one result or sees
	// returned, so the loop never waits forever.
	for {
		select {
		case <-fallbackTimer.C:
			go race(fallbackCtx, false)

		case res := <-results:
			if res.err == nil {
				return res.conn, res.addr, nil
			}
			if res.primary {
				primaryDone, primaryErr = true, res.err
			} else {
				fallbackDone = true
			}
			if primaryDone && fallbackDone {
				return nil, netip.Addr{}, primaryErr
			}
			// Stop returns true only if the timer had not fired yet, so
			// the fallback racer had not started. The primary racer
			// failed, so there is no reason to wait: start the fallback
			// racer now.
			if res.primary && fallbackTimer.Stop() {
				fallbackTimer.Reset(0)
			}
		}
	}
}

// dialSerial tries addrs one after the other and returns the first
// connection and its address. If all of them fail, it returns the error of
// the first address, which is the most useful one (as in net). It stops when
// ctx ends.
func (d *pinnedDialer) dialSerial(ctx context.Context, network string, port uint16, addrs []netip.Addr) (net.Conn, netip.Addr, error) {
	var firstErr error
	for i, addr := range addrs {
		// Stop when the caller gave up or the other racer won: the next
		// dial would fail too.
		if err := ctx.Err(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			break
		}
		conn, err := d.dialAttempt(ctx, network, netip.AddrPortFrom(addr, port), len(addrs)-i)
		if err == nil {
			return conn, addr, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, netip.Addr{}, firstErr
}

// dialAttempt dials one address. addrsLeft is the number of addresses that
// the list still has, this one included. If ctx has a deadline, the attempt
// gets only its share of the remaining time (see partialDeadline), so one
// address that does not answer cannot use the time of the next ones.
func (d *pinnedDialer) dialAttempt(ctx context.Context, network string, ap netip.AddrPort, addrsLeft int) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if partial := partialDeadline(time.Now(), deadline, addrsLeft); partial.Before(deadline) {
			// A child context with the earlier deadline. The cancel frees
			// its timer when the attempt ends; a connection that the dial
			// returned stays open.
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, partial)
			defer cancel()
		}
	}
	return d.dial(ctx, network, ap.String())
}

// partialDeadline returns the deadline for one attempt when addrsLeft
// addresses (at least 1) share the time from now to deadline. It is the
// partialDeadline of net: each address gets an equal share, but at least
// minAttemptTimeout, and never more than the time that is left.
func partialDeadline(now, deadline time.Time, addrsLeft int) time.Time {
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		// No time is left. The dial fails at once with the context error.
		return deadline
	}
	share := remaining / time.Duration(max(addrsLeft, 1))
	if share < minAttemptTimeout {
		share = min(remaining, minAttemptTimeout)
	}
	return now.Add(share)
}

// pinnedAddr returns the pinned address for key, if there is one.
func (d *pinnedDialer) pinnedAddr(key string) (netip.Addr, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	addr, ok := d.pinned[key]
	return addr, ok
}

// pinOrRedial pins addr for key and returns conn, which is connected to addr.
// Two first dials to the same host can run in parallel, and each one does its
// own lookup. If the other dial pinned a different address first, the pin
// wins: pinOrRedial closes conn and dials the pinned address, so all
// connections of one inspection go to one address.
func (d *pinnedDialer) pinOrRedial(ctx context.Context, network, key string, addr netip.Addr, port uint16, conn net.Conn) (net.Conn, error) {
	d.mu.Lock()
	pinned, ok := d.pinned[key]
	if !ok {
		d.pinned[key] = addr
	}
	// Unlock before the dial below: the mutex is never held during I/O.
	d.mu.Unlock()

	if !ok || pinned == addr {
		return conn, nil
	}
	// The close error does not matter: the connection is not used.
	_ = conn.Close()
	return d.dial(ctx, network, netip.AddrPortFrom(pinned, port).String())
}

// lookupNetworkFor returns the resolver network for a dial network: "ip" for
// "tcp" (IPv4 and IPv6 addresses), "ip4" for "tcp4" and "ip6" for "tcp6".
func lookupNetworkFor(network string) (string, error) {
	switch network {
	case "tcp":
		return "ip", nil
	case "tcp4":
		return "ip4", nil
	case "tcp6":
		return "ip6", nil
	default:
		return "", errDialNetwork
	}
}
