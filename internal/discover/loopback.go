package discover

import "net/netip"

// IsLoopbackHost reports whether host is a loopback host: the name
// "localhost", or a loopback IP address (127.0.0.0/8, ::1, or an IPv4-mapped
// IPv6 form of 127.x such as ::ffff:127.0.0.1). An IPv6 address can have a
// zone ("::1%lo0"). host is the host without brackets and port, as
// url.URL.Hostname gives it.
//
// Packages internal/inspect and internal/rules call it, so that both decide
// in the same way which servers are local.
//
// The name must be "localhost" in lower case. Go skips HTTP_PROXY for that
// exact name and for loopback IP addresses only, and its check is case
// sensitive. "LOCALHOST" goes through the proxy, so it is not loopback here
// and gets the cleartext warning.
//
// Only an exact match counts. "localhost.example.com" and
// "127.0.0.1.nip.io" are DNS names that can point anywhere, so they are not
// loopback. For the name "localhost" in any case, the pinned dialer in
// internal/inspect dials loopback addresses only, whatever the resolver
// answers (see pinnedDialer.DialContext).
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	// Unmap turns ::ffff:127.0.0.1 into 127.0.0.1, so that IsLoopback sees
	// the IPv4 address. The zone does not change whether it is loopback.
	return addr.Unmap().IsLoopback()
}
