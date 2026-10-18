package inspect

import (
	"net/netip"
	"net/url"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// cleartextWarnings returns a warning when Remote sends secrets to srv over
// plain http:// to a host that is not loopback (issue #98). u is the parsed
// server URL from parseEndpoint.
//
// Plain HTTP has no encryption. Anyone on the network path, for example on a
// shared Wi-Fi, and any proxy from HTTP_PROXY can read the requests, and so
// the header values, the Basic credentials from the URL user info and the
// secrets in the URL query and path. They can then use these credentials
// against the real server. Traffic to a loopback address does not leave the
// machine, so it gets no warning.
//
// This is a warning only. Remote still connects: a local or test server can
// use plain HTTP on purpose, and the user decides.
//
// It returns nil when the scheme is not http, when the host is loopback, or
// when no config header, no URL user info and no URL secret went out.
// Otherwise it returns one Warning of kind WarnCleartextSecrets with the
// header keys and the user info flag from sentHeaders, and the URL secrets
// flag from hasURLSecrets. It keeps no header value, no password and no part
// of the URL.
func cleartextWarnings(srv discover.Server, u *url.URL) []Warning {
	// url.Parse already lowercases the scheme. EqualFold keeps this check
	// correct even for a URL that was built another way.
	if u == nil || !strings.EqualFold(u.Scheme, "http") {
		return nil
	}
	if isLoopbackHost(u.Hostname()) {
		return nil
	}
	names, basic := sentHeaders(srv)
	// u comes from parseEndpoint(srv.URL.Reveal()) in Remote, so its query
	// and the path of the raw URL are the parts that Remote sends.
	inURL := hasURLSecrets(u.RawQuery, srv.URL.Reveal())
	if len(names) == 0 && !basic && !inURL {
		return nil
	}
	return []Warning{{
		Kind:        WarnCleartextSecrets,
		HeaderKeys:  names,
		URLUserInfo: basic,
		URLSecrets:  inURL,
	}}
}

// hasURLSecrets reports whether rawQuery or the path of raw, the configured
// URL, holds a part that discover.RedactURL masks (discover.SecretQueryParts
// and discover.SecretPathSegments). It returns a bool only, so no part of the
// URL can leak into a Warning.
//
// It does not use urlSecrets, which drops the parts shorter than
// minBareSecretLen. That length limit keeps classify from removing short,
// common words from error text. For the warning, a short password in the
// query still goes out in clear text, so every part counts. RedactURL masks
// every query value, so a query such as "?page=1" gets the warning too. This
// errs on the safe side: mcpmoat cannot tell a harmless value from a short
// secret.
func hasURLSecrets(rawQuery, raw string) bool {
	return len(discover.SecretQueryParts(rawQuery)) > 0 ||
		len(discover.SecretPathSegments(raw)) > 0
}

// isLoopbackHost reports whether host is a loopback host: the name
// "localhost" in any case, or a loopback IP address (127.0.0.0/8, ::1, or an
// IPv4-mapped IPv6 form of 127.x such as ::ffff:127.0.0.1). An IPv6 address
// can have a zone ("::1%lo0"). host is the host without brackets and port,
// as url.URL.Hostname gives it.
//
// Only an exact match counts. "localhost.example.com" and
// "127.0.0.1.nip.io" are DNS names that can point anywhere, so they are not
// loopback. For the name "localhost", the pinned dialer dials loopback
// addresses only, whatever the resolver answers (see
// pinnedDialer.DialContext).
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
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
