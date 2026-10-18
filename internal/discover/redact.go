package discover

import (
	"net/url"
	"strings"
)

// RedactURL returns raw with credentials masked, for display.
//
// It replaces these parts with [Mask]:
//
//   - the whole userinfo (username and password);
//   - every query value, and every bare query part with no "=";
//   - a non-empty fragment.
//
// It returns Mask for the whole input if raw does not parse, if raw is an
// opaque URL (such as "mailto:x" or "localhost:8080"), if raw has no host,
// or if the host has an IPv6 zone ID ("[::1%25zone]") or a non-ASCII byte
// (such as an IDN host written as "bücher.example"). Empty input gives "".
//
// It keeps the scheme (url.Parse lowercases it), the host, the port, the path
// and the query keys.
//
// The result holds only printable ASCII bytes (0x20 to 0x7e), so it cannot
// hold control or bidi characters. url.Parse rejects ASCII control bytes,
// url.URL.String percent-escapes non-ASCII bytes in the path, and
// RedactURL percent-escapes them in the query keys. Callers that print to a
// terminal still escape output as usual; RedactURL does not depend on it.
//
// Known limits:
//
//   - A token in the path (for example /mcp/<token>/sse) is not masked.
//   - A token used as a query key name is not masked.
//   - A token in the host or a subdomain (for example
//     https://<token>.example.com/) is not masked.
//
// RedactURL does not use url.URL.Redacted, because Redacted keeps the
// username, and the username of an MCP URL is often a token
// (https://ghp_xxx@host).
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Mask
	}
	// An opaque URL has no "//" after the scheme, for example "mailto:x" or
	// "localhost:token". We cannot tell which part is secret, so mask it all.
	if u.Opaque != "" {
		return Mask
	}
	// A real MCP URL always has a host. Input with no host, such as a bare
	// token or "tok@host/x", parses as a relative path, so a "tok@" part is
	// not seen as userinfo. Fail closed and mask it all.
	if u.Host == "" {
		return Mask
	}
	// u.Host is unescaped. A "%" in it comes from an IPv6 zone ID
	// ("[::1%25zone]"), and u.String writes the zone back as written, so it
	// could hold a secret or unsafe text. A non-ASCII host is an IDN name or
	// junk; we fail closed for both instead of trying to clean them.
	if strings.Contains(u.Host, "%") || !isASCII(u.Host) {
		return Mask
	}

	// redactQuery("") is "", so an empty query needs no special case.
	u.RawQuery = redactQuery(u.RawQuery)
	if u.Fragment != "" {
		// u.String escapes the fragment, but "*" is allowed there, so Mask
		// stays literal. RawFragment must be empty, or String would use it.
		u.Fragment = Mask
		u.RawFragment = ""
	}
	if u.User == nil {
		return u.String()
	}

	// Mask the whole userinfo (username and password). u.String escapes "*"
	// in the userinfo to "%2A", so we replace the escaped form with the
	// literal Mask after the call. The userinfo comes right after the scheme
	// and "//", and a scheme cannot contain "%", so the first match is the
	// userinfo.
	u.User = url.User(Mask)
	escaped := u.User.String() + "@"
	return strings.Replace(u.String(), escaped, Mask+"@", 1)
}

// redactQuery masks every value in a raw query string and keeps the keys as
// written (still escaped). A part "key=value" becomes "key=" + Mask, and a part
// with no "=" becomes Mask, because a bare part can itself be a token. Empty
// parts stay empty, so the shape of the query does not change.
//
// It splits on both "&" and ";". Go no longer treats ";" as a separator
// (since Go 1.17), but some servers do, so a value after ";" can be a secret.
// It does not use url.Values.Encode, because Encode sorts the keys and
// escapes "*" in Mask.
func redactQuery(rawQuery string) string {
	var b strings.Builder
	rest := rawQuery
	for {
		i := strings.IndexAny(rest, "&;")
		if i < 0 {
			// No separator left: rest is the last part.
			b.WriteString(redactQueryPart(rest))
			return b.String()
		}
		b.WriteString(redactQueryPart(rest[:i]))
		b.WriteByte(rest[i]) // keep the separator that was in the input
		rest = rest[i+1:]
	}
}

// redactQueryPart masks one part of a query, without its separator.
func redactQueryPart(part string) string {
	if part == "" {
		return ""
	}
	key, _, found := strings.Cut(part, "=")
	if !found {
		return Mask
	}
	return escapeUnsafeBytes(key) + "=" + Mask
}

// escapeUnsafeBytes percent-escapes every byte of s that is not printable
// ASCII: a control byte (below 0x20, or 0x7f) or a non-ASCII byte (0x80 and
// up, which includes each byte of a bidi or C1 character). Other bytes,
// including existing "%XX" escapes, stay as written.
//
// It does not use url.QueryEscape, because s is already escaped text:
// QueryEscape would escape "%" again and change the key.
func escapeUnsafeBytes(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0f])
	}
	return b.String()
}

// isASCII reports whether every byte of s is below 0x80.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
