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
// opaque URL (such as "mailto:x" or "localhost:8080"), or if raw has no host.
// Empty input gives "".
//
// It keeps the scheme (url.Parse lowercases it), the host, the port, the path
// and the query keys.
//
// Known limits:
//
//   - A token in the path (for example /mcp/<token>/sse) is not masked.
//   - A token used as a query key name is not masked.
//   - A token in the host or a subdomain (for example
//     https://<token>.example.com/) is not masked.
//   - Query keys are kept as written. The input comes from an untrusted
//     config, so the result can hold control or bidi characters. Callers must
//     still escape the result before they print it to a terminal.
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

	if u.RawQuery != "" {
		u.RawQuery = redactQuery(u.RawQuery)
	}
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
	start := 0
	for i := 0; i <= len(rawQuery); i++ {
		if i < len(rawQuery) && rawQuery[i] != '&' && rawQuery[i] != ';' {
			continue
		}
		b.WriteString(redactQueryPart(rawQuery[start:i]))
		if i < len(rawQuery) {
			// Keep the separator that was in the input.
			b.WriteByte(rawQuery[i])
		}
		start = i + 1
	}
	return b.String()
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
	return key + "=" + Mask
}
