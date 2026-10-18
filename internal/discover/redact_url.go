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
//   - every path segment that looks like a credential (see below);
//   - every matrix parameter in the path (each part after a ";" in a
//     segment, for example "tok" in "/x;tok");
//   - every query value, every bare query part with no "=", and every
//     query key that looks like a credential by the token rules below (a
//     normal key such as "api_key", "token" or "k" stays);
//   - a non-empty fragment.
//
// Hosted MCP providers often put the API key in the path, for example
// https://actions.zapier.com/mcp/<key>/sse, or an account ID as a UUID
// segment. A path segment is the escaped text between two "/", before any
// ";". RedactURL masks it when it does not unescape, when its unescaped
// form has a "=", "," or ";" (like a query value or a matrix parameter, for
// example "password=hunter2" or "a,b"), or when one of these texts looks
// like a token: the escaped segment, the unescaped segment, or a piece of
// the unescaped segment between two "/" (an escaped "%2F" gives a "/").
// Query keys get the same token checks (url.QueryUnescape, then each piece
// between two "/"), and a key that does not unescape is masked.
//
// A text looks like a token when one or more of these rules is true:
//
//   - it starts with a known token prefix, in any case (such as sk-, ghp_,
//     xox, AKIA, or eyJ for a JWT), and it is longer than the prefix;
//   - it has 20 or more bytes, at least one ASCII letter and at least one
//     digit;
//   - it has 32 or more bytes;
//   - it is a UUID (36 bytes: 8-4-4-4-12 hex digits).
//
// The slashes stay, so the shape of the path does not change. Normal
// segments such as "mcp", "sse", "v1", "messages" or "2024-11-05" stay as
// written. The rules are a heuristic: a long, readable segment (such as
// "server-sent-events-v2") is masked too, and a short token or a token with
// only letters is not detected. RedactURL unescapes only once, so a token
// that is escaped twice ("%2567hp_...") is checked in its once-escaped form.
//
// It returns Mask for the whole input if raw does not parse, if raw is an
// opaque URL (such as "mailto:x" or "localhost:8080"), if raw has no host,
// or if the host has an IPv6 zone ID ("[::1%25zone]") or a non-ASCII byte
// (such as an IDN host written as "bücher.example"). Empty input gives "".
//
// It also returns Mask if raw has an "@" after the host: in the path, in
// the query or in the fragment. An unescaped "/", "?" or "#" in a userinfo
// token ends the authority early. So https://tok/en@host/x parses with host
// "tok" and no userinfo, and https://user:p@ss/word@host/x parses with
// userinfo "user:p" and host "ss". In both cases part of the token would
// print as the host. The check runs with and without userinfo. A real MCP
// URL rarely has "@" in these places, so failing closed costs little. One
// cost is known: a query value with an "@" (such as ?email=a@b) also gives
// Mask, although RedactURL masks every query value anyway.
//
// It keeps the scheme (url.Parse lowercases it), the host, the port, the
// other path segments and the other query keys.
//
// The result holds only printable ASCII bytes (0x20 to 0x7e), so it cannot
// hold control or bidi characters. url.Parse rejects ASCII control bytes,
// url.URL.String percent-escapes non-ASCII bytes in the path, and
// RedactURL percent-escapes them in the query keys. Callers that print to a
// terminal still escape output as usual; RedactURL does not depend on it.
//
// Known limits:
//
//   - A short token, or a token with only letters, in the path is not
//     masked (see the token rules above).
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

	// An "@" after the host means that an unescaped "/", "?" or "#" in a
	// credential probably cut the authority short, so the host holds part
	// of the token. This is true with or without userinfo: in
	// "https://user:p@ss/word@host" the userinfo is "user:p" and the host is
	// "ss". Fail closed. The whole raw query counts, because a cut at "?"
	// can put the "@" in a query value ("?x=y@host").
	if strings.Contains(u.EscapedPath(), "@") ||
		strings.Contains(u.RawQuery, "@") ||
		strings.Contains(u.Fragment, "@") {
		return Mask
	}

	if !redactPath(u) {
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

// redactPath masks the path segments of u that look like credentials, and
// every matrix parameter. It works on the escaped path, so an escaped "/"
// ("%2F") does not split a segment. It reports false if the new path does
// not unescape, which cannot happen for the escaped form that url.URL
// returns; the caller then fails closed.
func redactPath(u *url.URL) bool {
	escaped := u.EscapedPath()
	segments := strings.Split(escaped, "/")
	changed := false
	for i, seg := range segments {
		if r := redactPathSegment(seg); r != seg {
			segments[i] = r
			changed = true
		}
	}
	if !changed {
		return true
	}
	newPath := strings.Join(segments, "/")
	unescaped, err := url.PathUnescape(newPath)
	if err != nil {
		return false
	}
	// u.String writes RawPath when it is a valid escaped form of Path. Mask
	// is "*" bytes, which are valid in a path, so RawPath is used as set.
	u.Path = unescaped
	u.RawPath = newPath
	return true
}

// redactPathSegment masks one escaped path segment, without its slashes.
// The part before the first ";" is masked if isSecretPathSegment reports
// true for it. Each non-empty part after a ";" is a matrix parameter and is
// always masked, as a query value is.
func redactPathSegment(seg string) string {
	parts := strings.Split(seg, ";")
	if isSecretPathSegment(parts[0]) {
		parts[0] = Mask
	}
	for i, p := range parts {
		if i > 0 && p != "" {
			parts[i] = Mask
		}
	}
	return strings.Join(parts, ";")
}

// isSecretPathSegment reports whether seg, one escaped path segment with no
// ";" part, must be masked. It fails closed: a segment that does not
// unescape, or whose unescaped form has "=", "," or ";", is masked.
func isSecretPathSegment(seg string) bool {
	plain, err := url.PathUnescape(seg)
	if err != nil {
		return true
	}
	// A "=" or "," marks a key=value pair or a list, as in a query value or
	// a matrix parameter. An escaped ";" ("%3B") is a hidden matrix
	// parameter. Such text can hold a short password, so mask it.
	if strings.ContainsAny(plain, "=,;") {
		return true
	}
	return looksLikeEscapedCredential(seg, plain)
}

// looksLikeEscapedCredential reports whether escaped, plain (the unescaped
// form of escaped), or a piece of plain between two "/", looks like a
// token. An escaped prefix ("%67hp_x" for "ghp_x") or a token after an
// escaped "/" ("a%2Fghp_x") is found only in the unescaped text.
func looksLikeEscapedCredential(escaped, plain string) bool {
	if looksLikeCredential(escaped) || looksLikeCredential(plain) {
		return true
	}
	for piece := range strings.SplitSeq(plain, "/") {
		if looksLikeCredential(piece) {
			return true
		}
	}
	return false
}

// redactQuery masks every value in a raw query string. It keeps each key as
// written (still escaped), unless the key looks like a credential. A part
// "key=value" becomes "key=" + Mask, or Mask + "=" + Mask for a token key,
// and a part with no "=" becomes Mask, because a bare part can itself be a
// token. Empty parts stay empty, so the shape of the query does not change.
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
	// A token used as a key (?ghp_xxx=) is a secret too. A normal key such
	// as "api_key" or "token" is short and has no digit, so it stays. A key
	// that does not unescape fails closed.
	plain, err := url.QueryUnescape(key)
	if err != nil || looksLikeEscapedCredential(key, plain) {
		return Mask + "=" + Mask
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
	for i := range len(s) {
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
