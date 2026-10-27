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
//     query key that looks like a credential (see below; a normal key such
//     as "api_key", "token" or "k" stays);
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
//
// A query key is masked (Mask + "=" + Mask) when it does not unescape
// (url.QueryUnescape), when its unescaped form has a "=", ",", ";" or ":"
// (for example "password%3Dhunter2", "pw,hunter2" or "admin:hunter2"), or
// when it looks like a token by the same checks as a path segment.
//
// A text looks like a token when one or more of these rules is true:
//
//   - it starts with a known token prefix, in any case (such as sk-, ghp_,
//     xox, AKIA, or eyJ for a JWT), and it is longer than the prefix;
//   - it has minMixedTokenLen or more bytes, at least one ASCII letter and
//     at least one digit;
//   - it has minTokenLen or more bytes;
//   - it is a UUID (uuidLen bytes: 8-4-4-4-12 hex digits).
//
// The constants are in token.go.
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
// It also returns Mask if the scheme is not in a fixed allowlist (see
// isKnownScheme): the MCP transport schemes http, https, ws and wss, and
// the schemes of the connection strings that args often hold (postgres,
// postgresql, mysql, redis, rediss, mongodb, mongodb+srv, amqp, amqps,
// file, unix, tcp, git, ssh, s3 and gs). A token pasted where the scheme
// goes, as in "sk-proj-abc123://host/x", parses as a valid scheme and
// would print. url.Parse lowercases the scheme, so "HTTPS" is kept as
// "https". A scheme-relative URL ("//host/x") has no scheme text and is
// kept.
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
// It keeps the scheme (lowercased), the host, the port, the other path
// segments and the other query keys.
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
	// The scheme is the text before ":", so a token can sit there too
	// ("sk-proj-abc123://host"). Keep only schemes that we know.
	if !isKnownScheme(u.Scheme) {
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

// isKnownScheme reports whether scheme, as url.Parse returns it (lower
// case), is in the RedactURL allowlist. The empty scheme of a
// scheme-relative URL ("//host/x") is allowed, because it prints no scheme
// text. A switch, not a map, keeps the list constant.
func isKnownScheme(scheme string) bool {
	switch scheme {
	case "",
		// MCP transports.
		"http", "https", "ws", "wss",
		// Connection strings (DSNs) and other URLs that args often hold.
		"postgres", "postgresql", "mysql", "redis", "rediss",
		"mongodb", "mongodb+srv", "amqp", "amqps",
		"file", "unix", "tcp", "git", "ssh", "s3", "gs":
		return true
	default:
		return false
	}
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

// SecretPathSegments returns the path segments of raw that RedactURL masks,
// each in its escaped form and, when it differs, in its unescaped form. It
// returns nil when raw does not parse or has no such segment.
//
// RedactURL masks a segment only as part of the whole URL. A caller that
// scrubs other text, for example an error that holds another URL with the
// same path prefix, uses this list to remove the segments one by one.
func SecretPathSegments(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var segments []string
	add := func(s string) {
		if s == "" {
			return
		}
		segments = append(segments, s)
		if plain, err := url.PathUnescape(s); err == nil && plain != s {
			segments = append(segments, plain)
		}
	}
	for seg := range strings.SplitSeq(u.EscapedPath(), "/") {
		if seg == "" || redactPathSegment(seg) == seg {
			continue
		}
		add(seg)
		// redactPathSegment masks each part after ";" (a matrix parameter),
		// and the part before it when it is secret. A server can echo such a
		// part alone, so list the masked parts too.
		if parts := strings.Split(seg, ";"); len(parts) > 1 {
			if isSecretPathSegment(parts[0]) {
				add(parts[0])
			}
			for _, p := range parts[1:] {
				add(p)
			}
		}
	}
	return segments
}

// SecretQueryParts returns the parts of rawQuery that RedactURL masks, one by
// one: every value, every bare part with no "=", and every key that looks
// like a credential (see isSecretQueryKey). Each part comes in its raw form
// and, when it differs, unescaped. It splits on "&" and ";", as RedactURL
// does.
//
// RedactURL masks the query only as part of the whole URL. A caller that
// scrubs other text, for example an error message that echoes a query value
// alone, uses this list to remove the parts one by one.
func SecretQueryParts(rawQuery string) []string {
	var parts []string
	add := func(s string) {
		if s == "" {
			return
		}
		parts = append(parts, s)
		if plain, err := url.QueryUnescape(s); err == nil && plain != s {
			parts = append(parts, plain)
		}
	}
	isSep := func(r rune) bool { return r == '&' || r == ';' }
	for part := range strings.FieldsFuncSeq(rawQuery, isSep) {
		key, value, found := strings.Cut(part, "=")
		if !found {
			add(part)
			continue
		}
		if isSecretQueryKey(key) {
			add(key)
		}
		add(value)
	}
	return parts
}

// maskedURLParts returns the parts of raw that RedactURL masks, for
// ArgSecrets, when RedactURL does not mask raw whole:
//
//   - the user info as written; the password as written and unescaped; and
//     the name as written and unescaped when IsSecretUserName reports true
//     for it: when there is no password, as in https://<token>@host/, or
//     when the name looks like a token, as in
//     https://<token>:x-oauth-basic@github.com/ (a name next to a password
//     is often a plain word);
//   - SecretPathSegments and SecretQueryParts;
//   - the fragment as written and unescaped.
//
// Each part is not empty. It returns nil when raw does not parse.
func maskedURLParts(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var parts []string
	if u.User != nil {
		info := RawUserinfo(raw)
		parts = appendForms(parts, info, "")
		name, password, _ := strings.Cut(info, ":")
		plainPassword, _ := u.User.Password()
		parts = append(parts, userinfoSecrets(name, password, u.User.Username(), plainPassword)...)
	}
	parts = append(parts, SecretPathSegments(raw)...)
	parts = append(parts, SecretQueryParts(u.RawQuery)...)
	if _, fragment, found := strings.Cut(raw, "#"); found {
		parts = appendForms(parts, fragment, u.Fragment)
	}
	return parts
}

// appendForms appends written and plain to parts. written is a part as it
// is in the URL. plain is its unescaped form. Each one is added when it is
// not empty, and plain is not added again when it equals written.
func appendForms(parts []string, written, plain string) []string {
	if written != "" {
		parts = append(parts, written)
	}
	if plain != "" && plain != written {
		parts = append(parts, plain)
	}
	return parts
}

// userinfoSecrets returns the secret parts of a user info: the password, and
// the user name when IsSecretUserName says it is a secret. name and password
// are the user info as written in the URL, and plainName and plainPassword
// are the unescaped forms (see appendForms).
func userinfoSecrets(name, password, plainName, plainPassword string) []string {
	parts := appendForms(nil, password, plainPassword)
	if IsSecretUserName(plainName, plainPassword) {
		parts = appendForms(parts, name, plainName)
	}
	return parts
}

// wholeURLParts returns the inner parts of raw, a text with "://" or "//"
// that RedactURL masks whole, for ArgSecrets. RedactURL masks such a text
// whole when the scheme is not on its list ("jdbc:postgresql://h/db?...") or
// when it cannot show the URL safely, so ArgSecrets keeps the whole text.
// A server can echo a password or a query value alone, so this is a best
// effort to find them: it cuts raw at its first "//" and gives the parts of
// the rest that maskedURLParts gives for a URL with no scheme. When the rest
// does not parse, it gives the user info as written, found as url.Parse
// would find it (see RawUserinfo), its password and, by the rule of
// IsSecretUserName, its name. It over-matches at worst: raw is masked
// already. It returns nil when raw has no "//" or no such part.
func wholeURLParts(raw string) []string {
	i := strings.Index(raw, "//")
	if i < 0 {
		return nil
	}
	rest := raw[i:]
	if parts := maskedURLParts(rest); parts != nil {
		return parts
	}
	info := RawUserinfo(rest)
	if info == "" {
		return nil
	}
	name, password, _ := strings.Cut(info, ":")
	return append([]string{info}, userinfoSecrets(name, password, name, password)...)
}

// IsSecretUserName reports whether name, the unescaped user name of a URL or
// of a Basic credential with the unescaped password, is a secret by itself,
// and not only a plain word next to the password. That is so when password
// is empty, as in https://<token>@host/, because then the name is the
// credential. With a password, it is so when name looks like a token: by
// the RedactArgs rules (a known token prefix such as "ghp_", or a long
// random-looking word), or when name has MinSecretBytes or more bytes
// and holds a digit. GitHub documents
// https://<token>:x-oauth-basic@github.com/ for a token in the name.
//
// A caller that removes the name from other text applies its own length
// floor. It never prints or stores name or password. It is exported so that
// ArgSecrets and the error scrub of internal/inspect agree on the rule.
func IsSecretUserName(name, password string) bool {
	if password == "" || containsToken(name) {
		return true
	}
	return len(name) >= MinSecretBytes && strings.ContainsAny(name, "0123456789")
}

// RawUserinfo returns the user info of raw as written, the text between "//"
// and the last "@" of the authority, without the "@", or "" when there is
// none. It finds the authority as url.Parse does: after the first "//" (a
// scheme has no "/"), up to the first "/", "?" or "#". It works on text that
// does not parse too. The result can hold a raw secret: never print, log or
// store it. It is exported so that the redaction and the error scrub of
// internal/inspect read the user info in the same way.
func RawUserinfo(raw string) string {
	_, authority, found := strings.Cut(raw, "//")
	if !found {
		return ""
	}
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return ""
	}
	return authority[:at]
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
	// parameter, and a ":" can join a user and a password. Such text can
	// hold a short password, so mask it (the same set as for query keys).
	if strings.ContainsAny(plain, "=,;:") {
		return true
	}
	return looksLikeEscapedCredential(seg, plain)
}

// looksLikeEscapedCredential reports whether escaped, plain (the unescaped
// form of escaped), or a piece of plain between two "/", looks like a
// token. An escaped prefix ("%67hp_x" for "ghp_x") or a token after an
// escaped "/" ("a%2Fghp_x") is found only in the unescaped text. Each piece
// is also checked for a token prefix after ".", "@", ":", "+" or "~", as in
// RedactArgs ("v1.ghp_x").
func looksLikeEscapedCredential(escaped, plain string) bool {
	if looksLikeCredential(escaped) || looksLikeCredential(plain) {
		return true
	}
	for piece := range strings.SplitSeq(plain, "/") {
		if containsToken(piece) {
			return true
		}
	}
	return false
}

// redactQuery masks every value in a raw query string. It keeps each key as
// written (still escaped), unless redactQueryPart masks it. A part
// "key=value" becomes "key=" + Mask, or Mask + "=" + Mask for a secret key,
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
	if isSecretQueryKey(key) {
		return Mask + "=" + Mask
	}
	return escapeUnsafeBytes(key) + "=" + Mask
}

// isSecretQueryKey reports whether key, one escaped query key, must be
// masked. It fails closed, as isSecretPathSegment does: a key that does not
// unescape is masked. So is a key whose unescaped form has "=", ",", ";" or
// ":", because such a key can hold a value or a "user:password" pair
// ("?password%3Dhunter2=", "?pw,hunter2=x", "?admin:hunter2=1"). A token
// used as a key (?ghp_xxx=) is a secret too. A normal key such as
// "api_key" or "token" is short and has no digit, so it stays.
func isSecretQueryKey(key string) bool {
	plain, err := url.QueryUnescape(key)
	if err != nil {
		return true
	}
	if strings.ContainsAny(plain, "=,;:") {
		return true
	}
	return looksLikeEscapedCredential(key, plain)
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
		if isPrintable(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0f])
	}
	return b.String()
}
