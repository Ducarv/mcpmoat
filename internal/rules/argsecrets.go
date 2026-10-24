package rules

import (
	"path"
	"regexp"
	"strings"
	"unicode"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// maxScanLen caps the length of one arg or one URL that the secret check
// reads. Both are untrusted text from a client config. A longer text is
// skipped (no finding), so a hostile config cannot cost parse time.
const maxScanLen = 2048

const (
	// minRandomLen is the shortest value that looksRandom accepts on the digit
	// route. Settings such as "cl100k_base", "my_key_1" or "google-oauth2" have a
	// digit but are shorter than this. Real tokens are longer.
	minRandomLen = 16

	// minDigitEntropy is the Shannon entropy, in bits per byte, that a value
	// with a digit (and minRandomLen bytes) needs to look random. It is lower
	// than minEntropy because the value must also hold a digit. Tested values:
	// readable hyphen-separated names such as "xoxo-mcp-server-v2-latest" (3.65)
	// and "sk-learn-mcp-server-v2" (3.48) stay below it. Random base62 text is
	// near 3.75 at 16 bytes (max 4.0) and 4.2 or more at 24 bytes or longer. So
	// a random 16-byte value is sometimes missed (known limit).
	minDigitEntropy = 3.8

	// minHexLen is the shortest pure hex string that counts as a secret under a
	// credential-like name. 32 hex digits are 128 bits: an MD5 size, a hex API
	// key, a session secret. A shorter hex text is often a build number or a
	// short commit id.
	minHexLen = 32

	// minLongRandomLen and minLongEntropy are the route for a random value of 20
	// bytes or more under a credential-like name (see looksLongRandom). The
	// value must hold a letter and a digit and fewer than 2 of "-", "_" and ".".
	//
	// Measured on 2000 random base62 samples (seeded, so the numbers repeat):
	//   - entropy at 20 bytes: min 3.34, 1% quantile 3.68, median 4.02; at 24
	//     bytes: min 3.69. So 3.5 passes 99.8% of the 20-byte samples on entropy.
	//   - values found with this route and looksRandom together: 1949 of 2000
	//     (97.5%) at 20 and 21 bytes, 1962 (98.1%) at 22, 1959 (98.0%) at 23.
	//     The rest hold no digit (3% of random base62 text of 20 bytes).
	//   - looksRandom alone found 1793 (89.7%) at 20 bytes, 1866 at 21, 1927 at
	//     22, 1941 at 23, 813 (40.7%) at 16, 1702 (85.1%) at 19.
	//
	// The false-positive corpus stays negative: "cl100k_base" (3.28),
	// "my_key_1", "google-oauth2" (3.18), "10.0.0.0/8", "ctrl+shift+1" (3.25),
	// "2024-10-01", "my-session-1" (3.02), "us-intl-2", "john.doe1", "banana12",
	// "read_user_1" (2.91), "abcdef123456" are shorter than 20 bytes. The two
	// 20-byte-plus names, "xoxo-mcp-server-v2-latest" (3.65) and
	// "sk-learn-mcp-server-v2" (3.48), have an entropy near the limit but 4
	// separators each, so the separator rule keeps them out.
	//
	// Known limit: a random value of 16 to 19 bytes is only found when its
	// entropy reaches minDigitEntropy (about 41% to 85% of them).
	minLongRandomLen = 20
	minLongEntropy   = 3.5

	// refMark stands in for a variable reference without a default while a URL
	// is split. It is plain letters and a digit, so it is valid in a scheme, a
	// host, a port-less authority and a path. literalPart removes it again.
	refMark = "refx0"

	// maxRefPasses bounds the nested ${A:-${B:-x}} expansion.
	maxRefPasses = 3
)

var (
	// envAssignName matches the NAME of a NAME=value arg: the shape of an
	// environment variable name.
	envAssignName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	// uuidText matches a UUID in its 8-4-4-4-12 text form. A UUID in a URL
	// path is an ID, not a secret.
	uuidText = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

	// refWithDefault matches one whole reference that has a default, such as
	// ${NAME:-default} or ${NAME-default} (also := and =, and an "env:" prefix).
	// Group 1 is the default. A reference like ${NAME}, ${NAME:?msg} or
	// ${input:my-id} has no default and does not match.
	refWithDefault = regexp.MustCompile(`^\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*(?::-|:=|-|=)(.*)\}$`)
)

// checkArgSecrets reports MOAT-T4-002 for a literal secret in the command
// args of a stdio server or in the URL of a remote server. It adds at most
// one finding with Field FieldArgs and at most one with Field FieldURL, and
// the findings hold no Key and no value, arg or URL. FieldURL is only for the
// URL of a remote server. A URL inside the args of a stdio server gives
// FieldArgs.
//
// The check favours precision: a finding can fail a CI run. A credential-like
// flag or NAME needs a value that looks like a token (see tokenForName). A
// plain word under such a name is not reported. See argsHaveSecret and
// urlHasSecret for the exact shapes.
//
// Like CheckConfig, it needs s as the config file holds it, before
// discover.Expand.
func checkArgSecrets(s discover.Server) []Finding {
	var findings []Finding
	if !s.Transport.IsRemote() && argsHaveSecret(s.Args.Values()) {
		findings = append(findings, secretFinding(s.Name, FieldArgs, ""))
	}
	if s.Transport.IsRemote() && urlHasSecret(s.URL.Reveal()) {
		findings = append(findings, secretFinding(s.Name, FieldURL, ""))
	}
	return findings
}

// argsHaveSecret reports whether one of the args holds a literal secret:
//   - a secret flag with a token-like value, as "--api-key VALUE" or
//     "--api-key=VALUE";
//   - a NAME=value arg (also the value after -e or --env) with a
//     credential-like NAME and a token-like value;
//   - an arg that is a well-known token (see bareToken);
//   - a URL arg, or a flag or NAME=value arg whose value is a URL, that
//     holds a secret (see urlHasSecret). The finding has Field args, not url.
//
// It never returns or logs an arg.
func argsHaveSecret(args []string) bool {
	for i, arg := range args {
		if len(arg) > maxScanLen {
			continue
		}
		next := "" // the arg after this one, or "" at the end of the list
		if i+1 < len(args) {
			next = args[i+1]
		}
		if argHasSecret(arg, next) {
			return true
		}
	}
	return false
}

// argHasSecret checks one arg. next is the arg that follows it, or "": a
// flag such as "--token" takes its value from there.
func argHasSecret(arg, next string) bool {
	if strings.HasPrefix(arg, "-") {
		return flagHasSecret(arg, next)
	}
	// A bare arg: a token on its own, or NAME=value.
	if bareToken(arg) {
		return true
	}
	if assignmentHasSecret(arg) {
		return true
	}
	return urlValueHasSecret(arg)
}

// flagHasSecret checks an arg that starts with "-". It handles "--flag=value",
// "--flag value", and the env flags "-e NAME=value" (the NAME=value arg is
// checked by argHasSecret when the loop reaches it), "-eNAME=value" and
// "--env=NAME=value".
func flagHasSecret(arg, next string) bool {
	trimmed := strings.TrimLeft(arg, "-")
	name, value, hasValue := strings.Cut(trimmed, "=")

	// "-eNAME=value": docker lets the env flag and its value touch. Only a
	// single dash counts, so a long flag such as "--extra-key=x" is not cut.
	if !strings.HasPrefix(arg, "--") && len(name) > 1 && name[0] == 'e' && hasValue {
		if assignmentHasSecret(trimmed[1:]) {
			return true
		}
	}

	if hasValue {
		if (name == "e" || name == "env") && assignmentHasSecret(value) {
			return true
		}
		return namedValueHasSecret(name, value) || urlValueHasSecret(value)
	}

	// "--flag value": the value is the next arg. A next arg that starts with
	// "-" is another flag, so this flag has no value.
	if next == "" || strings.HasPrefix(next, "-") || len(next) > maxScanLen {
		return false
	}
	return namedValueHasSecret(name, next)
}

// assignmentHasSecret checks a NAME=value text. It is false when the text has
// no "=" or when NAME is not an environment variable name.
func assignmentHasSecret(text string) bool {
	name, value, ok := strings.Cut(text, "=")
	if !ok || !envAssignName.MatchString(name) {
		return false
	}
	return namedValueHasSecret(name, value)
}

// namedValueHasSecret reports whether value, stored under name (a flag name
// or an env variable name), is a literal secret. It never returns or logs
// value.
//
// The order of the tests:
//  1. A reference ($VAR, %VAR%) is removed, as in looksLikePlaintextSecret. A
//     value with nothing literal left is not a secret.
//  2. A well-known token (see bareToken) is a secret, under any name.
//  3. A name of a path setting ("--key-file"), or a value that is a path or
//     a URL, is not a secret. A URL value goes through urlHasSecret instead.
//  4. A credential-like name needs a token-like value (see tokenForName). For
//     a query value, the caller tests several forms of the value (see
//     valueForms).
func namedValueHasSecret(name, value string) bool {
	value = literalPart(value)
	if value == "" {
		return false
	}
	if bareToken(value) {
		return true
	}
	if namesAPath(name) || looksLikePathOrURL(value) {
		return false
	}
	return discover.IsSecretName(name) && tokenForName(name, value)
}

// literalPart returns the text of value that is really written in the config:
// "" when value is only a reference ($VAR or %VAR%), and otherwise value with
// its ${...} references expanded (see expandRefs).
func literalPart(value string) string {
	if wholeVar.MatchString(value) {
		return ""
	}
	return strings.ReplaceAll(expandRefs(value, ""), refMark, "")
}

// expandRefs replaces every ${...} reference in value. A reference with a
// default ("${NAME:-default}") becomes that default, because a client expands
// it to the default when NAME is not set, so a secret written there is a
// literal secret. A reference with no default becomes stand. A default can hold
// another reference, so the replacement runs again, at most maxRefPasses times.
func expandRefs(value, stand string) string {
	for range maxRefPasses {
		if !strings.Contains(value, "${") {
			break
		}
		// A func literal can use stand from the code around it (a closure).
		value = varRef.ReplaceAllStringFunc(value, func(ref string) string {
			if m := refWithDefault.FindStringSubmatch(ref); m != nil {
				return m[1]
			}
			return stand
		})
	}
	return value
}

// tokenForName reports whether value is token-like enough to count as a secret
// under a credential-like name. It is stricter than looksLikePlaintextSecret
// on purpose: a plain word such as "my-secret-name" under "--secret-name" is a
// name, not a secret.
//
// A value has at least minNamedSecretLen bytes, is not a boolean or a number,
// and is a secret on one of these routes:
//  1. A UUID: only when name holds "key", "token", "secret" or "pass" (this
//     covers "password" and "passwd"). A session or auth ID is often a UUID, so
//     a name that is credential-like for another reason ("--session-id") does
//     not count. A UUID gets no other route.
//  2. A token prefix (see discover.HasTokenPrefix).
//  3. A random look (see looksRandom).
//  4. Pure hex of at least minHexLen digits ("--api-key" with an MD5 or SHA
//     hex digest).
//  5. A long random look (see looksLongRandom).
//
// Routes 4 and 5 live here and not in bareToken: a bare arg or a URL path
// segment has no credential-like name to back it, so it keeps the strict rule
// (a commit id or a hash in a path is not a secret).
func tokenForName(name, value string) bool {
	if len(value) < minNamedSecretLen || isBoolOrNumber(value) {
		return false
	}
	if uuidText.MatchString(value) {
		return nameHoldsSecretWord(name)
	}
	return discover.HasTokenPrefix(value) ||
		looksRandom(value) ||
		isHexString(value, minHexLen) ||
		looksLongRandom(value)
}

// nameHoldsSecretWord reports whether name, in any case, contains "key",
// "token", "secret" or "pass". The text "pass" also covers "password" and
// "passwd". The match is on the text and not on whole words, so "apikey" and
// "X-Api-Key" count.
func nameHoldsSecretWord(name string) bool {
	lower := strings.ToLower(name)
	for _, word := range [...]string{"key", "token", "secret", "pass"} {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// isHexString reports whether s has at least minLen bytes and only hex digits
// (0-9, a-f, A-F).
func isHexString(s string, minLen int) bool {
	if len(s) < minLen {
		return false
	}
	for i := range len(s) {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// looksLongRandom reports whether value is a token-shaped text of at least
// minLongRandomLen bytes that holds a letter and a digit and has an entropy of
// at least minLongEntropy. It catches a random value that looksRandom misses
// because the entropy of a sample of 20 to 23 bytes is below minDigitEntropy.
func looksLongRandom(value string) bool {
	if len(value) < minLongRandomLen || !isTokenShaped(value) {
		return false
	}
	hasLetter := strings.ContainsFunc(value, unicode.IsLetter)
	hasDigit := strings.ContainsFunc(value, unicode.IsDigit)
	// Two or more of "-", "_" and "." mean a name made of words
	// ("my-prod-secret-store-v2"), not a random token.
	separators := strings.Count(value, "-") + strings.Count(value, "_") + strings.Count(value, ".")
	return hasLetter && hasDigit && separators < 2 && shannonEntropy(value) >= minLongEntropy
}

// looksRandom reports whether value has the shape of a random token: only
// token bytes (see isTokenShaped) and one of two things:
//   - at least minRandomLen bytes, a digit and an entropy of at least
//     minDigitEntropy;
//   - at least minEntropyLen bytes and an entropy of at least minEntropy.
//
// A short value with a digit ("my_key_1", "ctrl+shift+1", "2024-10-01") is a
// setting, not a token. Known limit: a random value of under minRandomLen bytes
// is not found.
func looksRandom(value string) bool {
	if len(value) < minRandomLen || !isTokenShaped(value) {
		return false
	}
	entropy := shannonEntropy(value)
	if strings.ContainsFunc(value, unicode.IsDigit) && entropy >= minDigitEntropy {
		return true
	}
	return len(value) >= minEntropyLen && entropy >= minEntropy
}

// bareToken reports whether value is a well-known token format on its own: it
// starts with a token prefix, has at least minPrefixedTokenLen bytes, is not a
// path or a URL, and looks random (see looksRandom). The last test keeps out a
// readable name that shares a prefix, such as a package called
// "sk-learn-mcp-server-v2" or "xoxo-mcp-server-v2-latest".
func bareToken(value string) bool {
	return len(value) >= minPrefixedTokenLen &&
		discover.HasTokenPrefix(value) &&
		!looksLikePathOrURL(value) &&
		looksRandom(value)
}

// urlValueHasSecret checks the text that a flag or a NAME=value arg holds
// after its "=". It runs urlHasSecret on that value, or on the whole arg when
// the arg is a URL on its own. The caller reports a hit with Field args,
// because the URL sits in the args of a stdio server.
func urlValueHasSecret(arg string) bool {
	if !strings.Contains(arg, "://") {
		return false
	}
	// "NAME=https://..." and "--flag=https://...": cut at the first "=", but
	// only when the text before it is a name and not part of the URL.
	if name, value, ok := strings.Cut(arg, "="); ok && !strings.ContainsAny(name, "/:?#") {
		return urlHasSecret(value)
	}
	return urlHasSecret(arg)
}

// urlHasSecret reports whether raw is a URL that holds a literal secret:
//   - the value of a credential-like query key ("?api_key=...", "?token=..."),
//     when it is token-like (see tokenForName). The value is tested decoded
//     with "+" as a space, decoded with "+" kept, and without stray "%" bytes
//     (see valueForms);
//   - a password in the user info ("user:password@host"), or a token as the
//     user name ("https://ghp_...@host");
//   - a path segment that is a well-known token (see bareToken) or a long
//     random string (see randomPathSegment). A file extension is cut first and
//     a 32, 40 or 64 digit hex segment (a hash or a commit id) does not count.
//
// A UUID segment, a readable segment such as "mcp" or "sse", and a query such
// as "?page=2" are not secrets. The check reads the URL the way clients do: it
// removes tabs and newlines and trims control characters first (see
// checkInsecureURL).
//
// The URL is cut by splitURL, not by url.Parse. url.Parse fails on input that
// clients accept (a "%" in a password, a bad escape, a bad port, an empty host
// after a reference), and a check that gives up there would hide a secret.
func urlHasSecret(raw string) bool {
	if len(raw) > maxScanLen {
		return false
	}
	cleaned := strings.TrimFunc(tabsAndNewlines.Replace(raw), func(r rune) bool { return r <= ' ' || r == 0x7f })
	// A default is kept (it is scanned). A reference with no default becomes
	// refMark, so "?token=${TOKEN}" has no literal value and "${HOST}" is still
	// a host.
	cleaned = expandRefs(cleaned, refMark)
	parts := splitURL(cleaned)
	return userInfoHasSecret(parts.userInfo) || queryHasSecret(parts.query) || pathHasSecret(parts.path)
}

// urlParts holds the raw pieces of a URL that urlHasSecret checks.
type urlParts struct {
	userInfo string // text before the last "@" of the authority, or ""
	path     string // from the first "/" of the rest up to "?" or "#"
	query    string // text after "?" up to "#"
}

// splitURL cuts raw into its pieces by hand. It never fails and it never
// returns an error, so no input text can reach an error message.
//
// The scheme ends at "://". The authority runs up to the first "/", "?" or
// "#". The user info is the part of the authority before its last "@". The
// fragment is dropped.
func splitURL(raw string) urlParts {
	rest := raw
	if i := strings.Index(raw, "://"); i >= 0 && !strings.ContainsAny(raw[:i], "/?#") {
		rest = raw[i+len("://"):]
	} else {
		rest = strings.TrimPrefix(rest, "//")
	}

	var parts urlParts
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority, rest = rest[:i], rest[i:]
	} else {
		rest = ""
	}
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		parts.userInfo = authority[:i]
	}
	rest, _, _ = strings.Cut(rest, "#") // the fragment is not checked
	parts.path, parts.query, _ = strings.Cut(rest, "?")
	return parts
}

// lenientUnescape decodes the percent escapes in s, and "+" as a space when
// plusIsSpace is true (the query form). It never fails: url.PathUnescape and
// url.QueryUnescape return an error for a stray "%" or a bad escape such as
// "%zz", and their error text holds the input. Here a valid %XX is decoded and
// anything else is kept as it is, so the checks still see the rest of the text.
func lenientUnescape(s string, plusIsSpace bool) string {
	if !strings.ContainsAny(s, "%+") {
		return s // the common case: nothing to decode, no copy
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '%' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]):
			b.WriteByte(unhexByte(s[i+1])<<4 | unhexByte(s[i+2]))
			i += 2 // skip the two hex digits we just read
		case s[i] == '+' && plusIsSpace:
			b.WriteByte(' ')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// unhexByte returns the value (0 to 15) of the hex digit c. The caller checks
// isHexDigit first.
func unhexByte(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	default:
		return c - '0'
	}
}

// valueForms returns the texts of a query value that the secret check tests.
// Any one of them that qualifies is a hit:
//   - the value decoded the query way ("+" is a space);
//   - the value decoded the path way ("+" stays a plus), because a base64-like
//     secret holds "+" and a client may send it as it is;
//   - each of these with its "%" bytes removed, when one is left. A "%" that
//     stays after decoding is a stray or a bad escape ("?token=<random>%"),
//     and it would make the token shape test fail and hide the secret.
func valueForms(rawValue string) []string {
	forms := []string{
		lenientUnescape(rawValue, true),
		lenientUnescape(rawValue, false),
	}
	for _, form := range forms[:2] {
		if strings.Contains(form, "%") {
			forms = append(forms, strings.ReplaceAll(form, "%", ""))
		}
	}
	return forms
}

// userInfoHasSecret checks the user info of a URL ("user:password", "token" or
// ""). A password that is not only a reference is a secret. A user name is a
// secret when it is a token.
func userInfoHasSecret(userInfo string) bool {
	user, password, hasPassword := strings.Cut(userInfo, ":")
	if hasPassword && literalPart(password) != "" {
		return true
	}
	name := literalPart(lenientUnescape(user, false))
	return bareToken(name) || randomSegment(name)
}

// queryHasSecret checks the query string of a URL. It reads the pairs itself
// instead of url.ParseQuery, which skips a pair with a bad escape.
func queryHasSecret(rawQuery string) bool {
	for pair := range strings.SplitSeq(rawQuery, "&") {
		key, value, _ := strings.Cut(pair, "=")
		key = strings.ReplaceAll(lenientUnescape(key, true), refMark, "")
		for _, form := range valueForms(value) {
			if namedValueHasSecret(key, form) {
				return true
			}
		}
	}
	return false
}

// pathHasSecret checks every segment of a URL path. Each segment is decoded
// on its own, so "%2F" does not split a segment.
func pathHasSecret(urlPath string) bool {
	for segment := range strings.SplitSeq(urlPath, "/") {
		segment = literalPart(lenientUnescape(segment, false))
		if bareToken(segment) || randomPathSegment(segment) {
			return true
		}
	}
	return false
}

// randomSegment reports whether a path segment or a user name is a long
// random string: at least minEntropyLen token bytes with an entropy of at
// least minEntropy. A UUID is an ID and does not count. This test needs no
// digit, because a long readable segment must stay out of the findings.
func randomSegment(segment string) bool {
	return len(segment) >= minEntropyLen &&
		!uuidText.MatchString(segment) &&
		isTokenShaped(segment) &&
		shannonEntropy(segment) >= minEntropy
}

// randomPathSegment is randomSegment for one segment of a URL path, with two
// more rules for the file names that a path often ends in:
//   - a file extension is cut first (see trimFileExt), so that the commit id in
//     ".../archive/<40 hex>.zip" is tested as "<40 hex>";
//   - a pure hex text of 32, 40 or 64 digits (MD5, SHA-1 or SHA-256, so also a
//     commit id) is a hash, not a secret.
//
// A user name in the user info keeps the plain randomSegment, because a hex
// token there ("https://<40 hex>@host") is a real secret shape.
func randomPathSegment(segment string) bool {
	segment = trimFileExt(segment)
	if len(segment) == 32 || len(segment) == 40 || len(segment) == 64 {
		if isHexString(segment, len(segment)) {
			return false
		}
	}
	return randomSegment(segment)
}

// trimFileExt cuts a file extension from the end of segment: ".tar.gz",
// ".zip", ".whl" and the like. The extension is the text after the last "."
// when it is 1 to maxExtLen ASCII letters or digits, and a ".tar" before it is
// cut too. A segment with no such extension is returned as it is.
func trimFileExt(segment string) string {
	const maxExtLen = 8 // ".tar.bz2" has a 3 byte extension; 8 is generous
	ext := path.Ext(segment)
	if len(ext) < 2 || len(ext) > maxExtLen+1 || len(ext) == len(segment) {
		return segment
	}
	for i := 1; i < len(ext); i++ {
		c := ext[i]
		isAlnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !isAlnum {
			return segment
		}
	}
	return strings.TrimSuffix(strings.TrimSuffix(segment, ext), ".tar")
}
