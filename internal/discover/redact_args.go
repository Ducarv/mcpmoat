package discover

import "strings"

// RedactArgs returns a copy of args for display, with likely credentials
// masked. Use it wherever Server.Args are shown: Args is a plain []string,
// so fmt, log/slog and encoders print it unmasked. Server.Args itself stays
// as written, because the scanner runs exactly the configured command
// (NFR-04).
//
// Masking is heuristic. It looks at the shape of each argument, so it can
// miss a secret and it can mask a value that is not secret.
//
// A name (of a flag, a variable, a header or a list key) is secret-like if
// it contains a word such as "token", "secret", "password" or "key", or if
// one of its words is a short form such as "pass", "jwt" or "pat" (so
// "DB_PASS" and "--github-pat" are secret-like, but "bypass" and "--path"
// are not). isSecretName in this file has the full word list and the rule.
//
// Flags. A flag ("-name", "--name" or "--name=value") stays as written and
// tells how to treat its value: the next argument, or the part after "=".
//
//   - After a secret-like flag ("--token", "--api-key"), the value becomes
//     [Mask]. If the flag name ends in file, path, dir or url ("--key-file",
//     "--token-url"), a value that looks like a path or a URL (it has "/" or
//     "\", or starts with "~" or ".") is not a credential: it is kept, and a
//     URL goes through [RedactURL]. Any other value is masked.
//   - After a header flag ("-H", "--header", "--headers"), the value is a
//     header line: the name is kept and the value is masked
//     ("Authorization: " + Mask). A line with no valid name becomes Mask.
//   - After a user flag ("-u", "--user", as in curl), "user:password" keeps
//     the user and masks the part after the first ":". A value with no ":"
//     is kept.
//   - After any other flag, the value in "--flag=value" goes through the
//     value rules below. The next argument is not a value of that flag.
//   - An argument that parses as a flag is never the value of the flag
//     before it. It is treated as a flag. So a boolean flag cannot use up
//     the mask: in "--no-auth --token S", "S" is masked. A lone "-" (often
//     stdin) is not a flag, so it is a value.
//
// Values. Any other argument goes through these rules, in order:
//
//  1. A list of "Key=Value" parts split by ";" (a connection string such as
//     "Server=x;Password=y") masks the value of each secret-like key and
//     keeps the other parts. A part with no "=" right after a masked value
//     is masked too, because it can be the rest of that value.
//  2. "NAME=value" (NAME of letters, digits, "_", "-" and ".") becomes
//     "NAME=" + Mask if NAME is secret-like, as in docker "-e TOKEN=x". The
//     file, path, dir and url endings work as for flags. Otherwise the value
//     goes through rules 3 to 5.
//  3. A header line "Name: value" with a secret-like Name (Authorization,
//     Proxy-Authorization, X-Api-Key, Cookie, X-Auth-Token and others) keeps
//     the name and masks the value.
//  4. "Bearer x" or "Basic x" (any case, then a space or a tab) keeps the
//     scheme word and the spaces after it, and masks the rest.
//  5. An argument that contains "://" or starts with "//" goes through
//     [RedactURL].
//
// Any other argument stays as written.
//
// The output is untrusted text. Only the masked parts and the URLs that go
// through RedactURL are changed; everything else keeps control, bidi and
// non-ASCII characters as written in the config. Display code must escape
// the output before it prints it to a terminal (internal/report does).
//
// Known limits:
//
//   - A boolean flag with a secret-like name ("--no-auth") masks the next
//     argument if that argument is not a flag.
//   - A secret value that starts with "--", or that is a single-dash word
//     with a secret-like name ("--password -token"), is seen as a flag and
//     kept. Other values that start with "-" ("--password -abc") are masked.
//   - A short flag joined to its value ("-pSECRET", "-HAuthorization: x")
//     is not seen as a flag.
//   - "-H" is a header flag only in upper case, so "-h" (often help) does
//     not mask the next argument. Tools that use "-H" for something else
//     get their next argument masked. In the same way, tools that use "-u"
//     or "--user" for something else ("docker -u 1000:1000") get the part
//     after ":" masked.
//   - After a flag that ends in file, path, dir or url, a secret with a
//     "/" in it ("--token-url ab/cd") looks like a path and is kept.
//   - A short form glued to another word in lower case ("dbpass") is not
//     seen as secret-like.
//   - A secret in a positional argument with no recognisable shape (for
//     example a bare token) is not masked.
//
// RedactArgs returns nil for nil input, never changes args and always
// returns a slice of the same length as args.
func RedactArgs(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	// next tells how to treat the following argument. A flag with no
	// "=value" sets it; every other argument resets it to argPlain.
	next := argPlain
	for i, arg := range args {
		// A flag is never the value of the flag before it, so a boolean
		// flag such as "--no-auth" cannot use up the mask that a following
		// "--token" needs.
		if next != argPlain && !isFlagNotValue(arg) {
			out[i], next = redactFlagValue(next, arg), argPlain
			continue
		}
		out[i], next = redactArg(arg)
	}
	return out
}

// argKind tells how RedactArgs treats the value of a flag.
type argKind int

const (
	argPlain    argKind = iota // not secret: apply the value rules
	argSecret                  // mask the whole value
	argLocation                // secret-like name for a location: keep a path or URL, mask the rest
	argHeader                  // header line: keep the name, mask the value
	argUserPass                // "user:password": keep the user, mask the password
)

// redactArg redacts one argument that is not the value of the flag before
// it. It also returns how to treat the next argument: the kind of the flag
// if arg is a flag with no "=value", else argPlain.
func redactArg(arg string) (string, argKind) {
	name, value, hasValue, ok := parseFlag(arg)
	if !ok {
		return redactValue(arg), argPlain
	}
	kind := flagKind(name)
	if !hasValue {
		// "--token": the value is the next argument.
		return arg, kind
	}
	// "--token=value": keep everything up to and including "=".
	prefix := arg[:len(arg)-len(value)]
	return prefix + redactFlagValue(kind, value), argPlain
}

// redactFlagValue redacts value, the value of a flag of the given kind.
func redactFlagValue(kind argKind, value string) string {
	switch kind {
	case argSecret:
		return Mask
	case argLocation:
		return redactLocation(value)
	case argHeader:
		return redactHeaderLine(value)
	case argUserPass:
		return redactUserPass(value)
	default:
		return redactValue(value)
	}
}

// isFlagNotValue reports whether arg, which comes right after a flag that
// takes a value, is a new flag and not that value. A lone "-" and "--" are
// values. "--name" and a one-letter "-x" are flags. A longer single-dash word
// such as "-abc" can be a password, so it is a flag only when its own name is
// secret-like (Go-style "-token"): then the value after it is masked. In every
// other case it is the value, and it is masked (fail closed).
func isFlagNotValue(arg string) bool {
	name, _, _, ok := parseFlag(arg)
	switch {
	case !ok:
		return false
	case strings.HasPrefix(arg, "--"), len(name) == 1:
		return true
	default:
		return flagKind(name) != argPlain
	}
}

// parseFlag splits an argument of the form "-name", "--name" or
// "--name=value". ok is false if arg is not a flag: it does not start with
// "-", or the name is empty or has a byte that is not allowed in a name
// (see isName). "-" alone (often stdin) and "--" are not flags.
func parseFlag(arg string) (name, value string, hasValue, ok bool) {
	body, found := strings.CutPrefix(arg, "-")
	if !found {
		return "", "", false, false
	}
	body = strings.TrimPrefix(body, "-") // the second dash of "--name"
	name, value, hasValue = strings.Cut(body, "=")
	if !isName(name) {
		return "", "", false, false
	}
	return name, value, hasValue, true
}

// flagKind tells how to treat the value of the flag called name.
func flagKind(name string) argKind {
	// "H" and "u" are compared as written: "-h" is usually help, and "-U"
	// is often a user name with no password (psql).
	switch {
	case name == "H" || strings.EqualFold(name, "header") || strings.EqualFold(name, "headers"):
		return argHeader
	case name == "u" || strings.EqualFold(name, "user"):
		return argUserPass
	default:
		return secretKind(name)
	}
}

// secretKind tells how to treat the value of a flag, variable or list key
// called name: argSecret, argLocation or argPlain.
func secretKind(name string) argKind {
	if !isSecretName(name) {
		return argPlain
	}
	if hasLocationEnding(name) {
		return argLocation
	}
	return argSecret
}

// redactValue applies the rules for an argument that is not a flag and is
// not the value of a secret, header or user flag: a ";" list, then
// "NAME=value", then the rules of redactByShape.
func redactValue(arg string) string {
	if out, ok := redactKeyValueList(arg); ok {
		return out
	}
	name, value, found := strings.Cut(arg, "=")
	if found && isName(name) {
		return name + "=" + redactNamedValue(name, value)
	}
	return redactByShape(arg)
}

// redactNamedValue redacts value, the value of the variable or list key
// called name. A value with a name that is not secret can still hold a URL
// with a token, for example "API_URL=https://u:p@host", so it goes through
// redactByShape.
func redactNamedValue(name, value string) string {
	switch secretKind(name) {
	case argSecret:
		return Mask
	case argLocation:
		return redactLocation(value)
	default:
		return redactByShape(value)
	}
}

// redactKeyValueList redacts a list of "Key=Value" parts split by ";", such
// as the connection string "Server=x;Password=y;Database=z". ok is false if
// s is not such a list: it has no ";", or its first part is not
// "Key=Value" with a valid key (see isListKey).
func redactKeyValueList(s string) (out string, ok bool) {
	first, _, found := strings.Cut(s, ";")
	if !found {
		return "", false
	}
	if key, _, hasValue := strings.Cut(first, "="); !hasValue || !isListKey(key) {
		return "", false
	}
	parts := strings.Split(s, ";")
	// masking is true after a part whose value was masked. A ";" can be part
	// of a password, so a following part with no "Key=" can be the rest of
	// that password and is masked too.
	masking := false
	for i, part := range parts {
		key, value, hasValue := strings.Cut(part, "=")
		switch {
		case hasValue && isListKey(key):
			// The key stays as written, with any spaces around it.
			value = redactNamedValue(strings.TrimSpace(key), value)
			parts[i] = key + "=" + value
			masking = value == Mask
		case part == "":
			// Keep empty parts, so ";;" and a final ";" stay as written.
		case masking:
			parts[i] = Mask
		default:
			parts[i] = redactByShape(part)
		}
	}
	return strings.Join(parts, ";"), true
}

// redactByShape applies the header line, auth scheme and URL rules to s.
func redactByShape(s string) string {
	// A header line comes first: "Authorization: Bearer x" must keep its
	// name, and "token: x" holds no "://" for the URL rule to catch.
	if name, _, found := strings.Cut(s, ":"); found && isHeaderName(name) && isSecretName(name) {
		return redactHeaderLine(s)
	}
	for _, scheme := range []string{"Bearer", "Basic"} {
		if !hasPrefixFold(s, scheme) || len(s) == len(scheme) {
			continue
		}
		rest := s[len(scheme):]
		if rest[0] != ' ' && rest[0] != '\t' {
			continue // "Bearerx" or "basically" is one word, not a scheme
		}
		// Keep the scheme word and the spaces after it as written ("bearer",
		// "Basic\t"), and mask everything after them.
		spaces := len(rest) - len(strings.TrimLeft(rest, " \t"))
		return s[:len(scheme)+spaces] + Mask
	}
	// "//host/path" is a URL with no scheme. It can hold a userinfo or a
	// query token just like "https://host/path".
	if strings.Contains(s, "://") || strings.HasPrefix(s, "//") {
		return RedactURL(s)
	}
	return s
}

// redactLocation redacts the value of a secret-like name that ends in file,
// path, dir or url. A path or a URL is a location, not a credential, so it
// is kept (a URL still goes through RedactURL). Anything else can be the
// credential itself ("SECRET_URL=sk-123"), so it is masked.
func redactLocation(value string) string {
	if !isLocation(value) {
		return Mask
	}
	return redactByShape(value)
}

// isLocation reports whether value looks like a file path or a URL: it has
// a "/" or a "\", or it starts with "~" or ".".
func isLocation(value string) bool {
	return strings.ContainsAny(value, `/\`) ||
		strings.HasPrefix(value, "~") ||
		strings.HasPrefix(value, ".")
}

// redactUserPass keeps the user of a "user:password" value and masks the
// part after the first ":". A value with no ":" is only a user name, so it
// is kept.
func redactUserPass(value string) string {
	user, _, found := strings.Cut(value, ":")
	if !found {
		return value
	}
	return user + ":" + Mask
}

// redactHeaderLine keeps the name of a "Name: value" header line, with its
// colon and the spaces after it, and masks the value. A line with no colon
// or with a name that is not a valid header name becomes Mask, because we
// cannot tell which part is secret.
func redactHeaderLine(line string) string {
	name, value, found := strings.Cut(line, ":")
	if !found || !isHeaderName(name) {
		return Mask
	}
	spaces := len(value) - len(strings.TrimLeft(value, " \t"))
	return name + ":" + value[:spaces] + Mask
}

// isSecretName reports whether name looks like the name of a credential.
// This function holds the full word list; the RedactArgs doc gives only
// examples.
//
// name is split into lower-case words (see nameWords), so "api-key",
// "API_KEY" and "apiKey" all give the words "api" and "key".
func isSecretName(name string) bool {
	words := nameWords(name)
	for _, w := range words {
		// Short forms match only as a whole word, because as a part of a
		// word they give false positives: "bypass", "compass", "jwtish"
		// (pass), "path", "patch", "pattern" (pat).
		switch w {
		case "pass", "jwt", "pat":
			return true
		}
	}
	// Longer words match anywhere in the joined name, so "githubtoken",
	// "clientSecret" and "X-Api-Key" match. "apikey" needs no entry of its
	// own: "key" covers it.
	joined := strings.Join(words, "")
	for _, part := range []string{
		"token", "secret", "password", "passwd", "pwd", "key",
		"auth", "credential", "bearer", "cookie", "session",
	} {
		if strings.Contains(joined, part) {
			return true
		}
	}
	return false
}

// hasLocationEnding reports whether name, in lower case and without
// separators, ends in file, path, dir or url, as in "--key-file" or
// "TOKEN_URL".
func hasLocationEnding(name string) bool {
	joined := strings.Join(nameWords(name), "")
	for _, end := range []string{"file", "path", "dir", "url"} {
		if strings.HasSuffix(joined, end) {
			return true
		}
	}
	return false
}

// nameWords splits name into lower-case words. A word ends at every byte
// that is not an ASCII letter or digit ("-", "_", ".", a space) and before
// an upper-case letter that follows a lower-case letter or a digit. So
// "DB_PASS" gives "db", "pass"; "githubPat" gives "github", "pat"; and
// "bypass" stays one word.
func nameWords(name string) []string {
	var words []string
	start := -1 // index of the first byte of the current word, or -1
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case !isAlnum(c):
			if start >= 0 {
				words = append(words, strings.ToLower(name[start:i]))
				start = -1
			}
		case start < 0:
			start = i
		case isUpper(c) && !isUpper(name[i-1]):
			// camelCase boundary: "githubPat" splits before "P".
			words = append(words, strings.ToLower(name[start:i]))
			start = i
		}
	}
	if start >= 0 {
		words = append(words, strings.ToLower(name[start:]))
	}
	return words
}

// hasPrefixFold reports whether s starts with prefix, ignoring case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// isListKey reports whether key is a key in a ";" list: ASCII letters,
// digits, "_", "-", "." and spaces, with at least one byte that is not a
// space. Connection strings use keys with spaces, such as "User ID".
func isListKey(key string) bool {
	if strings.TrimSpace(key) == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if !isAlnum(c) && c != '_' && c != '-' && c != '.' && c != ' ' {
			return false
		}
	}
	return true
}

// isName reports whether s is a non-empty flag or variable name: ASCII
// letters, digits, "_", "-" and ".".
func isName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// isHeaderName reports whether s is a non-empty HTTP header name (an RFC
// 9110 token: ASCII letters, digits and !#$%&'*+-.^_`|~).
func isHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

// isAlnum reports whether c is an ASCII letter or digit.
func isAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || isUpper(c) || '0' <= c && c <= '9'
}

// isUpper reports whether c is an ASCII upper-case letter.
func isUpper(c byte) bool {
	return 'A' <= c && c <= 'Z'
}
