package discover

import (
	"strings"
	"unicode"
)

// RedactArgs returns a copy of args for display, with likely credentials
// masked. Use it wherever Server.Args are shown: Args is a plain []string,
// so fmt, log/slog and encoders print it unmasked. Server.Args itself stays
// as written, because the scanner runs exactly the configured command
// (NFR-04).
//
// Masking is heuristic. It looks at the shape of each argument, so it can
// miss a secret and it can mask a value that is not secret. The rules, in
// order:
//
//  1. The argument after a secret-like flag ("--token", "--api-key")
//     becomes [Mask], whatever it is. "--flag=value" becomes
//     "--flag=" + Mask. For "--flag=value" with any other flag, the value
//     goes through rules 3 to 6.
//  2. The argument after a header flag ("-H", "--header", "--headers") is a
//     header line: the name is kept and the value is masked
//     ("Authorization: " + Mask). "--header=line" works the same way. A
//     header line with no valid name becomes Mask.
//  3. "NAME=value" (NAME of letters, digits, "_", "-" and ".") becomes
//     "NAME=" + Mask if NAME is secret-like, as in docker "-e TOKEN=x".
//     Otherwise the value goes through rules 4 to 6.
//  4. A header line "Name: value" with a secret-like Name (Authorization,
//     Proxy-Authorization, X-Api-Key, Api-Key, Cookie, X-Auth-Token and
//     others) keeps the name and masks the value.
//  5. "Bearer x" or "Basic x" (any case) keeps the scheme word and masks
//     the rest.
//  6. An argument that contains "://" goes through [RedactURL].
//
// Any other argument stays as written.
//
// A name is secret-like if, in lower case and without "-", "_" and ".", it
// contains token, secret, password, passwd, pwd, apikey, key, auth,
// credential, bearer, cookie or session, and does not end in file, path,
// dir or url. The ending rule keeps "--key-file /path" and
// "--token-url URL" readable: a path is not a credential, and a URL value
// still goes through RedactURL.
//
// Known limits:
//
//   - A boolean flag with a secret-like name ("--no-auth") masks the next
//     argument even if that argument is not its value.
//   - A short flag joined to its value ("-pSECRET", "-HAuthorization: x")
//     is not seen as a flag.
//   - "-H" is a header flag only in upper case, so "-h" (often help) does
//     not mask the next argument. Tools that use "-H" for something else
//     get their next argument masked.
//   - A secret in a positional argument with no recognisable shape (for
//     example a bare token) is not masked.
//
// RedactArgs returns nil for nil input and never changes args.
func RedactArgs(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	// next tells how to treat the following argument. It is set by a
	// secret-like flag or a header flag with no "=value".
	next := argPlain
	for i, arg := range args {
		switch next {
		case argSecret:
			out[i], next = Mask, argPlain
		case argHeader:
			out[i], next = redactHeaderLine(arg), argPlain
		default:
			out[i], next = redactArg(arg)
		}
	}
	return out
}

// argKind tells how RedactArgs treats a flag value.
type argKind int

const (
	argPlain  argKind = iota // not secret: apply the value rules
	argSecret                // mask the whole value
	argHeader                // header line: keep the name, mask the value
)

// redactArg redacts one argument that does not follow a flag. It also
// returns how to treat the next argument: argSecret or argHeader after a
// flag that takes its value from the next argument, else argPlain.
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
	switch kind {
	case argSecret:
		return prefix + Mask, argPlain
	case argHeader:
		return prefix + redactHeaderLine(value), argPlain
	default:
		return prefix + redactValue(value), argPlain
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
	// "H" is compared in upper case only: "-h" is usually help.
	if name == "H" || strings.EqualFold(name, "header") || strings.EqualFold(name, "headers") {
		return argHeader
	}
	if isSecretName(name) {
		return argSecret
	}
	return argPlain
}

// redactValue applies the rules for an argument that is not a flag and
// does not follow one: "NAME=value", then the rules of redactPlain.
func redactValue(arg string) string {
	name, value, found := strings.Cut(arg, "=")
	if found && isName(name) {
		if isSecretName(name) {
			return name + "=" + Mask
		}
		// Not secret by name, but the value can still be a URL with a
		// token, for example "API_URL=https://u:p@host".
		return name + "=" + redactPlain(value)
	}
	return redactPlain(arg)
}

// redactPlain applies the header line, auth scheme and URL rules to s.
func redactPlain(s string) string {
	// A header line comes first: "Authorization: Bearer x" must keep its
	// name, and "token: x" holds no "://" for the URL rule to catch.
	if name, _, found := strings.Cut(s, ":"); found && isHeaderName(name) && isSecretName(name) {
		return redactHeaderLine(s)
	}
	for _, scheme := range []string{"Bearer ", "Basic "} {
		if len(s) >= len(scheme) && strings.EqualFold(s[:len(scheme)], scheme) {
			// Keep the scheme word as written, without its space.
			return s[:len(scheme)-1] + " " + Mask
		}
	}
	if strings.Contains(s, "://") {
		return RedactURL(s)
	}
	return s
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
// See RedactArgs for the rule.
func isSecretName(name string) bool {
	// Compare in lower case without "-", "_" and ".", so "api-key", "API_KEY"
	// and "apiKey" all become "apikey". strings.Map drops a rune when the
	// function returns -1.
	n := strings.Map(func(r rune) rune {
		switch r {
		case '-', '_', '.':
			return -1
		}
		return unicode.ToLower(r)
	}, name)

	// A name with one of these endings holds a location, not a credential,
	// for example "--key-file" or "--token-url".
	for _, end := range []string{"file", "path", "dir", "url"} {
		if strings.HasSuffix(n, end) {
			return false
		}
	}
	secretWords := []string{
		"token", "secret", "password", "passwd", "pwd", "apikey", "key",
		"auth", "credential", "bearer", "cookie", "session",
	}
	for _, word := range secretWords {
		if strings.Contains(n, word) {
			return true
		}
	}
	return false
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
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}
