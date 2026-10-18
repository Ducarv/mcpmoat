package discover

import (
	"slices"
	"strings"
)

// RedactArgs returns a copy of args for display. It shows an argument only
// when the argument has a shape that is known to be safe, and it replaces
// everything else with [Mask]. [Args] uses it in all its output, so
// Server.Args prints masked through fmt, log/slog and encoders. The values
// stay as written inside Args, because the scanner runs exactly the
// configured command (NFR-04).
//
// RedactArgs uses an allowlist and fails closed. A secret can hide in many
// shapes (JSON, connection strings, header lines, DSNs), so an argument with
// a shape that is not on the list is masked, even when it is not a secret.
//
// A name (of a flag or a variable) is secret-like if it contains a word such
// as "token", "secret", "password", "passphrase", "key", "auth", "private"
// or "cookie", or if one of its words is a short form such as "pass", "pw",
// "pin", "otp", "jwt", "pat" or "cred" ("DB_PASS", "--github-pat",
// "--pin"). An all-caps word that ends in a short form is secret-like too
// ("PGPASS", "DBPW"). "bypass", "--path", "--spin", "--option" and
// "--credit" are not secret-like.
//
// Flags. An argument "-name", "--name" or "--name=value", where name has only
// ASCII letters, digits, "_", "-" and ".", is a flag. The flag is shown as
// written.
//
//   - The value of a secret-like flag ("--token", "--api-key",
//     "--key-file"), a header flag ("-H", "--header", "--headers") or a user
//     flag ("-u", "--user") is always masked. The value is the part after
//     "=", or else the next argument. A header line is masked whole, with its
//     name, so no part of a badly formed line can show.
//   - For any other flag, the part after "=" follows the value rules below.
//     The next argument is not a value of that flag: it is a new argument.
//   - An argument that parses as a flag is never the value of the flag
//     before it. So a boolean flag cannot use up the mask: in
//     "--no-auth --token S", "S" is masked. A lone "-" or "--", and a
//     single-dash word that is longer than one letter and is not secret-like
//     ("--password -abc"), are values, so they are masked.
//   - A flag with a name that looks like a token (see below) is masked
//     whole. This catches a token glued to a short flag ("-p" + token), a
//     token that starts with "-" and a long secret-like name
//     ("--s3-secret-access-key"). If such a flag has no "=value", the next
//     argument is masked too, because it can be the value.
//   - An argument that starts with "-" but is not a flag, other than "-"
//     and "--", is masked whole. It can be a value glued to a short flag in
//     a shape that is not a name ("-uadmin:pw", "-HX-Key:v").
//
// Values. Every other argument is shown only in these shapes:
//
//  1. "NAME=value", where NAME has only ASCII letters, digits, "_", "-" and
//     ".". NAME is shown. The value is masked if NAME is secret-like. Else
//     the value follows rules 2 to 4, not rule 1 again. So a URL value goes
//     through RedactURL, and other text with a second "=" is masked by
//     rule 4, because "=" is not a safe byte.
//  2. A URL (the text contains "://" or starts with "//") goes through
//     [RedactURL].
//  3. ":" and "@" are shown only in fixed places. Text is masked if it has
//     both, or if the text before its first ":" is a secret-like name
//     ("token:abc"). One ":" is safe before a port of 1 to 5 digits
//     ("localhost:8080") or after a Windows drive letter at the start
//     ("C:\x"). An "@" is safe at the start of a path segment, as an npm
//     scope ("@scope/pkg"), or as one version marker in "name@version" or
//     "@scope/name@version". The version starts with a digit ("1.2.3",
//     "v2") or is a tag such as "latest". Text with a ":" or an "@" in any
//     other place is masked ("admin:pw", "scott/tiger@orcl").
//  4. Other text is split into segments at each "/" and "\". The separators
//     stay. A segment is shown if it is empty, or if it has only ASCII
//     letters, digits and "._:@+-~" and does not look like a token. Every
//     other segment becomes Mask.
//
// A segment looks like a token by the same rules as the path segments of
// [RedactURL]: long random-looking words and known token prefixes such as
// "ghp_" or "sk-".
//
// Examples:
//
//	-y @modelcontextprotocol/server-filesystem /home/me/proj    shown
//	--port 8080 localhost:8080 pkg@1.2.3 ./repo C:\keys\a.pem    shown
//	-e LOG_LEVEL=debug                                           shown
//	-e GITHUB_TOKEN=x            -e GITHUB_TOKEN=********
//	--token x                    --token ********
//	--s3-secret-access-key x     ******** ********
//	-H "Authorization: Bearer x" -H ********
//	-uadmin:x                    ********
//	https://h/sse?key=x          https://h/sse?key=********
//	{"token":"x"}                ********
//	"Bearer x"                   ********
//	a;Password=x                 ********
//	admin:x                      ********
//	scott/x@orcl                 ********
//	u:p@tcp(h)/db                ********
//	/data/ghp_abc123/x           /data/********/x
//
// Output. Each string in the result is empty, or has only printable ASCII
// bytes (0x20 to 0x7e): non-ASCII, control and bidi characters are not on
// the list, so they are masked. The output is still untrusted text from the
// config, so display code must escape it as usual (internal/report does).
//
// Known limits:
//
//   - A secret with a plain shape is shown when nothing marks it as secret:
//     a short word after a flag that is not secret-like ("--db mypassword"),
//     a positional word ("hunter2"), a short path segment
//     ("/run/hunter2/x"), a short value glued to a short flag
//     ("-phunter2"), or a number in the place of a port ("admin:1234").
//   - A token that "/" splits into short pieces (for example base64 text)
//     is shown, because each piece is checked alone.
//   - A secret value that starts with "--", or a single-dash word with a
//     secret-like name ("--password -token"), is seen as a flag and is shown,
//     unless it looks like a token.
//   - A short form glued to a lower-case word ("dbpass") is not seen as
//     secret-like.
//   - Some values that are not secret are masked: the argument after a
//     boolean flag with a secret-like or token-like name ("--no-auth
//     server.js", "--private x"), a path after a secret-like flag
//     ("--key-file /etc/key.pem"), "-u 1000:1000" (docker), text with
//     spaces, quotes, ",", ";", "=", "*" or "%" ("--pattern *.go", the
//     "Application Support" folder in a path), long readable segments, a
//     dash argument that is not a flag ("-javaagent:/x.jar"), an image tag
//     ("mcp/github:latest"), an IPv6 address ("[::1]:8080"), a mail or SSH
//     address ("me@example.com", "git@github.com:org/repo"), a version range
//     ("pkg@^1.2") and all-caps names such as "BYPASS" or "SPIN".
//
// RedactArgs returns nil for nil input, never changes args and always
// returns a slice of the same length as args.
func RedactArgs(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	// maskNext is true after a flag such as "--token" or "-H" with no
	// "=value", or a flag that is masked whole with no "=value": its value
	// is the next argument, and that value is masked.
	maskNext := false
	for i, arg := range args {
		// A flag is never the value of the flag before it, so a boolean
		// flag such as "--no-auth" cannot use up the mask that a following
		// "--token" needs.
		if maskNext && !isFlagNotValue(arg) {
			out[i], maskNext = Mask, false
			continue
		}
		out[i], maskNext = redactArg(arg)
	}
	return out
}

// redactArg redacts one argument that is not the value of the flag before
// it. shown is the text to display. maskNext is true if the next argument
// can be the value of arg and must be masked: arg is a flag such as
// "--token", or a flag that is masked whole, with no "=value".
func redactArg(arg string) (shown string, maskNext bool) {
	name, value, hasValue, ok := parseFlag(arg)
	switch {
	case !ok && strings.HasPrefix(arg, "-") && arg != "-" && arg != "--":
		// "-uadmin:pw" or "-HX-Key:v": a value glued to a short flag, in a
		// shape that is not a flag name.
		return Mask, false
	case !ok:
		return displayValue(arg), false
	case looksLikeCredential(name):
		// "-p" + token, a token that starts with "-", or a long secret-like
		// name such as "--s3-secret-access-key". With no "=value", the next
		// argument can be the value, so mask it too (fail closed).
		return Mask, !hasValue
	case !hasValue:
		// "--token": the value is the next argument.
		return arg, masksValue(name)
	}
	// "--name=value": keep everything up to and including "=".
	prefix := arg[:len(arg)-len(value)]
	if masksValue(name) {
		return prefix + Mask, false
	}
	return prefix + displayValue(value), false
}

// masksValue reports whether the value of the flag called name is always
// masked: a header flag, a user flag or a secret-like flag.
func masksValue(name string) bool {
	// "H" and "u" are compared as written: "-h" is usually help, and "-U"
	// is often a user name with no password (psql).
	if name == "H" || name == "u" || isSecretName(name) {
		return true
	}
	// valueFlags are long header and user flags, in any case.
	valueFlags := [...]string{"header", "headers", "user"}
	for _, f := range valueFlags {
		if strings.EqualFold(name, f) {
			return true
		}
	}
	return false
}

// isFlagNotValue reports whether arg, which comes right after a flag that
// takes a value, is a new flag and not that value. A lone "-" and "--" are
// values. "--name" and a one-letter "-x" are flags. A longer single-dash word
// such as "-abc" can be a password, so it is a flag only when its value is
// masked too (Go-style "-token"). In every other case it is the value, and
// it is masked (fail closed).
func isFlagNotValue(arg string) bool {
	name, _, _, ok := parseFlag(arg)
	switch {
	case !ok:
		return false
	case strings.HasPrefix(arg, "--"), len(name) == 1:
		return true
	default:
		return masksValue(name)
	}
}

// parseFlag splits an argument of the form "-name", "--name" or
// "--name=value". ok is false if arg is not a flag: it does not start with
// "-", or the name is not valid (see isName). "-" alone (often stdin) and
// "--" are not flags.
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

// displayValue returns a value for display: rule 1 of the RedactArgs doc
// ("NAME=value"), then displayShape for the rest.
func displayValue(s string) string {
	name, value, found := strings.Cut(s, "=")
	if !found || !isName(name) {
		return displayShape(s)
	}
	if isSecretName(name) {
		return name + "=" + Mask
	}
	// displayShape, not displayValue: one level only. A URL value such as
	// "U=https://h/?a=1" goes through RedactURL. Other text with a second
	// "=" ("A=B=c") gives "A=" + Mask, because "=" is not a safe byte in a
	// segment.
	return name + "=" + displayShape(value)
}

// displayShape applies rules 2 to 4 of the RedactArgs doc to s: it shows s
// only if s has a safe shape, and returns Mask otherwise.
func displayShape(s string) string {
	switch {
	case s == "":
		return "" // nothing to hide, and Mask would look like a value
	case strings.Contains(s, "://") || strings.HasPrefix(s, "//"):
		return RedactURL(s)
	case strings.Contains(s, ":") && strings.Contains(s, "@"):
		// "user:pass@host" or a DSN: the password has no fixed place.
		return Mask
	case hasSecretLabel(s):
		// "x-auth-token:abc" is a header line with no space after ":".
		return Mask
	case !safeColon(s) || !safeAts(s):
		// "admin:pw", "scott/tiger@orcl": a ":" or "@" in a place that is
		// not on the list.
		return Mask
	default:
		return maskSegments(s)
	}
}

// hasSecretLabel reports whether s has a ":" and the text before the first
// ":" is a secret-like name, as in "token:abc" or "X-Api-Key:abc".
func hasSecretLabel(s string) bool {
	label, _, found := strings.Cut(s, ":")
	return found && isSecretName(label)
}

// safeColon reports whether s has no ":", or exactly one ":" in a safe
// place: before a port ("localhost:8080", "127.0.0.1:3000") or after a
// Windows drive letter at the start ("C:", `C:\x`, "C:/x"). Any other ":"
// can split a user and a password ("admin:pw"), so it is not safe.
func safeColon(s string) bool {
	i := strings.IndexByte(s, ':')
	switch {
	case i < 0:
		return true
	case strings.Count(s, ":") > 1:
		return false
	case i == 1 && isLetter(s[0]) && (len(s) == 2 || s[2] == '/' || s[2] == '\\'):
		return true // a Windows drive
	default:
		return i > 0 && isPort(s[i+1:])
	}
}

// isPort reports whether s is a port number: 1 to 5 ASCII digits.
func isPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	for i := range len(s) {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// safeAts reports whether every "@" in s is in a safe place: at the start
// of a path segment, as an npm scope ("@scope/pkg",
// "node_modules/@scope/pkg"), or as a version marker after a package name
// ("pkg@1.2.3", "@scope/pkg@latest"; see isPackageName and isVersion). Any
// other "@" can end a user and a password ("scott/tiger@orcl") or join a
// user and a host, so it is not safe.
func safeAts(s string) bool {
	for i := range len(s) {
		if s[i] != '@' {
			continue
		}
		if i == 0 || s[i-1] == '/' || s[i-1] == '\\' {
			// A scope needs a name: "@" alone, "@/x" and "@@x" are not safe.
			if i+1 == len(s) || strings.IndexByte(`/\@`, s[i+1]) >= 0 {
				return false
			}
			continue
		}
		if !isPackageName(s[:i]) || !isVersion(s[i+1:]) {
			return false
		}
	}
	return true
}

// isPackageName reports whether s is a package name before a version
// marker: "name" or "@scope/name", where scope and name are not empty and
// have no "/", "\" or "@".
func isPackageName(s string) bool {
	name := s
	if rest, scoped := strings.CutPrefix(s, "@"); scoped {
		scope, n, found := strings.Cut(rest, "/")
		if !found || scope == "" || strings.ContainsAny(scope, `\@`) {
			return false
		}
		name = n
	}
	return name != "" && !strings.ContainsAny(name, `/\@`)
}

// isVersion reports whether s is a package version after "@": a tag such as
// "latest", or a version that starts with a digit, with an optional "v"
// before it ("1.2.3", "v2", "1.0.0-rc.1"). A version has only ASCII
// letters, digits, ".", "+" and "-". A host name ("user@host") is not a
// version.
func isVersion(s string) bool {
	// distTags are common npm dist-tags.
	distTags := [...]string{"latest", "next", "beta", "alpha", "canary"}
	if slices.Contains(distTags[:], s) {
		return true
	}
	rest := strings.TrimPrefix(s, "v")
	return rest != "" && isDigit(rest[0]) && onlyBytes(rest, ".+-")
}

// maskSegments splits s at every "/" and "\", keeps the separators, and
// passes each segment through safeSegment. A path such as
// "/data/ghp_abc123/x" keeps its shape and loses only the token.
func maskSegments(s string) string {
	var b strings.Builder
	start := 0 // index of the first byte of the current segment
	for i := range len(s) {
		if s[i] == '/' || s[i] == '\\' {
			b.WriteString(safeSegment(s[start:i]))
			b.WriteByte(s[i])
			start = i + 1
		}
	}
	b.WriteString(safeSegment(s[start:]))
	return b.String()
}

// safeSegment returns seg if it is empty, or a plain word that does not look
// like a token, and Mask otherwise. A plain word has only ASCII letters,
// digits and "._:@+-~": enough for package names ("@scope", "pkg@1.2.3"),
// host:port, file names and "~". displayShape has already checked where
// ":" and "@" are. Every other byte (space, quote, brace, ";", ",", "=",
// "%", "*" and every non-ASCII byte) is a sign of a shape we do not know, so
// the segment is masked.
func safeSegment(seg string) string {
	if seg == "" || (onlyBytes(seg, "._:@+-~") && !looksLikeCredential(seg)) {
		return seg
	}
	return Mask
}

// isSecretName reports whether name looks like the name of a credential.
// This function holds the full word list; the RedactArgs doc gives only
// examples.
//
// name is split into words (see nameWords), so "api-key", "API_KEY" and
// "apiKey" all give the words "api" and "key", in some case.
func isSecretName(name string) bool {
	words := nameWords(name)
	for _, w := range words {
		if isShortForm(w) {
			return true
		}
	}
	// secretParts match anywhere in the joined name, so "githubtoken",
	// "clientSecret" and "X-Api-Key" match. "apikey" needs no entry of its
	// own: "key" covers it. "credential" covers "credentials"; "cred" is a
	// short form, so that "credit" does not match.
	secretParts := [...]string{
		"token", "secret", "password", "passwd", "passphrase", "pwd", "key",
		"auth", "credential", "bearer", "cookie", "session", "mnemonic",
		"private",
	}
	joined := strings.ToLower(strings.Join(words, ""))
	for _, part := range secretParts {
		if strings.Contains(joined, part) {
			return true
		}
	}
	return false
}

// isShortForm reports whether word is a short form such as "pass", "pin" or
// "jwt" in any case, or an all-caps word that ends in one ("DBPASS",
// "PGPASS").
//
// Short forms do not match inside a lower-case or mixed-case word, because
// there they give false positives: "bypass", "compass" (pass), "path",
// "patch", "pattern" (pat), "spin", "pinned" (pin), "credit" (cred). All-caps
// env names glue words with no separator more often ("PGPASS" is the
// PostgreSQL password variable), so for them a suffix match is worth a rare
// false positive such as "BYPASS".
func isShortForm(word string) bool {
	shortForms := [...]string{"pass", "pw", "pin", "otp", "jwt", "pat", "cred", "creds"}
	lower := strings.ToLower(word)
	allCaps := word == strings.ToUpper(word)
	for _, short := range shortForms {
		if lower == short || (allCaps && strings.HasSuffix(lower, short)) {
			return true
		}
	}
	return false
}

// nameWords splits name into words, in their original case. A word ends at
// every byte that is not an ASCII letter or digit ("-", "_", ".", a space)
// and before an upper-case letter that starts a camelCase word (see
// startsCamelWord). So "DB_PASS" gives "DB", "PASS"; "githubPat" gives
// "github", "Pat"; "DBPass" gives "DB", "Pass"; and "bypass" stays one word.
func nameWords(name string) []string {
	var words []string
	start := -1 // index of the first byte of the current word, or -1
	for i := range len(name) {
		switch {
		case !isAlnum(name[i]):
			if start >= 0 {
				words = append(words, name[start:i])
				start = -1
			}
		case start < 0:
			start = i
		case startsCamelWord(name, i):
			words = append(words, name[start:i])
			start = i
		}
	}
	if start >= 0 {
		words = append(words, name[start:])
	}
	return words
}

// startsCamelWord reports whether name[i], a letter or digit inside a word
// (so i > 0 and name[i-1] is a letter or digit), starts a new camelCase
// word. That is so for an upper-case letter after a lower-case letter or a
// digit ("githubPat" splits before "P"), and for the last upper-case letter
// of a run when a lower-case letter follows ("DBPass" splits before "P").
func startsCamelWord(name string, i int) bool {
	if !isUpper(name[i]) {
		return false
	}
	if !isUpper(name[i-1]) {
		return true
	}
	return i+1 < len(name) && isLower(name[i+1])
}

// isName reports whether s is a non-empty flag or variable name: ASCII
// letters, digits, "_", "-" and ".".
func isName(s string) bool {
	return s != "" && onlyBytes(s, "_-.")
}

// onlyBytes reports whether every byte of s is an ASCII letter, an ASCII
// digit or one of the bytes in extra. It is true for "".
func onlyBytes(s, extra string) bool {
	for i := range len(s) {
		if !isAlnum(s[i]) && strings.IndexByte(extra, s[i]) < 0 {
			return false
		}
	}
	return true
}
