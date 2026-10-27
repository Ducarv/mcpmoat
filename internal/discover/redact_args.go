package discover

import (
	"net/url"
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
// ("PGPASS", "DBPW"). A number at the end of a word does not change this
// ("--pass2", "REDIS_PASS1"). "bypass", "--path", "--spin", "--option",
// "--opt2" and "--credit" are not secret-like.
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
//   - Right after a flag whose value is masked, an argument "--name" or
//     "--name=value" is a new flag, not the value. So a boolean flag cannot
//     use up the mask: in "--no-auth --token S", "S" is masked. Of the
//     single-dash arguments, only "-H" and "-u" are new flags there. Any
//     other argument there is the value, and it is masked: "-", "--",
//     "-p=x", "-x" and "-abc" in "--password -p=x". If that argument can be
//     a flag that masks its own value too (Go-style "-token"), the argument
//     after it is masked as well.
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
//     ".". The text before "=" can be a secret, not a name, so the whole
//     argument is masked if NAME looks like a token ("ghp_abc=1", base64
//     text such as "c2VjcmV0LXZhbHVlLTEyMzQ="), or if NAME has 16 bytes or
//     more and the value is empty or only "=" (base64 padding). An
//     environment name in upper case with "_" ("OTEL_EXPORTER_OTLP_ENDPOINT")
//     is not checked for these two shapes. Else NAME is shown, and the value
//     is masked if NAME is secret-like. Else the value follows rules 2 to 4,
//     not rule 1 again. So a URL value goes through RedactURL, and other
//     text with a second "=" is masked by rule 4, because "=" is not a safe
//     byte.
//  2. A URL (the text contains "://" or starts with "//") goes through
//     [RedactURL].
//  3. ":" and "@" are shown only in fixed places. Text is masked if it has
//     both, or if the text before its first ":" is a secret-like name
//     ("token:abc"). One ":" is safe before a port of 1 to 5 digits
//     ("localhost:8080") or after a Windows drive letter at the start
//     ("C:\x"). An "@" is safe at the start of a path segment, as an npm
//     scope ("@scope/pkg"), or as one version marker in "name@version" or
//     "@scope/name@version". The version is a tag such as "latest", or
//     numbers with at least one "." and an optional "v" before them, and an
//     optional "-label" or "+label" after them ("1.2.3", "v2.0.1-beta.1").
//     Text with a ":" or an "@" in any other place is masked ("admin:pw",
//     "scott/tiger@orcl", "scott@1tiger").
//  4. Other text is split into segments at each "/" and "\". The separators
//     stay. A segment is shown if it is empty, or if it has only ASCII
//     letters, digits and "._:@+-~" and does not look like a token. Every
//     other segment becomes Mask.
//
// A segment or a NAME looks like a token by the same rules as the path
// segments of [RedactURL]: long random-looking words and known token
// prefixes such as "ghp_" or "sk-". A token prefix also counts after ".",
// "@", ":", "+" and "~" ("@ghp_abc", "x.sk-abc"). A flag name is checked in
// the same way.
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
//   - A secret value that starts with "--" ("--password --hunter2") is seen
//     as a flag and is shown, unless it looks like a token.
//   - Base64 text with "=" padding is shown if the text before "=" has the
//     form of an environment name ("ABC_DEF=") or is shorter than 16 bytes
//     with no token sign ("abcdefgh=").
//   - A short form glued to a lower-case word ("dbpass") is not seen as
//     secret-like.
//   - Some values that are not secret are masked: the argument after a
//     boolean flag with a secret-like or token-like name ("--no-auth
//     server.js", "--private x"), a single-dash flag other than "-H" and
//     "-u" after such a flag ("--no-auth -v"; the argument after "-v" is
//     then shown; in "--no-auth -token x" both "-token" and "x" are
//     masked), a NAME of 32 bytes or more that is not an environment name
//     ("management.endpoints.web.exposure.include=x"), a path after a
//     secret-like flag ("--key-file /etc/key.pem"), "-u 1000:1000" (docker),
//     text with spaces, quotes, ",", ";", "=", "*" or "%" ("--pattern
//     *.go", the "Application Support" folder in a path), long readable
//     segments, a dash argument that is not a flag ("-javaagent:/x.jar"),
//     an image tag ("mcp/github:latest"), an IPv6 address ("[::1]:8080"), a
//     mail or SSH address ("me@example.com", "git@github.com:org/repo"), a
//     version range ("pkg@^1.2"), a version with no "." ("pkg@2",
//     "pkg@v2") and all-caps names such as "BYPASS" or "SPIN".
//
// RedactArgs returns nil for nil input, never changes args and always
// returns a slice of the same length as args.
func RedactArgs(args []string) []string {
	if args == nil {
		return nil
	}
	// The zero argScanner does not collect the masked text.
	var r argScanner
	return r.scan(args)
}

// ArgSecrets returns the text of args that [RedactArgs] masks, as written:
// each piece that RedactArgs replaces with [Mask], in the order of args. A
// caller that sends text off the machine uses it to remove from that text the
// secrets that a server got in its args and can echo (for example scan
// --llm, through Result.Secrets in internal/inspect). The rules are the ones
// of RedactArgs, and both functions run the same code, so the two cannot
// differ.
//
// A piece is a whole argument ("ghp_x" after "--token", "-uadmin:pw"), the
// value after "=" ("--api-key=x", "GITHUB_TOKEN=x") or one path segment
// ("ghp_abc123" in "/data/ghp_abc123/x"). For a URL, the pieces are the parts
// that RedactURL masks: the user info whole; the password; the name when
// there is no password or when it looks like a token (see IsSecretUserName),
// as in https://<token>:x-oauth-basic@github.com/ (each as written and
// unescaped); the secret path segments and query parts (see
// SecretPathSegments and SecretQueryParts); and the fragment. When RedactURL
// masks the URL whole ("jdbc:postgresql://h/db?password=x"), the pieces are
// the whole URL and then, as a best effort, the same parts of the text from
// its first "//" on.
//
// A server can echo an inner value of a masked piece alone, so ArgSecrets
// also returns, after the piece:
//
//   - for a header line or an auth value, as in -H "Authorization: Bearer
//     x": the value after "Name:" when the text before the first ":" is a
//     name ("Bearer x"), and the credential after an auth scheme, a name
//     followed by a space, when the credential has no space ("x"). Both are
//     trimmed of spaces.
//   - for key=value pairs and JSON ("Server=h;Password=x", "host=h
//     password=x", "session=x; other=1", "--password=x", {"token":"x"},
//     "admin:x"): the value after the first "=" of each piece and the text
//     after a ":" (see innerValues). This over-matches on purpose: it can
//     return ordinary words of a masked argument.
//   - for an argument that is masked whole because a token is glued to a
//     flag or stands as the flag name ("-p" + token, "--" + token): the text
//     after the dashes and before "=", and for one dash also that text
//     without its first byte (the token). For "NAME=value" that is masked
//     whole because NAME looks like a token ("ghp_x=1"): NAME.
//
// Each string is not empty. The result can hold a value more than one time,
// and it holds short values too: the caller filters them. It is nil when
// RedactArgs masks nothing. ArgSecrets never changes args.
//
// The result holds raw secret values. Never print, log, encode or store
// them; compare them with text in memory only.
func ArgSecrets(args []string) []string {
	r := argScanner{collect: true}
	r.scan(args)
	return r.secrets
}

// ArgCredentials returns the pieces of args that look like a credential: a
// subset of [ArgSecrets], in the order of args. ArgSecrets fails closed and
// also returns plain words of a masked argument (a word of a path segment
// with a space, a host name in a DSN). A caller that sends text off the
// machine and must not garble plain words uses ArgCredentials instead (scan
// --llm, through Result.Credentials in internal/inspect). It runs the same
// code as RedactArgs and ArgSecrets.
//
// A piece of ArgSecrets is a credential in these cases:
//
//   - the value of a secret-like flag or key, whole ("x" in "--api-key x",
//     "--token=x", "GITHUB_TOKEN=x", "token:x"), and an argument or a NAME
//     that RedactArgs masks because it looks like a token ("-p" + token,
//     "ghp_x=1");
//   - the value of a user flag ("-u", "--user"), whole, and the text after
//     its ":" (the password in "admin:pw"); the same for text with a ":"
//     before an "@" ("u:p@tcp(h)/db");
//   - in the value of a header flag ("-H", "--header"): the value after a
//     secret-like header name ("Authorization", "Cookie", "X-Api-Key"), a
//     value that looks like a token, and the whole line when it has no
//     "Name:" form;
//   - in any masked text: the credential after an auth scheme ("x" in
//     "Bearer x"; see isAuthScheme), the value of a key=value pair or of a
//     JSON key when the key is secret-like ("x" in "Password=x" and in
//     {"token":"x"}), and every word or value that looks like a token (see
//     tokenLike);
//   - for a URL: the user info, the password and, by the rule of
//     IsSecretUserName, the name, always; a path segment, a matrix
//     parameter, a query part or the fragment only when it looks like a
//     token or when its query key is secret-like ("?api_key=x").
//
// A token is a word with a known token prefix ("ghp_", "sk-"), a UUID or a
// long random-looking word (see LooksLikeCredential). Plain words are not
// credentials: "localhost", "production" and "postgres" in
// "host=localhost dbname=production user=postgres", "Documents" in a path
// segment "My Documents" ("My" is no auth scheme), "engineering" in
// "?workspace=engineering" and "application/json" in -H "Content-Type:
// application/json". A long readable word of minTokenLen or more bytes
// still counts as a token: the rule fails closed.
//
// Like ArgSecrets, each string is not empty, the result can hold a value
// more than one time and holds short values too: the caller filters them. It
// is nil when no piece is a credential. ArgCredentials never changes args.
//
// The result holds raw secret values. Never print, log, encode or store
// them; compare them with text in memory only.
func ArgCredentials(args []string) []string {
	r := argScanner{collectCredentials: true}
	r.scan(args)
	return r.credentials
}

// argScanner runs the rules of RedactArgs over a list of args. When collect
// is true, it also keeps the text that it masks in secrets, for ArgSecrets
// (see mask). When collectCredentials is true, it keeps the parts of that
// text that look like a credential in credentials, for ArgCredentials (see
// keepCredential). The zero value collects nothing, for RedactArgs. All the
// redaction code is in its methods, so RedactArgs, ArgSecrets and
// ArgCredentials cannot differ. An argScanner is used by one goroutine only.
type argScanner struct {
	collect            bool
	collectCredentials bool
	// secrets and credentials hold raw values from the args. Never print,
	// log or encode them.
	secrets     []string
	credentials []string
}

// pieceKind tells why RedactArgs masks a piece of text. keepCredential uses
// it to decide which parts of the piece are credentials.
type pieceKind int

const (
	// pieceNone means "nothing to mask". redactArg returns it when the next
	// argument is not a value that must be masked.
	pieceNone pieceKind = iota
	// pieceShape is text that is masked for its shape only (a space, a ":"
	// in an unknown place). Only its parts that look like a credential count.
	pieceShape
	// pieceSecret is text that a secret-like name marks, or text that looks
	// like a token. All of it is a credential.
	pieceSecret
	// pieceHeader is the value of a header flag: a header line.
	pieceHeader
	// pieceUser is the value of a user flag, or text with "user:password@".
	// All of it is a credential, and so is each value after a ":".
	pieceUser
)

// mask returns Mask in place of s, text that is masked for its shape only.
// When r collects, it keeps s and its inner values (see keep and
// keepCredential).
func (r *argScanner) mask(s string) string {
	return r.maskAs(s, pieceShape)
}

// maskAs returns Mask in place of s, a piece of the given kind. When r
// collects, it keeps s and its inner values (see keepAs).
func (r *argScanner) maskAs(s string, kind pieceKind) string {
	r.keepAs(s, kind)
	return Mask
}

// keepAs keeps s, a piece of the given kind, for ArgSecrets (see keep) and
// for ArgCredentials (see keepCredential).
func (r *argScanner) keepAs(s string, kind pieceKind) {
	r.keep(s)
	r.keepCredential(s, kind)
}

// keepCredential does nothing unless r collects credentials. Then it keeps
// the parts of s, a masked piece of the given kind, that look like a
// credential: s itself for pieceSecret and pieceUser, for a pieceHeader line
// with no "Name:" form and for any s that looks like a token (see
// tokenLike); for pieceUser also each value after a ":" (see innerValues);
// and for every kind the inner parts that credentialParts returns. Each part
// is also a part that keep returns for s, so ArgCredentials is a subset of
// ArgSecrets.
func (r *argScanner) keepCredential(s string, kind pieceKind) {
	if !r.collectCredentials || s == "" {
		return
	}
	whole := tokenLike(s)
	switch kind {
	case pieceSecret, pieceUser:
		whole = true
	case pieceHeader:
		// A header line with no "Name:" form is badly formed. Its parts
		// cannot be told apart, so all of it counts (fail closed).
		if name, _, found := strings.Cut(s, ":"); !found || !isName(name) {
			whole = true
		}
	}
	if whole {
		r.credentials = append(r.credentials, s)
	}
	if kind == pieceUser {
		// innerValues gives the text after each ":", which holds the
		// password in "admin:pw". It also gives the values of key=value
		// pairs: the whole text is a credential, so they count too.
		r.credentials = append(r.credentials, innerValues(s)...)
	}
	r.credentials = append(r.credentials, credentialParts(s)...)
}

// tokenLike reports whether s, or one of its words (the parts between
// spaces), looks like a token (see containsToken). A credential has no
// space, so a text with spaces is checked word by word: the length rule of
// LooksLikeCredential would else count every long sentence.
func tokenLike(s string) bool {
	return slices.ContainsFunc(strings.Fields(s), containsToken)
}

// isAuthScheme reports whether word is the scheme of an Authorization
// header ("Bearer", "Basic", "Token" and similar, in any case) or a
// secret-like name (see IsSecretName), such as "ApiKey". The credential
// after such a scheme is a credential. Any other word followed by a space is
// no scheme: "My" in "My Documents" is not.
func isAuthScheme(word string) bool {
	return isAuthSchemeWord(word) || IsSecretName(word)
}

// isAuthSchemeWord reports whether word is one of the usual HTTP auth
// schemes, in any case. Unlike isAuthScheme, it is false for other
// secret-like names, so a password such as "mykey" is not taken for a
// scheme.
func isAuthSchemeWord(word string) bool {
	// authSchemes are in lower case, so the match does not depend on case.
	authSchemes := [...]string{
		"basic", "bearer", "token", "digest", "negotiate", "ntlm", "dpop", "bot",
	}
	return slices.Contains(authSchemes[:], strings.ToLower(word))
}

// credentialParts returns the inner parts of s, a masked text, that look
// like a credential. They are the parts of headerLineParts and innerValues
// that pass these checks:
//
//   - the value after "Name:" when the name is secret-like (see
//     IsSecretName) or the value looks like a token (see tokenLike);
//   - the credential after a scheme when the scheme is an auth scheme (see
//     isAuthScheme) or the credential looks like a token;
//   - a value after a ":" when the text right before the ":" is a
//     secret-like name (a JSON key or a header name), or when the value
//     looks like a token. An auth scheme word there (see
//     isAuthSchemeWord) is no value: in "Authorization: Bearer x" the
//     credential is "x", not "Bearer";
//   - the value of a key=value piece when the key is secret-like or the
//     value looks like a token.
//
// So the plain words of a DSN ("host=localhost dbname=production") and a
// path segment with a space ("My Documents") give no part.
func credentialParts(s string) []string {
	var parts []string
	// The same cuts as headerLineParts.
	value := s
	if name, rest, found := strings.Cut(s, ":"); found && isName(name) {
		value = strings.TrimSpace(rest)
		if value != "" && (IsSecretName(name) || tokenLike(value)) {
			parts = append(parts, value)
		}
	}
	if scheme, rest, found := strings.Cut(value, " "); found && isName(scheme) {
		cred := strings.TrimSpace(rest)
		if cred != "" && !strings.ContainsAny(cred, " \t") && (isAuthScheme(scheme) || tokenLike(cred)) {
			parts = append(parts, cred)
		}
	}
	return append(parts, innerCredentials(s)...)
}

// innerCredentials returns the values of innerValues(s) that look like a
// credential (see credentialParts). It splits s in the same way as
// innerValues, and it also remembers the label of each ":": the piece right
// before it, with only quotes and spaces between.
func innerCredentials(s string) []string {
	var creds []string
	afterColon := false // a ":" came before the next piece
	last := ""          // the piece before the current separators, or ""
	label := ""         // the piece before the last ":", or ""
	start := 0          // index of the first byte of the current piece
	for i := 0; i <= len(s); i++ {
		if i < len(s) && strings.IndexByte(innerSeparators, s[i]) < 0 {
			continue
		}
		if piece := s[start:i]; piece != "" {
			if afterColon && !isAuthSchemeWord(piece) && (IsSecretName(label) || tokenLike(piece)) {
				creds = append(creds, piece)
			}
			if key, value, found := strings.Cut(piece, "="); found && value != "" && (IsSecretName(key) || tokenLike(value)) {
				creds = append(creds, value)
			}
			afterColon = false
			last = piece
		}
		if i < len(s) {
			switch s[i] {
			case ':':
				afterColon = true
				label, last = last, ""
			case '"', '\'', ' ', '\t', '\n', '\v', '\f', '\r':
				// Quotes and spaces can stand between a key, ":" and a value.
			default:
				afterColon = false
				last = ""
			}
		}
		start = i + 1
	}
	return creds
}

// keep does nothing unless r collects. Then it keeps s, the inner values of
// s as a header line or an auth value (see headerLineParts), and the values
// inside s as key=value pairs or JSON (see innerValues). It keeps nothing for
// an empty s: there is no secret to remove.
func (r *argScanner) keep(s string) {
	if !r.collect || s == "" {
		return
	}
	r.secrets = append(r.secrets, s)
	r.secrets = append(r.secrets, headerLineParts(s)...)
	r.secrets = append(r.secrets, innerValues(s)...)
}

// innerValues returns the values inside s, a text that RedactArgs masks
// whole, such as a connection string ("Server=h;Password=x"), libpq text
// ("host=h password=x"), a cookie line ("session=x; other=1") or JSON
// ({"token":"x"}). A server can echo such a value alone, so ArgSecrets
// returns it too.
//
// It splits s into pieces at each ";", "&", ",", ":", "{", "}", quote and
// space byte, and it returns, for each piece in order: the piece itself when
// a ":" comes before it with only quotes and spaces between (a JSON value or
// the text after "user:"), and the text after the first "=" of the piece (a
// value of key=value). Each value is not empty. It reads s one time, so the
// time is linear in the length of s.
//
// This is a fail-closed over-match: it can return ordinary words, such as a
// host name or "disable", and the caller then removes a word of 8 or more
// bytes from text that echoes it. The masked argument is not shown anyway,
// so only such an echo is changed, and no secret is shown.
func innerValues(s string) []string {
	var values []string
	afterColon := false // a ":" came before the next piece
	start := 0          // index of the first byte of the current piece
	for i := 0; i <= len(s); i++ {
		if i < len(s) && strings.IndexByte(innerSeparators, s[i]) < 0 {
			continue
		}
		if piece := s[start:i]; piece != "" {
			if afterColon {
				values = append(values, piece)
			}
			if _, value, found := strings.Cut(piece, "="); found && value != "" {
				values = append(values, value)
			}
			afterColon = false
		}
		if i < len(s) {
			switch s[i] {
			case ':':
				afterColon = true
			case '"', '\'', ' ', '\t', '\n', '\v', '\f', '\r':
				// Quotes and spaces can stand between ":" and a value.
			default:
				afterColon = false
			}
		}
		start = i + 1
	}
	return values
}

// innerSeparators are the bytes at which innerValues splits a masked text.
const innerSeparators = ";&,:{}\"' \t\n\v\f\r"

// headerLineParts returns the inner values of s, a masked text that can be a
// header line or an auth value: the value after "Name:", when the text
// before the first ":" is a name (see isName), and then the credential after
// an auth scheme, a name followed by a space. Each part is trimmed of spaces
// and is not empty. A credential has no space, so text such as "pid file
// $HOME" gives no credential part, and its words are not removed one by one.
// So "Authorization: Bearer x" gives "Bearer x" and "x", "X-Api-Key: v"
// gives "v", and "Bearer x" gives "x". It returns nil for other text.
func headerLineParts(s string) []string {
	var parts []string
	value := s
	if name, rest, found := strings.Cut(s, ":"); found && isName(name) {
		value = strings.TrimSpace(rest)
		if value != "" {
			parts = append(parts, value)
		}
	}
	if scheme, rest, found := strings.Cut(value, " "); found && isName(scheme) {
		if cred := strings.TrimSpace(rest); cred != "" && !strings.ContainsAny(cred, " \t") {
			parts = append(parts, cred)
		}
	}
	return parts
}

// scan returns the RedactArgs result for args, which is not nil.
func (r *argScanner) scan(args []string) []string {
	out := make([]string, len(args))
	// next is not pieceNone after a flag such as "--token" or "-H" with no
	// "=value", or a flag that is masked whole with no "=value": its value
	// is the next argument, and that value is masked as a piece of kind
	// next.
	next := pieceNone
	for i, arg := range args {
		// A new flag (see startsNewFlag) is not the value of the flag
		// before it, so a boolean flag such as "--no-auth" cannot use up the
		// mask that a following "--token" needs.
		if next != pieceNone && !startsNewFlag(arg) {
			// arg can be the value, so it is masked. arg can also be a flag
			// that masks its own value (Go-style "-token"), so if redactArg
			// would mask the next argument, mask it here too. A zero
			// argScanner gives that answer: the whole arg is masked, so its
			// parts are not kept on their own.
			var probe argScanner
			_, after := probe.redactArg(arg)
			out[i] = r.maskAs(arg, next)
			next = after
			continue
		}
		out[i], next = r.redactArg(arg)
	}
	return out
}

// redactArg redacts one argument that is not the value of the flag before
// it. shown is the text to display. next is not pieceNone if the next
// argument can be the value of arg and must be masked: arg is a flag such
// as "--token", or a flag that is masked whole, with no "=value". next then
// tells the kind of that value.
func (r *argScanner) redactArg(arg string) (shown string, next pieceKind) {
	name, value, hasValue, ok := parseFlag(arg)
	switch {
	case !ok && strings.HasPrefix(arg, "-") && arg != "-" && arg != "--":
		// "-uadmin:pw" or "-HX-Key:v": a value glued to a short flag, in a
		// shape that is not a flag name.
		shown := r.mask(arg)
		r.keepFlagBody(arg, pieceShape)
		return shown, pieceNone
	case !ok:
		return r.displayValue(arg), pieceNone
	case containsToken(name):
		// "-p" + token, a token that starts with "-", or a long secret-like
		// name such as "--s3-secret-access-key". The name looks like a
		// token, so the whole arg counts as a credential. With no "=value",
		// the next argument can be the value, so mask it too (fail closed).
		shown := r.maskAs(arg, pieceSecret)
		r.keepFlagBody(arg, pieceSecret)
		if hasValue {
			return shown, pieceNone
		}
		// The next argument is surely a value only after a secret-like
		// name. After a token glued to a flag ("-p" + token), it is more
		// often a new argument, so only a token there counts.
		if IsSecretName(name) {
			return shown, pieceSecret
		}
		return shown, pieceShape
	case !hasValue:
		// "--token": the value is the next argument.
		return arg, flagValueKind(name)
	}
	// "--name=value": keep everything up to and including "=".
	prefix := arg[:len(arg)-len(value)]
	if kind := flagValueKind(name); kind != pieceNone {
		return prefix + r.maskAs(value, kind), pieceNone
	}
	return prefix + r.displayValue(value), pieceNone
}

// keepFlagBody keeps the inner pieces of arg, an argument that starts with
// "-" and that redactArg masks whole, when r collects (see keepAs). A token
// can be glued to a flag ("-p" + token) or stand where the flag name goes
// ("--" + token), and a server can echo the token alone. The pieces are the
// body, the text after the dashes and before the first "=", and, for an
// argument with one dash and a body of two bytes or more, the body without
// its first byte: the text after a one-letter flag such as "-p".
//
// bodyKind is the kind of the body: pieceSecret when the flag name looks
// like a token, else pieceShape. The text after a one-letter flag is the
// value of that flag: a header line after "-H", a user and a password after
// "-u", and else a piece that counts only if it looks like a token.
func (r *argScanner) keepFlagBody(arg string, bodyKind pieceKind) {
	if !r.collect && !r.collectCredentials {
		return
	}
	body := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
	body, _, _ = strings.Cut(body, "=")
	r.keepAs(body, bodyKind)
	if !strings.HasPrefix(arg, "--") && len(body) > 1 {
		valueKind := pieceShape
		switch body[0] {
		case 'H':
			valueKind = pieceHeader
		case 'u':
			valueKind = pieceUser
		}
		r.keepAs(body[1:], valueKind)
	}
}

// flagValueKind returns the kind of the value of the flag called name, when
// that value is always masked: pieceHeader for a header flag, pieceUser for a
// user flag and pieceSecret for a secret-like flag. It returns pieceNone for
// any other flag.
func flagValueKind(name string) pieceKind {
	// "H" and "u" are compared as written: "-h" is usually help, and "-U"
	// is often a user name with no password (psql). The long flags match in
	// any case.
	switch {
	case name == "H" || strings.EqualFold(name, "header") || strings.EqualFold(name, "headers"):
		return pieceHeader
	case name == "u" || strings.EqualFold(name, "user"):
		return pieceUser
	case IsSecretName(name):
		return pieceSecret
	default:
		return pieceNone
	}
}

// startsNewFlag reports whether arg, which comes right after a flag whose
// value is masked, is a new flag and not that value. A flag "--name" or
// "--name=value" is a new flag. A single-dash argument ("-p", "-p=x",
// "-abc", "-token") can be a password, so only "-H" and "-u", with or
// without "=value", are new flags: they mask their own values, and a
// one-letter password is no secret. In every other case, a lone "-" and
// "--" included, arg is the value, and the caller masks it (fail closed).
func startsNewFlag(arg string) bool {
	name, _, _, ok := parseFlag(arg)
	return ok && (strings.HasPrefix(arg, "--") || name == "H" || name == "u")
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

// minPaddedTokenLen is the shortest NAME in "NAME=" or "NAME==" that
// displayValue masks as base64 text with "=" padding. Shorter names, such as
// "DEBUG=", are usually a variable with an empty value.
const minPaddedTokenLen = 16

// displayValue returns a value for display: rule 1 of the RedactArgs doc
// ("NAME=value"), then displayShape for the rest.
func (r *argScanner) displayValue(s string) string {
	name, value, found := strings.Cut(s, "=")
	if !found || !isName(name) {
		return r.displayShape(s)
	}
	if !isEnvName(name) {
		// The text before "=" can be a secret and not a name: base64 text
		// with "=" padding ("c2VjcmV0LXZhbHVlLTEyMzQ=") or a token followed
		// by "=x" ("ghp_abc=1"). Mask all of it, NAME included. A server can
		// echo the NAME alone, so when r collects, it keeps NAME too. Both
		// count as credentials: NAME looks like a token.
		if containsToken(name) || (strings.Trim(value, "=") == "" && len(name) >= minPaddedTokenLen) {
			shown := r.maskAs(s, pieceSecret)
			r.keepAs(name, pieceSecret)
			return shown
		}
	}
	if IsSecretName(name) {
		return name + "=" + r.maskAs(value, pieceSecret)
	}
	// displayShape, not displayValue: one level only. A URL value such as
	// "U=https://h/?a=1" goes through RedactURL. Other text with a second
	// "=" ("A=B=c") gives "A=" + Mask, because "=" is not a safe byte in a
	// segment.
	return name + "=" + r.displayShape(value)
}

// isEnvName reports whether name has the usual form of an environment
// variable name: an upper-case letter, then only upper-case letters, digits
// and "_", with at least one "_" ("GITHUB_TOKEN",
// "OTEL_EXPORTER_OTLP_ENDPOINT"). Base64 text of random bytes has lower-case
// letters, and base32 text has no "_", so such a name is not a padded token.
// displayValue shows it even when it is long.
func isEnvName(name string) bool {
	if name == "" || !isUpper(name[0]) || !strings.Contains(name, "_") {
		return false
	}
	for i := range len(name) {
		if !isUpper(name[i]) && !isDigit(name[i]) && name[i] != '_' {
			return false
		}
	}
	return true
}

// displayShape applies rules 2 to 4 of the RedactArgs doc to s: it shows s
// only if s has a safe shape, and returns Mask otherwise.
func (r *argScanner) displayShape(s string) string {
	switch {
	case s == "":
		return "" // nothing to hide, and Mask would look like a value
	case strings.Contains(s, "://") || strings.HasPrefix(s, "//"):
		return r.displayURL(s)
	case strings.Contains(s, ":") && strings.Contains(s, "@"):
		// "user:pass@host" or a DSN: the password has no fixed place. With
		// a ":" before the last "@", the text has the "user:password@" form,
		// so it counts as a credential. "git@host:org/repo" does not.
		kind := pieceShape
		if strings.IndexByte(s, ':') < strings.LastIndexByte(s, '@') {
			kind = pieceUser
		}
		return r.maskAs(s, kind)
	case hasSecretLabel(s):
		// "x-auth-token:abc" is a header line with no space after ":".
		return r.maskAs(s, pieceSecret)
	case !hasSafeColon(s) || !hasSafeAts(s):
		// "admin:pw", "scott/tiger@orcl": a ":" or "@" in a place that is
		// not on the list.
		return r.mask(s)
	default:
		return r.maskSegments(s)
	}
}

// displayURL returns RedactURL(s). When r collects, it keeps the parts of s
// that RedactURL masks (see maskedURLParts), or, when RedactURL masks s
// whole, all of s and then the best-effort parts of wholeURLParts. When r
// collects credentials, it keeps the credential parts of the same text (see
// keepURLCredentials).
func (r *argScanner) displayURL(s string) string {
	shown := RedactURL(s)
	if !r.collect && !r.collectCredentials {
		return shown
	}
	if shown == Mask {
		r.keepAs(s, pieceShape)
		for _, part := range wholeURLParts(s) {
			r.keep(part)
		}
		// The text from the first "//" on, as wholeURLParts reads it.
		if i := strings.Index(s, "//"); i >= 0 {
			r.keepURLCredentials(s[i:], true)
		}
		return Mask
	}
	for _, part := range maskedURLParts(s) {
		r.keep(part)
	}
	r.keepURLCredentials(s, false)
	return shown
}

// keepURLCredentials does nothing unless r collects credentials. Then it
// keeps the parts of raw that maskedURLParts returns and that are
// credentials (see ArgCredentials):
//
//   - the user info as written, the password and, by the rule of
//     IsSecretUserName, the name: always;
//   - a secret path segment or matrix parameter (see SecretPathSegments):
//     only when it looks like a token (see looksLikeEscapedCredential);
//   - a query part (see SecretQueryParts): a value when its key is
//     secret-like ("?api_key=x"), and any part that looks like a token;
//   - the fragment: only when it looks like a token.
//
// For each part, it also keeps the inner parts that credentialParts returns
// ("x" in a fragment "access_token=x"). fallback is true when raw is the
// text of a URL that RedactURL masks whole: when raw then does not parse,
// it keeps the user info and its parts, found as wholeURLParts finds them.
func (r *argScanner) keepURLCredentials(raw string, fallback bool) {
	if !r.collectCredentials {
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		if !fallback {
			return
		}
		info := RawUserinfo(raw)
		if info == "" {
			return
		}
		r.keepCredential(info, pieceSecret)
		name, password, _ := strings.Cut(info, ":")
		for _, part := range userinfoSecrets(name, password, name, password) {
			r.keepCredential(part, pieceSecret)
		}
		return
	}
	if u.User != nil {
		info := RawUserinfo(raw)
		r.keepCredential(info, pieceSecret)
		name, password, _ := strings.Cut(info, ":")
		plainPassword, _ := u.User.Password()
		for _, part := range userinfoSecrets(name, password, u.User.Username(), plainPassword) {
			r.keepCredential(part, pieceSecret)
		}
	}
	// The same loop as SecretPathSegments.
	for seg := range strings.SplitSeq(u.EscapedPath(), "/") {
		if seg == "" || redactPathSegment(seg) == seg {
			continue
		}
		r.keepEscapedCredential(seg, url.PathUnescape, false)
		if parts := strings.Split(seg, ";"); len(parts) > 1 {
			if isSecretPathSegment(parts[0]) {
				r.keepEscapedCredential(parts[0], url.PathUnescape, false)
			}
			for _, p := range parts[1:] {
				r.keepEscapedCredential(p, url.PathUnescape, false)
			}
		}
	}
	// The same loop as SecretQueryParts.
	isSep := func(c rune) bool { return c == '&' || c == ';' }
	for part := range strings.FieldsFuncSeq(u.RawQuery, isSep) {
		key, value, found := strings.Cut(part, "=")
		if !found {
			r.keepEscapedCredential(part, url.QueryUnescape, false)
			continue
		}
		if isSecretQueryKey(key) {
			r.keepEscapedCredential(key, url.QueryUnescape, false)
		}
		plainKey, err := url.QueryUnescape(key)
		if err != nil {
			plainKey = key
		}
		r.keepEscapedCredential(value, url.QueryUnescape, IsSecretName(plainKey))
	}
	if _, fragment, found := strings.Cut(raw, "#"); found {
		kind := pieceShape
		if looksLikeEscapedCredential(fragment, u.Fragment) {
			kind = pieceSecret
		}
		for _, form := range appendForms(nil, fragment, u.Fragment) {
			r.keepCredential(form, kind)
		}
	}
}

// keepEscapedCredential keeps the credential parts of s, an escaped part of
// a URL, and of its unescaped form when it differs (unescape is
// url.PathUnescape or url.QueryUnescape). Both forms are credentials when
// secret is true or when one of them looks like a token (see
// looksLikeEscapedCredential). Else only their inner parts can be (see
// keepCredential). It keeps nothing for an empty s.
func (r *argScanner) keepEscapedCredential(s string, unescape func(string) (string, error), secret bool) {
	if s == "" {
		return
	}
	plain, err := unescape(s)
	if err != nil {
		plain = "" // appendForms skips an empty form
	}
	kind := pieceShape
	if secret || looksLikeEscapedCredential(s, plain) {
		kind = pieceSecret
	}
	for _, form := range appendForms(nil, s, plain) {
		r.keepCredential(form, kind)
	}
}

// hasSecretLabel reports whether s has a ":" and the text before the first
// ":" is a secret-like name, as in "token:abc" or "X-Api-Key:abc".
func hasSecretLabel(s string) bool {
	label, _, found := strings.Cut(s, ":")
	return found && IsSecretName(label)
}

// hasSafeColon reports whether s has no ":", or exactly one ":" in a safe
// place: before a port ("localhost:8080", "127.0.0.1:3000") or after a
// Windows drive letter at the start ("C:", `C:\x`, "C:/x"). Any other ":"
// can split a user and a password ("admin:pw"), so it is not safe.
func hasSafeColon(s string) bool {
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
	return len(s) <= 5 && isNumber(s)
}

// isNumber reports whether s is one or more ASCII digits.
func isNumber(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// hasSafeAts reports whether every "@" in s is in a safe place: at the start
// of a path segment, as an npm scope ("@scope/pkg",
// "node_modules/@scope/pkg"), or as a version marker after a package name
// ("pkg@1.2.3", "@scope/pkg@latest"; see isPackageName and isVersion). Any
// other "@" can end a user and a password ("scott/tiger@orcl") or join a
// user and a host, so it is not safe.
func hasSafeAts(s string) bool {
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

// isVersion reports whether s is a package version after "@": a common npm
// dist-tag such as "latest", or a version with this form:
//
//	[v] NUMBER "." NUMBER ["." NUMBER]... ["-" LABEL] ["+" LABEL]
//
// NUMBER is one or more ASCII digits. LABEL is one or more ASCII letters,
// digits and ".". So "1.2.3", "v2.0.1-beta.1" and "1.0.0+build.5" are
// versions. A host name ("user@host"), a word that starts with a digit
// ("1tiger", "1password") and a number with no "." ("1234", "v2") are not:
// they can be a password.
func isVersion(s string) bool {
	// distTags are common npm dist-tags.
	distTags := [...]string{"latest", "next", "beta", "alpha", "canary"}
	if slices.Contains(distTags[:], s) {
		return true
	}
	rest, build, hasBuild := strings.Cut(s, "+")
	if hasBuild && !isVersionLabel(build) {
		return false
	}
	core, pre, hasPre := strings.Cut(rest, "-")
	if hasPre && !isVersionLabel(pre) {
		return false
	}
	numbers := strings.Split(strings.TrimPrefix(core, "v"), ".")
	if len(numbers) < 2 {
		return false
	}
	for _, n := range numbers {
		if !isNumber(n) {
			return false
		}
	}
	return true
}

// isVersionLabel reports whether s is a prerelease or build label of a
// version: one or more ASCII letters, digits and ".".
func isVersionLabel(s string) bool {
	return s != "" && onlyBytes(s, ".")
}

// maskSegments splits s at every "/" and "\", keeps the separators, and
// passes each segment through displaySegment. A path such as
// "/data/ghp_abc123/x" keeps its shape and loses only the token.
func (r *argScanner) maskSegments(s string) string {
	var b strings.Builder
	start := 0 // index of the first byte of the current segment
	for i := range len(s) {
		if s[i] == '/' || s[i] == '\\' {
			b.WriteString(r.displaySegment(s[start:i]))
			b.WriteByte(s[i])
			start = i + 1
		}
	}
	b.WriteString(r.displaySegment(s[start:]))
	return b.String()
}

// displaySegment returns seg if it is empty, or a plain word that does not
// look like a token (see containsToken), and Mask otherwise. A plain word
// has only ASCII letters, digits and "._:@+-~": enough for package names
// ("@scope", "pkg@1.2.3"), host:port, file names and "~". displayShape has
// already checked where ":" and "@" are. Every other byte (space, quote,
// brace, ";", ",", "=", "%", "*" and every non-ASCII byte) is a sign of a
// shape we do not know, so the segment is masked.
func (r *argScanner) displaySegment(seg string) string {
	if seg == "" || (onlyBytes(seg, "._:@+-~") && !containsToken(seg)) {
		return seg
	}
	return r.mask(seg)
}

// containsToken reports whether s looks like a token (see
// LooksLikeCredential), or whether one of its pieces starts with a known
// token prefix. The pieces are the parts of s between ".", "@", ":", "+" and
// "~", so a token after one of these bytes ("@ghp_abc", "x.sk-abc") is
// found too.
func containsToken(s string) bool {
	if LooksLikeCredential(s) {
		return true
	}
	pieces := strings.FieldsFunc(s, func(r rune) bool {
		return strings.ContainsRune(".@:+~", r)
	})
	return slices.ContainsFunc(pieces, HasTokenPrefix)
}

// IsSecretName reports whether name looks like the name of a credential.
// This function holds the full word list; the RedactArgs doc gives only
// examples.
//
// name is split into words (see nameWords), so "api-key", "API_KEY" and
// "apiKey" all give the words "api" and "key", in some case. It never prints
// or stores name. It is exported so that the redaction and the config checks
// (threat T4) agree on what looks like a credential name.
func IsSecretName(name string) bool {
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
	// A number at the end does not change the word: "--pass2", "DB_PW1" and
	// "REDIS_PASS1" are secret-like too.
	word = strings.TrimRight(word, "0123456789")
	if word == "" {
		return false
	}
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
