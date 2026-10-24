package rules

import (
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// maxScanLen caps the length of one arg or one URL that the secret check
// reads. Both are untrusted text from a client config. A longer text is
// skipped (no finding), so a hostile config cannot cost parse time. It is
// above the size of the largest real tokens: a JWT with many claims can pass
// 2 KiB. Every test on a value is linear in its length.
const maxScanLen = 64 * 1024

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

	// minWordLen is the shortest part of a name that counts as a word, and
	// minNumberLen the shortest that counts as a number (see isWordLike). Random
	// base62 parts pass as a word at 22% (3 bytes), 9% (4), 4% (5), 0.3% (8). So
	// the rule also needs 2 separators and half of the parts. Measured recall
	// of random 32-byte base64url under --api-key: 98.3%.
	minWordLen   = 3
	minNumberLen = 2

	// maxOpaquePartLen is the length from which a part makes the whole value not
	// word-like, unless it is all digits, a camelCase name, or letters of one case
	// with an entropy under minOpaqueEntropy ("aaaaaaaaaaaaaaaaaaaaaaaa"). A long
	// run like that is
	// a secret body, not a readable name. A hostile config can still split a
	// random value into pieces shorter than this: a documented limit.
	//
	// minOpaqueEntropy was set by measurement. Random lowercase letters have an
	// entropy of 3.25 (1% quantile) and 3.68 (median) at 20 bytes, 3.39 and 3.84
	// at 24, 3.66 and 4.05 at 32. Real words of 20 bytes or more are in
	// 2.9 to 3.6: "internationalization" 2.95. At 3.2 about 99% of random 20-byte
	// parts are found (100% from 24 bytes), and the longest common words stay
	// words. A higher limit, 3.5, would miss 15% of random 20-byte parts.
	maxOpaquePartLen = 20
	minOpaqueEntropy = 3.2

	// refMark stands in for a variable reference without a default while a URL
	// is split. It is a NUL byte, so no text of a config can hold it as a real
	// value (urlHasSecret drops NUL bytes first). literalPart removes it again.
	refMark = "\x00"

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

	// innermostRef matches a reference that holds no other reference.
	innermostRef = regexp.MustCompile(`\$\{[^{}]*\}`)

	// refWithDefault matches one whole reference that has a default, such as
	// ${NAME:-default} or ${NAME-default} (also := and =, and an "env:" prefix).
	// Group 1 is the default. A reference like ${NAME}, ${NAME:?msg} or
	// ${input:my-id} has no default and does not match.
	refWithDefault = regexp.MustCompile(`^\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*(?::-|:=|-|=)(.*)\}$`)
)

// checkArgSecrets reports MOAT-T4-002 for a literal secret in the command
// args of a stdio server or in the URL of a remote server. It gives at most
// one finding: with Field FieldArgs for a stdio server, or with Field FieldURL
// for a remote server. The finding holds no Key and no value, arg or URL. A URL
// inside the args of a stdio server gives FieldArgs.
//
// The check favours precision: a finding can fail a CI run. A credential-like
// flag or NAME needs a value that looks like a token (see tokenForName). A
// plain word under such a name is not reported, except under a name that ends
// in a password word. See argsHaveSecret and urlHasSecret for the exact shapes.
//
// Like CheckConfig, it needs s as the config file holds it, before
// discover.Expand.
func checkArgSecrets(s discover.Server) []Finding {
	if s.Transport.IsRemote() {
		if urlHasSecret(s.URL.Reveal()) {
			return []Finding{secretFinding(s.Name, FieldURL, "")}
		}
		return nil
	}
	// Any transport that is not remote is read as stdio, also an unknown one: a
	// secret in the args is worth a finding even if the transport is not set.
	if argsHaveSecret(s.Args.Values()) {
		return []Finding{secretFinding(s.Name, FieldArgs, "")}
	}
	return nil
}

// argsHaveSecret reports whether one of the args holds a literal secret:
//   - a secret flag with a token-like value, as "--api-key VALUE" or
//     "--api-key=VALUE";
//   - a NAME=value arg (also the value after -e or --env) with a
//     credential-like NAME and a token-like value;
//   - the value of a header flag ("-H", "--header", "--headers"), a
//     "Name: value" text (see headerEntryHasSecret);
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
// "--env=NAME=value". For a header flag it also reads the value as a header:
// "-H 'Name: value'", "--header=Name:value" and "-HName: value".
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

	// "-HName: value": curl lets the header flag and its value touch.
	if !strings.HasPrefix(arg, "--") && len(trimmed) > 1 && trimmed[0] == 'H' && headerEntryHasSecret(trimmed[1:]) {
		return true
	}

	header := isHeaderFlag(arg, name)
	if hasValue {
		if (name == "e" || name == "env") && assignmentHasSecret(value) {
			return true
		}
		return namedValueHasSecret(name, value) || urlValueHasSecret(value) ||
			(header && headerEntryHasSecret(value))
	}

	// "--flag value": the value is the next arg. A next arg that starts with
	// "-" is another flag, so this flag has no value.
	if next == "" || strings.HasPrefix(next, "-") || len(next) > maxScanLen {
		return false
	}
	return namedValueHasSecret(name, next) || (header && headerEntryHasSecret(next))
}

// isHeaderFlag reports whether the flag called name sends an HTTP header, as
// "-H" (compared as written: "-h" is usually help) and "--header" or
// "--headers" (any case). discover.RedactArgs masks the value of the same flags.
func isHeaderFlag(arg, name string) bool {
	if strings.HasPrefix(arg, "--") {
		return strings.EqualFold(name, "header") || strings.EqualFold(name, "headers")
	}
	return name == "H"
}

// headerEntryHasSecret checks the value of a header flag, a "Name: value"
// text such as "Authorization: Bearer <token>". The credential is the last
// word of the value, so a scheme word ("Bearer", "Basic", "Negotiate") is
// skipped. The credential then gets the rule of the other args (see
// namedValueHasSecret), not the looser rule of the headers map: a header flag
// is free text, and a reference such as "session=${SESSION}" leaves letters
// that must not count.
func headerEntryHasSecret(entry string) bool {
	name, value, found := strings.Cut(entry, ":")
	name = strings.TrimSpace(name)
	words := strings.Fields(value)
	if !found || name == "" || len(words) == 0 {
		return false
	}
	last := words[len(words)-1]
	// A Basic credential is "user:password" in base64, so any literal value of
	// minNamedSecretLen bytes or more is a secret, as for a password. Only the
	// authorization headers take this scheme.
	if len(words) >= 2 && strings.EqualFold(words[len(words)-2], "Basic") &&
		(strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization")) {
		return len(literalPart(last)) >= minNamedSecretLen
	}
	return namedValueHasSecret(name, last)
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
//  1. A value that is only a reference ($VAR or %VAR%) is not a secret, and
//     ${...} references are expanded (see literalPart). Unlike
//     looksLikePlaintextSecret, the default of ${NAME:-default} is kept and
//     scanned, because a client uses it when NAME is not set. A leading
//     "Bearer " or "Basic " is dropped (see stripAuthScheme). A value with
//     nothing literal left is not a secret.
//  2. A well-known token (see bareToken) is a secret, under any name.
//  3. A name of a path setting ("--key-file"), or a value that is a path or
//     a URL, is not a secret. A URL value in an arg goes through urlHasSecret
//     (see urlValueHasSecret). Known limit: a URL inside a query value is not
//     read again.
//  4. A credential-like name needs a token-like value (see tokenForName). For
//     a query value, the caller tests several forms of the value (see
//     valueForms).
func namedValueHasSecret(name, value string) bool {
	value = stripAuthScheme(literalPart(value))
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
// literal secret. A reference with no default becomes placeholder. A default
// can hold another reference, so each pass replaces the innermost references
// (the ones with no "${" or "}" inside), from the inside out, at most
// maxRefPasses times. So "${A:-${B}text}" gives "text".
func expandRefs(value, placeholder string) string {
	for range maxRefPasses {
		if !strings.Contains(value, "${") {
			break
		}
		value = innermostRef.ReplaceAllStringFunc(value, func(ref string) string {
			if m := refWithDefault.FindStringSubmatch(ref); m != nil {
				return m[1]
			}
			return placeholder
		})
	}
	// Deeper nesting than maxRefPasses is not read: a reference that is left is
	// not literal text. A default at that depth is not scanned (known limit).
	return varRef.ReplaceAllString(value, placeholder)
}

// tokenForName reports whether value is token-like enough to count as a secret
// under a credential-like name. It is stricter than looksLikePlaintextSecret
// on purpose: a plain word such as "my-secret-name" under "--secret-name" is a
// name, not a secret.
//
// A value has at least minNamedSecretLen bytes, is not a boolean or a number,
// and is a secret on one of these routes:
//  1. A name that ends in a password word (see endsInPasswordWord): any such
//     value, as in the env check. People choose passwords, so they do not look
//     random. The last word decides, so "--password-stdin" does not count, and
//     a name that starts with a negation or a prompt word ("--no-password")
//     is a switch, not a password.
//  2. A UUID: only when name holds "key", "token", "secret" or "pass" (this
//     covers "password" and "passwd"). A session or auth ID is often a UUID, so
//     a name that is credential-like for another reason ("--session-id") does
//     not count, and neither does a name that ends in "id" ("--key-id"). A
//     UUID gets no other route.
//  3. A token prefix (see discover.HasTokenPrefix), unless the value is made
//     of words ("sk-learn-tokenizer").
//  4. A random look (see looksRandom).
//  5. Pure hex of at least minHexLen digits ("--api-key" with an MD5 or SHA
//     hex digest), unless the name ends in "id". Known limit: a public hash
//     under a name with "key" in it ("--cache-key") is reported too.
//  6. A long random look (see looksLongRandom).
//
// Routes 5 and 6 live here and not in bareToken: a bare arg or a URL path
// segment has no credential-like name to back it, so it keeps the strict rule
// (a commit id or a hash in a path is not a secret).
func tokenForName(name, value string) bool {
	if len(value) < minNamedSecretLen || isBoolOrNumber(value) {
		return false
	}
	if endsInPasswordWord(name) {
		return true
	}
	if namesAClientID(name) {
		return false // an OAuth client ID is public
	}
	// A name that ends in "id" ("--key-id", "keyId") holds an identifier, and a
	// UUID or a hex digest there is a public ID, not a secret.
	if endsInIDWord(name) && (uuidText.MatchString(value) || isHex(value)) {
		return false
	}
	if uuidText.MatchString(value) {
		return nameHoldsSecretWord(name)
	}
	return (discover.HasTokenPrefix(value) && !isWordLike(value)) ||
		looksRandom(value) ||
		isHexString(value, minHexLen) ||
		looksLongRandom(value)
}

// endsInIDWord reports whether the last word of name is "id" or "ids", in any
// case, or name ends in camelCase "Id" or "ID" after a lower-case letter
// ("keyId", "clientID"). So "ANDROID" does not count.
func endsInIDWord(name string) bool {
	words := strings.FieldsFunc(name, isNameSeparator)
	if len(words) == 0 {
		return false
	}
	last := words[len(words)-1]
	if strings.EqualFold(last, "id") || strings.EqualFold(last, "ids") {
		return true
	}
	if n := len(last); n > 2 && (strings.HasSuffix(last, "Id") || strings.HasSuffix(last, "ID")) {
		return last[n-3] >= 'a' && last[n-3] <= 'z'
	}
	return false
}

// namesAClientID reports whether name ends in an ID word and holds the word
// "client": an OAuth client ID is public, whatever its look.
func namesAClientID(name string) bool {
	return endsInIDWord(name) && strings.Contains(strings.ToLower(name), "client")
}

// passwordWords are the last words of a name that takes a password.
var passwordWords = []string{"password", "passwd", "passphrase"}

// switchWords are the first words of a name that make a password name a
// switch: "--no-password", "--ask-password" and "--prompt-password" take no
// password, and the arg after them is something else. Known limit: a switch
// with a plain name, such as "psql --password", cannot be told from a flag that
// takes a password. "enable" is not in the list, because "--enable-password"
// is usually a device password.
var switchWords = []string{"no", "skip", "ask", "prompt", "disable", "show", "hide", "without"}

// endsInPasswordWord reports whether name, in any case, ends in "password",
// "passwd" or "passphrase": "--password", "--db-password", "DB_PASSWORD". It
// is false when the first word of name is in switchWords. "pwd" is not in the
// list, because "--pwd" is usually the working directory.
func endsInPasswordWord(name string) bool {
	lower := strings.ToLower(name)
	if first := strings.FieldsFunc(lower, isNameSeparator); len(first) > 0 && slices.Contains(switchWords, first[0]) {
		return false
	}
	for _, word := range passwordWords {
		if strings.HasSuffix(lower, word) {
			// "nopassword" and "noPassword" have no separator: the switch word is
			// glued to the password word.
			return !slices.Contains(switchWords, strings.TrimSuffix(lower, word))
		}
	}
	return false
}

// secretNameWords are the words that make nameHoldsSecretWord true. "pass" also
// covers "password" and "passwd".
var secretNameWords = []string{"key", "token", "secret", "pass"}

// nameHoldsSecretWord reports whether name, in any case, contains "key",
// "token", "secret" or "pass". The text "pass" also covers "password" and
// "passwd". The match is on the text and not on whole words, so "apikey" and
// "X-Api-Key" count.
func nameHoldsSecretWord(name string) bool {
	lower := strings.ToLower(name)
	for _, word := range secretNameWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// isHex reports whether s has only hex digits (0-9, a-f, A-F).
func isHex(s string) bool {
	for i := range len(s) {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// isHexString reports whether s has at least minLen bytes and only hex digits.
func isHexString(s string, minLen int) bool {
	return len(s) >= minLen && isHex(s)
}

// looksLongRandom reports whether value is a token-shaped text of at least
// minLongRandomLen bytes that holds a letter and a digit and has an entropy of
// at least minLongEntropy and is not word-like (a resource path, a camelCase
// name). It catches a random value that looksRandom misses
// because the entropy of a sample of 20 to 23 bytes is below minDigitEntropy.
func looksLongRandom(value string) bool {
	if len(value) < minLongRandomLen || !isTokenShaped(value) {
		return false
	}
	hasLetter := strings.ContainsFunc(value, unicode.IsLetter)
	hasDigit := strings.ContainsFunc(value, unicode.IsDigit)
	// Two or more of "-", "_" and "." mean a name made of words
	// ("my-prod-secret-store-v2"), not a random token.
	return hasLetter && hasDigit && countRunes(value, isNameSeparator) < 2 &&
		shannonEntropy(value) >= minLongEntropy && !isWordLike(value)
}

// isWordLike reports whether value is a name made of words and numbers, such
// as "production-session-2024-01" or "Document_Final_Version_2024_Q3_Report",
// and not a random token. A file extension is cut first. Then value must have
// 2 or more of "-", "_" and ".", and at least half of its counted parts (the
// text between the separators) must be words or numbers (see isWordPart). A
// random token has short parts of mixed letters and digits, so it fails. A
// value with 1 separator ("ghp_<36 random>", "sk-<30 random>") never passes.
// A part of maxOpaquePartLen or more bytes makes value not word-like at once,
// so a prefix or a padding of words does not hide a random body
// ("sk_live_<24 random>", "aaa-bbb-<24 random>"). Three kinds of long part are
// spared: digits only (a number), letters of one case with an entropy under
// minOpaqueEntropy (a word), and a camelCase name (see isCamelName). So
// one-case random letters are still caught.
//
// A "/" also separates words here ("projects/my-proj/secrets/token/versions/1"
// is a resource path, not a token), and a value made of Capitalized words
// ("GithubTokenStorage2024") is a name (see isCamelName). A value with a "/"
// and only one break is word-like when all its counted parts are words.
func isWordLike(value string) bool {
	// A file extension is not a word of the name: ".tar.gz" after a hash must
	// not add a word and a separator (see trimFileExt).
	value = trimFileExt(value)
	if isCamelName(value) {
		return true
	}
	counted, words := 0, 0
	for _, part := range strings.FieldsFunc(value, isWordBreak) {
		switch {
		case isNumberPart(part):
			counted++
			words++
		case isOpaquePart(part):
			return false // a long opaque run is a secret body, not a name
		case isWordPart(part):
			counted++
			words++
		case len(part) >= minWordLen:
			counted++ // long and not a word: it counts against
		}
		// A short part ("my", "v2", "q3", "1") decides nothing: not counted.
	}
	// Two breaks are enough. One "/" is too, when every counted part is a word:
	// "prod/ProductionDatabaseCredentials2024" is a path, and no random token
	// splits into words at its "/".
	breaks := countRunes(value, isWordBreak)
	onlyWords := strings.Contains(value, "/") && words == counted
	return (breaks >= 2 || onlyWords) && counted >= 2 && words*2 >= counted
}

// shortCamelWords are the two-letter words that a camelCase name can hold.
var shortCamelWords = []string{
	"My", "Db", "Ai", "Ui", "Ux", "Io", "Id", "Os", "Ip", "Js", "Ml", "Qa", "Ci", "Cd", "Vm",
	"Of", "To", "In", "On", "Is", "As", "At", "By", "Or", "No", "Go",
}

// isOpaquePart reports whether part is a long run that looks like the body of a
// secret and not a name: it has maxOpaquePartLen bytes or more, it is not a
// camelCase name, and it is not a word, or it is a word with an entropy of at
// least minOpaqueEntropy (one-case random letters).
func isOpaquePart(part string) bool {
	if len(part) < maxOpaquePartLen || isCamelName(part) {
		return false
	}
	return !isWordPart(part) || shannonEntropy(part) >= minOpaqueEntropy
}

// isWordBreak reports whether r ends a word of a name: a name separator or "/".
// Only isWordLike uses it. The tests for a random token (looksLongRandom) keep
// to isNameSeparator, because a base64 secret can hold "/".
func isWordBreak(r rune) bool {
	return isNameSeparator(r) || r == '/'
}

// isNameSeparator reports whether r separates the words of a name.
func isNameSeparator(r rune) bool {
	return r == '-' || r == '_' || r == '.'
}

// countRunes returns how many runes of s satisfy keep.
func countRunes(s string, keep func(rune) bool) int {
	n := 0
	for _, r := range s {
		if keep(r) {
			n++
		}
	}
	return n
}

// isNumberPart reports whether part is a number: minNumberLen or more digits.
func isNumberPart(part string) bool {
	return len(part) >= minNumberLen && strings.Trim(part, "0123456789") == ""
}

// isCamelName reports whether s is a name in camelCase or PascalCase, such as
// "GithubTokenStorage2024", "keyRings", "ProdDbCredentialsV2",
// "MySQLRootPassword2024" or "OAuthClientSecretProd1". It is made of words that
// start with a capital (the first one may be lower case), acronym runs of
// capitals ("SQL", "API") and digits. A Capitalized word has three letters or
// more, except the two-letter words in shortCamelWords ("Db", "Ai", "My"). It
// needs at least two such words, and few short items (a short word, an acronym
// run or a lone capital): at most half the long words plus one. So a fake token
// such as "Zq8Lm3Vx0Rt5" (words of two letters) and a random token are not
// names: random letters give a Capitalized word of three letters or more only
// one time in four, and a lower-case letter after a digit ends the check.
func isCamelName(s string) bool {
	isUpper := func(c byte) bool { return c >= 'A' && c <= 'Z' }
	isLower := func(c byte) bool { return c >= 'a' && c <= 'z' }
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }

	longWords, shortItems := 0, 0 // words of three or more letters, and the rest
	for i := 0; i < len(s); {
		j := i + 1
		switch c := s[i]; {
		case isDigit(c):
			for j < len(s) && isDigit(s[j]) {
				j++
			}
		case isUpper(c) && j < len(s) && isLower(s[j]):
			// A Capitalized word: "Credentials".
			for j < len(s) && isLower(s[j]) {
				j++
			}
			switch {
			case j-i >= minWordLen:
				longWords++
			case slices.Contains(shortCamelWords, s[i:j]):
				shortItems++
			default:
				return false // "Zq", "Lm": two letters that are not a known word
			}
		case isUpper(c) && strings.HasPrefix(s[i:], "OAuth"):
			j = i + len("OAuth") // "OAuth" is a word, but not a Capitalized one
			longWords++
		case isUpper(c):
			// An acronym run: "SQL" in "MySQLRoot", or a lone capital before a
			// digit or the end: "V2". The last capital of a run starts the next
			// word when a lower-case letter follows the run.
			for j < len(s) && isUpper(s[j]) {
				j++
			}
			run := j - i
			if j < len(s) && isLower(s[j]) && run > 1 {
				j--
			}
			if run > 1 && j-i == 1 {
				return false // a lone capital before a Capitalized word: "QZkj"
			}
			shortItems++
		case isLower(c) && i == 0:
			// A lower-case first word: "key" in "keyRings".
			for j < len(s) && isLower(s[j]) {
				j++
			}
			if j-i >= minWordLen {
				longWords++
			} else {
				shortItems++
			}
		default:
			return false // a separator, a symbol, or a lower-case letter after a digit
		}
		i = j
	}
	return longWords >= 2 && shortItems <= longWords/2+1
}

// isWordPart reports whether part is a word (minWordLen or more ASCII letters
// in one case, with an optional capital first), a camelCase name (see
// isCamelName) or a number (minNumberLen or more digits). A number is also
// checked first by isWordLike, which counts it on its own.
func isWordPart(part string) bool {
	if isNumberPart(part) || isCamelName(part) {
		return true
	}
	if len(part) < minWordLen {
		return false
	}
	// Skip a capital first letter ("Document"), then all letters must be of the
	// same case as the second one.
	rest := part
	if part[0] >= 'A' && part[0] <= 'Z' {
		rest = part[1:]
	}
	lower := rest[0] >= 'a' && rest[0] <= 'z'
	for i := range len(rest) {
		c := rest[i]
		if lower && (c < 'a' || c > 'z') {
			return false
		}
		if !lower && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// looksRandom reports whether value has the shape of a random token: only
// token bytes (see isTokenShaped), not word-like (see isWordLike), and one of
// two things:
//   - at least minRandomLen bytes, a digit and an entropy of at least
//     minDigitEntropy;
//   - at least minEntropyLen bytes and an entropy of at least minEntropy.
//
// A short value with a digit ("my_key_1", "ctrl+shift+1", "2024-10-01") is a
// setting, not a token. Known limit: a random value of under minRandomLen bytes
// is not found.
func looksRandom(value string) bool {
	if len(value) < minRandomLen || !isTokenShaped(value) || isWordLike(value) {
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
	if len(value) < minPrefixedTokenLen || !discover.HasTokenPrefix(value) {
		return false
	}
	// "eyJ" is the base64 of `{"`. A JWT has three dot-separated parts, but a
	// base64 JSON config ("?config=eyJkZWJ1ZyI6ZmFsc2V9") has none.
	if hasPrefixFold(value, "eyj") && strings.Count(value, ".") < 2 {
		return false
	}
	return !looksLikePathOrURL(value) && looksRandom(value)
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
//     (see valueForms). The fragment is read the same way;
//   - a password in the user info ("user:password@host"), or a token as the
//     user name ("https://ghp_...@host");
//   - a path segment that is a well-known token (see bareToken) or a long
//     random string (see randomPathSegment). A file extension is cut first and
//     a 32, 40 or 64 digit hex segment (a hash or a commit id) does not count.
//
// A UUID segment, a readable segment such as "mcp" or "sse", and a query such
// as "?page=2" are not secrets. Known limit: a long random resource ID in a
// path, such as a Google Sheets ID, looks like a token and is reported. The
// check reads the URL the way clients do: it removes tabs and newlines and
// trims control characters first (see cleanClientURL).
//
// The URL is cut by splitURL, not by url.Parse. url.Parse fails on input that
// clients accept (a "%" in a password, a bad escape, a bad port, an empty host
// after a reference), and a check that gives up there would hide a secret.
func urlHasSecret(raw string) bool {
	if len(raw) > maxScanLen {
		return false
	}
	cleaned := cleanClientURL(raw)
	// A default is kept (it is scanned). A reference with no default becomes
	// refMark, so "?token=${TOKEN}" has no literal value and "${HOST}" is still
	// a host. NUL bytes are dropped first, so the mark cannot come from the input.
	cleaned = expandRefs(strings.ReplaceAll(cleaned, refMark, ""), refMark)
	parts := splitURL(cleaned)
	// A client does not send the fragment, but a secret in it is still in the
	// file. It is read like a query ("#access_token=...").
	return userInfoHasSecret(parts.userInfo) || queryHasSecret(parts.query) ||
		queryHasSecret(parts.fragment) || pathHasSecret(parts.path)
}

// urlParts holds the raw pieces of a URL that urlHasSecret checks.
type urlParts struct {
	userInfo string // text before the last "@" of the authority, or ""
	path     string // from the first "/" of the rest up to "?" or "#"
	query    string // text after "?" up to "#"
	fragment string // text after the first "#"
}

// splitURL cuts raw into its pieces by hand. It has no error result, so no
// input text can reach an error message.
//
// The scheme ends at "://". The authority runs up to the first "/", "?" or
// "#". The user info is the part of the authority before its last "@".
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
	rest, parts.fragment, _ = strings.Cut(rest, "#")
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
//     secret holds "+" and a client may send it as it is (left out when it is
//     the same text);
//   - each of these with its "%" bytes removed, when one is left. A "%" that
//     stays after decoding is a stray or a bad escape ("?token=<random>%"),
//     and it would make the token shape test fail and hide the secret. A form
//     that is a whole reference ("%NAME%") is not stripped: without its "%"
//     marks it would look like a plain value.
func valueForms(rawValue string) []string {
	// A raw "%NAME%" is a reference. Decoded first, "%DB_PASSWORD%" would read
	// "%DB" as an escape and no longer be a reference.
	if wholeVar.MatchString(rawValue) {
		return nil
	}
	queryForm := lenientUnescape(rawValue, true)
	pathForm := lenientUnescape(rawValue, false)
	forms := []string{queryForm}
	if pathForm != queryForm {
		forms = append(forms, pathForm)
	}
	decoded := slices.Clone(forms)
	for _, form := range decoded {
		if strings.Contains(form, "%") && !wholeVar.MatchString(form) {
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
		!isWordLike(segment) &&
		shannonEntropy(segment) >= minEntropy
}

// md5HexLen and sha256HexLen are the lengths of a hex MD5 and SHA-256 digest.
// A SHA-1 digest has fullSHALen digits.
const (
	md5HexLen    = minHexLen
	sha256HexLen = 64
)

// hashHexLens are the lengths of a hex MD5, SHA-1 and SHA-256 digest.
var hashHexLens = []int{md5HexLen, fullSHALen, sha256HexLen}

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
	if slices.Contains(hashHexLens, len(segment)) && isHex(segment) {
		return false
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
		if !isASCIIAlnum(rune(ext[i])) {
			return segment
		}
	}
	return strings.TrimSuffix(strings.TrimSuffix(segment, ext), ".tar")
}
