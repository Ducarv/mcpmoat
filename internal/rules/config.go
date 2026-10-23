package rules

import (
	"math"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Thresholds of the plaintext secret check (MOAT-T4-002).
const (
	// minNamedSecretLen is the shortest value that counts as a secret when
	// the key name looks like a credential name. A shorter value is more
	// likely a flag, a mode or a port than a real credential.
	minNamedSecretLen = 8

	// minEntropyLen is the shortest value that the entropy test looks at.
	// Short strings have a low entropy even when they are random.
	minEntropyLen = 24

	// minEntropy is the Shannon entropy, in bits per byte, from which a long
	// value looks random. Words stay below 4.0. Base64-like tokens of 24 bytes
	// or more pass it. Random hex usually does not: hex has at most 16
	// symbols, so its entropy is at most 4.0 bits per byte and it rarely
	// reaches the threshold. A hex secret is caught only by the token-prefix
	// or named-key rules (known limit). The test runs only on token-shaped
	// values (see isTokenShaped).
	minEntropy = 4.0

	// minPrefixedTokenLen is the shortest value that a token prefix alone
	// marks as a secret. The shortest real format, an AWS access key ID, has
	// 20 bytes. Shorter values such as the locale "sk_SK.UTF-8" share a prefix
	// by chance.
	minPrefixedTokenLen = 20
)

var (
	// varRef matches a client variable reference such as ${VAR} or
	// ${env:VAR}.
	varRef = regexp.MustCompile(`\$\{[^}]*\}`)

	// shellVar matches a value that is only a reference such as $VAR.
	shellVar = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`)

	// varPath matches a path that starts with a variable, such as
	// "$HOME/.config" or "%APPDATA%\key".
	varPath = regexp.MustCompile(`^(\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)[/\\]`)
)

// CheckConfig runs the static config checks of threat T4 on one server. It
// needs no connection, so it also runs with --no-connect.
//
// It runs on every server, whatever its State: a disabled server stays in the
// config file, so its plaintext secret or its plain http:// URL is still
// dangerous, and the user can enable the server later.
//
// s must be the server as the config file holds it, before discover.Expand:
// after the expansion a reference such as ${GITHUB_TOKEN} is a literal value,
// and the check would report it.
//
// The findings come in a fixed order: MOAT-T4-001, then MOAT-T4-002 (env keys,
// then header keys, each sorted), then MOAT-T4-003. A finding never holds a
// secret value or a URL (see Finding).
func CheckConfig(s discover.Server) []Finding {
	var findings []Finding
	findings = append(findings, checkInsecureURL(s)...)
	findings = append(findings, checkPlaintextSecrets(s)...)
	findings = append(findings, checkUnpinnedPackage(s)...)
	return findings
}

// checkInsecureURL reports MOAT-T4-001: a remote server that uses http://
// to a host that is not loopback. A variable reference is read as its
// default first (see refDefault), so "http://${HOST}:${PORT}/mcp" still
// fires: the scheme is known even when the host is not. A URL that does not
// parse gives no finding.
func checkInsecureURL(s discover.Server) []Finding {
	if !s.Transport.IsRemote() {
		return nil
	}
	u, err := url.Parse(varRef.ReplaceAllStringFunc(s.URL.Reveal(), refDefault))
	if err != nil {
		return nil
	}
	if !strings.EqualFold(u.Scheme, "http") || discover.IsLoopbackHost(u.Hostname()) {
		return nil
	}
	return []Finding{{
		RuleID:  RuleInsecureURL,
		Server:  s.Name,
		Field:   FieldURL,
		Message: insecureURLMessage,
	}}
}

// refDefault returns the default of a reference "${NAME:-default}", or "0"
// for a reference with no default. "0" is a valid host and port, and it is
// not loopback.
func refDefault(ref string) string {
	if _, def, found := strings.Cut(ref[2:len(ref)-1], ":-"); found {
		return def
	}
	return "0"
}

// checkPlaintextSecrets reports MOAT-T4-002 for every env and header entry
// that holds a secret in clear text. It never copies a value into a finding.
func checkPlaintextSecrets(s discover.Server) []Finding {
	var findings []Finding
	for _, key := range s.Env.Keys() {
		if looksLikePlaintextSecret(key, s.Env[key].Reveal()) {
			findings = append(findings, secretFinding(s.Name, FieldEnv, key))
		}
	}
	for _, key := range s.Headers.Keys() {
		value := stripAuthScheme(s.Headers[key].Reveal())
		if looksLikePlaintextSecret(key, value) {
			findings = append(findings, secretFinding(s.Name, FieldHeaders, key))
		}
	}
	return findings
}

// secretFinding builds the MOAT-T4-002 finding for one key.
func secretFinding(server, field, key string) Finding {
	return Finding{
		RuleID:  RulePlaintextSecret,
		Server:  server,
		Field:   field,
		Key:     key,
		Message: plaintextSecretMessage,
	}
}

// stripAuthScheme removes a leading "Bearer " or "Basic " (in any case) from
// a header value, so the check looks at the credential itself.
func stripAuthScheme(value string) string {
	for _, scheme := range []string{"Bearer ", "Basic "} {
		if len(value) >= len(scheme) && strings.EqualFold(value[:len(scheme)], scheme) {
			return strings.TrimSpace(value[len(scheme):])
		}
	}
	return value
}

// looksLikePlaintextSecret reports whether value, stored under key, looks
// like a secret written in clear text. It never prints, logs or returns value.
//
// The order of the tests matters:
//  1. An empty value is not a secret.
//  2. A known token prefix (such as "ghp_") on a value of at least
//     minPrefixedTokenLen bytes is a secret, even when the value also holds
//     "${" or looks like a path.
//  3. A reference (${VAR}, ${env:VAR}, or a whole value $VAR) is the safe
//     form. The ${...} references are removed, and the tests below look at
//     the literal text that is left, so "hunter2hunter2${X}" is still a
//     secret. Known limit: a literal default in ${VAR:-literal} is not
//     flagged.
//  4. A URL with a password in it ("postgres://user:pass@host/db") is a
//     secret.
//  5. Any other path or URL is not a secret. A path can start with a
//     variable ("$HOME/x", "%APPDATA%\x"). Known limit: an absolute path is
//     never a secret, so a random token that starts with "/" is a false
//     negative, under any key.
//  6. A credential-like key name with a value of at least minNamedSecretLen
//     bytes is a secret, unless the value is true, false or a number. Known
//     limits: an all-digit secret such as a numeric PIN is not flagged,
//     because numbers under such names are mostly settings ("SESSION_TTL");
//     and a non-secret word under a credential-like name
//     ("AUTH_STRATEGY=client_credentials") is flagged.
//  7. A long, random, token-shaped value is a secret, whatever its key.
func looksLikePlaintextSecret(key, value string) bool {
	if value == "" {
		return false
	}
	if len(value) >= minPrefixedTokenLen && discover.HasTokenPrefix(value) {
		return true
	}
	if shellVar.MatchString(value) {
		return false
	}
	if value = varRef.ReplaceAllString(value, ""); value == "" {
		return false
	}
	if hasURLPassword(value) {
		return true
	}
	if looksLikePathOrURL(value) {
		return false
	}
	if discover.IsSecretName(key) && len(value) >= minNamedSecretLen && !isFlagOrNumber(value) {
		return true
	}
	return isTokenShaped(value) && len(value) >= minEntropyLen && shannonEntropy(value) >= minEntropy
}

// hasURLPassword reports whether value is a URL with a non-empty password
// in its user info, such as "postgres://user:pass@host/db".
func hasURLPassword(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.User == nil {
		return false
	}
	password, ok := u.User.Password()
	return ok && password != ""
}

// looksLikePathOrURL reports whether value is a file path or a URL: an
// absolute path, a "~/", "./" or "../" path, a path that starts with a
// variable, a "file:" value (in any case), or any value with "://" in it.
func looksLikePathOrURL(value string) bool {
	if filepath.IsAbs(value) || strings.Contains(value, "://") || varPath.MatchString(value) {
		return true
	}
	if len(value) >= len("file:") && strings.EqualFold(value[:len("file:")], "file:") {
		return true
	}
	for _, prefix := range []string{"~/", "./", "../"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// isTokenShaped reports whether value has the shape of an opaque token: no
// white space and only the bytes A-Z, a-z, 0-9, + / = _ . ~ and -. Prose, a
// User-Agent string or a header list has spaces or other punctuation, so the
// entropy test skips it.
func isTokenShaped(value string) bool {
	for i := range len(value) {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case strings.IndexByte("+/=_.~-", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// isFlagOrNumber reports whether value is "true", "false" (any case) or a
// number. Such a value under a name like "AUTH_ENABLED" is a setting, not a
// secret.
func isFlagOrNumber(value string) bool {
	if strings.EqualFold(value, "true") || strings.EqualFold(value, "false") {
		return true
	}
	_, err := strconv.ParseFloat(value, 64)
	return err == nil
}

// shannonEntropy returns the Shannon entropy of s in bits per byte. It is 0
// for an empty string.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := range len(s) {
		counts[s[i]]++
	}
	total := float64(len(s))
	entropy := 0.0
	for _, n := range counts {
		if n == 0 {
			continue
		}
		p := float64(n) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// checkUnpinnedPackage reports MOAT-T4-003: a stdio server whose package
// runner fetches a package with no fixed version.
func checkUnpinnedPackage(s discover.Server) []Finding {
	if s.Transport != discover.TransportStdio {
		return nil
	}
	args := s.Args.Values()
	spec, ok := ExtractPackage(s.Command, args)
	if !ok || !spec.Unpinned() {
		return nil
	}
	// Related names the package only when the redaction policy for args shows
	// it as written, and masks no arg that holds it. If the policy masks such
	// an arg, the name may be a misparsed secret, so the finding keeps no
	// name: a name that is also visible in another arg would tell the reader
	// what the mask hides.
	shown, masked := false, false
	for i, redacted := range discover.RedactArgs(args) {
		if strings.Contains(args[i], spec.Name) {
			shown = shown || redacted == args[i]
			masked = masked || redacted != args[i]
		}
	}
	related := ""
	if shown && !masked {
		related = spec.Name
	}
	return []Finding{{
		RuleID:  RuleUnpinnedPackage,
		Server:  s.Name,
		Field:   FieldArgs,
		Related: related,
		Message: unpinnedPackageMessage,
	}}
}
