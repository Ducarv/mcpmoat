package rules

import (
	"math"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

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

	// wholeVar matches a value that is only a reference such as $VAR or the
	// Windows form %VAR%.
	wholeVar = regexp.MustCompile(`^` + shellOrWindowsVar + `$`)

	// varPath matches a path that starts with a variable, such as
	// "$HOME/.config" or "%APPDATA%\key".
	varPath = regexp.MustCompile(`^` + shellOrWindowsVar + `[/\\]`)
)

// shellOrWindowsVar matches a $VAR or %VAR% reference.
const shellOrWindowsVar = `(\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)`

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
// then header keys, each sorted), then MOAT-T4-003, then MOAT-T4-004. A finding
// never holds a secret value or a URL (see Finding).
func CheckConfig(s discover.Server) []Finding {
	var findings []Finding
	findings = append(findings, checkInsecureURL(s)...)
	findings = append(findings, checkPlaintextSecrets(s)...)
	findings = append(findings, checkUnpinnedPackage(s)...)
	findings = append(findings, checkAutoInstall(s)...)
	return findings
}

// checkInsecureURL reports MOAT-T4-001: a remote server that uses http://
// to a host that is not loopback. A variable reference is read as its
// default first (see refDefault), so "http://${HOST}:${PORT}/mcp" still
// fires: the scheme is known even when the host is not. Known limit: a
// loopback default, as in "http://${HOST:-localhost}/mcp", counts as
// loopback. That default is what runs unless the user's own environment sets
// the variable, and reporting it would flag every local dev server.
//
// The check fails closed. Clients parse URLs more loosely than Go (the WHATWG
// URL rules): they trim spaces and control characters, remove every tab and
// newline, and accept a bad escape such as "%zz", and they still connect. So
// the same trim and removal run first, and a URL that Go still cannot parse
// fires when it starts with "http://".
func checkInsecureURL(s discover.Server) []Finding {
	if !s.Transport.IsRemote() {
		return nil
	}
	raw := strings.TrimFunc(tabsAndNewlines.Replace(s.URL.Reveal()), func(r rune) bool { return r <= ' ' || r == 0x7f })
	resolved := varRef.ReplaceAllStringFunc(raw, refDefault)
	u, err := url.Parse(resolved)
	switch {
	case err != nil:
		if !hasPrefixFold(resolved, "http://") && !hasPrefixFold(raw, "http://") {
			return nil
		}
	case !strings.EqualFold(u.Scheme, "http") || discover.IsLoopbackHost(u.Hostname()):
		return nil
	}
	return []Finding{{
		RuleID:  RuleInsecureURL,
		Server:  s.Name,
		Field:   FieldURL,
		Message: insecureURLMessage,
	}}
}

// tabsAndNewlines removes every tab and newline, as WHATWG URL parsers do.
var tabsAndNewlines = strings.NewReplacer("\t", "", "\n", "", "\r", "")

// refDefault returns the default of a reference "${NAME:-default}", or "0"
// for a reference with no default. "0" is a valid host and port, and it is
// not loopback.
func refDefault(ref string) string {
	inner := strings.TrimSuffix(strings.TrimPrefix(ref, "${"), "}")
	if _, def, found := strings.Cut(inner, ":-"); found {
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
		if hasPrefixFold(value, scheme) {
			return strings.TrimSpace(value[len(scheme):])
		}
	}
	return value
}

// looksLikePlaintextSecret reports whether value, stored under key, looks
// like a secret written in clear text. It never prints, logs or returns value.
//
// The order of the tests matters:
//  1. An empty value, or a value that is only a reference ($VAR or %VAR%),
//     is not a secret.
//  2. The ${...} references (${VAR}, ${env:VAR}) are the safe form. They are
//     removed, and the tests below look at the literal text that is left, so
//     "hunter2hunter2${X}" is still a secret and "sk-${OPENAI_KEY}" is not.
//     Known limit: a literal default in ${VAR:-literal} is not flagged.
//  3. A known token prefix (such as "ghp_") on a literal of at least
//     minPrefixedTokenLen bytes is a secret, even when it looks like a path.
//  4. A URL with a password in it ("postgres://user:pass@host/db"), or with
//     a token as the user name ("https://ghp_...@github.com/x"), is a secret.
//  5. A key that names a path (it ends in "PATH", "FILE", "DIR",
//     "DIRECTORY" or "FOLDER", in any case) holds a path, and any other
//     path or URL is not a secret either. A path can start with a variable
//     ("$HOME/x", "%APPDATA%\x") or end in a file extension such as ".json"
//     or ".pem". Known limits: an absolute path is never a secret, so a
//     random token that starts with "/" is a false negative, under any key;
//     and a long relative path or ID with no extension, such as
//     "projects/my-project/locations/us-central1" or the model ID
//     "meta-llama/Llama-3.1-70B-Instruct", can pass the entropy test of
//     step 7.
//  6. A credential-like key name with a value of at least minNamedSecretLen
//     bytes is a secret, unless the value is true, false or a number. Known
//     limits: an all-digit secret such as a numeric PIN is not flagged,
//     because numbers under such names are mostly settings ("SESSION_TTL");
//     and a non-secret word under a credential-like name
//     ("AUTH_STRATEGY=client_credentials") is flagged.
//  7. A long, random, token-shaped value is a secret, whatever its key.
func looksLikePlaintextSecret(key, value string) bool {
	if value == "" || wholeVar.MatchString(value) {
		return false
	}
	if value = varRef.ReplaceAllString(value, ""); value == "" {
		return false
	}
	if len(value) >= minPrefixedTokenLen && discover.HasTokenPrefix(value) {
		return true
	}
	if hasURLCredential(value) {
		return true
	}
	if namesAPath(key) || looksLikePathOrURL(value) {
		return false
	}
	if discover.IsSecretName(key) && len(value) >= minNamedSecretLen && !isBoolOrNumber(value) {
		return true
	}
	return isTokenShaped(value) && len(value) >= minEntropyLen && shannonEntropy(value) >= minEntropy
}

// namesAPath reports whether key is the name of a path setting: its last
// word is "path", "file", "dir", "directory" or "folder", as in
// "PRIVATE_KEY_PATH", "token_file" or "keyFile". "AWS_PROFILE" does not count,
// because "file" is not a word of its own there.
func namesAPath(key string) bool {
	for _, suffix := range []string{"path", "file", "dir", "directory", "folder"} {
		start := len(key) - len(suffix) // index of the suffix in key
		if start < 0 || !strings.EqualFold(key[start:], suffix) {
			continue
		}
		if start == 0 || strings.ContainsRune("_-.", rune(key[start-1])) ||
			unicode.IsUpper(rune(key[start])) && unicode.IsLower(rune(key[start-1])) {
			return true
		}
	}
	return false
}

// hasURLCredential reports whether value is a URL with a non-empty password
// in its user info, such as "postgres://user:pass@host/db", or with a token
// as the user name, such as "https://ghp_...@github.com/x".
func hasURLCredential(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.User == nil {
		return false
	}
	if password, ok := u.User.Password(); ok && password != "" {
		return true
	}
	return discover.HasTokenPrefix(u.User.Username())
}

// pathExtensions are file extensions of key, certificate and config files.
// A value that ends in one of them is a file name, not a secret.
var pathExtensions = []string{
	".json", ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".jks",
	".txt", ".env", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
}

// looksLikePathOrURL reports whether value is a file path or a URL: an
// absolute path, a "~/", "./" or "../" path, a path that starts with a
// variable, a file name with a known extension (see pathExtensions), a
// "file:" value (in any case), or any value with "://" in it.
func looksLikePathOrURL(value string) bool {
	if filepath.IsAbs(value) || strings.Contains(value, "://") || varPath.MatchString(value) {
		return true
	}
	if hasPrefixFold(value, "file:") || slices.Contains(pathExtensions, strings.ToLower(filepath.Ext(value))) {
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

// isBoolOrNumber reports whether value is "true", "false" (any case) or a
// number. Such a value under a name like "AUTH_ENABLED" is a setting, not a
// secret.
func isBoolOrNumber(value string) bool {
	if strings.EqualFold(value, "true") || strings.EqualFold(value, "false") {
		return true
	}
	if strings.Contains(value, "_") {
		return false // ParseFloat accepts "1_000", which a setting does not use
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
	spec, at, ok := packageAt(s.Command, args)
	if !ok || !spec.Unpinned() {
		return nil
	}
	// Related names the package only when the redaction policy for args shows
	// the arg that holds the spec as written. If the policy masks it, the
	// name may be a misparsed secret, so the finding keeps no name.
	related := ""
	if discover.RedactArgs(args)[at] == args[at] {
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

// npmYesEnv is the environment name that turns on the yes option of npm.
const npmYesEnv = "npm_config_yes"

// checkAutoInstall reports MOAT-T4-004: a stdio server that turns on the yes
// option of npx.
//
// The yes option is on when a yes flag comes before the npx command (see
// walkNPXFlags and isYesFlag), or when an env entry named npm_config_yes, in
// any letter case, has a value that npm does not read as false (see
// npmFalse). The flag is checked first. A server gets one finding at most. A
// flag finding names FieldArgs. An env finding names FieldEnv and the env key
// name. A finding never holds a value.
//
// Why it matters: an MCP client starts npx with no terminal on stdin, so npx
// installs a missing package with no prompt anyway. The yes option is a
// problem because it overrides the npm_config_yes=false that internal/inspect
// sets in the scrubbed environment, so mcpmoat scan itself installs and runs
// the package. Removing the option does not make the client safe; pinning an
// exact version (MOAT-T4-003) or npx --no does.
//
// The package spec is not parsed. It does not need to be a valid npm name: a
// git URL, a tarball URL, a local path or an upper-case name counts too. The
// check needs only that npx has something to run: a positional argument, a -p
// or --package value, or a -c or --call value. npx with no argument installs
// nothing, so it gives no finding.
//
// Known limits:
//   - Only npx is covered. npm exec, npm x, bunx, pnpm dlx and yarn dlx are not.
//   - sh -c, env and a single-string cmd /c "..." wrapper are not unwrapped.
//   - npm config files are not read: a project .npmrc, or a file named by
//     --userconfig, --globalconfig, npm_config_userconfig or
//     npm_config_globalconfig, can set yes=true and is not seen.
func checkAutoInstall(s discover.Server) []Finding {
	if s.Transport != discover.TransportStdio {
		return nil
	}
	command, npxArgs, _ := runnerArgs(s.Command, s.Args.Values())
	if runnerOf(command) != RunnerNPX {
		return nil
	}
	yes, runs := walkNPXFlags(npxArgs)
	if !runs {
		return nil // npx has nothing to install or run
	}
	if yes {
		return []Finding{{
			RuleID:  RuleAutoInstall,
			Server:  s.Name,
			Field:   FieldArgs,
			Message: autoInstallMessage,
		}}
	}
	if key, found := yesEnvKey(s.Env); found {
		return []Finding{{
			RuleID:  RuleAutoInstall,
			Server:  s.Name,
			Field:   FieldEnv,
			Key:     key,
			Message: autoInstallMessage,
		}}
	}
	return nil
}

// yesEnvKey returns the name of an env entry that turns the npm yes option on,
// and true when there is one. The name matches in any letter case, as npm reads
// it. Any value that npm does not read as false counts as on: an empty value or
// "null" leaves the option unset, which still overrides the scan's
// npm_config_yes=false. The value is read only to compare it. It is never
// returned or copied.
func yesEnvKey(env discover.SecretMap) (string, bool) {
	for _, key := range env.Keys() {
		if strings.EqualFold(key, npmYesEnv) && !npmFalse(env[key].Reveal()) {
			return key, true
		}
	}
	return "", false
}
