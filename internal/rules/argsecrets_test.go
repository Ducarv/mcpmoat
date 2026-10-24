package rules

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Synthetic values for the arg and URL secret tests. None of them is a real
// credential. A provider prefix is joined from two parts, so that a secret
// scanner does not take the source line for a leaked token.
const (
	// asBody has 40 distinct-looking mixed-case characters and digits. Its
	// entropy is above minEntropy at every length used here.
	asBody = "Zq7Xw2Lm9Vb4Nc8Kd3Rt6Yh1Jg5Fs0PaE7uI2oB"

	// testRandom32 has 32 distinct characters: 5 bits of entropy per byte.

	asHost = "mcp.example.com"

	// Fixed pseudo-random fakes for the credential-name routes. Each was picked
	// from a seeded generator and checked: the hex and base62 values miss
	// looksRandom, so only the new routes of tokenForName find them.
	asUUID  = "550e8400-e29b-41d4-a716-446655440000"
	asHex32 = "9fdd8712c201540b1cf6d97f119f1359"
	asHex40 = "30ae9f8b4759af2599402d145b1f15b782e7bcd5"
	asHex64 = "1C9F10BB6BB99F459EBDD9F88EFAF6B19A20936059F7EB39A1891939A8210ACA" // upper case
	asB20   = "6zDChErZjcP06r96j0Fu"
	asB21   = "iU1N2si8lKQlSlHSNg1Co"
	asB22   = "vy4vhJJLp6Nr33xrmJm97N"
	asB23   = "PBHPNk1LBoNUJKSK41k4bF1"
	asB28   = "oDNCPMT9VndWCl8n02AC5iv4JGCm"
	asPlus  = "vsvT2C0wxsk5g790n+PjtuFvmV" // a base64-like value with a literal "+"
	asPath  = "z0utDg56HZdnSBfbDboar9IBlSGYJSGi"
	asB16   = "o2fT20k0Yiud4JFj" // 16 bytes, entropy 3.75: below minDigitEntropy

	// Random base64url values with "-" or "_" inside. None is word-like (see
	// TestIsWordLike), so the separator guard of isWordLike must not hide them.
	asU24a = "u8jzPde0IgxLd6Gn-fBAepfJ"         // 24 bytes, 1 separator
	asU24b = "0Kh8oOOL-dKL-docJ2isAjIh"         // 24 bytes, 2 separators
	asU32a = "xgJTeKdNnFRIB_uDL7DxtpYlSXpfKtHF" // 32 bytes, 1 separator
	asU32b = "sMehG_kWvj7-Ac9QeWJKY40uvSwMFLZD" // 32 bytes, 2 separators
	asU32c = "dUStP_R0CsTy4Qwb8D-kNhFdnXsiVpzz" // 32 bytes, 2 separators

	// Hash-named archive segments. Each hex text, with its extension, reached
	// the entropy limit of the plain randomSegment rule (checked by
	// TestCheckArgSecretsArchiveHashes).
	asZipHex    = "453c56a1f927031fe5cb3376d37fbe837e7fc02f"
	asZipHex2   = "abb692acc530de61664d7538ac85a78822863e81"
	asZipHex3   = "a1460b5b55ac0cdcfa89e270dabc573ac66f7e25"
	asTarGzHex  = "fde7c1a159fce1cf698d0fa64323039a8c1d6a35"
	asTarGzHex2 = "ae5b115d78c84947cd4d002de0a6bf8762708617"
	asTgzHex    = "fde8962b650a50b31d24459dc73009d2ca87ebee"
	asWhlHex    = "02b6f71c8893554f0027162916df7a609a940d1e"
	asSha256Hex = "d4be08f8eebd68fbda75710f6c636f93aa8667e7e08196de85aadc3a9e65be19"
	asMD5Hex    = "35190c48ddaa9fa97dc061313ce26608"

	// Uniform hex: every digit appears the same number of times, so the entropy
	// is exactly 4.0 (minEntropy) and the plain rule flags it even without an
	// extension. Only the hash rule of randomPathSegment keeps it out.
	asUniMD5 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	asUniSHA = asUniMD5 + asUniMD5

	// Fake bodies for the prefixed and padded secret rows. Each has distinct
	// letters and digits, picked from a seeded generator, so its entropy is high
	// at every length used here. None is word-like and none is a real token.
	asT22  = "JTeKdNnFRIBXuDLWxtpl1f"
	asT24  = "u8jzPde0IgxL4GncfBA3pTJS"
	asT24b = "z63FfkC9JriB10TAwRyoj5lP"
	asT30  = "d0KhoO4L972z15cJisAjI68tUlgmxZ"
	asT32  = "oQ9aF1Llqs6jAIxNKuiGUdDJz3TMgEWb"
	asT59  = "KtHF4vUCsMehGAk5j6WcZJ9u3wSDPfrpNLQbxIT01ozmlayXB8RYqd7OEgi"

	// Random-looking bodies of one letter case, 24 distinct letters each (entropy
	// 4.58, far above minOpaqueEntropy). They hold no digit, so only the long-part
	// rule of isWordLike keeps a word prefix from hiding them. asL20 is the first
	// 20 bytes of asL24 (in the var block). None is a real token.
	asL24 = "qkzvbnhtrewlpdmsxcyjfguo"

	// Two 10-digit numbers for the Slack-style token.
	asDig1 = "2082410719"
	asDig2 = "9675202046"
)

var (
	asGH     = "gh" + "p_" + asBody[:36]                               // a GitHub-style token
	asSK     = "sk" + "-" + asBody[:30]                                // an OpenAI-style key
	asL20    = asL24[:20]                                              // 20 letters, one case
	asU24L   = strings.ToUpper(asL24)                                  // the same body in upper case
	asRand24 = asBody[:24]                                             // a random 24-byte value
	asNames  = []string{"GITHUB_PERSONAL_ACCESS_TOKEN", "DB_PASSWORD"} // env names

	// Prefixed tokens with 2 or more separators. Each prefix is joined from
	// parts, so that a secret scanner does not take the source line for a leak.
	asStripe   = "sk_" + "live_" + asT24                             // 2 separators
	asStripeRK = "rk_" + "live_" + asT30                             // 2 separators
	asSlack    = "xox" + "b-" + asDig1 + "-" + asDig2 + "-" + asT24b // 3 separators
	asGHPat    = "github_" + "pat_" + asT22 + "_" + asT59            // 3 separators
	asPrefixed = []string{asStripe, asStripeRK, asSlack, asGHPat}
)

// argServer builds a stdio server with the given args.
func argServer(args ...string) discover.Server {
	return stdioServer("docker", args...)
}

// assertOnlyField fails the test unless findings is exactly one MOAT-T4-002
// finding on field, with an empty Key and Related.
func assertOnlyField(t *testing.T, findings []Finding, field string) {
	t.Helper()
	want := []Finding{secretFinding("srv", field, "")}
	if !reflect.DeepEqual(findings, want) {
		t.Errorf("findings = %+v, want exactly %+v", findings, want)
	}
}

func TestCheckArgSecretsArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want bool
	}{
		// Positive: a literal secret in the args.
		{"env flag with a named token", []string{"run", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN=" + asGH, "img"}, true},
		{"api-key flag, value in the next arg", []string{"--api-key", asRand24}, true},
		{"token flag with equals", []string{"--token=" + asGH}, true},
		{"long env flag with equals", []string{"--env=API_KEY=" + asSK}, true},
		{"short env flag, value attached", []string{"-eAPI_KEY=" + asSK}, true},
		{"bare ghp token", []string{"serve", asGH}, true},
		{"bare NAME=value with a credential name", []string{"DB_PASSWORD=" + asRand24}, true},
		{"literal default holds a secret", []string{"--token=${X:-" + asGH + "}"}, true},
		{"token default after a flag", []string{"--token", "${X:-" + asGH + "}"}, true},
		{"token mixed with a reference", []string{"--token=${X}" + asGH}, true},
		{"flag value is a URL with a password", []string{"--url=https://user:pw@example.com/sse"}, true},
		{"NAME=URL with a token in the query", []string{"SERVER_URL=https://example.com/x?token=" + asRand24}, true},
		{"bare URL with a token as user", []string{"https://" + asGH + "@example.com/x"}, true},
		{"secret after clean args", []string{"-y", "pkg@1.0.0", "--port", "8080", "--password", asRand24}, true},
		{"oversize arg does not hide a later secret", []string{strings.Repeat("a", maxScanLen+1), "--token=" + asGH}, true},

		{"15 distinct bytes is not found", []string{"--api-key", testRandom32[:15]}, false},
		{"16 distinct bytes with digits is found", []string{"--api-key", testRandom32[:16]}, true},
		{"20 distinct bytes with digits is found", []string{"--api-key", testRandom32[:20]}, true},
		{"low entropy value with a digit", []string{"--api-key", "aaaaaaaabbbbbbbb1"}, false},
		{"readable value with a digit", []string{"--api-key", "my-service-name-1"}, false},
		{"next arg is a flag with a long random name", []string{"--token", "--" + asRand24}, false},
		{"prefix alone under a credential name", []string{"--api-key", "sk-abc12345"}, true},
		{"prefix of 20 bytes is a bare token", []string{"gh" + "p_" + testRandom32[:16]}, true},
		{"prefix of 19 bytes is not a bare token", []string{"gh" + "p_" + testRandom32[:15]}, false},
		{"locale with a token prefix", []string{"sk_SK.UTF-8"}, false},
		{"credential URL with two at signs", []string{"--url=https://a@b:pw@example.com/sse"}, true},
		{"percent-encoded key", []string{"--url=https://h/mcp?to%6Ben=" + asRand24}, true},
		{"flag value is a URL with a trailing space", []string{"--url=https://h/mcp?api_key=" + asRand24 + " "}, true},

		// Positive: hex and UUID values and long random values under a
		// credential name (tokenForName routes 1, 4 and 5).
		{"api-key flag with 32 hex", []string{"--api-key", asHex32}, true},
		{"api-key equals with 40 hex", []string{"--api-key=" + asHex40}, true},
		{"api-key flag with 64 upper-case hex", []string{"--api-key", asHex64}, true},
		{"token query with 32 hex in a URL arg", []string{"--url=https://h/mcp?token=" + asHex32}, true},
		{"api-key flag with a UUID", []string{"--api-key", asUUID}, true},
		{"client-secret equals with a UUID", []string{"--client-secret=" + asUUID}, true},
		{"password flag with a UUID", []string{"--password", asUUID}, true},

		// A name that ends in a password word takes any value of 8 bytes or more.
		{"password flag with a plain word", []string{"--password", "hunter2hunter2"}, true},
		{"password flag with equals and symbols", []string{"--password=S3cure!Pass#2024"}, true},
		{"db-password flag with a phrase", []string{"--db-password", "correct-horse-battery-staple"}, true},
		{"passphrase flag", []string{"--passphrase=correcthorse"}, true},
		{"password env name with a plain word", []string{"-e", "DB_PASSWORD=hunter2hunter2", "img"}, true},

		// A header flag holds "Name: value". The value is checked like a header
		// entry of the headers map.
		{"header flag with a bearer token", []string{"mcp-remote", "https://h/sse", "--header", "Authorization: Bearer " + asRand24}, true},
		{"header flag with a prefixed token", []string{"--header", "Authorization: Bearer " + asGH}, true},
		{"header flag, no space after the colon", []string{"--header", "Authorization:Bearer " + asRand24}, true},
		{"header flag with equals", []string{"--header=X-Api-Key: " + asRand24}, true},
		{"headers flag", []string{"--HEADERS", "X-Api-Key: " + asRand24}, true},
		{"short -H flag", []string{"-H", "X-Api-Key: " + asRand24}, true},
		{"header flag with a literal default", []string{"--header", "Authorization: Bearer ${API_TOKEN:-" + asRand24 + "}"}, true},
		{"api-key with random base62 of 20", []string{"--api-key", asB20}, true},
		{"api-key with random base62 of 21", []string{"--api-key", asB21}, true},
		{"api-key with random base62 of 22", []string{"--api-key", asB22}, true},
		{"api-key with random base62 of 23", []string{"--api-key", asB23}, true},

		// Negative: a UUID needs key, token, secret or pass in the name; a hash or
		// a name made of words is not a secret.
		{"session-id with a UUID", []string{"--session-id", asUUID}, false},
		{"auth-id with a UUID", []string{"--auth-id", asUUID}, false},
		{"bare 40 hex arg", []string{asHex40}, false},
		{"bare UUID arg", []string{asUUID}, false},
		{"key-name made of words (separator rule)", []string{"--key-name", "my-prod-secret-store-v2"}, false},
		{"limit: random 16 bytes under the entropy limit is not found", []string{"--api-key", asB16}, false},

		// A password word must be the last word of the name, and the value must
		// be 8 bytes or more and not a reference, a boolean or a number.
		{"password-stdin takes a registry", []string{"--password-stdin", "registry.example.com"}, false},
		{"password-prompt takes a mode", []string{"--password-prompt", "interactive"}, false},
		{"short password is not found", []string{"--password", "short"}, false},
		{"password reference", []string{"--password", "${DB_PASSWORD}"}, false},
		{"password flag with a number", []string{"--password", "12345678"}, false},
		{"password-file takes a path", []string{"--password-file", "secrets.txt"}, false},

		// Negative: header flags.
		{"header flag with a reference", []string{"--header", "Authorization: Bearer ${API_TOKEN}"}, false},
		{"header flag with a plain header", []string{"--header", "Accept: application/json"}, false},
		{"header flag without a colon", []string{"--header", "justtext" + asRand24}, false},
		{"-h is help, not a header flag", []string{"-h", "Authorization: Bearer " + asRand24}, false},

		// Positive: random base64url with "-" or "_" inside is not word-like.
		{"api-key with base64url 24, one separator", []string{"--api-key", asU24a}, true},
		{"api-key with base64url 24, two separators", []string{"--api-key", asU24b}, true},
		{"api-key with base64url 32, one separator", []string{"--api-key", asU32a}, true},
		{"api-key with base64url 32, two separators", []string{"--api-key", asU32b}, true},
		{"api-key equals with base64url 32", []string{"--api-key=" + asU32c}, true},
		{"api-key query in a URL arg, base64url 24", []string{"--url=https://h/mcp?api_key=" + asU24b}, true},
		{"base64url 32 path segment in a URL arg", []string{"https://h/mcp/" + asU32b}, true},

		// Negative: a name made of words and numbers under a credential-like
		// name (the word-like guard).
		{"session name with words and numbers", []string{"--session-name", "production-session-2024-01"}, false},
		{"auth flow name", []string{"--auth", "oauth2-client-credentials-flow"}, false},
		{"chrome profile name", []string{"--session", "chrome-profile-2024-user-1"}, false},
		{"signing key name", []string{"--key-name", "production-signing-key-2024"}, false},

		// Negative: a value that is only a %VAR% reference, even one that looks
		// like a random token inside the marks.
		{"api-key with a long %VAR%", []string{"--api-key", "%ANTHROPIC_API_KEY_PRODUCTION%"}, false},
		{"api-key with a %VAR% that holds digits", []string{"--api-key", "%AZURE_OPENAI_KEY_2024_PROD%"}, false},
		{"api-key with a %VAR% that looks random", []string{"--api-key", "%Q1w2E3r4T5y6U7i8O9p0Zx%"}, false},
		{"api-key equals with a %VAR%", []string{"--api-key=%AZURE_OPENAI_KEY_2024_PROD%"}, false},

		// Negative: the hash in an archive URL is a pin, not a secret.
		{"uvx from a .zip archive of a commit", []string{"--from=https://github.com/u/r/archive/" + asZipHex + ".zip", "tool"}, false},
		{"uvx from a .tar.gz archive of a commit", []string{"--from=https://github.com/u/r/archive/" + asTarGzHex + ".tar.gz", "tool"}, false},
		{"uvx from a .tgz archive of a commit", []string{"--from=https://github.com/u/r/archive/" + asTgzHex + ".tgz", "tool"}, false},
		{"uvx from a .whl file named by a hash", []string{"--from=https://github.com/u/r/archive/" + asWhlHex + ".whl", "tool"}, false},
		{"bare archive URL arg", []string{"https://github.com/u/r/archive/" + asZipHex2 + ".zip"}, false},

		// Negative: no value, only a reference, a path or a setting.
		{"env flag with a name only", []string{"-e", "GITHUB_TOKEN"}, false},
		{"NAME=reference", []string{"-e", "NAME=${VAR}"}, false},
		{"token flag with a reference", []string{"--token", "${GITHUB_TOKEN}"}, false},
		{"api-key flag with $VAR", []string{"--api-key", "$VAR"}, false},
		{"api-key flag with %VAR%", []string{"--api-key", "%API_KEY%"}, false},
		{"token flag as the last arg", []string{"--token"}, false},
		{"token flag followed by a flag", []string{"--token", "--verbose"}, false},
		{"key file path", []string{"--key-file", "/path/to/key"}, false},
		{"max tokens number", []string{"--max-tokens", "4096"}, false},
		{"max tokens long number", []string{"--max-tokens", "4096000000"}, false},
		{"plain setting", []string{"LOG_LEVEL=debug"}, false},
		{"secret name is a plain word", []string{"--secret-name", "my-secret-name"}, false},
		{"registry URL", []string{"--registry", "https://registry.invalid/"}, false},
		{"bare registry URL", []string{"https://registry.invalid/"}, false},
		{"default is empty", []string{"--token=${X:-}"}, false},
		{"default is a short word", []string{"--token=${X:-abc}"}, false},
		{"default is another reference", []string{"--token=${X:-${Y}}"}, false},
		{"no args", nil, false},
		{"empty arg", []string{""}, false},
		{"only a dash", []string{"-"}, false},

		// Negative: the false-positive corpus (S4).
		{"tokenizer name", []string{"--tokenizer", "cl100k_base"}, false},
		{"key name", []string{"--key-name", "my_key_1"}, false},
		{"auth provider", []string{"--auth-provider", "google-oauth2"}, false},
		{"private network", []string{"--private-network", "10.0.0.0/8"}, false},
		{"hotkey", []string{"--hotkey", "ctrl+shift+1"}, false},
		{"key version date", []string{"--key-version", "2024-10-01"}, false},
		{"session name", []string{"--session-name", "my-session-1"}, false},
		{"keyboard layout", []string{"--keyboard-layout", "us-intl-2"}, false},
		{"author", []string{"--author", "john.doe1"}, false},
		{"monkey", []string{"--monkey", "banana12"}, false},
		{"oauth scope", []string{"--oauth-scope", "read_user_1"}, false},
		{"package that starts with xox", []string{"xoxo-mcp-server-v2-latest"}, false},
		{"package that starts with sk-", []string{"sk-learn-mcp-server-v2"}, false},
		{"flag value package that starts with sk-", []string{"--package", "sk-learn-mcp-server-v2"}, false},

		// Documented accepted loss: a random value under 16 bytes.
		{"short otp value", []string{"--otp", "abcdef123456"}, false},

		// Oversize input is skipped.
		{"oversize arg", []string{strings.Repeat("a", maxScanLen+1)}, false},
		{"oversize token arg", []string{"gh" + "p_" + strings.Repeat(asBody, 60)}, false},
		{"oversize flag value", []string{"--token", "gh" + "p_" + strings.Repeat(asBody, 60)}, false},
		{"oversize flag with equals", []string{"--token=" + strings.Repeat(asBody, 60)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := checkArgSecrets(argServer(tt.args...))
			if !tt.want {
				if len(got) != 0 {
					t.Errorf("checkArgSecrets(%q) = %+v, want no finding", tt.args, got)
				}
				return
			}
			assertOnlyField(t, got, FieldArgs)
		})
	}
}

func TestCheckArgSecretsURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
		want bool
	}{
		// Positive.
		{"api_key query", "https://" + asHost + "/mcp?api_key=" + asRand24, true},
		{"token query", "https://" + asHost + "/mcp?token=" + asGH, true},
		{"token after another pair", "https://" + asHost + "/mcp?page=2&token=" + asGH, true},
		{"percent-encoded key name", "https://" + asHost + "/mcp?api%5Fkey=" + asGH, true},
		{"user and password", "https://user:pw@" + asHost + "/mcp", true},
		{"token as user", "https://" + asGH + "@" + asHost + "/mcp", true},
		{"random 32-byte path segment", "https://" + asHost + "/mcp/" + testRandom32, true},
		{"token path segment", "https://" + asHost + "/mcp/" + asGH, true},
		{"reference in host (S1)", "https://${HOST}/mcp?api_key=" + asGH, true},
		{"bad escape in path (S1)", "https://h/%zz/" + asGH, true},
		{"bad escape in the secret value", "https://h/mcp?token=" + asGH + "%zz", true},
		{"bad escape in password", "https://user:p%ss@h/x", true},
		{"token in the fragment", "https://" + asHost + "/sse#access_token=" + asRand24, true},
		{"token in the fragment after another pair", "https://" + asHost + "/sse#state=1&token=" + asGH, true},
		{"password query with a plain word and a stray percent", "https://h/mcp?password=hunter2%x", true},
		{"password query with a plain word", "https://h/mcp?password=hunter2hunter2", true},
		{"user info that holds the old reference marker text", "https://u:refx0@h/sse", true},
		{"bad port", "https://h:abc/mcp?token=" + asGH, true},
		{"reference as scheme", "${SCHEME}://h/mcp?token=" + asGH, true},
		{"literal default in query (S2)", "https://h/mcp?api_key=${K:-" + asGH + "}", true},
		{"nested default", "https://h/mcp?api_key=${K:-${J:-" + asGH + "}}", true},
		{"tab inside the token", "https://h/mcp?token=" + asGH[:10] + "\t" + asGH[10:], true},
		{"leading space", "  https://h/mcp?token=" + asGH, true},
		{"random user name", "https://" + testRandom32 + "@" + asHost + "/mcp", true},
		{"two at signs in the authority", "https://a@b:pw@h/mcp", true},
		{"percent-encoded key name hides the word", "https://h/mcp?to%6Ben=" + asRand24, true},
		{"tab inside a random value", "https://h/mcp?api_key=" + asRand24[:10] + "\t" + asRand24[10:], true},
		{"newline inside a random value", "https://h/mcp?api_key=" + asRand24[:10] + "\n" + asRand24[10:], true},
		{"trailing space", "https://h/mcp?api_key=" + asRand24 + " ", true},
		{"random value before the fragment", "https://h/mcp?api_key=" + asRand24 + "#frag", true},
		{"secret before the fragment", "https://h/mcp?token=" + asGH + "#frag", true},
		{"secret in an http URL", "http://h/mcp?token=" + asGH, true},
		{"token query with 32 hex", "https://h/mcp?token=" + asHex32, true},
		{"api_key query with a UUID", "https://h/mcp?api_key=" + asUUID, true},
		{"random 32-char path segment", "https://h/mcp/" + asPath, true},
		{"random 32-char path segment with .zip", "https://h/mcp/" + asPath + ".zip", true},
		{"random 32-char path segment with .tar.gz", "https://h/mcp/" + asPath + ".tar.gz", true},
		{"literal plus in a base64-like query value", "https://h.invalid/mcp?api_key=" + asPlus, true},
		{"%2B form of the same query value", "https://h.invalid/mcp?api_key=" + strings.Replace(asPlus, "+", "%2B", 1), true},
		{"stray percent after the value", "https://h/mcp?token=" + asB28 + "%", true},
		{"stray percent before the value", "https://h/mcp?token=%" + asB28, true},
		{"bad escape after the value", "https://h/mcp?token=" + asB28 + "%zz", true},
		{"base64url 24 with one separator in a query", "https://h/mcp?api_key=" + asU24a, true},
		{"base64url 24 with two separators in a query", "https://h/mcp?api_key=" + asU24b, true},
		{"base64url 32 with one separator in a query", "https://h/mcp?api_key=" + asU32a, true},
		{"base64url 32 with two separators in a query", "https://h/mcp?api_key=" + asU32b, true},
		{"base64url 32 path segment, one separator", "https://h/mcp/" + asU32a, true},
		{"base64url 32 path segment, two separators", "https://h/mcp/" + asU32b, true},
		{"base64url 32 path segment, other value", "https://h/mcp/" + asU32c, true},
		{"base64url 32 path segment with .zip", "https://h/mcp/" + asU32c + ".zip", true},

		// Negative: a %VAR% reference is not a literal value, in any form.
		{"api_key query with a long %VAR%", "https://h/mcp?api_key=%ANTHROPIC_API_KEY_PRODUCTION%", false},
		{"api_key query with a %VAR% that holds digits", "https://h/mcp?api_key=%AZURE_OPENAI_KEY_2024_PROD%", false},
		{"api_key query with a %VAR% that looks random", "https://h/mcp?api_key=%Q1w2E3r4T5y6U7i8O9p0Zx%", false},
		{"api_key query with an encoded %VAR%", "https://h/mcp?api_key=%25AZURE_OPENAI_KEY_2024_PROD%25", false},

		// Negative.
		{"page query", "https://" + asHost + "/mcp?page=2", false},
		{"readable path", "https://" + asHost + "/mcp/v1/sse", false},
		{"UUID path with many distinct digits", "https://" + asHost + "/mcp/0a1b2c3d-4e5f-6789-abcd-ef0123456789", false},
		{"UUID path", "https://" + asHost + "/mcp/123e4567-e89b-12d3-a456-426614174000", false},
		{"token reference", "https://h/mcp?token=${T}", false},
		{"password reference", "https://u:${PW}@h/mcp", false},
		{"empty default", "https://h/mcp?token=${T:-}", false},
		{"short default", "https://h/mcp?token=${T:-abc}", false},
		{"reference default", "https://h/mcp?token=${T:-${U}}", false},
		{"port reference", "https://h:${PORT}/mcp", false},
		{"host reference", "https://${HOST}/mcp", false},
		{"short token value", "https://h/mcp?token=abc", false},
		{"numeric token value", "https://h/mcp?token=123456789012", false},
		{"fragment only", "https://h/mcp#" + asGH, false},
		{"user without password", "https://user@h/mcp", false},
		{"empty URL", "", false},
		{"oversize URL", "https://h/mcp?token=" + strings.Repeat(asBody, 60), false},
		{"session query with a UUID", "https://h/mcp?session=" + asUUID, false},
		{"hex32 path segment", "https://h/mcp/" + asHex32, false},
		{"UUID path segment under a longer path", "https://h/mcp/v1/" + asUUID + "/sse", false},
		{"remote .tar.gz archive of a commit", "https://github.com/u/r/archive/" + asTarGzHex2 + ".tar.gz", false},
		{"sha256 .tar.gz archive", "https://h/dl/" + asSha256Hex + ".tar.gz", false},
		{"md5 .zip archive", "https://h/dl/" + asMD5Hex + ".zip", false},
		{"uniform md5 path segment", "https://h/dl/" + asUniMD5, false},
		{"uniform sha256 path segment", "https://h/dl/" + asUniSHA, false},
		{"limit: password under 8 bytes is not found", "https://h/mcp?password=hunter2", false},
		{"plain fragment", "https://h/docs#section-2", false},
		{"fragment with a reference", "https://h/sse#access_token=${TOKEN}", false},
		{"page query with a stray percent", "https://h/mcp?page=2%", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, tr := range []discover.Transport{discover.TransportHTTP, discover.TransportSSE} {
				got := checkArgSecrets(remoteServer(tr, tt.url))
				if !tt.want {
					if len(got) != 0 {
						t.Errorf("checkArgSecrets(%s, %q) = %+v, want no finding", tr, tt.url, got)
					}
					continue
				}
				assertOnlyField(t, got, FieldURL)
			}
		})
	}
}

// TestCheckArgSecretsWordURLs runs URLs with a readable long name in the path
// on a remote server and as a URL arg of a stdio server (bare, and after
// "--url="). None holds a secret. The positive rows show that the same shapes
// with a random base64url value are found in all three places.
func TestCheckArgSecretsWordURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"words in the last segment", "https://h/the-quick-brown-fox-jumps-over-the-lazy-dog", false},
		{"words in an organization segment", "https://h/api/v1/organizations/abcdef-ghijkl-mnopqr-stuvwx", false},
		{"project name with a number and hex-like tail", "https://h/v1/projects/my-project-1234567890abcdef/mcp", false},
		{"report file name", "https://h/files/Document_Final_Version_2024_Q3_Report.pdf", false},
		{"branch archive name", "https://h/org/repo/archive/refs/heads/feature-branch-name-long-1234.zip", false},
		{"api_key query with %VAR%", "https://h/mcp?api_key=%ANTHROPIC_API_KEY_PRODUCTION%", false},
		{"api_key query with an encoded %VAR%", "https://h/mcp?api_key=%25AZURE_OPENAI_KEY_2024_PROD%25", false},

		{"base64url 32 path segment", "https://h/mcp/" + asU32b, true},
		{"base64url 32 path segment after a name", "https://h/v1/projects/" + asU32a + "/mcp", true},
		{"base64url 24 api_key query", "https://h/mcp?api_key=" + asU24b, true},
		{"base64url 32 api_key query", "https://h/mcp?api_key=" + asU32c, true},
		{"stray percent before a random value", "https://h/mcp?token=%" + asB28, true},
		{"stray percent after a random value", "https://h/mcp?token=" + asB28 + "%", true},
		{"bad escape after a random value", "https://h/mcp?token=" + asB28 + "%zz", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			servers := map[string]struct {
				server discover.Server
				field  string
			}{
				"remote http":   {remoteServer(discover.TransportHTTP, tt.url), FieldURL},
				"remote sse":    {remoteServer(discover.TransportSSE, tt.url), FieldURL},
				"stdio bare":    {argServer("serve", tt.url), FieldArgs},
				"stdio --url=":  {argServer("--url=" + tt.url), FieldArgs},
				"stdio --url x": {argServer("--url", tt.url), FieldArgs},
			}
			for where, c := range servers {
				got := checkArgSecrets(c.server)
				if !tt.want {
					if len(got) != 0 {
						t.Errorf("%s: checkArgSecrets(%q) = %+v, want no finding", where, tt.url, got)
					}
					continue
				}
				assertOnlyField(t, got, c.field)
			}
		})
	}
}

// TestCheckArgSecretsOpaqueParts covers a long opaque part inside a value with
// 2 or more separators. A prefix ("sk_live_") or a padding of words
// ("aaa-bbb-") must not make the value word-like, because the maxOpaquePartLen
// branch of isWordLike sees the random body. Each row runs on a stdio server
// (args) and on a remote server (url). An empty args or url means that the row
// has no shape for that side.
func TestCheckArgSecretsOpaqueParts(t *testing.T) {
	t.Parallel()

	type row struct {
		name string
		args []string
		url  string
		want bool
	}
	var tests []row

	// Prefixed tokens in four places: a bare arg, NAME=value under a name that
	// is not credential-like, a URL path segment and the user name of a URL.
	for i, tok := range asPrefixed {
		label := []string{"sk_live", "rk_live", "xoxb", "github_pat"}[i]
		tests = append(tests,
			row{label + " bare arg", []string{"serve", tok}, "", true},
			row{label + " under a non-credential name", []string{"-e", "FOO=" + tok}, "", true},
			row{label + " as a path segment", nil, "https://" + asHost + "/mcp/" + tok, true},
			row{label + " as the user name", nil, "https://" + tok + "@" + asHost + "/mcp", true},
		)
	}

	// Padded secrets under a credential-like name, in a path and in a user name.
	tests = append(tests,
		row{"api-key padded with two words", []string{"--api-key=aaa-bbb-" + asT24}, "", true},
		row{"api-key padded with live-prod", []string{"--api-key=live-prod-" + asT24}, "", true},
		row{"api-key padded with three words", []string{"--api-key=my-secret-key-" + asT24}, "", true},
		row{"api-key with a suffix of words", []string{"--api-key=" + asT24 + "-prod-live"}, "", true},
		row{"api-key padded, 32 byte body", []string{"--api-key=prod-live-key-" + asT32}, "", true},
		row{"api-key with underscores", []string{"--api-key=read_write_" + asT24}, "", true},
		row{"api-key in the next arg", []string{"--api-key", "aaa-bbb-" + asT24}, "", true},
		row{"api_key query padded", nil, "https://" + asHost + "/mcp?api_key=aaa-bbb-" + asT24, true},
		row{"api_key query padded, in a stdio URL arg", []string{"https://" + asHost + "/mcp?api_key=aaa-bbb-" + asT24}, "", true},
		row{"path segment padded", nil, "https://" + asHost + "/aaa-bbb-" + asT24, true},
		row{"user name padded", nil, "https://aaa-bbb-" + asT24 + "@" + asHost + "/mcp", true},

		// One-case letters of 20 bytes or more are a secret body, not a word. Each
		// row below was hidden by its two-word or one-word prefix before the long
		// part rule required a low entropy for letters of one case.
		row{"letters: api-key, live-key- prefix, next arg", []string{"--api-key", "live-key-" + asL24}, "", true},
		row{"letters: api-key, prod-live- prefix, upper case", []string{"--api-key=prod-live-" + asU24L}, "", true},
		// limit: recall for a letters-only 20 byte body is bounded by the later
		// entropy rules (looksRandom needs minEntropy on the whole value), not by
		// the long part rule. This body passes both.
		row{"letters: api-key, aaa-bbb- prefix, 20 byte body", []string{"--api-key", "aaa-bbb-" + asL20}, "", true},
		row{"letters: query token", nil, "https://" + asHost + "/mcp?token=aaa-bbb-" + asL24, true},
		row{"letters: path segment", nil, "https://" + asHost + "/aaa-bbb-" + asL24, true},
		row{"letters: user name", nil, "https://aaa-bbb-" + asL24 + "@" + asHost + "/mcp", true},

		// Guards: long real words in a slug stay clean (entropy under minOpaqueEntropy).
		row{"guard: long words under --auth", []string{"--auth", "internationalization-configuration-file-v2"}, "", false},
		row{"guard: long words in a --auth flag name", []string{"--auth-internationalization-configuration-file-v2"}, "", false},
		row{"guard: long words in a path", nil, "https://h/docs/internationalization-and-localization-guide", false},
		row{"guard: long run of one letter under api-key", []string{"--api-key", "aaaaaaaaaaaaaaaaaaaaaaaa-bbb-ccc"}, "", false},
		row{"guard: long word with a year under session-name", []string{"--session-name", "institutionalization-guide-2024"}, "", false},

		// Guards: readable names stay clean. These show the boundary of the rule.
		row{"guard: signing key name", []string{"--api-key=production-signing-key-2024"}, "", false},
		row{"guard: pangram path", nil, "https://h/the-quick-brown-fox-jumps-over-the-lazy-dog", false},
		row{"guard: pangram user name", nil, "https://the-quick-brown-fox-jumps-over-the-lazy-dog@h/mcp", false},
		row{"guard: project name, 16 byte tail", nil, "https://h/v1/projects/my-project-1234567890abcdef/mcp", false},
		row{"guard: project name under api-key, 16 byte tail", []string{"--api-key=my-project-1234567890abcdef"}, "", false},
		// limit: an opaque tail of 19 bytes is still a counted part, not a long
		// opaque run, so "my-project-<19>" is word-like and is missed. A hostile
		// config can split a random value into pieces of under 20 bytes. This
		// is a documented limit of maxOpaquePartLen.
		row{"limit: 19 byte opaque tail in a path is missed", nil, "https://h/v1/projects/my-project-" + asT24[:19] + "/mcp", false},
		row{"limit: 19 byte opaque tail under api-key is missed", []string{"--api-key=my-project-" + asT24[:19]}, "", false},
		// The same shape with a 20 byte tail is found.
		row{"20 byte opaque tail in a path", nil, "https://h/v1/projects/my-project-" + asT24[:20] + "/mcp", true},
		row{"20 byte opaque tail under api-key", []string{"--api-key=my-project-" + asT24[:20]}, "", true},
	)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.args != nil {
				got := checkArgSecrets(argServer(tt.args...))
				if !tt.want {
					if len(got) != 0 {
						t.Errorf("checkArgSecrets(%q) = %+v, want no finding", tt.args, got)
					}
				} else {
					assertOnlyField(t, got, FieldArgs)
				}
			}
			if tt.url != "" {
				for _, tr := range []discover.Transport{discover.TransportHTTP, discover.TransportSSE} {
					got := checkArgSecrets(remoteServer(tr, tt.url))
					if !tt.want {
						if len(got) != 0 {
							t.Errorf("checkArgSecrets(%s, %q) = %+v, want no finding", tr, tt.url, got)
						}
					} else {
						assertOnlyField(t, got, FieldURL)
					}
				}
			}
		})
	}
}

// TestCheckArgSecretsStructure covers the transport split, the dedupe and the
// shape of every finding.
func TestCheckArgSecretsStructure(t *testing.T) {
	t.Parallel()

	secretURL := "https://" + asHost + "/mcp?token=" + asGH

	t.Run("several secret args give one args finding", func(t *testing.T) {
		t.Parallel()
		s := argServer("--token="+asGH, "--api-key", asRand24, "-e", "DB_PASSWORD="+asRand24, asGH)
		assertOnlyField(t, checkArgSecrets(s), FieldArgs)
	})

	t.Run("a remote server does not get an args finding", func(t *testing.T) {
		t.Parallel()
		s := remoteServer(discover.TransportHTTP, "https://"+asHost+"/mcp")
		s.Args = discover.NewArgs([]string{"--token=" + asGH})
		if got := checkArgSecrets(s); len(got) != 0 {
			t.Errorf("checkArgSecrets() = %+v, want no finding", got)
		}
	})

	t.Run("a stdio server does not get a url finding", func(t *testing.T) {
		t.Parallel()
		s := argServer("serve")
		s.URL = discover.NewURL(secretURL)
		if got := checkArgSecrets(s); len(got) != 0 {
			t.Errorf("checkArgSecrets() = %+v, want no finding", got)
		}
	})

	t.Run("a remote server with a secret URL and a secret arg gives only the url finding", func(t *testing.T) {
		t.Parallel()
		s := remoteServer(discover.TransportSSE, secretURL)
		s.Args = discover.NewArgs([]string{"--token=" + asGH})
		assertOnlyField(t, checkArgSecrets(s), FieldURL)
	})

	t.Run("a stdio URL arg gives an args finding", func(t *testing.T) {
		t.Parallel()
		// argsecrets.go reads a URL arg of a stdio server as FieldArgs: the URL
		// field of a stdio server is not set.
		s := argServer("--url=https://user:pw@example.com/sse", "SERVER_URL=https://example.com/x?token="+asRand24)
		assertOnlyField(t, checkArgSecrets(s), FieldArgs)
	})

	t.Run("an unknown transport is read as stdio", func(t *testing.T) {
		t.Parallel()
		s := argServer("--token=" + asGH)
		s.Transport = ""
		assertOnlyField(t, checkArgSecrets(s), FieldArgs)
	})

	t.Run("a different server name is kept", func(t *testing.T) {
		t.Parallel()
		s := argServer("--token=" + asGH)
		s.Name = "other"
		got := checkArgSecrets(s)
		want := []Finding{secretFinding("other", FieldArgs, "")}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("checkArgSecrets() = %+v, want %+v", got, want)
		}
	})

	t.Run("the finding has the fixed fields", func(t *testing.T) {
		t.Parallel()
		got := checkArgSecrets(argServer("--token=" + asGH))
		if len(got) != 1 {
			t.Fatalf("len(findings) = %d, want 1", len(got))
		}
		f := got[0]
		if f.RuleID != RulePlaintextSecret || f.Key != "" || f.Related != "" || f.Tool != "" || f.Message != plaintextSecretMessage {
			t.Errorf("finding = %+v, want rule %s, fixed message and empty Key, Related and Tool", f, RulePlaintextSecret)
		}
	})
}

// TestCheckArgSecretsNoLeak renders every positive finding in each common
// form and checks that no secret, arg, URL or host shows.
func TestCheckArgSecretsNoLeak(t *testing.T) {
	t.Parallel()

	secretURL := "https://user:" + asRand24 + "@" + asHost + "/mcp/" + testRandom32 + "?token=" + asGH
	servers := map[string]discover.Server{
		"named token":     argServer("run", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN="+asGH),
		"api-key flag":    argServer("--api-key", asRand24),
		"token equals":    argServer("--token=" + asGH),
		"env equals":      argServer("--env=API_KEY=" + asSK),
		"env attached":    argServer("-eAPI_KEY=" + asSK),
		"bare token":      argServer(asGH),
		"NAME=value":      argServer("DB_PASSWORD=" + asRand24),
		"literal default": argServer("--token=${X:-" + asGH + "}"),
		"URL arg":         argServer("--url=https://user:" + asRand24 + "@" + asHost + "/sse"),
		"NAME=URL":        argServer("SERVER_URL=https://" + asHost + "/x?token=" + asRand24),
		"remote":          remoteServer(discover.TransportHTTP, secretURL),
		"remote sse":      remoteServer(discover.TransportSSE, "https://"+asHost+"/mcp/"+testRandom32),
		"hex key":         argServer("--api-key", asHex32),
		"upper hex key":   argServer("--api-key=" + asHex64),
		"UUID password":   argServer("--password", asUUID),
		"long random":     argServer("--api-key", asB22),
		"remote plus":     remoteServer(discover.TransportHTTP, "https://"+asHost+"/mcp?api_key="+asPlus),
		"remote %2B":      remoteServer(discover.TransportHTTP, "https://"+asHost+"/mcp?api_key="+strings.Replace(asPlus, "+", "%2B", 1)),
		"remote stray %":  remoteServer(discover.TransportSSE, "https://"+asHost+"/mcp?token="+asB28+"%"),
		"remote UUID key": remoteServer(discover.TransportHTTP, "https://"+asHost+"/mcp?api_key="+asUUID),
		"random path zip": remoteServer(discover.TransportHTTP, "https://"+asHost+"/mcp/"+asPath+".zip"),
	}
	pieces := append([]string{asBody, asBody[:36], asGH, asSK, asRand24, testRandom32, asHost, secretURL,
		asUUID, asHex32, asHex64, asB22, asB28, asPlus, asPath}, asNames...)

	for name, s := range servers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			findings := checkArgSecrets(s)
			if len(findings) == 0 {
				t.Fatal("checkArgSecrets() = no finding, want one (the leak check needs a finding)")
			}
			secrets := append([]string{s.URL.Reveal()}, pieces...)
			for _, arg := range s.Args.Values() {
				if len(arg) >= 6 {
					secrets = append(secrets, arg)
				}
			}
			for _, f := range findings {
				assertFindingNoLeak(t, f, secrets...)
			}
		})
	}
}

// TestCheckArgSecretsArchiveHashes shows that the archive rows are not
// vacuous: the plain randomSegment rule flags each hash name below, and
// randomPathSegment, the rule that the URL check uses, does not.
func TestCheckArgSecretsArchiveHashes(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, hex, ext string }{
		{"sha1 zip", asZipHex, ".zip"},
		{"sha1 zip 2", asZipHex2, ".zip"},
		{"sha1 zip 3", asZipHex3, ".zip"},
		{"sha1 tar.gz", asTarGzHex, ".tar.gz"},
		{"sha1 tar.gz 2", asTarGzHex2, ".tar.gz"},
		{"sha1 tgz", asTgzHex, ".tgz"},
		{"sha1 whl", asWhlHex, ".whl"},
		{"sha256 tar.gz", asSha256Hex, ".tar.gz"},
		{"md5 zip", asMD5Hex, ".zip"},
		{"uniform md5 without extension", asUniMD5, ""},
		{"uniform md5 zip", asUniMD5, ".zip"},
		{"uniform sha256 without extension", asUniSHA, ""},
		{"uniform sha256 tar.gz", asUniSHA, ".tar.gz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			segment := tt.hex + tt.ext
			if !randomSegment(segment) {
				t.Errorf("randomSegment(%q) = false, want true (the row would be vacuous)", segment)
			}
			if randomPathSegment(segment) {
				t.Errorf("randomPathSegment(%q) = true, want false", segment)
			}
			if urlHasSecret("https://h/archive/" + segment) {
				t.Errorf("urlHasSecret(archive URL with %q) = true, want false", segment)
			}
		})
	}

	// A hex token as the user name keeps the plain rule.
	t.Run("hex as a user name is still a secret shape", func(t *testing.T) {
		t.Parallel()
		if !urlHasSecret("https://" + asZipHex + ".zip@h/mcp") {
			t.Error("urlHasSecret(hex+.zip as user name) = false, want true")
		}
	})
}

func TestTrimFileExt(t *testing.T) {
	t.Parallel()

	tests := []struct{ in, want string }{
		{"x.zip", "x"},
		{"x.tar.gz", "x"},
		{"x.tgz", "x"},
		{"x.whl", "x"},
		{"x.tar", "x"},
		{"x", "x"},
		{"", ""},
		{"a.b.c", "a.b"},
		{"x.", "x."},
		{".zip", ".zip"},
		{"x.abcdefgh", "x"},            // an extension of 8 bytes is the longest
		{"x.abcdefghi", "x.abcdefghi"}, // 9 bytes is not trimmed
		{"x.t-r", "x.t-r"},
		{"x.z%p", "x.z%p"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := trimFileExt(tt.in); got != tt.want {
				t.Errorf("trimFileExt(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestLenientUnescape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		in          string
		plusIsSpace bool
		want        string
	}{
		{"empty", "", true, ""},
		{"nothing to decode", "abc", true, "abc"},
		{"valid escape", "a%20b", false, "a b"},
		{"valid escape, lower-case hex", "a%2bb", false, "a+b"},
		{"valid escape, upper-case hex", "a%2Bb", true, "a+b"},
		{"escape at the end", "a%41", false, "aA"},
		{"escape of a percent", "%25", false, "%"},
		{"escape of a null byte", "%00", false, "\x00"},
		{"plus is a space", "a+b", true, "a b"},
		{"plus is kept", "a+b", false, "a+b"},
		{"escaped plus stays a plus when plus is a space", "a%2Bb+c", true, "a+b c"},
		{"bad escape is kept", "%zz", false, "%zz"},
		{"bad second digit is kept", "%4z", false, "%4z"},
		{"lone percent", "%", true, "%"},
		{"percent and one digit", "%4", true, "%4"},
		{"percent at the end", "100%", false, "100%"},
		{"percent then a valid escape", "%%41", false, "%A"},
		{"percent then a plus", "%+41", true, "% 41"},
		{"bad escape then a valid one", "%zz%41", false, "%zzA"},
		{"non-ASCII bytes pass through", "\xc3\xa9%41", false, "\xc3\xa9A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := lenientUnescape(tt.in, tt.plusIsSpace); got != tt.want {
				t.Errorf("lenientUnescape(%q, %v) = %q, want %q", tt.in, tt.plusIsSpace, got, tt.want)
			}
		})
	}
}

func TestValueForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"plain", "abc", []string{"abc", "abc"}},
		{"plus", "a+b", []string{"a b", "a+b"}},
		{"stray percent adds a stripped form of each", "a+b%", []string{"a b%", "a+b%", "a b", "a+b"}},
		{"%NAME% adds no stripped form", "%AZURE_OPENAI_KEY_2024_PROD%", []string{"%AZURE_OPENAI_KEY_2024_PROD%", "%AZURE_OPENAI_KEY_2024_PROD%"}},
		{"encoded %NAME% adds no stripped form", "%25KEY_NAME%25", []string{"%KEY_NAME%", "%KEY_NAME%"}},
		{"bad escape inside a value is still stripped", "ab%zzcd", []string{"ab%zzcd", "ab%zzcd", "abzzcd", "abzzcd"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := valueForms(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("valueForms(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsHexString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		in     string
		minLen int
		want   bool
	}{
		{"exact length", asHex32, 32, true},
		{"longer than the minimum", asHex40, 32, true},
		{"one byte short", asHex32[:31], 32, false},
		{"upper case", asHex64, 64, true},
		{"mixed case", "aBcDeF0123456789", 16, true},
		{"one non-hex letter at the end", asHex32[:31] + "g", 32, false},
		{"one non-hex letter at the start", "g" + asHex32[1:], 32, false},
		{"hyphen (a UUID)", asUUID, 32, false},
		{"space", asHex32[:31] + " ", 32, false},
		{"non-ASCII", asHex32[:30] + "\xc3\xa9", 32, false},
		{"empty with a minimum", "", 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isHexString(tt.in, tt.minLen); got != tt.want {
				t.Errorf("isHexString(%q, %d) = %v, want %v", tt.in, tt.minLen, got, tt.want)
			}
		})
	}
}

func TestNameHoldsSecretWord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"key", "key", true},
		{"token", "token", true},
		{"secret", "secret", true},
		{"password", "password", true},
		{"passwd", "passwd", true},
		{"pass", "pass", true},
		{"flag name with hyphens", "client-secret", true},
		{"joined words", "apikey", true},
		{"mixed case", "X-Api-Key", true},
		{"upper case", "TOKEN", true},
		{"env name", "DB_PASSWORD", true},
		{"session", "session", false},
		{"session id", "session-id", false},
		{"auth", "auth", false},
		{"auth id", "auth-id", false},
		{"pin", "pin", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := nameHoldsSecretWord(tt.in); got != tt.want {
				t.Errorf("nameHoldsSecretWord(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLooksLongRandom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"20 bytes with letter, digit and entropy", testRandom32[:20], true},
		{"19 bytes", testRandom32[:19], false},
		{"21 bytes", asB21, true},
		{"22 bytes", asB22, true},
		{"23 bytes", asB23, true},
		{"one separator", testRandom32[:10] + "-" + testRandom32[11:21], true},
		{"two separators", testRandom32[:10] + "-" + testRandom32[11:15] + "_" + testRandom32[16:21], false},
		{"two dots", testRandom32[:10] + "." + testRandom32[11:15] + "." + testRandom32[16:21], false},
		{"name made of words", "my-prod-secret-store-v2", false},
		{"no digit", "aBcDeFgHiJkLmNoPqRsT", false},
		{"low entropy", "a1a1a1a1a1a1a1a1a1a1", false},
		{"not token-shaped", testRandom32[:19] + "!", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := looksLongRandom(tt.in); got != tt.want {
				t.Errorf("looksLongRandom(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsWordLike(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		// Word-like: a name made of words and numbers.
		{"session name", "production-session-2024-01", true},
		{"oauth flow name", "oauth2-client-credentials-flow", true},
		{"pangram", "the-quick-brown-fox-jumps-over-the-lazy-dog", true},
		{"branch name", "feature-branch-name-long-1234", true},
		{"capitalised words with underscores", "Document_Final_Version_2024_Q3_Report", true},
		{"alphabet words", "abcdef-ghijkl-mnopqr-stuvwx", true},
		{"dots as separators", "john.doe.smith.jones", true},
		{"last dot part is cut as a file extension", "john.doe.smith", false}, // only 1 separator is left
		{"upper case words", "PRODUCTION_SESSION_NAME", true},
		{"file extension is cut first", "production-session-name.tar.gz", true},
		// Pinned limit: "my" is short and not counted, "project" is a word and
		// "1234567890abcdef" is a long non-word, so 1 of 2 counted parts is a
		// word: exactly half passes. A random value of that shape is a miss.
		{"half of the counted parts are words", "my-project-1234567890abcdef", true},
		// Pinned: a long part that is a word (letters of one case) or a number is
		// not opaque, so the maxOpaquePartLen branch does not apply to it.
		{"long word part stays word-like", "aaaaaaaaaaaaaaaaaaaaaaaa-bbb-ccc", true},
		{"long number part stays word-like", "123456789012345678901234-abc-def", true},
		// Pinned: long real words and a long run of one letter have an entropy under
		// minOpaqueEntropy, so they stay words.
		{"long real words", "internationalization-and-localization-guide", true},
		{"long real word with a year", "institutionalization-guide-2024", true},
		// Pinned limit: a part under maxOpaquePartLen is only counted.
		{"19 byte opaque tail is a limit", "my-project-" + asT24[:19], true},

		// Not word-like: a random token, or too few separators.
		{"random base62", testRandom32, false},
		{"base64url 24, one separator", asU24a, false},
		{"base64url 24, two separators", asU24b, false},
		{"base64url 32, one separator", asU32a, false},
		{"base64url 32, two separators", asU32b, false},
		{"base64url 32, two separators (other)", asU32c, false},
		{"github token", asGH, false},
		{"stripe-style key, prefix with two separators", asStripe, false},
		{"slack-style token with numbers and a body", asSlack, false},
		{"github_pat token, two long bodies", asGHPat, false},
		{"padded body, two words", "aaa-bbb-" + asT24, false},
		{"padded body, live-prod", "live-prod-" + asT24, false},
		// Hidden by the prefix before the long part rule checked the entropy of
		// one-case letters.
		{"padded random lower case letters", "aaa-bbb-" + asL24, false},
		{"padded random upper case letters", "prod-live-" + asU24L, false},
		{"padded random lower case letters, 20 bytes", "aaa-bbb-" + asL20, false},
		{"body with a suffix of words", asT24 + "-prod-live", false},
		{"openai-style key", asSK, false},
		{"uuid", asUUID, false},
		{"hex40", asHex40, false},
		{"hex40 with .tar.gz (extension cut first)", asTarGzHex + ".tar.gz", false},
		{"hex32 with .zip", asMD5Hex + ".zip", false},
		{"single separator", "abc-def", false},
		{"two words, one separator", "production-session", false},
		{"empty", "", false},
		{"only separators", "-_.-_.", false},
		{"two separators, no counted part", "a-b-c", false},
		{"two separators, short parts only", "my-v2-q3", false},
		{"no separator", "productionsessionname", false},
		{"mixed-case word is not a word", "aBcDe-fGhIj-kLmNo", false},
		{"word with digits is not a word", "ab1cd-ef2gh-ij3kl", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isWordLike(tt.in); got != tt.want {
				t.Errorf("isWordLike(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestIsWordLikeOpaqueTailBoundary pins the edge of maxOpaquePartLen: after
// "my-project-", a tail of 19 bytes is counted as one long part and the value
// stays word-like, and a tail of 20 bytes or more is a secret body.
func TestIsWordLikeOpaqueTailBoundary(t *testing.T) {
	t.Parallel()

	if maxOpaquePartLen != 20 {
		t.Fatalf("maxOpaquePartLen = %d, want 20 (update the rows below)", maxOpaquePartLen)
	}
	tests := []struct {
		tail int
		want bool
	}{
		{10, true}, {18, true}, {19, true}, {20, false}, {21, false}, {24, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("tail of %d bytes", tt.tail), func(t *testing.T) {
			t.Parallel()
			in := "my-project-" + asT24[:tt.tail]
			if got := isWordLike(in); got != tt.want {
				t.Errorf("isWordLike(%q) = %v, want %v", in, got, tt.want)
			}
		})
	}
}

// TestIsWordLikeLongLetters pins minOpaqueEntropy for a long part of letters of
// one case: below the limit it is a word, at or above it is a secret body. The
// entropies are computed, so a change of the limit or of a body shows here.
func TestIsWordLikeLongLetters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		below   bool // want shannonEntropy(body) < minOpaqueEntropy
		wantWL  bool // want isWordLike("aaa-bbb-" + body)
		wantWLU bool // want isWordLike of the same text in upper case
	}{
		// 9 letters: two used 3 times, seven used twice. Entropy 3.15.
		{"20 letters, entropy just below the limit", "aaabbbccddeeffgghhii", true, true, true},
		// 10 letters, each used twice. Entropy 3.32.
		{"20 letters, entropy just above the limit", "aabbccddeeffgghhiijj", false, false, false},
		// One letter. Entropy 0.
		{"24 letters, one letter repeated", strings.Repeat("a", 24), true, true, true},
		{"24 distinct-looking letters", asL24, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if len(tt.body) < maxOpaquePartLen {
				t.Fatalf("len(body) = %d, want at least maxOpaquePartLen (%d)", len(tt.body), maxOpaquePartLen)
			}
			// Precondition: the row sits on the side of the limit that it names.
			if e := shannonEntropy(tt.body); (e < minOpaqueEntropy) != tt.below {
				t.Fatalf("shannonEntropy(%q) = %.3f, want below %.1f = %v", tt.body, e, minOpaqueEntropy, tt.below)
			}
			if got := isWordLike("aaa-bbb-" + tt.body); got != tt.wantWL {
				t.Errorf("isWordLike(lower case) = %v, want %v", got, tt.wantWL)
			}
			if got := isWordLike("aaa-bbb-" + strings.ToUpper(tt.body)); got != tt.wantWLU {
				t.Errorf("isWordLike(upper case) = %v, want %v", got, tt.wantWLU)
			}
		})
	}
}

func TestIsNumberPart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"two digits", "01", true},
		{"long number", "123456789012345678901234", true},
		{"empty", "", false},
		{"one digit", "7", false},
		{"digits and a letter", "12a", false},
		{"letters", "abc", false},
		{"non-ASCII digit", "\u0663\u0664", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isNumberPart(tt.in); got != tt.want {
				t.Errorf("isNumberPart(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsWordPart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"lower case word", "session", true},
		{"minimum word length", "abc", true},
		{"capital first", "Document", true},
		{"upper case word", "FINAL", true},
		{"two letters", "ab", false},
		{"capital and two letters", "Ab", false},
		{"minimum number length", "01", true},
		{"long number", "1234567890", true},
		{"one digit", "7", false},
		{"letter and digit", "Q3", false},
		{"word with a digit inside", "oauth2", false},
		{"letters then digits", "abc123", false},
		{"mixed case", "aBcDe", false},
		{"capital then mixed", "AbCd", false},
		{"two capitals then lower", "ABcd", false},
		{"empty", "", false},
		{"non-ASCII letters", "\xc3\xa9t\xc3\xa9", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isWordPart(tt.in); got != tt.want {
				t.Errorf("isWordPart(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsNameSeparator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   rune
		want bool
	}{
		{'-', true}, {'_', true}, {'.', true},
		{'a', false}, {'Z', false}, {'0', false},
		{' ', false}, {'/', false}, {'+', false}, {'%', false}, {'=', false}, {0, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.in), func(t *testing.T) {
			t.Parallel()
			if got := isNameSeparator(tt.in); got != tt.want {
				t.Errorf("isNameSeparator(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// FuzzCheckArgSecrets checks that no input makes checkArgSecrets panic and that
// a finding never holds the input.
func FuzzCheckArgSecrets(f *testing.F) {
	f.Add("--token="+asGH, "", "https://"+asHost+"/mcp?token="+asGH)
	f.Add("--api-key", asRand24, "https://user:pw@h/mcp")
	f.Add("-e", "DB_PASSWORD="+asRand24, "https://h/mcp/"+testRandom32)
	f.Add("-eAPI_KEY="+asSK, "--token", "${SCHEME}://${HOST}:${PORT}/%zz?a=${K:-${J:-x}}")
	f.Add("--token=${X:-"+asGH+"}", "--env=A=B=C", "https://h:abc/mcp?token=")
	f.Add("--url=https://u:p%ss@h/", "SERVER_URL=https://h/x?token="+asRand24, "://")
	f.Add("--api-key", asHex32, "https://h.invalid/mcp?api_key="+asPlus)
	f.Add("--from=https://github.com/u/r/archive/"+asZipHex+".zip", "--password", "https://h/mcp?token="+asB28+"%zz")
	f.Add("--session-id", asUUID, "https://h/mcp?password=hunter2%x&page=2%")
	f.Add("--api-key", asU32b, "https://h/mcp?api_key="+asU24b)
	f.Add("--session-name", "production-session-2024-01", "https://h/files/Document_Final_Version_2024_Q3_Report.pdf")
	f.Add("--api-key", "%AZURE_OPENAI_KEY_2024_PROD%", "https://h/mcp?api_key=%25AZURE_OPENAI_KEY_2024_PROD%25")
	f.Add("https://h/v1/projects/my-project-1234567890abcdef/mcp", "--auth", "https://h/the-quick-brown-fox-jumps-over-the-lazy-dog")
	f.Add("--api-key=aaa-bbb-"+asT24, "-e", "https://"+asStripe+"@h/mcp")
	f.Add("FOO="+asSlack, "--api-key=read_write_"+asT24, "https://h/mcp/"+asGHPat)
	f.Add("--api-key", asT24+"-prod-live", "https://h/mcp?api_key=live-prod-"+asT24+"#x")
	f.Add("--api-key", "live-key-"+asL24, "https://h/mcp?token=aaa-bbb-"+asU24L)
	f.Add("--api-key=prod-live-"+asU24L, "--session-name", "https://aaa-bbb-"+asL20+"@h/docs/internationalization-and-localization-guide")
	f.Add("", "-", "\t\n\x00")
	f.Add(strings.Repeat("a", maxScanLen+1), "--token", strings.Repeat("b", maxScanLen+1))

	// The finding text is fixed, so an input that is a piece of it is no leak.
	fixed := fmt.Sprintf("%v %+v %#v", secretFinding("srv", FieldArgs, ""), secretFinding("srv", FieldURL, ""), secretFinding("srv", FieldURL, ""))

	f.Fuzz(func(t *testing.T, arg1, arg2, rawURL string) {
		stdio := argServer(arg1, arg2)
		remote := remoteServer(discover.TransportHTTP, rawURL)
		sse := remoteServer(discover.TransportSSE, rawURL)
		sse.Args = discover.NewArgs([]string{arg1, arg2})

		cases := []struct {
			server discover.Server
			field  string
		}{{stdio, FieldArgs}, {remote, FieldURL}, {sse, FieldURL}}
		for _, c := range cases {
			findings := checkArgSecrets(c.server)
			if len(findings) > 1 {
				t.Fatalf("len(findings) = %d, want at most 1", len(findings))
			}
			for _, got := range findings {
				if want := secretFinding("srv", c.field, ""); !reflect.DeepEqual(got, want) {
					t.Fatalf("finding = %+v, want %+v", got, want)
				}
				js, err := json.Marshal(got)
				if err != nil {
					t.Fatalf("json.Marshal() error = %v", err)
				}
				out := fmt.Sprintf("%v %+v %#v %s", got, got, got, js)
				for _, in := range []string{arg1, arg2, rawURL} {
					if len(in) >= 4 && !strings.Contains(fixed, in) && strings.Contains(out, in) {
						t.Fatalf("finding holds the input %q", in)
					}
				}
			}
		}
	})
}
