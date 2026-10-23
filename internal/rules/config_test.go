package rules

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// Synthetic values. None of them is a real credential.
const (
	// A GitHub-style token: "ghp_" plus 36 synthetic characters.
	testGHToken = "ghp_" + "mcpmoatCanaryAB12cdEF34ghIJ56klMN78"
	// 32 distinct characters: Shannon entropy of 5 bits per byte.
	testRandom32 = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xZ"
)

// wantFinding is the part of a Finding that the tests compare. Message is a fixed
// text; the tests only check that it is not empty.
type wantFinding struct {
	RuleID, Field, Key, Related string
}

// remoteServer builds a server with a remote transport.
func remoteServer(tr discover.Transport, rawURL string) discover.Server {
	return discover.Server{Name: "srv", Transport: tr, URL: discover.NewURL(rawURL)}
}

// stdioServer builds a stdio server.
func stdioServer(command string, args ...string) discover.Server {
	return discover.Server{
		Name:      "srv",
		Transport: discover.TransportStdio,
		Command:   command,
		Args:      discover.NewArgs(args),
	}
}

// withEnv returns s with one env entry.
func withEnv(s discover.Server, key, value string) discover.Server {
	s.Env = discover.SecretMap{key: discover.NewSecret(value)}
	return s
}

// withHeader returns s with one header.
func withHeader(s discover.Server, key, value string) discover.Server {
	s.Headers = discover.SecretMap{key: discover.NewSecret(value)}
	return s
}

// wantsOf turns findings into wants and checks the fields that every finding
// must have.
func wantsOf(t *testing.T, findings []Finding) []wantFinding {
	t.Helper()
	var got []wantFinding
	for _, f := range findings {
		if f.Server != "srv" {
			t.Errorf("Finding.Server = %q, want %q", f.Server, "srv")
		}
		if f.Message == "" {
			t.Errorf("Finding %s has an empty Message", f.RuleID)
		}
		got = append(got, wantFinding{f.RuleID, f.Field, f.Key, f.Related})
	}
	return got
}

func TestCheckConfig(t *testing.T) {
	t.Parallel()

	insecure := []wantFinding{{RuleID: RuleInsecureURL, Field: FieldURL}}
	secretEnv := func(key string) []wantFinding {
		return []wantFinding{{RuleID: RulePlaintextSecret, Field: FieldEnv, Key: key}}
	}
	secretHeader := func(key string) []wantFinding {
		return []wantFinding{{RuleID: RulePlaintextSecret, Field: FieldHeaders, Key: key}}
	}
	unpinned := func(name string) []wantFinding {
		return []wantFinding{{RuleID: RuleUnpinnedPackage, Field: FieldArgs, Related: name}}
	}

	// autoInstall is the MOAT-T4-004 finding. A -y server also gets it.
	autoInstall := []wantFinding{{RuleID: RuleAutoInstall, Field: FieldArgs}}
	unpinnedAutoInstall := func(name string) []wantFinding {
		return append(unpinned(name), autoInstall...)
	}

	disabled := remoteServer(discover.TransportHTTP, "http://mcp.example.com/sse")
	disabled.State = discover.StateDisabled

	remoteWithArgs := remoteServer(discover.TransportHTTP, "https://mcp.example.com/mcp")
	remoteWithArgs.Command = "npx"
	remoteWithArgs.Args = discover.NewArgs([]string{"-y", "@scope/server@latest"})

	stdioWithURL := stdioServer("node", "server.js")
	stdioWithURL.URL = discover.NewURL("http://mcp.example.com/sse")

	tests := []struct {
		name   string
		server discover.Server
		want   []wantFinding
	}{
		// MOAT-T4-001
		{"http remote fires", remoteServer(discover.TransportHTTP, "http://mcp.example.com/sse"), insecure},
		{"sse transport fires like http", remoteServer(discover.TransportSSE, "http://mcp.example.com/sse"), insecure},
		{"https is fine", remoteServer(discover.TransportHTTP, "https://mcp.example.com/mcp"), nil},
		{"uppercase scheme fires", remoteServer(discover.TransportHTTP, "HTTP://mcp.example.com/sse"), insecure},
		{"loopback 127.0.0.1 is fine", remoteServer(discover.TransportHTTP, "http://127.0.0.1:3000"), nil},
		{"localhost is fine", remoteServer(discover.TransportHTTP, "http://localhost:8080"), nil},
		{"ipv6 loopback is fine", remoteServer(discover.TransportHTTP, "http://[::1]:1"), nil},
		// IsLoopbackHost is case sensitive on purpose (Go skips the proxy
		// only for the exact name "localhost"), so LOCALHOST fires.
		{"uppercase LOCALHOST fires", remoteServer(discover.TransportHTTP, "http://LOCALHOST:8080"), insecure},
		{"localhost lookalike fires", remoteServer(discover.TransportHTTP, "http://localhost.example.com/"), insecure},
		{"127.0.0.1 lookalike fires", remoteServer(discover.TransportHTTP, "http://127.0.0.1.nip.io/"), insecure},
		{"stdio with empty URL", stdioServer("node", "server.js"), nil},
		{"stdio ignores URL", stdioWithURL, nil},
		{"port reference fires", remoteServer(discover.TransportHTTP, "http://mcp.example.com:${PORT}/mcp"), insecure},
		{"host reference fires", remoteServer(discover.TransportHTTP, "http://${HOST}:8080/mcp"), insecure},
		{"env host reference fires", remoteServer(discover.TransportSSE, "http://${env:MCP_HOST}/sse"), insecure},
		{"loopback default of a host reference is fine", remoteServer(discover.TransportHTTP, "http://${HOST:-localhost}:3000/mcp"), nil},
		{"remote default of a host reference fires", remoteServer(discover.TransportHTTP, "http://${HOST:-mcp.example.com}/mcp"), insecure},
		{"https with references is fine", remoteServer(discover.TransportHTTP, "https://${HOST}:${PORT}/mcp"), nil},
		// Clients parse more loosely than Go and still connect, so the check
		// fails closed on an http:// URL that Go cannot parse.
		{"unparsable http URL fires", remoteServer(discover.TransportHTTP, "http://[::1"), insecure},
		{"leading space fires", remoteServer(discover.TransportHTTP, " http://evil.example/mcp"), insecure},
		{"trailing newline fires", remoteServer(discover.TransportHTTP, "http://evil.example/mcp\n"), insecure},
		{"bad escape fires", remoteServer(discover.TransportHTTP, "http://evil.example/%zz"), insecure},
		{"scheme default with a bad escape fires", remoteServer(discover.TransportHTTP, "${SCHEME:-http}://evil.example/%zz"), insecure},
		{"tab inside the scheme fires", remoteServer(discover.TransportHTTP, "http:\t//evil.example/mcp"), insecure},
		{"newline inside the scheme fires", remoteServer(discover.TransportHTTP, "http\n://evil.example/mcp"), insecure},
		{"tab inside an https scheme gives none", remoteServer(discover.TransportHTTP, "https:\t//evil.example/mcp"), nil},
		{"unparsable https URL gives none", remoteServer(discover.TransportHTTP, "https://evil.example/%zz"), nil},
		{"empty remote URL gives none", remoteServer(discover.TransportHTTP, ""), nil},
		{"disabled server is still checked", disabled, insecure},

		// MOAT-T4-002 env
		{"ghp token in env", withEnv(stdioServer("node", "s.js"), "GITHUB_TOKEN", testGHToken), secretEnv("GITHUB_TOKEN")},
		{"ghp token under neutral key", withEnv(stdioServer("node", "s.js"), "FOO", testGHToken), secretEnv("FOO")},
		{"plain setting", withEnv(stdioServer("node", "s.js"), "LOG_LEVEL", "debug"), nil},
		{"${VAR} reference", withEnv(stdioServer("node", "s.js"), "GITHUB_TOKEN", "${GITHUB_TOKEN}"), nil},
		{"${env:VAR} reference", withEnv(stdioServer("node", "s.js"), "GITHUB_TOKEN", "${env:X}"), nil},
		{"${VAR:-default} reference", withEnv(stdioServer("node", "s.js"), "GITHUB_TOKEN", "${X:-default}"), nil},
		{"$VAR reference", withEnv(stdioServer("node", "s.js"), "GITHUB_TOKEN", "$X"), nil},
		{"literal that starts with $", withEnv(stdioServer("node", "s.js"), "DB_PASSWORD", "$uperS3cretPw!"), secretEnv("DB_PASSWORD")},
		{"literal next to a reference", withEnv(stdioServer("node", "s.js"), "PASSWORD", "hunter2hunter2${X}"), secretEnv("PASSWORD")},
		{"short literal next to a reference", withEnv(stdioServer("node", "s.js"), "API_KEY", "sk-${OPENAI_KEY}"), nil},
		{"token prefix next to a long reference", withEnv(stdioServer("node", "s.js"), "API_KEY", "sk-${OPENAI_API_KEY_VALUE}"), nil},
		{"path key with a relative path", withEnv(stdioServer("node", "s.js"), "PRIVATE_KEY_PATH", "keys/id_rsa"), nil},
		{"file key with a relative path", withEnv(stdioServer("node", "s.js"), "token_file", "secrets/gh"), nil},
		{"camelCase path key", withEnv(stdioServer("node", "s.js"), "keyFile", "secrets/gh"), nil},
		{"PROFILE is not a path key", withEnv(stdioServer("node", "s.js"), "AWS_PROFILE", testRandom32), secretEnv("AWS_PROFILE")},
		{"non-ASCII key ending like a path key", withEnv(stdioServer("node", "s.js"), "CLÉ_FILE", "secrets/gh"), nil},
		{"digits with underscores under secret name", withEnv(stdioServer("node", "s.js"), "PASSWORD", "1234_5678_9012"), secretEnv("PASSWORD")},
		{"token as URL user name", withEnv(stdioServer("node", "s.js"), "GIT_URL", "https://"+testGHToken+"@github.com/x"), secretEnv("GIT_URL")},
		{"plain URL user name", withEnv(stdioServer("node", "s.js"), "GIT_URL", "https://git@github.com/x"), nil},
		{"token under a path key still fires", withEnv(stdioServer("node", "s.js"), "TOKEN_FILE", testGHToken), secretEnv("TOKEN_FILE")},
		{"reference inside a path", withEnv(stdioServer("node", "s.js"), "TOKEN_PATH", "${HOME}/.config/token"), nil},
		{"$HOME path under secret name", withEnv(stdioServer("node", "s.js"), "TOKEN_PATH", "$HOME/.config/token"), nil},
		{"%APPDATA% path under secret name", withEnv(stdioServer("node", "s.js"), "API_KEY", `%APPDATA%\key.txt`), nil},
		{"upper-case FILE: value under secret name", withEnv(stdioServer("node", "s.js"), "GITHUB_TOKEN", "FILE:abc12345"), nil},
		{"URL with a password", withEnv(stdioServer("node", "s.js"), "DATABASE_URL", "postgres://admin:S3cr3tPass@db/prod"), secretEnv("DATABASE_URL")},
		{"URL with a password under neutral key", withEnv(stdioServer("node", "s.js"), "DSN", "mysql://u:pw@db:3306/x"), secretEnv("DSN")},
		{"URL with a password reference", withEnv(stdioServer("node", "s.js"), "DATABASE_URL", "postgres://admin:${PW}@db/prod"), nil},
		{"%VAR% reference", withEnv(stdioServer("node", "s.js"), "API_KEY", "%API_KEY%"), nil},
		{"file name under secret name", withEnv(stdioServer("node", "s.js"), "GOOGLE_APPLICATION_CREDENTIALS", "service-account.json"), nil},
		{"relative key path under secret name", withEnv(stdioServer("node", "s.js"), "SSH_KEY_PATH", "keys/id.pem"), nil},
		{"locale with a token prefix", withEnv(stdioServer("node", "s.js"), "LANG", "sk_SK.UTF-8"), nil},
		{"region with a token prefix", withEnv(stdioServer("node", "s.js"), "REGION", "pk_PK"), nil},
		{"empty value", withEnv(stdioServer("node", "s.js"), "API_KEY", ""), nil},
		{"secret name, literal of 12", withEnv(stdioServer("node", "s.js"), "API_KEY", "changeme123"), secretEnv("API_KEY")},
		{"secret name, literal of 8", withEnv(stdioServer("node", "s.js"), "API_KEY", "abcdefgh"), secretEnv("API_KEY")},
		{"secret name, literal of 7", withEnv(stdioServer("node", "s.js"), "API_KEY", "abcdefg"), nil},
		{"secret name, short", withEnv(stdioServer("node", "s.js"), "API_KEY", "abc"), nil},
		{"secret name, true", withEnv(stdioServer("node", "s.js"), "API_KEY", "true"), nil},
		{"secret name, FALSE", withEnv(stdioServer("node", "s.js"), "API_KEY", "FALSE"), nil},
		{"secret name, number", withEnv(stdioServer("node", "s.js"), "API_KEY", "12345678"), nil},
		{"neutral name, literal of 12", withEnv(stdioServer("node", "s.js"), "MODE", "changeme123"), nil},
		{"high entropy under neutral key", withEnv(stdioServer("node", "s.js"), "SETTING", testRandom32), secretEnv("SETTING")},
		{"long low entropy value", withEnv(stdioServer("node", "s.js"), "SETTING", strings.Repeat("a", 32)), nil},
		{"long low entropy under secret name still fires", withEnv(stdioServer("node", "s.js"), "API_KEY", strings.Repeat("a", 32)), secretEnv("API_KEY")},
		{"absolute path under secret name", withEnv(stdioServer("node", "s.js"), "GOOGLE_APPLICATION_CREDENTIALS", "/home/u/key.json"), nil},
		{"home path under secret name", withEnv(stdioServer("node", "s.js"), "GOOGLE_APPLICATION_CREDENTIALS", "~/x"), nil},
		// Known false negative: a path check runs before the entropy and
		// named-key tests, so a random token that starts with "/" is skipped
		// under any key. Only a token prefix beats the path check.
		{"high entropy absolute path", withEnv(stdioServer("node", "s.js"), "SETTING", "/"+testRandom32), nil},
		{"high entropy absolute path under secret key", withEnv(stdioServer("node", "s.js"), "API_KEY", "/"+testRandom32), nil},
		{"absolute path under neutral key", withEnv(stdioServer("node", "s.js"), "CONFIG", "/home/u/key.json"), nil},
		{"relative ./ path under secret name", withEnv(stdioServer("node", "s.js"), "PASSWORD_FILE", "./pw.txt"), nil},
		{"relative ../ path under secret name", withEnv(stdioServer("node", "s.js"), "PASSWORD_FILE", "../secrets/pw.txt"), nil},
		{"file: value under secret name", withEnv(stdioServer("node", "s.js"), "KEY_FILE", "file:key.pem"), nil},
		{"URL under secret name", withEnv(stdioServer("node", "s.js"), "TOKEN_URL", "https://x.com/token"), nil},
		{"BASE_URL with query", withEnv(stdioServer("node", "s.js"), "BASE_URL", "https://api.example.com/v1/search?x=1"), nil},
		{"DATABASE_URL without password", withEnv(stdioServer("node", "s.js"), "DATABASE_URL", "postgresql://user@localhost:5432/mydb_name"), nil},
		{"prose under neutral key", withEnv(stdioServer("node", "s.js"), "DESCRIPTION", "The quick brown fox jumps over the lazy dog"), nil},
		{"token prefix with ${ inside", withEnv(stdioServer("node", "s.js"), "FOO", testGHToken+"${X}"), secretEnv("FOO")},

		// MOAT-T4-002 headers
		{"bearer random", withHeader(remoteServer(discover.TransportHTTP, "https://mcp.example.com"), "Authorization", "Bearer "+testRandom32), secretHeader("Authorization")},
		{"bearer env reference", withHeader(remoteServer(discover.TransportHTTP, "https://mcp.example.com"), "Authorization", "Bearer ${env:T}"), nil},
		{"bearer token prefix, lowercase scheme", withHeader(remoteServer(discover.TransportHTTP, "https://mcp.example.com"), "Authorization", "bearer "+testGHToken), secretHeader("Authorization")},
		{"bearer short literal", withHeader(remoteServer(discover.TransportHTTP, "https://mcp.example.com"), "Authorization", "Bearer abcdefgh1234"), secretHeader("Authorization")},
		// "basic abc" is 9 bytes: it fires only if the scheme is NOT stripped.
		{"lowercase basic scheme is stripped", withHeader(remoteServer(discover.TransportHTTP, "https://mcp.example.com"), "Authorization", "basic abc"), nil},
		{"uppercase BASIC scheme is stripped", withHeader(remoteServer(discover.TransportHTTP, "https://mcp.example.com"), "Authorization", "BASIC abc"), nil},
		{"Accept header list", withHeader(remoteServer(discover.TransportHTTP, "https://mcp.example.com"), "Accept", "application/json, text/event-stream"), nil},
		{"User-Agent string", withHeader(remoteServer(discover.TransportHTTP, "https://mcp.example.com"), "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"), nil},
		{"neutral header", withHeader(remoteServer(discover.TransportHTTP, "https://mcp.example.com"), "User-Agent", "mcpmoat-test"), nil},
		{"x-api-key literal", withHeader(remoteServer(discover.TransportHTTP, "https://mcp.example.com"), "X-API-Key", "changeme123"), secretHeader("X-API-Key")},

		// MOAT-T4-003
		{"npx @latest", stdioServer("npx", "-y", "@scope/server@latest"), unpinnedAutoInstall("@scope/server")},
		{"npx no version", stdioServer("npx", "-y", "@scope/server"), unpinnedAutoInstall("@scope/server")},
		{"npx pinned", stdioServer("npx", "-y", "@scope/server@1.4.2"), autoInstall},
		{"npx any version *", stdioServer("npx", "-y", "@scope/server@*"), unpinnedAutoInstall("")},
		{"npx any version x", stdioServer("npx", "-y", "pkg-name@x"), unpinnedAutoInstall("")},
		{"docker tag x is a tag", stdioServer("docker", "run", "-i", "image:x"), nil},
		{"uvx no version", stdioServer("uvx", "some-server"), unpinned("some-server")},
		{"uvx pinned", stdioServer("uvx", "some-server==0.3.1"), nil},
		{"docker no tag", stdioServer("docker", "run", "-i", "image"), unpinned("image")},
		// RedactArgs masks "image:latest" (a ":" before a tag is not a safe
		// shape), so the finding fires without a Related name.
		{"docker :latest", stdioServer("docker", "run", "-i", "image:latest"), unpinned("")},
		{"docker tag", stdioServer("docker", "run", "-i", "image:1.2.3"), nil},
		// A flag the tables do not know takes a value: the scan picks it as the
		// package. The charset check or the redaction policy must stop it.
		{"unknown flag value is a token", stdioServer("npx", "--token", "ghp_SECRETSECRET", "pkg"), nil},
		// A token-like scope or name is still a package: an attacker can publish
		// "@xoxo/server-filesystem". The finding fires. RedactArgs masks such an
		// arg (a part has a token prefix), so Related stays empty.
		{"scope with xox prefix", stdioServer("npx", "-y", "@xoxo/server-filesystem"), unpinnedAutoInstall("")},
		{"scope with eyj prefix", stdioServer("npx", "-y", "@eyjay/server-github"), unpinnedAutoInstall("")},
		{"lower-case token value after unknown flag, masked by RedactArgs",
			stdioServer("npx", "--token", "ghp_secretsecret0123", "pkg"), unpinned("")},
		{"unknown flag value that looks like a package, masked by RedactArgs",
			stdioServer("npx", "--auth-key", "abcdef123456", "pkg"), unpinned("")},
		{"known value flag: the scan skips its value", stdioServer("npx", "--otp", "abcdef123456", "pkg"), unpinned("pkg")},
		{"secret flag in = form is skipped", stdioServer("npx", "--token=abcdef123456", "pkg"), unpinned("pkg")},
		// The scan takes the value of the unknown flag "--npm-token" as the
		// package. RedactArgs masks it there, so Related must stay empty even
		// though the text is visible in another arg.
		{"masked package name also in another arg", stdioServer("npx", "--npm-token", "secretpw", "x", "--secretpw"), unpinned("")},
		{"cmd /c wrapper", stdioServer("cmd", "/c", "npx", "-y", "@scope/server@latest"), unpinnedAutoInstall("@scope/server")},
		{"CMD.EXE /C wrapper", stdioServer("CMD.EXE", "/C", "npx", "-y", "@scope/server"), unpinnedAutoInstall("@scope/server")},
		// npx installs every -p package; which one runs is not known, so
		// T4-003 stays silent. The -y still fires T4-004.
		{"second -p is doubtful for T4-003, but -y still fires T4-004", stdioServer("npx", "-y", "-p", "@scope/server@1.0.0", "-p", "evil-pkg", "evil-bin"), autoInstall},
		{"server's own -p after the command", stdioServer("npx", "-y", "-p", "pkg-a", "bin", "-p", "3000"), unpinnedAutoInstall("pkg-a")},
		{"package name shown by RedactArgs", stdioServer("uvx", "some-server@latest"), unpinned("some-server")},
		{"remote server with args", remoteWithArgs, nil},
		{"unknown runner", stdioServer("node", "server.js"), nil},

		// Benign.
		{"benign local server with a neutral env", withEnv(stdioServer("node", "server.js"), "LOG_LEVEL", "info"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := wantsOf(t, CheckConfig(tt.server))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CheckConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCheckConfigOrder(t *testing.T) {
	t.Parallel()

	t.Run("url, env sorted, headers", func(t *testing.T) {
		t.Parallel()
		s := remoteServer(discover.TransportHTTP, "http://mcp.example.com/sse")
		s.Env = discover.SecretMap{
			"B_TOKEN": discover.NewSecret(testGHToken),
			"A_TOKEN": discover.NewSecret(testGHToken),
		}
		s.Headers = discover.SecretMap{
			"X-Zed-Token":   discover.NewSecret(testGHToken),
			"Authorization": discover.NewSecret("Bearer " + testRandom32),
		}
		want := []wantFinding{
			{RuleID: RuleInsecureURL, Field: FieldURL},
			{RuleID: RulePlaintextSecret, Field: FieldEnv, Key: "A_TOKEN"},
			{RuleID: RulePlaintextSecret, Field: FieldEnv, Key: "B_TOKEN"},
			{RuleID: RulePlaintextSecret, Field: FieldHeaders, Key: "Authorization"},
			{RuleID: RulePlaintextSecret, Field: FieldHeaders, Key: "X-Zed-Token"},
		}
		if got := wantsOf(t, CheckConfig(s)); !reflect.DeepEqual(got, want) {
			t.Errorf("CheckConfig() = %+v, want %+v", got, want)
		}
	})

	t.Run("env, then unpinned package", func(t *testing.T) {
		t.Parallel()
		s := withEnv(stdioServer("npx", "-y", "@scope/server"), "GITHUB_TOKEN", testGHToken)
		want := []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldEnv, Key: "GITHUB_TOKEN"},
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs, Related: "@scope/server"},
			{RuleID: RuleAutoInstall, Field: FieldArgs},
		}
		if got := wantsOf(t, CheckConfig(s)); !reflect.DeepEqual(got, want) {
			t.Errorf("CheckConfig() = %+v, want %+v", got, want)
		}
	})
}

// TestCheckConfigNoLeak proves that no finding holds a secret value or the
// URL host, in any common output form.
func TestCheckConfigNoLeak(t *testing.T) {
	t.Parallel()

	const host = "mcp.example.com"
	remote := remoteServer(discover.TransportSSE,
		"http://user:"+discovertest.CanaryURL+"@"+host+"/sse?token="+discovertest.CanaryURL)
	remote.Env = discover.SecretMap{"GITHUB_TOKEN": discover.NewSecret(discovertest.CanaryEnv)}
	remote.Headers = discover.SecretMap{
		"Authorization": discover.NewSecret("Bearer " + discovertest.CanaryHeader),
		"X-Token":       discover.NewSecret(testGHToken),
	}
	stdio := withEnv(
		stdioServer("npx", "-y", "@scope/server", "--api-key", discovertest.CanaryArgs),
		"API_KEY", discovertest.CanaryEnv)

	// The scan takes the value of the unknown flag "--auth-x" as the package.
	misparsed := stdioServer("npx", "--auth-x", testGHToken, "pkg")
	// "--auth-key" is not in npmFlags, so the scan takes its value as the
	// package. The value is a valid package name and RedactArgs masks it.
	maskedName := stdioServer("npx", "--auth-key", "abcdef123456", "pkg")
	// "--otp" is a known value flag: the scan skips its value and finds "pkg".
	knownFlag := stdioServer("npx", "--otp", "abcdef123456", "pkg")

	// A lower-case token is a valid npm name, so the scan returns it as the
	// package. RedactArgs masks it, so it must stay out of every field.
	lowerToken := "ghp_secretsecret0123"
	lowerTokenServer := stdioServer("npx", "--token", lowerToken, "pkg")
	// The same token after a known value flag is skipped by the scan.
	lowerTokenKnown := stdioServer("npx", "--otp", lowerToken, "pkg")
	// -y before the token: MOAT-T4-004 fires, and it must not show the token.
	autoInstallMasked := stdioServer("npx", "-y", "--token", lowerToken, "pkg")
	// A fake env value that npm reads as on. MOAT-T4-004 fires with FieldEnv,
	// and the value must not show in the finding.
	const yesEnvCanary = "trueFAKEcanary0000"
	autoInstallEnv := withEnv(stdioServer("npx", "@scope/server@1.2.3"), "npm_config_yes", yesEnvCanary)

	secrets := append(discovertest.Canaries(), testGHToken, testRandom32, host, "abcdef123456", lowerToken, yesEnvCanary)

	tests := []struct {
		name   string
		server discover.Server
		want   []wantFinding
	}{
		{"remote", remote, []wantFinding{
			{RuleID: RuleInsecureURL, Field: FieldURL},
			{RuleID: RulePlaintextSecret, Field: FieldEnv, Key: "GITHUB_TOKEN"},
			{RuleID: RulePlaintextSecret, Field: FieldHeaders, Key: "Authorization"},
			{RuleID: RulePlaintextSecret, Field: FieldHeaders, Key: "X-Token"},
		}},
		{"stdio", stdio, []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldEnv, Key: "API_KEY"},
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs, Related: "@scope/server"},
			{RuleID: RuleAutoInstall, Field: FieldArgs},
		}},
		{"auto install with a secret-like flag value", autoInstallMasked, []wantFinding{
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs},
			{RuleID: RuleAutoInstall, Field: FieldArgs},
		}},
		{"auto install by env value", autoInstallEnv, []wantFinding{
			{RuleID: RuleAutoInstall, Field: FieldEnv, Key: "npm_config_yes"},
		}},
		{"misparsed token", misparsed, nil},
		{"secret-like package name", maskedName, []wantFinding{
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs},
		}},
		{"lower-case token taken as the package", lowerTokenServer, []wantFinding{
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs},
		}},
		{"lower-case token after a known value flag", lowerTokenKnown, []wantFinding{
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs, Related: "pkg"},
		}},
		{"known value flag with a secret value", knownFlag, []wantFinding{
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs, Related: "pkg"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := CheckConfig(tt.server)
			// The checks must really fire, or the leak asserts prove nothing.
			if got := wantsOf(t, findings); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("CheckConfig() = %+v, want %+v", got, tt.want)
			}
			for _, f := range findings {
				assertFindingNoLeak(t, f, secrets...)
			}
		})
	}
}

// TestCheckAutoInstall covers the flag and runner rules of MOAT-T4-004.
func TestCheckAutoInstall(t *testing.T) {
	t.Parallel()

	fires := []wantFinding{{RuleID: RuleAutoInstall, Field: FieldArgs}}
	firesEnv := func(key string) []wantFinding {
		return []wantFinding{{RuleID: RuleAutoInstall, Field: FieldEnv, Key: key}}
	}

	remoteNpx := remoteServer(discover.TransportHTTP, "https://mcp.example.com/mcp")
	remoteNpx.Command = "npx"
	remoteNpx.Args = discover.NewArgs([]string{"-y", "pkg"})

	disabledNpx := stdioServer("npx", "-y", "pkg")
	disabledNpx.State = discover.StateDisabled

	tests := []struct {
		name   string
		server discover.Server
		want   []wantFinding
	}{
		{"npx -y", stdioServer("npx", "-y", "@scope/server"), fires},
		{"npx --yes", stdioServer("npx", "--yes", "pkg"), fires},
		{"pinned package still fires", stdioServer("npx", "-y", "@scope/server@1.2.3"), fires},
		{"cmd /c wrapper", stdioServer("cmd", "/c", "npx", "-y", "pkg"), fires},
		{"disabled server still fires", disabledNpx, fires},
		{"node script", stdioServer("node", "./server.js"), nil},
		{"npx pinned without -y", stdioServer("npx", "@scope/server@1.2.3"), nil},
		{"-y after the spec is a server arg", stdioServer("npx", "pkg", "-y"), nil},
		{"uvx -y is not npx", stdioServer("uvx", "-y", "pkg"), nil},
		{"bunx -y is not npx", stdioServer("bunx", "-y", "pkg"), nil},
		{"npx -y without a package", stdioServer("npx", "-y"), nil},
		{"remote server with -y args", remoteNpx, nil},

		// The yes flag may come after -p's value, be a prefix of --yes, sit in
		// a short cluster, or carry any value except "false".
		{"-y after -p spec", stdioServer("npx", "-p", "@evil/pkg", "-y", "bin"), fires},
		{"-y after --package= spec", stdioServer("npx", "--package=@evil/pkg", "-y", "bin"), fires},
		{"--yes=true", stdioServer("npx", "--yes=true", "pkg"), fires},
		// npm reads only the exact value "false" as off.
		{"--yes=FALSE", stdioServer("npx", "--yes=FALSE", "pkg"), fires},
		{"--y prefix of --yes", stdioServer("npx", "--y", "pkg"), fires},
		{"-qy short cluster", stdioServer("npx", "-qy", "pkg"), fires},
		{"cmd /c wrapper with -p, then -y", stdioServer("cmd", "/c", "npx", "-p", "pkg", "-y", "bin"), fires},
		{"-y and env npm_config_yes=true give the flag finding", withEnv(stdioServer("npx", "-y", "pkg"), "npm_config_yes", "true"), fires},

		// npx has something to run, so the spec form does not matter: a git URL,
		// a tarball URL, a local-looking name or an upper-case name still fires.
		{"-y with a github: spec", stdioServer("npx", "-y", "github:evil/pkg"), fires},
		{"-y with a tarball URL spec", stdioServer("npx", "-y", "https://evil.example/pkg.tgz"), fires},
		{"-y with a git+https spec", stdioServer("npx", "-y", "git+https://evil.example/r.git"), fires},
		{"-y with an upper-case name", stdioServer("npx", "-y", "Evil-Pkg"), fires},
		{"-p github spec, then -y", stdioServer("npx", "-p", "github:evil/pkg", "-y", "mcp"), fires},
		{"-y, -p github spec, -c command", stdioServer("npx", "-y", "-p", "github:evil/pkg", "-c", "mcp"), fires},
		{"cmd /c wrapper with a github spec", stdioServer("cmd", "/c", "npx", "-y", "github:evil/pkg"), fires},
		// --tag takes no value that starts with "-", so -y still counts.
		{"--tag before -y", stdioServer("npx", "--tag", "-y", "pkg"), fires},
		// A yes flag takes no word after it: npx runs that word as the command,
		// with the option on. "true" and "false" are no exception.
		{"-y true", stdioServer("npx", "-y", "true", "pkg"), fires},
		{"-y false", stdioServer("npx", "-y", "false", "pkg"), fires},
		{"--yes false", stdioServer("npx", "--yes", "false", "pkg"), fires},
		{"-p spec, then -y false", stdioServer("npx", "-p", "@evil/pkg", "-y", "false"), fires},
		// npx moves the value of the -y shorthand to its own argument, so the
		// option is on and the value is the command.
		{"-y=false", stdioServer("npx", "-y=false", "pkg"), fires},
		{"--y=false", stdioServer("npx", "--y=false", "pkg"), fires},
		{"-y=null", stdioServer("npx", "-y=null", "pkg"), fires},
		{"-y=pkg runs pkg", stdioServer("npx", "-y=pkg"), fires},
		// null resets the option to its default, which overrides the scan's
		// npm_config_yes=false.
		{"--yes=null", stdioServer("npx", "--yes=null", "pkg"), fires},
		// Fail-closed: an off flag does not clear an earlier yes flag.
		{"-y, then --no-yes", stdioServer("npx", "-y", "--no-yes", "pkg"), fires},

		// An env entry turns the yes option on unless its value is "false" or
		// "0" after trimming ASCII white space. The key matches in any letter case.
		{"env npm_config_yes=true", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "true"), firesEnv("npm_config_yes")},
		{"env NPM_CONFIG_YES=1", withEnv(stdioServer("npx", "pkg"), "NPM_CONFIG_YES", "1"), firesEnv("NPM_CONFIG_YES")},
		// npm skips an empty value and reads "null" as unset. Either one still
		// replaces the scan's npm_config_yes=false, so npx installs with no TTY.
		{"env npm_config_yes empty", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", ""), firesEnv("npm_config_yes")},
		{"env npm_config_yes=null", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "null"), firesEnv("npm_config_yes")},
		// npm reads white space only as on.
		{"env npm_config_yes blank", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "  "), firesEnv("npm_config_yes")},
		// npm does not trim U+0085, so it reads this value as on.
		{"env npm_config_yes=false and NEL", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "false\u0085"), firesEnv("npm_config_yes")},
		{"env npm_config_yes=true, github spec", withEnv(stdioServer("npx", "github:evil/pkg"), "npm_config_yes", "true"), firesEnv("npm_config_yes")},

		// A value after a valued flag is that flag's value, not a yes flag.
		{"-y is the value of --registry", stdioServer("npx", "--registry", "-y", "pkg"), nil},
		{"-y is the value of --loglevel", stdioServer("npx", "--loglevel", "-y", "pkg"), nil},
		{"-y after the -p spec is a server arg", stdioServer("npx", "-p", "pkg", "bin", "-y"), nil},
		{"--yes=false", stdioServer("npx", "--yes=false", "pkg"), nil},
		{"--yes=0", stdioServer("npx", "--yes=0", "pkg"), nil},
		{"--ye=false, a prefix of --yes", stdioServer("npx", "--ye=false", "pkg"), nil},
		// npx rewrites --shell to --script-shell, which takes -y as its value.
		{"-y is the value of --shell", stdioServer("npx", "--shell", "-y", "pkg"), nil},
		{"cmd /c wrapper, -y after the command", stdioServer("cmd", "/c", "npx", "-p", "pkg", "bin", "-y"), nil},
		{"env npm_config_yes=false", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "false"), nil},
		{"env NPM_CONFIG_YES padded false", withEnv(stdioServer("npx", "pkg"), "NPM_CONFIG_YES", " false "), nil},
		{"env npm_config_yes=0", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "0"), nil},
		{"uvx with env npm_config_yes=true", withEnv(stdioServer("uvx", "pkg"), "npm_config_yes", "true"), nil},
		{"npx with an unrelated env entry", withEnv(stdioServer("npx", "pkg"), "FOO", "true"), nil},

		// No target: npx installs nothing, so the yes flags alone give no finding.
		{"-y -y -- with no target", stdioServer("npx", "-y", "-y", "--"), nil},
		// Known limit: a shell wrapper is not unwrapped, so sh -c gives no finding.
		{"sh -c wrapper", stdioServer("sh", "-c", "npx -y pkg"), nil},
		// Fail-closed trade-off: an unknown flag may take the next word as its
		// value, so the walk reads past "pkg" and the -y after it still counts.
		{"unknown flag, then -y", stdioServer("npx", "--quiet", "pkg", "-y"), fires},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := wantsOf(t, checkAutoInstall(tt.server))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checkAutoInstall() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// assertFindingNoLeak fails the test when f, in any common output form,
// holds one of secrets.
func assertFindingNoLeak(t *testing.T, f Finding, secrets ...string) {
	t.Helper()
	js, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal(%s) error = %v", f.RuleID, err)
	}
	outputs := map[string]string{
		"%+v":  fmt.Sprintf("%+v", f),
		"%#v":  fmt.Sprintf("%#v", f),
		"json": string(js),
	}
	for form, out := range outputs {
		discovertest.AssertNoLeak(t, f.Server+"/"+f.RuleID+" "+form, out, secrets...)
	}
}
