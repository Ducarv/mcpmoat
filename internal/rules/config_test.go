package rules

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
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
	// A full 40 digit commit hash.
	testSHA = "0123456789abcdef0123456789abcdef01234567"
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
	// MOAT-T4-002 in the args or in the URL: Key is always empty.
	secretArgs := []wantFinding{{RuleID: RulePlaintextSecret, Field: FieldArgs}}
	secretURL := []wantFinding{{RuleID: RulePlaintextSecret, Field: FieldURL}}
	// A git, tarball or URL spec: MOAT-T4-003 with an empty Related, because the
	// spec can hold a credential.
	unpinnedSpec := unpinned("")

	// autoInstall is the MOAT-T4-004 finding. A -y server also gets it.
	autoInstall := []wantFinding{{RuleID: RuleAutoInstall, Field: FieldArgs}}
	unpinnedAutoInstall := func(name string) []wantFinding {
		return append(unpinned(name), autoInstall...)
	}

	disabled := remoteServer(discover.TransportHTTP, "http://mcp.example.com/sse")
	disabled.State = discover.StateDisabled

	// remoteWithCommand builds a remote server that also has a command and args.
	remoteWithCommand := func(command string, args ...string) discover.Server {
		s := remoteServer(discover.TransportHTTP, "https://mcp.example.com/mcp")
		s.Command = command
		s.Args = discover.NewArgs(args)
		return s
	}
	// A remote server with git-spec args and secret args: both checks are for
	// stdio servers only, so it gives no finding.
	remoteWithSpecArgs := remoteWithCommand("npx", "github:user/repo", "--api-key", testRandom32)

	// Remote servers with args of one kind each: the args checks are for stdio
	// servers only, so these give no finding either.
	remoteWithSecretArgs := remoteWithCommand("npx", "--api-key", testRandom32)
	remoteWithGitHubArgs := remoteWithCommand("npx", "github:user/repo")
	remoteWithUVXArgs := remoteWithCommand("uvx", "--from", "git+https://github.com/u/r", "tool")

	// A stdio server with a secret URL field: the URL field is read only for
	// remote servers, so it gives no finding.
	stdioWithSecretURL := stdioServer("node", "server.js")
	stdioWithSecretURL.URL = discover.NewURL("https://mcp.example.com/sse?token=" + testRandom32)

	remoteWithArgs := remoteWithCommand("npx", "-y", "@scope/server@latest")

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
		// "--token" is a secret flag and "ghp_SECRETSECRET" has a token prefix and
		// 16 bytes, so MOAT-T4-002 fires on the args. T4-003 stays silent: the
		// charset check refuses the value as a package.
		{"unknown flag value is a token", stdioServer("npx", "--token", "ghp_SECRETSECRET", "pkg"), secretArgs},
		// A token-like scope or name is still a package: an attacker can publish
		// "@xoxo/server-filesystem". The finding fires. RedactArgs masks such an
		// arg (a part has a token prefix), so Related stays empty.
		{"scope with xox prefix", stdioServer("npx", "-y", "@xoxo/server-filesystem"), unpinnedAutoInstall("")},
		{"scope with eyj prefix", stdioServer("npx", "-y", "@eyjay/server-github"), unpinnedAutoInstall("")},
		// The token is also a literal secret under "--token", so T4-002 comes
		// first. The row still tests that T4-003 keeps Related empty.
		{"lower-case token value after unknown flag, masked by RedactArgs",
			stdioServer("npx", "--token", "ghp_secretsecret0123", "pkg"), slices.Concat(secretArgs, unpinned(""))},
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

		// MOAT-T4-002 args (stdio servers only; Key is empty)
		{"docker -e NAME=token", stdioServer("docker", "run", "-i", "-e", "GITHUB_TOKEN="+testGHToken, "image:1.2.3"), secretArgs},
		{"docker -eNAME=token", stdioServer("docker", "run", "-i", "-eGITHUB_TOKEN="+testGHToken, "image:1.2.3"), secretArgs},
		{"docker --env=NAME=token", stdioServer("docker", "run", "-i", "--env=GITHUB_TOKEN="+testGHToken, "image:1.2.3"), secretArgs},
		{"docker -e NAME=${VAR}", stdioServer("docker", "run", "-i", "-e", "GITHUB_TOKEN=${GITHUB_TOKEN}", "image:1.2.3"), nil},
		{"docker -e NAME only", stdioServer("docker", "run", "-i", "-e", "GITHUB_TOKEN", "image:1.2.3"), nil},
		{"docker -e neutral NAME with a short value", stdioServer("docker", "run", "-i", "-e", "LOG_LEVEL=debug", "image:1.2.3"), nil},
		{"--api-key random value", stdioServer("node", "server.js", "--api-key", testRandom32), secretArgs},
		{"--api-key=random value", stdioServer("node", "server.js", "--api-key="+testRandom32), secretArgs},
		{"--api-key ${VAR}", stdioServer("node", "server.js", "--api-key", "${API_KEY}"), nil},
		{"--api-key=${env:VAR}", stdioServer("node", "server.js", "--api-key=${env:API_KEY}"), nil},
		{"--api-key $VAR", stdioServer("node", "server.js", "--api-key", "$API_KEY"), nil},
		{"--api-key reference with a literal default", stdioServer("node", "server.js", "--api-key=${API_KEY:-"+testRandom32+"}"), secretArgs},
		// Precision: a plain 12 byte word is not token-like.
		{"--api-key plain word", stdioServer("node", "server.js", "--api-key", "changeme123"), nil},
		{"--otp 12 bytes is not token-like", stdioServer("node", "server.js", "--otp", "abcdef123456"), nil},
		{"--token with a token prefix of 8 bytes", stdioServer("node", "server.js", "--token", "ghp_abcd"), secretArgs},
		{"--key-file path", stdioServer("node", "server.js", "--key-file", "/home/u/"+testRandom32+".pem"), nil},
		{"--api-key followed by a flag", stdioServer("node", "server.js", "--api-key", "--verbose"), nil},
		{"bare token arg", stdioServer("node", "server.js", testGHToken), secretArgs},
		{"two secret args give one finding", stdioServer("node", "server.js", "--api-key", testRandom32, "--token="+testGHToken), secretArgs},
		{"URL arg with a query token", stdioServer("node", "server.js", "https://mcp.example.com/sse?token="+testRandom32), secretArgs},
		{"URL arg with a password", stdioServer("node", "server.js", "--url=https://user:hunter2@mcp.example.com/sse"), secretArgs},
		{"URL arg without a secret", stdioServer("node", "server.js", "https://mcp.example.com/sse?page=2"), nil},
		{"remote server with secret args gives none", remoteWithSecretArgs, nil},
		{"args secret comes after the env secret", withEnv(stdioServer("node", "server.js", "--api-key", testRandom32), "GITHUB_TOKEN", testGHToken),
			slices.Concat(secretEnv("GITHUB_TOKEN"), secretArgs)},

		// MOAT-T4-002 url (remote servers only; Key is empty)
		{"URL query token", remoteServer(discover.TransportHTTP, "https://mcp.example.com/sse?token="+testRandom32), secretURL},
		{"URL query api_key token prefix", remoteServer(discover.TransportSSE, "https://mcp.example.com/sse?api_key="+testGHToken), secretURL},
		{"URL password", remoteServer(discover.TransportHTTP, "https://user:hunter2@mcp.example.com/mcp"), secretURL},
		{"URL token as user name", remoteServer(discover.TransportHTTP, "https://"+testGHToken+"@mcp.example.com/mcp"), secretURL},
		{"URL random path segment", remoteServer(discover.TransportHTTP, "https://mcp.example.com/"+testRandom32+"/mcp"), secretURL},
		{"URL query token reference", remoteServer(discover.TransportHTTP, "https://mcp.example.com/sse?token=${TOKEN}"), nil},
		{"URL query token $VAR reference", remoteServer(discover.TransportHTTP, "https://mcp.example.com/sse?token=$TOKEN"), nil},
		{"URL password reference", remoteServer(discover.TransportHTTP, "https://user:${PW}@mcp.example.com/mcp"), nil},
		{"URL query without a secret", remoteServer(discover.TransportHTTP, "https://mcp.example.com/sse?page=2&mode=fast"), nil},
		{"URL UUID path segment", remoteServer(discover.TransportHTTP, "https://mcp.example.com/12345678-1234-1234-1234-123456789abc/mcp"), nil},
		{"URL plain user name", remoteServer(discover.TransportHTTP, "https://git@mcp.example.com/mcp"), nil},
		{"http URL with a query token gives both", remoteServer(discover.TransportHTTP, "http://mcp.example.com/sse?token="+testRandom32), slices.Concat(insecure, secretURL)},
		{"URL secret and header secret: headers first", withHeader(remoteServer(discover.TransportHTTP, "https://mcp.example.com/sse?token="+testRandom32), "X-Token", testGHToken),
			slices.Concat(secretHeader("X-Token"), secretURL)},
		{"stdio server ignores a secret URL field", stdioWithSecretURL, nil},

		// MOAT-T4-003 git, tarball and URL specs (stdio only; Related is empty)
		{"npx github: spec", stdioServer("npx", "github:user/repo"), unpinnedSpec},
		{"npx -y github: spec also gives T4-004", stdioServer("npx", "-y", "github:user/repo"), slices.Concat(unpinnedSpec, autoInstall)},
		{"npx github: spec pinned to a full commit", stdioServer("npx", "github:user/repo#"+testSHA), nil},
		{"npx github: spec pinned to an upper-case commit", stdioServer("npx", "github:user/repo#"+strings.ToUpper(testSHA)), nil},
		{"npx github: spec with a branch", stdioServer("npx", "github:user/repo#main"), unpinnedSpec},
		{"npx github: spec with a short commit", stdioServer("npx", "github:user/repo#"+testSHA[:7]), unpinnedSpec},
		{"npx github: spec with a 39 digit commit", stdioServer("npx", "github:user/repo#"+testSHA[:39]), unpinnedSpec},
		{"npx github: spec with a 41 digit commit", stdioServer("npx", "github:user/repo#"+testSHA+"a"), unpinnedSpec},
		{"npx github: spec with a non-hex 40 char commit", stdioServer("npx", "github:user/repo#"+strings.Repeat("g", 40)), unpinnedSpec},
		{"npx user/repo shorthand", stdioServer("npx", "user/repo"), unpinnedSpec},
		{"npx user/repo shorthand pinned", stdioServer("npx", "user/repo#"+testSHA), nil},
		{"npx git+https spec", stdioServer("npx", "git+https://github.com/u/r.git"), unpinnedSpec},
		{"npx git+https spec pinned", stdioServer("npx", "git+https://github.com/u/r.git#"+testSHA), nil},
		{"npx tarball URL", stdioServer("npx", "https://example.com/p.tgz"), unpinnedSpec},
		{"npx tarball URL with a hash fragment is never pinned", stdioServer("npx", "https://example.com/p.tgz#"+testSHA), unpinnedSpec},
		{"bunx github: spec", stdioServer("bunx", "github:user/repo"), unpinnedSpec},
		{"bunx github: spec pinned", stdioServer("bunx", "github:user/repo#"+testSHA), nil},
		{"uvx --from git+https", stdioServer("uvx", "--from", "git+https://github.com/u/r", "tool"), unpinnedSpec},
		{"uvx --from git+https pinned", stdioServer("uvx", "--from", "git+https://github.com/u/r@"+testSHA, "tool"), nil},
		{"uvx --from git+https with a tag", stdioServer("uvx", "--from", "git+https://github.com/u/r@v1.0.0", "tool"), unpinnedSpec},
		{"uvx --from git+https with a short commit", stdioServer("uvx", "--from", "git+https://github.com/u/r@"+testSHA[:7], "tool"), unpinnedSpec},
		{"uvx --from=git+https", stdioServer("uvx", "--from=git+https://github.com/u/r", "tool"), unpinnedSpec},
		{"uvx --from wheel URL", stdioServer("uvx", "--from", "https://example.com/p-1.0-py3-none-any.whl", "tool"), unpinnedSpec},
		{"pipx run --spec git+https", stdioServer("pipx", "run", "--spec", "git+https://github.com/u/r", "tool"), unpinnedSpec},
		{"pipx run --spec git+https pinned", stdioServer("pipx", "run", "--spec", "git+https://github.com/u/r@"+testSHA, "tool"), nil},
		{"remote server with a github: spec gives none", remoteWithGitHubArgs, nil},
		{"remote server with git+https uvx args gives none", remoteWithUVXArgs, nil},
		{"remote server with git spec and secret args gives none", remoteWithSpecArgs, nil},

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

	// A remote server cannot have args or T4-003/T4-004 findings, and a stdio
	// server cannot have T4-001 or a URL finding, so the full order needs two
	// servers. Together they cover every rule in the CheckConfig doc order.
	t.Run("remote: T4-001, then T4-002 env, headers, url", func(t *testing.T) {
		t.Parallel()
		s := remoteServer(discover.TransportHTTP, "http://user:hunter2@mcp.example.com/sse?token="+testRandom32)
		s.Env = discover.SecretMap{
			"B_TOKEN": discover.NewSecret(testGHToken),
			"A_TOKEN": discover.NewSecret(testGHToken),
		}
		s.Headers = discover.SecretMap{
			"X-Zed-Token":   discover.NewSecret(testGHToken),
			"Authorization": discover.NewSecret("Bearer " + testRandom32),
		}
		// Args are ignored on a remote server, even with a git spec and a secret.
		s.Command = "npx"
		s.Args = discover.NewArgs([]string{"-y", "github:user/repo", "--api-key", testRandom32})
		want := []wantFinding{
			{RuleID: RuleInsecureURL, Field: FieldURL},
			{RuleID: RulePlaintextSecret, Field: FieldEnv, Key: "A_TOKEN"},
			{RuleID: RulePlaintextSecret, Field: FieldEnv, Key: "B_TOKEN"},
			{RuleID: RulePlaintextSecret, Field: FieldHeaders, Key: "Authorization"},
			{RuleID: RulePlaintextSecret, Field: FieldHeaders, Key: "X-Zed-Token"},
			{RuleID: RulePlaintextSecret, Field: FieldURL},
		}
		if got := wantsOf(t, CheckConfig(s)); !reflect.DeepEqual(got, want) {
			t.Errorf("CheckConfig() = %+v, want %+v", got, want)
		}
	})

	t.Run("stdio: T4-002 env, headers, args, then T4-003, then T4-004", func(t *testing.T) {
		t.Parallel()
		// The spec is a git spec, so T4-003 keeps Related empty. The server
		// arg after it holds the args secret.
		s := stdioServer("npx", "-y", "github:user/repo", "--api-key", testRandom32)
		s.URL = discover.NewURL("http://mcp.example.com/sse?token=" + testRandom32) // ignored: not remote
		s.Env = discover.SecretMap{
			"B_TOKEN": discover.NewSecret(testGHToken),
			"A_TOKEN": discover.NewSecret(testGHToken),
		}
		s.Headers = discover.SecretMap{"Authorization": discover.NewSecret("Bearer " + testRandom32)}
		want := []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldEnv, Key: "A_TOKEN"},
			{RuleID: RulePlaintextSecret, Field: FieldEnv, Key: "B_TOKEN"},
			{RuleID: RulePlaintextSecret, Field: FieldHeaders, Key: "Authorization"},
			{RuleID: RulePlaintextSecret, Field: FieldArgs},
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs},
			{RuleID: RuleAutoInstall, Field: FieldArgs},
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

	// Fake secrets that pass the token test, so the args and URL checks fire.
	// The Canary* values are readable words and some stay below the entropy rule.
	const (
		argsToken  = "xK9mQ2vL7pR4tW8zB3nY6cH1jD5fG0sA" //nolint:gosec // G101: synthetic test token
		queryToken = "Zq8Lw3Rt6Yx1Vn5Mc9Hb2Kd7Pf4Sg0J"  //nolint:gosec // G101: synthetic test token
		specHost   = "host.example"
	)
	argsSecret := stdioServer("node", "server.js", "--api-key", argsToken)
	querySecret := remoteServer(discover.TransportHTTP, "https://"+host+"/sse?token="+queryToken)
	// The userinfo password of a tarball URL is a literal secret. T4-003 must
	// not name the spec, because the spec holds the password and the host.
	npxTarball := stdioServer("npx", "https://user:"+discovertest.CanaryArgs+"@"+specHost+"/x.tgz")
	uvxGit := stdioServer("uvx", "--from", "git+https://user:"+discovertest.CanaryArgs+"@"+specHost+"/u/r", "tool")

	secrets := append(discovertest.Canaries(), testGHToken, testRandom32, host, "abcdef123456", lowerToken, yesEnvCanary,
		argsToken, queryToken, specHost)

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
			// The URL holds a password and a query token.
			{RuleID: RulePlaintextSecret, Field: FieldURL},
		}},
		{"stdio", stdio, []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldEnv, Key: "API_KEY"},
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs, Related: "@scope/server"},
			{RuleID: RuleAutoInstall, Field: FieldArgs},
		}},
		// "--token" with a "ghp_" value is a literal secret, so T4-002 fires too.
		{"auto install with a secret-like flag value", autoInstallMasked, []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldArgs},
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs},
			{RuleID: RuleAutoInstall, Field: FieldArgs},
		}},
		{"auto install by env value", autoInstallEnv, []wantFinding{
			{RuleID: RuleAutoInstall, Field: FieldEnv, Key: "npm_config_yes"},
		}},
		{"misparsed token", misparsed, []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldArgs},
		}},
		{"secret-like package name", maskedName, []wantFinding{
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs},
		}},
		{"lower-case token taken as the package", lowerTokenServer, []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldArgs},
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs},
		}},
		// "--otp" is a known value flag, so T4-003 names "pkg". The value is a
		// "ghp_" token of 20 bytes under a secret flag name, so T4-002 fires.
		{"lower-case token after a known value flag", lowerTokenKnown, []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldArgs},
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs, Related: "pkg"},
		}},
		{"known value flag with a secret value", knownFlag, []wantFinding{
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs, Related: "pkg"},
		}},
		{"secret in the args", argsSecret, []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldArgs},
		}},
		{"secret in the URL query", querySecret, []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldURL},
		}},
		{"npx tarball URL with a password", npxTarball, []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldArgs},
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs},
		}},
		{"uvx --from git URL with a password", uvxGit, []wantFinding{
			{RuleID: RulePlaintextSecret, Field: FieldArgs},
			{RuleID: RuleUnpinnedPackage, Field: FieldArgs},
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
		// nopt reads only an exact "=false" as off. Any other value is on.
		{"--yes=0", stdioServer("npx", "--yes=0", "pkg"), fires},
		{"--yes= false", stdioServer("npx", "--yes= false", "pkg"), fires},
		{"--yes=false with a trailing space", stdioServer("npx", "--yes=false ", "pkg"), fires},
		// nopt strips each "no-" and flips the result.
		{"--no-yes=false", stdioServer("npx", "--no-yes=false", "pkg"), fires},
		{"--no-yes false", stdioServer("npx", "--no-yes", "false", "pkg"), fires},
		{"--NO-yes false", stdioServer("npx", "--NO-yes", "false", "pkg"), fires},
		{"--no-no-yes", stdioServer("npx", "--no-no-yes", "pkg"), fires},
		{"--no-yes=null", stdioServer("npx", "--no-yes=null", "pkg"), fires},
		// A lone "-" is the value of a String option, so a later -y counts.
		{"--tag - then -y", stdioServer("npx", "--tag", "-", "-y", "pkg"), fires},
		{"-c - then -y", stdioServer("npx", "-p", "@evil/pkg", "-c", "-", "-y"), fires},
		// npm's shorthand "no" is --no-yes, so null and false after it turn yes on.
		{"--no=null", stdioServer("npx", "--no=null", "@scope/server@1.2.3"), fires},
		{"--no false", stdioServer("npx", "--no", "false", "pkg"), fires},
		{"-no false", stdioServer("npx", "-no", "false", "pkg"), fires},
		// npx drops a removed option and the next argument, and --reg is an alias
		// of --registry, so -p does not take the -y in npm.
		{"--node-arg -p -y", stdioServer("npx", "--node-arg", "-p", "-y", "@scope/server@1.2.3"), fires},
		{"--reg -p --y", stdioServer("npx", "--reg", "-p", "--y", "@scope/server@1.2.3"), fires},
		// npx reads a bare "-" as a flag and goes on.
		{"- then -y", stdioServer("npx", "-", "-y", "@scope/server@1.2.3"), fires},
		// "--" can be the value of -p, so the walk goes on past it.
		{"-p -- then -y", stdioServer("npx", "-p", "--", "-y", "bin"), fires},
		// nopt expands a flag made only of one-letter shorthands, even with "--".
		{"--qy", stdioServer("npx", "--qy", "pkg"), fires},
		{"--yy", stdioServer("npx", "--yy", "pkg"), fires},
		{"--ny", stdioServer("npx", "--ny", "pkg"), fires},
		{"--dy", stdioServer("npx", "--dy", "pkg"), fires},
		// npx skips the yes flag as the value of --call, so "false" is the
		// command and not the value of --no-no-yes.
		{"--call --no-no-yes false", stdioServer("npx", "--call", "--no-no-yes", "false"), fires},
		// npx expands -q to "--loglevel warn", and "warn" becomes the command.
		{"--loglevel -q -y", stdioServer("npx", "--loglevel", "-q", "-y"), fires},
		{"cmd /k wrapper", stdioServer("cmd", "/k", "npx", "-y", "pkg"), fires},

		// An env entry turns the yes option on unless its value is "false" or
		// "0" after trimming ASCII white space. The key matches in any ASCII letter
		// case.
		{"env npm_config_yes=true", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "true"), firesEnv("npm_config_yes")},
		{"env NPM_CONFIG_YES=1", withEnv(stdioServer("npx", "pkg"), "NPM_CONFIG_YES", "1"), firesEnv("NPM_CONFIG_YES")},
		// npm reads "null" as unset. That still replaces the scan's
		// npm_config_yes=false, so npx installs with no TTY.
		// npm skips an empty value, but inspect counts the entry as set and
		// adds no npm_config_yes=false, so the scan installs too.
		{"env npm_config_yes empty", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", ""), firesEnv("npm_config_yes")},
		{"env npm_config_yes=null", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "null"), firesEnv("npm_config_yes")},
		// npm reads white space only as on.
		{"env npm_config_yes blank", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "  "), firesEnv("npm_config_yes")},
		// npm does not trim U+0085, so it reads this value as on.
		{"env npm_config_yes=false and NEL", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "false\u0085"), firesEnv("npm_config_yes")},
		{"env npm_config_yes=true, github spec", withEnv(stdioServer("npx", "github:evil/pkg"), "npm_config_yes", "true"), firesEnv("npm_config_yes")},

		// Fail-closed: npm reads -y as the value of --registry, but the walk
		// checks every flag-like argument before the command.
		{"-y as the value of --registry", stdioServer("npx", "--registry", "-y", "pkg"), fires},
		{"-y as the value of --shell", stdioServer("npx", "--shell", "-y", "pkg"), fires},
		{"-y after the -p spec is a server arg", stdioServer("npx", "-p", "pkg", "bin", "-y"), nil},
		{"--yes=false", stdioServer("npx", "--yes=false", "pkg"), nil},
		{"--no-yes", stdioServer("npx", "--no-yes", "pkg"), nil},
		{"--dd is a group with no y or n", stdioServer("npx", "--dd", "pkg"), nil},
		// npm exec validates its config, which reads "0" as false.
		{"env npm_config_yes=0", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "0"), nil},
		{"--no-yes true", stdioServer("npx", "--no-yes", "true", "pkg"), nil},
		{"--ye=false, a prefix of --yes", stdioServer("npx", "--ye=false", "pkg"), nil},
		{"cmd /c wrapper, -y after the command", stdioServer("cmd", "/c", "npx", "-p", "pkg", "bin", "-y"), nil},
		{"env npm_config_yes=false", withEnv(stdioServer("npx", "pkg"), "npm_config_yes", "false"), nil},
		{"env NPM_CONFIG_YES padded false", withEnv(stdioServer("npx", "pkg"), "NPM_CONFIG_YES", " false "), nil},
		// npm matches env names with ASCII case folding only, so it ignores
		// U+017F (long s). This entry is not the yes option.
		{"env look-alike name", withEnv(stdioServer("npx", "pkg"), "npm_config_ye\u017f", "true"), nil},
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

// findingOutputs renders f in every common output form, keyed by the form.
func findingOutputs(t testing.TB, f Finding) map[string]string {
	t.Helper()
	js, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal(%s) error = %v", f.RuleID, err)
	}
	return map[string]string{
		"%v":   fmt.Sprintf("%v", f),
		"%+v":  fmt.Sprintf("%+v", f),
		"%#v":  fmt.Sprintf("%#v", f),
		"json": string(js),
	}
}

// assertFindingNoLeak fails the test when f, in any common output form,
// holds one of secrets.
func assertFindingNoLeak(t *testing.T, f Finding, secrets ...string) {
	t.Helper()
	for form, out := range findingOutputs(t, f) {
		discovertest.AssertNoLeak(t, f.Server+"/"+f.RuleID+" "+form, out, secrets...)
	}
}
