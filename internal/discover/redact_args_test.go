package discover_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// Test values for the RedactArgs cases.
const (
	argEnv    = discovertest.CanaryEnv
	argHeader = discovertest.CanaryHeader
	argURL    = discovertest.CanaryURL
	argMask   = discover.Mask

	// argShort is a secret that is too short to look like a token, so only
	// the shape rules can mask it. The canaries above are long enough that
	// the token rules alone mask them; argShort checks the shape rules.
	argShort = "pw9Zq"
)

// redactArgsCase is one RedactArgs input and the output it must give.
type redactArgsCase struct {
	name string
	args []string
	want []string
}

// runRedactArgsCases runs each case as a parallel subtest. For each case it
// checks the output, that no canary and no short secret leaks, and that
// RedactArgs does not change its input.
func runRedactArgsCases(t *testing.T, tests []redactArgsCase) {
	t.Helper()
	secrets := append(discovertest.Canaries(), argShort)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Keep a copy, to check that RedactArgs does not change its input.
			before := slices.Clone(tt.args)
			got := discover.RedactArgs(tt.args)

			discovertest.AssertNoLeak(t, "RedactArgs", strings.Join(got, " "), secrets...)
			if !slices.Equal(got, tt.want) {
				t.Errorf("RedactArgs(%q) = %q, want %q", tt.args, got, tt.want)
			}
			if !slices.Equal(tt.args, before) {
				t.Errorf("RedactArgs changed its input: now %q, was %q", tt.args, before)
			}
			if got == nil {
				t.Errorf("RedactArgs(%q) = nil, want a non-nil slice", tt.args)
			}
		})
	}
}

// TestRedactArgsFlagValues checks that the value of a secret-like, header or
// user flag is always masked, and that a flag is never taken as the value of
// the flag before it.
func TestRedactArgsFlagValues(t *testing.T) {
	t.Parallel()
	runRedactArgsCases(t, []redactArgsCase{
		// Secret-like flags: the next argument or the part after "=".
		{
			name: "secret flag then value",
			args: []string{"--token", argShort},
			want: []string{"--token", argMask},
		},
		{
			name: "secret flag with equals",
			args: []string{"--api-key=" + argEnv},
			want: []string{"--api-key=" + argMask},
		},
		{
			name: "secret flag with empty equals value",
			args: []string{"--password="},
			want: []string{"--password=" + argMask},
		},
		{
			name: "single-dash secret flag with underscores",
			args: []string{"-API_KEY", argShort},
			want: []string{"-API_KEY", argMask},
		},
		{
			name: "camel case secret flag",
			args: []string{"--githubToken", argShort},
			want: []string{"--githubToken", argMask},
		},
		{
			name: "value after a secret flag that does not parse as a flag",
			args: []string{"--secret", "-" + argShort + "!"},
			want: []string{"--secret", argMask},
		},
		{
			name: "lone dash after a secret flag is a value",
			args: []string{"--token", "-"},
			want: []string{"--token", argMask},
		},
		{
			name: "single-dash word that is not secret-like is a value",
			args: []string{"--password", "-" + argShort},
			want: []string{"--password", argMask},
		},
		{
			name: "secret flag as the last argument",
			args: []string{"--token"},
			want: []string{"--token"},
		},
		{
			name: "location flag value is masked, even a path or a URL",
			args: []string{"--key-file", "/etc/ssl/key.pem", "--token-url=https://h/?code=" + argURL},
			want: []string{"--key-file", argMask, "--token-url=" + argMask},
		},

		// Header flags: the whole header line is masked, name included.
		{
			name: "long header flag with authorization",
			args: []string{"--header", "Authorization: Bearer " + argShort},
			want: []string{"--header", argMask},
		},
		{
			name: "short header flag with an api key header",
			args: []string{"-H", "X-Api-Key: " + argShort},
			want: []string{"-H", argMask},
		},
		{
			name: "header flag with equals",
			args: []string{"--header=Authorization: Bearer " + argShort},
			want: []string{"--header=" + argMask},
		},
		{
			name: "headers flag with JSON",
			args: []string{"--headers", `{"Authorization":"` + argShort + `"}`},
			want: []string{"--headers", argMask},
		},

		// User flags (curl): the whole value is masked.
		{
			name: "user flag with user and password",
			args: []string{"-u", "admin:" + argShort},
			want: []string{"-u", argMask},
		},
		{
			name: "user flag with a key and an empty password",
			args: []string{"-u", argShort + ":"},
			want: []string{"-u", argMask},
		},
		{
			name: "user flag with equals",
			args: []string{"--user=admin:" + argShort},
			want: []string{"--user=" + argMask},
		},

		// A flag is never the value of the flag before it.
		{
			name: "boolean secret-like flag does not use up the mask",
			args: []string{"--no-auth", "--token", argShort},
			want: []string{"--no-auth", "--token", argMask},
		},
		{
			name: "single-dash secret-like flag after a boolean flag",
			args: []string{"--no-auth", "-token", argShort},
			want: []string{"--no-auth", "-token", argMask},
		},
		{
			name: "header flag after a boolean flag",
			args: []string{"--no-auth", "-H", "Authorization: Bearer " + argHeader},
			want: []string{"--no-auth", "-H", argMask},
		},
		{
			name: "secret-like flag before another secret flag",
			args: []string{"--oauth", "--client-secret", argShort},
			want: []string{"--oauth", "--client-secret", argMask},
		},
		{
			name: "header flag before a secret flag",
			args: []string{"-H", "--api-key", argShort},
			want: []string{"-H", "--api-key", argMask},
		},
		{
			name: "user flag before a secret flag",
			args: []string{"-u", "--token", argShort},
			want: []string{"-u", "--token", argMask},
		},
		{
			name: "plain flag after a secret flag is shown",
			args: []string{"--token", "--port", "8080"},
			want: []string{"--token", "--port", "8080"},
		},

		// A flag with a name that looks like a token is masked whole.
		{
			name: "token glued to a short flag",
			args: []string{"-p" + argEnv},
			want: []string{argMask},
		},
		{
			name: "token that starts with two dashes after a secret flag",
			args: []string{"--password", "--ghp_" + argShort},
			want: []string{"--password", argMask},
		},
	})
}

// TestRedactArgsSecretNames checks which flag and variable names are
// secret-like.
func TestRedactArgsSecretNames(t *testing.T) {
	t.Parallel()
	runRedactArgsCases(t, []redactArgsCase{
		// Short forms match as a whole word.
		{
			name: "pass as a variable suffix",
			args: []string{"-e", "DB_PASS=" + argShort, "SMTP_PASS=" + argShort},
			want: []string{"-e", "DB_PASS=" + argMask, "SMTP_PASS=" + argMask},
		},
		{
			name: "pass as a flag name and a camel case word",
			args: []string{"--pass", argShort, "--dbPass=" + argShort, "--DBPass=" + argShort},
			want: []string{"--pass", argMask, "--dbPass=" + argMask, "--DBPass=" + argMask},
		},
		{
			name: "jwt and pat as whole words",
			args: []string{"--jwt", argShort, "--github-pat", argShort, "GITHUB_PAT=" + argShort, "--githubPat=" + argShort},
			want: []string{"--jwt", argMask, "--github-pat", argMask, "GITHUB_PAT=" + argMask, "--githubPat=" + argMask},
		},

		// Short forms also match at the end of an all-caps glued word.
		{
			name: "all-caps glued pass",
			args: []string{"DBPASS=" + argShort, "PGPASS=" + argShort, "--MYJWT", argShort},
			want: []string{"DBPASS=" + argMask, "PGPASS=" + argMask, "--MYJWT", argMask},
		},

		// Words that only contain a short form are not secret-like.
		{
			name: "words that contain pass",
			args: []string{"--bypass", "x", "--compass", "north", "--passthrough", "on"},
			want: []string{"--bypass", "x", "--compass", "north", "--passthrough", "on"},
		},
		{
			name: "path, patch and pattern are not pat",
			args: []string{"--path", "src", "--patch", "fix.diff", "--pattern", "go", "PATH=bin"},
			want: []string{"--path", "src", "--patch", "fix.diff", "--pattern", "go", "PATH=bin"},
		},
		{
			name: "lower case h is help, not a header flag",
			args: []string{"-h", "server"},
			want: []string{"-h", "server"},
		},
	})
}

// TestRedactArgsMasksUnknownShapes checks that values with no safe shape are
// masked. Each case is a shape that a denylist of secret shapes missed.
func TestRedactArgsMasksUnknownShapes(t *testing.T) {
	t.Parallel()
	runRedactArgsCases(t, []redactArgsCase{
		// Config and connection text.
		{
			name: "JSON config after a plain flag",
			args: []string{"--config", `{"apiKey":"` + argShort + `"}`},
			want: []string{"--config", argMask},
		},
		{
			name: "DSN with user and password",
			args: []string{"--dsn", "user:" + argShort + "@tcp(db:3306)/app"},
			want: []string{"--dsn", argMask},
		},
		{
			name: "user and password before a host",
			args: []string{"admin:" + argShort + "@db.example.com"},
			want: []string{argMask},
		},
		{
			name: "semicolon list with a password",
			args: []string{"foo;Password=" + argShort},
			want: []string{argMask},
		},
		{
			name: "connection string with a plain first key",
			args: []string{"Server=db;Password=" + argShort + ";Database=app"},
			want: []string{"Server=" + argMask},
		},
		{
			name: "connection string with a secret first key",
			args: []string{"Password=ab;" + argShort + "=d"},
			want: []string{"Password=" + argMask},
		},
		{
			name: "value with a second equals sign",
			args: []string{"--env=X=a=" + argShort},
			want: []string{"--env=X=" + argMask},
		},

		// URLs keep their shape and lose the secret parts (see RedactURL).
		{
			name: "mcp-remote URL with a token in the query",
			args: []string{"-y", "mcp-remote", "https://host/sse?api_key=" + argURL},
			want: []string{"-y", "mcp-remote", "https://host/sse?api_key=" + argMask},
		},
		{
			name: "URL with userinfo",
			args: []string{"https://u:" + argShort + "@host/mcp"},
			want: []string{"https://" + argMask + "@host/mcp"},
		},
		{
			name: "variable with a URL and a semicolon query part",
			args: []string{"MCP_URL=https://h/x?a=1;sig=" + argShort},
			want: []string{"MCP_URL=https://h/x?a=" + argMask + ";sig=" + argMask},
		},
		{
			name: "variable with a URL and a matrix parameter",
			args: []string{"SERVER_URL=https://h/x;" + argShort},
			want: []string{"SERVER_URL=https://h/x;" + argMask},
		},
		{
			name: "variable with a URL with userinfo",
			args: []string{"API_URL=https://u:" + argURL + "@host/"},
			want: []string{"API_URL=https://" + argMask + "@host/"},
		},
		{
			name: "scheme-relative URL with userinfo",
			args: []string{"//u:" + argShort + "@host/mcp"},
			want: []string{"//" + argMask + "@host/mcp"},
		},
		{
			name: "scheme-relative URL with a query token",
			args: []string{"//host/sse?key=" + argShort},
			want: []string{"//host/sse?key=" + argMask},
		},

		// Tokens and auth values.
		{
			name: "bare GitHub token",
			args: []string{"ghp_" + argShort},
			want: []string{argMask},
		},
		{
			name: "bare canary tokens",
			args: []string{argEnv, argHeader, argURL},
			want: []string{argMask, argMask, argMask},
		},
		{
			name: "bearer and basic values",
			args: []string{"Bearer " + argShort, "Bearer\t" + argShort, "basic " + argShort},
			want: []string{argMask, argMask, argMask},
		},
		{
			name: "header lines",
			args: []string{"Authorization: Bearer " + argShort, "Cookie: sid=" + argShort, "x-auth-token:" + argShort},
			want: []string{argMask, argMask, argMask},
		},
		{
			name: "secret variable",
			args: []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN=" + argShort, "ghcr.io/github/github-mcp-server"},
			want: []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN=" + argMask, "ghcr.io/github/github-mcp-server"},
		},
		{
			name: "env flag with equals and a secret variable",
			args: []string{"--env=API_KEY=" + argShort},
			want: []string{"--env=API_KEY=" + argMask},
		},
		{
			name: "path with a token segment",
			args: []string{"/data/ghp_" + argShort + "/x"},
			want: []string{"/data/" + argMask + "/x"},
		},

		// Bytes that are not printable ASCII.
		{
			name: "non-ASCII, control and bidi characters",
			args: []string{"pässword", "a\x1bb", "x\u202ey", "/home/\u202e/x"},
			want: []string{argMask, argMask, argMask, "/home/" + argMask + "/x"},
		},
	})
}

// TestRedactArgsShowsSafeShapes checks that common MCP server arguments with
// nothing to hide are shown as written.
func TestRedactArgsShowsSafeShapes(t *testing.T) {
	t.Parallel()
	runRedactArgsCases(t, []redactArgsCase{
		// Real MCP server commands (the command itself is not in Args).
		{
			name: "npx package and a path",
			args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/home/me/proj"},
			want: []string{"-y", "@modelcontextprotocol/server-filesystem", "/home/me/proj"},
		},
		{
			name: "uvx package and a relative path",
			args: []string{"mcp-server-git", "--repository", "./repo"},
			want: []string{"mcp-server-git", "--repository", "./repo"},
		},
		{
			name: "node script and a port",
			args: []string{"dist/index.js", "--port", "8080", "--verbose", "-v"},
			want: []string{"dist/index.js", "--port", "8080", "--verbose", "-v"},
		},
		{
			name: "python module",
			args: []string{"-m", "server"},
			want: []string{"-m", "server"},
		},
		{
			name: "docker image names and env names",
			args: []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN", "-e", "LOG_LEVEL=debug", "mcp/github", "ghcr.io/github/github-mcp-server"},
			want: []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN", "-e", "LOG_LEVEL=debug", "mcp/github", "ghcr.io/github/github-mcp-server"},
		},

		// Plain tokens.
		{
			name: "host and port, package versions",
			args: []string{"localhost:8080", "pkg@1.2.3", "@scope/pkg@latest", "1.5"},
			want: []string{"localhost:8080", "pkg@1.2.3", "@scope/pkg@latest", "1.5"},
		},
		{
			name: "flag with a plain value after equals",
			args: []string{"--log-level=debug", "--root=/srv/data"},
			want: []string{"--log-level=debug", "--root=/srv/data"},
		},
		{
			name: "URL without credentials",
			args: []string{"--url", "https://example.com/mcp"},
			want: []string{"--url", "https://example.com/mcp"},
		},

		// Path shapes.
		{
			name: "home, parent and Windows paths",
			args: []string{"~/keys/a.pem", "../x", `C:\Users\me\a.txt`, "C:/x"},
			want: []string{"~/keys/a.pem", "../x", `C:\Users\me\a.txt`, "C:/x"},
		},

		// Arguments with nothing in them.
		{
			name: "dash, double dash and empty arguments",
			args: []string{"-", "--", ""},
			want: []string{"-", "--", ""},
		},
		{
			name: "no arguments",
			args: []string{},
			want: []string{},
		},
	})
}

// TestRedactArgsNil checks that nil input gives nil, not an empty slice.
func TestRedactArgsNil(t *testing.T) {
	t.Parallel()
	if got := discover.RedactArgs(nil); got != nil {
		t.Errorf("RedactArgs(nil) = %q, want nil", got)
	}
}

// TestRedactArgsReturnsCopy checks that the result does not share memory
// with the input: changing the result must not change args.
func TestRedactArgsReturnsCopy(t *testing.T) {
	t.Parallel()
	args := []string{"-y", "pkg"}
	got := discover.RedactArgs(args)
	got[0] = "changed"
	if args[0] != "-y" {
		t.Errorf("changing the result changed the input: args[0] = %q", args[0])
	}
}

// TestRedactArgsKnownLimits records cases that RedactArgs gets wrong today.
// The RedactArgs doc comment lists them. If a future change fixes one,
// update this test on purpose.
func TestRedactArgsKnownLimits(t *testing.T) {
	t.Parallel()

	// weak is a secret with a plain shape: a short word.
	const weak = "hunter2"

	tests := []redactArgsCase{
		// Misses: a secret with a plain shape is shown.
		{
			name: "plain word after a flag that is not secret-like",
			args: []string{"--db", weak},
			want: []string{"--db", weak},
		},
		{
			name: "positional plain word",
			args: []string{weak},
			want: []string{weak},
		},
		{
			name: "short path segment",
			args: []string{"/run/" + weak + "/x"},
			want: []string{"/run/" + weak + "/x"},
		},
		{
			name: "short value glued to a short flag",
			args: []string{"-p" + weak},
			want: []string{"-p" + weak},
		},
		{
			name: "token split by slashes into short pieces",
			args: []string{"AbCdEfGh/IjKlMnOp"},
			want: []string{"AbCdEfGh/IjKlMnOp"},
		},
		{
			name: "secret value that starts with two dashes",
			args: []string{"--password", "--" + weak},
			want: []string{"--password", "--" + weak},
		},
		{
			name: "lower-case glued short form",
			args: []string{"--dbpass", weak},
			want: []string{"--dbpass", weak},
		},

		// False positives: a value that is not secret is masked.
		{
			name: "boolean secret-like flag masks the next positional argument",
			args: []string{"--no-auth", "server.js"},
			want: []string{"--no-auth", argMask},
		},
		{
			name: "docker user flag",
			args: []string{"-u", "1000:1000"},
			want: []string{"-u", argMask},
		},
		{
			name: "glob, list and spaces",
			args: []string{"--pattern", "*.go", "a,b", "/Users/me/Library/Application Support/x"},
			want: []string{"--pattern", argMask, argMask, "/Users/me/Library/" + argMask + "/x"},
		},
		{
			name: "long readable segment",
			args: []string{"@modelcontextprotocol/server-with-a-very-long-name-here"},
			want: []string{"@modelcontextprotocol/" + argMask},
		},
		{
			name: "git SSH address",
			args: []string{"git@github.com:org/repo"},
			want: []string{argMask},
		},
		{
			name: "image with a secret-like word before a colon",
			args: []string{"keycloak:latest"},
			want: []string{argMask},
		},
		{
			name: "all-caps word that ends in a short form",
			args: []string{"BYPASS=1"},
			want: []string{"BYPASS=" + argMask},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := discover.RedactArgs(tt.args)
			if !slices.Equal(got, tt.want) {
				t.Errorf("RedactArgs(%q) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

// FuzzRedactArgs checks that RedactArgs never panics, never changes its
// input, keeps the length, gives only printable ASCII, and always masks the
// value after "--token", whatever comes before and after it. The fuzz
// strings are split on NUL bytes into arguments.
func FuzzRedactArgs(f *testing.F) {
	f.Add("", "")
	f.Add("--no-auth", "server.js")
	f.Add("-H\x00--header", "-u\x00a:b")
	f.Add("Server=x;Password=y", "Bearer\tz")
	f.Add("--key-file\x00/p", "//u:p@h/?k=v")
	f.Add("-\x00--", "-e\x00TOKEN=x")
	f.Add(`{"a":"b"}`, "u:p@tcp(h)/db")
	f.Add("C:\\x\\y", "~/a/b\x00x\u202ey")

	f.Fuzz(func(t *testing.T, before, after string) {
		args := strings.Split(before, "\x00")
		tokenAt := len(args)
		args = append(args, "--token", argEnv)
		args = append(args, strings.Split(after, "\x00")...)
		input := slices.Clone(args)

		got := discover.RedactArgs(args)

		if !slices.Equal(args, input) {
			t.Fatalf("RedactArgs changed its input: now %q, was %q", args, input)
		}
		if len(got) != len(args) {
			t.Fatalf("len(RedactArgs(%q)) = %d, want %d", args, len(got), len(args))
		}
		if got[tokenAt] != "--token" || got[tokenAt+1] != argMask {
			t.Fatalf("RedactArgs(%q)[%d:%d] = %q, want [--token %s]",
				args, tokenAt, tokenAt+2, got[tokenAt:tokenAt+2], argMask)
		}
		for i, s := range got {
			if !isPrintableASCII(s) {
				t.Fatalf("RedactArgs(%q)[%d] = %q, want only printable ASCII", args, i, s)
			}
		}
		// The canary can reach the output only if the fuzz strings hold it.
		if !strings.Contains(before+after, argEnv) &&
			strings.Contains(strings.Join(got, "\x00"), argEnv) {
			t.Fatalf("RedactArgs(%q) = %q leaks the canary", args, got)
		}
	})
}

// isPrintableASCII reports whether every byte of s is printable ASCII (0x20
// to 0x7e). It is true for "".
func isPrintableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ExampleRedactArgs shows a typical mcp-remote command with a token in the
// URL and in a header.
func ExampleRedactArgs() {
	args := []string{"-y", "mcp-remote", "https://host/sse?api_key=abc", "--header", "Authorization: Bearer abc"}
	fmt.Println(discover.RedactArgs(args))
	// Output: [-y mcp-remote https://host/sse?api_key=******** --header ********]
}
