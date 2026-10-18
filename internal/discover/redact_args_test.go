package discover_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// TestRedactArgs checks masked and kept arguments, and that no canary
// value reaches the output.
func TestRedactArgs(t *testing.T) {
	t.Parallel()

	const (
		env    = discovertest.CanaryEnv
		header = discovertest.CanaryHeader
		inURL  = discovertest.CanaryURL
		mask   = discover.Mask
	)

	tests := []struct {
		name string
		args []string
		want []string
	}{
		// Credentials found in real MCP configs.
		{
			name: "mcp-remote URL with a token in the query",
			args: []string{"-y", "mcp-remote", "https://host/sse?api_key=" + inURL},
			want: []string{"-y", "mcp-remote", "https://host/sse?api_key=" + mask},
		},
		{
			name: "URL with userinfo",
			args: []string{"https://u:" + inURL + "@host/mcp"},
			want: []string{"https://" + mask + "@host/mcp"},
		},
		{
			name: "secret flag then value",
			args: []string{"--token", env},
			want: []string{"--token", mask},
		},
		{
			name: "secret flag with equals",
			args: []string{"--api-key=" + env},
			want: []string{"--api-key=" + mask},
		},
		{
			name: "secret flag with empty equals value",
			args: []string{"--password="},
			want: []string{"--password=" + mask},
		},
		{
			name: "single dash secret flag with underscores",
			args: []string{"-API_KEY", env},
			want: []string{"-API_KEY", mask},
		},
		{
			name: "camel case secret flag",
			args: []string{"--githubToken", env},
			want: []string{"--githubToken", mask},
		},
		{
			name: "value after a secret flag is masked if it does not parse as a flag",
			args: []string{"--secret", "-" + env + "!"},
			want: []string{"--secret", mask},
		},
		{
			name: "lone dash after a secret flag is a value",
			args: []string{"--token", "-"},
			want: []string{"--token", mask},
		},

		// A flag is never the value of the flag before it.
		{
			name: "boolean secret-like flag does not use up the mask",
			args: []string{"--no-auth", "--token", env},
			want: []string{"--no-auth", "--token", mask},
		},
		{
			name: "single-dash secret-like flag after a boolean flag",
			args: []string{"--no-auth", "-token", env},
			want: []string{"--no-auth", "-token", mask},
		},
		{
			name: "one-letter flag after a boolean flag",
			args: []string{"--no-auth", "-H", "Authorization: Bearer " + header},
			want: []string{"--no-auth", "-H", "Authorization: " + mask},
		},
		{
			name: "secret value that starts with a dash is masked",
			args: []string{"--password", "-" + env},
			want: []string{"--password", mask},
		},
		{
			name: "secret-like flag before another secret flag",
			args: []string{"--oauth", "--client-secret", env},
			want: []string{"--oauth", "--client-secret", mask},
		},
		{
			name: "header flag before a secret flag",
			args: []string{"-H", "--api-key", header},
			want: []string{"-H", "--api-key", mask},
		},
		{
			name: "user flag before a secret flag",
			args: []string{"-u", "--token", env},
			want: []string{"-u", "--token", mask},
		},
		{
			name: "plain flag after a secret flag is kept",
			args: []string{"--token", "--port", "8080"},
			want: []string{"--token", "--port", "8080"},
		},

		// Short forms match only as a whole word.
		{
			name: "pass as a variable suffix",
			args: []string{"-e", "DB_PASS=" + env, "SMTP_PASS=" + env},
			want: []string{"-e", "DB_PASS=" + mask, "SMTP_PASS=" + mask},
		},
		{
			name: "pass as a flag name",
			args: []string{"--pass", env, "--dbPass=" + env},
			want: []string{"--pass", mask, "--dbPass=" + mask},
		},
		{
			name: "jwt and pat as whole words",
			args: []string{"--jwt", env, "--github-pat", env, "GITHUB_PAT=" + env, "--githubPat=" + env},
			want: []string{"--jwt", mask, "--github-pat", mask, "GITHUB_PAT=" + mask, "--githubPat=" + mask},
		},

		// Location endings keep only a path or a URL.
		{
			name: "location variable with a value that is not a location",
			args: []string{"SECRET_URL=" + env},
			want: []string{"SECRET_URL=" + mask},
		},
		{
			name: "location flag with a value that is not a location",
			args: []string{"--token-url", env, "--key-file=" + env},
			want: []string{"--token-url", mask, "--key-file=" + mask},
		},
		{
			name: "location flag with a URL redacts the URL",
			args: []string{"--token-url", "https://u:" + inURL + "@h/"},
			want: []string{"--token-url", "https://" + mask + "@h/"},
		},

		// curl-style user flag.
		{
			name: "user flag with user and password",
			args: []string{"-u", "admin:" + env},
			want: []string{"-u", "admin:" + mask},
		},
		{
			name: "user flag with equals",
			args: []string{"--user=admin:" + env},
			want: []string{"--user=admin:" + mask},
		},
		{
			name: "user flag masks after the first colon only",
			args: []string{"--user", "admin:" + env + ":x"},
			want: []string{"--user", "admin:" + mask},
		},

		// ";" lists of Key=Value parts.
		{
			name: "connection string with a password",
			args: []string{"Server=db;Password=" + env + ";Database=app"},
			want: []string{"Server=db;Password=" + mask + ";Database=app"},
		},
		{
			name: "connection string after a plain flag, key in any case",
			args: []string{"--conn", "Data Source=db;User ID=sa;PWD=" + env + ";"},
			want: []string{"--conn", "Data Source=db;User ID=sa;PWD=" + mask + ";"},
		},
		{
			name: "connection string with a semicolon in the password",
			args: []string{"--dsn=Server=db;Password=ab;" + env},
			want: []string{"--dsn=Server=db;Password=" + mask + ";" + mask},
		},

		// Auth schemes and scheme-relative URLs.
		{
			name: "bearer with a tab",
			args: []string{"Bearer\t" + header},
			want: []string{"Bearer\t" + mask},
		},
		{
			name: "bearer in upper case with two spaces",
			args: []string{"BEARER  " + header},
			want: []string{"BEARER  " + mask},
		},
		{
			name: "scheme-relative URL with userinfo",
			args: []string{"//u:" + inURL + "@host/mcp"},
			want: []string{"//" + mask + "@host/mcp"},
		},
		{
			name: "scheme-relative URL with a query token",
			args: []string{"//host/sse?key=" + inURL},
			want: []string{"//host/sse?key=" + mask},
		},
		{
			name: "secret flag as the last argument",
			args: []string{"--token"},
			want: []string{"--token"},
		},
		{
			name: "long header flag with authorization",
			args: []string{"--header", "Authorization: Bearer " + header},
			want: []string{"--header", "Authorization: " + mask},
		},
		{
			name: "short header flag with an api key header",
			args: []string{"-H", "X-Api-Key: " + header},
			want: []string{"-H", "X-Api-Key: " + mask},
		},
		{
			name: "header flag masks the value of any header",
			args: []string{"-H", "X-Custom:" + header},
			want: []string{"-H", "X-Custom:" + mask},
		},
		{
			name: "header flag with equals",
			args: []string{"--header=Authorization: Bearer " + header},
			want: []string{"--header=Authorization: " + mask},
		},
		{
			name: "header flag value without a colon",
			args: []string{"--header", header},
			want: []string{"--header", mask},
		},
		{
			name: "header flag value with an invalid header name",
			args: []string{"--headers", `{"Authorization":"` + header + `"}`},
			want: []string{"--headers", mask},
		},
		{
			name: "docker env with a token",
			args: []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN=" + env, "ghcr.io/github/github-mcp-server"},
			want: []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN=" + mask, "ghcr.io/github/github-mcp-server"},
		},
		{
			name: "env flag with equals and a secret variable",
			args: []string{"--env=API_KEY=" + env},
			want: []string{"--env=API_KEY=" + mask},
		},
		{
			name: "variable with a non-secret name and a URL value",
			args: []string{"API_URL=https://u:" + inURL + "@host/"},
			want: []string{"API_URL=https://" + mask + "@host/"},
		},
		{
			name: "standalone bearer value",
			args: []string{"Bearer " + header},
			want: []string{"Bearer " + mask},
		},
		{
			name: "standalone basic value in lower case",
			args: []string{"basic " + header},
			want: []string{"basic " + mask},
		},
		{
			name: "standalone authorization header line",
			args: []string{"Authorization: Bearer " + header},
			want: []string{"Authorization: " + mask},
		},
		{
			name: "standalone cookie header line",
			args: []string{"Cookie: sid=" + header},
			want: []string{"Cookie: " + mask},
		},
		{
			name: "standalone x-auth-token header line",
			args: []string{"x-auth-token:" + header},
			want: []string{"x-auth-token:" + mask},
		},
		{
			name: "token-url flag keeps the flag and redacts the URL",
			args: []string{"--token-url=https://h/?code=" + inURL},
			want: []string{"--token-url=https://h/?code=" + mask},
		},

		// Arguments with nothing to hide stay the same.
		{
			name: "npx package",
			args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"},
			want: []string{"-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"},
		},
		{
			name: "port and verbose flags",
			args: []string{"--port", "8080", "--verbose", "-v"},
			want: []string{"--port", "8080", "--verbose", "-v"},
		},
		{
			name: "lower case h is help, not a header flag",
			args: []string{"-h", "server"},
			want: []string{"-h", "server"},
		},
		{
			name: "key file path is a location, not a credential",
			args: []string{"--key-file", "/etc/ssl/key.pem", "--token-path=/run/token"},
			want: []string{"--key-file", "/etc/ssl/key.pem", "--token-path=/run/token"},
		},
		{
			name: "other location shapes are kept",
			args: []string{"KEY_FILE=~/keys/a.pem", "--key-dir", "./keys", "--secret-path", `C:\keys\a.pem`},
			want: []string{"KEY_FILE=~/keys/a.pem", "--key-dir", "./keys", "--secret-path", `C:\keys\a.pem`},
		},
		{
			name: "words that contain pass or pat are not secret-like",
			args: []string{"--bypass", "x", "--compass", "north", "--passthrough", "on"},
			want: []string{"--bypass", "x", "--compass", "north", "--passthrough", "on"},
		},
		{
			name: "path, patch and pattern are not pat",
			args: []string{"--path", "src", "--patch", "fix.diff", "--pattern", "*.go", "PATH=bin"},
			want: []string{"--path", "src", "--patch", "fix.diff", "--pattern", "*.go", "PATH=bin"},
		},
		{
			name: "user flag with no colon",
			args: []string{"-u", "root"},
			want: []string{"-u", "root"},
		},
		{
			name: "list with no secret key",
			args: []string{"Server=db;Database=app", "a=1;b=2"},
			want: []string{"Server=db;Database=app", "a=1;b=2"},
		},
		{
			name: "text with a semicolon that is not a list",
			args: []string{"echo hi; ls", "-c", "x=1; echo $x"},
			want: []string{"echo hi; ls", "-c", "x=1; echo $x"},
		},
		{
			name: "words that start with bearer or basic",
			args: []string{"Bearerless", "basically"},
			want: []string{"Bearerless", "basically"},
		},
		{
			name: "URL without credentials",
			args: []string{"--url", "https://example.com/mcp"},
			want: []string{"--url", "https://example.com/mcp"},
		},
		{
			name: "non-secret variable",
			args: []string{"-e", "LOG_LEVEL=debug"},
			want: []string{"-e", "LOG_LEVEL=debug"},
		},
		{
			name: "docker env passed by name only",
			args: []string{"-e", "GITHUB_TOKEN"},
			want: []string{"-e", "GITHUB_TOKEN"},
		},
		{
			name: "non-auth header line outside a header flag",
			args: []string{"Content-Type: application/json"},
			want: []string{"Content-Type: application/json"},
		},
		{
			name: "dash, double dash and empty arguments",
			args: []string{"-", "--", ""},
			want: []string{"-", "--", ""},
		},
		{
			name: "host and port",
			args: []string{"localhost:8080"},
			want: []string{"localhost:8080"},
		},
		{
			name: "empty",
			args: []string{},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Keep a copy, to check that RedactArgs does not change its input.
			before := slices.Clone(tt.args)
			got := discover.RedactArgs(tt.args)

			discovertest.AssertNoLeak(t, "RedactArgs", strings.Join(got, " "))
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

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			// False positive: "--no-auth" takes no value, but RedactArgs
			// cannot know that, so it masks the next argument if that
			// argument is not a flag.
			name: "boolean secret-like flag masks the next positional argument",
			args: []string{"--no-auth", "server.js"},
			want: []string{"--no-auth", discover.Mask},
		},
		{
			// Miss: a value that starts with "--" is treated as a flag.
			name: "secret value that starts with -- is kept",
			args: []string{"--password", "--" + discovertest.CanaryEnv},
			want: []string{"--password", "--" + discovertest.CanaryEnv},
		},
		{
			// Miss: a value with "/" after a location flag looks like a path.
			name: "secret with a slash after a location flag is kept",
			args: []string{"--token-url", "ab/" + discovertest.CanaryEnv},
			want: []string{"--token-url", "ab/" + discovertest.CanaryEnv},
		},
		{
			// Miss: a short form glued to a word in lower case.
			name: "lower-case glued short form is kept",
			args: []string{"--dbpass", discovertest.CanaryEnv},
			want: []string{"--dbpass", discovertest.CanaryEnv},
		},
		{
			// False positive: docker uses "-u" for "uid:gid".
			name: "docker user flag masks the group",
			args: []string{"-u", "1000:1000"},
			want: []string{"-u", "1000:" + discover.Mask},
		},
		{
			// Miss: a short flag joined to its value is not seen as a flag.
			name: "short flag joined to its value is kept",
			args: []string{"-p" + discovertest.CanaryEnv},
			want: []string{"-p" + discovertest.CanaryEnv},
		},
		{
			// Miss: a bare token has no shape to recognise.
			name: "bare token is kept",
			args: []string{discovertest.CanaryEnv},
			want: []string{discovertest.CanaryEnv},
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
// input, keeps the length, and always masks the value after "--token",
// whatever comes before and after it. The fuzz strings are split on NUL
// bytes into arguments.
func FuzzRedactArgs(f *testing.F) {
	f.Add("", "")
	f.Add("--no-auth", "server.js")
	f.Add("-H\x00--header", "-u\x00a:b")
	f.Add("Server=x;Password=y", "Bearer\tz")
	f.Add("--key-file\x00/p", "//u:p@h/?k=v")
	f.Add("-\x00--", "-e\x00TOKEN=x")

	f.Fuzz(func(t *testing.T, before, after string) {
		args := strings.Split(before, "\x00")
		tokenAt := len(args)
		args = append(args, "--token", discovertest.CanaryEnv)
		args = append(args, strings.Split(after, "\x00")...)
		input := slices.Clone(args)

		got := discover.RedactArgs(args)

		if !slices.Equal(args, input) {
			t.Fatalf("RedactArgs changed its input: now %q, was %q", args, input)
		}
		if len(got) != len(args) {
			t.Fatalf("len(RedactArgs(%q)) = %d, want %d", args, len(got), len(args))
		}
		if got[tokenAt] != "--token" || got[tokenAt+1] != discover.Mask {
			t.Fatalf("RedactArgs(%q)[%d:%d] = %q, want [--token %s]",
				args, tokenAt, tokenAt+2, got[tokenAt:tokenAt+2], discover.Mask)
		}
		// The canary can reach the output only if the fuzz strings hold it.
		if !strings.Contains(before+after, discovertest.CanaryEnv) &&
			strings.Contains(strings.Join(got, "\x00"), discovertest.CanaryEnv) {
			t.Fatalf("RedactArgs(%q) = %q leaks the canary", args, got)
		}
	})
}

// ExampleRedactArgs shows a typical mcp-remote command with a token in the
// URL and in a header.
func ExampleRedactArgs() {
	args := []string{"-y", "mcp-remote", "https://host/sse?api_key=abc", "--header", "Authorization: Bearer abc"}
	fmt.Println(discover.RedactArgs(args))
	// Output: [-y mcp-remote https://host/sse?api_key=******** --header Authorization: ********]
}
