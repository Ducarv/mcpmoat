package discover_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

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
			name: "value after a secret flag is masked even if it looks like a flag",
			args: []string{"--secret", "-" + env},
			want: []string{"--secret", mask},
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
			// cannot know that, so it masks the next argument.
			name: "boolean secret-like flag masks the next argument",
			args: []string{"--no-auth", "server.js"},
			want: []string{"--no-auth", discover.Mask},
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

func ExampleRedactArgs() {
	args := []string{"-y", "mcp-remote", "https://host/sse?api_key=abc", "--header", "Authorization: Bearer abc"}
	fmt.Println(discover.RedactArgs(args))
	// Output: [-y mcp-remote https://host/sse?api_key=******** --header Authorization: ********]
}
