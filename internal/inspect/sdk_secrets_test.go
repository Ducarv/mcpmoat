package inspect_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// These tests cover Result.Secrets of a stdio server (issue #185): the
// configured env values, the expanded values and the argv secrets (the text
// that discover.RedactArgs masks) of at least 8 bytes, each one time,
// longest first, and nil when the inspection fails. They also check that
// Inspect removes an argv secret from error text. The remote side is in
// secrets_test.go.

// sdkSecretsParent is the injected parent environment of the tests below.
// MCPMOAT_TEST_SHORT has a value under 8 bytes.
var sdkSecretsParent = []string{
	"PATH=/usr/bin:/bin",
	"MCPMOAT_TEST_VALUE=" + sdkExpandSecret,
	"MCPMOAT_TEST_SHORT=tiny",
	"MCPMOAT_TEST_PARENT_ONLY=" + sdkParentCanary,
}

// TestSDKInspectSecretsStdio checks Result.Secrets of a stdio server that
// succeeds. Each case adds one kind of value, so a missing kind fails one
// named case. want is written in the order of Result.Secrets on purpose.
func TestSDKInspectSecretsStdio(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		client discover.Client
		env    map[string]string
		want   []string
	}{
		{name: "no env", client: discover.ClientClaudeCode, want: nil},
		{
			name:   "env value",
			client: discover.ClientCodex,
			env:    map[string]string{"MCPMOAT_TEST_TOKEN": discovertest.CanaryEnv},
			want:   []string{discovertest.CanaryEnv},
		},
		{
			// 7 bytes is under the limit, 8 bytes is at it.
			name:   "short env values are dropped",
			client: discover.ClientCodex,
			env:    map[string]string{"A": "SEVEN77", "B": "EIGHT888", "C": "1", "D": "true"},
			want:   []string{"EIGHT888"},
		},
		{
			// The looked-up value, and the env value that holds it.
			name:   "expanded value",
			client: discover.ClientClaudeCode,
			env:    map[string]string{"MCPMOAT_TEST_MIXED": "x-${MCPMOAT_TEST_VALUE}"},
			want:   []string{"x-" + sdkExpandSecret, sdkExpandSecret},
		},
		{
			name:   "short expanded value is dropped",
			client: discover.ClientClaudeCode,
			env:    map[string]string{"MCPMOAT_TEST_KEY": "${MCPMOAT_TEST_SHORT}"},
			want:   nil,
		},
		{
			// The expanded value is also the env value, and two env
			// entries hold the same value: each one is in the list one
			// time.
			name:   "duplicates once",
			client: discover.ClientClaudeCode,
			env: map[string]string{
				"MCPMOAT_TEST_A": "${MCPMOAT_TEST_VALUE}",
				"MCPMOAT_TEST_B": "${MCPMOAT_TEST_VALUE}",
				"MCPMOAT_TEST_C": discovertest.CanaryEnv,
				"MCPMOAT_TEST_D": discovertest.CanaryEnv,
			},
			want: []string{sdkExpandSecret, discovertest.CanaryEnv},
		},
		{
			// Longest first, then by value. The parent values that no
			// placeholder names are never in the list.
			name:   "all kinds sorted",
			client: discover.ClientClaudeCode,
			env: map[string]string{
				"MCPMOAT_TEST_MIXED": "x-${MCPMOAT_TEST_VALUE}",
				"MCPMOAT_TEST_PLAIN": "stdio-env-value-1",
				"MCPMOAT_TEST_DUP":   "stdio-env-value-1",
				"MCPMOAT_TEST_LEX_B": "bbbbbbbb",
				"MCPMOAT_TEST_LEX_A": "aaaaaaaa",
				"MCPMOAT_TEST_SHORT": "${MCPMOAT_TEST_SHORT}",
				"MCPMOAT_TEST_FLAG":  "1234567",
			},
			want: []string{"x-" + sdkExpandSecret, sdkExpandSecret, "stdio-env-value-1", "aaaaaaaa", "bbbbbbbb"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := sdkBenign(t)
			s.Client = tt.client
			s.Env = sdkSecretEnv(tt.env)

			inspector := inspect.NewForTest(inspect.SDKOptions{}, filepath.Join(t.TempDir(), "run"), sdkSecretsParent, 0)
			got, err := inspector.Inspect(sdkCtx(t, sdkTimeout), s)
			if err != nil {
				t.Fatalf("Inspect() error = %v, want nil", err)
			}
			// With the masked segments of the fixture path (an argv
			// secret), in the order of Result.Secrets.
			want := inspect.WantSecrets(append(slices.Clone(tt.want), sdkPathSecrets(t, s.Command)...)...)
			sdkAssertResult(t, got, inspecttest.BenignResult(), want...)
			for _, s := range got.Secrets {
				if s.Reveal() == sdkParentCanary {
					t.Error("Result.Secrets holds a parent value that no placeholder names")
				}
			}
			if len(tt.want) > 0 {
				inspect.AssertResultMasked(t, got, tt.want...)
			}
		})
	}
}

// TestSDKInspectSecretsStdioNilOnFailure checks that a failed inspection of
// a stdio server returns a nil Result.Secrets, also when the env and the
// expanded values hold long secrets: a refused server, a command that does
// not start, and a server that exits during the handshake.
func TestSDKInspectSecretsStdioNilOnFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		server func(t *testing.T) discover.Server
		kinds  []inspect.ConnectKind
	}{
		{
			name: "refused untrusted server",
			server: func(t *testing.T) discover.Server {
				s := sdkBenign(t)
				s.Untrusted = true
				return s
			},
			kinds: []inspect.ConnectKind{inspect.KindConfig},
		},
		{
			name: "command does not start",
			server: func(t *testing.T) discover.Server {
				s := sdkBenign(t)
				s.Command = filepath.Join(t.TempDir(), "missing-mcpmoat-server")
				return s
			},
			kinds: []inspect.ConnectKind{inspect.KindStart},
		},
		{
			name:   "server crashes",
			server: func(t *testing.T) discover.Server { return sdkBenign(t, "-mode", "crash") },
			kinds:  []inspect.ConnectKind{inspect.KindProtocol},
		},
		{
			// The argv holds a secret too (see sdkWrapped).
			name: "server with an argv secret crashes",
			server: func(t *testing.T) discover.Server {
				return sdkWrapped(t, `exec "$0" -mode crash`, "--token="+discovertest.CanaryArgs)
			},
			kinds: []inspect.ConnectKind{inspect.KindProtocol},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := tt.server(t)
			s.Client = discover.ClientClaudeCode
			s.Env = sdkSecretEnv(map[string]string{
				"MCPMOAT_TEST_TOKEN":    discovertest.CanaryEnv,
				"MCPMOAT_TEST_EXPANDED": "${MCPMOAT_TEST_VALUE}",
			})

			inspector := inspect.NewForTest(inspect.SDKOptions{}, filepath.Join(t.TempDir(), "run"), sdkSecretsParent, 0)
			res, err := inspector.Inspect(sdkCtx(t, sdkTimeout), s)

			// sdkAssertFailed checks for the zero Result, so it covers a
			// nil Secrets too. The explicit check names the field.
			sdkAssertFailed(t, res, err, tt.kinds...)
			if res.Secrets != nil {
				t.Errorf("Result.Secrets has %d values on failure, want nil", len(res.Secrets))
			}
			sdkAssertNoLeak(t, err, sdkExpandSecret)
		})
	}
}

// sdkWrapped returns a stdio server that runs the benign fixture through
// /bin/sh -c script, with the fixture path as $0 and args after it. The
// script decides what the fixture gets (`exec "$0"` gives it no args), so
// args can hold any shape: the benign fixture refuses unknown args. Inspect
// still sees the whole argv of /bin/sh, so the argv secrets are in args.
func sdkWrapped(t *testing.T, script string, args ...string) discover.Server {
	t.Helper()
	argv := append([]string{"-c", script, inspecttest.Fixture(t, "benign")}, args...)
	return discover.Server{
		Name:      "wrapped",
		Client:    discover.ClientCodex,
		Transport: discover.TransportStdio,
		Command:   "/bin/sh",
		Args:      discover.NewArgs(argv),
	}
}

// sdkArgCanary is a fake secret in an argv value of 8 bytes or more.
const sdkArgCanary = "mcpmoat-arg-canary-sdk-8Kp3Zt"

// sdkCmdSegment is a fake token in a directory name of the command path.
// The "ghp_" prefix makes RedactArgs mask it as a path segment.
const sdkCmdSegment = "ghp_mcpmoat0cmd0canary7Rq4"

// TestSDKInspectSecretsStdioArgs checks that Result.Secrets of a stdio
// server holds the secrets in its argv (the text that discover.RedactArgs
// masks) and not the plain args. want lists values that must be in
// Result.Secrets, and notWant values that must not be. The lists are not
// exact, because the fixture path adds masked segments that depend on the
// machine (see sdkPathSecrets).
func TestSDKInspectSecretsStdioArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		server  func(t *testing.T) discover.Server
		want    []string
		notWant []string
	}{
		{
			name: "value after equals",
			server: func(t *testing.T) discover.Server {
				return sdkWrapped(t, `exec "$0"`, "--token="+sdkArgCanary)
			},
			want:    []string{sdkArgCanary},
			notWant: []string{"--token=" + sdkArgCanary},
		},
		{
			// The whole line, the value after "Name:" and the credential.
			name: "authorization header",
			server: func(t *testing.T) discover.Server {
				return sdkWrapped(t, `exec "$0"`, "-H", "Authorization: Bearer "+sdkArgCanary)
			},
			want: []string{"Authorization: Bearer " + sdkArgCanary, "Bearer " + sdkArgCanary, sdkArgCanary},
		},
		{
			// The expanded arg, not the configured one. The lookup gives only
			// sdkExpandSecret, so "x-" + sdkExpandSecret comes from the argv.
			name: "secret flag value after expansion",
			server: func(t *testing.T) discover.Server {
				s := sdkWrapped(t, `exec "$0"`, "--api-key", "x-${MCPMOAT_TEST_VALUE}")
				s.Client = discover.ClientClaudeCode
				return s
			},
			want:    []string{"x-" + sdkExpandSecret, sdkExpandSecret},
			notWant: []string{"x-${MCPMOAT_TEST_VALUE}", "${MCPMOAT_TEST_VALUE}"},
		},
		{
			// RedactArgs shows these args, so they stay readable.
			name: "plain args are not secrets",
			server: func(t *testing.T) discover.Server {
				return sdkWrapped(t, `exec "$0"`, "-y", "@modelcontextprotocol/server-filesystem", "/home/me/proj", "--port", "8080")
			},
			notWant: []string{"@modelcontextprotocol/server-filesystem", "server-filesystem", "@modelcontextprotocol", "/home/me/proj", "8080"},
		},
		{
			// 7 bytes is under the limit, 8 bytes is at it.
			name: "short argv values are dropped",
			server: func(t *testing.T) discover.Server {
				return sdkWrapped(t, `exec "$0"`, "--token", "SEVEN77", "--api-key=EIGHT888")
			},
			want:    []string{"EIGHT888"},
			notWant: []string{"SEVEN77"},
		},
		{
			// The command is argv[0]: a token in its path is a secret too.
			name: "token segment in the command",
			server: func(t *testing.T) discover.Server {
				dir := filepath.Join(t.TempDir(), sdkCmdSegment)
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				command := filepath.Join(dir, "benign")
				if err := os.Symlink(inspecttest.Fixture(t, "benign"), command); err != nil {
					t.Fatal(err)
				}
				s := sdkBenign(t)
				s.Command = command
				return s
			},
			want:    []string{sdkCmdSegment},
			notWant: []string{"benign"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inspector := inspect.NewForTest(inspect.SDKOptions{}, filepath.Join(t.TempDir(), "run"), sdkSecretsParent, 0)
			got, err := inspector.Inspect(sdkCtx(t, sdkTimeout), tt.server(t))
			if err != nil {
				t.Fatalf("Inspect() error = %v, want nil", err)
			}
			// The values are fake test secrets, so the messages show them.
			values := inspect.RevealSecrets(got.Secrets)
			for _, w := range tt.want {
				if !slices.Contains(values, w) {
					t.Errorf("Result.Secrets = %q, want it to hold %q", values, w)
				}
			}
			for _, w := range tt.notWant {
				if slices.Contains(values, w) {
					t.Errorf("Result.Secrets = %q, want it not to hold %q", values, w)
				}
			}
			for _, v := range values {
				if len(v) < 8 {
					t.Errorf("Result.Secrets holds %q, want only values of 8 bytes or more", v)
				}
			}
			if len(tt.want) > 0 {
				inspect.AssertResultMasked(t, got, tt.want...)
			}
		})
	}
}

// TestSDKInspectStdioArgSecretEcho checks that Inspect removes an argv
// secret from the error text when a stdio server echoes it (see
// sdkEchoScript, which echoes $1). The secret is only in the argv, where no
// env value and no looked-up value covers it. The last case echoes only the
// last word of $1: the credential of the header line on its own.
func TestSDKInspectStdioArgSecretEcho(t *testing.T) {
	t.Parallel()

	// lastWord echoes the text after the last space of $1. Codex does not
	// expand, so the "${" of the script is not a placeholder.
	lastWord := strings.Replace(sdkEchoScript, `"$1"`, `"${1##* }"`, 1)
	tests := []struct {
		name   string
		script string
		args   []string // $0, $1, ...
	}{
		{name: "value after equals", script: sdkEchoScript, args: []string{"sh", "--token=" + sdkArgCanary}},
		{name: "header line", script: sdkEchoScript, args: []string{"-H", "Authorization: Bearer " + sdkArgCanary}},
		{name: "credential of a header line", script: lastWord, args: []string{"-H", "Authorization: Bearer " + sdkArgCanary}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := discover.Server{
				Name:      "echo",
				Client:    discover.ClientCodex,
				Transport: discover.TransportStdio,
				Command:   "/bin/sh",
				Args:      discover.NewArgs(append([]string{"-c", tt.script}, tt.args...)),
			}
			inspector := inspect.NewForTest(inspect.SDKOptions{}, filepath.Join(t.TempDir(), "run"), sdkSecretsParent, 0)
			res, err := inspector.Inspect(sdkCtx(t, sdkTimeout), s)

			_, reason := sdkAssertFailed(t, res, err, inspect.KindProtocol)
			sdkAssertNoLeak(t, err, sdkArgCanary)
			// The echo must reach the reason or the cause, masked; else the
			// test would pass on an error that dropped the server text.
			text := reason
			if cause := errors.Unwrap(err); cause != nil {
				text += " | " + cause.Error()
			}
			if !strings.Contains(text, "unknown tenant ") || !strings.Contains(text, discover.Mask) {
				t.Errorf("reason and cause = %q, want the echo with %q", text, discover.Mask)
			}
		})
	}
}
