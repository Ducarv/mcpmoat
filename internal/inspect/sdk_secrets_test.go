package inspect_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
			// Not "unknown tenant": the JSON in the -c script makes "unknown"
			// a short argv piece (see argSecrets), so the whole-word scrub
			// masks it too.
			if !strings.Contains(text, "tenant ") || !strings.Contains(text, discover.Mask) {
				t.Errorf("reason and cause = %q, want the echo with %q", text, discover.Mask)
			}
		})
	}
}

// sdkShortPin is a fake 6-byte value of a variable that the config expands,
// and sdkShortLiteral is a fake 6-byte value that the config writes as is.
// Both are under discover.MinSecretBytes, so only the whole-word scrub (see
// replaceWords) removes them from error text (issue #180).
const (
	sdkShortPin     = "123456"
	sdkShortLiteral = "tok-42"
)

// sdkShortEchoParent is the parent environment of
// TestSDKInspectShortValueEcho.
var sdkShortEchoParent = []string{"PATH=/usr/bin:/bin", "MCPMOAT_TEST_PIN=" + sdkShortPin}

// sdkShortEchoMessage is the text that the fake servers of
// TestSDKInspectShortValueEcho send back, with the short expanded value and
// the short literal as words.
const sdkShortEchoMessage = "rejected pin %s with key %s"

// sdkShortStdio returns a stdio server, a /bin/sh script that answers each
// request with a JSON-RPC message: the id of the request, then member, a JSON
// member whose one "%s" gets sdkShortEchoMessage with the two short values.
//
// Its env holds the expanded value inside a longer value ("pin-" + the
// value, which the long-value scrub removes as a whole), so the 6-byte value
// on its own is only in the list of looked-up short values. The script cuts
// it out with cut, because a "${...}" form would be a placeholder for Claude
// Code. The literal is a configured env value of 6 bytes.
func sdkShortStdio(member string) discover.Server {
	reply := `{"jsonrpc":"2.0","id":%s,` + fmt.Sprintf(member, sdkShortEchoMessage) + `}`
	script := `pin=$(printf %s "$MCPMOAT_TEST_KEY" | cut -c5-)
while read -r line; do
  id=$(printf '%s\n' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  if [ -n "$id" ]; then
    printf '` + reply + `\n' "$id" "$pin" "$MCPMOAT_TEST_LIT"
  fi
done`
	return discover.Server{
		Name:      "short-echo",
		Client:    discover.ClientClaudeCode,
		Transport: discover.TransportStdio,
		Command:   "/bin/sh",
		Args:      discover.NewArgs([]string{"-c", script}),
		Env: sdkSecretEnv(map[string]string{
			"MCPMOAT_TEST_KEY": "pin-${MCPMOAT_TEST_PIN}",
			"MCPMOAT_TEST_LIT": sdkShortLiteral,
		}),
	}
}

// sdkShortRemote starts an HTTP server that answers each JSON-RPC request
// with a JSON-RPC error that echoes two request headers: the X-Tenant value
// without its "team-" prefix (the expanded value alone) and the X-Lit value.
// It returns a remote server entry for it, with these headers. A remote server
// has no env, so the literal is a header value here, which the scrub removes
// wherever it stands; the expanded value alone is a short looked-up value.
func sdkShortRemote(t *testing.T) discover.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		// A notification (no id) or any other request gets an empty 202.
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil || req.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		pin := strings.TrimPrefix(r.Header.Get("X-Tenant"), "team-")
		w.Header().Set("Content-Type", "application/json")
		// The encoder escapes the message as JSON needs (Go's %q does not).
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"error":   map[string]any{"code": -32603, "message": fmt.Sprintf(sdkShortEchoMessage, pin, r.Header.Get("X-Lit"))},
		})
	}))
	t.Cleanup(ts.Close)
	return discover.Server{
		Name:      "short-echo",
		Client:    discover.ClientClaudeCode,
		Transport: discover.TransportHTTP,
		URL:       discover.NewURL(ts.URL + "/mcp"),
		Headers: sdkSecretEnv(map[string]string{
			"X-Tenant": "team-${MCPMOAT_TEST_PIN}",
			"X-Lit":    sdkShortLiteral,
		}),
	}
}

// TestSDKInspectShortValueEcho checks that a short expanded value and a short
// literal value that a server echoes as words do not reach the error text
// (issue #180): not ConnectError.Error, which the scan summary prints on
// stdout, nor its Reason or cause. The child's stderr goes to /dev/null, so
// the stdio servers echo in a JSON-RPC error or in an invalid MCP answer.
// Whole words cannot stop a server that glues a letter to the value; this
// test does not claim that.
func TestSDKInspectShortValueEcho(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		server func(t *testing.T) discover.Server
	}{
		{
			name: "stdio JSON-RPC error",
			server: func(*testing.T) discover.Server {
				return sdkShortStdio(`"error":{"code":-32603,"message":"%s"}`)
			},
		},
		{
			// An invalid MCP answer: the SDK quotes the protocol version of
			// the initialize result in its error. Output that is not JSON at
			// all gives a decoder error that quotes no server text.
			name: "stdio invalid initialize result",
			server: func(*testing.T) discover.Server {
				return sdkShortStdio(`"result":{"protocolVersion":"%s"}`)
			},
		},
		{name: "remote JSON-RPC error", server: sdkShortRemote},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inspector := inspect.NewForTest(inspect.SDKOptions{}, filepath.Join(t.TempDir(), "run"), sdkShortEchoParent, 0)
			res, err := inspector.Inspect(sdkCtx(t, sdkTimeout), tt.server(t))

			_, reason := sdkAssertFailed(t, res, err, inspect.KindProtocol)
			text := err.Error() + " | " + reason
			if cause := errors.Unwrap(err); cause != nil {
				text += " | " + cause.Error()
			}
			sdkAssertNoLeak(t, err, sdkShortPin, sdkShortLiteral)
			discovertest.AssertNoLeak(t, "reason and cause", text, sdkShortPin, sdkShortLiteral)
			// The echo must reach the text, masked; else the test would pass
			// on an error that dropped the server text. Not "rejected pin":
			// the JSON in the stdio scripts makes "rejected" a short argv
			// piece (see argSecrets), so the whole-word scrub masks it too.
			if want := "pin " + discover.Mask + " with key " + discover.Mask; !strings.Contains(text, want) {
				t.Errorf("error, reason and cause = %q, want the echo %q", text, want)
			}
		})
	}
}

// sdkCredTok is a fake token: 21 bytes with letters and digits, so it looks
// like a credential whatever its name.
const sdkCredTok = "FAKE-TOKEN-0123456789"

// sdkCredDSN is a fake connection URL with a password.
const sdkCredDSN = "postgres://app:hunter2pw@db/prod" //nolint:gosec // G101: fake test credential

// sdkCredDSNPort is a fake connection URL with a port and a password of 14
// bytes, so its inner pieces are long enough for Result.Secrets.
const sdkCredDSNPort = "postgres://app:S3cretPassw0rd@db:5432/app" //nolint:gosec // G101: fake test credential

// sdkCredDSNShortPW is a fake connection URL with a password of 2 bytes, so
// its inner pieces are too short for Result.Secrets.
const sdkCredDSNShortPW = "postgres://app:pw@db/app" //nolint:gosec // G101: fake test credential

// sdkCredScript is the sh script of the arg cases of
// TestSDKInspectCredentialsStdio, for the fixture "benign". discover.ArgSecrets
// masks the value after "-c", so it is in the wide Result.Secrets. It is not a
// credential.
const sdkCredScript = "exec benign"

// sdkCredParent returns the parent environment of
// TestSDKInspectCredentialsStdio. PATH starts with the directory of the
// benign fixture, so the server runs by its bare name "benign" and the argv holds no
// temp path: the masked segments of such a path depend on the machine (see
// sdkPathSecrets), and the lists below can then be exact. REGION and
// API_KEY hold the same plain value under a plain and a secret-like name.
// DB_URL holds a connection URL under a plain name.
func sdkCredParent(t *testing.T) []string {
	t.Helper()
	return []string{
		"PATH=" + filepath.Dir(inspecttest.Fixture(t, "benign")) + ":/usr/bin:/bin",
		"MCPMOAT_TEST_REGION=production",
		"MCPMOAT_TEST_API_KEY=production",
		"MCPMOAT_TEST_DB_URL=" + sdkCredDSNPort,
	}
}

// TestSDKInspectCredentialsStdio checks Result.Secrets and
// Result.Credentials of a stdio server that succeeds (issues #229 and
// #235). Secrets is the wide list: every env value, expanded value and argv
// secret of 8 bytes or more. Credentials is the subset that looks like a
// credential: plain config words, such as NODE_ENV=production, stay out of
// it. Both lists are in the order of Result.Secrets.
func TestSDKInspectCredentialsStdio(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		// args, when set, run the fixture through sh, so that the argv can
		// hold args that the fixture would refuse. Their wantSecrets hold
		// sdkCredScript too.
		args        []string
		wantSecrets []string
		wantCreds   []string
	}{
		{
			name:        "plain env values",
			env:         map[string]string{"NODE_ENV": "production", "LOG_LEVEL": "information"},
			wantSecrets: []string{"information", "production"},
			wantCreds:   nil,
		},
		{
			name:        "secret-like env key",
			env:         map[string]string{"API_KEY": "production"},
			wantSecrets: []string{"production"},
			wantCreds:   []string{"production"},
		},
		{
			name:        "token-like env value",
			env:         map[string]string{"MCPMOAT_TEST_PLAIN": sdkCredTok},
			wantSecrets: []string{sdkCredTok},
			wantCreds:   []string{sdkCredTok},
		},
		{
			name: "connection URL with a password",
			env:  map[string]string{"DATABASE_URL": sdkCredDSN},
			// The credentials inside the value too (see valueCredentials).
			wantSecrets: []string{sdkCredDSN, "app:hunter2pw", "hunter2pw"},
			wantCreds:   []string{sdkCredDSN, "app:hunter2pw", "hunter2pw"},
		},
		{
			name:        "connection URL with a port",
			env:         map[string]string{"DATABASE_URL": sdkCredDSNPort},
			wantSecrets: []string{sdkCredDSNPort, "app:S3cretPassw0rd", "S3cretPassw0rd"},
			wantCreds:   []string{sdkCredDSNPort, "app:S3cretPassw0rd", "S3cretPassw0rd"},
		},
		{
			// The inner pieces are short: they go to the whole-word list of
			// the error scrub only (see envSecrets).
			name:        "connection URL with a short password",
			env:         map[string]string{"DATABASE_URL": sdkCredDSNShortPW},
			wantSecrets: []string{sdkCredDSNShortPW},
			wantCreds:   []string{sdkCredDSNShortPW},
		},
		{
			// The env key and the variable name are plain; the value is not.
			name:        "expanded connection URL",
			env:         map[string]string{"MCPMOAT_TEST_A": "${MCPMOAT_TEST_DB_URL}"},
			wantSecrets: []string{sdkCredDSNPort, "app:S3cretPassw0rd", "S3cretPassw0rd"},
			wantCreds:   []string{sdkCredDSNPort, "app:S3cretPassw0rd", "S3cretPassw0rd"},
		},
		{
			name:        "connection string with no password",
			env:         map[string]string{"PGOPTS": "host=localhost dbname=production user=postgres"},
			wantSecrets: []string{"host=localhost dbname=production user=postgres"},
			wantCreds:   nil,
		},
		{
			name:        "expanded plain variable",
			env:         map[string]string{"MCPMOAT_TEST_A": "${MCPMOAT_TEST_REGION}"},
			wantSecrets: []string{"production"},
			wantCreds:   nil,
		},
		{
			// The env key and the value are plain; the variable name is not.
			name:        "expanded secret-like variable",
			env:         map[string]string{"MCPMOAT_TEST_A": "${MCPMOAT_TEST_API_KEY}"},
			wantSecrets: []string{"production"},
			wantCreds:   []string{"production"},
		},
		{
			// Only the expanded value is a credential, not the longer env
			// value that holds it.
			name:        "expanded secret-like variable inside a value",
			env:         map[string]string{"MCPMOAT_TEST_A": "x-${MCPMOAT_TEST_API_KEY}"},
			wantSecrets: []string{"x-production", "production"},
			wantCreds:   []string{"production"},
		},
		{
			// The same value under a plain name and a secret-like name. The
			// two cases swap the names, so one of them looks the value up
			// under the plain name first, whatever order Expand uses.
			name:        "same value, plain name in A",
			env:         map[string]string{"MCPMOAT_TEST_A": "${MCPMOAT_TEST_REGION}", "MCPMOAT_TEST_B": "${MCPMOAT_TEST_API_KEY}"},
			wantSecrets: []string{"production"},
			wantCreds:   []string{"production"},
		},
		{
			name:        "same value, plain name in B",
			env:         map[string]string{"MCPMOAT_TEST_A": "${MCPMOAT_TEST_API_KEY}", "MCPMOAT_TEST_B": "${MCPMOAT_TEST_REGION}"},
			wantSecrets: []string{"production"},
			wantCreds:   []string{"production"},
		},
		{
			name:        "secret flag with a plain value",
			args:        []string{"--api-key", "plainvalue1"},
			wantSecrets: []string{sdkCredScript, "plainvalue1"},
			wantCreds:   []string{"plainvalue1"},
		},
		{
			// discover.ArgSecrets masks the words of the value, so they are
			// in the wide list. None is a credential.
			name:        "connection string arg with no password",
			args:        []string{"--dsn", "host=localhost dbname=production"},
			wantSecrets: []string{"localhost dbname=production", "dbname=production", sdkCredScript, "production"},
			wantCreds:   nil,
		},
		{
			// "SEVEN77" has 7 bytes: under the limit of both lists.
			name:        "short arg dropped",
			args:        []string{"--token", "SEVEN77", "--api-key=EIGHT888"},
			wantSecrets: []string{sdkCredScript, "EIGHT888"},
			wantCreds:   []string{"EIGHT888"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parent := sdkCredParent(t)
			s := discover.Server{
				Name:      "creds",
				Client:    discover.ClientClaudeCode,
				Transport: discover.TransportStdio,
				Command:   "benign",
				Env:       sdkSecretEnv(tt.env),
			}
			if tt.args != nil {
				// sh runs the fixture by name with no args. "creds" is $0,
				// and tt.args are $1 and on, which the script ignores.
				s.Command = "sh"
				s.Args = discover.NewArgs(append([]string{"-c", sdkCredScript, "creds"}, tt.args...))
			}

			inspector := inspect.NewForTest(inspect.SDKOptions{}, filepath.Join(t.TempDir(), "run"), parent, 0)
			got, err := inspector.Inspect(sdkCtx(t, sdkTimeout), s)
			if err != nil {
				t.Fatalf("Inspect() error = %v, want nil", err)
			}
			sdkAssertResult(t, got, inspecttest.BenignResult(), tt.wantSecrets...)
			inspect.CheckCredentials(t, got, tt.wantCreds)
		})
	}
}
