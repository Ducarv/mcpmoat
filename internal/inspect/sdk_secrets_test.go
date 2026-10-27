package inspect_test

import (
	"path/filepath"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// These tests cover Result.Secrets of a stdio server (issue #185): the
// configured env values and the expanded values of at least 8 bytes, each
// one time, longest first, and nil when the inspection fails. The remote
// side is in secrets_test.go.

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
			sdkAssertResult(t, got, inspecttest.BenignResult(), tt.want...)
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
