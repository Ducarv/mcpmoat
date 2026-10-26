package inspect_test

import (
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// sdkHiddenValue is the value of the hidden variable MCPMOAT_TEST_HIDDEN in
// the injected parent environment. It stands for the API key of --llm. It
// must never reach a server or an error.
const sdkHiddenValue = "mcpmoat-hidden-canary-sdk-3Vb9Qx"

// sdkHiddenNote is the end of the reason for a placeholder of a hidden
// variable.
const sdkHiddenNote = "; this variable is hidden from placeholders"

// sdkHiddenParent is sdkExpandParent plus the hidden variable.
func sdkHiddenParent(t *testing.T, dir string) []string {
	t.Helper()
	return append(sdkExpandParent(t, dir), "MCPMOAT_TEST_HIDDEN="+sdkHiddenValue)
}

// TestSDKInspectHiddenEnvRefused checks that no server reads a variable of
// SDKOptions.HiddenEnv through a placeholder: trusted or untrusted, stdio or
// remote, Claude Code or Cursor syntax, and a hidden name in another case.
// Inspect fails with KindConfig and discover.ErrMissingVariable, the reason
// names the variable and says that it is hidden, the server does not start
// or gets no request, and the error holds no value.
func TestSDKInspectHiddenEnvRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		client discover.Client
		// hidden is SDKOptions.HiddenEnv. nil means MCPMOAT_TEST_HIDDEN.
		hidden    []string
		untrusted bool
		args      []string // "PIDFILE" is replaced by the pidfile path
		env       map[string]string
		// url makes a remote server when set; "URL" is replaced by the
		// counting server.
		url        string
		headers    map[string]string
		wantReason string
	}{
		{
			name:       "trusted claude code stdio env value",
			client:     discover.ClientClaudeCode,
			args:       []string{"-pidfile", "PIDFILE"},
			env:        map[string]string{"MCPMOAT_TEST_KEY": "${MCPMOAT_TEST_HIDDEN}"},
			wantReason: "cannot expand env: variable MCPMOAT_TEST_HIDDEN: variable is not set" + sdkHiddenNote,
		},
		{
			name:       "trusted cursor stdio arg",
			client:     discover.ClientCursor,
			args:       []string{"-pidfile", "PIDFILE", "--key=${env:MCPMOAT_TEST_HIDDEN}"},
			wantReason: "cannot expand args: variable MCPMOAT_TEST_HIDDEN: variable is not set" + sdkHiddenNote,
		},
		{
			name:       "trusted claude code remote header",
			client:     discover.ClientClaudeCode,
			url:        "URL",
			headers:    map[string]string{"X-Key": "${MCPMOAT_TEST_HIDDEN}"},
			wantReason: "cannot expand headers: variable MCPMOAT_TEST_HIDDEN: variable is not set" + sdkHiddenNote,
		},
		{
			name:       "trusted cursor remote URL",
			client:     discover.ClientCursor,
			url:        "URL?k=${env:MCPMOAT_TEST_HIDDEN}",
			wantReason: "cannot expand url: variable MCPMOAT_TEST_HIDDEN: variable is not set" + sdkHiddenNote,
		},
		{
			name:       "hidden name in another case",
			client:     discover.ClientClaudeCode,
			hidden:     []string{"mcpmoat_test_hidden"},
			url:        "URL",
			headers:    map[string]string{"X-Key": "${MCPMOAT_TEST_HIDDEN}"},
			wantReason: "cannot expand headers: variable MCPMOAT_TEST_HIDDEN: variable is not set" + sdkHiddenNote,
		},
		{
			// The hidden note wins over the untrusted note: the cause is
			// the hidden name, not the trust of the file.
			name:       "untrusted claude code stdio env value",
			client:     discover.ClientClaudeCode,
			untrusted:  true,
			args:       []string{"-pidfile", "PIDFILE"},
			env:        map[string]string{"MCPMOAT_TEST_KEY": "${MCPMOAT_TEST_HIDDEN}"},
			wantReason: "cannot expand env: variable MCPMOAT_TEST_HIDDEN: variable is not set" + sdkHiddenNote,
		},
		{
			name:       "untrusted claude code remote header",
			client:     discover.ClientClaudeCode,
			untrusted:  true,
			url:        "URL",
			headers:    map[string]string{"X-Key": "${MCPMOAT_TEST_HIDDEN}"},
			wantReason: "cannot expand headers: variable MCPMOAT_TEST_HIDDEN: variable is not set" + sdkHiddenNote,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			pidfile := filepath.Join(dir, "pid")
			args := make([]string, len(tt.args))
			for i, a := range tt.args {
				args[i] = strings.Replace(a, "PIDFILE", pidfile, 1)
			}
			s := discover.Server{
				Name:      "hidden",
				Client:    tt.client,
				Scope:     discover.ScopeGlobal,
				Transport: discover.TransportStdio,
				Command:   inspecttest.Fixture(t, "benign"),
				Args:      discover.NewArgs(args),
				Env:       sdkSecretEnv(tt.env),
				Untrusted: tt.untrusted,
			}
			var count *atomic.Int32
			if tt.url != "" {
				var endpoint string
				endpoint, count = sdkCountingServer(t)
				s.Transport = discover.TransportHTTP
				s.Command = ""
				s.Args = discover.Args{}
				s.URL = discover.NewURL(strings.Replace(tt.url, "URL", endpoint, 1))
				s.Headers = sdkSecretEnv(tt.headers)
			}
			hidden := tt.hidden
			if hidden == nil {
				hidden = []string{"MCPMOAT_TEST_HIDDEN"}
			}

			opts := inspect.SDKOptions{AllowUntrusted: tt.untrusted, HiddenEnv: hidden}
			inspector := inspect.NewForTest(opts, filepath.Join(t.TempDir(), "run"), sdkHiddenParent(t, dir), 0)
			res, err := inspector.Inspect(sdkCtx(t, sdkTimeout), s)

			_, reason := sdkAssertFailed(t, res, err, inspect.KindConfig)
			if !errors.Is(err, discover.ErrMissingVariable) {
				t.Errorf("Inspect() error = %v, want errors.Is %v", err, discover.ErrMissingVariable)
			}
			if reason != tt.wantReason {
				t.Errorf("Inspect() reason = %q, want %q", reason, tt.wantReason)
			}
			sdkAssertNotExist(t, pidfile, "a server with a hidden placeholder must not start")
			if count != nil {
				if n := count.Load(); n != 0 {
					t.Errorf("the server got %d requests, want none", n)
				}
			}
			sdkAssertNoLeak(t, err, sdkHiddenValue, sdkExpandSecret, dir)
		})
	}
}

// TestSDKInspectHiddenEnvOthers checks what HiddenEnv does not change: with
// a hidden name, the other variables still expand and a default of a hidden
// placeholder applies; with HiddenEnv nil, the same placeholder reads the
// variable as before.
func TestSDKInspectHiddenEnvOthers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		hidden []string
		env    map[string]string
		want   map[string]string
	}{
		{
			name:   "other variables expand",
			hidden: []string{"MCPMOAT_TEST_HIDDEN"},
			env: map[string]string{
				"MCPMOAT_TEST_EXPANDED": "${MCPMOAT_TEST_VALUE}",
				"MCPMOAT_TEST_DEFAULT":  "${MCPMOAT_TEST_HIDDEN:-fallback-value}",
			},
			want: map[string]string{
				"MCPMOAT_TEST_EXPANDED": sdkExpandSecret,
				"MCPMOAT_TEST_DEFAULT":  "fallback-value",
			},
		},
		{
			name:   "nil HiddenEnv reads the variable",
			hidden: nil,
			env:    map[string]string{"MCPMOAT_TEST_KEY": "${MCPMOAT_TEST_HIDDEN}"},
			want:   map[string]string{"MCPMOAT_TEST_KEY": sdkHiddenValue},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			s := discover.Server{
				Name:      "hidden",
				Client:    discover.ClientClaudeCode,
				Scope:     discover.ScopeGlobal,
				Transport: discover.TransportStdio,
				Command:   inspecttest.Fixture(t, "benign"),
				Args:      discover.NewArgs([]string{"-envfile", filepath.Join(dir, "env")}),
				Env:       sdkSecretEnv(tt.env),
			}
			opts := inspect.SDKOptions{HiddenEnv: tt.hidden}
			inspector := inspect.NewForTest(opts, filepath.Join(t.TempDir(), "run"), sdkHiddenParent(t, dir), 0)
			got, err := inspector.Inspect(sdkCtx(t, sdkTimeout), s)
			if err != nil {
				t.Fatalf("Inspect() error = %v, want nil", err)
			}
			sdkAssertResult(t, got, inspecttest.BenignResult())

			vars, _ := sdkReadEnvFile(t, filepath.Join(dir, "env"))
			for k, v := range tt.want {
				// Print keys only: the values hold the canaries.
				if vars[k] != v {
					t.Errorf("child env %s has the wrong value", k)
				}
			}
			if _, ok := vars["MCPMOAT_TEST_HIDDEN"]; ok {
				t.Errorf("child env has MCPMOAT_TEST_HIDDEN, want it scrubbed")
			}
		})
	}
}
