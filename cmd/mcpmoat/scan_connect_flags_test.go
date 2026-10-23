package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestScanConnectFlags checks --timeout and --concurrency of "mcpmoat scan".
// Both flags are checked in both modes: with --no-connect, which does not use
// them yet, and without it, where scan stops with "not implemented yet" after
// the check. A bad value is a usage error with exit code 2, and stdout stays
// empty.
func TestScanConnectFlags(t *testing.T) {
	t.Parallel()

	const (
		hint           = `Run "mcpmoat help" for usage.`
		timeoutMsg     = "mcpmoat scan: --timeout must be greater than 0\n"
		concurrencyMsg = "mcpmoat scan: --concurrency must be at least 1\n"
		notImplemented = "connecting to servers is not implemented yet"
	)

	tests := []struct {
		name string
		// args are the arguments after "scan". The token "CONFIG" is replaced
		// with the path of a small valid config file.
		args       []string
		wantCode   int
		wantStdout []string
		wantStderr []string
		noStderr   []string // strings that stderr must not contain
	}{
		// Valid values with --no-connect: the table is printed.
		{
			name:       "defaults",
			args:       []string{"--no-connect", "--config", "CONFIG"},
			wantCode:   exitOK,
			wantStdout: []string{"ok-srv"},
		},
		{
			name:       "timeout in seconds",
			args:       []string{"--no-connect", "--config", "CONFIG", "--timeout", "2s"},
			wantCode:   exitOK,
			wantStdout: []string{"ok-srv"},
		},
		{
			name:       "timeout with minutes and seconds",
			args:       []string{"--no-connect", "--config", "CONFIG", "--timeout", "1m30s"},
			wantCode:   exitOK,
			wantStdout: []string{"ok-srv"},
		},
		{
			name:       "concurrency 1",
			args:       []string{"--no-connect", "--config", "CONFIG", "--concurrency", "1"},
			wantCode:   exitOK,
			wantStdout: []string{"ok-srv"},
		},
		{
			name:       "concurrency 16",
			args:       []string{"--no-connect", "--config", "CONFIG", "--concurrency", "16"},
			wantCode:   exitOK,
			wantStdout: []string{"ok-srv"},
		},
		{
			name:       "both flags with equals signs",
			args:       []string{"--no-connect", "--config", "CONFIG", "--timeout=3s", "--concurrency=2"},
			wantCode:   exitOK,
			wantStdout: []string{"ok-srv"},
		},
		{
			name:       "flags before --no-connect",
			args:       []string{"--timeout", "5s", "--concurrency", "3", "--no-connect", "--config", "CONFIG"},
			wantCode:   exitOK,
			wantStdout: []string{"ok-srv"},
		},

		// Bad values with --no-connect.
		{
			name:       "timeout 0",
			args:       []string{"--no-connect", "--config", "CONFIG", "--timeout", "0"},
			wantCode:   exitError,
			wantStderr: []string{timeoutMsg, hint},
			noStderr:   []string{noRulesText},
		},
		{
			name:       "timeout 0s",
			args:       []string{"--no-connect", "--config", "CONFIG", "--timeout", "0s"},
			wantCode:   exitError,
			wantStderr: []string{timeoutMsg, hint},
		},
		{
			name:       "negative timeout",
			args:       []string{"--no-connect", "--config", "CONFIG", "--timeout", "-5s"},
			wantCode:   exitError,
			wantStderr: []string{timeoutMsg, hint},
		},
		{
			// The flag package refuses the value before the range check.
			name:       "timeout that is no duration",
			args:       []string{"--no-connect", "--config", "CONFIG", "--timeout", "abc"},
			wantCode:   exitError,
			wantStderr: []string{"mcpmoat scan: ", "timeout", hint},
			noStderr:   []string{"must be greater than 0"},
		},
		{
			// A bare number has no unit, so time.ParseDuration refuses it.
			name:       "timeout without a unit",
			args:       []string{"--no-connect", "--config", "CONFIG", "--timeout", "5"},
			wantCode:   exitError,
			wantStderr: []string{"mcpmoat scan: ", "timeout", hint},
		},
		{
			name:       "concurrency 0",
			args:       []string{"--no-connect", "--config", "CONFIG", "--concurrency", "0"},
			wantCode:   exitError,
			wantStderr: []string{concurrencyMsg, hint},
		},
		{
			name:       "negative concurrency",
			args:       []string{"--no-connect", "--config", "CONFIG", "--concurrency", "-1"},
			wantCode:   exitError,
			wantStderr: []string{concurrencyMsg, hint},
		},
		{
			name:       "concurrency that is no number",
			args:       []string{"--no-connect", "--config", "CONFIG", "--concurrency", "x"},
			wantCode:   exitError,
			wantStderr: []string{"mcpmoat scan: ", "concurrency", hint},
			noStderr:   []string{"must be at least 1"},
		},
		{
			name:       "concurrency that is a decimal",
			args:       []string{"--no-connect", "--config", "CONFIG", "--concurrency", "1.5"},
			wantCode:   exitError,
			wantStderr: []string{"mcpmoat scan: ", "concurrency", hint},
		},
		{
			// The timeout is checked first, so it is the one message.
			name:       "both values bad",
			args:       []string{"--no-connect", "--config", "CONFIG", "--timeout", "0", "--concurrency", "0"},
			wantCode:   exitError,
			wantStderr: []string{timeoutMsg, hint},
			noStderr:   []string{"--concurrency"},
		},
		{
			// The check comes before the config file is read, so the missing
			// file is not reported.
			name:       "bad value before a missing config file",
			args:       []string{"--no-connect", "--config", "missing-config-file.json", "--timeout", "0"},
			wantCode:   exitError,
			wantStderr: []string{timeoutMsg, hint},
			noStderr:   []string{"file not found"},
		},

		// Without --no-connect.
		{
			name:       "valid values without --no-connect",
			args:       []string{"--timeout", "2s", "--concurrency", "2"},
			wantCode:   exitError,
			wantStderr: []string{"mcpmoat scan: ", notImplemented, "use --no-connect"},
		},
		{
			name:       "defaults without --no-connect",
			args:       nil,
			wantCode:   exitError,
			wantStderr: []string{notImplemented},
		},
		{
			name:       "timeout 0 without --no-connect",
			args:       []string{"--timeout", "0"},
			wantCode:   exitError,
			wantStderr: []string{timeoutMsg, hint},
			noStderr:   []string{notImplemented},
		},
		{
			name:       "negative timeout without --no-connect",
			args:       []string{"--timeout", "-5s"},
			wantCode:   exitError,
			wantStderr: []string{timeoutMsg, hint},
			noStderr:   []string{notImplemented},
		},
		{
			name:       "timeout that is no duration without --no-connect",
			args:       []string{"--timeout", "abc"},
			wantCode:   exitError,
			wantStderr: []string{"mcpmoat scan: ", "timeout", hint},
			noStderr:   []string{notImplemented},
		},
		{
			name:       "concurrency 0 without --no-connect",
			args:       []string{"--concurrency", "0"},
			wantCode:   exitError,
			wantStderr: []string{concurrencyMsg, hint},
			noStderr:   []string{notImplemented},
		},
		{
			name:       "negative concurrency without --no-connect",
			args:       []string{"--concurrency", "-1"},
			wantCode:   exitError,
			wantStderr: []string{concurrencyMsg, hint},
			noStderr:   []string{notImplemented},
		},
		{
			name:       "concurrency that is no number without --no-connect",
			args:       []string{"--concurrency", "x"},
			wantCode:   exitError,
			wantStderr: []string{"mcpmoat scan: ", "concurrency", hint},
			noStderr:   []string{notImplemented},
		},

		// --config must not take the next flag as its file name.
		{
			name:       "config followed by timeout",
			args:       []string{"--no-connect", "--config", "--timeout", "2s"},
			wantCode:   exitError,
			wantStderr: []string{"--config needs a file name", hint},
		},
		{
			name:       "config followed by concurrency",
			args:       []string{"--no-connect", "--config", "--concurrency=2"},
			wantCode:   exitError,
			wantStderr: []string{"--config needs a file name", hint},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// A config with one server, so that exit code 0 prints a table.
			// The home is an empty directory.
			path := writeServers(t, t.TempDir(), "mcp.json", map[string]any{
				"ok-srv": map[string]any{"command": "npx"},
			})
			c, stdout, stderr := scanConfigCLI(t, t.TempDir())

			args := []string{"scan"}
			for _, a := range tt.args {
				if a == "CONFIG" {
					a = path
				}
				args = append(args, a)
			}

			code := c.dispatch(args)

			if code != tt.wantCode {
				t.Errorf("dispatch(%q) = %d, want %d\nstdout:\n%s\nstderr:\n%s", args, code, tt.wantCode, stdout, stderr)
			}
			assertContainsAll(t, "stdout", stdout.String(), tt.wantStdout)
			assertContainsAll(t, "stderr", stderr.String(), tt.wantStderr)
			for _, bad := range tt.noStderr {
				if strings.Contains(stderr.String(), bad) {
					t.Errorf("stderr contains %q\nstderr:\n%s", bad, stderr)
				}
			}
			if len(tt.wantStdout) == 0 && stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if tt.wantCode == exitOK {
				assertNoRulesNotice(t, stderr.String())
			} else if strings.Contains(stderr.String(), noRulesNotice) {
				t.Errorf("stderr holds the notice %q, but the scan failed\nstderr:\n%s", noRulesNotice, stderr)
			}
			assertNoLeakBoth(t, stdout.String(), stderr.String())
			assertNoEscape(t, stdout.String(), stderr.String())
		})
	}
}

// TestScanConnectFlagsErrorIsTerminalSafe checks that a bad value with a
// control character is escaped in the flag error, as for any other flag.
func TestScanConnectFlagsErrorIsTerminalSafe(t *testing.T) {
	t.Parallel()

	for _, flagName := range []string{"--timeout", "--concurrency"} {
		t.Run(flagName, func(t *testing.T) {
			t.Parallel()

			c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)

			code := c.dispatch([]string{"scan", "--no-connect", flagName, "\x1b[31mred"})

			if code != exitError {
				t.Errorf("exit code = %d, want %d", code, exitError)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			assertContainsAll(t, "stderr", stderr.String(), []string{"mcpmoat scan: ", strings.TrimPrefix(flagName, "--")})
			assertNoEscape(t, stdout.String(), stderr.String())
		})
	}
}

// TestScanConnectFlagsHelp checks that "scan -h" lists the two flags with their
// defaults, and that the main help shows the same text.
func TestScanConnectFlagsHelp(t *testing.T) {
	t.Parallel()

	wants := []string{"--timeout <duration>", "--concurrency <n>", "default 10s", "default 4"}

	t.Run("scan -h", func(t *testing.T) {
		t.Parallel()

		c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)

		code := c.dispatch([]string{"scan", "-h"})

		if code != exitOK {
			t.Errorf("exit code = %d, want %d", code, exitOK)
		}
		assertContainsAll(t, "stdout", stdout.String(), wants)
		if stderr.Len() != 0 {
			t.Errorf("stderr = %q, want empty", stderr)
		}
		assertNoEscape(t, stdout.String(), stderr.String())
	})

	t.Run("main help", func(t *testing.T) {
		t.Parallel()

		assertContainsAll(t, "the main help", usageText(t), wants)
	})

	t.Run("help with a bad value still prints help", func(t *testing.T) {
		t.Parallel()

		// The flag package stops at -h, before it reads a later flag.
		c, stdout, _ := newTestCLI(fakeGetenv(nil), testBuild)

		code := c.dispatch([]string{"scan", "-h", "--timeout", "0"})

		if code != exitOK {
			t.Errorf("exit code = %d, want %d", code, exitOK)
		}
		assertContainsAll(t, "stdout", stdout.String(), wants)
	})
}

// TestScanConnectFlagsDoNotChangeNoConnectOutput checks that valid values of
// --timeout and --concurrency do not change the output of scan --no-connect,
// which does not use them yet. It does not check the default values: the help
// test and TestDefaultOptions in internal/inspect do that.
func TestScanConnectFlagsDoNotChangeNoConnectOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := writeServers(t, dir, "mcp.json", map[string]any{"ok-srv": map[string]any{"command": "npx"}})

	run := func(extra ...string) (int, string, string) {
		c, stdout, stderr := scanConfigCLI(t, filepath.Join(dir, "home"))
		args := append([]string{"scan", "--no-connect", "--config", path}, extra...)
		code := c.dispatch(args)
		return code, stdout.String(), stderr.String()
	}

	codeA, outA, errA := run()
	codeB, outB, errB := run("--timeout", "1m30s", "--concurrency", "16")

	if codeA != exitOK || codeB != exitOK {
		t.Fatalf("exit codes = %d and %d, want %d", codeA, codeB, exitOK)
	}
	if outA != outB || errA != errB {
		t.Errorf("valid flag values change the output\n--- default ---\n%s%s\n--- explicit ---\n%s%s", outA, errA, outB, errB)
	}
}
