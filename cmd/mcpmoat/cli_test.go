package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

// fakeGetenv returns a getenv function that reads from a map. A missing key
// gives an empty string, like os.Getenv.
func fakeGetenv(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

// newTestCLI builds a cli with in-memory writers. The test reads the output
// from the two returned buffers (stdout first, then stderr).
func newTestCLI(getenv func(string) string, build buildInfo) (*cli, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	c := &cli{
		stdout: &stdout,
		stderr: &stderr,
		getenv: getenv,
		build:  build,
	}
	return c, &stdout, &stderr
}

// usageText returns the exact help text that c.usage writes.
func usageText(t *testing.T) string {
	t.Helper()
	c, stdout, _ := newTestCLI(fakeGetenv(nil), buildInfo{})
	c.usage(stdout)
	return stdout.String()
}

func TestCLIRun(t *testing.T) {
	t.Parallel()

	build := buildInfo{version: "1.2.3", commit: "abc123", date: "2026-01-01T00:00:00Z"}
	const wantVersionLine = "mcpmoat 1.2.3 (commit abc123, built 2026-01-01T00:00:00Z)\n"

	tests := []struct {
		name            string
		args            []string
		env             map[string]string
		wantCode        int
		wantStdout      []string // substrings
		wantStderr      []string // substrings
		wantStdoutEmpty bool
		wantStderrEmpty bool
	}{
		{
			name:            "help command",
			args:            []string{"help"},
			wantCode:        exitOK,
			wantStdout:      []string{"Usage:", "scan", "pin", "version", "help"},
			wantStderrEmpty: true,
		},
		{
			name:            "short help flag",
			args:            []string{"-h"},
			wantCode:        exitOK,
			wantStdout:      []string{"Usage:", "scan", "pin", "version", "help"},
			wantStderrEmpty: true,
		},
		{
			name:            "long help flag",
			args:            []string{"--help"},
			wantCode:        exitOK,
			wantStdout:      []string{"Usage:", "scan", "pin", "version", "help"},
			wantStderrEmpty: true,
		},
		{
			name:            "no arguments",
			args:            nil,
			wantCode:        exitError,
			wantStderr:      []string{"Usage:"},
			wantStdoutEmpty: true,
		},
		{
			name:            "only a global flag",
			args:            []string{"--no-color"},
			wantCode:        exitError,
			wantStderr:      []string{"Usage:"},
			wantStdoutEmpty: true,
		},
		{
			name:            "unknown command",
			args:            []string{"bogus"},
			wantCode:        exitError,
			wantStderr:      []string{`unknown command "bogus"`, "Usage:"},
			wantStdoutEmpty: true,
		},
		{
			// The command name is untrusted. It must be quoted with %q, so a
			// raw ESC byte never reaches the terminal.
			name:            "unknown command with control characters",
			args:            []string{"bo\x1b[31mgus"},
			wantCode:        exitError,
			wantStderr:      []string{`unknown command "bo\x1b[31mgus"`, "Usage:"},
			wantStdoutEmpty: true,
		},
		{
			name:            "version",
			args:            []string{"version"},
			wantCode:        exitOK,
			wantStdout:      []string{wantVersionLine},
			wantStderrEmpty: true,
		},
		{
			name:            "global flag with two dashes",
			args:            []string{"--no-color", "version"},
			wantCode:        exitOK,
			wantStdout:      []string{wantVersionLine},
			wantStderrEmpty: true,
		},
		{
			name:            "global flag with one dash",
			args:            []string{"-no-color", "version"},
			wantCode:        exitOK,
			wantStdout:      []string{wantVersionLine},
			wantStderrEmpty: true,
		},
		{
			// Global flags must come before the command. After the command,
			// the flag is an argument that version does not accept.
			name:            "global flag after the command",
			args:            []string{"version", "--no-color"},
			wantCode:        exitError,
			wantStderr:      []string{"mcpmoat version: unexpected arguments"},
			wantStdoutEmpty: true,
		},
		{
			name:            "unknown global flag",
			args:            []string{"--bogus-flag"},
			wantCode:        exitError,
			wantStderr:      []string{"flag provided but not defined", "Usage:"},
			wantStdoutEmpty: true,
		},
		{
			name:            "unknown global flag before a command",
			args:            []string{"--bogus-flag", "version"},
			wantCode:        exitError,
			wantStderr:      []string{"flag provided but not defined"},
			wantStdoutEmpty: true,
		},
		{
			name:            "version with an extra argument",
			args:            []string{"version", "extra"},
			wantCode:        exitError,
			wantStderr:      []string{"unexpected arguments"},
			wantStdoutEmpty: true,
		},
		{
			name:            "help with an extra argument",
			args:            []string{"help", "extra"},
			wantCode:        exitError,
			wantStderr:      []string{"mcpmoat help: unexpected arguments"},
			wantStdoutEmpty: true,
		},
		{
			// The extra argument is untrusted, so it must be quoted.
			name:            "extra argument with control characters",
			args:            []string{"version", "x\x1b[31my"},
			wantCode:        exitError,
			wantStderr:      []string{`x\x1b[31my`},
			wantStdoutEmpty: true,
		},
		{
			name:            "scan is not implemented",
			args:            []string{"scan"},
			wantCode:        exitError,
			wantStderr:      []string{"not implemented"},
			wantStdoutEmpty: true,
		},
		{
			name:            "pin is not implemented",
			args:            []string{"pin"},
			wantCode:        exitError,
			wantStderr:      []string{"not implemented"},
			wantStdoutEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, stdout, stderr := newTestCLI(fakeGetenv(tt.env), build)
			code := c.run(tt.args)

			if code != tt.wantCode {
				t.Errorf("run(%q) = %d, want %d", tt.args, code, tt.wantCode)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("run(%q) stdout does not contain %q", tt.args, want)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("run(%q) stderr does not contain %q", tt.args, want)
				}
			}
			if tt.wantStdoutEmpty && stdout.Len() != 0 {
				t.Errorf("run(%q) stdout = %q, want empty", tt.args, stdout.String())
			}
			if tt.wantStderrEmpty && stderr.Len() != 0 {
				t.Errorf("run(%q) stderr = %q, want empty", tt.args, stderr.String())
			}
			// Terminal safety: untrusted argv must never put a raw ESC byte on
			// stdout or stderr.
			if strings.Contains(stdout.String(), "\x1b") || strings.Contains(stderr.String(), "\x1b") {
				t.Errorf("run(%q) wrote a raw ESC byte\nstdout: %q\nstderr: %q",
					tt.args, stdout.String(), stderr.String())
			}
			if t.Failed() {
				t.Logf("stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
			}
		})
	}
}

func TestCLIRunVersionOutputIsExact(t *testing.T) {
	t.Parallel()

	build := buildInfo{version: "1.2.3", commit: "abc123", date: "2026-01-01T00:00:00Z"}
	c, stdout, stderr := newTestCLI(fakeGetenv(nil), build)

	code := c.run([]string{"version"})

	if code != exitOK {
		t.Errorf("run(version) = %d, want %d", code, exitOK)
	}
	const want = "mcpmoat 1.2.3 (commit abc123, built 2026-01-01T00:00:00Z)\n"
	if got := stdout.String(); got != want {
		t.Errorf("run(version) stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("run(version) stderr = %q, want empty", stderr.String())
	}
}

func TestCLIRunHelpMatchesUsage(t *testing.T) {
	t.Parallel()

	want := usageText(t)
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		c, stdout, stderr := newTestCLI(fakeGetenv(nil), buildInfo{})

		code := c.run(args)

		if code != exitOK {
			t.Errorf("run(%q) = %d, want %d", args, code, exitOK)
		}
		if got := stdout.String(); got != want {
			t.Errorf("run(%q) stdout differs from usage text\n--- got ---\n%s\n--- want ---\n%s", args, got, want)
		}
		if stderr.Len() != 0 {
			t.Errorf("run(%q) stderr = %q, want empty", args, stderr.String())
		}
	}
}

func TestCLIRunNoArgsPrintsUsageOnStderr(t *testing.T) {
	t.Parallel()

	want := usageText(t)
	c, stdout, stderr := newTestCLI(fakeGetenv(nil), buildInfo{})

	code := c.run(nil)

	if code != exitError {
		t.Errorf("run(nil) = %d, want %d", code, exitError)
	}
	if got := stderr.String(); got != want {
		t.Errorf("run(nil) stderr differs from usage text\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if stdout.Len() != 0 {
		t.Errorf("run(nil) stdout = %q, want empty", stdout.String())
	}
}

func TestUsageContent(t *testing.T) {
	t.Parallel()

	got := usageText(t)
	for _, want := range []string{
		"Usage:\n  mcpmoat [--no-color] <command> [arguments]\n",
		"Commands:\n",
		"  scan ",
		"  pin ",
		"  version ",
		"  help ",
		"--no-color",
		"Exit codes:\n",
		"  0  no findings\n",
		"  1  findings at or above --fail-on\n",
		"  2  execution error\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("usage text does not contain %q\n--- got ---\n%s", want, got)
		}
	}
}

// TestCLIRunUnknownFlagEscapesControlChars checks terminal safety for the flag
// parse error. The flag package puts the raw flag name in its error, so cli.run
// must quote the error text. A raw ESC byte must never reach stderr.
func TestCLIRunUnknownFlagEscapesControlChars(t *testing.T) {
	t.Parallel()

	c, stdout, stderr := newTestCLI(fakeGetenv(nil), buildInfo{})

	code := c.run([]string{"--\x1b[31mx"})

	if code != exitError {
		t.Errorf("run() = %d, want %d", code, exitError)
	}
	if strings.Contains(stderr.String(), "\x1b") {
		t.Errorf("stderr contains a raw ESC byte: %q", stderr.String())
	}
	if want := `flag provided but not defined: -\x1b[31mx`; !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr does not contain the escaped form %q\nstderr: %q", want, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

func TestColorDisabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		flag bool
		env  map[string]string
		want bool
	}{
		{name: "flag set, env unset", flag: true, env: nil, want: true},
		{name: "flag unset, env unset", flag: false, env: nil, want: false},
		{name: "NO_COLOR empty", flag: false, env: map[string]string{"NO_COLOR": ""}, want: false},
		{name: "NO_COLOR is 1", flag: false, env: map[string]string{"NO_COLOR": "1"}, want: true},
		// no-color.org: any non-empty value disables color, even "0".
		{name: "NO_COLOR is 0", flag: false, env: map[string]string{"NO_COLOR": "0"}, want: true},
		{name: "flag set and NO_COLOR set", flag: true, env: map[string]string{"NO_COLOR": "1"}, want: true},
		{name: "flag set and NO_COLOR empty", flag: true, env: map[string]string{"NO_COLOR": ""}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := colorDisabled(tt.flag, fakeGetenv(tt.env))
			if got != tt.want {
				t.Errorf("colorDisabled(%v, env=%v) = %v, want %v", tt.flag, tt.env, got, tt.want)
			}
		})
	}
}

func TestRunNoColorFromEnv(t *testing.T) {
	t.Parallel()

	build := buildInfo{version: "1.2.3", commit: "abc123", date: "2026-01-01T00:00:00Z"}
	c, stdout, stderr := newTestCLI(fakeGetenv(map[string]string{"NO_COLOR": "1"}), build)

	code := c.run([]string{"version"})

	if code != exitOK {
		t.Errorf("run(version) with NO_COLOR=1 = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "mcpmoat 1.2.3") {
		t.Errorf("stdout = %q, want the version line", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

// TestRun covers the real run function. It reads the real environment, but the
// help command does not depend on it, so the test needs no t.Setenv.
func TestRun(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer

	code := run([]string{"help"}, &stdout, &stderr)

	if code != exitOK {
		t.Errorf("run(help) = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("run(help) stdout = %q, want it to contain %q", stdout.String(), "Usage:")
	}
	if stderr.Len() != 0 {
		t.Errorf("run(help) stderr = %q, want empty", stderr.String())
	}
}

func TestCommandsOrder(t *testing.T) {
	t.Parallel()

	var names []string
	for _, cmd := range (&cli{}).commands() {
		names = append(names, cmd.name)
	}

	want := []string{"scan", "pin", "version", "help"}
	if !slices.Equal(names, want) {
		t.Errorf("commands() names = %q, want %q", names, want)
	}
}
