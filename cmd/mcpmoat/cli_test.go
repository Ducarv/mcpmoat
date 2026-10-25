package main

import (
	"bytes"
	"errors"
	"flag"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// testBuild is the build information that the CLI tests inject.
var testBuild = buildInfo{version: "1.2.3", commit: "abc123", date: "2026-01-01T00:00:00Z"}

// wantVersionLine is the exact output of "mcpmoat version" for testBuild.
const wantVersionLine = "mcpmoat 1.2.3 (commit abc123, built 2026-01-01T00:00:00Z)\n"

// assertNoEscape fails the test if stdout or stderr holds a raw ESC byte.
// Untrusted argv must never put terminal escape sequences on the terminal.
func assertNoEscape(t *testing.T, stdout, stderr string) {
	t.Helper()
	if strings.Contains(stdout, "\x1b") || strings.Contains(stderr, "\x1b") {
		t.Errorf("output has a raw ESC byte\nstdout: %q\nstderr: %q", stdout, stderr)
	}
}

// fakeGetenv returns a getenv function that reads from a map. A missing key
// gives an empty string, like os.Getenv.
func fakeGetenv(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

// newTestCLI builds a cli with in-memory writers. The test reads the output
// from the two returned buffers (stdout first, then stderr).
//
// homeDir and getwd return an error by default. A test that needs them must
// set them to a fixture path. This way a test that forgets cannot read the
// real home directory or the real working directory.
func newTestCLI(getenv func(string) string, build buildInfo) (*cli, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	c := &cli{
		stdout: &stdout,
		stderr: &stderr,
		getenv: getenv,
		build:  build,
		homeDir: func() (string, error) {
			return "", errors.New("test: home not set")
		},
		getwd: func() (string, error) {
			return "", errors.New("test: working directory not set")
		},
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

	tests := []struct {
		name            string
		args            []string
		env             map[string]string
		wantCode        int
		wantStdoutExact string   // the whole stdout, checked when not empty
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
			// The command name is untrusted. quoteArg quotes it, so a raw ESC
			// byte never reaches the terminal.
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
			wantStdoutExact: wantVersionLine,
			wantStderrEmpty: true,
		},
		{
			name:            "global flag with two dashes",
			args:            []string{"--no-color", "version"},
			wantCode:        exitOK,
			wantStdoutExact: wantVersionLine,
			wantStderrEmpty: true,
		},
		{
			name:            "global flag with one dash",
			args:            []string{"-no-color", "version"},
			wantCode:        exitOK,
			wantStdoutExact: wantVersionLine,
			wantStderrEmpty: true,
		},
		{
			// Global flags must come before the command. After the command,
			// the flag is an argument that version does not accept.
			name:            "global flag after the command",
			args:            []string{"version", "--no-color"},
			wantCode:        exitError,
			wantStderr:      []string{`mcpmoat version: unexpected arguments ["--no-color"]`},
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
			wantStderr:      []string{`mcpmoat version: unexpected arguments ["extra"]`, usageHint},
			wantStdoutEmpty: true,
		},
		{
			name:            "help with an extra argument",
			args:            []string{"help", "extra"},
			wantCode:        exitError,
			wantStderr:      []string{`mcpmoat help: unexpected arguments ["extra"]`, usageHint},
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
			// %q keeps a blank rune as it is. termsafe.Quote escapes it.
			name:            "extra argument with a blank rune",
			args:            []string{"version", "\u3164"},
			wantCode:        exitError,
			wantStderr:      []string{`mcpmoat version: unexpected arguments ["\u3164"]`},
			wantStdoutEmpty: true,
		},
		{
			// Each argument is quoted, so a space or an empty argument shows.
			name:            "extra arguments with a space and an empty one",
			args:            []string{"help", "a b", ""},
			wantCode:        exitError,
			wantStderr:      []string{`mcpmoat help: unexpected arguments ["a b" ""]`},
			wantStdoutEmpty: true,
		},
		{
			name:            "unknown command with a blank rune",
			args:            []string{"\u3164"},
			wantCode:        exitError,
			wantStderr:      []string{`mcpmoat: unknown command "\u3164"`},
			wantStdoutEmpty: true,
		},
		{
			// A plain flag error is printed as it is.
			name:            "unknown global flag message",
			args:            []string{"--bogus-flag"},
			wantCode:        exitError,
			wantStderr:      []string{"mcpmoat: flag provided but not defined: -bogus-flag\n"},
			wantStdoutEmpty: true,
		},
		{
			name:            "unknown global flag with a blank rune",
			args:            []string{"--\u3164"},
			wantCode:        exitError,
			wantStderr:      []string{`mcpmoat: "flag provided but not defined: -\u3164"`},
			wantStdoutEmpty: true,
		},
		{
			// scan without --no-connect needs the home directory first, like
			// scan --no-connect. The default test cli has none, so scan stops
			// before it reaches the inspector (which is nil here).
			name:            "scan without --no-connect with no home directory",
			args:            []string{"scan"},
			wantCode:        exitError,
			wantStderr:      []string{"cannot find the home directory"},
			wantStdoutEmpty: true,
		},
		{
			// With the default test cli, homeDir fails. This proves that a
			// test (or a bug) cannot reach the real home directory.
			name:            "scan --no-connect with no home directory",
			args:            []string{"scan", "--no-connect"},
			wantCode:        exitError,
			wantStderr:      []string{"cannot find the home directory"},
			wantStdoutEmpty: true,
		},
		{
			name:            "pin without --accept is a usage error",
			args:            []string{"pin"},
			wantCode:        exitError,
			wantStderr:      []string{"mcpmoat pin: --accept <server> is required", usageHint},
			wantStdoutEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, stdout, stderr := newTestCLI(fakeGetenv(tt.env), testBuild)
			code := c.dispatch(tt.args)

			if code != tt.wantCode {
				t.Errorf("run(%q) = %d, want %d", tt.args, code, tt.wantCode)
			}
			if tt.wantStdoutExact != "" && stdout.String() != tt.wantStdoutExact {
				t.Errorf("run(%q) stdout = %q, want %q", tt.args, stdout.String(), tt.wantStdoutExact)
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
			assertNoEscape(t, stdout.String(), stderr.String())
			if t.Failed() {
				t.Logf("stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
			}
		})
	}
}

func TestCLIRunHelpMatchesUsage(t *testing.T) {
	t.Parallel()

	want := usageText(t)
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()

			c, stdout, stderr := newTestCLI(fakeGetenv(nil), buildInfo{})

			code := c.dispatch(args)

			if code != exitOK {
				t.Errorf("run(%q) = %d, want %d", args, code, exitOK)
			}
			if got := stdout.String(); got != want {
				t.Errorf("run(%q) stdout differs from usage text\n--- got ---\n%s\n--- want ---\n%s", args, got, want)
			}
			if stderr.Len() != 0 {
				t.Errorf("run(%q) stderr = %q, want empty", args, stderr.String())
			}
		})
	}
}

func TestCLIRunNoArgsPrintsUsageOnStderr(t *testing.T) {
	t.Parallel()

	want := usageText(t)
	c, stdout, stderr := newTestCLI(fakeGetenv(nil), buildInfo{})

	code := c.dispatch(nil)

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
		"Scan flags (after \"scan\"):\n",
		"  --no-connect ",
		"  --config <file> ",
		"A file that is not your own global config is read as an untrusted project file\n",
		"Exit codes:\n",
		"  0  no findings\n",
		"  1  findings at or above --fail-on\n",
		"  2  execution error\n",
		"     (scan also exits 2 when a config file has a problem or when pins.json cannot be read\n" +
			"     or saved, or when it is stopped by a signal; a missing file is not a problem in auto-discovery,\n" +
			"     but a missing --config file is. A server that fails or times out is a warning and does not\n" +
			"     change the exit code, unless its pins are already stored: then it is a high finding and scan exits 1)\n",
		"The file cannot ignore the pin rules (MOAT-T2-*)",
		"  If that server is already pinned, it is also a finding (MOAT-T2-004, high, exit code 1): its pinned tools were not checked.\n",
		"  scan reads pins.json before it starts a server, and reads it again just before it saves the first-run pins.\n",
		"  Ctrl-C (or SIGTERM or SIGHUP) stops the servers, saves no pins and exits 2.\n",
		"  pin changes only the entry of this server: it reads pins.json again just before it saves, and keeps the other entries.\n",
		"Ctrl-C stops the server and saves nothing (exit 2)",
		"Pin flags (after \"pin\"):\n",
		"  --accept <server> ",
		"MOAT-T2-001",
		"MOAT-T2-004",
		"\"pin --accept <server>\" accepts the changes.\n",
		"Scan output:\n",
		"  A heuristic masks secret-like arguments. Review the output before you share it.\n",
		"  --no-connect: scan runs only the built-in config rules (T4 and T5). It reads and writes no pins.\n",
		"  The tool rules (YAML) are not applied to tools yet. Rules from --rules are loaded and checked, but not applied yet.\n",
		"  Exit code 1 means a finding of severity high or above that is not ignored.\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("usage text does not contain %q\n--- got ---\n%s", want, got)
		}
	}
	// The scan help says once which rules scan runs, and says that the
	// --no-connect line lists and checks the configs. The old text said that
	// scan applies no rules: it must be gone.
	for _, once := range []string{
		"built-in config rules (T4 and T5)",
		"List the servers in the configs and check the configs.",
		"not applied yet",
	} {
		if n := strings.Count(got, once); n != 1 {
			t.Errorf("usage text holds %q %d times, want 1\n--- got ---\n%s", once, n, got)
		}
	}
	for _, gone := range []string{"no rules", "applies no rules", "No rules were applied"} {
		if strings.Contains(got, gone) {
			t.Errorf("usage text holds the old text %q\n--- got ---\n%s", gone, got)
		}
	}
}

func TestQuoteArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "extra", want: `"extra"`},
		{name: "empty", in: "", want: `""`},
		{name: "space", in: "a b", want: `"a b"`},
		{name: "quote and backslash", in: `a"b\c`, want: `"a\"b\\c"`},
		{name: "leading quote", in: `"x"`, want: `"\"x\""`},
		{name: "ESC", in: "a\x1b[31mb", want: `"a\x1b[31mb"`},
		// %q keeps a Hangul filler as it is. termsafe.Quote escapes it.
		{name: "blank rune", in: "a\u3164b", want: `"a\u3164b"`},
		{name: "invalid UTF-8", in: "a\xffb", want: `"a\xffb"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := quoteArg(tt.in)
			if got != tt.want {
				t.Errorf("quoteArg(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if back, err := strconv.Unquote(got); err != nil || back != tt.in {
				t.Errorf("Unquote(quoteArg(%q)) = %q, %v, want the input", tt.in, back, err)
			}
		})
	}
}

// TestCLIRunUnknownFlagEscapesControlChars checks terminal safety for the flag
// parse error. The flag package puts the raw flag name in its error, so
// cli.dispatch must escape the error text with termsafe.Quote. A raw ESC byte must never reach stderr.
func TestCLIRunUnknownFlagEscapesControlChars(t *testing.T) {
	t.Parallel()

	c, stdout, stderr := newTestCLI(fakeGetenv(nil), buildInfo{})

	code := c.dispatch([]string{"--\x1b[31mx"})

	if code != exitError {
		t.Errorf("run() = %d, want %d", code, exitError)
	}
	assertNoEscape(t, stdout.String(), stderr.String())
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

func TestParseGlobals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		args        []string
		env         map[string]string
		wantNoColor bool
		wantRest    []string
	}{
		{name: "no flag, NO_COLOR unset", args: []string{"version"}, wantNoColor: false, wantRest: []string{"version"}},
		{name: "two-dash flag", args: []string{"--no-color", "version"}, wantNoColor: true, wantRest: []string{"version"}},
		{name: "one-dash flag", args: []string{"-no-color", "version"}, wantNoColor: true, wantRest: []string{"version"}},
		{name: "NO_COLOR is 1", args: []string{"version"}, env: map[string]string{"NO_COLOR": "1"}, wantNoColor: true, wantRest: []string{"version"}},
		// no-color.org: any non-empty value disables color, even "0".
		{name: "NO_COLOR is 0", args: []string{"version"}, env: map[string]string{"NO_COLOR": "0"}, wantNoColor: true, wantRest: []string{"version"}},
		{name: "NO_COLOR is empty", args: []string{"version"}, env: map[string]string{"NO_COLOR": ""}, wantNoColor: false, wantRest: []string{"version"}},
		{
			// Flags after the command are not global. They stay in rest.
			name:        "flag after the command",
			args:        []string{"version", "--no-color"},
			wantNoColor: false,
			wantRest:    []string{"version", "--no-color"},
		},
		{name: "no arguments", args: nil, wantNoColor: false, wantRest: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, _, _ := newTestCLI(fakeGetenv(tt.env), buildInfo{})

			opts, rest, err := c.parseGlobals(tt.args)

			if err != nil {
				t.Fatalf("parseGlobals(%q) error = %v, want nil", tt.args, err)
			}
			if opts.noColor != tt.wantNoColor {
				t.Errorf("parseGlobals(%q) noColor = %v, want %v", tt.args, opts.noColor, tt.wantNoColor)
			}
			if !slices.Equal(rest, tt.wantRest) {
				t.Errorf("parseGlobals(%q) rest = %q, want %q", tt.args, rest, tt.wantRest)
			}
		})
	}
}

func TestParseGlobalsErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		wantHelp bool
	}{
		{name: "short help flag", args: []string{"-h"}, wantHelp: true},
		{name: "long help flag", args: []string{"--help"}, wantHelp: true},
		{name: "unknown flag", args: []string{"--bogus"}, wantHelp: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, _, _ := newTestCLI(fakeGetenv(nil), buildInfo{})

			_, _, err := c.parseGlobals(tt.args)

			if err == nil {
				t.Fatalf("parseGlobals(%q) error = nil, want an error", tt.args)
			}
			if got := errors.Is(err, flag.ErrHelp); got != tt.wantHelp {
				t.Errorf("parseGlobals(%q) errors.Is(err, flag.ErrHelp) = %v, want %v (err: %v)", tt.args, got, tt.wantHelp, err)
			}
		})
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
