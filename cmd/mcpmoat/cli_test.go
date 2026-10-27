package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/llm"
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
//
// toolBudget is one hour. The default budget is 5 s of wall-clock time, so a
// test that reads a big tool text could reach it on a busy machine (for
// example with -race and the whole suite in parallel) and get an extra
// MOAT-T1-023 row. A test of the budget sets c.toolBudget itself (see
// scanWithBudget).
func newTestCLI(getenv func(string) string, build buildInfo) (*cli, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	c := &cli{
		stdout:     &stdout,
		stderr:     &stderr,
		getenv:     getenv,
		build:      build,
		toolBudget: time.Hour,
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
		"  0  no finding that is not ignored at or above --fail-on\n",
		"  1  a finding that is not ignored at or above --fail-on (default high)\n",
		// Exit code 2 wins over 1 (FR-16). docs/exit-codes.md owns the
		// exact contract, so the usage text points to it.
		"  2  execution or usage error, also when there are findings\n",
		"     (https://github.com/Ducarv/mcpmoat/blob/HEAD/docs/exit-codes.md lists the causes and when the report still prints)\n",
		// The --fail-on flag line and its continuation lines. Only the text is
		// checked, not the padding that tabwriter prints.
		"  --fail-on <severity>  Exit 1 for a finding of this severity or above: low, medium, high or critical (default high)\n",
		"No built-in rule is critical yet, so critical passes every built-in finding and scan prints a note\n",
		"An unknown rule ID or severity still gives exit 1 (fail closed)\n",
		"The file cannot ignore the pin rules (MOAT-T2-*), the LLM rules (MOAT-LLM-001, MOAT-LLM-002) or the finding of a cut rule analysis",
		"  A new tool is medium, so alone it does not give exit code 1 with the default --fail-on high; next to a removed tool (a likely rename) it is high.\n",
		"  If that server is already pinned and failed or timed out, it is also a finding (MOAT-T2-004, high).\n",
		"  scan reads pins.json before it starts a server, and reads it again just before it saves the first-run pins.\n",
		"  Ctrl-C (or SIGTERM or SIGHUP) during the inspection, or after it while scan has new pins to save, stops scan with exit 2 and saves no pins.\n",
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
		// The description and schema rules (T1 and T3) run when scan
		// connects, with a time budget for each server. Config rules from
		// --rules never run. The --rules continuation line is checked
		// without the tabwriter padding.
		"Rules with target description or schema apply to the tools. Rules with target config are not applied\n",
		"  When scan connects to the servers, it applies the description and schema rules (T1 and T3, built-in and from --rules)\n",
		"  to the tools of each server. --no-connect applies none of them, and scan prints a note when --rules has such a rule.\n",
		"  The rule analysis of each server has a time budget of 5s. A server that uses it up is a finding (MOAT-T1-023):\n",
		"  high, or critical when a description or schema rule from --rules is critical.\n",
		"  Rules from --rules with target config are not applied: scan runs only its built-in config checks, and prints a note.\n",
		"  Exit code 1 means a finding that is not ignored, with severity at or above --fail-on (default high).\n",
		// The LLM flags (FR-17). The first line says that --llm is the one
		// exception to "offline". The flag lines and their continuation lines
		// are checked without the tabwriter padding where it can change.
		"mcpmoat finds malicious or tampered MCP servers. It runs offline, unless you use scan --llm.\n",
		"(schema: docs/schema/scan-output.v2.json)\n",
		"  --llm ",
		"Also ask an LLM to rate each tool description. Off by default. Not with --no-connect\n",
		"It sends the name and description of every tool to the LLM provider: this data leaves your machine\n",
		"The API key comes only from the MCPMOAT_LLM_API_KEY environment variable\n",
		"  --llm-provider <api>  The LLM API: anthropic, or openai for an OpenAI-compatible API (default anthropic)\n",
		"  --llm-model <name> ",
		"The model name (default for anthropic: " + llm.DefaultAnthropicModel + "; required for openai)\n",
		"  --llm-base-url <url>  The base URL of the API: https, or http for a loopback host only (default: the public API)\n",
		"  --llm: the LLM findings (MOAT-LLM-001, and MOAT-LLM-002 for an invalid answer) are advisory and marked [LLM].\n",
		"  They are high at most, and they count for --fail-on. They never remove a rule finding.\n",
		fmt.Sprintf("  scan sends at most %d tools. A provider error or more tools than that gives exit 2; the report still prints.\n", maxLLMTools),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("usage text does not contain %q\n--- got ---\n%s", want, got)
		}
	}
	// The scan help says once which rules scan runs, and says that the
	// --no-connect line lists and checks the configs. The old text said that
	// scan applies no rules: it must be gone. The failing-server note is only
	// in the scan notes, not in the exit code block too. The time budget and
	// its rule ID are named once, in the scan notes.
	for _, once := range []string{
		"built-in config rules (T4 and T5)",
		"List the servers in the configs and check the configs.",
		"description and schema rules (T1 and T3",
		"MOAT-T1-023",
		"time budget",
		"failed or timed out",
		// The key has one source, named once. The data warning is said once
		// in the flag list; the scan notes do not repeat it.
		"MCPMOAT_LLM_API_KEY",
		"leaves your machine",
	} {
		if n := strings.Count(got, once); n != 1 {
			t.Errorf("usage text holds %q %d times, want 1\n--- got ---\n%s", once, n, got)
		}
	}
	// Text that is not true and must not come back: the old "no rules"
	// lines, the limit fixed at high from before --fail-on, a bare exit code
	// 0 or 2 line, and the claim that any signal gives exit 2.
	for _, gone := range []string{
		"no rules", "applies no rules", "No rules were applied",
		"a finding of severity high or above",
		"(MOAT-T2-004, high, exit code 1)",
		"  0  no findings\n",
		"  2  execution error\n",
		"when it is stopped by a signal",
		"stops the servers, saves no pins and exits 2",
		// Before --llm the tool was offline with no exception, and the JSON
		// schema had version 1.
		"It runs offline.\n",
		"scan-output.v1.json",
		// Before issue #143 scan did not apply the tool rules (YAML) or the
		// rules from --rules.
		"not applied yet",
		"are not applied to tools",
	} {
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

// TestArgErrorsHideURLPassword checks that no argument error of any command
// shows the user info of a URL (FR-16, FR-17). A base URL can hold a user name
// and a password, and the flag package and the argument checks put the user
// argument in their error text. Each case is exit code 2, with the error kind
// in want and no part of the canary in stdout or stderr. A case with hidden
// set must also show hiddenArgText, so the test cannot pass when the error
// line drops the argument.
func TestArgErrorsHideURLPassword(t *testing.T) {
	t.Parallel()

	const canary = "CANARYpw-9f3a"
	// passURL has a user name and a password. userURL has only a user name,
	// which can be a token too.
	const passURL = "https://user:" + canary + "@host.example"
	const userURL = "https://" + canary + "@host.example"

	// The worlds of the cases. worldPlain has no home and no working
	// directory: the args must fail before scan or pin reads a config.
	// worldPin has one server "srv" in a --config file. worldAmbiguous has
	// two global config files in the home, each with a server named passURL.
	const (
		worldPlain = iota
		worldPin
		worldAmbiguous
	)
	tests := []struct {
		name   string
		world  int
		args   []string
		want   string // a part of stderr that names the error
		hidden bool   // stderr shows hiddenArgText
	}{
		{name: "global bad flag syntax", args: []string{"---llm-base-url=" + passURL, "scan"},
			want: "mcpmoat: bad flag syntax: ", hidden: true},
		{name: "global bad flag syntax, user only", args: []string{"---llm-base-url=" + userURL, "scan"},
			want: "mcpmoat: bad flag syntax: ", hidden: true},
		{name: "unknown command is the URL", args: []string{passURL},
			want: "mcpmoat: unknown command ", hidden: true},
		{name: "unknown command is the URL, user only", args: []string{userURL},
			want: "mcpmoat: unknown command ", hidden: true},
		{name: "pin bad flag syntax", args: []string{"pin", "---llm-base-url=" + passURL},
			want: "mcpmoat pin: bad flag syntax: ", hidden: true},
		{name: "pin --timeout=URL", args: []string{"pin", "--timeout=" + passURL},
			want: "mcpmoat pin: invalid value ", hidden: true},
		{name: "pin --timeout URL", args: []string{"pin", "--timeout", passURL},
			want: "mcpmoat pin: invalid value ", hidden: true},
		{name: "pin --timeout=URL, user only", args: []string{"pin", "--timeout=" + userURL},
			want: "mcpmoat pin: invalid value ", hidden: true},
		{name: "pin positional URL", args: []string{"pin", "--accept", "srv", passURL},
			want: "mcpmoat pin: unexpected arguments ", hidden: true},
		{name: "pin --accept URL, unknown server", world: worldPin, args: []string{"pin", "--accept", passURL},
			want: "mcpmoat pin: unknown server ", hidden: true},
		{name: "pin --accept URL, unknown server, user only", world: worldPin, args: []string{"pin", "--accept", userURL},
			want: "mcpmoat pin: unknown server ", hidden: true},
		{name: "pin --accept=URL, ambiguous server", world: worldAmbiguous, args: []string{"pin", "--accept=" + passURL},
			want: "mcpmoat pin: 2 servers are named ", hidden: true},
		{name: "version URL", args: []string{"version", passURL},
			want: "mcpmoat version: unexpected arguments ", hidden: true},
		{name: "version URL, user only", args: []string{"version", userURL},
			want: "mcpmoat version: unexpected arguments ", hidden: true},
		{name: "help URL", args: []string{"help", passURL},
			want: "mcpmoat help: unexpected arguments ", hidden: true},
		{name: "scan --llm=URL", args: []string{"scan", "--llm=" + passURL},
			want: "mcpmoat scan: invalid boolean value ", hidden: true},
		{name: "scan --llm URL", args: []string{"scan", "--llm", passURL},
			want: "mcpmoat scan: unexpected arguments ", hidden: true},
		{name: "scan --llm URL, user only", args: []string{"scan", "--llm", userURL},
			want: "mcpmoat scan: unexpected arguments ", hidden: true},
		{name: "scan --timeout=llm-base-url=URL", args: []string{"scan", "--timeout=llm-base-url=" + passURL},
			want: "mcpmoat scan: invalid value ", hidden: true},
		{name: "scan --timeout=URL, user only", args: []string{"scan", "--timeout=" + userURL},
			want: "mcpmoat scan: invalid value ", hidden: true},
		{name: "scan --llm-base-url=URL before a bad flag", args: []string{"scan", "--llm-base-url=" + passURL, "--bogus"},
			want: "mcpmoat scan: flag provided but not defined: -bogus"},
		{name: "scan --llm-base-url URL after a bad flag", args: []string{"scan", "--bogus", "--llm-base-url", passURL},
			want: "mcpmoat scan: flag provided but not defined: -bogus"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			args := tt.args
			var c *cli
			var stdoutBuf, stderrBuf *bytes.Buffer
			switch tt.world {
			case worldPlain:
				c, stdoutBuf, stderrBuf = newTestCLI(fakeGetenv(nil), testBuild)
			case worldPin:
				e := newPinEnv(t, oneServer("srv"))
				c, stdoutBuf, stderrBuf = e.cli(fakeServers(nil))
				args = append(slices.Clone(args), "--config", e.config)
			case worldAmbiguous:
				e := newPinEnv(t, oneServer("srv"))
				writeServers(t, e.home, ".claude.json", oneServer(passURL))
				writeServers(t, e.home, filepath.Join(".cursor", "mcp.json"), oneServer(passURL))
				c, stdoutBuf, stderrBuf = e.cli(fakeServers(nil))
			default:
				t.Fatalf("unknown world %d", tt.world)
			}

			code := c.dispatch(args)

			stdout, stderr := stdoutBuf.String(), stderrBuf.String()
			if code != exitError {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitError, stderr)
			}
			for _, out := range []struct{ name, text string }{{"stdout", stdout}, {"stderr", stderr}} {
				if part, leak := secretPartLeak(canary, out.text); leak {
					t.Errorf("%s holds %q, a part of the password %q:\n%s", out.name, part, canary, out.text)
				}
			}
			if !strings.Contains(stderr, tt.want) {
				t.Errorf("stderr does not hold %q:\n%s", tt.want, stderr)
			}
			if got := strings.Contains(stderr, hiddenArgText); got != tt.hidden {
				t.Errorf("stderr holds %q = %v, want %v:\n%s", hiddenArgText, got, tt.hidden, stderr)
			}
			assertNoEscape(t, stdout, stderr)
		})
	}
}
