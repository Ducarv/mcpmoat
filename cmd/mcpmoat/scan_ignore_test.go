package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/rules"
)

// Tests for the --ignore flag and the .mcpmoat-ignore file of "mcpmoat scan"
// (FR-10). The ignore list is not used yet (scan has no findings before M4),
// so these tests check only what the user sees: the usage errors of the flag,
// the notice and the warnings for the file, and that the exit code and the
// table on stdout never change because of ignore content.

// ignoreUsageMsg is the end of the flag error for a bad --ignore value. The
// flag package writes it as `invalid value "<v>" for flag -ignore: <msg>`.
const ignoreUsageMsg = "for flag -ignore: --ignore needs a rule ID"

// usageHint is the line that every usage error prints after the message.
const usageHint = `Run "mcpmoat help" for usage.`

// ignoreCwdWarning is the warning of --config mode when getwd fails.
const ignoreCwdWarning = "mcpmoat scan: warning: cannot read the working directory; .mcpmoat-ignore is not read"

// ignoreWarnPrefix is the start of every warning about .mcpmoat-ignore.
const ignoreWarnPrefix = "mcpmoat scan: warning: "

// writeHomeConfig writes ~/.claude.json with one valid server (ok-srv) into
// home, so an auto-discovery scan of home exits with 0 and prints a table.
func writeHomeConfig(t *testing.T, home string) {
	t.Helper()
	writeServers(t, home, ".claude.json", map[string]any{
		"ok-srv": map[string]any{"command": "npx"},
	})
}

// runScanArgs runs "mcpmoat <args>" on c and returns the exit code, stdout and
// stderr.
func runScanArgs(c *cli, stdout, stderr *bytes.Buffer, args ...string) (int, string, string) {
	code := c.dispatch(args)
	return code, stdout.String(), stderr.String()
}

// lineWant is the expected text of one stderr line: the exact line, or only
// its start when prefix is true.
type lineWant struct {
	text   string
	prefix bool
}

// exactLine wants a line that is exactly s.
func exactLine(s string) lineWant { return lineWant{text: s} }

// prefixLine wants a line that starts with s.
func prefixLine(s string) lineWant { return lineWant{text: s, prefix: true} }

// assertStderrLines fails the test unless the non-empty lines of stderr match
// wants, one for one and in order.
func assertStderrLines(t *testing.T, stderr string, wants []lineWant) {
	t.Helper()
	lines := nonEmptyLines(stderr)
	if len(lines) != len(wants) {
		t.Fatalf("stderr has %d lines, want %d:\n%s", len(lines), len(wants), stderr)
	}
	for i, w := range wants {
		ok := lines[i] == w.text
		if w.prefix {
			ok = strings.HasPrefix(lines[i], w.text)
		}
		if !ok {
			kind := "="
			if w.prefix {
				kind = "starting with"
			}
			t.Errorf("stderr line %d = %q, want a line %s %q", i+1, lines[i], kind, w.text)
		}
	}
}

// assertScanPrefix fails the test if a non-empty stderr line does not start
// with "mcpmoat scan: ".
func assertScanPrefix(t *testing.T, stderr string) {
	t.Helper()
	for _, line := range nonEmptyLines(stderr) {
		if !strings.HasPrefix(line, "mcpmoat scan: ") {
			t.Errorf("stderr line %q does not start with %q", line, "mcpmoat scan: ")
		}
	}
}

// ignoreFileOfSize returns a valid .mcpmoat-ignore content of exactly size
// bytes: one entry, then comment lines. size must be at least 12.
func ignoreFileOfSize(size int) string {
	const entry = "MOAT-T1-001\n" // 12 bytes
	rest := size - len(entry)
	content := entry + strings.Repeat("#\n", rest/2)
	if rest%2 == 1 {
		content += "#"
	}
	return content
}

// TestScanIgnoreFlag checks the --ignore flag. A valid rule ID, given once or
// more, changes nothing that the user sees: exit code 0, the table, and only
// the no-rules notice on stderr (the IDs come from the user, so they give no
// notice). A value that is not a rule ID is a usage error with exit code 2
// and an empty stdout.
func TestScanIgnoreFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// args are the arguments after "scan". The token "CONFIG" is replaced
		// with the path of the home config file.
		args     []string
		wantCode int
		// wantStderr are substrings of stderr for a usage error.
		wantStderr []string
		noStderr   []string
	}{
		{
			name:     "one rule ID",
			args:     []string{"--no-connect", "--ignore", "MOAT-T1-003"},
			wantCode: exitOK,
		},
		{
			name:     "one rule ID with an equals sign",
			args:     []string{"--no-connect", "--ignore=MOAT-T1-003"},
			wantCode: exitOK,
		},
		{
			name:     "repeated flag",
			args:     []string{"--no-connect", "--ignore", "MOAT-T1-003", "--ignore", "MOAT-T2-001", "--ignore=custom_rule.v2"},
			wantCode: exitOK,
		},
		{
			name:     "the same rule ID twice",
			args:     []string{"--no-connect", "--ignore", "MOAT-T1-003", "--ignore", "MOAT-T1-003"},
			wantCode: exitOK,
		},
		{
			name:     "flag before --no-connect",
			args:     []string{"--ignore", "MOAT-T1-003", "--no-connect"},
			wantCode: exitOK,
		},
		{
			name:     "with --config",
			args:     []string{"--no-connect", "--config", "CONFIG", "--ignore", "MOAT-T1-003", "--ignore", "X1"},
			wantCode: exitOK,
		},
		{
			name:     "rule ID of 64 bytes",
			args:     []string{"--no-connect", "--ignore", "A" + strings.Repeat("b", 63)},
			wantCode: exitOK,
		},

		// Bad values.
		{
			name:       "empty value",
			args:       []string{"--no-connect", "--ignore", ""},
			wantCode:   exitError,
			wantStderr: []string{`mcpmoat scan: invalid value "" ` + ignoreUsageMsg, usageHint},
		},
		{
			name:       "empty value with an equals sign",
			args:       []string{"--no-connect", "--ignore="},
			wantCode:   exitError,
			wantStderr: []string{`mcpmoat scan: invalid value "" ` + ignoreUsageMsg, usageHint},
		},
		{
			// The flag package takes the next argument as the value.
			name:       "next flag taken as the value",
			args:       []string{"--ignore", "--no-connect"},
			wantCode:   exitError,
			wantStderr: []string{`invalid value "--no-connect" ` + ignoreUsageMsg, usageHint},
			noStderr:   []string{"not implemented"},
		},
		{
			name:       "value with a slash",
			args:       []string{"--no-connect", "--ignore", "bad/id"},
			wantCode:   exitError,
			wantStderr: []string{`invalid value "bad/id" ` + ignoreUsageMsg, usageHint},
		},
		{
			name:       "value that starts with a digit",
			args:       []string{"--no-connect", "--ignore", "1ABC"},
			wantCode:   exitError,
			wantStderr: []string{`invalid value "1ABC" ` + ignoreUsageMsg, usageHint},
		},
		{
			name:       "value with a space",
			args:       []string{"--no-connect", "--ignore", "MOAT T1"},
			wantCode:   exitError,
			wantStderr: []string{ignoreUsageMsg, usageHint},
		},
		{
			name:       "rule ID of 65 bytes",
			args:       []string{"--no-connect", "--ignore", "A" + strings.Repeat("b", 64)},
			wantCode:   exitError,
			wantStderr: []string{ignoreUsageMsg, usageHint},
		},
		{
			name:       "one bad value among good ones",
			args:       []string{"--no-connect", "--ignore", "MOAT-T1-003", "--ignore", "bad/id"},
			wantCode:   exitError,
			wantStderr: []string{`invalid value "bad/id" ` + ignoreUsageMsg, usageHint},
		},
		{
			name:       "bad value without --no-connect",
			args:       []string{"--ignore", "bad/id"},
			wantCode:   exitError,
			wantStderr: []string{ignoreUsageMsg, usageHint},
			noStderr:   []string{"not implemented"},
		},
		{
			name:       "value with an escape sequence",
			args:       []string{"--no-connect", "--ignore", "\x1b[31mred"},
			wantCode:   exitError,
			wantStderr: []string{"mcpmoat scan: ", ignoreUsageMsg, usageHint},
		},
		{
			// The flag package refuses a missing value with its own message.
			name:       "missing value",
			args:       []string{"--no-connect", "--ignore"},
			wantCode:   exitError,
			wantStderr: []string{"mcpmoat scan: ", "-ignore", usageHint},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			home := t.TempDir()
			writeHomeConfig(t, home)
			config := filepath.Join(home, ".claude.json")
			// The work dir is empty: no ignore file, no project config.
			c, stdout, stderr := dirsCLI(t, home, t.TempDir())

			args := []string{"scan"}
			for _, a := range tt.args {
				if a == "CONFIG" {
					a = config
				}
				args = append(args, a)
			}

			code, out, errOut := runScanArgs(c, stdout, stderr, args...)

			if code != tt.wantCode {
				t.Errorf("dispatch(%q) = %d, want %d\nstdout:\n%s\nstderr:\n%s", args, code, tt.wantCode, out, errOut)
			}
			if tt.wantCode == exitOK {
				assertContainsAll(t, "stdout", out, []string{"ok-srv"})
				assertNoRulesNotice(t, errOut)
			} else {
				if out != "" {
					t.Errorf("stdout = %q, want empty", out)
				}
				// A usage error is one message line and the hint, nothing
				// more: no notice, no warning and no table problem.
				assertStderrLines(t, errOut, []lineWant{
					prefixLine("mcpmoat scan: "),
					exactLine(usageHint),
				})
			}
			assertContainsAll(t, "stderr", errOut, tt.wantStderr)
			for _, bad := range tt.noStderr {
				if strings.Contains(errOut, bad) {
					t.Errorf("stderr contains %q\nstderr:\n%s", bad, errOut)
				}
			}
			assertNoEscape(t, out, errOut)
		})
	}
}

// TestScanIgnoreFile checks the .mcpmoat-ignore file in the working directory
// in auto-discovery mode. Valid entries give one notice with their number. A
// malformed line or a file that scan cannot read gives a warning. The exit
// code and stdout stay the same as without the file, and no warning shows
// file content.
func TestScanIgnoreFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup creates the ignore file (or something else with its name)
		// in the work dir.
		setup     func(t *testing.T, work string)
		wantLines []lineWant // all stderr lines, in order
		// wantStderr are more substrings of stderr.
		wantStderr []string
	}{
		{
			name:      "no file",
			setup:     func(*testing.T, string) {},
			wantLines: []lineWant{exactLine(noRulesNotice)},
		},
		{
			name: "two entries",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "MOAT-T1-003\nMOAT-T2-001 ok-srv/read_file\n")
			},
			wantLines: []lineWant{
				exactLine("mcpmoat scan: using 2 entries from .mcpmoat-ignore"),
				exactLine(noRulesNotice),
			},
		},
		{
			name: "one entry",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "# reviewed\nMOAT-T1-003 ok-srv  # a comment\n\n")
			},
			wantLines: []lineWant{
				exactLine("mcpmoat scan: using 1 entry from .mcpmoat-ignore"),
				exactLine(noRulesNotice),
			},
		},
		{
			name: "entries with CRLF and a byte order mark",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "\xef\xbb\xbfMOAT-T1-003\r\nMOAT-T1-004\r\nMOAT-T1-005\r\n")
			},
			wantLines: []lineWant{
				exactLine("mcpmoat scan: using 3 entries from .mcpmoat-ignore"),
				exactLine(noRulesNotice),
			},
		},
		{
			name: "only comments and blank lines",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "# nothing here\n\n   # indented comment\n\t\n")
			},
			wantLines: []lineWant{exactLine(noRulesNotice)},
		},
		{
			name: "empty file",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "")
			},
			wantLines: []lineWant{exactLine(noRulesNotice)},
		},
		{
			name: "malformed lines 2 and 4",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName,
					"MOAT-T1-003\nZZMARK/bad\nMOAT-T1-004 ok-srv\nMOAT-T1-005 a b ZZMARK\n")
			},
			wantLines: []lineWant{
				prefixLine(ignoreWarnPrefix + ".mcpmoat-ignore:2: "),
				prefixLine(ignoreWarnPrefix + ".mcpmoat-ignore:4: "),
				exactLine("mcpmoat scan: using 2 entries from .mcpmoat-ignore"),
				exactLine(noRulesNotice),
			},
		},
		{
			name: "only malformed lines",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName,
					"9ZZMARK\nMOAT-T1-001 /ZZMARK\n")
			},
			wantLines: []lineWant{
				prefixLine(ignoreWarnPrefix + ".mcpmoat-ignore:1: "),
				prefixLine(ignoreWarnPrefix + ".mcpmoat-ignore:2: "),
				exactLine(noRulesNotice),
			},
		},
		{
			name: "bad line with an escape sequence",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName,
					"\x1b[31mZZMARK\x1b[0m\nMOAT-T1-001 srv\x1b]0;ZZMARK\x07\n")
			},
			wantLines: []lineWant{
				prefixLine(ignoreWarnPrefix + ".mcpmoat-ignore:1: "),
				// A server name with an escape byte is not checked by the
				// parser, so line 2 can be an entry or a warning. Both are
				// fine; only the escaping matters here.
				prefixLine("mcpmoat scan: "),
				exactLine(noRulesNotice),
			},
		},
		{
			name: "bad line with invalid UTF-8",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "MOAT-\xffZZMARK\n")
			},
			wantLines: []lineWant{
				prefixLine(ignoreWarnPrefix + ".mcpmoat-ignore:1: "),
				exactLine(noRulesNotice),
			},
		},
		{
			name: "line too long",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "MOAT-T1-001 "+strings.Repeat("Z", 5000)+"ZZMARK\nMOAT-T1-002\n")
			},
			wantLines: []lineWant{
				prefixLine(ignoreWarnPrefix + ".mcpmoat-ignore:1: "),
				exactLine("mcpmoat scan: using 1 entry from .mcpmoat-ignore"),
				exactLine(noRulesNotice),
			},
		},
		{
			name: "directory with the file name",
			setup: func(t *testing.T, work string) {
				if err := os.Mkdir(filepath.Join(work, rules.IgnoreFileName), 0o750); err != nil {
					t.Fatal(err)
				}
			},
			wantLines: []lineWant{
				prefixLine(ignoreWarnPrefix),
				exactLine(noRulesNotice),
			},
			wantStderr: []string{".mcpmoat-ignore", "not a regular file"},
		},
		{
			name: "file larger than 1 MiB",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, ignoreFileOfSize(rules.MaxIgnoreFileBytes+1))
			},
			wantLines: []lineWant{
				prefixLine(ignoreWarnPrefix),
				exactLine(noRulesNotice),
			},
			wantStderr: []string{".mcpmoat-ignore", "larger than"},
		},
		{
			name: "file of exactly 1 MiB",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, ignoreFileOfSize(rules.MaxIgnoreFileBytes))
			},
			wantLines: []lineWant{
				exactLine("mcpmoat scan: using 1 entry from .mcpmoat-ignore"),
				exactLine(noRulesNotice),
			},
		},
		{
			// os.Root refuses a symlink that leaves the working directory.
			name: "symlink to a file outside the working directory",
			setup: func(t *testing.T, work string) {
				target := writeTestFile(t, t.TempDir(), "outside-ignore", "MOAT-T1-003\n")
				symlink(t, target, filepath.Join(work, rules.IgnoreFileName))
			},
			wantLines: []lineWant{
				prefixLine(ignoreWarnPrefix),
				exactLine(noRulesNotice),
			},
			wantStderr: []string{".mcpmoat-ignore"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			home := t.TempDir()
			writeHomeConfig(t, home)

			// The baseline: the same home and an empty work dir.
			base, baseOut, baseErr := dirsCLI(t, home, t.TempDir())
			baseCode, wantOut, _ := runScanArgs(base, baseOut, baseErr, "scan", "--no-connect")
			if baseCode != exitOK {
				t.Fatalf("baseline exit code = %d, want %d\nstderr:\n%s", baseCode, exitOK, baseErr)
			}

			work := t.TempDir()
			tt.setup(t, work)
			c, stdout, stderr := dirsCLI(t, home, work)

			code, out, errOut := runScanArgs(c, stdout, stderr, "scan", "--no-connect")

			if code != exitOK {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, out, errOut)
			}
			if out != wantOut {
				t.Errorf("the ignore file changes stdout\n--- without ---\n%s--- with ---\n%s", wantOut, out)
			}
			assertStderrLines(t, errOut, tt.wantLines)
			assertContainsAll(t, "stderr", errOut, tt.wantStderr)
			if strings.Contains(errOut, "ZZMARK") {
				t.Errorf("stderr shows content of the ignore file\nstderr:\n%s", errOut)
			}
			assertScanPrefix(t, errOut)
			assertNoEscape(t, out, errOut)
		})
	}
}

// TestScanIgnoreFileWarningCap checks that a file with many malformed lines
// gives at most rules.MaxIgnoreWarnings line warnings and one summary warning,
// so a hostile file cannot flood the terminal.
func TestScanIgnoreFileWarningCap(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	writeHomeConfig(t, home)
	work := t.TempDir()
	const bad = 25
	writeTestFile(t, work, rules.IgnoreFileName, strings.Repeat("ZZMARK/bad\n", bad)+"MOAT-T1-003\n")
	c, stdout, stderr := dirsCLI(t, home, work)

	code, out, errOut := runScanArgs(c, stdout, stderr, "scan", "--no-connect")

	if code != exitOK {
		t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, errOut)
	}
	var warnings []string
	for _, line := range nonEmptyLines(errOut) {
		if strings.HasPrefix(line, ignoreWarnPrefix) {
			warnings = append(warnings, line)
		}
	}
	if want := rules.MaxIgnoreWarnings + 1; len(warnings) != want {
		t.Fatalf("got %d warning lines, want %d\nstderr:\n%s", len(warnings), want, errOut)
	}
	for i, w := range warnings[:rules.MaxIgnoreWarnings] {
		if want := ignoreWarnPrefix + ".mcpmoat-ignore:" + strconv.Itoa(i+1) + ": "; !strings.HasPrefix(w, want) {
			t.Errorf("warning %d = %q, want it to start with %q", i+1, w, want)
		}
	}
	// The summary has no line number.
	if last := warnings[rules.MaxIgnoreWarnings]; !strings.HasPrefix(last, ignoreWarnPrefix+".mcpmoat-ignore: ") {
		t.Errorf("summary warning = %q, want it to start with %q", last, ignoreWarnPrefix+".mcpmoat-ignore: ")
	}
	assertContainsAll(t, "stderr", errOut, []string{"mcpmoat scan: using 1 entry from .mcpmoat-ignore", noRulesNotice})
	if strings.Contains(errOut, "ZZMARK") {
		t.Errorf("stderr shows content of the ignore file\nstderr:\n%s", errOut)
	}
	assertNoEscape(t, out, errOut)
}

// TestScanIgnoreFileNoticeCountsOnlyFileEntries checks that the notice counts
// only the entries of the file, not the --ignore IDs.
func TestScanIgnoreFileNoticeCountsOnlyFileEntries(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	writeHomeConfig(t, home)
	work := t.TempDir()
	writeTestFile(t, work, rules.IgnoreFileName, "MOAT-T1-003\n")
	c, stdout, stderr := dirsCLI(t, home, work)

	code, out, errOut := runScanArgs(c, stdout, stderr,
		"scan", "--no-connect", "--ignore", "MOAT-T2-001", "--ignore", "MOAT-T3-001")

	if code != exitOK {
		t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, errOut)
	}
	assertStderrLines(t, errOut, []lineWant{
		exactLine("mcpmoat scan: using 1 entry from .mcpmoat-ignore"),
		exactLine(noRulesNotice),
	})
	assertNoEscape(t, out, errOut)
}

// TestScanIgnoreFileDoesNotChangeErrorExit checks that a valid ignore file
// does not hide a config problem: the scan still exits with 2, and the
// notice still shows.
func TestScanIgnoreFileDoesNotChangeErrorExit(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	writeTestFile(t, home, ".claude.json", "{not json")
	work := t.TempDir()
	writeTestFile(t, work, rules.IgnoreFileName, "MOAT-T1-003\nMOAT-T1-004\n")
	c, stdout, stderr := dirsCLI(t, home, work)

	code, out, errOut := runScanArgs(c, stdout, stderr, "scan", "--no-connect", "--ignore", "MOAT-T2-001")

	if code != exitError {
		t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitError, out, errOut)
	}
	assertContainsAll(t, "stderr", errOut, []string{
		"mcpmoat scan: using 2 entries from .mcpmoat-ignore",
		".claude.json",
		configErrorHint,
	})
	if strings.Contains(errOut, noRulesNotice) {
		t.Errorf("stderr holds the notice %q, but the scan failed\nstderr:\n%s", noRulesNotice, errOut)
	}
	assertScanPrefix(t, errOut)
	assertNoEscape(t, out, errOut)
}

// TestScanIgnoreFileConfigMode checks that --config mode also reads
// .mcpmoat-ignore from the working directory, also when the config file is
// in another directory.
func TestScanIgnoreFileConfigMode(t *testing.T) {
	t.Parallel()

	t.Run("absolute config path in another directory", func(t *testing.T) {
		t.Parallel()

		config := writeServers(t, t.TempDir(), "mcp.json", map[string]any{"ok-srv": map[string]any{"command": "npx"}})
		work := t.TempDir()
		writeTestFile(t, work, rules.IgnoreFileName, "MOAT-T1-003\nMOAT-T1-004 ok-srv\n")
		c, stdout, stderr := dirsCLI(t, t.TempDir(), work)

		code, out, errOut := runScanArgs(c, stdout, stderr, "scan", "--no-connect", "--config", config)

		if code != exitOK {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, errOut)
		}
		assertContainsAll(t, "stdout", out, []string{"ok-srv"})
		assertStderrLines(t, errOut, []lineWant{
			exactLine("mcpmoat scan: using 2 entries from .mcpmoat-ignore"),
			exactLine(noRulesNotice),
		})
		assertNoEscape(t, out, errOut)
	})

	t.Run("relative config path", func(t *testing.T) {
		t.Parallel()

		work := t.TempDir()
		writeServers(t, work, "mcp.json", map[string]any{"ok-srv": map[string]any{"command": "npx"}})
		writeTestFile(t, work, rules.IgnoreFileName, "MOAT-T1-003\n")
		c, stdout, stderr := dirsCLI(t, t.TempDir(), work)

		code, out, errOut := runScanArgs(c, stdout, stderr, "scan", "--no-connect", "--config", "mcp.json")

		if code != exitOK {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, errOut)
		}
		assertContainsAll(t, "stdout", out, []string{"ok-srv"})
		assertStderrLines(t, errOut, []lineWant{
			exactLine("mcpmoat scan: using 1 entry from .mcpmoat-ignore"),
			exactLine(noRulesNotice),
		})
	})

	t.Run("malformed line", func(t *testing.T) {
		t.Parallel()

		config := writeServers(t, t.TempDir(), "mcp.json", map[string]any{"ok-srv": map[string]any{"command": "npx"}})
		work := t.TempDir()
		writeTestFile(t, work, rules.IgnoreFileName, "ZZMARK/bad\n")
		c, stdout, stderr := dirsCLI(t, t.TempDir(), work)

		code, out, errOut := runScanArgs(c, stdout, stderr, "scan", "--no-connect", "--config", config)

		if code != exitOK {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, errOut)
		}
		assertStderrLines(t, errOut, []lineWant{
			prefixLine(ignoreWarnPrefix + ".mcpmoat-ignore:1: "),
			exactLine(noRulesNotice),
		})
		if strings.Contains(errOut, "ZZMARK") {
			t.Errorf("stderr shows content of the ignore file\nstderr:\n%s", errOut)
		}
		assertNoEscape(t, out, errOut)
	})
}

// TestScanIgnoreConfigModeWithoutWorkDir checks --config mode when getwd
// fails: scan prints one warning, reads no ignore file and goes on. The exit
// code is the same as without the warning.
func TestScanIgnoreConfigModeWithoutWorkDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// missing makes the --config path a file that does not exist.
		missing   bool
		extra     []string
		wantCode  int
		wantLines []lineWant
	}{
		{
			name:     "valid config",
			wantCode: exitOK,
			wantLines: []lineWant{
				exactLine(ignoreCwdWarning),
				exactLine(noRulesNotice),
			},
		},
		{
			name:     "valid config with --ignore",
			extra:    []string{"--ignore", "MOAT-T1-003"},
			wantCode: exitOK,
			wantLines: []lineWant{
				exactLine(ignoreCwdWarning),
				exactLine(noRulesNotice),
			},
		},
		{
			name:     "missing config file",
			missing:  true,
			wantCode: exitError,
			wantLines: []lineWant{
				exactLine(ignoreCwdWarning),
				prefixLine("mcpmoat scan: "),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			config := filepath.Join(dir, "missing.json")
			if !tt.missing {
				config = writeServers(t, dir, "mcp.json", map[string]any{"ok-srv": map[string]any{"command": "npx"}})
			}
			// newTestCLI keeps a getwd that fails. Only the home is set.
			c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)
			home := t.TempDir()
			c.homeDir = func() (string, error) { return home, nil }

			args := append([]string{"scan", "--no-connect", "--config", config}, tt.extra...)
			code, out, errOut := runScanArgs(c, stdout, stderr, args...)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out, errOut)
			}
			if tt.wantCode == exitOK {
				assertContainsAll(t, "stdout", out, []string{"ok-srv"})
			}
			assertStderrLines(t, errOut, tt.wantLines)
			assertNoEscape(t, out, errOut)
		})
	}
}

// TestScanIgnoreHelp checks that "scan -h" and "mcpmoat help" describe the
// --ignore flag and the .mcpmoat-ignore file.
func TestScanIgnoreHelp(t *testing.T) {
	t.Parallel()

	wants := []string{"--ignore <rule-id>", "repeatable", ".mcpmoat-ignore"}

	for _, args := range [][]string{{"scan", "-h"}, {"help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()

			c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)

			code, out, errOut := runScanArgs(c, stdout, stderr, args...)

			if code != exitOK {
				t.Errorf("exit code = %d, want %d", code, exitOK)
			}
			assertContainsAll(t, "stdout", out, wants)
			if errOut != "" {
				t.Errorf("stderr = %q, want empty", errOut)
			}
		})
	}
}
