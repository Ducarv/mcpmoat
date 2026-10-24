package main

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// Tests for the --ignore flag and the .mcpmoat-ignore file of "mcpmoat scan"
// (FR-10). They check what the user sees: the usage errors of the flag, the
// notice and the warnings for the file, and the effect of the ignore list on
// the findings block and on the exit code (TestScanIgnoreDropsFindings). An
// ignore entry for a rule that the config does not trigger changes nothing.

// ignoreUsageMsg is the end of the flag error for a bad --ignore value. The
// flag package writes it as `invalid value "<v>" for flag -ignore: <msg>`.
const ignoreUsageMsg = "for flag -ignore: --ignore needs a rule ID"

// ignoreCwdWarning is the warning of --config mode when getwd fails.
const ignoreCwdWarning = "mcpmoat scan: warning: cannot read the working directory; .mcpmoat-ignore is not read"

// ignoreMarker is a marker inside the bad lines of the ignore files of these
// tests. stderr must never contain it.
const ignoreMarker = "ZZMARK"

// writeHomeConfig writes ~/.claude.json with one valid server (ok-srv) into
// home, so an auto-discovery scan of home exits with 0 and prints a table.
func writeHomeConfig(t *testing.T, home string) {
	t.Helper()
	writeServers(t, home, ".claude.json", okServer)
}

// assertNoIgnoreContent fails the test if stderr shows ignoreMarker, which
// only the ignore file holds.
func assertNoIgnoreContent(t *testing.T, stderr string) {
	t.Helper()
	if strings.Contains(stderr, ignoreMarker) {
		t.Errorf("stderr shows content of the ignore file\nstderr:\n%s", stderr)
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
// more, for a rule that the config does not trigger, changes nothing that the
// user sees: exit code 0, the table, and nothing on stderr (the IDs come from
// the user, so they give no notice). A value that is not a rule ID is a usage
// error with exit code 2 and an empty stdout.
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

			args := append([]string{"scan"}, replaceToken(tt.args, "CONFIG", config)...)

			code, out, errOut := runScanArgs(c, stdout, stderr, args...)

			if code != tt.wantCode {
				t.Errorf("dispatch(%q) = %d, want %d\nstdout:\n%s\nstderr:\n%s", args, code, tt.wantCode, out, errOut)
			}
			if tt.wantCode == exitOK {
				assertContainsAll(t, "stdout", out, []string{"ok-srv"})
				assertCleanStderr(t, errOut)
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
			assertContainsNone(t, "stderr", errOut, tt.noStderr)
			assertNoEscape(t, out, errOut)
		})
	}
}

// TestScanIgnoreDropsFindings checks that --ignore and .mcpmoat-ignore remove
// findings from stdout and, when no finding of severity high or above is left,
// turn exit code 1 into exit code 0. Both servers hold a plaintext secret in
// an env entry, so each has one MOAT-T4-002 finding (high). Every case runs in
// auto-discovery and with --config.
func TestScanIgnoreDropsFindings(t *testing.T) {
	t.Parallel()

	const rule = "MOAT-T4-002"
	servers := map[string]any{
		"leaky-a": map[string]any{"command": "run", "env": map[string]string{"API_KEY": discovertest.CanaryEnv}},
		"leaky-b": map[string]any{"command": "run", "env": map[string]string{"API_KEY": discovertest.CanaryEnv}},
	}

	tests := []struct {
		name string
		// file is the content of .mcpmoat-ignore ("" writes no file).
		file string
		// flags are more arguments after --no-connect.
		flags []string
		// wantServers are the SERVER cells of the MOAT-T4-002 rows that stay.
		wantServers []string
		wantCode    int
		// wantNotice is the "using N entries" notice line on stderr ("" for
		// none). It comes first.
		wantNotice string
		// wantIgnored is the line that counts the dropped findings ("" for
		// none: a scan that drops nothing prints no such line). It follows
		// the notice.
		wantIgnored string
	}{
		{
			name:        "no ignore entry",
			wantServers: []string{"leaky-a", "leaky-b"},
			wantCode:    exitFindings,
		},
		{
			name:        "flag by rule",
			flags:       []string{"--ignore", rule},
			wantCode:    exitOK,
			wantIgnored: "mcpmoat scan: 2 findings ignored: MOAT-T4-002 (2)",
		},
		{
			name:        "flag for another rule",
			flags:       []string{"--ignore", "MOAT-T4-003"},
			wantServers: []string{"leaky-a", "leaky-b"},
			wantCode:    exitFindings,
		},
		{
			// The comparison is case-sensitive, so this is another rule.
			name:        "flag with the wrong case",
			flags:       []string{"--ignore", "moat-t4-002"},
			wantServers: []string{"leaky-a", "leaky-b"},
			wantCode:    exitFindings,
		},
		{
			name:        "file by rule",
			file:        rule + "\n",
			wantCode:    exitOK,
			wantIgnored: "mcpmoat scan: 2 findings ignored: MOAT-T4-002 (2)",
			wantNotice:  "mcpmoat scan: using 1 entry from .mcpmoat-ignore",
		},
		{
			// Only leaky-a is silenced, so leaky-b keeps the exit code at 1.
			name:        "file by rule and server",
			file:        rule + " leaky-a\n",
			wantServers: []string{"leaky-b"},
			wantCode:    exitFindings,
			wantIgnored: "mcpmoat scan: 1 finding ignored: MOAT-T4-002 (1)",
			wantNotice:  "mcpmoat scan: using 1 entry from .mcpmoat-ignore",
		},
		{
			name:        "file by rule and server for both servers",
			file:        rule + " leaky-a\n" + rule + " leaky-b\n",
			wantCode:    exitOK,
			wantIgnored: "mcpmoat scan: 2 findings ignored: MOAT-T4-002 (2)",
			wantNotice:  "mcpmoat scan: using 2 entries from .mcpmoat-ignore",
		},
		{
			// A server entry for another rule drops nothing.
			name:        "file by another rule and server",
			file:        "MOAT-T4-003 leaky-a\n",
			wantServers: []string{"leaky-a", "leaky-b"},
			wantCode:    exitFindings,
			wantNotice:  "mcpmoat scan: using 1 entry from .mcpmoat-ignore",
		},
		{
			// A rule entry for a server that does not exist drops nothing.
			name:        "file by rule and unknown server",
			file:        rule + " other-srv\n",
			wantServers: []string{"leaky-a", "leaky-b"},
			wantCode:    exitFindings,
			wantNotice:  "mcpmoat scan: using 1 entry from .mcpmoat-ignore",
		},
		{
			// A tool entry does not match a server-level finding.
			name:        "file by rule and tool",
			file:        rule + " leaky-a/read_file\n",
			wantServers: []string{"leaky-a", "leaky-b"},
			wantCode:    exitFindings,
			wantNotice:  "mcpmoat scan: using 1 entry from .mcpmoat-ignore",
		},
		{
			name:        "file by server plus flag by rule",
			file:        rule + " leaky-a\n",
			flags:       []string{"--ignore", rule},
			wantCode:    exitOK,
			wantIgnored: "mcpmoat scan: 2 findings ignored: MOAT-T4-002 (2)",
			wantNotice:  "mcpmoat scan: using 1 entry from .mcpmoat-ignore",
		},
		{
			// A comment line is no entry, so there is no notice either.
			name:        "commented line",
			file:        "# " + rule + "\n",
			wantServers: []string{"leaky-a", "leaky-b"},
			wantCode:    exitFindings,
		},
	}

	for _, tt := range tests {
		for _, mode := range configModes {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				t.Parallel()

				home, work := t.TempDir(), t.TempDir()
				args := scanServersArgs(t, mode, home, servers)
				if tt.file != "" {
					writeTestFile(t, work, rules.IgnoreFileName, tt.file)
				}
				args = append(args, tt.flags...)
				c, stdout, stderr := dirsCLI(t, home, work)

				code, out, errOut := runScanArgs(c, stdout, stderr, args...)

				if code != tt.wantCode {
					t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out, errOut)
				}
				// The server table never changes: both servers stay in it.
				if got := column(tableRows(t, out), 0); !slices.Equal(got, []string{"leaky-a", "leaky-b"}) {
					t.Errorf("table servers = %v, want both\nstdout:\n%s", got, out)
				}
				rows := findingRows(t, out)
				var gotServers []string
				for _, row := range rows {
					if row[0] == rule {
						gotServers = append(gotServers, row[2])
					}
				}
				if !slices.Equal(gotServers, tt.wantServers) {
					t.Errorf("%s findings for servers %v, want %v\nstdout:\n%s", rule, gotServers, tt.wantServers, out)
				}
				// A scan that drops every finding prints no findings block.
				if tt.wantServers == nil && len(rows) != 0 {
					t.Errorf("stdout still holds a findings block\n%s", out)
				}
				var wantLines []lineWant
				if tt.wantNotice != "" {
					wantLines = append(wantLines, exactLine(tt.wantNotice))
				}
				if tt.wantIgnored != "" {
					wantLines = append(wantLines, exactLine(tt.wantIgnored))
				}
				if len(wantLines) == 0 {
					assertCleanStderr(t, errOut)
				} else {
					assertStderrLines(t, errOut, wantLines)
				}
				if tt.wantIgnored == "" && strings.Contains(errOut, "ignored:") {
					t.Errorf("stderr has an ignored line, but nothing is dropped\nstderr:\n%s", errOut)
				}
				// The secret value never shows, in the findings block too.
				assertNoLeakBoth(t, out, errOut)
				assertNoEscape(t, out, errOut)
			})
		}
	}
}

// TestScanIgnoreHiddenHighFinding is the security case of FR-10: a project
// .mcpmoat-ignore file in the scanned folder (which can be untrusted) hides a
// high finding. The exit code stays 0, so the file does change the verdict.
// Then scan must not be silent about it: the ignored line is on stderr. The
// line names only the rule ID and a count, never a server name or a key.
func TestScanIgnoreHiddenHighFinding(t *testing.T) {
	t.Parallel()

	const (
		rule       = "MOAT-T4-002"
		serverName = "hidden-high-srv"
		envKey     = "HIDDEN_HIGH_KEY_NAME"
		wantLine   = "mcpmoat scan: 1 finding ignored: MOAT-T4-002 (1)"
	)
	servers := map[string]any{
		serverName: map[string]any{"command": "run", "env": map[string]string{envKey: discovertest.CanaryEnv}},
	}

	for _, mode := range configModes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			home, work := t.TempDir(), t.TempDir()
			args := scanServersArgs(t, mode, home, servers)

			// Control run: without the file the high finding fails the scan.
			c, stdout, stderr := dirsCLI(t, home, work)
			code, out, errOut := runScanArgs(c, stdout, stderr, args...)
			if code != exitFindings {
				t.Fatalf("control: exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFindings, out, errOut)
			}
			if !slices.Contains(findingIDs(findingRows(t, out)), rule) {
				t.Fatalf("control: stdout has no %s finding\n%s", rule, out)
			}
			assertCleanStderr(t, errOut)

			// With the project ignore file the finding is hidden.
			writeTestFile(t, work, rules.IgnoreFileName, rule+" "+serverName+"\n")
			c, stdout, stderr = dirsCLI(t, home, work)
			code, out, errOut = runScanArgs(c, stdout, stderr, args...)

			if code != exitOK {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, out, errOut)
			}
			if len(findingRows(t, out)) != 0 {
				t.Errorf("stdout still holds a findings block\n%s", out)
			}
			assertStderrLines(t, errOut, []lineWant{
				exactLine("mcpmoat scan: using 1 entry from .mcpmoat-ignore"),
				exactLine(wantLine),
			})
			// The ignored line holds no server name and no key. (The notice
			// line cannot, so check the whole stderr.)
			assertContainsNone(t, "stderr", errOut, []string{serverName, envKey})
			assertNoLeakBoth(t, out, errOut)
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
			wantLines: nil,
		},
		{
			name: "two entries",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "MOAT-T1-003\nMOAT-T2-001 ok-srv/read_file\n")
			},
			wantLines: []lineWant{
				exactLine("mcpmoat scan: using 2 entries from .mcpmoat-ignore"),
			},
		},
		{
			name: "one entry",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "# reviewed\nMOAT-T1-003 ok-srv  # a comment\n\n")
			},
			wantLines: []lineWant{
				exactLine("mcpmoat scan: using 1 entry from .mcpmoat-ignore"),
			},
		},
		{
			name: "entries with CRLF and a byte order mark",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "\xef\xbb\xbfMOAT-T1-003\r\nMOAT-T1-004\r\nMOAT-T1-005\r\n")
			},
			wantLines: []lineWant{
				exactLine("mcpmoat scan: using 3 entries from .mcpmoat-ignore"),
			},
		},
		{
			name: "only comments and blank lines",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "# nothing here\n\n   # indented comment\n\t\n")
			},
			wantLines: nil,
		},
		{
			name: "empty file",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "")
			},
			wantLines: nil,
		},
		{
			name: "malformed lines 2 and 4",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName,
					"MOAT-T1-003\n"+ignoreMarker+"/bad\nMOAT-T1-004 ok-srv\nMOAT-T1-005 a b "+ignoreMarker+"\n")
			},
			wantLines: []lineWant{
				prefixLine(scanWarnPrefix + ".mcpmoat-ignore:2: "),
				prefixLine(scanWarnPrefix + ".mcpmoat-ignore:4: "),
				exactLine("mcpmoat scan: using 2 entries from .mcpmoat-ignore"),
			},
		},
		{
			name: "only malformed lines",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName,
					"9"+ignoreMarker+"\nMOAT-T1-001 /"+ignoreMarker+"\n")
			},
			wantLines: []lineWant{
				prefixLine(scanWarnPrefix + ".mcpmoat-ignore:1: "),
				prefixLine(scanWarnPrefix + ".mcpmoat-ignore:2: "),
			},
		},
		{
			name: "bad line with an escape sequence",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName,
					"\x1b[31m"+ignoreMarker+"\x1b[0m\nMOAT-T1-001 srv\x1b]0;"+ignoreMarker+"\x07\n")
			},
			wantLines: []lineWant{
				prefixLine(scanWarnPrefix + ".mcpmoat-ignore:1: "),
				// A server name with an escape byte is not checked by the
				// parser, so line 2 can be an entry or a warning. Both are
				// fine; only the escaping matters here.
				prefixLine("mcpmoat scan: "),
			},
		},
		{
			name: "bad line with invalid UTF-8",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "MOAT-\xff"+ignoreMarker+"\n")
			},
			wantLines: []lineWant{
				prefixLine(scanWarnPrefix + ".mcpmoat-ignore:1: "),
			},
		},
		{
			name: "line too long",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, "MOAT-T1-001 "+strings.Repeat("Z", 5000)+ignoreMarker+"\nMOAT-T1-002\n")
			},
			wantLines: []lineWant{
				prefixLine(scanWarnPrefix + ".mcpmoat-ignore:1: "),
				exactLine("mcpmoat scan: using 1 entry from .mcpmoat-ignore"),
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
				prefixLine(scanWarnPrefix),
			},
			wantStderr: []string{".mcpmoat-ignore", "not a regular file"},
		},
		{
			name: "file larger than 1 MiB",
			setup: func(t *testing.T, work string) {
				writeTestFile(t, work, rules.IgnoreFileName, ignoreFileOfSize(rules.MaxIgnoreFileBytes+1))
			},
			wantLines: []lineWant{
				prefixLine(scanWarnPrefix),
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
				prefixLine(scanWarnPrefix),
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
			assertNoIgnoreContent(t, errOut)
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
	writeTestFile(t, work, rules.IgnoreFileName, strings.Repeat(ignoreMarker+"/bad\n", bad)+"MOAT-T1-003\n")
	c, stdout, stderr := dirsCLI(t, home, work)

	code, out, errOut := runScanArgs(c, stdout, stderr, "scan", "--no-connect")

	if code != exitOK {
		t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, errOut)
	}
	var warnings []string
	for _, line := range nonEmptyLines(errOut) {
		if strings.HasPrefix(line, scanWarnPrefix) {
			warnings = append(warnings, line)
		}
	}
	if want := rules.MaxIgnoreWarnings + 1; len(warnings) != want {
		t.Fatalf("got %d warning lines, want %d\nstderr:\n%s", len(warnings), want, errOut)
	}
	for i, w := range warnings[:rules.MaxIgnoreWarnings] {
		if want := scanWarnPrefix + ".mcpmoat-ignore:" + strconv.Itoa(i+1) + ": "; !strings.HasPrefix(w, want) {
			t.Errorf("warning %d = %q, want it to start with %q", i+1, w, want)
		}
	}
	// The summary has no line number.
	if last := warnings[rules.MaxIgnoreWarnings]; !strings.HasPrefix(last, scanWarnPrefix+".mcpmoat-ignore: ") {
		t.Errorf("summary warning = %q, want it to start with %q", last, scanWarnPrefix+".mcpmoat-ignore: ")
	}
	assertContainsAll(t, "stderr", errOut, []string{"mcpmoat scan: using 1 entry from .mcpmoat-ignore"})
	assertNoIgnoreContent(t, errOut)
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
	assertScanPrefix(t, errOut)
	assertNoEscape(t, out, errOut)
}

// TestScanIgnoreFileConfigMode checks that --config mode also reads
// .mcpmoat-ignore from the working directory, also when the config file is
// in another directory.
func TestScanIgnoreFileConfigMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// inWork puts mcp.json in the working directory and passes the
		// relative path; otherwise the config is an absolute path in
		// another directory.
		inWork    bool
		ignore    string
		wantLines []lineWant
	}{
		{
			name:   "absolute config path in another directory",
			ignore: "MOAT-T1-003\nMOAT-T1-004 ok-srv\n",
			wantLines: []lineWant{
				exactLine("mcpmoat scan: using 2 entries from .mcpmoat-ignore"),
			},
		},
		{
			name:   "relative config path",
			inWork: true,
			ignore: "MOAT-T1-003\n",
			wantLines: []lineWant{
				exactLine("mcpmoat scan: using 1 entry from .mcpmoat-ignore"),
			},
		},
		{
			name:   "malformed line",
			ignore: ignoreMarker + "/bad\n",
			wantLines: []lineWant{
				prefixLine(scanWarnPrefix + ".mcpmoat-ignore:1: "),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			work := t.TempDir()
			config := "mcp.json"
			if tt.inWork {
				writeServers(t, work, config, okServer)
			} else {
				config = writeServers(t, t.TempDir(), config, okServer)
			}
			writeTestFile(t, work, rules.IgnoreFileName, tt.ignore)
			c, stdout, stderr := dirsCLI(t, t.TempDir(), work)

			code, out, errOut := runScanArgs(c, stdout, stderr, "scan", "--no-connect", "--config", config)

			if code != exitOK {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, errOut)
			}
			assertContainsAll(t, "stdout", out, []string{"ok-srv"})
			assertStderrLines(t, errOut, tt.wantLines)
			assertNoIgnoreContent(t, errOut)
			assertNoEscape(t, out, errOut)
		})
	}
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
			},
		},
		{
			name:     "valid config with --ignore",
			extra:    []string{"--ignore", "MOAT-T1-003"},
			wantCode: exitOK,
			wantLines: []lineWant{
				exactLine(ignoreCwdWarning),
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
				config = writeServers(t, dir, "mcp.json", okServer)
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
