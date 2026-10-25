package main

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// Tests for the --fail-on flag of "mcpmoat scan" and the exit-code contract of
// FR-16: 0 for no finding at or above --fail-on, 1 for such a finding, 2 for an
// execution or usage error, also when there are findings. They run scan in
// process, in both modes (with and without --no-connect) where the case allows.

// The config servers of these tests. Each gives exactly one built-in config
// finding of one severity, or none.
var (
	// failOnLowServer turns on the npx yes option for a pinned package:
	// MOAT-T4-004 (low).
	failOnLowServer = map[string]any{"command": "npx", "args": []string{"-y", "@acme/fixture-tool@1.2.3"}}
	// failOnMediumServer runs an unpinned npx package: MOAT-T4-003 (medium).
	failOnMediumServer = map[string]any{"command": "npx", "args": []string{"@acme/fixture-other"}}
	// failOnHighServer is a remote server on plain http: MOAT-T4-001 (high).
	failOnHighServer = map[string]any{"type": "http", "url": "http://mcp.example.invalid/mcp"}
	// failOnCleanServer runs a pinned npx package: no finding.
	failOnCleanServer = map[string]any{"command": "npx", "args": []string{"@acme/fixture-clean@2.0.0"}}
)

// failOnMixedServers gives one low, one medium and one high finding.
func failOnMixedServers() map[string]any {
	return map[string]any{
		"low-srv":    failOnLowServer,
		"medium-srv": failOnMediumServer,
		"high-srv":   failOnHighServer,
	}
}

// failOnMixedIDs are the rule IDs of the findings of failOnMixedServers,
// sorted.
var failOnMixedIDs = []string{"MOAT-T4-001", "MOAT-T4-003", "MOAT-T4-004"}

// failOnFake returns a fake inspector that gives every server in servers one
// tool, so a scan without --no-connect pins them on its first run.
func failOnFake(servers map[string]any) *inspecttest.Fake {
	tools := make(map[string][]inspect.Tool, len(servers))
	for name := range servers {
		tools[name] = []inspect.Tool{mkTool("a", "Add.")}
	}
	return fakeServers(tools)
}

// sortedFindingIDs returns the rule IDs of the findings table of stdout,
// sorted.
func sortedFindingIDs(t *testing.T, stdout string) []string {
	t.Helper()
	ids := findingIDs(findingRows(t, stdout))
	slices.Sort(ids)
	return ids
}

// TestScanFailOnThresholds checks the exit code for every --fail-on value on
// configs with findings of known severities. A finding at or above the value
// gives 1, else 0. No built-in config rule is critical, so --fail-on critical
// gives 0 for all of them. The findings table is the same at every value:
// --fail-on changes only the exit code.
func TestScanFailOnThresholds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		servers map[string]any
		wantIDs []string // sorted; nil for no findings table
		// want is the exit code for low, medium, high and critical, in this
		// order (see failOnLevels).
		want [4]int
	}{
		{
			name:    "clean config",
			servers: map[string]any{"clean-srv": failOnCleanServer},
			want:    [4]int{exitOK, exitOK, exitOK, exitOK},
		},
		{
			name:    "low finding",
			servers: map[string]any{"low-srv": failOnLowServer, "clean-srv": failOnCleanServer},
			wantIDs: []string{"MOAT-T4-004"},
			want:    [4]int{exitFindings, exitOK, exitOK, exitOK},
		},
		{
			name:    "medium finding",
			servers: map[string]any{"medium-srv": failOnMediumServer},
			wantIDs: []string{"MOAT-T4-003"},
			want:    [4]int{exitFindings, exitFindings, exitOK, exitOK},
		},
		{
			name:    "high finding",
			servers: map[string]any{"high-srv": failOnHighServer},
			wantIDs: []string{"MOAT-T4-001"},
			want:    [4]int{exitFindings, exitFindings, exitFindings, exitOK},
		},
		{
			name:    "low, medium and high findings",
			servers: failOnMixedServers(),
			wantIDs: failOnMixedIDs,
			want:    [4]int{exitFindings, exitFindings, exitFindings, exitOK},
		},
	}

	for _, tt := range tests {
		for _, mode := range scanModes {
			for i, failOn := range failOnLevels {
				t.Run(tt.name+"/"+mode.name+"/fail-on "+string(failOn), func(t *testing.T) {
					t.Parallel()
					e := newPinEnv(t, tt.servers)
					args := append(slices.Clone(mode.args), "--fail-on", string(failOn))

					got := e.scan(failOnFake(tt.servers), args...)

					want := scanWant{code: tt.want[i]}
					if mode.args == nil {
						// The first run pins the servers: the notice shows
						// that scan connected.
						want.stderr = []string{"mcpmoat scan: pinned 1 tool for "}
					}
					assertScanRun(t, got, want)
					if ids := sortedFindingIDs(t, got.stdout); !slices.Equal(ids, tt.wantIDs) {
						t.Errorf("finding IDs = %v, want %v\nstdout:\n%s", ids, tt.wantIDs, got.stdout)
					}
				})
			}
		}
	}

	// The default is high, the PRD default, and --fail-on=<value> is the same
	// as --fail-on <value>.
	t.Run("default and equals form", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			args []string
			want int
		}{
			{nil, exitFindings},
			{[]string{"--fail-on=critical"}, exitOK},
			{[]string{"--fail-on=high"}, exitFindings},
		} {
			e := newPinEnv(t, map[string]any{"high-srv": failOnHighServer})
			got := e.scan(nil, append([]string{"--no-connect"}, tc.args...)...)
			if got.code != tc.want {
				t.Errorf("scan --no-connect %q: exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s",
					tc.args, got.code, tc.want, got.stdout, got.stderr)
			}
		}
	})
}

// TestScanFailOnIgnored checks that an ignored finding never counts for
// --fail-on: with --fail-on low, a config whose every finding is ignored exits
// 0. The ignored findings are still counted on stderr.
func TestScanFailOnIgnored(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// file is the content of .mcpmoat-ignore ("" writes no file).
		file  string
		flags []string
		// wantIDs are the rule IDs that stay in the table, sorted.
		wantIDs    []string
		wantCode   int
		wantStderr []string
	}{
		{
			name:       "every rule ignored with --ignore",
			flags:      []string{"--ignore", "MOAT-T4-001", "--ignore", "MOAT-T4-003", "--ignore", "MOAT-T4-004"},
			wantCode:   exitOK,
			wantStderr: []string{"mcpmoat scan: 3 findings ignored: "},
		},
		{
			name:     "every rule ignored with .mcpmoat-ignore",
			file:     "MOAT-T4-001\nMOAT-T4-003\nMOAT-T4-004\n",
			wantCode: exitOK,
			wantStderr: []string{
				"mcpmoat scan: using 3 entries from .mcpmoat-ignore",
				"mcpmoat scan: 3 findings ignored: ",
			},
		},
		{
			name:     "every server ignored with .mcpmoat-ignore",
			file:     "MOAT-T4-001 high-srv\nMOAT-T4-003 medium-srv\nMOAT-T4-004 low-srv\n",
			wantCode: exitOK,
			wantStderr: []string{
				"mcpmoat scan: using 3 entries from .mcpmoat-ignore",
				"mcpmoat scan: 3 findings ignored: ",
			},
		},
		{
			// The low finding stays, so --fail-on low still gives 1.
			name:       "only the medium and high rules ignored",
			flags:      []string{"--ignore", "MOAT-T4-001"},
			file:       "MOAT-T4-003\n",
			wantIDs:    []string{"MOAT-T4-004"},
			wantCode:   exitFindings,
			wantStderr: []string{"mcpmoat scan: 2 findings ignored: "},
		},
	}

	for _, tt := range tests {
		for _, mode := range scanModes {
			t.Run(tt.name+"/"+mode.name, func(t *testing.T) {
				t.Parallel()
				servers := failOnMixedServers()
				e := newPinEnv(t, servers)
				if tt.file != "" {
					writeTestFile(t, e.work, rules.IgnoreFileName, tt.file)
				}
				args := append(slices.Clone(mode.args), "--fail-on", "low")
				args = append(args, tt.flags...)

				got := e.scan(failOnFake(servers), args...)

				assertScanRun(t, got, scanWant{code: tt.wantCode, stderr: tt.wantStderr})
				if ids := sortedFindingIDs(t, got.stdout); !slices.Equal(ids, tt.wantIDs) {
					t.Errorf("finding IDs = %v, want %v\nstdout:\n%s", ids, tt.wantIDs, got.stdout)
				}
			})
		}
	}
}

// TestScanFailOnUsageErrors checks the values that --fail-on refuses. Each is a
// usage error with exit code 2: an empty stdout, the flag error and the usage
// hint on stderr, in both modes. scan starts no server and writes no pins. The
// check comes before the config file is read, so a missing file is not
// reported.
func TestScanFailOnUsageErrors(t *testing.T) {
	t.Parallel()

	const needs = "--fail-on needs low, medium, high or critical"

	tests := []struct {
		name string
		// args come after "scan --config <file>" and the mode flags.
		args    []string
		wantMsg string // the first stderr line, without "mcpmoat scan: "
		// missingConfig gives a --config file that does not exist.
		missingConfig bool
	}{
		{name: "empty value", args: []string{"--fail-on", ""}, wantMsg: `invalid value "" for flag -fail-on: ` + needs},
		{name: "upper case", args: []string{"--fail-on", "HIGH"}, wantMsg: `invalid value "HIGH" for flag -fail-on: ` + needs},
		{name: "upper case with equals", args: []string{"--fail-on=High"}, wantMsg: `invalid value "High" for flag -fail-on: ` + needs},
		{name: "unknown word", args: []string{"--fail-on", "bogus"}, wantMsg: `invalid value "bogus" for flag -fail-on: ` + needs},
		{name: "short form", args: []string{"--fail-on", "med"}, wantMsg: `invalid value "med" for flag -fail-on: ` + needs},
		{name: "value with a space", args: []string{"--fail-on", " high"}, wantMsg: `invalid value " high" for flag -fail-on: ` + needs},
		{name: "number", args: []string{"--fail-on", "3"}, wantMsg: `invalid value "3" for flag -fail-on: ` + needs},
		{
			// The flag package takes the next argument as the value.
			name:    "flag name taken as the value",
			args:    []string{"--fail-on", "--no-connect"},
			wantMsg: `invalid value "--no-connect" for flag -fail-on: ` + needs,
		},
		{name: "no value", args: []string{"--fail-on"}, wantMsg: "flag needs an argument: -fail-on"},
		{
			name:    "given twice with the same value",
			args:    []string{"--fail-on", "high", "--fail-on", "high"},
			wantMsg: `invalid value "high" for flag -fail-on: --fail-on given more than once`,
		},
		{
			name:    "given twice with other values",
			args:    []string{"--fail-on", "low", "--fail-on=critical"},
			wantMsg: `invalid value "critical" for flag -fail-on: --fail-on given more than once`,
		},
		{
			name:          "bad value before a missing config file",
			args:          []string{"--fail-on", "bogus"},
			wantMsg:       `invalid value "bogus" for flag -fail-on: ` + needs,
			missingConfig: true,
		},
	}

	for _, tt := range tests {
		for _, mode := range scanModes {
			t.Run(tt.name+"/"+mode.name, func(t *testing.T) {
				t.Parallel()
				servers := failOnMixedServers()
				e := newPinEnv(t, servers)
				config := e.config
				if tt.missingConfig {
					config = filepath.Join(t.TempDir(), "missing.json")
				}
				fake := failOnFake(servers)
				xdgBefore := dirSnapshot(t, e.xdg)
				args := append([]string{"scan", "--config", config}, mode.args...)
				args = append(args, tt.args...)

				got := e.raw(fake, args...)

				if got.code != exitError {
					t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got.code, exitError, got.stdout, got.stderr)
				}
				assertEmptyStdout(t, got.stdout)
				assertStderrLines(t, got.stderr, []lineWant{exactLine(scanPrefix + tt.wantMsg), exactLine(usageHint)})
				assertTerminalSafe(t, got.stderr)
				if calls := fake.Calls(); len(calls) != 0 {
					t.Errorf("the inspector was called for %v, want no call", calls)
				}
				assertDirUnchanged(t, e.xdg, xdgBefore)
			})
		}
	}
}

// TestScanFailOnExecErrors checks that an execution error gives exit code 2 at
// every --fail-on value, also when there are findings at or above it (FR-16:
// 2 wins over 1). When scan could read some configs, the report still prints
// the findings.
func TestScanFailOnExecErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup prepares e and returns the arguments after "scan" and before
		// the mode flags.
		setup      func(t *testing.T, e *pinEnv) []string
		modes      []string // the scanModes names to run; nil runs both
		wantStdout []string
		wantEmpty  bool // stdout must be empty
		wantStderr []string
	}{
		{
			name: "invalid --rules folder",
			setup: func(_ *testing.T, e *pinEnv) []string {
				return []string{"--config", e.config, "--rules", scanRulesFixture("invalid")}
			},
			wantEmpty:  true,
			wantStderr: []string{"mcpmoat scan: ", "bad-severity.yaml", "field severity"},
		},
		{
			name: "missing --config file",
			setup: func(t *testing.T, _ *pinEnv) []string {
				return []string{"--config", filepath.Join(t.TempDir(), "nope.json")}
			},
			wantEmpty:  true,
			wantStderr: []string{"mcpmoat scan: ", "nope.json", "file not found"},
		},
		{
			// Auto-discovery: ~/.claude.json is broken, ~/.cursor/mcp.json
			// holds a high finding. The report prints the finding, and the
			// exit code is 2.
			name: "a config file problem and a high finding",
			setup: func(t *testing.T, e *pinEnv) []string {
				writeTestFile(t, e.home, ".claude.json", `{"mcpServers": {`)
				writeServers(t, filepath.Join(e.home, ".cursor"), "mcp.json",
					map[string]any{"high-srv": map[string]any{"url": "http://mcp.example.invalid/mcp"}})
				return nil
			},
			wantStdout: []string{"MOAT-T4-001", "high-srv"},
			wantStderr: []string{"invalid JSON", configErrorHint},
		},
		{
			// The first-run pins cannot be saved. The report prints before
			// the save, so the findings still show.
			name: "pins.json cannot be saved and there are findings",
			setup: func(t *testing.T, e *pinEnv) []string {
				readOnlyPinsDir(t, e)
				return []string{"--config", e.config}
			},
			modes:      []string{"without --no-connect"},
			wantStdout: failOnMixedIDs,
			wantStderr: []string{"mcpmoat scan: cannot save the pins file: "},
		},
	}

	for _, tt := range tests {
		for _, mode := range scanModes {
			if tt.modes != nil && !slices.Contains(tt.modes, mode.name) {
				continue
			}
			for _, failOn := range failOnLevels {
				t.Run(tt.name+"/"+mode.name+"/fail-on "+string(failOn), func(t *testing.T) {
					t.Parallel()
					servers := failOnMixedServers()
					e := newPinEnv(t, servers)
					fake := failOnFake(servers)
					args := append([]string{"scan"}, tt.setup(t, e)...)
					args = append(args, mode.args...)
					args = append(args, "--fail-on", string(failOn))

					got := e.raw(fake, args...)

					assertScanRun(t, got, scanWant{code: exitError, stdout: tt.wantStdout, stderr: tt.wantStderr})
					if tt.wantEmpty {
						assertEmptyStdout(t, got.stdout)
					}
				})
			}
		}
	}
}

// TestScanFailOnServerFailure checks how a server that fails to answer counts
// for --fail-on. A server with no pins is a warning only, so it never changes
// the exit code, not even with --fail-on low. A pinned server that fails is a
// MOAT-T2-004 high finding: it gives 1 up to --fail-on high and 0 at critical,
// unless --ignore drops it. A .mcpmoat-ignore file cannot drop it.
func TestScanFailOnServerFailure(t *testing.T) {
	t.Parallel()

	const failWarning = "mcpmoat scan: warning: server srv: failed: inspect: boom\n"
	failing := func() *inspecttest.Fake {
		return &inspecttest.Fake{Errors: map[string]error{"srv": errors.New("boom")}}
	}

	t.Run("unpinned server with --fail-on low", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		got := e.scan(failing(), "--fail-on", "low")

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}, stderr: []string{failWarning}})
		if got.stderr != failWarning {
			t.Errorf("stderr = %q, want only the warning %q", got.stderr, failWarning)
		}
		assertNoPinRows(t, got.stdout)
		if rows := findingRows(t, got.stdout); len(rows) != 0 {
			t.Errorf("findings table has %d rows, want none\nstdout:\n%s", len(rows), got.stdout)
		}
	})

	pinned := []struct {
		failOn rules.Severity
		want   int
	}{
		{rules.SeverityLow, exitFindings},
		{rules.SeverityMedium, exitFindings},
		{rules.SeverityHigh, exitFindings},
		{rules.SeverityCritical, exitOK},
	}
	for _, tc := range pinned {
		t.Run("pinned server with --fail-on "+string(tc.failOn), func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			firstScan(t, e, mkTool("a", "Add."))

			got := e.scan(failing(), "--fail-on", string(tc.failOn))

			// The finding shows at every value: --fail-on changes only the
			// exit code.
			assertScanRun(t, got, scanWant{
				code:   tc.want,
				stdout: []string{"MOAT-T2-004", "high", "srv"},
				stderr: []string{failWarning},
			})
		})
	}

	t.Run("pinned server ignored with --ignore and --fail-on low", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("a", "Add."))

		got := e.scan(failing(), "--ignore", "MOAT-T2-004", "--fail-on", "low")

		assertScanRun(t, got, scanWant{
			code:     exitOK,
			noStdout: []string{"MOAT-T2-004"},
			stderr:   []string{failWarning, "mcpmoat scan: 1 finding ignored: MOAT-T2-004 (1)"},
		})
	})

	t.Run("pinned server in .mcpmoat-ignore still fails with --fail-on low", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("a", "Add."))
		writeTestFile(t, e.work, rules.IgnoreFileName, "MOAT-T2-004\n")

		got := e.scan(failing(), "--fail-on", "low")

		assertScanRun(t, got, scanWant{
			code:   exitFindings,
			stdout: []string{"MOAT-T2-004"},
			stderr: []string{failWarning, ".mcpmoat-ignore cannot ignore MOAT-T2-004"},
		})
		if strings.Contains(got.stderr, "finding ignored") {
			t.Errorf("stderr counts an ignored finding, want none\nstderr:\n%s", got.stderr)
		}
	})
}

// TestScanFailOnPin checks that --fail-on is a scan flag only: pin refuses it
// as an unknown flag with exit code 2.
func TestScanFailOnPin(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"pin", "--fail-on", "high"},
		{"pin", "--accept", "srv", "--fail-on", "high"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})
			xdgBefore := dirSnapshot(t, e.xdg)

			got := e.raw(fake, args...)

			assertEmptyStdout(t, got.stdout)
			if got.code != exitError {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", got.code, exitError, got.stderr)
			}
			assertStderrLines(t, got.stderr, []lineWant{
				exactLine("mcpmoat pin: flag provided but not defined: -fail-on"),
				exactLine(usageHint),
			})
			if calls := fake.Calls(); len(calls) != 0 {
				t.Errorf("the inspector was called for %v, want no call", calls)
			}
			assertDirUnchanged(t, e.xdg, xdgBefore)
		})
	}
}
