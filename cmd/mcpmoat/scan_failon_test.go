package main

import (
	"errors"
	"fmt"
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

// failOnInvalid is the flag error for a bad --fail-on value v, without the
// "mcpmoat scan: " prefix. The flag package writes it as
// `invalid value "<v>" for flag -fail-on: <msg>`.
func failOnInvalid(v string) string {
	return fmt.Sprintf("invalid value %q for flag -fail-on: --fail-on needs low, medium, high or critical", v)
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
		// want is the exit code for low, medium, high and critical.
		want perLevel[int]
	}{
		{
			name:    "clean config",
			servers: map[string]any{"clean-srv": failOnCleanServer},
			want:    perLevel[int]{exitOK, exitOK, exitOK, exitOK},
		},
		{
			name:    "low finding",
			servers: map[string]any{"low-srv": failOnLowServer, "clean-srv": failOnCleanServer},
			wantIDs: []string{"MOAT-T4-004"},
			want:    perLevel[int]{exitFindings, exitOK, exitOK, exitOK},
		},
		{
			name:    "medium finding",
			servers: map[string]any{"medium-srv": failOnMediumServer},
			wantIDs: []string{"MOAT-T4-003"},
			want:    perLevel[int]{exitFindings, exitFindings, exitOK, exitOK},
		},
		{
			name:    "high finding",
			servers: map[string]any{"high-srv": failOnHighServer},
			wantIDs: []string{"MOAT-T4-001"},
			want:    perLevel[int]{exitFindings, exitFindings, exitFindings, exitOK},
		},
		{
			name:    "low, medium and high findings",
			servers: failOnMixedServers(),
			wantIDs: failOnMixedIDs,
			want:    perLevel[int]{exitFindings, exitFindings, exitFindings, exitOK},
		},
	}

	for _, tt := range tests {
		for _, mode := range scanModes {
			for _, failOn := range failOnLevels {
				t.Run(tt.name+"/"+mode.name+"/fail-on "+string(failOn), func(t *testing.T) {
					t.Parallel()
					e := newPinEnv(t, tt.servers)
					args := append(slices.Clone(mode.args), "--fail-on", string(failOn))

					got := e.scan(failOnFake(tt.servers), args...)

					want := scanWant{code: tt.want.at(t, failOn)}
					if !slices.Contains(mode.args, "--no-connect") {
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
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"default is high", nil, exitFindings},
		{"equals form critical", []string{"--fail-on=critical"}, exitOK},
		{"equals form high", []string{"--fail-on=high"}, exitFindings},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, map[string]any{"high-srv": failOnHighServer})

			got := e.scan(nil, append([]string{"--no-connect"}, tc.args...)...)

			assertScanRun(t, got, scanWant{code: tc.want, stdout: []string{"MOAT-T4-001"}})
		})
	}
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

	tests := []struct {
		name string
		// args come after "scan --config <file>" and the mode flags.
		args    []string
		wantMsg string // the first stderr line, without "mcpmoat scan: "
		// missingConfig gives a --config file that does not exist.
		missingConfig bool
	}{
		{name: "empty value", args: []string{"--fail-on", ""}, wantMsg: failOnInvalid("")},
		{name: "upper case", args: []string{"--fail-on", "HIGH"}, wantMsg: failOnInvalid("HIGH")},
		{name: "upper case with equals", args: []string{"--fail-on=High"}, wantMsg: failOnInvalid("High")},
		{name: "unknown word", args: []string{"--fail-on", "bogus"}, wantMsg: failOnInvalid("bogus")},
		{name: "short form", args: []string{"--fail-on", "med"}, wantMsg: failOnInvalid("med")},
		{name: "value with a space", args: []string{"--fail-on", " high"}, wantMsg: failOnInvalid(" high")},
		{name: "number", args: []string{"--fail-on", "3"}, wantMsg: failOnInvalid("3")},
		{
			// The flag package takes the next argument as the value.
			name:    "flag name taken as the value",
			args:    []string{"--fail-on", "--no-connect"},
			wantMsg: failOnInvalid("--no-connect"),
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
			wantMsg:       failOnInvalid("bogus"),
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
// the findings. A case that stops before scan has findings runs at one
// --fail-on value only: with no finding, the value cannot change the result.
func TestScanFailOnExecErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup prepares e and returns the arguments after "scan" and before
		// the mode flags.
		setup func(t *testing.T, e *pinEnv) []string
		modes []string // the scanModes names to run; nil runs both
		// early is true when scan stops before it has findings: stdout must
		// be empty, and the case runs with --fail-on low only.
		early      bool
		wantStdout []string
		wantStderr []string
	}{
		{
			name: "invalid --rules folder",
			setup: func(_ *testing.T, e *pinEnv) []string {
				return []string{"--config", e.config, "--rules", scanRulesFixture("invalid")}
			},
			early:      true,
			wantStderr: []string{"mcpmoat scan: ", "bad-severity.yaml", "field severity"},
		},
		{
			name: "missing --config file",
			setup: func(t *testing.T, _ *pinEnv) []string {
				return []string{"--config", filepath.Join(t.TempDir(), "nope.json")}
			},
			early:      true,
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
			levels := failOnLevels
			if tt.early {
				levels = []rules.Severity{rules.SeverityLow}
			}
			for _, failOn := range levels {
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
					if tt.early {
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
// MOAT-T2-004 high finding: it gives 1 up to --fail-on high and 0 at critical.
//
// This test covers only the --fail-on dimension. TestScanPinnedNotInspectedExit
// (pin_flow_test.go) covers the default threshold, --ignore MOAT-T2-004 and the
// "1 finding ignored" line. TestScanPinsIgnoreFileWarningPerRule
// (scan_pins_test.go) covers that .mcpmoat-ignore cannot ignore a pin rule.
func TestScanFailOnServerFailure(t *testing.T) {
	t.Parallel()

	const failWarning = "mcpmoat scan: warning: server srv: failed: inspect: boom\n"
	// failing is the inspecttest fake that the scan_pins tests also use for
	// a server that fails. Its error is fixed, so the warning is exact.
	failing := func() *inspecttest.Fake {
		return &inspecttest.Fake{Errors: map[string]error{"srv": errors.New("boom")}}
	}

	t.Run("unpinned server with --fail-on low", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		got := e.scan(failing(), "--fail-on", "low")

		// The warning must be in scanWant: assertScanRun wants an empty
		// stderr for exit code 0 otherwise. A substring in scanWant also
		// turns off the clean-stderr rule, so check the exact stderr too:
		// the warning is the only line.
		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}, stderr: []string{failWarning}})
		if got.stderr != failWarning {
			t.Errorf("stderr = %q, want exactly %q", got.stderr, failWarning)
		}
		if rows := findingRows(t, got.stdout); len(rows) != 0 {
			t.Errorf("findings table has %d rows, want none\nstdout:\n%s", len(rows), got.stdout)
		}
	})

	// pinnedWant is the exit code for low, medium, high and critical.
	pinnedWant := perLevel[int]{exitFindings, exitFindings, exitFindings, exitOK}
	for _, failOn := range failOnLevels {
		t.Run("pinned server with --fail-on "+string(failOn), func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			firstScan(t, e, mkTool("a", "Add."))

			got := e.scan(failing(), "--fail-on", string(failOn))

			// The finding shows at every value: --fail-on changes only the
			// exit code.
			assertScanRun(t, got, scanWant{
				code:   pinnedWant.at(t, failOn),
				stdout: []string{"MOAT-T2-004", "high", "srv"},
				stderr: []string{failWarning},
			})
		})
	}
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
