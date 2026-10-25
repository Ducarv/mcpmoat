package main

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// Tests for the findings block of "scan --no-connect" on the fixtures under
// testdata/configs (the rule checks themselves are tested in internal/rules,
// see fixtures_test.go). Each test runs the scan on a copy of the fixture, in
// auto-discovery and with --config, and compares the whole findings table.

// findingsFixtureHost is the host of the remote servers of the fixtures. The
// server table may show it, the findings block must not.
const findingsFixtureHost = "mcp.example.invalid"

// findingsScan runs "scan --no-connect" on a copy of the fixture
// testdata/configs/<fixture>, in auto-discovery (mode "auto") or with
// --config on the copy of .cursor/mcp.json (mode "config"). Any other mode
// fails the test. It returns the exit code, stdout and stderr. It never
// touches the real $HOME.
func findingsScan(t *testing.T, fixture, mode string) (code int, stdout, stderr string) {
	t.Helper()
	home, work := discovertest.CopyFixture(t, testdataPath("configs", fixture))
	args := []string{"scan", "--no-connect"}
	switch mode {
	case "auto":
	case "config":
		args = append(args, "--config", filepath.Join(home, ".cursor", "mcp.json"))
	default:
		t.Fatalf("unknown scan mode %q", mode)
	}
	c, out, errOut := dirsCLI(t, home, work)
	return runScanArgs(c, out, errOut, args...)
}

// assertFindingRows fails the test unless the findings table of stdout has
// exactly the rows in want, in this order. A row is RULE, SEVERITY, SERVER,
// FIELD and KEY/RELATED, as printed.
func assertFindingRows(t *testing.T, stdout string, want [][]string) {
	t.Helper()
	got := findingRows(t, stdout)
	if len(got) != len(want) {
		t.Errorf("findings table has %d rows, want %d\nstdout:\n%s", len(got), len(want), stdout)
	}
	for i := range min(len(got), len(want)) {
		if !slices.Equal(got[i], want[i]) {
			t.Errorf("finding row %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// findingsBlock returns the part of stdout after the first blank line, which
// is the findings table. It fails the test when stdout has no blank line.
func findingsBlock(t *testing.T, stdout string) string {
	t.Helper()
	_, block, found := splitScanOutput(stdout)
	if !found {
		t.Fatalf("stdout has no findings block\nstdout:\n%s", stdout)
	}
	return block
}

// TestScanFindingsDangerousFixture scans testdata/configs/dangerous: nine
// servers, with findings of every T4 rule. It has high findings, so the exit
// code is 1. The rows are sorted by server name, and the T4 checks keep the
// order of rules.CheckConfig inside one server. No secret of the fixture
// shows, and the findings block names no host.
func TestScanFindingsDangerousFixture(t *testing.T) {
	t.Parallel()

	wantServers := []string{
		"docker-arg-secret", "docker-untagged", "env-secret", "latest-pkg", "npx-git-pinned",
		"npx-git-unpinned", "remote-local", "remote-plain", "remote-url-secret",
	}
	wantRows := [][]string{
		{"MOAT-T4-002", "high", "docker-arg-secret", "args", "-"},
		{"MOAT-T4-003", "medium", "docker-untagged", "args", "registry.invalid/example/mcp-server"},
		{"MOAT-T4-002", "high", "env-secret", "env", "GITHUB_TOKEN"},
		{"MOAT-T4-004", "low", "env-secret", "args", "-"},
		{"MOAT-T4-003", "medium", "latest-pkg", "args", "@example-corp/files-mcp"},
		{"MOAT-T4-004", "low", "latest-pkg", "args", "-"},
		{"MOAT-T4-004", "low", "npx-git-pinned", "args", "-"},
		{"MOAT-T4-003", "medium", "npx-git-unpinned", "args", "-"},
		{"MOAT-T4-004", "low", "npx-git-unpinned", "args", "-"},
		{"MOAT-T4-001", "high", "remote-plain", "url", "-"},
		{"MOAT-T4-002", "high", "remote-plain", "headers", "X-Api-Key"},
		{"MOAT-T4-002", "high", "remote-url-secret", "url", "-"},
	}
	canaries := dangerousCanaries

	for _, mode := range configModes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := findingsScan(t, "dangerous", mode)

			assertScanResult(t, code, stdout, stderr, scanWant{code: exitFindings, noStdout: canaries})
			assertCleanStderr(t, stderr)
			assertContainsNone(t, "stderr", stderr, canaries)
			if got := column(tableRows(t, stdout), 0); !slices.Equal(got, wantServers) {
				t.Errorf("table servers = %v, want %v\nstdout:\n%s", got, wantServers, stdout)
			}
			assertFindingRows(t, stdout, wantRows)
			assertContainsNone(t, "the findings block", findingsBlock(t, stdout), []string{findingsFixtureHost})
		})
	}

	// The same input gives the same output: the order of the rows is fixed.
	t.Run("same output on every run", func(t *testing.T) {
		t.Parallel()

		_, first, _ := findingsScan(t, "dangerous", "config")
		for range 5 {
			_, again, _ := findingsScan(t, "dangerous", "config")
			if got, want := findingsBlock(t, again), findingsBlock(t, first); got != want {
				t.Fatalf("the findings block changed between runs\nfirst:\n%s\nagain:\n%s", want, got)
			}
		}
	})
}

// TestScanFindingsTyposquatFixture scans testdata/configs/typosquat: three
// servers, with T5 (medium) and T4-004 (low) findings only. Nothing reaches
// severity high, so the exit code is 0.
func TestScanFindingsTyposquatFixture(t *testing.T) {
	t.Parallel()

	wantServers := []string{"filesystem", "mcp-server-fecth", "memory"}
	wantRows := [][]string{
		{"MOAT-T4-004", "low", "filesystem", "args", "-"},
		{"MOAT-T5-001", "medium", "filesystem", "args", "@modelcontextprotocol/server-filesystem"},
		{"MOAT-T5-001", "medium", "mcp-server-fecth", "name", "mcp-server-fetch"},
		{"MOAT-T4-004", "low", "memory", "args", "-"},
	}

	for _, mode := range configModes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := findingsScan(t, "typosquat", mode)

			assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
			if got := column(tableRows(t, stdout), 0); !slices.Equal(got, wantServers) {
				t.Errorf("table servers = %v, want %v\nstdout:\n%s", got, wantServers, stdout)
			}
			assertFindingRows(t, stdout, wantRows)
			assertContainsNone(t, "the findings block", findingsBlock(t, stdout), []string{findingsFixtureHost})
		})
	}
}

// TestPrintIgnored checks the one stderr line that counts the findings which
// the ignore list dropped (FR-10): the noun, the total, the sorted rule IDs
// with their counts, and no output for an empty or nil map.
func TestPrintIgnored(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ignored map[string]int
		want    string // the whole stderr, "" for nothing
	}{
		{name: "nil map", ignored: nil, want: ""},
		{name: "empty map", ignored: map[string]int{}, want: ""},
		{
			name:    "one finding is singular",
			ignored: map[string]int{"MOAT-T4-002": 1},
			want:    "mcpmoat scan: 1 finding ignored: MOAT-T4-002 (1)\n",
		},
		{
			name:    "several findings of one rule are plural",
			ignored: map[string]int{"MOAT-T4-002": 2},
			want:    "mcpmoat scan: 2 findings ignored: MOAT-T4-002 (2)\n",
		},
		{
			name:    "rule IDs are sorted",
			ignored: map[string]int{"MOAT-T4-002": 4, "MOAT-T4-001": 1},
			want:    "mcpmoat scan: 5 findings ignored: MOAT-T4-001 (1), MOAT-T4-002 (4)\n",
		},
		{
			name: "many rules sort as text and add up",
			ignored: map[string]int{
				"MOAT-T5-001": 1, "MOAT-T4-004": 3, "MOAT-T4-001": 2, "MOAT-T4-003": 1,
			},
			want: "mcpmoat scan: 7 findings ignored: " +
				"MOAT-T4-001 (2), MOAT-T4-003 (1), MOAT-T4-004 (3), MOAT-T5-001 (1)\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, stdout, stderr := newTestCLI(fakeGetenv(nil), testBuild)

			c.printIgnored(tt.ignored)

			if got := stderr.String(); got != tt.want {
				t.Errorf("stderr = %q, want %q", got, tt.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty: the line goes to stderr", stdout.String())
			}
		})
	}
}

// builtinSet loads the built-in rules into a set. It fails the test on a
// load error.
func builtinSet(t *testing.T) *rules.Set {
	t.Helper()
	builtin, errs := rules.Builtin()
	if len(errs) > 0 {
		t.Fatalf("rules.Builtin() returned %d errors, first: %v", len(errs), errs[0])
	}
	set, errs := rules.NewSet(builtin, nil)
	if len(errs) > 0 {
		t.Fatalf("rules.NewSet() returned %d errors, first: %v", len(errs), errs[0])
	}
	return set
}

// TestFindingSeverity checks the severity of a row: the YAML severity for a
// known rule, and "critical" (fail closed) for a rule that the set does not
// have, also when the set is nil.
func TestFindingSeverity(t *testing.T) {
	t.Parallel()
	set := builtinSet(t)

	tests := []struct {
		name string
		set  *rules.Set
		id   string
		want string
	}{
		{"insecure url is high", set, rules.RuleInsecureURL, "high"},
		{"plaintext secret is high", set, rules.RulePlaintextSecret, "high"},
		{"unpinned package is medium", set, rules.RuleUnpinnedPackage, "medium"},
		{"auto install is low", set, rules.RuleAutoInstall, "low"},
		{"unknown rule fails closed", set, "MOAT-X-999", "critical"},
		{"empty rule ID fails closed", set, "", "critical"},
		{"nil set fails closed", nil, rules.RuleInsecureURL, "critical"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := findingSeverity(tt.set, tt.id); got != tt.want {
				t.Errorf("findingSeverity(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

// severityRows returns one report row for each severity word, in order.
func severityRows(severities ...string) []report.FindingRow {
	var rows []report.FindingRow
	for _, sev := range severities {
		rows = append(rows, report.FindingRow{RuleID: "MOAT-T4-001", Severity: sev})
	}
	return rows
}

// TestHasFailingFinding checks the exit-code rule of FR-16 for every --fail-on
// value: a row fails when its severity is at or above the threshold. An
// unknown row severity fails at every threshold (fail closed), and so does
// every row when the threshold itself is unknown (rank 0).
func TestHasFailingFinding(t *testing.T) {
	t.Parallel()

	// byLevel is the result for each --fail-on value.
	type byLevel = map[rules.Severity]bool
	low, medium, high, critical := rules.SeverityLow, rules.SeverityMedium, rules.SeverityHigh, rules.SeverityCritical
	never := byLevel{low: false, medium: false, high: false, critical: false}
	always := byLevel{low: true, medium: true, high: true, critical: true}

	tests := []struct {
		name string
		rows []report.FindingRow
		want byLevel
	}{
		{"nil rows", nil, never},
		{"empty rows", severityRows(), never},
		{"low", severityRows("low"), byLevel{low: true, medium: false, high: false, critical: false}},
		{"medium", severityRows("medium"), byLevel{low: true, medium: true, high: false, critical: false}},
		{"high", severityRows("high"), byLevel{low: true, medium: true, high: true, critical: false}},
		{"critical", severityRows("critical"), always},
		{"unknown severity word", severityRows("bogus"), always},
		{"empty severity", severityRows(""), always},
		{"wrong case is unknown", severityRows("HIGH"), always},
		{"low and medium", severityRows("low", "medium"), byLevel{low: true, medium: true, high: false, critical: false}},
		{"low and high", severityRows("low", "high"), byLevel{low: true, medium: true, high: true, critical: false}},
		{"high and low", severityRows("high", "low"), byLevel{low: true, medium: true, high: true, critical: false}},
		{"medium and critical", severityRows("medium", "critical"), always},
		{"low and unknown", severityRows("low", "bogus"), always},
		{"every severity", severityRows("low", "medium", "high", "critical"), always},
	}
	for _, tt := range tests {
		for _, failOn := range failOnLevels {
			t.Run(tt.name+"/fail-on "+string(failOn), func(t *testing.T) {
				t.Parallel()
				want := levelWant(t, tt.want, failOn)
				if got := hasFailingFinding(tt.rows, failOn); got != want {
					t.Errorf("hasFailingFinding(%v, %q) = %v, want %v", tt.rows, failOn, got, want)
				}
			})
		}
	}

	// runScan accepts only a known --fail-on value. If an unknown one gets
	// through anyway, its rank is 0, so every finding fails (fail closed).
	// No finding still passes.
	for _, failOn := range []rules.Severity{"", "bogus", "HIGH"} {
		t.Run("unknown threshold "+strconv.Quote(string(failOn)), func(t *testing.T) {
			t.Parallel()
			for _, sev := range []string{"low", "medium", "high", "critical", "bogus"} {
				if !hasFailingFinding(severityRows(sev), failOn) {
					t.Errorf("hasFailingFinding(%s row, %q) = false, want true", sev, failOn)
				}
			}
			if hasFailingFinding(nil, failOn) {
				t.Errorf("hasFailingFinding(nil, %q) = true, want false", failOn)
			}
		})
	}
}

// TestScanExitCode checks how scanExitCode maps its inputs to an exit code
// (FR-16): 2 when the scan failed, else 1 when a finding is at or above the
// threshold, else 0. TestHasFailingFinding covers the threshold rule for every
// severity, so this test checks only the mapping and the precedence: exit code
// 2 wins over 1 at every --fail-on value, whatever the rows are.
func TestScanExitCode(t *testing.T) {
	t.Parallel()

	t.Run("no failure, finding below --fail-on gives 0", func(t *testing.T) {
		t.Parallel()
		if got := scanExitCode(false, severityRows("low"), rules.SeverityHigh); got != exitOK {
			t.Errorf("scanExitCode(false, low row, high) = %d, want %d", got, exitOK)
		}
	})
	t.Run("no failure, finding at --fail-on gives 1", func(t *testing.T) {
		t.Parallel()
		if got := scanExitCode(false, severityRows("high"), rules.SeverityHigh); got != exitFindings {
			t.Errorf("scanExitCode(false, high row, high) = %d, want %d", got, exitFindings)
		}
	})

	// A failed scan gives 2 for no rows, for a row that fails at every
	// threshold (critical) and for a row with an unknown severity.
	failed := []struct {
		name string
		rows []report.FindingRow
	}{
		{"no findings", nil},
		{"a critical finding", severityRows("critical")},
		{"an unknown severity", severityRows("bogus")},
	}
	for _, tt := range failed {
		for _, failOn := range failOnLevels {
			t.Run("failed with "+tt.name+"/fail-on "+string(failOn), func(t *testing.T) {
				t.Parallel()
				if got := scanExitCode(true, tt.rows, failOn); got != exitError {
					t.Errorf("scanExitCode(true, %v, %q) = %d, want %d", tt.rows, failOn, got, exitError)
				}
			})
		}
	}
}

// TestConfigFindings checks configChecks.findings with servers built in the
// test: the rows, the severity of every row, the ignore list and the secrets.
func TestConfigFindings(t *testing.T) {
	t.Parallel()
	set := builtinSet(t)
	typo, err := rules.NewBuiltinTyposquat()
	if err != nil {
		t.Fatalf("rules.NewBuiltinTyposquat() error = %v", err)
	}

	const canary = "mcpmoat-canary-env-Qw9Rt4Yu7Io2"
	servers := []discover.Server{
		{
			Name:      "leaky",
			Transport: discover.TransportStdio,
			Command:   "node",
			Args:      discover.NewArgs([]string{"server.js"}),
			Env:       discover.SecretMap{"GITHUB_TOKEN": discover.NewSecret(canary)},
		},
		{
			Name:      "auto",
			Transport: discover.TransportStdio,
			Command:   "npx",
			Args:      discover.NewArgs([]string{"-y", "pkg"}),
		},
	}

	var ignoreSecret rules.IgnoreList
	ignoreSecret.Add(rules.IgnoreEntry{RuleID: rules.RulePlaintextSecret})

	hasRule := func(rows []report.FindingRow, id string) bool {
		return slices.ContainsFunc(rows, func(r report.FindingRow) bool { return r.RuleID == id })
	}

	tests := []struct {
		name        string
		ignore      *rules.IgnoreList
		wantSecret  bool
		wantIgnored map[string]int
	}{
		{"nil ignore list keeps all findings", nil, true, nil},
		{"empty ignore list keeps all findings", &rules.IgnoreList{}, true, nil},
		{"ignore list drops the secret finding", &ignoreSecret, false, map[string]int{rules.RulePlaintextSecret: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rows, ignored := configChecks{set: set, typo: typo}.findings(tt.ignore, servers)

			if got := hasRule(rows, rules.RulePlaintextSecret); got != tt.wantSecret {
				t.Errorf("rows hold %s = %v, want %v\nrows: %+v", rules.RulePlaintextSecret, got, tt.wantSecret, rows)
			}
			// The other server must keep its findings in every case.
			for _, id := range []string{rules.RuleUnpinnedPackage, rules.RuleAutoInstall} {
				if !hasRule(rows, id) {
					t.Errorf("rows have no %s finding\nrows: %+v", id, rows)
				}
			}
			if len(ignored) != len(tt.wantIgnored) {
				t.Errorf("ignored = %v, want %v", ignored, tt.wantIgnored)
			}
			for id, n := range tt.wantIgnored {
				if ignored[id] != n {
					t.Errorf("ignored[%q] = %d, want %d", id, ignored[id], n)
				}
			}

			for i, r := range rows {
				if r.Severity == "" {
					t.Errorf("row %d (%s) has an empty Severity", i, r.RuleID)
				}
				if r.RuleID == rules.RulePlaintextSecret && r.Severity != "high" {
					t.Errorf("row %d (%s) Severity = %q, want high", i, r.RuleID, r.Severity)
				}
				for name, field := range map[string]string{
					"RuleID": r.RuleID, "Severity": r.Severity, "Server": r.Server,
					"Field": r.Field, "Key": r.Key, "Related": r.Related,
				} {
					if strings.Contains(field, canary) {
						t.Errorf("row %d field %s holds the secret value", i, name)
					}
				}
			}
		})
	}
}
