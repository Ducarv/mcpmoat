package main

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// Tests for the findings block of "scan --no-connect" on the fixtures under
// testdata/configs (the rule checks themselves are tested in internal/rules,
// see fixtures_test.go). Each test runs the scan on a copy of the fixture, in
// auto-discovery and with --config, and compares the whole FINDINGS block.
// The findings are grouped by severity, highest first, and keep the order of
// the servers inside one group.

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

// assertFindingRows fails the test unless the FINDINGS block of stdout has
// exactly the rows in want, in this order. A row is RULE, SEVERITY, SERVER,
// FIELD and KEY/RELATED, as findingRows builds it from the printed lines.
func assertFindingRows(t *testing.T, stdout string, want [][]string) {
	t.Helper()
	got := findingRows(t, stdout)
	if len(got) != len(want) {
		t.Errorf("findings block has %d rows, want %d\nstdout:\n%s", len(got), len(want), stdout)
	}
	for i := range min(len(got), len(want)) {
		if !slices.Equal(got[i], want[i]) {
			t.Errorf("finding row %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// assertFindingRuleText fails the test unless every finding of stdout shows
// the title, the risk and the fix of its built-in rule, and sits in the group
// of the severity of that rule. It checks that the text of the rule reaches
// the output. It fails when stdout holds no finding.
func assertFindingRuleText(t *testing.T, stdout string) {
	t.Helper()
	set := builtinSet(t)
	found := parseFindings(t, stdout)
	if len(found) == 0 {
		t.Fatalf("stdout holds no finding\nstdout:\n%s", stdout)
	}
	for _, f := range found {
		rule, ok := set.Get(f.RuleID)
		if !ok {
			t.Errorf("finding %s is not a built-in rule", f.RuleID)
			continue
		}
		if f.Title != rule.Title {
			t.Errorf("%s Title = %q, want %q", f.RuleID, f.Title, rule.Title)
		}
		if f.Risk != rule.Risk {
			t.Errorf("%s Risk = %q, want %q", f.RuleID, f.Risk, rule.Risk)
		}
		if f.Fix != rule.Remediation {
			t.Errorf("%s Fix = %q, want %q", f.RuleID, f.Fix, rule.Remediation)
		}
		if f.Severity != string(rule.Severity) {
			t.Errorf("%s is in group %q, want %q", f.RuleID, f.Severity, rule.Severity)
		}
	}
}

// findingsBlock returns the FINDINGS block of stdout, without its heading. It
// fails the test when stdout has no such block.
func findingsBlock(t *testing.T, stdout string) string {
	t.Helper()
	block := splitScanSections(stdout).Findings
	if block == "" {
		t.Fatalf("stdout has no findings block\nstdout:\n%s", stdout)
	}
	return block
}

// TestScanFindingsDangerousFixture scans testdata/configs/dangerous: nine
// servers, with findings of every T4 rule. It has high findings, so the exit
// code is 1. The findings come in groups from high to low. Inside a group they
// follow the server order (sorted by name), and the T4 checks keep the order
// of rules.CheckConfig inside one server. Each finding shows the title, the
// risk and the fix of its rule. No secret of the fixture shows, and the
// findings block names no host.
func TestScanFindingsDangerousFixture(t *testing.T) {
	t.Parallel()

	wantServers := []string{
		"docker-arg-secret", "docker-untagged", "env-secret", "latest-pkg", "npx-git-pinned",
		"npx-git-unpinned", "remote-local", "remote-plain", "remote-url-secret",
	}
	wantRows := [][]string{
		// high
		{"MOAT-T4-002", "high", "docker-arg-secret", "args", "-"},
		{"MOAT-T4-002", "high", "env-secret", "env", "GITHUB_TOKEN"},
		{"MOAT-T4-001", "high", "remote-plain", "url", "-"},
		{"MOAT-T4-002", "high", "remote-plain", "headers", "X-Api-Key"},
		{"MOAT-T4-002", "high", "remote-url-secret", "url", "-"},
		// medium
		{"MOAT-T4-003", "medium", "docker-untagged", "args", "registry.invalid/example/mcp-server"},
		{"MOAT-T4-003", "medium", "latest-pkg", "args", "@example-corp/files-mcp"},
		{"MOAT-T4-003", "medium", "npx-git-unpinned", "args", "-"},
		// low
		{"MOAT-T4-004", "low", "env-secret", "args", "-"},
		{"MOAT-T4-004", "low", "latest-pkg", "args", "-"},
		{"MOAT-T4-004", "low", "npx-git-pinned", "args", "-"},
		{"MOAT-T4-004", "low", "npx-git-unpinned", "args", "-"},
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
			assertFindingRuleText(t, stdout)
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
// severity high, so the exit code is 0. The medium findings come before the
// low ones, and each finding shows the text of its rule.
func TestScanFindingsTyposquatFixture(t *testing.T) {
	t.Parallel()

	wantServers := []string{"filesystem", "mcp-server-fecth", "memory"}
	wantRows := [][]string{
		{"MOAT-T5-001", "medium", "filesystem", "args", "@modelcontextprotocol/server-filesystem"},
		{"MOAT-T5-001", "medium", "mcp-server-fecth", "name", "mcp-server-fetch"},
		{"MOAT-T4-004", "low", "filesystem", "args", "-"},
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
			assertFindingRuleText(t, stdout)
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

// TestFindingRule checks the rule and the severity of a row: the rule and its
// YAML severity for a known rule, and a zero rule with "critical" (fail closed)
// for a rule that the set does not have, also when the set is nil.
func TestFindingRule(t *testing.T) {
	t.Parallel()
	set := builtinSet(t)

	tests := []struct {
		name string
		set  *rules.Set
		id   string
		want string
		// known is true when the set has the rule, so the result is that rule.
		known bool
	}{
		{"insecure url is high", set, rules.RuleInsecureURL, "high", true},
		{"plaintext secret is high", set, rules.RulePlaintextSecret, "high", true},
		{"unpinned package is medium", set, rules.RuleUnpinnedPackage, "medium", true},
		{"auto install is low", set, rules.RuleAutoInstall, "low", true},
		{"unknown rule fails closed", set, "MOAT-X-999", "critical", false},
		{"empty rule ID fails closed", set, "", "critical", false},
		{"nil set fails closed", nil, rules.RuleInsecureURL, "critical", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule, got := findingRule(tt.set, tt.id)
			if got != tt.want {
				t.Errorf("findingRule(%q) severity = %q, want %q", tt.id, got, tt.want)
			}
			if tt.known && (rule.ID != tt.id || rule.Risk == "" || rule.Remediation == "") {
				t.Errorf("findingRule(%q) rule = %+v, want the rule of the set", tt.id, rule)
			}
			if !tt.known && rule.ID+rule.Title+rule.Risk+rule.Remediation != "" {
				t.Errorf("findingRule(%q) rule = %+v, want a zero rule (empty texts)", tt.id, rule)
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

// TestNoBuiltinCriticalSeverity checks that no built-in rule and no pin change
// kind is critical. failOnCriticalNotice, the --fail-on help text and README
// "Exit codes" say so. When a critical rule is added, change those texts and
// this test.
func TestNoBuiltinCriticalSeverity(t *testing.T) {
	t.Parallel()

	builtin, errs := rules.Builtin()
	if len(errs) > 0 {
		t.Fatalf("rules.Builtin() errors: %v", errs)
	}
	for _, r := range builtin {
		if r.Severity == rules.SeverityCritical {
			t.Errorf("built-in rule %s is critical", r.ID)
		}
	}
	// A pin change can be raised to high, never above (pins.Compare).
	for _, k := range []pins.ChangeKind{pins.KindChanged, pins.KindNew, pins.KindRemoved, pins.KindUnverified} {
		if rules.Severity(k.Severity()) == rules.SeverityCritical {
			t.Errorf("pin change kind %s is critical", k)
		}
	}
}

// TestHasFailingFinding checks the exit-code rule of FR-16 for every --fail-on
// value: a row fails when its severity is at or above the threshold. An
// unknown row severity fails at every threshold (fail closed), and so does
// every row when the threshold itself is unknown (rank 0).
func TestHasFailingFinding(t *testing.T) {
	t.Parallel()

	// The want values are in the order low, medium, high, critical.
	never := perLevel[bool]{false, false, false, false}
	always := perLevel[bool]{true, true, true, true}
	upToMedium := perLevel[bool]{true, true, false, false}
	upToHigh := perLevel[bool]{true, true, true, false}
	onlyLow := perLevel[bool]{true, false, false, false}

	tests := []struct {
		name string
		rows []report.FindingRow
		want perLevel[bool]
	}{
		{"nil rows", nil, never},
		{"empty rows", severityRows(), never},
		{"low", severityRows("low"), onlyLow},
		{"medium", severityRows("medium"), upToMedium},
		{"high", severityRows("high"), upToHigh},
		{"critical", severityRows("critical"), always},
		{"unknown severity word", severityRows("bogus"), always},
		{"empty severity", severityRows(""), always},
		{"wrong case is unknown", severityRows("HIGH"), always},
		{"low and medium", severityRows("low", "medium"), upToMedium},
		{"low and high", severityRows("low", "high"), upToHigh},
		{"high and low", severityRows("high", "low"), upToHigh},
		{"medium and critical", severityRows("medium", "critical"), always},
		{"low and unknown", severityRows("low", "bogus"), always},
		{"every severity", severityRows("low", "medium", "high", "critical"), always},
	}
	for _, tt := range tests {
		for _, failOn := range failOnLevels {
			t.Run(tt.name+"/fail-on "+string(failOn), func(t *testing.T) {
				t.Parallel()
				want := tt.want.at(t, failOn)
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

	// The want values are in the order low, medium, high, critical.
	alwaysError := perLevel[int]{exitError, exitError, exitError, exitError}
	alwaysOK := perLevel[int]{exitOK, exitOK, exitOK, exitOK}

	tests := []struct {
		name string
		// execFailed is the first argument of scanExitCode: true when the
		// scan had an execution error.
		execFailed bool
		rows       []report.FindingRow
		want       perLevel[int]
	}{
		{
			name: "no failure, no findings",
			want: alwaysOK,
		},
		{
			name: "no failure, a low finding",
			rows: severityRows("low"),
			want: perLevel[int]{exitFindings, exitOK, exitOK, exitOK},
		},
		{
			name: "no failure, a high finding",
			rows: severityRows("high"),
			want: perLevel[int]{exitFindings, exitFindings, exitFindings, exitOK},
		},
		// A failed scan gives 2 for no rows, for a row that fails at every
		// threshold (critical) and for a row with an unknown severity.
		{name: "failed with no findings", execFailed: true, want: alwaysError},
		{name: "failed with a critical finding", execFailed: true, rows: severityRows("critical"), want: alwaysError},
		{name: "failed with an unknown severity", execFailed: true, rows: severityRows("bogus"), want: alwaysError},
	}
	for _, tt := range tests {
		for _, failOn := range failOnLevels {
			t.Run(tt.name+"/fail-on "+string(failOn), func(t *testing.T) {
				t.Parallel()
				want := tt.want.at(t, failOn)
				if got := scanExitCode(tt.execFailed, tt.rows, failOn); got != want {
					t.Errorf("scanExitCode(%v, %v, %q) = %d, want %d", tt.execFailed, tt.rows, failOn, got, want)
				}
			})
		}
	}
}

// TestConfigFindings checks configChecks.findings with servers built in the
// test: the rows, the severity and the rule text of every row, the rows of
// each server, the ignore list and the secrets.
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
			rows, ignored, counts := configChecks{set: set, typo: typo}.findings(tt.ignore, servers)

			if got := hasRule(rows, rules.RulePlaintextSecret); got != tt.wantSecret {
				t.Errorf("rows hold %s = %v, want %v\nrows: %+v", rules.RulePlaintextSecret, got, tt.wantSecret, rows)
			}
			// The other server must keep its findings in every case.
			for _, id := range []string{rules.RuleUnpinnedPackage, rules.RuleAutoInstall} {
				if !hasRule(rows, id) {
					t.Errorf("rows have no %s finding\nrows: %+v", id, rows)
				}
			}
			// One count for each server, and the counts add up to the rows.
			if len(counts) != len(servers) {
				t.Fatalf("counts = %v, want %d entries", counts, len(servers))
			}
			total := 0
			for _, n := range counts {
				total += n
			}
			if total != len(rows) {
				t.Errorf("counts = %v add up to %d, want %d rows", counts, total, len(rows))
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
				rule, ok := set.Get(r.RuleID)
				if !ok {
					t.Errorf("row %d (%s) is not a built-in rule", i, r.RuleID)
				} else if r.Title != rule.Title || r.Risk != rule.Risk || r.Remediation != rule.Remediation {
					t.Errorf("row %d (%s) has Title %q, Risk %q, Remediation %q, want the text of the rule",
						i, r.RuleID, r.Title, r.Risk, r.Remediation)
				}
				if r.RuleID == rules.RulePlaintextSecret && r.Severity != "high" {
					t.Errorf("row %d (%s) Severity = %q, want high", i, r.RuleID, r.Severity)
				}
				for name, field := range map[string]string{
					"RuleID": r.RuleID, "Severity": r.Severity, "Server": r.Name,
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
