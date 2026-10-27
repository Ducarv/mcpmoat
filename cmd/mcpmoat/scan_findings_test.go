package main

import (
	"fmt"
	"maps"
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
			assertServerNames(t, stdout, wantServers...)
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
			assertServerNames(t, stdout, wantServers...)
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
// kind is critical. failOnCriticalNotice, the --fail-on help text and docs/exit-codes.md
// say so. When a critical rule is added, change those texts and
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

	// The secret entry is in both lists, as if it came from --ignore.
	tests := []struct {
		name        string
		ignore      *scanIgnores
		wantSecret  bool
		wantIgnored map[string]int
	}{
		{"nil ignore list keeps all findings", nil, true, nil},
		{"empty ignore list keeps all findings", &scanIgnores{}, true, nil},
		{"ignore list drops the secret finding", &scanIgnores{all: ignoreSecret, flags: ignoreSecret}, false, map[string]int{rules.RulePlaintextSecret: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rows, ignored, counts, fileBlocked, cutServers := configChecks{set: set, typo: typo}.findings(tt.ignore, servers)
			if fileBlocked != nil {
				t.Errorf("fileBlocked = %v, want nil", fileBlocked)
			}
			// The servers have a few findings, far below the default caps.
			if cutServers != 0 {
				t.Errorf("cutServers = %d, want 0", cutServers)
			}

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

// Tests for the caps of the config findings (issue #213): at most
// configRowsPerServer rows for one server and configRowsTotal rows for the
// whole scan, with one MOAT-T4-005 row for each server that lost rows.

// cfgCapCanary is the env value of the servers of the cap tests. It looks
// like a secret, and no row, stdout or stderr may hold it.
const cfgCapCanary = "mcpmoat-canary-cap-Vb7Nm2Kq9Wx4"

// cfgCapServer returns a stdio server with n env keys TOKEN_000, TOKEN_001
// and so on, which all hold cfgCapCanary. Each key gives one MOAT-T4-002 row
// (high with the built-in rules), in key order. With npx true, the server
// runs "npx -y pkg", which adds one MOAT-T4-003 row (medium) and then one
// MOAT-T4-004 row (low) after the env rows. Else it runs "node server.js",
// which gives no other row.
func cfgCapServer(name string, n int, npx bool) discover.Server {
	env := make(discover.SecretMap, n)
	for i := range n {
		env[cfgCapKey(i)] = discover.NewSecret(cfgCapCanary)
	}
	s := discover.Server{
		Name:      name,
		Transport: discover.TransportStdio,
		Command:   "node",
		Args:      discover.NewArgs([]string{"server.js"}),
		Env:       env,
	}
	if npx {
		s.Command = "npx"
		s.Args = discover.NewArgs([]string{"-y", "pkg"})
	}
	return s
}

// cfgCapKey returns the env key number i of cfgCapServer.
func cfgCapKey(i int) string { return fmt.Sprintf("TOKEN_%03d", i) }

// cfgCapSet returns the built-in rule set with the severities in sev in place
// of the YAML severities, and without the rules in drop. A severity can be a
// word that mcpmoat does not know: NewSet does not check it. A dropped rule is
// unknown to the set, so findingRule gives its rows "critical".
func cfgCapSet(t *testing.T, sev map[string]rules.Severity, drop ...string) *rules.Set {
	t.Helper()
	builtin, errs := rules.Builtin()
	if len(errs) > 0 {
		t.Fatalf("rules.Builtin() returned %d errors, first: %v", len(errs), errs[0])
	}
	var kept []rules.Rule
	for _, r := range builtin {
		if slices.Contains(drop, r.ID) {
			continue
		}
		if s, ok := sev[r.ID]; ok {
			r.Severity = s
		}
		kept = append(kept, r)
	}
	set, errs := rules.NewSet(kept, nil)
	if len(errs) > 0 {
		t.Fatalf("rules.NewSet() returned %d errors, first: %v", len(errs), errs[0])
	}
	return set
}

// cfgCapView returns a row as "server|rule|severity|field|key|related", so a
// test can compare rows as short strings.
func cfgCapView(r report.FindingRow) string {
	return strings.Join([]string{r.Name, r.RuleID, r.Severity, r.Field, r.Key, r.Related}, "|")
}

// The views of the rows of cfgCapServer, for the want lists.
func secretView(server string, i int, sev string) string {
	return server + "|" + rules.RulePlaintextSecret + "|" + sev + "|env|" + cfgCapKey(i) + "|"
}

func unpinnedView(server, sev string) string {
	return server + "|" + rules.RuleUnpinnedPackage + "|" + sev + "|args||pkg"
}

func autoInstallView(server, sev string) string {
	return server + "|" + rules.RuleAutoInstall + "|" + sev + "|args||"
}

func capView(server, sev, related string) string {
	return server + "|" + rules.RuleConfigFindingCap + "|" + sev + "|||" + related
}

// cfgCapIgnores returns a scanIgnores. The entries in file are only in the
// all list, as if they came from .mcpmoat-ignore with --use-ignore-file. The
// entries in flags are in both lists, as if they came from --ignore.
func cfgCapIgnores(file, flags []rules.IgnoreEntry) *scanIgnores {
	ign := &scanIgnores{fileEntries: len(file)}
	for _, e := range file {
		ign.all.Add(e)
	}
	for _, e := range flags {
		ign.all.Add(e)
		ign.flags.Add(e)
	}
	return ign
}

// TestConfigFindingsCaps checks the caps of configChecks.findings with small
// caps: the rows that it keeps, their order, the MOAT-T4-005 row of each
// server that lost rows, the counts of each server, the ignored counts and
// the rule IDs that .mcpmoat-ignore cannot drop.
func TestConfigFindingsCaps(t *testing.T) {
	t.Parallel()
	typo, err := rules.NewBuiltinTyposquat()
	if err != nil {
		t.Fatalf("rules.NewBuiltinTyposquat() error = %v", err)
	}
	builtin := builtinSet(t)
	// lowFirst makes the env rows low and the last row (MOAT-T4-004)
	// critical, so the low rows come before the critical one.
	lowFirst := cfgCapSet(t, map[string]rules.Severity{
		rules.RulePlaintextSecret: rules.SeverityLow,
		rules.RuleAutoInstall:     rules.SeverityCritical,
	})
	secretCritical := cfgCapSet(t, map[string]rules.Severity{rules.RulePlaintextSecret: rules.SeverityCritical})
	secretBogus := cfgCapSet(t, map[string]rules.Severity{rules.RulePlaintextSecret: "bogus"})
	secretUnknown := cfgCapSet(t, nil, rules.RulePlaintextSecret)

	capEntry := rules.IgnoreEntry{RuleID: rules.RuleConfigFindingCap}
	secretEntry := rules.IgnoreEntry{RuleID: rules.RulePlaintextSecret, Server: "a"}

	tests := []struct {
		name    string
		set     *rules.Set
		caps    configCaps
		ignore  *scanIgnores
		servers []discover.Server
		want    []string // the rows, see cfgCapView
		// wantCounts is the number of rows of each server (the third result).
		wantCounts      []int
		wantIgnored     map[string]int
		wantFileBlocked []string
		// wantCut is the number of servers that lost rows to a cap (the
		// fifth result). It does not change when --ignore drops cap rows.
		wantCut int
	}{
		{
			name:    "below the per-server cap",
			set:     builtin,
			caps:    configCaps{perServer: 5, total: 100},
			servers: []discover.Server{cfgCapServer("a", 3, true), cfgCapServer("b", 2, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				unpinnedView("a", "medium"), autoInstallView("a", "low"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
			},
			wantCounts: []int{5, 2},
		},
		{
			name:    "exactly at both caps",
			set:     builtin,
			caps:    configCaps{perServer: 5, total: 7},
			servers: []discover.Server{cfgCapServer("a", 3, true), cfgCapServer("b", 2, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				unpinnedView("a", "medium"), autoInstallView("a", "low"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
			},
			wantCounts: []int{5, 2},
		},
		{
			name:    "equal severity keeps the first rows",
			set:     builtin,
			caps:    configCaps{perServer: 2},
			servers: []discover.Server{cfgCapServer("a", 5, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"),
				capView("a", "high", "3 more config findings are not listed; limit 2"),
			},
			// The cap row is one of the rows of the server, but it does not
			// count toward the cap: 2 rows and the cap row.
			wantCounts: []int{3},
			wantCut:    1,
		},
		{
			name:    "the most severe rows win and keep their order",
			set:     builtin,
			caps:    configCaps{perServer: 4},
			servers: []discover.Server{cfgCapServer("a", 3, true)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				unpinnedView("a", "medium"),
				capView("a", "high", "1 more config finding is not listed; limit 4"),
			},
			wantCounts: []int{5},
			wantCut:    1,
		},
		{
			name:    "a critical row after low rows is kept",
			set:     lowFirst,
			caps:    configCaps{perServer: 2},
			servers: []discover.Server{cfgCapServer("a", 3, true)},
			// The medium and the critical row are kept, in scan order. The
			// three low rows are left out, and the cap row is still high.
			want: []string{
				unpinnedView("a", "medium"), autoInstallView("a", "critical"),
				capView("a", "high", "3 more config findings are not listed; limit 2"),
			},
			wantCounts: []int{3},
			wantCut:    1,
		},
		{
			name:    "an omitted critical row makes the cap row critical",
			set:     secretCritical,
			caps:    configCaps{perServer: 1},
			servers: []discover.Server{cfgCapServer("a", 3, false)},
			want: []string{
				secretView("a", 0, "critical"),
				capView("a", "critical", "2 more config findings are not listed; limit 1"),
			},
			wantCounts: []int{2},
			wantCut:    1,
		},
		{
			name:    "an unknown severity counts as critical",
			set:     secretBogus,
			caps:    configCaps{perServer: 2},
			servers: []discover.Server{cfgCapServer("a", 3, true)},
			// The env rows keep the unknown word. They rank as critical, so
			// the first two win over the medium and the low row, and the
			// left-out one makes the cap row critical.
			want: []string{
				secretView("a", 0, "bogus"), secretView("a", 1, "bogus"),
				capView("a", "critical", "3 more config findings are not listed; limit 2"),
			},
			wantCounts: []int{3},
			wantCut:    1,
		},
		{
			name:    "a rule that the set does not have counts as critical",
			set:     secretUnknown,
			caps:    configCaps{perServer: 1},
			servers: []discover.Server{cfgCapServer("a", 2, true)},
			want: []string{
				secretView("a", 0, "critical"),
				capView("a", "critical", "3 more config findings are not listed; limit 1"),
			},
			wantCounts: []int{2},
			wantCut:    1,
		},
		{
			name:    "only medium and low rows left out give a high cap row",
			set:     builtin,
			caps:    configCaps{perServer: 3},
			servers: []discover.Server{cfgCapServer("a", 3, true)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				capView("a", "high", "2 more config findings are not listed; limit 3"),
			},
			wantCounts: []int{4},
			wantCut:    1,
		},
		{
			name:    "the caps count only the rows that the ignore list keeps",
			set:     builtin,
			caps:    configCaps{perServer: 2},
			ignore:  cfgCapIgnores([]rules.IgnoreEntry{secretEntry}, nil),
			servers: []discover.Server{cfgCapServer("a", 5, true), cfgCapServer("b", 3, false)},
			// The file drops the five env rows of server a, so its other two
			// rows fit. Server b has no entry and loses a row.
			want: []string{
				unpinnedView("a", "medium"), autoInstallView("a", "low"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
				capView("b", "high", "1 more config finding is not listed; limit 2"),
			},
			wantCounts:  []int{2, 3},
			wantIgnored: map[string]int{rules.RulePlaintextSecret: 5},
			wantCut:     1,
		},
		{
			name:    "the scan cap cuts the later servers",
			set:     builtin,
			caps:    configCaps{perServer: 3, total: 4},
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 3, false), cfgCapServer("c", 2, false)},
			// a takes 3 of the 4 rows, b gets the last one and c gets only
			// its cap row. The cap rows name the scan cap, which cut them.
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				secretView("b", 0, "high"),
				capView("b", "high", "2 more config findings are not listed; limit 4"),
				capView("c", "high", "2 more config findings are not listed; limit 4"),
			},
			wantCounts: []int{3, 2, 1},
			wantCut:    2,
		},
		{
			name:    "the per-server cap and then the scan cap",
			set:     builtin,
			caps:    configCaps{perServer: 3, total: 4},
			servers: []discover.Server{cfgCapServer("a", 5, false), cfgCapServer("b", 3, false)},
			// The per-server cap cuts a (limit 3). The scan cap cuts b
			// (limit 4). The cap row of a does not use the scan cap.
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
				capView("a", "high", "2 more config findings are not listed; limit 3"),
				secretView("b", 0, "high"),
				capView("b", "high", "2 more config findings are not listed; limit 4"),
			},
			wantCounts: []int{4, 2},
			wantCut:    2,
		},
		{
			name:    "a server with no rows after the scan cap gets no cap row",
			set:     builtin,
			caps:    configCaps{perServer: 3, total: 3},
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 0, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"), secretView("a", 2, "high"),
			},
			wantCounts: []int{3, 0},
		},
		{
			name:    "--ignore drops the cap row",
			set:     builtin,
			caps:    configCaps{perServer: 2},
			ignore:  cfgCapIgnores(nil, []rules.IgnoreEntry{capEntry}),
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 4, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
			},
			wantCounts:  []int{2, 2},
			wantIgnored: map[string]int{rules.RuleConfigFindingCap: 2},
			// Both servers still count: the report is not complete.
			wantCut: 2,
		},
		{
			name:    "--ignore for one server drops only its cap row",
			set:     builtin,
			caps:    configCaps{perServer: 2},
			ignore:  cfgCapIgnores(nil, []rules.IgnoreEntry{{RuleID: rules.RuleConfigFindingCap, Server: "b"}}),
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 4, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"),
				capView("a", "high", "1 more config finding is not listed; limit 2"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
			},
			wantCounts:  []int{3, 2},
			wantIgnored: map[string]int{rules.RuleConfigFindingCap: 1},
			wantCut:     2,
		},
		{
			name:    ".mcpmoat-ignore cannot drop the cap row",
			set:     builtin,
			caps:    configCaps{perServer: 2},
			ignore:  cfgCapIgnores([]rules.IgnoreEntry{capEntry}, nil),
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 4, false)},
			// Both cap rows stay. The blocked rule ID is listed once.
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"),
				capView("a", "high", "1 more config finding is not listed; limit 2"),
				secretView("b", 0, "high"), secretView("b", 1, "high"),
				capView("b", "high", "2 more config findings are not listed; limit 2"),
			},
			wantCounts:      []int{3, 3},
			wantFileBlocked: []string{rules.RuleConfigFindingCap},
			wantCut:         2,
		},
		{
			name:    "a .mcpmoat-ignore entry with no cap row is not blocked",
			set:     builtin,
			caps:    configCaps{perServer: 5},
			ignore:  cfgCapIgnores([]rules.IgnoreEntry{capEntry}, nil),
			servers: []discover.Server{cfgCapServer("a", 2, false)},
			want: []string{
				secretView("a", 0, "high"), secretView("a", 1, "high"),
			},
			wantCounts: []int{2},
		},
		// The scan cap keeps the most severe rows of the whole scan (issue
		// #213), not the rows of the first servers. Servers early in the
		// order cannot push a severe row of a later server out of the
		// report with many weak rows.
		{
			name:    "the scan cap keeps a critical row of a later server",
			set:     lowFirst,
			caps:    configCaps{perServer: 3, total: 4},
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 2, false), cfgCapServer("c", 0, true)},
			// a has 3 low rows, b 2 low rows, c a medium and a critical row:
			// 7 rows for a cap of 4. The critical and the medium row of c
			// are kept. The 2 other places go to low rows, and among equal
			// rows the earlier server wins: a keeps 2 rows, b keeps none.
			// Each kept row stays in scan order, and the cap rows name the
			// scan cap.
			want: []string{
				secretView("a", 0, "low"), secretView("a", 1, "low"),
				capView("a", "high", "1 more config finding is not listed; limit 4"),
				capView("b", "high", "2 more config findings are not listed; limit 4"),
				unpinnedView("c", "medium"), autoInstallView("c", "critical"),
			},
			wantCounts: []int{3, 1, 2},
			wantCut:    2,
		},
		{
			name:    "the scan cap keeps a high row of a later server",
			set:     builtin,
			caps:    configCaps{perServer: 3, total: 3},
			servers: []discover.Server{cfgCapServer("a", 0, true), cfgCapServer("b", 0, true), cfgCapServer("c", 1, false)},
			// a and b each have a medium and a low row, c one high row: 5
			// rows for a cap of 3. The high row of c and the two medium
			// rows are kept. The low rows are left out, and the cap rows
			// are high.
			want: []string{
				unpinnedView("a", "medium"),
				capView("a", "high", "1 more config finding is not listed; limit 3"),
				unpinnedView("b", "medium"),
				capView("b", "high", "1 more config finding is not listed; limit 3"),
				secretView("c", 0, "high"),
			},
			wantCounts: []int{2, 2, 1},
			wantCut:    2,
		},
		{
			name:    "at the scan cap rows of mixed severity keep scan order",
			set:     lowFirst,
			caps:    configCaps{perServer: 3, total: 7},
			servers: []discover.Server{cfgCapServer("a", 3, false), cfgCapServer("b", 2, false), cfgCapServer("c", 0, true)},
			// The same servers as above, with a scan cap that all 7 rows
			// fit: no row moves and there is no cap row.
			want: []string{
				secretView("a", 0, "low"), secretView("a", 1, "low"), secretView("a", 2, "low"),
				secretView("b", 0, "low"), secretView("b", 1, "low"),
				unpinnedView("c", "medium"), autoInstallView("c", "critical"),
			},
			wantCounts: []int{3, 2, 2},
		},
		{
			name:    "a server cut by both caps gets one cap row",
			set:     secretCritical,
			caps:    configCaps{perServer: 3, total: 4},
			servers: []discover.Server{cfgCapServer("z", 3, false), cfgCapServer("a", 2, true)},
			// z has 3 critical rows. a has 2 critical rows, a medium and a
			// low row. The per-server cap leaves out the low row of a. The
			// scan cap then keeps the 3 rows of z and the first critical row
			// of a, so it leaves out a critical and the medium row of a. The
			// one cap row of a counts all 3 rows (1 + 2), names the scan cap
			// and has the highest severity of both steps: critical.
			want: []string{
				secretView("z", 0, "critical"), secretView("z", 1, "critical"), secretView("z", 2, "critical"),
				secretView("a", 0, "critical"),
				capView("a", "critical", "3 more config findings are not listed; limit 4"),
			},
			wantCounts: []int{3, 2},
			// a counts once, although both caps cut it.
			wantCut: 1,
		},
		{
			name:    "a server cut by both caps with only weak rows left out is high",
			set:     lowFirst,
			caps:    configCaps{perServer: 3, total: 2},
			servers: []discover.Server{cfgCapServer("a", 3, true), cfgCapServer("b", 0, true)},
			// a has 3 low rows, a medium and a critical row. The per-server
			// cap leaves out 2 low rows. b has a medium and a critical row.
			// The scan cap keeps the two critical rows, so a loses its
			// medium and one more low row, and b loses its medium row.
			want: []string{
				autoInstallView("a", "critical"),
				capView("a", "high", "4 more config findings are not listed; limit 2"),
				autoInstallView("b", "critical"),
				capView("b", "high", "1 more config finding is not listed; limit 2"),
			},
			wantCounts: []int{2, 2},
			wantCut:    2,
		},
		{
			name:    "--ignore drops the cap rows of both caps",
			set:     secretCritical,
			caps:    configCaps{perServer: 3, total: 4},
			ignore:  cfgCapIgnores(nil, []rules.IgnoreEntry{capEntry}),
			servers: []discover.Server{cfgCapServer("z", 3, false), cfgCapServer("a", 2, true)},
			// The same cut as above. The cap row is gone, but a still
			// counts as a server that lost rows.
			want: []string{
				secretView("z", 0, "critical"), secretView("z", 1, "critical"), secretView("z", 2, "critical"),
				secretView("a", 0, "critical"),
			},
			wantCounts:  []int{3, 1},
			wantIgnored: map[string]int{rules.RuleConfigFindingCap: 1},
			wantCut:     1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rows, ignored, counts, fileBlocked, cutServers := configChecks{set: tt.set, typo: typo, caps: tt.caps}.findings(tt.ignore, tt.servers)
			if cutServers != tt.wantCut {
				t.Errorf("cutServers = %d, want %d", cutServers, tt.wantCut)
			}

			got := make([]string, 0, len(rows))
			for _, r := range rows {
				got = append(got, cfgCapView(r))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("rows =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(tt.want, "\n  "))
			}
			if !slices.Equal(counts, tt.wantCounts) {
				t.Errorf("counts = %v, want %v", counts, tt.wantCounts)
			}
			if !maps.Equal(ignored, tt.wantIgnored) {
				t.Errorf("ignored = %v, want %v", ignored, tt.wantIgnored)
			}
			if tt.wantIgnored == nil && ignored != nil {
				t.Errorf("ignored = %#v, want nil", ignored)
			}
			if !slices.Equal(fileBlocked, tt.wantFileBlocked) || (tt.wantFileBlocked == nil && fileBlocked != nil) {
				t.Errorf("fileBlocked = %#v, want %#v", fileBlocked, tt.wantFileBlocked)
			}
			assertCapRowText(t, rows)
		})
	}
}

// assertCapRowText fails the test unless every MOAT-T4-005 row of rows has
// the fixed texts, no field and no key. It also fails when a row holds
// cfgCapCanary.
func assertCapRowText(t *testing.T, rows []report.FindingRow) {
	t.Helper()
	for i, r := range rows {
		for name, field := range map[string]string{
			"RuleID": r.RuleID, "Severity": r.Severity, "Server": r.Name, "Title": r.Title,
			"Risk": r.Risk, "Remediation": r.Remediation, "Field": r.Field, "Key": r.Key, "Related": r.Related,
		} {
			if strings.Contains(field, cfgCapCanary) {
				t.Errorf("row %d (%s) field %s holds the secret value", i, r.RuleID, name)
			}
		}
		if r.RuleID != rules.RuleConfigFindingCap {
			continue
		}
		if r.Title != configCapTitle || r.Risk != configCapRisk || r.Remediation != configCapRemediation {
			t.Errorf("cap row %d has Title %q, Risk %q, Remediation %q, want the fixed texts", i, r.Title, r.Risk, r.Remediation)
		}
		if r.Field != "" || r.Key != "" {
			t.Errorf("cap row %d has Field %q and Key %q, want both empty", i, r.Field, r.Key)
		}
	}
}

// TestConfigFindingsCapsDefault checks the real caps (the zero configCaps):
// 100 rows for one server and 10,000 rows for the scan. Below the caps, the
// rows are the same as with caps that are much larger.
func TestConfigFindingsCapsDefault(t *testing.T) {
	t.Parallel()
	set := builtinSet(t)
	typo, err := rules.NewBuiltinTyposquat()
	if err != nil {
		t.Fatalf("rules.NewBuiltinTyposquat() error = %v", err)
	}
	// rowsOf returns the views of the rows, the counts of findings and the
	// number of servers that lost rows to a cap.
	rowsOf := func(caps configCaps, servers []discover.Server) ([]string, []int, int) {
		rows, _, counts, _, cut := configChecks{set: set, typo: typo, caps: caps}.findings(nil, servers)
		views := make([]string, 0, len(rows))
		for _, r := range rows {
			views = append(views, cfgCapView(r))
		}
		return views, counts, cut
	}

	t.Run("below the caps the rows do not change", func(t *testing.T) {
		t.Parallel()
		servers := []discover.Server{cfgCapServer("a", configRowsPerServer-2, true), cfgCapServer("b", 7, false)}
		got, gotCounts, gotCut := rowsOf(configCaps{}, servers)
		want, wantCounts, _ := rowsOf(configCaps{perServer: 1 << 20, total: 1 << 20}, servers)
		if !slices.Equal(got, want) || !slices.Equal(gotCounts, wantCounts) {
			t.Errorf("rows with the default caps differ from the rows with no cap\ngot:  %v %q\nwant: %v %q", gotCounts, got, wantCounts, want)
		}
		if gotCut != 0 {
			t.Errorf("cutServers = %d, want 0", gotCut)
		}
		if gotCounts[0] != configRowsPerServer {
			t.Errorf("server a has %d rows, want %d", gotCounts[0], configRowsPerServer)
		}
	})

	t.Run("the per-server cap is 100", func(t *testing.T) {
		t.Parallel()
		got, counts, cut := rowsOf(configCaps{}, []discover.Server{cfgCapServer("a", 150, false)})
		if cut != 1 {
			t.Errorf("cutServers = %d, want 1", cut)
		}
		if counts[0] != configRowsPerServer+1 || len(got) != configRowsPerServer+1 {
			t.Fatalf("counts = %v and %d rows, want %d", counts, len(got), configRowsPerServer+1)
		}
		if want := secretView("a", configRowsPerServer-1, "high"); got[configRowsPerServer-1] != want {
			t.Errorf("last kept row = %q, want %q", got[configRowsPerServer-1], want)
		}
		if want := capView("a", "high", "50 more config findings are not listed; limit 100"); got[configRowsPerServer] != want {
			t.Errorf("cap row = %q, want %q", got[configRowsPerServer], want)
		}
	})

	t.Run("the scan cap is 10000", func(t *testing.T) {
		t.Parallel()
		// 101 servers of 100 rows each: the first 100 fill the scan cap, and
		// the last one gets only its cap row.
		n := configRowsTotal/configRowsPerServer + 1
		servers := make([]discover.Server, n)
		for i := range servers {
			servers[i] = cfgCapServer(fmt.Sprintf("s%03d", i), configRowsPerServer, false)
		}
		got, counts, cut := rowsOf(configCaps{}, servers)
		if cut != 1 {
			t.Errorf("cutServers = %d, want 1", cut)
		}
		if len(got) != configRowsTotal+1 {
			t.Fatalf("got %d rows, want %d", len(got), configRowsTotal+1)
		}
		if counts[n-2] != configRowsPerServer || counts[n-1] != 1 {
			t.Errorf("the last two counts = %v, want [%d 1]", counts[n-2:], configRowsPerServer)
		}
		want := capView(fmt.Sprintf("s%03d", n-1), "high", "100 more config findings are not listed; limit 10000")
		if got[len(got)-1] != want {
			t.Errorf("last row = %q, want %q", got[len(got)-1], want)
		}
	})
}

// TestConfigCapsOrDefault checks that a zero or negative cap gives the
// default, and that a positive cap stays.
func TestConfigCapsOrDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   configCaps
		want configCaps
	}{
		{"zero value", configCaps{}, configCaps{perServer: configRowsPerServer, total: configRowsTotal}},
		{"negative values", configCaps{perServer: -1, total: -5}, configCaps{perServer: configRowsPerServer, total: configRowsTotal}},
		{"only per server", configCaps{perServer: 3}, configCaps{perServer: 3, total: configRowsTotal}},
		{"only total", configCaps{total: 7}, configCaps{perServer: configRowsPerServer, total: 7}},
		{"both set", configCaps{perServer: 3, total: 7}, configCaps{perServer: 3, total: 7}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.orDefault(); got != tt.want {
				t.Errorf("%+v.orDefault() = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
	if configRowsPerServer != 100 || configRowsTotal != 10_000 {
		t.Errorf("caps = %d and %d, want 100 and 10000 (the help text and docs name them)", configRowsPerServer, configRowsTotal)
	}
}

// cfgHits returns one configHit for each severity word, with index i.
func cfgHits(severities ...string) []configHit {
	hits := make([]configHit, 0, len(severities))
	for i, s := range severities {
		hits = append(hits, configHit{index: i, severity: s})
	}
	return hits
}

// TestConfigCapCutHits checks which hits cutConfigHits keeps: the most severe
// ones (an unknown severity counts as critical), the first ones among equal
// severities, in their first order.
func TestConfigCapCutHits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		hits        []configHit
		limit       int
		wantKept    []int // the indexes of the kept hits
		wantOmitted []int // the indexes of the omitted hits, in any order
	}{
		{"no hits", nil, 3, nil, nil},
		{"all fit", cfgHits("low", "high"), 2, []int{0, 1}, nil},
		{"equal severity keeps the first", cfgHits("high", "high", "high"), 2, []int{0, 1}, []int{2}},
		{"severe hits win and keep their order", cfgHits("low", "critical", "low", "medium"), 2, []int{1, 3}, []int{0, 2}},
		{"unknown word ranks as critical", cfgHits("high", "bogus", "critical"), 2, []int{1, 2}, []int{0}},
		{"empty word ranks as critical", cfgHits("medium", ""), 1, []int{1}, []int{0}},
		{"wrong case ranks as critical", cfgHits("high", "HIGH"), 1, []int{1}, []int{0}},
		{"zero limit keeps nothing", cfgHits("high", "low"), 0, []int{}, []int{0, 1}},
		{"negative limit keeps nothing", cfgHits("high"), -1, []int{}, []int{0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kept, omitted := cutConfigHits(tt.hits, tt.limit)
			indexes := func(hs []configHit) []int {
				out := make([]int, 0, len(hs))
				for _, h := range hs {
					out = append(out, h.index)
				}
				return out
			}
			if got := indexes(kept); !slices.Equal(got, tt.wantKept) {
				t.Errorf("kept = %v, want %v", got, tt.wantKept)
			}
			gotOmitted := indexes(omitted)
			slices.Sort(gotOmitted)
			if !slices.Equal(gotOmitted, tt.wantOmitted) {
				t.Errorf("omitted = %v, want %v", gotOmitted, tt.wantOmitted)
			}
		})
	}
}

// TestConfigCapSeverity checks the severity of the cap row: the highest
// severity of the omitted hits, never below high, and critical for an
// unknown word.
func TestConfigCapSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		omitted []configHit
		want    rules.Severity
	}{
		{"no hits is high", nil, rules.SeverityHigh},
		{"low is raised to high", cfgHits("low"), rules.SeverityHigh},
		{"medium and low are raised to high", cfgHits("medium", "low"), rules.SeverityHigh},
		{"high stays high", cfgHits("high", "low"), rules.SeverityHigh},
		{"a critical hit makes it critical", cfgHits("low", "critical", "high"), rules.SeverityCritical},
		{"an unknown word is critical", cfgHits("low", "bogus"), rules.SeverityCritical},
		{"an empty word is critical", cfgHits(""), rules.SeverityCritical},
		{"a wrong case word is critical", cfgHits("HIGH"), rules.SeverityCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := configCapSeverity(tt.omitted); got != tt.want {
				t.Errorf("configCapSeverity(%v) = %q, want %q", tt.omitted, got, tt.want)
			}
		})
	}
}

// TestConfigCapText checks the Related text of the cap row and the stderr
// warning text: singular for one, plural for more.
func TestConfigCapText(t *testing.T) {
	t.Parallel()

	related := []struct {
		omitted, limit int
		want           string
	}{
		{1, 100, "1 more config finding is not listed; limit 100"},
		{2, 100, "2 more config findings are not listed; limit 100"},
		{9990, 10000, "9990 more config findings are not listed; limit 10000"},
	}
	for _, tt := range related {
		if got := configCapText(tt.omitted, tt.limit); got != tt.want {
			t.Errorf("configCapText(%d, %d) = %q, want %q", tt.omitted, tt.limit, got, tt.want)
		}
	}

	warnings := []struct {
		servers int
		want    string
	}{
		{1, "config findings were left out for 1 server; see MOAT-T4-005"},
		{2, "config findings were left out for 2 servers; see MOAT-T4-005"},
		{37, "config findings were left out for 37 servers; see MOAT-T4-005"},
	}
	for _, tt := range warnings {
		if got := configCapWarningText(tt.servers); got != tt.want {
			t.Errorf("configCapWarningText(%d) = %q, want %q", tt.servers, got, tt.want)
		}
	}
}

// cfgCapEnv returns n env entries TOKEN_000, TOKEN_001 and so on, which all
// hold value, for a server of writeServers.
func cfgCapEnv(n int, value string) map[string]string {
	env := make(map[string]string, n)
	for i := range n {
		env[cfgCapKey(i)] = value
	}
	return env
}

// cfgCapScanServers are the servers of TestScanConfigCap. With a per-server
// cap of 2, env-srv (5 env secrets) loses 3 rows and hdr-srv (3 header
// secrets) loses 1. small-srv (1 env secret) fits. The values are the
// canaries of discovertest, which assertNoLeakBoth looks for.
func cfgCapScanServers() map[string]any {
	headers := make(map[string]string, 3)
	for i := range 3 {
		headers[fmt.Sprintf("X-Api-Key-%d", i)] = discovertest.CanaryHeader
	}
	return map[string]any{
		"env-srv":   map[string]any{"command": "run", "env": cfgCapEnv(5, discovertest.CanaryEnv)},
		"hdr-srv":   map[string]any{"type": "http", "url": "https://" + findingsFixtureHost + "/mcp", "headers": headers},
		"small-srv": map[string]any{"command": "run", "env": cfgCapEnv(1, discovertest.CanaryEnv)},
	}
}

// cfgCapWarning is the stderr line of a scan in which two servers lost config
// rows. It prints also when --ignore drops the cap rows.
const cfgCapWarning = scanWarnPrefix + "config findings were left out for 2 servers; see MOAT-T4-005"

// TestScanConfigCap runs "scan --no-connect" with a per-server cap of 2 config
// rows (cli.maxConfigRows) and checks what the user sees: the MOAT-T4-005 rows
// in the report and in --json, the one stderr warning, the exit code, the
// .mcpmoat-ignore file that cannot drop the cap rows, and --ignore that can.
// No env or header value shows anywhere.
func TestScanConfigCap(t *testing.T) {
	t.Parallel()

	envRelated := "3 more config findings are not listed; limit 2"
	hdrRelated := "1 more config finding is not listed; limit 2"

	tests := []struct {
		name string
		// flags are the scan flags after the --no-connect and --config ones.
		flags []string
		// ignoreFile is the content of .mcpmoat-ignore, or "" for no file.
		ignoreFile string
		wantCode   int
		wantLines  []lineWant // all stderr lines, in order
		// wantCapRows is true when the report holds the two cap rows.
		wantCapRows bool
	}{
		{
			name:        "default",
			wantCode:    exitFindings,
			wantLines:   []lineWant{exactLine(cfgCapWarning)},
			wantCapRows: true,
		},
		{
			name:        "--fail-on critical",
			flags:       []string{"--fail-on", "critical"},
			wantCode:    exitOK,
			wantLines:   []lineWant{exactLine(failOnCriticalNotice), exactLine(cfgCapWarning)},
			wantCapRows: true,
		},
		{
			name:     "--ignore MOAT-T4-005",
			flags:    []string{"--ignore", rules.RuleConfigFindingCap},
			wantCode: exitFindings,
			// The cap rows are gone, but the report is still not complete,
			// so the warning prints. The config step prints it before the
			// count of ignored findings.
			wantLines: []lineWant{
				exactLine(cfgCapWarning),
				exactLine(scanPrefix + "2 findings ignored: MOAT-T4-005 (2)"),
			},
		},
		{
			name:       ".mcpmoat-ignore cannot drop the cap rows",
			flags:      []string{useIgnoreFileFlag},
			ignoreFile: rules.RuleConfigFindingCap + "\n",
			wantCode:   exitFindings,
			wantLines: []lineWant{
				exactLine(scanPrefix + "using 1 entry from .mcpmoat-ignore"),
				exactLine(fileCannotIgnoreWarning(rules.RuleConfigFindingCap)),
				exactLine(cfgCapWarning),
			},
			wantCapRows: true,
		},
	}
	for _, tt := range tests {
		for _, format := range []string{"text", "json"} {
			t.Run(tt.name+"/"+format, func(t *testing.T) {
				t.Parallel()

				home, work := t.TempDir(), t.TempDir()
				args := scanServersArgs(t, "config", home, cfgCapScanServers())
				args = append(args, tt.flags...)
				if format == "json" {
					args = append(args, "--json")
				}
				if tt.ignoreFile != "" {
					writeTestFile(t, work, rules.IgnoreFileName, tt.ignoreFile)
				}
				c, stdout, stderr := dirsCLI(t, home, work)
				c.maxConfigRows = 2

				code, out, errOut := runScanArgs(c, stdout, stderr, args...)

				if code != tt.wantCode {
					t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out, errOut)
				}
				assertStderrLines(t, errOut, tt.wantLines)
				assertNoLeakBoth(t, out, errOut)
				assertNoEscape(t, out, errOut)
				assertContainsNone(t, "stderr", errOut, []string{"env-srv", "hdr-srv", "TOKEN_", "X-Api-Key"})

				if format == "json" {
					checkCapJSON(t, out, tt.wantCapRows, envRelated, hdrRelated)
					return
				}
				checkCapText(t, out, tt.wantCapRows, envRelated, hdrRelated)
			})
		}
	}
}

// checkCapText checks the terminal report of TestScanConfigCap: two kept rows
// for env-srv and hdr-srv, one for small-srv, and, when wantCap is true, one
// high MOAT-T4-005 row for env-srv and for hdr-srv with its Related text.
func checkCapText(t *testing.T, stdout string, wantCap bool, envRelated, hdrRelated string) {
	t.Helper()
	perServer := map[string]int{}
	var capRows []scanFinding
	for _, f := range parseFindings(t, stdout) {
		if f.RuleID == rules.RuleConfigFindingCap {
			capRows = append(capRows, f)
			continue
		}
		if f.RuleID != rules.RulePlaintextSecret {
			t.Errorf("unexpected finding %s for %s", f.RuleID, f.Name)
		}
		perServer[f.Name]++
	}
	if want := map[string]int{"env-srv": 2, "hdr-srv": 2, "small-srv": 1}; !maps.Equal(perServer, want) {
		t.Errorf("MOAT-T4-002 findings by server = %v, want %v\nstdout:\n%s", perServer, want, stdout)
	}
	if !wantCap {
		if len(capRows) != 0 {
			t.Errorf("stdout has %d MOAT-T4-005 findings, want none\nstdout:\n%s", len(capRows), stdout)
		}
		return
	}
	if len(capRows) != 2 {
		t.Fatalf("stdout has %d MOAT-T4-005 findings, want 2\nstdout:\n%s", len(capRows), stdout)
	}
	for _, f := range capRows {
		if f.Severity != "high" || f.Title != configCapTitle || f.Risk != configCapRisk || f.Fix != configCapRemediation {
			t.Errorf("cap finding of %s = %+v, want high with the fixed texts", f.Name, f)
		}
	}
	assertContainsAll(t, "stdout", stdout, []string{envRelated, hdrRelated})
	// The summary counts the cap row as a finding of the server.
	for _, row := range summaryRows(t, stdout) {
		want := map[string]int{"env-srv": 3, "hdr-srv": 3, "small-srv": 1}[row.Name]
		if row.Findings != want {
			t.Errorf("summary of %s has %d findings, want %d", row.Name, row.Findings, want)
		}
	}
}

// checkCapJSON checks the --json report of TestScanConfigCap: the report is
// complete, and, when wantCap is true, it has one high MOAT-T4-005 finding
// for env-srv and for hdr-srv with no field and no key.
func checkCapJSON(t *testing.T, stdout string, wantCap bool, envRelated, hdrRelated string) {
	t.Helper()
	doc := decodeScanJSON(t, stdout)
	if !doc.Complete {
		t.Errorf("complete = false, want true: a cut of config findings is not an execution error")
	}
	var got []report.JSONFinding
	for _, f := range doc.Findings {
		if f.RuleID == rules.RuleConfigFindingCap {
			got = append(got, f)
		}
	}
	var want []report.JSONFinding
	if wantCap {
		want = []report.JSONFinding{
			{RuleID: rules.RuleConfigFindingCap, Severity: "high", Server: "env-srv", Related: envRelated, Source: report.SourceRule},
			{RuleID: rules.RuleConfigFindingCap, Severity: "high", Server: "hdr-srv", Related: hdrRelated, Source: report.SourceRule},
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("MOAT-T4-005 findings = %+v, want %+v", got, want)
	}
	if n := len(doc.Findings) - len(got); n != 5 {
		t.Errorf("JSON has %d other findings, want 5 (2 + 2 + 1 kept rows)", n)
	}
}

// TestScanConfigCapOneServer checks the singular warning: one server lost
// config rows. The warning prints also when --ignore drops the cap row. Below
// the cap, the same scan prints no warning and no cap row.
func TestScanConfigCapOneServer(t *testing.T) {
	t.Parallel()

	servers := map[string]any{"env-srv": map[string]any{"command": "run", "env": cfgCapEnv(3, discovertest.CanaryEnv)}}
	const oneServerWarning = scanWarnPrefix + "config findings were left out for 1 server; see MOAT-T4-005"
	tests := []struct {
		name      string
		maxRows   int
		flags     []string
		wantLines []lineWant
		wantIDs   []string
	}{
		{
			name:      "over the cap",
			maxRows:   2,
			wantLines: []lineWant{exactLine(oneServerWarning)},
			wantIDs:   []string{rules.RulePlaintextSecret, rules.RulePlaintextSecret, rules.RuleConfigFindingCap},
		},
		{
			name:    "over the cap with --ignore MOAT-T4-005",
			maxRows: 2,
			flags:   []string{"--ignore", rules.RuleConfigFindingCap},
			wantLines: []lineWant{
				exactLine(oneServerWarning),
				exactLine(scanPrefix + "1 finding ignored: MOAT-T4-005 (1)"),
			},
			wantIDs: []string{rules.RulePlaintextSecret, rules.RulePlaintextSecret},
		},
		{
			name:    "at the cap",
			maxRows: 3,
			wantIDs: []string{rules.RulePlaintextSecret, rules.RulePlaintextSecret, rules.RulePlaintextSecret},
		},
	}
	for _, tt := range tests {
		for _, mode := range configModes {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				home, work := t.TempDir(), t.TempDir()
				args := scanServersArgs(t, mode, home, servers)
				args = append(args, tt.flags...)
				c, stdout, stderr := dirsCLI(t, home, work)
				c.maxConfigRows = tt.maxRows

				code, out, errOut := runScanArgs(c, stdout, stderr, args...)

				if code != exitFindings {
					t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFindings, out, errOut)
				}
				assertStderrLines(t, errOut, tt.wantLines)
				assertFindingIDs(t, out, tt.wantIDs)
				assertNoLeakBoth(t, out, errOut)
			})
		}
	}
}
