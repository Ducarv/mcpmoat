package main

// End-to-end acceptance test of the threats T1 to T5 (docs/PRD.md, milestone
// M7). It runs the real binary (see runBin in e2e_test.go) on one fake home
// that holds the fixtures of testdata/servers and testdata/configs together.

import (
	"encoding/json"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// acceptanceGuard is the time that the scans of TestE2EAcceptance may take,
// after the binary and the fixture servers are built. It catches a slow run,
// for example a server that hits a per-server timeout in each scan. It cannot
// catch a real hang, because runBin has no timeout: the real time is a few
// seconds.
const acceptanceGuard = 60 * time.Second

// acceptanceStdioServers are the fixtures of testdata/servers that the trusted
// global config runs, other than rugpullServer. Each server has the name of
// its fixture.
var acceptanceStdioServers = []string{"benign", "poisoned", "shadowing", "mailer"}

// acceptanceConfigIDs are the sorted rule IDs of each server of the project
// file, as the READMEs of testdata/configs/dangerous (T4) and
// testdata/configs/typosquat (T5) list them. nil means no finding.
var acceptanceConfigIDs = map[string][]string{
	// testdata/configs/dangerous
	"remote-plain":      {"MOAT-T4-001", "MOAT-T4-002"},
	"remote-local":      nil,
	"env-secret":        {"MOAT-T4-002", "MOAT-T4-004"},
	"latest-pkg":        {"MOAT-T4-003", "MOAT-T4-004"},
	"docker-untagged":   {"MOAT-T4-003"},
	"docker-arg-secret": {"MOAT-T4-002"},
	"remote-url-secret": {"MOAT-T4-002"},
	"npx-git-unpinned":  {"MOAT-T4-003", "MOAT-T4-004"},
	"npx-git-pinned":    {"MOAT-T4-004"},
	// testdata/configs/typosquat
	"filesystem":       {"MOAT-T4-004", "MOAT-T5-001"},
	"mcp-server-fecth": {"MOAT-T5-001"},
	"memory":           {"MOAT-T4-004"},
}

// acceptanceSecrets are the strings that must never show in the output or in
// pins.json: the canaries and the other secret-like values of the dangerous
// config fixture. The key names (API_TOKEN, API_KEY) can show, the values
// cannot.
var acceptanceSecrets = append(slices.Clone(dangerousCanaries), "Bearer", "${env:API_TOKEN}", "${env:API_KEY}")

// writeAcceptanceHome writes home/.claude.json with the fixture servers of
// acceptanceStdioServers and rugpullServer with the given variant. Every
// command is an absolute path. writeServers replaces the whole file, so a
// second call keeps all five servers and only switches the variant.
func writeAcceptanceHome(t *testing.T, home, variant string) {
	t.Helper()
	servers := map[string]any{
		rugpullServer: map[string]any{
			"command": inspecttest.Fixture(t, "rugpull"),
			"args":    []string{rugpullFlag, variant},
		},
	}
	for _, name := range acceptanceStdioServers {
		servers[name] = map[string]any{"command": inspecttest.Fixture(t, name)}
	}
	writeServers(t, home, ".claude.json", servers)
}

// acceptanceProjectServers returns the merged mcpServers maps of the Cursor
// configs of testdata/configs/dangerous and testdata/configs/typosquat. Each
// server stays raw JSON, so its secret values are never decoded or logged. A
// name in both files fails the test.
func acceptanceProjectServers(t *testing.T) map[string]any {
	t.Helper()
	merged := map[string]any{}
	for _, fixture := range []string{"dangerous", "typosquat"} {
		path := testdataPath("configs", fixture, "home", ".cursor", "mcp.json")
		var cfg struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
		}
		// The error names the JSON position, never the content of the file.
		if err := json.Unmarshal(readFileBytes(t, path), &cfg); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		for name, server := range cfg.MCPServers {
			if _, dup := merged[name]; dup {
				t.Fatalf("server %q is in more than one config fixture", name)
			}
			merged[name] = server
		}
	}
	if got := slices.Sorted(maps.Keys(merged)); !slices.Equal(got, slices.Sorted(maps.Keys(acceptanceConfigIDs))) {
		t.Fatalf("project servers = %v, want the servers of acceptanceConfigIDs", got)
	}
	return merged
}

// acceptanceWantIDs returns the expected sorted rule IDs of every server.
// rugpullIDs are the IDs of rugpullServer.
//
// Scan does not apply the T1 and T3 description and schema rules yet (issue
// #143). So poisoned, shadowing and the injected rugpull get_time have no T1
// or T3 finding here. When #143 lands, add the IDs of testdata/servers/README.md
// to poisoned, shadowing and rugpull.
func acceptanceWantIDs(rugpullIDs []string) map[string][]string {
	want := maps.Clone(acceptanceConfigIDs)
	for _, name := range acceptanceStdioServers {
		want[name] = nil
	}
	want[rugpullServer] = rugpullIDs
	return want
}

// idsByServer returns the sorted rule IDs of each server of names. A row is
// RULE, SEVERITY, SERVER (the name), as findingRows returns it. A row of a
// server that is not in names fails the test.
func idsByServer(t *testing.T, names []string, rows [][]string) map[string][]string {
	t.Helper()
	got := map[string][]string{}
	for _, name := range names {
		got[name] = nil
	}
	for _, row := range rows {
		if _, ok := got[row[2]]; !ok {
			t.Errorf("finding %s is on the unknown server %q", row[0], row[2])
			continue
		}
		got[row[2]] = append(got[row[2]], row[0])
	}
	for _, ids := range got {
		slices.Sort(ids)
	}
	return got
}

// assertIDsByServer fails the test unless got equals want, server by server.
func assertIDsByServer(t *testing.T, what string, got, want map[string][]string) {
	t.Helper()
	for _, name := range slices.Sorted(maps.Keys(want)) {
		ids, ok := got[name]
		if !ok {
			t.Errorf("%s: server %s is missing from the report", what, name)
			continue
		}
		if !slices.Equal(ids, want[name]) {
			t.Errorf("%s: server %s has rule IDs %v, want %v", what, name, ids, want[name])
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("%s: server %s is not expected", what, name)
		}
	}
}

// TestE2EAcceptance runs one journey on the real binary that covers T1 to T5.
// The trusted global config runs the five stdio fixtures, with rugpull clean.
// An untrusted Cursor project file holds the T4 and T5 config fixtures. The
// inspect gate refuses every server of a project file, so none of them starts
// (the npx and docker commands would fetch packages), but the config rules
// still check them. The npx and docker of PATH are marker scripts, so a broken
// gate fails the test and never starts the real tools.
//
// Scan 1 pins the stdio servers. The config then switches rugpull to the
// injected variant, and scan 2 reports MOAT-T2-001 with the diff and the
// accept hint. Scan 2 runs again with --json: scan never re-pins a pinned
// server, so the repeat sees the same change.
func TestE2EAcceptance(t *testing.T) {
	t.Parallel()
	home, work := t.TempDir(), t.TempDir()
	requirePrivateChain(t, home)
	// The project file is only untrusted when work is not the home folder.
	realHome, errHome := filepath.EvalSymlinks(home)
	realWork, errWork := filepath.EvalSymlinks(work)
	if errHome != nil || errWork != nil || realHome == realWork {
		t.Fatalf("home and work must be two folders: %q (%v), %q (%v)", realHome, errHome, realWork, errWork)
	}
	// os/exec uses the last value of a duplicate key, so this PATH replaces
	// the PATH of runBinEnv. A started npx or docker only creates the marker.
	script, marker := writeMarkerScript(t, t.TempDir())
	shimDir := t.TempDir()
	for _, name := range []string{"npx", "docker"} {
		symlink(t, script, filepath.Join(shimDir, name))
	}
	shimEnv := []string{"PATH=" + shimDir + ":/usr/bin:/bin"}
	writeAcceptanceHome(t, home, "clean")
	writeServers(t, filepath.Join(work, ".cursor"), "mcp.json", acceptanceProjectServers(t))
	binaryPath(t) // build first, so the guard does not count the build
	start := time.Now()

	// assertScan checks one plain scan: exit code 1 (the T4 findings are
	// high), the stderr lines, the rule IDs of each server, no secret, no
	// started npx or docker, and the project servers not inspected. It returns
	// the stdout.
	assertScan := func(t *testing.T, wantStderr []lineWant, wantIDs map[string][]string) string {
		t.Helper()
		stdout, stderr, code := runBinEnv(t, home, work, shimEnv, "scan")
		e2eNetAssertMarker(t, marker, false)
		assertScanResult(t, code, stdout, stderr, scanWant{code: exitFindings})
		assertStderrLines(t, stderr, wantStderr)
		assertContainsNone(t, "stdout", stdout, acceptanceSecrets)
		assertContainsNone(t, "stderr", stderr, acceptanceSecrets)
		names := column(tableRows(t, stdout), 0)
		assertIDsByServer(t, "text", idsByServer(t, names, findingRows(t, stdout)), wantIDs)
		summary := summaryRows(t, stdout)
		if len(summary) != len(names) {
			t.Errorf("SUMMARY has %d servers, the table has %d\nstdout:\n%s", len(summary), len(names), stdout)
		}
		for _, row := range summary {
			_, project := acceptanceConfigIDs[row.Name]
			if want := map[bool]string{true: "not inspected", false: "ok"}[project]; row.Status != want {
				t.Errorf("server %s: status = %q (%s), want %q", row.Name, row.Status, row.Reason, want)
			}
		}
		return stdout
	}

	// Scan 1: every stdio server is new, so scan pins its tools, in name
	// order. Only the project servers are refused, and they show in the
	// SUMMARY, not on stderr. rugpull is clean, so it has no MOAT-T2 finding.
	stdout := assertScan(t, []lineWant{
		exactLine("mcpmoat scan: pinned 2 tools for benign"),
		exactLine("mcpmoat scan: pinned 1 tool for mailer"),
		exactLine("mcpmoat scan: pinned 5 tools for poisoned"),
		exactLine("mcpmoat scan: pinned 2 tools for " + rugpullServer),
		exactLine("mcpmoat scan: pinned 1 tool for shadowing"),
	}, acceptanceWantIDs(nil))
	assertContainsNone(t, "scan 1 stdout", stdout, []string{"MOAT-T2", acceptHintPrefix})
	assertContainsNone(t, "pins.json", string(readFileBytes(t, pinsPath(home))), acceptanceSecrets)
	// No project server starts, so only the stdio servers are pinned.
	wantPinned := slices.Sorted(slices.Values(append(slices.Clone(acceptanceStdioServers), rugpullServer)))
	if got := readPinsFile(t, pinsPath(home)).serverNames(); !slices.Equal(got, wantPinned) {
		t.Errorf("pinned servers = %v, want %v", got, wantPinned)
	}

	// The config switches rugpull to the injected variant. The other four
	// servers stay the same.
	writeAcceptanceHome(t, home, "injected")

	// Scan 2: only the description of rugpull get_time changed. Nothing is
	// pinned, so stderr is empty.
	stdout = assertScan(t, nil, acceptanceWantIDs([]string{"MOAT-T2-001"}))
	wantRow := []string{"MOAT-T2-001", "high", rugpullServer, "tool", "get_time"}
	if !slices.ContainsFunc(findingRows(t, stdout), func(row []string) bool { return slices.Equal(row, wantRow) }) {
		t.Errorf("no finding row %v\nstdout:\n%s", wantRow, stdout)
	}
	// The diffs come after the FINDINGS block and before the accept hints.
	body, hints := cutAcceptHints(stdout)
	assertDiffsOf(t, splitScanSections(body).Rest, rugpullServer, []string{"get_time"})
	if len(hints) != 1 {
		t.Errorf("accept hints = %q, want one for %s", hints, rugpullServer)
	}
	assertInOrder(t, stdout, []string{
		"Changed tool get_time on server " + rugpullServer + ":\n",
		"--- pinned\n",
		"+++ current\n",
		"@@ -1,6 +1,6 @@",
		"\n-description: " + rugpullClean + "\n",
		"+description: " + rugpullInjected + "\n",
		"\n" + acceptHintPrefix + rugpullServer + ": mcpmoat pin --accept " + rugpullServer + " --expect pd1:",
	})
	hintDigest(t, stdout, rugpullServer) // fails the test when the hint has no valid digest

	// Scan 2 again with --json: the same findings and the same exit code.
	// JSON has no SUMMARY, so the refusal of each project server is a warning
	// on stderr. The warning names the server, never a secret.
	jsonOut, jsonErr, jsonCode := runBinEnv(t, home, work, shimEnv, "scan", "--json")
	e2eNetAssertMarker(t, marker, false)
	if jsonCode != exitFindings {
		t.Errorf("--json: exit code %d, want %d\nstderr:\n%s", jsonCode, exitFindings, jsonErr)
	}
	assertNoLeakBoth(t, jsonOut, jsonErr)
	assertNoEscape(t, jsonOut, jsonErr)
	assertContainsNone(t, "--json stdout", jsonOut, acceptanceSecrets)
	assertContainsNone(t, "--json stderr", jsonErr, acceptanceSecrets)
	var wantWarnings []lineWant
	for _, name := range slices.Sorted(maps.Keys(acceptanceConfigIDs)) {
		wantWarnings = append(wantWarnings, prefixLine(scanWarnPrefix+"server "+name+": failed: inspect: "+name+": untrusted project server; "))
	}
	assertStderrLines(t, jsonErr, wantWarnings)
	for _, line := range nonEmptyLines(jsonErr) {
		if !strings.Contains(line, " needs explicit opt-in") {
			t.Errorf("--json stderr line %q is not a gate refusal", line)
		}
	}
	doc := decodeScanJSON(t, jsonOut)
	if doc.Mode != report.ModeConnect {
		t.Errorf("mode = %q, want %q", doc.Mode, report.ModeConnect)
	}
	var names []string
	var rows [][]string
	for _, s := range doc.Servers {
		names = append(names, s.Name)
		_, project := acceptanceConfigIDs[s.Name]
		if want := map[bool]report.InspectionStatus{true: report.InspectionRefused, false: report.InspectionOK}[project]; s.Inspection.Status != want {
			t.Errorf("--json: server %s: inspection status = %q, want %q", s.Name, s.Inspection.Status, want)
		}
	}
	for _, f := range doc.Findings {
		rows = append(rows, []string{f.RuleID, f.Severity, f.Server})
		if f.RuleID == "MOAT-T2-001" && (f.Severity != "high" || f.Server != rugpullServer) {
			t.Errorf("--json: MOAT-T2-001 finding = %+v, want severity high on %s", f, rugpullServer)
		}
	}
	assertIDsByServer(t, "--json", idsByServer(t, names, rows), acceptanceWantIDs([]string{"MOAT-T2-001"}))
	if len(doc.Diffs) != 1 || doc.Diffs[0].Server != rugpullServer || doc.Diffs[0].Tool != "get_time" ||
		!strings.Contains(doc.Diffs[0].Diff, "+description: "+rugpullInjected+"\n") {
		t.Errorf("--json diffs = %+v, want one diff of %s get_time with the injected description", doc.Diffs, rugpullServer)
	}

	if d := time.Since(start); d > acceptanceGuard {
		t.Errorf("the scans took %v, want less than %v", d, acceptanceGuard)
	}
}
