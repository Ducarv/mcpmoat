package main

// End-to-end acceptance test of the threats of docs/PRD.md (milestone M7). It
// runs the real binary (see runBinEnv in e2e_test.go) on one fake home that
// holds the fixtures of testdata/servers and testdata/configs together. It
// covers T2, T4 and T5. Scan does not apply the T1 and T3 rules yet (issue
// #143), so the test asserts that they report nothing (see
// acceptanceWantFindings).

import (
	"encoding/json"
	"maps"
	"net/http"
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

// acceptanceLocalServer is the server of the dangerous config fixture whose url
// is a loopback address. The test points it at a server that counts its
// connections.
const acceptanceLocalServer = "remote-local"

// acceptanceConfigFindings are the sorted findings of each server of the
// project file, as "RULE severity". The rule IDs are the ones that the READMEs
// of testdata/configs/dangerous (T4) and testdata/configs/typosquat (T5) list.
// The severities are the ones of the rule files in rules/. nil means no
// finding. These sets repeat the tables of the per-fixture scan tests on
// purpose: the acceptance test is an independent oracle of what the whole
// binary reports.
var acceptanceConfigFindings = map[string][]string{
	// testdata/configs/dangerous
	"remote-plain":        {"MOAT-T4-001 high", "MOAT-T4-002 high"},
	acceptanceLocalServer: nil,
	"env-secret":          {"MOAT-T4-002 high", "MOAT-T4-004 low"},
	"latest-pkg":          {"MOAT-T4-003 medium", "MOAT-T4-004 low"},
	"docker-untagged":     {"MOAT-T4-003 medium"},
	"docker-arg-secret":   {"MOAT-T4-002 high"},
	"remote-url-secret":   {"MOAT-T4-002 high"},
	"npx-git-unpinned":    {"MOAT-T4-003 medium", "MOAT-T4-004 low"},
	"npx-git-pinned":      {"MOAT-T4-004 low"},
	// testdata/configs/typosquat
	"filesystem":       {"MOAT-T4-004 low", "MOAT-T5-001 medium"},
	"mcp-server-fecth": {"MOAT-T5-001 medium"},
	"memory":           {"MOAT-T4-004 low"},
}

// acceptanceProjectNames are the sorted names of the project servers.
var acceptanceProjectNames = slices.Sorted(maps.Keys(acceptanceConfigFindings))

// acceptancePinnedNames are the sorted names of the servers that scan pins:
// the trusted stdio servers.
var acceptancePinnedNames = func() []string {
	names := append(slices.Clone(acceptanceStdioServers), rugpullServer)
	slices.Sort(names)
	return names
}()

// acceptanceGateReason is the text of the reason of a project server that the
// inspect gate refuses.
const acceptanceGateReason = "untrusted project server; "

// acceptanceGateOptIn is the end of the reason of a project server that the
// inspect gate refuses.
const acceptanceGateOptIn = " needs explicit opt-in"

// acceptancePublicText is the text of mcpmoat itself that holds a part of
// dangerousCanaries[0]. The remediation of the T1 rules tells the user to add
// a line to this file.
const acceptancePublicText = ".mcpmoat-ignore"

// acceptanceRugPullFinding is the finding of the changed get_time of
// rugpullServer in scan 2.
const acceptanceRugPullFinding = "MOAT-T2-001 high"

// acceptanceSecrets are the strings that must never show in the output or in
// pins.json: the canaries and the other secret-like values of the dangerous
// config fixture. The key names (API_TOKEN, API_KEY) can show, the values
// cannot.
var acceptanceSecrets = append(slices.Clone(dangerousCanaries), "${env:API_TOKEN}", "${env:API_KEY}")

// isAcceptanceProject reports whether name is a server of the untrusted project
// file.
func isAcceptanceProject(name string) bool {
	_, ok := acceptanceConfigFindings[name]
	return ok
}

// assertAcceptanceNoSecrets fails the test when got holds a string of
// acceptanceSecrets, or a part of a canary of dangerousCanaries of 8 bytes or
// more (see secretPartLeak). The message names the secret by its index only,
// never by its value. tmpNames are the temporary folder names that the part
// check ignores.
//
// The part check first replaces two kinds of text that are not secret. The
// first is each name of tmpNames. These names are not output of mcpmoat, and
// a name such as "mcpmoat-e2e-N", "mcpmoat-fixtures-N" or the "mcpmoat-offline.X"
// TMPDIR of .github/scripts/run-offline.sh holds "mcpmoat-", the first 8 bytes
// of dangerousCanaries[0]. The check replaces names, not whole paths, because
// scan masks some folder names of a path. A canary holds no "/", so a shorter
// name cannot hold a part. The second is acceptancePublicText, which mcpmoat
// prints in the Fix line of the T1 rules. The whole-string check uses the text
// as it is. A TMPDIR that is a symlink to a folder with another name can fail
// the part check, because scan can print the resolved name.
func assertAcceptanceNoSecrets(t *testing.T, what, got string, tmpNames []string) {
	t.Helper()
	for i, secret := range acceptanceSecrets {
		if strings.Contains(got, secret) {
			t.Errorf("%s holds acceptanceSecrets[%d]", what, i)
		}
	}
	got = strings.ReplaceAll(got, acceptancePublicText, "<public>")
	for _, name := range tmpNames {
		got = strings.ReplaceAll(got, name, "<tmp>")
	}
	for i, canary := range dangerousCanaries {
		if _, ok := secretPartLeak(canary, got); ok {
			t.Errorf("%s holds a part of dangerousCanaries[%d]", what, i)
		}
	}
}

// TestAcceptanceNoSecretsPublicText checks that the part check accepts the
// text of mcpmoat that is not secret.
func TestAcceptanceNoSecretsPublicText(t *testing.T) {
	t.Parallel()
	assertAcceptanceNoSecrets(t, "text", "Add the line MOAT-T1-004 server/tool to "+acceptancePublicText+" in /tmp/mcpmoat-e2e-123/bin", []string{"mcpmoat-e2e-123"})
}

// acceptanceTmpNames returns the folder names of secretPartLen bytes or more in
// the paths of the fixture build folder and the binary build folder. Both are
// below the temporary folder of every t.TempDir(), and every fixture builds
// into the same folder.
func acceptanceTmpNames(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, root := range []string{filepath.Dir(inspecttest.Fixture(t, rugpullServer)), filepath.Dir(binaryPath(t))} {
		for _, name := range strings.Split(root, string(filepath.Separator)) {
			if len(name) >= secretPartLen {
				names = append(names, name)
			}
		}
	}
	return names
}

// writeAcceptanceHome writes home/.claude.json with the fixture servers of
// acceptanceStdioServers and rugpullServer with the given variant. Every
// command is an absolute path. writeServers replaces the whole file, so a
// second call keeps all five servers and only switches the variant.
func writeAcceptanceHome(t *testing.T, home, variant string) {
	t.Helper()
	servers := map[string]any{rugpullServer: rugpullConfig(t, variant)}
	for _, name := range acceptanceStdioServers {
		servers[name] = map[string]any{"command": inspecttest.Fixture(t, name)}
	}
	writeServers(t, home, ".claude.json", servers)
}

// acceptanceProjectServers returns the merged mcpServers maps of the Cursor
// configs of testdata/configs/dangerous and testdata/configs/typosquat. Each
// server stays raw JSON, so its secret values are never decoded or logged. A
// name in both files fails the test. The url of acceptanceLocalServer becomes
// localURL, a server of the test that counts its connections.
func acceptanceProjectServers(t *testing.T, localURL string) map[string]any {
	t.Helper()
	merged := map[string]json.RawMessage{}
	for _, fixture := range []string{"dangerous", "typosquat"} {
		path := testdataPath("configs", fixture, "home", ".cursor", "mcp.json")
		var cfg struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
		}
		// The error names the JSON position and at most one character of the
		// content.
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
	gotNames := slices.Sorted(maps.Keys(merged))
	if !slices.Equal(gotNames, acceptanceProjectNames) {
		t.Fatalf("project servers = %v, want the servers of acceptanceConfigFindings", gotNames)
	}
	// remote-local holds no secret, so the test can decode it.
	var local map[string]any
	if err := json.Unmarshal(merged[acceptanceLocalServer], &local); err != nil {
		t.Fatalf("decode %s: %v", acceptanceLocalServer, err)
	}
	local["url"] = localURL
	servers := make(map[string]any, len(merged))
	for name, server := range merged {
		servers[name] = server
	}
	servers[acceptanceLocalServer] = local
	return servers
}

// acceptanceWantFindings returns the expected sorted findings of every server,
// as "RULE severity". rugpull holds the findings of rugpullServer.
//
// Scan does not apply the T1 and T3 description and schema rules yet (issue
// #143), so the stdio servers have no T1 or T3 finding here. When #143 lands,
// set poisoned, shadowing and mailer to the IDs that scan reports (see
// testdata/servers/README.md), and add the T1 IDs of the injected get_time
// (see testdata/servers/rugpull/README.md) to the rugpull set in scan 2.
func acceptanceWantFindings(rugpull []string) map[string][]string {
	want := maps.Clone(acceptanceConfigFindings)
	for _, name := range acceptanceStdioServers {
		want[name] = nil
	}
	want[rugpullServer] = rugpull
	return want
}

// acceptanceFinding is one finding of a report.
type acceptanceFinding struct {
	server, rule, severity string
}

// acceptanceTextFindings returns the findings of a plain stdout (see parseFindings).
func acceptanceTextFindings(t *testing.T, stdout string) []acceptanceFinding {
	t.Helper()
	var out []acceptanceFinding
	for _, f := range parseFindings(t, stdout) {
		out = append(out, acceptanceFinding{server: f.Name, rule: f.RuleID, severity: f.Severity})
	}
	return out
}

// acceptanceJSONFindings returns the findings of a --json report.
func acceptanceJSONFindings(doc report.ScanReport) []acceptanceFinding {
	var out []acceptanceFinding
	for _, f := range doc.Findings {
		out = append(out, acceptanceFinding{server: f.Server, rule: f.RuleID, severity: f.Severity})
	}
	return out
}

// acceptanceFindingsByServer returns the sorted findings of each server of names, as
// "RULE severity". A finding of a server that is not in names fails the test.
func acceptanceFindingsByServer(t *testing.T, names []string, findings []acceptanceFinding) map[string][]string {
	t.Helper()
	got := map[string][]string{}
	for _, name := range names {
		got[name] = nil
	}
	for _, f := range findings {
		if _, ok := got[f.server]; !ok {
			t.Errorf("finding %s is on the unknown server %q", f.rule, f.server)
			continue
		}
		got[f.server] = append(got[f.server], f.rule+" "+f.severity)
	}
	for _, pairs := range got {
		slices.Sort(pairs)
	}
	return got
}

// assertFindingsByServer fails the test unless got equals want, server by
// server.
func assertFindingsByServer(t *testing.T, what string, got, want map[string][]string) {
	t.Helper()
	for _, name := range slices.Sorted(maps.Keys(want)) {
		pairs, ok := got[name]
		if !ok {
			t.Errorf("%s: server %s is missing from the report", what, name)
			continue
		}
		if !slices.Equal(pairs, want[name]) {
			t.Errorf("%s: server %s has findings %v, want %v", what, name, pairs, want[name])
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("%s: server %s is not expected", what, name)
		}
	}
}

// acceptanceRun is the fake home of TestE2EAcceptance and its guards.
type acceptanceRun struct {
	home, work string
	// env is the extra child environment: a PATH with the npx and docker
	// shims, and the proxy variables.
	env []string
	// marker is the marker file of the npx and docker shims.
	marker string
	// proxy is the HTTP_PROXY and HTTPS_PROXY of the child. local is the
	// counting server that the url of remote-local points at. Go never sends a
	// loopback url through a proxy, so the proxy guards the other remote
	// servers and local guards remote-local.
	proxy, local *e2eNetServer
	// tmpNames are the folder names that assertAcceptanceNoSecrets ignores.
	tmpNames []string
	// seen is the traffic that each counting server had after the last scan.
	seen map[*e2eNetServer]acceptanceTraffic
}

// acceptanceTraffic is the number of connections and requests of a counting
// server.
type acceptanceTraffic struct{ conns, reqs int }

// newAcceptanceRun writes the fake home. The trusted global config runs the
// five stdio fixtures, with rugpull clean. An untrusted Cursor project file
// holds the T4 and T5 config fixtures.
func newAcceptanceRun(t *testing.T) *acceptanceRun {
	t.Helper()
	// The project file is only untrusted when work is not the home folder, so
	// the test needs two separate folders.
	r := &acceptanceRun{home: t.TempDir(), work: t.TempDir(), seen: map[*e2eNetServer]acceptanceTraffic{}}
	requirePrivateChain(t, r.home)
	// This builds the fixtures and the binary, so the guard of the test does not
	// count the build.
	r.tmpNames = acceptanceTmpNames(t)
	// os/exec uses the last value of a duplicate key, so this PATH replaces
	// the PATH of runBinEnv. A started npx or docker only creates the marker.
	script, marker := writeMarkerScript(t, t.TempDir())
	shimDir := t.TempDir()
	for _, name := range []string{"npx", "docker"} {
		symlink(t, script, filepath.Join(shimDir, name))
	}
	r.marker = marker
	refuse := func(w http.ResponseWriter, _ []byte) { w.WriteHeader(http.StatusBadGateway) }
	r.proxy = e2eNetStart(t, refuse)
	r.local = e2eNetStart(t, refuse)
	r.env = []string{
		"PATH=" + shimDir + ":" + e2eBasePath,
		"HTTP_PROXY=" + r.proxy.srv.URL,
		"HTTPS_PROXY=" + r.proxy.srv.URL,
	}
	writeAcceptanceHome(t, r.home, "clean")
	writeServers(t, filepath.Join(r.work, ".cursor"), "mcp.json", acceptanceProjectServers(t, r.local.srv.URL+"/mcp"))
	return r
}

// scan runs mcpmoat with args and checks the guards that hold after every
// run: no started npx or docker, no new connection to the proxy or to
// remote-local, no secret in stdout, stderr or pins.json, and only the stdio
// servers pinned.
func (r *acceptanceRun) scan(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	stdout, stderr, code = runBinEnv(t, r.home, r.work, r.env, args...)
	assertMarker(t, r.marker, false)
	r.assertNoNewTraffic(t, "the proxy", r.proxy, args)
	r.assertNoNewTraffic(t, acceptanceLocalServer, r.local, args)
	assertAcceptanceNoSecrets(t, "stdout", stdout, r.tmpNames)
	assertAcceptanceNoSecrets(t, "stderr", stderr, r.tmpNames)
	assertAcceptanceNoSecrets(t, "pins.json", string(readFileBytes(t, pinsPath(r.home))), r.tmpNames)
	if got := readPinsFile(t, pinsPath(r.home)).serverNames(); !slices.Equal(got, acceptancePinnedNames) {
		t.Errorf("pinned servers = %v, want %v", got, acceptancePinnedNames)
	}
	return stdout, stderr, code
}

// assertNoNewTraffic fails the test when s got a connection or a request since
// the last call: a remote project server was inspected by the scan with args.
func (r *acceptanceRun) assertNoNewTraffic(t *testing.T, what string, s *e2eNetServer, args []string) {
	t.Helper()
	conns, reqs := s.settle(t) // the counts are cumulative
	now := acceptanceTraffic{conns: int(conns), reqs: len(reqs)}
	if before := r.seen[s]; now != before {
		t.Errorf("%s got %d new connections and %d new requests in `scan %v`, want none: a remote project server was inspected",
			what, now.conns-before.conns, now.reqs-before.reqs, args)
		r.seen[s] = now
	}
}

// scanAndCheck runs one plain scan and checks it: exit code 1 (the T4 findings
// are high), the stderr lines, the findings of each server, a SUMMARY that
// agrees with the FINDINGS block, and the project servers not inspected. It
// returns the stdout.
func (r *acceptanceRun) scanAndCheck(t *testing.T, wantStderr []lineWant, want map[string][]string) string {
	t.Helper()
	stdout, stderr, code := r.scan(t, "scan")
	assertScanResult(t, code, stdout, stderr, scanWant{code: exitFindings})
	assertStderrLines(t, stderr, wantStderr)
	names := column(tableRows(t, stdout), 0)
	assertFindingsByServer(t, "text", acceptanceFindingsByServer(t, names, acceptanceTextFindings(t, stdout)), want)
	assertReportConsistent(t, stdout)
	summary := summaryRows(t, stdout)
	var summaryNames []string
	for _, row := range summary {
		summaryNames = append(summaryNames, row.Name)
	}
	if !slices.Equal(slices.Sorted(slices.Values(summaryNames)), slices.Sorted(slices.Values(names))) {
		t.Errorf("SUMMARY has the servers %v, the table has %v\nstdout:\n%s", summaryNames, names, stdout)
	}
	for _, row := range summary {
		wantStatus := "ok"
		if isAcceptanceProject(row.Name) {
			wantStatus = "not inspected"
		}
		if row.Status != wantStatus {
			t.Errorf("server %s: status = %q (%s), want %q", row.Name, row.Status, row.Reason, wantStatus)
		}
		if isAcceptanceProject(row.Name) && !strings.Contains(row.Reason, acceptanceGateReason) {
			t.Errorf("server %s: reason = %q, want it to hold %q", row.Name, row.Reason, acceptanceGateReason)
		}
	}
	return stdout
}

// assertAcceptanceJSON checks scan 2 with --json: the same findings and the
// same exit code as the plain scan. JSON has no SUMMARY, so the refusal of
// each project server is a warning on stderr. The warning names the server,
// never a secret.
func assertAcceptanceJSON(t *testing.T, stdout, stderr string, code int) {
	t.Helper()
	if code != exitFindings {
		t.Errorf("--json: exit code %d, want %d\nstderr:\n%s", code, exitFindings, stderr)
	}
	assertNoLeakBoth(t, stdout, stderr)
	assertNoEscape(t, stdout, stderr)
	var wantWarnings []lineWant
	for _, name := range acceptanceProjectNames {
		wantWarnings = append(wantWarnings, prefixLine(scanWarnPrefix+"server "+name+": failed: inspect: "+name+": "+acceptanceGateReason))
	}
	assertStderrLines(t, stderr, wantWarnings)
	for _, line := range nonEmptyLines(stderr) {
		if !strings.Contains(line, acceptanceGateOptIn) {
			t.Errorf("--json stderr line %q is not a gate refusal", line)
		}
	}
	doc := decodeScanJSON(t, stdout)
	if doc.Mode != report.ModeConnect {
		t.Errorf("mode = %q, want %q", doc.Mode, report.ModeConnect)
	}
	var names []string
	for _, s := range doc.Servers {
		names = append(names, s.Name)
		wantStatus := report.InspectionOK
		if isAcceptanceProject(s.Name) {
			wantStatus = report.InspectionRefused
		}
		if s.Inspection.Status != wantStatus {
			t.Errorf("--json: server %s: inspection status = %q, want %q", s.Name, s.Inspection.Status, wantStatus)
		}
	}
	assertFindingsByServer(t, "--json", acceptanceFindingsByServer(t, names, acceptanceJSONFindings(doc)), acceptanceWantFindings([]string{acceptanceRugPullFinding}))
	if len(doc.Diffs) != 1 || doc.Diffs[0].Server != rugpullServer || doc.Diffs[0].Tool != "get_time" ||
		!strings.Contains(doc.Diffs[0].Diff, "+description: "+rugpullInjected+"\n") {
		t.Errorf("--json diffs = %+v, want one diff of %s get_time with the injected description", doc.Diffs, rugpullServer)
	}
}

// TestE2EAcceptance runs one journey on the real binary that covers T2, T4 and
// T5. T1 and T3 are asserted empty until issue #143 (see
// acceptanceWantFindings). The inspect gate refuses every server of the
// project file, so none of them starts (the npx and docker commands would
// fetch packages) and no remote one gets a connection, but the config rules
// still check them. The npx and docker of PATH are marker scripts, the proxy
// and the url of remote-local are counting servers of the test, so a broken
// gate fails the test and never reaches a real tool or host.
//
// Scan 1 pins the stdio servers. The config then switches rugpull to the
// injected variant, and scan 2 reports MOAT-T2-001 with the diff and the
// accept hint. Scan 2 runs again with --json: scan never re-pins a pinned
// server, so the repeat sees the same change.
func TestE2EAcceptance(t *testing.T) {
	t.Parallel()
	r := newAcceptanceRun(t)
	start := time.Now()

	// Scan 1: every stdio server is new, so scan pins its tools, in name
	// order. Only the project servers are refused, and they show in the
	// SUMMARY, not on stderr. rugpull is clean, so it has no MOAT-T2 finding.
	stdout := r.scanAndCheck(t, []lineWant{
		exactLine("mcpmoat scan: pinned 2 tools for benign"),
		exactLine("mcpmoat scan: pinned 1 tool for mailer"),
		exactLine("mcpmoat scan: pinned 5 tools for poisoned"),
		exactLine("mcpmoat scan: pinned 2 tools for " + rugpullServer),
		exactLine("mcpmoat scan: pinned 1 tool for shadowing"),
	}, acceptanceWantFindings(nil))
	assertNoPinRows(t, stdout)
	assertContainsNone(t, "scan 1 stdout", stdout, []string{acceptHintPrefix})

	// Scan 2: the config switches rugpull to the injected variant. The other
	// four servers stay the same, so only the description of rugpull get_time
	// changed. Nothing is pinned, so stderr is empty.
	writeAcceptanceHome(t, r.home, "injected")
	stdout = r.scanAndCheck(t, nil, acceptanceWantFindings([]string{acceptanceRugPullFinding}))
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
	assertInOrder(t, stdout, rugpullDiffParts(rugpullServer))
	hintDigest(t, stdout, rugpullServer) // fails the test when the hint has no valid digest

	// Scan 2 again with --json.
	stdout, stderr, code := r.scan(t, "scan", "--json")
	assertAcceptanceJSON(t, stdout, stderr, code)

	assertFast(t, start, acceptanceGuard)
}
