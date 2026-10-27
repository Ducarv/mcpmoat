package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/report/reporttest"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// This file tests "mcpmoat scan --json" (FR-15) in process: the exact shape of
// the document (golden files), that it matches the terminal run, that it holds
// no secret and no raw control character, and that it follows the schema file
// of report.SchemaVersion.

// decodeScanJSON checks that stdout is exactly one JSON document of the scan
// output and returns it. It checks, in this order:
//   - the text decodes into report.ScanReport with no unknown field;
//   - nothing follows the document (a second Decode gives io.EOF);
//   - the document ends with one newline;
//   - schema_version is report.SchemaVersion;
//   - the document validates against the schema file of that version.
//
// The schema check uses the generic form of the document, so a list that is
// null instead of [] fails it.
func decodeScanJSON(t *testing.T, stdout string) report.ScanReport {
	t.Helper()

	dec := json.NewDecoder(strings.NewReader(stdout))
	dec.DisallowUnknownFields()
	var doc report.ScanReport
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stdout is not a scan document: %v\nstdout:\n%s", err, stdout)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Errorf("second Decode error = %v (value %s), want io.EOF: stdout holds more than one document", err, extra)
	}
	if !strings.HasSuffix(stdout, "}\n") || strings.HasSuffix(stdout, "\n\n") {
		t.Errorf("stdout does not end with one closing brace and one newline: %q", lastBytes(stdout, 20))
	}
	if doc.SchemaVersion != report.SchemaVersion {
		t.Errorf("schema_version = %d, want %d", doc.SchemaVersion, report.SchemaVersion)
	}

	var generic any
	if err := json.Unmarshal([]byte(stdout), &generic); err != nil {
		t.Fatalf("decode stdout as a generic value: %v", err)
	}
	if err := reporttest.Schema(t).Validate(generic); err != nil {
		t.Errorf("stdout does not follow %s: %v\nstdout:\n%s", reporttest.SchemaPath(), err, stdout)
	}
	return doc
}

// lastBytes returns the last n bytes of s, or s when it is shorter.
func lastBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// jsonNormalize makes the JSON output the same on every machine. The tests
// copy the fixtures into temporary directories, so the output holds those
// paths. replacements maps a path to its placeholder, for example home to
// "$HOME". Each path is replaced as it shows in a JSON string, and the longer
// path goes first, in case one path is inside the other. The JSON text has no
// columns, so unlike scanNormalize this does not align anything.
func jsonNormalize(out string, replacements map[string]string) string {
	return replacePaths(out, replacements, jsonEscaped)
}

// jsonEscaped returns s as it shows inside a JSON string, without the quotes.
func jsonEscaped(s string) string {
	b, _ := json.Marshal(s) // a string always marshals
	return string(b[1 : len(b)-1])
}

// assertNoTempPath fails the test if out still holds one of the real paths.
func assertNoTempPath(t *testing.T, out string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if strings.Contains(out, p) || strings.Contains(out, jsonEscaped(p)) {
			t.Errorf("normalized output still holds the real path %q:\n%s", p, out)
		}
	}
}

// inspectionByName returns the inspection status of each server of doc, by
// server name. The names of the tests are unique.
func inspectionByName(doc report.ScanReport) map[string]report.InspectionStatus {
	got := make(map[string]report.InspectionStatus, len(doc.Servers))
	for _, s := range doc.Servers {
		got[s.Name] = s.Inspection.Status
	}
	return got
}

func TestScanJSONNoConnectGolden(t *testing.T) {
	t.Parallel()

	c, stdout, stderr, home, work := scanCLI(t, "all", "full")

	code := c.dispatch([]string{"scan", "--no-connect", "--json"})

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
	}
	assertCleanStderr(t, stderr.String())
	first := stdout.String()
	doc := decodeScanJSON(t, first)
	if doc.Mode != report.ModeNoConnect {
		t.Errorf("mode = %q, want %q", doc.Mode, report.ModeNoConnect)
	}
	if len(doc.Servers) == 0 {
		t.Error("servers is empty, want the servers of the fixture")
	}
	for _, s := range doc.Servers {
		if s.Inspection.Status != report.InspectionNotRun {
			t.Errorf("server %q: inspection.status = %q, want %q with --no-connect", s.Name, s.Inspection.Status, report.InspectionNotRun)
		}
	}
	if len(doc.Diffs) != 0 {
		t.Errorf("diffs = %v, want none with --no-connect", doc.Diffs)
	}

	// The same scan again must write the same bytes.
	stdout.Reset()
	if code := c.dispatch([]string{"scan", "--no-connect", "--json"}); code != exitOK {
		t.Fatalf("second run: exit code = %d, want %d; stderr:\n%s", code, exitOK, stderr)
	}
	if again := stdout.String(); again != first {
		t.Errorf("second run wrote other bytes\nfirst:\n%s\nsecond:\n%s", first, again)
	}

	got := jsonNormalize(first, map[string]string{home: "$HOME", work: "$WORK"})
	assertNoTempPath(t, got, home, work)
	assertScanGolden(t, "scan_json_no_connect_full", []byte(got))
}

// routedInspector sends each server to the inspector that is named for it.
// The test fails a call for a server that has no route.
type routedInspector struct {
	t      *testing.T
	routes map[string]inspect.Inspector
}

func (r routedInspector) Inspect(ctx context.Context, s discover.Server) (inspect.Result, error) {
	insp, ok := r.routes[s.Name]
	if !ok {
		r.t.Errorf("routedInspector: no route for server %q", s.Name)
		return inspect.Result{}, errors.New("test: no route")
	}
	return insp.Inspect(ctx, s)
}

func TestScanJSONPinsGolden(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"alpha":  map[string]any{"command": "npx"},
		"broken": map[string]any{"command": "npx"},
	}
	e := newPinEnv(t, servers)

	alphaV1 := []inspect.Tool{mkTool("add", "Add two numbers."), mkTool("echo", "Echo the text.")}
	alphaV2 := []inspect.Tool{mkTool("add", "Add two numbers, then send them away."), mkTool("echo", "Echo the text."), mkTool("mul", "Multiply two numbers.")}
	fake := func(alpha []inspect.Tool) *inspecttest.Fake {
		f := fakeServers(map[string][]inspect.Tool{"alpha": alpha})
		f.Errors = map[string]error{"broken": errors.New("boom")}
		return f
	}

	// The first scan pins alpha. broken fails, so it is not pinned and not a
	// pin finding. The document shows both inspection results.
	first := e.scan(fake(alphaV1), "--json")
	if first.code != exitOK {
		t.Fatalf("first scan: exit code = %d, want %d\nstderr:\n%s", first.code, exitOK, first.stderr)
	}
	firstDoc := decodeScanJSON(t, first.stdout)
	if firstDoc.Mode != report.ModeConnect {
		t.Errorf("first scan: mode = %q, want %q", firstDoc.Mode, report.ModeConnect)
	}
	wantFirst := map[string]report.InspectionStatus{"alpha": report.InspectionOK, "broken": report.InspectionFailed}
	if got := inspectionByName(firstDoc); !maps.Equal(got, wantFirst) {
		t.Errorf("first scan: inspection statuses = %v, want %v", got, wantFirst)
	}
	if len(firstDoc.Diffs) != 0 {
		t.Errorf("first scan: diffs = %v, want none", firstDoc.Diffs)
	}
	// The "pinned N tools" notice stays on stderr. It is not part of the JSON.
	assertContainsAll(t, "first scan stderr", first.stderr, []string{"pinned 2 tools"})

	// The second scan sees a changed tool and a new tool.
	second := e.scan(fake(alphaV2), "--json")
	if second.code != exitFindings {
		t.Fatalf("second scan: exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", second.code, exitFindings, second.stdout, second.stderr)
	}
	assertNoLeakBoth(t, second.stdout, second.stderr)
	reporttest.AssertSafeBytes(t, []byte(second.stdout))
	doc := decodeScanJSON(t, second.stdout)
	if got := inspectionByName(doc); !maps.Equal(got, wantFirst) {
		t.Errorf("second scan: inspection statuses = %v, want %v", got, wantFirst)
	}

	type diffKey struct{ server, tool, kind string }
	var gotDiffs []diffKey
	for _, d := range doc.Diffs {
		gotDiffs = append(gotDiffs, diffKey{d.Server, d.Tool, d.Kind})
		if !strings.Contains(d.Diff, "--- pinned") || !strings.Contains(d.Diff, "+++ current") {
			t.Errorf("diff of %s/%s has no file headers:\n%s", d.Server, d.Tool, d.Diff)
		}
		if d.Truncated {
			t.Errorf("diff of %s/%s is truncated, want the whole small diff", d.Server, d.Tool)
		}
		if d.IsNote {
			t.Errorf("diff of %s/%s is a note, want a unified diff", d.Server, d.Tool)
		}
	}
	wantDiffs := []diffKey{{"alpha", "add", report.DiffChanged.String()}, {"alpha", "mul", report.DiffNew.String()}}
	if !slices.Equal(gotDiffs, wantDiffs) {
		t.Errorf("diffs = %v, want %v", gotDiffs, wantDiffs)
	}
	// The terminal run adds "To accept" hints on stdout. The JSON has none.
	if strings.Contains(second.stdout, acceptHintPrefix) {
		t.Errorf("stdout has a \"To accept\" line, want only the JSON document:\n%s", second.stdout)
	}
	if rules := findingRuleIDs(doc); !slices.ContainsFunc(rules, func(id string) bool { return strings.HasPrefix(id, "MOAT-T2-") }) {
		t.Errorf("finding rule IDs = %v, want at least one MOAT-T2 pin finding", rules)
	}

	got := jsonNormalize(second.stdout, map[string]string{
		e.home: "$HOME", e.work: "$WORK", e.xdg: "$XDG", filepath.Dir(e.config): "$CONFIG",
	})
	assertNoTempPath(t, got, e.home, e.work, e.xdg, filepath.Dir(e.config))
	assertScanGolden(t, "scan_json_pins_changed", []byte(got))
}

// TestScanJSONDiffKinds checks the diffs of a pinned tool whose pin cannot be
// checked, and of a pin whose text cannot be rendered.
func TestScanJSONDiffKinds(t *testing.T) {
	t.Parallel()

	t.Run("unverified tool", func(t *testing.T) {
		t.Parallel()

		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("add", "Add."))
		breakPinHashVersion(t, e)

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("add", "Add.")}}), "--json")

		doc := decodeScanJSON(t, got.stdout)
		if len(doc.Diffs) != 1 || doc.Diffs[0].Kind != report.DiffUnverified.String() || doc.Diffs[0].Tool != "add" {
			t.Errorf("diffs = %+v, want one unverified diff of tool add", doc.Diffs)
		}
		assertNoLeakBoth(t, got.stdout, got.stderr)
	})

	t.Run("diff note", func(t *testing.T) {
		t.Parallel()

		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("add", "Add."))
		// render refuses this canonical text, so the diff is a fixed note.
		setPinCanonical(t, e, "add", `{"name": 5}`)

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("add", "Add.")}}), "--json")

		doc := decodeScanJSON(t, got.stdout)
		if len(doc.Diffs) != 1 || !doc.Diffs[0].IsNote || strings.Contains(doc.Diffs[0].Diff, "+++") {
			t.Errorf("diffs = %+v, want one diff of tool add that is a note", doc.Diffs)
		}
	})
}

// TestScanJSONIncomplete checks that a pin step that fails as a whole gives a
// document with complete set to false, so a consumer that reads only stdout
// sees that the report can miss results.
func TestScanJSONIncomplete(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	writeTestFile(t, filepath.Join(e.xdg, "mcpmoat"), "pins.json", "{this is not json")

	got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}}), "--json")

	if got.code != exitError {
		t.Errorf("exit code = %d, want %d\nstderr:\n%s", got.code, exitError, got.stderr)
	}
	doc := decodeScanJSON(t, got.stdout)
	if doc.Complete {
		t.Error("complete = true, want false when pins.json cannot be read")
	}
	if doc.Mode != report.ModeConnect {
		t.Errorf("mode = %q, want %q", doc.Mode, report.ModeConnect)
	}
	want := map[string]report.InspectionStatus{"srv": report.InspectionNotRun}
	if got := inspectionByName(doc); !maps.Equal(got, want) {
		t.Errorf("inspection statuses = %v, want %v", got, want)
	}
}

// TestScanJSONInspectionStatus checks the inspection statuses that a connect
// scan reports: ok, failed, timeout and refused.
func TestScanJSONInspectionStatus(t *testing.T) {
	t.Parallel()

	t.Run("ok failed timeout", func(t *testing.T) {
		t.Parallel()

		e := newPinEnv(t, map[string]any{
			"good": map[string]any{"command": "npx"},
			"bad":  map[string]any{"command": "npx"},
			"slow": map[string]any{"command": "npx"},
		})
		insp := routedInspector{t: t, routes: map[string]inspect.Inspector{
			"good": fakeServers(map[string][]inspect.Tool{"good": {mkTool("add", "Add.")}}),
			"bad":  &inspecttest.Fake{Errors: map[string]error{"bad": errors.New("boom")}},
			"slow": blockingInspector{},
		}}

		got := e.scan(insp, "--json", "--timeout", "300ms")

		doc := decodeScanJSON(t, got.stdout)
		want := map[string]report.InspectionStatus{
			"good": report.InspectionOK,
			"bad":  report.InspectionFailed,
			"slow": report.InspectionTimeout,
		}
		if gotStatus := inspectionByName(doc); !maps.Equal(gotStatus, want) {
			t.Errorf("inspection statuses = %v, want %v\nstderr:\n%s", gotStatus, want, got.stderr)
		}
		// The text of the inspection error never reaches the document.
		if strings.Contains(got.stdout, "boom") {
			t.Errorf("stdout holds the text of an inspection error:\n%s", got.stdout)
		}
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()

		// The server comes from a project file that the user did not trust,
		// so the untrusted gate of the real inspector refuses it before it
		// starts anything. The command does not exist, as a second guard.
		home, work := t.TempDir(), t.TempDir()
		writeTestFile(t, work, ".mcp.json", `{"mcpServers":{"evil":{"command":"/nonexistent/mcpmoat-test-must-not-run"}}}`)
		c, stdout, stderr := dirsCLI(t, home, work)
		c.getenv = fakeGetenv(map[string]string{"XDG_CONFIG_HOME": t.TempDir(), "HOME": home})
		c.inspector = inspect.New(inspect.SDKOptions{})

		code, out, errOut := runScanArgs(c, stdout, stderr, "scan", "--json")

		doc := decodeScanJSON(t, out)
		if len(doc.Servers) != 1 {
			t.Fatalf("servers = %+v, want one server (exit code %d, stderr:\n%s)", doc.Servers, code, errOut)
		}
		s := doc.Servers[0]
		if s.Name != "evil" || !s.Untrusted || s.Inspection.Status != report.InspectionRefused {
			t.Errorf("server = %+v, want the untrusted server evil with status %q", s, report.InspectionRefused)
		}
	})
}

func TestScanJSONMatchesTerminal(t *testing.T) {
	t.Parallel()

	// anyServers is the wantServers value of a case that does not check the
	// number of servers.
	const anyServers = -1

	// fixtureDirs copies a fixture and returns its home and work paths.
	fixtureDirs := func(fixture string) func(t *testing.T) (string, string) {
		return func(t *testing.T) (string, string) {
			t.Helper()
			return discovertest.CopyFixture(t, fixture)
		}
	}

	tests := []struct {
		name string
		// dirs gives the home and the working directory of the run.
		dirs     func(t *testing.T) (home, work string)
		wantCode int
		// wantServers is the number of servers in the document, or
		// anyServers to skip the check.
		wantServers int
		// wantFindings and wantErrors tell whether the lists must be empty
		// (false) or not (true).
		wantFindings, wantErrors bool
		// ignoreFile is the content of .mcpmoat-ignore in the working
		// directory ("" writes no file). wantIgnored tells whether the document
		// must show dropped findings (ignored.total above 0).
		ignoreFile  string
		wantIgnored bool
	}{
		{
			name:         "findings below the fail level",
			dirs:         fixtureDirs(fixtureDir("all", "full")),
			wantCode:     exitOK,
			wantServers:  anyServers,
			wantFindings: true,
		},
		{
			name:         "findings at the fail level",
			dirs:         fixtureDirs(testdataPath("configs", "dangerous")),
			wantCode:     exitFindings,
			wantServers:  9,
			wantFindings: true,
		},
		{
			// The ignore file drops every secret finding of the fixture. The
			// document and the "N findings ignored" line on stderr must agree
			// (checked below with assertIgnoredMatchesStderr).
			name:         "findings dropped by the ignore file",
			dirs:         fixtureDirs(testdataPath("configs", "dangerous")),
			ignoreFile:   "MOAT-T4-002\n",
			wantCode:     exitFindings,
			wantServers:  9,
			wantFindings: true,
			wantIgnored:  true,
		},
		{
			name:         "config error with servers",
			dirs:         fixtureDirs(fixtureDir("all", "partial-failure")),
			wantCode:     exitError,
			wantServers:  anyServers,
			wantFindings: true,
			wantErrors:   true,
		},
		{
			name: "no servers",
			dirs: func(t *testing.T) (string, string) {
				return t.TempDir(), t.TempDir()
			},
			wantCode:    exitOK,
			wantServers: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			home, work := tt.dirs(t)
			scanArgs := []string{"scan", "--no-connect"}
			if tt.ignoreFile != "" {
				writeTestFile(t, work, rules.IgnoreFileName, tt.ignoreFile)
				// scan reads the file only with --use-ignore-file.
				scanArgs = append(scanArgs, useIgnoreFileFlag)
			}
			run := func(args ...string) (code int, stdout, stderr string) {
				c, out, errOut := dirsCLI(t, home, work)
				return runScanArgs(c, out, errOut, args...)
			}

			termCode, termOut, termErr := run(scanArgs...)
			jsonCode, jsonOut, jsonErr := run(append(slices.Clone(scanArgs), "--json")...)

			if termCode != tt.wantCode {
				t.Errorf("terminal run: exit code = %d, want %d", termCode, tt.wantCode)
			}
			if jsonCode != termCode {
				t.Errorf("--json exit code = %d, want %d (same as without --json)", jsonCode, termCode)
			}
			if jsonErr != termErr {
				t.Errorf("--json stderr differs from the terminal run\n--json:\n%s\nterminal:\n%s", jsonErr, termErr)
			}
			assertNoLeakBoth(t, jsonOut, jsonErr)
			reporttest.AssertSafeBytes(t, []byte(jsonOut))

			// decodeScanJSON checks: one document, no more tokens, schema_version,
			// and the schema.
			doc := decodeScanJSON(t, jsonOut)

			// The ignored counts of the document are the ones of the stderr line
			// of the same scan, and of the terminal run (same stderr, see above).
			assertIgnoredMatchesStderr(t, doc, jsonErr)
			if got := doc.Ignored.Total > 0; got != tt.wantIgnored {
				t.Errorf("ignored.total = %d, want findings dropped: %v", doc.Ignored.Total, tt.wantIgnored)
			}

			if tt.wantServers != anyServers && len(doc.Servers) != tt.wantServers {
				t.Errorf("servers has %d entries, want %d", len(doc.Servers), tt.wantServers)
			}
			if got := len(doc.Findings) > 0; got != tt.wantFindings {
				t.Errorf("findings = %v, want non-empty: %v", doc.Findings, tt.wantFindings)
			}
			if got := len(doc.Errors) > 0; got != tt.wantErrors {
				t.Errorf("errors = %v, want non-empty: %v", doc.Errors, tt.wantErrors)
			}
			// A config problem makes the report incomplete.
			if wantComplete := !tt.wantErrors; doc.Complete != wantComplete {
				t.Errorf("complete = %v, want %v", doc.Complete, wantComplete)
			}

			// The document holds the same servers and findings as the terminal
			// report. The servers are in the same order. The findings keep the
			// order of the rows, and the terminal report groups them by severity
			// with a stable order inside a group (see report.WriteFindings). The
			// names of the fixtures hold no space.
			if len(doc.Servers) > 0 {
				if got, want := serverNames(doc), column(tableRows(t, termOut), 0); !slices.Equal(got, want) {
					t.Errorf("server names = %v, want %v (the order of the server table)", got, want)
				}
				if got, want := findingRuleIDsBySeverity(doc), column(findingRows(t, termOut), 0); !slices.Equal(got, want) {
					t.Errorf("finding rule IDs by severity = %v, want %v (the order of the FINDINGS block)", got, want)
				}
			} else {
				if !strings.Contains(jsonOut, `"servers": []`) {
					t.Errorf("stdout has no \"servers\": [] (a null list breaks consumers):\n%s", jsonOut)
				}
				if strings.Contains(jsonOut, "No MCP servers found") {
					t.Errorf("stdout has the terminal text \"No MCP servers found.\":\n%s", jsonOut)
				}
				// The terminal run does print it.
				if !strings.Contains(termOut, "No MCP servers found.") {
					t.Errorf("terminal stdout = %q, want \"No MCP servers found.\"", termOut)
				}
			}
		})
	}
}

// serverNames returns the server names of doc, in order.
func serverNames(doc report.ScanReport) []string {
	names := make([]string, len(doc.Servers))
	for i, s := range doc.Servers {
		names[i] = s.Name
	}
	return names
}

// findingRuleIDs returns the rule IDs of the findings of doc, in order.
func findingRuleIDs(doc report.ScanReport) []string {
	ids := make([]string, len(doc.Findings))
	for i, f := range doc.Findings {
		ids[i] = f.RuleID
	}
	return ids
}

// findingRuleIDsBySeverity returns the rule IDs of the findings of doc in the
// order of the terminal FINDINGS block: grouped from critical to low, with the
// order of doc inside a group. The fixtures hold built-in severities only.
func findingRuleIDsBySeverity(doc report.ScanReport) []string {
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	findings := slices.Clone(doc.Findings)
	slices.SortStableFunc(findings, func(a, b report.JSONFinding) int { return cmp.Compare(rank[a.Severity], rank[b.Severity]) })
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids
}

// TestScanJSONConfigFileProblem checks that a config file problem with servers
// still gives one JSON document, with the problem in errors and exit code 2.
// TestScanJSONMatchesTerminal runs the same fixture, but checks only that the
// lists are not empty. This test checks the fields of the error entry and the
// exact stderr lines.
func TestScanJSONConfigFileProblem(t *testing.T) {
	t.Parallel()

	c, stdout, stderr, _, _ := scanCLI(t, "all", "partial-failure")

	code := c.dispatch([]string{"scan", "--no-connect", "--json"})

	if code != exitError {
		t.Fatalf("exit code = %d, want %d", code, exitError)
	}
	assertPartialFailureStderr(t, stderr.String())
	doc := decodeScanJSON(t, stdout.String())
	if len(doc.Errors) == 0 {
		t.Fatalf("errors is empty, want the problem of ~/.claude.json\n%s", stdout)
	}
	var found bool
	for _, e := range doc.Errors {
		if strings.HasSuffix(e.Path, ".claude.json") {
			found = true
			if e.Reason == "" || e.Line == 0 {
				t.Errorf("error %+v: want a reason and a line", e)
			}
		}
	}
	if !found {
		t.Errorf("no error for .claude.json in %+v", doc.Errors)
	}
	if len(doc.Servers) == 0 {
		t.Error("servers is empty, want the servers of the files that loaded")
	}
}

// TestScanJSONConfigLoadFailure checks that a --config file that cannot be
// loaded gives exit code 2 and an empty stdout with --json: there is no
// document, and the problem is on stderr.
func TestScanJSONConfigLoadFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// config returns the --config value.
		config func(t *testing.T, dir string) string
		stderr []string
	}{
		{
			name:   "missing file",
			config: func(_ *testing.T, dir string) string { return filepath.Join(dir, "missing.json") },
			stderr: []string{"missing.json", "file not found"},
		},
		{
			name: "invalid JSON",
			config: func(t *testing.T, dir string) string {
				return writeTestFile(t, dir, "broken.json", `{"mcpServers": {`)
			},
			stderr: []string{"broken.json", "invalid JSON"},
		},
	}
	for _, tt := range tests {
		for _, mode := range scanModes {
			t.Run(tt.name+" "+mode.name, func(t *testing.T) {
				t.Parallel()

				dir := t.TempDir()
				c, stdout, stderr := scanConfigCLI(t, t.TempDir())
				args := append([]string{"scan", "--json", "--config", tt.config(t, dir)}, mode.args...)

				code, out, errOut := runScanArgs(c, stdout, stderr, args...)

				if code != exitError {
					t.Errorf("exit code = %d, want %d", code, exitError)
				}
				if out != "" {
					t.Errorf("stdout = %q, want empty", out)
				}
				assertContainsAll(t, "stderr", errOut, tt.stderr)
				assertScanErrorLines(t, errOut)
			})
		}
	}
}

// TestScanJSONNoSecret scans the dangerous fixture, which holds canary secrets
// and env and header keys, and checks that the document shows none of them.
func TestScanJSONNoSecret(t *testing.T) {
	t.Parallel()

	for _, mode := range configModes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			home, work := discovertest.CopyFixture(t, testdataPath("configs", "dangerous"))
			args := []string{"scan", "--no-connect", "--json"}
			if mode == "config" {
				args = append(args, "--config", filepath.Join(home, ".cursor", "mcp.json"))
			}
			c, stdout, stderr := dirsCLI(t, home, work)

			code, out, errOut := runScanArgs(c, stdout, stderr, args...)

			if code != exitFindings {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitFindings, errOut)
			}
			assertCleanStderr(t, errOut)
			assertNoLeakBoth(t, out, errOut)
			assertContainsNone(t, "stdout", out, dangerousCanaries)
			assertNoEscape(t, out, errOut)
			reporttest.AssertSafeBytes(t, []byte(out))
			doc := decodeScanJSON(t, out)

			// The servers hold no env and no header at all: their JSON has
			// neither the keys nor the values of the config. A finding may
			// name a key (GITHUB_TOKEN), because the project rule is to print
			// keys only.
			serversJSON, err := json.Marshal(doc.Servers)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"API_KEY", "GITHUB_TOKEN", "LOG_LEVEL", "X-Api-Key", "Authorization"} {
				if strings.Contains(string(serversJSON), key) {
					t.Errorf("servers hold the env or header key %q:\n%s", key, serversJSON)
				}
			}
			if strings.Contains(errOut, "API_KEY") {
				t.Errorf("stderr shows the env key API_KEY:\n%s", errOut)
			}
			var gotKey bool
			for _, f := range doc.Findings {
				if f.RuleID == "MOAT-T4-002" && f.Key == "GITHUB_TOKEN" {
					gotKey = true
				}
			}
			if !gotKey {
				t.Errorf("no MOAT-T4-002 finding with the key GITHUB_TOKEN, so the key check is not exercised:\n%s", out)
			}
		})
	}
}

// TestScanJSONEscapesUntrustedText checks that a server name with control and
// bidi runes shows only as \uXXXX escapes, and that the text is lossless after
// decoding.
func TestScanJSONEscapesUntrustedText(t *testing.T) {
	t.Parallel()

	// The JSON escapes below are decoded by the JSON reader of mcpmoat, so the
	// Go source holds no raw control character. The name holds ESC, U+0085
	// (a C1 control) and U+202E (a bidi override).
	const config = `{"mcpServers":{"a\u001b[31mb\u0085c\u202ed":{"command":"echo"}}}`
	const wantName = "a\x1b[31mb\u0085c\u202ed"

	c, stdout, stderr := scanConfigCLI(t, t.TempDir())
	path := writeTestFile(t, t.TempDir(), ".mcp.json", config)

	code, out, errOut := runScanArgs(c, stdout, stderr, "scan", "--no-connect", "--json", "--config", path)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, errOut)
	}
	assertNoEscape(t, out, errOut)
	reporttest.AssertSafeBytes(t, []byte(out))
	doc := decodeScanJSON(t, out)
	if len(doc.Servers) != 1 || doc.Servers[0].Name != wantName {
		t.Errorf("servers = %+v, want one server named %q", doc.Servers, wantName)
	}
	assertContainsAll(t, "stdout", out, []string{`\u001b`, `\u0085`, `\u202e`})
}

// The stderr lines that the "ignored" part of the document repeats (see
// printIgnored and loadIgnore). The tests parse them, so the document is
// compared with what the user sees on the terminal, not with a copy of the
// code under test.
var (
	// ignoredLinePattern matches "mcpmoat scan: 3 findings ignored: A (2), B (1)".
	ignoredLinePattern = regexp.MustCompile(`(?m)^mcpmoat scan: (\d+) findings? ignored: (.+)$`)
	// ignoredPartPattern matches one "RULE-ID (n)" part of that line.
	ignoredPartPattern = regexp.MustCompile(`^(\S+) \((\d+)\)$`)
	// fileNoticePattern matches "mcpmoat scan: using 2 entries from .mcpmoat-ignore".
	fileNoticePattern = regexp.MustCompile(`(?m)^mcpmoat scan: using (\d+) entr(?:y|ies) from \.mcpmoat-ignore$`)
)

// stderrIgnored parses the "N findings ignored: ..." line of stderr. It returns
// N and the count of each rule ID. It returns 0 and an empty map when stderr has
// no such line. It fails the test when the line is malformed, when stderr has
// more than one such line, or when the counts do not add up to N.
func stderrIgnored(t *testing.T, stderr string) (total int, byRule map[string]int) {
	t.Helper()
	byRule = map[string]int{}
	lines := ignoredLinePattern.FindAllStringSubmatch(stderr, -1)
	switch len(lines) {
	case 0:
		return 0, byRule
	case 1:
	default:
		t.Fatalf("stderr has %d \"findings ignored\" lines, want at most 1:\n%s", len(lines), stderr)
	}
	total, err := strconv.Atoi(lines[0][1])
	if err != nil {
		t.Fatalf("bad total in %q: %v", lines[0][0], err)
	}
	sum := 0
	for _, part := range strings.Split(lines[0][2], ", ") {
		m := ignoredPartPattern.FindStringSubmatch(part)
		if m == nil {
			t.Fatalf("part %q of the line %q is not \"RULE-ID (n)\"", part, lines[0][0])
		}
		n, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("bad count in %q: %v", part, err)
		}
		byRule[m[1]] = n
		sum += n
	}
	if sum != total {
		t.Fatalf("the counts of %q add up to %d, not %d", lines[0][0], sum, total)
	}
	return total, byRule
}

// stderrFileEntries returns N of the notice "using N entries from
// .mcpmoat-ignore" on stderr, or 0 when there is no notice.
func stderrFileEntries(t *testing.T, stderr string) int {
	t.Helper()
	m := fileNoticePattern.FindAllStringSubmatch(stderr, -1)
	if len(m) == 0 {
		return 0
	}
	if len(m) > 1 {
		t.Fatalf("stderr has %d ignore-file notices, want at most 1:\n%s", len(m), stderr)
	}
	n, err := strconv.Atoi(m[0][1])
	if err != nil {
		t.Fatalf("bad number in %q: %v", m[0][0], err)
	}
	return n
}

// assertIgnoredMatchesStderr checks that the "ignored" part of doc says the same
// as the stderr of the same scan: total is the N of "N findings ignored", rules
// has the rule IDs and counts of that line and nothing else, and file_entries is
// the N of the notice "using N entries from .mcpmoat-ignore".
func assertIgnoredMatchesStderr(t *testing.T, doc report.ScanReport, stderr string) {
	t.Helper()
	total, byRule := stderrIgnored(t, stderr)
	if doc.Ignored.Total != total {
		t.Errorf("ignored.total = %d, want %d (the stderr line)\nstderr:\n%s", doc.Ignored.Total, total, stderr)
	}
	if doc.Ignored.Rules == nil {
		t.Error("ignored.rules is nil, want an object (empty when nothing is ignored)")
	}
	if !maps.Equal(doc.Ignored.Rules, byRule) {
		t.Errorf("ignored.rules = %v, want %v (the stderr line)", doc.Ignored.Rules, byRule)
	}
	if want := stderrFileEntries(t, stderr); doc.Ignored.FileEntries != want {
		t.Errorf("ignored.file_entries = %d, want %d (the stderr notice)", doc.Ignored.FileEntries, want)
	}
}

// rawJSON decodes out as a generic JSON object, so a test can tell a missing key
// from a key with a zero value (the report types cannot).
func rawJSON(t *testing.T, out string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not a JSON object: %v\nstdout:\n%s", err, out)
	}
	return doc
}

// rawServers returns the servers of the JSON document out, as generic objects.
func rawServers(t *testing.T, out string) []map[string]any {
	t.Helper()
	list, ok := rawJSON(t, out)["servers"].([]any)
	if !ok {
		t.Fatalf("servers is not a list:\n%s", out)
	}
	servers := make([]map[string]any, len(list))
	for i, v := range list {
		servers[i], ok = v.(map[string]any)
		if !ok {
			t.Fatalf("servers[%d] is not an object:\n%s", i, out)
		}
	}
	return servers
}

// ignoreTestServers are the servers of the ignore tests, for writeServers:
//   - leaky-a gives MOAT-T4-002 (a secret in env) and MOAT-T4-003 (an unpinned
//     npx package);
//   - leaky-b gives MOAT-T4-002 only.
//
// So an unfiltered scan has two MOAT-T4-002 findings and one MOAT-T4-003.
func ignoreTestServers() map[string]any {
	env := map[string]string{"API_KEY": discovertest.CanaryEnv}
	return map[string]any{
		"leaky-a": map[string]any{"command": "npx", "args": []string{"some-server"}, "env": env},
		"leaky-b": map[string]any{"command": "run", "env": env},
	}
}

// TestScanJSONIgnored checks the "ignored" part of the document (FR-10, FR-15):
// it holds the same numbers as the stderr line "N findings ignored: ID (n), ..."
// and the notice "using N entries from .mcpmoat-ignore", and it counts the
// entries of the file only, not the --ignore flags.
func TestScanJSONIgnored(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// file is the content of .mcpmoat-ignore ("" writes no file).
		file  string
		flags []string
		// The expected numbers. The test also compares them with stderr.
		wantRules   map[string]int
		wantEntries int
	}{
		{
			name:        "file drops two rules",
			file:        "MOAT-T4-002\nMOAT-T4-003\n",
			wantRules:   map[string]int{"MOAT-T4-002": 2, "MOAT-T4-003": 1},
			wantEntries: 2,
		},
		{
			// The flags give no notice, so they are not file entries.
			name:        "flags only",
			flags:       []string{"--ignore", "MOAT-T4-002", "--ignore", "MOAT-T4-003"},
			wantRules:   map[string]int{"MOAT-T4-002": 2, "MOAT-T4-003": 1},
			wantEntries: 0,
		},
		{
			name:        "file and flags",
			file:        "MOAT-T4-002 leaky-a\n",
			flags:       []string{"--ignore", "MOAT-T4-003", "--ignore", "MOAT-T3-001"},
			wantRules:   map[string]int{"MOAT-T4-002": 1, "MOAT-T4-003": 1},
			wantEntries: 1,
		},
		{
			// Comments, blank lines and a malformed line are no entries.
			name:        "comments and a malformed line",
			file:        "# note\n\nMOAT-T4-003\n9 bad line\n",
			wantRules:   map[string]int{"MOAT-T4-003": 1},
			wantEntries: 1,
		},
		{
			// An entry that matches no finding drops nothing, but the file is
			// still in use, so the notice and file_entries count it.
			name:        "entry that drops nothing",
			file:        "MOAT-T4-002 other-srv\n",
			wantRules:   map[string]int{},
			wantEntries: 1,
		},
		{
			name:      "nothing ignored",
			wantRules: map[string]int{},
		},
	}

	for _, tt := range tests {
		for _, mode := range configModes {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				t.Parallel()

				home, work := t.TempDir(), t.TempDir()
				args := scanServersArgs(t, mode, home, ignoreTestServers())
				if tt.file != "" {
					writeTestFile(t, work, rules.IgnoreFileName, tt.file)
					// scan reads the file only with --use-ignore-file. The
					// base run below gets the flag too: it reads no file,
					// because its working directory is empty.
					args = append(args, useIgnoreFileFlag)
				}
				run := func(extra ...string) (string, string) {
					c, stdout, stderr := dirsCLI(t, home, work)
					_, out, errOut := runScanArgs(c, stdout, stderr, append(slices.Clone(args), extra...)...)
					return out, errOut
				}
				// The same scan without any ignore entry: the findings that the
				// document must have lost.
				var base report.ScanReport
				{
					plain := t.TempDir()
					c, stdout, stderr := dirsCLI(t, home, plain)
					_, out, _ := runScanArgs(c, stdout, stderr, append(slices.Clone(args), "--json")...)
					base = decodeScanJSON(t, out)
				}

				out, errOut := run(append([]string{"--json"}, tt.flags...)...)

				doc := decodeScanJSON(t, out)
				assertIgnoredMatchesStderr(t, doc, errOut)
				wantTotal := 0
				for _, n := range tt.wantRules {
					wantTotal += n
				}
				if doc.Ignored.Total != wantTotal || !maps.Equal(doc.Ignored.Rules, tt.wantRules) || doc.Ignored.FileEntries != tt.wantEntries {
					t.Errorf("ignored = %+v, want total %d, rules %v, file_entries %d\nstderr:\n%s",
						doc.Ignored, wantTotal, tt.wantRules, tt.wantEntries, errOut)
				}
				// The dropped findings are really gone from the list.
				if got, want := len(doc.Findings), len(base.Findings)-wantTotal; got != want {
					t.Errorf("findings has %d entries, want %d (%d without ignore entries, minus %d dropped)",
						got, want, len(base.Findings), wantTotal)
				}
				if wantTotal == 0 {
					// An empty object, never null: a consumer can read
					// ignored.rules without a nil check.
					if !strings.Contains(out, `"rules": {}`) {
						t.Errorf("stdout has no \"rules\": {} (a null breaks consumers):\n%s", out)
					}
				}
				assertNoLeakBoth(t, out, errOut)
			})
		}
	}
}

// TestScanJSONIgnoredNoFileText checks that the document shows no text of the
// ignore file. The file is untrusted, so only rule IDs of dropped findings may
// reach "ignored": no server name, tool name, comment or ID of an entry that
// dropped nothing. The entries below name a server and a tool that the scan does
// not have, and one rule that no finding of the scan has.
func TestScanJSONIgnoredNoFileText(t *testing.T) {
	t.Parallel()

	const file = "# ZZLEAK-comment\n" +
		"MOAT-T4-003 ghost-server/ghost-tool\n" +
		"MOAT-T3-001 ghost-server\n" +
		"MOAT-T4-002 leaky-a  # ZZLEAK-trailing\n"
	// Only the last entry drops a finding.
	wantRules := map[string]int{"MOAT-T4-002": 1}

	for _, mode := range configModes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			home, work := t.TempDir(), t.TempDir()
			args := append(scanServersArgs(t, mode, home, ignoreTestServers()), "--json", useIgnoreFileFlag)
			writeTestFile(t, work, rules.IgnoreFileName, file)
			c, stdout, stderr := dirsCLI(t, home, work)

			_, out, errOut := runScanArgs(c, stdout, stderr, args...)

			doc := decodeScanJSON(t, out)
			assertIgnoredMatchesStderr(t, doc, errOut)
			if !maps.Equal(doc.Ignored.Rules, wantRules) || doc.Ignored.Total != 1 || doc.Ignored.FileEntries != 3 {
				t.Errorf("ignored = %+v, want total 1, rules %v, file_entries 3", doc.Ignored, wantRules)
			}
			assertContainsNone(t, "stdout", out, []string{"ZZLEAK", "ghost-server", "ghost-tool", "MOAT-T3-001"})
			assertContainsNone(t, "stderr", errOut, []string{"ZZLEAK", "ghost-server", "ghost-tool"})
			// "ignored" holds the three fixed keys and nothing else.
			ignored, ok := rawJSON(t, out)["ignored"].(map[string]any)
			if !ok {
				t.Fatalf("ignored is not an object:\n%s", out)
			}
			keys := slices.Sorted(maps.Keys(ignored))
			if want := []string{"file_entries", "rules", "total"}; !slices.Equal(keys, want) {
				t.Errorf("ignored has the keys %v, want %v", keys, want)
			}
		})
	}
}

// TestScanJSONIgnoreFileWithoutFlag checks a .mcpmoat-ignore file in the
// working directory without --use-ignore-file. scan does not read the file, so
// it drops nothing: "ignored" has zero counts, and the findings that the file
// lists stay in the document. stderr has the note line once, and no "using N
// entries" or "findings ignored" line.
func TestScanJSONIgnoreFileWithoutFlag(t *testing.T) {
	t.Parallel()

	// Each entry matches findings of ignoreTestServers.
	const file = "MOAT-T4-002\nMOAT-T4-003\n"
	wantCounts := map[string]int{"MOAT-T4-002": 2, "MOAT-T4-003": 1}

	for _, mode := range configModes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			home, work := t.TempDir(), t.TempDir()
			args := append(scanServersArgs(t, mode, home, ignoreTestServers()), "--json")
			writeTestFile(t, work, rules.IgnoreFileName, file)
			c, stdout, stderr := dirsCLI(t, home, work)

			_, out, errOut := runScanArgs(c, stdout, stderr, args...)

			doc := decodeScanJSON(t, out)
			assertIgnoredMatchesStderr(t, doc, errOut)
			if doc.Ignored.Total != 0 || doc.Ignored.FileEntries != 0 || len(doc.Ignored.Rules) != 0 {
				t.Errorf("ignored = %+v, want total 0, no rules, file_entries 0\nstderr:\n%s", doc.Ignored, errOut)
			}
			gotCounts := map[string]int{}
			for _, f := range doc.Findings {
				if _, ok := wantCounts[f.RuleID]; ok {
					gotCounts[f.RuleID]++
				}
			}
			if !maps.Equal(gotCounts, wantCounts) {
				t.Errorf("findings of the rules in the file = %v, want %v (the file is not read)", gotCounts, wantCounts)
			}
			if n := strings.Count(errOut, ignoreNoteLine+"\n"); n != 1 {
				t.Errorf("stderr has the note line %d times, want 1\nstderr:\n%s", n, errOut)
			}
			if fileNoticePattern.MatchString(errOut) || ignoredLinePattern.MatchString(errOut) {
				t.Errorf("stderr has a line of an ignore file in use, want only the note\nstderr:\n%s", errOut)
			}
			assertNoLeakBoth(t, out, errOut)
		})
	}
}

// termHint is one "To accept" line of the terminal report, split into parts.
type termHint struct {
	name string
	// text is what follows "To accept <name>: ", with no note at the end for a
	// command.
	text string
	// digest is the value after "--expect " in text.
	digest string
	// isCommand is true when text is the command "mcpmoat pin --accept ...",
	// and false when it is the prose steps.
	isCommand bool
}

// parseTermHints returns the "To accept" lines at the end of the terminal
// stdout, in order. It fails the test when a line has no valid digest.
func parseTermHints(t *testing.T, stdout string) []termHint {
	t.Helper()
	_, lines := cutAcceptHints(stdout)
	hints := make([]termHint, len(lines))
	for i, line := range lines {
		rest, _ := strings.CutPrefix(line, acceptHintPrefix)
		name, text, ok := strings.Cut(rest, ": ")
		if !ok {
			t.Fatalf("hint line %q has no \": \"", line)
		}
		_, afterExpect, ok := strings.Cut(text, "--expect ")
		if !ok {
			t.Fatalf("hint line %q has no --expect", line)
		}
		digest, _, _ := strings.Cut(afterExpect, " ")
		if !pins.ValidDigest(digest) {
			t.Fatalf("hint line %q has no valid digest", line)
		}
		hints[i] = termHint{
			name: name, text: text, digest: digest,
			isCommand: strings.HasPrefix(text, "mcpmoat pin --accept "),
		}
	}
	return hints
}

// assertAcceptMatchesTerminal checks the accept objects of the JSON document
// jsonOut against the "To accept" lines of the terminal run termOut of the same
// scan: the same servers in the same order, accept.digest equal to the digest of
// the line, and accept.command equal to the command of the line. When the line
// shows prose steps, the key "command" must be missing from the object, not
// empty, and the prose must not be in the document. It returns the hints.
func assertAcceptMatchesTerminal(t *testing.T, jsonOut, termOut string) []termHint {
	t.Helper()
	hints := parseTermHints(t, termOut)

	type acceptOfServer struct {
		name   string
		accept map[string]any
	}
	var got []acceptOfServer
	for _, s := range rawServers(t, jsonOut) {
		raw, has := s["accept"]
		if !has {
			continue
		}
		accept, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("accept of server %v is not an object: %v", s["name"], raw)
		}
		got = append(got, acceptOfServer{name: s["name"].(string), accept: accept})
	}
	if len(got) != len(hints) {
		t.Fatalf("%d servers have accept, the terminal has %d hint lines\njson:\n%s\nterminal hints: %+v", len(got), len(hints), jsonOut, hints)
	}
	for i, h := range hints {
		g := got[i]
		if g.name != h.name {
			t.Errorf("accept %d is on server %q, the terminal hint %d is for %q", i, g.name, i, h.name)
		}
		if g.accept["digest"] != h.digest {
			t.Errorf("server %q: accept.digest = %v, want %q (the terminal digest)", h.name, g.accept["digest"], h.digest)
		}
		command, hasCommand := g.accept["command"]
		switch {
		case h.isCommand && command != h.text:
			t.Errorf("server %q: accept.command = %v, want %q (the terminal command)", h.name, command, h.text)
		case !h.isCommand && hasCommand:
			t.Errorf("server %q: accept has the key command (%v) but the terminal shows prose steps %q", h.name, command, h.text)
		}
		for key := range g.accept {
			if key != "digest" && key != "command" {
				t.Errorf("server %q: accept has the unknown key %q", h.name, key)
			}
		}
		if !h.isCommand && strings.Contains(jsonOut, h.text) {
			t.Errorf("server %q: the document holds the prose steps %q", h.name, h.text)
		}
	}
	return hints
}

// TestScanJSONAccept checks the "accept" object of a server with changed tools
// (FR-15), against the "To accept" line of the terminal run of the same scan.
// A command is in the document only when the terminal shows a command. In each
// prose case the key "command" is missing.
func TestScanJSONAccept(t *testing.T) {
	t.Parallel()

	short := []inspect.Tool{mkTool("a", "Add.")}
	changed := []inspect.Tool{mkTool("a", "Add. Changed.")}
	cut := []inspect.Tool{mkTool("a", linesDescription(2500))}
	// brokenConfig has a config file problem: scan still reports the servers of
	// the other files, but pin refuses to run, so the hint has no command.
	const brokenConfig = `{"mcpServers": {`

	tests := []struct {
		name string
		// servers are the servers of the --config file, or nil for auto-discovery.
		servers map[string]any
		// stage writes more files before the first scan. after writes files
		// between the first scan and the compared scan.
		stage, after func(t *testing.T, e *pinEnv)
		// first and current are the tools of each server at the first scan and
		// at the compared scan.
		first, current map[string][]inspect.Tool
		flags          []string
		// wantAccepts are the servers that must have an accept object, in order.
		wantAccepts []string
		// wantCommand tells whether the terminal must show a command.
		wantCommand bool
	}{
		{
			name:    "command",
			servers: oneServer("srv"),
			first:   map[string][]inspect.Tool{"srv": short}, current: map[string][]inspect.Tool{"srv": changed},
			wantAccepts: []string{"srv"}, wantCommand: true,
		},
		{
			name:    "cut diff",
			servers: oneServer("srv"),
			first:   map[string][]inspect.Tool{"srv": short}, current: map[string][]inspect.Tool{"srv": cut},
			wantAccepts: []string{"srv"},
		},
		{
			// MOAT-T2-002 (a new tool) is dropped by --ignore, so the report
			// does not show that change, but the digest covers it.
			name:    "change hidden by --ignore of the pin rule",
			servers: oneServer("srv"),
			first:   map[string][]inspect.Tool{"srv": short},
			current: map[string][]inspect.Tool{"srv": {mkTool("a", "Add. Changed."), mkTool("b", "New.")}},
			flags:   []string{"--ignore", "MOAT-T2-002"}, wantAccepts: []string{"srv"},
		},
		{
			// A name with a space is not a bare shell word.
			name:    "server name that is not a bare shell word",
			servers: oneServer("my srv"),
			first:   map[string][]inspect.Tool{"my srv": short}, current: map[string][]inspect.Tool{"my srv": changed},
			wantAccepts: []string{"my srv"},
		},
		{
			// Two global files with one server name: pin refuses the name
			// without --config. Both servers have a hint.
			name: "ambiguous server name",
			stage: func(t *testing.T, e *pinEnv) {
				writeServers(t, e.home, ".claude.json", oneServer("dup"))
				writeServers(t, e.home, filepath.Join(".cursor", "mcp.json"), oneServer("dup"))
			},
			first: map[string][]inspect.Tool{"dup": short}, current: map[string][]inspect.Tool{"dup": changed},
			wantAccepts: []string{"dup", "dup"},
		},
		{
			name: "config problem",
			stage: func(t *testing.T, e *pinEnv) {
				writeServers(t, e.home, ".claude.json", oneServer("srv"))
			},
			after: func(t *testing.T, e *pinEnv) {
				writeTestFile(t, filepath.Join(e.home, ".cursor"), "mcp.json", brokenConfig)
			},
			first: map[string][]inspect.Tool{"srv": short}, current: map[string][]inspect.Tool{"srv": changed},
			wantAccepts: []string{"srv"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := newPinEnv(t, tt.servers)
			if tt.stage != nil {
				tt.stage(t, e)
			}
			// A nil servers map means auto-discovery: scan reads the files that
			// stage wrote in the home, not --config.
			run := func(insp inspect.Inspector, args ...string) pinRunResult {
				if tt.servers == nil {
					return e.raw(insp, append([]string{"scan"}, args...)...)
				}
				return e.scan(insp, args...)
			}
			if got := run(fakeServers(tt.first)); got.code != exitOK {
				t.Fatalf("first scan: exit code = %d, want %d\nstderr:\n%s", got.code, exitOK, got.stderr)
			}
			if tt.after != nil {
				tt.after(t, e)
			}

			// The terminal run and the --json run see the same pins: a scan
			// that finds changes does not save them.
			term := run(fakeServers(tt.current), tt.flags...)
			got := run(fakeServers(tt.current), append([]string{"--json"}, tt.flags...)...)

			if got.code != term.code {
				t.Errorf("--json exit code = %d, want %d (same as the terminal run)", got.code, term.code)
			}
			if got.stderr != term.stderr {
				t.Errorf("--json stderr differs from the terminal run\n--json:\n%s\nterminal:\n%s", got.stderr, term.stderr)
			}
			assertNoLeakBoth(t, got.stdout, got.stderr)
			reporttest.AssertSafeBytes(t, []byte(got.stdout))
			doc := decodeScanJSON(t, got.stdout)
			assertIgnoredMatchesStderr(t, doc, got.stderr)

			hints := assertAcceptMatchesTerminal(t, got.stdout, term.stdout)

			var names []string
			for _, h := range hints {
				names = append(names, h.name)
				if h.isCommand != tt.wantCommand {
					t.Errorf("terminal hint of %q is a command: %v, want %v (text %q)", h.name, h.isCommand, tt.wantCommand, h.text)
				}
				// The digest covers all current tools of the server, also a change
				// that --ignore hid.
				if want := digestOf(t, tt.current[h.name]...); h.digest != want {
					t.Errorf("accept digest of %q = %s, want %s (the digest of its current tools)", h.name, h.digest, want)
				}
			}
			if !slices.Equal(names, tt.wantAccepts) {
				t.Errorf("hints are for %v, want %v", names, tt.wantAccepts)
			}
			if tt.wantCommand {
				// The exact command: name, the --config of the scan, the digest.
				want := "mcpmoat pin --accept srv --config " + e.config + " --expect " + digestOf(t, tt.current["srv"]...)
				if len(hints) != 1 || hints[0].text != want {
					t.Errorf("terminal hints = %+v, want one command %q", hints, want)
				}
			}
		})
	}
}

// TestScanJSONNoAccept checks that a server with nothing to accept has no
// "accept" key at all: not null, not an empty object. These are the cases where
// scan prints no "To accept" line.
func TestScanJSONNoAccept(t *testing.T) {
	t.Parallel()

	pinned := []inspect.Tool{mkTool("a", "Add.")}
	changed := []inspect.Tool{mkTool("a", "Add. X.")}

	tests := []struct {
		name     string
		pinFirst bool
		insp     func() inspect.Inspector
		flags    []string
	}{
		{
			name: "first run",
			insp: func() inspect.Inspector { return fakeServers(map[string][]inspect.Tool{"srv": changed}) },
		},
		{
			name: "first run that cannot be pinned",
			insp: func() inspect.Inspector {
				return fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "One."), mkTool("a", "Two.")}})
			},
		},
		{
			name: "pinned server that did not change", pinFirst: true,
			insp: func() inspect.Inspector { return fakeServers(map[string][]inspect.Tool{"srv": pinned}) },
		},
		{
			name: "pinned server that was not inspected", pinFirst: true,
			insp: func() inspect.Inspector { return failingFake("srv") },
		},
		{
			// Every change is dropped by --ignore, so no row is kept.
			name: "every finding is dropped by --ignore", pinFirst: true,
			insp:  func() inspect.Inspector { return fakeServers(map[string][]inspect.Tool{"srv": changed}) },
			flags: []string{"--ignore", "MOAT-T2-001"},
		},
		{
			// The tools cannot be pinned, so they cannot be accepted either.
			name: "tools that cannot be pinned", pinFirst: true,
			insp: func() inspect.Inspector {
				return fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add."), mkTool("a", "Copy.")}})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := newPinEnv(t, oneServer("srv"))
			if tt.pinFirst {
				firstScan(t, e, pinned...)
			}

			got := e.scan(tt.insp(), append([]string{"--json"}, tt.flags...)...)

			doc := decodeScanJSON(t, got.stdout)
			if len(doc.Servers) != 1 {
				t.Fatalf("servers = %+v, want one server\nstderr:\n%s", doc.Servers, got.stderr)
			}
			if _, has := rawServers(t, got.stdout)[0]["accept"]; has || strings.Contains(got.stdout, `"accept"`) {
				t.Errorf("stdout has the key accept, want none:\n%s", got.stdout)
			}
			if doc.Servers[0].Accept != nil {
				t.Errorf("accept = %+v, want nil", doc.Servers[0].Accept)
			}
		})
	}

	// Two servers: only the one with a change gets accept.
	t.Run("one server changed and one not", func(t *testing.T) {
		t.Parallel()

		e := newPinEnv(t, map[string]any{
			"alpha": map[string]any{"command": "npx"},
			"beta":  map[string]any{"command": "npx"},
		})
		if got := e.scan(fakeServers(map[string][]inspect.Tool{"alpha": pinned, "beta": pinned})); got.code != exitOK {
			t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
		}
		current := map[string][]inspect.Tool{"alpha": changed, "beta": pinned}

		term := e.scan(fakeServers(current))
		got := e.scan(fakeServers(current), "--json")

		doc := decodeScanJSON(t, got.stdout)
		for _, s := range doc.Servers {
			switch s.Name {
			case "alpha":
				if s.Accept == nil || s.Accept.Digest != digestOf(t, changed...) {
					t.Errorf("alpha accept = %+v, want the digest of its changed tools", s.Accept)
				}
			case "beta":
				if s.Accept != nil {
					t.Errorf("beta accept = %+v, want nil: its tools did not change", s.Accept)
				}
			}
		}
		if hints := assertAcceptMatchesTerminal(t, got.stdout, term.stdout); len(hints) != 1 || hints[0].name != "alpha" {
			t.Errorf("terminal hints = %+v, want one hint for alpha", hints)
		}
	})
}
