package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/report/reporttest"
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
		t.Errorf("stdout does not follow %s: %v\nstdout:\n%s", reporttest.SchemaName(), err, stdout)
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
func jsonNormalize(t *testing.T, out string, replacements map[string]string) string {
	t.Helper()
	return replacePaths(out, replacements, func(p string) string { return jsonEscaped(t, p) })
}

// jsonEscaped returns s as it shows inside a JSON string, without the quotes.
func jsonEscaped(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b[1 : len(b)-1])
}

// assertNoTempPath fails the test if out still holds one of the real paths.
func assertNoTempPath(t *testing.T, out string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if strings.Contains(out, p) || strings.Contains(out, jsonEscaped(t, p)) {
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

	got := jsonNormalize(t, first, map[string]string{home: "$HOME", work: "$WORK"})
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
		if d.DiffIsNote {
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

	got := jsonNormalize(t, second.stdout, map[string]string{
		e.home: "$HOME", e.work: "$WORK", e.xdg: "$XDG", filepath.Dir(e.config): "$CONFIG",
	})
	assertNoTempPath(t, got, e.home, e.work, e.xdg, filepath.Dir(e.config))
	assertScanGolden(t, "scan_json_pins_changed", []byte(got))

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
		if len(doc.Diffs) != 1 || !doc.Diffs[0].DiffIsNote || strings.Contains(doc.Diffs[0].Diff, "+++") {
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
			run := func(args ...string) (code int, stdout, stderr string) {
				c, out, errOut := dirsCLI(t, home, work)
				return runScanArgs(c, out, errOut, args...)
			}

			termCode, termOut, termErr := run("scan", "--no-connect")
			jsonCode, jsonOut, jsonErr := run("scan", "--no-connect", "--json")

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
			if doc.Complete == tt.wantErrors {
				t.Errorf("complete = %v, want %v", doc.Complete, !tt.wantErrors)
			}

			// The document holds the same servers and findings as the tables,
			// in the same order. The names of the fixtures hold no space.
			if len(doc.Servers) > 0 {
				if got, want := serverNames(doc), column(tableRows(t, termOut), 0); !slices.Equal(got, want) {
					t.Errorf("server names = %v, want %v (the order of the server table)", got, want)
				}
				if got, want := findingRuleIDs(doc), column(findingRows(t, termOut), 0); !slices.Equal(got, want) {
					t.Errorf("finding rule IDs = %v, want %v (the order of the findings table)", got, want)
				}
			}

			if len(doc.Servers) == 0 {
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

// setPinCanonical sets the canonical text of the pinned tool in pins.json of
// e, with the matching hash, so the store still loads it.
func setPinCanonical(t *testing.T, e *pinEnv, tool, canonical string) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(readFileBytes(t, e.pinsPath()), &doc); err != nil {
		t.Fatal(err)
	}
	servers, _ := doc["servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("pins.json has %d servers, want 1", len(servers))
	}
	tools, _ := servers[0].(map[string]any)["tools"].(map[string]any)
	if _, ok := tools[tool]; !ok {
		t.Fatalf("pins.json has no tool %q", tool)
	}
	sum := sha256.Sum256([]byte(canonical))
	tools[tool] = map[string]any{"hash": pins.HashVersion + ":" + hex.EncodeToString(sum[:]), "canonical": canonical}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.pinsPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
