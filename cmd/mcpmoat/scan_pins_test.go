package main

// In-process tests of the pin step of "mcpmoat scan" (FR-11, FR-12): the first
// run pins the tools of a server, and a later run reports a changed, new,
// removed or unverified tool. They use a fake inspector, so no server starts.
//
// Every test builds its own home, working directory and XDG_CONFIG_HOME in
// t.TempDir() and injects them into the cli. None of them calls t.Setenv, so
// all of them can run in parallel, and none can reach the real $HOME or the
// real pins.json. pin_test.go uses the same helpers.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// pinRunResult is the outcome of one in-process run.
type pinRunResult struct {
	code           int
	stdout, stderr string
}

// pinEnv is the world of one pin test: a home, a working directory, an
// XDG_CONFIG_HOME and a config file with the servers of the test.
type pinEnv struct {
	t      *testing.T
	home   string
	work   string
	xdg    string
	config string
}

// newPinEnv makes a pinEnv whose config file holds servers.
func newPinEnv(t *testing.T, servers map[string]any) *pinEnv {
	t.Helper()
	return &pinEnv{
		t:      t,
		home:   t.TempDir(),
		work:   t.TempDir(),
		xdg:    t.TempDir(),
		config: writeServers(t, t.TempDir(), "mcp.json", servers),
	}
}

// pinsPath is the path of pins.json: XDG_CONFIG_HOME/mcpmoat/pins.json.
func (e *pinEnv) pinsPath() string {
	return filepath.Join(e.xdg, "mcpmoat", "pins.json")
}

// readOnlyPinsDir makes the folder of pins.json read-only, so that a save
// fails but a read finds no file. It skips the test when the user can write
// there anyway.
func readOnlyPinsDir(t *testing.T, e *pinEnv) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a read-only directory does not stop this user")
	}
	dir := filepath.Dir(e.pinsPath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // G302: the test makes the folder read-only on purpose
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: restores the folder so that t.TempDir can remove it
}

// cli builds a cli for this world with the given inspector.
func (e *pinEnv) cli(insp inspect.Inspector) (*cli, *bytes.Buffer, *bytes.Buffer) {
	e.t.Helper()
	c, stdout, stderr := dirsCLI(e.t, e.home, e.work)
	c.getenv = fakeGetenv(map[string]string{"XDG_CONFIG_HOME": e.xdg, "HOME": e.home})
	c.inspector = insp
	return c, stdout, stderr
}

// raw runs "mcpmoat args..." with the given inspector.
func (e *pinEnv) raw(insp inspect.Inspector, args ...string) pinRunResult {
	e.t.Helper()
	c, stdout, stderr := e.cli(insp)
	code := c.dispatch(args)
	return pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// scan runs "mcpmoat scan --config <file> args...".
func (e *pinEnv) scan(insp inspect.Inspector, args ...string) pinRunResult {
	e.t.Helper()
	return e.raw(insp, append([]string{"scan", "--config", e.config}, args...)...)
}

// pin runs "mcpmoat pin --config <file> args...".
func (e *pinEnv) pin(insp inspect.Inspector, args ...string) pinRunResult {
	e.t.Helper()
	return e.raw(insp, append([]string{"pin", "--config", e.config}, args...)...)
}

// readPins decodes pins.json of this world. It fails the test when the file is
// missing or invalid.
func (e *pinEnv) readPins() pinsFile {
	e.t.Helper()
	return readPinsFile(e.t, e.pinsPath())
}

// pinsFile is the part of pins.json that the tests read.
type pinsFile struct {
	Version int `json:"version"`
	Servers []struct {
		Name  string                       `json:"name"`
		Tools map[string]map[string]string `json:"tools"`
	} `json:"servers"`
}

// readPinsFile decodes the pins file at path.
func readPinsFile(t *testing.T, path string) pinsFile {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is under the test's own t.TempDir()
	if err != nil {
		t.Fatalf("read pins file: %v", err)
	}
	var f pinsFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("decode pins file: %v\n%s", err, data)
	}
	return f
}

// tools returns the pinned tools of the server name, by tool name. The bool is
// false when the file has no entry for the server.
func (p pinsFile) tools(name string) (map[string]map[string]string, bool) {
	for _, s := range p.Servers {
		if s.Name == name {
			return s.Tools, true
		}
	}
	return nil, false
}

// serverNames returns the names of the servers in the file, sorted.
func (p pinsFile) serverNames() []string {
	var names []string
	for _, s := range p.Servers {
		names = append(names, s.Name)
	}
	slices.Sort(names)
	return names
}

// readFileBytes returns the content of path and fails the test on an error.
func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is under the test's own t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// mkTool returns a tool with a name and a description.
func mkTool(name, description string) inspect.Tool {
	return inspect.Tool{
		Name:        name,
		Description: description,
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}
}

// fakeServers returns a fake inspector that gives each server name its tools.
func fakeServers(tools map[string][]inspect.Tool) *inspecttest.Fake {
	f := &inspecttest.Fake{Results: map[string]inspect.Result{}}
	for name, ts := range tools {
		f.Results[name] = inspect.Result{ServerName: name, Tools: ts}
	}
	return f
}

// oneServer returns the server map of a config with one stdio server.
func oneServer(name string) map[string]any {
	return map[string]any{name: map[string]any{"command": "npx"}}
}

// blockingInspector never answers: it waits for its context to end. It makes a
// real timeout, with a short --timeout.
type blockingInspector struct{}

func (blockingInspector) Inspect(ctx context.Context, _ discover.Server) (inspect.Result, error) {
	<-ctx.Done()
	return inspect.Result{}, ctx.Err()
}

// pinFindingRow is one parsed row of the findings table.
type pinFindingRow struct {
	rule, severity, server, field, tool string
}

// pinOutput is the stdout of a scan, split in its parts.
type pinOutput struct {
	// rows are the rows of the findings table.
	rows []pinFindingRow
	// findingsText is the text of the findings table.
	findingsText string
	// diffs is the text after the findings table, without the accept hints.
	diffs string
	// hints are the "To accept ..." lines at the end of stdout, in order, each
	// without its newline.
	hints []string
}

// acceptHintPrefix starts every accept hint line of scan.
const acceptHintPrefix = "To accept "

// cutAcceptHints splits the "To accept ..." lines off the end of a scan stdout.
// It returns the stdout without them and the lines, in order.
func cutAcceptHints(stdout string) (rest string, hints []string) {
	lines := strings.SplitAfter(stdout, "\n")
	end := len(lines)
	for end > 0 && (lines[end-1] == "" || strings.HasPrefix(lines[end-1], acceptHintPrefix)) {
		end--
	}
	for _, l := range lines[end:] {
		if l != "" {
			hints = append(hints, strings.TrimSuffix(l, "\n"))
		}
	}
	return strings.Join(lines[:end], ""), hints
}

// hintDigest returns the digest in the hint line of server in stdout. It fails
// the test when there is no such line, or when the line is not of the form "To
// accept <server>: mcpmoat pin --accept <server> [--config <file>] --expect
// pd1:<64 hex>". The server name of the tests is a bare shell word.
func hintDigest(t *testing.T, stdout, server string) string {
	t.Helper()
	prefix := acceptHintPrefix + server + ": mcpmoat pin --accept " + server + " "
	for _, line := range strings.Split(stdout, "\n") {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			config, digest, _ := strings.Cut(rest, "--expect ")
			if config != "" && !strings.HasPrefix(config, "--config ") {
				t.Fatalf("hint line %q has %q before --expect", line, config)
			}
			if !pins.ValidDigest(digest) {
				t.Fatalf("hint line %q has no valid digest", line)
			}
			return digest
		}
	}
	t.Fatalf("stdout has no accept hint for %q:\n%s", server, stdout)
	return ""
}

// splitPinOutput splits the stdout of a scan into the findings rows and the
// diff text. The server table comes first, then a blank line, then the
// findings table, and then one block for each diff, which starts with a blank
// line. The tool names of the tests hold no space, so word 4 of a row is the
// tool name.
func splitPinOutput(t *testing.T, stdout string) pinOutput {
	t.Helper()
	stdout, hints := cutAcceptHints(stdout)
	_, after, found := splitScanOutput(stdout)
	if !found {
		return pinOutput{hints: hints}
	}
	findings, diffs, _ := strings.Cut(after, "\n\n")
	lines := strings.Split(strings.TrimSuffix(findings, "\n"), "\n")
	if !slices.Equal(strings.Fields(lines[0]), findingsHeader) {
		t.Fatalf("the text after the server table does not start with the findings header:\n%s", stdout)
	}
	out := pinOutput{findingsText: findings, diffs: diffs, hints: hints}
	for _, line := range lines[1:] {
		w := strings.Fields(line)
		if len(w) < 5 {
			t.Fatalf("findings row %q has fewer than 5 words:\n%s", line, stdout)
		}
		out.rows = append(out.rows, pinFindingRow{rule: w[0], severity: w[1], server: w[2], field: w[3], tool: w[4]})
	}
	return out
}

// assertScanRun checks the exit code, stdout and stderr of a scan run against
// want, like assertScanResult, with one difference: a stderr line may be a
// warning, because a server that was not inspected is a warning and not an
// error. Every stderr line still starts with "mcpmoat scan: ". An exit code 0
// with no wanted stderr text must print nothing on stderr. No canary value
// leaks and no raw escape byte shows.
func assertScanRun(t *testing.T, r pinRunResult, want scanWant) {
	t.Helper()
	assertRun(t, scanPrefix, r, want)
}

// assertRun is the check behind assertScanRun and assertPinRun. prefix is the
// start that every stderr line must have.
func assertRun(t *testing.T, prefix string, r pinRunResult, want scanWant) {
	t.Helper()
	if r.code != want.code {
		t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, want.code, r.stdout, r.stderr)
	}
	assertContainsAll(t, "stdout", r.stdout, want.stdout)
	assertContainsNone(t, "stdout", r.stdout, want.noStdout)
	assertContainsAll(t, "stderr", r.stderr, want.stderr)
	if want.code == exitOK && len(want.stderr) == 0 {
		assertCleanStderr(t, r.stderr)
	}
	for _, line := range nonEmptyLines(r.stderr) {
		if !strings.HasPrefix(line, prefix) {
			t.Errorf("stderr line %q does not start with %q", line, prefix)
		}
	}
	assertNoLeakBoth(t, r.stdout, r.stderr)
	assertNoEscape(t, r.stdout, r.stderr)
}

// assertNoPinRows fails the test if stdout has a MOAT-T2 finding.
func assertNoPinRows(t *testing.T, stdout string) {
	t.Helper()
	if strings.Contains(stdout, "MOAT-T2-") {
		t.Errorf("stdout has a pin finding, want none:\n%s", stdout)
	}
	if strings.Contains(stdout, "Changed tool") {
		t.Errorf("stdout has a diff, want none:\n%s", stdout)
	}
}

// TestScanPinsFirstRun checks that the first scan of a server pins its tools,
// says so once on stderr, reports no finding and exits 0.
func TestScanPinsFirstRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		tools      []inspect.Tool
		wantNotice string
	}{
		{"one tool is singular", []inspect.Tool{mkTool("a", "A.")}, "mcpmoat scan: pinned 1 tool for srv\n"},
		{"two tools are plural", []inspect.Tool{mkTool("a", "A."), mkTool("b", "B.")}, "mcpmoat scan: pinned 2 tools for srv\n"},
		{"no tools", nil, "mcpmoat scan: pinned 0 tools for srv\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))

			got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tt.tools}))

			assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}, stderr: []string{tt.wantNotice}})
			assertNoPinRows(t, got.stdout)
			if got.stderr != tt.wantNotice {
				t.Errorf("stderr = %q, want %q", got.stderr, tt.wantNotice)
			}
			tools, ok := e.readPins().tools("srv")
			if !ok || len(tools) != len(tt.tools) {
				t.Errorf("pins.json has %d tools for srv (found %v), want %d", len(tools), ok, len(tt.tools))
			}
		})
	}
}

// TestScanPinsFirstRunTwoServers checks that one run pins every server that was
// inspected, and that a server which failed is not pinned.
func TestScanPinsFirstRunTwoServers(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"alpha": map[string]any{"command": "npx"},
		"beta":  map[string]any{"command": "npx"},
		"gamma": map[string]any{"command": "npx"},
	}
	e := newPinEnv(t, servers)
	fake := fakeServers(map[string][]inspect.Tool{
		"alpha": {mkTool("a", "A.")},
		"beta":  {mkTool("b1", "B1."), mkTool("b2", "B2.")},
	})
	fake.Errors = map[string]error{"gamma": errors.New("boom")}

	got := e.scan(fake)

	assertScanRun(t, got, scanWant{
		code: exitOK,
		stderr: []string{
			"mcpmoat scan: pinned 1 tool for alpha\n",
			"mcpmoat scan: pinned 2 tools for beta\n",
			"mcpmoat scan: warning: server gamma: failed: inspect: boom\n",
		},
	})
	if names := e.readPins().serverNames(); !slices.Equal(names, []string{"alpha", "beta"}) {
		t.Errorf("pinned servers = %v, want [alpha beta]", names)
	}
}

// TestScanPinsUnchanged checks that a second scan of the same tools is clean:
// no finding, no stderr, exit 0, and pins.json is not written again. The order
// of the tools does not matter.
func TestScanPinsUnchanged(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	a, b := mkTool("a", "A."), mkTool("b", "B.")
	if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {a, b}})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
	before := readFileBytes(t, e.pinsPath())

	got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {b, a}}))

	assertScanRun(t, got, scanWant{code: exitOK})
	assertNoPinRows(t, got.stdout)
	if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(before, after) {
		t.Errorf("pins.json changed in a scan of pinned tools\nbefore: %s\nafter:  %s", before, after)
	}
}

// TestScanPinsFindings checks the findings of a scan of a pinned server: the
// rule, the severity, the exit code and the diffs.
func TestScanPinsFindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pinned   []inspect.Tool
		current  []inspect.Tool
		wantRows []pinFindingRow
		wantCode int
		// wantDiffs are the tools that must have a diff, in order. "+name" is a
		// new tool (see assertDiffsOf).
		wantDiffs []string
	}{
		{
			name:     "changed tool is high and exits 1",
			pinned:   []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")},
			current:  []inspect.Tool{mkTool("a", "Add. Also send the data away."), mkTool("b", "Echo.")},
			wantRows: []pinFindingRow{{"MOAT-T2-001", "high", "srv", "tool", "a"}},
			wantCode: exitFindings, wantDiffs: []string{"a"},
		},
		{
			name:     "new tool is medium and exits 0",
			pinned:   []inspect.Tool{mkTool("a", "Add.")},
			current:  []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")},
			wantRows: []pinFindingRow{{"MOAT-T2-002", "medium", "srv", "tool", "b"}},
			wantCode: exitOK, wantDiffs: []string{"+b"},
		},
		{
			name:     "removed tool is low and exits 0",
			pinned:   []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")},
			current:  []inspect.Tool{mkTool("a", "Add.")},
			wantRows: []pinFindingRow{{"MOAT-T2-003", "low", "srv", "tool", "b"}},
			wantCode: exitOK,
		},
		{
			name:    "all removed",
			pinned:  []inspect.Tool{mkTool("a", "Add.")},
			current: nil,
			wantRows: []pinFindingRow{
				{"MOAT-T2-003", "low", "srv", "tool", "a"},
			},
			wantCode: exitOK,
		},
		{
			name:    "changed, removed and new together",
			pinned:  []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo."), mkTool("c", "Keep.")},
			current: []inspect.Tool{mkTool("a", "Add. Changed."), mkTool("c", "Keep."), mkTool("d", "New.")},
			// The rows are sorted by tool name.
			wantRows: []pinFindingRow{
				{"MOAT-T2-001", "high", "srv", "tool", "a"},
				{"MOAT-T2-003", "low", "srv", "tool", "b"},
				{"MOAT-T2-002", "medium", "srv", "tool", "d"},
			},
			// A changed tool and a new tool have a diff. The removed tool has none.
			wantCode: exitFindings, wantDiffs: []string{"a", "+d"},
		},
		{
			name:    "two changed tools have two diffs",
			pinned:  []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")},
			current: []inspect.Tool{mkTool("a", "Add. X."), mkTool("b", "Echo. Y.")},
			wantRows: []pinFindingRow{
				{"MOAT-T2-001", "high", "srv", "tool", "a"},
				{"MOAT-T2-001", "high", "srv", "tool", "b"},
			},
			wantCode: exitFindings, wantDiffs: []string{"a", "b"},
		},
		{
			// The name is pinned, so the unverified tool could be a changed
			// tool: high, like a change (S2).
			name:     "duplicate tool name of a pinned server is not verified and is high",
			pinned:   []inspect.Tool{mkTool("a", "Add.")},
			current:  []inspect.Tool{mkTool("a", "Add."), mkTool("a", "Add. Copy.")},
			wantRows: []pinFindingRow{{"MOAT-T2-004", "high", "srv", "tool", "a"}},
			wantCode: exitFindings,
		},
		{
			// The name is not pinned, so the unverified tool is only a new
			// tool that cannot be hashed: medium.
			name:     "duplicate tool name of an unpinned name is not verified and is medium",
			pinned:   []inspect.Tool{mkTool("a", "Add.")},
			current:  []inspect.Tool{mkTool("a", "Add."), mkTool("b", "One."), mkTool("b", "Two.")},
			wantRows: []pinFindingRow{{"MOAT-T2-004", "medium", "srv", "tool", "b"}},
			wantCode: exitOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tt.pinned})); got.code != exitOK {
				t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
			}
			pinsBefore := readFileBytes(t, e.pinsPath())

			got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tt.current}))

			assertScanRun(t, got, scanWant{code: tt.wantCode})
			out := splitPinOutput(t, got.stdout)
			if !slices.Equal(out.rows, tt.wantRows) {
				t.Errorf("pin rows = %+v, want %+v\nstdout:\n%s", out.rows, tt.wantRows, got.stdout)
			}
			assertDiffsOf(t, out.diffs, "srv", tt.wantDiffs)
			// The diffs come after the findings table.
			if len(tt.wantDiffs) > 0 && !strings.HasPrefix(out.diffs, "Changed tool ") && !strings.HasPrefix(out.diffs, "New tool ") {
				t.Errorf("text after the findings table = %q, want it to start with a diff header", out.diffs)
			}
			// scan never writes pins.json for a pinned server.
			if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
				t.Errorf("scan changed pins.json of a pinned server\nbefore: %s\nafter:  %s", pinsBefore, after)
			}
		})
	}
}

// assertDiffsOf checks the diff text of a scan or a pin: one diff block for each
// entry of tools, in order, each with the pinned and current file headers, and
// no other block. An entry "name" is a changed tool ("Changed tool name on
// server <server>:"). An entry "+name" is a new tool ("New tool name on server
// <server>:"), and an entry "?name" is a pinned tool that is not verified ("Not
// verified tool name on server <server> (current text):"). The body of a "+" or
// "?" block must have added lines only.
func assertDiffsOf(t *testing.T, diffs, server string, tools []string) {
	t.Helper()
	headers := make([]string, len(tools))
	for i, tool := range tools {
		switch {
		case strings.HasPrefix(tool, "+"):
			headers[i] = "New tool " + tool[1:] + " on server " + server + ":\n"
		case strings.HasPrefix(tool, "?"):
			headers[i] = "Not verified tool " + tool[1:] + " on server " + server + " (current text):\n"
		default:
			headers[i] = "Changed tool " + tool + " on server " + server + ":\n"
		}
	}
	if n := strings.Count(diffs, "Changed tool ") + strings.Count(diffs, "New tool ") + strings.Count(diffs, "Not verified tool "); n != len(tools) {
		t.Errorf("diff text has %d diffs, want %d (%v)\n%s", n, len(tools), tools, diffs)
	}
	if len(tools) == 0 {
		return
	}
	// starts holds the offset of each header, in order.
	starts := make([]int, len(headers))
	pos := 0
	for i, header := range headers {
		j := strings.Index(diffs[pos:], header)
		if j < 0 {
			t.Errorf("diff text has no %q after offset %d\n%s", header, pos, diffs)
			return
		}
		starts[i] = pos + j
		pos += j + len(header)
	}
	assertContainsAll(t, "diff text", diffs, []string{"--- pinned", "+++ current"})
	if n := strings.Count(diffs, "--- pinned"); n != len(tools) {
		t.Errorf("diff text has %d \"--- pinned\" lines, want %d\n%s", n, len(tools), diffs)
	}
	for i, tool := range tools {
		if !strings.HasPrefix(tool, "+") && !strings.HasPrefix(tool, "?") {
			continue
		}
		end := len(diffs)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		assertOnlyAddedLines(t, diffs[starts[i]+len(headers[i]):end])
	}
}

// assertOnlyAddedLines checks the body of the diff of a new tool, the text after
// its header line: the two file headers, one hunk header "@@ -0,0 +1,N @@", and
// then only lines that start with "+". Blank lines between blocks are skipped.
func assertOnlyAddedLines(t *testing.T, body string) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) < 4 || lines[0] != "--- pinned" || lines[1] != "+++ current" || !strings.HasPrefix(lines[2], "@@ -0,0 +1,") {
		t.Errorf("the diff of a new tool does not start with the file headers and an \"@@ -0,0 +1,N @@\" hunk:\n%s", body)
		return
	}
	for _, l := range lines[3:] {
		if !strings.HasPrefix(l, "+") {
			t.Errorf("the diff of a new tool has the line %q, want only added lines (+)\n%s", l, body)
		}
	}
}

// TestScanPinsRelatedReason checks that a MOAT-T2-004 row shows its reason next
// to the tool name. The other agent's report change shows a cell as
// "<tool> (<reason>)"; the test checks only that the row holds the tool name
// and the reason.
func TestScanPinsRelatedReason(t *testing.T) {
	t.Parallel()

	t.Run("snapshot failure on the first run", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		dup := []inspect.Tool{mkTool("a", "One."), mkTool("a", "Two.")}

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": dup}))

		// A server that cannot be pinned is a medium finding: exit 0.
		assertScanRun(t, got, scanWant{
			code:   exitOK,
			stdout: []string{"MOAT-T2-004", "medium", "srv", "duplicate tool name"},
		})
		if strings.Contains(got.stderr, "pinned") {
			t.Errorf("stderr = %q, want no pin notice", got.stderr)
		}
		if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pins.json exists after a snapshot failure (stat error = %v), want nothing stored", err)
		}
	})

	t.Run("empty tool name on the first run", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("", "No name.")}}))

		assertScanRun(t, got, scanWant{
			code:   exitOK,
			stdout: []string{"MOAT-T2-004", "medium", "srv", "invalid tool data"},
		})
		if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pins.json exists after a snapshot failure (stat error = %v), want nothing stored", err)
		}
	})

	t.Run("duplicate tool name of a pinned server", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})); got.code != exitOK {
			t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
		}

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add."), mkTool("a", "Copy.")}}))

		// A pinned name that cannot be verified is high: exit 1.
		assertScanRun(t, got, scanWant{
			code:   exitFindings,
			stdout: []string{"MOAT-T2-004", "high", "srv", "a", "duplicate tool name"},
		})
	})

	t.Run("pin with another hash version", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		tools := []inspect.Tool{mkTool("a", "Add.")}
		if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tools})); got.code != exitOK {
			t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
		}
		breakPinHashVersion(t, e)

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tools}))

		assertScanRun(t, got, scanWant{
			code:   exitFindings,
			stdout: []string{"MOAT-T2-004", "high", "srv", "a", "pinned with another hash version"},
		})
	})
}

// breakPinHashVersion rewrites the hashes in pins.json so that they use another
// hash version. Compare then cannot check them and reports them as not
// verified. The file stays valid for Load.
func breakPinHashVersion(t *testing.T, e *pinEnv) {
	t.Helper()
	data := readFileBytes(t, e.pinsPath())
	changed := bytes.ReplaceAll(data, []byte(`"sha256-v1:`), []byte(`"sha256-v0:`))
	if bytes.Equal(data, changed) {
		t.Fatalf("pins.json has no sha256-v1 hash to change:\n%s", data)
	}
	if err := os.WriteFile(e.pinsPath(), changed, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestScanPinsPinnedServerNeverRewritten checks that a scan with a pinned and a
// new server pins only the new server, and leaves the entry of the pinned
// server as it was, even when the pinned server changed.
func TestScanPinsPinnedServerNeverRewritten(t *testing.T) {
	t.Parallel()

	servers := map[string]any{"old": map[string]any{"command": "npx"}}
	e := newPinEnv(t, servers)
	if got := e.scan(fakeServers(map[string][]inspect.Tool{"old": {mkTool("a", "Add.")}})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
	oldTools, _ := e.readPins().tools("old")

	// Add a second server to the same config file.
	e.config = writeServers(t, filepath.Dir(e.config), filepath.Base(e.config), map[string]any{
		"old": map[string]any{"command": "npx"},
		"new": map[string]any{"command": "npx"},
	})
	got := e.scan(fakeServers(map[string][]inspect.Tool{
		"old": {mkTool("a", "Add. Changed.")},
		"new": {mkTool("n", "New.")},
	}))

	assertScanRun(t, got, scanWant{
		code:   exitFindings,
		stdout: []string{"MOAT-T2-001"},
		stderr: []string{"mcpmoat scan: pinned 1 tool for new\n"},
	})
	pins := e.readPins()
	if got, _ := pins.tools("old"); !reflect.DeepEqual(got, oldTools) {
		t.Errorf("the pins of the old server changed\nbefore: %v\nafter:  %v", oldTools, got)
	}
	if _, ok := pins.tools("new"); !ok {
		t.Errorf("the new server is not pinned: %v", pins.serverNames())
	}
}

// TestScanPinsNotInspected checks that a server that was not inspected is a
// warning on stderr: no finding, no pin, and the exit code does not change.
func TestScanPinsNotInspected(t *testing.T) {
	t.Parallel()

	t.Run("failed", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := &inspecttest.Fake{Errors: map[string]error{"srv": errors.New("boom")}}

		got := e.scan(fake)

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}, stderr: []string{"warning: server srv: failed: "}})
		assertNoPinRows(t, got.stdout)
		if want := "mcpmoat scan: warning: server srv: failed: inspect: boom\n"; got.stderr != want {
			t.Errorf("stderr = %q, want %q", got.stderr, want)
		}
		// No server was inspected, so scan did not read or write pins.json.
		if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pins.json exists after a scan where no server was inspected (stat error = %v)", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))

		got := e.scan(blockingInspector{}, "--timeout", "20ms")

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}, stderr: []string{"warning: server srv: timeout: "}})
		assertNoPinRows(t, got.stdout)
		if want := "mcpmoat scan: warning: server srv: timeout: inspect: no answer within 20ms: context deadline exceeded\n"; got.stderr != want {
			t.Errorf("stderr = %q, want %q", got.stderr, want)
		}
	})

	t.Run("a pinned server that fails is an unverified finding", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})); got.code != exitOK {
			t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
		}
		before := readFileBytes(t, e.pinsPath())

		got := e.scan(&inspecttest.Fake{Errors: map[string]error{"srv": errors.New("boom")}})

		// A failing server must not avoid the rug-pull check (S3): one
		// MOAT-T2-004 high row for the server, with no tool name, and exit 1.
		// The warning stays on stderr.
		assertScanRun(t, got, scanWant{
			code:   exitFindings,
			stdout: []string{"MOAT-T2-004", "high", "srv", "pinned server could not be inspected"},
			stderr: []string{"mcpmoat scan: warning: server srv: failed: inspect: boom\n"},
		})
		out := splitPinOutput(t, got.stdout)
		if len(out.rows) != 1 || out.rows[0].rule != "MOAT-T2-004" || out.rows[0].severity != "high" || out.rows[0].server != "srv" {
			t.Errorf("pin rows = %+v, want one MOAT-T2-004 high row for srv\nstdout:\n%s", out.rows, got.stdout)
		}
		if strings.Contains(got.stdout, "Changed tool") {
			t.Errorf("stdout has a diff, want none:\n%s", got.stdout)
		}
		if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(before, after) {
			t.Errorf("pins.json changed after a failed inspection")
		}
	})

	t.Run("a pinned server that times out is an unverified finding", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})); got.code != exitOK {
			t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
		}

		got := e.scan(blockingInspector{}, "--timeout", "20ms")

		assertScanRun(t, got, scanWant{
			code:   exitFindings,
			stdout: []string{"MOAT-T2-004", "high", "srv", "pinned server could not be inspected"},
			stderr: []string{"warning: server srv: timeout: "},
		})
	})

	t.Run("an unpinned server that fails gives no finding", func(t *testing.T) {
		t.Parallel()
		// "other" is pinned, so pins.json exists. "srv" was never pinned: its
		// failure is a warning only.
		e := newPinEnv(t, map[string]any{"other": map[string]any{"command": "npx"}})
		if got := e.scan(fakeServers(map[string][]inspect.Tool{"other": {mkTool("o", "Other.")}})); got.code != exitOK {
			t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
		}
		e.config = writeServers(t, filepath.Dir(e.config), filepath.Base(e.config), map[string]any{
			"other": map[string]any{"command": "npx"},
			"srv":   map[string]any{"command": "npx"},
		})
		before := readFileBytes(t, e.pinsPath())
		fake := fakeServers(map[string][]inspect.Tool{"other": {mkTool("o", "Other.")}})
		fake.Errors = map[string]error{"srv": errors.New("boom")}

		got := e.scan(fake)

		assertScanRun(t, got, scanWant{
			code:   exitOK,
			stderr: []string{"mcpmoat scan: warning: server srv: failed: inspect: boom\n"},
		})
		assertNoPinRows(t, got.stdout)
		if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(before, after) {
			t.Errorf("pins.json changed after a failed inspection of an unpinned server")
		}
	})

	t.Run("error text is escaped", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := &inspecttest.Fake{Errors: map[string]error{"srv": errors.New("boom \x1b[31mred\x1b[0m \u202e")}}

		got := e.scan(fake)

		assertScanRun(t, got, scanWant{
			code:   exitOK,
			stderr: []string{"mcpmoat scan: warning: server srv: failed: ", `\x1b[31m`, `\u202e`},
		})
		assertTerminalSafe(t, got.stderr)
	})
}

// TestScanPinsServerNameEscaped checks that a server name with an escape
// sequence is escaped in the warning and in the pin notice.
func TestScanPinsServerNameEscaped(t *testing.T) {
	t.Parallel()

	name := "evil\x1b[31m"
	e := newPinEnv(t, map[string]any{name: map[string]any{"command": "npx"}, "ok": map[string]any{"command": "npx"}})
	fake := fakeServers(map[string][]inspect.Tool{"ok": {mkTool("a", "Add.")}})
	fake.Errors = map[string]error{name: errors.New("boom")}

	got := e.scan(fake)

	assertScanRun(t, got, scanWant{
		code:   exitOK,
		stderr: []string{`warning: server "evil\x1b[31m": failed: inspect: boom`, "pinned 1 tool for ok\n"},
	})
	assertTerminalSafe(t, got.stderr)
	assertTerminalSafe(t, got.stdout)
}

// TestScanPinsToolTextEscaped checks that a hostile tool name and description
// never put a raw control character on stdout, in the findings or in the diff.
func TestScanPinsToolTextEscaped(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	pinned := []inspect.Tool{mkTool("evil", "Add.")}
	if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": pinned})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}

	got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {
		mkTool("evil", "Add.\x1b[2J\u202e hidden \u200b"),
		mkTool("new\x1b[31mtool", "New."),
	}}))

	assertScanRun(t, got, scanWant{code: exitFindings, stdout: []string{"MOAT-T2-001", "MOAT-T2-002", `\x1b[2J`}})
	assertTerminalSafe(t, got.stdout)
	assertTerminalSafe(t, got.stderr)
}

// TestScanPinsStoreErrors checks that a pins.json that cannot be read or saved
// gives exit code 2, and that scan prints its report in both cases.
func TestScanPinsStoreErrors(t *testing.T) {
	t.Parallel()

	t.Run("corrupt pins.json", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		const corrupt = "{this is not json"
		writeTestFile(t, filepath.Join(e.xdg, "mcpmoat"), "pins.json", corrupt)
		fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})

		got := e.scan(fake)

		assertScanRun(t, got, scanWant{
			code:   exitError,
			stdout: []string{"srv"}, // the server table is still printed
			stderr: []string{"mcpmoat scan: cannot read the pins file: "},
		})
		assertNoPinRows(t, got.stdout)
		// pins.json is read before any server starts (M2).
		if calls := fake.Calls(); len(calls) != 0 {
			t.Errorf("the inspector was called for %v, want no call", calls)
		}
		// scan never replaces a bad file with an empty one.
		if after := string(readFileBytes(t, e.pinsPath())); after != corrupt {
			t.Errorf("pins.json = %q, want it unchanged (%q)", after, corrupt)
		}
	})

	t.Run("newer format version", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		const newer = `{"version": 999, "servers": []}`
		writeTestFile(t, filepath.Join(e.xdg, "mcpmoat"), "pins.json", newer)
		fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})

		got := e.scan(fake)

		assertScanRun(t, got, scanWant{
			code:   exitError,
			stderr: []string{"mcpmoat scan: cannot read the pins file: "},
		})
		if calls := fake.Calls(); len(calls) != 0 {
			t.Errorf("the inspector was called for %v, want no call", calls)
		}
		if after := string(readFileBytes(t, e.pinsPath())); after != newer {
			t.Errorf("pins.json = %q, want it unchanged (%q)", after, newer)
		}
	})

	t.Run("corrupt pins.json with --no-connect is not read", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		writeTestFile(t, filepath.Join(e.xdg, "mcpmoat"), "pins.json", "{this is not json")

		got := e.scan(nil, "--no-connect")

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}})
	})

	t.Run("save error exits 2 after the report", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		readOnlyPinsDir(t, e)

		got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}}))

		assertScanRun(t, got, scanWant{
			code:   exitError,
			stdout: []string{"srv"}, // the report is printed before the save
			stderr: []string{"mcpmoat scan: cannot save the pins file: "},
		})
		// The pin was lost, so scan must not say "pinned" (M2).
		assertContainsNone(t, "stderr", got.stderr, []string{"pinned 1 tool"})
	})
}

// ignoreFileWarning is the stderr line that scan prints when a .mcpmoat-ignore
// entry matches a pin finding but is not applied (S4).
const ignoreFileWarning = "mcpmoat scan: warning: .mcpmoat-ignore cannot ignore MOAT-T2-001; use --ignore on the command line\n"

// TestScanPinsIgnore checks that --ignore drops a pin finding and its diff,
// counts it on stderr, and changes the exit code. A .mcpmoat-ignore file never
// drops a pin finding: it can come from a cloned repository. The scan warns
// instead.
func TestScanPinsIgnore(t *testing.T) {
	t.Parallel()

	pinned := []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo.")}
	changedA := []inspect.Tool{mkTool("a", "Add. X."), mkTool("b", "Echo.")}
	changedAB := []inspect.Tool{mkTool("a", "Add. X."), mkTool("b", "Echo. Y.")}

	tests := []struct {
		name string
		// ignoreFile is the content of .mcpmoat-ignore, when not empty.
		ignoreFile string
		flags      []string
		current    []inspect.Tool
		wantCode   int
		wantRows   []pinFindingRow
		wantDiffs  []string
		wantStderr []string
		// noStderr are texts that stderr must not hold.
		noStderr []string
	}{
		{
			name:       "--ignore by rule ID drops the row and the diff",
			flags:      []string{"--ignore", "MOAT-T2-001"},
			current:    changedA,
			wantCode:   exitOK,
			wantStderr: []string{"mcpmoat scan: 1 finding ignored: MOAT-T2-001 (1)\n"},
		},
		{
			name:       "--ignore by rule ID drops every changed tool",
			flags:      []string{"--ignore", "MOAT-T2-001"},
			current:    changedAB,
			wantCode:   exitOK,
			wantStderr: []string{"mcpmoat scan: 2 findings ignored: MOAT-T2-001 (2)\n"},
		},
		{
			name:       "a rule ID that does not match changes nothing",
			flags:      []string{"--ignore", "MOAT-T2-002"},
			current:    changedA,
			wantCode:   exitFindings,
			wantRows:   []pinFindingRow{{"MOAT-T2-001", "high", "srv", "tool", "a"}},
			wantDiffs:  []string{"a"},
			wantStderr: nil,
		},
		{
			// A .mcpmoat-ignore file can come from a cloned repository, so it
			// never ignores a pin rule (S4). The scan warns once instead.
			name:       "ignore file entry for one tool does not drop it",
			ignoreFile: "MOAT-T2-001 srv/a\n",
			current:    changedAB,
			wantCode:   exitFindings,
			wantRows:   []pinFindingRow{{"MOAT-T2-001", "high", "srv", "tool", "a"}, {"MOAT-T2-001", "high", "srv", "tool", "b"}},
			wantDiffs:  []string{"a", "b"},
			wantStderr: []string{"mcpmoat scan: using 1 entry from .mcpmoat-ignore\n", ignoreFileWarning},
			noStderr:   []string{"finding ignored", "findings ignored"},
		},
		{
			name:       "ignore file entry for another tool changes nothing and gives no warning",
			ignoreFile: "MOAT-T2-001 srv/zzz\n",
			current:    changedA,
			wantCode:   exitFindings,
			wantRows:   []pinFindingRow{{"MOAT-T2-001", "high", "srv", "tool", "a"}},
			wantDiffs:  []string{"a"},
			wantStderr: []string{"mcpmoat scan: using 1 entry from .mcpmoat-ignore\n"},
			noStderr:   []string{"cannot ignore"},
		},
		{
			name:       "ignore file entry for one server does not drop it",
			ignoreFile: "MOAT-T2-001 srv\n",
			current:    changedAB,
			wantCode:   exitFindings,
			wantRows:   []pinFindingRow{{"MOAT-T2-001", "high", "srv", "tool", "a"}, {"MOAT-T2-001", "high", "srv", "tool", "b"}},
			wantDiffs:  []string{"a", "b"},
			wantStderr: []string{ignoreFileWarning},
			noStderr:   []string{"finding ignored", "findings ignored"},
		},
		{
			name:       "ignore file entry with only a rule ID does not drop a pin rule",
			ignoreFile: "MOAT-T2-001\n",
			current:    changedA,
			wantCode:   exitFindings,
			wantRows:   []pinFindingRow{{"MOAT-T2-001", "high", "srv", "tool", "a"}},
			wantDiffs:  []string{"a"},
			wantStderr: []string{ignoreFileWarning},
		},
		{
			// The user typed --ignore, so it still counts, and no warning is
			// needed: the finding is dropped.
			name:       "--ignore drops the finding although the file has an entry too",
			ignoreFile: "MOAT-T2-001 srv\n",
			flags:      []string{"--ignore", "MOAT-T2-001"},
			current:    changedAB,
			wantCode:   exitOK,
			wantStderr: []string{"mcpmoat scan: 2 findings ignored: MOAT-T2-001 (2)\n"},
			noStderr:   []string{"cannot ignore"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if tt.ignoreFile != "" {
				writeTestFile(t, e.work, rules.IgnoreFileName, tt.ignoreFile)
			}
			if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": pinned})); got.code != exitOK {
				t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
			}

			got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tt.current}), tt.flags...)

			assertScanRun(t, got, scanWant{code: tt.wantCode, stderr: tt.wantStderr})
			out := splitPinOutput(t, got.stdout)
			if !slices.Equal(out.rows, tt.wantRows) {
				t.Errorf("pin rows = %+v, want %+v\nstdout:\n%s", out.rows, tt.wantRows, got.stdout)
			}
			assertDiffsOf(t, out.diffs, "srv", tt.wantDiffs)
			assertContainsNone(t, "stderr", got.stderr, tt.noStderr)
			// The warning comes once for each rule ID, not once for each row.
			if n := strings.Count(got.stderr, "cannot ignore"); n > 1 {
				t.Errorf("stderr has the ignore file warning %d times, want at most 1\n%s", n, got.stderr)
			}
		})
	}
}

// TestScanPinsNoConnect checks that scan --no-connect never calls the
// inspector and never reads, creates or changes pins.json or its folder.
func TestScanPinsNoConnect(t *testing.T) {
	t.Parallel()

	t.Run("no pins file or folder is created", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})
		before := dirSnapshot(t, e.xdg)

		got := e.scan(fake, "--no-connect")

		assertScanRun(t, got, scanWant{code: exitOK, stdout: []string{"srv"}})
		if calls := fake.Calls(); len(calls) != 0 {
			t.Errorf("the inspector was called for %v, want no call", calls)
		}
		assertDirUnchanged(t, e.xdg, before)
		if _, err := os.Stat(filepath.Join(e.xdg, "mcpmoat")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the pins folder exists after --no-connect (stat error = %v)", err)
		}
	})

	t.Run("an existing pins file is not changed", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})); got.code != exitOK {
			t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
		}
		before := dirSnapshot(t, e.xdg)

		// A nil inspector would make a connecting scan fail with exit 2.
		got := e.scan(nil, "--no-connect")

		assertScanRun(t, got, scanWant{code: exitOK})
		assertNoPinRows(t, got.stdout)
		assertDirUnchanged(t, e.xdg, before)
	})
}

// TestScanPinsNilInspector checks that a connecting scan with no inspector is
// an execution error and not a clean scan. run always sets an inspector, so
// this is a guard against a bug in the wiring.
func TestScanPinsNilInspector(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))

	got := e.scan(nil)

	assertScanRun(t, got, scanWant{code: exitError, stderr: []string{"mcpmoat scan: cannot inspect the servers: "}})
}

// TestScanPinsSameIdentityTwice checks that a second outcome with the same
// identity gets a MOAT-T2-004 finding, and is not compared with the pins of the
// first one. Discovery cannot give two servers with one identity, so the test
// calls pinOutcomes with two outcomes.
func TestScanPinsSameIdentityTwice(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	c, _, stderr := e.cli(nil)
	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"}
	outcome := func(tools ...inspect.Tool) inspect.Outcome {
		return inspect.Outcome{Server: srv, Status: inspect.StatusOK, Result: inspect.Result{Tools: tools}}
	}

	store, ok := c.readPins("scan")
	if !ok {
		t.Fatal("readPins() = false, want true")
	}
	pr := c.pinOutcomes(store, []inspect.Outcome{
		outcome(mkTool("a", "Add.")),
		outcome(mkTool("a", "Add. Changed.")),
	}, &scanIgnores{})

	if len(pr.rows) != 1 || pr.rows[0].RuleID != "MOAT-T2-004" || pr.rows[0].Severity != "medium" || pr.rows[0].Server != "srv" {
		t.Fatalf("rows = %+v, want one MOAT-T2-004 medium row for srv", pr.rows)
	}
	if len(pr.diffs) != 0 {
		t.Errorf("diffs = %+v, want none", pr.diffs)
	}
	var out bytes.Buffer
	if err := report.WriteFindings(&out, pr.rows); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "the server is listed twice") {
		t.Errorf("findings table does not hold the reason:\n%s", out.String())
	}
	// pinOutcomes prints nothing: the notice comes after a successful save.
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	if len(pr.pinned) != 1 || pr.pinned[0].name != "srv" || pr.pinned[0].tools != 1 {
		t.Errorf("pinned = %+v, want one entry: srv with 1 tool", pr.pinned)
	}
}

// TestScanPinsNoSecretLeak checks that no env, header, URL or args value of the
// config reaches pins.json, stdout or stderr, in the first scan, in a scan with
// findings and in "pin --accept".
func TestScanPinsNoSecretLeak(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"stdio-srv": map[string]any{
			"command": "npx",
			"args":    []string{"--token", discovertest.CanaryArgs},
			"env":     map[string]string{"API_TOKEN": discovertest.CanaryEnv},
		},
		"http-srv": map[string]any{
			"type":    "http",
			"url":     "https://example.invalid/mcp?key=" + discovertest.CanaryURL,
			"headers": map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader},
		},
	}
	e := newPinEnv(t, servers)
	var outputs []string
	collect := func(r pinRunResult) {
		outputs = append(outputs, r.stdout, r.stderr)
	}

	collect(e.scan(fakeServers(map[string][]inspect.Tool{
		"stdio-srv": {mkTool("a", "Add."), mkTool("b", "Echo.")},
		"http-srv":  {mkTool("h", "Http.")},
	})))
	got := e.scan(fakeServers(map[string][]inspect.Tool{
		"stdio-srv": {mkTool("a", "Add. Changed."), mkTool("c", "New.")},
		"http-srv":  {mkTool("h", "Http.")},
	}))
	collect(got)
	if got.code != exitFindings {
		t.Fatalf("second scan: exit code = %d, want %d\n%s", got.code, exitFindings, got.stderr)
	}
	accepted := e.pin(fakeServers(map[string][]inspect.Tool{"stdio-srv": {mkTool("a", "Add. Changed.")}}), "--accept", "stdio-srv")
	collect(accepted)
	if accepted.code != exitOK {
		t.Fatalf("pin --accept: exit code = %d, want %d\n%s", accepted.code, exitOK, accepted.stderr)
	}
	collect(e.scan(fakeServers(map[string][]inspect.Tool{
		"stdio-srv": {mkTool("a", "Add. Changed.")},
		"http-srv":  {mkTool("h", "Http.")},
	})))
	outputs = append(outputs, string(readFileBytes(t, e.pinsPath())))

	for i, out := range outputs {
		discovertest.AssertNoLeak(t, "output "+string(rune('0'+i)), out)
	}
	// The key names of env and headers are not stored either: the identity
	// holds the client, the source, the project path and the name only.
	pinsText := outputs[len(outputs)-1]
	assertContainsNone(t, "pins.json", pinsText, []string{"API_TOKEN", "Authorization", "example.invalid", "--token"})
}

// TestScanPinsIgnoreFileWarningPerRule checks that the warning about a
// .mcpmoat-ignore entry that cannot ignore a pin rule comes once for each rule
// ID, in the order of the findings, and not once for each finding.
func TestScanPinsIgnoreFileWarningPerRule(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	writeTestFile(t, e.work, rules.IgnoreFileName, "MOAT-T2-001\nMOAT-T2-002\nMOAT-T2-003\n")
	pinned := []inspect.Tool{mkTool("a", "Add."), mkTool("b", "Echo."), mkTool("c", "Keep.")}
	if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": pinned})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}

	got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {
		mkTool("a", "Add. X."), mkTool("b", "Echo. Y."), mkTool("d", "New."), mkTool("e", "New too."),
	}}))

	assertScanRun(t, got, scanWant{code: exitFindings, stderr: []string{
		"mcpmoat scan: warning: .mcpmoat-ignore cannot ignore MOAT-T2-001; use --ignore on the command line\n",
		"mcpmoat scan: warning: .mcpmoat-ignore cannot ignore MOAT-T2-002; use --ignore on the command line\n",
		"mcpmoat scan: warning: .mcpmoat-ignore cannot ignore MOAT-T2-003; use --ignore on the command line\n",
	}})
	if n := strings.Count(got.stderr, "cannot ignore"); n != 3 {
		t.Errorf("stderr has %d ignore file warnings, want 3 (one for each rule ID)\n%s", n, got.stderr)
	}
	if len(splitPinOutput(t, got.stdout).rows) != 5 {
		t.Errorf("want 5 pin rows (2 changed, 2 new, 1 removed)\n%s", got.stdout)
	}
}

// TestScanPinsUnverifiedSeverity checks that a MOAT-T2-004 row is high for a
// pinned tool name and medium for a name that is not pinned, in one scan (S2).
func TestScanPinsUnverifiedSeverity(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}

	got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": {
		mkTool("a", "Add."), mkTool("a", "Add. Copy."), // pinned name
		mkTool("n", "One."), mkTool("n", "Two."), // name that is not pinned
	}}))

	assertScanRun(t, got, scanWant{code: exitFindings})
	want := []pinFindingRow{
		{"MOAT-T2-004", "high", "srv", "tool", "a"},
		{"MOAT-T2-004", "medium", "srv", "tool", "n"},
	}
	if rows := splitPinOutput(t, got.stdout).rows; !slices.Equal(rows, want) {
		t.Errorf("pin rows = %+v, want %+v\nstdout:\n%s", rows, want, got.stdout)
	}
}

// cancelingInspector cancels a context when Inspect runs and then returns what
// the fake would. It simulates a signal that arrives while a server is
// inspected.
type cancelingInspector struct {
	inner  *inspecttest.Fake
	cancel context.CancelFunc
}

func (i cancelingInspector) Inspect(ctx context.Context, s discover.Server) (inspect.Result, error) {
	i.cancel()
	return i.inner.Inspect(ctx, s)
}

// TestScanPinsInterrupted checks that a signal during the inspection (S1) gives
// exit code 2, one fixed line on stderr, no report on stdout, and no change to
// pins.json: not a new pin, and not a changed pin.
func TestScanPinsInterrupted(t *testing.T) {
	t.Parallel()

	const notice = "mcpmoat scan: interrupted; no pins were saved\n"
	tools := map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}}

	tests := []struct {
		name string
		// pinFirst makes scan pin the server before the interrupted run.
		pinFirst bool
		current  map[string][]inspect.Tool
	}{
		{name: "during the inspection of a new server", current: tools},
		{name: "during the inspection of a pinned server that changed", pinFirst: true, current: map[string][]inspect.Tool{"srv": {mkTool("a", "Add. Changed.")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if tt.pinFirst {
				if got := e.scan(fakeServers(tools)); got.code != exitOK {
					t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
				}
			}
			var pinsBefore []byte
			if tt.pinFirst {
				pinsBefore = readFileBytes(t, e.pinsPath())
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fake := fakeServers(tt.current)
			c, stdout, stderr := e.cli(cancelingInspector{inner: fake, cancel: cancel})
			c.ctx = ctx

			code := c.dispatch([]string{"scan", "--config", e.config})

			got := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
			assertScanRun(t, got, scanWant{code: exitError, stderr: []string{notice}})
			if got.stderr != notice {
				t.Errorf("stderr = %q, want only %q", got.stderr, notice)
			}
			// No report: the result would be partial.
			assertEmptyStdout(t, got.stdout)
			if tt.pinFirst {
				if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(pinsBefore, after) {
					t.Errorf("pins.json changed in an interrupted scan\nbefore: %s\nafter:  %s", pinsBefore, after)
				}
			} else if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("pins.json exists after an interrupted scan (stat error = %v), want nothing stored", err)
			}
		})
	}
}

// TestScanPinsCorruptStoreStartsNoServer checks that a pins.json that cannot be
// read stops scan before the inspector is called, for a corrupt file, a newer
// version and a pins path that is a folder (M2).
func TestScanPinsCorruptStoreStartsNoServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, e *pinEnv)
	}{
		{"corrupt file", func(t *testing.T, e *pinEnv) {
			writeTestFile(t, filepath.Dir(e.pinsPath()), "pins.json", "{this is not json")
		}},
		{"newer version", func(t *testing.T, e *pinEnv) {
			writeTestFile(t, filepath.Dir(e.pinsPath()), "pins.json", `{"version": 999, "servers": []}`)
		}},
		{"empty file", func(t *testing.T, e *pinEnv) {
			writeTestFile(t, filepath.Dir(e.pinsPath()), "pins.json", "")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			tt.setup(t, e)
			before := readFileBytes(t, e.pinsPath())
			fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})

			got := e.scan(fake)

			assertScanRun(t, got, scanWant{code: exitError, stderr: []string{"mcpmoat scan: cannot read the pins file: "}})
			if calls := fake.Calls(); len(calls) != 0 {
				t.Errorf("the inspector was called for %v, want no call", calls)
			}
			if after := readFileBytes(t, e.pinsPath()); !bytes.Equal(before, after) {
				t.Errorf("pins.json changed: %q, want %q", after, before)
			}
		})
	}
}

// TestScanPinsCanceledBeforeInspection checks that a context that ended before
// the inspection starts (a signal during discovery) still gives exit code 2,
// starts no server and writes no pins.json. The message is the discovery error,
// not the interrupted notice: discovery reports the canceled read of the config.
func TestScanPinsCanceledBeforeInspection(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	fake := fakeServers(map[string][]inspect.Tool{"srv": {mkTool("a", "Add.")}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c, stdout, stderr := e.cli(fake)
	c.ctx = ctx

	code := c.dispatch([]string{"scan", "--config", e.config})

	if code != exitError {
		t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitError, stdout, stderr)
	}
	if calls := fake.Calls(); len(calls) != 0 {
		t.Errorf("the inspector was called for %v, want no call", calls)
	}
	if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pins.json exists after a canceled scan (stat error = %v), want nothing stored", err)
	}
	if strings.Contains(stdout.String(), "MOAT-T2-") {
		t.Errorf("stdout has a pin finding:\n%s", stdout)
	}
}
