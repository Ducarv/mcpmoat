package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/pins"
)

// This file holds the helpers of the in-process pin tests (scan_pins_test.go,
// pin_test.go, pin_flow_test.go, pin_expect_test.go and pins_diff_test.go):
// the pinEnv world, the fake servers, and the checks of the output.

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

// assertNoPinsFile fails the test if pins.json exists. after names the run,
// for example "a snapshot failure".
func (e *pinEnv) assertNoPinsFile(t *testing.T, after string) {
	t.Helper()
	if _, err := os.Stat(e.pinsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pins.json exists after %s (stat error = %v), want nothing stored", after, err)
	}
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

// metaTool returns a tool like mkTool(name, "Add.") with the raw JSON _meta and
// icons given. An empty string means the field is not set.
func metaTool(name, meta, icons string) inspect.Tool {
	t := mkTool(name, "Add.")
	if meta != "" {
		t.Meta = json.RawMessage(meta)
	}
	if icons != "" {
		t.Icons = json.RawMessage(icons)
	}
	return t
}

// fakeServers returns a fake inspector that gives each server name its tools.
func fakeServers(tools map[string][]inspect.Tool) *inspecttest.Fake {
	f := &inspecttest.Fake{Results: map[string]inspect.Result{}}
	for name, ts := range tools {
		f.Results[name] = inspect.Result{ServerName: name, Tools: ts}
	}
	return f
}

// failingFake returns a fake inspector that fails for the server with the
// fixed error "boom", so a test can check the exact warning text.
func failingFake(server string) *inspecttest.Fake {
	return &inspecttest.Fake{Errors: map[string]error{server: errors.New("boom")}}
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
	for _, header := range []string{"Changed tool ", "New tool ", "Not verified tool "} {
		if strings.Contains(stdout, header) {
			t.Errorf("stdout has a diff (%q), want none:\n%s", header, stdout)
		}
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

// setPinCanonical sets the canonical text of the pinned tool in pins.json of
// e, with the matching hash, so the store still loads it. The hash is built
// like the unexported hashCanonical in internal/pins: HashVersion, a colon,
// and the lowercase hex SHA-256 of the canonical text. If that format
// changes, the store refuses the pin and the test fails.
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

// ignoreFileWarning is the stderr line that scan prints when a .mcpmoat-ignore
// entry matches a pin finding but is not applied (S4).
const ignoreFileWarning = "mcpmoat scan: warning: .mcpmoat-ignore cannot ignore MOAT-T2-001; use --ignore on the command line\n"

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

// writePinsAside simulates another mcpmoat run: it reads the pins file at path,
// sets the pins of the server id to tools and saves the file. It reports an
// error with t.Errorf and not t.Fatalf, because it can run in a goroutine of
// inspect.Run.
func writePinsAside(t *testing.T, path string, id pins.Identity, tools ...inspect.Tool) {
	t.Helper()
	store, err := pins.Load(path)
	if err != nil {
		t.Errorf("pins.Load(%q) error = %v, want nil", path, err)
		return
	}
	snap, err := pins.Snapshot(tools)
	if err != nil {
		t.Errorf("pins.Snapshot() error = %v, want nil", err)
		return
	}
	if err := store.Set(id, snap); err != nil {
		t.Errorf("Store.Set() error = %v, want nil", err)
		return
	}
	if err := store.Save(); err != nil {
		t.Errorf("Store.Save() error = %v, want nil", err)
	}
}

// digestOf returns the digest that scan and pin compute for tools. It fails the
// test when the tools cannot be pinned.
func digestOf(t *testing.T, tools ...inspect.Tool) string {
	t.Helper()
	snap, err := pins.Snapshot(tools)
	if err != nil {
		t.Fatalf("Snapshot() error = %v, want nil", err)
	}
	return pins.Digest(snap)
}

// firstScan pins tools as the first run of the server srv of e.
func firstScan(t *testing.T, e *pinEnv, tools ...inspect.Tool) {
	t.Helper()
	if got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": tools})); got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
}

// assertPinRun checks a pin run like assertScanRun does a scan run. Every
// stderr line of a usage error starts with "mcpmoat pin: ", and the usage hint
// is the one exception (it starts with "Run").
func assertPinRun(t *testing.T, r pinRunResult, want scanWant) {
	t.Helper()
	assertRun(t, pinPrefix, pinRunWithoutHint(r), want)
}

// assertNoExpectNote fails the test unless stderr is exactly the note of a
// successful pin without --expect.
func assertNoExpectNote(t *testing.T, stderr string) {
	t.Helper()
	if stderr != noExpectNote {
		t.Errorf("stderr = %q, want exactly the no --expect note %q", stderr, noExpectNote)
	}
}
