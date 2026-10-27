package main

// The acceptance test of issue #170 (FR-15): "scan --json" keeps its output
// size and its peak memory under a documented bound for a hostile config. The
// test runs the whole in-process scan (discovery, inspection with a fake
// inspector, the tool rules, the row cap, the pins and WriteJSON), not only
// WriteJSON. TestWriteJSONBoundsOutputAndMemory in internal/report does the
// same for WriteJSON alone.

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// The hostile config of TestScanJSONBound: one server in a project .mcp.json
// whose name is hostileNameBytes long, that lists hostileTools tools, and
// hostileRuleCount description rules that match every description. Each tool
// hits every rule, so the server has about hostileTools x hostileRuleCount
// tool findings before the cap.
const (
	// hostileNameBytes is 1 MiB. A project file may hold 4 MiB, and the name
	// sits in the file once, so the file is a little over 1 MiB.
	hostileNameBytes = 1 << 20
	hostileTools     = 3000
	hostileRuleCount = 25

	// hostileToolsRace is the tool count under -race. The race detector makes
	// the rule step slow, so the test uses fewer tools. 300 tools x 25 rules
	// give 7500 findings, far over the cap of maxToolRowsPerServer, so the cap
	// path (the MOAT-T1-024 row) is still tested.
	hostileToolsRace = 300
)

// The documented bounds of TestScanJSONBound. They come from a measurement of
// this hostile config, and each has about 2x headroom. They are a regression
// guard: if the output or the allocations grow with the length of the name or
// with the number of findings again, the test fails.
//
// Output size. A server keeps at most maxToolRowsPerServer (1000) tool rows,
// and scan adds one MOAT-T1-024 row for the rest. A row holds the server name
// (cut to 515 characters), the tool name and fixed text, so one row is about
// 0.7 KiB and the document is about 1000 x 0.7 KiB = 0.7 MiB (measured:
// 711,753 bytes, with the same bytes with and without -race). The old v2
// output had no cut: each row held the 1 MiB name once (in "server"; the key is
// the tool name and "related" is "description"), so the same 1002 rows would be
// about 1.05 GB, about 1,500 times the bounded output. Without the row cap, it
// would be 3000 tools x 25 rules x 1 MiB, about 75 GB.
//
// Row count. At most maxToolRowsPerServer tool rows, plus one MOAT-T1-024 row,
// plus the pin and other rows of the server: toolRowSlack is the room for those
// rows (measured: 1002 rows).
//
// Memory (checked only without -race). The scan itself holds the 1 MiB config name several times (the file
// text, the decoded config, the server, the pin store, the report), the 3000
// tools, and it runs 25 rules and the built-in rules on each tool. Those costs
// do not depend on the output, so they get a fixed budget. On top of that,
// writing the document may allocate at most maxJSONAllocFactor bytes for each
// byte of output (WriteJSON streams the document; the same idea as
// TestWriteJSONBoundsOutputAndMemory in internal/report).
//
// Under -race the test skips the allocation check. The Go regexp package
// allocates a matcher state for each match when it is built with -race (the
// sync.Pool of the matchers drops values on purpose), so the allocations of the
// rule step are dominated by the race detector and not by the output. A budget
// that fits that cost (several GiB) could not catch a regression, so it would
// only give a false sense of a guard. Under -race the test still checks the
// output size, the row count and the structure. Measured without -race: about
// 65 MiB.
const (
	// maxJSONOutputBytes is the most bytes that stdout may hold (1.5 MiB). The
	// measured output is 0.7 MiB.
	maxJSONOutputBytes = 3 << 19

	// toolRowSlack is the number of rows over maxToolRowsPerServer that the
	// document may hold: the MOAT-T1-024 row and the other rows of the server.
	toolRowSlack = 10

	// maxJSONAllocFactor is the most bytes that the output may cost in
	// allocations, for each byte of output, on top of the fixed budget.
	maxJSONAllocFactor = 8

	// maxScanAllocBytes is the fixed allocation budget of the scan itself
	// (128 MiB, measured about 65 MiB), for a binary built without -race.
	maxScanAllocBytes = 128 << 20
)

// hostileRulesDirMatchAll writes hostileRuleCount description rules that match
// every description with a letter in a new folder and returns it.
func hostileRulesDirMatchAll(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for i := 1; i <= hostileRuleCount; i++ {
		id := fmt.Sprintf("MOAT-X-%03d", i)
		writeTestFile(t, dir, id+".yaml", fmt.Sprintf(
			"id: %s\ntitle: Fixture rule that matches every description\nseverity: low\ntarget: description\n"+
				"match:\n  any_regex:\n    - '\\pL'\n"+
				"risk: Fixture.\nremediation: Fixture.\n"+
				"should_match:\n  - 'Reads a file.'\nshould_not_match:\n  - '12345'\n", id))
	}
	return dir
}

// TestScanJSONBound runs "mcpmoat scan --json" on a hostile config and checks
// that the output and the allocations stay under the bounds above. See the
// constants for the numbers.
//
// The test does NOT call t.Parallel(). It reads runtime.MemStats.TotalAlloc,
// which counts the allocations of the whole process, and parallel tests that
// allocate at the same time would skew the delta. A test that is not parallel
// runs alone, before the parallel ones resume.
func TestScanJSONBound(t *testing.T) {
	home, work := t.TempDir(), t.TempDir()
	xdg := t.TempDir()
	name := strings.Repeat("N", hostileNameBytes)
	writeServers(t, work, ".mcp.json", map[string]any{name: map[string]any{"command": "npx"}})

	toolCount := hostileTools
	if raceEnabled {
		toolCount = hostileToolsRace
	}
	tools := make([]inspect.Tool, toolCount)
	for i := range tools {
		tools[i] = mkTool(fmt.Sprintf("tool_%05d", i), "Reads a file.")
	}
	insp := fakeServers(map[string][]inspect.Tool{name: tools})

	c, stdoutBuf, stderrBuf := dirsCLI(t, home, work)
	c.getenv = fakeGetenv(map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": home})
	c.inspector = insp
	args := []string{"scan", "--json", "--rules", hostileRulesDirMatchAll(t)}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	code := c.dispatch(args)
	runtime.ReadMemStats(&after)

	stdout, stderr := stdoutBuf.String(), stderrBuf.String()
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("exit code = %d, output = %d bytes, alloc delta = %d bytes (%.1f MiB), stderr = %d bytes",
		code, len(stdout), alloc, float64(alloc)/(1<<20), len(stderr))

	if code != exitFindings {
		t.Fatalf("exit code = %d, want %d; stderr:\n%.500s", code, exitFindings, stderr)
	}

	// The document: valid JSON that follows the v3 schema (maxLength of every
	// name and path included).
	doc := decodeScanJSON(t, stdout)

	if len(stdout) > maxJSONOutputBytes {
		t.Errorf("output = %d bytes, want at most %d: the cut and the row cap do not bound the output",
			len(stdout), maxJSONOutputBytes)
	}
	// Each row of the old, unbounded output held the name once, in "server", and
	// the bound must be far under that.
	if unbounded := hostileNameBytes * maxToolRowsPerServer; len(stdout) >= unbounded/100 {
		t.Errorf("output = %d bytes, too close to the unbounded size %d", len(stdout), unbounded)
	}
	if limit := maxToolRowsPerServer + toolRowSlack; len(doc.Findings) > limit {
		t.Errorf("findings = %d rows, want at most %d (the row cap and %d other rows)",
			len(doc.Findings), limit, toolRowSlack)
	}
	if !doc.FieldsTruncated {
		t.Error("fields_truncated = false, want true: the server name is over the cap")
	}

	// The cap row is there, so the reader knows that the list is short, and it
	// is at least high, so the exit code is 1.
	var capRows int
	for _, f := range doc.Findings {
		if f.RuleID != rules.RuleToolFindingCap {
			continue
		}
		capRows++
		if f.Severity != "high" && f.Severity != "critical" {
			t.Errorf("%s severity = %q, want high or critical", f.RuleID, f.Severity)
		}
	}
	if capRows != 1 {
		t.Errorf("%s rows = %d, want 1", rules.RuleToolFindingCap, capRows)
	}

	// Every server name in the document is cut: 512 characters, then "...".
	const maxNameChars = 515
	if len(doc.Servers) != 1 {
		t.Fatalf("servers = %d, want 1", len(doc.Servers))
	}
	if n := utf8.RuneCountInString(doc.Servers[0].Name); n > maxNameChars {
		t.Errorf("servers[0].name = %d characters, want at most %d", n, maxNameChars)
	}
	for i, f := range doc.Findings {
		if n := utf8.RuneCountInString(f.Server); n > maxNameChars {
			t.Errorf("findings[%d].server = %d characters, want at most %d", i, n, maxNameChars)
			break
		}
	}

	// The memory: a fixed budget for the scan, and a factor of the output.
	// Under -race the allocations are dominated by the race detector (see the
	// constants), so the check would not catch a regression.
	if raceEnabled {
		t.Logf("-race: allocation check skipped (alloc delta = %.1f MiB is dominated by the race detector)",
			float64(alloc)/(1<<20))
	} else if limit := uint64(maxScanAllocBytes) + uint64(maxJSONAllocFactor)*uint64(len(stdout)); alloc > limit {
		t.Errorf("scan allocated %d bytes, want at most %d (%d bytes for the scan and %dx the %d bytes of output)",
			alloc, limit, uint64(maxScanAllocBytes), maxJSONAllocFactor, len(stdout))
	}

	// What the old output would have held: the name once in each row, for the
	// same number of rows.
	t.Logf("rows = %d, v2 output without the cut = about %d bytes", len(doc.Findings), hostileNameBytes*len(doc.Findings))
}
