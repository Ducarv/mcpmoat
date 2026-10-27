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
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
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
// Memory (checked only without -race). The scan itself holds the 1 MiB config
// name several times (the file text, the decoded config, the server, the pin
// store, the report), the 3000 tools, and it runs 25 rules and the built-in
// rules on each tool. Those costs do not depend on the output, so they get a
// fixed budget. On top of that, writing the document may allocate at most
// maxJSONAllocFactor bytes for each byte of output (WriteJSON streams the
// document; the same idea as TestWriteJSONBoundsOutputAndMemory in
// internal/report).
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
	// The test checks the size of the output, not the time budget: a slow or
	// busy machine must not cut the rule analysis and change the row count.
	c.toolBudget = time.Hour
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
	// 512 is jsonMaxNameRunes in internal/report, which is not exported.
	maxNameChars := 512 + utf8.RuneCountInString(termsafe.CutMarker)
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

// The acceptance test of issue #213: the config findings of "scan" are capped,
// so a hostile project .mcp.json cannot make a huge report. The config checks
// add one MOAT-T4-002 finding for each env key and each header key that looks
// like a secret (secretFinding in internal/rules), so short keys in a large
// file give very many findings. scan keeps at most configRowsPerServer (100)
// config rows for each server and configRowsTotal (10,000) for the whole scan,
// plus one MOAT-T4-005 row for each server that lost rows.

// The hostile configs of TestScanJSONConfigBound.
const (
	// configFloodFileBytes is the size limit of a project .mcp.json
	// (maxProjectConfigSize in internal/discover, 4 MiB). Discovery reads a
	// file of exactly this size, so the configs fill it as far as they can.
	configFloodFileBytes = 4 << 20

	// configFloodFileBytesRace is the file size under -race. The race
	// detector makes the scan about 10 to 20 times slower (a 4 MiB file takes
	// about 15 s for each run), so the test uses a smaller file. 1 MiB still
	// gives about 28,000 keys for one server and 230 servers, far over both
	// caps.
	configFloodFileBytesRace = 1 << 20

	// configFloodNameBytes is the length of each server name. --json cuts a
	// name over 512 characters to 515 (512 and "..."), so each row holds the
	// longest name that --json writes. The bound below includes that name in
	// every row.
	configFloodNameBytes = 600

	// configFloodKeysPerServer is the number of env keys of each server in the
	// many-servers config. It is over configRowsPerServer, so each of the
	// first servers loses rows to the per-server cap. Then the scan-wide cap
	// cuts all the rows of the other servers.
	configFloodKeysPerServer = 110

	// configFloodMaxServers is the most entries that discovery accepts in one
	// file (maxServersPerFile in internal/discover). The size of the file
	// stops the many-servers config long before this.
	configFloodMaxServers = 10_000
)

// The documented bounds of TestScanJSONConfigBound. They come from a
// measurement of the configs above (Apple M1 Pro, go1.27, without -race,
// 4 MiB files). They are a regression guard: if a config cap goes away, or if
// a row grows with the number of keys again, the test fails. The numbers
// "without a cap" come from a one-off run with the cap constants raised.
//
// Row count. One server: at most configRowsPerServer (100) config rows plus one
// MOAT-T4-005 row (measured: 101). Many servers: at most configRowsTotal
// (10,000) config rows plus one MOAT-T4-005 row for each server (measured:
// 10,921 rows for 921 servers). The cap rows do not count toward the caps.
// Without the caps there is one row for each key: 111,622 for the one-server
// env config, 103,453 for the header config and 101,310 for the many-servers
// config. So the row checks fail when a cap is removed, also under -race.
//
// Output size. A JSON row holds the cut server name (515 characters), the key
// and the fixed texts of the rule: about 0.7 KiB (0.85 KiB on the terminal).
//   - One server: about 100 x 0.7 KiB, so about 70 KiB (measured: 71,690 bytes
//     for env keys and 72,104 bytes for header keys in JSON, 87,531 bytes on
//     the terminal). maxConfigFloodOneServerBytes (256 KiB) has about 3x
//     headroom. Without the per-server cap the scan-wide cap still holds, and
//     the output has 10,000 rows (measured: 6,961,811 bytes in JSON and
//     8,581,562 bytes on the terminal), so the test fails. Without both caps
//     it has 111,622 rows (measured: 77,642,284 bytes in JSON and 95,724,778
//     bytes on the terminal).
//   - Many servers: about 10,000 x 0.7 KiB for the config rows, plus 921 cap
//     rows and the server list (measured: 8,576,786 bytes in JSON and
//     9,765,244 bytes on the terminal). maxConfigFloodManyBytes (16 MiB) has
//     about 2x headroom. Without the scan-wide cap the 921 servers keep 100
//     rows each, 93,021 rows in all (measured: 65,528,535 bytes in JSON and
//     79,446,798 bytes on the terminal), so the test fails. Without both caps
//     the output is 71,235,972 bytes in JSON. Under -race the file is 1 MiB
//     (230 servers), and without the scan-wide cap the output would be about
//     23,230 x 0.7 KiB, about 16 MB, just under the bound: there the row check
//     is the guard.
//
// Memory (checked only without -race, as in TestScanJSONBound). The caps bound
// the rows, not the work before the cut: discovery decodes the whole file, and
// the config checks build one finding for each key before scan cuts them. That
// cost does not depend on the output, so it gets a fixed budget (measured:
// 202 to 251 MiB for a 4 MiB file; without both caps 762 to 1087 MiB). On top
// of that, writing the report may allocate at most maxJSONAllocFactor bytes
// for each byte of output. This check is not the guard of the caps: without
// them the larger output also raises the limit. The row and output checks
// are.
const (
	// maxConfigFloodOneServerBytes is the most bytes that stdout may hold for
	// the one-server configs (256 KiB).
	maxConfigFloodOneServerBytes = 256 << 10

	// maxConfigFloodManyBytes is the most bytes that stdout may hold for the
	// many-servers config (16 MiB).
	maxConfigFloodManyBytes = 16 << 20

	// maxConfigFloodStderrBytes is the most bytes that stderr may hold. scan
	// prints one fixed warning about the cut servers there (measured: about
	// 100 bytes).
	maxConfigFloodStderrBytes = 4 << 10

	// maxConfigFloodAllocBytes is the fixed allocation budget of the scan of
	// a 4 MiB config (384 MiB, measured 202 to 251 MiB), for a binary built
	// without -race.
	maxConfigFloodAllocBytes = 384 << 20
)

// floodEntry returns the JSON text of the env or header entry number i. Its
// key is "KEY" and i in base 36, so it is short and unique, and "key" in the
// name makes it look like a credential name. value is a canary of 8 bytes or
// more, so each entry is one MOAT-T4-002 finding (see looksLikePlaintextSecret
// in internal/rules).
func floodEntry(i int, value string) string {
	return `"KEY` + strconv.FormatInt(int64(i), 36) + `":"` + value + `"`
}

// oneServerFlood returns a project .mcp.json of at most maxBytes bytes with
// one server called name. The server has as many env keys as fit, or, when
// remote is true, it is an http server with as many header keys as fit. It
// also returns the number of keys. name must need no JSON escape.
func oneServerFlood(name string, remote bool, maxBytes int) (config string, keys int) {
	head, value := `{"command":"npx","env":{`, discovertest.CanaryEnv
	if remote {
		head = `{"type":"http","url":"https://mcp.example.invalid/mcp","headers":{`
		value = discovertest.CanaryHeader
	}
	const tail = `}}}}` // the keys, the server, mcpServers and the file
	var b strings.Builder
	b.WriteString(`{"mcpServers":{"` + name + `":` + head)
	for {
		entry := floodEntry(keys, value)
		if keys > 0 {
			entry = "," + entry
		}
		if b.Len()+len(entry)+len(tail) > maxBytes {
			break
		}
		b.WriteString(entry)
		keys++
	}
	b.WriteString(tail)
	return b.String(), keys
}

// manyServersFlood returns a project .mcp.json of at most maxBytes bytes with
// as many servers as fit. Each server has configFloodKeysPerServer env keys
// and a name of configFloodNameBytes bytes that starts with its number. It also
// returns the number of servers.
func manyServersFlood(maxBytes int) (config string, servers int) {
	const tail = `}}` // mcpServers and the file
	var b, server strings.Builder
	b.WriteString(`{"mcpServers":{`)
	for servers < configFloodMaxServers {
		server.Reset()
		if servers > 0 {
			server.WriteString(",")
		}
		name := fmt.Sprintf("S%05d", servers) + strings.Repeat("N", configFloodNameBytes-6)
		server.WriteString(`"` + name + `":{"command":"npx","env":{`)
		for k := range configFloodKeysPerServer {
			if k > 0 {
				server.WriteString(",")
			}
			server.WriteString(floodEntry(k, discovertest.CanaryEnv))
		}
		server.WriteString(`}}`)
		if b.Len()+server.Len()+len(tail) > maxBytes {
			break
		}
		b.WriteString(server.String())
		servers++
	}
	b.WriteString(tail)
	return b.String(), servers
}

// configFloodCase is one case of TestScanJSONConfigBound.
type configFloodCase struct {
	name string
	// config is the text of the project .mcp.json.
	config string
	// json is true for "scan --json" and false for the terminal report.
	json bool
	// keys is the number of secret-looking keys in config, over all servers.
	keys int
	// servers is the number of servers in config.
	servers int
	// maxKept is the most config rows that the caps keep (100 or 10,000).
	maxKept int
	// maxStdout is the documented bound of the output, in bytes.
	maxStdout int
}

// TestScanJSONConfigBound runs "mcpmoat scan --no-connect" on hostile project
// configs with very many secret-looking env and header keys, and checks that
// the config finding caps bound the rows, the output and the allocations. It
// checks the JSON output and the terminal report. See the constants for the
// numbers.
//
// The test does NOT call t.Parallel(), for the same reason as
// TestScanJSONBound: it reads runtime.MemStats.TotalAlloc.
func TestScanJSONConfigBound(t *testing.T) {
	fileBytes := configFloodFileBytes
	if raceEnabled {
		fileBytes = configFloodFileBytesRace
	}
	name := strings.Repeat("N", configFloodNameBytes)
	envConfig, envKeys := oneServerFlood(name, false, fileBytes)
	headerConfig, headerKeys := oneServerFlood(name, true, fileBytes)
	manyConfig, manyServers := manyServersFlood(fileBytes)
	manyKeys := manyServers * configFloodKeysPerServer
	// The configs must be over the caps, or the test proves nothing.
	if envKeys <= configRowsPerServer || headerKeys <= configRowsPerServer {
		t.Fatalf("one-server configs have %d env keys and %d header keys, want more than %d",
			envKeys, headerKeys, configRowsPerServer)
	}
	if manyServers*configRowsPerServer <= configRowsTotal {
		t.Fatalf("many-servers config has %d servers, want more than %d", manyServers, configRowsTotal/configRowsPerServer)
	}

	cases := []configFloodCase{
		{"one_server_env_keys/json", envConfig, true, envKeys, 1, configRowsPerServer, maxConfigFloodOneServerBytes},
		{"one_server_header_keys/json", headerConfig, true, headerKeys, 1, configRowsPerServer, maxConfigFloodOneServerBytes},
		{"many_servers/json", manyConfig, true, manyKeys, manyServers, configRowsTotal, maxConfigFloodManyBytes},
		{"one_server_env_keys/terminal", envConfig, false, envKeys, 1, configRowsPerServer, maxConfigFloodOneServerBytes},
		{"many_servers/terminal", manyConfig, false, manyKeys, manyServers, configRowsTotal, maxConfigFloodManyBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testConfigFlood(t, tc)
		})
	}
}

// testConfigFlood runs one case of TestScanJSONConfigBound.
func testConfigFlood(t *testing.T, tc configFloodCase) {
	if len(tc.config) > configFloodFileBytes {
		t.Fatalf("config = %d bytes, want at most %d: discovery would refuse it", len(tc.config), configFloodFileBytes)
	}
	home, work, xdg := t.TempDir(), t.TempDir(), t.TempDir()
	writeTestFile(t, work, ".mcp.json", tc.config)
	c, stdoutBuf, stderrBuf := dirsCLI(t, home, work)
	c.getenv = fakeGetenv(map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": home})
	args := []string{"scan", "--no-connect", "--no-color"}
	if tc.json {
		args = append(args, "--json")
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	code := c.dispatch(args)
	runtime.ReadMemStats(&after)

	stdout, stderr := stdoutBuf.String(), stderrBuf.String()
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("config = %d bytes, %d servers, %d keys; exit code = %d, stdout = %d bytes, stderr = %d bytes, alloc delta = %.1f MiB",
		len(tc.config), tc.servers, tc.keys, code, len(stdout), len(stderr), float64(alloc)/(1<<20))

	if code != exitFindings {
		t.Fatalf("exit code = %d, want %d; stderr:\n%.500s", code, exitFindings, stderr)
	}
	// No env or header value may show, in any form (NFR-07).
	discovertest.AssertNoLeak(t, "stdout", stdout, discovertest.Canaries()...)
	discovertest.AssertNoLeak(t, "stderr", stderr, discovertest.Canaries()...)

	// The rows. The cap rows do not count toward the caps, so the bound is
	// the cap plus one MOAT-T4-005 row for each server.
	if tc.json {
		checkConfigFloodJSON(t, tc, stdout)
	} else {
		// The terminal report prints the rule ID once in each row.
		kept := strings.Count(stdout, rules.RulePlaintextSecret)
		capRows := strings.Count(stdout, rules.RuleConfigFindingCap)
		t.Logf("rows = %d %s rows and %d %s rows", kept, rules.RulePlaintextSecret, capRows, rules.RuleConfigFindingCap)
		if kept != tc.maxKept {
			t.Errorf("%s rows = %d, want %d (the cap)", rules.RulePlaintextSecret, kept, tc.maxKept)
		}
		if capRows != tc.servers {
			t.Errorf("%s rows = %d, want %d (one for each server)", rules.RuleConfigFindingCap, capRows, tc.servers)
		}
	}

	// The output. Without the caps it would be far over the bound (see the
	// constants), so this check fails when a cap is removed.
	if len(stdout) > tc.maxStdout {
		t.Errorf("stdout = %d bytes, want at most %d: the config caps do not bound the output", len(stdout), tc.maxStdout)
	}
	if len(stderr) > maxConfigFloodStderrBytes {
		t.Errorf("stderr = %d bytes, want at most %d", len(stderr), maxConfigFloodStderrBytes)
	}

	// The memory: a fixed budget for the scan, and a factor of the output.
	// Under -race the regexp package allocates for each match (see
	// TestScanJSONBound), so the check would not catch a regression.
	if raceEnabled {
		t.Logf("-race: allocation check skipped (alloc delta = %.1f MiB is dominated by the race detector)",
			float64(alloc)/(1<<20))
	} else if limit := uint64(maxConfigFloodAllocBytes) + uint64(maxJSONAllocFactor)*uint64(len(stdout)); alloc > limit {
		t.Errorf("scan allocated %d bytes, want at most %d (%d bytes for the scan and %dx the %d bytes of output)",
			alloc, limit, uint64(maxConfigFloodAllocBytes), maxJSONAllocFactor, len(stdout))
	}
}

// checkConfigFloodJSON checks the rows of the --json output of one case of
// TestScanJSONConfigBound.
func checkConfigFloodJSON(t *testing.T, tc configFloodCase, stdout string) {
	t.Helper()
	// The document: valid JSON that follows the v3 schema.
	doc := decodeScanJSON(t, stdout)
	if len(doc.Servers) != tc.servers {
		t.Errorf("servers = %d, want %d", len(doc.Servers), tc.servers)
	}
	if !doc.FieldsTruncated {
		t.Error("fields_truncated = false, want true: the server names are over the cap")
	}

	var kept, capRows, omitted int
	for i, f := range doc.Findings {
		if f.RuleID != rules.RuleConfigFindingCap {
			kept++
			continue
		}
		capRows++
		// The cap row is at least high, so the exit code is 1.
		if f.Severity != "high" && f.Severity != "critical" {
			t.Errorf("findings[%d] (%s) severity = %q, want high or critical", i, f.RuleID, f.Severity)
		}
		// "N more config findings are not listed; limit M": add up N.
		var n int
		if _, err := fmt.Sscanf(f.Related, "%d more", &n); err != nil {
			t.Errorf("findings[%d] (%s) related = %q, want a count first: %v", i, f.RuleID, f.Related, err)
		}
		omitted += n
	}
	t.Logf("rows = %d: %d config rows and %d %s rows", len(doc.Findings), kept, capRows, rules.RuleConfigFindingCap)

	if limit := tc.maxKept + tc.servers; len(doc.Findings) > limit {
		t.Errorf("findings = %d rows, want at most %d (the cap %d and one %s row for each of the %d servers)",
			len(doc.Findings), limit, tc.maxKept, rules.RuleConfigFindingCap, tc.servers)
	}
	if kept != tc.maxKept {
		t.Errorf("config rows = %d, want %d (the cap)", kept, tc.maxKept)
	}
	if capRows != tc.servers {
		t.Errorf("%s rows = %d, want %d (one for each server)", rules.RuleConfigFindingCap, capRows, tc.servers)
	}
	// Every key was a finding: the kept rows and the omitted ones add up to
	// the number of keys. This shows that the config really floods the report.
	if kept+omitted != tc.keys {
		t.Errorf("kept rows %d + omitted findings %d = %d, want %d (one for each key)", kept, omitted, kept+omitted, tc.keys)
	}

	// Every server name in the document is cut to 515 characters (see
	// TestScanJSONBound).
	maxNameChars := 512 + utf8.RuneCountInString(termsafe.CutMarker)
	for i, f := range doc.Findings {
		if n := utf8.RuneCountInString(f.Server); n > maxNameChars {
			t.Errorf("findings[%d].server = %d characters, want at most %d", i, n, maxNameChars)
			break
		}
	}
}
