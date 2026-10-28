package main

// Tests of issue #227: the Key of a pin row (MOAT-T2-001 changed tool,
// MOAT-T2-002 new tool, MOAT-T2-003 removed tool) is cut like the Key of a
// tool rule row: a tool name longer than maxToolKeyRunes runes gives the first
// maxToolKeyRunes runes and termsafe.CutMarker. An empty tool name keeps the
// empty Key of a row about the whole server. The ignore list still matches
// the real tool name, never the cut Key.
//
// The checks read the rows of pinOutcomes itself, not only stdout: the diff of
// a changed or new tool holds the full name, and the --json writer cuts every
// Key again (boundReport), so an output check alone would pass without the
// cut. The scan tests then check the same rows in the --json and terminal
// output. They use a fake inspector and never call t.Setenv.

import (
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// The pin rules of the rows whose Key is a tool name.
const (
	ruleChanged = "MOAT-T2-001"
	ruleNew     = "MOAT-T2-002"
	ruleRemoved = "MOAT-T2-003"
)

// pinKeyRules are the three pin rules with a tool name in the Key, in order.
var pinKeyRules = []string{ruleChanged, ruleNew, ruleRemoved}

// pinKeyTail ends each long tool name. It comes after the cut, so it must
// never show in a Key or a "Tool:" cell.
const pinKeyTail = "ZQPINTAIL"

// pinKeyNames holds one tool name for each pin rule of pinKeyRules.
type pinKeyNames struct {
	changed, added, removed string
}

// byRule returns the tool name of the row of the pin rule ruleID.
func (n pinKeyNames) byRule(ruleID string) string {
	switch ruleID {
	case ruleChanged:
		return n.changed
	case ruleNew:
		return n.added
	default:
		return n.removed
	}
}

// longPinKeyNames returns three names of about size bytes each: a one-letter
// prefix, then the rune fill, then pinKeyTail. The prefixes keep the names
// apart, and they sort in the order of pinKeyRules.
func longPinKeyNames(fill string, size int) pinKeyNames {
	body := strings.Repeat(fill, (size-len(pinKeyTail))/len(fill)) + pinKeyTail
	return pinKeyNames{changed: "c" + body, added: "n" + body, removed: "r" + body}
}

// runePinKeyNames returns three names of exactly runes runes: a one-letter
// prefix, then the letter "x". The ignore tests use them: an ignore line has at
// most 4096 bytes, so the name must be short enough for one line.
func runePinKeyNames(runes int) pinKeyNames {
	body := strings.Repeat("x", runes-1)
	return pinKeyNames{changed: "c" + body, added: "n" + body, removed: "r" + body}
}

// pinKeyTools returns the pinned tools and the current tools of a server that
// gives one row of each rule of pinKeyRules: names.changed has another
// description, names.added is new and names.removed is gone. The tool "keep"
// is in both lists.
func pinKeyTools(names pinKeyNames) (pinned, current []inspect.Tool) {
	keep := mkTool("keep", "Keep.")
	pinned = []inspect.Tool{keep, mkTool(names.changed, "Old text."), mkTool(names.removed, "Gone soon.")}
	current = []inspect.Tool{keep, mkTool(names.changed, "New text."), mkTool(names.added, "Added.")}
	return pinned, current
}

// wantCutKey returns the Key that a pin row must have for a name longer than
// maxToolKeyRunes runes: its first maxToolKeyRunes runes and
// termsafe.CutMarker. It fails the test when name is not that long.
func wantCutKey(t *testing.T, name string) string {
	t.Helper()
	short, cut := termsafe.Cut(name, maxToolKeyRunes)
	if !cut {
		t.Fatalf("name of %d runes is not longer than %d", utf8.RuneCountInString(name), maxToolKeyRunes)
	}
	return short + termsafe.CutMarker
}

// pinKeyServer returns the server of the direct pinOutcomes tests. Its config
// path is absolute, so the pinner compares its tools with the pins.
func pinKeyServer(t *testing.T) discover.Server {
	t.Helper()
	return discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: filepath.Join(t.TempDir(), "mcp.json")}
}

// pinKeyOutcomes runs pinOutcomes for the server srv, pinned with pinned,
// that now has the tools current, with the ignore lists ign. The store is a
// new store in t.TempDir() and is never saved.
func pinKeyOutcomes(t *testing.T, srv discover.Server, pinned, current []inspect.Tool, ign *scanIgnores) pinReport {
	t.Helper()
	store := newPinsStore(t, filepath.Join(t.TempDir(), "mcpmoat", "pins.json"))
	if err := store.Set(serverIdentity(srv), snapshotOf(t, pinned...)); err != nil {
		t.Fatalf("Store.Set() error = %v, want nil", err)
	}
	c, _, _ := newTestCLI(fakeGetenv(nil), testBuild)
	return c.pinOutcomes(store, []inspect.Outcome{{Server: srv, Status: inspect.StatusOK, Result: inspect.Result{Tools: current}}}, ign)
}

// rowsByRule returns the rows of rows by rule ID. It fails the test when a
// rule has more than one row.
func rowsByRule(t *testing.T, rows []report.FindingRow) map[string]report.FindingRow {
	t.Helper()
	out := make(map[string]report.FindingRow, len(rows))
	for _, r := range rows {
		if _, dup := out[r.RuleID]; dup {
			t.Fatalf("pinOutcomes gave two %s rows, want one", r.RuleID)
		}
		out[r.RuleID] = r
	}
	return out
}

// TestPinKey checks pinKey, the Key of a pin row: an empty name stays empty
// (a row about the whole server, not noToolNameKey), a name of up to
// maxToolKeyRunes runes stays as it is, and a longer one is cut to
// maxToolKeyRunes runes (not bytes) and termsafe.CutMarker.
func TestPinKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, tool, want string
	}{
		{"empty", "", ""},
		{"short", "read_file", "read_file"},
		{"at the cap", strings.Repeat("a", maxToolKeyRunes), strings.Repeat("a", maxToolKeyRunes)},
		{"one over the cap", strings.Repeat("a", maxToolKeyRunes+1), strings.Repeat("a", maxToolKeyRunes) + termsafe.CutMarker},
		{"multi-byte at the cap", strings.Repeat("é", maxToolKeyRunes), strings.Repeat("é", maxToolKeyRunes)},
		{"multi-byte over the cap", strings.Repeat("é", maxToolKeyRunes+5), strings.Repeat("é", maxToolKeyRunes) + termsafe.CutMarker},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pinKey(tt.tool); got != tt.want {
				t.Errorf("pinKey(%d runes) = %d runes %.20q..., want %d runes %.20q...",
					utf8.RuneCountInString(tt.tool), utf8.RuneCountInString(got), got, utf8.RuneCountInString(tt.want), tt.want)
			}
		})
	}
}

// TestPinKeyLongToolNameRows checks the rows of pinOutcomes for a 100 KiB
// tool name of each pin rule: the Key has maxToolKeyRunes runes and
// termsafe.CutMarker (515 runes), and Related stays empty. The multi-byte
// name has two bytes in each rune, so a cut that counts bytes gives a Key of
// the wrong length.
func TestPinKeyLongToolNameRows(t *testing.T) {
	t.Parallel()

	for _, fill := range []string{"n", "é"} {
		t.Run(fill, func(t *testing.T) {
			t.Parallel()
			names := longPinKeyNames(fill, 100<<10)
			pinned, current := pinKeyTools(names)

			pr := pinKeyOutcomes(t, pinKeyServer(t), pinned, current, &scanIgnores{})

			rows := rowsByRule(t, pr.rows)
			if len(rows) != len(pinKeyRules) {
				t.Fatalf("pinOutcomes gave rows for %d rules, want %d (%v)", len(rows), len(pinKeyRules), pinKeyRules)
			}
			wantRunes := maxToolKeyRunes + utf8.RuneCountInString(termsafe.CutMarker)
			for _, id := range pinKeyRules {
				row, ok := rows[id]
				if !ok {
					t.Errorf("pinOutcomes gave no %s row", id)
					continue
				}
				want := wantCutKey(t, names.byRule(id))
				if row.Key != want {
					t.Errorf("%s Key = %d bytes, %d runes, want the cut name of %d runes ending with %q",
						id, len(row.Key), utf8.RuneCountInString(row.Key), wantRunes, termsafe.CutMarker)
				}
				if n := utf8.RuneCountInString(row.Key); n != wantRunes {
					t.Errorf("%s Key has %d runes, want %d", id, n, wantRunes)
				}
				if strings.Contains(row.Key, pinKeyTail) {
					t.Errorf("%s Key holds the end of the tool name", id)
				}
				if row.Related != "" || row.Field != rules.FieldTool || row.Name != "srv" {
					t.Errorf("%s Related = %q, Field = %q, Name = %q; want \"\", %q, \"srv\"", id, row.Related, row.Field, row.Name, rules.FieldTool)
				}
			}
		})
	}
}

// TestPinKeyIgnoreRealName checks that the ignore list of the pin rows
// matches the real tool name, not the cut Key. The names have 600 runes:
// longer than maxToolKeyRunes, and short enough for one line of the ignore
// format (4096 bytes at most). The list comes from rules.ParseIgnore, so the
// entry is the one a user would write. An entry for the real name drops the
// row of its rule only, and counts it. An entry for the cut Key, or for the
// first maxToolKeyRunes runes of the name, drops nothing.
//
// Only --ignore (the flags list) drops a pin row (see scanIgnores), and the
// flag takes a rule ID only. So the test gives the parsed list to pinOutcomes
// as both lists. TestScanPinKeyIgnoreFile checks the real name through the
// CLI.
func TestPinKeyIgnoreRealName(t *testing.T) {
	t.Parallel()

	names := runePinKeyNames(600)
	entries := []struct {
		name string
		// tool returns the tool part of the entry for the tool name.
		tool func(t *testing.T, name string) string
		drop bool
	}{
		{"real name", func(_ *testing.T, name string) string { return name }, true},
		{"cut key", wantCutKey, false},
		{"first runes of the name", func(_ *testing.T, name string) string {
			short, _ := termsafe.Cut(name, maxToolKeyRunes)
			return short
		}, false},
	}
	for _, rule := range pinKeyRules {
		for _, entry := range entries {
			t.Run(rule+"/"+entry.name, func(t *testing.T) {
				t.Parallel()
				line := rule + " srv/" + entry.tool(t, names.byRule(rule)) + "\n"
				list, warnings := rules.ParseIgnore([]byte(line))
				if len(warnings) != 0 || list.Len() != 1 {
					t.Fatalf("ParseIgnore(line of %d bytes) = %d entries, warnings %v; want 1 entry and no warning", len(line), list.Len(), warnings)
				}
				pinned, current := pinKeyTools(names)

				pr := pinKeyOutcomes(t, pinKeyServer(t), pinned, current, &scanIgnores{all: list, flags: list})

				rows := rowsByRule(t, pr.rows)
				for _, id := range pinKeyRules {
					_, kept := rows[id]
					if wantKept := id != rule || !entry.drop; kept != wantKept {
						t.Errorf("%s row kept = %v, want %v", id, kept, wantKept)
					}
				}
				var want map[string]int
				if entry.drop {
					want = map[string]int{rule: 1}
				}
				// maps.Equal treats a nil map and an empty map as equal.
				if !maps.Equal(pr.ignored, want) {
					t.Errorf("ignored = %v, want %v", pr.ignored, want)
				}
			})
		}
	}
}

// TestPinKeyEmptyName checks that a pin row about a tool with an empty name,
// and a row about a whole server, keep the empty Key: the report then shows
// the reason on a "Reason:" line and not a "Tool:" line. pins.Compare reports
// an empty name as a MOAT-T2-004 row with pins.ReasonEmptyName, and a pinned
// server that could not be inspected gives a MOAT-T2-004 row with
// reasonNotInspected.
func TestPinKeyEmptyName(t *testing.T) {
	t.Parallel()

	t.Run("empty tool name", func(t *testing.T) {
		t.Parallel()
		keep := mkTool("keep", "Keep.")

		pr := pinKeyOutcomes(t, pinKeyServer(t), []inspect.Tool{keep}, []inspect.Tool{keep, mkTool("", "No name.")}, &scanIgnores{})

		rows := rowsByRule(t, pr.rows)
		row, ok := rows["MOAT-T2-004"]
		if !ok || len(rows) != 1 {
			t.Fatalf("rows = %+v, want one MOAT-T2-004 row", pr.rows)
		}
		if row.Key != "" || row.Related != pins.ReasonEmptyName {
			t.Errorf("MOAT-T2-004 Key = %q, Related = %q; want \"\", %q", row.Key, row.Related, pins.ReasonEmptyName)
		}
	})

	t.Run("pinned server not inspected", func(t *testing.T) {
		t.Parallel()
		srv := pinKeyServer(t)
		store := newPinsStore(t, filepath.Join(t.TempDir(), "mcpmoat", "pins.json"))
		if err := store.Set(serverIdentity(srv), snapshotOf(t, mkTool("keep", "Keep."))); err != nil {
			t.Fatal(err)
		}
		c, _, _ := newTestCLI(fakeGetenv(nil), testBuild)

		pr := c.pinOutcomes(store, []inspect.Outcome{{Server: srv, Status: inspect.StatusFailed, Err: errors.New("boom")}}, &scanIgnores{})

		if len(pr.rows) != 1 || pr.rows[0].RuleID != "MOAT-T2-004" {
			t.Fatalf("rows = %+v, want one MOAT-T2-004 row", pr.rows)
		}
		if row := pr.rows[0]; row.Key != "" || row.Related != reasonNotInspected {
			t.Errorf("MOAT-T2-004 Key = %q, Related = %q; want \"\", %q", row.Key, row.Related, reasonNotInspected)
		}
	})
}

// wantToolCell returns the "Tool:" cell that the terminal report prints for
// the Key key of a pin row (which has no Related): the first
// report.MaxShortCellRunes runes, escaped by termsafe (and quoted when they
// hold a space or an unsafe rune), then termsafe.CutMarker. key must be
// longer than the cap.
func wantToolCell(key string) string {
	short, _ := termsafe.Cut(key, report.MaxShortCellRunes)
	return termsafe.QuoteIf(short, strings.Contains(short, " ")) + termsafe.CutMarker
}

// TestScanPinKeyLongToolName checks the three pin rows of a scan whose tools
// have 100 KiB names, in the --json and the terminal report. The --json key
// of each row is the cut Key (515 runes). The terminal "Tool:" cell is cut
// again to report.MaxShortCellRunes runes. Neither report shows the end of a
// name in a finding.
func TestScanPinKeyLongToolName(t *testing.T) {
	t.Parallel()

	names := longPinKeyNames("n", 100<<10)
	pinned, current := pinKeyTools(names)
	e := newPinEnv(t, oneServer("srv"))
	firstScan(t, e, pinned...)
	insp := fakeServers(map[string][]inspect.Tool{"srv": current})

	text := e.scan(insp)
	jsonRun := e.scan(insp, "--json")

	// A changed tool is high, so both runs exit with 1.
	if text.code != exitFindings || jsonRun.code != exitFindings {
		t.Errorf("exit codes = %d (terminal), %d (json), want %d\nstderr:\n%.2000s\n%.2000s", text.code, jsonRun.code, exitFindings, text.stderr, jsonRun.stderr)
	}
	assertNoEscape(t, text.stdout, text.stderr)
	assertNoEscape(t, jsonRun.stdout, jsonRun.stderr)

	wantRunes := maxToolKeyRunes + utf8.RuneCountInString(termsafe.CutMarker)
	findings := jsonFindings(t, jsonRun.stdout)
	for _, id := range pinKeyRules {
		rows := jsonRowsOf(findings, id)
		want := wantCutKey(t, names.byRule(id))
		if len(rows) != 1 || rows[0].Key != want || rows[0].Server != "srv" || rows[0].Related != "" {
			t.Errorf("JSON %s rows have keys of %v bytes, want one row of srv with a key of %d bytes", id, keyLens(rows), len(want))
			continue
		}
		if n := utf8.RuneCountInString(rows[0].Key); n > wantRunes {
			t.Errorf("JSON %s key has %d runes, want at most %d", id, n, wantRunes)
		}
	}
	for _, f := range findings {
		if strings.Contains(f.Key, pinKeyTail) {
			t.Errorf("JSON %s key holds the end of the tool name", f.RuleID)
		}
	}

	textRows := 0
	for _, f := range parseFindings(t, text.stdout) {
		if !slices.Contains(pinKeyRules, f.RuleID) {
			continue
		}
		textRows++
		want := wantToolCell(wantCutKey(t, names.byRule(f.RuleID)))
		if f.Tool != want {
			t.Errorf("terminal %s Tool cell = %d runes %.40q..., want %d runes %.40q...",
				f.RuleID, utf8.RuneCountInString(f.Tool), f.Tool, utf8.RuneCountInString(want), want)
		}
		if n, limit := utf8.RuneCountInString(f.Tool), report.MaxShortCellRunes+utf8.RuneCountInString(termsafe.CutMarker); n > limit {
			t.Errorf("terminal %s Tool cell has %d runes, want at most %d", f.RuleID, n, limit)
		}
	}
	if textRows != len(pinKeyRules) {
		t.Errorf("terminal pin rows = %d, want %d", textRows, len(pinKeyRules))
	}
	if block := splitScanSections(text.stdout).Findings; strings.Contains(block, pinKeyTail) {
		t.Error("the terminal FINDINGS block holds the end of a tool name")
	}
}

// TestScanPinKeyHostileName checks a new tool whose name of 600 runes starts
// with terminal escapes and control characters. The --json key is the cut Key
// with the raw characters, which the JSON encoder escapes, and the terminal
// "Tool:" cell is the termsafe form of the cut name. No output holds a raw
// ESC byte.
func TestScanPinKeyHostileName(t *testing.T) {
	t.Parallel()

	name := "\x1b[2J\x1b]0;pwn\x07\r\u202e" + strings.Repeat("x", 600)
	keep := mkTool("keep", "Keep.")
	e := newPinEnv(t, oneServer("srv"))
	firstScan(t, e, keep)
	insp := fakeServers(map[string][]inspect.Tool{"srv": {keep, mkTool(name, "Added.")}})

	text := e.scan(insp)
	jsonRun := e.scan(insp, "--json")

	assertNoEscape(t, text.stdout, text.stderr)
	assertNoEscape(t, jsonRun.stdout, jsonRun.stderr)
	key := wantCutKey(t, name)

	var jsonRows int
	for _, f := range decodeScanJSON(t, jsonRun.stdout).Findings {
		if !strings.HasPrefix(f.RuleID, "MOAT-T2-") {
			continue
		}
		jsonRows++
		if f.RuleID != ruleNew {
			t.Errorf("JSON pin row has the rule %s, want %s", f.RuleID, ruleNew)
		}
		if f.Key != key {
			t.Errorf("JSON %s key = %.40q... (%d runes), want %.40q... (%d runes)",
				f.RuleID, f.Key, utf8.RuneCountInString(f.Key), key, utf8.RuneCountInString(key))
		}
	}
	if jsonRows != 1 {
		t.Errorf("JSON pin rows = %d, want 1", jsonRows)
	}

	var textRows int
	for _, f := range parseFindings(t, text.stdout) {
		if !strings.HasPrefix(f.RuleID, "MOAT-T2-") {
			continue
		}
		textRows++
		if f.RuleID != ruleNew {
			t.Errorf("terminal pin row has the rule %s, want %s", f.RuleID, ruleNew)
		}
		if want := wantToolCell(key); f.Tool != want {
			t.Errorf("terminal %s Tool cell = %q, want %q", f.RuleID, f.Tool, want)
		}
	}
	if textRows != 1 {
		t.Errorf("terminal pin rows = %d, want 1", textRows)
	}
}

// TestScanPinKeyIgnoreFile checks the ignore match of the pin rows through
// the CLI. A .mcpmoat-ignore file cannot drop a pin row (see scanIgnores), so
// the rows stay, and the sign of a match is the warning that the file cannot
// ignore the rule (fileCannotIgnoreWarning). Entries for the real names of
// 600 runes match, one warning for each rule. Entries for the cut Keys match
// nothing.
func TestScanPinKeyIgnoreFile(t *testing.T) {
	t.Parallel()

	names := runePinKeyNames(600)
	for _, tt := range []struct {
		name  string
		match bool
	}{
		{"real names", true},
		{"cut keys", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pinned, current := pinKeyTools(names)
			e := newPinEnv(t, oneServer("srv"))
			firstScan(t, e, pinned...)
			var file strings.Builder
			for _, id := range pinKeyRules {
				tool := names.byRule(id)
				if !tt.match {
					tool = wantCutKey(t, tool)
				}
				file.WriteString(id + " srv/" + tool + "\n")
			}
			writeTestFile(t, e.work, rules.IgnoreFileName, file.String())

			got := e.scan(fakeServers(map[string][]inspect.Tool{"srv": current}), "--json", "--use-ignore-file")

			if got.code != exitFindings {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", got.code, exitFindings, got.stderr)
			}
			findings := jsonFindings(t, got.stdout)
			for _, id := range pinKeyRules {
				rows := jsonRowsOf(findings, id)
				if want := wantCutKey(t, names.byRule(id)); len(rows) != 1 || rows[0].Key != want {
					t.Errorf("JSON %s rows have keys of %v bytes, want one row with the cut key of %d bytes", id, keyLens(rows), len(want))
				}
				warning := fileCannotIgnoreWarning(id) + "\n"
				wantWarnings := 0
				if tt.match {
					wantWarnings = 1
				}
				if n := strings.Count(got.stderr, warning); n != wantWarnings {
					t.Errorf("stderr has the warning for %s %d times, want %d\nstderr:\n%s", id, n, wantWarnings, got.stderr)
				}
			}
			if !strings.Contains(got.stderr, scanPrefix+"using 3 entries from "+rules.IgnoreFileName+"\n") {
				t.Errorf("stderr has no line about the 3 entries of %s\nstderr:\n%s", rules.IgnoreFileName, got.stderr)
			}
		})
	}
}
