package report

// This file is in package report, not report_test, because boundReport is not
// exported. A test in package report cannot import reporttest (reporttest
// imports report, which would be an import cycle), so the schema check of the
// hostile report is in json_schema_test.go (package report_test).

import (
	"bytes"
	"encoding/json"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// boundField describes one text field that boundReport cuts: its cap, a way to
// set it on a report that holds one element of each list, and a way to read it.
type boundField struct {
	name  string
	limit int
	set   func(r *ScanReport, v string)
	get   func(r ScanReport) string
}

// oneOfEach returns a report with one element in each list, so every field of
// boundField can be set and read.
func oneOfEach() ScanReport {
	return ScanReport{
		Servers:  make([]JSONServer, 1),
		Findings: make([]JSONFinding, 1),
		Diffs:    make([]JSONDiff, 1),
		Errors:   make([]JSONFileError, 1),
	}
}

// boundFields lists every field that boundReport cuts (see its doc comment).
func boundFields() []boundField {
	return []boundField{
		{"JSONServer.Name", MaxJSONNameRunes,
			func(r *ScanReport, v string) { r.Servers[0].Name = v },
			func(r ScanReport) string { return r.Servers[0].Name }},
		{"JSONFinding.Server", MaxJSONNameRunes,
			func(r *ScanReport, v string) { r.Findings[0].Server = v },
			func(r ScanReport) string { return r.Findings[0].Server }},
		{"JSONFinding.Key", MaxJSONNameRunes,
			func(r *ScanReport, v string) { r.Findings[0].Key = v },
			func(r ScanReport) string { return r.Findings[0].Key }},
		{"JSONFinding.Related", MaxJSONNameRunes,
			func(r *ScanReport, v string) { r.Findings[0].Related = v },
			func(r ScanReport) string { return r.Findings[0].Related }},
		{"JSONDiff.Server", MaxJSONNameRunes,
			func(r *ScanReport, v string) { r.Diffs[0].Server = v },
			func(r ScanReport) string { return r.Diffs[0].Server }},
		{"JSONDiff.Tool", MaxJSONNameRunes,
			func(r *ScanReport, v string) { r.Diffs[0].Tool = v },
			func(r ScanReport) string { return r.Diffs[0].Tool }},
		{"JSONFileError.Server", MaxJSONNameRunes,
			func(r *ScanReport, v string) { r.Errors[0].Server = v },
			func(r ScanReport) string { return r.Errors[0].Server }},
		{"JSONServer.Source", jsonMaxPathRunes,
			func(r *ScanReport, v string) { r.Servers[0].Source = v },
			func(r ScanReport) string { return r.Servers[0].Source }},
		{"JSONServer.ProjectPath", jsonMaxPathRunes,
			func(r *ScanReport, v string) { r.Servers[0].ProjectPath = v },
			func(r ScanReport) string { return r.Servers[0].ProjectPath }},
		{"JSONFileError.Path", jsonMaxPathRunes,
			func(r *ScanReport, v string) { r.Errors[0].Path = v },
			func(r ScanReport) string { return r.Errors[0].Path }},
		{"JSONFileError.ProjectPath", jsonMaxPathRunes,
			func(r *ScanReport, v string) { r.Errors[0].ProjectPath = v },
			func(r ScanReport) string { return r.Errors[0].ProjectPath }},
	}
}

func TestBoundReportCutsEveryField(t *testing.T) {
	t.Parallel()

	// Each value builder gets the cap of the field.
	values := []struct {
		name string
		make func(limit int) string
		// want returns the expected result and whether it was cut.
		want func(in string, limit int) (string, bool)
	}{
		{"empty", func(int) string { return "" },
			func(in string, _ int) (string, bool) { return in, false }},
		{"exactly at the limit", func(l int) string { return strings.Repeat("a", l) },
			func(in string, _ int) (string, bool) { return in, false }},
		{"one rune over", func(l int) string { return strings.Repeat("a", l) + "b" },
			func(in string, l int) (string, bool) { return in[:l] + "...", true }},
		{"huge", func(l int) string { return strings.Repeat("a", l*1000) },
			func(in string, l int) (string, bool) { return in[:l] + "...", true }},
		{"multi-byte runes exactly at the limit", func(l int) string { return strings.Repeat("世", l) },
			func(in string, _ int) (string, bool) { return in, false }},
		{"multi-byte runes one over", func(l int) string { return strings.Repeat("世", l+1) },
			func(_ string, l int) (string, bool) { return strings.Repeat("世", l) + "...", true }},
		{"mixed width runes one over", func(l int) string { return strings.Repeat("é😀", l/2) + "éx" },
			func(_ string, l int) (string, bool) { return strings.Repeat("é😀", l/2) + "...", true }},
		{"invalid UTF-8 at the limit", func(l int) string { return strings.Repeat("\xff", l) },
			func(in string, _ int) (string, bool) { return in, false }},
		{"invalid UTF-8 over the limit", func(l int) string { return strings.Repeat("\xff", l+5) },
			func(_ string, l int) (string, bool) { return strings.Repeat("\xff", l) + "...", true }},
	}

	for _, f := range boundFields() {
		for _, v := range values {
			t.Run(f.name+"/"+v.name, func(t *testing.T) {
				t.Parallel()
				in := v.make(f.limit)
				wantValue, wantCut := v.want(in, f.limit)

				r := oneOfEach()
				f.set(&r, in)
				got, cut := boundReport(r)

				if gotValue := f.get(got); gotValue != wantValue {
					t.Errorf("%s = %d runes (%d bytes), want %d runes (%d bytes)",
						f.name, utf8.RuneCountInString(gotValue), len(gotValue),
						utf8.RuneCountInString(wantValue), len(wantValue))
				}
				if cut != wantCut {
					t.Errorf("boundReport() cut = %v, want %v", cut, wantCut)
				}
				if wantCut {
					// A cut value is exactly limit runes and the marker.
					// An invalid byte counts as one rune here, as in termsafe.Cut.
					short, _ := termsafe.Cut(f.get(got), f.limit)
					if f.get(got) != short+termsafe.CutMarker || utf8.RuneCountInString(f.get(got)) != f.limit+len(termsafe.CutMarker) {
						t.Errorf("%s is not exactly %d runes and %q", f.name, f.limit, termsafe.CutMarker)
					}
				}
			})
		}
	}
}

// Cutting one field must not cut or change its neighbours.
func TestBoundReportCutsOnlyTheLongField(t *testing.T) {
	t.Parallel()
	for _, f := range boundFields() {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			r := oneOfEach()
			for _, other := range boundFields() {
				other.set(&r, "short")
			}
			f.set(&r, strings.Repeat("x", f.limit+1))

			got, cut := boundReport(r)
			if !cut {
				t.Fatal("boundReport() cut = false, want true")
			}
			for _, other := range boundFields() {
				want := "short"
				if other.name == f.name {
					want = strings.Repeat("x", f.limit) + "..."
				}
				if g := other.get(got); g != want {
					t.Errorf("%s = %.20q (%d bytes), want %.20q (%d bytes)", other.name, g, len(g), want, len(want))
				}
			}
		})
	}
}

func TestBoundReportKeepsNeverCutFields(t *testing.T) {
	t.Parallel()
	huge := strings.Repeat("z", 1<<20)
	r := ScanReport{
		Servers: []JSONServer{{
			Name:   "s",
			Argv:   []string{"cmd", huge, huge},
			URL:    "https://example.com/" + huge,
			Accept: &JSONAccept{Digest: huge, Command: huge},
		}},
		Diffs: []JSONDiff{{Server: "s", Tool: "t", Diff: huge}},
	}
	want := ScanReport{
		Servers: []JSONServer{{
			Name:   "s",
			Argv:   slices.Clone(r.Servers[0].Argv),
			URL:    r.Servers[0].URL,
			Accept: &JSONAccept{Digest: huge, Command: huge},
		}},
		Diffs: []JSONDiff{{Server: "s", Tool: "t", Diff: huge}},
	}

	got, cut := boundReport(r)
	if cut {
		t.Error("boundReport() cut = true, want false: no cut field is long")
	}
	if !reflect.DeepEqual(got, want) {
		t.Error("boundReport() changed Argv, URL, Accept or Diff, want them whole")
	}
}

func TestBoundReportDoesNotChangeTheCallersData(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("n", MaxJSONNameRunes+10)
	longPath := strings.Repeat("p", jsonMaxPathRunes+10)
	build := func() ScanReport {
		return ScanReport{
			Servers:  []JSONServer{{Name: long, Source: longPath, ProjectPath: longPath, Argv: []string{"a"}}},
			Findings: []JSONFinding{{Server: long, Key: long, Related: long}},
			Diffs:    []JSONDiff{{Server: long, Tool: long, Diff: long}},
			Errors:   []JSONFileError{{Path: longPath, ProjectPath: longPath, Server: long}},
		}
	}
	r := build()

	got, cut := boundReport(r)
	if !cut {
		t.Fatal("boundReport() cut = false, want true")
	}
	if !reflect.DeepEqual(r, build()) {
		t.Error("boundReport() changed an element of the slices of the caller")
	}
	// The result really is cut, so the check above is not trivially true.
	if got.Servers[0].Name == long || got.Errors[0].Path == longPath {
		t.Error("boundReport() result is not cut")
	}
}

func TestBoundReportKeepsNilAndEmptyLists(t *testing.T) {
	t.Parallel()
	got, cut := boundReport(ScanReport{})
	if cut {
		t.Error("boundReport() cut = true for an empty report, want false")
	}
	if got.Servers != nil || got.Findings != nil || got.Diffs != nil || got.Errors != nil {
		t.Error("boundReport() made a nil list non-nil, want nil kept")
	}
}

// Two names that differ only after the cap become equal after the cut. This is
// a known and accepted limit of the cut: fields_truncated tells the reader that
// the names are not whole. server_index (the position in servers) still tells
// the findings and the diffs of the two servers apart. This test documents
// both, so a change is a decision.
func TestWriteJSONCutNamesKeepServerIndex(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		char string
	}{
		{"ascii name", "a"},
		{"multi-byte name", "é"}, // the cap counts runes, not bytes
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			prefix := strings.Repeat(tt.char, MaxJSONNameRunes)
			tags := []string{"one", "two"}
			var r ScanReport
			for _, tag := range tags {
				r.Servers = append(r.Servers, JSONServer{Name: prefix + "-" + tag, Source: "/src/" + tag})
			}
			// The lists are in the reverse order of servers, so the position
			// in a list does not give the right index by chance.
			for i := len(tags) - 1; i >= 0; i-- {
				name := prefix + "-" + tags[i]
				r.Findings = append(r.Findings, NewJSONFinding(FindingRow{
					ServerRef: ServerRef{Name: name, Index: i},
					RuleID:    "MOAT-T1-001", Severity: "high", Field: "tool", Key: tags[i],
				}))
				r.Diffs = append(r.Diffs, NewJSONDiff(ToolDiff{
					Server: name, ServerIndex: i, Tool: tags[i], Kind: DiffChanged, Diff: "-a\n+b\n",
				}))
			}

			var buf bytes.Buffer
			if err := WriteJSON(&buf, r); err != nil {
				t.Fatalf("WriteJSON() error = %v, want nil", err)
			}
			var got ScanReport
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}
			if !got.FieldsTruncated {
				t.Error("fields_truncated = false, want true")
			}
			if len(got.Servers) != 2 || len(got.Findings) != 2 || len(got.Diffs) != 2 {
				t.Fatalf("got %d servers, %d findings, %d diffs; want 2 of each", len(got.Servers), len(got.Findings), len(got.Diffs))
			}

			// The known limit: every cut name is the same text, at most the
			// cap plus the marker.
			wantName := prefix + termsafe.CutMarker
			maxRunes := MaxJSONNameRunes + utf8.RuneCountInString(termsafe.CutMarker)
			cutNames := []string{
				got.Servers[0].Name, got.Servers[1].Name,
				got.Findings[0].Server, got.Findings[1].Server,
				got.Diffs[0].Server, got.Diffs[1].Server,
			}
			for i, n := range cutNames {
				if n != wantName {
					t.Errorf("cut name %d is %d runes, want the %d runes of the cut prefix", i, utf8.RuneCountInString(n), utf8.RuneCountInString(wantName))
				}
				if c := utf8.RuneCountInString(n); c > maxRunes {
					t.Errorf("cut name %d is %d runes, want at most %d", i, c, maxRunes)
				}
			}

			// server_index tells the servers apart. Key and Tool carry the tag
			// of the server, and Source of the server entry carries it too.
			for i, tag := range []string{"two", "one"} {
				f, d := got.Findings[i], got.Diffs[i]
				wantIndex := slices.Index(tags, tag)
				if f.Key != tag || d.Tool != tag {
					t.Fatalf("finding %d key = %q, diff %d tool = %q; want %q (order changed)", i, f.Key, i, d.Tool, tag)
				}
				if f.ServerIndex != wantIndex {
					t.Errorf("finding %d server_index = %d, want %d", i, f.ServerIndex, wantIndex)
				} else if src := got.Servers[f.ServerIndex].Source; src != "/src/"+tag {
					t.Errorf("servers[%d].source = %q for finding %d, want %q", f.ServerIndex, src, i, "/src/"+tag)
				}
				if d.ServerIndex != wantIndex {
					t.Errorf("diff %d server_index = %d, want %d", i, d.ServerIndex, wantIndex)
				} else if src := got.Servers[d.ServerIndex].Source; src != "/src/"+tag {
					t.Errorf("servers[%d].source = %q for diff %d, want %q", d.ServerIndex, src, i, "/src/"+tag)
				}
			}
		})
	}
}

// The caller can set FieldsTruncated; WriteJSON never sets it back to false,
// and does not set it when nothing was cut.
func TestWriteJSONFieldsTruncatedFlag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    ScanReport
		want bool
	}{
		{"nothing cut", ScanReport{Servers: []JSONServer{{Name: "s"}}}, false},
		{"name at the limit", ScanReport{Servers: []JSONServer{{Name: strings.Repeat("a", MaxJSONNameRunes)}}}, false},
		{"name one over", ScanReport{Servers: []JSONServer{{Name: strings.Repeat("a", MaxJSONNameRunes+1)}}}, true},
		{"set by the caller", ScanReport{FieldsTruncated: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := WriteJSON(&buf, tt.r); err != nil {
				t.Fatalf("WriteJSON() error = %v, want nil", err)
			}
			var got struct {
				FieldsTruncated bool `json:"fields_truncated"`
			}
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}
			if got.FieldsTruncated != tt.want {
				t.Errorf("fields_truncated = %v, want %v", got.FieldsTruncated, tt.want)
			}
		})
	}
}

// hostileReport has one server with a name of nameBytes bytes and findings
// findings that each repeat that name and carry the same long text in Key and
// Related. The strings are shared, so building the report costs little memory.
func hostileReport(nameBytes, findings int) ScanReport {
	name := strings.Repeat("N", nameBytes)
	r := ScanReport{
		SchemaVersion: SchemaVersion,
		Tool:          ToolInfo{Name: "mcpmoat", Version: "dev"},
		Mode:          ModeNoConnect,
		Complete:      true,
		Servers: []JSONServer{{
			Name: name, Client: "claude-code", Scope: "project", State: "enabled",
			Transport: "stdio", ProjectPath: name, Source: name,
			Inspection: JSONInspection{Status: InspectionNotRun},
		}},
		Diffs: []JSONDiff{
			{Server: name, Tool: name, Kind: "new", Diff: "+x\n"},
			{Server: name, Tool: name, Kind: "changed", Diff: "-a\n+b\n"},
			{Server: name, Tool: name, Kind: "unverified", Diff: "-x\n"},
		},
		Ignored: JSONIgnored{Rules: map[string]int{}},
	}
	for range findings {
		r.Findings = append(r.Findings, JSONFinding{
			RuleID: "MM001", Severity: "high", Server: name, Field: "description",
			Key: name, Related: name, Source: SourceRule,
		})
	}
	return r
}

// countingWriter counts the bytes that it receives and keeps none of them.
type countingWriter struct{ n uint64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += uint64(len(p))
	return len(p), nil
}

// The limits of TestWriteJSONBoundsOutputAndMemory. They come from a
// measurement with the hostile report below (10,000 findings, a name of 1 MiB).
// The output limit has about 2x headroom. WriteJSON streams the document one
// element at a time: it allocated 2.3 times the output size, and 3.8 times with
// -race. The old version, which built the whole document in memory, needed 16
// to 19 times. The factor below is about 2x the highest measure (3.8). They are
// a regression guard: if the output or the allocations grow with the size of
// the name, or WriteJSON builds the whole document again, they fail.
const (
	hostileNameBytes = 1 << 20
	hostileFindings  = 10_000

	// maxJSONOutputBytes is the most bytes the hostile report may produce.
	maxJSONOutputBytes = 32 << 20
	// maxJSONAllocFactor is the most bytes WriteJSON may allocate for each byte
	// of output.
	maxJSONAllocFactor = 8
)

// TestWriteJSONBoundsOutputAndMemory does NOT call t.Parallel(). It reads
// runtime.MemStats.TotalAlloc, which counts the allocations of the whole
// process, and parallel tests that allocate at the same time would skew the
// delta. A test that is not parallel runs alone, before the parallel ones
// resume.
func TestWriteJSONBoundsOutputAndMemory(t *testing.T) {
	r := hostileReport(hostileNameBytes, hostileFindings)
	var cw countingWriter

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err := WriteJSON(&cw, r)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("WriteJSON() error = %v, want nil", err)
	}

	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("output = %d bytes, alloc delta = %d bytes, factor = %.2f", cw.n, alloc, float64(alloc)/float64(cw.n))

	if cw.n > maxJSONOutputBytes {
		t.Errorf("output = %d bytes, want at most %d: the cut does not bound the output", cw.n, maxJSONOutputBytes)
	}
	if limit := maxJSONAllocFactor * cw.n; alloc > limit {
		t.Errorf("WriteJSON allocated %d bytes for %d bytes of output, want at most %d (factor %d)",
			alloc, cw.n, limit, maxJSONAllocFactor)
	}
	// Each finding holds the name three times (Server, Key, Related): without
	// the cut the output would be at least that size.
	if unbounded := uint64(3 * hostileNameBytes * hostileFindings); cw.n >= unbounded/100 {
		t.Errorf("output = %d bytes, too close to the unbounded size", cw.n)
	}
}
