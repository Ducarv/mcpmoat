package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/report/reporttest"
)

// writeJSON returns the bytes that report.WriteJSON writes for r. It fails the
// test if WriteJSON returns an error.
func writeJSON(t *testing.T, r report.ScanReport) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Fatalf("WriteJSON() error = %v, want nil", err)
	}
	return buf.Bytes()
}

// decodeJSON unmarshals the output of WriteJSON back into a ScanReport.
func decodeJSON(t *testing.T, out []byte) report.ScanReport {
	t.Helper()
	var got report.ScanReport
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	return got
}

// newReport wraps the parts in a ScanReport with the fixed header fields.
func newReport(servers []report.JSONServer, diffs []report.JSONDiff) report.ScanReport {
	return report.ScanReport{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.ToolInfo{Name: "mcpmoat", Version: "test"},
		Mode:          report.ModeConnect,
		Servers:       servers,
		Diffs:         diffs,
	}
}

func TestWriteJSONRedactionParity(t *testing.T) {
	t.Parallel()

	stdio := discover.Server{
		Name:      "fs",
		Client:    discover.ClientClaudeCode,
		Scope:     discover.ScopeGlobal,
		Transport: discover.TransportStdio,
		Command:   "npx",
		Args: discover.NewArgs([]string{
			"-y", "@scope/server-fs", "--token", discovertest.CanaryArgs, "/data",
		}),
		Env: discover.SecretMap{"API_KEY_NAME": discover.NewSecret(discovertest.CanaryEnv)},
	}
	remote := discover.Server{
		Name:      "remote",
		Client:    discover.ClientCursor,
		Scope:     discover.ScopeGlobal,
		Transport: discover.TransportHTTP,
		URL: discover.NewURL("https://user:" + discovertest.CanaryURL +
			"@example.com/mcp?token=" + discovertest.CanaryURL),
		Headers: discover.SecretMap{
			"X-Auth-Header-Name": discover.NewSecret("Bearer " + discovertest.CanaryHeader),
		},
	}

	js := []report.JSONServer{
		report.NewJSONServer(stdio, report.InspectionNotRun),
		report.NewJSONServer(remote, report.InspectionNotRun),
	}
	out := writeJSON(t, newReport(js, nil))
	got := decodeJSON(t, out)

	// No canary in any form, and no env or header key either.
	discovertest.AssertNoLeak(t, "WriteJSON output", string(out))
	for _, key := range []string{"API_KEY_NAME", "X-Auth-Header-Name"} {
		if strings.Contains(string(out), key) {
			t.Errorf("output contains env or header key %q", key)
		}
	}

	// The argv is the redacted command line, as the terminal shows it.
	wantArgv := discover.RedactArgs(append([]string{stdio.Command}, stdio.Args.Values()...))
	if !slices.Equal(got.Servers[0].Argv, wantArgv) {
		t.Errorf("argv = %q, want %q", got.Servers[0].Argv, wantArgv)
	}
	if !slices.Contains(got.Servers[0].Argv, discover.Mask) {
		t.Errorf("argv = %q, want the secret masked with %q", got.Servers[0].Argv, discover.Mask)
	}
	// Same text as the COMMAND cell of WriteServers (no part needs quoting here).
	if cmd := report.FormatCommand(stdio.Command, stdio.Args); cmd != strings.Join(got.Servers[0].Argv, " ") {
		t.Errorf("COMMAND cell = %q, joined argv = %q, want equal", cmd, strings.Join(got.Servers[0].Argv, " "))
	}
	if got.Servers[0].URL != "" {
		t.Errorf("stdio server url = %q, want empty", got.Servers[0].URL)
	}

	// The URL is the redacted string of the URL type.
	if got.Servers[1].URL != remote.URL.String() {
		t.Errorf("url = %q, want %q", got.Servers[1].URL, remote.URL.String())
	}
	if len(got.Servers[1].Argv) != 0 {
		t.Errorf("http server argv = %q, want none", got.Servers[1].Argv)
	}
	if strings.Contains(got.Servers[1].URL, "user:") {
		t.Errorf("url = %q, want no userinfo", got.Servers[1].URL)
	}
	// The raw output has no argv key for http and no url key for stdio.
	var raw struct {
		Servers []map[string]any `json:"servers"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.Servers[0]["url"]; ok {
		t.Error("stdio server has a url key, want none")
	}
	if _, ok := raw.Servers[1]["argv"]; ok {
		t.Error("http server has an argv key, want none")
	}
	for _, banned := range []string{"env", "headers", "cwd"} {
		for i, s := range raw.Servers {
			if _, ok := s[banned]; ok {
				t.Errorf("server %d has key %q, want none", i, banned)
			}
		}
	}
}

func TestWriteJSONEscaping(t *testing.T) {
	t.Parallel()

	// Untrusted text with every kind of unsafe character.
	hostile := map[string]string{
		"esc":       "a\x1b[31mred\x1b]0;title\x07b",
		"c1 csi":    "a\u009bb",
		"bidi rlo":  "a\u202eb",
		"bidi lri":  "a\u2066b",
		"zero-wide": "a\u200bb",
		"tag char":  "a\U000E0041b",
		"line sep":  "a\u2028b\u2029c",
		"newline":   "a\nb\tc\rd",
		"del":       "a\x7fb",
	}
	for name, s := range hostile {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newReport(nil, []report.JSONDiff{{Server: s, Tool: s, Kind: report.DiffChanged.String(), Diff: "+" + s + "\n"}})
			out := writeJSON(t, r)
			reporttest.AssertSafeBytes(t, out)
			got := decodeJSON(t, out)
			if d := got.Diffs[0]; d.Tool != s || d.Server != s || d.Diff != "+"+s+"\n" {
				t.Errorf("round trip changed the text: server %q, tool %q, diff %q; want %q, %q, %q", d.Server, d.Tool, d.Diff, s, s, "+"+s+"\n")
			}
		})
	}

	t.Run("invalid utf-8", func(t *testing.T) {
		t.Parallel()
		bad := "a\xffb\xc3"
		out := writeJSON(t, newReport(nil, []report.JSONDiff{{Tool: bad, Diff: bad}}))
		reporttest.AssertSafeBytes(t, out)
		got := decodeJSON(t, out)
		want := "a\ufffdb\ufffd"
		if got.Diffs[0].Tool != want || got.Diffs[0].Diff != want {
			t.Errorf("tool = %q, diff = %q, want %q", got.Diffs[0].Tool, got.Diffs[0].Diff, want)
		}
	})

	t.Run("all in one name", func(t *testing.T) {
		t.Parallel()
		var all strings.Builder
		for _, s := range hostile {
			all.WriteString(s)
		}
		js := report.NewJSONServer(discover.Server{Name: all.String(), Source: all.String(), Transport: discover.TransportStdio}, report.InspectionNotRun)
		out := writeJSON(t, newReport([]report.JSONServer{js}, nil))
		reporttest.AssertSafeBytes(t, out)
		if got := decodeJSON(t, out); got.Servers[0].Name != all.String() || got.Servers[0].Source != all.String() {
			t.Error("round trip changed the name or the source")
		}
	})

	t.Run("printable text stays literal", func(t *testing.T) {
		t.Parallel()
		s := "café \U0001F600 <a&b>"
		out := writeJSON(t, newReport(nil, []report.JSONDiff{{Tool: s}}))
		if !strings.Contains(string(out), `"tool": "`+s+`"`) {
			t.Errorf("output does not hold %q literally:\n%s", s, out)
		}
		if got := decodeJSON(t, out); got.Diffs[0].Tool != s {
			t.Errorf("tool = %q, want %q", got.Diffs[0].Tool, s)
		}
	})
}

func TestWriteJSONEmptyReport(t *testing.T) {
	t.Parallel()

	r := report.ScanReport{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.ToolInfo{Name: "mcpmoat", Version: "test"},
		Mode:          report.ModeNoConnect,
	}
	out := writeJSON(t, r)

	if !bytes.HasSuffix(out, []byte("}\n")) || bytes.HasSuffix(out, []byte("\n\n")) {
		t.Errorf("output must end with one newline, got tail %q", out[max(0, len(out)-4):])
	}
	if bytes.Contains(out, []byte("null")) {
		t.Errorf("output holds null:\n%s", out)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"servers", "findings", "diffs", "errors"} {
		list, ok := raw[key].([]any)
		if !ok || len(list) != 0 {
			t.Errorf("%s = %#v, want an empty list", key, raw[key])
		}
	}
}

func TestWriteJSONNilListsDoNotChangeCaller(t *testing.T) {
	t.Parallel()
	// WriteJSON takes the report by value, so the caller's nil slices stay nil.
	r := report.ScanReport{}
	writeJSON(t, r)
	if r.Servers != nil || r.Findings != nil || r.Diffs != nil || r.Errors != nil {
		t.Error("WriteJSON changed the report of the caller")
	}
}

func TestWriteJSONStdioWithoutArgsHasArgv(t *testing.T) {
	t.Parallel()
	js := report.NewJSONServer(discover.Server{Name: "s", Transport: discover.TransportStdio, Command: "mycmd"}, report.InspectionNotRun)
	out := writeJSON(t, newReport([]report.JSONServer{js}, nil))
	got := decodeJSON(t, out)
	if len(got.Servers[0].Argv) != 1 || got.Servers[0].Argv[0] != "mycmd" {
		t.Errorf("argv = %q, want [mycmd]", got.Servers[0].Argv)
	}
	if !strings.Contains(string(out), `"argv"`) {
		t.Errorf("output has no argv key:\n%s", out)
	}
}

func TestWriteJSONDeterministic(t *testing.T) {
	t.Parallel()
	r := richReport()
	first := writeJSON(t, r)
	for range 5 {
		if again := writeJSON(t, r); !bytes.Equal(first, again) {
			t.Fatalf("two calls gave different bytes:\n%s\n---\n%s", first, again)
		}
	}
}

func TestDiffKindString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind report.DiffKind
		want string
	}{
		{report.DiffChanged, "changed"},
		{report.DiffNew, "new"},
		{report.DiffUnverified, "unverified"},
		{report.DiffKind(99), "unknown"},
		{report.DiffKind(-1), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("DiffKind(%d).String() = %q, want %q", int(tt.kind), got, tt.want)
		}
	}
}

// TestNewJSONDiffCopiesFields checks every field of NewJSONDiff. The kind is
// a literal on purpose: it is the stable name in the schema.
func TestNewJSONDiffCopiesFields(t *testing.T) {
	t.Parallel()
	got := report.NewJSONDiff(report.ToolDiff{Server: "s", Tool: "t", Kind: report.DiffNew, Diff: "a note", Truncated: true, IsNote: true})
	want := report.JSONDiff{Server: "s", Tool: "t", Kind: "new", Diff: "a note", Truncated: true, IsNote: true}
	if got != want {
		t.Errorf("NewJSONDiff() = %+v, want %+v", got, want)
	}
}

func TestNewJSONFileErrorNeverCopiesErr(t *testing.T) {
	t.Parallel()
	e := &discover.FileError{
		Path: "/p/mcp.json", ProjectPath: "/p", Server: "s", Line: 3, Col: 7, Reason: "invalid JSON", Untrusted: true,
		Err: errors.New("secret " + discovertest.CanaryEnv),
	}
	out := writeJSON(t, report.ScanReport{Errors: []report.JSONFileError{report.NewJSONFileError(e)}})
	discovertest.AssertNoLeak(t, "WriteJSON output", string(out))
	got := decodeJSON(t, out).Errors[0]
	want := report.JSONFileError{Path: "/p/mcp.json", ProjectPath: "/p", Server: "s", Line: 3, Col: 7, Reason: "invalid JSON", Untrusted: true}
	if got != want {
		t.Errorf("file error = %+v, want %+v", got, want)
	}
}

// failWriter fails every write.
type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriteJSONWriteError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("pipe closed")
	err := report.WriteJSON(failWriter{sentinel}, richReport())
	if err == nil {
		t.Fatal("WriteJSON() error = nil, want the write error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("WriteJSON() error = %v, want it to wrap %v", err, sentinel)
	}
}
