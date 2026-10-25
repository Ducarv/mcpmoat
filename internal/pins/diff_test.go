package pins

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// diffSchema is the input schema of the tools in the diff tests.
const diffSchema = `{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`

// emptyAnnotations is the rendered annotations of a tool that has none: the
// canonical form writes every hint, as null, and an empty title.
const emptyAnnotations = "annotations:\n  {\n    \"destructiveHint\": null,\n    \"idempotentHint\": null,\n" +
	"    \"openWorldHint\": null,\n    \"readOnlyHint\": null,\n    \"title\": \"\"\n  }\n"

// emptyMetaIcons is the rendered _meta and icons of a tool that has none. They
// come after annotations and before the schemas.
const emptyMetaIcons = "_meta:\n  null\nicons:\n  null\n"

// diffTool returns a tool with a name, a title, the given description and a
// small input schema.
func diffTool(description string) inspect.Tool {
	return inspect.Tool{
		Name:        "read_file",
		Title:       "Read file",
		Description: description,
		InputSchema: []byte(diffSchema),
	}
}

// numberedLines returns n lines "row-01", "row-02", ... joined with "\n".
func numberedLines(n int) string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("row-%02d", i+1)
	}
	return strings.Join(lines, "\n")
}

// mustDiff returns unifiedDiff of the two tools and fails the test on an error.
func mustDiff(t testing.TB, oldTool, newTool inspect.Tool) string {
	t.Helper()
	got, _, err := unifiedDiff(mustCanonical(t, oldTool), mustCanonical(t, newTool))
	if err != nil {
		t.Fatalf("unifiedDiff() error = %v, want nil", err)
	}
	return got
}

func TestRender(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		tool inspect.Tool
		want string
	}{
		{
			name: "all fields, schema indented in key order",
			tool: inspect.Tool{
				Name:        "read_file",
				Title:       "Read file",
				Description: "Read a file.",
				InputSchema: []byte(`{"type":"object","properties":{"path":{"type":"string"}}}`),
			},
			want: "name: read_file\n" +
				"title: Read file\n" +
				"description: Read a file.\n" +
				emptyAnnotations + emptyMetaIcons +
				"inputSchema:\n" +
				"  {\n" +
				"    \"properties\": {\n" +
				"      \"path\": {\n" +
				"        \"type\": \"string\"\n" +
				"      }\n" +
				"    },\n" +
				"    \"type\": \"object\"\n" +
				"  }\n" +
				"outputSchema:\n  null\n",
		},
		{
			name: "absent fields",
			tool: inspect.Tool{Name: "t"},
			want: "name: t\ntitle: \ndescription: \n" + emptyAnnotations + emptyMetaIcons + "inputSchema:\n  null\noutputSchema:\n  null\n",
		},
		{
			name: "empty object schema stays on one line",
			tool: inspect.Tool{Name: "t", InputSchema: []byte(`{}`)},
			want: "name: t\ntitle: \ndescription: \n" + emptyAnnotations + emptyMetaIcons + "inputSchema:\n  {}\noutputSchema:\n  null\n",
		},
		{
			name: "every line of a multi-line description has the prefix",
			tool: inspect.Tool{Name: "t", Description: "one\ntwo\n\nfour"},
			want: "name: t\ntitle: \n" +
				"description: one\ndescription: two\ndescription: \ndescription: four\n" +
				emptyAnnotations + emptyMetaIcons + "inputSchema:\n  null\noutputSchema:\n  null\n",
		},
		{
			name: "name and title with line breaks get the prefix on every line",
			tool: inspect.Tool{Name: "a\nb", Title: "c\nd"},
			want: "name: a\nname: b\ntitle: c\ntitle: d\ndescription: \n" +
				emptyAnnotations + emptyMetaIcons + "inputSchema:\n  null\noutputSchema:\n  null\n",
		},
		{
			name: "text is not escaped or normalised",
			tool: inspect.Tool{Name: "t", Description: "a\u200bb <&> \x1b[31m"},
			want: "name: t\ntitle: \ndescription: a\u200bb <&> \x1b[31m\n" +
				emptyAnnotations + emptyMetaIcons + "inputSchema:\n  null\noutputSchema:\n  null\n",
		},
		{
			name: "_meta set, keys sorted at every level",
			tool: inspect.Tool{
				Name: "t",
				Meta: []byte(`{"ui":{"resourceUri":"ui://x/y","a":1},"anthropic/z":true}`),
			},
			want: "name: t\ntitle: \ndescription: \n" + emptyAnnotations +
				"_meta:\n" +
				"  {\n" +
				"    \"anthropic/z\": true,\n" +
				"    \"ui\": {\n" +
				"      \"a\": 1,\n" +
				"      \"resourceUri\": \"ui://x/y\"\n" +
				"    }\n" +
				"  }\n" +
				"icons:\n  null\n" +
				"inputSchema:\n  null\noutputSchema:\n  null\n",
		},
		{
			name: "icons set, array of two icons",
			tool: inspect.Tool{
				Name:  "t",
				Icons: []byte(`[{"src":"https://e.example/a.png","mimeType":"image/png"},{"src":"https://e.example/b.svg","sizes":["any"]}]`),
			},
			want: "name: t\ntitle: \ndescription: \n" + emptyAnnotations +
				"_meta:\n  null\n" +
				"icons:\n" +
				"  [\n" +
				"    {\n" +
				"      \"mimeType\": \"image/png\",\n" +
				"      \"src\": \"https://e.example/a.png\"\n" +
				"    },\n" +
				"    {\n" +
				"      \"sizes\": [\n" +
				"        \"any\"\n" +
				"      ],\n" +
				"      \"src\": \"https://e.example/b.svg\"\n" +
				"    }\n" +
				"  ]\n" +
				"inputSchema:\n  null\noutputSchema:\n  null\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := render(mustCanonical(t, tt.tool))
			if err != nil {
				t.Fatalf("render() error = %v, want nil", err)
			}
			if got != tt.want {
				t.Errorf("render() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

func TestRenderAnnotations(t *testing.T) {
	t.Parallel()
	tool := inspect.Tool{Name: "t"}
	ensureAnnotations(&tool).Title = "Annotated"
	got, err := render(mustCanonical(t, tool))
	if err != nil {
		t.Fatalf("render() error = %v, want nil", err)
	}
	if !strings.Contains(got, "annotations:\n  {\n") || !strings.Contains(got, `"title": "Annotated"`) {
		t.Errorf("render() = %q, want an indented annotations object with the title", got)
	}
	if strings.Contains(got, "annotations:\n  null") {
		t.Errorf("render() = %q, want annotations not null", got)
	}
}

func TestRenderInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"not json", "{not json"},
		{"truncated", `{"name":"t"`},
		{"array", `[]`},
		{"string", `"x"`},
		{"number", `1`},
		{"name is a number", `{"name":1}`},
		{"description is an object", `{"description":{}}`},
		{"trailing garbage", `{"name":"t"} x`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := render(tt.input)
			if err == nil {
				t.Fatalf("render(%q) = %q, error = nil, want an error", tt.input, got)
			}
			if got != "" {
				t.Errorf("render(%q) = %q with an error, want empty text", tt.input, got)
			}
		})
	}
}

func TestRenderErrorDoesNotQuoteServerText(t *testing.T) {
	t.Parallel()
	// The input is not valid JSON. The secret stands for server text that
	// must not leak into the error.
	const secret = "SECRET-SERVER-TEXT"
	_, err := render(`{"name":"ok","inputSchema":` + `{"a":"` + secret + `"` + `}x}`)
	if err == nil {
		t.Fatal("render() error = nil, want an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("render() error = %q, want no server text", err)
	}
}

func TestUnifiedDiffEqual(t *testing.T) {
	t.Parallel()
	tools := map[string]inspect.Tool{
		"simple":    diffTool("Read a file."),
		"multiline": diffTool(numberedLines(10)),
		"empty":     {Name: "t"},
	}
	for name, tool := range tools {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := mustDiff(t, tool, cloneTool(tool)); got != "" {
				t.Errorf("unifiedDiff(equal tools) = %q, want empty", got)
			}
		})
	}
}

func TestUnifiedDiffChangedLine(t *testing.T) {
	t.Parallel()
	oldDesc := numberedLines(20)
	newDesc := strings.Replace(oldDesc, "row-10", "row-10 CHANGED", 1)
	got := mustDiff(t, diffTool(oldDesc), diffTool(newDesc))

	// Description line k is line k+2 of the rendered text (name and title come first).
	for _, line := range []string{
		"--- pinned\n", "+++ current\n",
		"-description: row-10\n", "+description: row-10 CHANGED\n",
		" description: row-07\n", " description: row-09\n",
		" description: row-11\n", " description: row-13\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("diff has no line %q:\n%s", line, got)
		}
	}
	// Far-away lines and the unchanged name line are not in the diff.
	for _, absent := range []string{"row-01\n", "row-06\n", "row-14\n", "row-20\n", "name: read_file", "inputSchema"} {
		if strings.Contains(got, absent) {
			t.Errorf("diff has far-away text %q:\n%s", absent, got)
		}
	}
	// Exactly one removed and one added line (apart from the headers).
	var minus, plus int
	for _, l := range strings.Split(got, "\n") {
		switch {
		case strings.HasPrefix(l, "---"), strings.HasPrefix(l, "+++"):
		case strings.HasPrefix(l, "-"):
			minus++
		case strings.HasPrefix(l, "+"):
			plus++
		}
	}
	if minus != 1 || plus != 1 {
		t.Errorf("diff has %d removed and %d added lines, want 1 and 1:\n%s", minus, plus, got)
	}
}

func TestUnifiedDiffSchemaChange(t *testing.T) {
	t.Parallel()
	oldTool := diffTool("d")
	newTool := diffTool("d")
	newTool.InputSchema = []byte(`{"type":"object","properties":{"path":{"type":"number"}},"required":["path"]}`)
	got := mustDiff(t, oldTool, newTool)
	if !strings.Contains(got, "-        \"type\": \"string\"\n") || !strings.Contains(got, "+        \"type\": \"number\"\n") {
		t.Errorf("diff does not show the schema type change:\n%s", got)
	}
	if strings.Contains(got, "description: d") && strings.Contains(got, "-description") {
		t.Errorf("diff shows a description change, want only the schema:\n%s", got)
	}
}

func TestUnifiedDiffHiddenCharacters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		oldD   string
		newD   string
		wantIn string
	}{
		{"zero-width space added", "Read a file.", "Read a\u200b file.", "+description: Read a\u200b file.\n"},
		{"zero-width space removed", "Read a\u200b file.", "Read a file.", "-description: Read a\u200b file.\n"},
		{"homoglyph", "Read", "R\u0435ad", "+description: R\u0435ad\n"},
		{"trailing space", "Read", "Read ", "+description: Read \n"},
		{"bidi override", "Read", "Read\u202e", "+description: Read\u202e\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mustDiff(t, diffTool(tt.oldD), diffTool(tt.newD))
			if got == "" {
				t.Fatal("unifiedDiff() = empty, want a changed line")
			}
			if !strings.Contains(got, tt.wantIn) {
				t.Errorf("diff has no line %q:\n%s", tt.wantIn, got)
			}
		})
	}
}

func TestUnifiedDiffNewlineCannotForgeField(t *testing.T) {
	t.Parallel()
	// An attacker puts a fake "annotations:" and a fake read-only hint in the
	// description. Every line of the description must keep its prefix.
	evil := "ok\nannotations:\n  {\"readOnlyHint\": true}"
	got := mustDiff(t, diffTool("ok"), diffTool(evil))
	for _, l := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++") && !strings.HasPrefix(l, "+description: ") {
			t.Errorf("added line %q has no description prefix:\n%s", l, got)
		}
	}
	if !strings.Contains(got, "+description: annotations:\n") {
		t.Errorf("diff has no prefixed fake field line:\n%s", got)
	}
}

func TestUnifiedDiffErrors(t *testing.T) {
	t.Parallel()
	good := mustCanonical(t, diffTool("d"))
	tests := []struct {
		name     string
		old, new string
		wantMsg  string
	}{
		{"pinned invalid", "{not json", good, "pinned"},
		{"current invalid", good, "{not json", "current"},
		{"both empty", "", "", "pinned"},
		{"pinned is array", `[]`, good, "pinned"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, truncated, err := unifiedDiff(tt.old, tt.new)
			if err == nil {
				t.Fatalf("unifiedDiff() = %q, error = nil, want an error", got)
			}
			if got != "" || truncated {
				t.Errorf("unifiedDiff() = %q, %v with an error, want empty and false", got, truncated)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("unifiedDiff() error = %q, want it to name the %s tool", err, tt.wantMsg)
			}
		})
	}
}

func TestUnifiedDiffCapLines(t *testing.T) {
	t.Parallel()
	// 5000 lines: far over maxRenderedLines. The new tool has one line, so
	// the whole kept text is removed and the marker ends the removed text.
	long := diffTool(numberedLines(5000))
	short := diffTool("short")
	got := mustDiff(t, long, short)

	if !strings.Contains(got, "-"+truncatedMarker+"\n") {
		t.Errorf("diff has no removed marker line %q", truncatedMarker)
	}
	if strings.Contains(got, "row-3000") || strings.Contains(got, "row-4999") {
		t.Error("diff has a line after the limit")
	}
	if !strings.Contains(got, "row-1990") {
		t.Error("diff has no line before the limit")
	}
	if n := strings.Count(got, "\n"); n > maxRenderedLines+50 {
		t.Errorf("diff has %d lines, want at most about %d", n, maxRenderedLines)
	}
	if !utf8.ValidString(got) {
		t.Error("diff is not valid UTF-8")
	}

	// The marker also shows when it is inside the context of a change. The
	// first change (row-01) starts the diffed window at the start of the text.
	// Description line k is rendered line k+2, so row-1997 is rendered line
	// 1999, and the marker is rendered line 2001.
	lines := strings.Split(numberedLines(5000), "\n")
	lines[0] += " CHANGED"
	lines[1996] += " CHANGED"
	got = mustDiff(t, long, diffTool(strings.Join(lines, "\n")))
	if !strings.Contains(got, " "+truncatedMarker+"\n") {
		t.Errorf("diff has no context marker line near the limit:\n%s", tail(got, 400))
	}
}

func TestUnifiedDiffCapBytes(t *testing.T) {
	t.Parallel()
	const size = 200 * 1024
	tests := []struct {
		name string
		unit string
	}{
		{"ascii", "a"},
		{"two-byte rune", "\u00e9"},
		{"three-byte rune", "\u20ac"},
		{"four-byte rune", "\U0001F600"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Every line of the new text differs from the old text, so the
			// diffed window is far over the byte limit.
			oldD := strings.Repeat(tt.unit, size/len(tt.unit))
			newD := strings.Repeat("z", size)
			got := mustDiff(t, diffTool(oldD), diffTool(newD))
			if !utf8.ValidString(got) {
				t.Fatal("diff is not valid UTF-8")
			}
			if !strings.Contains(got, truncatedMarker) {
				t.Errorf("diff has no marker %q", truncatedMarker)
			}
			// Two cut texts plus the headers: far below the 200 KiB input.
			if len(got) > 2*(maxRenderedBytes+1024) {
				t.Errorf("diff is %d bytes, want at most %d", len(got), 2*(maxRenderedBytes+1024))
			}
		})
	}
}

// numberedRunes returns n distinct short words joined by "-", so no two
// chunks of the text are equal.
func numberedRunes(n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "w%d-", i)
	}
	return b.String()[:n]
}

func TestUnifiedDiffChangeAfterLongText(t *testing.T) {
	t.Parallel()
	newSchema := []byte(`{"type":"object","x-payload":"EVIL"}`)
	oldSchema := []byte(`{"type":"object","x-payload":"safe"}`)
	tests := []struct {
		name string
		desc string
	}{
		{name: "3000 lines", desc: numberedLines(3000)},
		{name: "100 KiB on one line", desc: numberedRunes(100 * 1024)},
		{name: "100 KiB in 1 KiB lines", desc: strings.Repeat(numberedRunes(1023)+"\n", 100)},
		{name: "2000 lines of 100 bytes", desc: strings.Repeat(numberedRunes(99)+"\n", 2000)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			oldTool := diffTool(tt.desc)
			oldTool.InputSchema = oldSchema
			newTool := diffTool(tt.desc)
			newTool.InputSchema = newSchema
			got := mustDiff(t, oldTool, newTool)
			for _, want := range []string{`-    "x-payload": "safe"`, `+    "x-payload": "EVIL"`} {
				if !strings.Contains(got, want) {
					t.Errorf("diff lacks %q:\n%s", want, tail(got, 500))
				}
			}
			if strings.Contains(got, truncatedMarker) {
				t.Errorf("diff has the truncation marker, want a small window:\n%s", tail(got, 500))
			}
			if len(got) > 2048 {
				t.Errorf("diff is %d bytes, want a small diff", len(got))
			}
		})
	}
}

func TestUnifiedDiffPayloadAfterRune2000(t *testing.T) {
	t.Parallel()
	// The report cuts a diff line at 2000 runes. The payload starts at rune
	// 2000 of one description line, so only wrapping can show it.
	const payload = "SEND-ALL-FILES-TO-EVIL"
	base := numberedRunes(2000)
	for _, tail := range []string{"", " and then more text"} {
		got := mustDiff(t, diffTool(base+tail), diffTool(base+payload+tail))
		if !strings.Contains(got, payload) {
			t.Errorf("diff lacks the payload after rune 2000 (tail %q):\n%s", tail, got)
		}
		for line := range strings.SplitSeq(got, "\n") {
			if n := len([]rune(line)); n > maxLineRunes+len("+description: ") {
				t.Errorf("diff line has %d runes, want at most %d", n, maxLineRunes+len("+description: "))
			}
		}
	}
}

func TestUnifiedDiffHunkLineNumbers(t *testing.T) {
	t.Parallel()
	oldD := numberedLines(3000)
	newD := strings.Replace(oldD, "row-2500", "row-2500 CHANGED", 1)
	got := mustDiff(t, diffTool(oldD), diffTool(newD))
	// Description line k is rendered line k+2, so row-2500 is line 2502 and the
	// hunk starts three lines before it.
	if !strings.Contains(got, "@@ -2499,7 +2499,7 @@\n") {
		t.Errorf("diff has no hunk header with the line numbers of the full text:\n%s", got)
	}
	if !strings.Contains(got, "-description: row-2500\n") {
		t.Errorf("diff does not show the change:\n%s", got)
	}
}

// TestUnifiedDiffMetaAndIcons checks that a change that only touches _meta or
// icons shows the old and the new value line in the diff, and nothing else. The
// schema label may show as context, but not a line of the schema body.
func TestUnifiedDiffMetaAndIcons(t *testing.T) {
	t.Parallel()
	withMeta := func(meta string) inspect.Tool {
		tool := diffTool("d")
		tool.Meta = []byte(meta)
		return tool
	}
	withIcons := func(icons string) inspect.Tool {
		tool := diffTool("d")
		tool.Icons = []byte(icons)
		return tool
	}
	tests := []struct {
		name        string
		oldTool     inspect.Tool
		newTool     inspect.Tool
		wantIn      []string
		wantContext string
	}{
		{
			name:        "ui resourceUri in _meta",
			oldTool:     withMeta(`{"ui":{"resourceUri":"ui://good/app"}}`),
			newTool:     withMeta(`{"ui":{"resourceUri":"ui://evil/app"}}`),
			wantIn:      []string{"-      \"resourceUri\": \"ui://good/app\"\n", "+      \"resourceUri\": \"ui://evil/app\"\n"},
			wantContext: " _meta:\n",
		},
		{
			name:        "_meta added",
			oldTool:     diffTool("d"),
			newTool:     withMeta(`{"ui":{"resourceUri":"ui://evil/app"}}`),
			wantIn:      []string{"-  null\n", "+      \"resourceUri\": \"ui://evil/app\"\n"},
			wantContext: " _meta:\n",
		},
		{
			name:        "icon src",
			oldTool:     withIcons(`[{"src":"https://good.example/a.png"}]`),
			newTool:     withIcons(`[{"src":"https://evil.example/a.png"}]`),
			wantIn:      []string{"-      \"src\": \"https://good.example/a.png\"\n", "+      \"src\": \"https://evil.example/a.png\"\n"},
			wantContext: " icons:\n",
		},
		{
			name:        "icons added",
			oldTool:     diffTool("d"),
			newTool:     withIcons(`[{"src":"https://evil.example/a.png"}]`),
			wantIn:      []string{"-  null\n", "+      \"src\": \"https://evil.example/a.png\"\n"},
			wantContext: " icons:\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mustDiff(t, tt.oldTool, tt.newTool)
			if got == "" {
				t.Fatal("unifiedDiff() = empty, want a changed line")
			}
			for _, want := range append([]string{tt.wantContext}, tt.wantIn...) {
				if !strings.Contains(got, want) {
					t.Errorf("diff lacks %q:\n%s", want, got)
				}
			}
			for _, absent := range []string{"description", `"required"`} {
				if strings.Contains(got, absent) {
					t.Errorf("diff has unchanged text %q:\n%s", absent, got)
				}
			}
		})
	}
}

// TestUnifiedDiffMetaSurvivesCut checks that a change in _meta is in the diff
// when the description changes too and a large unchanged input schema follows.
// annotations, _meta and icons are rendered before the schemas. So the
// unchanged schema is a shared tail that the diff trims, and it cannot push
// the _meta change into a cut part. With _meta after the schemas, the window would hold the
// whole schema and the cap would hide the _meta change.
func TestUnifiedDiffMetaSurvivesCut(t *testing.T) {
	t.Parallel()
	var props strings.Builder
	for i := range 3000 {
		if i > 0 {
			props.WriteByte(',')
		}
		fmt.Fprintf(&props, `"p%04d":{"type":"string"}`, i)
	}
	schema := `{"type":"object","properties":{` + props.String() + `}}`

	build := func(description, meta string) inspect.Tool {
		return inspect.Tool{
			Name:        "read_file",
			Description: description,
			Meta:        []byte(meta),
			InputSchema: []byte(schema),
		}
	}
	oldTool := build("old text", `{"ui":{"resourceUri":"ui://good/app"}}`)
	newTool := build("new text", `{"ui":{"resourceUri":"ui://evil/app"}}`)

	got, truncated, err := unifiedDiff(mustCanonical(t, oldTool), mustCanonical(t, newTool))
	if err != nil {
		t.Fatalf("unifiedDiff() error = %v, want nil", err)
	}
	if truncated {
		t.Error("unifiedDiff() truncated = true, want false: the unchanged schema is trimmed")
	}
	if len(got) > maxRenderedBytes/10 {
		t.Errorf("diff has %d bytes, want a small diff without the unchanged schema", len(got))
	}
	for _, want := range []string{
		"-description: old text\n",
		"+description: new text\n",
		"-      \"resourceUri\": \"ui://good/app\"\n",
		"+      \"resourceUri\": \"ui://evil/app\"\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("cut diff lacks %q", want)
		}
	}
}

func TestUnifiedDiffChangeAtEdges(t *testing.T) {
	t.Parallel()
	oldD := numberedLines(30)
	tests := []struct {
		name    string
		newD    string
		wantIn  string
		wantHdr string
	}{
		{"first description line", strings.Replace(oldD, "row-01", "row-01 X", 1), "+description: row-01 X\n", "@@ -1,6 +1,6 @@\n"},
		{"last description line", strings.Replace(oldD, "row-30", "row-30 X", 1), "+description: row-30 X\n", "@@ -29,"},
		{"line appended", oldD + "\nrow-31", "+description: row-31\n", "@@ -30,6 +30,7 @@\n"},
		{"line removed at the end", strings.TrimSuffix(oldD, "\nrow-30"), "-description: row-30\n", "@@ -29,"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mustDiff(t, diffTool(oldD), diffTool(tt.newD))
			if !strings.Contains(got, tt.wantIn) {
				t.Errorf("diff lacks %q:\n%s", tt.wantIn, got)
			}
			if !strings.Contains(got, tt.wantHdr) {
				t.Errorf("diff lacks header %q:\n%s", tt.wantHdr, got)
			}
		})
	}
}

// splitLines returns the lines of s, each with its "\n".
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// sharedLines returns the number of lines that a and b share at the start, and
// at the end, when they are not the same line list.
func sharedLines(a, b []string) (prefix, suffix int) {
	n := min(len(a), len(b))
	for prefix < n && a[prefix] == b[prefix] {
		prefix++
	}
	for suffix < n-prefix && a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}
	return prefix, suffix
}

func TestTrimCommon(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(testSeed, testSeed)) //nolint:gosec // G404: deterministic seed for a reproducible test, not for security
	words := []string{"a", "b", "ab", "ba", ""}
	randomText := func() string {
		var b strings.Builder
		for range rng.IntN(12) {
			b.WriteString(words[rng.IntN(len(words))])
			b.WriteByte('\n')
		}
		return b.String()
	}
	for range 3000 {
		a, b := randomText(), randomText()
		if a == b {
			continue
		}
		wa, wb, skipped := trimCommon(a, b, diffContextLines)
		la, lb := splitLines(a), splitLines(b)

		// a and b are the same except for the windows: the first lines, and
		// the rest after the window, are shared.
		if skipped > len(la) || skipped > len(lb) {
			t.Fatalf("trimCommon(%q, %q) skipped %d lines, more than a text has", a, b, skipped)
		}
		head := strings.Join(la[:skipped], "")
		if !strings.HasPrefix(b, head) || !strings.HasPrefix(a[len(head):], wa) || !strings.HasPrefix(b[len(head):], wb) {
			t.Fatalf("trimCommon(%q, %q) = %q, %q, %d: windows do not follow the skipped lines", a, b, wa, wb, skipped)
		}
		tailA, tailB := a[len(head)+len(wa):], b[len(head)+len(wb):]
		if tailA != tailB {
			t.Fatalf("trimCommon(%q, %q) = %q, %q: the removed tails differ: %q, %q", a, b, wa, wb, tailA, tailB)
		}
		if wa == wb {
			t.Fatalf("trimCommon(%q, %q): the windows are equal: %q", a, b, wa)
		}
		// The windows keep at most diffContextLines shared lines at each side,
		// and exactly that many when lines were removed there.
		prefix, suffix := sharedLines(splitLines(wa), splitLines(wb))
		if prefix > diffContextLines || suffix > diffContextLines {
			t.Fatalf("trimCommon(%q, %q) = %q, %q: %d shared lines at the start, %d at the end", a, b, wa, wb, prefix, suffix)
		}
		fullPrefix, fullSuffix := sharedLines(la, lb)
		if want := min(fullPrefix, diffContextLines); prefix != want {
			t.Fatalf("trimCommon(%q, %q) kept %d shared lines at the start, want %d", a, b, prefix, want)
		}
		if want := min(fullSuffix, diffContextLines); suffix != want {
			t.Fatalf("trimCommon(%q, %q) kept %d shared lines at the end, want %d", a, b, suffix, want)
		}
	}
}

func TestShiftHunks(t *testing.T) {
	t.Parallel()
	in := "--- pinned\n+++ current\n@@ -3,4 +3,5 @@\n a\n@@ -10 +11 @@\n-@@ -1 +1 @@\n+x\n"
	want := "--- pinned\n+++ current\n@@ -103,4 +103,5 @@\n a\n@@ -110 +111 @@\n-@@ -1 +1 @@\n+x\n"
	if got := shiftHunks(in, 100); got != want {
		t.Errorf("shiftHunks() =\n%q\nwant\n%q", got, want)
	}
	if got := shiftHunks(in, 0); got != in {
		t.Errorf("shiftHunks(offset 0) changed the diff: %q", got)
	}
	if got := shiftHunks("", 5); got != "" {
		t.Errorf("shiftHunks(empty) = %q, want empty", got)
	}
}

func TestRenderWrapsLongLines(t *testing.T) {
	t.Parallel()
	long := numberedRunes(3*maxLineRunes + 50)
	tool := inspect.Tool{
		Name:        long,
		Title:       long,
		Description: long + "\n" + long,
		InputSchema: []byte(`{"k":"` + long + `"}`),
	}
	got, err := render(mustCanonical(t, tool))
	if err != nil {
		t.Fatalf("render() error = %v, want nil", err)
	}
	if !utf8.ValidString(got) {
		t.Fatal("render() is not valid UTF-8")
	}
	var counts = map[string]int{}
	for line := range strings.SplitSeq(strings.TrimSuffix(got, "\n"), "\n") {
		text := line
		for _, field := range []string{"name", "title", "description"} {
			if rest, ok := cutFieldLead(line, field); ok {
				counts[field]++
				text = rest
			}
		}
		if strings.HasPrefix(line, "    ") {
			counts["schema"]++
			text = strings.TrimPrefix(strings.TrimLeft(line, " "), "+ ")
		}
		if n := utf8.RuneCountInString(text); n > maxLineRunes {
			t.Errorf("line has %d runes of text, want at most %d: %q", n, maxLineRunes, line)
		}
	}
	// 650 runes give 4 chunks. The description has two such lines.
	want := map[string]int{"name": 4, "title": 4, "description": 8}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s has %d lines, want %d:\n%s", k, counts[k], v, got)
		}
	}
	if counts["schema"] < 4 {
		t.Errorf("schema value has %d lines, want at least 4 (wrapped chunks keep the indentation):\n%s", counts["schema"], got)
	}
	// Joining the chunks of the name gives the whole name back.
	var name strings.Builder
	for line := range strings.SplitSeq(got, "\n") {
		if text, ok := cutFieldLead(line, "name"); ok {
			name.WriteString(text)
		}
	}
	if name.String() != long {
		t.Errorf("the chunks of the name do not give the name back: %q", name.String())
	}
}

// cutFieldLead returns the text of a rendered line of field, after its lead:
// "field: " on the first chunk, or "field+ " on a continuation chunk.
func cutFieldLead(line, field string) (string, bool) {
	if text, ok := strings.CutPrefix(line, field+": "); ok {
		return text, true
	}
	return strings.CutPrefix(line, field+"+ ")
}

func TestRenderWrapCutsOnRuneBoundaries(t *testing.T) {
	t.Parallel()
	for _, r := range []string{"a", "\u00e9", "\u20ac", "\U0001F600"} {
		for _, n := range []int{maxLineRunes - 1, maxLineRunes, maxLineRunes + 1, 2*maxLineRunes + 1} {
			t.Run(fmt.Sprintf("%d-byte rune x %d", len(r), n), func(t *testing.T) {
				t.Parallel()
				desc := strings.Repeat(r, n)
				got, err := render(mustCanonical(t, inspect.Tool{Name: "t", Description: desc}))
				if err != nil {
					t.Fatalf("render() error = %v, want nil", err)
				}
				if !utf8.ValidString(got) {
					t.Fatal("render() is not valid UTF-8")
				}
				var joined strings.Builder
				for line := range strings.SplitSeq(got, "\n") {
					if text, ok := cutFieldLead(line, "description"); ok {
						if c := utf8.RuneCountInString(text); c > maxLineRunes {
							t.Errorf("chunk has %d runes, want at most %d", c, maxLineRunes)
						}
						joined.WriteString(text)
					}
				}
				if joined.String() != desc {
					t.Error("the chunks do not give the description back")
				}
			})
		}
	}
}

func TestWriteWrapped(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", maxLineRunes+1)
	deep := strings.Repeat(" ", maxIndent+50)
	tests := []struct {
		name             string
		lead, cont, text string
		want             string
	}{
		{"empty text", "p: ", "p+ ", "", "p: \n"},
		{"short", "p: ", "p+ ", "abc", "p: abc\n"},
		{"exactly the limit", "p: ", "p+ ", long[:maxLineRunes], "p: " + long[:maxLineRunes] + "\n"},
		{"one over: the next chunk has the continuation lead", "p: ", "p+ ", long, "p: " + long[:maxLineRunes] + "\np+ a\n"},
		{"invalid UTF-8 bytes count one each", "p: ", "p+ ", strings.Repeat("\xff", maxLineRunes+1), "p: " + strings.Repeat("\xff", maxLineRunes) + "\np+ \xff\n"},
		{"huge indentation is capped on every chunk", deep, deep + "+ ", long, deep[:maxIndent] + long[:maxLineRunes] + "\n" + deep[:maxIndent] + "+ a\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			writeWrapped(&b, tt.lead, tt.cont, tt.text)
			if b.String() != tt.want {
				t.Errorf("writeWrapped() = %q, want %q", b.String(), tt.want)
			}
		})
	}
}

// TestRenderWrapDiffersFromLineBreak checks that a wrapped line and a real line
// break in the text never render the same.
func TestRenderWrapDiffersFromLineBreak(t *testing.T) {
	t.Parallel()
	a := strings.Repeat("A", maxLineRunes)
	wrapped := mustCanonical(t, inspect.Tool{Name: "t", Description: a + "B"})
	broken := mustCanonical(t, inspect.Tool{Name: "t", Description: a + "\nB"})
	rw, err := render(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := render(broken)
	if err != nil {
		t.Fatal(err)
	}
	if rw == rb {
		t.Errorf("a wrapped line and a line break render the same:\n%s", rw)
	}
}

func TestCapText(t *testing.T) {
	t.Parallel()
	marker := truncatedMarker + "\n"
	tests := []struct {
		name string
		in   string
		want string // "" means: use the checks in check
		same bool
	}{
		{name: "empty", in: "", same: true},
		{name: "short", in: "a\nb\n", same: true},
		{name: "no final newline", in: "a\nb", same: true},
		{name: "exactly the byte limit", in: strings.Repeat("a", maxRenderedBytes), same: true},
		{name: "exactly the line limit", in: strings.Repeat("x\n", maxRenderedLines), same: true},
		{name: "one byte over", in: strings.Repeat("a", maxRenderedBytes+1), want: strings.Repeat("a", maxRenderedBytes) + "\n" + marker},
		{name: "one line over", in: strings.Repeat("x\n", maxRenderedLines+1), want: strings.Repeat("x\n", maxRenderedLines) + marker},
		{name: "line limit before byte limit", in: strings.Repeat("x\n", maxRenderedBytes), want: strings.Repeat("x\n", maxRenderedLines) + marker},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, cut := capText(tt.in)
			want := tt.want
			if tt.same {
				want = tt.in
			}
			if got != want {
				t.Errorf("capText() = %.60q (len %d), want %.60q (len %d)", got, len(got), want, len(want))
			}
			if cut == tt.same {
				t.Errorf("capText() cut = %v, want %v", cut, !tt.same)
			}
		})
	}
}

func TestCapTextCutsOnRuneStart(t *testing.T) {
	t.Parallel()
	runes := []string{"\u00e9", "\u20ac", "\U0001F600"}
	for _, r := range runes {
		for prefix := range utf8.UTFMax {
			t.Run(fmt.Sprintf("%d-byte rune, prefix %d", len(r), prefix), func(t *testing.T) {
				t.Parallel()
				in := strings.Repeat("a", prefix) + strings.Repeat(r, maxRenderedBytes/len(r)+4)
				got, _ := capText(in)
				if !utf8.ValidString(got) {
					t.Fatalf("capText() is not valid UTF-8: tail %q", tail(got, 20))
				}
				if !strings.HasSuffix(got, "\n"+truncatedMarker+"\n") {
					t.Errorf("capText() tail = %q, want the marker on its own line", tail(got, 60))
				}
				kept := strings.TrimSuffix(got, "\n"+truncatedMarker+"\n")
				if len(kept) > maxRenderedBytes {
					t.Errorf("kept %d bytes, want at most %d", len(kept), maxRenderedBytes)
				}
				if len(kept) <= maxRenderedBytes-utf8.UTFMax {
					t.Errorf("kept %d bytes, want more than %d (cut too early)", len(kept), maxRenderedBytes-utf8.UTFMax)
				}
			})
		}
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// checkWrapped fails the test when a line of the rendered text has more than
// maxLineRunes runes of text after its prefix or indentation. Invalid UTF-8
// counts one rune for each byte, as writeWrapped does.
func checkWrapped(t *testing.T, rendered string) {
	t.Helper()
	for line := range strings.SplitSeq(rendered, "\n") {
		// A JSON line never starts with "+", so "+ " after the indentation is
		// the continuation lead.
		text := strings.TrimPrefix(strings.TrimLeft(line, " "), "+ ")
		for _, field := range []string{"name", "title", "description"} {
			if rest, ok := cutFieldLead(line, field); ok {
				text = rest
			}
		}
		if n := utf8.RuneCountInString(text); n > maxLineRunes {
			t.Fatalf("rendered line has %d runes of text, want at most %d: %.80q", n, maxLineRunes, line)
		}
	}
}

func FuzzRender(f *testing.F) {
	seeds := []inspect.Tool{
		diffTool("Read a file."),
		diffTool("one\ntwo\nthree"),
		diffTool("zero\u200bwidth \U0001F600 \u00e9"),
		{Name: "t"},
		{Name: "n\nm", Title: "x\ny", Description: "\n\n"},
	}
	for _, s := range seeds {
		c := mustCanonical(f, s)
		f.Add(c, c)
		f.Add(c, mustCanonical(f, diffTool("other\ntext")))
	}
	longLine := mustCanonical(f, diffTool(strings.Repeat("\u00e9x", 3*maxLineRunes)))
	f.Add(longLine, mustCanonical(f, diffTool(strings.Repeat("\u00e9x", 3*maxLineRunes)+"!")))
	for _, s := range []string{"", "{", "[]", "null", `{"name":1}`, `{"inputSchema":{`, "{\"name\":\"\xff\"}", `{"name":"\ud800"}`} {
		f.Add(s, s)
	}

	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a) > 64<<10 || len(b) > 64<<10 {
			t.Skip("input larger than 64 KiB")
		}
		// json.Indent passes raw bytes of the schemas through, so invalid UTF-8
		// in the input can stay in the output. Canonical never makes such input.
		valid := utf8.ValidString(a) && utf8.ValidString(b)
		r, err := render(a)
		if err == nil {
			if utf8.ValidString(a) && !utf8.ValidString(r) {
				t.Fatalf("render(%q) = %q is not valid UTF-8", a, r)
			}
			checkWrapped(t, r)
		} else if r != "" {
			t.Fatalf("render(%q) = %q with error %v, want empty text", a, r, err)
		}

		d, _, err := unifiedDiff(a, b)
		if err != nil {
			if d != "" {
				t.Fatalf("unifiedDiff() = %q with error %v, want empty text", d, err)
			}
			return
		}
		if valid && !utf8.ValidString(d) {
			t.Fatalf("unifiedDiff(%q, %q) = %q is not valid UTF-8", a, b, d)
		}
		if a == b && d != "" {
			t.Fatalf("unifiedDiff(a, a) = %q, want empty", d)
		}
		// Different rendered texts never give an empty diff: this is how a
		// change behind a long text stays visible.
		ra, errA := render(a)
		rb, errB := render(b)
		if errA == nil && errB == nil && ra != rb && d == "" {
			t.Fatalf("unifiedDiff(%q, %q) is empty, but the rendered texts differ", a, b)
		}
		if len(d) > 4*maxRenderedBytes {
			t.Fatalf("diff is %d bytes, want it bounded", len(d))
		}
	})
}

func TestNewToolDiffErrors(t *testing.T) {
	t.Parallel()
	got, truncated, err := newToolDiff("{not json")
	if err == nil {
		t.Fatalf("newToolDiff() = %q, error = nil, want an error", got)
	}
	if got != "" || truncated {
		t.Errorf("newToolDiff() = %q, %v with an error, want empty and false", got, truncated)
	}
	if !strings.Contains(err.Error(), "current") {
		t.Errorf("newToolDiff() error = %q, want it to name the current tool", err)
	}
}
