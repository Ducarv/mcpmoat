package pins

// Tests of CompareMasked (issues #228 and #234). A server can echo a secret
// value from the config (an env value, a header value or an argument) in the
// text of a tool. CompareMasked must hide it in Tool and Diff, also when the
// render wrap, the 64 KiB cut or a JSON escape would split or change it. The
// verdicts (Kind, Reason, Severity, the hashes) must stay those of Compare.
//
// All secret values here are fake. The test mask uses strings.ReplaceAll, so
// this package does not import internal/discover.

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// The fake secret values. No fixture text holds a leakWindow-byte piece of
// one of them, so leakedPiece finds only a real leak.
const (
	fakeToken = "FAKE-TOKEN-0123456789"
	// fakeOther is a second secret value. It sorts before fakeToken
	// ('O' < 'T').
	fakeOther = "FAKE-OTHER-9876543210"
	// fakeEscToken holds a quote and a backslash, which JSON writes as \" and
	// \\. The mask must find it in the decoded text.
	fakeEscToken = `FAKE"QUOTE\SLASH-TOKEN` //nolint:gosec // G101: fake test value
	// fakeNumber is a secret value that a server can send as a JSON number.
	fakeNumber = "8172635490"

	// maskMarker is what fakeMask puts in place of a secret value.
	maskMarker = "[MASKED]"

	// leakWindow is the length of the token pieces that leakedPiece looks
	// for. A wrap or a cut splits a token in two, and the longer part always
	// holds a piece this long.
	leakWindow = 6
)

var fakeTokens = []string{fakeToken, fakeOther, fakeEscToken, fakeNumber}

// fakeMask replaces each fake secret value with maskMarker, as
// (*discover.TextRedactor).Text does with the real values.
func fakeMask(s string) string {
	for _, tok := range fakeTokens {
		s = strings.ReplaceAll(s, tok, maskMarker)
	}
	return s
}

// leakedPiece returns the first leakWindow-byte piece of a fake token that s
// holds, or "" when s holds none.
func leakedPiece(s string) string {
	for _, tok := range fakeTokens {
		for i := 0; i+leakWindow <= len(tok); i++ {
			if p := tok[i : i+leakWindow]; strings.Contains(s, p) {
				return p
			}
		}
	}
	return ""
}

// changeLeak returns "Field: piece" for the first string field of c, except
// RawTool, that holds a piece of a fake token, or "" when none does. It reads
// the fields with reflect, so a string field that is added to Change later is
// checked too.
func changeLeak(c Change) string {
	v := reflect.ValueOf(c)
	for i := range v.NumField() {
		f := v.Type().Field(i)
		// Kind() is the underlying kind, so ChangeKind counts as a string too.
		if f.Name == "RawTool" || f.Type.Kind() != reflect.String {
			continue
		}
		if p := leakedPiece(v.Field(i).String()); p != "" {
			return f.Name + ": " + p
		}
	}
	return ""
}

// jsonQuote returns s as a JSON string, with its quotes.
func jsonQuote(t testing.TB, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal(%q) error = %v", s, err)
	}
	return string(b)
}

// jsonInner returns s as JSON writes it inside a string, without the quotes.
func jsonInner(t testing.TB, s string) string {
	t.Helper()
	q := jsonQuote(t, s)
	return q[1 : len(q)-1]
}

// mustRender returns the rendered text of tool without a mask.
func mustRender(t testing.TB, tool inspect.Tool) string {
	t.Helper()
	r, err := render(mustCanonical(t, tool), nil)
	if err != nil {
		t.Fatalf("render() error = %v", err)
	}
	return r
}

// toolHashes returns the Hash of each tool, or the error text when a tool has
// no hash.
func toolHashes(tools []inspect.Tool) []string {
	out := make([]string, len(tools))
	for i, tool := range tools {
		h, err := Hash(tool)
		if err != nil {
			h = err.Error()
		}
		out[i] = h
	}
	return out
}

// maskedBase is the pinned tool that most cases change.
func maskedBase() inspect.Tool {
	return inspect.Tool{
		Name:        "fetch",
		Description: "Fetch a page.\nKeep this line.",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}
}

// withBase returns a copy of maskedBase changed by edit.
func withBase(edit func(*inspect.Tool)) inspect.Tool {
	tool := maskedBase()
	edit(&tool)
	return tool
}

// wrapSplitTool returns a changed fetch tool whose description holds
// fakeToken across the wrap column, and checks that the wrap really splits it.
func wrapSplitTool(t *testing.T) inspect.Tool {
	t.Helper()
	tool := withBase(func(c *inspect.Tool) {
		c.Description = strings.Repeat("w", maxLineRunes-10) + fakeToken + " tail"
	})
	if strings.Contains(mustRender(t, tool), fakeToken) {
		t.Fatal("fixture: the wrap does not split the token in the description")
	}
	return tool
}

// wrapSplitSchemaTool returns a new tool whose inputSchema has a string value
// with fakeToken across the wrap column, and checks that the wrap splits it.
func wrapSplitSchemaTool(t *testing.T) inspect.Tool {
	t.Helper()
	// The text of the indented line is `"description": "` (16 runes), the
	// padding and the token, so the token starts at rune 190.
	value := strings.Repeat("w", maxLineRunes-10-16) + fakeToken
	tool := inspect.Tool{Name: "wide", InputSchema: json.RawMessage(`{"description":` + jsonQuote(t, value) + `}`)}
	if strings.Contains(mustRender(t, tool), fakeToken) {
		t.Fatal("fixture: the wrap does not split the token in the schema")
	}
	return tool
}

// cutSplitTool returns a new tool whose rendered text holds fakeToken across
// the maxRenderedBytes cut of capText: the first lead bytes of the token are
// before the cut. It checks that capText really keeps only that part.
func cutSplitTool(t *testing.T) inspect.Tool {
	t.Helper()
	const lead = 10
	// 399 short lines bring the text close to the cut, without the line cap
	// or the wrap.
	body := strings.Repeat(strings.Repeat("x", 150)+"\n", 399)
	build := func(pad int) inspect.Tool {
		return inspect.Tool{Name: "big", Description: body + strings.Repeat("y", pad) + fakeToken + " end"}
	}
	pad := maxRenderedBytes - lead - strings.Index(mustRender(t, build(0)), fakeToken)
	if pad < 0 || pad > 100 {
		t.Fatalf("fixture: pad = %d, want 0 to 100", pad)
	}
	tool := build(pad)
	kept, cut := capText(mustRender(t, tool))
	if !cut || strings.Contains(kept, fakeToken) || !strings.Contains(kept, fakeToken[:lead]) {
		t.Fatal("fixture: the cut does not split the token")
	}
	return tool
}

func TestCompareMaskedHidesSecrets(t *testing.T) {
	t.Parallel()
	pinsOf := func(tools ...inspect.Tool) ServerPins { return mustSnapshot(t, tools) }
	base := maskedBase()
	withDesc := func(d string) inspect.Tool { return withBase(func(c *inspect.Tool) { c.Description = d }) }
	withSchema := func(s string) inspect.Tool {
		return withBase(func(c *inspect.Tool) { c.InputSchema = json.RawMessage(s) })
	}
	tokenDesc := "Fetch a page.\nUse key " + fakeToken + " now.\nKeep this line."

	// A pin whose canonical text is of another tool, so it does not match
	// its hash.
	mismatch := pinsOf(base)
	mismatch["fetch"] = Pin{Hash: mismatch["fetch"].Hash, Canonical: mustCanonical(t, withDesc("Other."))}

	tests := []struct {
		name    string
		stored  ServerPins
		current []inspect.Tool
		want    []string // kinds() of the result: "kind:masked tool"
		// plainToMasked, when set, are the old, new pairs of a
		// strings.Replacer that turns each Diff of Compare into the Diff of
		// CompareMasked. So the mask changes the token and nothing else.
		plainToMasked []string
		// wantInDiff are lines that the joined Diffs must hold.
		wantInDiff []string
		// wantSecretOnly means that the masked texts are equal, so each
		// change with a diff has the note diffSecretOnly.
		wantSecretOnly bool
	}{
		{
			name:          "token in description of changed tool",
			stored:        pinsOf(base),
			current:       []inspect.Tool{withDesc(tokenDesc)},
			want:          []string{"changed:fetch"},
			plainToMasked: []string{fakeToken, maskMarker},
			wantInDiff: []string{
				"\n description: Fetch a page.\n",
				"\n+description: Use key " + maskMarker + " now.\n",
				"\n description: Keep this line.\n",
			},
		},
		{
			name:          "token only in pinned description",
			stored:        pinsOf(withDesc(tokenDesc)),
			current:       []inspect.Tool{base},
			want:          []string{"changed:fetch"},
			plainToMasked: []string{fakeToken, maskMarker},
			wantInDiff:    []string{"\n-description: Use key " + maskMarker + " now.\n"},
		},
		{
			name:          "token in title of changed tool",
			stored:        pinsOf(base),
			current:       []inspect.Tool{withBase(func(c *inspect.Tool) { c.Title = "Fetch " + fakeToken })},
			want:          []string{"changed:fetch"},
			plainToMasked: []string{fakeToken, maskMarker},
			wantInDiff:    []string{"\n+title: Fetch " + maskMarker + "\n"},
		},
		{
			name:   "token in name and description of new tool",
			stored: pinsOf(base),
			current: []inspect.Tool{
				base,
				{Name: "leak_" + fakeToken, Description: "Send " + fakeToken + "."},
			},
			want:          []string{"new:leak_" + maskMarker},
			plainToMasked: []string{fakeToken, maskMarker},
			wantInDiff:    []string{"\n+name: leak_" + maskMarker + "\n", "\n+description: Send " + maskMarker + ".\n"},
		},
		{
			name:    "token in name of removed tool",
			stored:  pinsOf(base, inspect.Tool{Name: "old_" + fakeToken, Description: "Old."}),
			current: []inspect.Tool{base},
			want:    []string{"removed:old_" + maskMarker},
		},
		{
			name:    "token in names of a rename",
			stored:  pinsOf(inspect.Tool{Name: "a_" + fakeToken, Description: "Old."}),
			current: []inspect.Tool{{Name: "a_" + fakeOther, Description: "New."}},
			// Both names mask to the same text. The sort is on the raw
			// names, so the new tool (fakeOther) comes first.
			want:          []string{"new:a_" + maskMarker, "removed:a_" + maskMarker},
			plainToMasked: []string{fakeOther, maskMarker},
		},
		{
			name:    "token split by the wrap in description",
			stored:  pinsOf(base),
			current: []inspect.Tool{wrapSplitTool(t)},
			want:    []string{"changed:fetch"},
		},
		{
			name:    "token split by the wrap in schema value",
			stored:  pinsOf(base),
			current: []inspect.Tool{base, wrapSplitSchemaTool(t)},
			want:    []string{"new:wide"},
		},
		{
			name:    "token split by the 64 KiB cut",
			stored:  pinsOf(base),
			current: []inspect.Tool{base, cutSplitTool(t)},
			want:    []string{"new:big"},
		},
		{
			name:          "token as schema key",
			stored:        pinsOf(base),
			current:       []inspect.Tool{withSchema(`{"properties":{` + jsonQuote(t, fakeToken) + `:{"type":"string"}}}`)},
			want:          []string{"changed:fetch"},
			plainToMasked: []string{fakeToken, maskMarker},
		},
		{
			name:          "escaped token as schema key",
			stored:        pinsOf(base),
			current:       []inspect.Tool{withSchema(`{"properties":{` + jsonQuote(t, fakeEscToken) + `:{"type":"string"}}}`)},
			want:          []string{"changed:fetch"},
			plainToMasked: []string{jsonInner(t, fakeEscToken), maskMarker},
		},
		{
			name:          "escaped token as schema value",
			stored:        pinsOf(base),
			current:       []inspect.Tool{withSchema(`{"default":` + jsonQuote(t, fakeEscToken) + `}`)},
			want:          []string{"changed:fetch"},
			plainToMasked: []string{jsonInner(t, fakeEscToken), maskMarker},
			wantInDiff:    []string{`"default": "` + maskMarker + `"`},
		},
		{
			name:          "token in enum",
			stored:        pinsOf(base),
			current:       []inspect.Tool{withSchema(`{"enum":["safe",` + jsonQuote(t, fakeToken) + `]}`)},
			want:          []string{"changed:fetch"},
			plainToMasked: []string{fakeToken, maskMarker},
		},
		{
			name:    "token as JSON number",
			stored:  pinsOf(base),
			current: []inspect.Tool{withSchema(`{"default":` + fakeNumber + `}`)},
			want:    []string{"changed:fetch"},
			// The masked number is no longer a number, so it becomes a
			// JSON string.
			plainToMasked: []string{fakeNumber, `"` + maskMarker + `"`},
		},
		{
			name:   "token in _meta key and escaped token in _meta value",
			stored: pinsOf(base),
			current: []inspect.Tool{withBase(func(c *inspect.Tool) {
				c.Meta = json.RawMessage(`{` + jsonQuote(t, fakeToken) + `:` + jsonQuote(t, fakeEscToken) + `}`)
			})},
			want:          []string{"changed:fetch"},
			plainToMasked: []string{fakeToken, maskMarker, jsonInner(t, fakeEscToken), maskMarker},
		},
		{
			name:   "token in icon src",
			stored: pinsOf(base),
			current: []inspect.Tool{withBase(func(c *inspect.Tool) {
				c.Icons = json.RawMessage(`[{"src":"https://example.test/icon.png?k=` + fakeToken + `"}]`)
			})},
			want:          []string{"changed:fetch"},
			plainToMasked: []string{fakeToken, maskMarker},
		},
		{
			name:   "escaped token in annotations title",
			stored: pinsOf(base),
			current: []inspect.Tool{withBase(func(c *inspect.Tool) {
				c.Annotations = &inspect.ToolAnnotations{Title: "Run with " + fakeEscToken}
			})},
			want:          []string{"changed:fetch"},
			plainToMasked: []string{jsonInner(t, fakeEscToken), maskMarker},
			wantInDiff:    []string{`"title": "Run with ` + maskMarker + `"`},
		},
		{
			name:           "only the secret value changed in description",
			stored:         pinsOf(withDesc("Use key " + fakeToken)),
			current:        []inspect.Tool{withDesc("Use key " + fakeOther)},
			want:           []string{"changed:fetch"},
			wantSecretOnly: true,
		},
		{
			name:           "only the secret value changed in schema key",
			stored:         pinsOf(withSchema(`{"properties":{` + jsonQuote(t, fakeToken) + `:{}}}`)),
			current:        []inspect.Tool{withSchema(`{"properties":{` + jsonQuote(t, fakeOther) + `:{}}}`)},
			want:           []string{"changed:fetch"},
			wantSecretOnly: true,
		},
		{
			name:    "token in duplicate name",
			stored:  pinsOf(base),
			current: []inspect.Tool{base, {Name: "dup_" + fakeToken}, {Name: "dup_" + fakeToken}},
			want:    []string{"unverified:dup_" + maskMarker},
		},
		{
			name:    "token in name of invalid tool",
			stored:  pinsOf(base),
			current: []inspect.Tool{base, {Name: "bad_" + fakeToken, InputSchema: json.RawMessage(`{`)}},
			want:    []string{"unverified:bad_" + maskMarker},
		},
		{
			name:          "token in tool pinned with another hash version",
			stored:        ServerPins{"fetch": {Hash: "sha256-v0:00", Canonical: "{}"}},
			current:       []inspect.Tool{withDesc(tokenDesc)},
			want:          []string{"unverified:fetch"},
			plainToMasked: []string{fakeToken, maskMarker},
		},
		{
			name:          "token in tool whose pin does not match its hash",
			stored:        mismatch,
			current:       []inspect.Tool{withDesc(tokenDesc)},
			want:          []string{"unverified:fetch"},
			plainToMasked: []string{fakeToken, maskMarker},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			storedBefore := maps.Clone(tt.stored)
			hashesBefore := toolHashes(tt.current)

			got := CompareMasked(tt.stored, tt.current, fakeMask)
			plain := Compare(tt.stored, tt.current)

			if k := kinds(got); !slices.Equal(k, tt.want) {
				t.Fatalf("kinds = %q, want %q", k, tt.want)
			}
			if len(plain) != len(got) {
				t.Fatalf("Compare() gives %d changes, CompareMasked() %d", len(plain), len(got))
			}
			// Self-check: without the mask the token shows, so the case
			// tests a real leak.
			plainLeaks := false
			for _, c := range plain {
				plainLeaks = plainLeaks || changeLeak(c) != ""
			}
			if !plainLeaks {
				t.Fatal("fixture: Compare() shows no token, so the case tests nothing")
			}

			for i, c := range got {
				if leak := changeLeak(c); leak != "" {
					t.Errorf("changes[%d] leaks a token piece in %s", i, leak)
				}
				p := plain[i]
				// The verdicts come from the raw text.
				if c.Kind != p.Kind || c.Reason != p.Reason || c.Severity != p.Severity {
					t.Errorf("changes[%d] = %s/%q/%s, want %s/%q/%s as Compare()",
						i, c.Kind, c.Reason, c.Severity, p.Kind, p.Reason, p.Severity)
				}
				if c.RawTool != p.Tool {
					t.Errorf("changes[%d].RawTool is not the raw name of Compare()", i)
				}
				if c.Tool != fakeMask(p.Tool) {
					t.Errorf("changes[%d].Tool = %q, want %q", i, c.Tool, fakeMask(p.Tool))
				}
				if (c.Diff == "") != (p.Diff == "") {
					t.Errorf("changes[%d].Diff empty = %v, want %v as Compare()", i, c.Diff == "", p.Diff == "")
				}
				switch {
				case c.Diff == "":
				case tt.wantSecretOnly:
					if c.Diff != diffSecretOnly || !c.DiffIsNote() {
						t.Errorf("changes[%d].Diff = %q, want the note diffSecretOnly", i, c.Diff)
					}
				case c.DiffIsNote():
					t.Errorf("changes[%d].Diff is the note %q, want a diff", i, c.Diff)
				case leakedPiece(p.Diff) != "" && !strings.Contains(c.Diff, maskMarker):
					t.Errorf("changes[%d].Diff has no %s where Compare() shows the token:\n%s", i, maskMarker, c.Diff)
				}
				if tt.plainToMasked != nil {
					if want := strings.NewReplacer(tt.plainToMasked...).Replace(p.Diff); c.Diff != want {
						t.Errorf("changes[%d].Diff =\n%s\nwant\n%s", i, c.Diff, want)
					}
				}
			}
			var all strings.Builder
			for _, c := range got {
				all.WriteString(c.Diff)
			}
			for _, line := range tt.wantInDiff {
				if !strings.Contains(all.String(), line) {
					t.Errorf("Diff does not hold %q:\n%s", line, all.String())
				}
			}

			// The mask must not change the input, so the hashes and the
			// pins stay raw.
			if !reflect.DeepEqual(tt.stored, storedBefore) {
				t.Error("CompareMasked() changed the stored pins")
			}
			if h := toolHashes(tt.current); !slices.Equal(h, hashesBefore) {
				t.Error("CompareMasked() changed the hash of a current tool")
			}
		})
	}
}

// TestCompareMaskedEscapeLikeSecretLimit pins the current behaviour of an
// accepted limit, the encoded-form limit in docs/limits.md. The mask compares
// the decoded JSON text. A configured value that holds a backslash sequence
// as plain characters, such as the "\t" and "\n" of a Windows path, is not
// found when a server echoes it into a JSON string as is: JSON decodes "\t"
// to a tab and "\n" to a newline. The render writes them back as "\t" and
// "\n", so the configured value shows in the diff. If a change closes this
// limit, this test fails: then update it and docs/limits.md.
func TestCompareMaskedEscapeLikeSecretLimit(t *testing.T) {
	t.Parallel()

	// A raw string literal (in backquotes) keeps each backslash as a plain
	// character: this is the fake value as the user typed it in the config.
	const configured = `C:\tools\new_dir`
	mask := func(s string) string { return strings.ReplaceAll(s, configured, maskMarker) }
	// The server writes the value into the JSON text with no escaping.
	current := withBase(func(c *inspect.Tool) {
		c.InputSchema = json.RawMessage(`{"default":"` + configured + `"}`)
	})

	// Self-check: the decoded default holds a tab and a newline (an
	// interpreted string literal, in double quotes, reads "\t" and "\n" as
	// those characters), so the mask cannot find the configured text in it.
	var schema struct {
		Default string `json:"default"`
	}
	if err := json.Unmarshal(current.InputSchema, &schema); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if schema.Default != "C:\tools\new_dir" {
		t.Fatalf("fixture: decoded default = %q, want a tab and a newline in it", schema.Default)
	}

	got := CompareMasked(mustSnapshot(t, []inspect.Tool{maskedBase()}), []inspect.Tool{current}, mask)
	if k := kinds(got); !slices.Equal(k, []string{"changed:fetch"}) {
		t.Fatalf("kinds = %q, want %q", k, []string{"changed:fetch"})
	}
	if !strings.Contains(got[0].Diff, configured) {
		t.Errorf("Diff does not show the configured value, so the limit changed; update this test and docs/limits.md:\n%s", got[0].Diff)
	}
	if strings.Contains(got[0].Diff, maskMarker) {
		t.Errorf("Diff holds %s, so the mask found the value; update this test and docs/limits.md:\n%s", maskMarker, got[0].Diff)
	}
}

// TestCompareMaskedKeepsVerdict checks that the verdicts come from the raw
// text: a tool that holds a secret value but did not change is not reported,
// and a mask that hides all text still gives the changes of Compare.
func TestCompareMaskedKeepsVerdict(t *testing.T) {
	t.Parallel()
	withToken := withBase(func(c *inspect.Tool) { c.Description = "Use key " + fakeToken })
	stored := mustSnapshot(t, []inspect.Tool{withToken})
	digest := Digest(stored)

	if got := CompareMasked(stored, []inspect.Tool{withToken}, fakeMask); got != nil {
		t.Errorf("CompareMasked() on an unchanged tool = %d changes, want nil", len(got))
	}
	if d := Digest(stored); d != digest {
		t.Errorf("Digest() after CompareMasked() = %s, want %s", d, digest)
	}
	if h, err := Hash(withToken); err != nil || h != stored["fetch"].Hash {
		t.Errorf("Hash() = %s, %v, want the pinned hash", h, err)
	}

	// erase hides every string and number, so all masked texts of a tool
	// with the same JSON shape are equal.
	erase := func(string) string { return "" }
	base := compareTools()
	pins := mustSnapshot(t, base)
	current := append(
		withTool(t, without(base, "list"), "read_file", func(c *inspect.Tool) { c.Description = "Read any file." }),
		inspect.Tool{Name: "upload", Description: "Upload a file."},
		inspect.Tool{Description: "no name"},
	)
	got := CompareMasked(pins, current, erase)
	want := Compare(pins, current)
	if len(got) != len(want) {
		t.Fatalf("CompareMasked() gives %d changes, want %d as Compare()", len(got), len(want))
	}
	for i := range got {
		g, w := got[i], want[i]
		if g.Kind != w.Kind || g.RawTool != w.Tool || g.Reason != w.Reason || g.Severity != w.Severity {
			t.Errorf("changes[%d] = %s %q/%s, want %s %q/%s", i, g.Kind, g.Reason, g.Severity, w.Kind, w.Reason, w.Severity)
		}
		if g.Kind == KindChanged && g.Diff != diffSecretOnly {
			t.Errorf("changes[%d].Diff = %q, want diffSecretOnly", i, g.Diff)
		}
	}
}

// TestCompareMaskedNoopMask checks that a nil mask, and a mask that changes
// nothing, give exactly the result of Compare for every kind of change.
func TestCompareMaskedNoopMask(t *testing.T) {
	t.Parallel()
	base := compareTools()
	pins := mustSnapshot(t, base)
	otherVersion := maps.Clone(pins)
	otherVersion["list"] = Pin{Hash: "sha256-v0:00", Canonical: pins["list"].Canonical}
	corrupt := maps.Clone(pins)
	corrupt["list"] = Pin{Hash: pins["list"].Hash, Canonical: pins["read_file"].Canonical}
	changedList := withTool(t, base, "list", func(c *inspect.Tool) { c.Description = "List all files." })

	tests := []struct {
		name    string
		stored  ServerPins
		current []inspect.Tool
	}{
		{"no change", pins, base},
		{"changed", pins, withTool(t, base, "read_file", func(c *inspect.Tool) { c.Description = "Read any file." })},
		{"new", pins, append(slices.Clone(base), inspect.Tool{Name: "upload", Description: "Upload."})},
		{"removed", pins, without(base, "list")},
		{"duplicate", pins, append(slices.Clone(base), base[0])},
		{"empty name", pins, append(slices.Clone(base), inspect.Tool{Description: "x"})},
		{"invalid tool", pins, append(slices.Clone(base), inspect.Tool{Name: "bad", InputSchema: json.RawMessage(`{`)})},
		{"hash version", otherVersion, base},
		{"pin mismatch", corrupt, changedList},
		{"no pins", nil, base},
	}
	masks := []struct {
		name string
		mask func(string) string
	}{
		{"nil", nil},
		{"identity", func(s string) string { return s }},
	}
	for _, tt := range tests {
		for _, m := range masks {
			t.Run(tt.name+"/"+m.name, func(t *testing.T) {
				t.Parallel()
				got := CompareMasked(tt.stored, tt.current, m.mask)
				want := Compare(tt.stored, tt.current)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("CompareMasked() =\n%#v\nwant\n%#v", got, want)
				}
			})
		}
	}
}

// TestCompareMaskedSortsByRawName checks that RawTool is the raw name, Tool
// the masked name, and that the order follows the raw names: two tools whose
// masked names are equal both show, in the same order on every run and for
// every input order.
func TestCompareMaskedSortsByRawName(t *testing.T) {
	t.Parallel()
	newA := inspect.Tool{Name: "x_" + fakeToken, Description: "Same."}
	newB := inspect.Tool{Name: "x_" + fakeOther, Description: "Same."}
	// Two removed tools too: Compare finds them in a map, whose order
	// changes from run to run.
	stored := mustSnapshot(t, []inspect.Tool{
		{Name: "y_" + fakeToken, Description: "Old."},
		{Name: "y_" + fakeOther, Description: "Old."},
	})
	wantRaw := []string{"x_" + fakeOther, "x_" + fakeToken, "y_" + fakeOther, "y_" + fakeToken}
	wantTool := []string{"x_" + maskMarker, "x_" + maskMarker, "y_" + maskMarker, "y_" + maskMarker}

	var first []Change
	for _, current := range [][]inspect.Tool{{newA, newB}, {newB, newA}} {
		for range 20 {
			got := CompareMasked(stored, current, fakeMask)
			var raw, tool []string
			for _, c := range got {
				raw = append(raw, c.RawTool)
				tool = append(tool, c.Tool)
			}
			if !slices.Equal(raw, wantRaw) {
				t.Fatalf("RawTool order = %q, want %q", raw, wantRaw)
			}
			if !slices.Equal(tool, wantTool) {
				t.Fatalf("Tool = %q, want %q", tool, wantTool)
			}
			if first == nil {
				first = got
			} else if !reflect.DeepEqual(got, first) {
				t.Fatal("CompareMasked() result changes between runs")
			}
		}
	}
}
