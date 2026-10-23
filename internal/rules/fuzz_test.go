package rules

import (
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParse checks that Parse holds its contract for any bytes: no panic, one
// of two outcomes, safe error text, bounded errors and the same result twice.
// A rule file is untrusted, so the file name is fuzzed too.
func FuzzParse(f *testing.F) {
	repo := os.DirFS("../..") // fs.ReadFile keeps the paths inside the repository
	fixtures := []string{
		"testdata/rules/valid/MOAT-T1-003.yaml",
		"testdata/rules/invalid/bad-severity.yaml",
		"testdata/rules/collide/MOAT-T1-003.yaml",
		"testdata/rules/extra/MOAT-X-001.yaml",
		"rules/MOAT-T1-003.yaml",
	}
	for _, path := range fixtures {
		data, err := fs.ReadFile(repo, path)
		if err != nil {
			f.Fatalf("read fixture: %v", err)
		}
		f.Add("fixture.yaml", data)
	}

	seeds := []string{
		"",
		"---\n",
		"id: a\n---\nid: b\n",
		"id: &a x\ntitle: *a\n",
		"<<: *a\n",
		"? [a]\n: b\n",
		strings.Repeat("[", 40) + strings.Repeat("]", 40),
		"[" + strings.Repeat("a,", 11000) + "a]",
		"id: a\nmatch:\n  nope: 1\n  other: [x]\n",
		"id: a\nshould_match: [{text: a, note: b}, c]\n",
		"id: a\x00\ntitle: \x1b[31m\xff\xfe\n\xef\xbb\xbf: v\n",
		"\xef\xbb\xbfid: x\n",
		"id: 'x'\ntitle: t\nseverity: low\ntarget: config\nmatch: {keywords: [k]}\n",
		strings.Repeat("a", maxFileBytes),
		strings.Repeat("a", maxFileBytes+1),
	}
	for _, s := range seeds {
		f.Add("seed.yaml", []byte(s))
	}
	f.Add("bad\x00\x1b[2Jname\xff.yaml", []byte("id: a\n"))

	// Invisible runes in a key and in the file name, once as raw runes (the
	// YAML reader may reject them) and once as YAML escapes (they reach Field).
	f.Add("n\u009b\u202e\u200b\u2066\u3164.yaml", []byte("id: a\n"))
	f.Add("seed.yaml", []byte("a\u009b\u202e\u200b: 1\n"))
	f.Add("seed.yaml", []byte("\"a\\u009b\\u202e\\u200b\\u2066\\u3164\": 1\nid: a\n"))
	f.Add("seed.yaml", []byte("id: &a\u202e x\ntitle: *a\u200b\n"))

	// Files that give far more errors than the cap: 9970 null case items and
	// 4985 unknown keys. Both stay below the size and node caps.
	f.Add("cap.yaml", []byte("id: a\nshould_match:\n"+strings.Repeat("  -\n", 9970)))
	var keys strings.Builder
	for i := range 4985 {
		keys.WriteString("k" + strconv.Itoa(i) + ": 1\n")
	}
	f.Add("cap.yaml", []byte(keys.String()))

	f.Fuzz(func(t *testing.T, name string, data []byte) {
		rule, errs := Parse(name, data)
		checkParseResult(t, name, len(data), rule, errs)

		// Parse is deterministic: a second call gives the same errors.
		rule2, errs2 := Parse(name, data)
		if len(errs) != len(errs2) {
			t.Fatalf("not deterministic: %d then %d errors (input %d bytes)", len(errs), len(errs2), len(data))
		}
		for i := range errs {
			if errs[i].Error() != errs2[i].Error() {
				t.Fatalf("not deterministic: error %d differs (input %d bytes)", i, len(data))
			}
		}
		if (rule.ID == "") != (rule2.ID == "") {
			t.Fatalf("not deterministic: rule differs (input %d bytes)", len(data))
		}
	})
}

// checkParseResult checks the invariants of one Parse result.
func checkParseResult(t *testing.T, name string, size int, rule Rule, errs []*LoadError) {
	t.Helper()

	if len(errs) == 0 {
		if rule.ID == "" {
			t.Fatalf("valid outcome with empty ID (input %d bytes)", size)
		}
		if rule.Source != name {
			t.Fatalf("Source differs from the name (input %d bytes)", size)
		}
		if verrs := rule.Validate(); verrs != nil {
			t.Fatalf("valid outcome fails Validate: %d errors (input %d bytes)", len(verrs), size)
		}
		return
	}

	if rule.ID != "" || rule.Source != "" || rule.Title != "" {
		t.Fatalf("error outcome with a non-zero Rule (input %d bytes)", size)
	}
	if len(errs) > maxErrorsPerFile+1 {
		t.Fatalf("%d errors, want at most %d (input %d bytes)", len(errs), maxErrorsPerFile+1, size)
	}
	// ReasonTooManyErrors is the note at the end of a full list, never anywhere else.
	for i, e := range errs {
		if e != nil && e.Reason == ReasonTooManyErrors && (i != len(errs)-1 || len(errs) != maxErrorsPerFile+1) {
			t.Fatalf("error %d of %d has Reason %q, want it only last in a full list (input %d bytes)", i, len(errs), e.Reason, size)
		}
	}
	// The file name is quoted but never cut, so the bound grows with it.
	maxLen := 4096 + 6*len(name)
	for i, e := range errs {
		if e == nil {
			t.Fatalf("error %d is nil (input %d bytes)", i, size)
		}
		if e.File != name || e.Line < 0 || e.Col < 0 || e.Reason == "" {
			t.Fatalf("error %d has a bad File, Line, Col or Reason (input %d bytes)", i, size)
		}
		msg := e.Error()
		if !utf8.ValidString(msg) {
			t.Fatalf("error %d text is not valid UTF-8 (input %d bytes)", i, size)
		}
		if len(msg) > maxLen {
			t.Fatalf("error %d text has %d bytes, want at most %d (input %d bytes)", i, len(msg), maxLen, size)
		}
		// Controls (C0, DEL, C1), format runes (bidi, zero-width) and U+2028/9.
		noRawControls(t, msg)
	}
}
