package rules

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// Benchmarks for the matchers (#35, NFR-03). Run them with:
//
//	go test -run '^$' -bench . -benchmem ./internal/rules/
//
// Non-ASCII runes are Go escape sequences, so this file stays pure ASCII.

// benchTextSize is the size of the long description of #35: "a 10 MB
// description is matched within the time budget".
const benchTextSize = 10 << 20

// benchSentences is the filler of the benchmark texts: plain English with
// some accented letters, CJK and an emoji. No sentence holds a keyword of
// benchKeywords, an invisible rune or a long base64 run.
var benchSentences = []string{
	"This tool lists the files in a directory and returns their names and sizes. ",
	"Use it to read a caf\u00e9 menu, a na\u00efve summary or a r\u00e9sum\u00e9 from the workspace. ",
	"The result is sorted by name; hidden entries are skipped unless you set the flag. ",
	"\u65e5\u672c\u8a9e\u306e\u30c6\u30ad\u30b9\u30c8\u3082\u6271\u3048\u307e\u3059\u3002 ",
	"Errors are returned as text, for example when the path does not exist \U0001F600. ",
	"Large folders are paged: pass the cursor from the last call to get the next page. ",
}

// benchKeywords is a realistic T1 keyword list.
var benchKeywords = []string{
	"ignore previous",
	"ignore all previous instructions",
	"disregard prior instructions",
	"do not tell the user",
	"do not mention",
	"without telling the user",
	"~/.ssh",
	"id_rsa",
	"id_ed25519",
	".env",
	"aws_access_key_id",
	"system prompt",
	"<important>",
	"exfiltrate",
	"send the contents",
	"private key",
	"before using this tool",
	"secretly",
	"conversation history",
	"api key",
}

// benchMatcherSet compiles a realistic set of matchers: one any_regex with
// the PRD MOAT-T1-003 patterns and other T1 patterns, one keywords list and
// the text heuristics with their defaults.
func benchMatcherSet(tb testing.TB) []*Matcher {
	tb.Helper()
	blocks := []Match{
		{AnyRegex: append(slices.Clone(t1003Patterns),
			`(?i)ignore (all |any )?(previous|prior|above) (instructions|rules|prompts)`,
			`(?i)<\s*(important|system|secret)\s*>`,
			`(?i)(read|cat|open|send|upload)\s.{0,40}(~/\.ssh|id_rsa|\.aws/credentials|\.env\b)`,
			`(?i)before (using|calling) (this|any) tool.{0,60}(must|always)`,
		)},
		{Keywords: benchKeywords},
		{Heuristic: HeuristicInvisibleUnicode},
		{Heuristic: HeuristicMaxLength},
		{Heuristic: HeuristicBase64Blob},
		{Heuristic: HeuristicMixedScript},
	}
	return mustCompileAll(tb, blocks)
}

// benchText returns a deterministic text of at least size bytes, made of
// benchSentences starting at sentence first.
func benchText(size, first int) string {
	var b strings.Builder
	b.Grow(size + 256)
	for i := first; b.Len() < size; i++ {
		b.WriteString(benchSentences[i%len(benchSentences)])
	}
	return b.String()
}

// matchAll runs every matcher on text and returns the number of hits. It
// builds the forms of text once and shares them between the matchers, as the
// engine must do for one target text (#143).
func matchAll(ms []*Matcher, text string) int {
	p := prepareText(text)
	n := 0
	for _, m := range ms {
		n += len(m.matchPrepared(p))
	}
	return n
}

// matchAllPerMatcher is matchAll without the shared forms: each Match call
// builds the forms of text again. BenchmarkAnalysis10x20PerMatcher uses it to
// show what the shared forms save.
func matchAllPerMatcher(ms []*Matcher, text string) int {
	n := 0
	for _, m := range ms {
		n += len(m.Match(text))
	}
	return n
}

// BenchmarkMatch10MB is the #35 acceptance check "a 10 MB description is
// matched within the time budget". The regex and keyword work is bounded by
// MaxMatchInputBytes; the heuristics scan the full 10 MB text.
func BenchmarkMatch10MB(b *testing.B) {
	ms := benchMatcherSet(b)
	text := benchText(benchTextSize, 0)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		matchAll(ms, text)
	}
}

// BenchmarkAnalysis10x20 is the NFR-03 benchmark: the analysis of 10 servers
// with 20 tools each (200 descriptions of about 1 KiB) runs in under 1 s. One
// op is the whole analysis. The matchers share the forms of each description
// (see matchAll).
func BenchmarkAnalysis10x20(b *testing.B) {
	benchAnalysis(b, matchAll)
}

// BenchmarkAnalysis10x20PerMatcher is BenchmarkAnalysis10x20 with a Match
// call for each matcher, so each matcher builds the forms again. Compare the
// two to see the cost of the forms.
func BenchmarkAnalysis10x20PerMatcher(b *testing.B) {
	benchAnalysis(b, matchAllPerMatcher)
}

// benchAnalysis runs match on 200 descriptions of about 1 KiB with the
// matchers of benchMatcherSet. One op is the 200 calls.
func benchAnalysis(b *testing.B, match func([]*Matcher, string) int) {
	b.Helper()
	ms := benchMatcherSet(b)
	descs := make([]string, 200)
	total := 0
	for i := range descs {
		descs[i] = benchText(1<<10, i)
		total += len(descs[i])
	}
	b.SetBytes(int64(total))
	b.ReportAllocs()
	for b.Loop() {
		for _, d := range descs {
			match(ms, d)
		}
	}
}

// worstBlock returns an any_regex list that is about as costly as the caps
// allow: regexes of the form \pL{0,k}!X, each as large as maxProgInsts
// allows, and a last smaller one, until the sum is just under maxTotalInsts.
// On a text of letters no regex matches, and each one keeps about k threads
// alive at every byte.
func worstBlock(tb testing.TB) []string {
	tb.Helper()
	pattern := func(k int) string { return fmt.Sprintf(`\pL{0,%d}!X`, k) }
	// largest returns the pattern with the largest k (at most 1000, the
	// repeat limit of syntax.Parse) whose program fits in limit, and its
	// size. ok is false when not even k = 1 fits.
	largest := func(limit int) (expr string, insts int, ok bool) {
		for k := 1000; k >= 1; k-- {
			if n := progInsts(tb, pattern(k)); n <= limit {
				return pattern(k), n, true
			}
		}
		return "", 0, false
	}

	var list []string
	total := 0
	for len(list) < MaxPatterns {
		expr, n, ok := largest(min(maxProgInsts, maxTotalInsts-total))
		if !ok {
			break
		}
		list = append(list, expr)
		total += n
	}
	if _, _, ok := largest(maxTotalInsts - total); ok {
		tb.Fatalf("worstBlock: %d instructions left unused", maxTotalInsts-total)
	}
	if _, err := (Match{AnyRegex: list}).CompileFor(TargetDescription); err != nil {
		tb.Fatalf("worstBlock: Compile() error = %v", err)
	}
	return list
}

// BenchmarkWorstCaseBlock measures the most costly match block that passes
// the caps (32 KiB of text, 2500 instructions), on MaxMatchInputBytes of text
// that has all fourteen regex forms (see preparedText.regexForms). It starts
// with allFormsText: the ZWSP, U+0001, ESC [ I and ESC U+0001 [8m give the
// seven base forms of matchForms, and the ligature U+FB03 makes each base form
// not ASCII, so its fold ("ffi") is a new form. The rest is 'a', after the
// short prefix, so each of the fourteen forms is about MaxMatchInputBytes long.
//
// The block is \pL{0,498}!X twice and \pL{0,248}!X: 1000 + 1000 + 500 =
// maxTotalInsts instructions. One op is one Match call over the fourteen forms.
// For the time on an Apple M1 Pro, see the cost comment in match.go.
// A hostile --rules directory can repeat such a block in every rule, and
// every tool text is matched against every rule, so this cost is multiplied
// by the number of rules and the number of texts.
func BenchmarkWorstCaseBlock(b *testing.B) {
	m, err := Match{AnyRegex: worstBlock(b)}.CompileFor(TargetDescription)
	if err != nil {
		b.Fatalf("Compile() error = %v", err)
	}
	text := allFormsText + strings.Repeat("a", MaxMatchInputBytes-len(allFormsText))
	forms := regexForms(text)
	if len(forms) != maxRegexForms {
		b.Fatalf("len(regexForms(text)) = %d, want %d", len(forms), maxRegexForms)
	}
	// Each form must fill the cap, or the benchmark does not hit the bound.
	for i, f := range forms {
		if len(f) < MaxMatchInputBytes-len(allFormsText) {
			b.Fatalf("len(regexForms(text)[%d]) = %d, want at least %d", i, len(f), MaxMatchInputBytes-len(allFormsText))
		}
	}
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		if m.Match(text) != nil {
			b.Fatal("Match() != nil, want no match")
		}
	}
}

// BenchmarkOSCStartRun times one matchForms and one matchWindowCut call on
// about maxRawScanBytes of U+009D, then U+0001, ESC and ZWSP, so that all
// seven forms are built. Each U+009D can start an OSC, so this is the slowest
// known input for the OSC part of ansiSeq (see oscExprC0).
func BenchmarkOSCStartRun(b *testing.B) {
	text := strings.Repeat("\u009d", maxRawScanBytes/2-3) + "\x01\x1b\u200b"
	if got := len(formModes(text)); got != maxBaseForms {
		b.Fatalf("len(formModes(text)) = %d, want %d", got, maxBaseForms)
	}
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		matchForms(text)
		matchWindowCut(text)
	}
}

// worstSchema returns a JSON array of n distinct strings that fills the caps
// of schemaFit exactly: each string is maxSchemaMatchBytes/n bytes long, and
// n is at most maxSchemaMatchStrings. Each string starts with allFormsText,
// so it has all fourteen regex forms, and the rest is letters, so no regex of
// worstBlock matches. It also checks that the seam pass runs on as many seams
// as maxSeamBytes allows.
func worstSchema(tb testing.TB, n int) string {
	tb.Helper()
	size := maxSchemaMatchBytes / n
	strs := make([]string, n)
	for i := range strs {
		// Three letters make each string distinct: 26*26*26 > maxSchemaMatchStrings.
		id := string([]byte{byte('a' + i/676%26), byte('a' + i/26%26), byte('a' + i%26)})
		strs[i] = allFormsText + id + strings.Repeat("a", size-len(allFormsText)-len(id))
	}
	raw := mustJSON(tb, strs)

	got, complete := schemaStrings([]byte(raw))
	if fit, cut := schemaFit(got); !complete || cut || fit != n || len(got) != n {
		tb.Fatalf("worstSchema(%d): %d strings, %d fit, cut %v, complete %v", n, len(got), fit, cut, complete)
	}
	if forms := len(regexForms(got[0])); forms != maxRegexForms || len(got[0]) != size {
		tb.Fatalf("worstSchema(%d): string of %d bytes with %d forms, want %d bytes and %d forms",
			n, len(got[0]), forms, size, maxRegexForms)
	}

	// No string matches, so the seam pass runs until maxSeamBytes stops it.
	var strCalls, seamCalls int
	var firstSeam string
	matchSchema(raw, schemaBudget, func(s string) []Hit {
		if !strings.Contains(s, seamSep) {
			strCalls++
			return nil
		}
		if seamCalls == 0 {
			firstSeam = s
		}
		seamCalls++
		return nil
	})
	wantSeams := min(n-1, maxSeamBytes/(2*min(size, seamSideBytes)+len(seamSep)))
	if strCalls != n || seamCalls != wantSeams || len(regexForms(firstSeam)) != maxRegexForms {
		tb.Fatalf("worstSchema(%d): %d string calls, %d seam calls, first seam %d forms; want %d, %d, %d",
			n, strCalls, seamCalls, len(regexForms(firstSeam)), n, wantSeams, maxRegexForms)
	}
	return raw
}

// BenchmarkSchemaWorstCase measures the worst-case block of
// BenchmarkWorstCaseBlock, compiled for the schema target, on a schema that
// fills the caps of schemaFit. Each string has the fourteen regex forms. No string
// matches, so the seam pass also runs until maxSeamBytes stops it. Three
// shapes fill the byte cap:
//
//   - 4096 strings of 32 bytes: they also fill maxSchemaMatchStrings, so this
//     shape has the most match calls (4096 strings and 1365 seams);
//   - 256 strings of 512 bytes: each seam is 544 bytes, the longest, so this
//     shape has the most seam bytes (240 seams);
//   - 4 strings of 32 KiB (MaxMatchInputBytes): this shape is four times the
//     description worst case, plus only 3 seams.
//
// The JSON is complete, so the raw text is not matched. A broken schema adds
// one raw text match, at most one BenchmarkWorstCaseBlock.
//
// The seam pass reads up to maxSeamBytes more, so the cost bound of one
// schema is about twice the bound of the strings alone.
//
// Measured on 2026-10-24 on an Apple M1 Pro (go1.27.3 darwin/arm64), caps
// 128 KiB and 4096 strings, fourteen regex forms for each string, with
// -benchtime=3x, in the same run as BenchmarkWorstCaseBlock (about 10.3 s):
//
//   - 4096 strings: about 1.3 s for one Match call, about 0.13 times the
//     description worst case. Each string and seam is short, so few regex
//     threads are alive at each byte;
//   - 256 strings: about 35.1 s for one Match call, about 3.4 times the
//     description worst case;
//   - 4 strings: about 43.1 s for one Match call, about 4.2 times the
//     description worst case. This is the worst shape.
func BenchmarkSchemaWorstCase(b *testing.B) {
	m, err := Match{AnyRegex: worstBlock(b)}.CompileFor(TargetSchema)
	if err != nil {
		b.Fatalf("CompileFor() error = %v", err)
	}
	for _, n := range []int{maxSchemaMatchStrings, 256, 4} {
		raw := worstSchema(b, n)
		b.Run(fmt.Sprintf("%d strings", n), func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for b.Loop() {
				if m.Match(raw) != nil {
					b.Fatal("Match() != nil, want no match")
				}
			}
		})
	}
}

// TestMatch10MBCorrect checks that the matchers give the right result on a
// 10 MB text: the regex and keyword matchers read only the first
// MaxMatchInputBytes, and the heuristics read the full text.
func TestMatch10MBCorrect(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("builds a 10 MB text")
	}
	keywords := mustCompileMatch(t, Match{Keywords: benchKeywords})
	invisible := mustCompileMatch(t, Match{Heuristic: HeuristicInvisibleUnicode})
	maxLen := mustCompileMatch(t, Match{Heuristic: HeuristicMaxLength})
	b64 := mustCompileMatch(t, Match{Heuristic: HeuristicBase64Blob})
	mixed := mustCompileMatch(t, Match{Heuristic: HeuristicMixedScript})

	const early = "ignore previous" // planted in the first KiB
	const late = "id_rsa"           // planted after the cap
	earlyHit := fmt.Sprintf("keywords[%d] matched", slices.Index(benchKeywords, early))
	lateHit := fmt.Sprintf("keywords[%d] matched", slices.Index(benchKeywords, late))
	filler := benchText(benchTextSize, 0)
	zwspAt := len(filler) - 100
	for !utf8.RuneStart(filler[zwspAt]) {
		zwspAt--
	}
	lateAt := MaxMatchInputBytes + 100
	for !utf8.RuneStart(filler[lateAt]) {
		lateAt++
	}
	text := filler[:100] + " " + early + " " +
		filler[100:lateAt] + " " + late + " " +
		filler[lateAt:zwspAt] + "\u200b" + filler[zwspAt:]
	// The planted text before zwspAt moves it.
	zwspAt += len(early) + len(late) + 4

	t.Run("keyword in the first KiB is found, keyword after the cap is not", func(t *testing.T) {
		t.Parallel()
		got := keywords.Match(text)
		want := []Hit{{Offset: -1, Detail: earlyHit}}
		if len(got) != 1 || got[0] != want[0] {
			t.Errorf("keywords.Match() = %v, want %v", got, want)
		}
		// The late keyword alone is found when it is inside the cap.
		if got := keywords.Match(late); len(got) != 1 || got[0].Detail != lateHit {
			t.Errorf("keywords.Match(%q) = %v, want %q", late, got, lateHit)
		}
	})

	t.Run("invisible_unicode finds the ZWSP near the end", func(t *testing.T) {
		t.Parallel()
		if text[zwspAt:zwspAt+3] != "\u200b" {
			t.Fatalf("test setup: no ZWSP at offset %d", zwspAt)
		}
		got := invisible.Match(text)
		want := Hit{Offset: zwspAt, Detail: fmt.Sprintf("U+200B at offset %d", zwspAt)}
		if len(got) != 1 || got[0] != want {
			t.Errorf("invisible.Match() = %v, want [%v]", got, want)
		}
	})

	t.Run("max_length hits at rune 4096", func(t *testing.T) {
		t.Parallel()
		got := maxLen.Match(text)
		// The first 4096 runes are in the first 4*4096 bytes.
		wantOffset := len(string([]rune(text[:4*4096])[:4096]))
		wantCount := fmt.Sprint(utf8.RuneCountInString(text))
		if len(got) != 1 || got[0].Offset != wantOffset || !strings.Contains(got[0].Detail, wantCount) {
			t.Errorf("maxLen.Match() = %v, want offset %d and count %s", got, wantOffset, wantCount)
		}
	})

	t.Run("base64_blob does not flag the filler", func(t *testing.T) {
		t.Parallel()
		if got := b64.Match(text); got != nil {
			t.Errorf("b64.Match() = %v, want nil", got)
		}
	})

	t.Run("mixed_script does not flag the filler", func(t *testing.T) {
		t.Parallel()
		if got := mixed.Match(text); got != nil {
			t.Errorf("mixed.Match() = %v, want nil", got)
		}
	})
}
