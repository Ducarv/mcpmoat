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
// the three heuristics with their defaults.
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
// engine must do for one target text (#35).
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
	if _, err := (Match{AnyRegex: list}).Compile(); err != nil {
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
	m, err := Match{AnyRegex: worstBlock(b)}.Compile()
	if err != nil {
		b.Fatalf("Compile() error = %v", err)
	}
	text := allFormsText + strings.Repeat("a", MaxMatchInputBytes-len(allFormsText))
	forms := regexForms(text)
	if len(forms) != 14 {
		b.Fatalf("len(regexForms(text)) = %d, want 14 (fourteen forms)", len(forms))
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
}
