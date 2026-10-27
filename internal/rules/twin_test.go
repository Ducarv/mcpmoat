package rules

import (
	"fmt"
	"math"
	"math/rand/v2"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"time"
)

// Invisible and non-ASCII runes are written as Go escape sequences on purpose,
// so the source file stays pure ASCII (see normalize_test.go).

// ilTwin returns the I/l-blind twin of re (see twinFromTree). It parses the
// pattern of re again, so the tests can get a twin from a compiled regex.
// compileRegexList passes the tree of compileRegexTree instead. re must come
// from compileRegex, so its pattern parses and is not too large.
func ilTwin(re *regexp.Regexp) *regexp.Regexp {
	tree, insts, err := progSize(re.String())
	if err != nil {
		return re // compileRegex parsed the pattern, so this does not happen
	}
	return twinFromTree(re, tree, insts)
}

// mustTwin compiles expr as compileRegex does and returns it and its twin.
func mustTwin(tb testing.TB, expr string) (re, twin *regexp.Regexp) {
	tb.Helper()
	re, _, err := compileRegex("any_regex[0]", expr)
	if err != nil {
		tb.Fatalf("compileRegex(%q) error = %v", expr, err)
	}
	return re, ilTwin(re)
}

func TestILTwin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		expr     string
		match    []string // the twin must match each one
		noMatch  []string // the twin must not match any one
		wantSame bool     // ilTwin returns re itself
	}{
		{name: "literal I", expr: `Ix`, match: []string{"Ix", "lx"}, noMatch: []string{"ix", "Lx", "1x"}},
		{name: "literal l", expr: `al`, match: []string{"al", "aI"}, noMatch: []string{"ai", "aL", "a1"}},
		{
			name: "fold ignore", expr: `(?i)ignore`,
			match:   []string{"ignore", "Ignore", "IGNORE", "lgnore", "Lgnore"},
			noMatch: []string{"gnore", "jgnore", "1gnore", "\u0131gnore"},
		},
		{name: "fold all", expr: `(?i)all`, match: []string{"all", "ALL", "aII", "aIl", "aiL"}, noMatch: []string{"a1l", "a|l"}},
		{name: "class il", expr: `[il]x`, match: []string{"ix", "lx", "Ix"}, noMatch: []string{"Lx"}},
		{name: "fold class l", expr: `(?i)[l]x`, match: []string{"lx", "Lx", "Ix", "iX"}, noMatch: []string{"1x"}},
		{name: "case-sensitive i stays", expr: `ignore`, match: []string{"ignore"}, noMatch: []string{"lgnore", "Ignore"}, wantSame: true},
		{name: "case-sensitive L stays", expr: `Lx`, match: []string{"Lx"}, noMatch: []string{"Ix", "lx", "ix"}, wantSame: true},
		{name: "class Il has both", expr: `[Il]x`, match: []string{"Ix", "lx"}, noMatch: []string{"ix"}, wantSame: true},
		{name: "fold class il has all four", expr: `(?i)[il]x`, match: []string{"Ix", "Lx"}, wantSame: true},
		{name: "range A-Z stays", expr: `[A-Z]x`, match: []string{"Ix"}, noMatch: []string{"lx"}, wantSame: true},
		{name: "range a-z stays", expr: `[a-z]x`, match: []string{"lx"}, noMatch: []string{"Ix"}, wantSame: true},
		{name: "word class stays", expr: `\wx`, match: []string{"Ix", "lx"}, wantSame: true},
		{name: "letter class stays", expr: `\pLx`, match: []string{"Ix", "lx"}, wantSame: true},
		{name: "negated class stays", expr: `[^a]x`, match: []string{"Ix", "lx"}, noMatch: []string{"ax"}, wantSame: true},
		{name: "negated I stays", expr: `[^I]x`, match: []string{"lx"}, noMatch: []string{"Ix"}, wantSame: true},
		{name: "word edge", expr: `\bIgnore\b`, match: []string{"Ignore", "lgnore now"}, noMatch: []string{"xlgnore", "lgnores"}},
		{name: "alternation", expr: `Ia|xb`, match: []string{"Ia", "la", "xb"}, noMatch: []string{"ia", "xa"}},
		{name: "repetition", expr: `a[il]{2}`, match: []string{"ail", "aII", "aIl", "ali"}, noMatch: []string{"aLL", "ai"}},
		{name: "fold group inside", expr: `x(?i:l)y`, match: []string{"xly", "xLy", "xIy", "xiy"}, noMatch: []string{"Xly", "xlY"}},
		{name: "fold group before", expr: `(?i:a)l`, match: []string{"al", "Al", "AI"}, noMatch: []string{"ai", "AL"}},
		{name: "anchors", expr: `^Il$`, match: []string{"Il", "lI", "II", "ll"}, noMatch: []string{" Il", "Il ", "iL"}},
		{name: "no I or l", expr: `(?i)foo\s+bar`, match: []string{"FOO bar"}, noMatch: []string{"fo bar"}, wantSame: true},
		{
			// The twin (?:[Il]a|[Il]a) parses again to [Il]a, a smaller
			// program, so the exact check fails. It is a fixpoint, so the
			// fixpoint rule of twinPattern keeps it.
			name: "fixpoint join", expr: `Ia|la`, match: []string{"Ia", "la"}, noMatch: []string{"ia", "La"},
		},
		{
			// Each \pL prints to about 4 KiB, so the twin pattern is over
			// maxTwinPatternBytes and printRE2 fails: no twin, and "I" does
			// not match the "l".
			name: "too long to print", expr: `(?i)l` + strings.Repeat(`\pL`, 20),
			match:    []string{"l" + strings.Repeat("a", 20), "L" + strings.Repeat("a", 20)},
			noMatch:  []string{"I" + strings.Repeat("a", 20), "i" + strings.Repeat("a", 20)},
			wantSame: true,
		},
		// The narrow-range rule of blurClass: a class that holds "l" but not
		// all of a-z, or "I" but not all of A-Z, gets both letters.
		{name: "range k-l", expr: `[kl]ey`, match: []string{"key", "ley", "Iey"}, noMatch: []string{"iey", "Ley"}},
		{name: "range h-m", expr: `[h-m]x`, match: []string{"hx", "lx", "Ix"}, noMatch: []string{"Lx", "nx"}},
		{name: "range b-z", expr: `[b-z]x`, match: []string{"bx", "lx", "Ix"}, noMatch: []string{"ax", "Lx"}},
		{name: "range H-M", expr: `[H-M]x`, match: []string{"Ix", "lx"}, noMatch: []string{"ix", "Nx"}},
		{
			// The parser factors talk|tall to tal[kl]; under (?i) the class is
			// [KLkl] and U+212A (Kelvin sign).
			name: "fold factored talk tall", expr: `(?i)\b(?:talk|tall)\b`,
			match:   []string{"talk", "tall", "taIk", "TAlL", "taiI", "taLK"},
			noMatch: []string{"tak", "tal1", "talks"},
		},
		{name: "letters and digits stay", expr: `[A-Za-z0-9]x`, match: []string{"Ix", "lx", "0x"}, noMatch: []string{"_x"}, wantSame: true},
		{name: "negated l stays", expr: `[^l]x`, match: []string{"Ix", "ax"}, noMatch: []string{"lx"}, wantSame: true},
		{name: "negated l at the end stays", expr: `x[^l]`, match: []string{"xI", "xa"}, noMatch: []string{"xl"}, wantSame: true},
		{
			// The camelCase part of MOAT-T3-001: [A-Z] must not match "l".
			name: "camelCase class stays", expr: `[a-z][a-z0-9]+[A-Z]`,
			match: []string{"callI", "fooBar"}, noMatch: []string{"call", "all"}, wantSame: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			re, twin := mustTwin(t, tt.expr)
			if same := twin == re; same != tt.wantSame {
				t.Errorf("ilTwin(%q) same as re = %v, want %v (twin %q)", tt.expr, same, tt.wantSame, twin)
			}
			for _, s := range tt.match {
				if !twin.MatchString(s) {
					t.Errorf("twin %q of %q does not match %q, want match", twin, tt.expr, s)
				}
			}
			for _, s := range tt.noMatch {
				if twin.MatchString(s) {
					t.Errorf("twin %q of %q matches %q, want no match", twin, tt.expr, s)
				}
			}
			if got, want := progInsts(t, twin.String()), progInsts(t, re.String()); got > want {
				t.Errorf("twin %q has %d instructions, want at most %d", twin, got, want)
			}
		})
	}
}

func TestBlurILReportsChange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		expr string
		want bool
	}{
		{expr: `Ix`, want: true},
		{expr: `al`, want: true},
		{expr: `(?i)i`, want: true},
		{expr: `(?i)L`, want: true},
		{expr: `[il]`, want: true},
		{expr: `x(?:y|l)+`, want: true},
		{expr: `ignore`, want: false},
		{expr: `L`, want: false},
		{expr: `[Il]`, want: false},
		{expr: `(?i)[il]`, want: false},
		{expr: `[A-Z][a-z]\w\pL[^a]`, want: false},
		{expr: `(?i)\bfoo\b`, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			t.Parallel()
			tree, err := syntax.Parse(tt.expr, syntax.Perl)
			if err != nil {
				t.Fatalf("syntax.Parse(%q) error = %v", tt.expr, err)
			}
			before := tree.String()
			if got := needsBlur(tree); got != tt.want {
				t.Errorf("needsBlur(%q) = %v, want %v", tt.expr, got, tt.want)
			}
			if tree.String() != before {
				t.Errorf("needsBlur(%q) changed the tree to %q", tt.expr, tree.String())
			}
			got := blurIL(tree)
			if got != tt.want {
				t.Errorf("blurIL(%q) = %v, want %v", tt.expr, got, tt.want)
			}
			if !got && tree.String() != before {
				t.Errorf("blurIL(%q) = false but changed the tree to %q", tt.expr, tree.String())
			}
		})
	}
}

// TestCloneRegexp checks that cloneRegexp makes a deep copy: blurIL on the
// copy does not change the original tree, at any depth. twinFromTree needs
// this, because printsSame checks the printer on the original tree.
func TestCloneRegexp(t *testing.T) {
	t.Parallel()
	tests := []string{
		`Ix`,
		`xI+`,
		`x(?:y|l)+z`,
		`Ia|la`,
		`(a)(?P<n>Il)`,
		`(?:(?:(?:l)))`,
		`[il]{2,3}L`,
		`(?i)\b(?:fail|fall)\b`,
		`(?:a(?:b(?:c(?:Il)*)+)?)`,
	}
	for _, expr := range tests {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			tree := mustParse(t, expr)
			before := tree.String()
			c := cloneRegexp(tree)
			if !c.Equal(tree) {
				t.Fatalf("cloneRegexp(%q) = %q, want an equal tree", expr, c.String())
			}
			if !blurIL(c) {
				t.Fatalf("blurIL(clone of %q) = false, want true", expr)
			}
			if after := tree.String(); after != before {
				t.Errorf("blurIL on the clone changed the original %q to %q", before, after)
			}
			if c.Equal(tree) {
				t.Errorf("blurIL(clone of %q) did not change the clone", expr)
			}
			// twinFromTree also leaves its tree as it is.
			re := regexp.MustCompile(expr)
			_, insts, err := progSize(expr)
			if err != nil {
				t.Fatalf("progSize(%q) error = %v", expr, err)
			}
			twinFromTree(re, tree, insts)
			if after := tree.String(); after != before {
				t.Errorf("twinFromTree changed the tree of %q to %q", before, after)
			}
		})
	}
}

func TestMergeRanges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []rune
		want []rune
	}{
		{name: "empty", in: nil, want: []rune{}},
		{name: "sorts", in: []rune{'l', 'l', 'I', 'I'}, want: []rune{'I', 'I', 'l', 'l'}},
		{name: "joins touching", in: []rune{'a', 'k', 'l', 'l'}, want: []rune{'a', 'l'}},
		{name: "joins overlap", in: []rune{'a', 'z', 'l', 'l'}, want: []rune{'a', 'z'}},
		{name: "keeps gaps", in: []rune{'I', 'I', 'L', 'L', 'i', 'i', 'l', 'l'}, want: []rune{'I', 'I', 'L', 'L', 'i', 'i', 'l', 'l'}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := mergeRanges(tt.in); string(got) != string(tt.want) {
				t.Errorf("mergeRanges(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// builtinRegexMatcher is a compiled any_regex or all_regex rule of the
// built-in set.
type builtinRegexMatcher struct {
	id string
	m  *Matcher
}

// builtinRegexMatchers compiles every built-in any_regex and all_regex rule.
func builtinRegexMatchers(tb testing.TB) []builtinRegexMatcher {
	tb.Helper()
	var out []builtinRegexMatcher
	for _, r := range mustBuiltin(tb) {
		m, err := r.Match.CompileFor(r.Target)
		if err != nil {
			tb.Fatalf("%s: CompileFor() error = %v", r.ID, err)
		}
		if m.kind == kindAnyRegex || m.kind == kindAllRegex {
			out = append(out, builtinRegexMatcher{id: r.ID, m: m})
		}
	}
	if len(out) == 0 {
		tb.Fatal("no built-in any_regex or all_regex rule")
	}
	return out
}

// TestBuiltinRegexesHaveTwins catches a silent fallback of ilTwin: each
// built-in regex with an "I" or "l" to blur must get a twin of its own, and
// each twin must not be larger than its regex (the cost bound in match.go).
func TestBuiltinRegexesHaveTwins(t *testing.T) {
	t.Parallel()
	blurred := map[string]int{}
	for _, b := range builtinRegexMatchers(t) {
		if len(b.m.twins) != len(b.m.regexps) {
			t.Fatalf("%s: %d twins for %d regexes", b.id, len(b.m.twins), len(b.m.regexps))
		}
		for i, re := range b.m.regexps {
			twin := b.m.twins[i]
			if got, want := progInsts(t, twin.String()), progInsts(t, re.String()); got > want {
				t.Errorf("%s regex %d: twin has %d instructions, want at most %d", b.id, i, got, want)
			}
			tree, err := syntax.Parse(re.String(), syntax.Perl)
			if err != nil {
				t.Fatalf("%s regex %d: syntax.Parse error = %v", b.id, i, err)
			}
			if !blurIL(tree) {
				continue // nothing to blur, so the twin is re itself
			}
			blurred[b.id]++
			if twin == re {
				t.Errorf("%s regex %d: ilTwin fell back to the original regex %q", b.id, i, re)
			}
		}
	}
	// The override rules hold "ignore" and "all" in every pattern.
	for _, id := range []string{"MOAT-T1-001", "MOAT-T1-009"} {
		if blurred[id] < 5 {
			t.Errorf("%s: %d regexes with an I or l to blur, want at least 5", id, blurred[id])
		}
	}
}

// ilTokens are the pieces of the random texts of TestILTwinSuperset: words
// of the built-in rules, the four letters that the twin reads, and spaces
// and marks between words.
var ilTokens = []string{
	"ignore", "all", "previous", "instructions", "disregard", "forget", "prior",
	"before", "using", "this", "tool", "you", "must", "always", "call", "first",
	"do", "not", "tell", "the", "user", "hide", "from", "without", "telling",
	"file", "list", "id_rsa", "~/.ssh", ".env", "a", "x", "Il", "ll", "II",
	"I", "l", "i", "L", "I", "l", " ", " ", " ", "\n", "-", "_", "*", ".", ",", "'",
}

// swapIL replaces each "i", "I", "l" and "L" in s with one of the four,
// picked at random, so a should_match text gets many I/l readings.
func swapIL(rng *rand.Rand, s string) string {
	letters := []rune("iIlL")
	b := []rune(s)
	for i, r := range b {
		if strings.ContainsRune("iIlL", r) && rng.IntN(2) == 0 {
			b[i] = letters[rng.IntN(len(letters))]
		}
	}
	return string(b)
}

// TestILTwinSuperset checks on random texts that the twin of each built-in
// regex matches every text that the regex matches. The texts are random
// token lists and the rule cases with their I/l letters swapped. The seed is
// fixed, so a failure repeats.
func TestILTwinSuperset(t *testing.T) {
	t.Parallel()
	matchers := builtinRegexMatchers(t)
	var cases []string
	for _, r := range mustBuiltin(t) {
		for _, c := range append(r.ShouldMatch, r.ShouldNotMatch...) {
			if len(c.Text) <= 512 {
				cases = append(cases, c.Text)
			}
		}
	}
	rng := rand.New(rand.NewPCG(149, 1)) //nolint:gosec // G404: fixed seed for a reproducible test, not for security
	const n = 5000
	var origHits, twinOnly int
	for k := range n {
		var text string
		if k%2 == 0 {
			var sb strings.Builder
			for range 1 + rng.IntN(10) {
				sb.WriteString(ilTokens[rng.IntN(len(ilTokens))])
			}
			text = sb.String()
		} else {
			text = swapIL(rng, cases[rng.IntN(len(cases))])
		}
		for _, b := range matchers {
			for i, re := range b.m.regexps {
				orig, twin := re.MatchString(text), b.m.twins[i].MatchString(text)
				if orig && !twin {
					t.Fatalf("%s regex %d matches %+q, but its twin does not", b.id, i, text)
				}
				if orig {
					origHits++
				} else if twin {
					twinOnly++
				}
			}
		}
	}
	// Without matches the test above checks nothing.
	if origHits < 100 || twinOnly < 100 {
		t.Errorf("original matches = %d, twin-only matches = %d, want at least 100 of each", origHits, twinOnly)
	}
}

// mustParse parses expr with the flags of regexp.Compile, or stops the test.
func mustParse(tb testing.TB, expr string) *syntax.Regexp {
	tb.Helper()
	tree, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		tb.Fatalf("syntax.Parse(%q) error = %v", expr, err)
	}
	return tree
}

// mustProg compiles tree as progSize does, or stops the test.
func mustProg(tb testing.TB, tree *syntax.Regexp) *syntax.Prog {
	tb.Helper()
	prog, err := syntax.Compile(tree.Simplify())
	if err != nil {
		tb.Fatalf("syntax.Compile(%v) error = %v", tree.Op, err)
	}
	return prog
}

// checkPrintsSameProg fails the test unless printRE2 prints tree to a
// pattern that parses to the program of tree. label names the case.
func checkPrintsSameProg(tb testing.TB, label string, tree *syntax.Regexp) string {
	tb.Helper()
	want := mustProg(tb, tree)
	text, ok := printRE2(tree)
	if !ok {
		tb.Errorf("%s: printRE2() ok = false, want true", label)
		return ""
	}
	_, got, err := parseProg(text)
	if err != nil {
		tb.Errorf("%s: printRE2() = %q does not parse: %v", label, text, err)
		return text
	}
	if !sameProg(got, want) {
		tb.Errorf("%s: printRE2() = %q has program\n%v\nwant\n%v", label, text, got, want)
	}
	return text
}

// hasOp reports whether re or a node under it has the op op.
func hasOp(re *syntax.Regexp, op syntax.Op) bool {
	if re.Op == op {
		return true
	}
	for _, sub := range re.Sub {
		if hasOp(sub, op) {
			return true
		}
	}
	return false
}

func TestPrintRE2Ops(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		expr string
		op   syntax.Op // the parse tree of expr holds this op
		want string
	}{
		{name: "literal", expr: `abc`, op: syntax.OpLiteral, want: `abc`},
		// The parser keeps the smallest rune of each fold orbit, here the
		// uppercase letter.
		{name: "fold literal", expr: `(?i)ab`, op: syntax.OpLiteral, want: `(?i:AB)`},
		{name: "fold-less literal comma", expr: `(?i),`, op: syntax.OpLiteral, want: `(?i:\,)`},
		{name: "fold-less literal digits", expr: `(?i)1-2`, op: syntax.OpLiteral, want: `(?i:1\-2)`},
		{name: "fold literal with a comma", expr: `(?i)a,`, op: syntax.OpLiteral, want: `(?i:A\,)`},
		{name: "non-ASCII literal", expr: `caf\x{e9}`, op: syntax.OpLiteral, want: "caf\u00e9"},
		{name: "control and DEL", expr: `\x01\x7f`, op: syntax.OpLiteral, want: `\x{1}\x{7f}`},
		{name: "underscore and space", expr: `_ `, op: syntax.OpLiteral, want: `\_\ `},
		{name: "surrogate", expr: `\x{d800}`, op: syntax.OpLiteral, want: `\x{d800}`},
		{name: "class range", expr: `[a-c]`, op: syntax.OpCharClass, want: `[a-c]`},
		{name: "class single runes", expr: `[ace]`, op: syntax.OpCharClass, want: `[ace]`},
		{name: "class special runes", expr: `[\]\-^]`, op: syntax.OpCharClass, want: `[\-\]-\^]`},
		{name: "fold class", expr: `(?i)[k]`, op: syntax.OpCharClass, want: "[Kk\u212a]"},
		{name: "negated class", expr: `[^a]`, op: syntax.OpCharClass, want: "[\\x{0}-\\`b-\U0010ffff]"},
		{name: "empty class", expr: `[^\x00-\x{10FFFF}]`, op: syntax.OpCharClass, want: `[^\x00-\x{10FFFF}]`},
		{name: "any rune but newline", expr: `.`, op: syntax.OpAnyCharNotNL, want: `(?-s:.)`},
		{name: "any rune", expr: `(?s).`, op: syntax.OpAnyChar, want: `(?s:.)`},
		{name: "begin text", expr: `^a`, op: syntax.OpBeginText, want: `\Aa`},
		{name: "end text", expr: `a$`, op: syntax.OpEndText, want: `a\z`},
		{name: "begin text escape", expr: `\Aa`, op: syntax.OpBeginText, want: `\Aa`},
		{name: "end text escape", expr: `a\z`, op: syntax.OpEndText, want: `a\z`},
		{name: "begin line", expr: `(?m)^a`, op: syntax.OpBeginLine, want: `(?m:^)a`},
		{name: "end line", expr: `(?m)a$`, op: syntax.OpEndLine, want: `a(?m:$)`},
		{name: "word boundary", expr: `\ba\b`, op: syntax.OpWordBoundary, want: `\ba\b`},
		{name: "no word boundary", expr: `\Ba`, op: syntax.OpNoWordBoundary, want: `\Ba`},
		{name: "capture", expr: `(a)`, op: syntax.OpCapture, want: `(a)`},
		{name: "named capture", expr: `(?P<name>a)`, op: syntax.OpCapture, want: `(?P<name>a)`},
		{name: "named capture new syntax", expr: `(?<n_1>a)`, op: syntax.OpCapture, want: `(?P<n_1>a)`},
		{name: "two captures keep order", expr: `(a)(?P<x>b)`, op: syntax.OpCapture, want: `(a)(?P<x>b)`},
		{name: "star", expr: `a*`, op: syntax.OpStar, want: `(?:a)*`},
		{name: "plus", expr: `a+`, op: syntax.OpPlus, want: `(?:a)+`},
		{name: "quest", expr: `a?`, op: syntax.OpQuest, want: `(?:a)?`},
		{name: "non-greedy star", expr: `a*?`, op: syntax.OpStar, want: `(?:a)*?`},
		{name: "non-greedy plus", expr: `a+?`, op: syntax.OpPlus, want: `(?:a)+?`},
		{name: "non-greedy quest", expr: `a??`, op: syntax.OpQuest, want: `(?:a)??`},
		{name: "ungreedy flag", expr: `(?U)a*`, op: syntax.OpStar, want: `(?:a)*?`},
		{name: "ungreedy flag and question mark", expr: `(?U)a*?`, op: syntax.OpStar, want: `(?:a)*`},
		{name: "repeat n", expr: `a{3}`, op: syntax.OpRepeat, want: `(?:a){3}`},
		{name: "repeat n or more", expr: `a{3,}`, op: syntax.OpRepeat, want: `(?:a){3,}`},
		{name: "repeat n to m", expr: `a{2,5}`, op: syntax.OpRepeat, want: `(?:a){2,5}`},
		{name: "non-greedy repeat n to m", expr: `a{2,5}?`, op: syntax.OpRepeat, want: `(?:a){2,5}?`},
		{name: "repeat zero", expr: `ba{0}`, op: syntax.OpRepeat, want: `b(?:a){0}`},
		{name: "repeat of a group", expr: `(?:ab){2}`, op: syntax.OpRepeat, want: `(?:ab){2}`},
		{name: "concat", expr: `ab.`, op: syntax.OpConcat, want: `ab(?-s:.)`},
		{name: "alternate", expr: `ab|cd`, op: syntax.OpAlternate, want: `(?:ab|cd)`},
		{name: "alternate with empty", expr: `a|`, op: syntax.OpAlternate, want: `(?:a|(?:))`},
		// The second "@" has the FoldCase flag and the first does not, so the
		// parser does not join them. The printed pattern keeps the flag
		// (found by FuzzILTwin).
		{name: "fold flag on a fold-less prefix", expr: `@x(?i)|@\b`, op: syntax.OpAlternate, want: `(?:\@x|(?i:\@)\b)`},
		{name: "empty match", expr: ``, op: syntax.OpEmptyMatch, want: `(?:)`},
		{name: "empty group", expr: `(?:)`, op: syntax.OpEmptyMatch, want: `(?:)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tree := mustParse(t, tt.expr)
			if !hasOp(tree, tt.op) {
				t.Fatalf("parse tree of %q has no %v node", tt.expr, tt.op)
			}
			if got := checkPrintsSameProg(t, tt.expr, tree); got != tt.want {
				t.Errorf("printRE2(%q) = %q, want %q", tt.expr, got, tt.want)
			}
		})
	}
}

// TestPrintRE2Nodes prints nodes that the parser does not build from a
// pattern, but that are valid.
func TestPrintRE2Nodes(t *testing.T) {
	t.Parallel()
	lit := func(s string) *syntax.Regexp { return &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune(s)} }
	tests := []struct {
		name string
		re   *syntax.Regexp
		want string
	}{
		{name: "empty class", re: &syntax.Regexp{Op: syntax.OpCharClass}, want: `[^\x00-\x{10FFFF}]`},
		{name: "empty concat", re: &syntax.Regexp{Op: syntax.OpConcat}, want: `(?:)`},
		{name: "concat of literals", re: &syntax.Regexp{Op: syntax.OpConcat, Sub: []*syntax.Regexp{lit("a"), lit("b")}}, want: `ab`},
		{name: "fold-less fold literal", re: &syntax.Regexp{Op: syntax.OpLiteral, Flags: syntax.FoldCase, Rune: []rune("1,_")}, want: `(?i:1\,\_)`},
		{name: "max rune", re: lit("\U0010ffff"), want: "\U0010ffff"},
		{name: "NUL", re: lit("\x00"), want: `\x{0}`},
		{name: "literal at the cap", re: lit(strings.Repeat("a", maxTwinPatternBytes)), want: strings.Repeat("a", maxTwinPatternBytes)},
		// The next two shapes come only from blurIL: blurLiteral gives each
		// class the flags of its literal, so under (?i) a class has the
		// FoldCase flag, and a literal inside a concat becomes a concat. The
		// fixpoint path of twinPattern does not check the program of the
		// blurred tree, so printRE2 must print these shapes right.
		{
			name: "fold class",
			re:   &syntax.Regexp{Op: syntax.OpCharClass, Flags: syntax.FoldCase | syntax.PerlX, Rune: []rune{'I', 'I', 'L', 'L', 'i', 'i', 'l', 'l'}},
			want: `[ILil]`,
		},
		{
			name: "concat in a concat",
			re: &syntax.Regexp{Op: syntax.OpConcat, Sub: []*syntax.Regexp{
				lit("x"),
				{Op: syntax.OpConcat, Sub: []*syntax.Regexp{
					{Op: syntax.OpCharClass, Rune: []rune{'I', 'I', 'l', 'l'}},
					lit("a"),
				}},
				lit("b"),
			}},
			want: `x[Il]ab`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := checkPrintsSameProg(t, tt.name, tt.re); got != tt.want {
				t.Errorf("printRE2() = %q, want %q", got, tt.want)
			}
		})
	}
	// OpNoMatch compiles to a fail instruction, and the empty class that
	// printRE2 writes compiles to a rune instruction with no runes. Both
	// match nothing, but the programs differ, so a tree with OpNoMatch gets
	// no twin. The parser does not build OpNoMatch from a pattern.
	t.Run("no match", func(t *testing.T) {
		t.Parallel()
		got, ok := printRE2(&syntax.Regexp{Op: syntax.OpNoMatch})
		if want := `[^\x00-\x{10FFFF}]`; !ok || got != want {
			t.Fatalf("printRE2(OpNoMatch) = %q, %v, want %q, true", got, ok, want)
		}
		re := regexp.MustCompile(got)
		for _, s := range []string{"", "a", "\x00", "\U0010ffff"} {
			if re.MatchString(s) {
				t.Errorf("printRE2(OpNoMatch) = %q matches %q, want no match", got, s)
			}
		}
	})
}

func TestPrintRE2Fails(t *testing.T) {
	t.Parallel()
	lit := &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune("a")}
	bad := &syntax.Regexp{Op: syntax.Op(128)} // opPseudo of the parser: not a node op
	sub1 := func(op syntax.Op, sub *syntax.Regexp) *syntax.Regexp {
		return &syntax.Regexp{Op: op, Sub: []*syntax.Regexp{sub}, Min: 1, Max: 2}
	}
	rep := func(lo, hi int) *syntax.Regexp {
		return &syntax.Regexp{Op: syntax.OpRepeat, Sub: []*syntax.Regexp{lit}, Min: lo, Max: hi}
	}
	capture := func(name string) *syntax.Regexp {
		return &syntax.Regexp{Op: syntax.OpCapture, Name: name, Sub: []*syntax.Regexp{lit}}
	}
	class := func(r ...rune) *syntax.Regexp { return &syntax.Regexp{Op: syntax.OpCharClass, Rune: r} }
	tests := []struct {
		name string
		re   *syntax.Regexp
	}{
		{name: "unknown op", re: bad},
		{name: "unknown op number", re: &syntax.Regexp{Op: syntax.Op(99)}},
		{name: "unknown op in concat", re: &syntax.Regexp{Op: syntax.OpConcat, Sub: []*syntax.Regexp{lit, bad}}},
		{name: "unknown op in alternate", re: &syntax.Regexp{Op: syntax.OpAlternate, Sub: []*syntax.Regexp{lit, bad}}},
		{name: "unknown op in capture", re: sub1(syntax.OpCapture, bad)},
		{name: "unknown op in star", re: sub1(syntax.OpStar, bad)},
		{name: "unknown op in repeat", re: sub1(syntax.OpRepeat, bad)},
		{name: "alternate with no sub", re: &syntax.Regexp{Op: syntax.OpAlternate}},
		{name: "capture with no sub", re: &syntax.Regexp{Op: syntax.OpCapture}},
		{name: "capture with two subs", re: &syntax.Regexp{Op: syntax.OpCapture, Sub: []*syntax.Regexp{lit, lit}}},
		{name: "star with no sub", re: &syntax.Regexp{Op: syntax.OpStar}},
		{name: "plus with two subs", re: &syntax.Regexp{Op: syntax.OpPlus, Sub: []*syntax.Regexp{lit, lit}}},
		{name: "repeat with no sub", re: &syntax.Regexp{Op: syntax.OpRepeat, Min: 1, Max: 1}},
		{name: "empty literal", re: &syntax.Regexp{Op: syntax.OpLiteral}},
		{name: "odd class", re: class('a')},
		{name: "odd class of three", re: class('a', 'b', 'c')},
		{name: "class lo over hi", re: class('z', 'a')},
		{name: "second range lo over hi", re: class('a', 'b', 'z', 'x')},
		{name: "repeat min below zero", re: rep(-1, 2)},
		{name: "repeat max below minus one", re: rep(1, -2)},
		{name: "repeat max below min", re: rep(3, 2)},
		{name: "capture name with a dash", re: capture("a-b")},
		{name: "capture name with a space", re: capture("a b")},
		{name: "capture name with a close", re: capture("a>b")},
		{name: "capture name not ASCII", re: capture("\u00e9")},
		{name: "literal rune below zero", re: &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{-1}}},
		{name: "literal rune over the max", re: &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{0x110000}}},
		{name: "class lo over the max", re: class(0x110000, 0x110001)},
		{name: "class hi over the max", re: class('a', 0x110000)},
		{name: "literal over the cap", re: &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune(strings.Repeat("a", maxTwinPatternBytes+1))}},
		{name: "classes over the cap", re: mustParse(t, strings.Repeat(`\pL`, 20))},
		{name: "fold class over the cap", re: mustParse(t, `(?i)l`+strings.Repeat(`\pL`, 340))},
		// A class of one rune and its case pair: the parser reads a printed
		// [Ii] as the literal (?i:I), which has another program. The
		// parser keeps such a class only in an alternation (found by
		// FuzzILTwin).
		{name: "fold pair class", re: class('I', 'I', 'i', 'i')},
		{name: "fold pair range", re: class(0x100, 0x101)},
		{name: "fold pair class in an alternation", re: mustParse(t, `I||i|I`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, ok := printRE2(tt.re); ok || got != "" {
				t.Errorf("printRE2() = %q, %v, want \"\", false", got, ok)
			}
		})
	}
}

// printRE2Corpus are patterns for TestPrintRE2Corpus, next to the built-in
// regexes: flags in groups, nested repeats, classes with many ranges and
// patterns that the parser factors.
var printRE2Corpus = []string{
	`(?i)ignore`, `(?i)\ball\b`, `Ix`, `a[il]{2}`, `x(?i:l)y`, `Ia|la`, `[A-Z]l`, `^Il$`,
	`(?i)\b(?:fail|fall)\b`, `(?i)(?:ignore|lgnore)`, `(?:Ix|lx|ix)`, `(?i)\b(?:talk|tall)\b`,
	`(?i)foo\s+bar`, `\bIgnore\b`, `[kl]ey`, `[h-m]`, `[b-z]`, `[^l]`, `x[^l]`, `\w+\pL\PL`,
	`\d\D\s\S\w\W`, `[[:alpha:]][[:^digit:]]`, `\p{Greek}\P{Han}`, `(?i)\p{Lu}`, `[\p{L}\d_-]`,
	`(?s)a.b`, `(?m)^a$`, `(?ms)^.+$`, `(?U)a+b*?c{2,3}`, `(?i)a(?-i)b(?i)c`, `(?i:a(?-i:b)c)`,
	`a{0,}`, `a{1,1}`, `a{0,1}`, `(?:a{2}){3}`, `(?:a*)*`, `(?:a+)?`, `(a|b)*c`, `(?:(a)|(b))+`,
	`abc|abd|abe`, `a|ab|abc`, `foo|foobar|fo`, `x|y|z`, `[ab]|[cd]|e`, `(?i)k|K|\x{212a}`,
	`\x{0}\x{7f}\x{80}\x{ffff}\x{10000}\x{10ffff}`, `[\x00-\x1f\x7f]`, `[\x{d7ff}-\x{e000}]`,
	`[\\\]\[\-\^]`, `\.\*\+\?\(\)\{\}\|\$\^`, `[ \t\n\r\f\v]`, `\Q[*.]\E`, "caf\u00e9|na\u00efve",
	"[\u0400-\u04ff]+", `\x{1d5a8}\x{1d5c5}`, `(?i)\x{130}\x{131}`, `(?i)\x{3a3}`, `(?i)st`,
	`(?P<a>x)(?P<b>y)(z)`, `(?:)a`, `a(?:|b)`, `\A\z`, `\b\B`, `(?m)^$`, `[^\n]`, `[^\x00-\x{10FFFF}]a|b`,
	`(?i)(?:disregard|forget|ignore)\s+(?:all\s+)?(?:previous|prior)\s+instructions`,
	`~/\.ssh`, `(?i)id_rsa`, `[^\w.]\.env`, `(?i)\bdo\s+not\s+tell\s+the\s+user\b`,
}

// randomPatterns returns n patterns made of random tokens that parse, built
// with a fixed seed so a failure repeats.
func randomPatterns(tb testing.TB, n int) []string {
	tb.Helper()
	tokens := []string{
		"a", "b", "I", "l", "i", "L", "_", ",", ".", " ", "\u00e9", `\b`, `\B`, `\s`, `\S`, `\d`, `\w`,
		`\pL`, "[a-z]", "[kl]", "[^l]", "[A-Z0-9]", `[\x{0}-\x{7f}]`, "(?i)", "(?-i)", "(?s)", "(?m)",
		"(?U)", "(?i:", "(?:", "(", "(?P<n>", ")", ")", "|", "|", "*", "+", "?", "*?", "{2}", "{1,3}",
		"{2,}", "^", "$", `\A`, `\z`,
	}
	rng := rand.New(rand.NewPCG(149, 2)) //nolint:gosec // G404: fixed seed for a reproducible test, not for security
	var out []string
	for len(out) < n {
		var sb strings.Builder
		for range 1 + rng.IntN(12) {
			sb.WriteString(tokens[rng.IntN(len(tokens))])
		}
		if _, err := syntax.Parse(sb.String(), syntax.Perl); err == nil {
			out = append(out, sb.String())
		}
	}
	return out
}

// builtinRegexSources returns the pattern of every compiled regex of the
// built-in rules: any_regex, all_regex and the regexes built from keywords.
func builtinRegexSources(tb testing.TB) []string {
	tb.Helper()
	var out []string
	for _, r := range mustBuiltin(tb) {
		m, err := r.Match.CompileFor(r.Target)
		if err != nil {
			tb.Fatalf("%s: CompileFor() error = %v", r.ID, err)
		}
		for _, re := range m.regexps {
			out = append(out, re.String())
		}
	}
	return out
}

// TestPrintRE2Corpus checks that printRE2 prints each pattern of a corpus
// to a pattern with the same program, and that a second print of the new
// tree gives the same program again (the text can differ: [\s\S] prints
// as a class of all runes, which parses to (?s:.)).
func TestPrintRE2Corpus(t *testing.T) {
	t.Parallel()
	builtin := builtinRegexSources(t)
	if len(builtin) < 50 {
		t.Fatalf("%d built-in regexes, want at least 50", len(builtin))
	}
	corpus := append(append(builtin, printRE2Corpus...), randomPatterns(t, 400)...)
	for i, expr := range corpus {
		label := fmt.Sprintf("corpus[%d] %q", i, expr)
		text := checkPrintsSameProg(t, label, mustParse(t, expr))
		if text == "" {
			continue
		}
		checkPrintsSameProg(t, label+" printed again", mustParse(t, text))
	}
}

// TestILTwinFixpoint checks the patterns in which blurIL makes two
// alternatives equal, so the twin passes only through the fixpoint rule of
// twinPattern. Each gets a twin, and the twin matches every random text that
// the pattern matches.
func TestILTwinFixpoint(t *testing.T) {
	t.Parallel()
	tokens := []string{
		"I", "l", "i", "L", "a", "x", "X", "fa", "gnore", "GNORE", " ", "-", "1",
		"Ia", "la", "Ix", "lx", "ix", "fail", "FALL", "ignore", "lgnore",
	}
	tests := []struct {
		expr  string
		match []string // the twin must match each one
	}{
		{expr: `Ia|la`, match: []string{"Ia", "la"}},
		{expr: `(?i)\b(?:fail|fall)\b`, match: []string{"fail", "FALL", "faIl", "faiL", "fall ", " faII"}},
		{expr: `(?i)(?:ignore|lgnore)`, match: []string{"ignore", "Ignore", "lgnore", "LGNORE"}},
		{expr: `(?:Ix|lx|ix)`, match: []string{"Ix", "lx", "ix"}},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			t.Parallel()
			re, twin := mustTwin(t, tt.expr)
			if twin == re {
				t.Fatalf("ilTwin(%q) fell back to the original regex", tt.expr)
			}
			// The exact check fails for these patterns: the fixpoint rule kept
			// the twin.
			tree := mustParse(t, tt.expr)
			blurIL(tree)
			_, got, err := parseProg(twin.String())
			if err != nil {
				t.Fatalf("twin %q does not parse: %v", twin, err)
			}
			if sameProg(got, mustProg(t, tree)) {
				t.Errorf("twin %q of %q has the program of the blurred tree, want the joined program", twin, tt.expr)
			}
			for _, s := range tt.match {
				if !twin.MatchString(s) {
					t.Errorf("twin %q of %q does not match %q, want match", twin, tt.expr, s)
				}
			}
			rng := rand.New(rand.NewPCG(149, 3)) //nolint:gosec // G404: fixed seed for a reproducible test, not for security
			hits := 0
			for range 3000 {
				var sb strings.Builder
				for range 1 + rng.IntN(6) {
					sb.WriteString(tokens[rng.IntN(len(tokens))])
				}
				s := sb.String()
				if re.MatchString(s) {
					hits++
					if !twin.MatchString(s) {
						t.Fatalf("%q matches %q, but its twin %q does not", tt.expr, s, twin)
					}
				}
			}
			if hits < 20 {
				t.Errorf("%q matched %d random texts, want at least 20", tt.expr, hits)
			}
		})
	}
}

// TestPrintRE2ParserFactoring checks patterns where printRE2 is right, but
// the parser factors the printed pattern again. The first row is the fuzz
// input in testdata/fuzz/FuzzILTwin/1ac6af9f414fe39c. The parser factors
// the alternation of expr to (?-s:.)(?:(?:)|(?-s:.)|(?-s:.)(?:(?:)|...)),
// and a parse of that printed pattern factors its inner alternation again,
// so the program gets smaller. The alternation factoring of the parser is
// not idempotent. The program of the reparse is then a fixpoint, but
// printsSame fails on the original tree, so twinPattern reports false and
// twinFromTree keeps the original regex: it fails closed and no match is
// lost.
func TestPrintRE2ParserFactoring(t *testing.T) {
	t.Parallel()
	tests := []struct {
		expr     string
		fixpoint bool // isPrintFixpoint on the reparsed tree
	}{
		{expr: ".|>|..|.6|..|..III\u0127I", fixpoint: true},
		{expr: ".|>|..|.6|..|..l", fixpoint: true},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			t.Parallel()
			tree := mustParse(t, tt.expr)
			want := mustProg(t, tree)
			text, ok := printRE2(tree)
			if !ok {
				t.Fatalf("printRE2(%q) ok = false, want true", tt.expr)
			}
			gotTree, got, err := parseProg(text)
			if err != nil {
				t.Fatalf("printRE2(%q) = %q does not parse: %v", tt.expr, text, err)
			}
			// The parser factors the printed pattern again.
			if sameProg(got, want) {
				t.Errorf("printRE2(%q) = %q has the program of the tree, want a smaller program", tt.expr, text)
			}
			if len(got.Inst) >= len(want.Inst) {
				t.Errorf("printRE2(%q) = %q has %d instructions, want fewer than %d", tt.expr, text, len(got.Inst), len(want.Inst))
			}
			if fix := isPrintFixpoint(gotTree, got); fix != tt.fixpoint {
				t.Errorf("isPrintFixpoint(%q) = %v, want %v", text, fix, tt.fixpoint)
			}
			re, insts, err := compileRegex("any_regex[0]", tt.expr)
			if err != nil {
				t.Fatalf("compileRegex(%q) error = %v", tt.expr, err)
			}
			if twin := twinFromTree(re, tree, insts); twin != re {
				t.Errorf("twinFromTree(%q) = %q, want the original regex", tt.expr, twin)
			}
		})
	}
}

// bestOf returns the shortest time of three runs of f. The shortest run is
// the least affected by other work on the machine.
func bestOf(f func()) time.Duration {
	best := time.Duration(math.MaxInt64)
	for range 3 {
		start := time.Now()
		f()
		best = min(best, time.Since(start))
	}
	return best
}

// hostileTwinPattern is a pattern of MaxPatternBytes - 1 bytes with one "l"
// to blur and 511 classes that are closed under case folding. The String
// method of syntax.Regexp takes about 2 ms for each such class, about 1 s in
// all; printRE2 takes under 1 ms.
var hostileTwinPattern = "l" + strings.Repeat(`\S`, 511)

// TestILTwinTime is a guard against a slow printer, such as a return to
// the String method of syntax.Regexp. The bounds are generous for CI. The
// test is not parallel, so other tests do not slow it down.
func TestILTwinTime(t *testing.T) {
	re, _, err := compileRegex("any_regex[0]", hostileTwinPattern)
	if err != nil {
		t.Fatalf("compileRegex() error = %v", err)
	}
	var twin *regexp.Regexp
	if d := bestOf(func() { twin = ilTwin(re) }); d > 50*time.Millisecond {
		t.Errorf("ilTwin(l + 511 x \\S) took %v, want under 50ms", d)
	}
	if twin == re {
		t.Fatal("ilTwin(l + 511 x \\S) fell back to the original regex, want a twin")
	}
	if !twin.MatchString("I" + strings.Repeat("x", 511)) {
		t.Error("twin does not match I + 511 x x, want match")
	}

	hostile := Match{AnyRegex: []string{hostileTwinPattern, hostileTwinPattern, hostileTwinPattern, hostileTwinPattern}}
	var m *Matcher
	if d := bestOf(func() { m = mustCompileMatch(t, hostile) }); d > 250*time.Millisecond {
		t.Errorf("compiling 4 x (l + 511 x \\S) took %v, want under 250ms", d)
	}
	for i, tw := range m.twins {
		if tw == m.regexps[i] {
			t.Errorf("hostile regex %d: no twin, want one", i)
		}
	}
}

// TestCompileBuiltinTime compiles every built-in rule once, as a scan does,
// under a generous bound, so a slow twin build of a built-in regex is
// caught. The test is not parallel, as TestILTwinTime.
func TestCompileBuiltinTime(t *testing.T) {
	rs := mustBuiltin(t)
	compileAll := func() {
		for _, r := range rs {
			if _, err := r.Match.CompileFor(r.Target); err != nil {
				t.Fatalf("%s: CompileFor() error = %v", r.ID, err)
			}
		}
	}
	if d := bestOf(compileAll); d > time.Second {
		t.Errorf("compiling all %d built-in rules took %v, want under 1s", len(rs), d)
	}
}
