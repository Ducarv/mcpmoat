package rules

import (
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
			// blurIL must change the tree exactly when needsBlur says so.
			work := cloneRegexp(tree)
			blurIL(work)
			if changed := !work.Equal(tree); changed != tt.want {
				t.Errorf("blurIL(%q) changed the tree = %v, want %v (tree %q)", tt.expr, changed, tt.want, work.String())
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
			if !needsBlur(c) {
				t.Fatalf("needsBlur(clone of %q) = false, want true", expr)
			}
			blurIL(c)
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
			if !needsBlur(tree) {
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
// test is not parallel, so the parallel tests of this package do not slow
// it down.
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
// caught. The test is not parallel, as TestILTwinTime, so the parallel
// tests of this package do not slow it down.
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
