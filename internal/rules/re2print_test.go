package rules

import (
	"fmt"
	"math/rand/v2"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

// Non-ASCII runes are written as Go escape sequences on purpose, so the
// source file stays pure ASCII (see normalize_test.go).

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
