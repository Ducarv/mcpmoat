package rules

import (
	"cmp"
	"regexp"
	"regexp/syntax"
	"slices"
	"unicode"
)

// This file builds the I/l-blind twin of a regex (see twinFromTree): blurIL
// rewrites a copy of the parse tree, and twinPattern checks the pattern that
// printRE2 (in re2print.go) writes for it. This comment is the one full
// description of the twin: why it exists, which forms it reads, what it
// costs and its limits. Other comments point here. The package doc
// (Normalization, and the limits of the confusable skeleton) has a short
// summary for rule authors, and docs/writing-rules.md has the same summary.
//
// Why. The skeleton fold reads each look-alike of "I" or "l" as one of the
// two letters (see skeletonTable). TR39 reads them all as one letter, but
// the rules need both: the "i" of ignore and the "l" of all. So with one
// fixed reading, an attacker picks the look-alike whose reading the rules do
// not expect: Cyrillic U+04CF (small palochka, read "l") + "gnore", U+01C0
// (a bare bar, read "l") + "gnore", or "a" + U+0406 U+0406 (Cyrillic
// capital I, read "I") for "all". The plain fold (foldMarks) has look-alikes
// too: fullwidth U+FF29 and U+FF4C, the roman numerals U+2160 and U+217C,
// U+2110, U+2113, the ligature U+FB02 ("fl") and many mathematical letters,
// such as the sans-serif U+1D5A8 and U+1D5C5 (two bars), fold to an ASCII
// "I" or "l".
//
// What. The twin of a regex reads ASCII "I" and "l" as one letter (see
// blurIL): a literal "I" or "l", and under (?i) also "i" and "L", matches
// both, and so does a class that names one of them, such as [il] or [kl].
// So `(?i)ignore` matches U+04CF + "gnore", U+01C0 + "gnore" and U+217C +
// "gnore", and `(?i)all` matches "a" + U+0406 U+0406 and "a" + U+FF29
// U+FF29, also when one rune is used both ways. The twin matches every text
// that the regex matches. Only any_regex and all_regex get a twin (see
// compileRegexMatcher), and it is built when the rule compiles.
//
// Where. The twin reads only the twin forms: the skeleton folds, and the
// plain folds in which a compatibility mapping made a new "I" or "l" (see
// foldAddsIL and preparedText.regexFormParts). The regex itself reads the
// other forms: the base forms and the other plain folds. A base form keeps
// each look-alike as it is, so a pattern of ASCII letters does not match it
// there, and the twin is not needed. So a plain ASCII "lgnore" still does
// not match `(?i)ignore`. On the twin forms, the twin runs in place of the
// regex, not next to it (see Matcher.matchRegex), so the number of forms
// does not change and each form is read by one regex.
//
// Cost. twinPattern keeps a twin only when its program is not larger than
// the program of the regex, so the worst-case match bound does not change.
// A pattern that starts with a literal "I" or "l" can be slower on the twin
// forms, because its twin loses the literal prefix that package regexp uses
// to search fast. No built-in rule starts this way. The twin also adds
// compile time and memory. The cost comment at the top of match.go has the
// measured numbers.
//
// The twin has these limits:
//
//   - only any_regex and all_regex get a twin. A keyword rule reads no
//     skeleton fold, and its plain folds read with the keyword as it is, so
//     a look-alike of "I" or "l" in a keyword is not read as either letter;
//   - a pattern that writes a lowercase "i" or an uppercase "L" without
//     (?i) keeps it: such a letter does not match "I" or "l" in the pattern
//     either;
//   - a class that holds all of a-z keeps its "l", and a class that holds
//     all of A-Z keeps its "I" (see blurClass). So [a-z], [A-Z], \w and \pL
//     do not change;
//   - a negated class, such as [^l], does not change (see blurClass);
//   - a pattern whose twin pattern is longer than maxTwinPatternBytes
//     (64 KiB, such as a pattern with many wide classes like \pL), or whose
//     twin fails a check (see twinPattern), keeps no twin: the twin forms
//     read with the pattern itself;
//   - a text with no look-alike of "I" or "l" (and no other rune of
//     skeletonTable) is read with the pattern only, so ASCII "lgnore" or
//     "aII" is not read as "ignore" or "all". An accented "I" or "l", such
//     as U+00CF or U+013E, is not a look-alike (see foldAddsIL), also when
//     its mark is small: "a" + U+1ECA U+1ECA (I with dot below) does not
//     match `(?i)all`, and U+1E37 (l with dot below) + "gnore" does not
//     match `(?i)ignore`;
//   - a text that holds one look-alike is read by the twin as a whole. So
//     its ASCII "I" and "l" also read as either letter: ASCII "lgnore all
//     previous instructions." next to one Cyrillic word matches
//     MOAT-T1-001, and pairs such as "all" and "ail" or "URl" and "URI" can
//     match. This false positive is the cost of the fix.

// twinFromTree returns the I/l-blind twin of re: a regex that matches every
// text that re matches, and also the same texts with any ASCII "I" read as
// "l" and any "l" read as "I". tree is the parse tree of the pattern of re,
// as progSize returns it, and insts is the size of the program of re.
// compileRegexList passes the tree that compileRegexTree made, so the
// pattern is not parsed again. twinFromTree does not change tree.
//
// The twin is built from a copy of tree (see cloneRegexp). blurIL rewrites
// the copy (see blurIL for what changes). printRE2 then writes the new tree
// as a pattern, and regexp.Compile compiles that pattern. Package regexp
// cannot compile a tree directly, so this round trip through the text is
// needed. tree itself stays as the parser made it, so twinPattern can check
// the printer on it without a new parse of the pattern. Under (?i), the
// parser folds each rune of a wide class, up to U+1E943, so one parse of a
// hostile pattern can cost about as much as its whole compile.
//
// printRE2 is used, and not the String method of syntax.Regexp, because
// String is slow for some classes (see re2print.go). twinFromTree calls no
// function with that slow loop.
//
// twinFromTree returns re itself when the twin is the same as re, and also
// when a safety check fails (see twinPattern). The twin forms then read with
// the original regex, as before the twin.
func twinFromTree(re *regexp.Regexp, tree *syntax.Regexp, insts int) *regexp.Regexp {
	if !needsBlur(tree) {
		return re // no "I" or "l" to blur, so no copy of the tree
	}
	work := cloneRegexp(tree)
	blurIL(work)
	text, ok := twinPattern(tree, work, insts)
	if !ok {
		return re
	}
	twin, err := regexp.Compile(text)
	if err != nil {
		return re
	}
	return twin
}

// cloneRegexp returns a deep copy of the parse tree re: each node and each
// Rune and Sub slice is new, so blurIL can rewrite the copy and re does not
// change. The copy has the fields that the parser sets and that blurIL,
// printRE2 and syntax.Compile read: Op, Flags, Sub, Rune, Min, Max, Cap and
// Name. Rune0 and Sub0 are only the storage of the parser for short slices,
// so the copy does not need them.
func cloneRegexp(re *syntax.Regexp) *syntax.Regexp {
	c := &syntax.Regexp{
		Op:    re.Op,
		Flags: re.Flags,
		Rune:  slices.Clone(re.Rune),
		Min:   re.Min,
		Max:   re.Max,
		Cap:   re.Cap,
		Name:  re.Name,
	}
	if len(re.Sub) > 0 {
		c.Sub = make([]*syntax.Regexp, len(re.Sub))
		for i, sub := range re.Sub {
			c.Sub[i] = cloneRegexp(sub)
		}
	}
	return c
}

// twinPattern returns the pattern of the twin: printRE2 of tree, a copy of
// orig after blurIL. orig is the parse tree of the pattern, as the parser
// made it, and insts is the size of its program. ok is false when a check
// fails:
//
//   - printRE2 must print the tree, and the printed pattern must parse
//     again;
//   - the printed pattern must give the program of tree (exact), or be a
//     fixpoint (see below);
//   - the program of the twin has at most insts instructions. blurIL turns
//     one rune into one class, and each is one instruction, so the sizes are
//     equal or smaller. So the twin keeps maxProgInsts and maxTotalInsts,
//     and the cost bound of the match block does not change;
//   - the twin cannot match the empty text (see minLen), as
//     compileRegexTree checks for re.
//
// The fixpoint rule: blurIL can make two alternatives equal. In
// `(?i)\b(?:fail|fall)\b`, both "il" and "ll" become [IiLl][IiLl], and in
// `Ia|la` both branches become [Il]a. The parser joins equal alternatives
// when it reads the printed pattern, so the program is smaller than the
// program of tree, and the exact check fails. The joined program matches the
// same texts. So the pattern is also accepted when it is a fixpoint: a
// second print and parse gives the same program again. As a guard on the
// printer, printRE2 must then also print orig to a pattern with the same
// program as orig (see printsSame).
func twinPattern(orig, tree *syntax.Regexp, insts int) (string, bool) {
	want, err := syntax.Compile(tree.Simplify())
	if err != nil {
		return "", false
	}
	text, gotTree, got, same := printsToProg(tree, want)
	if got == nil || len(got.Inst) > insts || minLen(gotTree) == 0 {
		return "", false
	}
	if same {
		return text, true
	}
	// The fixpoint rule.
	if !isPrintFixpoint(gotTree, got) || !printsSame(orig) {
		return "", false
	}
	return text, true
}

// printsToProg prints tree with printRE2, parses the printed pattern with
// parseProg, and reports whether the program of that parse is prog (see
// sameProg). It returns the printed pattern, its parse tree gotTree and its
// program got. gotTree and got are nil when printRE2 or the parse fails;
// same is then false. twinPattern, isPrintFixpoint and printsSame make
// their print, parse and compare check with it.
func printsToProg(tree *syntax.Regexp, prog *syntax.Prog) (text string, gotTree *syntax.Regexp, got *syntax.Prog, same bool) {
	text, ok := printRE2(tree)
	if !ok {
		return "", nil, nil, false
	}
	gotTree, got, err := parseProg(text)
	if err != nil {
		return "", nil, nil, false
	}
	return text, gotTree, got, sameProg(got, prog)
}

// isPrintFixpoint reports whether a second print and parse keeps the
// program: printRE2 prints tree, the parse tree of a printed pattern, to a
// pattern whose program is prog, the program of tree. The parser can join
// alternatives again when it reads a printed pattern, so one print can give
// a smaller program than the tree it printed (see the fixpoint rule in
// twinPattern).
func isPrintFixpoint(tree *syntax.Regexp, prog *syntax.Prog) bool {
	_, _, _, same := printsToProg(tree, prog)
	return same
}

// printsSame reports whether printRE2 prints the parse tree orig to a
// pattern with the same program as orig. It compiles orig, but it does not
// parse its pattern again (see twinFromTree). The printed pattern writes
// each class as its ranges, with no (?i), so its parse is cheap.
func printsSame(orig *syntax.Regexp) bool {
	prog, err := syntax.Compile(orig.Simplify())
	if err != nil {
		return false
	}
	_, _, _, same := printsToProg(orig, prog)
	return same
}

// sameProg reports whether the programs a and b are the same: the same
// instructions in the same order, and the same start. It compares what the
// String method of syntax.Prog prints, without building the text.
func sameProg(a, b *syntax.Prog) bool {
	if a.Start != b.Start || a.NumCap != b.NumCap || len(a.Inst) != len(b.Inst) {
		return false
	}
	for i := range a.Inst {
		x, y := &a.Inst[i], &b.Inst[i]
		if x.Op != y.Op || x.Out != y.Out || x.Arg != y.Arg || !slices.Equal(x.Rune, y.Rune) {
			return false
		}
	}
	return true
}

// parseProg parses expr with the flags of regexp.Compile, as progSize does,
// and returns the parse tree and its compiled program.
func parseProg(expr string) (*syntax.Regexp, *syntax.Prog, error) {
	tree, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, nil, err
	}
	prog, err := syntax.Compile(tree.Simplify())
	if err != nil {
		return nil, nil, err
	}
	return tree, prog, nil
}

// blurIL rewrites the tree re in place so that ASCII "I" and "l" match as one
// letter. re must be a fresh tree that only the caller uses. needsBlur tells,
// without a change to re, whether blurIL changes it.
//
// The rewrite only adds runes, so the new tree matches every text that re
// matches:
//
//   - a literal "I" or "l" becomes the class [Il]. Under (?i), a literal "i",
//     "I", "l" or "L" becomes [IiLl]. A literal "i" or "L" without (?i) does
//     not match "I" or "l", so it stays;
//   - a class that holds "I" or "l" as a letter of its own gets both "I" and
//     "l" (and "i" and "L" when the class has the FoldCase flag). See
//     blurClass for when a class names the letter;
//   - all other nodes stay, and blurIL reads their sub-trees. The word edge
//     \b and \w do not change: "I" and "l" are both word runes.
func blurIL(re *syntax.Regexp) {
	switch re.Op {
	case syntax.OpLiteral:
		blurLiteral(re)
		return
	case syntax.OpCharClass:
		blurClass(re)
		return
	}
	for _, sub := range re.Sub {
		blurIL(sub)
	}
}

// needsBlur reports whether blurIL would change the tree re. It does not
// change re, so twinFromTree can call it first and copy the tree only when
// blurIL has work to do.
func needsBlur(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral:
		fold := re.Flags&syntax.FoldCase != 0
		for _, r := range re.Rune {
			if isILRune(r, fold) {
				return true
			}
		}
		return false
	case syntax.OpCharClass:
		return len(classAdds(re)) > 0
	}
	return slices.ContainsFunc(re.Sub, needsBlur)
}

// blurLiteral rewrites the literal node re as blurIL says. Each rune that
// changes becomes a class node. The runes that do not change stay together
// in literal nodes with the flags of re. When re splits into more than one
// node, re becomes a concatenation of them.
func blurLiteral(re *syntax.Regexp) {
	fold := re.Flags&syntax.FoldCase != 0
	var parts []*syntax.Regexp
	var run []rune // runes that stay, not yet in parts
	changed := false
	flush := func() {
		if len(run) > 0 {
			parts = append(parts, &syntax.Regexp{Op: syntax.OpLiteral, Flags: re.Flags, Rune: run})
			run = nil
		}
	}
	for _, r := range re.Rune {
		class := ilClassOf(r, fold)
		if class == nil {
			run = append(run, r)
			continue
		}
		changed = true
		flush()
		parts = append(parts, &syntax.Regexp{Op: syntax.OpCharClass, Flags: re.Flags, Rune: class})
	}
	if !changed {
		return
	}
	flush()
	if len(parts) == 1 {
		*re = *parts[0]
		return
	}
	*re = syntax.Regexp{Op: syntax.OpConcat, Flags: re.Flags, Sub: parts}
}

// ilClassOf returns the class ranges of the blurred literal rune r, or nil
// when r stays (see blurIL). fold tells whether the literal has (?i).
//
// Without (?i), only "I" and "l" change, to [Il]. With (?i), a rune changes
// when its fold orbit (unicode.SimpleFold) holds "I" or "l": "i", "I", "l"
// and "L". It becomes the orbits of "I" and "l" together, [IiLl].
func ilClassOf(r rune, fold bool) []rune {
	if !isILRune(r, fold) {
		return nil
	}
	if !fold {
		return []rune{'I', 'I', 'l', 'l'}
	}
	var ranges []rune
	for _, f := range append(foldOrbit('I'), foldOrbit('l')...) {
		ranges = append(ranges, f, f)
	}
	return mergeRanges(ranges)
}

// isILRune reports whether the literal rune r changes in blurIL (see
// ilClassOf). fold tells whether the literal has (?i). It does not
// allocate.
func isILRune(r rune, fold bool) bool {
	if r == 'I' || r == 'l' {
		return true
	}
	if !fold {
		return false
	}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f == 'I' || f == 'l' {
			return true
		}
	}
	return false
}

// foldOrbit returns r and every rune that r folds to under (?i): the orbit of
// r in unicode.SimpleFold.
func foldOrbit(r rune) []rune {
	orbit := []rune{r}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		orbit = append(orbit, f)
	}
	return orbit
}

// blurClass rewrites the class node re as blurIL says. re.Rune holds pairs
// of rune ranges, lo and hi, sorted and with no overlap, as the parser
// builds them.
//
// A class names the letter "l" when it holds "l" but not all of a-z, and it
// names "I" when it holds "I" but not all of A-Z. Such a class gets both
// letters. So [il] becomes [Iil], and so do the narrow ranges that the
// parser builds: it joins neighbour runes, so [kl] is the range k-l, and it
// factors alternations, so `(?i)\b(?:talk|tall)\b` holds the class [KLkl]
// (with U+212A, the Kelvin sign). [h-m] and [b-z] get "I" too.
//
// A class that holds all of a-z keeps its "l", and one that holds all of
// A-Z keeps its "I": [a-z], [A-Z], [A-Za-z0-9], \w and \pL do not change.
// Such a class names a case or a set of letters, not the letter "I" or "l".
// If [A-Z] matched "l", the camelCase test of MOAT-T3-001
// ([a-z][a-z0-9]+[A-Z]) would match almost every word with an "l" in it.
//
// A negated class does not change. The parser writes it as the ranges
// around the runes it leaves out, so it holds U+0000 and the last rune
// U+10FFFF, as a class that the user writes rarely holds. Such a class
// leaves runes out on purpose: [^l] must not match "l", and the twin of
// `x[^l]` must still mean "x and one rune that is not l". Most negated
// classes, such as [^<] or \S, hold all of a-z and A-Z, so the two rules
// above keep them as well.
func blurClass(re *syntax.Regexp) {
	add := classAdds(re)
	if len(add) == 0 {
		return
	}
	ranges := slices.Clone(re.Rune)
	for _, r := range add {
		ranges = append(ranges, r, r)
	}
	re.Rune = mergeRanges(ranges)
}

// classAdds returns the runes that blurClass adds to the class node re, or
// nil when the class does not change: it does not name "I" or "l", or it
// holds all the runes already, such as (?i)[il]. It does not change re.
func classAdds(re *syntax.Regexp) []rune {
	if !namesIL(re.Rune) {
		return nil
	}
	var add []rune
	for _, r := range []rune{'I', 'l', 'i', 'L'} {
		if (r == 'i' || r == 'L') && re.Flags&syntax.FoldCase == 0 {
			continue // "i" and "L" only with the FoldCase flag
		}
		if !inRanges(re.Rune, r) {
			add = append(add, r)
		}
	}
	return add
}

// namesIL reports whether the class ranges name the letter "I" or "l" (see
// blurClass).
func namesIL(ranges []rune) bool {
	n := len(ranges)
	if n < 2 || n%2 != 0 {
		return false
	}
	if ranges[0] == 0 && ranges[n-1] == unicode.MaxRune {
		return false // a negated class
	}
	return inRanges(ranges, 'l') && !coversAll(ranges, 'a', 'z') ||
		inRanges(ranges, 'I') && !coversAll(ranges, 'A', 'Z')
}

// coversAll reports whether the class ranges hold every rune from lo to hi.
func coversAll(ranges []rune, lo, hi rune) bool {
	for r := lo; r <= hi; r++ {
		if !inRanges(ranges, r) {
			return false
		}
	}
	return true
}

// inRanges reports whether one of the class ranges holds r.
func inRanges(ranges []rune, r rune) bool {
	for i := 0; i+1 < len(ranges); i += 2 {
		if ranges[i] <= r && r <= ranges[i+1] {
			return true
		}
	}
	return false
}

// mergeRanges returns the class ranges sorted by lo, with overlapping and
// touching ranges joined into one, as the parser builds a class. printRE2
// and syntax.Compile expect this shape.
func mergeRanges(ranges []rune) []rune {
	type span struct{ lo, hi rune }
	spans := make([]span, 0, len(ranges)/2)
	for i := 0; i+1 < len(ranges); i += 2 {
		spans = append(spans, span{ranges[i], ranges[i+1]})
	}
	slices.SortFunc(spans, func(a, b span) int { return cmp.Compare(a.lo, b.lo) })
	out := make([]rune, 0, len(ranges))
	for _, s := range spans {
		n := len(out)
		if n > 0 && s.lo <= out[n-1]+1 {
			out[n-1] = max(out[n-1], s.hi)
			continue
		}
		out = append(out, s.lo, s.hi)
	}
	return out
}
