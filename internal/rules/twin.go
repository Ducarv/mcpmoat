package rules

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file builds the I/l-blind twin of a regex (see twinFromTree).
//
// The skeleton fold reads each look-alike of "I" or "l" as one of the two
// letters (see skeletonTable). TR39 reads them all as one letter, but the
// rules need both: the "i" of ignore and the "l" of all. So with one fixed
// reading, an attacker picks the look-alike whose reading the rules do not
// expect: Cyrillic U+04CF (small palochka, read "l") + "gnore", or "a" +
// U+0406 U+0406 (Cyrillic capital I, read "I") for "all". The plain fold has
// look-alikes too: fullwidth U+FF29 and U+FF4C, the roman numerals U+2160
// and U+217C and many mathematical letters fold to an ASCII "I" or "l". The
// twin of a regex reads ASCII "I" and "l" as one letter, so it matches both
// readings. The matcher runs the twin only on the skeleton folds and on the
// plain folds that got a new "I" or "l" from a compatibility mapping (see
// preparedText.regexFormParts and Matcher.matchRegex), so a plain ASCII
// "lgnore" still does not match.
//
// The twin has these limits:
//
//   - only any_regex and all_regex get a twin. A keyword rule reads no
//     skeleton fold, and its plain folds read with the keyword as it is;
//   - a pattern that writes a lowercase "i" or an uppercase "L" without
//     (?i) keeps it: such a letter does not match "I" or "l" in the pattern
//     either;
//   - a class that holds all of a-z keeps its "l", and a class that holds
//     all of A-Z keeps its "I" (see blurClass). So [a-z], [A-Z], \w and \pL
//     do not change;
//   - a negated class, such as [^l], does not change (see blurClass);
//   - a pattern whose twin pattern is longer than maxTwinPatternBytes, or
//     whose twin fails a check (see twinPattern), keeps no twin: the twin
//     forms read with the pattern itself;
//   - a text with no look-alike of "I" or "l" (and no other rune of
//     skeletonTable) is read with the pattern only. An accented "I" or "l",
//     such as U+00CF or U+013E, is not a look-alike (see foldAddsIL), also
//     when its mark is small, such as U+1ECA (I with dot below);
//   - a text that holds one look-alike is read by the twin as a whole. So
//     its ASCII "I" and "l" also read as either letter: ASCII "lgnore all
//     previous instructions." next to one Cyrillic word matches
//     MOAT-T1-001, and "URl" next to it matches a pattern for "URI". This
//     false positive is the cost of the fix.

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
// printRE2 is used, and not the String method of syntax.Regexp. In the Go
// version of go.mod (1.27), String loops over every rune from "A" to
// U+1E943 for each class that is closed under case folding, such as \S,
// [^<] or a class under (?i). That is about 2 ms for each such class, so a
// pattern of 1 KiB, such as "l" + 511 times `\S`, took about 1 s to get its
// twin. twinFromTree calls no function with this loop.
//
// twinFromTree returns re itself when the twin is the same as re, and also
// when a safety check fails (see twinPattern). The twin forms then read with
// the original regex, as before the twin.
func twinFromTree(re *regexp.Regexp, tree *syntax.Regexp, insts int) *regexp.Regexp {
	if !needsBlur(tree) {
		return re // no "I" or "l" to blur, so no copy of the tree
	}
	work := cloneRegexp(tree)
	if !blurIL(work) {
		return re // needsBlur and blurIL agree, so this does not happen
	}
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
//   - the twin cannot match the empty text (see minLen), as compileRegex
//     checks for re.
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
	text, ok := printRE2(tree)
	if !ok {
		return "", false
	}
	gotTree, got, err := parseProg(text)
	if err != nil || len(got.Inst) > insts || minLen(gotTree) == 0 {
		return "", false
	}
	if sameProg(got, want) {
		return text, true
	}
	// The fixpoint rule.
	if !isPrintFixpoint(gotTree, got) || !printsSame(orig) {
		return "", false
	}
	return text, true
}

// isPrintFixpoint reports whether a second print and parse keeps the
// program: printRE2 prints tree, the parse tree of a printed pattern, to a
// pattern whose program is prog, the program of tree. The parser can join
// alternatives again when it reads a printed pattern, so one print can give
// a smaller program than the tree it printed (see the fixpoint rule in
// twinPattern).
func isPrintFixpoint(tree *syntax.Regexp, prog *syntax.Prog) bool {
	text, ok := printRE2(tree)
	if !ok {
		return false
	}
	_, again, err := parseProg(text)
	return err == nil && sameProg(again, prog)
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
	text, ok := printRE2(orig)
	if !ok {
		return false
	}
	_, got, err := parseProg(text)
	return err == nil && sameProg(got, prog)
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

// printRE2 writes the parse tree re as a pattern for regexp.Compile (RE2
// syntax with the flags of syntax.Perl). It reports false when re holds a
// node that it does not know, or a node of a shape that the parser does
// not build. Then no twin is built.
//
// The pattern says each flag where the node needs it, so it does not
// depend on the flags of the pattern that re came from:
//
//   - a literal with the FoldCase flag is written in (?i:...), also when no
//     rune of it has a fold, such as "," or "1". (?i) does not change what
//     such a literal matches, but the parser joins the common prefix of two
//     alternatives only when the FoldCase flags are equal. So the flag must
//     stay, or `@x(?i)|@\b` would print to a pattern with a smaller program.
//     The other flags of a literal do not change what it matches;
//   - a class is written as its ranges, each rune as writeRune says. The
//     parser has applied (?i) and the negation to the ranges already, so
//     the flags of the class node do not matter. A class of one rune and
//     its one case pair, such as [Ii], makes printRE2 report false (see
//     isFoldPairClass);
//   - "." is (?s:.) or (?-s:.), "^" and "$" for a line are (?m:^) and
//     (?m:$), the start and end of the text are \A and \z;
//   - a repeat writes its sub-tree in (?:...), and a "?" after it when it
//     has the NonGreedy flag. The parser sets this flag on a repeat as (?U)
//     and a trailing "?" say, so the flag is the real mode of the repeat;
//   - an alternation is written in (?:...);
//   - a capture is written as (...) or (?P<name>...). The captures are
//     written in the order of the tree, so they keep their numbers.
//
// The (?:...) groups add no nodes, so the pattern parses to the same tree,
// up to the joins of the parser (see twinPattern). twinPattern checks the
// printed pattern in one of two ways. Usually its program must be the
// program of the tree. On the fixpoint path, the check is weaker: a second
// print of the parsed pattern must give the same program, and printRE2 must
// print the original tree to its own program (see printsSame). Any other
// op, such as a new op of a later Go version, makes printRE2 report false.
func printRE2(re *syntax.Regexp) (string, bool) {
	var b strings.Builder
	if !writeRE2(&b, re) || b.Len() > maxTwinPatternBytes {
		return "", false
	}
	return b.String(), true
}

// maxTwinPatternBytes caps the pattern that printRE2 writes. A class is
// written as all its ranges, so one \pL is about 4 KiB, and a pattern of
// 1 KiB with many of them would print to more than 1 MiB, which takes about
// 20 ms to parse twice. The longest twin pattern of the built-in rules is
// under 2 KiB. A pattern whose twin is longer keeps no twin.
const maxTwinPatternBytes = 64 << 10

// writeRE2 writes re to b as printRE2 says, and reports false when it
// cannot, or when b grows over maxTwinPatternBytes. b can hold part of the
// pattern then.
func writeRE2(b *strings.Builder, re *syntax.Regexp) bool {
	if b.Len() > maxTwinPatternBytes {
		return false
	}
	switch re.Op {
	case syntax.OpNoMatch:
		b.WriteString(`[^\x00-\x{10FFFF}]`)
	case syntax.OpEmptyMatch:
		b.WriteString(`(?:)`)
	case syntax.OpLiteral:
		return writeLiteral(b, re)
	case syntax.OpCharClass:
		return writeClass(b, re.Rune)
	case syntax.OpAnyCharNotNL:
		b.WriteString(`(?-s:.)`)
	case syntax.OpAnyChar:
		b.WriteString(`(?s:.)`)
	case syntax.OpBeginLine:
		b.WriteString(`(?m:^)`)
	case syntax.OpEndLine:
		b.WriteString(`(?m:$)`)
	case syntax.OpBeginText:
		b.WriteString(`\A`)
	case syntax.OpEndText:
		b.WriteString(`\z`)
	case syntax.OpWordBoundary:
		b.WriteString(`\b`)
	case syntax.OpNoWordBoundary:
		b.WriteString(`\B`)
	case syntax.OpCapture:
		return writeCapture(b, re)
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		return writeRepeat(b, re)
	case syntax.OpConcat:
		if len(re.Sub) == 0 {
			b.WriteString(`(?:)`)
			return true
		}
		for _, sub := range re.Sub {
			if !writeRE2(b, sub) {
				return false
			}
		}
	case syntax.OpAlternate:
		if len(re.Sub) == 0 {
			return false
		}
		b.WriteString(`(?:`)
		for i, sub := range re.Sub {
			if i > 0 {
				b.WriteByte('|')
			}
			if !writeRE2(b, sub) {
				return false
			}
		}
		b.WriteByte(')')
	default:
		return false
	}
	return true
}

// writeLiteral writes the literal node re (see printRE2). The literal
// keeps its FoldCase flag as (?i:...), so the parser joins the same
// alternatives as in re.
func writeLiteral(b *strings.Builder, re *syntax.Regexp) bool {
	if len(re.Rune) == 0 {
		return false
	}
	fold := re.Flags&syntax.FoldCase != 0
	if fold {
		b.WriteString(`(?i:`)
	}
	for _, r := range re.Rune {
		if !writeRune(b, r) {
			return false
		}
	}
	if fold {
		b.WriteByte(')')
	}
	return true
}

// writeClass writes a class with the ranges of ranges, pairs of lo and hi
// (see printRE2). An empty class never matches, so it is written as
// [^\x00-\x{10FFFF}], as the String method of syntax.Regexp writes it.
func writeClass(b *strings.Builder, ranges []rune) bool {
	if len(ranges)%2 != 0 || isFoldPairClass(ranges) {
		return false
	}
	if len(ranges) == 0 {
		b.WriteString(`[^\x00-\x{10FFFF}]`)
		return true
	}
	b.WriteByte('[')
	for i := 0; i < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		if lo > hi || b.Len() > maxTwinPatternBytes || !writeRune(b, lo) {
			return false
		}
		if hi != lo {
			b.WriteByte('-')
			if !writeRune(b, hi) {
				return false
			}
		}
	}
	b.WriteByte(']')
	return true
}

// isFoldPairClass reports whether the class ranges hold one rune and its
// one case pair, such as [Ii] or the range U+0100-U+0101. The parser
// rewrites such a printed class as a literal with the FoldCase flag (see
// the push method of the parser in regexp/syntax), and that literal
// compiles to a different program. Such a class stays a class only as a
// branch of an alternation, as in `I||i|I`, so printRE2 cannot print it to
// the same program and reports false. The check mirrors the parser.
func isFoldPairClass(ranges []rune) bool {
	switch len(ranges) {
	case 4:
		return ranges[0] == ranges[1] && ranges[2] == ranges[3] &&
			unicode.SimpleFold(ranges[0]) == ranges[2] &&
			unicode.SimpleFold(ranges[2]) == ranges[0]
	case 2:
		return ranges[0]+1 == ranges[1] &&
			unicode.SimpleFold(ranges[0]) == ranges[1] &&
			unicode.SimpleFold(ranges[1]) == ranges[0]
	}
	return false
}

// writeCapture writes the capture node re (see printRE2). A name holds only
// ASCII letters, digits and "_", as the parser checks.
func writeCapture(b *strings.Builder, re *syntax.Regexp) bool {
	if len(re.Sub) != 1 {
		return false
	}
	if re.Name == "" {
		b.WriteByte('(')
	} else {
		for _, r := range re.Name {
			if !isASCIIWordRune(r) {
				return false
			}
		}
		b.WriteString(`(?P<`)
		b.WriteString(re.Name)
		b.WriteByte('>')
	}
	if !writeRE2(b, re.Sub[0]) {
		return false
	}
	b.WriteByte(')')
	return true
}

// writeRepeat writes the star, plus, quest or repeat node re (see
// printRE2).
func writeRepeat(b *strings.Builder, re *syntax.Regexp) bool {
	if len(re.Sub) != 1 {
		return false
	}
	b.WriteString(`(?:`)
	if !writeRE2(b, re.Sub[0]) {
		return false
	}
	b.WriteByte(')')
	switch re.Op {
	case syntax.OpStar:
		b.WriteByte('*')
	case syntax.OpPlus:
		b.WriteByte('+')
	case syntax.OpQuest:
		b.WriteByte('?')
	default: // syntax.OpRepeat
		switch {
		case re.Min < 0 || re.Max < -1 || re.Max != -1 && re.Max < re.Min:
			return false
		case re.Max == re.Min:
			b.WriteString("{" + strconv.Itoa(re.Min) + "}")
		case re.Max == -1:
			b.WriteString("{" + strconv.Itoa(re.Min) + ",}")
		default:
			b.WriteString("{" + strconv.Itoa(re.Min) + "," + strconv.Itoa(re.Max) + "}")
		}
	}
	if re.Flags&syntax.NonGreedy != 0 {
		b.WriteByte('?')
	}
	return true
}

// writeRune writes r as one rune of a literal or a class, in a form that
// has no special meaning there: an ASCII letter or digit as it is, other
// printable ASCII after a backslash (RE2 reads a backslash and an ASCII
// rune that is not a letter or digit as that rune), an ASCII control rune
// or a surrogate as \x{...}, and any other rune as its UTF-8 bytes. The
// short forms keep the pattern small, so it parses faster. It reports false
// for a value that is not a rune.
func writeRune(b *strings.Builder, r rune) bool {
	switch {
	case r < 0 || r > unicode.MaxRune:
		return false
	case r < 0x80 && isASCIIWordRune(r) && r != '_':
		b.WriteByte(byte(r))
	case 0x20 <= r && r < 0x7f:
		b.WriteByte('\\')
		b.WriteByte(byte(r))
	case r < 0x80 || utf8.RuneLen(r) < 0: // a control rune or a surrogate
		b.WriteString(`\x{`)
		b.WriteString(strconv.FormatInt(int64(r), 16))
		b.WriteByte('}')
	default:
		b.WriteRune(r)
	}
	return true
}

// isASCIIWordRune reports whether r is an ASCII letter, an ASCII digit or
// "_".
func isASCIIWordRune(r rune) bool {
	return r == '_' || 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9'
}

// blurIL rewrites the tree re in place so that ASCII "I" and "l" match as one
// letter, and reports whether it changed re. re must be a fresh tree that
// only the caller uses.
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
func blurIL(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral:
		return blurLiteral(re)
	case syntax.OpCharClass:
		return blurClass(re)
	}
	changed := false
	for _, sub := range re.Sub {
		if blurIL(sub) {
			changed = true
		}
	}
	return changed
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
func blurLiteral(re *syntax.Regexp) bool {
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
		return false
	}
	flush()
	if len(parts) == 1 {
		*re = *parts[0]
		return true
	}
	*re = syntax.Regexp{Op: syntax.OpConcat, Flags: re.Flags, Sub: parts}
	return true
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
func blurClass(re *syntax.Regexp) bool {
	add := classAdds(re)
	if len(add) == 0 {
		return false
	}
	ranges := slices.Clone(re.Rune)
	for _, r := range add {
		ranges = append(ranges, r, r)
	}
	re.Rune = mergeRanges(ranges)
	return true
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
	slices.SortFunc(spans, func(a, b span) int { return int(a.lo - b.lo) })
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
