package rules

import (
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file holds printRE2, the printer that writes a parse tree back as a
// pattern for the I/l-blind twin (see twinFromTree).
//
// The package has its own printer because the String method of
// syntax.Regexp is slow for some trees. In the Go version of go.mod (1.27),
// String loops over every rune from "A" to U+1E943 for each class that is
// closed under case folding, such as \S, [^<] or a class under (?i). That is
// about 2 ms for each such class, so a pattern of 1 KiB, such as "l" + 511
// times `\S`, took about 1 s to get its twin. printRE2 has no such loop.
// Check the cost of String again on each Go upgrade (TestILTwinTime is the
// guard).

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

// noMatchClass is the pattern of a class with no runes, which never
// matches. The String method of syntax.Regexp writes an empty class in the
// same way. printRE2 writes it for an empty class and for OpNoMatch.
const noMatchClass = `[^\x00-\x{10FFFF}]`

// writeRE2 writes re to b as printRE2 says, and reports false when it
// cannot, or when b grows over maxTwinPatternBytes. b can hold part of the
// pattern then.
func writeRE2(b *strings.Builder, re *syntax.Regexp) bool {
	if b.Len() > maxTwinPatternBytes {
		return false
	}
	switch re.Op {
	case syntax.OpNoMatch:
		b.WriteString(noMatchClass)
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
// noMatchClass.
func writeClass(b *strings.Builder, ranges []rune) bool {
	if len(ranges)%2 != 0 || isFoldPairClass(ranges) {
		return false
	}
	if len(ranges) == 0 {
		b.WriteString(noMatchClass)
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
			if !isASCIIAlnum(r) && r != '_' {
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
		case re.Min < 0 || re.Max < -1 || (re.Max != -1 && re.Max < re.Min):
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
	case r < 0x80 && isASCIIAlnum(r): // the bound keeps byte(r) exact
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
