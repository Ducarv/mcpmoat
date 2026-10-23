package rules

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits for the match block of a rule. Rule files can come from an untrusted
// --rules directory, and the matched text comes from untrusted MCP servers, so
// every part of a match has a size cap.
//
// Go's regexp package (RE2) runs in linear time, but it has no timeout. The
// cost of one regex is about the input bytes times the program size. So the
// cost of one match block is at most MaxMatchInputBytes times maxTotalInsts:
// maxProgInsts caps one regex, and maxTotalInsts caps the sum over all the
// regexes of one any_regex, all_regex or keywords list.
//
// The worst case for one match block is about 32 KiB x 2500, about 80M
// instruction-bytes. BenchmarkWorstCaseBlock measured about 0.8 s for it on
// an Apple M1 Pro (about 10 ns for each instruction-byte). A hostile --rules
// directory multiplies this cost by the number of rules and the number of
// texts. A cap at the loader level is future work (#33).
const (
	// MaxPatternBytes is the largest regex or keyword, in bytes, before
	// compilation.
	MaxPatternBytes = 1024
	// MaxPatterns is the largest number of entries in one any_regex,
	// all_regex or keywords list.
	MaxPatterns = 64
	// maxProgInsts caps the size of one compiled regex program, in
	// instructions. The cost of matching one input byte grows with the
	// program size, so this cap bounds the cost of one regex.
	maxProgInsts = 1000
	// maxTotalInsts caps the sum of the program sizes of all the regexes in
	// one list, including the regexes that compileKeywords builds. So 64
	// large regexes cannot multiply the cost of a match block.
	maxTotalInsts = 2500
	// MaxHits is the largest number of hits that one Match call returns,
	// plus one summary hit that counts the rest.
	MaxHits = 16
)

// Match is the `match:` block of a rule. Exactly one kind is set: AnyRegex,
// AllRegex, Keywords or Heuristic. Params is only for Heuristic.
//
// Regexes use Go RE2 syntax (package regexp). They are case sensitive: write
// (?i) in the pattern for a case-insensitive match. Keywords always match
// without regard to case, and only as whole words.
type Match struct {
	AnyRegex  []string       `yaml:"any_regex,omitempty"`
	AllRegex  []string       `yaml:"all_regex,omitempty"`
	Keywords  []string       `yaml:"keywords,omitempty"`
	Heuristic string         `yaml:"heuristic,omitempty"`
	Params    map[string]int `yaml:"params,omitempty"` // only with Heuristic
}

// FieldError reports an invalid field in the match block, for example
// "any_regex[2]" or "params.max_runes". The rule loader adds the file name.
//
// Field and Msg never hold the pattern, a parameter key or other text from
// the rule file, so the error is safe to print.
type FieldError struct {
	Field string // field in the match block; "" for the block itself
	Msg   string
}

// Error returns "match.<Field>: <Msg>", or "match: <Msg>" when Field is empty.
func (e *FieldError) Error() string {
	if e.Field == "" {
		return "match: " + e.Msg
	}
	return "match." + e.Field + ": " + e.Msg
}

// Hit is one reason why a Matcher matched a text.
type Hit struct {
	// Offset is a byte offset in the raw text, or -1 for regex and keyword
	// hits: they run on the normalized text, so no raw offset is known.
	Offset int
	// Detail is short printable ASCII that mcpmoat builds. It never holds
	// text from the input.
	Detail string
}

// The kinds of a Matcher. Each value is also the field name in the match
// block.
const (
	kindAnyRegex  = "any_regex"
	kindAllRegex  = "all_regex"
	kindKeywords  = "keywords"
	kindHeuristic = "heuristic"
)

// Matcher is a compiled match block. Make one with Match.Compile. A Matcher
// is immutable and safe for concurrent use.
type Matcher struct {
	kind      string
	regexps   []*regexp.Regexp       // any_regex, all_regex and keywords
	heuristic func(raw string) []Hit // heuristic
}

// Compile checks the match block and compiles it. Every error is a
// *FieldError that names the field.
func (m Match) Compile() (*Matcher, error) {
	// A list that is present but empty (YAML "[]") counts as given, so the
	// error says "must not be empty" and not "set exactly one".
	given := 0
	for _, set := range []bool{m.AnyRegex != nil, m.AllRegex != nil, m.Keywords != nil, m.Heuristic != ""} {
		if set {
			given++
		}
	}
	if given != 1 {
		return nil, &FieldError{Msg: "set exactly one of any_regex, all_regex, keywords, heuristic"}
	}
	if m.Params != nil && m.Heuristic == "" {
		return nil, &FieldError{Field: "params", Msg: "allowed only with heuristic"}
	}

	switch {
	case m.Heuristic != "":
		fn, err := compileHeuristic(m.Heuristic, m.Params)
		if err != nil {
			return nil, err
		}
		return &Matcher{kind: kindHeuristic, heuristic: fn}, nil
	case m.AnyRegex != nil:
		res, err := compileRegexList(kindAnyRegex, m.AnyRegex)
		if err != nil {
			return nil, err
		}
		return &Matcher{kind: kindAnyRegex, regexps: res}, nil
	case m.AllRegex != nil:
		res, err := compileRegexList(kindAllRegex, m.AllRegex)
		if err != nil {
			return nil, err
		}
		return &Matcher{kind: kindAllRegex, regexps: res}, nil
	default:
		res, err := compileKeywords(m.Keywords)
		if err != nil {
			return nil, err
		}
		return &Matcher{kind: kindKeywords, regexps: res}, nil
	}
}

// Match returns the hits of the matcher in text, or nil when it does not
// match.
//
// Regexes and keywords read the normalized text (see normalizeForMatch), so
// an invisible character cannot split a keyword. A heuristic reads the full
// raw text.
func (m *Matcher) Match(text string) []Hit {
	if m == nil {
		return nil
	}
	switch m.kind {
	case kindHeuristic:
		return m.heuristic(text)
	case kindAnyRegex:
		t := normalizeForMatch(text)
		for i, re := range m.regexps {
			if re.MatchString(t) {
				return []Hit{{Offset: -1, Detail: fmt.Sprintf("any_regex[%d] matched", i)}}
			}
		}
		return nil
	case kindAllRegex:
		t := normalizeForMatch(text)
		for _, re := range m.regexps {
			if !re.MatchString(t) {
				return nil
			}
		}
		var l hitList
		for i := range m.regexps {
			if l.keep(-1) {
				l.hits = append(l.hits, Hit{Offset: -1, Detail: fmt.Sprintf("all_regex[%d] matched", i)})
			}
		}
		return l.result("patterns")
	case kindKeywords:
		t := foldMarks(normalizeForMatch(text))
		var l hitList
		for i, re := range m.regexps {
			if re.MatchString(t) && l.keep(-1) {
				l.hits = append(l.hits, Hit{Offset: -1, Detail: fmt.Sprintf("keyword[%d] matched", i)})
			}
		}
		return l.result("keywords")
	}
	return nil
}

// compileRegexList compiles the patterns of the list named field.
func compileRegexList(field string, patterns []string) ([]*regexp.Regexp, error) {
	if err := checkList(field, patterns); err != nil {
		return nil, err
	}
	res := make([]*regexp.Regexp, 0, len(patterns))
	total := 0
	for i, p := range patterns {
		entry := fmt.Sprintf("%s[%d]", field, i)
		if err := checkEntry(entry, p); err != nil {
			return nil, err
		}
		re, insts, err := compileRegex(entry, p)
		if err != nil {
			return nil, err
		}
		total += insts
		if err := checkTotal(field, total); err != nil {
			return nil, err
		}
		res = append(res, re)
	}
	return res, nil
}

// checkTotal checks the sum of the program sizes of the regexes of the list
// named field. The callers call it after each regex, so a list that is too
// complex fails early, and the error gives the sum at that point.
func checkTotal(field string, total int) error {
	if total > maxTotalInsts {
		return &FieldError{Field: field, Msg: fmt.Sprintf("regexes are too complex in total: %d instructions, over the limit of %d", total, maxTotalInsts)}
	}
	return nil
}

// compileKeywords builds and compiles one regex for each keyword.
//
// A keyword is normalized like the text it is matched against, with
// normalizeForMatch and then foldMarks. It then matches without regard to
// case, any run of white space in the text matches the white space between
// its words, and it matches only as a whole word.
//
// Go's \b, \w and \s know only ASCII, so the word edges and the white space
// are written as Unicode classes:
//
//   - a word rune is a letter, a mark, a number or '_': [\p{L}\p{M}\p{N}_];
//   - white space is [\s\v\x{85}\p{Z}\x{2800}]: the same set as
//     unicode.IsSpace, plus U+2800 (braille blank), a symbol that shows as a
//     blank.
//
// The edge check is added only on a side where the keyword starts or ends
// with a word rune. So the keyword "C++" still matches in "C++, Go".
func compileKeywords(keywords []string) ([]*regexp.Regexp, error) {
	if err := checkList(kindKeywords, keywords); err != nil {
		return nil, err
	}
	res := make([]*regexp.Regexp, 0, len(keywords))
	total := 0
	for i, kw := range keywords {
		entry := fmt.Sprintf("%s[%d]", kindKeywords, i)
		if err := checkEntry(entry, kw); err != nil {
			return nil, err
		}
		words := strings.FieldsFunc(foldMarks(normalizeForMatch(kw)), isKeywordSpace)
		if len(words) == 0 {
			return nil, &FieldError{Field: entry, Msg: "has no visible characters"}
		}
		for j, w := range words {
			words[j] = regexp.QuoteMeta(w)
		}
		expr := `(?i:` + strings.Join(words, `[\s\v\x{85}\p{Z}\x{2800}]+`) + `)`

		first, _ := utf8.DecodeRuneInString(words[0])
		if isWordRune(first) {
			expr = `(?:^|[^\p{L}\p{M}\p{N}_])` + expr
		}
		last, _ := utf8.DecodeLastRuneInString(words[len(words)-1])
		if isWordRune(last) {
			expr += `(?:$|[^\p{L}\p{M}\p{N}_])`
		}

		re, insts, err := compileRegex(entry, expr)
		if err != nil {
			return nil, err
		}
		total += insts
		if err := checkTotal(kindKeywords, total); err != nil {
			return nil, err
		}
		res = append(res, re)
	}
	return res, nil
}

// isKeywordSpace reports whether r separates the words of a keyword. It is
// the same set as the white-space class in compileKeywords.
func isKeywordSpace(r rune) bool {
	return unicode.IsSpace(r) || r == '⠀'
}

// isWordRune reports whether r is a letter, a mark, a number or '_'. It is
// the same set as the class [\p{L}\p{M}\p{N}_] in compileKeywords.
func isWordRune(r rune) bool {
	return r == '_' || unicode.In(r, unicode.L, unicode.M, unicode.N)
}

// checkList checks the length of the list named field.
func checkList(field string, list []string) error {
	switch {
	case len(list) == 0:
		return &FieldError{Field: field, Msg: "must not be empty"}
	case len(list) > MaxPatterns:
		return &FieldError{Field: field, Msg: fmt.Sprintf("has %d entries, over the limit of %d", len(list), MaxPatterns)}
	}
	return nil
}

// checkEntry checks one regex or keyword before compilation.
func checkEntry(field, s string) error {
	switch {
	case s == "":
		return &FieldError{Field: field, Msg: "must not be empty"}
	case len(s) > MaxPatternBytes:
		return &FieldError{Field: field, Msg: fmt.Sprintf("is %d bytes long, over the limit of %d", len(s), MaxPatternBytes)}
	case !utf8.ValidString(s):
		return &FieldError{Field: field, Msg: "is not valid UTF-8"}
	}
	return nil
}

// compileRegex compiles expr and rejects a regex that is too large or that
// can match the empty text (see minLen).
//
// regexp.Compile works in three steps, and the first two are public in
// package regexp/syntax:
//
//  1. syntax.Parse turns the text into a tree. It rejects bad syntax and
//     repeat counts over 1000, such as a{1001} or (?:a{100}){100}.
//  2. Simplify expands the repeats (a{3} becomes aaa), and syntax.Compile
//     turns the tree into a program of instructions for the matching
//     machine. A short pattern can expand into a large program:
//     (?:abcdef){1000} is 16 bytes but 6002 instructions.
//  3. regexp.Compile does steps 1 and 2 again and builds the Regexp.
//
// So the first two steps run here only to count the instructions, before the
// real compilation. syntax.Perl is the flag set that regexp.Compile uses.
//
// compileRegex also returns the number of instructions, so the caller can
// check the sum over a list (see maxTotalInsts).
func compileRegex(field, expr string) (*regexp.Regexp, int, error) {
	tree, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, 0, regexError(field, err)
	}
	prog, err := syntax.Compile(tree.Simplify())
	if err != nil {
		return nil, 0, regexError(field, err)
	}
	insts := len(prog.Inst)
	if insts > maxProgInsts {
		return nil, 0, &FieldError{Field: field, Msg: fmt.Sprintf("regex is too complex: %d instructions, over the limit of %d", insts, maxProgInsts)}
	}
	// A regex that can match without reading a rune, such as a* or \b, can
	// match at many places in almost any text, so the rule would fire on
	// almost every tool. The program has at most maxProgInsts instructions
	// here, so minLen cannot overflow.
	if minLen(tree) == 0 {
		return nil, 0, &FieldError{Field: field, Msg: "regex matches the empty text"}
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, 0, regexError(field, err)
	}
	return re, insts, nil
}

// minLen returns the smallest number of runes that a match of re can read.
// It is 0 when re can match the empty text at some place, also through an
// assertion such as ^, $, \b or \B, which reads no rune. re.MatchString("")
// is not enough: \b does not match "", but it matches in "a".
//
// OpNoMatch (for example [^\x00-\x{10FFFF}]) never matches. minLen gives it
// 1, so a branch that can never match does not make the regex count as
// empty.
func minLen(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL, syntax.OpNoMatch:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return minLen(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min * minLen(re.Sub[0])
	case syntax.OpConcat:
		n := 0
		for _, sub := range re.Sub {
			n += minLen(sub)
		}
		return n
	case syntax.OpAlternate:
		n := minLen(re.Sub[0])
		for _, sub := range re.Sub[1:] {
			n = min(n, minLen(sub))
		}
		return n
	}
	// OpEmptyMatch, OpStar, OpQuest and the assertions OpBeginLine,
	// OpEndLine, OpBeginText, OpEndText, OpWordBoundary and OpNoWordBoundary.
	return 0
}

// regexError returns a *FieldError for a compile error. The message is only
// the error code, such as "missing closing )". A *syntax.Error also holds
// the pattern text, which must not reach the output.
func regexError(field string, err error) error {
	var se *syntax.Error
	if errors.As(err, &se) {
		return &FieldError{Field: field, Msg: "invalid regex: " + string(se.Code)}
	}
	return &FieldError{Field: field, Msg: "invalid regex"}
}

// hitList collects at most MaxHits hits and counts the hits that do not fit.
// So a text with a million hits costs no million Detail strings.
//
// Use it as:
//
//	if l.keep(offset) {
//		l.hits = append(l.hits, Hit{...})
//	}
type hitList struct {
	hits         []Hit
	dropped      int // hits that did not fit
	firstDropped int // offset of the first hit that did not fit
}

// keep reports whether the next hit fits. When it does not fit, keep counts
// it as dropped, at offset.
func (l *hitList) keep(offset int) bool {
	if len(l.hits) < MaxHits {
		return true
	}
	if l.dropped == 0 {
		l.firstDropped = offset
	}
	l.dropped++
	return false
}

// result returns the kept hits, and one summary hit "and N more <what>" when
// hits were dropped. It returns nil when there are no hits.
func (l *hitList) result(what string) []Hit {
	if l.dropped == 0 {
		return l.hits
	}
	return append(l.hits, Hit{Offset: l.firstDropped, Detail: fmt.Sprintf("and %d more %s", l.dropped, what)})
}
