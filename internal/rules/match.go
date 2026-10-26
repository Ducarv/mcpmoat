package rules

import (
	"context"
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
// The worst case for one match block on one form of the text is about 32 KiB
// x 2500, about 82M instruction-bytes. That is about 0.75 s on an Apple M1
// Pro (about 9.2 ns for each instruction-byte: the BenchmarkWorstCaseBlock
// time below divided by 21 forms). A text can have more forms (see
// baseFormsCut and preparedText):
//
//   - keywords read up to maxKeywordForms (7) forms: the plain folds of the
//     base forms of baseFormsCut;
//   - any_regex and all_regex read up to maxRegexForms (21) forms: the seven
//     base forms, their seven plain folds and their seven skeleton folds,
//     when the text is not only ASCII.
//
// The skeleton fold (#140) is a new form only when a base form or its plain
// fold holds a rune of skeletonTable. The plain fold stays a regex form next
// to it, so no match of the plain fold is lost (see preparedText). A text
// with no rune of skeletonTable has at most 14 regex forms. Only a text with
// such a rune, which the server picks, reaches 21.
//
// Each form is at most MaxMatchInputBytes long, so the worst case for one
// match block is 21 times the cost above: 21 x 32 KiB x 2500, about 1.7G
// instruction-bytes. BenchmarkWorstCaseBlock measured about 15.9 s for one
// Match call over the 21 forms on an Apple M1 Pro (median of five runs with
// -benchtime=1x, 15.60 s to 16.03 s, go1.27.3). In the same run, the 14
// forms of BenchmarkWorstCaseBlockNoSkeleton took about 10.7 s, the same as
// before #140. So the seven skeleton folds add about 49%, in line with 21/14
// forms. These times are for one Match call: one rule on one text. The
// package doc says how the rule count multiplies this cost.
//
// The server alone picks the forms, so its text alone can raise the cost of
// one text about 18 times with the built-in rules. Before #140, the 13
// description rules on 32 KiB took about 50 ms for plain text and about
// 612 ms with a prefix that gave all fourteen forms (Apple M1 Pro), one
// Match call for each rule. For the current code, scaled by the ratio of the
// two benchmarks above (15.9 s / 10.7 s, about 1.49), the all-forms time is
// about 0.91 s. This is an estimate, not a new measurement. The plain text
// has one form, so it stays at about 50 ms.
//
// A scan does not pay this cost without a limit. It builds the forms of each
// text once and shares them across all the rules that read the text (see
// preparedText and Matcher.matchCtx). It also stops the analysis of a server
// at a deadline: matchCtx checks the context before each regex reads each
// form, so the overshoot past the deadline is at most about one regex on one
// form plus one build of the forms of one text.
//
// Building the forms has a cost too. The slowest known input is a run of
// U+009D, because each one can start an OSC (see oscExprC0): 128 KiB of it
// takes about 240 ms for each form that reads with ansiSeq.
// BenchmarkOSCStartRun times two baseFormsCut calls (through the test
// helpers matchForms and matchWindowCut): about 1.7 s (Apple M1 Pro, five
// runs with -benchtime=5x). A scan calls baseFormsCut once for each text,
// for all its rules, so it pays about half of that.
//
// A text longer than the window is cut, so padding can push a payload out of
// the reach of the regex and keyword rules. The match_window heuristic closes
// this evasion: a high rule with it fires when the window cuts one of the
// forms of baseFormsCut. The OSC text of a form, such as a link URL, does not
// count (see baseFormsCut).
//
// A schema target is many short texts (see matchSchemaPrepared). An
// any_regex, all_regex or keywords rule reads one schema in three passes:
// its strings (at most maxSchemaMatchBytes, 128 KiB, and
// maxSchemaMatchStrings strings), the seams of neighbour strings (at most
// maxSeamBytes, 128 KiB), and, when the JSON cannot be read in full, the raw
// text once, in the window of one description. So one schema costs about
// nine times the bound of one description: the seam pass doubles the cost of
// the string pass.
// BenchmarkSchemaWorstCase measured at most about 63.0 s for one Match call
// (4 strings of 32 KiB, 21 forms each), about 4 times the description worst
// case. In a scan, the schema rules of one tool share the decoded schema and
// the forms of each string, seam and raw text (see preparedText.schema), and
// the deadline above stops them too. The match_window heuristic fires on a
// schema whose strings these caps cut, but not when the seam budget is used
// up. The package doc gives the details.
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
	// one list, including the regexes that keywordExpr builds. So 64
	// large regexes cannot multiply the cost of a match block.
	maxTotalInsts = 2500
	// MaxHits is the largest number of hits that one Match call returns,
	// plus one summary hit that counts the rest.
	MaxHits = 16
)

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

// NoOffset is the Offset of a Hit that has no place in the raw text.
const NoOffset = -1

// Hit is one reason why a Matcher matched a text.
type Hit struct {
	// Offset is a byte offset in the raw text, or NoOffset for regex and
	// keyword hits: they run on the normalized text, so no raw offset is
	// known. Every hit of a schema target has NoOffset too, also a hit of a
	// heuristic or of the raw JSON text (see matchSchemaPrepared).
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

// Matcher is a compiled match block for one target. Make one with
// Match.CompileFor. A Matcher is immutable and safe for concurrent use.
type Matcher struct {
	kind      string
	target    Target           // how Match reads the text
	mode      schemaMode       // how Match reads a schema
	regexps   []*regexp.Regexp // any_regex, all_regex and keywords
	heuristic heuristicFunc    // heuristic
}

// heuristicFunc is the compiled function of a heuristic. It reads the
// prepared text p and returns its hits. It must not change p.
//
// Most heuristics read only p.raw (see rawHeuristic), so they build no forms
// of p. The match_window heuristic reads p.windowCut, so it shares the base
// forms of p with the regex and keyword rules (see matchWindowPrepared).
type heuristicFunc func(p *preparedText) []Hit

// rawHeuristic turns a heuristic that reads the raw text into a
// heuristicFunc. The result reads only p.raw.
func rawHeuristic(fn func(raw string) []Hit) heuristicFunc {
	return func(p *preparedText) []Hit { return fn(p.raw) }
}

// CompileFor checks the match block and compiles it for the target t. Every
// error is a *FieldError that names the field.
//
// The target decides how Matcher.Match reads its text. For TargetSchema, the
// text is a JSON schema, and Match reads each of its strings, and for some
// kinds also the seams of neighbour strings (see Matcher.Match). For any
// other target, Match reads the text as one text.
// CompileFor does not check t: Validate checks the target of a rule.
func (m Match) CompileFor(t Target) (*Matcher, error) {
	mt, err := m.compile()
	if err != nil {
		return nil, err
	}
	mt.target = t
	return mt, nil
}

// compile checks the match block and compiles it, with no target. Every
// error is a *FieldError that names the field.
func (m Match) compile() (*Matcher, error) {
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
		h, err := compileHeuristic(m.Heuristic, m.Params)
		if err != nil {
			return nil, err
		}
		mode := schemaAll
		if m.Heuristic == HeuristicMatchWindow {
			// match_window reports the schemas that the regex and keyword
			// rules cannot read in full (see schemaWindowHit).
			mode = schemaWindow
		}
		return &Matcher{kind: kindHeuristic, mode: mode, heuristic: h}, nil
	case m.AnyRegex != nil:
		return compileRegexMatcher(kindAnyRegex, m.AnyRegex, nil)
	case m.AllRegex != nil:
		return compileRegexMatcher(kindAllRegex, m.AllRegex, nil)
	default:
		return compileRegexMatcher(kindKeywords, m.Keywords, keywordExpr)
	}
}

// compileRegexMatcher compiles a list of the given kind into a Matcher. See
// compileRegexList for build.
func compileRegexMatcher(kind string, list []string, build func(entry, s string) (string, error)) (*Matcher, error) {
	res, err := compileRegexList(kind, list, build)
	if err != nil {
		return nil, err
	}
	return &Matcher{kind: kind, mode: schemaBudget, regexps: res}, nil
}

// Match returns the hits of the matcher in text, or nil when it does not
// match. It is safe for concurrent use: it builds the forms of text for this
// call only (see matchPrepared).
//
// Regexes and keywords read the normalized forms of the text, so an
// invisible character cannot split a keyword. Regexes read the forms of
// preparedText.regexForms, which also hold the folded forms, so a fullwidth
// letter or a combining mark cannot hide a word from a regex. Keywords read
// the forms of preparedText.keywordForms, the base forms of baseFormsCut folded
// with foldMarks. A regex or a keyword matches when it matches in one form.
// In all_regex, each regex must match, but each one can match in a different
// form. A heuristic reads the full raw text. The match_window heuristic
// reads the cut flag of the base forms (see matchWindowPrepared).
//
// A regex or keyword hit has the offset NoOffset, whatever form it matched
// in, because a form has no byte offsets in the raw text.
//
// For the schema target, text is a JSON schema, and Match runs the steps
// above on each decoded object key and string value (see
// matchSchemaPrepared).
// Every hit then has the offset NoOffset, and its detail starts with a label
// such as "schema string N" (the package doc lists the labels). The schema
// mode depends on the kind:
//
//   - a heuristic reads every string, with no cap and no seams (schemaAll).
//     So invisible_unicode, base64_blob and tag_or_bidi_override flag a
//     decoded string, also when the JSON text writes its runes as \u escapes;
//   - the match_window heuristic fires once when the regex and keyword rules
//     cannot read all the strings of the schema: the JSON is broken, the
//     schema caps cut the strings, or one string is longer than the match
//     window (schemaWindow). It does not fire when the seam budget is used
//     up;
//   - any_regex, all_regex and keywords read the strings until the schema
//     caps stop them. When no string matched, they also read each seam of
//     two neighbour strings, until the seam budget stops them (schemaBudget).
//     Only this mode has the seam pass.
//
// When the JSON cannot be read in full, every mode except schemaWindow also
// reads the raw text once.
func (m *Matcher) Match(text string) []Hit {
	if m == nil {
		return nil
	}
	return m.matchPrepared(prepareText(text))
}

// matchPrepared returns the hits of the matcher in p, as Match does. It is
// matchCtx with a context that is never done, so it never stops early and
// has no error.
//
// m and p must not be nil. Match does the nil check for m.
func (m *Matcher) matchPrepared(p *preparedText) []Hit {
	// The error is always nil here: context.Background is never done, and
	// matchCtx fails only when its context is done.
	hits, _ := m.matchCtx(context.Background(), p)
	return hits
}

// matchCtx returns the hits of the matcher in p, as Match does, and stops
// early when ctx is done.
//
// The forms of p are built at most once, so the matchers of many rules can
// share one p for the same text (see preparedText). A heuristic other than
// match_window gets only p.raw, so it does not build the forms of p. The
// match_window heuristic reads p.windowCut, so it builds only the base forms
// of p, and the regex and keyword rules then reuse them. matchCtx never
// writes into the forms of p.
//
// For the schema target, p.raw is a JSON schema. matchCtx reads it with
// matchSchemaPrepared and p.schema, so p decodes the schema once. All the
// schema rules that share p then share the decoded strings, and the
// preparedText of each string, seam and raw text, with its forms.
//
// The context: matchCtx checks ctx before it decodes a schema, before it
// builds the forms, before each regex or keyword reads each form, and before
// the heuristic. For a schema, matchSchemaPrepared also checks it before
// each string, seam and raw text. So when ctx ends, the extra work is at
// most one build of the forms of one text plus one regex on one form, or one
// heuristic call. matchCtx then returns the hits that it found so far, and
// an error that wraps ctx.Err(). The error names the kind and the list
// index, never input text. With a context that is never done, the error is
// nil, and the hits are the hits of Match.
//
// m and p must not be nil.
func (m *Matcher) matchCtx(ctx context.Context, p *preparedText) ([]Hit, error) {
	// Check before p.schema too, so a done ctx does not decode a schema.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("match %s: %w", m.kind, err)
	}
	if m.target == TargetSchema {
		return matchSchemaPrepared(ctx, p.schema(), m.mode, m.matchOne)
	}
	return m.matchOne(ctx, p)
}

// matchOne returns the hits of m in p.raw, read as one text (not as a
// schema), with the forms of p. It is the schemaMatchFunc of a schema rule
// (see matchCtx), and it checks ctx as matchCtx says.
func (m *Matcher) matchOne(ctx context.Context, p *preparedText) ([]Hit, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("match %s: %w", m.kind, err)
	}
	switch m.kind {
	case kindHeuristic:
		return m.heuristic(p), nil
	case kindAnyRegex:
		forms := p.regexForms()
		for i, re := range m.regexps {
			ok, err := matchesAny(ctx, re, forms)
			if err != nil {
				return nil, fmt.Errorf("match any_regex[%d]: %w", i, err)
			}
			if ok {
				return []Hit{{Offset: NoOffset, Detail: fmt.Sprintf("any_regex[%d] matched", i)}}, nil
			}
		}
		return nil, nil
	case kindAllRegex:
		forms := p.regexForms()
		for i, re := range m.regexps {
			ok, err := matchesAny(ctx, re, forms)
			if err != nil {
				return nil, fmt.Errorf("match all_regex[%d]: %w", i, err)
			}
			if !ok {
				return nil, nil
			}
		}
		var l hitList
		for i := range m.regexps {
			if l.keep(NoOffset) {
				l.hits = append(l.hits, Hit{Offset: NoOffset, Detail: fmt.Sprintf("all_regex[%d] matched", i)})
			}
		}
		return l.result("patterns"), nil
	case kindKeywords:
		forms := p.keywordForms()
		var l hitList
		for i, re := range m.regexps {
			ok, err := matchesAny(ctx, re, forms)
			if err != nil {
				// The keywords before i are read in full, so their hits stay.
				return l.result("keywords"), fmt.Errorf("match keywords[%d]: %w", i, err)
			}
			if ok && l.keep(NoOffset) {
				l.hits = append(l.hits, Hit{Offset: NoOffset, Detail: fmt.Sprintf("keywords[%d] matched", i)})
			}
		}
		return l.result("keywords"), nil
	}
	return nil, nil
}

// matchesAny reports whether re matches one of forms. It checks ctx before
// each form, so it stops after at most one regex call on one form when ctx
// ends. It then returns ctx.Err() as it is; the caller adds the context.
func matchesAny(ctx context.Context, re *regexp.Regexp, forms []string) (bool, error) {
	for _, f := range forms {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if re.MatchString(f) {
			return true, nil
		}
	}
	return false, nil
}

// compileRegexList compiles the entries of the list named field, with the
// size caps on each entry and on the sum of the programs. build turns an
// entry into its regex; a nil build uses the entry as it is.
func compileRegexList(field string, list []string, build func(entry, s string) (string, error)) ([]*regexp.Regexp, error) {
	if err := checkList(field, list); err != nil {
		return nil, err
	}
	res := make([]*regexp.Regexp, 0, len(list))
	total := 0
	for i, s := range list {
		entry := fmt.Sprintf("%s[%d]", field, i)
		if err := checkEntry(entry, s); err != nil {
			return nil, err
		}
		expr := s
		if build != nil {
			var err error
			if expr, err = build(entry, s); err != nil {
				return nil, err
			}
		}
		re, insts, err := compileRegex(entry, expr)
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
// named field. compileRegexList calls it after each regex, so a list that is
// too complex fails early, and the error gives the sum at that point.
func checkTotal(field string, total int) error {
	if total > maxTotalInsts {
		return &FieldError{Field: field, Msg: fmt.Sprintf("too complex in total: %d regex instructions, over the limit of %d", total, maxTotalInsts)}
	}
	return nil
}

// keywordExpr builds the regex of the keyword kw. entry names the keyword
// in an error.
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
func keywordExpr(entry, kw string) (string, error) {
	words := strings.FieldsFunc(foldMarks(normalizeForMatch(kw)), isKeywordSpace)
	if len(words) == 0 {
		return "", &FieldError{Field: entry, Msg: "has no visible characters"}
	}
	for j, w := range words {
		words[j] = regexp.QuoteMeta(w)
	}
	expr := `(?i:` + strings.Join(words, keywordSpaceClass+`+`) + `)`

	first, _ := utf8.DecodeRuneInString(words[0])
	if isWordRune(first) {
		expr = `(?:^|[^` + wordRuneClass + `])` + expr
	}
	last, _ := utf8.DecodeLastRuneInString(words[len(words)-1])
	if isWordRune(last) {
		expr += `(?:$|[^` + wordRuneClass + `])`
	}
	return expr, nil
}

// keywordSpaceClass is the regex class of the white space between the words
// of a keyword. isKeywordSpace is the same set. After normalizeForMatch, only
// the runes of re2SpaceRunes are left of this set in the text, so the rest of
// the class is defence in depth.
const keywordSpaceClass = `[\s\v\x{85}\p{Z}\x{2800}]`

// wordRuneClass is the content of the regex class of a word rune.
// isWordRune is the same set.
const wordRuneClass = `\p{L}\p{M}\p{N}_`

// isKeywordSpace reports whether r separates the words of a keyword. It is
// the same set as keywordSpaceClass.
func isKeywordSpace(r rune) bool {
	return unicode.IsSpace(r) || r == '\u2800'
}

// isWordRune reports whether r is a letter, a mark, a number or '_'. It is
// the same set as wordRuneClass.
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
	tree, insts, err := progSize(expr)
	if err != nil {
		return nil, 0, regexError(field, err)
	}
	if insts > maxProgInsts {
		return nil, 0, &FieldError{Field: field, Msg: fmt.Sprintf("too complex: %d regex instructions, over the limit of %d", insts, maxProgInsts)}
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

// progSize parses expr with the flags of regexp.Compile and returns the
// parse tree and the number of instructions of its compiled program.
func progSize(expr string) (*syntax.Regexp, int, error) {
	tree, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, 0, err
	}
	prog, err := syntax.Compile(tree.Simplify())
	if err != nil {
		return nil, 0, err
	}
	return tree, len(prog.Inst), nil
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
