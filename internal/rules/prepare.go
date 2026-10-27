package rules

import (
	"slices"
	"strings"
	"sync"

	"golang.org/x/text/unicode/norm"
)

// maxRegexForms is the largest number of forms that regexFormParts
// returns, 21 in all: the seven base forms of baseFormsCut, the seven plain
// folds (foldMarks) and the seven skeleton folds (foldSkeleton) of the base
// forms.
const maxRegexForms = 3 * maxBaseForms

// maxKeywordForms is the largest number of forms that keywordForms returns:
// the folds of the base forms of baseFormsCut.
const maxKeywordForms = maxBaseForms

// preparedText is one target text and the match forms built from it. The
// forms are built once for each target text, so the rules that read the same
// text do not normalize it again.
//
// The build is lazy and has two steps. Each step runs at most once:
//
//   - Step one (buildBase) calls baseFormsCut once. It keeps the base forms
//     and the cut flag of the match window. windowCut runs only this step,
//     so the match_window heuristic does not build the folds, and the regex
//     and keyword rules that read p later reuse its base forms.
//   - Step two (buildFolds) builds the plain folds and the skeleton folds
//     from the base forms of step one. regexFormParts and keywordForms run it,
//     and it runs step one first when step one did not run yet.
//
// The other heuristics get only raw, so they build no forms of p.
//
// The forms are shared only when the caller shares the preparedText: a
// caller that builds one preparedText for each target text and calls
// matchPrepared for every rule with it builds the forms once. Match builds
// one preparedText for each call.
//
// For the schema target, raw is a JSON schema. schema decodes it once into
// a preparedSchema and keeps it. So all schema rules of one tool that share
// p also share the decoded strings, the preparedText of each string, of each
// seam and of the raw text (p itself), and so the forms and the window cut
// flag of each of them (see preparedSchema).
//
// A preparedText is safe for concurrent reads. A sync.Once guards each step
// and the schema: the first call builds, and the other calls wait for it and
// then only read. Do not copy a preparedText (it holds sync.Once values);
// pass the pointer.
type preparedText struct {
	raw string // the target text, as the server sent it

	baseOnce sync.Once // guards buildBase (step one)
	base     []string  // the base forms of baseFormsCut (dedup)
	cut      bool      // the cut flag of baseFormsCut

	foldOnce  sync.Once // guards buildFolds (step two)
	regex     []string  // the front forms, then the twin forms (dedup; see regexFormParts)
	twinStart int       // regex[twinStart:] are the twin forms
	keywords  []string  // the foldMarks of each base form, no skeleton (dedup)

	schemaOnce sync.Once       // guards the prepareSchemaFrom call of schema
	sch        *preparedSchema // raw decoded as a schema; nil until schema runs
}

// prepareText returns a preparedText for raw. It does not build the forms or
// the schema yet (see preparedText).
func prepareText(raw string) *preparedText {
	return &preparedText{raw: raw}
}

// windowCut reports whether the match window cuts raw: the cut flag of
// baseFormsCut(raw). It runs step one (buildBase) when it did not run yet,
// and it does not build the folds.
func (p *preparedText) windowCut() bool {
	p.baseOnce.Do(p.buildBase)
	return p.cut
}

// schema returns raw decoded as a tool schema (see prepareSchemaFrom). The
// first call decodes it, and the next calls return the same preparedSchema.
// So the schema rules that share p decode the schema once and share the
// forms of its strings and seams. The raw text pass of the schema reads p
// itself, so p is not prepared a second time.
func (p *preparedText) schema() *preparedSchema {
	p.schemaOnce.Do(func() { p.sch = prepareSchemaFrom(p) })
	return p.sch
}

// regexFormParts returns the forms that the regex matchers (any_regex and
// all_regex) read, in two parts: front and then twin. The forms are the
// base forms of baseFormsCut, and for each base form that is not only
// ASCII, its plain fold (foldMarks) and its skeleton fold (foldSkeleton).
// Each form is kept only when it is a new form. A regex matches when it
// matches in one form. So the regex `ignore` also matches the fullwidth
// "ignore" (U+FF49 ...), the mathematical bold "ignore" (U+1D422 ...),
// "ig" + U+0336 + "nore" and U+0456 + "gnore" (Cyrillic i).
//
// The skeleton fold is the plain fold with the confusable skeleton of
// confusables.go applied to it: each letter of another script that looks
// like an ASCII letter becomes that letter. So "~/." + U+0455 U+0455 U+04BB
// (Cyrillic) matches the regex `~/\.ssh`. The keyword forms do not get the
// skeleton (see keywordForms).
//
// twin holds the twin forms: the skeleton folds, and the plain folds for
// which foldAddsIL is true. front holds the other forms: the base forms and
// the other plain folds. Matcher.matchRegex reads twin with the I/l-blind
// twin of each regex and front with the regex itself (see the twin.go file
// comment). A text with no rune of skeletonTable and no compatibility rune
// that folds to "I" or "l", such as a plain ASCII text, has an empty twin.
//
// Only the text is folded, not the pattern. So a pattern with an accent, a
// mark or a letter of skeletonTable matches only in the base forms.
//
// Equal forms are kept only once, so there are at most maxRegexForms forms
// in the two parts: the maxBaseForms base forms, their plain folds and
// their skeleton folds. When no rune of skeletonTable is in a base form or
// in its plain fold, its skeleton fold equals its plain fold, so it adds no
// form: such a text has only its base forms and their plain folds. Each
// form is at most MaxMatchInputBytes long. A plain ASCII text has one form,
// so it costs no more.
//
// front has no room after its end, so an append to it cannot write into
// twin. The caller must not modify the returned slices or their elements:
// the next call returns the same slices.
func (p *preparedText) regexFormParts() (front, twin []string) {
	p.foldOnce.Do(p.buildFolds)
	return p.regex[:p.twinStart:p.twinStart], p.regex[p.twinStart:]
}

// keywordForms returns the forms that the keyword matcher reads: the fold
// (foldMarks) of each base form of baseFormsCut, without the confusable
// skeleton of the regex forms. Equal folds are kept only once, so there are
// at most maxKeywordForms forms, each at most MaxMatchInputBytes long.
//
// The caller must not modify the returned slice or its elements: the next
// call returns the same slice.
func (p *preparedText) keywordForms() []string {
	p.foldOnce.Do(p.buildFolds)
	return p.keywords
}

// buildBase is step one of the build (see preparedText). windowCut and
// buildFolds call it through p.baseOnce, so it runs once. It calls
// baseFormsCut once, so the base forms and the cut flag come from the same
// build of each form.
func (p *preparedText) buildBase() {
	p.base, p.cut = baseFormsCut(p.raw)
}

// buildFolds is step two of the build (see preparedText). regexFormParts
// and keywordForms call it through p.foldOnce, so it runs once. It gets the
// base forms from step one, and it folds each base form once with
// foldMarks: the plain fold is a keyword form and a regex form. It then adds
// the skeleton fold (foldSkeleton) to the regex forms. A base form that is
// only ASCII is its own fold, so it is not folded (foldMarks and
// foldSkeleton would return it unchanged).
//
// The regex forms are built in two lists, front and twin (see
// regexFormParts), and twinStart keeps the index of the first twin form.
// The base forms and the plain folds go to front, but a plain fold in which
// a compatibility mapping made a new "I" or "l" (see foldAddsIL) goes to
// twin, and so does each skeleton fold that differs from its plain fold. A
// skeleton fold that equals its plain fold has no rune of skeletonTable, so
// it adds nothing. A form is added only when neither list holds it. When a
// twin form is in front already, it moves to twin (see addTwinForm). So
// each text is in one list only, and the texts and their count are the same
// as with one list: at most maxRegexForms.
//
// The two steps have their own sync.Once, so buildFolds can call
// p.baseOnce.Do while it runs under p.foldOnce. buildBase never calls
// p.foldOnce, so the two never wait for each other in a loop.
//
// The plain fold stays a regex form next to the skeleton fold, so no match
// of the plain fold is lost. The skeleton can move a word edge: a rune of
// skeletonTable next to a payload becomes an ASCII letter. So Arabic U+0647
// (heh, "o") + "." + U+FF45 U+FF4E U+FF56 (fullwidth "env") has the
// skeleton fold "o.env", which a pattern that needs a non-word rune before
// the dot, such as `[^\w.]\.env`, does not match. The plain fold U+0647 +
// ".env" keeps the old edge, so the pattern matches in it.
//
// skeletonFold computes the skeleton fold from the plain fold when it can,
// so buildFolds does not call foldMarks twice for one base form.
//
// The cut of the match window does not change: windowCut reads the cut flag
// of the base forms of raw (see buildFormCut), and the max_length heuristic
// counts the runes of raw. Neither reads the folds. A fold is never longer
// than its base form (see foldMarks and skeleton), so it holds all of the
// text of the base form.
func (p *preparedText) buildFolds() {
	p.baseOnce.Do(p.buildBase)
	base := p.base // distinct already (see appendNew)
	// A copy: front gets new elements, and base must stay as step one made it.
	front := append(make([]string, 0, maxRegexForms), base...)
	twin := make([]string, 0, maxRegexForms)
	keywords := make([]string, 0, maxKeywordForms)
	type skelFold struct{ plain, skel string }
	skels := make([]skelFold, 0, maxBaseForms) // added after all plain folds
	for _, f := range base {
		// An ASCII form is its own fold, and front holds it already.
		if isASCII(f) {
			keywords = appendNew(keywords, f)
			continue
		}
		kw := foldMarks(f)
		keywords = appendNew(keywords, kw)
		switch {
		case foldAddsIL(f, kw):
			front, twin = addTwinForm(front, twin, kw)
		case !slices.Contains(twin, kw):
			front = appendNew(front, kw)
		}
		skels = append(skels, skelFold{kw, skeletonFold(f, kw)})
	}
	for _, s := range skels {
		// Usually equal to its plain fold (no rune of skeletonTable), so it
		// adds nothing: the plain fold is in its list already.
		if s.skel != s.plain {
			front, twin = addTwinForm(front, twin, s.skel)
		}
	}
	p.twinStart = len(front)
	// Clip, so an append by a caller cannot write into the shared array.
	p.regex = slices.Clip(append(front, twin...))
	p.keywords = slices.Clip(keywords)
}

// foldAddsIL reports whether the plain fold kw = foldMarks(f) holds more
// ASCII "I" and "l" than the canonical decomposition (NFD) of f. So it is
// true when the fold made an "I" or an "l" from a compatibility mapping,
// such as from fullwidth U+FF29 or the roman numeral U+217C (see the twin.go
// file comment for the look-alikes). Such a rune is not in skeletonTable,
// so the skeleton fold of f equals kw and adds no form. So kw goes to the
// twin forms (see regexFormParts).
//
// An accented letter, such as U+00CF (I with diaeresis), U+0130 (I with dot
// above) or U+013E (l with caron), is not a look-alike: its NFD is the ASCII
// "I" or "l" and combining marks, and the fold only drops the marks. It is
// a normal letter of French, Czech, Slovak, Turkish and other languages. So
// it does not count, and a text with such a letter reads with each regex as
// it is. NFD splits each accented "I" and "l" of f into the ASCII letter and
// its marks, and keeps each compatibility rune as it is. So NFD(f) holds the
// ASCII "I" and "l" of f and of its accented letters, and no other. For
// each rune, the fold holds at least the "I" and "l" of its NFD (a test
// checks all runes), so the counts add up rune by rune. In the Unicode
// tables of the Go version of go.mod, 61 runes fold to exactly "I" or "l":
// 38 of them count, and 23 are an "I" or "l" with marks (U+00CC to U+00CF,
// U+0128, U+012A, U+012C, U+012E, U+0130, U+013A, U+013C, U+013E, U+01CF,
// U+0208, U+020A, U+1E2C, U+1E2E, U+1E37, U+1E39, U+1E3B, U+1E3D, U+1EC8
// and U+1ECA) that do not. The 27 runes that fold to a longer text with an
// "I" or "l", such as U+2161 ("II") and U+FB02 ("fl"), all count.
//
// The first test is cheap and has no allocation: foldMarks keeps each ASCII
// byte of f, so when kw has no more "I" and "l" than f, no rune folded to
// them, and NFD does not run. This is the case for every ASCII f (kw is f)
// and for most other texts. NFD runs only when a rune folded to "I" or "l",
// and it allocates only when f is not in NFD already.
func foldAddsIL(f, kw string) bool {
	n := countIL(kw)
	if n <= countIL(f) {
		return false
	}
	return n > countIL(norm.NFD.String(f))
}

// countIL returns the number of the bytes "I" and "l" in s.
func countIL(s string) int {
	return strings.Count(s, "I") + strings.Count(s, "l")
}

// addTwinForm adds s to the twin forms and returns both lists. It does
// nothing when twin holds s already. When front holds s, s moves from front
// to twin: the I/l-blind twin of a regex matches every text that the regex
// matches (see twinFromTree), so reading s with the twin only loses no match.
func addTwinForm(front, twin []string, s string) (newFront, newTwin []string) {
	if slices.Contains(twin, s) {
		return front, twin
	}
	if i := slices.Index(front, s); i >= 0 {
		front = slices.Delete(front, i, i+1)
	}
	return front, append(twin, s)
}

// skeletonFold returns foldSkeleton(f), with kw = foldMarks(f) computed by
// the caller. When no rune of f maps, skeleton(f) is f, so the result is
// skeleton(kw), and foldMarks does not run again. Only a base form with a rune of
// skeletonTable runs foldMarks a second time, on skeleton(f).
func skeletonFold(f, kw string) string {
	s1 := skeleton(f)
	if s1 == f {
		return skeleton(kw)
	}
	return skeleton(foldMarks(s1))
}
