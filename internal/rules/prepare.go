package rules

import (
	"slices"
	"sync"
)

// maxRegexForms is the largest number of forms that regexForms returns, 21
// in all: the seven base forms of baseFormsCut, the seven plain folds
// (foldMarks) and the seven skeleton folds (foldSkeleton) of the base forms.
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
//     so the match_window heuristic does not build the folds.
//   - Step two (buildFolds) builds the plain folds and the skeleton folds
//     from the base forms of step one. regexForms and keywordForms run it,
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
// p also share the decoded strings, the preparedText of each string and of
// each seam, and so the forms and the window cut flag of each of them (see
// preparedSchema).
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

	foldOnce sync.Once // guards buildFolds (step two)
	regex    []string  // base forms, then their plain and skeleton folds (dedup)
	keywords []string  // the foldMarks of each base form, no skeleton (dedup)

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

// regexForms returns the forms that the regex matchers (any_regex and
// all_regex) read: the base forms of baseFormsCut, and then, for each base
// form that is not only ASCII, its plain fold (foldMarks) and its skeleton
// fold (foldSkeleton), each one when it is a new form. A regex matches when
// it matches in one form. So the regex `ignore` also matches the fullwidth
// "ignore" (U+FF49 ...), the mathematical bold "ignore" (U+1D422 ...),
// "ig" + U+0336 + "nore" and U+0456 + "gnore" (Cyrillic i).
//
// The skeleton fold is the plain fold with the confusable skeleton of
// confusables.go applied to it: each letter of another script that looks
// like an ASCII letter becomes that letter. So "~/." + U+0455 U+0455 U+04BB
// (Cyrillic) matches the regex `~/\.ssh`. The keyword forms do not get the
// skeleton (see keywordForms).
//
// Only the text is folded, not the pattern. So a pattern with an accent, a
// mark or a letter of skeletonTable matches only in the base forms.
//
// Equal forms are kept only once, so there are at most maxRegexForms forms:
// the maxBaseForms base forms, their plain folds and their skeleton folds.
// When no rune of skeletonTable is in a base form or in its plain fold, its
// skeleton fold equals its plain fold, so it adds no form: such a text has
// only its base forms and their plain folds. Each form is at most
// MaxMatchInputBytes long. A plain ASCII text has one form, so it costs no
// more.
//
// The caller must not modify the returned slice or its elements: the next
// call returns the same slice.
func (p *preparedText) regexForms() []string {
	p.foldOnce.Do(p.buildFolds)
	return p.regex
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

// buildFolds is step two of the build (see preparedText). regexForms and
// keywordForms call it through p.foldOnce, so it runs once. It gets the base
// forms from step one, and it folds each base form once with foldMarks: the
// plain fold is a keyword form and a regex form. It then adds the skeleton
// fold (foldSkeleton) to the regex forms. A base form that is only ASCII is
// its own fold, so it is not folded (foldMarks and foldSkeleton would return
// it unchanged).
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
	// A copy: regex gets new elements, and base must stay as step one made it.
	regex := append(make([]string, 0, maxRegexForms), base...)
	keywords := make([]string, 0, maxKeywordForms)
	for _, f := range base {
		// An ASCII form is its own fold, and regex holds it already.
		if isASCII(f) {
			keywords = appendNew(keywords, f)
			continue
		}
		kw := foldMarks(f)
		keywords = appendNew(keywords, kw)
		regex = appendNew(regex, kw)
		// Usually equal to kw (no rune of skeletonTable), so not added.
		regex = appendNew(regex, skeletonFold(f, kw))
	}
	// Clip, so an append by a caller cannot write into the shared array.
	p.regex = slices.Clip(regex)
	p.keywords = slices.Clip(keywords)
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
