package rules

import (
	"slices"
	"sync"
)

// maxRegexForms is the largest number of forms that regexForms returns: the
// base forms of matchForms and their folds.
const maxRegexForms = 2 * maxBaseForms

// maxKeywordForms is the largest number of forms that keywordForms returns:
// the folds of the base forms of matchForms.
const maxKeywordForms = maxBaseForms

// preparedText is one target text and the match forms built from it. The
// forms are built once for each target text, so the rules that read the same
// text do not normalize it again. The build is lazy: it runs on the first
// call of regexForms or keywordForms. A heuristic gets only raw, so it does
// not build the forms of p. The match_window heuristic builds its own forms
// of raw (see matchWindowCut).
//
// The forms are shared only when the caller shares the preparedText: a
// caller that builds one preparedText for each target text and calls
// matchPrepared for every rule with it builds the forms once. Match builds
// one preparedText for each call. A schema rule does not share p:
// matchPrepared reads a schema with matchSchema, and each schema string gets
// its own preparedText (see matchPrepared).
//
// A preparedText is safe for concurrent reads: once guards the build, so the
// first call of regexForms or keywordForms builds the forms, and the other
// calls wait for it and then only read them. Do not copy a preparedText
// (it holds a sync.Once); pass the pointer.
type preparedText struct {
	raw      string    // the target text, as the server sent it
	once     sync.Once // guards build
	regex    []string  // base forms, then the fold of each non-ASCII base form (dedup)
	keywords []string  // the fold of each base form (dedup)
}

// prepareText returns a preparedText for raw. It does not build the forms yet
// (see preparedText).
func prepareText(raw string) *preparedText {
	return &preparedText{raw: raw}
}

// regexForms returns the forms that the regex matchers (any_regex and
// all_regex) read: the base forms of matchForms, and then the fold
// (foldMarks) of each base form that is not only ASCII, when the fold is a
// new form. A regex matches when it matches in one form. So the regex
// `ignore` also matches the fullwidth "ignore" (U+FF49 ...), the
// mathematical bold "ignore" (U+1D422 ...) and "ig" + U+0336 + "nore".
//
// Only the text is folded, not the pattern. So a pattern with an accent or a
// mark matches only in the base forms.
//
// Equal forms are kept only once, so there are at most maxRegexForms forms:
// the maxBaseForms base forms and their folds. Each form is at most
// MaxMatchInputBytes long. A plain ASCII text has one form, so it costs no
// more.
//
// The caller must not modify the returned slice or its elements: the next
// call returns the same slice.
func (p *preparedText) regexForms() []string {
	p.once.Do(p.build)
	return p.regex
}

// keywordForms returns the forms that the keyword matcher reads: the fold
// (foldMarks) of each base form of matchForms. Equal folds are kept only
// once, so there are at most maxKeywordForms forms, each at most
// MaxMatchInputBytes long.
//
// The caller must not modify the returned slice or its elements: the next
// call returns the same slice.
func (p *preparedText) keywordForms() []string {
	p.once.Do(p.build)
	return p.keywords
}

// build builds the forms of p. regexForms and keywordForms call it through
// p.once, so it runs once. It calls matchForms once and folds each base form
// once. A base form that is only ASCII is its own fold, so it is not folded
// (foldMarks would return it unchanged).
func (p *preparedText) build() {
	base := matchForms(p.raw) // distinct already (see appendNew)
	regex := append(make([]string, 0, maxRegexForms), base...)
	keywords := make([]string, 0, maxKeywordForms)
	for _, f := range base {
		fold := f
		if !isASCII(f) {
			fold = foldMarks(f)
		}
		keywords = appendNew(keywords, fold)
		regex = appendNew(regex, fold) // an ASCII fold is a base form, so it is not added
	}
	// Clip, so an append by a caller cannot write into the shared array.
	p.regex = slices.Clip(regex)
	p.keywords = slices.Clip(keywords)
}
