package rules

import "slices"

// preparedText is one target text and the match forms built from it. The
// forms are built once for each target text, so the rules that read the same
// text do not normalize it again. The build is lazy: it runs on the first
// call of regexForms or keywordForms. A heuristic reads only raw, so a text
// that only heuristics read is never normalized.
//
// A preparedText is not safe for concurrent use: the first call builds the
// forms and writes them into the struct. Use one preparedText in one
// goroutine. A Matcher stays safe for concurrent use, because Match makes a
// new preparedText for each call.
type preparedText struct {
	raw      string   // the target text, as the server sent it
	built    bool     // regex and keywords hold the forms
	regex    []string // base forms, then the fold of each non-ASCII base form (dedup)
	keywords []string // the fold of each base form (dedup)
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
// Equal forms are kept only once. matchForms gives at most six base forms,
// so there are at most twelve forms: the six base forms and their six folds.
// Each form is at most MaxMatchInputBytes long. A plain ASCII text has one
// form, so it costs no more.
//
// The caller must not modify the returned slice or its elements: the next
// call returns the same slice.
func (p *preparedText) regexForms() []string {
	p.build()
	return p.regex
}

// keywordForms returns the forms that the keyword matcher reads: the fold
// (foldMarks) of each base form of matchForms. Equal folds are kept only
// once, so there are at most six forms, each at most MaxMatchInputBytes
// long.
//
// The caller must not modify the returned slice or its elements: the next
// call returns the same slice.
func (p *preparedText) keywordForms() []string {
	p.build()
	return p.keywords
}

// build builds the forms of p once. It calls matchForms once and folds each
// base form once. A base form that is only ASCII is its own fold, so it is
// not folded (foldMarks would return it unchanged).
func (p *preparedText) build() {
	if p.built {
		return
	}
	p.built = true
	base := matchForms(p.raw) // distinct already (see appendNew)
	regex := slices.Clone(base)
	var keywords []string
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
