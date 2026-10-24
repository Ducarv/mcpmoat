package rules

import (
	"slices"
	"sync"
)

// maxRegexForms is the largest number of forms that regexForms returns, 21
// in all: the seven base forms of matchForms, the seven plain folds
// (foldMarks) and the seven skeleton folds (foldSkeleton) of the base forms.
const maxRegexForms = 3 * maxBaseForms

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
	regex    []string  // base forms, then the foldMarks and the foldSkeleton of each non-ASCII base form (dedup)
	keywords []string  // the foldMarks of each base form, no skeleton (dedup)
}

// prepareText returns a preparedText for raw. It does not build the forms yet
// (see preparedText).
func prepareText(raw string) *preparedText {
	return &preparedText{raw: raw}
}

// regexForms returns the forms that the regex matchers (any_regex and
// all_regex) read: the base forms of matchForms, and then, for each base
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
// the same forms as before the skeleton. Each form is at most
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
// (foldMarks) of each base form of matchForms, without the confusable
// skeleton of the regex forms. Equal folds are kept only once, so there are
// at most maxKeywordForms forms, each at most MaxMatchInputBytes long.
//
// The caller must not modify the returned slice or its elements: the next
// call returns the same slice.
func (p *preparedText) keywordForms() []string {
	p.once.Do(p.build)
	return p.keywords
}

// build builds the forms of p. regexForms and keywordForms call it through
// p.once, so it runs once. It calls matchForms once, and it folds each base
// form once with foldMarks: the plain fold is a keyword form and a regex
// form. It then adds the skeleton fold (foldSkeleton) to the regex forms. A
// base form that is only ASCII is its own fold, so it is not folded
// (foldMarks and foldSkeleton would return it unchanged).
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
// so build does not call foldMarks twice for one base form.
//
// The cut of the match window does not change: matchWindowCut reads the
// base forms of raw (see buildFormCut), and the max_length heuristic counts
// the runes of raw. Neither reads the folds. A fold is never longer than its
// base form (see foldMarks and skeleton), so it holds all of the text of the
// base form.
func (p *preparedText) build() {
	base := matchForms(p.raw) // distinct already (see appendNew)
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
// the caller. foldSkeleton(f) is skeleton(foldMarks(skeleton(f))). When no
// rune of f maps, skeleton(f) is f, so the result is skeleton(kw), and
// foldMarks does not run again. Only a base form with a rune of
// skeletonTable runs foldMarks a second time, on skeleton(f).
func skeletonFold(f, kw string) string {
	s1 := skeleton(f)
	if s1 == f {
		return skeleton(kw)
	}
	return skeleton(foldMarks(s1))
}
