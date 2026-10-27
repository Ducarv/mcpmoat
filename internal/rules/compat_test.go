package rules

// Test-only entry points. The production code has one entry point for each
// job (baseFormsCut, prepareSchemaFrom, matchSchemaPrepared and
// compileRegexTree). The helpers below wrap it, so a test can check one
// part of the result with one short call.

import (
	"context"
	"regexp"
)

// matchForms returns the base forms of s: baseFormsCut without the cut flag.
func matchForms(s string) []string {
	forms, _ := baseFormsCut(s)
	return forms
}

// matchWindowCut returns the cut flag of the match window for s:
// baseFormsCut without the forms.
func matchWindowCut(s string) bool {
	_, cut := baseFormsCut(s)
	return cut
}

// formModes returns the modes of the forms that baseFormsCut builds for s,
// in the order of the forms (see formFlags.modes). It reads the part of s
// that normalizeForMatch reads, as baseFormsCut does (see rawFormFlags).
func formModes(s string) []formMode {
	return rawFormFlags(s).modes()
}

// compileRegex is compileRegexTree without the parse tree: it returns the
// compiled regex of expr and the number of instructions of its program.
func compileRegex(field, expr string) (*regexp.Regexp, int, error) {
	re, _, insts, err := compileRegexTree(field, expr)
	return re, insts, err
}

// hasSeqStart reports whether s holds ESC, U+009B or U+009D: the seqStart
// flag that formModes reads from scanFormFlags.
func hasSeqStart(s string) bool {
	return scanFormFlags(s).seqStart
}

// hasSeqC0 reports whether s holds ESC or U+009B and a C0 control rune of
// csiC0: the check that formModes reads from scanFormFlags (see
// formFlags.hasSeqC0).
func hasSeqC0(s string) bool {
	return scanFormFlags(s).hasSeqC0()
}

// prepareSchema decodes raw and returns its preparedSchema, with a new
// preparedText for raw (see prepareSchemaFrom).
func prepareSchema(raw string) *preparedSchema {
	return prepareSchemaFrom(prepareText(raw))
}

// matchSchema runs match on the strings, seams and raw text of the schema
// raw, as matchSchemaPrepared does, and returns the hits. It makes a new
// preparedSchema for raw, so nothing is shared with other rules. It uses a
// background context and a match that cannot fail, so it has no error to
// return.
func matchSchema(raw string, mode schemaMode, match func(string) []Hit) []Hit {
	inner := func(_ context.Context, p *preparedText) ([]Hit, error) {
		return match(p.raw), nil
	}
	// The error is always nil here: context.Background is never done, and
	// inner never fails.
	hits, _ := matchSchemaPrepared(context.Background(), prepareSchema(raw), mode, inner)
	return hits
}
