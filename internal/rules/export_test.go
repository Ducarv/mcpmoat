package rules

// Test helpers of package rules that the external test package rules_test
// also uses.
var (
	LoadPopular         = loadPopular
	AssertFindingNoLeak = assertFindingNoLeak
	BuiltinCompiler     = builtinCompiler
	MustBuiltin         = mustBuiltin

	// PrepareText builds a preparedText for one target text (see prepareText).
	PrepareText = prepareText
	// MatchPrepared matches one Matcher against a shared preparedText (see
	// Matcher.matchPrepared). It is a method expression, so the Matcher is
	// the first argument.
	MatchPrepared = (*Matcher).matchPrepared
)

// regexForms returns the forms of s that the regex matchers read: at most
// fourteen forms, the seven base forms of matchForms and their folds. It
// builds a new preparedText for s each time, so the tests, the fuzz tests and
// the benchmarks can call it. The matchers use preparedText.regexForms, which
// builds the forms only once for each text.
func regexForms(s string) []string {
	return prepareText(s).regexForms()
}
