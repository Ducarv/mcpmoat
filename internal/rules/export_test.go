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
