package rules

// Test helpers of package rules that the external test package rules_test
// also uses.
var (
	LoadPopular         = loadPopular
	AssertFindingNoLeak = assertFindingNoLeak
	BuiltinCompiler     = builtinCompiler
	MustBuiltin         = mustBuiltin
)
