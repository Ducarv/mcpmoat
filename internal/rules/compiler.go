package rules

// Compiler turns the Match section of a rule into a Matcher for a target.
// A nil Compiler means "do not compile": the loader then skips matching.
//
// The loader takes a Compiler through WithCompiler. RunCases takes the Matcher
// that a Compiler returns. The usual Compiler calls Match.Compile.
type Compiler func(m Match, t Target) (*Matcher, error)
