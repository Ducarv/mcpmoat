package rules

// Compiler turns the Match section of a rule into a Matcher for a target.
// A nil Compiler means "do not compile": the loader then skips matching.
//
// The loader takes a Compiler through WithCompiler. RunCases takes the Matcher
// that a Compiler returns. The usual Compiler calls Match.CompileFor(t). The
// Target decides how the Matcher reads its text: a schema rule reads each
// string of the JSON schema alone and, for any_regex, all_regex and keywords,
// each seam of two neighbour strings (see the package doc). The other targets
// read one text.
type Compiler func(m Match, t Target) (*Matcher, error)
