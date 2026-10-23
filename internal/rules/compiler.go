package rules

// Matcher reports whether a rule matches one piece of text.
type Matcher interface {
	Match(text string) (bool, error)
}

// Compiler turns the Match section of a rule into a Matcher for a target.
// A nil Compiler means "do not compile": the loader then skips matching.
//
// The loader takes a Compiler through WithCompiler. RunCases takes the Matcher
// that a Compiler returns. A Compiler must return a nil interface, not a typed
// nil pointer, when it has no Matcher. Issues #35 and #36 provide the real
// implementation.
type Compiler func(m Match, t Target) (Matcher, error)
