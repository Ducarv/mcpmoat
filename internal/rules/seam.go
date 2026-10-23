package rules

// Matcher reports whether a rule matches one piece of text.
type Matcher interface {
	Match(text string) (bool, error)
}

// Compiler turns the Match section of a rule into a Matcher for a target.
// Issues #35 and #36 provide the real implementation. A nil Compiler means
// "do not compile": the loader and the test harness then skip matching.
//
// The loader and the harness take a Compiler as an option. There is no global
// variable. The real one will be
// `func Compile(m Match, t Target) (Matcher, error)`, added by issue #35 in a
// new file named matcher.go.
type Compiler func(m Match, t Target) (Matcher, error)
