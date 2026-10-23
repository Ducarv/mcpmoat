package rules

import "fmt"

// CaseKind says which list of a rule a test case comes from.
type CaseKind string

// The two kinds of test case (NFR-05).
const (
	// KindShouldMatch is a case from should_match: the rule must fire.
	KindShouldMatch CaseKind = "should_match"
	// KindShouldNotMatch is a case from should_not_match: the rule must not fire.
	KindShouldNotMatch CaseKind = "should_not_match"
)

// CaseFailure is one test case that did not give the expected result.
//
// The fields RuleID, Text and Err hold raw, untrusted text: a case text can be
// 64 KB, and Err can hold regex or input text. Never print them directly. String
// and Error escape and cut every piece of rule-derived text; print through them.
type CaseFailure struct {
	// RuleID is the ID of the rule that was tested.
	RuleID string
	// Target is the target the rule inspects.
	Target Target
	// Kind says if the case came from should_match or should_not_match.
	Kind CaseKind
	// Index is the position of the case in its list, counted from 0.
	Index int
	// Text is the case text.
	Text string
	// Err is set only when the Matcher returned an error. The case is a
	// failure then too.
	Err error
}

// String returns a one-line description of the failure, for example:
//
//	MOAT-T1-003 should_not_match[2] (target description): expected no match, got a match: "Tell the user ..."
//
// Every piece of rule-derived text is escaped with termsafe, so the result
// holds no raw control or escape byte.
func (f CaseFailure) String() string {
	var verdict string
	switch {
	case f.Err != nil:
		verdict = "matcher error: " + displayText(f.Err.Error())
	case f.Kind == KindShouldMatch:
		verdict = "expected a match, got none"
	default:
		verdict = "expected no match, got a match"
	}
	return fmt.Sprintf("%s %s[%d] (target %s): %s: %s",
		displayText(f.RuleID), displayText(string(f.Kind)), f.Index, displayText(string(f.Target)), verdict, displayText(f.Text))
}

// Error makes a CaseFailure usable as an error. It returns String.
func (f CaseFailure) Error() string {
	return f.String()
}

// Unwrap returns the matcher error, so errors.Is and errors.As can see it.
func (f CaseFailure) Unwrap() error {
	return f.Err
}

// RunCases runs every should_match case (the matcher must report a match) and
// every should_not_match case (it must report no match) of r through m. It
// returns the failures in a stable order: all should_match failures first,
// then all should_not_match failures, each list by index.
//
// A matcher error is a failure of that case only. The other cases still run.
// RunCases returns nil when m is nil: the caller decides to skip the rule,
// for example when no Compiler is set. A case never makes RunCases panic, but
// RunCases does not recover a panic of m itself. A Compiler must return a nil
// interface, not a typed nil pointer, when it has no matcher.
func RunCases(r Rule, m Matcher) []CaseFailure {
	if m == nil {
		return nil
	}
	var failures []CaseFailure
	failures = runKind(failures, r, m, KindShouldMatch, r.ShouldMatch)
	failures = runKind(failures, r, m, KindShouldNotMatch, r.ShouldNotMatch)
	return failures
}

// runKind runs the cases of one kind and appends the failures to out.
func runKind(out []CaseFailure, r Rule, m Matcher, kind CaseKind, cases []Case) []CaseFailure {
	want := kind == KindShouldMatch
	for i, c := range cases {
		got, err := m.Match(c.Text)
		if err != nil {
			out = append(out, newFailure(r, kind, i, c.Text, fmt.Errorf("match case: %w", err)))
			continue
		}
		if got != want {
			out = append(out, newFailure(r, kind, i, c.Text, nil))
		}
	}
	return out
}

// newFailure builds a CaseFailure for case number i of a rule.
func newFailure(r Rule, kind CaseKind, i int, text string, err error) CaseFailure {
	return CaseFailure{
		RuleID: r.ID,
		Target: r.Target,
		Kind:   kind,
		Index:  i,
		Text:   text,
		Err:    err,
	}
}
