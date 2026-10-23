package rules

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// builtinIDPattern is the ID format of a built-in rule: MOAT, a threat from
// T1 to T5, and three digits. It is compiled once and never changed.
var builtinIDPattern = regexp.MustCompile(`^MOAT-T[1-5]-[0-9]{3}$`)

// CaseKind says which list of a rule a test case comes from.
type CaseKind string

// The two kinds of test case (NFR-05).
const (
	// KindShouldMatch is a case from should_match: the rule must fire.
	KindShouldMatch CaseKind = "should_match"
	// KindShouldNotMatch is a case from should_not_match: the rule must not fire.
	KindShouldNotMatch CaseKind = "should_not_match"
)

// CheckDocumented checks the strict requirements for a built-in rule
// (NFR-05, NFR-07) and returns one problem text for each violation. It
// returns nil when the rule meets all of them.
//
// The requirements are:
//   - the ID matches ^MOAT-T[1-5]-[0-9]{3}$;
//   - when Source is set, its base name is the ID plus ".yaml";
//   - Risk is not empty, has no line break and has at most 500 runes. This is
//     a simple stand-in for "one sentence"; the check does not parse text;
//   - Remediation is not empty;
//   - there is at least one reference;
//   - there is at least one should_match case and one should_not_match case.
//
// Each problem starts with the escaped rule ID, so a failing test names the
// rule. Every piece of rule text in a problem is escaped with termsafe.
func CheckDocumented(r Rule) []string {
	id := displayText(r.ID)
	if r.ID == "" {
		id = "(empty id)"
	}
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, id+": "+fmt.Sprintf(format, args...))
	}

	if !builtinIDPattern.MatchString(r.ID) {
		add("id does not match MOAT-T[1-5]-NNN")
	}
	if r.Source != "" {
		// filepath.ToSlash makes a Windows path use "/", so path.Base works.
		base := path.Base(filepath.ToSlash(r.Source))
		if base != r.ID+".yaml" {
			add("file name %s does not match the id (want %s)", displayText(base), displayText(r.ID+".yaml"))
		}
	}
	problems = append(problems, checkRisk(id, r.Risk)...)
	if isBlank(r.Remediation) {
		add("remediation is empty")
	}
	if !hasText(r.References) {
		add("no reference")
	}
	if len(r.ShouldMatch) == 0 {
		add("no %s case", KindShouldMatch)
	}
	if len(r.ShouldNotMatch) == 0 {
		add("no %s case", KindShouldNotMatch)
	}
	return problems
}

// checkRisk returns the problems of a Risk text, each starting with id.
func checkRisk(id, risk string) []string {
	var problems []string
	if isBlank(risk) {
		return []string{id + ": risk is empty"}
	}
	// Unicode line and paragraph separators count as line breaks too.
	if strings.ContainsAny(risk, "\r\n\u0085\u2028\u2029") {
		problems = append(problems, id+": risk has a line break (use one sentence)")
	}
	if n := utf8.RuneCountInString(risk); n > maxRiskRunes {
		problems = append(problems, fmt.Sprintf("%s: risk has %d runes (at most %d)", id, n, maxRiskRunes))
	}
	return problems
}

// hasText reports whether at least one item holds more than white space.
func hasText(items []string) bool {
	for _, s := range items {
		if !isBlank(s) {
			return true
		}
	}
	return false
}

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
// for example when no Compiler is set. It never panics because of a case.
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
			out = append(out, newFailure(r, kind, i, c, fmt.Errorf("match case: %w", err)))
			continue
		}
		if got != want {
			out = append(out, newFailure(r, kind, i, c, nil))
		}
	}
	return out
}

// newFailure builds a CaseFailure for case number i of a rule.
func newFailure(r Rule, kind CaseKind, i int, c Case, err error) CaseFailure {
	return CaseFailure{
		RuleID: r.ID,
		Target: r.Target,
		Kind:   kind,
		Index:  i,
		Text:   c.Text,
		Err:    err,
	}
}
