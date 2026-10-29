package rules

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// builtinIDPattern is the ID format of a built-in rule: MOAT, a threat from
// T1 to T5, and three digits. It is compiled once and never changed.
var builtinIDPattern = regexp.MustCompile(`^MOAT-T[1-5]-[0-9]{3}$`)

// maxBuiltinRemediationRunes is the longest remediation of a built-in rule,
// in runes. Validate allows longer remediation text (maxRemediationRunes),
// but the terminal report cuts rule text at maxRuleTextRunes (500) in
// internal/report/findings.go. A built-in rule must fit, so its "Fix:" line
// is never cut. Keep this value equal to report.maxRuleTextRunes:
// TestBuiltinRuleTextFitsReport in internal/report fails when they differ.
const maxBuiltinRemediationRunes = 500

// CheckDocumented checks the strict requirements for a built-in rule
// (NFR-05, NFR-07) and returns one problem text for each violation. It
// returns nil when the rule meets all of them.
//
// The requirements are:
//   - the ID matches ^MOAT-T[1-5]-[0-9]{3}$;
//   - when Source is set, its base name is the ID plus ".yaml";
//   - Risk is not empty, has no line break and has at most maxRiskRunes runes.
//     This is a simple stand-in for "one sentence"; the check does not parse
//     text;
//   - Remediation is not empty and has at most maxBuiltinRemediationRunes
//     runes, so the terminal report never cuts it;
//   - there is at least one reference;
//   - there is at least one should_match case and one should_not_match case;
//   - for a rule with target schema, every case text is valid JSON. A schema
//     rule reads the strings of a JSON schema, so a case that is not JSON
//     does not test what a scan sees.
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
		base := filepath.Base(r.Source)
		if base != r.ID+".yaml" {
			add("file name %s does not match the id (want %s)", displayText(base), displayText(r.ID+".yaml"))
		}
	}
	checkRisk(r.Risk, add)
	if isBlank(r.Remediation) {
		add("remediation is empty")
	} else if n := utf8.RuneCountInString(r.Remediation); n > maxBuiltinRemediationRunes {
		add("remediation has %d runes (at most %d)", n, maxBuiltinRemediationRunes)
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
	if r.Target == TargetSchema {
		checkJSONCases(KindShouldMatch, r.ShouldMatch, add)
		checkJSONCases(KindShouldNotMatch, r.ShouldNotMatch, add)
	}
	return problems
}

// checkJSONCases reports to add each case whose text is not valid JSON. The
// problem names the kind and the index of the case only, never its text.
func checkJSONCases(kind CaseKind, cases []Case, add func(format string, args ...any)) {
	for i, c := range cases {
		if !json.Valid([]byte(c.Text)) {
			add("%s[%d] is not valid JSON", kind, i)
		}
	}
}

// checkRisk reports the problems of a Risk text to add. Validate also caps the
// length of a risk, but CheckDocumented must work on a Rule that did not come
// from Parse, so it checks the length too.
func checkRisk(risk string, add func(format string, args ...any)) {
	if isBlank(risk) {
		add("risk is empty")
		return
	}
	// Unicode line and paragraph separators count as line breaks too.
	if strings.ContainsAny(risk, "\r\n\u0085\u2028\u2029") {
		add("risk has a line break (use one sentence)")
	}
	if n := utf8.RuneCountInString(risk); n > maxRiskRunes {
		add("risk has %d runes (at most %d)", n, maxRiskRunes)
	}
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
