package rules

import (
	"cmp"
	"errors"
	"slices"
	"strings"
)

// maxRules is the largest number of rules (built-in and external together)
// that NewSet accepts. It stops a huge rules directory from using too much
// memory and time.
const maxRules = 5000

// maxSetErrors is the largest number of problems NewSet returns before its
// summary error. It has the same value as maxFolderErrors, so a rules directory
// cannot bypass the cap of LoadDir through duplicate IDs.
const maxSetErrors = maxFolderErrors

// setLabel is the File of the errors that are about the whole rule set and not
// about one rule file.
const setLabel = "rule set"

// Set is a collection of rules with unique IDs, sorted by ID. Build one with
// NewSet. A Set is read-only after NewSet returns, so it is safe to share
// between goroutines.
type Set struct {
	rules []Rule
}

// NewSet joins built-in and external rules into one Set. It checks that no ID
// is used twice and that the total is at most maxRules.
//
// It returns the problems it finds, not only the first, in a fixed order:
// duplicates inside builtin, then problems with the external rules in input
// order. It returns at most maxSetErrors of them. If there are more, the last
// error has ReasonTooManyErrors and says how many were not shown. If there is
// any error, the returned *Set is nil.
// Two IDs in the same list are duplicates only when they are equal, so "A" and
// "a" are different IDs.
//
// When an external rule has the ID of a built-in rule, in any case, the
// built-in rule stays and the external rule is reported with
// ReasonBuiltinIDClash. An ID that differs only in case would look like the
// built-in ID in a report.
//
// When an external rule has an ID that ReservedRuleID reports, the external
// rule is reported with ReasonReservedID. Such an ID belongs to a finding
// that mcpmoat makes in Go code, for example a pin finding. NewSet does not
// check the built-in rules for reserved IDs: a test does.
func NewSet(builtin, external []Rule) (*Set, []*LoadError) {
	if len(builtin)+len(external) > maxRules {
		return nil, []*LoadError{newLoadError(setLabel, ReasonTooManyRules)}
	}

	var errs []*LoadError
	// dropped counts the errors after the cap. They are counted, not built.
	dropped := 0
	// full reports whether errs already holds maxSetErrors errors. In that
	// case it counts one more dropped error, and the caller must not build
	// the error.
	full := func() bool {
		if len(errs) >= maxSetErrors {
			dropped++
			return true
		}
		return false
	}
	add := func(r, other Rule, reason Reason) {
		if full() {
			return
		}
		errs = append(errs, duplicateIDError(r, other, reason))
	}

	// builtinByID maps an ID to the first built-in rule that uses it.
	builtinByID := make(map[string]Rule, len(builtin))
	for _, r := range builtin {
		if first, ok := builtinByID[r.ID]; ok {
			add(r, first, ReasonDuplicateID)
			continue
		}
		builtinByID[r.ID] = r
	}

	// builtinByFold maps an ID in lower case to the first built-in rule that
	// uses it. An external ID that differs from a built-in ID only in case
	// would look like it in a report, so it clashes too.
	builtinByFold := make(map[string]Rule, len(builtin))
	for _, r := range builtin {
		key := strings.ToLower(r.ID)
		if _, ok := builtinByFold[key]; !ok {
			builtinByFold[key] = r
		}
	}

	// externalByID maps an ID to the first external rule that uses it.
	externalByID := make(map[string]Rule, len(external))
	for _, r := range external {
		if ReservedRuleID(r.ID) {
			if !full() {
				errs = append(errs, reservedIDError(r))
			}
			continue
		}
		if b, ok := builtinByFold[strings.ToLower(r.ID)]; ok {
			add(r, b, ReasonBuiltinIDClash)
			continue
		}
		if first, ok := externalByID[r.ID]; ok {
			add(r, first, ReasonDuplicateID)
			continue
		}
		externalByID[r.ID] = r
	}

	if dropped > 0 {
		errs = append(errs, newLoadError(setLabel, ReasonTooManyErrors).wrap(moreErrors(dropped)))
	}
	if len(errs) > 0 {
		return nil, errs
	}

	// With no error, both maps hold exactly the rules to keep. Their IDs do not
	// overlap, so the set is unique by ID.
	all := make([]Rule, 0, len(builtinByID)+len(externalByID))
	for _, r := range builtinByID {
		all = append(all, r)
	}
	for _, r := range externalByID {
		all = append(all, r)
	}
	// Map iteration order is random in Go, so sort to get a stable result.
	slices.SortFunc(all, func(a, b Rule) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return &Set{rules: all}, nil
}

// duplicateIDError returns the error for rule r, which reuses the ID of the
// earlier rule other. The error names the file of r and, in its Err, the file
// of other. The name of other is plain text: LoadError.Error escapes it.
func duplicateIDError(r, other Rule, reason Reason) *LoadError {
	err := errors.New("already defined in " + other.Source)
	return newLoadError(r.Source, reason).inField("id").wrap(err)
}

// reservedIDError returns the error for the external rule r, whose ID is
// reserved (see ReservedRuleID). The error names the file of r and holds no
// rule text: the reason is fixed text and Err is nil.
func reservedIDError(r Rule) *LoadError {
	return newLoadError(r.Source, ReasonReservedID).inField("id")
}

// Prefixes of the reserved rule ID families (see ReservedRuleID).
const (
	// pinRuleIDPrefix starts the IDs of the pin findings: MOAT-T2-001 to
	// MOAT-T2-004 (internal/pins, ChangeKind.RuleID). pins.IsPinRuleID treats
	// every ID with this prefix as a pin rule, so the whole family is
	// reserved, not only the four IDs.
	pinRuleIDPrefix = "MOAT-T2-"
	// llmRuleIDPrefix starts the IDs of the LLM findings: MOAT-LLM-001 and
	// MOAT-LLM-002 (internal/llm, RuleID and RuleIDInvalid).
	llmRuleIDPrefix = "MOAT-LLM-"
)

// ReservedRuleID reports whether id is reserved for a native rule: a rule
// with no YAML file that mcpmoat makes findings for in Go code. A rule from
// --rules must not use such an ID (NewSet refuses it with ReasonReservedID).
// Otherwise --ignore for the external rule would also drop the native
// findings, and a report could show a fake pin or LLM finding.
//
// The reserved IDs are:
//
//   - RuleAnalysisBudget (MOAT-T1-023), the rule analysis budget finding.
//   - RuleToolFindingCap (MOAT-T1-024), the summary finding for a server with
//     more tool findings than the per-server cap.
//   - RuleConfigFindingCap (MOAT-T4-005), the summary finding for a server
//     whose config findings the cap cuts.
//   - Every ID that starts with "MOAT-T2-", the pin findings MOAT-T2-001 to
//     MOAT-T2-004 of internal/pins.
//   - Every ID that starts with "MOAT-LLM-", the LLM findings MOAT-LLM-001
//     and MOAT-LLM-002 of internal/llm.
//
// The comparison ignores case (strings.EqualFold), so "moat-t2-001" is
// reserved too: it would look like MOAT-T2-001 in a report.
//
// This list is the one place for the reserved IDs. The rules package cannot
// read the IDs from internal/pins and internal/llm without a dependency on
// them, so a test (TestReservedRuleIDCoversNativeIDs) checks that the list
// covers their IDs.
func ReservedRuleID(id string) bool {
	if strings.EqualFold(id, RuleAnalysisBudget) || strings.EqualFold(id, RuleToolFindingCap) ||
		strings.EqualFold(id, RuleConfigFindingCap) {
		return true
	}
	return hasPrefixFold(id, pinRuleIDPrefix) || hasPrefixFold(id, llmRuleIDPrefix)
}

// Rules returns the rules of the set, sorted by ID. It returns a new slice, so
// a caller can reorder or cut it without changing the set. The Rule values are
// shallow copies: callers must treat their slice and map fields as read-only.
// A nil Set returns nil.
func (s *Set) Rules() []Rule {
	if s == nil {
		return nil
	}
	return slices.Clone(s.rules)
}

// Get returns the rule with the given ID. The second result is false if the
// set has no such rule. The ID is compared exactly. A nil Set has no rules.
func (s *Set) Get(id string) (Rule, bool) {
	if s == nil {
		return Rule{}, false
	}
	// The rules are sorted by ID, so a binary search finds the rule quickly.
	i, found := slices.BinarySearchFunc(s.rules, id, func(r Rule, id string) int {
		return cmp.Compare(r.ID, id)
	})
	if !found {
		return Rule{}, false
	}
	return s.rules[i], true
}

// Len returns the number of rules in the set. A nil Set has length 0.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}
