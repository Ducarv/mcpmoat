package rules_test

// Checks that the reserved rule IDs of the rules package (see
// rules.ReservedRuleID) cover the native rule IDs of internal/pins and
// internal/llm. The rules package does not import them, so this external test
// package checks that the list cannot drift from them.

import (
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// TestReservedRuleIDCoversNativeIDs checks that every native rule ID is
// reserved, in its own case and in lower case.
func TestReservedRuleIDCoversNativeIDs(t *testing.T) {
	t.Parallel()

	native := []string{
		rules.RuleAnalysisBudget, rules.RuleToolFindingCap, rules.RuleConfigFindingCap,
		llm.RuleID, llm.RuleIDInvalid,
	}
	for _, k := range []pins.ChangeKind{pins.KindChanged, pins.KindNew, pins.KindRemoved, pins.KindUnverified} {
		id := k.RuleID()
		if id == "" {
			t.Fatalf("pins.ChangeKind(%q).RuleID() is empty", k)
		}
		if !pins.IsPinRuleID(id) {
			t.Errorf("pins.IsPinRuleID(%q) = false, want true", id)
		}
		native = append(native, id)
	}
	for _, id := range native {
		for _, v := range []string{id, strings.ToLower(id)} {
			if !rules.ReservedRuleID(v) {
				t.Errorf("rules.ReservedRuleID(%q) = false, want true for a native rule ID", v)
			}
		}
	}
}

// TestReservedRuleIDCoversPinFamily checks that every ID that
// pins.IsPinRuleID treats as a pin rule is reserved, not only the four IDs of
// today. A rule from --rules with such an ID would get the special handling
// of a pin rule.
func TestReservedRuleIDCoversPinFamily(t *testing.T) {
	t.Parallel()

	ids := []string{
		"MOAT-T2-001", "MOAT-T2-005", "MOAT-T2-999", "MOAT-T2-x", "MOAT-T2-",
		"MOAT-T1-001", "MOAT-T2", "MOAT-T3-001", "ACME-1",
	}
	for _, id := range ids {
		if pins.IsPinRuleID(id) && !rules.ReservedRuleID(id) {
			t.Errorf("pins.IsPinRuleID(%q) = true, but rules.ReservedRuleID(%q) = false", id, id)
		}
	}
}

// TestBuiltinRulesUseNoReservedID checks that no built-in YAML rule uses a
// reserved ID. NewSet checks only the external rules for reserved IDs.
func TestBuiltinRulesUseNoReservedID(t *testing.T) {
	t.Parallel()

	builtin, errs := rules.Builtin()
	if len(errs) > 0 {
		t.Fatalf("rules.Builtin() errors = %v, want none", errs)
	}
	if len(builtin) == 0 {
		t.Fatal("no built-in rule; the check would pass with no rule")
	}
	for _, r := range builtin {
		if rules.ReservedRuleID(r.ID) {
			t.Errorf("built-in rule %s (%s) uses a reserved native ID", r.ID, r.Source)
		}
	}
}
