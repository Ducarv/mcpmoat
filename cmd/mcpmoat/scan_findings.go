package main

import (
	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// configFindings runs the static config checks on every server and returns
// one report row for each finding that the ignore list does not drop. The
// order of the rows follows the order of servers. For one server, the T4
// checks (rules.CheckConfig) come first, then the T5 check (typo.Check).
//
// The servers are checked as discover gives them, with no expansion of
// variables in the command, args or URL. The checks look at the text in the
// config file, not at what a shell would run. Disabled servers are checked
// too, because a user can turn a disabled server on later.
//
// The severity of a row comes from the rule set. A finding whose rule is not
// in the set gets severity "critical": an unknown rule must never pass
// silently. A row holds only names (rule ID, server, field, key, related). It
// never holds a Finding.Message or a config value.
//
// The second result counts the findings that the ignore list dropped, by rule
// ID. It is nil when the list dropped nothing. The caller must tell the user
// about these findings, because an ignore file can come from an untrusted
// folder and hide a finding. The map holds only rule IDs and counts.
//
// A nil ignore list ignores nothing.
func configFindings(set *rules.Set, typo *rules.Typosquat, ignore *rules.IgnoreList, servers []discover.Server) ([]report.FindingRow, map[string]int) {
	var rows []report.FindingRow
	var ignored map[string]int
	for _, s := range servers {
		found := rules.CheckConfig(s)
		found = append(found, typo.Check(s)...)
		for _, f := range found {
			key := rules.FindingKey{RuleID: f.RuleID, Server: f.Server, Tool: f.Tool}
			if ignore.Ignored(key) {
				if ignored == nil {
					ignored = make(map[string]int)
				}
				ignored[f.RuleID]++
				continue
			}
			rows = append(rows, report.FindingRow{
				RuleID:   f.RuleID,
				Severity: findingSeverity(set, f.RuleID),
				Server:   f.Server,
				Field:    f.Field,
				Key:      f.Key,
				Related:  f.Related,
			})
		}
	}
	return rows, ignored
}

// findingSeverity returns the severity word of the rule with the given ID. It
// returns "critical" when the set has no such rule (fail closed).
func findingSeverity(set *rules.Set, id string) string {
	rule, ok := set.Get(id)
	if !ok {
		return string(rules.SeverityCritical)
	}
	return string(rule.Severity)
}

// hasFailingFinding reports whether any row has severity high or above, which
// makes scan exit with code 1 (FR-16). A severity that mcpmoat does not know
// counts as failing (fail closed).
func hasFailingFinding(rows []report.FindingRow) bool {
	high := rules.SeverityHigh.Rank()
	for _, r := range rows {
		rank := rules.Severity(r.Severity).Rank()
		if rank == 0 || rank >= high {
			return true
		}
	}
	return false
}
