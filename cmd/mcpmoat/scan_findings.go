package main

import (
	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// configChecks holds what the config rules need: the rule set (for the
// severity of a finding) and the typosquat check (T5).
type configChecks struct {
	set  *rules.Set
	typo *rules.Typosquat
}

// findings runs the static config checks on every server and returns one
// report row for each finding that the ignore list does not drop. The order
// of the rows follows the order of servers. For one server, the T4 checks
// (rules.CheckConfig) come first, then the T5 check (typo.Check).
//
// The servers are checked as discover gives them, with no expansion of
// variables in the command, args or URL. The checks look at the text in the
// config file, not at what a shell would run. Disabled servers are checked
// too, because a user can turn a disabled server on later.
//
// The severity, the title, the risk and the remediation of a row come from the
// rule set. A finding whose rule is not in the set gets severity "critical"
// (an unknown rule must never pass silently) and empty texts. The report
// leaves out an empty title and prints "-" for an empty risk or remediation.
// A row holds the names of the server and the rule text from the built-in rule
// set (rule ID, field, key, related). It never holds a Finding.Message or a
// config value.
//
// ignored counts the findings that the ignore list dropped, by rule ID. It is
// nil when the list dropped nothing. The caller must tell the user
// about these findings, because an ignore file can come from an untrusted
// folder and hide a finding. The map holds only rule IDs and counts.
//
// perServer holds, for each server, the number of rows that the server got.
// The index is the index in servers, so two servers with the same name are
// counted apart.
//
// A nil ignore list ignores nothing.
func (cc configChecks) findings(ignore *rules.IgnoreList, servers []discover.Server) (rows []report.FindingRow, ignored map[string]int, perServer []int) {
	perServer = make([]int, len(servers))
	for i, s := range servers {
		ref := report.NewServerRef(s)
		found := rules.CheckConfig(s)
		found = append(found, cc.typo.Check(s)...)
		for _, f := range found {
			key := rules.FindingKey{RuleID: f.RuleID, Server: f.Server, Tool: f.Tool}
			if ignore.Ignored(key) {
				ignored = addIgnored(ignored, f.RuleID, 1)
				continue
			}
			rule, severity := findingRule(cc.set, f.RuleID)
			rows = append(rows, report.FindingRow{
				ServerRef:   ref,
				RuleID:      f.RuleID,
				Severity:    severity,
				Title:       rule.Title,
				Risk:        rule.Risk,
				Remediation: rule.Remediation,
				Field:       f.Field,
				Key:         f.Key,
				Related:     f.Related,
			})
			perServer[i]++
		}
	}
	return rows, ignored, perServer
}

// findingRule returns the rule with the given ID and its severity word. When
// the set has no such rule, it returns a zero Rule, so the texts are empty,
// and "critical" (fail closed).
func findingRule(set *rules.Set, id string) (rules.Rule, string) {
	rule, ok := set.Get(id)
	if !ok {
		return rules.Rule{}, string(rules.SeverityCritical)
	}
	return rule, string(rule.Severity)
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

// addIgnored adds n to the count of the rule ID in dst and returns dst. It makes
// a new map when dst is nil, so the callers keep the map nil until a finding is
// dropped.
func addIgnored(dst map[string]int, ruleID string, n int) map[string]int {
	if dst == nil {
		dst = make(map[string]int)
	}
	dst[ruleID] += n
	return dst
}

// mergeIgnored adds the counts of extra to dst and returns dst. It makes a new
// map when dst is nil and extra is not.
func mergeIgnored(dst, extra map[string]int) map[string]int {
	for id, n := range extra {
		dst = addIgnored(dst, id, n)
	}
	return dst
}
