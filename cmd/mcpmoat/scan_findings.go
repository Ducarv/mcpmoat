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
func (cc configChecks) findings(ignore *rules.IgnoreList, servers []discover.Server) ([]report.FindingRow, map[string]int) {
	var rows []report.FindingRow
	var ignored map[string]int
	for _, s := range servers {
		found := rules.CheckConfig(s)
		found = append(found, cc.typo.Check(s)...)
		for _, f := range found {
			key := rules.FindingKey{RuleID: f.RuleID, Server: f.Server, Tool: f.Tool}
			if ignore.Ignored(key) {
				ignored = addIgnored(ignored, f.RuleID, 1)
				continue
			}
			rows = append(rows, report.FindingRow{
				RuleID:   f.RuleID,
				Severity: findingSeverity(cc.set, f.RuleID),
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

// hasFailingFinding reports whether any row has severity failOn or above,
// which makes scan exit with code 1 (FR-16). A row severity that mcpmoat does
// not know counts as failing at every threshold (fail closed). An invalid or
// zero failOn has rank 0, so every finding fails (fail closed). runScan always
// sets a valid failOn, so this case does not occur in a normal run.
func hasFailingFinding(rows []report.FindingRow, failOn rules.Severity) bool {
	limit := failOn.Rank()
	for _, r := range rows {
		rank := rules.Severity(r.Severity).Rank()
		if rank == 0 || rank >= limit {
			return true
		}
	}
	return false
}

// scanExitCode maps the result of a scan to its exit code (FR-16). execFailed
// is true when a config file has a problem or when pins.json cannot be read
// or saved. Exit code 2 wins over 1: the result is incomplete, so "only
// findings" would claim more than scan knows. The report is already printed,
// so the user still sees the findings.
func scanExitCode(execFailed bool, rows []report.FindingRow, failOn rules.Severity) int {
	switch {
	case execFailed:
		return exitError
	case hasFailingFinding(rows, failOn):
		return exitFindings
	default:
		return exitOK
	}
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
