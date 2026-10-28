package main

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// configRowsPerServer is the largest number of config finding rows that scan
// keeps for one server (issue #213). The config checks add one finding for
// each env key and each header key of a server (MOAT-T4-* and MOAT-T5-*), so a
// hostile project .mcp.json with many short keys could make a huge report. A
// server with more rows gets one summary finding (rules.RuleConfigFindingCap)
// in place of the rest. The step keeps the most severe rows (see
// cutConfigHits), so a server cannot push a severe finding out of the report
// with many weak ones.
const configRowsPerServer = 100

// configRowsTotal is the largest number of config finding rows that scan keeps
// for all the servers together. Without it, a hostile config with many
// servers could still make a huge report, 100 rows at a time. Scan keeps the
// most severe rows of the whole scan, not the rows of the first servers, so
// many servers with weak findings cannot push a severe finding of a later
// server out of the report. A server that loses rows to this cap gets the
// same summary finding as for the per-server cap. That finding does not count
// toward the cap, so the report holds at most configRowsTotal rows plus one
// summary row for each server that lost rows (see docs/limits.md).
const configRowsTotal = 10_000

// configCaps holds the two limits of the config finding rows. A value of zero
// or less means the default (configRowsPerServer and configRowsTotal), so the
// zero configCaps gives the real limits. Tests set small values, so that they
// do not need a hundred findings.
type configCaps struct {
	// perServer is the largest number of config rows of one server.
	perServer int
	// total is the largest number of config rows of the whole scan.
	total int
}

// orDefault returns c with each value of zero or less set to its default.
func (c configCaps) orDefault() configCaps {
	if c.perServer <= 0 {
		c.perServer = configRowsPerServer
	}
	if c.total <= 0 {
		c.total = configRowsTotal
	}
	return c
}

// The fixed texts of a rules.RuleConfigFindingCap row (see configCapRow). Like
// the tool findings cap, this rule has no YAML file, so the rule set does not
// hold its texts. They never hold config text.
const (
	configCapTitle = "Config findings over the limit are not listed"
	configCapRisk  = "This server has more config findings than the report lists, " +
		"so the report is short but not complete. A hostile config file can use this to hide a finding among many."
	configCapRemediation = "Do not use this server until you have read its config entry yourself: " +
		"the command, the args, the URL and the env and header keys. " +
		"Treat the findings that the report lists as a sample, not as the full list."
)

// configChecks holds what the config rules need: the rule set (for the
// severity of a finding), the typosquat check (T5) and the row caps.
type configChecks struct {
	set  *rules.Set
	typo *rules.Typosquat
	// caps holds the limits of the config rows. The zero value gives the
	// default limits (see configCaps).
	caps configCaps
}

// configHit is a config finding that the ignore list keeps, while findings
// waits to know which ones fit under the caps. It holds the index of the
// finding in a list, not a copy of it or of its row, so a server with very
// many findings does not hold a row for each one. The memory before the cut is
// not bounded by the caps: findings holds all the findings of one server while
// it cuts them, and then up to the per-server cap for each server until the row
// build (see docs/limits.md).
type configHit struct {
	// index is the index of the finding in the list that is cut: the
	// findings of one server for the per-server cap, or the hits of all the
	// servers for the scan cap.
	index int
	// severity is the severity word of the row (see findingRule).
	severity string
	// untrusted is true when the server of the hit comes from a project file
	// (discover.Server.Untrusted). The scan cap keeps the hits of other
	// servers first among hits of the same severity (see cutConfigHits).
	untrusted bool
}

// configServerHits holds what findings knows about one server after the
// per-server cap, while it waits for the scan cap.
type configServerHits struct {
	// ref is the server of the rows. Its Name is the server name, also for
	// the ignore key of the cap row.
	ref report.ServerRef
	// kept holds the findings that the per-server cap keeps, in their first
	// order. There are at most caps.perServer of them.
	kept []rules.Finding
	// start is the index of the first kept finding in the hits of all the
	// servers (see findings).
	start int
	// omitted is the number of findings that the per-server cap left out.
	omitted int
	// worst is the severity of the cap row for these omitted findings (see
	// configCapSeverity). It is high when the per-server cap left out
	// nothing.
	worst rules.Severity
}

// findings runs the static config checks on every server and returns one
// report row for each finding that the ignore list does not drop, up to the
// caps. The order of the rows follows the order of servers. For one server,
// the T4 checks (rules.CheckConfig) come first, then the T5 check
// (typo.Check), then the rules.RuleConfigFindingCap row when there is one.
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
// A server keeps at most cc.caps.perServer rows (configRowsPerServer by
// default), and the whole scan at most cc.caps.total rows (configRowsTotal by
// default). The caps count the rows after the ignore list: a row that the list
// drops does not count, so the user can make room for the other rows. The cut
// has two steps, and each keeps the most severe rows (see cutConfigHits):
//
//  1. The per-server cap cuts the rows of each server.
//  2. When the rows that are left are more than the scan cap, the scan keeps
//     the most severe of them across all the servers. Among rows of the same
//     severity, it keeps the rows of servers from a user file before the rows
//     of servers from a project file (discover.Server.Untrusted), then the
//     rows of the first servers, and in one server the first rows.
//
// The kept rows of a server stay in their first order. A server that lost
// rows in one or both steps gets one rules.RuleConfigFindingCap row after its
// kept rows (see configCapRow). It counts all the rows that the server lost
// in the two steps, and its severity is the highest of them, but never lower
// than high. Its limit is the per-server cap when only that cap cut the
// server, and the scan cap when the scan cap cut one or more rows of the
// server. The cap row does not count toward the caps. Below the caps, the
// rows are the same as with no caps. The per-server cut comes first, so the
// scan step holds at most cc.caps.perServer findings for each server.
//
// Each finding and the cap row go through ignore.ignored. So .mcpmoat-ignore
// can drop a config finding but not the cap row: only --ignore can (see
// fileCannotIgnore). A nil ignore ignores nothing.
//
// ignored counts the findings that the ignore list dropped, by rule ID. It is
// nil when the list dropped nothing. The caller must tell the user
// about these findings, because an ignore file can come from an untrusted
// folder and hide a finding. The map holds only rule IDs and counts.
//
// perServer holds, for each server, the number of rows that the server got,
// with the cap row. The index is the index in servers, so two servers with the
// same name are counted apart.
//
// fileBlocked lists the rule IDs that have a .mcpmoat-ignore entry that
// matches a row but is not applied (see scanIgnores.ignored). It is sorted,
// each ID is in it once, and it is nil when there is no such entry. The caller
// must call warnFileCannotIgnore for each ID.
//
// cutServers is the number of servers that lost rows to a cap. A server
// counts even when the ignore list then drops its cap row, so the caller can
// still tell the user that the report is not complete.
func (cc configChecks) findings(ignore *scanIgnores, servers []discover.Server) (rows []report.FindingRow, ignored map[string]int, perServer []int, fileBlocked []string, cutServers int) {
	if ignore == nil {
		// The zero scanIgnores has empty lists, so it ignores nothing.
		ignore = &scanIgnores{}
	}
	caps := cc.caps.orDefault()
	// pass applies the ignore list to the finding key k. It returns false,
	// after it counted the finding as ignored, when the list drops it. It
	// notes the rule ID when a .mcpmoat-ignore entry matches but is not
	// applied. This is the same as toolRulesRun.passIgnore. The closure
	// writes to the named results ignored and fileBlocked directly.
	pass := func(k rules.FindingKey) bool {
		drop, blocked := ignore.ignored(k)
		if drop {
			ignored = addIgnored(ignored, k.RuleID, 1)
			return false
		}
		if blocked && !slices.Contains(fileBlocked, k.RuleID) {
			fileBlocked = append(fileBlocked, k.RuleID)
		}
		return true
	}

	// Step 1: check each server and apply the per-server cap. all holds the
	// kept hits of all the servers, in server order and then in finding
	// order. Its index field is its own position in all, so that the scan
	// cut below can tell which hits it left out.
	byServer := make([]configServerHits, len(servers))
	var all []configHit
	for i, s := range servers {
		found := rules.CheckConfig(s)
		found = append(found, cc.typo.Check(s)...)

		// First apply the ignore list, so that a dropped finding does not
		// count toward the caps.
		var hits []configHit
		for j, f := range found {
			if !pass(rules.FindingKey{RuleID: f.RuleID, Server: f.Server, Tool: f.Tool}) {
				continue
			}
			_, severity := findingRule(cc.set, f.RuleID)
			hits = append(hits, configHit{index: j, severity: severity, untrusted: s.Untrusted})
		}

		kept, omitted := cutConfigHits(hits, caps.perServer)
		sh := configServerHits{
			// servers is res.Servers, the same slice that the --json "servers"
			// array lists in order, so i is the server_index of every row here.
			ref:     report.NewServerRef(s, i),
			kept:    make([]rules.Finding, 0, len(kept)),
			start:   len(all),
			omitted: len(omitted),
			worst:   configCapSeverity(omitted),
		}
		for _, h := range kept {
			sh.kept = append(sh.kept, found[h.index])
			all = append(all, configHit{index: len(all), severity: h.severity, untrusted: h.untrusted})
		}
		byServer[i] = sh
	}

	// Step 2: apply the scan cap to the hits of all the servers. scanCut
	// marks the hits that the scan cap left out, by their index in all.
	// Below the scan cap, cutConfigHits leaves out nothing.
	scanCut := make([]bool, len(all))
	_, scanOmitted := cutConfigHits(all, caps.total)
	for _, h := range scanOmitted {
		scanCut[h.index] = true
	}

	// Step 3: build the rows in server order. The kept rows of each server
	// come first, in their first order, then its cap row when it lost rows.
	perServer = make([]int, len(servers))
	for i, sh := range byServer {
		// lost holds the hits of this server that the scan cap left out.
		var lost []configHit
		for k, f := range sh.kept {
			if scanCut[sh.start+k] {
				lost = append(lost, all[sh.start+k])
				continue
			}
			rows = append(rows, cc.row(sh.ref, f))
			perServer[i]++
		}

		omitted := sh.omitted + len(lost)
		if omitted == 0 {
			continue
		}
		// Count the server before the ignore list sees its cap row: the
		// report is not complete even when --ignore drops that row.
		cutServers++
		severity, limit := sh.worst, caps.perServer
		if len(lost) > 0 {
			// The scan cap cut this server, so the cap row names that cap.
			limit = caps.total
			if s := configCapSeverity(lost); s.Rank() > severity.Rank() {
				severity = s
			}
		}
		// The cap row goes through the ignore list too, but only --ignore can
		// drop it (see fileCannotIgnore).
		if pass(rules.FindingKey{RuleID: rules.RuleConfigFindingCap, Server: sh.ref.Name}) {
			rows = append(rows, configCapRow(sh.ref, severity, omitted, limit))
			perServer[i]++
		}
	}
	slices.Sort(fileBlocked)
	return rows, ignored, perServer, fileBlocked, cutServers
}

// row returns the report row of the config finding f of the server ref. The
// severity and the texts come from the rule set (see findingRule).
func (cc configChecks) row(ref report.ServerRef, f rules.Finding) report.FindingRow {
	// findings already looked up this rule for the severity. The second
	// lookup is accepted: it is a map lookup, and the first needs only the
	// severity, so findings does not keep the rule.
	rule, severity := findingRule(cc.set, f.RuleID)
	return report.FindingRow{
		ServerRef:   ref,
		RuleID:      f.RuleID,
		Severity:    severity,
		Title:       rule.Title,
		Risk:        rule.Risk,
		Remediation: rule.Remediation,
		Field:       f.Field,
		Key:         f.Key,
		Related:     f.Related,
	}
}

// cutConfigHits splits hits into the ones to keep, at most limit of them, and
// the ones to leave out. It keeps the most severe hits (see capRank: an
// unknown severity counts as critical), the same way as the tool findings cap
// (toolRulesRun.flushTools). Among hits of the same severity it keeps the hits
// of trusted servers before the hits of untrusted ones, and then the first
// ones. The kept hits stay in their first order. When all the hits fit,
// it returns hits as they are and no omitted hits. A limit of zero or less
// keeps nothing.
func cutConfigHits(hits []configHit, limit int) (kept, omitted []configHit) {
	limit = max(limit, 0)
	if len(hits) <= limit {
		return hits, nil
	}
	// order holds the indexes of hits. Sort the indexes, not the hits, so
	// that the kept ones can go back to their first order after the cut.
	order := make([]int, len(hits))
	for i := range order {
		order[i] = i
	}
	// Most severe first: compare b to a, not a to b. Among hits of the same
	// severity, the hits of trusted servers come before the hits of
	// untrusted ones: a project file can ship many servers, so it must not
	// use up the scan cap and push out the finding of a server that the user
	// set up. SortStableFunc keeps the order of two equal elements, so the
	// first ones stay in front and are kept.
	slices.SortStableFunc(order, func(a, b int) int {
		if c := cmp.Compare(capRank(hits[b].severity), capRank(hits[a].severity)); c != 0 {
			return c
		}
		switch {
		case hits[a].untrusted == hits[b].untrusted:
			return 0
		case hits[a].untrusted:
			return 1
		default:
			return -1
		}
	})
	keep := order[:limit]
	// Put the kept indexes back in their first order.
	slices.Sort(keep)
	kept = make([]configHit, 0, len(keep))
	for _, i := range keep {
		kept = append(kept, hits[i])
	}
	omitted = make([]configHit, 0, len(hits)-limit)
	for _, i := range order[limit:] {
		omitted = append(omitted, hits[i])
	}
	return kept, omitted
}

// configCapSeverity returns the severity of a rules.RuleConfigFindingCap row:
// the highest severity of the omitted hits, but never lower than high. An
// unknown severity counts as critical. The row fails closed: the hits that
// the report does not list could hold a critical finding, so a config that
// floods the report still fails "--fail-on critical".
func configCapSeverity(omitted []configHit) rules.Severity {
	worst := rules.SeverityHigh
	for _, h := range omitted {
		s := rules.Severity(h.severity)
		if !s.Valid() {
			s = rules.SeverityCritical
		}
		if s.Rank() > worst.Rank() {
			worst = s
		}
	}
	return worst
}

// configCapRow returns the rules.RuleConfigFindingCap row of the server ref,
// which has omitted config findings over the limit limit. severity is the
// severity of the row (see configCapSeverity). The row is about the whole
// server, so its Field and Key are empty. All its texts are fixed (see
// configCapTitle), apart from the two numbers in Related. They do not come
// from the rule set: the rule has no YAML file (NewSet refuses the ID, see
// rules.ReservedRuleID).
func configCapRow(ref report.ServerRef, severity rules.Severity, omitted, limit int) report.FindingRow {
	return report.FindingRow{
		ServerRef:   ref,
		RuleID:      rules.RuleConfigFindingCap,
		Severity:    string(severity),
		Title:       configCapTitle,
		Risk:        configCapRisk,
		Remediation: configCapRemediation,
		Related:     configCapText(omitted, limit),
	}
}

// configCapText returns "N more config findings are not listed; limit M" (or
// "1 more config finding is not listed; limit M"). It holds two numbers and
// fixed words only.
func configCapText(omitted, limit int) string {
	return fmt.Sprintf("%d more config %s not listed; limit %d",
		omitted, plural(omitted, "finding is", "findings are"), limit)
}

// configStep runs the config rules (T4 and T5) on the servers, with the ignore
// lists and the row caps of checks (see configChecks.findings). findings
// prints nothing, so configStep prints the warnings of the step on stderr: one
// for each rule ID that .mcpmoat-ignore cannot ignore (see
// warnFileCannotIgnore), then one line when a cap cut the rows of one or more
// servers (see configCapWarningText). That line prints even when --ignore
// drops the cap rows. The lines hold rule IDs and counts only: no server
// name, key or config text.
//
// counts holds the number of config rows of each server, by the index of the
// server in servers.
func (c *cli) configStep(checks configChecks, ignore *scanIgnores, servers []discover.Server) (rows []report.FindingRow, ignored map[string]int, counts []int) {
	rows, ignored, counts, fileBlocked, cutServers := checks.findings(ignore, servers)
	for _, id := range fileBlocked {
		c.warnFileCannotIgnore(id)
	}
	// cutServers counts the servers that lost rows, also when --ignore
	// dropped their cap rows. The report is not complete in both cases, so
	// the warning prints in both cases, like the warning of the tool step.
	if cutServers > 0 {
		c.scanWarnf("%s", configCapWarningText(cutServers))
	}
	return rows, ignored, counts
}

// configCapWarningText returns the text of the warning for the servers that
// lost config rows to a cap, for example "config findings were left out for
// 2 servers; see MOAT-T4-005". It holds the count and fixed words only: no
// server name. The text points to the rule ID and does not say that each
// server has a MOAT-T4-005 finding, because --ignore can drop those rows.
func configCapWarningText(servers int) string {
	return fmt.Sprintf("config findings were left out for %d %s; see %s",
		servers, plural(servers, "server", "servers"), rules.RuleConfigFindingCap)
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
// is true when the scan is incomplete (see reportScan). Exit code 2 wins over
// 1: the result is incomplete, so "only findings" would claim more than scan
// knows.
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
