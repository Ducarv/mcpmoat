package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// This file holds the tool rule step of scan: it applies the description and
// schema rules (threats T1 and T3) to the tools of each inspected server.

// toolRulesBudget is the wall-clock time that the tool rule step can use for
// the tools of one server. A real server needs far less: its tool texts are
// short. But a hostile server can send tool texts that make one regex take
// seconds. The budget stops such a server from holding up the whole scan.
// The analyzer checks the context before each regex on each form of the text
// (see rules.Analyzer.CheckTool), so it stops soon after the budget is used
// up. A server that uses up the budget gets a rules.RuleAnalysisBudget
// finding (see budgetRow).
const toolRulesBudget = 5 * time.Second

// maxToolKeyRunes caps the tool name in the Key of a tool rule row (see
// toolKey). A hostile server can send a tool name of up to the size limit of
// its answer, and one tool can give one row for each rule. Without the cap,
// the --json report could hold the long name many times. It is the same
// number as the cap of the tool name in an LLM request (llm.MaxToolNameBytes),
// but in runes: termsafe.Cut, which the report writers use too, counts runes.
// So a Key has at most 4 bytes for each rune of valid UTF-8, and 1 byte for
// each byte that is not valid UTF-8, before the JSON encoder escapes it.
const maxToolKeyRunes = 512

// toolRulesResult is the result of the tool rule step.
type toolRulesResult struct {
	// rows are the findings that the ignore list does not drop, in the order
	// of the servers (inspect.Outcome.Index), then of the tools. The
	// rules.RuleAnalysisBudget row of a server comes after its tool rows.
	rows []report.FindingRow
	// ignored counts the findings that the ignore list dropped, by rule ID.
	// It is nil when the list dropped nothing.
	ignored map[string]int
}

// errToolRulesFailed means that the analyzer failed for a reason that is not
// the end of a context. The step already wrote the line on stderr. Its text
// is never printed.
var errToolRulesFailed = errors.New("tool rule step failed")

// toolRulesInternalText is the text of the stderr line, after the server
// label, when the analyzer fails for a reason that is not the end of a
// context. This is a bug in mcpmoat. It is fixed text: the error text of the
// analyzer is never printed.
const toolRulesInternalText = "the rule analysis failed (internal error)"

// The fixed texts of a rules.RuleAnalysisBudget row (see budgetRow). This
// rule has no YAML file, so the rule set does not hold its texts.
const (
	budgetTitle = "Rule analysis stopped at the time budget"
	budgetRisk  = "mcpmoat did not check all the tools of this server against the description and schema rules, " +
		"so a hostile tool text could pass without a finding. Tool texts that take this long to check are suspect."
	budgetRemediation = "Do not use this server until you have read its tool descriptions and schemas yourself, " +
		"and found out why they take so long to check. Then run mcpmoat scan again."
)

// toolRulesStep applies the description and schema rules of a to the tools
// of the inspected servers in outcomes (FR-07, FR-09). set gives the severity
// and the texts of each finding (see findingRule). It skips a server that was
// not inspected (inspect.StatusOK is not set) or that lists no tools. A nil
// analyzer checks nothing.
//
// The servers go in the order of inspect.Outcome.Index, and the tools of a
// server in the order that the server lists them, one after the other. Each
// server gets its own context with the time limit budget (toolRulesBudget in
// a real scan). When the budget of a server is used up, the step keeps the
// rows that it found for that server, adds one rules.RuleAnalysisBudget row
// (see budgetRow and budgetSeverity), prints one warning on stderr, and goes
// on with the next server. A budget of 0 or less is used up at once.
//
// A finding row holds the rule ID, the tool name in Key (see toolKey) and the
// target ("description" or "schema") in Related. It never holds tool text or
// pattern text. The ignore list compares the real tool name, not the Key. The ignore list drops rows like the
// rows of the config rules (see scanIgnores.ignored). The step prints one
// warning for each rule ID that .mcpmoat-ignore cannot ignore.
//
// counts holds the finding counts of each server by the index of the server
// (see serverStatuses). The step adds the rows that it keeps for a server to
// counts[Index]. An index outside counts cannot happen; it is skipped rather
// than panic.
//
// On an error the result is empty, and scan must print no report, save no
// pins and exit with code 2. The step already wrote the line on stderr:
//   - errInterrupted when ctx ended (the process got a signal) while the
//     analyzer ran. The line is interruptedText (see interrupted).
//   - errToolRulesFailed when the analyzer failed for any other reason. The
//     line is toolRulesInternalText, after the server label.
func (c *cli) toolRulesStep(ctx context.Context, a *rules.Analyzer, set *rules.Set, outcomes []inspect.Outcome, ignore *scanIgnores, budget time.Duration, counts []int) (toolRulesResult, error) {
	if a == nil {
		return toolRulesResult{}, nil
	}
	run := toolRulesRun{
		c: c, a: a, set: set, ignore: ignore, budget: budget, counts: counts,
		budgetSeverity: budgetSeverity(a),
	}
	// inspect.Run sorts the outcomes, so their order is not the order of the
	// servers.
	sorted := slices.SortedStableFunc(slices.Values(outcomes), func(x, y inspect.Outcome) int {
		return cmp.Compare(x.Index, y.Index)
	})
	for _, o := range sorted {
		if o.Status != inspect.StatusOK || len(o.Result.Tools) == 0 {
			continue
		}
		if err := run.checkServer(ctx, o); err != nil {
			return toolRulesResult{}, err
		}
	}
	for _, id := range run.fileBlocked {
		c.warnFileCannotIgnore(id)
	}
	return run.res, nil
}

// toolRulesRun holds the state of one toolRulesStep call.
type toolRulesRun struct {
	c      *cli
	a      *rules.Analyzer
	set    *rules.Set
	ignore *scanIgnores
	budget time.Duration
	// budgetSeverity is the severity of a rules.RuleAnalysisBudget row (see
	// budgetSeverity). It is the same for each server, so the step computes
	// it once.
	budgetSeverity rules.Severity
	counts         []int
	res            toolRulesResult
	// fileBlocked lists the rule IDs that have a .mcpmoat-ignore entry that
	// matches a kept row but is not applied (see scanIgnores). Each ID is in
	// it once, in the order of the first row that it matched.
	fileBlocked []string
}

// checkServer applies the rules to the tools of the inspected server o, with
// the time limit r.budget. It returns errInterrupted or errToolRulesFailed
// (see toolRulesStep), after it wrote the line on stderr, and nil when the
// server is done, also when the budget was used up.
func (r *toolRulesRun) checkServer(ctx context.Context, o inspect.Outcome) error {
	serverCtx, cancel := context.WithTimeout(ctx, r.budget)
	defer cancel()

	ref := report.NewServerRef(o.Server)
	tools := o.Result.Tools
	for i, t := range tools {
		found, err := r.a.CheckTool(serverCtx, t)
		// Keep the findings also when err is not nil: every finding that
		// CheckTool returns is a real match.
		for _, f := range found {
			r.add(o.Index, t.Name, textRow(r.set, ref, t.Name, f))
		}
		if err == nil {
			continue
		}
		switch {
		case r.c.interrupted(ctx, "scan"):
			// The process got a signal. interrupted wrote the line.
			return errInterrupted
		case errors.Is(err, context.DeadlineExceeded) && serverCtx.Err() != nil:
			// The budget of this server is used up. The tool at i was cut,
			// so it counts as not fully checked.
			notChecked := len(tools) - i
			r.add(o.Index, "", budgetRow(ref, r.budgetSeverity, notChecked, len(tools)))
			r.c.scanWarnf("server %s: the rule analysis stopped after %s; %d of %d %s not fully checked",
				cutName(o.Server.Name), r.budget, notChecked, len(tools), plural(len(tools), "tool", "tools"))
			return nil
		default:
			// A guard: CheckTool fails only when its context ends. The text
			// of err is never printed.
			r.c.cmdPrintf("scan", "server %s: %s", cutName(o.Server.Name), toolRulesInternalText)
			return errToolRulesFailed
		}
	}
	return nil
}

// add keeps row, a row of the server at index, or counts it when the ignore
// list drops it. toolName is the real tool name of the row ("" for a row
// about the whole server): the ignore list compares it, not the Key of the
// row.
func (r *toolRulesRun) add(index int, toolName string, row report.FindingRow) {
	key := rules.FindingKey{RuleID: row.RuleID, Server: row.Name, Tool: toolName}
	drop, fileBlocked := r.ignore.ignored(key)
	if drop {
		r.res.ignored = addIgnored(r.res.ignored, row.RuleID, 1)
		return
	}
	if fileBlocked && !slices.Contains(r.fileBlocked, row.RuleID) {
		r.fileBlocked = append(r.fileBlocked, row.RuleID)
	}
	r.res.rows = append(r.res.rows, row)
	if index >= 0 && index < len(r.counts) {
		r.counts[index]++
	}
}

// textRow returns the finding row of the rule hit f on the tool toolName of
// the server ref. The severity, the title, the risk and the remediation come
// from the rule set, as for the config rules (see findingRule). The Key is
// toolKey(toolName).
func textRow(set *rules.Set, ref report.ServerRef, toolName string, f rules.TextFinding) report.FindingRow {
	rule, severity := findingRule(set, f.RuleID)
	return report.FindingRow{
		ServerRef:   ref,
		RuleID:      f.RuleID,
		Severity:    severity,
		Title:       rule.Title,
		Risk:        rule.Risk,
		Remediation: rule.Remediation,
		Field:       rules.FieldTool,
		Key:         toolKey(toolName),
		Related:     string(f.Target),
	}
}

// toolKey returns the Key of a tool rule row for the tool name: the name cut
// to maxToolKeyRunes runes, with termsafe.CutMarker at the end when it was
// cut. An empty name gives noToolNameKey: the report writers treat a row with
// an empty Key as a row about the whole server. The Key is raw text: the
// report writers escape it, as they escape every Key.
func toolKey(name string) string {
	if name == "" {
		return noToolNameKey
	}
	short, cut := termsafe.Cut(name, maxToolKeyRunes)
	if cut {
		return short + termsafe.CutMarker
	}
	return short
}

// budgetSeverity returns the severity of a rules.RuleAnalysisBudget row: the
// highest severity of the description and schema rules of a (see
// rules.Analyzer.MaxSeverity), but never lower than high.
//
// The rules that did not run could have given a finding of that severity. So
// a server cannot make a critical finding go away when it uses up the budget:
// with a critical rule (from --rules) the budget row is critical too, and
// "--fail-on critical" still gives exit code 1.
func budgetSeverity(a *rules.Analyzer) rules.Severity {
	if s := a.MaxSeverity(); s.Rank() > rules.SeverityHigh.Rank() {
		return s
	}
	return rules.SeverityHigh
}

// budgetRow returns the rules.RuleAnalysisBudget row of the server ref, whose
// rule analysis used up its time budget. severity is the severity of the row
// (see budgetSeverity). notChecked is the number of tools that were not fully
// checked, out of total. The row is about the whole server, so its Key is
// empty. All its texts are fixed (see budgetTitle), apart from the two
// numbers in Related. They do not come from the rule set: a rule from --rules
// could use the same ID.
func budgetRow(ref report.ServerRef, severity rules.Severity, notChecked, total int) report.FindingRow {
	return report.FindingRow{
		ServerRef:   ref,
		RuleID:      rules.RuleAnalysisBudget,
		Severity:    string(severity),
		Title:       budgetTitle,
		Risk:        budgetRisk,
		Remediation: budgetRemediation,
		Field:       rules.FieldTool,
		Related: fmt.Sprintf("rule analysis time budget used up; %d of %d %s not fully checked",
			notChecked, total, plural(total, "tool", "tools")),
	}
}
