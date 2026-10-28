package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// This file holds the tool rule step of scan: it applies the description and
// schema rules (threats T1 and T3) to the tools of each inspected server.

// toolRulesBudget is the largest wall-clock time that the tool rule step can
// use for the tools of one server. A real server needs far less: its tool
// texts are short. But a hostile server can send tool texts that make one
// regex take seconds. The budget stops such a server from holding up the
// whole scan. A server can get less than this: see toolRulesStepBudget.
// The analyzer checks the context before each regex on each form of the text
// (see rules.Analyzer.CheckTool), so it stops soon after the budget is used
// up. A server that uses up the budget gets a rules.RuleAnalysisBudget
// finding (see budgetRow).
const toolRulesBudget = 5 * time.Second

// toolRulesStepBudget is the wall-clock time that the whole tool rule step
// can use, for all the servers together (issue #210). Without it, a hostile
// --rules folder with slow regexes makes each server use its full
// toolRulesBudget, so 20 servers take about 100 seconds.
//
// Each server gets a fair share of the time that is left (see serverShare).
// The step stops at most one overshoot after this limit: one regex on one
// form of a text, plus one build of the forms of one text, which cannot be
// stopped (issue #146). A server that the step reaches after the limit, or
// with a fair share under minServerShare, is not checked: it gets a
// rules.RuleAnalysisBudget finding for all its tools.
//
// That overshoot comes out of the shared limit too. So servers early in the
// order can use up the time of later servers. Those later servers get a
// rules.RuleAnalysisBudget finding, never a silent pass.
const toolRulesStepBudget = 30 * time.Second

// minServerShare is the smallest fair share of the step limit that a server
// needs to be checked (see checkTools). It is the rounding unit of the budget
// in the warning of a cut server. A share under it cannot analyse anything:
// the server would be cut at once, with the warning "stopped after 0s". So the
// step treats such a server as a server that it reached after the limit.
const minServerShare = time.Millisecond

// toolChecker is the part of *rules.Analyzer that the tool rule step uses.
// The step takes this interface, not the struct, so a test can pass a fake
// checker with a known speed and known findings.
type toolChecker interface {
	// CheckTool applies the description and schema rules to t. When ctx
	// ends, it returns the findings so far and an error that wraps
	// ctx.Err() (see rules.Analyzer.CheckTool).
	CheckTool(ctx context.Context, t inspect.Tool) ([]rules.TextFinding, error)
	// MaxSeverity returns the highest severity of the rules that CheckTool
	// applies (see failClosedSeverity).
	MaxSeverity() rules.Severity
}

// maxToolRowsPerServer is the largest number of tool finding rows that scan
// keeps for one server. A server with more findings gets one summary finding
// (rules.RuleToolFindingCap) in place of the rest, so that a hostile server
// cannot flood the report. The step keeps the most severe rows (see
// toolRulesRun.flushTools), so a server cannot push a severe finding out of
// the report with many weak ones.
const maxToolRowsPerServer = 1000

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
	// rules.RuleAnalysisBudget row and the rules.RuleToolFindingCap row of a
	// server come after its tool rows.
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

// The fixed texts of a rules.RuleToolFindingCap row (see capRow). Like the
// budget rule, this rule has no YAML file, so the rule set does not hold its
// texts.
const (
	capTitle = "Tool findings over the limit are not listed"
	capRisk  = "This server has more tool findings than the report lists for one server, " +
		"so the report is short but not complete. A hostile server can use this to hide a finding among many."
	capRemediation = "Do not use this server until you have read its tool descriptions and schemas yourself. " +
		"Treat the findings that the report lists as a sample, not as the full list."
)

// toolRulesStep applies the description and schema rules of setup.analyzer
// to the tools of the inspected servers in outcomes (FR-07, FR-09). The rule
// set setup.checks.set gives the severity and the texts of each finding (see
// findingRule). It skips a server that was not inspected (inspect.StatusOK is
// not set) or that lists no tools. A nil analyzer checks nothing.
//
// The servers go in the order of inspect.Outcome.Index, and the tools of a
// server in the order that the server lists them, one after the other.
//
// The whole step has the time limit setup.toolStepBudget
// (toolRulesStepBudget in a real scan). Each server gets its own context,
// made from the step context, with a fair share of the time that is left (see
// serverShare), but never more than setup.toolBudget (toolRulesBudget in a real
// scan). So no server runs past the step limit. When the budget of a server is
// used up, the step keeps the rows that it found for that server, adds one
// rules.RuleAnalysisBudget row (see budgetRow and failClosedSeverity), prints
// one warning on stderr with the budget that the server got, and goes on with
// the next server. A budget of 0 or less is used up at once.
//
// When the step limit has passed before a server starts, or the fair share of
// the server is under minServerShare, the step does not check that server or
// any server after it. It adds the rules.RuleAnalysisBudget row for all the
// tools of each such server, as for a server that was cut. It prints no warning for
// each such server, but one warning at the end of the step with their count
// (see lateServersText). The JSON "complete" field stays true: the budget row
// marks each server that was not fully checked.
//
// A finding row holds the rule ID, the tool name in Key (see
// maskedToolKey: each secret value of the server, from
// inspect.Result.Secrets, shows as discover.Mask) and the target
// ("description" or "schema") in Related. It never holds tool text or pattern
// text. The ignore list ignore drops rows like the rows of the config
// rules (see scanIgnores.ignored), apart from the rules.RuleAnalysisBudget
// row and the rules.RuleToolFindingCap row, which only --ignore drops (see
// fileCannotIgnore). It compares the real tool name, not the Key. The step
// prints one warning for each rule ID that .mcpmoat-ignore cannot ignore.
//
// A server keeps at most toolRulesRun.maxRows tool rows (maxToolRowsPerServer
// by default), counted after the ignore list: a row that the list drops does
// not count. The step keeps the most severe rows. Among rows of the same
// severity it keeps the ones of the first tools. The rows over the limit are
// not kept. At the end of the check of the server, the step adds one
// rules.RuleToolFindingCap row for them (see capRow) and prints one warning on
// stderr. The budget row and the cap row do not count toward the limit.
//
// counts holds the finding counts of each server by the index of the server
// (see serverStatuses). The step adds the rows that it keeps for a server to
// counts[Index]. An index outside counts cannot happen; it is skipped rather
// than panic.
//
// On an error the result is empty, and scan must print no report, save no
// pins and exit with code 2. The step already wrote the line on stderr:
//   - errInterrupted when ctx ended (the process got a signal) while the
//     analyzer ran. The line is interruptedText (see interrupted). The end of
//     the step limit is not an interrupt: it only adds budget rows.
//   - errToolRulesFailed when the analyzer failed for any other reason. The
//     line is toolRulesInternalText, after the server label.
func (c *cli) toolRulesStep(ctx context.Context, setup scanSetup, outcomes []inspect.Outcome, ignore *scanIgnores, counts []int) (toolRulesResult, error) {
	// Check the pointer before it goes into a toolChecker. An interface that
	// holds a nil *rules.Analyzer is not == nil (it has a type), so
	// checkTools could not see that there is no analyzer.
	if setup.analyzer == nil {
		return toolRulesResult{}, nil
	}
	return c.checkTools(ctx, setup.analyzer, setup, outcomes, ignore, counts)
}

// checkTools is toolRulesStep with the checker as an argument, so a test can
// pass a fake. It does not use setup.analyzer. checker must not be nil.
func (c *cli) checkTools(ctx context.Context, checker toolChecker, setup scanSetup, outcomes []inspect.Outcome, ignore *scanIgnores, counts []int) (toolRulesResult, error) {
	// stepCtx ends at the step limit. ctx stays the parent: interrupted
	// checks ctx, so the end of the step limit is never seen as a signal.
	stepCtx, cancel := context.WithTimeout(ctx, setup.toolStepBudget)
	defer cancel()

	run := toolRulesRun{
		c:                  c,
		checker:            checker,
		set:                setup.checks.set,
		ignore:             ignore,
		budget:             setup.toolBudget,
		maxRows:            setup.maxToolRows,
		failClosedSeverity: failClosedSeverity(checker),
		counts:             counts,
	}
	// inspect.Run sorts the outcomes, so their order is not the order of the
	// servers.
	sorted := slices.SortedStableFunc(slices.Values(outcomes), func(x, y inspect.Outcome) int {
		return cmp.Compare(x.Index, y.Index)
	})
	// todo holds only the servers to check, so that len(todo)-i is the
	// number of servers left, with the server at i. DeleteFunc changes its
	// slice in place: sorted is a new slice, so outcomes does not change.
	todo := slices.DeleteFunc(sorted, func(o inspect.Outcome) bool {
		return o.Status != inspect.StatusOK || len(o.Result.Tools) == 0
	})
	late := 0
	for i, o := range todo {
		// A signal stops the scan, also when the step limit has passed too.
		if c.interrupted(ctx, "scan") {
			// interrupted wrote the line.
			return toolRulesResult{}, errInterrupted
		}
		// The deadline is always set: context.WithTimeout set it above.
		deadline, _ := stepCtx.Deadline()
		left := time.Until(deadline)
		// servers counts this server and the ones after it. A late server
		// counts too, until the loop reaches it, as in serverShare.
		servers := len(todo) - i
		// fair is the share of the step time of this server, before the
		// per-server cap. A negative left gives a negative fair.
		fair := left / time.Duration(servers)
		// Once one server is late, all the servers after it are late too.
		// Else a late server would leave its share to the next one, and the
		// step would check that one for about 1 ms and cut it, with its own
		// warning. So the late servers are always the last ones.
		if late > 0 || stepCtx.Err() != nil || fair < minServerShare {
			run.addLateServer(o)
			late++
			continue
		}
		budget := serverShare(run.budget, left, servers)
		if err := run.checkServer(ctx, stepCtx, o, budget); err != nil {
			return toolRulesResult{}, err
		}
	}
	if late > 0 {
		c.scanWarnf("%s", lateServersText(setup.toolStepBudget, late))
	}
	for _, id := range run.fileBlocked {
		c.warnFileCannotIgnore(id)
	}
	return run.res, nil
}

// serverShare returns the time budget of the next server: the time left until
// the step limit, split evenly among the servers left (with the next one),
// but never more than perServer. A server that ends early leaves its unused
// time to the servers after it. left can be zero or less: the share is then
// zero or less too. A servers value under 1 counts as 1. perServer can be 0 or
// less: the budget is then used up at once.
func serverShare(perServer, left time.Duration, servers int) time.Duration {
	// time.Duration is an int64 count of nanoseconds, so this is an integer
	// division.
	share := left / time.Duration(max(servers, 1))
	return min(perServer, share)
}

// lateServersText returns the text of the warning for the servers that the
// step did not check, because the step limit had passed before they started,
// or their fair share was under minServerShare.
// It holds the limit and the count, and fixed words only: no server name.
func lateServersText(limit time.Duration, late int) string {
	return fmt.Sprintf("the %s time limit of the rule analysis left too little time; %d %s not checked",
		limit, late, plural(late, "server was", "servers were"))
}

// toolRulesRun holds the state of one toolRulesStep call.
type toolRulesRun struct {
	c       *cli
	checker toolChecker
	set     *rules.Set
	ignore  *scanIgnores
	// budget is the largest time budget of one server: scanSetup.toolBudget.
	// A server can get less (see serverShare).
	budget time.Duration
	// maxRows is the largest number of tool rows that the step keeps for one
	// server. The caller sets it to more than zero: scanSetup.maxToolRows. The
	// budget row and the cap row do not count toward it.
	maxRows int
	// failClosedSeverity is the severity of the rules.RuleAnalysisBudget row
	// and of the rules.RuleToolFindingCap row (see failClosedSeverity). It is
	// the same for each server, so the step computes it once.
	failClosedSeverity rules.Severity
	counts             []int
	res                toolRulesResult
	// pending holds the tool rows of the server that it checks now, after the
	// ignore list, in tool order. flushTools keeps the most severe ones.
	// checkServer empties it at the start of each server. maxRows bounds the
	// output, not pending: pending holds at most one row for each tool, rule
	// and target, and the time budget of the server limits how many rows the
	// analyzer can make. The step before the cap held the same rows.
	pending []report.FindingRow
	// omitted counts the tool rows that flushTools did not keep for the server
	// that it checks now, because there were more than maxRows. checkServer
	// sets it to zero at the start of each server.
	omitted int
	// fileBlocked lists the rule IDs that have a .mcpmoat-ignore entry that
	// matches a kept row but is not applied (see scanIgnores). Each ID is in
	// it once, in the order of the first row that it matched.
	fileBlocked []string
}

// checkServer applies the rules to the tools of the inspected server o, with
// the time limit budget. ctx is the parent context of the step: it ends only
// on a signal. stepCtx ends at the step limit. The server context comes from
// stepCtx, so the server cannot run past the step limit. It returns
// errInterrupted or errToolRulesFailed (see toolRulesStep), after it wrote
// the line on stderr, and nil when the server is done, also when the budget
// was used up.
func (r *toolRulesRun) checkServer(ctx, stepCtx context.Context, o inspect.Outcome, budget time.Duration) error {
	serverCtx, cancel := context.WithTimeout(stepCtx, budget)
	defer cancel()

	r.pending, r.omitted = r.pending[:0], 0
	ref := report.NewServerRef(o.Server, o.Index)
	// One redactor for the whole server: the secret values are the same for
	// each tool, so they are read once.
	redactor := discover.NewTextRedactor(o.Result.Secrets)
	tools := o.Result.Tools
	for i, t := range tools {
		found, err := r.checker.CheckTool(serverCtx, t)
		// Keep the findings also when err is not nil: every finding that
		// CheckTool returns is a real match. All rows of one tool share one
		// Key, so the mask runs once for each tool with a finding. The ignore
		// list gets the real name, the row gets the masked Key.
		if len(found) > 0 {
			key := maskedToolKey(redactor, t.Name)
			for _, f := range found {
				r.addTool(t.Name, textRow(r.set, ref, key, f))
			}
		}
		if err == nil {
			continue
		}
		// Check the parent context first: when the process got a signal, the
		// scan stops, also when the budget is used up too.
		if r.c.interrupted(ctx, "scan") {
			// interrupted wrote the line.
			return errInterrupted
		}
		switch {
		case errors.Is(err, context.DeadlineExceeded) && serverCtx.Err() != nil:
			// The budget of this server is used up (its own share, or the
			// step limit). The tool at i was cut, so it counts as not fully
			// checked. The warning shows the budget that this server got,
			// rounded to milliseconds.
			notChecked := len(tools) - i
			r.flushTools(o.Index)
			r.add(o.Index, "", budgetRow(ref, r.failClosedSeverity, notChecked, len(tools)))
			r.c.scanWarnf("server %s: the rule analysis stopped after %s; %s",
				cutName(o.Server.Name), budget.Round(time.Millisecond), notCheckedText(notChecked, len(tools)))
			r.addCapRow(o, ref)
			return nil
		default:
			// A guard: CheckTool fails only when its context ends. The text
			// of err is never printed.
			r.c.cmdPrintf("scan", "server %s: %s", cutName(o.Server.Name), toolRulesInternalText)
			return errToolRulesFailed
		}
	}
	r.flushTools(o.Index)
	r.addCapRow(o, ref)
	return nil
}

// addLateServer adds the rules.RuleAnalysisBudget row of the inspected server
// o, which the step did not check because the step limit had passed, or its
// fair share was under minServerShare (see checkTools). All its tools count as
// not fully checked. The row is the same as for a server that was cut (see
// budgetRow), so the gate and the ignore list treat it the same way. It prints
// no warning: toolRulesStep prints one for all such servers.
func (r *toolRulesRun) addLateServer(o inspect.Outcome) {
	total := len(o.Result.Tools)
	ref := report.NewServerRef(o.Server, o.Index)
	r.add(o.Index, "", budgetRow(ref, r.failClosedSeverity, total, total))
}

// addCapRow adds the rules.RuleToolFindingCap row of the server o, with the
// severity r.failClosedSeverity (the same fail-closed severity as the budget
// row), and prints one warning on stderr. It does nothing when flushTools kept
// all the tool rows of the server. The row goes through the ignore list like the
// budget row: --ignore drops it, .mcpmoat-ignore does not. The warning holds
// the server name, cut and quoted (see cutName), and two numbers. The
// warning also appears when --ignore drops the row, as the budget warning does.
func (r *toolRulesRun) addCapRow(o inspect.Outcome, ref report.ServerRef) {
	if r.omitted == 0 {
		return
	}
	r.add(o.Index, "", capRow(ref, r.failClosedSeverity, r.omitted, r.maxRows))
	r.c.scanWarnf("server %s: %s", cutName(o.Server.Name), capText(r.omitted, r.maxRows))
}

// add keeps row, a row of the server at index, or counts it when the ignore
// list drops it. toolName is the real tool name of the row ("" for a row
// about the whole server): the ignore list compares it, not the Key of the
// row. add has no limit. It is for the budget row and the cap row (see
// addTool for the tool rows).
func (r *toolRulesRun) add(index int, toolName string, row report.FindingRow) {
	if r.passIgnore(toolName, row) {
		r.keep(index, row)
	}
}

// addTool holds the tool row row of the server for flushTools, or counts it as
// ignored when the ignore list drops it. A dropped row does not count toward
// the limit. The tool name is the real one (see add).
func (r *toolRulesRun) addTool(toolName string, row report.FindingRow) {
	if r.passIgnore(toolName, row) {
		r.pending = append(r.pending, row)
	}
}

// capRank returns the number that the caps sort a finding by: flushTools for
// the tool rows and cutConfigHits for the config findings. A severity that is
// not valid counts as critical, so a cap never drops such a finding before a
// valid one. This is the rule of hasFailingFinding and rules.higherSeverity: an
// unknown severity fails closed.
func capRank(severity string) int {
	s := rules.Severity(severity)
	if !s.Valid() {
		return rules.SeverityCritical.Rank()
	}
	return s.Rank()
}

// flushTools keeps the pending tool rows of the server at index, at most
// r.maxRows of them, and counts the rest in r.omitted. It keeps the most severe
// rows, so a server cannot push a severe finding out of the report with many
// weak ones in front of it. Among rows of the same severity it keeps the ones
// of the first tools (the sort is stable). The kept rows stay in tool order.
func (r *toolRulesRun) flushTools(index int) {
	rows := r.pending
	if len(rows) <= r.maxRows {
		for _, row := range rows {
			r.keep(index, row)
		}
		return
	}
	r.omitted = len(rows) - r.maxRows
	order := make([]int, len(rows))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		return cmp.Compare(capRank(rows[b].Severity), capRank(rows[a].Severity))
	})
	kept := order[:r.maxRows]
	slices.Sort(kept)
	for _, i := range kept {
		r.keep(index, rows[i])
	}
}

// passIgnore applies the ignore list to row. It returns false, after it
// counted the row as ignored, when the list drops the row. It notes the rule
// ID when a .mcpmoat-ignore entry matches the row but is not applied.
func (r *toolRulesRun) passIgnore(toolName string, row report.FindingRow) bool {
	key := rules.FindingKey{RuleID: row.RuleID, Server: row.Name, Tool: toolName}
	drop, fileBlocked := r.ignore.ignored(key)
	if drop {
		r.res.ignored = addIgnored(r.res.ignored, row.RuleID, 1)
		return false
	}
	if fileBlocked && !slices.Contains(r.fileBlocked, row.RuleID) {
		r.fileBlocked = append(r.fileBlocked, row.RuleID)
	}
	return true
}

// keep adds row to the result and to the finding count of the server at
// index.
func (r *toolRulesRun) keep(index int, row report.FindingRow) {
	r.res.rows = append(r.res.rows, row)
	if index >= 0 && index < len(r.counts) {
		r.counts[index]++
	}
}

// textRow returns the finding row of the rule hit f on a tool of the server
// ref. The severity, the title, the risk and the remediation come from the
// rule set, as for the config rules (see findingRule). key is the Key of the
// row: maskedToolKey of the tool name, so a secret value that the server
// echoes in the name shows as discover.Mask. The ignore list never reads the
// Key: it compares the real tool name (see passIgnore).
func textRow(set *rules.Set, ref report.ServerRef, key string, f rules.TextFinding) report.FindingRow {
	rule, severity := findingRule(set, f.RuleID)
	return report.FindingRow{
		ServerRef:   ref,
		RuleID:      f.RuleID,
		Severity:    severity,
		Title:       rule.Title,
		Risk:        rule.Risk,
		Remediation: rule.Remediation,
		Field:       rules.FieldTool,
		Key:         key,
		Related:     string(f.Target),
	}
}

// toolKey returns the name cut to maxToolKeyRunes runes, with
// termsafe.CutMarker at the end when it was cut. An empty name gives
// noToolNameKey: the report writers treat a row with an empty Key as a row
// about the whole server. The Key is raw text: the report writers escape it,
// as they escape every Key.
//
// toolKey does not hide secret values. A row Key comes from maskedToolKey,
// which hides them first and then calls toolKey.
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

// maskedToolKey returns the Key of a tool rule row or an LLM row for the tool
// name: the name with each secret value of the server replaced with
// discover.Mask, then cut like toolKey (to maxToolKeyRunes runes, or
// noToolNameKey for an empty name).
//
// r holds the secret values of the server (discover.NewTextRedactor of
// inspect.Result.Secrets). A server gets the configured env values, header
// values and argv secrets, and a hostile server can echo one of them in a tool
// name. mcpmoat never prints such a value (FR-14, FR-17). A nil r hides
// nothing: the methods of discover.TextRedactor work on a nil pointer and
// then return their input.
//
// The mask comes before the cut, so a cut can split a Mask but never a secret
// value. The mask reads only the start of a long name: maxToolKeyRunes runes
// have at most utf8.UTFMax bytes each, so a masked text of more than
// utf8.UTFMax*maxToolKeyRunes bytes has more than maxToolKeyRunes runes, and
// the start that r.Prefix returns for that limit gives the same cut as the
// whole masked name.
func maskedToolKey(r *discover.TextRedactor, name string) string {
	masked, _ := r.Prefix(name, utf8.UTFMax*maxToolKeyRunes)
	return toolKey(masked)
}

// failClosedSeverity returns the severity of a rules.RuleAnalysisBudget row and
// of a rules.RuleToolFindingCap row: the highest severity of the description
// and schema rules of a (see rules.Analyzer.MaxSeverity), but never lower than
// high. a must not be nil.
//
// The rules that did not run (budget row) or whose findings the report does
// not list (cap row) could have given a finding of that severity. So a server
// cannot make a critical finding go away when it uses up the budget or floods
// the report: with a critical rule (from --rules) the row is critical too, and
// "--fail-on critical" still gives exit code 1.
//
// MaxSeverity counts every description and schema rule that the analyzer
// applies, also a rule whose findings --ignore or .mcpmoat-ignore drops. This
// is on purpose, so the severity fails closed: the budget row is the sign in
// the report that a rule did not run, and an ignored rule cannot make it
// less severe. To drop the budget row itself, use --ignore with
// rules.RuleAnalysisBudget: the .mcpmoat-ignore file cannot (see
// fileCannotIgnore).
func failClosedSeverity(a toolChecker) rules.Severity {
	if s := a.MaxSeverity(); s.Rank() > rules.SeverityHigh.Rank() {
		return s
	}
	return rules.SeverityHigh
}

// budgetRow returns the rules.RuleAnalysisBudget row of the server ref, whose
// rule analysis used up its time budget. severity is the severity of the row
// (see failClosedSeverity). notChecked is the number of tools that were not
// fully checked, out of total. The row is about the whole server, so its Key is
// empty. All its texts are fixed (see budgetTitle), apart from the two
// numbers in Related. They do not come from the rule set: the rule has no YAML
// file (NewSet refuses the ID, see rules.ReservedRuleID), and fixed texts stay
// right even if a reserved-ID check is ever bypassed.
func budgetRow(ref report.ServerRef, severity rules.Severity, notChecked, total int) report.FindingRow {
	return report.FindingRow{
		ServerRef:   ref,
		RuleID:      rules.RuleAnalysisBudget,
		Severity:    string(severity),
		Title:       budgetTitle,
		Risk:        budgetRisk,
		Remediation: budgetRemediation,
		Field:       rules.FieldTool,
		Related:     "rule analysis time budget used up; " + notCheckedText(notChecked, total),
	}
}

// notCheckedText returns "N of M tools not fully checked". The stderr warning
// and the Related text of the budget row both use it, so they say the same.
func notCheckedText(notChecked, total int) string {
	return fmt.Sprintf("%d of %d %s not fully checked", notChecked, total, plural(total, "tool", "tools"))
}

// capRow returns the rules.RuleToolFindingCap row of the server ref, which has
// omitted tool findings that the step did not keep, over the limit. severity is
// the severity of the row (see failClosedSeverity: the row fails closed, so a
// server that floods the report still fails the gate). The row is about the whole
// server, so its Key is empty. All its texts are fixed (see capTitle), apart
// from the two numbers in Related. They do not come from the rule set: the
// rule has no YAML file (NewSet refuses the ID, see rules.ReservedRuleID).
func capRow(ref report.ServerRef, severity rules.Severity, omitted, limit int) report.FindingRow {
	return report.FindingRow{
		ServerRef:   ref,
		RuleID:      rules.RuleToolFindingCap,
		Severity:    string(severity),
		Title:       capTitle,
		Risk:        capRisk,
		Remediation: capRemediation,
		Field:       rules.FieldTool,
		Related:     capText(omitted, limit),
	}
}

// capText returns "N more tool findings are not listed; limit M". The stderr
// warning and the Related text of the cap row both use it, so they say the
// same. It holds two numbers and fixed words only.
func capText(omitted, limit int) string {
	return fmt.Sprintf("%d more tool %s not listed; limit %d",
		omitted, plural(omitted, "finding is", "findings are"), limit)
}
