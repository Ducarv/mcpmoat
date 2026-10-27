package main

import (
	"errors"
	"path/filepath"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// This file holds the connect step of scan after inspect.Run: the inspection
// status of each server for the --json report, the pinner, which checks the
// tools of each inspected server against pins.json, and the ignore lists of
// the pin rules and the LLM rules.

// pinReport is the result of the connect step of scan: the inspection status
// of each server, and from the pin step what scan adds to its report and what
// it must still save. The status lives here because inspectAndPin returns only
// this value, and because two servers with one identity get their status by
// the same rule that checkOutcome uses (see recordInspection).
type pinReport struct {
	// rows are the pin findings that the ignore list does not drop, in the
	// order of the servers, then of the tools.
	rows []report.FindingRow
	// diffs are the diffs of the changed and new tools in rows. A change that
	// the ignore list drops has no diff.
	diffs []report.ToolDiff
	// ignored counts the pin findings that the ignore list dropped, by rule
	// ID. It is nil when the list dropped nothing.
	ignored map[string]int
	// pinned lists the servers that this run wants to pin for the first time,
	// in the order of the servers. It holds only servers that fit in pins.json
	// (see pinner.budget). savePinned writes them (see there), and scan prints
	// one notice for each server that it saved (see printPinned).
	pinned []pinnedServer
	// hints lists the pinned servers that have at least one pin finding that
	// the ignore list does not drop, in the order of the servers. Each one
	// holds the digest of the tools that scan saw, for the line "To accept ...
	// --expect <digest>" (see writeAcceptHints). A server whose tools cannot be
	// pinned has no hint: pin --accept would refuse those tools (see compare).
	hints []acceptHint
	// statuses holds the inspection result of each outcome, in the order of
	// the outcomes (not of the config). serverStatuses puts them in the order
	// of the servers for the summary. It is nil when scan inspected nothing.
	statuses []outcomeStatus
	// inspection holds the inspection status of each server that scan
	// inspected, as one of the report.InspectionStatus constants. It is keyed by
	// serverIdentity, because inspect.Run sorts the servers, so the outcomes
	// are not in the order of the server table. A server that is not in the
	// map was not inspected: the --json report shows it as not run (see
	// inspectionOf). It is nil when scan inspected nothing.
	inspection map[pins.Identity]report.InspectionStatus
	// storeExisted is pins.Store.Existed of the store that scan read before it
	// started the servers. savePinned compares it with the store that it reads
	// again with the lock, to find a pins file that was removed while scan ran
	// (see pinsRemovedWhileRunning).
	storeExisted bool
}

// outcomeStatus is the summary entry of one outcome, with the index of the
// server that it belongs to. The report.ServerStatus holds only the pin
// findings of the server: serverStatuses adds the findings of the config rules.
type outcomeStatus struct {
	// index is inspect.Outcome.Index: the index of the server in the servers
	// slice that scan gave to inspect.Run.
	index  int
	status report.ServerStatus
}

// pinnedServer is one server that scan pinned for the first time. It holds what
// savePinned needs to write the pins.
type pinnedServer struct {
	id    pins.Identity
	snap  pins.ServerPins // the pins of the tools that scan saw
	name  string          // the server name from the config file: untrusted
	tools int
}

// scanIgnores holds the two ignore lists of one scan.
//
// A .mcpmoat-ignore file can come from a cloned repository, and the user did
// not write it. If it could ignore a pin finding (MOAT-T2-*), a hostile
// project could silence the rug-pull alarm for the user's own servers. If it
// could ignore an LLM finding (MOAT-LLM-001 or MOAT-LLM-002), it could silence
// the classifier for every server of a user who runs "scan --llm" there. If it
// could ignore the budget finding (MOAT-T1-023), it could hide that a server
// used up its rule time budget, so that the tools after the cut look clean.
// If it could ignore the tool findings cap (MOAT-T1-024), it could silence the
// summary row of the findings that scan did not list. So the file never
// ignores these rules (see fileCannotIgnore). Only --ignore on the command
// line does, because the user typed it. A cloned repository cannot hide that
// findings were left out.
type scanIgnores struct {
	// all holds the entries of .mcpmoat-ignore and of --ignore. It drops
	// the findings of the config rules and of the tool rules. It does not drop
	// the findings of the pin rules, of the LLM rules, of the budget rule
	// and of the tool findings cap (see ignored).
	all rules.IgnoreList
	// flags holds only the --ignore entries. It drops the findings of the pin
	// rules, of the LLM rules, of the budget rule and of the tool findings
	// cap.
	flags rules.IgnoreList
	// fileEntries is the number of entries that scan read from the
	// .mcpmoat-ignore file: the N in the stderr line "using N entries". It
	// counts the entries that the file cannot apply too (see
	// fileCannotIgnore), and the ones that match no finding.
	fileEntries int
}

// fileCannotIgnore reports whether the rule id is one that .mcpmoat-ignore
// cannot ignore: a pin rule (MOAT-T2-*), llm.RuleID, llm.RuleIDInvalid,
// rules.RuleAnalysisBudget or rules.RuleToolFindingCap. Only --ignore drops
// the findings of these rules (see scanIgnores).
func fileCannotIgnore(id string) bool {
	return pins.IsPinRuleID(id) || id == llm.RuleID || id == llm.RuleIDInvalid ||
		id == rules.RuleAnalysisBudget || id == rules.RuleToolFindingCap
}

// ignored reports whether the user asked to ignore the finding k. For a pin
// rule, an LLM rule, the budget rule or the tool findings cap (see
// fileCannotIgnore) only the --ignore list counts.
// The second result is true when the .mcpmoat-ignore file has an entry that
// matches k but is not applied, so that the caller can warn about it (see
// warnFileCannotIgnore).
func (s *scanIgnores) ignored(k rules.FindingKey) (drop, fileBlocked bool) {
	if !fileCannotIgnore(k.RuleID) {
		return s.all.Ignored(k), false
	}
	if s.flags.Ignored(k) {
		return true, false
	}
	return false, s.all.Ignored(k)
}

// warnFileCannotIgnore prints the warning that .mcpmoat-ignore has an entry
// for the rule ruleID that is not applied (see scanIgnores). The pin step, the
// tool rule step and the LLM step print it once for each rule ID.
func (c *cli) warnFileCannotIgnore(ruleID string) {
	c.scanWarnf("%s cannot ignore %s; use --ignore on the command line",
		rules.IgnoreFileName, termsafe.Quote(ruleID))
}

// pinOutcomes checks the tools of the servers that were inspected against
// the pins store (FR-11 and FR-12). It gets the store from readPins, which
// scan calls before the servers are inspected. It only reads the store and
// writes nothing. The servers to pin for the first time are in the result:
// savePinned writes them after the report is printed.
//
// pins.json has a size limit (pins.MaxFileSize), and Store.Set refuses a server
// that would make the file larger (pins.ErrStoreFull). The report is printed
// before savePinned runs, so the refusal must be known now, or the report could
// not show it. So pinOutcomes adds the first-run servers to a copy of the store
// (see pinner.budget), in the order that savePinned uses. A server that does
// not fit gets a finding and is not saved.
//
// The ignore list drops pin findings by rule ID, server name and tool name,
// but only with --ignore (see scanIgnores). A dropped finding is counted in
// the result, and its diff is not kept. A .mcpmoat-ignore entry that would
// drop a pin finding is not applied, and gives one warning for each rule ID.
func (c *cli) pinOutcomes(store *pins.Store, outcomes []inspect.Outcome, ign *scanIgnores) pinReport {
	p := &pinner{
		c:       c,
		ign:     ign,
		store:   store,
		budget:  store.Clone(),
		handled: make(map[pins.Identity]bool),
		failed:  make(map[pins.Identity]bool),
		warned:  make(map[string]bool),
		res: pinReport{
			inspection:   make(map[pins.Identity]report.InspectionStatus, len(outcomes)),
			storeExisted: store.Existed(),
		},
	}
	servers := make([]discover.Server, len(outcomes))
	for i, o := range outcomes {
		p.recordInspection(o)
		before := len(p.res.rows)
		p.checkOutcome(o)
		servers[i] = o.Server
		// The rows that checkOutcome kept are the pin findings of this
		// outcome. Counting here (not by name) keeps two servers with one
		// name apart.
		p.res.statuses = append(p.res.statuses, outcomeStatus{
			index:  o.Index,
			status: outcomeSummary(o, len(p.res.rows)-before),
		})
	}
	// pin selects its server among all the servers, also the ones that were
	// not inspected.
	setSelectors(p.res.hints, servers)
	return p.res
}

// pinner holds the state of one pinOutcomes call.
type pinner struct {
	c   *cli
	ign *scanIgnores
	// store is the store that scan read before it started the servers. The
	// pinner only reads it.
	store *pins.Store
	// budget is a copy of store (pins.Store.Clone). firstPin adds each server
	// that it wants to pin to it with Set, as savePinned will add it to the
	// real store, to find a server that would make pins.json too large
	// (pins.ErrStoreFull). The report is printed before the save, so this
	// must be known before the save. Set on the copy never changes store, and
	// the copy is never saved.
	budget *pins.Store
	res    pinReport
	// handled holds the servers that this run already checked or pinned. Two
	// servers with one identity should not happen, but if they do, the second
	// must not be compared with the pins of the first.
	handled map[pins.Identity]bool
	// failed holds the pinned servers that already got the row for a server
	// that was not inspected, so that a second failing outcome with the same
	// identity gives no second row. It is not part of handled: an outcome that
	// was inspected after a failed one is still compared with the pins.
	failed map[pins.Identity]bool
	// warned holds the rule IDs for which the user already got the warning
	// that .mcpmoat-ignore cannot ignore them.
	warned map[string]bool
}

// recordInspection stores the inspection status of o (see pinReport.inspection).
// Two servers with one identity should not happen. If they do, they share one
// status: ok when one of them was inspected, because checkOutcome then checks
// the tools of the first one that was inspected. Otherwise the first outcome
// keeps its status.
func (p *pinner) recordInspection(o inspect.Outcome) {
	id := serverIdentity(o.Server)
	status := inspectionStatus(o)
	old, seen := p.res.inspection[id]
	firstOK := old != report.InspectionOK && status == report.InspectionOK
	if !seen || firstOK {
		p.res.inspection[id] = status
	}
}

// inspectionStatus maps the outcome of an inspection to a
// report.InspectionStatus constant. It reads the status and the kind of the
// error, never the error text. A refusal comes first: a gate that refuses a
// server also sets inspect.StatusFailed.
func inspectionStatus(o inspect.Outcome) report.InspectionStatus {
	if inspect.Refused(o.Err) {
		return report.InspectionRefused
	}
	switch o.Status {
	case inspect.StatusOK:
		return report.InspectionOK
	case inspect.StatusTimeout:
		return report.InspectionTimeout
	default:
		return report.InspectionFailed
	}
}

// inspectionOf returns the inspection status of the server s for the --json
// report. A server that scan did not inspect (--no-connect, or no outcome)
// has the status report.InspectionNotRun.
func (r pinReport) inspectionOf(s discover.Server) report.InspectionStatus {
	if status, ok := r.inspection[serverIdentity(s)]; ok {
		return status
	}
	return report.InspectionNotRun
}

// checkOutcome checks one outcome. A server that was not inspected shows its
// status in the summary (see outcomeSummary), and also gets a high MOAT-T2-004
// finding when it is pinned and failed or timed out (see notInspected). For a
// server that was inspected:
//   - one that is not in the store is pinned (see firstPin);
//   - one that is in the store is compared with its pins (see compare);
//   - a second server with the same identity is a MOAT-T2-004 finding, so that
//     its tools are not skipped. It is "high" when the identity is in the
//     store, and "medium" when it is not;
//   - a server whose config path is not absolute (the working directory is not
//     known) is a high MOAT-T2-004 finding. Its identity would not match the
//     one in the store, so it would be pinned again with no comparison.
func (p *pinner) checkOutcome(o inspect.Outcome) {
	s := o.Server
	id := serverIdentity(s)
	if o.Status != inspect.StatusOK {
		p.notInspected(s, id, o.Err)
		return
	}
	if p.handled[id] {
		p.addUnverified(s, reasonListedTwice, riskServerUnverified, fixListedTwice, p.unverifiedSeverity(id))
		return
	}
	p.handled[id] = true
	if !filepath.IsAbs(s.Source) {
		p.addUnverified(s, reasonRelativeSource, riskServerUnverified, fixRelativeSource, pins.UnverifiedSeverity(true))
		return
	}

	tools := o.Result.Tools
	if stored, found := p.store.Get(id); found {
		p.compare(s, id, tools, stored)
		return
	}
	p.firstPin(s, id, tools)
}

// add keeps a row, or counts it when the ignore list drops it. It returns false
// for a dropped row, so the caller keeps no diff for it.
func (p *pinner) add(row report.FindingRow) bool {
	key := rules.FindingKey{RuleID: row.RuleID, Server: row.Name, Tool: row.Key}
	dropped, blocked := p.ign.ignored(key)
	if blocked && !p.warned[row.RuleID] {
		p.warned[row.RuleID] = true
		p.c.warnFileCannotIgnore(row.RuleID)
	}
	if dropped {
		p.res.ignored = addIgnored(p.res.ignored, row.RuleID, 1)
		return false
	}
	p.res.rows = append(p.res.rows, row)
	return true
}

// addUnverified adds the MOAT-T2-004 row of a server that scan cannot verify,
// with the given severity. reason and fix must be fixed texts: they are shown
// in the report. fix replaces the remediation of pins.KindUnverified, because
// scan prints no "To accept" line for these rows, so "pin --accept" cannot
// solve them (see the fix constants). risk replaces the risk of
// pins.KindUnverified too: the row is about the whole server, which may have
// no pin at all, not about the pin of one tool (see the risk constants).
func (p *pinner) addUnverified(s discover.Server, reason, risk, fix, severity string) {
	row := pinRow(pins.KindUnverified, s, "", severity)
	row.Related = reason
	row.Risk = risk
	row.Remediation = fix
	p.add(row)
}

// unverifiedSeverity returns the severity of a MOAT-T2-004 row about the server
// id: "high" when the store holds pins for it, because a pinned server that
// scan cannot check can hide a rug pull, and "medium" when it is not pinned.
func (p *pinner) unverifiedSeverity(id pins.Identity) string {
	_, pinned := p.store.Get(id)
	return pins.UnverifiedSeverity(pinned)
}

// notInspected handles a server that failed, timed out or was refused. The
// summary on stdout shows its status (see outcomeSummary). A server that
// was pinned before this run and failed or timed out also gets a MOAT-T2-004
// finding with severity high and the fixed reason reasonNotInspected, so scan
// exits with 1: its pinned tools could not be checked, and a hostile server
// must not be able to avoid the rug-pull check by failing on purpose.
//
// A server that a gate refused (inspect.Refused: the client config turns it
// off or does not approve it, or it is in an untrusted project file) stays a
// warning only, also when it is pinned. The config of the user sets that
// state, not the server, and the client does not load such a server. A
// server that is not in the store is only a warning (FR-06). A server that this
// run already inspected gets no row: the first outcome checked its tools. A
// second failing outcome with one identity gives no second row (see failed).
func (p *pinner) notInspected(s discover.Server, id pins.Identity, err error) {
	if inspect.Refused(err) {
		return
	}
	if _, pinned := p.store.Get(id); pinned && !p.handled[id] && !p.failed[id] {
		p.addUnverified(s, reasonNotInspected, riskServerUnverified, fixNotInspected, pins.UnverifiedSeverity(true))
		p.failed[id] = true
	}
}

// firstPin records the tools of a server that is not in the store yet, so that
// savePinned can pin them. The store is not changed here. scan prints "pinned N
// tools for <server>" on stderr only after savePinned saved the server (see
// printPinned). When the tools cannot be pinned (see pinnable), nothing is
// recorded and the server gets a high MOAT-T2-004 finding. Such a server is
// never pinned, so later changes of its tools would never show: it must fail
// the default --fail-on high, like a pinned tool that cannot be verified.
//
// firstPin also adds the pins to p.budget, a copy of the store. When the pins
// would make pins.json larger than its size limit (pins.ErrStoreFull), the
// server is not recorded either, and it gets the same high MOAT-T2-004 finding
// with the fixed reason reasonStoreFull. The report is printed before
// savePinned runs, so firstPin must decide this now: otherwise the server
// would be refused at the save with no finding in the report. The servers
// before it stay in the budget, so the servers that fit are still pinned.
func (p *pinner) firstPin(s discover.Server, id pins.Identity, tools []inspect.Tool) {
	snap, err := pinnable(id, tools)
	if err != nil {
		// The row gets the fixed reason, never the error text (see
		// pinnableReason).
		p.addUnverified(s, pinnableReason(err), riskServerUnverified, fixNotPinnable, pins.UnverifiedSeverity(true))
		return
	}
	// pinnable checked the pins with pins.ValidateServer, so the only error
	// that Set can give here is pins.ErrStoreFull. Any other error keeps the
	// server in the list: savePinned calls Set again, which gives the same
	// error, and reports it there (exit code 2).
	if err := p.budget.Set(id, snap); errors.Is(err, pins.ErrStoreFull) {
		p.addUnverified(s, reasonStoreFull, riskServerUnverified, fixStoreFull, pins.UnverifiedSeverity(true))
		return
	}
	p.res.pinned = append(p.res.pinned, pinnedServer{id: id, snap: snap, name: s.Name, tools: len(tools)})
}

// compare compares the tools of a pinned server with its pins (pins.Compare).
// Each change is one finding row. The rule ID comes from the change kind and
// the severity from Change.Severity (a pinned name that cannot be verified is
// high), not from the rule set, which does not hold the pin rules. A changed or
// new tool, and a pinned tool whose pin cannot be checked, also gets a diff
// (see appendDiff). The store is never changed. When at least one row is kept
// (not ignored), compare also records the digest for the "--expect" hint
// (see writeAcceptHints). The hint says so when a kept diff was cut, or when
// the ignore list dropped a row: the digest covers that change, but the report
// shows no diff for it.
//
// Tools that cannot be pinned (see pinnable) cannot be accepted either, so
// they get no hint, and every row of the server gets the fix fixNotPinnable:
// the remediation of the change kind names the "To accept" command, which scan
// does not print for them. The error text is not printed. pins.Compare reports
// a duplicate, empty or invalid tool itself. For any other reason (the entry is
// over the size limit of pins.json), compare adds the high MOAT-T2-004 row of
// firstPin, so the server fails the default --fail-on high: no change of its
// tools could ever be accepted.
func (p *pinner) compare(s discover.Server, id pins.Identity, tools []inspect.Tool, stored pins.ServerPins) {
	snap, pinErr := pinnable(id, tools)
	if pinErr != nil && pins.ReasonOf(pinErr) == "" {
		p.addUnverified(s, pinnableReason(pinErr), riskPinnedNotPinnable, fixNotPinnable, pins.UnverifiedSeverity(true))
	}
	h := acceptHint{name: s.Name, id: id}
	kept := false // true when at least one row of this server is not ignored
	for _, ch := range pins.Compare(stored, tools) {
		row := pinRow(ch.Kind, s, ch.Tool, ch.Severity)
		if ch.Kind == pins.KindUnverified {
			// ch.Reason is a fixed text from internal/pins.
			row.Related = ch.Reason
		}
		if pinErr != nil {
			row.Remediation = fixNotPinnable
		}
		if !p.add(row) {
			h.ignored = true
			continue
		}
		kept = true
		h.truncated = h.truncated || ch.Truncated
		h.noText = h.noText || ch.DiffIsNote()
		p.res.diffs = p.c.appendDiff("scan", p.res.diffs, s.Name, ch)
	}
	if kept && pinErr == nil {
		h.digest = pins.Digest(snap)
		p.res.hints = append(p.res.hints, h)
	}
}

// Fixed reasons for a MOAT-T2-004 row that scan makes itself. They hold no
// server text and no error text.
const (
	// reasonListedTwice is the reason for a second server with the same identity.
	reasonListedTwice = "the server is listed twice"
	// reasonNotInspected is the reason for a server that is in the pins store
	// but that scan could not inspect (it failed, timed out or was refused).
	reasonNotInspected = "pinned server could not be inspected"
	// reasonNotPinnable is the reason when the tools cannot be pinned and no
	// more exact pins reason fits.
	reasonNotPinnable = "the tools cannot be pinned"
	// reasonRelativeSource is the reason for a server whose config path is not
	// absolute.
	reasonRelativeSource = "the config path is not absolute"
)

// reasonStoreFull is the reason for a first-run server whose pins would make
// pins.json larger than its size limit (pins.ErrStoreFull, see firstPin).
// riskServerUnverified tells what the missing pins mean. The terminal report
// cuts a reason at 80 runes (report.MaxShortCellRunes), so it must stay
// shorter. It starts with pinsFullText, so the size is written in one place.
// pinsFullText is a var, so this is a var too.
var reasonStoreFull = pinsFullText + ", so this server is not pinned"

// Fixed risks for the MOAT-T2-004 rows that scan makes itself (see
// addUnverified). They hold no server text.
const (
	// riskServerUnverified is the risk when scan did not check the tools of
	// the server against pins: a server listed twice, a relative config path,
	// a pinned server that was not inspected, or a first run that cannot pin
	// (the tools are not valid, or pins.json is full).
	riskServerUnverified = "mcpmoat cannot check the tools of this server against pins, so a changed or hostile tool could pass without a review."
	// riskPinnedNotPinnable is the risk when scan compared the tools of a
	// pinned server, but the current tools cannot be pinned (see compare).
	riskPinnedNotPinnable = "The current tools of this pinned server cannot be pinned, so no change of them can be accepted, and the pins stay on an older version of the server."
)

// Fixed remediations for the MOAT-T2-004 rows that scan makes itself, one for
// each reason above (a reason from pinnableReason uses fixNotPinnable). They
// are not the text of pins.KindUnverified: scan prints no "To accept" line for
// these rows, and pin --accept would refuse them. Each is one plain sentence
// with no server text.
const (
	fixListedTwice    = "Remove the duplicate entry of this server from the config file, then run mcpmoat scan again."
	fixNotInspected   = "Find out why the server could not be inspected (see its status in the summary), fix it, then run mcpmoat scan again."
	fixNotPinnable    = "Do not use this server until its tools are valid, have unique names and fit the size limit of pins.json, then run mcpmoat scan again."
	fixRelativeSource = "Run mcpmoat scan again with an absolute --config path, or from a working directory that mcpmoat can read."
	fixStoreFull      = "Remove servers you no longer use from pins.json, or remove this server from the client config, then run mcpmoat scan again."
)

// pinRow returns the report row of one pin change on the server s. The caller
// gives the severity: findingRule would answer "critical" for these rule
// IDs, because the rule set has no rule for them. The risk and the remediation
// are the fixed texts of the change kind (see pins.ChangeKind). The pin rules
// have no title, so the row has an empty Title and the report leaves the
// title out of the finding line.
func pinRow(kind pins.ChangeKind, s discover.Server, tool, severity string) report.FindingRow {
	return report.FindingRow{
		ServerRef:   report.NewServerRef(s),
		RuleID:      kind.RuleID(),
		Severity:    severity,
		Risk:        kind.Risk(),
		Remediation: kind.Remediation(),
		Field:       rules.FieldTool,
		Key:         tool,
	}
}

// outcomeSummary returns the summary entry of one outcome. findings is the
// number of pin findings that the outcome got.
//
//   - A server that inspect started and read gives "ok" and its tool count.
//   - A timeout gives "timeout", and any other failure gives "failed". The
//     reason is the raw error text: the report escapes and cuts it.
//   - A server that a gate refused (the client config turns it off, or it is
//     untrusted) was not started, so it gives "not inspected".
//
// The warnings of the inspection come from outcomeWarnings.
func outcomeSummary(o inspect.Outcome, findings int) report.ServerStatus {
	status := report.ServerStatus{
		ServerRef: report.NewServerRef(o.Server),
		Findings:  findings,
		Warnings:  outcomeWarnings(o),
	}
	if o.Status == inspect.StatusOK {
		status.Status = report.StatusOK
		status.Tools = len(o.Result.Tools)
		return status
	}
	switch {
	case inspect.Refused(o.Err):
		status.Status = report.StatusNotInspected
	case o.Status == inspect.StatusTimeout:
		status.Status = report.StatusTimeout
	default:
		status.Status = report.StatusFailed
	}
	status.Reason = outcomeReason(o)
	return status
}

// serverStatuses returns the summary of all servers, in the order of servers
// (the config order), so it lines up with the server table. configFindings
// holds the number of config findings of each server, by index in servers
// (configChecks.findings gives one entry for each server).
//
// servers must be the slice that scan gave to inspect.Run. An outcome belongs
// to the server at its Index (see inspect.Outcome.Index). The outcomes come
// sorted, so their position does not tell which server they are for, and the
// data of a server does not either: two servers can be equal in every field.
// A server with no outcome (scan inspected nothing, for example with
// --no-connect) is "not inspected" and has only its config findings.
func (r pinReport) serverStatuses(servers []discover.Server, configFindings []int) []report.ServerStatus {
	if len(servers) == 0 {
		return nil
	}
	// One slot for each server. A slot stays "not inspected" until an outcome
	// with its index fills it.
	out := make([]report.ServerStatus, len(servers))
	for i, s := range servers {
		out[i] = report.ServerStatus{
			ServerRef: report.NewServerRef(s),
			Status:    report.StatusNotInspected,
		}
	}
	// An index outside servers, or a configFindings of another length, cannot
	// happen when the caller passes the slices of one scan. Use only what fits
	// rather than panic.
	for _, entry := range r.statuses {
		if entry.index >= 0 && entry.index < len(out) {
			out[entry.index] = entry.status
		}
	}
	for i, n := range configFindings {
		if i < len(out) {
			out[i].Findings += n
		}
	}
	return out
}

// printPinned writes the line "pinned N tools for <server>" on stderr for
// each server in the list. scan calls it only after the store is saved, so
// the line never says "pinned" for a pin that was lost. The server name comes
// from a config file, so it is escaped and cut.
func (c *cli) printPinned(servers []pinnedServer) {
	for _, p := range servers {
		c.cmdPrintf("scan", "pinned %d %s for %s", p.tools, plural(p.tools, "tool", "tools"), cutName(p.name))
	}
}
