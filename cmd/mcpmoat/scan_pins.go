package main

import (
	"errors"
	"path/filepath"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// This file holds the pin step of scan: the pinner, which checks the tools of
// each inspected server against pins.json, and the ignore lists of the pin
// rules.

// pinReport is the result of the pin step: what scan adds to its report, and
// what it must still save.
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
	// in the order of the servers. savePinned writes them (see there), and scan
	// prints one notice for each server that it saved (see printPinned).
	pinned []pinnedServer
	// hints lists the pinned servers that have at least one pin finding that
	// the ignore list does not drop, in the order of the servers. Each one
	// holds the digest of the tools that scan saw, for the line "To accept ...
	// --expect <digest>" (see writeAcceptHints). A server whose tools cannot be
	// pinned has no hint: pin --accept would refuse those tools (see addHint).
	hints []acceptHint
	// statuses holds the inspection result of each outcome, in the order of
	// the outcomes (not of the config). serverStatuses puts them in the order
	// of the servers for the summary. It is nil when scan inspected nothing.
	statuses []outcomeStatus
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
// project could silence the rug-pull alarm for the user's own servers. So the
// file never ignores a pin rule. Only --ignore on the command line does,
// because the user typed it.
type scanIgnores struct {
	// all holds the entries of .mcpmoat-ignore and of --ignore. It drops
	// the findings of the config rules.
	all rules.IgnoreList
	// flags holds only the --ignore entries. It drops the pin findings.
	flags rules.IgnoreList
}

// ignored reports whether the user asked to ignore the finding k. For a pin
// rule only the --ignore list counts. The second result is true when the
// .mcpmoat-ignore file has an entry that matches k but is not applied, so
// that the caller can warn about it.
func (s *scanIgnores) ignored(k rules.FindingKey) (drop, fileBlocked bool) {
	if !pins.IsPinRuleID(k.RuleID) {
		return s.all.Ignored(k), false
	}
	if s.flags.Ignored(k) {
		return true, false
	}
	return false, s.all.Ignored(k)
}

// pinOutcomes checks the tools of the servers that were inspected against
// the pins store (FR-11 and FR-12). It gets the store from readPins, which
// scan calls before the servers are inspected. It only reads the store and
// writes nothing. The servers to pin for the first time are in the result:
// savePinned writes them after the report is printed.
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
		handled: make(map[pins.Identity]bool),
		failed:  make(map[pins.Identity]bool),
		warned:  make(map[string]bool),
	}
	servers := make([]discover.Server, len(outcomes))
	for i, o := range outcomes {
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
	res   pinReport
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
		p.addUnverified(s, reasonListedTwice, fixListedTwice, p.unverifiedSeverity(id))
		return
	}
	p.handled[id] = true
	if !filepath.IsAbs(s.Source) {
		p.addUnverified(s, reasonRelativeSource, fixRelativeSource, pins.UnverifiedSeverity(true))
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
		p.c.scanWarnf("%s cannot ignore %s; use --ignore on the command line",
			rules.IgnoreFileName, termsafe.Quote(row.RuleID))
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
// solve them (see the fix constants).
func (p *pinner) addUnverified(s discover.Server, reason, fix, severity string) {
	row := pinRow(pins.KindUnverified, s, "", severity)
	row.Related = reason
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
		p.addUnverified(s, reasonNotInspected, fixNotInspected, pins.UnverifiedSeverity(true))
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
func (p *pinner) firstPin(s discover.Server, id pins.Identity, tools []inspect.Tool) {
	snap, err := pinnable(id, tools)
	if err != nil {
		// The row gets the fixed reason, never the error text (see
		// pinnableReason).
		p.addUnverified(s, pinnableReason(err), fixNotPinnable, pins.UnverifiedSeverity(true))
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
// (not ignored), compare also records the digest for the "--expect" hint (see
// addHint). The hint says so when a kept diff was cut, or when the ignore list
// dropped a row: the digest covers that change, but the report shows no diff
// for it.
func (p *pinner) compare(s discover.Server, id pins.Identity, tools []inspect.Tool, stored pins.ServerPins) {
	h := acceptHint{name: s.Name, id: id}
	kept := false // true when at least one row of this server is not ignored
	for _, ch := range pins.Compare(stored, tools) {
		row := pinRow(ch.Kind, s, ch.Tool, ch.Severity)
		if ch.Kind == pins.KindUnverified {
			// ch.Reason is a fixed text from internal/pins.
			row.Related = ch.Reason
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
	if kept {
		p.addHint(h, tools)
	}
}

// addHint records h with the pins.Digest of the tools that scan saw, so scan
// can print the "--expect" line (see writeAcceptHints). Tools that cannot be
// pinned (see pinnable) cannot be accepted either, so there is no hint for
// them. The error text is not printed.
func (p *pinner) addHint(h acceptHint, tools []inspect.Tool) {
	if snap, err := pinnable(h.id, tools); err == nil {
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

// Fixed remediations for the MOAT-T2-004 rows that scan makes itself, one for
// each reason above (a reason from pinnableReason uses fixNotPinnable). They
// are not the text of pins.KindUnverified: scan prints no "To accept" line for
// these rows, and pin --accept would refuse them. Each is one plain sentence
// with no server text.
const (
	fixListedTwice    = "Remove the duplicate entry of this server from the config file, then run mcpmoat scan again."
	fixNotInspected   = "Find out why the server could not be inspected (see its status in the summary), fix it, then run mcpmoat scan again."
	fixNotPinnable    = "Do not use this server until its tools are valid and have unique names, then run mcpmoat scan again."
	fixRelativeSource = "Run mcpmoat scan again with an absolute --config path, or from a working directory that mcpmoat can read."
)

// pinRow returns the report row of one pin change on the server s. The caller
// gives the severity: findingSeverity would answer "critical" for these rule
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
// The warnings of the inspection come from Result.Warnings, or, for a server
// that failed, from ConnectError.Warnings. They hold keys and fixed names,
// never values.
func outcomeSummary(o inspect.Outcome, findings int) report.ServerStatus {
	st := report.ServerStatus{
		ServerRef: report.NewServerRef(o.Server),
		Findings:  findings,
	}
	if o.Status == inspect.StatusOK {
		st.Status = report.StatusOK
		st.Tools = len(o.Result.Tools)
		st.Warnings = o.Result.Warnings
		return st
	}
	switch {
	case inspect.Refused(o.Err):
		st.Status = report.StatusNotInspected
	case o.Status == inspect.StatusTimeout:
		st.Status = report.StatusTimeout
	default:
		st.Status = report.StatusFailed
	}
	st.Reason = outcomeReason(o)
	var ce *inspect.ConnectError
	if errors.As(o.Err, &ce) {
		st.Warnings = ce.Warnings
	}
	return st
}

// serverStatuses returns the summary of all servers, in the order of servers
// (the config order), so it lines up with the server table. configFindings
// holds the number of config findings of each server, by index in servers.
//
// servers must be the slice that scan gave to inspect.Run. An outcome belongs
// to the server at its Index (see inspect.Outcome.Index). The outcomes come
// sorted, so their position does not tell which server they are for, and the
// data of a server does not either: two servers can be equal in every field.
// A server with no outcome (scan inspected nothing, for example with
// --no-connect) is "not inspected" and has only its config findings.
func (pr pinReport) serverStatuses(servers []discover.Server, configFindings []int) []report.ServerStatus {
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
	for _, entry := range pr.statuses {
		// An index outside servers cannot happen when the caller passes the
		// slice that went to inspect.Run. Skip it rather than panic.
		if entry.index >= 0 && entry.index < len(out) {
			out[entry.index] = entry.status
		}
	}
	for i := range out {
		out[i].Findings += configFindings[i]
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
