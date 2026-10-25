package main

import (
	"path/filepath"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// This file holds the connect step of scan after inspect.Run: the inspection
// status of each server for the --json report, the pinner, which checks the
// tools of each inspected server against pins.json, and the ignore lists of
// the pin rules.

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
	// in the order of the servers. savePinned writes them (see there), and scan
	// prints one notice for each server that it saved (see printPinned).
	pinned []pinnedServer
	// hints lists the pinned servers that have at least one pin finding that
	// the ignore list does not drop, in the order of the servers. Each one
	// holds the digest of the tools that scan saw, for the line "To accept ...
	// --expect <digest>" (see writeAcceptHints). A server whose tools cannot be
	// pinned has no hint: pin --accept would refuse those tools (see addHint).
	hints []acceptHint
	// inspection holds the inspection status of each server that scan
	// inspected, as one of the report.InspectionStatus constants. It is keyed by
	// serverIdentity, because inspect.Run sorts the servers, so the outcomes
	// are not in the order of the server table. A server that is not in the
	// map was not inspected: the --json report shows it as not run (see
	// inspectionOf). It is nil when scan inspected nothing.
	inspection map[pins.Identity]report.InspectionStatus
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
		res:     pinReport{inspection: make(map[pins.Identity]report.InspectionStatus, len(outcomes))},
	}
	servers := make([]discover.Server, len(outcomes))
	for i, o := range outcomes {
		p.recordInspection(o)
		p.checkOutcome(o)
		servers[i] = o.Server
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

// checkOutcome checks one outcome. A server that was not inspected is a
// warning, and also a high MOAT-T2-004 finding when it is pinned and failed or
// timed out (see notInspected). For a server that was inspected:
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
		p.notInspected(s.Name, id, o.Err)
		return
	}
	if p.handled[id] {
		p.addUnverified(s.Name, reasonListedTwice, p.unverifiedSeverity(id))
		return
	}
	p.handled[id] = true
	if !filepath.IsAbs(s.Source) {
		p.addUnverified(s.Name, reasonRelativeSource, pins.UnverifiedSeverity(true))
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
	key := rules.FindingKey{RuleID: row.RuleID, Server: row.Server, Tool: row.Key}
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
// with the given severity. reason must be a fixed text: it is shown in the
// report.
func (p *pinner) addUnverified(name, reason, severity string) {
	row := pinRow(pins.KindUnverified, name, "", severity)
	row.Related = reason
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
// warning on stderr is already written (see warnNotInspected). A server that
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
func (p *pinner) notInspected(name string, id pins.Identity, err error) {
	if inspect.Refused(err) {
		return
	}
	if _, pinned := p.store.Get(id); pinned && !p.handled[id] && !p.failed[id] {
		p.addUnverified(name, reasonNotInspected, pins.UnverifiedSeverity(true))
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
		p.addUnverified(s.Name, pinnableReason(err), pins.UnverifiedSeverity(true))
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
		row := pinRow(ch.Kind, s.Name, ch.Tool, ch.Severity)
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

// pinRow returns the report row of one pin change. The caller gives the
// severity: findingSeverity would answer "critical" for these rule IDs,
// because the rule set has no rule for them.
func pinRow(kind pins.ChangeKind, server, tool, severity string) report.FindingRow {
	return report.FindingRow{
		RuleID:   kind.RuleID(),
		Severity: severity,
		Server:   server,
		Field:    rules.FieldTool,
		Key:      tool,
	}
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

// warnNotInspected writes one line on stderr for each outcome that is not
// inspect.StatusOK, for example
// "mcpmoat scan: warning: server foo: timeout: inspect: no answer within 10s".
// It writes the warning only, never exit code 2 (FR-06, FR-16). For a server
// that is pinned, pinOutcomes also adds a high MOAT-T2-004 finding (see
// notInspected). It also writes the inspection warnings of every outcome (see
// warnInspection).
func (c *cli) warnNotInspected(outcomes []inspect.Outcome) {
	for _, o := range outcomes {
		if o.Status != inspect.StatusOK {
			c.scanWarnf("%s", notInspectedText(o))
		}
		c.warnInspection("scan", o)
	}
}
