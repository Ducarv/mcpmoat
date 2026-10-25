package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// maxWarnNameRunes, maxWarnPathRunes and maxWarnErrRunes cap the untrusted text
// that a line on the terminal shows: a server name from a config file, a path
// (a config file or a project), and the error text of an inspection, which can
// carry server output. A cut ends with termsafe.CutMarker, so a cut is never
// silent.
const (
	maxWarnNameRunes = 100
	maxWarnPathRunes = 500
	maxWarnErrRunes  = 500
)

// serverIdentity returns the identity that names a server in the pins store.
// It holds the client, the config file, the project path and the server name
// only: no command, args, URL, env or headers (FR-11). pins does not import
// discover, so this mapping lives here.
func serverIdentity(s discover.Server) pins.Identity {
	return pins.Identity{
		Client:      string(s.Client),
		Source:      s.Source,
		ProjectPath: s.ProjectPath,
		Name:        s.Name,
	}
}

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
	// pinned has no hint: pin --accept would refuse those tools (see hint).
	hints []acceptHint
}

// pinnedServer is one server that scan pinned for the first time. It holds what
// savePinned needs to write the pins.
type pinnedServer struct {
	id    pins.Identity
	snap  pins.ServerPins // the pins of the tools that scan saw
	name  string          // the server name from the config file: untrusted
	tools int
}

// acceptHint is the digest of the tools that scan saw on one changed server.
type acceptHint struct {
	name   string // the server name from the config file: untrusted
	digest string // pins.Digest of the tools; our own hex, safe to print
	// truncated is true when at least one diff of the server, in the report, was
	// cut at the size limit: the user did not see the full tool.
	truncated bool
	// ignored is true when --ignore dropped at least one pin finding of the
	// server. The digest still covers that change, but the report shows no diff
	// for it.
	ignored bool
	// shared is true when another server that scan inspected has the same
	// name. pin refuses such a name without a --config that narrows it.
	shared bool
}

// The notes at the end of a "To accept" line. They are fixed text.
const (
	// hintCutNote ends the line of a server that has a cut diff.
	hintCutNote = " (the diff was cut: review the full tool first)"
	// hintIgnoredNote ends the line of a server with a pin finding that
	// --ignore dropped.
	hintIgnoredNote = " (--ignore hid some changes: run scan without it to review them first)"
)

// writeAcceptHints writes one line on w for each hint:
//
//	To accept <server>: mcpmoat pin --accept <server> --expect <digest>
//
// The user reviews the diff of scan, then runs the line. "pin --accept" saves
// the tools only when they have the same digest, so a server cannot show good
// tools to scan and bad tools to pin (a time-of-check to time-of-use attack).
// configPath is the --config of the scan, or empty. pin must read the same
// file, so the command holds "--config <configPath>" too. configProblem is true
// when a config file of the scan has a problem: pin then refuses to run.
//
// The line holds a command only when pin can run it as printed and the user saw
// every change (see acceptCommand). Else it says what to run and gives the
// digest, so the user must type the command: when a diff was cut, when another
// server has the same name, when a config file has a problem, or when the name
// or configPath is not a bare shell word. Before the colon the name is escaped
// and cut for the terminal. The digest is made by mcpmoat from hex, so it needs
// no escape. The line ends with hintCutNote when a diff of the server was cut,
// and with hintIgnoredNote when --ignore dropped a change. writeAcceptHints
// returns the first write error: the caller must check it, like for the report.
func writeAcceptHints(w io.Writer, hints []acceptHint, configPath string, configProblem bool) error {
	for _, h := range hints {
		text, ok := acceptCommand(h.name, configPath, h.digest)
		if !ok || h.truncated || h.shared || configProblem {
			text = acceptSteps(configPath, h.shared || configProblem, h.digest)
		}
		line := "To accept " + cutName(h.name) + ": " + text
		if h.truncated {
			line += hintCutNote
		}
		if h.ignored {
			line += hintIgnoredNote
		}
		if _, err := io.WriteString(w, line+"\n"); err != nil {
			return err
		}
	}
	return nil
}

// acceptCommand returns the command that accepts the tools with the digest, and
// true. It returns false when name or configPath (when not empty) is not a bare
// shell word (see isBareShellWord): quotes are not safe, because each shell
// (POSIX, PowerShell, cmd.exe) escapes them in its own way.
func acceptCommand(name, configPath, digest string) (string, bool) {
	if !isBareShellWord(name, maxWarnNameRunes) {
		return "", false
	}
	cmd := "mcpmoat pin --accept " + name
	if configPath != "" {
		if !isBareShellWord(configPath, maxWarnPathRunes) {
			return "", false
		}
		cmd += " --config " + configPath
	}
	return cmd + " --expect " + digest, true
}

// acceptSteps returns the text of a "To accept" line that has no command: what
// to run, and the digest. needConfig is true when pin needs a --config that
// names the config file of the server.
func acceptSteps(configPath string, needConfig bool, digest string) string {
	config := ""
	switch {
	case configPath != "":
		config = ", --config with the file of this scan,"
	case needConfig:
		config = ", --config with its config file,"
	}
	return "run pin --accept with this server name" + config + " and --expect " + digest
}

// isBareShellWord reports whether s is not empty, has at most maxBytes bytes,
// and holds only the ASCII characters [A-Za-z0-9._@/:+=-], so a byte is a rune.
// POSIX shells, PowerShell and cmd.exe read such a word as plain text when its
// first character is a letter, "_" or "/". Other first characters can be
// special: pin reads "-config" as a flag, zsh expands "=ls", PowerShell reads
// "@x" as a variable and "1kb" as a number.
func isBareShellWord(s string, maxBytes int) bool {
	if s == "" || len(s) > maxBytes {
		return false
	}
	switch c := s[0]; {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c == '/':
	default:
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("._@/:+=-", c) >= 0:
		default:
			return false
		}
	}
	return true
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
func (s *scanIgnores) ignored(k rules.FindingKey) (ignored, fileBlocked bool) {
	if !pins.IsPinRuleID(k.RuleID) {
		return s.all.Ignored(k), false
	}
	if s.flags.Ignored(k) {
		return true, false
	}
	return false, s.all.Ignored(k)
}

// readPins reads the pins store, from pins.DefaultPath with the getenv and
// homeDir of the cli. It returns false, after a message on stderr for the
// command cmd ("scan" or "pin"), when the path is not known or the file cannot
// be read (a corrupt file, an unsupported version). scan and pin never replace
// a bad store with an empty one. Both read the store before they start any
// server, so a bad file stops them before a stdio server runs (exit code 2).
func (c *cli) readPins(cmd string) (*pins.Store, bool) {
	path, err := pins.DefaultPath(c.getenv, c.homeDir)
	if err != nil {
		c.cmdErr(cmd, "cannot find the pins file", err)
		return nil, false
	}
	store, err := pins.Load(path)
	if err != nil {
		c.cmdErr(cmd, "cannot read the pins file", err)
		return nil, false
	}
	return store, true
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
	names := make(map[string]int, len(outcomes))
	for _, o := range outcomes {
		p.outcome(o)
		names[o.Server.Name]++
	}
	// pin finds its server by name among all the servers, also the ones that
	// were not inspected, so a name that two of them use needs --config.
	for i := range p.res.hints {
		p.res.hints[i].shared = names[p.res.hints[i].name] > 1
	}
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

// outcome checks one outcome. A server that was not inspected is a warning,
// and also a high MOAT-T2-004 finding when it is pinned (see notInspected). For
// a server that was inspected:
//   - one that is not in the store is pinned (see firstPin);
//   - one that is in the store is compared with its pins (see compare);
//   - a second server with the same identity is a MOAT-T2-004 finding, so that
//     its tools are not skipped. It is "high" when the identity is in the
//     store, and "medium" when it is not.
func (p *pinner) outcome(o inspect.Outcome) {
	s := o.Server
	id := serverIdentity(s)
	if o.Status != inspect.StatusOK {
		p.notInspected(s, id)
		return
	}
	if p.handled[id] {
		p.unverified(s.Name, reasonListedTwice, p.unverifiedSeverity(id))
		return
	}
	p.handled[id] = true

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

// unverified adds the MOAT-T2-004 row of a server that scan cannot verify, with
// the given severity. reason must be a fixed text: it is shown in the report.
func (p *pinner) unverified(name, reason, severity string) {
	row := pinRow(pins.KindUnverified, name, "", severity)
	row.Related = reason
	p.add(row)
}

// unverifiedSeverity returns the severity of a MOAT-T2-004 row about the server
// id: "high" when the store holds pins for it, because a pinned server that scan
// cannot check can hide a rug pull, and "medium" when it is not pinned.
func (p *pinner) unverifiedSeverity(id pins.Identity) string {
	if _, pinned := p.store.Get(id); pinned {
		return string(rules.SeverityHigh)
	}
	return pins.KindUnverified.Severity()
}

// notInspected handles a server that failed, timed out or was refused. The
// warning on stderr is already written (see warnNotInspected). A server that
// was pinned before this run also gets a MOAT-T2-004 finding with severity high
// and the fixed reason reasonNotInspected, so scan exits with 1: its pinned
// tools could not be checked, and a hostile server must not be able to avoid the
// rug-pull check by failing on purpose. A server that is not in the store is
// only a warning (FR-06). A server that this run already inspected gets no row:
// the first outcome checked its tools. A second failing outcome with one
// identity gives no second row (see failed).
func (p *pinner) notInspected(s discover.Server, id pins.Identity) {
	if _, pinned := p.store.Get(id); pinned && !p.handled[id] && !p.failed[id] {
		p.unverified(s.Name, reasonNotInspected, string(rules.SeverityHigh))
		p.failed[id] = true
	}
}

// firstPin records the tools of a server that is not in the store yet, so that
// savePinned can pin them. The store is not changed here. scan prints "pinned N
// tools for <server>" on stderr only after savePinned saved the server (see
// printPinned). When the tools cannot be pinned (see pinnable), nothing is
// recorded and the server gets a MOAT-T2-004 finding (not verified, medium: the
// server was never pinned): a server that cannot be pinned must never pass in
// silence.
func (p *pinner) firstPin(s discover.Server, id pins.Identity, tools []inspect.Tool) {
	snap, err := pinnable(id, tools)
	if err != nil {
		// The error text is not printed: it can name a tool. The row gets a
		// fixed reason instead.
		p.unverified(s.Name, snapshotReason(err), pins.KindUnverified.Severity())
		return
	}
	p.res.pinned = append(p.res.pinned, pinnedServer{id: id, snap: snap, name: s.Name, tools: len(tools)})
}

// compare compares the tools of a pinned server with its pins (pins.Compare).
// Each change is one finding row. The rule ID comes from the change kind and
// the severity from Change.Severity (a pinned name that cannot be verified is
// high), not from the rule set, which does not hold the pin rules. A changed
// or new tool, and a pinned tool whose pin cannot be checked, also gets a diff
// (see appendDiff). The store is never changed. When at least one row is kept (not
// ignored), compare also records the digest for the "--expect" hint (see
// hint). The hint says so when a kept diff was cut, or when the ignore list
// dropped a row: the digest covers that change, but the report shows no diff
// for it.
func (p *pinner) compare(s discover.Server, id pins.Identity, tools []inspect.Tool, stored pins.ServerPins) {
	h := acceptHint{name: s.Name}
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
		p.res.diffs = p.c.appendDiff("scan", p.res.diffs, s.Name, ch)
	}
	if kept {
		p.hint(h, id, tools)
	}
}

// hint records h with the pins.Digest of the tools that scan saw, so scan can
// print the "--expect" line (see writeAcceptHints). Tools that cannot be pinned
// (see pinnable) cannot be accepted either, so there is no hint for them. The
// error text is not printed.
func (p *pinner) hint(h acceptHint, id pins.Identity, tools []inspect.Tool) {
	if snap, err := pinnable(id, tools); err == nil {
		h.digest = pins.Digest(snap)
		p.res.hints = append(p.res.hints, h)
	}
}

// pinnable returns the pins of the tools of the server id. It returns an error
// when pins.Snapshot refuses the tools, or when the pins break a rule of the
// store file (pins.ValidateServer), so Store.Set would refuse them too. The
// error text can name a tool: do not print it.
func pinnable(id pins.Identity, tools []inspect.Tool) (pins.ServerPins, error) {
	snap, err := pins.Snapshot(tools)
	if err != nil {
		return nil, err
	}
	if err := pins.ValidateServer(id, snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// diffOf returns the diff of one change for the report. The change must have a
// diff (see appendDiff). server is the name that the report shows.
func diffOf(server string, ch pins.Change) report.ToolDiff {
	d := report.ToolDiff{Server: server, Tool: ch.Tool, Diff: ch.Diff}
	switch ch.Kind {
	case pins.KindNew:
		d.Kind = report.DiffNew
	case pins.KindUnverified:
		d.Kind = report.DiffUnverified
	}
	return d
}

// appendDiff adds the diff of ch to diffs and returns the result. A changed
// tool, a new tool and a pinned tool whose pin cannot be checked have a diff
// (see pins.Change.Diff): the user must see the content of a tool before they
// accept it. A change without a diff adds nothing. When the diff was cut at the size limit, it
// prints one warning on stderr for the command cmd ("scan" or "pin"), because
// the user would review only a part of the tool.
func (c *cli) appendDiff(cmd string, diffs []report.ToolDiff, server string, ch pins.Change) []report.ToolDiff {
	if ch.Diff == "" {
		return diffs
	}
	if ch.Truncated {
		c.warnf(cmd, "the diff of tool %s on server %s was cut at the size limit; review the full tool before you accept it",
			cutName(ch.Tool), cutName(server))
	}
	return append(diffs, diffOf(server, ch))
}

// cutName returns an untrusted name (a server or a tool) escaped and cut for a
// line on stderr.
func cutName(name string) string {
	return termsafe.QuoteCut(name, maxWarnNameRunes)
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
)

// snapshotReason maps an error of pinnable to a fixed reason
// text. It never returns the error text, which can name a tool.
func snapshotReason(err error) string {
	switch {
	case errors.Is(err, pins.ErrDuplicateTool):
		return pins.ReasonDuplicateName
	case errors.Is(err, pins.ErrInvalidTool):
		return pins.ReasonInvalidTool
	}
	return reasonNotPinnable
}

// pinRow returns the report row of one pin change. The caller gives the
// severity: findingSeverity would answer "critical" for these rule IDs,
// because the rule set has no rule for them.
func pinRow(kind pins.ChangeKind, server, tool, severity string) report.FindingRow {
	return report.FindingRow{
		RuleID:   kind.RuleID(),
		Severity: severity,
		Server:   server,
		Field:    "tool",
		Key:      tool,
	}
}

// printPinned writes the line "pinned N tools for <server>" on stderr for
// each server in the list. scan calls it only after the store is saved, so
// the line never says "pinned" for a pin that was lost. The server name comes
// from a config file, so it is escaped and cut.
func (c *cli) printPinned(servers []pinnedServer) {
	for _, p := range servers {
		noun := "tools"
		if p.tools == 1 {
			noun = "tool"
		}
		c.cmdErrorf("scan", "pinned %d %s for %s", p.tools, noun, cutName(p.name))
	}
}

// warnNotInspected writes one line on stderr for each outcome that is not
// inspect.StatusOK, for example
// "mcpmoat scan: warning: server foo: timeout: inspect: no answer within 10s".
// It writes the warning only, never exit code 2 (FR-06, FR-16). For a server
// that is pinned, pinOutcomes also adds a high MOAT-T2-004 finding (see
// notInspected).
func (c *cli) warnNotInspected(outcomes []inspect.Outcome) {
	for _, o := range outcomes {
		if o.Status != inspect.StatusOK {
			c.scanWarnf("%s", notInspectedText(o))
		}
	}
}

// notInspectedText returns "server <name>: <status>: <reason>" for an outcome
// that is not inspect.StatusOK. scan shows it as a warning and pin as an error.
// The server name and the error text come from untrusted sources (the error can
// carry server output), so both are escaped and cut.
func notInspectedText(o inspect.Outcome) string {
	reason := "no error text"
	if o.Err != nil {
		reason = o.Err.Error()
	}
	return fmt.Sprintf("server %s: %s: %s",
		cutName(o.Server.Name),
		termsafe.Quote(string(o.Status)),
		termsafe.QuoteCut(reason, maxWarnErrRunes))
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
