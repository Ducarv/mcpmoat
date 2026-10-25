package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// maxWarnNameRunes and maxWarnErrRunes cap the untrusted text that a stderr
// line shows: a server name from a config file and the error text of an
// inspection, which can carry server output. A cut ends with
// termsafe.CutMarker, so a cut is never silent.
const (
	maxWarnNameRunes = 100
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
	// pinned lists the servers that this run pinned for the first time, in
	// the order of the servers. scan prints one notice for each of them, but
	// only after save worked (see printPinned).
	pinned []pinnedServer
	// hints lists the pinned servers that have at least one pin finding that
	// the ignore list does not drop, in the order of the servers. Each one
	// holds the digest of the tools that scan saw, for the line "To accept ...
	// --expect <digest>" (see writeAcceptHints). A server whose tools
	// pins.Snapshot refuses has no hint: those tools cannot be accepted.
	hints []acceptHint

	store *pins.Store
	dirty bool
}

// pinnedServer is one server that scan pinned for the first time.
type pinnedServer struct {
	name  string // the server name from the config file: untrusted
	tools int
}

// acceptHint is the digest of the tools that scan saw on one changed server.
type acceptHint struct {
	name   string // the server name from the config file: untrusted
	digest string // pins.Digest of the tools; our own hex, safe to print
}

// writeAcceptHints writes one line on w for each hint:
//
//	To accept <server>: mcpmoat pin --accept <server> --expect <digest>
//
// The user reviews the diff of scan, then runs the line. "pin --accept" saves
// the tools only when they have the same digest, so a server cannot show good
// tools to scan and bad tools to pin (a time-of-check to time-of-use attack).
// The server name comes from a config file. Before the colon it is escaped and
// cut for the terminal. In the command it is quoted for the shell (see
// shellArg), and when no safe quoting exists the line has no command. The
// digest is made by mcpmoat from hex, so it needs no escape. writeAcceptHints
// returns the first write error: the caller must check it, like for the report.
func writeAcceptHints(w io.Writer, hints []acceptHint) error {
	for _, h := range hints {
		label := termsafe.QuoteCut(h.name, maxWarnNameRunes)
		var err error
		if arg, ok := shellArg(h.name); ok {
			_, err = fmt.Fprintf(w, "To accept %s: mcpmoat pin --accept %s --expect %s\n", label, arg, h.digest)
		} else {
			_, err = fmt.Fprintf(w, "To accept %s: run pin --accept with this server name and --expect %s\n", label, h.digest)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// shellArg returns name as one argument that is safe to paste in a POSIX shell,
// and true. It returns false when no safe form exists: the name is over
// maxWarnNameRunes, or it has a rune that termsafe would escape (a control
// character, a bidi or invisible rune, invalid UTF-8), so the user could not
// see what they paste. A name that starts with a dash has no safe form either:
// even in quotes, pin would read it as a flag.
//
// A name of plain ASCII characters stays bare. Any other safe name goes in
// single quotes, where the shell reads every character as text. Each single
// quote in the name closes the quotes, adds an escaped quote and opens the
// quotes again (the four characters quote, backslash, quote, quote). This is
// POSIX-shell quoting: cmd.exe does not read single quotes, and PowerShell
// escapes a single quote by doubling it, so on Windows the user may need to
// adapt the line.
func shellArg(name string) (string, bool) {
	if strings.HasPrefix(name, "-") ||
		utf8.RuneCountInString(name) > maxWarnNameRunes || termsafe.Quote(name) != name {
		return "", false
	}
	if isBareShellWord(name) {
		return name, true
	}
	return "'" + strings.ReplaceAll(name, "'", `'\''`) + "'", true
}

// isBareShellWord reports whether name is not empty, does not start with a
// dash, and holds only the ASCII characters [A-Za-z0-9._@/:+=-], which no
// shell treats as special.
func isBareShellWord(name string) bool {
	if name == "" || name[0] == '-' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("._@/:+=-", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// save writes the store when the pin step pinned a server for the first time.
// It writes nothing when no server was pinned, so a scan of pinned servers
// never writes pins.json (only "pin --accept" re-pins). The caller must call
// save after it printed the report.
func (p pinReport) save() error {
	if p.store == nil || !p.dirty {
		return nil
	}
	return p.store.Save()
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

// loadPins reads the pins store, from pins.DefaultPath with the getenv and
// homeDir of the cli. An error from the path or from pins.Load (a corrupt
// file, an unsupported version) is returned. scan never replaces a bad store
// with an empty one. scan calls loadPins before it starts any server, so a bad
// file stops the scan before a stdio server runs (exit code 2).
func (c *cli) loadPins() (*pins.Store, error) {
	path, err := pins.DefaultPath(c.getenv, c.homeDir)
	if err != nil {
		return nil, err
	}
	return pins.Load(path)
}

// pinOutcomes checks the tools of the servers that were inspected against
// the pins store (FR-11 and FR-12). It gets the store from loadPins, which
// scan calls before the servers are inspected. It does not save the store: call
// save on the result after the report is printed.
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
		res:     pinReport{store: store},
		handled: make(map[pins.Identity]bool),
		warned:  make(map[string]bool),
	}
	for _, o := range outcomes {
		p.outcome(o)
	}
	return p.res
}

// pinner holds the state of one pinOutcomes call.
type pinner struct {
	c     *cli
	ign   *scanIgnores
	store *pins.Store
	res   pinReport
	// handled holds the servers that this run already checked or pinned. Two
	// servers with one identity should not happen, but if they do, the second
	// must not be compared with the pins of the first.
	handled map[pins.Identity]bool
	// warned holds the rule IDs for which the user already got the warning
	// that .mcpmoat-ignore cannot ignore them.
	warned map[string]bool
}

// outcome checks one outcome. A server that was not inspected is a warning
// only (see notInspected). For a server that was inspected:
//   - one that is not in the store is pinned (see firstPin);
//   - one that is in the store is compared with its pins (see compare);
//   - a second server with the same identity is a MOAT-T2-004 finding, so that
//     its tools are not skipped.
func (p *pinner) outcome(o inspect.Outcome) {
	s := o.Server
	id := serverIdentity(s)
	if o.Status != inspect.StatusOK {
		p.notInspected(s, id)
		return
	}
	if p.handled[id] {
		p.unverified(s.Name, reasonListedTwice)
		return
	}
	p.handled[id] = true

	tools := o.Result.Tools
	if stored, found := p.store.Get(id); found {
		p.compare(s, tools, stored)
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
		if p.res.ignored == nil {
			p.res.ignored = make(map[string]int)
		}
		p.res.ignored[row.RuleID]++
		return false
	}
	p.res.rows = append(p.res.rows, row)
	return true
}

// unverified adds the MOAT-T2-004 row of a server that scan cannot verify.
// reason must be a fixed text: it is shown in the report.
func (p *pinner) unverified(name, reason string) {
	row := pinRow(pins.KindUnverified, name, "", pins.KindUnverified.Severity())
	row.Related = reason
	p.add(row)
}

// notInspected handles a server that failed, timed out or was refused. The
// warning on stderr is already written (see warnNotInspected). A server that
// was pinned before this run also gets a MOAT-T2-004 finding with the fixed
// reason reasonNotInspected: its pinned tools could not be checked, so a
// hostile server must not be able to avoid the rug-pull check by failing on
// purpose. A server that is not in the store is only a warning (FR-06). A
// server that this run already handled gets no row: it was not pinned before.
func (p *pinner) notInspected(s discover.Server, id pins.Identity) {
	if _, pinned := p.store.Get(id); pinned && !p.handled[id] {
		p.unverified(s.Name, reasonNotInspected)
	}
}

// firstPin pins the tools of a server that is not in the store yet. The result
// records it, and scan prints "pinned N tools for <server>" on stderr only after
// the store is saved (see printPinned). When pins.Snapshot or Store.Set refuses
// the tools, nothing is stored and the server gets a MOAT-T2-004 finding (not
// verified): a server that cannot be pinned must never pass in silence.
func (p *pinner) firstPin(s discover.Server, id pins.Identity, tools []inspect.Tool) {
	snap, err := pins.Snapshot(tools)
	if err == nil {
		err = p.store.Set(id, snap)
	}
	if err != nil {
		// The error text is not printed: it can name a tool. The row gets a
		// fixed reason instead.
		p.unverified(s.Name, snapshotReason(err))
		return
	}
	p.res.dirty = true
	p.res.pinned = append(p.res.pinned, pinnedServer{name: s.Name, tools: len(tools)})
}

// compare compares the tools of a pinned server with its pins (pins.Compare).
// Each change is one finding row. The rule ID comes from the change kind and
// the severity from Change.Severity (a pinned name that cannot be verified is
// high), not from the rule set, which does not hold the pin rules. A changed
// or new tool also gets a diff. The store is never changed. When at least one
// row is kept (not ignored), compare also records the digest for the
// "--expect" hint (see hint).
func (p *pinner) compare(s discover.Server, tools []inspect.Tool, stored pins.ServerPins) {
	kept := false // true when at least one row of this server is not ignored
	for _, ch := range pins.Compare(stored, tools) {
		row := pinRow(ch.Kind, s.Name, ch.Tool, ch.Severity)
		if ch.Kind == pins.KindUnverified {
			// ch.Reason is a fixed text from internal/pins.
			row.Related = ch.Reason
		}
		if !p.add(row) {
			continue
		}
		kept = true
		p.res.diffs = p.c.appendDiff("scan", p.res.diffs, s.Name, ch)
	}
	if kept {
		p.hint(s.Name, tools)
	}
}

// hint records the pins.Digest of the tools that scan saw, so scan can print
// the "--expect" line (see writeAcceptHints). The error text is not printed.
// Tools that cannot be pinned cannot be accepted either, so there is no hint
// for them.
func (p *pinner) hint(server string, tools []inspect.Tool) {
	if snap, err := pins.Snapshot(tools); err == nil {
		p.res.hints = append(p.res.hints, acceptHint{name: server, digest: pins.Digest(snap)})
	}
}

// diffOf returns the diff of one change for the report. The change must have a
// diff (see hasDiff). server is the name that the report shows.
func diffOf(server string, ch pins.Change) report.ToolDiff {
	return report.ToolDiff{Server: server, Tool: ch.Tool, Diff: ch.Diff, New: ch.Kind == pins.KindNew}
}

// hasDiff reports whether the change is one that has a diff: a changed tool or
// a new tool. The user must see the content of a new tool before they accept it.
func hasDiff(ch pins.Change) bool {
	return ch.Kind == pins.KindChanged || ch.Kind == pins.KindNew
}

// appendDiff adds the diff of ch to diffs and returns the result. A change
// without a diff adds nothing. When the diff was cut at the size limit, it
// prints one warning on stderr for the command cmd ("scan" or "pin"), because
// the user would review only a part of the tool.
func (c *cli) appendDiff(cmd string, diffs []report.ToolDiff, server string, ch pins.Change) []report.ToolDiff {
	if !hasDiff(ch) {
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

// snapshotReason maps an error of pins.Snapshot or Store.Set to a fixed reason
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
		fprintf(c.stderr, "mcpmoat scan: pinned %d %s for %s\n", p.tools, noun, termsafe.QuoteCut(p.name, maxWarnNameRunes))
	}
}

// warnNotInspected writes one line on stderr for each outcome that is not
// inspect.StatusOK, for example
// "mcpmoat scan: warning: server foo: timeout: inspect: no answer within 10s".
// A server that was not inspected is a warning, not a finding and not exit
// code 2 (FR-06, FR-16).
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

// mergeIgnored adds the counts of extra to dst and returns dst. It makes a new
// map when dst is nil and extra is not.
func mergeIgnored(dst, extra map[string]int) map[string]int {
	for id, n := range extra {
		if dst == nil {
			dst = make(map[string]int)
		}
		dst[id] += n
	}
	return dst
}

// scanStoreErrorf writes one pin store error on stderr. The error text can hold
// the path of pins.json, which comes from the environment, so it is escaped.
func (c *cli) scanStoreErrorf(what string, err error) {
	c.cmdErrorf("scan", "%s: %s", what, termsafe.Quote(err.Error()))
}
