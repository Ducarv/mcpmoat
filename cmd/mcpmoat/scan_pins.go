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
	// diffs are the diffs of the changed tools in rows. A change that the
	// ignore list drops has no diff.
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
// see what they paste.
//
// A name of plain ASCII characters stays bare. Any other safe name goes in
// single quotes, where the shell reads every character as text. Each single
// quote in the name closes the quotes, adds an escaped quote and opens the
// quotes again (the four characters quote, backslash, quote, quote). This is
// POSIX-shell quoting: cmd.exe does not read single quotes, and PowerShell
// escapes a single quote by doubling it, so on Windows the user may need to
// adapt the line.
func shellArg(name string) (string, bool) {
	if utf8.RuneCountInString(name) > maxWarnNameRunes || termsafe.Quote(name) != name {
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

// pinRulePrefix starts the ID of every pin rule (MOAT-T2-001 to MOAT-T2-004).
const pinRulePrefix = "MOAT-T2-"

// ignored reports whether the user asked to ignore the finding k. For a pin
// rule only the --ignore list counts. The second result is true when the
// .mcpmoat-ignore file has an entry that matches k but is not applied, so
// that the caller can warn about it.
func (s *scanIgnores) ignored(k rules.FindingKey) (ignored, fileBlocked bool) {
	if !strings.HasPrefix(k.RuleID, pinRulePrefix) {
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
// scan calls before the servers are inspected.
//
// For each outcome with inspect.StatusOK:
//   - A server that is not in the store is pinned (first run). pinOutcomes
//     records it in the result. scan prints "pinned N tools for <server>" on
//     stderr only after the store is saved (see printPinned). When
//     pins.Snapshot or Store.Set refuses the tools, nothing is stored and the
//     server gets a MOAT-T2-004 finding (not verified): a server that cannot
//     be pinned must never pass in silence. A second server with the same
//     identity gets the same finding, so that its tools are not skipped.
//   - A server that is in the store is compared with pins.Compare. Each
//     change is one finding row. The rule ID comes from the change kind and
//     the severity from Change.Severity (a pinned name that cannot be
//     verified is high), not from the rule set, which does not hold the pin
//     rules. A changed tool also gets a diff. The store is never changed for
//     a pinned server. When at least one row of the server is kept (not
//     ignored), pinOutcomes also records the pins.Digest of the tools that scan
//     saw, so scan can print the "--expect" hint (see writeAcceptHints). No
//     hint is recorded when pins.Snapshot refuses the tools.
//
// For an outcome that is not OK (failed, timeout or refused):
//   - A server that is in the store gets a MOAT-T2-004 finding with severity
//     medium and the fixed reason reasonNotInspected. Its pinned tools could
//     not be checked, so a hostile server must not be able to avoid the
//     rug-pull check by failing on purpose. The warning on stderr stays.
//   - A server that is not in the store gets no finding: it is only a warning
//     (FR-06).
//
// The ignore list drops pin findings by rule ID, server name and tool name,
// but only with --ignore (see scanIgnores). A dropped finding is counted in
// the result, and its diff is not kept. A .mcpmoat-ignore entry that would
// drop a pin finding is not applied, and gives one warning for each rule ID.
//
// pinOutcomes does not save the store: call save on the result after the
// report is printed.
func (c *cli) pinOutcomes(store *pins.Store, outcomes []inspect.Outcome, ign *scanIgnores) pinReport {
	res := pinReport{store: store}
	// handled holds the servers that this run already checked or pinned. Two
	// servers with one identity should not happen, but if they do, the second
	// must not be compared with the pins of the first.
	handled := make(map[pins.Identity]bool)
	// warned holds the rule IDs for which the user already got the warning
	// that .mcpmoat-ignore cannot ignore them.
	warned := make(map[string]bool)

	// add keeps a row, or counts it when the ignore list drops it. It returns
	// false for a dropped row, so the caller keeps no diff for it.
	add := func(row report.FindingRow) bool {
		key := rules.FindingKey{RuleID: row.RuleID, Server: row.Server, Tool: row.Key}
		dropped, blocked := ign.ignored(key)
		if blocked && !warned[row.RuleID] {
			warned[row.RuleID] = true
			c.scanWarnf("%s cannot ignore %s; use --ignore on the command line",
				rules.IgnoreFileName, termsafe.Quote(row.RuleID))
		}
		if dropped {
			if res.ignored == nil {
				res.ignored = make(map[string]int)
			}
			res.ignored[row.RuleID]++
			return false
		}
		res.rows = append(res.rows, row)
		return true
	}
	// unverified adds the MOAT-T2-004 row of a server that scan cannot verify.
	// reason must be a fixed text: it is shown in the report.
	unverified := func(name, reason string) {
		row := pinRow(pins.KindUnverified, name, "", pins.KindUnverified.Severity())
		row.Related = reason
		add(row)
	}

	for _, o := range outcomes {
		s := o.Server
		id := serverIdentity(s)

		if o.Status != inspect.StatusOK {
			// The warning on stderr is already written (warnNotInspected).
			// A pinned server that cannot be inspected is also a finding.
			if _, pinned := store.Get(id); pinned {
				unverified(s.Name, reasonNotInspected)
			}
			continue
		}
		tools := o.Result.Tools

		if handled[id] {
			unverified(s.Name, reasonListedTwice)
			continue
		}
		handled[id] = true

		stored, found := store.Get(id)
		if !found {
			snap, err := pins.Snapshot(tools)
			if err == nil {
				err = store.Set(id, snap)
			}
			if err != nil {
				// The error text is not printed: it can name a tool. The
				// row gets a fixed reason instead.
				unverified(s.Name, snapshotReason(err))
				continue
			}
			res.dirty = true
			res.pinned = append(res.pinned, pinnedServer{name: s.Name, tools: len(tools)})
			continue
		}

		kept := false // true when at least one row of this server is not ignored
		for _, ch := range pins.Compare(stored, tools) {
			row := pinRow(ch.Kind, s.Name, ch.Tool, ch.Severity)
			if ch.Kind == pins.KindUnverified {
				// ch.Reason is a fixed text from internal/pins.
				row.Related = ch.Reason
			}
			if !add(row) {
				continue
			}
			kept = true
			if ch.Kind == pins.KindChanged {
				res.diffs = append(res.diffs, report.ToolDiff{Server: s.Name, Tool: ch.Tool, Diff: ch.Diff})
			}
		}
		if kept {
			// The error text is not printed. Tools that cannot be pinned
			// cannot be accepted either, so there is no hint for them.
			if snap, err := pins.Snapshot(tools); err == nil {
				res.hints = append(res.hints, acceptHint{name: s.Name, digest: pins.Digest(snap)})
			}
		}
	}
	return res
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
// The server name and the error text come from untrusted sources (the error
// can carry server output), so both are escaped and cut. A server that was
// not inspected is a warning, not a finding and not exit code 2 (FR-06, FR-16).
func (c *cli) warnNotInspected(outcomes []inspect.Outcome) {
	for _, o := range outcomes {
		if o.Status == inspect.StatusOK {
			continue
		}
		reason := "no error text"
		if o.Err != nil {
			reason = o.Err.Error()
		}
		c.scanWarnf("server %s: %s: %s",
			termsafe.QuoteCut(o.Server.Name, maxWarnNameRunes),
			termsafe.Quote(string(o.Status)),
			termsafe.QuoteCut(reason, maxWarnErrRunes))
	}
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

// pinErrorf writes one pin store error on stderr. The error text can hold the
// path of pins.json, which comes from the environment, so it is escaped.
func (c *cli) pinErrorf(what string, err error) {
	fprintf(c.stderr, "mcpmoat scan: %s: %s\n", what, termsafe.Quote(err.Error()))
}
