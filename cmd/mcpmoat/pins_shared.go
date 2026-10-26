package main

import (
	"errors"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// This file holds the helpers of the pin step that scan and pin both use: the
// server identity, the read of pins.json, the pinnable check, the diffs, the
// reason and the warnings of an outcome, and the caps of untrusted text on the
// terminal. The stderr texts that only pin prints are in pin.go.

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

// pinnable returns the pins of the tools of the server id. It returns an error
// when pins.Snapshot refuses the tools, or when the pins break a rule of the
// store file (pins.ValidateServer), so Store.Set would refuse them too. The
// errors hold no tool text, but callers print only pinnableReason, so that a
// later error cannot leak server text.
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
	d := report.ToolDiff{Server: server, Tool: ch.Tool, Diff: ch.Diff, Truncated: ch.Truncated, IsNote: ch.DiffIsNote()}
	switch ch.Kind {
	case pins.KindNew:
		d.Kind = report.DiffNew
	case pins.KindUnverified:
		d.Kind = report.DiffUnverified
	default:
		// KindChanged. A kind without a diff never gets here (see the doc).
		d.Kind = report.DiffChanged
	}
	return d
}

// appendDiff adds the diff of ch to diffs and returns the result. A changed
// tool, a new tool and a pinned tool whose pin cannot be checked have a diff
// (see pins.Change.Diff): the user must see the content of a tool before they
// accept it. A change without a diff adds nothing. When the diff was cut at
// the size limit, it prints one warning on stderr for the command cmd ("scan"
// or "pin"), because the user would review only a part of the tool.
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

// pinnableReason maps an error of pinnable to a fixed reason text, the same
// text that pins.Compare gives for the same tool on a pinned server. It never
// returns the error text: scan and pin print only fixed reasons, so a later
// error text cannot leak server text.
func pinnableReason(err error) string {
	if r := pins.ReasonOf(err); r != "" {
		return r
	}
	return reasonNotPinnable
}

// outcomeReason returns the raw text that says why o was not inspected: the
// error text, or "no error text" when there is none. The text is untrusted
// (see inspect.Outcome.Err). The caller must escape it before it prints it.
func outcomeReason(o inspect.Outcome) string {
	if o.Err != nil {
		return o.Err.Error()
	}
	return "no error text"
}

// outcomeWarnings returns the warnings of the inspection of o: Result.Warnings
// for a server that inspect read, and ConnectError.Warnings for a server that
// failed. A Warning holds keys and fixed names only, never values, URLs or
// server text (see inspect.Warning).
func outcomeWarnings(o inspect.Outcome) []inspect.Warning {
	if o.Status == inspect.StatusOK {
		return o.Result.Warnings
	}
	var ce *inspect.ConnectError
	if errors.As(o.Err, &ce) {
		return ce.Warnings
	}
	return nil
}
