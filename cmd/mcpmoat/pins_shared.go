package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// This file holds the helpers of the pin step that scan and pin both use: the
// server identity, the read of pins.json, the pinnable check, the diffs and the
// fixed texts for stderr.

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
	d := report.ToolDiff{Server: server, Tool: ch.Tool, Diff: ch.Diff}
	switch ch.Kind {
	case pins.KindChanged:
		d.Kind = report.DiffChanged
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
	switch {
	case errors.Is(err, pins.ErrDuplicateTool):
		return pins.ReasonDuplicateName
	case errors.Is(err, pins.ErrEmptyName):
		return pins.ReasonEmptyName
	case errors.Is(err, pins.ErrInvalidTool):
		return pins.ReasonInvalidTool
	}
	return reasonNotPinnable
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

// warnInspection writes the warnings of the inspection of o on stderr for the
// command cmd ("scan" or "pin"): one line for each inspect.Warning, also for a
// server that failed (ConnectError.Warnings). A Warning holds keys and fixed
// names only, never values, URLs or server text (see inspect.Warning).
func (c *cli) warnInspection(cmd string, o inspect.Outcome) {
	warnings := o.Result.Warnings
	var ce *inspect.ConnectError
	if o.Status != inspect.StatusOK && errors.As(o.Err, &ce) {
		warnings = ce.Warnings
	}
	for _, w := range warnings {
		c.warnf(cmd, "%s", warningText(o.Server.Name, w))
	}
}

// warningText returns "server <name>: <kind>: <what it means>" for one
// inspection warning. The server name and the header keys come from the config
// file, so they are escaped and cut.
func warningText(name string, w inspect.Warning) string {
	var detail string
	switch w.Kind {
	case inspect.WarnCleartextSecrets:
		var parts []string
		for _, k := range w.HeaderKeys {
			parts = append(parts, "header "+cutName(k))
		}
		if w.URLUserInfo {
			parts = append(parts, "the user info of the URL")
		}
		if w.URLSecrets {
			parts = append(parts, "secret parts of the URL")
		}
		detail = "secrets go over plain http to a host that is not loopback: " + strings.Join(parts, ", ")
	case inspect.WarnUndeclaredCapability:
		detail = "the server answered lists that it did not declare (it can show other lists to other clients): " +
			termsafe.Quote(strings.Join(w.Capabilities, ", "))
	case inspect.WarnDNSPinUnavailable:
		detail = "a proxy from the environment resolves the host, so the DNS pin and the address checks do not apply"
	default:
		detail = "unknown warning"
	}
	return fmt.Sprintf("server %s: %s: %s", cutName(name), termsafe.Quote(string(w.Kind)), detail)
}
