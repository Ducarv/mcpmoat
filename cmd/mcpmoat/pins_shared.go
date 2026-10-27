package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

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
	path, ok := c.pinsPath(cmd)
	if !ok {
		return nil, false
	}
	store, err := pins.Load(path)
	if err != nil {
		c.cmdErr(cmd, "cannot read the pins file", err)
		return nil, false
	}
	return store, true
}

// pinsPath returns the path of pins.json, from pins.DefaultPath with the
// getenv and homeDir of the cli. It returns false, after a message on stderr
// for the command cmd, when the path is not known.
func (c *cli) pinsPath(cmd string) (string, bool) {
	path, err := pins.DefaultPath(c.getenv, c.homeDir)
	if err != nil {
		c.cmdErr(cmd, "cannot find the pins file", err)
		return "", false
	}
	return path, true
}

// readPinsLocked reads the pins store like readPins, but with the lock on the
// pins directory (pins.LoadLocked), for a run that changes and saves the pins.
// It waits up to c.pinsLockWait for another process that holds the lock. It
// returns the store and the release function of the lock. The path of
// pins.json (for printNewPinsFile) is store.Path().
//
// The caller must hold the lock through Save, so it defers release at once:
//
//	store, release, ok := c.readPinsLocked(ctx, "scan")
//	defer release()
//	if !ok { ... }
//
// release is never nil, also when ok is false (then it does nothing), so the
// defer is safe on every path. A second call does nothing, so the caller can
// also call release early: right after Save, or before an early return, and
// always before it prints, so that a slow reader of stdout or stderr never
// holds the lock.
//
// ok is false, after a message on stderr for the command cmd ("scan" or
// "pin"), when the path is not known or the file cannot be read. The caller
// then exits with 2. The message depends on the error of LoadLocked:
//   - A context error (context.Canceled or context.DeadlineExceeded) gives
//     interruptedText. LoadLocked returns it when ctx ended before or during
//     the wait for the lock (the process got a signal). It then never reads
//     the file, so a corrupt file also gives interruptedText here.
//   - pins.ErrLocked (another process held the lock for the whole wait) gives
//     the "cannot read the pins file" line and then pinsLockedText.
//   - Any other error (unsafe permissions, a corrupt file, a newer version, a
//     lock error) gives the "cannot read the pins file" line only.
//
// An error of the pins directory or its parents is a read error also when ctx
// has ended: the lock is on an open handle of the pins directory, so
// LoadLocked checks and opens the directory before the lock step, and only the
// lock step checks ctx. LoadLocked does not check ctx after it takes the lock,
// so a read error after that point also stays a read error.
//
// When the file system cannot lock the pins directory, LoadLocked goes on
// without the lock. readPinsLocked then prints one warning: a parallel run can
// still lose an update.
//
// readPinsLocked prints only when it holds no lock: LoadLocked holds no lock
// after an error, and the warning is for a run without the lock.
func (c *cli) readPinsLocked(ctx context.Context, cmd string) (store *pins.Store, release func(), ok bool) {
	noop := func() {}
	path, ok := c.pinsPath(cmd)
	if !ok {
		return nil, noop, false
	}
	store, release, err := pins.LoadLocked(ctx, path, c.pinsLockWait)
	if err != nil {
		// A signal during the wait: say "interrupted", as the other steps do.
		// Only a context error means that: a file error stays a file error.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			c.cmdPrintf(cmd, "%s", interruptedText)
			return nil, release, false
		}
		c.cmdErr(cmd, "cannot read the pins file", err)
		if errors.Is(err, pins.ErrLocked) {
			c.cmdPrintf(cmd, "%s", pinsLockedText)
		}
		return nil, release, false
	}
	if store.RanWithoutLock() {
		c.warnf(cmd, "the file system of the pins directory %s does not support file locks, so a parallel run can overwrite these pins",
			termsafe.QuoteCut(filepath.Dir(store.Path()), maxWarnPathRunes))
	}
	return store, release, true
}

// pinsRemovedWhileRunning reports whether the pins file was removed while the
// command ran. firstExisted tells whether the file existed at an earlier read
// of the command. later is the store of a later read. For scan, and for the
// check of pin that holds the lock, that is the read with the lock. For the
// early check of pin, it is the read for the diffs, which takes no lock. When
// the earlier read found the file and the later read did not, the file was
// removed. A save would then write a new file with only the pins of this run,
// and drop every older pin without a word. A later rug pull would then look
// like a first run. So the caller saves nothing.
//
// It only checks and prints nothing. When it returns true, the caller prints
// pinsRemovedText on stderr and exits with 2. A caller that holds the lock on
// the pins directory releases the lock first, so a blocked stderr never holds
// the lock.
func pinsRemovedWhileRunning(firstExisted bool, later *pins.Store) bool {
	return firstExisted && !later.Existed()
}

// pinsFullText is the shared part of the three messages for a server that
// does not fit in pins.json (pins.ErrStoreFull): "the pins file is full
// (32 MiB)". scan uses it at report time (reasonStoreFull) and at save time
// (savePinned), and pin uses it in saveAccepted. The size comes from
// pins.MaxFileSizeMiB, the limit that Set enforces, so the number is written
// in one place.
//
// It is a var and not a const: Go cannot turn a number into text at compile
// time, so fmt.Sprintf builds the text once, when the program starts.
var pinsFullText = fmt.Sprintf("the pins file is full (%d MiB)", pins.MaxFileSizeMiB)

// pinsLockedText is the line that readPinsLocked prints after the read error
// when another process held the lock on the pins directory for the whole wait.
// The holder is normally another mcpmoat run, but any local process that can
// open the directory can hold the lock. It is fixed text.
const pinsLockedText = "another process is using the pins file; run the command again in a moment"

// pinsRemovedText is the line that scan and pin print when the pins file was
// removed while the command ran (see pinsRemovedWhileRunning). It is fixed
// text.
const pinsRemovedText = "the pins file was removed while this command ran, so no pins were saved; run the command again"

// printNewPinsFile prints one line on stderr for the command cmd: the save
// created a new pins file at path. The caller prints it after a successful
// Save when the store did not exist (pins.Store.Existed is false), before the
// lines that say what was pinned. On a first run the line is expected. On a
// later run it tells the user that the old file is gone, so every server
// looked new and was pinned with no alert. path comes from the environment,
// so it is escaped and cut.
func (c *cli) printNewPinsFile(cmd, path string) {
	c.cmdPrintf(cmd, "no pins file was found, so a new one was created at %s; if this is not your first run, the old file was removed or moved",
		termsafe.QuoteCut(path, maxWarnPathRunes))
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

// compareMask returns the mask for pins.CompareMasked that hides the secret
// values of a server: r.Text, where r is discover.NewTextRedactor of
// inspect.Result.Secrets. scan and pin both compare with it, so the tool names
// and the diffs that they print show each secret value as discover.Mask. Only
// the printed text is masked: the hashes, the verdicts and the lookups by name
// use the real tool text.
//
// For a nil r (a server with no secret value of at least
// discover.MinSecretBytes bytes) it returns nil, and CompareMasked then works
// like pins.Compare. The check is needed because a method value such as r.Text
// is never nil, also when r is nil: it is a func that calls Text on r.
func compareMask(r *discover.TextRedactor) func(string) string {
	if r == nil {
		return nil
	}
	return r.Text
}

// diffOf returns the diff of one change for the report. The change must have a
// diff (see appendDiff). server is the name that the report shows.
//
// The tool name of the diff is ch.Tool and never ch.RawTool. ch must come from
// pins.CompareMasked with the mask of the server (see compareMask), so ch.Tool
// and ch.Diff show each secret value of the server as discover.Mask.
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
//
// ch must come from pins.CompareMasked with the mask of the server (see
// diffOf). The warning and the diff print ch.Tool, the masked name, and the
// cut of the warning (cutName) comes after the mask, so it cannot leave a part
// of a secret value.
func (c *cli) appendDiff(cmd string, diffs []report.ToolDiff, server string, ch pins.Change) []report.ToolDiff {
	if ch.Diff == "" {
		return diffs
	}
	if ch.Truncated {
		// ch.Tool is the masked name; never print ch.RawTool.
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
