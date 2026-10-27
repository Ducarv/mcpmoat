package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"text/tabwriter"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// runPin implements "mcpmoat pin --accept <server>" (FR-13). It accepts the
// tools that one server offers now as the new pins of that server. The user
// runs it after "mcpmoat scan" reported a change and the user reviewed the
// diff.
//
// The steps, each in its own function:
//  1. parsePinArgs: read and check the flags.
//  2. findPinServer: find the one server that has the --accept name.
//  3. readPins: check that pins.json can be read. This comes before the next
//     step, so a corrupt or newer file stops pin before it starts a stdio
//     server. This is the first read of the command. Whether the file existed
//     here goes to acceptTools.
//  4. inspectOne: inspect only that server.
//  5. acceptTools: read pins.json again, show the diffs and check --expect.
//     Then saveAccepted reads the file once more with the lock on the pins
//     directory, sets the pins of this server only and saves the file.
//
// When the pins file existed at the first read of the command and a later read
// does not find it, pin saves nothing and gives exit code 2 (see
// pinsRemovedWhileRunning). Nothing is written unless every step before the
// save worked.
//
// The server runs in its own session, so the terminal does not signal it. When
// the process gets SIGINT, SIGTERM or SIGHUP (see main), the context ends and
// inspect.Run stops the server. The usage text (pinUsage and usage in cli.go)
// lists the flags and the exit codes (FR-16).
func (c *cli) runPin(_ options, args []string) int {
	a, code, ok := c.parsePinArgs(args)
	if !ok {
		return code
	}

	// The context ends on a signal, like in runScan.
	ctx := c.ctxOrBackground()

	server, ok := c.findPinServer(ctx, a.accept, a.configPath, a.project)
	if !ok {
		return exitError
	}
	first, ok := c.readPins("pin")
	if !ok {
		return exitError
	}
	res, ok := c.inspectOne(ctx, server, a.connOpts)
	if !ok {
		return exitError
	}
	return c.acceptTools(ctx, server, res, a.expect, first.Existed())
}

// pinArgs holds the checked flags of "pin".
type pinArgs struct {
	accept     string // the server name; never empty
	configPath string // --config, or empty for auto-discovery
	project    string // --project, or empty
	// expect is the --expect digest, or empty. It is a valid digest: it passed
	// pins.ValidDigest.
	expect   string
	connOpts inspect.Options
}

// parsePinArgs parses and checks the flags of "pin". When ok is false, it has
// printed the message (or the help text) and code is the exit code.
func (c *cli) parsePinArgs(args []string) (a pinArgs, code int, ok bool) {
	fs := flag.NewFlagSet("mcpmoat pin", flag.ContinueOnError)
	// We print our own messages and pinUsage prints the help, so the flag
	// package prints nothing.
	fs.SetOutput(io.Discard)
	timeout := fs.Duration("timeout", inspect.DefaultTimeout, "")

	// onceStringFlag refuses an empty value and a value that looks like a
	// flag, so a result that is not "" means the flag was given.
	onceStringFlag(fs, "accept", "a server name", &a.accept)
	onceStringFlag(fs, "config", "a file name", &a.configPath)
	onceStringFlag(fs, "project", "a project path", &a.project)
	onceStringFlag(fs, "expect", "a digest", &a.expect)

	// pin has no --llm-base-url flag, but the user can still type one, and
	// its value can hold a password. hider hides it in the error text, as
	// in scan (see argscrub.go).
	hider := newBaseURLHider(args)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			pinUsage(c.stdout)
			return pinArgs{}, exitOK, false
		}
		// The flag error holds untrusted argv, so it is escaped, after
		// hider.errorText hides a secret in it. See dispatch in cli.go.
		return pinArgs{}, c.usageError("pin", "%s", termsafe.Quote(hider.errorText(err.Error()))), false
	}
	if c.rejectArgs("pin", hider, fs.Args()) {
		return pinArgs{}, exitError, false
	}
	// isFlagOf knows only the pin flags, so "--accept --llm-base-url=URL"
	// gives the server name "--llm-base-url=URL". The later messages print
	// the --accept name, the --config file and the --project path, and they
	// hide only the user info of a URL (see hideUserinfo), not a value
	// without a scheme. So pin refuses each of these values that holds a
	// value of --llm-base-url, and the message does not print the value.
	for _, f := range []struct{ name, value string }{
		{"accept", a.accept}, {"config", a.configPath}, {"project", a.project},
	} {
		if hider.hide(f.value) != f.value {
			return pinArgs{}, c.usageError("pin", "--%s holds a --%s value; --%s is a scan flag and pin does not take it", f.name, flagLLMBaseURL, flagLLMBaseURL), false
		}
	}
	if a.accept == "" {
		return pinArgs{}, c.usageError("pin", "--accept <server> is required"), false
	}
	// Check the digest before discovery, so a typo stops pin before it reads a
	// file or starts a server. The value is not printed: it is untrusted argv.
	if a.expect != "" && !pins.ValidDigest(a.expect) {
		return pinArgs{}, c.usageError("pin", "--expect needs a digest such as %s:<64 hex>", pins.DigestVersion), false
	}

	// The concurrency is 1 for the one server. connectOptions gives the same
	// --timeout message as scan.
	connOpts, err := connectOptions(*timeout, 1)
	if err != nil {
		return pinArgs{}, c.usageError("pin", "%v", err), false
	}
	a.connOpts = connOpts
	return a, exitOK, true
}

// inspectOne inspects the one server and returns the result: its tools, and
// the secret values that it got (inspect.Result.Secrets), so that pin can hide
// them in what it prints. It returns false, after a message on stderr, when
// the process got a signal (the result may be partial, so pin saves nothing)
// or when the server was not inspected (failed, timeout, or refused: an
// untrusted or turned-off server). scan prints the second case as a warning,
// but here it is an error: nothing is accepted.
func (c *cli) inspectOne(ctx context.Context, server discover.Server, opts inspect.Options) (inspect.Result, bool) {
	outcomes, err := inspect.Run(ctx, []discover.Server{server}, opts, c.inspector)
	if c.interrupted(ctx, "pin") {
		return inspect.Result{}, false
	}
	if err != nil {
		// The text of an inspect.Run error holds only our own words.
		c.cmdErr("pin", "cannot inspect the server", err)
		return inspect.Result{}, false
	}
	// Run gives one outcome for one server. Any other number is a bug.
	if len(outcomes) != 1 {
		c.cmdPrintf("pin", "server %s: not inspected", cutName(server.Name))
		return inspect.Result{}, false
	}
	c.warnInspection(outcomes[0])
	if outcomes[0].Status != inspect.StatusOK {
		c.cmdPrintf("pin", "%s", notInspectedText(outcomes[0]))
		return inspect.Result{}, false
	}
	return outcomes[0].Result, true
}

// acceptTools sets the pins of the server to the tools of res, the result of
// its inspection, and saves the store. It prints the diff of each changed or
// new tool first, so the user sees what the accept changes. Then saveAccepted
// does the save with the lock. It returns the exit code.
//
// The diffs and the stderr warnings show each secret value of the server
// (res.Secrets) as discover.Mask (see pinChanges). The pins and the --expect
// digest use the real tools.
//
// The server can run for a long time, so acceptTools reads pins.json again
// after the inspection, without the lock, and prints the diffs against that
// store. A slow reader of stdout must not hold the lock, so the lock comes
// only after the diffs, in saveAccepted.
//
// firstExisted tells whether pins.json existed at the first read of the
// command (in runPin, before the server started). When the file existed at the
// first read and a later read does not find it, it was removed while pin ran.
// A save would drop every older pin, so pin saves nothing and gives exit code 2
// (see pinsRemovedWhileRunning). pin checks this twice. The first check is
// here, right after the read for the diffs, and covers the inspection: it
// stops pin before it prints a diff in which every tool looks new. The second
// check is in saveAccepted, at the locked read.
//
// With a non-empty expect, it compares that digest with pins.Digest of the
// tools that it just inspected. This closes a time-of-check to time-of-use gap:
// a hostile server can show good tools to "scan", which the user reviews, and
// bad tools to "pin --accept", which then saves them (see writeAcceptHints). If
// the digests differ, pin saves nothing. Without expect, pin trusts the tools
// that the server returns now, and prints the note pinNoExpectNote on stderr
// before it saves.
func (c *cli) acceptTools(ctx context.Context, server discover.Server, res inspect.Result, expect string, firstExisted bool) int {
	tools := res.Tools
	name := cutName(server.Name)
	id := serverIdentity(server)
	// A relative path gives another identity than the one in the store, so
	// the accept would add an entry and leave the old pins in place.
	if !filepath.IsAbs(server.Source) {
		c.cmdPrintf("pin", "cannot pin server %s: the path of its config file is not absolute (the working directory is not known)", name)
		return exitError
	}

	// The same check as the "To accept" hint of scan (see pinnable). Only the
	// fixed reason is printed (see pinnableReason).
	snap, err := pinnable(id, tools)
	if err != nil {
		c.cmdPrintf("pin", "cannot pin the tools of server %s: %s", name, pinnableReason(err))
		return exitError
	}

	// A read error stops pin before the save. This read takes no lock: the
	// diffs below go to stdout, which can be slow (a pager, for example), and
	// another run must not wait for that.
	shown, ok := c.readPins("pin")
	if !ok {
		return exitError
	}
	// The file can go away while the server is inspected. Then every tool
	// would look new in the diffs, so stop before they print.
	if pinsRemovedWhileRunning(firstExisted, shown) {
		c.cmdPrintf("pin", "%s", pinsRemovedText)
		return exitError
	}
	diffs := c.pinChanges(shown, id, server.Name, tools, discover.NewTextRedactor(res.Secrets))

	// Show the diffs before pin saves. Do not use fprintf: a write error (a
	// closed pipe) must stop pin before the save, because the user did not see
	// the diff.
	if err := report.WriteDiffs(c.stdout, diffs); err != nil {
		c.cmdPrintf("pin", "cannot write output; no pins were saved")
		return exitError
	}

	if !c.checkExpect(name, snap, expect) {
		return exitError
	}

	// A signal while the diffs printed means the user stopped pin: save
	// nothing.
	if c.interrupted(ctx, "pin") {
		return exitError
	}
	return c.saveAccepted(ctx, name, id, tools, snap, shown)
}

// saveAccepted is the locked part of acceptTools, like savePinned for scan. It
// reads pins.json a third time, now with the lock on the pins directory (see
// readPinsLocked), sets the pins of the server id to snap, saves the file and
// returns the exit code. name is the server name, already escaped and cut for
// the messages. tools are the tools that snap pins. shown is the store that
// acceptTools read for the diffs. acceptTools has already stopped when the file
// existed at the first read of the command and was gone at the read for the
// diffs, so shown.Existed() is true whenever the file existed at the first read.
//
// saveAccepted holds the lock until the save is done. No other run that locks
// can save between this read and this save, so the save keeps every entry that
// another run wrote, and no update is lost. An accept always overwrites the
// entry of this one server. The counts of the "accepted" line come from the
// locked store, because they describe the entry that the save replaces. If
// another run changed that entry after the diffs printed, a warning says that
// the diffs are against the older pins.
//
// saveAccepted writes nothing on stdout or stderr while it holds the lock, so
// a blocked stdout or stderr never holds the lock. While it holds the lock, it
// only notes what to print: whether the pins changed, and the error of Set or
// Save. It releases the lock right after the Save, or right after the step
// that failed, and only then prints, in this order: the warning, the error,
// and on success the new pins file notice and the "accepted" line.
//
// This is the second check for a removed pins file (see acceptTools). When the
// file existed at the read for the diffs (shown), and the locked read does not
// find it, it was removed while pin showed the diffs: saveAccepted saves nothing, prints pinsRemovedText after the release
// and gives exit code 2. A file that is missing at every read is a real first
// run: the save creates it.
//
// A Set that would make pins.json larger than its size limit
// (pins.ErrStoreFull) saves nothing and gives exit code 2, with a message that
// tells the user to remove old servers. When the save created a new pins file,
// saveAccepted prints a notice before the "accepted" line (see
// printNewPinsFile).
func (c *cli) saveAccepted(ctx context.Context, name string, id pins.Identity, tools []inspect.Tool, snap pins.ServerPins, shown *pins.Store) int {
	store, release, ok := c.readPinsLocked(ctx, "pin")
	// release is never nil. Each path below calls release before it prints.
	// The deferred call is a safety net: a second call does nothing.
	defer release()
	if !ok {
		// readPinsLocked holds no lock after an error, and it printed the
		// message.
		return exitError
	}
	// A file that existed at the read for the diffs and is gone now was
	// removed while pin showed the diffs.
	if pinsRemovedWhileRunning(shown.Existed(), store) {
		release()
		c.cmdPrintf("pin", "%s", pinsRemovedText)
		return exitError
	}
	// changed is printed as a warning after the release.
	changed := pinsChanged(shown, store, id)
	counts := changeCounts(store, id, tools)

	setErr := store.Set(id, snap)
	var saveErr error
	if setErr == nil {
		saveErr = store.Save()
	}
	// The last step that needs the lock is done. Free the lock before the
	// output: a blocked pipe must not keep other runs from the pins file.
	release()

	if changed {
		c.warnf("pin", "another mcpmoat run changed the pins of server %s while pin showed the diff; the diff is against the older pins", name)
	}
	if errors.Is(setErr, pins.ErrStoreFull) {
		c.cmdPrintf("pin", "cannot pin %s: %s; remove servers you no longer use from pins.json", name, pinsFullText)
		return exitError
	}
	if setErr != nil {
		c.cmdErr("pin", "cannot set the pins of server "+name, setErr)
		return exitError
	}
	if saveErr != nil {
		c.cmdErr("pin", "cannot save the pins file", saveErr)
		return exitError
	}
	if !store.Existed() {
		c.printNewPinsFile("pin", store.Path())
	}

	fprintf(c.stdout, "accepted %s: %s\n", name, counts)
	return exitOK
}

// pinsChanged reports whether the entry of the server id differs between the
// store a, which pin read for the diffs, and the store b, which pin read with
// the lock. A server that is in one store but not in the other has changed,
// also when its entry has no tools.
func pinsChanged(a, b *pins.Store, id pins.Identity) bool {
	pa, inA := a.Get(id)
	pb, inB := b.Get(id)
	// maps.Equal compares the keys and the values. A Pin holds only strings,
	// so == on two Pins compares their text.
	return inA != inB || !maps.Equal(pa, pb)
}

// checkExpect compares expect, when it is not empty, with pins.Digest of snap,
// the tools of the server name. It returns false, after a message on stderr,
// when they differ. Without expect it prints pinNoExpectNote and returns true:
// the note comes before the save, so it shows whenever the run reaches the
// save step.
func (c *cli) checkExpect(name string, snap pins.ServerPins, expect string) bool {
	if expect == "" {
		c.cmdPrintf("pin", "%s", pinNoExpectNote)
		return true
	}
	if got := pins.Digest(snap); got != expect {
		// The two digests are hex made by mcpmoat (expect passed ValidDigest),
		// so they need no escape.
		c.cmdPrintf("pin", "the tools of %s differ from what scan showed (digest %s, expected %s); nothing was saved. Run scan again and review the diff.", name, got, expect)
		return false
	}
	return true
}

// pinNoExpectNote is the line that pin prints on stderr, before it saves, when
// --expect is not given. It is fixed text.
const pinNoExpectNote = "note: without --expect, pin trusts the tools the server returns now; " +
	"use the digest from scan to be sure they match what you reviewed."

// pinUsage writes the flags of the pin command to w. usage includes it, and
// "mcpmoat pin -h" prints it alone.
func pinUsage(w io.Writer) {
	fprintf(w, "Pin flags (after \"pin\"):\n")
	// Padding 2 keeps the descriptions in one column, like scanUsage.
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fprintf(tw, "  --accept <server>\tAccept the tools that the server offers now as its new pins (required)\n")
	fprintf(tw, "  \tpin connects to this one server (a stdio server is started). Review the diff of \"scan\" first\n")
	fprintf(tw, "  \tpin prints the diff of each changed, new or not verified tool, then \"accepted ...\". Ctrl-C stops the server and saves nothing (exit 2)\n")
	fprintf(tw, "  \tThe name must match exactly one server. If two clients or projects use it, narrow it with --config or --project\n")
	fprintf(tw, "  --expect <digest>\tSave the tools only if their digest is this one (pd1:<64 hex>); scan prints it as\n")
	fprintf(tw, "  \t\"To accept <server>: mcpmoat pin --accept <server> --expect <digest>\". If the tools differ, pin prints\n")
	fprintf(tw, "  \tthe diff, saves nothing and exits 2. Without it, pin trusts the tools the server returns now (a note on stderr)\n")
	fprintf(tw, "  --config <file>\tRead only this file, like \"scan --config\"; skips auto-discovery\n")
	fprintf(tw, "  --project <path>\tAccept the server of this project only (the project path of ~/.claude.json, or the folder of a project file;\n")
	fprintf(tw, "  \ta relative path is read from the working directory)\n")
	fprintf(tw, "  \tWithout it, when one name is in several places, pin takes the one outside any project, if there is exactly one\n")
	fprintf(tw, "  --timeout <duration>\tTime limit for the server, a Go duration such as 10s or 1m30s (default %s)\n", inspect.DefaultTimeout)
	_ = tw.Flush() // the write error is ignored on purpose, see fprintf
	fprintf(w, "  A problem with a config file is an error (exit 2): it can hide a second server with the same name. Fix the file or use --config\n")
	fprintf(w, "  pin changes only the entry of this server: it reads pins.json again just before it saves, and keeps the other entries.\n")
	fprintf(w, "  A server that fails, times out, or that pin refuses to start is an error (exit 2) and pin changes nothing.\n")
}

// findPinServer finds the one server that has the name accept, exactly, and
// the project path project when it is not empty (see selectServers). It reads
// the config files like scan does (see loadConfigs): only configPath when it is
// not empty, else auto-discovery. It returns false, after a message on stderr,
// when the server is unknown, when more than one server matches, or when the
// configs cannot be read at all.
//
// pin fails closed on a config problem. If discovery reports any problem with
// a config file, findPinServer prints each problem on stderr and returns false,
// even when exactly one server matches: the broken file can hide a second
// server with the same name, and "pin --accept" could trust the wrong one. The
// user fixes the file or narrows the search with --config.
func (c *cli) findPinServer(ctx context.Context, accept, configPath, project string) (discover.Server, bool) {
	// pin does not read .mcpmoat-ignore, so it does not need the working
	// directory.
	res, _, ok := c.loadConfigs(ctx, "pin", configPath)
	if !ok {
		return discover.Server{}, false
	}
	if len(res.Errors) > 0 {
		c.printFileErrors("pin", res.Errors)
		// A --config file that did not load needs no hint: the error says it.
		if configPath == "" || !loadFailed(res) {
			c.cmdPrintf("pin", "fix the config file or choose one with --config <file>")
		}
		return discover.Server{}, false
	}

	if project != "" {
		// discover stores clean, absolute project paths, so "/p/a/" means
		// "/p/a", and a relative path is joined with the working directory,
		// like --config.
		if wd, err := c.getwd(); err == nil && !filepath.IsAbs(project) {
			project = filepath.Join(wd, project)
		}
		project = filepath.Clean(project)
	}
	matches := selectServers(res.Servers, accept, project)
	if len(matches) == 1 {
		return matches[0], true
	}
	if len(matches) == 0 {
		// accept is user-typed argv and can hold a URL with a password.
		// hideUserinfo runs before the cut, so the cut cannot split the URL
		// before its '@' and leave the password unhidden. accept holds no
		// --llm-base-url value: parsePinArgs refused that.
		name := cutName(hideUserinfo(accept))
		if project != "" {
			c.cmdPrintf("pin", "unknown server %s in project %s", name, termsafe.QuoteCut(project, maxWarnPathRunes))
		} else {
			c.cmdPrintf("pin", "unknown server %s", name)
		}
		return discover.Server{}, false
	}
	c.printAmbiguous(accept, matches)
	return discover.Server{}, false
}

// selectServers returns the servers that "pin --accept name [--project
// project]" selects, in the order of servers. They have exactly the name name.
// With a project, they also have exactly that ProjectPath. Without one, when
// more than one server has the name and exactly one of them is outside any
// project (an empty ProjectPath), only that one is kept: ~/.claude.json can use
// one name in its global section and in several projects. scan uses the same
// function for its "To accept" line, so the line selects the server that it
// names.
func selectServers(servers []discover.Server, name, project string) []discover.Server {
	var named, global []discover.Server
	for _, s := range servers {
		if s.Name != name || (project != "" && s.ProjectPath != project) {
			continue
		}
		named = append(named, s)
		if s.ProjectPath == "" {
			global = append(global, s)
		}
	}
	if project == "" && len(named) > 1 && len(global) == 1 {
		return global
	}
	return named
}

// printAmbiguous tells the user that more than one server has the name accept,
// and lists where each one comes from, so the user can narrow it with --config
// or --project.
// The fields come from config files, so they are escaped and cut. accept is
// user-typed, so hideUserinfo hides a URL password in it before the cut. It
// holds no --llm-base-url value: parsePinArgs refused that.
func (c *cli) printAmbiguous(accept string, matches []discover.Server) {
	c.cmdPrintf("pin", "%d servers are named %s; narrow it with --config <file> or --project <path>:", len(matches), cutName(hideUserinfo(accept)))
	for _, s := range matches {
		line := "  client " + cutName(string(s.Client)) +
			", source " + termsafe.QuoteCut(s.Source, maxWarnPathRunes) +
			", scope " + cutName(string(s.Scope))
		if s.ProjectPath != "" {
			line += ", project " + termsafe.QuoteCut(s.ProjectPath, maxWarnPathRunes)
		}
		fprintf(c.stderr, "%s\n", line)
	}
}

// pinCounts holds how many tools "pin --accept" adds, changes and removes.
type pinCounts struct {
	added, changed, removed, unverified int
}

// String returns the text of the "accepted" line after the server name, for
// example "2 new, 1 changed, 0 removed". The not verified count shows only
// when it is above 0.
func (p pinCounts) String() string {
	s := fmt.Sprintf("%d new, %d changed, %d removed", p.added, p.changed, p.removed)
	if p.unverified > 0 {
		s += fmt.Sprintf(", %d not verified", p.unverified)
	}
	return s
}

// add counts one change of the kind k.
func (p *pinCounts) add(k pins.ChangeKind) {
	switch k {
	case pins.KindNew:
		p.added++
	case pins.KindChanged:
		p.changed++
	case pins.KindRemoved:
		p.removed++
	case pins.KindUnverified:
		p.unverified++
	}
}

// changeCounts counts what accepting tools changes in the pins of the server
// id. It makes no diff and prints nothing. saveAccepted uses it on the locked
// store, after pinChanges gave the diffs, because the counts describe the
// entry that the save replaces. It reads only the kind of each change, never
// a tool name or a diff, so it uses pins.Compare without a mask.
func changeCounts(store *pins.Store, id pins.Identity, tools []inspect.Tool) pinCounts {
	var n pinCounts
	stored, _ := store.Get(id)
	for _, ch := range pins.Compare(stored, tools) {
		n.add(ch.Kind)
	}
	return n
}

// pinChanges returns the diff of each tool that accepting tools changes in the
// pins of the server id: a changed tool, a new tool, and a pinned tool whose
// pin cannot be checked (see appendDiff). server is the name that the diffs
// show. A server that is not pinned yet has no pins, so all its tools are new,
// and each one gets a diff of added lines. It reads the store and does not
// change it. It prints a warning on stderr for each diff that was cut at the
// size limit. It does not count the changes: changeCounts does that.
//
// redactor holds the secret values of the server (nil when it has none, see
// compareMask). The compare is pins.CompareMasked with it, so the tool names
// and the text of the diffs, and the tool names in the warnings, show each
// secret value as discover.Mask.
func (c *cli) pinChanges(store *pins.Store, id pins.Identity, server string, tools []inspect.Tool, redactor *discover.TextRedactor) []report.ToolDiff {
	var diffs []report.ToolDiff
	// An unpinned server gives nil pins, and pins.CompareMasked then reports
	// every valid tool as new.
	stored, _ := store.Get(id)
	for _, ch := range pins.CompareMasked(stored, tools, compareMask(redactor)) {
		diffs = c.appendDiff("pin", diffs, server, ch)
	}
	return diffs
}

// notInspectedText returns "server <name>: <status>: <reason>" for an outcome
// that is not inspect.StatusOK. pin shows it as an error. scan shows the status
// in its summary on stdout (see outcomeSummary), and uses this text only with
// --json, as a warning on stderr (see warnNotInspected).
// The server name and the error text come from untrusted sources (the error can
// carry server output), so both are escaped and cut.
func notInspectedText(o inspect.Outcome) string {
	return fmt.Sprintf("server %s: %s: %s",
		cutName(o.Server.Name),
		termsafe.Quote(string(o.Status)),
		termsafe.QuoteCut(outcomeReason(o), maxWarnErrRunes))
}

// warnInspection writes the warnings of the inspection of o on stderr, for
// pin: one line for each warning of outcomeWarnings. scan shows them in its
// summary on stdout instead (see outcomeSummary), or on stderr with --json
// (see warnNotInspected).
func (c *cli) warnInspection(o inspect.Outcome) {
	for _, w := range outcomeWarnings(o) {
		c.warnf("pin", "%s", warningText(o.Server.Name, w))
	}
}

// warningText returns "server <name>: <kind>: <what it means>" for one
// inspection warning. The server name is escaped and cut here. The rest comes
// from report.WarningText, the one owner of the warning wording.
func warningText(name string, w inspect.Warning) string {
	return "server " + cutName(name) + ": " + report.WarningText(w)
}
