package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

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
//     server.
//  4. inspectOne: inspect only that server.
//  5. acceptTools: read pins.json again, show the diffs, check --expect, set
//     the pins of this server only and save the file.
//
// Nothing is written unless every step before the save worked. The server runs
// in its own session, so the terminal does not signal it. When the process gets
// SIGINT, SIGTERM or SIGHUP (see main), the context ends and inspect.Run stops
// the server. The usage text (pinUsage and usage in cli.go) lists the flags and
// the exit codes (FR-16).
func (c *cli) runPin(_ options, args []string) int {
	a, code, ok := c.parsePinArgs(args)
	if !ok {
		return code
	}

	// The context ends on a signal, like in runScan.
	ctx := c.ctxOrBackground()

	server, ok := c.findPinServer(ctx, a.accept, a.configPath)
	if !ok {
		return exitError
	}
	if _, ok := c.readPins("pin"); !ok {
		return exitError
	}
	tools, ok := c.inspectOne(ctx, server, a.connOpts)
	if !ok {
		return exitError
	}
	return c.acceptTools(server, tools, a.expect)
}

// pinArgs holds the checked flags of "pin".
type pinArgs struct {
	accept     string // the server name; never empty
	configPath string // --config, or empty for auto-discovery
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

	// pathFlag refuses an empty value and a value that looks like a flag, so
	// a result that is not "" means the flag was given.
	pathFlag(fs, "accept", "a server name", &a.accept)
	pathFlag(fs, "config", "a file name", &a.configPath)
	pathFlag(fs, "expect", "a digest", &a.expect)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			pinUsage(c.stdout)
			return pinArgs{}, exitOK, false
		}
		// The flag error holds untrusted argv, so it is escaped. See
		// dispatch in cli.go.
		return pinArgs{}, c.usageError("pin", "%s", termsafe.Quote(err.Error())), false
	}
	if c.rejectArgs("pin", fs.Args()) {
		return pinArgs{}, exitError, false
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

// inspectOne inspects the one server and returns its tools. It returns false,
// after a message on stderr, when the process got a signal (the result may be
// partial, so pin saves nothing) or when the server was not inspected (failed,
// timeout, or refused: an untrusted or turned-off server). scan prints the
// second case as a warning, but here it is an error: nothing is accepted.
func (c *cli) inspectOne(ctx context.Context, server discover.Server, opts inspect.Options) ([]inspect.Tool, bool) {
	outcomes, err := inspect.Run(ctx, []discover.Server{server}, opts, c.inspector)
	if ctx.Err() != nil {
		c.pinErrorf("%s", interruptedText)
		return nil, false
	}
	if err != nil {
		// The text of an inspect.Run error holds only our own words.
		c.cmdErr("pin", "cannot inspect the server", err)
		return nil, false
	}
	// Run gives one outcome for one server. Any other number is a bug.
	if len(outcomes) != 1 {
		c.pinErrorf("server %s: not inspected", cutName(server.Name))
		return nil, false
	}
	if outcomes[0].Status != inspect.StatusOK {
		c.pinErrorf("%s", notInspectedText(outcomes[0]))
		return nil, false
	}
	return outcomes[0].Result.Tools, true
}

// acceptTools sets the pins of the server to its tools and saves the store. It
// prints the diff of each changed or new tool first, so the user sees what the
// accept changes. It returns the exit code.
//
// The server can run for a long time, so acceptTools reads pins.json again
// after the inspection. The diffs, the counts and the save all use that fresh
// store: the diffs show the change against the entry that the save replaces,
// and the save keeps an entry that another run wrote in the meantime. An
// accept always overwrites the entry of this one server. This makes the window
// for a lost update short but does not close it. A lock on the file is issue
// #150.
//
// With a non-empty expect, it compares that digest with pins.Digest of the
// tools that it just inspected. This closes a time-of-check to time-of-use gap:
// a hostile server can show good tools to "scan", which the user reviews, and
// bad tools to "pin --accept", which then saves them (see writeAcceptHints). If
// the digests differ, pin saves nothing. Without expect, pin trusts the tools
// that the server returns now, and prints the note pinNoExpectNote on stderr
// before it saves.
func (c *cli) acceptTools(server discover.Server, tools []inspect.Tool, expect string) int {
	name := cutName(server.Name)
	id := serverIdentity(server)

	// The same check as the "To accept" hint of scan (see pinnable). The error
	// text is not printed: it can name a tool of the server.
	snap, err := pinnable(id, tools)
	if err != nil {
		c.pinErrorf("cannot pin the tools of server %s: %s", name, snapshotReason(err))
		return exitError
	}

	// A read error stops pin before the save.
	store, ok := c.readPins("pin")
	if !ok {
		return exitError
	}
	counts, diffs := c.pinChanges(store, id, server.Name, tools)

	// Show the diffs before pin saves. Do not use fprintf: a write error (a
	// closed pipe) must stop pin before the save, because the user did not see
	// the diff.
	if err := report.WriteDiffs(c.stdout, diffs); err != nil {
		c.pinErrorf("cannot write output; no pins were saved")
		return exitError
	}

	if expect == "" {
		// The note comes before the save, so it shows whenever the run reaches
		// the save step.
		fprintf(c.stderr, "%s\n", pinNoExpectNote)
	} else if got := pins.Digest(snap); got != expect {
		// The two digests are hex made by mcpmoat (expect passed ValidDigest),
		// so they need no escape.
		c.pinErrorf("the tools of %s differ from what scan showed (digest %s, expected %s); nothing was saved. Run scan again and review the diff.", name, got, expect)
		return exitError
	}

	if err := store.Set(id, snap); err != nil {
		c.cmdErr("pin", "cannot set the pins of server "+name, err)
		return exitError
	}
	if err := store.Save(); err != nil {
		c.cmdErr("pin", "cannot save the pins file", err)
		return exitError
	}

	fprintf(c.stdout, "accepted %s: %s\n", name, counts)
	return exitOK
}

// pinNoExpectNote is the line that pin prints on stderr, before it saves, when
// --expect is not given. It is fixed text.
const pinNoExpectNote = "mcpmoat pin: note: without --expect, pin trusts the tools the server returns now; " +
	"use the digest from scan to be sure they match what you reviewed."

// pinUsage writes the flags of the pin command to w. usage includes it, and
// "mcpmoat pin -h" prints it alone.
func pinUsage(w io.Writer) {
	fprintf(w, "Pin flags (after \"pin\"):\n")
	fprintf(w, "  --accept <server>    Accept the tools that the server offers now as its new pins (required)\n")
	fprintf(w, "                       pin connects to this one server (a stdio server is started). Review the diff of \"scan\" first\n")
	fprintf(w, "                       pin prints the diff of each changed, new or not verified tool, then \"accepted ...\". Ctrl-C stops the server and saves nothing (exit 2)\n")
	fprintf(w, "                       The name must match exactly one server. If two clients or projects use it, narrow it with --config\n")
	fprintf(w, "  --expect <digest>    Save the tools only if their digest is this one (pd1:<64 hex>); scan prints it as\n")
	fprintf(w, "                       \"To accept <server>: mcpmoat pin --accept <server> --expect <digest>\". If the tools differ, pin prints\n")
	fprintf(w, "                       the diff, saves nothing and exits 2. Without it, pin trusts the tools the server returns now (a note on stderr)\n")
	fprintf(w, "  --config <file>      Read only this file, like \"scan --config\"; skips auto-discovery\n")
	fprintf(w, "  --timeout <duration> Time limit for the server, a Go duration such as 10s or 1m30s (default %s)\n", inspect.DefaultTimeout)
	fprintf(w, "  A problem with a config file is an error (exit 2): it can hide a second server with the same name. Fix the file or use --config\n")
	fprintf(w, "  pin changes only the entry of this server: it reads pins.json again just before it saves, and keeps the other entries.\n")
	fprintf(w, "  A server that fails, times out, or that pin refuses to start is an error (exit 2) and pin changes nothing.\n")
}

// pinErrorf writes one error line on stderr, with the prefix "mcpmoat pin: ".
// The caller must escape untrusted text in a.
func (c *cli) pinErrorf(format string, a ...any) {
	c.cmdErrorf("pin", format, a...)
}

// findPinServer finds the one server that has the name accept, exactly. It
// reads the config files like scan does (see loadConfigs): only configPath when
// it is not empty, else auto-discovery. It returns false, after a message on
// stderr, when the server is unknown, when more than one server has the name,
// or when the configs cannot be read at all.
//
// pin fails closed on a config problem. If discovery reports any problem with
// a config file, findPinServer prints each problem on stderr and returns false,
// even when exactly one server matches: the broken file can hide a second
// server with the same name, and "pin --accept" could trust the wrong one. The
// user fixes the file or narrows the search with --config.
func (c *cli) findPinServer(ctx context.Context, accept, configPath string) (discover.Server, bool) {
	// pin does not read .mcpmoat-ignore, so it does not need the working
	// directory.
	res, _, ok := c.loadConfigs(ctx, "pin", configPath)
	if !ok {
		return discover.Server{}, false
	}
	if configPath != "" && loadFailed(res) {
		c.printFileErrors("pin", res.Errors)
		return discover.Server{}, false
	}
	if len(res.Errors) > 0 {
		c.printFileErrors("pin", res.Errors)
		c.pinErrorf("fix the config file or choose one with --config <file>")
		return discover.Server{}, false
	}

	matches := serversNamed(res.Servers, accept)
	if len(matches) == 1 {
		return matches[0], true
	}
	if len(matches) == 0 {
		c.pinErrorf("unknown server %s", cutName(accept))
		return discover.Server{}, false
	}
	c.printAmbiguous(accept, matches)
	return discover.Server{}, false
}

// serversNamed returns the servers that have exactly the name name, in the
// order of servers.
func serversNamed(servers []discover.Server, name string) []discover.Server {
	var matches []discover.Server
	for _, s := range servers {
		if s.Name == name {
			matches = append(matches, s)
		}
	}
	return matches
}

// printAmbiguous tells the user that more than one server has the name accept,
// and lists where each one comes from, so the user can narrow it with --config.
// The fields come from config files, so they are escaped and cut.
func (c *cli) printAmbiguous(accept string, matches []discover.Server) {
	c.pinErrorf("%d servers are named %s; narrow it with --config <file>:", len(matches), cutName(accept))
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

// pinChanges counts what accepting tools changes in the pins of the server id,
// and returns the diff of each changed or new tool. server is the name that the
// diffs show. A server that is not pinned yet has no pins, so all its tools are
// new, and each one gets a diff of added lines. It reads the store and does not
// change it. It prints a warning on stderr for each diff that was cut at the
// size limit (see appendDiff).
func (c *cli) pinChanges(store *pins.Store, id pins.Identity, server string, tools []inspect.Tool) (pinCounts, []report.ToolDiff) {
	var n pinCounts
	var diffs []report.ToolDiff
	// An unpinned server gives nil pins, and pins.Compare then reports every
	// valid tool as new.
	stored, _ := store.Get(id)
	for _, ch := range pins.Compare(stored, tools) {
		switch ch.Kind {
		case pins.KindNew:
			n.added++
		case pins.KindChanged:
			n.changed++
		case pins.KindRemoved:
			n.removed++
		case pins.KindUnverified:
			n.unverified++
		}
		diffs = c.appendDiff("pin", diffs, server, ch)
	}
	return n, diffs
}
