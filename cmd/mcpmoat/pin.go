package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"strconv"

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
// The steps:
//  1. Find the servers whose name is exactly the --accept value. --config
//     chooses the source like it does for scan (see pinServers). No match, or
//     more than one match, is an error: pin never accepts more than one server.
//  2. Read pins.json. This comes before the next step, so a corrupt or newer
//     file stops pin before it starts a stdio server.
//  3. Inspect only that server, with the --timeout value. The server runs in
//     its own session, so the terminal does not signal it. When the process
//     gets SIGINT, SIGTERM or SIGHUP (see main), the context ends and
//     inspect.Run stops the server. pin then prints
//     "mcpmoat pin: interrupted; no pins were saved" and exits with 2.
//  4. Make the snapshot of its tools, count what changes, print the diff of
//     each changed tool, set the pins of this server only, and save the file.
//
// Nothing is written unless every step before the save worked.
//
// --expect <digest> closes a time-of-check to time-of-use gap. A hostile server
// can show good tools to "scan", which the user reviews, and bad tools to "pin
// --accept", which then saves them. "scan" prints the digest of the tools that
// it saw (see writeAcceptHints). With --expect, pin compares that digest with
// pins.Digest of the tools that it just inspected. The flag value is checked
// with pins.ValidDigest before pin reads any file or starts any server, and a
// bad value is a usage error. If the digests differ, pin prints the diffs (so
// the user sees what changed) and an error on stderr, saves nothing and exits
// with 2. Without --expect, pin trusts the tools that the server returns now.
// It prints the one-line note pinNoExpectNote on stderr after a successful
// save, to say so.
//
// pin prints on stdout the unified diff of each changed tool (the same text as
// scan, see report.WriteDiffs), so the user sees what the accept changes. The
// diffs come before the save. Then pin prints one line, for example
// "accepted foo: 2 new, 1 changed, 0 removed" (", N not verified" is added
// only when N is above 0). Warnings and errors go to stderr.
//
// Exit codes: 0 the pins are saved, 2 a usage error, a config problem that
// hides the server, an unknown or ambiguous server, a server that was not
// inspected (failed, timeout, or refused: an untrusted or turned-off server),
// a signal during the inspection, tools that cannot be pinned, a write error
// on stdout, or a pins.json that cannot be read or saved.
func (c *cli) runPin(_ options, args []string) int {
	fs := flag.NewFlagSet("mcpmoat pin", flag.ContinueOnError)
	// We print our own messages and pinUsage prints the help, so the flag
	// package prints nothing.
	fs.SetOutput(io.Discard)
	timeout := fs.Duration("timeout", inspect.DefaultTimeout, "")

	// pathFlag refuses an empty value and a value that looks like a flag, so
	// a result that is not "" means the flag was given.
	var accept, configPath, expect string
	pathFlag(fs, "accept", "a server name", &accept)
	pathFlag(fs, "config", "a file name", &configPath)
	pathFlag(fs, "expect", "a digest", &expect)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			pinUsage(c.stdout)
			return exitOK
		}
		// The flag error holds untrusted argv, so it is escaped. See
		// dispatch in cli.go.
		return c.usageError("pin", "%s", termsafe.Quote(err.Error()))
	}
	if c.rejectArgs("pin", fs.Args()) {
		return exitError
	}
	if accept == "" {
		return c.usageError("pin", "--accept <server> is required")
	}
	// Check the digest before discovery, so a typo stops pin before it reads a
	// file or starts a server. The value is not printed: it is untrusted argv.
	if expect != "" && !pins.ValidDigest(expect) {
		return c.usageError("pin", "--expect needs a digest such as %s:<32 hex>", pins.DigestVersion)
	}

	// The concurrency is 1 for the one server. connectOptions gives the same
	// --timeout message as scan.
	connOpts, err := connectOptions(*timeout, 1)
	if err != nil {
		return c.usageError("pin", "%v", err)
	}

	// The context ends on a signal, like in runScan.
	ctx := c.context()

	server, ok := c.findPinServer(ctx, accept, configPath)
	if !ok {
		return exitError
	}
	name := termsafe.QuoteCut(server.Name, maxWarnNameRunes)

	// Read pins.json before inspect.Run starts the server. A corrupt or newer
	// file must stop pin before any server runs.
	path, err := pins.DefaultPath(c.getenv, c.homeDir)
	if err != nil {
		c.pinFailf("cannot find the pins file: %s", termsafe.Quote(err.Error()))
		return exitError
	}
	store, err := pins.Load(path)
	if err != nil {
		c.pinFailf("cannot read the pins file: %s", termsafe.Quote(err.Error()))
		return exitError
	}

	outcomes, err := inspect.Run(ctx, []discover.Server{server}, connOpts, c.inspector)
	if ctx.Err() != nil {
		// The process got a signal. The result may be partial, so pin saves
		// nothing. The text is fixed.
		c.pinFailf("interrupted; no pins were saved")
		return exitError
	}
	if err != nil {
		// The text of an inspect.Run error holds only our own words.
		c.pinFailf("cannot inspect the server: %s", termsafe.Quote(err.Error()))
		return exitError
	}
	if len(outcomes) != 1 || outcomes[0].Status != inspect.StatusOK {
		// Run gives one outcome for one server. This line is the same warning
		// that scan prints, but it is an error here: nothing is accepted.
		if len(outcomes) == 0 {
			c.pinFailf("server %s: not inspected", name)
		} else {
			o := outcomes[0]
			reason := "no error text"
			if o.Err != nil {
				reason = o.Err.Error()
			}
			c.pinFailf("server %s: %s: %s", name,
				termsafe.Quote(string(o.Status)),
				termsafe.QuoteCut(reason, maxWarnErrRunes))
		}
		return exitError
	}
	tools := outcomes[0].Result.Tools

	// The error text is not printed: it can name a tool of the server.
	snap, err := pins.Snapshot(tools)
	if err != nil {
		c.pinFailf("cannot pin the tools of server %s: a tool name is empty or used twice, or a tool cannot be hashed", name)
		return exitError
	}

	id := serverIdentity(server)
	counts, diffs := pinChanges(store, id, server.Name, tools)
	got := pins.Digest(snap)

	// Show the diffs before pin saves, so the user sees what the accept
	// changes. Do not use fprintf: a write error (a closed pipe) must stop pin
	// before the save, because the user did not see the diff.
	if err := report.WriteDiffs(c.stdout, diffs); err != nil {
		c.pinFailf("cannot write output; no pins were saved")
		return exitError
	}

	if expect != "" && got != expect {
		// The diffs are out, so the user sees what the server shows now. The
		// two digests are hex made by mcpmoat (expect passed ValidDigest), so
		// they need no escape.
		c.pinFailf("the tools of %s differ from what scan showed (digest %s, expected %s); nothing was saved. Run scan again and review the diff.", name, got, expect)
		return exitError
	}

	if err := store.Set(id, snap); err != nil {
		c.pinFailf("cannot set the pins of server %s: %s", name, termsafe.Quote(err.Error()))
		return exitError
	}
	if err := store.Save(); err != nil {
		c.pinFailf("cannot save the pins file: %s", termsafe.Quote(err.Error()))
		return exitError
	}

	fprintf(c.stdout, "accepted %s: %s\n", name, counts)
	if expect == "" {
		fprintf(c.stderr, "%s\n", pinNoExpectNote)
	}
	return exitOK
}

// pinNoExpectNote is the line that pin prints on stderr, after a successful
// save, when --expect is not given. It is fixed text.
const pinNoExpectNote = "mcpmoat pin: note: without --expect, pin trusts the tools the server returns now; " +
	"use the digest from scan to be sure they match what you reviewed."

// pinUsage writes the flags of the pin command to w. usage includes it, and
// "mcpmoat pin -h" prints it alone.
func pinUsage(w io.Writer) {
	fprintf(w, "Pin flags (after \"pin\"):\n")
	fprintf(w, "  --accept <server>    Accept the tools that the server offers now as its new pins (required)\n")
	fprintf(w, "                       pin connects to this one server (a stdio server is started). Review the diff of \"scan\" first\n")
	fprintf(w, "                       pin prints the diff of each changed tool, then \"accepted ...\". Ctrl-C stops the server and saves nothing (exit 2)\n")
	fprintf(w, "                       The name must match exactly one server. If two clients or projects use it, narrow it with --config\n")
	fprintf(w, "  --expect <digest>    Save the tools only if their digest is this one (pd1:<32 hex>); scan prints it as\n")
	fprintf(w, "                       \"To accept <server>: mcpmoat pin --accept <server> --expect <digest>\". If the tools differ, pin prints\n")
	fprintf(w, "                       the diff, saves nothing and exits 2. Without it, pin trusts the tools the server returns now (a note on stderr)\n")
	fprintf(w, "  --config <file>      Read only this file, like \"scan --config\"; skips auto-discovery\n")
	fprintf(w, "  --timeout <duration> Time limit for the server, a Go duration such as 10s or 1m30s (default %s)\n", inspect.DefaultTimeout)
	fprintf(w, "  A problem with a config file is an error (exit 2): it can hide a second server with the same name. Fix the file or use --config\n")
	fprintf(w, "  Other servers keep their pins. A server that fails, times out, or that pin refuses to start is an error (exit 2) and pin changes nothing.\n")
}

// pinFailf writes one error line on stderr, with the prefix "mcpmoat pin: ".
// The caller must escape untrusted text in a.
func (c *cli) pinFailf(format string, a ...any) {
	fprintf(c.stderr, "mcpmoat pin: "+format+"\n", a...)
}

// findPinServer finds the one server that has the name accept, exactly. It
// reads the config files like scan does: only configPath when it is not
// empty, else auto-discovery. It returns false, after a message on stderr,
// when the server is unknown, when more than one server has the name, or when
// the configs cannot be read at all.
//
// pin fails closed on a config problem. If discovery reports any problem with
// a config file, findPinServer prints each problem on stderr and returns false,
// even when exactly one server matches: the broken file can hide a second
// server with the same name, and "pin --accept" could trust the wrong one. The
// user fixes the file or narrows the search with --config.
func (c *cli) findPinServer(ctx context.Context, accept, configPath string) (discover.Server, bool) {
	res, ok := c.readPinConfigs(ctx, configPath)
	if !ok {
		return discover.Server{}, false
	}
	if len(res.Errors) > 0 {
		// FileError.Error already escapes the path and the server name.
		for _, e := range res.Errors {
			c.pinFailf("%s", e.Error())
		}
		c.pinFailf("fix the config file or choose one with --config <file>")
		return discover.Server{}, false
	}

	var matches []discover.Server
	for _, s := range res.Servers {
		if s.Name == accept {
			matches = append(matches, s)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], true
	case 0:
		c.pinFailf("unknown server %s", termsafe.QuoteCut(accept, maxWarnNameRunes))
		return discover.Server{}, false
	}

	c.pinFailf("%d servers are named %s; narrow it with --config <file>:", len(matches), termsafe.QuoteCut(accept, maxWarnNameRunes))
	for _, s := range matches {
		line := "  client " + termsafe.QuoteCut(string(s.Client), maxWarnNameRunes) +
			", source " + termsafe.QuoteCut(s.Source, maxWarnErrRunes) +
			", scope " + termsafe.QuoteCut(string(s.Scope), maxWarnNameRunes)
		if s.ProjectPath != "" {
			line += ", project " + termsafe.QuoteCut(s.ProjectPath, maxWarnErrRunes)
		}
		fprintf(c.stderr, "%s\n", line)
	}
	return discover.Server{}, false
}

// readPinConfigs reads the client configs for pin, with the same rules as
// scan. With --config it reads the one file (scanConfig explains the path and
// the trust rules). Without it, it discovers the files in the home and the
// working directory (scanAuto). It returns false, after a message on stderr,
// when a needed directory is not known, or when the file of --config gave no
// server and has a problem.
func (c *cli) readPinConfigs(ctx context.Context, configPath string) (discover.Result, bool) {
	if configPath != "" {
		// A relative path is made absolute first, so that the project path
		// and the trust check do not depend on how the user spells the path.
		// Without a working directory the path stays relative: that is the
		// safe side, the file is read as untrusted.
		if wd, err := c.getwd(); err == nil && !filepath.IsAbs(configPath) {
			configPath = filepath.Join(wd, configPath)
		}
		// The home directory only tells ReadConfig whether the file is the
		// user's own global file. Without a home, the file is untrusted.
		home, err := c.homeDir()
		if err != nil {
			home = ""
		}
		res := discover.ReadConfig(ctx, configPath, home)
		if len(res.Servers) == 0 && len(res.Errors) > 0 {
			for _, e := range res.Errors {
				c.pinFailf("%s", e.Error())
			}
			return discover.Result{}, false
		}
		return res, true
	}

	// The error texts are not printed: fixed messages are enough.
	home, err := c.homeDir()
	if err != nil {
		c.pinFailf("cannot find the home directory: set HOME or use --config")
		return discover.Result{}, false
	}
	wd, err := c.getwd()
	if err != nil {
		c.pinFailf("cannot read the working directory; use --config")
		return discover.Result{}, false
	}
	return discover.Discover(ctx, discover.Options{Home: home, WorkDir: wd}), true
}

// pinCounts holds how many tools "pin --accept" adds, changes and removes.
type pinCounts struct {
	added, changed, removed, unverified int
}

// String returns the text of the "accepted" line after the server name, for
// example "2 new, 1 changed, 0 removed". The not verified count shows only
// when it is above 0.
func (p pinCounts) String() string {
	s := strconv.Itoa(p.added) + " new, " + strconv.Itoa(p.changed) + " changed, " + strconv.Itoa(p.removed) + " removed"
	if p.unverified > 0 {
		s += ", " + strconv.Itoa(p.unverified) + " not verified"
	}
	return s
}

// pinChanges counts what accepting tools changes in the pins of the server id,
// and returns the diff of each changed tool. server is the name that the diffs
// show. A server that is not pinned yet has only new tools and no diff. It
// reads the store and does not change it.
func pinChanges(store *pins.Store, id pins.Identity, server string, tools []inspect.Tool) (pinCounts, []report.ToolDiff) {
	var n pinCounts
	var diffs []report.ToolDiff
	stored, found := store.Get(id)
	if !found {
		n.added = len(tools)
		return n, nil
	}
	for _, ch := range pins.Compare(stored, tools) {
		switch ch.Kind {
		case pins.KindNew:
			n.added++
		case pins.KindChanged:
			n.changed++
			diffs = append(diffs, report.ToolDiff{Server: server, Tool: ch.Tool, Diff: ch.Diff})
		case pins.KindRemoved:
			n.removed++
		case pins.KindUnverified:
			n.unverified++
		}
	}
	return n, diffs
}
