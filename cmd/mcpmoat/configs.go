package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// This file holds the code that scan and pin share to read the client configs,
// and the helpers that print a line with the prefix of one command.

// loadConfigs reads the client configs for the command cmd ("scan" or "pin").
// cmd only names the command in the messages. With configPath it reads that one
// file (readConfigFile). Without it, it discovers the files in the home and the
// working directory (discoverConfigs).
//
// The second result is the working directory, where .mcpmoat-ignore is. It is
// empty only with --config, when the directory is not known. The last result is
// false, after a message on stderr, when auto-discovery misses a directory.
func (c *cli) loadConfigs(ctx context.Context, cmd, configPath string) (discover.Result, string, bool) {
	if configPath != "" {
		res, wd := c.readConfigFile(ctx, configPath)
		return res, wd, true
	}
	return c.discoverConfigs(ctx, cmd)
}

// readConfigFile reads the one file that --config names. It returns the result
// and the working directory ("" if it is not known).
//
// A relative path is made absolute first, from the working directory.
// ReadConfig takes the project path of a project file from the file path, so
// a relative path would give a relative project path. Then the result would
// depend on how the user spells the path: the SCOPE cell would change, the
// check that keeps an absolute Codex cwd inside the project would refuse
// every such cwd, and the user's own global file would not be found.
//
// If the working directory is not known, the path stays relative. That is
// the safe side: the file is read as untrusted, and an absolute Codex cwd is
// refused. A server can be refused that the absolute path would accept, but
// never the other way.
//
// The file can come from anywhere, for example from a cloned repository, so
// discover.ReadConfig reads it as an untrusted project file (confined to its
// directory, no "projects" section), unless it is the user's own global config
// file (~/.claude.json, ~/.cursor/mcp.json or ~/.codex/config.toml). The home
// directory is only used for that check.
func (c *cli) readConfigFile(ctx context.Context, path string) (discover.Result, string) {
	// The error text is not printed: the caller warns when wd is empty.
	wd, err := c.getwd()
	if err != nil {
		wd = "" // do not use a value that comes with an error
	}
	if !filepath.IsAbs(path) && wd != "" {
		path = filepath.Join(wd, path)
	}

	// Without a home, no file is the user's own: the file is read as
	// untrusted, the safe side. So a home error is not fatal, and its text is
	// not printed.
	home, err := c.homeDir()
	if err != nil {
		home = ""
	}
	return discover.ReadConfig(ctx, path, home), wd
}

// discoverConfigs looks for the config files of the known clients, in the home
// directory and in the working directory. It returns false, after a message on
// stderr, when one of them is not known. The error texts are not printed:
// fixed messages are enough.
func (c *cli) discoverConfigs(ctx context.Context, cmd string) (discover.Result, string, bool) {
	home, err := c.homeDir()
	if err != nil {
		c.cmdPrintf(cmd, "cannot find the home directory: set HOME or use --config")
		return discover.Result{}, "", false
	}
	wd, err := c.getwd()
	if err != nil {
		c.cmdPrintf(cmd, "cannot read the working directory; use --config")
		return discover.Result{}, "", false
	}
	return discover.Discover(ctx, discover.Options{Home: home, WorkDir: wd}), wd, true
}

// loadFailed reports whether res is the result of a file that failed to load
// and gave no servers. It is only used with --config.
func loadFailed(res discover.Result) bool {
	return len(res.Servers) == 0 && len(res.Errors) > 0
}

// printFileErrors writes one line per file problem on stderr, with the prefix
// "mcpmoat <cmd>: ". A line holds only the fields of the FileError (path,
// position, project path, server name, fixed reason and OS error), never config
// text.
func (c *cli) printFileErrors(cmd string, errs []*discover.FileError) {
	// FileError.Error already escapes the path and the server name.
	for _, e := range errs {
		c.cmdPrintf(cmd, "%s", e.Error())
	}
}

// interrupted reports whether ctx ended (the process got a signal). When it
// did, it writes interruptedText on stderr for the command cmd first.
func (c *cli) interrupted(ctx context.Context, cmd string) bool {
	if ctx.Err() == nil {
		return false
	}
	c.cmdPrintf(cmd, "%s", interruptedText)
	return true
}

// plural returns one when n is 1, and many otherwise.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// cmdPrintf writes one line on stderr, with the prefix "mcpmoat <cmd>: ": an
// error or a notice. The caller must escape untrusted text in a.
func (c *cli) cmdPrintf(cmd, format string, a ...any) {
	fprintf(c.stderr, "mcpmoat %s: %s\n", cmd, fmt.Sprintf(format, a...))
}

// cmdErr writes one error line on stderr, with the prefix "mcpmoat <cmd>: ":
// "what: <err>". what is fixed text from the caller. The text of err can hold
// a path from the environment or output of a server, so it is escaped.
func (c *cli) cmdErr(cmd, what string, err error) {
	c.cmdPrintf(cmd, "%s: %s", what, termsafe.Quote(err.Error()))
}

// interruptedText is the text after the prefix of the error line that scan and
// pin print when the process got a signal during the inspection, or during the
// LLM step of scan (--llm). It is fixed text.
const interruptedText = "interrupted; no pins were saved"

// warnf writes one warning line on stderr, with the prefix
// "mcpmoat <cmd>: warning: ". The caller must escape untrusted text in a.
func (c *cli) warnf(cmd, format string, a ...any) {
	fprintf(c.stderr, "mcpmoat %s: warning: %s\n", cmd, fmt.Sprintf(format, a...))
}
