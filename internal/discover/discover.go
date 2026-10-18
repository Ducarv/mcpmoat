package discover

import (
	"context"
	"path/filepath"
)

// Options tells Discover where to look. The caller injects both directories,
// so the package never reads $HOME or the current directory by itself.
type Options struct {
	// Home is the home directory of the user. If it is empty, Discover skips
	// the files in the home directory. Discover cleans the path with
	// filepath.Clean, so "/home/me/." and "/home/me/" mean "/home/me".
	Home string

	// WorkDir is the project directory. If it is empty, Discover skips the
	// project files (.mcp.json and .cursor/mcp.json). Discover cleans the path
	// with filepath.Clean, and the cleaned path is the ProjectPath of the
	// project servers.
	WorkDir string
}

// Result is what a reader or Discover found: the servers, and the problems
// with config files or server entries.
type Result struct {
	// Servers are the servers found, in a fixed order. See [Discover].
	Servers []Server

	// Errors are the problems found, in the same file order as Servers. Each
	// error names its file.
	Errors []*FileError
}

// The user's own config files, relative to the home directory, with forward
// slashes. buildSteps reads them as the global steps of Discover, and
// globalFiles lists them for ReadConfig. homePath joins one to a home
// directory.
const (
	globalClaudeCodeFile = ".claude.json"
	globalCursorFile     = ".cursor/mcp.json"
	globalCodexFile      = ".codex/config.toml"
)

// homePath returns the path of rel, one of the global files above, below
// home.
func homePath(home, rel string) string {
	return filepath.Join(home, filepath.FromSlash(rel))
}

// step is one config file that Discover reads.
type step struct {
	// path is used for the FileError when the context is canceled before the
	// step runs.
	path string
	// untrusted is true for a project file from WorkDir. The reader marks its
	// own errors. runSteps uses untrusted only for the canceled error that it
	// makes before the step runs.
	untrusted bool
	// read reads the file with the context that runSteps passes.
	read func(context.Context) Result
}

// Discover reads the MCP server configs of Claude Code, Cursor and Codex and
// returns the servers and the problems it found.
//
// It only reads config files. It never starts a server. A file that does not
// exist is skipped without an error (FR-01). Home and WorkDir are given by the
// caller; the package never reads $HOME. An empty value skips the files that
// belong to it.
//
// The files are read in this fixed order, so the output is the same on every
// run:
//
//  1. Home/.claude.json
//  2. WorkDir/.mcp.json
//  3. Home/.cursor/mcp.json
//  4. WorkDir/.cursor/mcp.json (skipped if it is the same file as step 3)
//  5. Home/.codex/config.toml
//
// Result.Servers and Result.Errors come in this file order. Inside one file,
// they keep the order of the reader; see the package doc, Reading configs.
//
// If WorkDir and Home are the same directory, step 4 is the same file as
// step 3, so Discover reads the Cursor file once, as a global config. This
// check is lexical: Discover compares the cleaned paths as text. It does not
// detect a symlinked WorkDir, or a second name for the same directory (for
// example /var and /private/var on macOS, or a case-insensitive file
// system).
//
// Steps 2 and 4 read project files that a cloned repository can ship. Their
// servers and their errors have Untrusted set, and a symlink that leaves
// WorkDir is refused. See the package doc, Untrusted files.
//
// If ctx ends, Discover stops and returns what it has. It adds one FileError
// with the reason "canceled" for the first file that it does not read because
// ctx ended: the file that was being read, or the next file if no read had
// started. When that file is step 2 or 4, the error has Untrusted set. When
// ctx ends after the last read, or when there is no file to read, Discover
// adds no error. A caller that must know can check ctx.Err().
func Discover(ctx context.Context, opts Options) Result {
	return runSteps(ctx, buildSteps(opts))
}

// runSteps runs the steps in order and joins their results. It stops at the
// first canceled error, so the result never has two of them.
func runSteps(ctx context.Context, steps []step) Result {
	var res Result
	for _, s := range steps {
		if err := ctx.Err(); err != nil {
			fe := canceledError(s.path, err)
			fe.Untrusted = s.untrusted
			res.Errors = append(res.Errors, fe)
			return res
		}
		r := s.read(ctx)
		res.Servers = append(res.Servers, r.Servers...)
		res.Errors = append(res.Errors, r.Errors...)
		// A reader reports its own canceled error when ctx ends during the read.
		if hasCanceled(r.Errors) {
			return res
		}
	}
	return res
}

// hasCanceled reports whether errs holds a canceled error.
func hasCanceled(errs []*FileError) bool {
	for _, e := range errs {
		if e.Reason == reasonCanceled {
			return true
		}
	}
	return false
}

// buildSteps lists the files to read, in order. Each step is a small closure
// (a function that keeps the variables around it), so Discover can run all
// steps with one loop. runSteps passes the context to each step.
func buildSteps(opts Options) []step {
	// Clean the paths once. filepath.Clean("") returns ".", so an empty value
	// must stay empty: it means "skip these files".
	opts.Home = cleanDir(opts.Home)
	opts.WorkDir = cleanDir(opts.WorkDir)

	var steps []step

	if opts.Home != "" {
		path := homePath(opts.Home, globalClaudeCodeFile)
		steps = append(steps, step{path: path, read: func(ctx context.Context) Result {
			return ReadClaudeCode(ctx, path, ScopeGlobal, "")
		}})
	}
	if opts.WorkDir != "" {
		path := filepath.Join(opts.WorkDir, ".mcp.json")
		steps = append(steps, step{path: path, untrusted: true, read: func(ctx context.Context) Result {
			return ReadClaudeCode(ctx, path, ScopeProject, opts.WorkDir)
		}})
	}

	// homeCursor stays empty when Home is empty. The Cursor project path is
	// never empty, so it never equals an empty homeCursor.
	var homeCursor string
	if opts.Home != "" {
		homeCursor = homePath(opts.Home, globalCursorFile)
		steps = append(steps, step{path: homeCursor, read: func(ctx context.Context) Result {
			return ReadCursor(ctx, homeCursor, ScopeGlobal, "")
		}})
	}
	if opts.WorkDir != "" {
		path := filepath.Join(opts.WorkDir, ".cursor", "mcp.json")
		// When WorkDir is Home, this is the same file as the home Cursor
		// config: read it once, as a global config. Both paths are already
		// cleaned, so a string compare is enough. See Discover for the limits
		// of this lexical check.
		if path != homeCursor {
			steps = append(steps, step{path: path, untrusted: true, read: func(ctx context.Context) Result {
				return ReadCursor(ctx, path, ScopeProject, opts.WorkDir)
			}})
		}
	}

	if opts.Home != "" {
		path := homePath(opts.Home, globalCodexFile)
		steps = append(steps, step{path: path, read: func(ctx context.Context) Result {
			return ReadCodex(ctx, path)
		}})
	}
	return steps
}

// cleanDir cleans a directory path. It keeps the empty string empty, because
// filepath.Clean("") returns "." and that would select the current directory.
func cleanDir(dir string) string {
	if dir == "" {
		return ""
	}
	return filepath.Clean(dir)
}
