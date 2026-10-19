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

// The names that the clients use for their files and directories.
const (
	// projectClaudeCodeFile is the Claude Code project file in a project
	// directory: <WorkDir>/.mcp.json.
	projectClaudeCodeFile = ".mcp.json"
	// cursorDir is the directory of a Cursor config, in the home directory
	// and in a project directory: .cursor/mcp.json.
	cursorDir = ".cursor"
	// cursorFile is the name of a Cursor config in cursorDir.
	cursorFile = "mcp.json"
	// codexDir is the directory of a Codex config: .codex/config.toml.
	codexDir = ".codex"
	// codexFile is the name of a Codex config in codexDir.
	codexFile = "config.toml"
)

// The user's own config files, relative to the home directory, with forward
// slashes. The globalFile values below pair each one with its reader.
const (
	globalClaudeCodeFile = ".claude.json"
	globalCursorFile     = cursorDir + "/" + cursorFile
	globalCodexFile      = codexDir + "/" + codexFile
)

// globalFile is one of the user's own config files, and the read that
// ReadConfig does for it. Discover uses the same read for Cursor and Codex;
// for ~/.claude.json it calls readGlobalClaudeCodeState instead (see the
// globalClaudeCode var).
type globalFile struct {
	rel  string // one of the global file constants, such as globalCodexFile
	read func(ctx context.Context, path string) Result
}

// path returns the path of the global file below home.
func (g globalFile) path(home string) string {
	return filepath.Join(home, filepath.FromSlash(g.rel))
}

// The user's own config files, each with the reader and the scope that
// Discover uses for it. buildSteps uses them for the global steps of
// Discover, and globalFor finds them for ReadConfig through globalFiles, so
// both use one list of paths, scopes and readers. No code writes to them.
//
// One difference: for ~/.claude.json, Discover calls
// readGlobalClaudeCodeState with its WorkDir, not globalClaudeCode.read.
// ReadConfig knows no WorkDir, so the State of a top-level server can differ
// in two ways:
//
//   - In Discover, the projects.<WorkDir>.disabledMcpServers list can give
//     it StateDisabled. In ReadConfig it keeps StateEnabled.
//   - In Discover, it gets StateUnapproved when the projects.<WorkDir> state
//     cannot be read (see readGlobalClaudeCodeState). In ReadConfig it keeps
//     StateEnabled.
//
// The servers, the errors and all other fields are the same.
var (
	globalClaudeCode = globalFile{globalClaudeCodeFile, readGlobalClaudeCode}
	globalCursor     = globalFile{globalCursorFile, readGlobalCursor}
	globalCodex      = globalFile{globalCodexFile, ReadCodex}
)

// globalFiles lists the global files above, in the order of the global steps
// of Discover (TestBuildStepsGlobalFiles checks this). No code writes to it.
var globalFiles = [...]globalFile{globalClaudeCode, globalCursor, globalCodex}

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
//  2. WorkDir/.mcp.json, then the Claude Code settings files (see State
//     below)
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
// State: each server gets the State that its client config gives it. For
// Claude Code, Discover joins data from more than one file:
//
//   - Step 1 reads the projects.<WorkDir> object of Home/.claude.json. Its
//     disabledMcpServers list gives StateDisabled to the top-level servers
//     of that file. The servers of projects.<path>.mcpServers get the state
//     of their own project. The project key must match WorkDir as given or
//     WorkDir with its symlinks resolved (see readGlobalClaudeCodeState).
//   - Step 1 fails closed. When the file exists but its projects section
//     could not be read to the end (for example the file is refused as a
//     whole), or when a projects.<WorkDir> object has an error, a
//     top-level server with StateEnabled gets StateUnapproved: mcpmoat
//     cannot confirm that the project does not turn it off.
//   - Step 2, only when WorkDir/.mcp.json has servers, also reads the
//     settings files WorkDir/.claude/settings.local.json and
//     WorkDir/.claude/settings.json (untrusted, confined to WorkDir) and
//     Home/.claude/settings.json (trusted). Each .mcp.json server gets
//     StateEnabled, StateProjectApproved, StateDisabled or StateUnapproved
//     from the approval lists of these files and of the projects.<WorkDir>
//     object (see mcpjsonState). An approval only from the untrusted project
//     settings files gives StateProjectApproved, not StateEnabled. A
//     settings file that is missing gives no setting. A settings file with
//     an error gives no setting and one FileError, after the errors of
//     .mcp.json. The errors of the project settings files have Untrusted
//     set. When WorkDir is Home, WorkDir/.claude/settings.json is the user
//     file: it is read once, as the trusted user file.
//   - Step 2 fails closed. When a settings file has an error, or step 1
//     could not read the projects.<WorkDir> state, no .mcp.json server keeps
//     an approval: a server with StateEnabled or StateProjectApproved gets
//     StateUnapproved, and StateDisabled stays. The FileError tells the user
//     why (see setMcpjsonStates).
//
// A cloned repository can ship settings files that approve its own .mcp.json
// servers. Such an approval gives only StateProjectApproved, which inspect
// treats as StateUnapproved, and the servers stay Untrusted.
//
// If ctx ends, Discover stops and returns what it has. It adds one FileError
// with the reason "canceled" for the first file that it does not read because
// ctx ended: the file that was being read, or the next file if no read had
// started. The error has Untrusted set when that file is untrusted: a
// project file of step 2 or 4, or a settings file in WorkDir. When ctx ends
// after the last read, or when there is no file to read, Discover adds no
// error. A caller that must know can check ctx.Err().
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
// steps with one loop. runSteps passes the context to each step. The global
// steps take their path and their reader from the globalFile values
// (globalClaudeCode, globalCursor and globalCodex), so ReadConfig reads a
// global file as Discover does. The one difference is the Claude Code step,
// which also uses WorkDir (see the globalFile values).
func buildSteps(opts Options) []step {
	// Clean the paths once. filepath.Clean("") returns ".", so an empty value
	// must stay empty: it means "skip these files".
	opts.Home = cleanDir(opts.Home)
	opts.WorkDir = cleanDir(opts.WorkDir)

	var steps []step
	// addGlobal adds the step of the global file g, when Home is set.
	addGlobal := func(g globalFile) {
		if opts.Home == "" {
			return
		}
		path := g.path(opts.Home)
		steps = append(steps, step{path: path, read: func(ctx context.Context) Result {
			return g.read(ctx, path)
		}})
	}

	// legacyState is the projects.<WorkDir> state of ~/.claude.json, and
	// legacyFailed tells that this state could not be read (see
	// readGlobalClaudeCodeState). The Claude Code step writes them and the
	// .mcp.json step reads them. Both closures capture the same variables. runSteps
	// calls the steps one after the other in one goroutine, in the order of
	// steps, so the write always happens before the read and there is no
	// data race. If a later change runs the steps in parallel, these
	// variables need a sync, or the .mcp.json step must wait for the Claude
	// Code step. When Home is empty, or ctx ends before the Claude Code
	// step, the state stays zero and legacyFailed stays false.
	var legacyState claudeProjectState
	var legacyFailed bool
	if opts.Home != "" {
		path := globalClaudeCode.path(opts.Home)
		steps = append(steps, step{path: path, read: func(ctx context.Context) Result {
			res, st, failed := readGlobalClaudeCodeState(ctx, path, opts.WorkDir)
			legacyState, legacyFailed = st, failed
			return res
		}})
	}
	if opts.WorkDir != "" {
		path := filepath.Join(opts.WorkDir, projectClaudeCodeFile)
		steps = append(steps, step{path: path, untrusted: true, read: func(ctx context.Context) Result {
			res := ReadClaudeCode(ctx, path, ScopeProject, opts.WorkDir)
			// The settings files only matter for .mcp.json servers, so they
			// are not read when there are none.
			if len(res.Servers) == 0 {
				return res
			}
			errs := setMcpjsonStates(ctx, res.Servers, opts.Home, opts.WorkDir, legacyState, legacyFailed)
			res.Errors = append(res.Errors, errs...)
			return res
		}})
	}

	addGlobal(globalCursor)
	if opts.WorkDir != "" {
		// homeCursor stays empty when Home is empty. The Cursor project path
		// is never empty, so it never equals an empty homeCursor.
		var homeCursor string
		if opts.Home != "" {
			homeCursor = globalCursor.path(opts.Home)
		}
		path := filepath.Join(opts.WorkDir, cursorDir, cursorFile)
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

	addGlobal(globalCodex)
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
