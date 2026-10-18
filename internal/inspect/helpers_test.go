package inspect

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// This file holds the test helpers that several test files of the package
// use. A helper that only one file uses stays in that file.

// skipOnWindows skips the test on Windows. Starting stdio servers is
// Unix only, and Windows is a non-goal (PRD section 2.2).
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("starting stdio servers is Unix only; Windows is a non-goal (PRD 2.2)")
	}
}

// mustWriteFile creates a file at path with the given mode. It sets the mode
// with os.Chmod after the write, so the umask does not change it.
func mustWriteFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), mode); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("os.Chmod(%q) error = %v", path, err)
	}
}

// mustMkdir creates the directory dir and its parents.
func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("os.MkdirAll(%q) error = %v", dir, err)
	}
}

// mustSymlink creates a symlink at link that points to target.
func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink(%q, %q) error = %v", target, link, err)
	}
}

// stdioServer returns a trusted global stdio server with the given command
// and args. Tests change the other fields when they need to.
func stdioServer(command string, args ...string) discover.Server {
	return discover.Server{
		Name:      "test-server",
		Client:    discover.ClientCodex,
		Scope:     discover.ScopeGlobal,
		Source:    "/home/user/.codex/config.toml",
		Transport: discover.TransportStdio,
		Command:   command,
		Args:      discover.NewArgs(args),
	}
}

// envDumpServer returns a stdio server config that runs command with
// envDumpArg as the first argument, then args, and the declared env.
func envDumpServer(command string, args []string, env discover.SecretMap) discover.Server {
	argv := make([]string, 0, len(args)+1)
	argv = append(argv, envDumpArg)
	argv = append(argv, args...)
	return discover.Server{
		Name:      "envdump",
		Transport: discover.TransportStdio,
		Command:   command,
		Args:      discover.NewArgs(argv),
		Env:       env,
	}
}

// mustExecutable creates the directory dir and an executable file name in
// it. It returns the path of the file, built with string concatenation like
// lookPath does.
func mustExecutable(t *testing.T, dir, name string) string {
	t.Helper()
	mustMkdir(t, dir)
	path := dir + "/" + name
	mustWriteFile(t, path, 0o755)
	return path
}

// secrets builds a discover.SecretMap from plain name and value pairs.
func secrets(kv map[string]string) discover.SecretMap {
	if kv == nil {
		return nil
	}
	m := make(discover.SecretMap, len(kv))
	for k, v := range kv {
		m[k] = discover.NewSecret(v)
	}
	return m
}

// envKey returns the name part of a "name=value" entry.
func envKey(entry string) string {
	name, _, _ := strings.Cut(entry, "=")
	return name
}

// objectSchema is the smallest input schema that the SDK server accepts.
func objectSchema() map[string]any {
	return map[string]any{"type": "object"}
}

func noopTool(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{}, nil
}

// onMethod returns a receiving middleware that answers method with h and
// passes every other method on.
func onMethod(method string, h mcp.MethodHandler) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, m string, req mcp.Request) (mcp.Result, error) {
			if m == method {
				return h(ctx, m, req)
			}
			return next(ctx, m, req)
		}
	}
}

// connectStdio connects the client of a stdio session (newStdioClient), with
// the raw size limit limit, to server over in-memory transports. No process
// and no network are involved. It returns the session and the rawLists and
// rawLimit of the client. t.Cleanup closes both sessions.
func connectStdio(t *testing.T, server *mcp.Server, limit int64) (*mcp.ClientSession, *rawLists, *rawLimit) {
	t.Helper()
	ctx := t.Context()
	ct, st := mcp.NewInMemoryTransports()

	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	raw, lim := &rawLists{}, &rawLimit{limit: limit}
	cs, err := newStdioClient(raw, lim).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, raw, lim
}

// noopPrompt is a prompt handler that returns an empty result.
func noopPrompt(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{}, nil
}

// noopResource is a resource handler that returns an empty result.
func noopResource(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	return &mcp.ReadResourceResult{}, nil
}
