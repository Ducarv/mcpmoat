//go:build unix

package inspect_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// This file holds the test helpers for the process tests in this external
// test package. The fixture servers themselves (the helper modes) are in
// helpermodes_unix_test.go in package inspect, because the one TestMain of
// the test binary is there. A command runs a mode with the arguments
// inspect.HelperModeArg and the mode name.

// The tests that start helper processes in this package (proctree_unix_test.go
// and run_process_unix_test.go) do not call t.Parallel. They measure wall time,
// and TestRunNoGoroutineLeak counts the goroutines of the whole test binary,
// so no other test may run at the same time. A test that never calls
// t.Parallel runs alone.

const (
	// processTreeSlack is added to the upper time bound of a process test.
	// The race detector makes the helper process start slowly, so the bounds
	// must be generous.
	processTreeSlack = 3 * time.Second
	// reapLimit is how long a test waits for something that the operating
	// system or the runtime does a moment later: init reaps an orphan, and
	// exec stops its goroutines after Wait.
	reapLimit = 5 * time.Second
)

// helperServer returns a stdio discover.Server that runs the test binary in
// the given helper mode.
func helperServer(t testing.TB, name, mode string) discover.Server {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}
	return discover.Server{
		Name:      name,
		Client:    discover.ClientClaudeCode,
		Source:    "/test/helper/.mcp.json",
		Transport: discover.TransportStdio,
		Command:   exe,
		Args:      discover.NewArgs([]string{inspect.HelperModeArg, mode}),
	}
}

// helperCommand returns a command that runs the test binary at path with
// args, in its own process group, as a stdio inspector starts a server. For a
// helper mode, args start with inspect.HelperModeArg. attr is the SysProcAttr
// before ConfigureProcessGroup; nil means none.
//
// The child inherits the environment of the test. The scrubbed environment
// of stdioCommand is checked in package inspect (proctree_stdio_test.go and
// the stdio tests); the stdio Inspector of issue #25 joins the two.
func helperCommand(ctx context.Context, path string, attr *syscall.SysProcAttr, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // G204: the test runs its own test binary as a fixture server
	cmd.SysProcAttr = attr
	inspect.ConfigureProcessGroup(cmd)
	return cmd
}

// execInspector is an inspect.Inspector that runs the server as a child
// process. It reads stdout to EOF, kills the process group and then waits for
// the child. It reads no MCP content. It follows the
// Inspector contract the way a real stdio inspector must: its own process
// group, a pipe read that ends when ctx is done, and a group kill before Wait.
//
// It is safe for concurrent use.
type execInspector struct {
	// pids receives the PID of a grandchild when the server prints a line
	// "PID <n>". It may be nil. The channel should be buffered: Inspect never
	// blocks on it and drops the value when the channel is full.
	pids chan<- int
}

// Inspect starts the server in its own process group, reads its stdout to EOF,
// kills the group and then waits for the child. A server killed because ctx is
// done gives a non-nil error.
func (e execInspector) Inspect(ctx context.Context, s discover.Server) (inspect.Result, error) {
	cmd := helperCommand(ctx, s.Command, nil, s.Args.Values()...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return inspect.Result{}, fmt.Errorf("execInspector: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return inspect.Result{}, fmt.Errorf("execInspector: start: %w", err)
	}

	// The group kill does not reach a process that left the group. Such a
	// process can keep stdout open, and then the read below never sees EOF.
	// So close our end of the pipe when ctx is done: the read then returns at
	// once. stop removes the callback when Inspect returns first.
	stop := context.AfterFunc(ctx, func() { _ = stdout.Close() })
	defer stop()

	// Read to EOF before Wait, as the exec package requires for a pipe. EOF
	// comes when the server and all its children close stdout, or when the
	// group kill ends them. The read also ends when the callback above closes
	// the pipe. No goroutine is left behind.
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		rest, ok := strings.CutPrefix(scanner.Text(), "PID ")
		if !ok || e.pids == nil {
			continue
		}
		pid, err := strconv.Atoi(rest)
		if err != nil {
			continue
		}
		select {
		case e.pids <- pid:
		default:
		}
	}

	// Stop the members that stay in the group, for example a daemon that the
	// server started, also when the server exited with success. Wait has not
	// reaped the child yet, so its PID is still taken and the kill cannot
	// reach another process. The error is not useful here: on macOS the kill
	// fails with EPERM when only the exited child is left in the group. Wait
	// must run in every case, or the child stays a zombie and exec leaves a
	// goroutine behind.
	_ = inspect.KillProcessGroup(cmd)

	if err := cmd.Wait(); err != nil {
		return inspect.Result{}, fmt.Errorf("execInspector: wait: %w", err)
	}
	return inspect.Result{}, nil
}

// processGone reports whether the process pid no longer exists, or is only a
// zombie that waits to be reaped. A process we may not signal (EPERM) still
// exists, so it is not gone.
func processGone(pid int) bool {
	err := syscall.Kill(pid, 0)
	if errors.Is(err, syscall.ESRCH) {
		return true
	}
	if err != nil {
		return false
	}
	// The PID still exists. It may be a zombie that init has not reaped yet.
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output() //nolint:gosec // G204: fixed program "ps", the only variable argument is an integer PID
	if err != nil {
		// If ps fails we cannot tell the state of the process. Report "not
		// gone" so a leak is never hidden: waitProcessGone keeps polling and
		// fails the test if the process stays.
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(string(out)), "Z")
}

// waitProcessGone fails the test if the process pid still exists after limit.
func waitProcessGone(t testing.TB, pid int, limit time.Duration) {
	t.Helper()
	// An orphan is reaped by init asynchronously, so a bounded poll is the
	// only option. This is not synchronisation between our own goroutines.
	deadline := time.Now().Add(limit)
	for {
		if processGone(pid) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d still exists after %s", pid, limit)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
