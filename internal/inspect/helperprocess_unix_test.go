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

// This file holds the fixture MCP servers for the inspect tests. The real MCP
// connection does not exist yet, so a fixture "server" is the test binary
// itself, started again in a helper mode (the os/exec helper-process pattern).
// The mode is the first argument after the binary name. The environment
// variable below tells TestMain to run the helper instead of the tests.

// helperEnv is the environment variable that switches the test binary into
// helper mode.
const helperEnv = "MCPMOAT_INSPECT_HELPER"

// TestMain runs the helper when helperEnv is set, and the tests otherwise.
//
// In helper mode it never calls m.Run, so the testing package does not parse
// the helper arguments as test flags.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		os.Exit(helperMain(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// helperMain runs one helper mode and returns the process exit code.
func helperMain(args []string) int {
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "hang":
		// A hung server never answers. Block until a kill ends the process.
		return hangForever()
	case "crash":
		// A server that fails on start.
		fmt.Fprintln(os.Stderr, "helper: crash on start")
		return 3
	case "slow":
		// This sleep is simulated start-up work inside the fixture. It is not
		// test synchronisation.
		time.Sleep(1 * time.Second)
		fmt.Println("ready")
		return 0
	case "grandchild":
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper: executable:", err)
			return 1
		}
		// Plain exec.Command, not CommandContext: the grandchild must live on
		// unless the kill of the whole process group reaches it. The child
		// inherits the environment, so it also runs in helper mode.
		gc := exec.Command(exe, "hang") //nolint:gosec // G204: the helper starts its own test binary as a fixture grandchild
		if err := gc.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "helper: start grandchild:", err)
			return 1
		}
		// os.Stdout is not buffered, so the parent sees the line at once. We
		// do not Wait: the grandchild must outlive nothing but the group kill.
		fmt.Printf("PID %d\n", gc.Process.Pid)
		return hangForever()
	default:
		return 2
	}
}

// hangForever blocks until the process is killed.
//
// A bare select{} does not work here: with no other goroutine the Go runtime
// sees a deadlock and exits with code 2. A pending timer avoids that.
func hangForever() int {
	for {
		time.Sleep(time.Hour)
	}
}

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
		Args:      discover.NewArgs([]string{mode}),
	}
}

// execInspector is an inspect.Inspector that runs the server as a child
// process and waits for it to exit. It reads no MCP content.
//
// It is safe for concurrent use.
type execInspector struct {
	// pids receives the PID of a grandchild when the server prints a line
	// "PID <n>". It may be nil. The channel should be buffered: Inspect never
	// blocks on it and drops the value when the channel is full.
	pids chan<- int
}

// Inspect starts the server in its own process group and waits until it exits.
// A server killed because ctx is done gives a non-nil error.
func (e execInspector) Inspect(ctx context.Context, s discover.Server) (inspect.Result, error) {
	cmd := exec.CommandContext(ctx, s.Command, s.Args.Values()...) //nolint:gosec // G204: the test runs its own test binary as a fixture server
	// The test's own environment plus the helper switch. Scrubbing the
	// environment is issue #27.
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	inspect.ConfigureProcessGroup(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return inspect.Result{}, fmt.Errorf("execInspector: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return inspect.Result{}, fmt.Errorf("execInspector: start: %w", err)
	}

	// Read to EOF before Wait, as the exec package requires for a pipe. EOF
	// comes when the server and all its children close stdout, or when the
	// group kill ends them. No goroutine is left behind.
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
