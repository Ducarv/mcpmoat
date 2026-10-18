//go:build unix

package inspect_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// The tests in this file do not call t.Parallel. TestRunNoGoroutineLeak counts
// the goroutines of the whole test binary, so no other test may run at the same
// time. A test that never calls t.Parallel runs alone.

// processTreeSlack is added to every upper time bound below. The race detector
// makes the helper process start slowly, so the bounds must be generous.
const processTreeSlack = 3 * time.Second

// killWaitDelayForBound mirrors the unexported killWaitDelay (2s) of the
// package under test. It only sizes an upper bound.
const killWaitDelayForBound = 2 * time.Second

// namedMode is a fixture server: a unique name and a helper mode.
type namedMode struct{ name, mode string }

// runModes runs one helper server per entry through inspect.Run and returns
// the outcomes indexed by server name. Names must be unique.
func runModes(t *testing.T, opts inspect.Options, insp inspect.Inspector, modes ...namedMode) map[string]inspect.Outcome {
	t.Helper()
	servers := make([]discover.Server, 0, len(modes))
	for _, m := range modes {
		servers = append(servers, helperServer(t, m.name, m.mode))
	}
	outcomes, err := inspect.Run(t.Context(), servers, opts, insp)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if len(outcomes) != len(modes) {
		t.Fatalf("Run() returned %d outcomes, want %d", len(outcomes), len(modes))
	}
	byName := make(map[string]inspect.Outcome, len(outcomes))
	for _, o := range outcomes {
		byName[o.Server.Name] = o
	}
	if len(byName) != len(modes) {
		t.Fatalf("outcome names are not unique: %v", outcomes)
	}
	return byName
}

// TestRunHangTimesOut checks that a server that never answers ends with
// StatusTimeout after about opts.Timeout, and that Run returns by itself.
func TestRunHangTimesOut(t *testing.T) {
	opts := inspect.Options{Timeout: time.Second, Concurrency: 1}

	start := time.Now()
	got := runModes(t, opts, execInspector{}, namedMode{"hang", "hang"})
	elapsed := time.Since(start)

	o := got["hang"]
	if o.Status != inspect.StatusTimeout {
		t.Errorf("Status = %q, want %q (Err = %v)", o.Status, inspect.StatusTimeout, o.Err)
	}
	if !errors.Is(o.Err, context.DeadlineExceeded) {
		t.Errorf("errors.Is(Err, context.DeadlineExceeded) = false, Err = %v", o.Err)
	}
	if elapsed < opts.Timeout {
		t.Errorf("Run took %s, want at least the timeout %s", elapsed, opts.Timeout)
	}
	if limit := opts.Timeout + killWaitDelayForBound + processTreeSlack; elapsed > limit {
		t.Errorf("Run took %s, want at most %s", elapsed, limit)
	}
}

// TestRunCrashIsFailedOthersOK checks that one server that exits with an error
// does not change the outcome of the other servers (FR-06).
func TestRunCrashIsFailedOthersOK(t *testing.T) {
	opts := inspect.Options{Timeout: 10 * time.Second, Concurrency: 3}

	got := runModes(t, opts, execInspector{},
		namedMode{"crash", "crash"},
		namedMode{"slow-a", "slow"},
		namedMode{"slow-b", "slow"},
	)

	crash := got["crash"]
	if crash.Status != inspect.StatusFailed {
		t.Errorf("crash: Status = %q, want %q", crash.Status, inspect.StatusFailed)
	}
	if crash.Err == nil {
		t.Error("crash: Err = nil, want an error")
	}
	if errors.Is(crash.Err, context.DeadlineExceeded) {
		t.Errorf("crash: Err wraps DeadlineExceeded, want a plain failure: %v", crash.Err)
	}
	for _, name := range []string{"slow-a", "slow-b"} {
		o := got[name]
		if o.Status != inspect.StatusOK {
			t.Errorf("%s: Status = %q, want %q (Err = %v)", name, o.Status, inspect.StatusOK, o.Err)
		}
		if o.Err != nil {
			t.Errorf("%s: Err = %v, want nil", name, o.Err)
		}
	}
}

// TestTimeoutKillsProcessTree is the acceptance check "no process leaks" for
// issue 28. The server starts a grandchild that would live forever. After the
// timeout, the grandchild must be gone too, because the whole process group
// gets SIGKILL.
func TestTimeoutKillsProcessTree(t *testing.T) {
	// The channel has room for one PID. execInspector drops further values.
	pids := make(chan int, 1)
	// A generous timeout: under -race the helper needs about a second to start
	// and print the grandchild PID before the timeout fires.
	opts := inspect.Options{Timeout: 4 * time.Second, Concurrency: 1}

	got := runModes(t, opts, execInspector{pids: pids}, namedMode{"tree", "grandchild"})

	o := got["tree"]
	if o.Status != inspect.StatusTimeout {
		t.Fatalf("Status = %q, want %q (Err = %v)", o.Status, inspect.StatusTimeout, o.Err)
	}

	// Run has returned, so every Inspect call has returned and any PID is in
	// the buffered channel already. A non-blocking read is enough.
	var pid int
	select {
	case pid = <-pids:
	default:
		t.Fatal("no grandchild PID was reported before the timeout; the test cannot check the process tree")
	}
	if pid <= 1 {
		t.Fatalf("grandchild PID = %d, want a real PID", pid)
	}
	// The grandchild is an orphan now. init reaps it asynchronously.
	waitProcessGone(t, pid, 5*time.Second)
}

// TestConfigureProcessGroupSetsAttrs checks what ConfigureProcessGroup sets
// and what it leaves alone.
func TestConfigureProcessGroupSetsAttrs(t *testing.T) {
	t.Run("keeps existing SysProcAttr", func(t *testing.T) {
		cmd := exec.CommandContext(t.Context(), "/bin/echo", "a", "b")
		attr := &syscall.SysProcAttr{Noctty: true}
		cmd.SysProcAttr = attr
		cmd.WaitDelay = time.Millisecond
		wantPath, wantArgs := cmd.Path, slices.Clone(cmd.Args)

		inspect.ConfigureProcessGroup(cmd)

		if cmd.SysProcAttr != attr {
			t.Error("SysProcAttr pointer changed, want the same pointer")
		}
		if !cmd.SysProcAttr.Setpgid {
			t.Error("Setpgid = false, want true")
		}
		if !cmd.SysProcAttr.Noctty {
			t.Error("Noctty = false, want it kept as true")
		}
		if cmd.Cancel == nil {
			t.Error("Cancel = nil, want a function")
		}
		if cmd.WaitDelay <= time.Millisecond {
			t.Errorf("WaitDelay = %s, want the fixed delay to replace the old value", cmd.WaitDelay)
		}
		if cmd.Path != wantPath {
			t.Errorf("Path = %q, want %q", cmd.Path, wantPath)
		}
		if !slices.Equal(cmd.Args, wantArgs) {
			t.Errorf("Args = %q, want %q", cmd.Args, wantArgs)
		}
		if cmd.Env != nil {
			t.Errorf("Env = %q, want nil (unchanged)", cmd.Env)
		}
	})

	t.Run("creates SysProcAttr when nil", func(t *testing.T) {
		cmd := exec.CommandContext(t.Context(), "/bin/echo")
		if cmd.SysProcAttr != nil {
			t.Fatal("precondition: SysProcAttr must start nil")
		}

		inspect.ConfigureProcessGroup(cmd)

		if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
			t.Errorf("SysProcAttr = %+v, want Setpgid true", cmd.SysProcAttr)
		}
		if cmd.Cancel == nil {
			t.Error("Cancel = nil, want a function")
		}
		if cmd.WaitDelay <= 0 {
			t.Errorf("WaitDelay = %s, want greater than 0", cmd.WaitDelay)
		}
	})

	t.Run("keeps Env", func(t *testing.T) {
		cmd := exec.CommandContext(t.Context(), "/bin/echo")
		cmd.Env = []string{"A=1", "B=2"}
		want := slices.Clone(cmd.Env)

		inspect.ConfigureProcessGroup(cmd)

		if !slices.Equal(cmd.Env, want) {
			t.Errorf("Env = %q, want %q", cmd.Env, want)
		}
	})
}

// TestKillProcessGroupRefusesBadPID checks the PID guard.
//
// This test matters. kill(-0) signals our OWN process group, so a missing
// guard would SIGKILL the test run (and its shell). kill(-1) would signal
// every process we may signal. The guard must return an error before any
// signal is sent. Do not "test the test" by removing the guard: the test
// process would kill itself.
func TestKillProcessGroupRefusesBadPID(t *testing.T) {
	tests := []struct {
		name string
		// process builds cmd.Process. A nil process means "not started".
		process func(t *testing.T) *os.Process
	}{
		{name: "not started", process: func(*testing.T) *os.Process { return nil }},
		{name: "pid 0", process: findProcess(0)},
		{name: "pid 1", process: findProcess(1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "/bin/echo")
			cmd.Process = tt.process(t)

			err := inspect.KillProcessGroup(cmd)

			if err == nil {
				t.Fatal("KillProcessGroup() error = nil, want an error")
			}
			// ErrProcessDone would mean the guard was skipped and the kill
			// ran into ESRCH. It must be a refusal.
			if errors.Is(err, os.ErrProcessDone) {
				t.Errorf("KillProcessGroup() error = %v, want a refusal, not ErrProcessDone", err)
			}
		})
	}

	// The same guard protects the Cancel function that exec calls.
	t.Run("Cancel func refuses pid 0", func(t *testing.T) {
		cmd := exec.CommandContext(t.Context(), "/bin/echo")
		inspect.ConfigureProcessGroup(cmd)
		cmd.Process = findProcess(0)(t)

		if err := cmd.Cancel(); err == nil {
			t.Error("Cancel() error = nil, want an error")
		}
	})
}

// findProcess returns a builder for os.FindProcess(pid). It never signals the
// process. On unix FindProcess does not fail for a missing process, but on
// Linux with pidfd it may; then the case is skipped.
func findProcess(pid int) func(t *testing.T) *os.Process {
	return func(t *testing.T) *os.Process {
		t.Helper()
		p, err := os.FindProcess(pid)
		if err != nil || p == nil {
			t.Skipf("os.FindProcess(%d) cannot build a handle here: %v", pid, err)
		}
		// Release frees the handle (a pidfd on Linux). It sends no signal.
		t.Cleanup(func() { _ = p.Release() })
		return p
	}
}

// startHang starts the "hang" helper in its own process group, as
// execInspector does. The process is killed at test cleanup if the test did
// not already do it.
func startHang(t *testing.T) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}
	cmd := exec.CommandContext(t.Context(), exe, "hang") //nolint:gosec // G204: the test runs its own test binary as a fixture server
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	inspect.ConfigureProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		// Safety net if the test failed early. After Wait, Kill returns
		// ErrProcessDone and signals nothing (os.Process tracks the state),
		// so this is safe against PID reuse. t.Context is already cancelled
		// here, which kills the process too; this call is belt and braces.
		_ = cmd.Process.Kill()
	})
	return cmd
}

// TestKillProcessGroupOnRunningProcess checks the two kill paths on a live
// process: the explicit KillProcessGroup and the Cancel func that exec calls.
//
// It never calls KillProcessGroup after Wait. After Wait the OS may reuse the
// PID for another process, and kill(-pid) could then hit a stranger. The
// os.ErrProcessDone mapping (ESRCH) is therefore not tested here.
func TestKillProcessGroupOnRunningProcess(t *testing.T) {
	tests := []struct {
		name string
		kill func(cmd *exec.Cmd) error
	}{
		{name: "KillProcessGroup", kill: inspect.KillProcessGroup},
		{name: "configured Cancel", kill: func(cmd *exec.Cmd) error { return cmd.Cancel() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := startHang(t)

			if err := tt.kill(cmd); err != nil {
				t.Fatalf("kill error = %v, want nil", err)
			}

			err := cmd.Wait()
			if err == nil {
				t.Fatal("Wait() error = nil, want an error for a killed process")
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("Wait() error = %v, want *exec.ExitError", err)
			}
			ws, ok := exitErr.Sys().(syscall.WaitStatus)
			if !ok {
				t.Fatalf("ExitError.Sys() = %T, want syscall.WaitStatus", exitErr.Sys())
			}
			if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Errorf("wait status = %v, want killed by SIGKILL", ws)
			}
		})
	}
}

// TestRunNoGoroutineLeak checks that Run leaves no goroutine behind after a
// mix of a hang, a crash and a slow server.
func TestRunNoGoroutineLeak(t *testing.T) {
	baseline := runtime.NumGoroutine()

	opts := inspect.Options{Timeout: time.Second, Concurrency: 3}
	got := runModes(t, opts, execInspector{},
		namedMode{"hang", "hang"},
		namedMode{"crash", "crash"},
		namedMode{"slow", "slow"},
	)
	// Make sure the run did what the test needs: all three paths ran.
	want := map[string]inspect.Status{
		"hang":  inspect.StatusTimeout,
		"crash": inspect.StatusFailed,
	}
	for name, status := range want {
		if got[name].Status != status {
			t.Errorf("%s: Status = %q, want %q (Err = %v)", name, got[name].Status, status, got[name].Err)
		}
	}
	// "slow" needs about 1s plus start-up time, so under -race it can hit the
	// 1s timeout. Either result is fine for a leak check.
	if s := got["slow"].Status; s != inspect.StatusOK && s != inspect.StatusTimeout {
		t.Errorf("slow: Status = %q, want ok or timeout", s)
	}

	// The exec package and the runtime stop their own goroutines (pipe copiers,
	// the context watcher) a moment after Wait returns. A bounded poll is the
	// only way to see that. This is a leak check, not synchronisation.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("goroutines = %d, want at most the baseline %d\n%s", runtime.NumGoroutine(), baseline, trimStacks(string(buf)))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// trimStacks keeps a goroutine dump short enough for a test log.
func trimStacks(s string) string {
	const limit = 6000
	if len(s) > limit {
		return strings.TrimSpace(s[:limit]) + "\n... (truncated)"
	}
	return s
}
