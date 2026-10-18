//go:build unix

package inspect_test

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// The tests in this file do not call t.Parallel. They start real processes
// and measure wall time, and TestRunNoGoroutineLeak (run_process_unix_test.go)
// counts the goroutines of the whole test binary. A test that never calls
// t.Parallel runs alone.

// processTreeSlack is added to every upper time bound of the process tests.
// The race detector makes the helper process start slowly, so the bounds must
// be generous.
const processTreeSlack = 3 * time.Second

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

// TestTimeoutWithEscapedGrandchild checks the Inspector contract for pipe
// reads. The server starts a grandchild that leaves the process group and
// keeps the stdout pipe open, so the group kill misses it and the pipe never
// sees EOF. execInspector closes its end of the pipe when ctx is done, so
// Inspect, and Run, must still return at the timeout.
func TestTimeoutWithEscapedGrandchild(t *testing.T) {
	pids := make(chan int, 1)
	// The escaped grandchild survives the group kill on purpose. Kill it at
	// the end of the test, also when the test fails early.
	t.Cleanup(func() {
		select {
		case pid := <-pids:
			if pid > 1 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		default:
		}
	})

	opts := inspect.Options{Timeout: 4 * time.Second, Concurrency: 1}
	input := helperServers(t, namedMode{"escape", "escape"})
	// The goroutine only calls Run. t.Fatal must stay in the test goroutine.
	done := make(chan []inspect.Outcome, 1)
	go func() {
		outcomes, _ := inspect.Run(t.Context(), input, opts, execInspector{pids: pids})
		done <- outcomes
	}()

	limit := opts.Timeout + inspect.KillWaitDelay + processTreeSlack
	var outcomes []inspect.Outcome
	select {
	case outcomes = <-done:
	case <-time.After(limit):
		t.Fatalf("Run() did not return within %s: the pipe read did not end", limit)
	}
	if len(outcomes) != 1 {
		t.Fatalf("Run() returned %d outcomes, want 1", len(outcomes))
	}
	checkStatus(t, outcomes[0], inspect.StatusTimeout)

	// The test is only useful if the grandchild really escaped. Peek at the
	// PID and put it back for the cleanup.
	var pid int
	select {
	case pid = <-pids:
		pids <- pid
	default:
		t.Fatal("no grandchild PID was reported before the timeout; the test cannot check the escape")
	}
	if processGone(pid) {
		t.Errorf("grandchild %d is gone, want it alive: it did not leave the process group, so this test checks nothing", pid)
	}
}

// TestConfigureProcessGroupSetsAttrs checks what ConfigureProcessGroup sets
// and what it leaves alone. TestKillProcessGroupOnRunningProcess starts real
// processes with these settings.
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
		if cmd.WaitDelay != inspect.KillWaitDelay {
			t.Errorf("WaitDelay = %s, want %s to replace the old value", cmd.WaitDelay, inspect.KillWaitDelay)
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
		if cmd.WaitDelay != inspect.KillWaitDelay {
			t.Errorf("WaitDelay = %s, want %s", cmd.WaitDelay, inspect.KillWaitDelay)
		}
	})

	// setpgid(2) fails with EPERM for a session leader, so Setpgid together
	// with Setsid makes cmd.Start fail. A new session is already a new group.
	t.Run("keeps Setsid and does not add Setpgid", func(t *testing.T) {
		cmd := exec.CommandContext(t.Context(), "/bin/echo")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

		inspect.ConfigureProcessGroup(cmd)

		if !cmd.SysProcAttr.Setsid {
			t.Error("Setsid = false, want it kept as true")
		}
		if cmd.SysProcAttr.Setpgid {
			t.Error("Setpgid = true with Setsid, want false: cmd.Start would fail with EPERM")
		}
		if cmd.Cancel == nil {
			t.Error("Cancel = nil, want a function")
		}
	})

	// A non-zero Pgid would put the child into an existing group, and the
	// group kill would then miss it.
	t.Run("resets Pgid", func(t *testing.T) {
		cmd := exec.CommandContext(t.Context(), "/bin/echo")
		cmd.SysProcAttr = &syscall.SysProcAttr{Pgid: 12345}

		inspect.ConfigureProcessGroup(cmd)

		if cmd.SysProcAttr.Pgid != 0 {
			t.Errorf("Pgid = %d, want 0", cmd.SysProcAttr.Pgid)
		}
		if !cmd.SysProcAttr.Setpgid {
			t.Error("Setpgid = false, want true")
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
// execInspector does. attr is the SysProcAttr before ConfigureProcessGroup;
// nil means none. The process is killed at test cleanup if the test did not
// already do it.
func startHang(t *testing.T, attr *syscall.SysProcAttr) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}
	cmd := exec.CommandContext(t.Context(), exe, "hang") //nolint:gosec // G204: the test runs its own test binary as a fixture server
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.SysProcAttr = attr
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
// It runs each path with a plain command and with a command that already asks
// for a new session (Setsid), as the stdio command of issue #27 does. In both
// cases the child must start and must lead its own process group.
//
// It never calls KillProcessGroup after Wait. After Wait the OS may reuse the
// PID for another process, and kill(-pid) could then hit a stranger. The
// os.ErrProcessDone mapping (ESRCH) is therefore not tested here.
func TestKillProcessGroupOnRunningProcess(t *testing.T) {
	kills := []struct {
		name string
		kill func(cmd *exec.Cmd) error
	}{
		{name: "KillProcessGroup", kill: inspect.KillProcessGroup},
		{name: "configured Cancel", kill: func(cmd *exec.Cmd) error { return cmd.Cancel() }},
	}
	attrs := []struct {
		name string
		attr func() *syscall.SysProcAttr
	}{
		{name: "no SysProcAttr", attr: func() *syscall.SysProcAttr { return nil }},
		{name: "Setsid", attr: func() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }},
	}
	for _, k := range kills {
		for _, a := range attrs {
			t.Run(k.name+" with "+a.name, func(t *testing.T) {
				cmd := startHang(t, a.attr())

				pgid, err := syscall.Getpgid(cmd.Process.Pid)
				if err != nil {
					t.Fatalf("Getpgid(%d) error = %v", cmd.Process.Pid, err)
				}
				if pgid != cmd.Process.Pid {
					t.Errorf("process group = %d, want the child PID %d", pgid, cmd.Process.Pid)
				}

				checkKilledBySIGKILL(t, cmd, k.kill)
			})
		}
	}
}

// checkKilledBySIGKILL calls kill on the running cmd and checks that Wait
// reports a death by SIGKILL.
func checkKilledBySIGKILL(t *testing.T, cmd *exec.Cmd, kill func(cmd *exec.Cmd) error) {
	t.Helper()
	if err := kill(cmd); err != nil {
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
}
