// The syscall package has Getpgid only on these systems, not on every Unix.
// See sysproc_pgid_test.go.

//go:build darwin || freebsd || linux || netbsd || openbsd

package inspect

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// TestKillProcessGroupOnStdioCommand joins the two halves of the stdio start:
// a child from stdioCommand (scrubbed environment, Setsid) and the group kill
// of killProcessGroup. The child must run the helper mode (so the helper
// argument survives the scrubbed environment), lead its own process group,
// and die by SIGKILL.
//
// The test does not call configureProcessGroup: stdioCommand uses
// exec.Command, and exec refuses a Cancel on a Cmd without a context. The
// stdio Inspector of issue #25 must build the Cmd with a context first.
func TestKillProcessGroupOnStdioCommand(t *testing.T) {
	s := discover.Server{
		Name:      "hang",
		Transport: discover.TransportStdio,
		Command:   envDumpExe(t),
		Args:      discover.NewArgs([]string{helperModeArg, "hang"}),
	}
	cmd, err := stdioCommand(s, stdioOptions{FallbackDir: t.TempDir()})
	if err != nil {
		t.Fatalf("stdioCommand() error = %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() error = %v", err)
	}
	waited := false
	t.Cleanup(func() {
		// If the test fails before Wait, stop the child and reap it.
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	pid := cmd.Process.Pid
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("syscall.Getpgid(%d) error = %v", pid, err)
	}
	if pgid != pid {
		t.Errorf("child process group = %d, want the child PID %d", pgid, pid)
	}

	if err := killProcessGroup(cmd); err != nil {
		t.Fatalf("killProcessGroup() error = %v", err)
	}
	err = cmd.Wait()
	waited = true

	// A hang child only ends by a signal. An exit with a code would mean that
	// it did not run the helper mode.
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
