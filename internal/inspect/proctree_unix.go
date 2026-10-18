//go:build unix

package inspect

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// killWaitDelay is how long Wait waits for the I/O pipes to close after the
// kill. Without it, a grandchild that holds stdout open could block Wait
// forever.
const killWaitDelay = 2 * time.Second

// ConfigureProcessGroup prepares cmd so that a timeout kills the whole child
// process tree, not only the direct child. Call it before cmd.Start, on a cmd
// made with exec.CommandContext.
//
// It makes the child lead a new process group (Setpgid), so all its children
// join that group. It sets cmd.Cancel to kill the whole group with SIGKILL.
// The exec package calls cmd.Cancel when the context is done. It also sets
// cmd.WaitDelay to a fixed value and replaces any earlier value.
//
// Other fields of cmd.SysProcAttr stay as they are. The function does not
// change cmd.Path, cmd.Args or cmd.Env, and it never adds a shell.
//
// Note: with Setpgid the child is not in the foreground process group of the
// terminal, so Ctrl-C does not reach it. The caller must cancel the context
// when the program gets a signal, so that cmd.Cancel runs.
func ConfigureProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = killWaitDelay
}

// KillProcessGroup kills the process group of cmd with SIGKILL. Use it for
// explicit cleanup, for example on a normal close.
//
// Call it only before Wait has returned. After Wait, the operating system can
// reuse the PID for another process. If the group is already gone, it returns
// os.ErrProcessDone.
func KillProcessGroup(cmd *exec.Cmd) error {
	return killGroup(cmd)
}

// killGroup sends SIGKILL to the process group led by cmd.Process.
func killGroup(cmd *exec.Cmd) error {
	// A PID of 0 or lower is not a real child. kill(-0) would signal our own
	// process group. kill(-1) would signal every process we may signal. PID 1
	// is refused for the same reason.
	if cmd.Process == nil {
		return errors.New("inspect: kill process group: process not started")
	}
	pid := cmd.Process.Pid
	if pid <= 1 {
		return fmt.Errorf("inspect: kill process group: refusing unsafe pid %d", pid)
	}
	// A negative PID means "the process group with this ID".
	err := syscall.Kill(-pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		// The group is already gone. exec treats this as fine.
		return os.ErrProcessDone
	}
	if err != nil {
		return fmt.Errorf("inspect: kill process group: %w", err)
	}
	return nil
}
