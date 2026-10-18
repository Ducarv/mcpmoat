//go:build unix

package inspect

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// configureProcessGroup prepares cmd so that a timeout kills the process group
// of the child, not only the direct child. Call it before cmd.Start, on a cmd
// made with exec.CommandContext.
//
// The child leads a new process group with a group ID equal to its PID. Its
// children join that group unless they leave it. If cmd.SysProcAttr.Setsid is
// already set, the new session already gives the child a new group, so the
// function clears Setpgid: setpgid(2) fails with EPERM for a session leader,
// and cmd.Start would fail. Otherwise it sets Setpgid. It always sets Pgid to
// 0, so the child never joins an existing group.
//
// It sets cmd.Cancel to kill the whole group with SIGKILL. The exec package
// calls cmd.Cancel when the context is done. It also sets cmd.WaitDelay to
// killWaitDelay and replaces any earlier value.
//
// The kill reaches only the processes that are still in the group. A process
// that leaves the group on purpose (with setsid, setpgid or a double fork)
// lives on. This is not a sandbox.
//
// Other fields of cmd.SysProcAttr stay as they are. The function does not
// change cmd.Path, cmd.Args or cmd.Env, and it never adds a shell.
//
// Note: the child is not in the foreground process group of the terminal, so
// Ctrl-C does not reach it. The caller must cancel the context when the
// program gets a signal, so that cmd.Cancel runs.
func configureProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = !cmd.SysProcAttr.Setsid
	cmd.SysProcAttr.Pgid = 0
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = killWaitDelay
}

// killProcessGroup sends SIGKILL to the process group led by cmd.Process. Use
// it for explicit cleanup too: on a normal close, call it before cmd.Wait (see
// the Inspector contract). Until Wait reaps the child, its PID stays taken,
// also after the child has exited. On macOS, the kill fails with EPERM when
// every member of the group has exited but the child is not reaped yet, so
// on a normal close an error does not mean that a process is left.
//
// After Wait has reaped the child, the operating system can give its PID to a
// new process. So the function first asks the process handle: after Wait, it
// sends no signal and returns os.ErrProcessDone. If the group is already gone,
// it also returns os.ErrProcessDone.
//
// One small window is left. The exec package can call cmd.Cancel while Wait
// reaps the child, so the reap can come between the check and the kill. The
// kill then reaches a group whose leader is gone. While other members are
// alive, the group ID stays taken and the kill reaches only them. With no
// member left, a new process would have to take the PID and lead a group with
// it within microseconds, so this risk is accepted.
func killProcessGroup(cmd *exec.Cmd) error {
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
	// Signal 0 sends nothing. Through the handle, it returns
	// os.ErrProcessDone once Wait has reaped the child.
	if err := cmd.Process.Signal(syscall.Signal(0)); errors.Is(err, os.ErrProcessDone) {
		return os.ErrProcessDone
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
