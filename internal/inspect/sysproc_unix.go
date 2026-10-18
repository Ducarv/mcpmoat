//go:build unix

package inspect

import "syscall"

// detachSysProcAttr returns the process attributes that stdioCommand puts in
// cmd.SysProcAttr.
//
// Setsid makes the child call setsid(2) before it runs the command. So the
// child starts in a new session with no controlling terminal. GUI clients
// also give servers no terminal, so this matches the client.
//
// No controlling terminal is defence in depth, not a guarantee:
//   - Opening /dev/tty fails.
//   - Signals from the terminal (Ctrl-C, SIGHUP) do not reach the child.
//   - TIOCSTI input injection fails, because it needs a controlling
//     terminal.
//
// But the terminal device of the user (/dev/pts/N on Linux, /dev/ttysNNN on
// macOS) is owned by the user. A server that runs as the same user can
// find its path (from /proc/<ppid>/fd, from ps -o tty or from a list of
// /dev/pts) and open it. Then it can write escape sequences or read
// keystrokes. So the caller must never connect cmd.Stdout or cmd.Stderr to
// the terminal of the user (see stdioCommand).
//
// Setsid also makes the child the leader of a new process group, with a
// group ID equal to its PID. So the caller (killProcessGroup, from
// stdioProcess in stdioproc.go) can stop the process group with
// syscall.Kill(-pid, syscall.SIGKILL). This code does not
// send that signal; the caller does. The signal reaches only the processes
// that are still in the group. That includes the descendants that stay in
// it (for example npx, then node). A process that leaves the group on
// purpose (with setsid, setpgid or a double fork) is not stopped. This is
// not a sandbox.
//
// Side effect: a Ctrl-C in the terminal sends SIGINT only to the foreground
// process group of the terminal. The child is not in that group, so it does
// not get the signal. The caller must stop the child when the context is
// cancelled: stdioProcess in stdioproc.go kills the process group then.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
