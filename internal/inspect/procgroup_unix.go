//go:build unix

package inspect

import "syscall"

// killGroup sends SIGKILL to the process group pgid. The child that
// stdioCommand builds starts a new session (detachSysProcAttr), so it leads
// its own process group, and pgid is its PID. The signal also reaches the
// processes that the child started and that stayed in the group (for
// example node, started by npx). A process that left the group is not
// stopped.
//
// pgid must be the PID of such a child. A pgid of 0 or 1 is ignored: kill
// with -0 would signal the group of mcpmoat, and -1 every process of the
// user. An error (for example ESRCH: the group is empty) is ignored.
func killGroup(pgid int) {
	if pgid <= 1 {
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}
