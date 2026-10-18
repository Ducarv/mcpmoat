//go:build !unix

package inspect

import (
	"errors"
	"os/exec"
	"time"
)

// killWaitDelay is how long Wait waits for the I/O pipes to close after the
// kill. It has the same value as in proctree_unix.go.
const killWaitDelay = 2 * time.Second

// ConfigureProcessGroup prepares cmd so that a timeout kills the direct child.
// Call it before cmd.Start, on a cmd made with exec.CommandContext.
//
// On this platform the helper cannot kill grandchildren. mcpmoat supports only
// macOS and Linux; this file only keeps other systems compiling.
func ConfigureProcessGroup(cmd *exec.Cmd) {
	cmd.Cancel = func() error { return killProcess(cmd) }
	cmd.WaitDelay = killWaitDelay
}

// KillProcessGroup kills the direct child of cmd. It cannot kill grandchildren
// on this platform. If the process is already gone, it returns
// os.ErrProcessDone.
func KillProcessGroup(cmd *exec.Cmd) error {
	return killProcess(cmd)
}

// killProcess kills cmd.Process and returns the error of Kill as is.
func killProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return errors.New("inspect: kill process: process not started")
	}
	return cmd.Process.Kill()
}
