//go:build !unix

package inspect

import (
	"errors"
	"os/exec"
)

// configureProcessGroup prepares cmd so that a timeout kills the direct child.
// Call it before cmd.Start, on a cmd made with exec.CommandContext.
//
// On this platform the helper cannot kill grandchildren. mcpmoat supports only
// macOS and Linux; this file only keeps other systems compiling.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = killWaitDelay
}

// killProcessGroup kills the direct child of cmd. It cannot kill grandchildren
// on this platform. If the process is already gone, it returns
// os.ErrProcessDone.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return errors.New("inspect: kill process: process not started")
	}
	return cmd.Process.Kill()
}
