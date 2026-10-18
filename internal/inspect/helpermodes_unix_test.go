//go:build unix

package inspect

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// This file holds the fixture servers for the process tests of Run and of the
// process-group helpers. A fixture "server" is the test binary itself,
// started again with helperModeArg and a mode (see TestMain). The tests that
// use the modes are in helperprocess_unix_test.go, proctree_unix_test.go,
// run_process_unix_test.go and proctree_stdio_test.go.

// runHelperMode runs a helper mode when args (os.Args[1:]) start with
// helperModeArg. It returns the exit code and true, or 0 and false when args
// do not ask for a helper mode.
func runHelperMode(args []string) (int, bool) {
	if len(args) == 0 || args[0] != helperModeArg {
		return 0, false
	}
	return helperMain(args[1:]), true
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
		time.Sleep(time.Second)
		fmt.Println("ready")
		return 0
	case "grandchild":
		// A grandchild that stays in the process group. Its stdout is
		// /dev/null (exec.Command with a nil Stdout).
		if code := startGrandchild(nil); code != 0 {
			return code
		}
		return hangForever()
	case "escape":
		// A hostile grandchild: it leaves the process group with a new
		// session, so the group kill misses it, and it keeps the stdout pipe
		// of the server open.
		code := startGrandchild(func(gc *exec.Cmd) {
			gc.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			gc.Stdout = os.Stdout
		})
		if code != 0 {
			return code
		}
		return hangForever()
	case "daemon":
		// A server that leaves a daemon behind: the grandchild stays in the
		// process group, and the server exits at once with success.
		return startGrandchild(nil)
	default:
		return 2
	}
}

// startGrandchild starts the test binary again in "hang" mode as a
// grandchild and prints "PID <n>" on stdout. setup, if not nil, changes the
// grandchild command before it starts. It returns 0, or an exit code for an
// error.
func startGrandchild(setup func(gc *exec.Cmd)) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper: executable:", err)
		return 1
	}
	// Plain exec.Command, not CommandContext: the grandchild must live on
	// unless a kill reaches it.
	gc := exec.Command(exe, helperModeArg, "hang") //nolint:gosec // G204: the helper starts its own test binary as a fixture grandchild
	if setup != nil {
		setup(gc)
	}
	if err := gc.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "helper: start grandchild:", err)
		return 1
	}
	// os.Stdout is not buffered, so the parent sees the line at once. We do
	// not Wait for the grandchild: only a kill may end it.
	fmt.Printf("PID %d\n", gc.Process.Pid)
	return 0
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
