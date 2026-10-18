// The syscall package has Getpgid only on these systems, not on every Unix
// (for example not on Solaris or AIX). So this test has its own file with a
// narrower build constraint than sysproc_unix_test.go.

//go:build darwin || freebsd || linux || netbsd || openbsd

package inspect

import (
	"io"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// Sizes of the filler args in TestStdioChildNewProcessGroup. The child
// writes its argv to stdout, so its dump is larger than procFillerArgs times
// procFillerArgSize (256 KiB). That is more than the default pipe buffer
// (64 KiB on Linux and macOS). Each arg stays below the 128 KiB limit that
// Linux puts on one argv string, and the total stays far below ARG_MAX.
const (
	procFillerArgs    = 8
	procFillerArgSize = 32 << 10
)

// TestStdioChildNewProcessGroup starts the env dump child with a command
// from stdioCommand and checks that the child leads a new process group: its
// process group ID is equal to its PID. setsid(2) makes the caller the
// leader of a new session and of a new process group, so this proves that
// the Setsid attribute reached the operating system. Without Setsid, the
// child stays in the process group of the test binary.
//
// The check must run while the child is alive. The child does not read
// stdin, so a stdin pipe does not stop it. Instead, the test gives the child
// argv strings that make its JSON dump larger than the stdout pipe buffer,
// and it does not read stdout until after the check. So the child blocks in
// its write to stdout and cannot exit. No time.Sleep is needed.
func TestStdioChildNewProcessGroup(t *testing.T) {
	t.Parallel()

	args := make([]string, procFillerArgs)
	for i := range args {
		args[i] = strings.Repeat(string(rune('a'+i)), procFillerArgSize)
	}
	s := procServer(envDumpExe(t), args, nil)
	cmd, err := stdioCommand(s, stdioOptions{FallbackDir: t.TempDir()})
	if err != nil {
		t.Fatalf("stdioCommand() error = %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("cmd.StdoutPipe() error = %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() error = %v", err)
	}

	// If the test fails before it reads stdout, the child stays blocked in
	// its write. The cleanup stops it and reaps it, so no process outlives
	// the test.
	waited := false
	t.Cleanup(func() {
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
		t.Errorf("child process group = %d, want %d (the child PID); parent process group = %d",
			pgid, pid, syscall.Getpgrp())
	}

	// Now let the child finish. The dump must hold the filler args, so the
	// child was the env dump fixture and it was blocked as planned.
	out, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatalf("read child stdout error = %v", err)
	}
	waited = true
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child process error = %v", err)
	}
	if len(out) <= procFillerArgs*procFillerArgSize {
		t.Errorf("child stdout = %d bytes, want more than %d bytes", len(out), procFillerArgs*procFillerArgSize)
	}
	dump := decodeEnvDump(t, out)
	if len(dump.Args) < 2 || !reflect.DeepEqual(dump.Args[2:], args) {
		// Only the count: each arg is 32 KiB of filler.
		t.Errorf("child got %d args, want envDumpArg plus %d filler args", len(dump.Args)-1, len(args))
	}
}
