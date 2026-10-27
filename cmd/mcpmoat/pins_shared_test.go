package main

// In-process tests of readPinsLocked (pins_shared.go), the locked read of
// pins.json that scan and pin both use before they save. scan and pin check
// for a signal (cli.interrupted) before they call it, so a run of the whole
// command never reaches readPinsLocked with an ended context. These tests
// call it directly.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestReadPinsLockedContextError checks which message readPinsLocked prints
// when its context has ended. Only a context error from pins.LoadLocked means
// a signal, so only then does it print interruptedText. A file error stays a
// file error, also when the context has ended: the normal "cannot read the
// pins file" line, and no interrupted line. In every case ok is false, the
// store is nil and release is callable.
//
// The file error is a pins directory that the group and others can write.
// LoadLocked checks the directory before it takes the lock, so it returns
// that error even with an ended context. (A corrupt pins.json does not work
// here: LoadLocked reads the file only after the lock, and the lock step
// returns the context error first.)
func TestReadPinsLockedContextError(t *testing.T) {
	t.Parallel()

	cancelled := func(t *testing.T) context.Context {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		return ctx
	}
	expired := func(t *testing.T) context.Context {
		ctx, cancel := context.WithDeadline(t.Context(), time.Unix(0, 0))
		t.Cleanup(cancel)
		return ctx
	}
	// unsafeDir makes a pins directory that the group and others can write,
	// so LoadLocked refuses it before it takes the lock.
	unsafeDir := func(t *testing.T, e *pinEnv) {
		if err := os.MkdirAll(filepath.Dir(e.pinsPath()), 0o700); err != nil {
			t.Fatal(err)
		}
		setPinsMode(t, e, pinsKindDir, 0o777)
	}

	tests := []struct {
		name string
		ctx  func(t *testing.T) context.Context
		// setup prepares the pins directory of e. nil leaves no pins
		// directory, a first run.
		setup func(t *testing.T, e *pinEnv)
		// wait is cli.pinsLockWait.
		wait time.Duration
		// wantErr is true when the read error line is wanted, and false when
		// the interrupted line is wanted.
		wantErr bool
	}{
		{
			name: "cancelled, free lock",
			ctx:  cancelled,
		},
		{
			name: "deadline exceeded, free lock",
			ctx:  expired,
		},
		{
			name:  "cancelled, existing pins file",
			ctx:   cancelled,
			setup: func(t *testing.T, e *pinEnv) { firstScan(t, e, mkTool("a", "Add.")) },
		},
		{
			// The context ends before the wait, so the run says
			// "interrupted" and not that the lock is held.
			name:  "cancelled, lock held by another process",
			ctx:   cancelled,
			setup: func(t *testing.T, e *pinEnv) { holdPinsLock(t, e.pinsPath()) },
			wait:  time.Minute,
		},
		{
			name:    "cancelled, unsafe pins directory",
			ctx:     cancelled,
			setup:   unsafeDir,
			wantErr: true,
		},
		{
			// The control: the same file error with a live context.
			name:    "live context, unsafe pins directory",
			ctx:     func(t *testing.T) context.Context { return t.Context() },
			setup:   unsafeDir,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		for _, cmd := range []string{"scan", "pin"} {
			t.Run(tt.name+"/"+cmd, func(t *testing.T) {
				t.Parallel()
				e := newPinEnv(t, oneServer("srv"))
				if tt.setup != nil {
					tt.setup(t, e)
				}
				c, stdout, stderr := e.cli(nil)
				c.pinsLockWait = tt.wait
				prefix := "mcpmoat " + cmd + ": "

				store, release, ok := c.readPinsLocked(tt.ctx(t), cmd)
				release()

				if ok || store != nil {
					t.Errorf("readPinsLocked() = (%v, ok %v), want (nil, false)", store, ok)
				}
				if stdout.Len() != 0 {
					t.Errorf("stdout = %q, want empty", stdout.String())
				}
				if tt.wantErr {
					assertStderrLines(t, stderr.String(), []lineWant{prefixLine(prefix + "cannot read the pins file: ")})
					assertContainsNone(t, "stderr", stderr.String(), []string{interruptedText})
				} else {
					assertStderrLines(t, stderr.String(), []lineWant{exactLine(prefix + interruptedText)})
				}
				assertContainsNone(t, "stderr", stderr.String(), []string{pinsLockedText})
				assertNoEscape(t, stdout.String(), stderr.String())
			})
		}
	}
}
