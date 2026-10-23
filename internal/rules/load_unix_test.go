//go:build unix

package rules

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLoadDirFIFO(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	name := filepath.Join(dir, "p.yaml")
	if err := syscall.Mkfifo(name, 0o600); err != nil {
		t.Skipf("cannot create a named pipe: %v", err)
	}

	type result struct {
		rules []Rule
		errs  []*LoadError
	}
	done := make(chan result, 1)
	go func() {
		rules, errs := LoadDir(dir)
		done <- result{rules, errs}
	}()

	select {
	case res := <-done:
		if res.rules != nil {
			t.Errorf("rules = %v, want nil", ruleIDs(res.rules))
		}
		wantOneError(t, res.errs, name, ReasonNotRegular)
	case <-time.After(5 * time.Second):
		// The goroutine stays blocked in open(2); the test already fails.
		t.Fatal("LoadDir blocked on a named pipe")
	}
}

// TestReadRuleFileFIFORace opens a FIFO through nonBlockFS, as if a writer
// swapped it in after the directory listing. LoadDir refuses a FIFO by its
// entry type before any open, so this calls readRuleFile directly. A plain
// open would block until a writer appears.
func TestReadRuleFileFIFORace(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "x.yaml"), 0o600); err != nil {
		t.Skipf("cannot create a named pipe: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	done := make(chan *LoadError, 1)
	go func() {
		data, lerr := readRuleFile(nonBlockFS{root}, "x.yaml", "x.yaml")
		if data != nil {
			lerr = newLoadError("x.yaml", ReasonUnreadable).wrap(errors.New("got data from a FIFO"))
		}
		done <- lerr
	}()

	select {
	case lerr := <-done:
		if lerr == nil {
			t.Fatal("readRuleFile() error = nil, want ReasonNotRegular")
		}
		if lerr.File != "x.yaml" || lerr.Reason != ReasonNotRegular {
			t.Errorf("error = {File: %q, Reason: %q}, want {File: %q, Reason: %q}", lerr.File, lerr.Reason, "x.yaml", ReasonNotRegular)
		}
	case <-time.After(10 * time.Second):
		// The goroutine stays blocked in open(2); the test already fails.
		t.Fatal("readRuleFile blocked on a named pipe")
	}
}
