//go:build unix

package rules

import (
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
