//go:build unix

package rules

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLoadDirFIFO(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	name := filepath.Join(dir, "p.yaml")
	if err := syscall.Mkfifo(name, 0o600); err != nil {
		t.Skipf("cannot create a named pipe: %v", err)
	}

	rules, errs := loadDirWithin(t, dir)
	if rules != nil {
		t.Errorf("rules = %v, want nil", ruleIDs(rules))
	}
	wantOneError(t, errs, name, ReasonNotRegular)
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

	lerr := within(t, "readRuleFile", func() *LoadError {
		data, lerr := readRuleFile(nonBlockFS{root}, "x.yaml", "x.yaml")
		if data != nil {
			lerr = newLoadError("x.yaml", ReasonUnreadable).wrap(errors.New("got data from a FIFO"))
		}
		return lerr
	})
	if lerr == nil {
		t.Fatal("readRuleFile() error = nil, want ReasonNotRegular")
	}
	if lerr.File != "x.yaml" || lerr.Reason != ReasonNotRegular {
		t.Errorf("error = {File: %q, Reason: %q}, want {File: %q, Reason: %q}", lerr.File, lerr.Reason, "x.yaml", ReasonNotRegular)
	}
}

// TestLoadDirNotDirectoryUnix gives LoadDir a FIFO, a symlink to a FIFO and a
// regular file as the rules path. A plain open(2) of a FIFO blocks until a
// writer appears, so LoadDir must check the type before it opens the path.
func TestLoadDirNotDirectoryUnix(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	fifo := filepath.Join(base, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a named pipe: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Skipf("cannot create a symlink: %v", err)
	}
	regular := writeFile(t, base, "file.txt", "hello")

	tests := []struct {
		name string
		dir  string
	}{
		{name: "fifo", dir: fifo},
		{name: "symlink to fifo", dir: link},
		{name: "regular file", dir: regular},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rules, errs := loadDirWithin(t, tt.dir)
			if rules != nil {
				t.Errorf("rules = %v, want nil", ruleIDs(rules))
			}
			wantOneError(t, errs, tt.dir, ReasonDirUnreadable)
			if !errors.Is(errs[0], syscall.ENOTDIR) {
				t.Errorf("error = %v, want it to wrap ENOTDIR", errs[0])
			}
		})
	}
}
