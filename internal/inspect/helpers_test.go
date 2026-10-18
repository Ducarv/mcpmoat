package inspect

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// This file holds the test helpers that several test files of the package
// use. A helper that only one file uses stays in that file.

// skipOnWindows skips the test on Windows. Starting stdio servers is
// Unix only, and Windows is a non-goal (PRD section 2.2).
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("starting stdio servers is Unix only; Windows is a non-goal (PRD 2.2)")
	}
}

// mustWriteFile creates a file at path with the given mode. It sets the mode
// with os.Chmod after the write, so the umask does not change it.
func mustWriteFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), mode); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("os.Chmod(%q) error = %v", path, err)
	}
}

// mustMkdir creates the directory dir and its parents.
func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("os.MkdirAll(%q) error = %v", dir, err)
	}
}

// mustSymlink creates a symlink at link that points to target.
func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink(%q, %q) error = %v", target, link, err)
	}
}

// secrets builds a discover.SecretMap from plain name and value pairs.
func secrets(t *testing.T, kv map[string]string) discover.SecretMap {
	t.Helper()
	if kv == nil {
		return nil
	}
	m := make(discover.SecretMap, len(kv))
	for k, v := range kv {
		m[k] = discover.NewSecret(v)
	}
	return m
}

// envKey returns the name part of a "name=value" entry.
func envKey(entry string) string {
	name, _, _ := strings.Cut(entry, "=")
	return name
}
