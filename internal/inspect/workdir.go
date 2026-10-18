package inspect

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// noCleanup is the cleanup func that workDir returns when there is nothing
// to remove. Callers can always call cleanup without a nil check.
func noCleanup() {}

// workDir returns the stdioOptions.FallbackDir for a server whose config
// Dir is configDir: "" when configDir is absolute (stdioCommand then uses
// it), else a new, empty directory below the run root that runRoot returns.
//
// The returned cleanup removes that directory. Call it after the process has
// exited. cleanup is never nil, also on error. An error wraps [ErrStart].
func workDir(configDir string, runRoot func() (string, error)) (dir string, cleanup func(), err error) {
	if filepath.IsAbs(configDir) {
		return "", noCleanup, nil
	}
	root, err := runRoot()
	if err != nil {
		return "", noCleanup, fmt.Errorf("%w: work directory root: %w", ErrStart, err)
	}
	// MkdirTemp makes a new directory with mode 0o700 and a random suffix,
	// so no earlier run can put files in it.
	dir, err = os.MkdirTemp(root, "mcpmoat-server-*")
	if err != nil {
		return "", noCleanup, fmt.Errorf("%w: create work directory: %w", ErrStart, err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// defaultRunRoot returns <user cache dir>/mcpmoat/run, the directory in
// which workDir makes the work directory of a server without an absolute
// Dir ($XDG_CACHE_HOME or ~/.cache on Linux, ~/Library/Caches on macOS).
//
// It follows the rules of stdioOptions.FallbackDir: npm and uv read files
// in all the parent directories of their work directory, so the run root and
// every parent up to "/" must be safe from other users (see
// checkPrivateChain). os.TempDir is not used, because it is /tmp on most
// Linux systems, where another local user could put node_modules/.bin/<name>
// or .npmrc in place.
func defaultRunRoot() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return runRootIn(cache, checkPrivateChain)
}

// runRootIn makes <cache>/mcpmoat/run with [privateDir] and checks its
// parent chain with checkChain. It returns the run root with symbolic links
// resolved, so later steps do not follow a link that could change.
func runRootIn(cache string, checkChain func(string) error) (string, error) {
	root, err := privateDir(filepath.Join(cache, "mcpmoat", "run"))
	if err != nil {
		return "", err
	}
	if err := checkChain(root); err != nil {
		return "", err
	}
	return root, nil
}

// privateDir makes dir with mode 0o700 if it does not exist, and returns it
// with symbolic links resolved. It returns an error when the resolved path
// is not a directory or when, on Unix, its group or other users have any
// access to it. It does not change an existing directory, and it does not
// check the parent directories (see checkPrivateChain).
func privateDir(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", resolved)
	}
	// Windows reports no Unix permission bits for a directory.
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm&0o077 != 0 {
		return "", fmt.Errorf("%s has mode %v, want no access for group and others", resolved, perm)
	}
	return resolved, nil
}
