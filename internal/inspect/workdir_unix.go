//go:build unix

package inspect

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// checkPrivateChain checks dir and every parent directory up to "/" with
// os.Lstat, as stdioOptions.FallbackDir asks. dir must have no symbolic
// links (privateDir resolves them). See checkChain for the rule.
func checkPrivateChain(dir string) error {
	return checkChain(dir, os.Getuid(), os.Lstat)
}

// checkPrivateMode returns an error when the group of dir or other users
// have any access to it. info is the os.Lstat result of dir.
func checkPrivateMode(dir string, info fs.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s has mode %v, want no access for group and others", dir, perm)
	}
	return nil
}

// checkChain returns an error for the first directory, from dir up to "/",
// that another user could change. Each one must be a directory owned by uid
// or by root, and must not be writable by its group or by others. A sticky,
// world-writable directory such as /tmp fails too: the sticky bit stops
// other users from removing entries, not from adding node_modules or
// .npmrc. lstat is a parameter, so tests can give a fake file system.
//
// The check reads the owner and the mode bits only. On macOS an extended ACL
// can give another user write access to a directory whose mode bits look
// private; checkChain does not read ACLs. On Linux the mask of a POSIX ACL
// shows in the group bits, so the check covers it.
func checkChain(dir string, uid int, lstat func(string) (fs.FileInfo, error)) error {
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		info, err := lstat(p)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", p)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: no owner information", p)
		}
		if int(st.Uid) != uid && st.Uid != 0 {
			return fmt.Errorf("%s is owned by another user", p)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by its group or by others", p)
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}
