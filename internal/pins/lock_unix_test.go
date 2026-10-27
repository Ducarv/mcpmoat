//go:build unix

package pins

import (
	"errors"
	"syscall"
	"testing"
)

// TestLockErrno covers how tryLock maps the errno of flock(2) to its results.
// No real file system returns most of these errnos on demand, so the test
// calls the pure function lockErrno.
func TestLockErrno(t *testing.T) {
	t.Parallel()
	const name = "/home/u/.config/mcpmoat"
	tests := []struct {
		name            string
		errno           syscall.Errno
		wantAcquired    bool
		wantUnsupported bool // the error wraps errLockUnsupported
		wantErr         bool // any error
	}{
		{"success", 0, true, false, false},
		{"EWOULDBLOCK is busy", syscall.EWOULDBLOCK, false, false, false},
		{"EAGAIN is busy", syscall.EAGAIN, false, false, false},
		{"ENOTSUP", syscall.ENOTSUP, false, true, true},
		{"EOPNOTSUPP", syscall.EOPNOTSUPP, false, true, true},
		{"ENOLCK", syscall.ENOLCK, false, true, true},
		{"ENOSYS", syscall.ENOSYS, false, true, true},
		{"EBADF from NFS on Linux", syscall.EBADF, false, true, true},
		{"EINVAL from FUSE or a network file system", syscall.EINVAL, false, true, true},
		{"EIO is a plain error", syscall.EIO, false, false, true},
		{"EACCES is a plain error", syscall.EACCES, false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			acquired, err := lockErrno(name, tt.errno)
			if acquired != tt.wantAcquired {
				t.Errorf("lockErrno(%v) acquired = %v, want %v", tt.errno, acquired, tt.wantAcquired)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("lockErrno(%v) error = %v, want an error: %v", tt.errno, err, tt.wantErr)
			}
			if got := errors.Is(err, errLockUnsupported); got != tt.wantUnsupported {
				t.Errorf("lockErrno(%v) error = %v, wraps errLockUnsupported = %v, want %v", tt.errno, err, got, tt.wantUnsupported)
			}
			// The errno stays in the chain, so a caller can still test for it.
			if err != nil && !errors.Is(err, tt.errno) {
				t.Errorf("lockErrno(%v) error = %v, want it to wrap the errno", tt.errno, err)
			}
		})
	}
}
