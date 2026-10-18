//go:build unix

package inspect

import (
	"io/fs"
	"syscall"
	"testing"
	"time"
)

// fakeInfo is an fs.FileInfo with a mode and an owner, for checkChain.
type fakeInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

// TestCheckChain checks the parent chain rule of stdioOptions.FallbackDir
// on a fake file system: every directory up to "/" must be owned by the user
// or root and must not be writable by its group or by others.
func TestCheckChain(t *testing.T) {
	t.Parallel()

	const user, other = 501, 502
	dir := fs.ModeDir
	safe := map[string]fakeInfo{
		"/":                                {dir | 0o755, 0},
		"/home":                            {dir | 0o755, 0},
		"/home/u":                          {dir | 0o750, user},
		"/home/u/.cache":                   {dir | 0o700, user},
		"/home/u/.cache/mcpmoat":           {dir | 0o700, user},
		"/home/u/.cache/mcpmoat/run":       {dir | 0o700, user},
		"/tmp":                             {dir | fs.ModeSticky | 0o777, 0},
		"/tmp/c":                           {dir | 0o700, user},
		"/tmp/c/mcpmoat":                   {dir | 0o700, user},
		"/tmp/c/mcpmoat/run":               {dir | 0o700, user},
		"/home/u/shared":                   {dir | 0o770, user},
		"/home/u/shared/run":               {dir | 0o700, user},
		"/home/u/theirs":                   {dir | 0o755, other},
		"/home/u/theirs/run":               {dir | 0o700, user},
		"/home/u/file":                     {0o600, user},
		"/home/u/.cache/mcpmoat/run/inner": {dir | 0o700, user},
	}
	lstat := func(p string) (fs.FileInfo, error) {
		info, ok := safe[p]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return info, nil
	}

	tests := []struct {
		dir     string
		wantErr bool
	}{
		{"/home/u/.cache/mcpmoat/run", false},
		{"/home/u/.cache/mcpmoat/run/inner", false},
		{"/tmp/c/mcpmoat/run", true},  // sticky, world-writable /tmp
		{"/home/u/shared/run", true},  // group-writable parent
		{"/home/u/theirs/run", true},  // parent owned by another user
		{"/home/u/file", true},        // not a directory
		{"/home/u/missing/run", true}, // lstat fails
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			t.Parallel()
			err := checkChain(tt.dir, user, lstat)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkChain(%q) error = %v, want error: %v", tt.dir, err, tt.wantErr)
			}
		})
	}
}
