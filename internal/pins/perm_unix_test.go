//go:build unix

package pins

// These tests cover the owner and mode rule of the pins directory and of
// pins.json. They need Unix owners and mode bits, so the file has the unix tag.
// A foreign owner is faked with an injected uid, so no test needs root. The
// tests do not skip when the user is root: root owns the files it creates, and
// a mode check does not depend on the user.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// permLeakToken is a distinctive text that tests put in pins.json. No
// permission error may contain it, because the file content is untrusted.
const permLeakToken = "PERMLEAKTOKEN"

// Modes that group or others can write. The owner always has full access, so
// each mode is a path that only the extra write bit makes unsafe.
var (
	unsafeDirModes  = []os.FileMode{0o770, 0o707, 0o777, 0o720, 0o702}
	unsafeFileModes = []os.FileMode{0o660, 0o606, 0o666, 0o620, 0o602}
)

// chmodForTest sets the mode of path and fails the test on an error. It is the
// one place that carries the gosec exception for loose modes.
func chmodForTest(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod(%q, %#o) error = %v", path, mode, err)
	}
}

// newPinsDir makes a pins directory with the given mode under t.TempDir() and
// restores mode 0o700 at the end, so t.TempDir can remove it.
func newPinsDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	return newNamedPinsDir(t, "pins", mode)
}

// newNamedPinsDir works as newPinsDir for a directory called name, so a test
// can use a name with a space or a quote.
func newNamedPinsDir(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir(%q) error = %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: the cleanup restores the private mode so t.TempDir can delete the directory
	chmodForTest(t, dir, mode)
	return dir
}

// seedPins writes a valid pins.json with mode fileMode in dir and returns its
// path. The directory must be safe while it runs, so call it before the
// directory gets a loose mode.
func seedPins(t *testing.T, dir string, fileMode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "pins.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) error = %v", path, err)
	}
	id := Identity{Client: "claude-code", Source: "/home/u/.claude.json", Name: "alpha"}
	if err := s.Set(id, ServerPins{"tool": {Hash: "h1", Canonical: "c-h1"}}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	chmodForTest(t, path, fileMode)
	return path
}

// wantInsecure fails the test unless err wraps ErrInsecurePermissions and its
// text is exactly the message for the given problems, with the path in single
// quotes in the fix hint, and never holds the leak token. path must not hold a
// single quote: use wantInsecureQuoted for that.
func wantInsecure(t *testing.T, err error, kind, path string, mode os.FileMode, foreign, writable bool) {
	t.Helper()
	wantInsecureQuoted(t, err, kind, path, "'"+path+"'", mode, foreign, writable)
}

// wantInsecureQuoted works as wantInsecure, with the shell-quoted form of path
// given by the caller.
func wantInsecureQuoted(t *testing.T, err error, kind, path, quoted string, mode os.FileMode, foreign, writable bool) {
	t.Helper()
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("error = %v, want it to wrap ErrInsecurePermissions", err)
	}
	chmod := "chmod go-w -- " + quoted
	chown := `you must own the path: chown -- "$(id -un)" ` + quoted + ", or remove the path"
	var problems, fix string
	switch {
	case foreign && writable:
		problems, fix = "owned by another user, "+problemWritable, chmod+"; "+chown
	case foreign:
		problems, fix = "owned by another user", chown
	case writable:
		problems, fix = problemWritable, chmod
	default:
		t.Fatal("wantInsecure: foreign and writable are both false")
	}
	want := fmt.Sprintf("pins %s %s is not safe: mode %04o, %s (fix: %s): insecure permissions",
		kind, path, mode, problems, fix)
	if msg := err.Error(); msg != want {
		t.Errorf("error = %q\nwant    %q", msg, want)
	}
	if strings.Contains(err.Error(), permLeakToken) {
		t.Errorf("error = %q, must not contain the file content", err)
	}
}

const problemWritable = "writable by group or others"

func TestCheckStorePermSafeModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		kind string
		mode os.FileMode
	}{
		{"dir 0700", "directory", 0o700},
		{"dir 0755", "directory", 0o755},
		{"file 0600", "file", 0o600},
		{"file 0644", "file", 0o644},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := dir
			if tt.kind == "file" {
				path = seedPins(t, dir, tt.mode)
			} else {
				chmodForTest(t, dir, tt.mode)
			}
			if err := checkStorePerm(path, tt.kind); err != nil {
				t.Errorf("checkStorePerm(%q) error = %v, want nil", path, err)
			}
			wantPerm(t, path, tt.mode)
		})
	}
}

func TestCheckStorePermRefusesWritableModes(t *testing.T) {
	t.Parallel()
	type tc struct {
		kind string
		mode os.FileMode
	}
	var tests []tc
	for _, m := range unsafeDirModes {
		tests = append(tests, tc{"directory", m})
	}
	for _, m := range unsafeFileModes {
		tests = append(tests, tc{"file", m})
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s %04o", tt.kind, tt.mode), func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := dir
			if tt.kind == "file" {
				path = seedPins(t, dir, tt.mode)
			} else {
				chmodForTest(t, dir, tt.mode)
			}
			err := checkStorePerm(path, tt.kind)
			wantInsecure(t, err, tt.kind, path, tt.mode, false, true)
			wantPerm(t, path, tt.mode) // refusing never changes the mode
		})
	}
}

func TestCheckOwnerAndModeForeignOwner(t *testing.T) {
	t.Parallel()
	me := os.Geteuid()
	tests := []struct {
		name         string
		mode         os.FileMode
		uid          int
		wantForeign  bool
		wantWritable bool
	}{
		{"own safe path", 0o700, me, false, false},
		{"foreign owner, safe mode", 0o700, me + 1, true, false},
		{"foreign owner, 0755", 0o755, me + 1, true, false},
		{"foreign owner, writable mode", 0o777, me + 1, true, true},
		{"own owner, writable mode", 0o777, me, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, tt.mode)
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatalf("Stat(%q) error = %v", dir, err)
			}
			err = checkOwnerAndMode(dir, "directory", info, tt.uid)
			if !tt.wantForeign && !tt.wantWritable {
				if err != nil {
					t.Fatalf("checkOwnerAndMode() error = %v, want nil", err)
				}
				return
			}
			wantInsecure(t, err, "directory", dir, tt.mode, tt.wantForeign, tt.wantWritable)
		})
	}
}

// fakeInfo wraps a real FileInfo and replaces what Sys returns.
type fakeInfo struct {
	fs.FileInfo
	sys any
}

func (f fakeInfo) Sys() any { return f.sys }

func TestCheckOwnerAndModeUnknownOwnerFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		sys  any
	}{
		{"nil", nil},
		{"other type", "not a stat"},
		{"Stat_t value, not pointer", syscall.Stat_t{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700) // safe on disk: only Sys() hides the owner
			target, err := os.Stat(dir)
			if err != nil {
				t.Fatalf("Stat(%q) error = %v", dir, err)
			}
			err = checkOwnerAndMode(dir, "directory", fakeInfo{target, tt.sys}, os.Geteuid())
			if !errors.Is(err, ErrInsecurePermissions) {
				t.Fatalf("error = %v, want it to wrap ErrInsecurePermissions", err)
			}
			if !strings.Contains(err.Error(), dir) {
				t.Errorf("error = %q, want it to name %q", err, dir)
			}
		})
	}
}

func TestCheckStorePermMissingAndStatError(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	plain := filepath.Join(root, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	// A symlink loop gives ELOOP from Stat: an error that is not "missing".
	loopA, loopB := filepath.Join(root, "loop-a"), filepath.Join(root, "loop-b")
	if err := os.Symlink(loopB, loopA); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := os.Symlink(loopA, loopB); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr error // nil means no error
	}{
		{"missing path", filepath.Join(root, "nope", "pins.json"), nil},
		{"path below a regular file (ENOTDIR)", filepath.Join(plain, "pins.json"), nil},
		{"symlink loop (ELOOP)", loopA, syscall.ELOOP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checkStorePerm(tt.path, "file")
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("checkStorePerm(%q) error = %v, want nil", tt.path, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("checkStorePerm(%q) error = %v, want it to wrap %v", tt.path, err, tt.wantErr)
			}
			// Another Stat error is an error, but not a permission verdict.
			if errors.Is(err, ErrInsecurePermissions) {
				t.Errorf("error = %v, must not wrap ErrInsecurePermissions", err)
			}
		})
	}
}

func TestCheckStorePermFollowsSymlink(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		targetMode os.FileMode
		wantErr    bool
	}{
		{"safe target", 0o700, false},
		{"unsafe target", 0o777, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target := newPinsDir(t, tt.targetMode)
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
			// The mode of a symlink itself is not 0o777 on every system. Only the
			// target counts, so the check must report the target mode.
			err := checkStorePerm(link, "directory")
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("checkStorePerm(link) error = %v, want nil", err)
				}
				return
			}
			wantInsecure(t, err, "directory", link, tt.targetMode, false, true)
		})
	}
}

func TestLoadPermSymlinkedDir(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o700, 0o777} {
		t.Run(fmt.Sprintf("target %04o", mode), func(t *testing.T) {
			t.Parallel()
			target := newPinsDir(t, 0o700)
			seedPins(t, target, 0o600)
			chmodForTest(t, target, mode)
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
			_, err := Load(filepath.Join(link, "pins.json"))
			if mode == 0o700 {
				if err != nil {
					t.Errorf("Load() error = %v, want nil for a safe target", err)
				}
				return
			}
			if !errors.Is(err, ErrInsecurePermissions) {
				t.Errorf("Load() error = %v, want ErrInsecurePermissions for an unsafe target", err)
			}
		})
	}
}

func TestLoadPermMissingFileInSafeDirIsFirstRun(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o700, 0o755} {
		t.Run(fmt.Sprintf("dir %04o", mode), func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, mode)
			s, err := Load(filepath.Join(dir, "pins.json"))
			if err != nil {
				t.Fatalf("Load() error = %v, want nil on a first run", err)
			}
			if s == nil {
				t.Fatal("Load() store = nil, want an empty store")
			}
			wantPerm(t, dir, mode)
		})
	}
}

func TestLoadPermRefusesInsecurePaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		dirMode  os.FileMode
		fileMode os.FileMode
		hasFile  bool
		wantKind string // "directory" or "file": the path that Load must name
	}{
		{"first run, unsafe dir 0777", 0o777, 0, false, "directory"},
		{"first run, unsafe dir 0770", 0o770, 0, false, "directory"},
		{"unsafe dir, safe file", 0o777, 0o600, true, "directory"},
		{"safe dir, unsafe file 0666", 0o700, 0o666, true, "file"},
		{"safe dir, unsafe file 0660", 0o700, 0o660, true, "file"},
		{"safe dir, unsafe file 0602", 0o700, 0o602, true, "file"},
		{"readable dir 0755, unsafe file 0622", 0o755, 0o622, true, "file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := filepath.Join(dir, "pins.json")
			if tt.hasFile {
				// The content is not valid JSON on purpose: Load must refuse the
				// mode before it parses, so the token can never reach the error.
				if err := os.WriteFile(path, []byte(permLeakToken), 0o600); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
				chmodForTest(t, path, tt.fileMode)
			}
			chmodForTest(t, dir, tt.dirMode)

			s, err := Load(path)
			if s != nil {
				t.Errorf("Load() store = %v, want nil on a refused path", s)
			}
			want, wantMode := dir, tt.dirMode
			if tt.wantKind == "file" {
				want, wantMode = path, tt.fileMode
			}
			wantInsecure(t, err, tt.wantKind, want, wantMode, false, true)

			wantPerm(t, dir, tt.dirMode)
			if tt.hasFile {
				wantPerm(t, path, tt.fileMode)
			}
		})
	}
}

func TestSavePermRefusesInsecureDir(t *testing.T) {
	t.Parallel()
	for _, mode := range unsafeDirModes {
		t.Run(fmt.Sprintf("dir %04o", mode), func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := seedPins(t, dir, 0o600)
			s, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			id := Identity{Client: "cursor", Source: "/home/u/.cursor/mcp.json", Name: "beta"}
			if err := s.Set(id, ServerPins{"t": {Hash: "h2", Canonical: "c-h2"}}); err != nil {
				t.Fatalf("Set() error = %v", err)
			}
			before := readFile(t, path)
			namesBefore := dirNames(t, dir)
			chmodForTest(t, dir, mode)

			err = s.Save()
			wantInsecure(t, err, "directory", dir, mode, false, true)

			if got := readFile(t, path); string(got) != string(before) {
				t.Errorf("pins.json changed by a refused Save:\n got %q\nwant %q", got, before)
			}
			if got := dirNames(t, dir); !slices.Equal(got, namesBefore) {
				t.Errorf("directory entries = %v, want %v (no temp file)", got, namesBefore)
			}
			wantPerm(t, dir, mode)
			wantPerm(t, path, 0o600)
		})
	}
}

func TestSavePermIgnoresOldFileMode(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o666, 0o660, 0o644} {
		t.Run(fmt.Sprintf("old file %04o", mode), func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := seedPins(t, dir, 0o600)
			s, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			id := Identity{Client: "cursor", Source: "/home/u/.cursor/mcp.json", Name: "beta"}
			if err := s.Set(id, ServerPins{"t": {Hash: "h2", Canonical: "c-h2"}}); err != nil {
				t.Fatalf("Set() error = %v", err)
			}
			chmodForTest(t, path, mode) // the rename replaces this file

			if err := s.Save(); err != nil {
				t.Fatalf("Save() error = %v, want nil: the old file is replaced", err)
			}
			wantPerm(t, path, 0o600)
			wantPerm(t, dir, 0o700)
			if got := dirNames(t, dir); !slices.Equal(got, []string{"pins.json"}) {
				t.Errorf("directory entries = %v, want only pins.json", got)
			}
			if _, err := Load(path); err != nil {
				t.Errorf("Load() after Save error = %v, want nil", err)
			}
		})
	}
}

func TestSavePermMissingDirIsCreated(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "new", "pins.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil: a missing directory is a first run", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save() error = %v, want nil", err)
	}
	wantPerm(t, filepath.Dir(path), 0o700)
	wantPerm(t, path, 0o600)
}

func TestShellQuote(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", `''`},
		{"plain", "/home/u/pins.json", `'/home/u/pins.json'`},
		{"space", "/home/my user/pins.json", `'/home/my user/pins.json'`},
		{"single quote", "/home/o'brien/pins", `'/home/o'\''brien/pins'`},
		{"only a single quote", "'", `''\'''`},
		{"two single quotes", "''", `''\'''\'''`},
		{"command substitution", "$(rm -rf ~)", `'$(rm -rf ~)'`},
		{"backtick and double quote", "`x`\"y\"", "'`x`\"y\"'"},
		{"newline", "a\nb", "'a\nb'"},
		{"leading dash", "-rf", `'-rf'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := shellQuote(tt.in); got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCheckStorePermQuotesOddPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		dirName string
		// quotedName is dirName as shellQuote writes it, without the outer
		// quotes of the whole path.
		quotedName string
	}{
		{"space", "my pins", "my pins"},
		{"single quote", "it's", `it'\''s`},
		{"shell metacharacters", "$(touch x);y", "$(touch x);y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := newNamedPinsDir(t, tt.dirName, 0o777)
			// The temp dir path holds no quote, so the quoted form is the parent,
			// a slash and the quoted name, all inside one pair of quotes.
			quoted := "'" + filepath.Dir(dir) + "/" + tt.quotedName + "'"
			err := checkStorePerm(dir, "directory")
			wantInsecureQuoted(t, err, "directory", dir, quoted, 0o777, false, true)
		})
	}
}

func TestLoadPermRefusesFileThroughDescriptor(t *testing.T) {
	t.Parallel()
	valid := `{"version":1,"servers":[]}`
	tests := []struct {
		name    string
		content string
		mode    os.FileMode
		viaLink bool
	}{
		{"invalid content, 0666", permLeakToken, 0o666, false},
		{"valid-looking content, 0666", valid + permLeakToken, 0o666, false},
		{"valid-looking content, 0620", valid, 0o620, false},
		{"symlink to a 0666 file", permLeakToken, 0o666, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := filepath.Join(dir, "pins.json")
			target := path
			if tt.viaLink {
				target = filepath.Join(dir, "real.json")
			}
			if err := os.WriteFile(target, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			chmodForTest(t, target, tt.mode)
			if tt.viaLink {
				if err := os.Symlink("real.json", path); err != nil {
					t.Fatalf("Symlink() error = %v", err)
				}
			}

			s, err := Load(path)
			if s != nil {
				t.Errorf("Load() store = %v, want nil", s)
			}
			// Load must refuse the mode, not the content: the error is the mode
			// error, and the mode is the mode of the opened file.
			wantInsecure(t, err, "file", path, tt.mode, false, true)
			wantPerm(t, target, tt.mode) // refusing never changes the mode
		})
	}
}
