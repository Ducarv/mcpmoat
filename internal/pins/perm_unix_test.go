//go:build unix

package pins

// These tests cover the owner and mode rule of the pins directory and of
// pins.json. A foreign owner is faked with an injected uid, so no test needs
// root, and no test skips for root.

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

const (
	// permLeakToken is a distinctive text that tests put in pins.json. No
	// permission error may contain it, because the file content is untrusted.
	permLeakToken = "PERMLEAKTOKEN"

	// Stable pieces of the error text. {path} stands for the path under test.
	msgWritable = "writable by group or others"
	msgForeign  = "owned by another user"
	msgChown    = "ask the owner or root to run chown"
	msgChmod    = "chmod go-w -- '{path}'"

	validPins = `{"version":1,"servers":[]}`

	unknownOwnerMsg = "pins directory {path} is not safe: its owner is unknown: insecure permissions"
)

// chmodForTest sets the mode of path and fails the test on an error.
func chmodForTest(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod(%q, %#o) error = %v", path, mode, err)
	}
}

// newNamedPinsDir makes a directory called name under t.TempDir() with the
// given mode, and restores mode 0o700 at the end, so t.TempDir can remove it.
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

// newPinsDir makes a pins directory with the given mode.
func newPinsDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	return newNamedPinsDir(t, "pins", mode)
}

// seedPins writes a valid, empty pins.json with mode fileMode in dir and
// returns its path. The directory must be safe while it runs.
func seedPins(t *testing.T, dir string, fileMode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "pins.json")
	if err := os.WriteFile(path, []byte(validPins), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
	chmodForTest(t, path, fileMode)
	return path
}

// loadWithBeta loads the store at path and adds a pin for the server "beta".
func loadWithBeta(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) error = %v", path, err)
	}
	id := Identity{Client: "cursor", Source: "/home/u/.cursor/mcp.json", Name: "beta"}
	if err := s.Set(id, ServerPins{"t": {Hash: "h2", Canonical: "c-h2"}}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	return s
}

// newTarget makes a pins directory, or a pins.json in a safe directory, with
// the given mode and returns its path.
func newTarget(t *testing.T, kind string, mode os.FileMode) string {
	t.Helper()
	dir := newPinsDir(t, 0o700)
	switch kind {
	case kindFile:
		return seedPins(t, dir, mode)
	case kindDir:
		chmodForTest(t, dir, mode)
		return dir
	}
	t.Fatalf("unknown kind %q", kind)
	return ""
}

// wantInsecure fails the test unless err wraps ErrInsecurePermissions, holds
// every part (with {path} replaced by path) and does not hold the leak token.
func wantInsecure(t *testing.T, err error, path string, parts ...string) {
	t.Helper()
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("error = %v, want it to wrap ErrInsecurePermissions", err)
	}
	msg := err.Error()
	for _, p := range parts {
		p = strings.ReplaceAll(p, "{path}", path)
		if !strings.Contains(msg, p) {
			t.Errorf("error = %q, want it to contain %q", msg, p)
		}
	}
	if strings.Contains(msg, permLeakToken) {
		t.Errorf("error = %q, must not contain the file content", msg)
	}
}

// fakeInfo wraps a real FileInfo and replaces what Sys returns.
type fakeInfo struct {
	fs.FileInfo
	sys any
}

func (f fakeInfo) Sys() any { return f.sys }

func TestCheckOwnerAndMode(t *testing.T) {
	t.Parallel()
	me := os.Geteuid()
	tests := []struct {
		name string
		kind string
		mode os.FileMode
		uid  int
		// want holds the pieces that the error must contain. A nil want means no
		// error. The foreign, chown, writable and chmod pieces must be absent
		// when not listed.
		want []string
	}{
		{"dir 0700", kindDir, 0o700, me, nil},
		{"dir 0755", kindDir, 0o755, me, nil},
		{"file 0600", kindFile, 0o600, me, nil},
		{"file 0644", kindFile, 0o644, me, nil},
		{"dir 0770 group only", kindDir, 0o770, me, []string{"mode 0770", msgWritable, msgChmod}},
		{"dir 0707 others only", kindDir, 0o707, me, []string{"mode 0707", msgWritable, msgChmod}},
		{"dir 0777", kindDir, 0o777, me, []string{"mode 0777", msgWritable, msgChmod}},
		{"file 0660 group only", kindFile, 0o660, me, []string{"mode 0660", msgWritable, msgChmod}},
		{"file 0606 others only", kindFile, 0o606, me, []string{"mode 0606", msgWritable, msgChmod}},
		{"file 0666", kindFile, 0o666, me, []string{"mode 0666", msgWritable, msgChmod}},
		{"foreign dir 0700", kindDir, 0o700, me + 1, []string{"mode 0700", msgForeign, msgChown}},
		{"foreign dir 0755", kindDir, 0o755, me + 1, []string{"mode 0755", msgForeign, msgChown}},
		{"foreign file 0600", kindFile, 0o600, me + 1, []string{"mode 0600", msgForeign, msgChown}},
		{"foreign dir 0777", kindDir, 0o777, me + 1, []string{"mode 0777", msgForeign, msgChown, msgWritable, msgChmod}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := newTarget(t, tt.kind, tt.mode)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat(%q) error = %v", path, err)
			}
			err = checkOwnerAndMode(path, tt.kind, info, tt.uid)
			if tt.want == nil {
				if err != nil {
					t.Errorf("checkOwnerAndMode() error = %v, want nil", err)
				}
				return
			}
			wantInsecure(t, err, path, append(tt.want, "pins "+tt.kind+" {path}")...)
			// Each piece appears only when listed in want. The chmod piece in want
			// holds the path, so the error is matched against its short form.
			pieces := []struct{ inError, inWant string }{
				{msgForeign, msgForeign},
				{msgChown, msgChown},
				{msgWritable, msgWritable},
				{"chmod go-w", msgChmod},
			}
			for _, p := range pieces {
				if got := strings.Contains(err.Error(), p.inError); got != slices.Contains(tt.want, p.inWant) {
					t.Errorf("error = %q, contains %q = %v", err, p.inError, got)
				}
			}
			wantPerm(t, path, tt.mode) // refusing never changes the mode
		})
	}
}

// TestCheckOwnerAndModeExactMessages pins the full text once for each shape
// (also the fail-closed owner cases). Other tests look at stable pieces only.
func TestCheckOwnerAndModeExactMessages(t *testing.T) {
	t.Parallel()
	me := os.Geteuid()
	tests := []struct {
		name string
		mode os.FileMode
		uid  int
		fake bool // replace Sys() with sys, so the owner is unknown
		sys  any
		want string
	}{
		{"mode only", 0o777, me, false, nil,
			"pins directory {path} is not safe: mode 0777, writable by group or others (fix: chmod go-w -- '{path}'): insecure permissions"},
		{"owner only", 0o700, me + 1, false, nil,
			"pins directory {path} is not safe: mode 0700, owned by another user (fix: ask the owner or root to run chown, or to remove the path): insecure permissions"},
		{"mode and owner", 0o777, me + 1, false, nil,
			"pins directory {path} is not safe: mode 0777, owned by another user, writable by group or others (fix: ask the owner or root to run chown, then chmod go-w -- '{path}', or to remove the path): insecure permissions"},
		{"unknown owner, nil Sys", 0o700, me, true, nil, unknownOwnerMsg},
		{"unknown owner, Sys of another type", 0o700, me, true, "not a stat", unknownOwnerMsg},
		{"unknown owner, Stat_t value, not pointer", 0o700, me, true, syscall.Stat_t{}, unknownOwnerMsg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, tt.mode)
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatalf("Stat(%q) error = %v", dir, err)
			}
			if tt.fake {
				info = fakeInfo{info, tt.sys}
			}
			err = checkOwnerAndMode(dir, kindDir, info, tt.uid)
			want := strings.ReplaceAll(tt.want, "{path}", dir)
			if err == nil || err.Error() != want {
				t.Errorf("error = %v\nwant    %q", err, want)
			}
			if !errors.Is(err, ErrInsecurePermissions) {
				t.Errorf("error = %v, want it to wrap ErrInsecurePermissions", err)
			}
		})
	}
}

// TestCheckDirPermNoVerdict covers the paths that checkDirPerm does not judge:
// a missing path, a path that is not a directory and a Stat error.
func TestCheckDirPermNoVerdict(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	plain := filepath.Join(root, "plain")
	if err := os.WriteFile(plain, []byte(permLeakToken), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	chmodForTest(t, plain, 0o666)
	// A symlink loop gives ELOOP from Stat: an error that is not "missing".
	loopA, loopB := filepath.Join(root, "loop-a"), filepath.Join(root, "loop-b")
	for _, l := range [][2]string{{loopB, loopA}, {loopA, loopB}} {
		if err := os.Symlink(l[0], l[1]); err != nil {
			t.Fatalf("Symlink() error = %v", err)
		}
	}

	tests := []struct {
		name    string
		path    string
		wantErr error // nil means no error
	}{
		{"missing path", filepath.Join(root, "nope", "pins"), nil},
		{"path below a regular file (ENOTDIR)", filepath.Join(plain, "pins"), nil},
		{"regular file 0666 is not a directory", plain, nil},
		{"symlink loop (ELOOP)", loopA, syscall.ELOOP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checkDirPerm(tt.path)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("checkDirPerm(%q) error = %v, want %v", tt.path, err, tt.wantErr)
			}
			// No case here is a permission verdict.
			if errors.Is(err, ErrInsecurePermissions) {
				t.Errorf("error = %v, must not wrap ErrInsecurePermissions", err)
			}
		})
	}
}

// TestLoadDirIsFile checks that Load reports a pins directory that is a file
// with its own "not a directory" text, not as a permission error.
func TestLoadDirIsFile(t *testing.T) {
	t.Parallel()
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, []byte(permLeakToken), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	chmodForTest(t, plain, 0o666)

	s, err := Load(filepath.Join(plain, "pins.json"))
	if s != nil || err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("Load() = %v, %v, want a \"not a directory\" error", s, err)
	}
	if errors.Is(err, ErrInsecurePermissions) || strings.Contains(err.Error(), permLeakToken) {
		t.Errorf("Load() error = %q, must not be a permission error or hold the file content", err)
	}
}

func TestPinsDirSymlinkFollowsTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mode    os.FileMode
		wantErr bool // the target is unsafe, so Load and checkDirPerm refuse it
	}{
		{0o700, false},
		{0o777, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("target %04o", tt.mode), func(t *testing.T) {
			t.Parallel()
			target := newPinsDir(t, 0o700)
			seedPins(t, target, 0o600)
			chmodForTest(t, target, tt.mode)
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}

			checkErr := checkDirPerm(link)
			_, loadErr := Load(filepath.Join(link, "pins.json"))
			if !tt.wantErr {
				if checkErr != nil || loadErr != nil {
					t.Errorf("checkDirPerm() error = %v, Load() error = %v, want nil for a safe target", checkErr, loadErr)
				}
				return
			}
			wantInsecure(t, checkErr, link, "mode 0777", msgChmod, msgWritable)
			if !errors.Is(loadErr, ErrInsecurePermissions) {
				t.Errorf("Load() error = %v, want ErrInsecurePermissions for an unsafe target", loadErr)
			}
		})
	}
}

// TestCheckFilePermByPath covers the check that Load runs when it cannot open
// pins.json. The foreign owner is faked with an injected uid.
func TestCheckFilePermByPath(t *testing.T) {
	t.Parallel()
	me := os.Geteuid()
	tests := []struct {
		name string
		mode os.FileMode
		uid  int
		want []string // nil means no error
	}{
		{"own file 0600", 0o600, me, nil},
		{"foreign file 0600", 0o600, me + 1, []string{"mode 0600", msgForeign, msgChown}},
		{"foreign file 0666", 0o666, me + 1, []string{"mode 0666", msgForeign, msgChown, msgWritable, msgChmod}},
		{"own file 0666", 0o666, me, []string{"mode 0666", msgWritable, msgChmod}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := seedPins(t, newPinsDir(t, 0o700), tt.mode)
			err := checkFilePermByPath(path, tt.uid)
			if tt.want == nil {
				if err != nil {
					t.Errorf("checkFilePermByPath() error = %v, want nil", err)
				}
				return
			}
			wantInsecure(t, err, path, append(tt.want, "pins file {path}")...)
		})
	}

	// It cannot tell for a missing path or for a path that is not a regular
	// file, so it returns nil and the caller reports the read error.
	t.Run("missing path and a directory", func(t *testing.T) {
		t.Parallel()
		dir := newPinsDir(t, 0o700)
		for _, path := range []string{filepath.Join(dir, "nope.json"), dir} {
			if err := checkFilePermByPath(path, os.Geteuid()+1); err != nil {
				t.Errorf("checkFilePermByPath(%q) error = %v, want nil", path, err)
			}
		}
	})
}

// TestLoadUnreadableFile checks that a pins.json that the user may not read
// still gives a refusal. The owner is the user here, so Load has no owner
// problem to report and gives the read error (not ErrInsecurePermissions).
func TestLoadUnreadableFile(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root can read a file with mode 0000")
	}
	path := seedPins(t, newPinsDir(t, 0o700), 0o000)

	s, err := Load(path)

	if s != nil || err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Load() = %v, %v, want a permission denied error", s, err)
	}
	if errors.Is(err, ErrInsecurePermissions) {
		t.Errorf("Load() error = %v, must not claim an insecure owner or mode", err)
	}
}

func TestLoadChecksPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		dirMode  os.FileMode
		content  string // empty means no pins.json
		fileMode os.FileMode
		viaLink  bool   // pins.json is a symlink to real.json
		wantKind string // kindDir or kindFile: the path that Load must name; "" means Load succeeds
	}{
		{"first run, dir 0700", 0o700, "", 0, false, ""},
		{"first run, dir 0755", 0o755, "", 0, false, ""},
		{"first run, unsafe dir 0777", 0o777, "", 0, false, kindDir},
		{"unsafe dir, safe file", 0o770, validPins, 0o600, false, kindDir},
		// The content is not valid JSON on purpose: Load must refuse the mode
		// before it parses, so the token can never reach the error.
		{"unsafe file 0666, invalid content", 0o700, permLeakToken, 0o666, false, kindFile},
		{"unsafe file 0620 group only", 0o700, validPins, 0o620, false, kindFile},
		{"readable dir 0755, unsafe file 0602 others only", 0o755, validPins, 0o602, false, kindFile},
		{"symlink to a 0666 file", 0o700, validPins, 0o666, true, kindFile},
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
			if tt.content != "" {
				if err := os.WriteFile(target, []byte(tt.content), 0o600); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
				chmodForTest(t, target, tt.fileMode)
			}
			if tt.viaLink {
				if err := os.Symlink("real.json", path); err != nil {
					t.Fatalf("Symlink() error = %v", err)
				}
			}
			chmodForTest(t, dir, tt.dirMode)

			s, err := Load(path)
			if tt.wantKind == "" {
				if err != nil || s == nil {
					t.Errorf("Load() = %v, %v, want a store and no error", s, err)
				}
				wantPerm(t, dir, tt.dirMode)
				return
			}
			if s != nil {
				t.Errorf("Load() store = %v, want nil on a refused path", s)
			}
			want, wantMode := dir, tt.dirMode
			if tt.wantKind == kindFile {
				want, wantMode = path, tt.fileMode
			}
			wantInsecure(t, err, want, "pins "+tt.wantKind+" {path}",
				fmt.Sprintf("mode %04o", wantMode), msgChmod, msgWritable)

			// Refusing never changes a mode.
			wantPerm(t, dir, tt.dirMode)
			if tt.content != "" {
				wantPerm(t, target, tt.fileMode)
			}
		})
	}
}

func TestSaveRefusesInsecureDir(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777} {
		t.Run(fmt.Sprintf("dir %04o", mode), func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := seedPins(t, dir, 0o600)
			s := loadWithBeta(t, path)
			before := readFile(t, path)
			namesBefore := dirNames(t, dir)
			chmodForTest(t, dir, mode)

			err := s.Save()
			wantInsecure(t, err, dir, "pins directory {path}", fmt.Sprintf("mode %04o", mode), msgChmod, msgWritable)

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

// TestWriteFileAtomicChecksDir checks that the write itself checks the
// directory after MkdirAll, so a directory that appeared after a caller's
// check is refused too. It writes no temp file and does not change the mode.
func TestWriteFileAtomicChecksDir(t *testing.T) {
	t.Parallel()
	dir := newPinsDir(t, 0o777)

	err := writeFileAtomic(filepath.Join(dir, "pins.json"), []byte(validPins))

	wantInsecure(t, err, dir, "pins directory {path}", "mode 0777", msgChmod, msgWritable)
	if got := dirNames(t, dir); len(got) != 0 {
		t.Errorf("directory entries = %v, want none (no temp file)", got)
	}
	wantPerm(t, dir, 0o777)
}

func TestSaveIgnoresOldFileMode(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o666, 0o644} {
		t.Run(fmt.Sprintf("old file %04o", mode), func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := seedPins(t, dir, 0o600)
			s := loadWithBeta(t, path)
			chmodForTest(t, path, mode) // the rename replaces this file

			if err := s.Save(); err != nil {
				t.Fatalf("Save() error = %v, want nil: the old file is replaced", err)
			}
			wantPerm(t, path, 0o600)
			if got := dirNames(t, dir); !slices.Equal(got, []string{"pins.json"}) {
				t.Errorf("directory entries = %v, want only pins.json", got)
			}
			if _, err := Load(path); err != nil {
				t.Errorf("Load() after Save error = %v, want nil", err)
			}
		})
	}
}

func TestSaveCreatesMissingDir(t *testing.T) {
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
		{"two single quotes", "''", `''\'''\'''`},
		{"command substitution", "$(rm -rf ~)", `'$(rm -rf ~)'`},
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

func TestCheckDirPermQuotesOddPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		dirName string
		// quotedName is dirName as shellQuote writes it, inside the quotes of the
		// whole path.
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
			wantInsecure(t, checkDirPerm(dir), dir, "chmod go-w -- "+quoted)
		})
	}
}
