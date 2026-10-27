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

	"github.com/Ducarv/mcpmoat/internal/safefile"
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

	// A symlink that leaves the pins directory is not followed, so the hint
	// never names a file outside the directory.
	t.Run("symlink that leaves the directory", func(t *testing.T) {
		t.Parallel()
		outside := seedPins(t, newPinsDir(t, 0o700), 0o666)
		dir := newPinsDir(t, 0o700)
		link := filepath.Join(dir, "pins.json")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatalf("Symlink() error = %v", err)
		}
		if err := checkFilePermByPath(link, os.Geteuid()+1); err != nil {
			t.Errorf("checkFilePermByPath() error = %v, want nil for a link that leaves the directory", err)
		}
	})

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

// wantSymlink is the wantKind of TestLoadChecksPaths for a pins.json that is a
// symlink: Load refuses the link itself, whatever the mode of its target.
const wantSymlink = "symlink"

func TestLoadChecksPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		dirMode  os.FileMode
		content  string // empty means no pins.json
		fileMode os.FileMode
		viaLink  bool   // pins.json is a symlink to real.json
		wantKind string // kindDir, kindFile or wantSymlink: what Load must refuse; "" means Load succeeds
	}{
		{"first run, dir 0700", 0o700, "", 0, false, ""},
		{"first run, dir 0755", 0o755, "", 0, false, ""},
		{"dir 0700, file 0600", 0o700, validPins, 0o600, false, ""},
		{"dir 0755, file 0644", 0o755, validPins, 0o644, false, ""},
		{"first run, unsafe dir 0777", 0o777, "", 0, false, kindDir},
		{"unsafe dir, safe file", 0o770, validPins, 0o600, false, kindDir},
		{"unsafe dir 0777, safe file", 0o777, validPins, 0o600, false, kindDir},
		// The content is not valid JSON on purpose: Load must refuse the mode
		// before it parses, so the token can never reach the error.
		{"unsafe file 0666, invalid content", 0o700, permLeakToken, 0o666, false, kindFile},
		{"unsafe file 0620 group only", 0o700, validPins, 0o620, false, kindFile},
		{"readable dir 0755, unsafe file 0602 others only", 0o755, validPins, 0o602, false, kindFile},
		// A pins.json symlink is refused as a symlink, also when its target in
		// the same directory is safe. The text does not report the target mode.
		{"symlink to a 0666 file", 0o700, validPins, 0o666, true, wantSymlink},
		{"symlink to a 0600 file", 0o700, validPins, 0o600, true, wantSymlink},
		{"symlink to invalid content", 0o700, permLeakToken, 0o600, true, wantSymlink},
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
			switch tt.wantKind {
			case wantSymlink:
				wantInsecure(t, err, path, "pins file {path} is a symlink", "(fix: replace the symlink with the file)")
				if strings.Contains(err.Error(), "mode ") || strings.Contains(err.Error(), "real.json") {
					t.Errorf("Load() error = %q, must not report the target of the symlink", err)
				}
			case kindFile:
				wantInsecure(t, err, path, "pins file {path}",
					fmt.Sprintf("mode %04o", tt.fileMode), msgChmod, msgWritable)
			default:
				wantInsecure(t, err, dir, "pins directory {path}",
					fmt.Sprintf("mode %04o", tt.dirMode), msgChmod, msgWritable)
			}

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

// TestLoadRefusesPinsSymlinkTargets covers pins.json symlinks that Load cannot
// follow at all: a dangling link is an error and not a first run, and a link
// that leaves the pins directory is refused before any permission check.
func TestLoadRefusesPinsSymlinkTargets(t *testing.T) {
	t.Parallel()
	outside := seedPins(t, newNamedPinsDir(t, "outside", 0o700), 0o600)
	tests := []struct {
		name    string
		target  string
		wantMsg string
		wantErr error // nil means any error
	}{
		{"dangling relative link", "real.json", "the target of the symlink is missing", nil},
		{"dangling link into a missing directory", "nope/real.json", "the target of the symlink is missing", nil},
		{"absolute link out of the directory", outside, "", safefile.ErrOutsideRoot},
		{"relative link out of the directory", "../../outside/pins.json", "", safefile.ErrOutsideRoot},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(newPinsDir(t, 0o700), "pins.json")
			if err := os.Symlink(tt.target, path); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
			s, err := Load(path)
			if s != nil || err == nil {
				t.Fatalf("Load() = %v, %v, want an error and no store", s, err)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Load() error = %q, want it to contain %q", err, tt.wantMsg)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Load() error = %v, want errors.Is %v", err, tt.wantErr)
			}
		})
	}
}

// TestLoadUnsafeFileBeforeSize checks that the owner and mode check of
// pins.json runs before the size check (#203): an unsafe file that is also too
// large gives ErrInsecurePermissions, not ErrTooLarge. The file is sparse, so
// the test writes no data.
func TestLoadUnsafeFileBeforeSize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		mode     os.FileMode
		wantPerm bool // true: ErrInsecurePermissions, false: safefile.ErrTooLarge
	}{
		{"unsafe 0666, too large", 0o666, true},
		{"unsafe 0620, too large", 0o620, true},
		{"safe 0600, too large", 0o600, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := filepath.Join(dir, "pins.json")
			f, err := os.Create(path) //nolint:gosec // G304: the test builds path under t.TempDir().
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			if err := f.Truncate(MaxFileSize + 1<<20); err != nil {
				_ = f.Close()
				t.Fatalf("Truncate() error = %v", err)
			}
			if err := f.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			chmodForTest(t, path, tt.mode)

			s, err := Load(path)
			if s != nil || err == nil {
				t.Fatalf("Load() = %v, %v, want an error", s, err)
			}
			if got := errors.Is(err, ErrInsecurePermissions); got != tt.wantPerm {
				t.Errorf("Load() error = %v, errors.Is ErrInsecurePermissions = %v, want %v", err, got, tt.wantPerm)
			}
			if got := errors.Is(err, safefile.ErrTooLarge); got == tt.wantPerm {
				t.Errorf("Load() error = %v, errors.Is safefile.ErrTooLarge = %v, want %v", err, got, !tt.wantPerm)
			}
			if tt.wantPerm {
				wantInsecure(t, err, path, "pins file {path}", fmt.Sprintf("mode %04o", tt.mode), msgChmod)
			}
		})
	}
}

// TestCheckDirHandle covers the check of the open pins directory.
func TestCheckDirHandle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mode os.FileMode
		want bool // true: refused with ErrInsecurePermissions
	}{
		{0o700, false},
		{0o755, false},
		{0o770, true},
		{0o707, true},
		{0o777, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("dir %04o", tt.mode), func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, tt.mode)
			d, err := os.Open(dir) //nolint:gosec // G304: the test builds dir under t.TempDir().
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			t.Cleanup(func() { _ = d.Close() })
			err = checkDirHandle(dir, d)
			if !tt.want {
				if err != nil {
					t.Errorf("checkDirHandle() error = %v, want nil", err)
				}
				return
			}
			wantInsecure(t, err, dir, "pins directory {path}", fmt.Sprintf("mode %04o", tt.mode), msgChmod, msgWritable)
		})
	}

	// A handle that is not a directory, or that is closed, is an error, but not
	// a permission verdict.
	t.Run("not a directory and closed", func(t *testing.T) {
		t.Parallel()
		path := seedPins(t, newPinsDir(t, 0o700), 0o600)
		f, err := os.Open(path) //nolint:gosec // G304: the test builds path under t.TempDir().
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		err = checkDirHandle(path, f)
		if err == nil || !strings.Contains(err.Error(), "not a directory") || errors.Is(err, ErrInsecurePermissions) {
			t.Errorf("checkDirHandle(file) error = %v, want a \"not a directory\" error", err)
		}
		_ = f.Close()
		if err := checkDirHandle(path, f); err == nil {
			t.Error("checkDirHandle(closed) error = nil, want an error")
		}
	})
}

// TestLoadDirHint checks the hint for a pins directory that its owner cannot
// open (dirOpenError): a group or other writable mode gets the chmod hint, a
// plain 0000 stays "permission denied".
func TestLoadDirHint(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root can open a directory with any mode")
	}
	tests := []struct {
		mode     os.FileMode
		wantPerm bool
	}{
		{0o070, true},
		{0o007, true},
		{0o000, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("dir %04o", tt.mode), func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := seedPins(t, dir, 0o600)
			chmodForTest(t, dir, tt.mode)

			s, err := Load(path)
			if s != nil || err == nil {
				t.Fatalf("Load() = %v, %v, want an error", s, err)
			}
			if !tt.wantPerm {
				if !errors.Is(err, fs.ErrPermission) || errors.Is(err, ErrInsecurePermissions) {
					t.Errorf("Load() error = %v, want only permission denied", err)
				}
				return
			}
			wantInsecure(t, err, dir, "read "+path, "pins directory {path}", fmt.Sprintf("mode %04o", tt.mode), msgChmod, msgWritable)
		})
	}
}

// TestLoadUnderTempDir is the real-world sanity check: on macOS the parents of
// t.TempDir() are /var (a symlink to /private/var), /private/var/folders and
// so on, owned by root or the user. Load and Save must work there end to end.
func TestLoadUnderTempDir(t *testing.T) {
	t.Parallel()
	if err := checkParents(t.TempDir()); err != nil {
		t.Fatalf("checkParents(t.TempDir()) error = %v, want nil", err)
	}
	path := filepath.Join(t.TempDir(), "mcpmoat", "pins.json")
	s, err := Load(path)
	if err != nil || s.Existed() {
		t.Fatalf("Load() = %v, %v, want an empty store for a first run", s, err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if s, err = Load(path); err != nil || !s.Existed() {
		t.Fatalf("Load() after Save = %v, %v, want the saved store", s, err)
	}
}

// TestCheckParentOwnerAndMode covers the rule for one parent directory. The
// owner is faked with a Stat_t, so no test needs root.
func TestCheckParentOwnerAndMode(t *testing.T) {
	t.Parallel()
	me := os.Geteuid()
	const other = 4242 // a non-root owner that is not the current user
	if me == other {
		t.Skip("the current user has the uid of the fake owner")
	}
	meOwner := uint32(me) //nolint:gosec // G115: a uid from Geteuid fits in the uint32 of Stat_t.
	sticky := os.ModeSticky
	tests := []struct {
		name  string
		mode  os.FileMode
		owner uint32 // the faked owner
		uid   int
		want  []string // nil means no error
	}{
		{"own 0700", 0o700, meOwner, me, nil},
		{"own 0755", 0o755, meOwner, me, nil},
		{"own 0555", 0o555, meOwner, me, nil},
		{"own 1777 sticky", 0o777 | sticky, meOwner, me, nil},
		{"own 1770 sticky", 0o770 | sticky, meOwner, me, nil},
		{"own 0777", 0o777, meOwner, me, []string{"mode 0777", msgWritable, msgChmod, privateConfigHint}},
		{"own 0775", 0o775, meOwner, me, []string{"mode 0775", msgWritable, msgChmod}},
		{"own 0757", 0o757, meOwner, me, []string{"mode 0757", msgWritable, msgChmod}},
		{"own 0770", 0o770, meOwner, me, []string{"mode 0770", msgWritable}},
		{"root 0755", 0o755, 0, me + 1, nil},
		{"root 1777 sticky", 0o777 | sticky, 0, me + 1, nil},
		{"root 0775", 0o775, 0, me + 1, []string{"mode 0775", msgWritable, "ask root to run chmod go-w -- '{path}'"}},
		{"root 0777 as root", 0o777, 0, 0, []string{"mode 0777", msgWritable, "(fix: chmod go-w -- '{path}'"}},
		{"foreign 0700", 0o700, other, me, []string{"mode 0700", msgForeign, "ask the owner or root to run chown"}},
		{"foreign 0755", 0o755, other, me, []string{"mode 0755", msgForeign}},
		{"foreign 1777 sticky", 0o777 | sticky, other, me, []string{"mode 1777", msgForeign}},
		{"foreign 0777", 0o777, other, me, []string{"mode 0777", msgForeign, msgWritable, msgChmod}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := newNamedPinsDir(t, "parent", tt.mode)
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatalf("Stat() error = %v", err)
			}
			err = checkParentOwnerAndMode(dir, fakeInfo{info, &syscall.Stat_t{Uid: tt.owner}}, tt.uid)
			if tt.want == nil {
				if err != nil {
					t.Errorf("checkParentOwnerAndMode() error = %v, want nil", err)
				}
				return
			}
			wantInsecure(t, err, dir, append(tt.want, "pins parent directory {path} is not safe")...)
		})
	}

	t.Run("exact text", func(t *testing.T) {
		t.Parallel()
		dir := newNamedPinsDir(t, "parent", 0o777)
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		want := "pins parent directory " + dir + " is not safe: mode 0777, writable by group or others (fix: chmod go-w -- '" +
			dir + "', or use a private XDG_CONFIG_HOME): insecure permissions"
		if err := checkParentOwnerAndMode(dir, info, me); err == nil || err.Error() != want {
			t.Errorf("error = %v\nwant    %q", err, want)
		}
	})

	t.Run("unknown owner fails closed", func(t *testing.T) {
		t.Parallel()
		dir := newNamedPinsDir(t, "parent", 0o700)
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		wantInsecure(t, checkParentOwnerAndMode(dir, fakeInfo{info, nil}, me), dir, "its owner is unknown")
	})

	t.Run("real root directory", func(t *testing.T) {
		t.Parallel()
		info, err := os.Stat("/")
		if err != nil {
			t.Fatalf("Stat(/) error = %v", err)
		}
		if err := checkParentOwnerAndMode("/", info, me); err != nil {
			t.Errorf("checkParentOwnerAndMode(/) error = %v, want nil", err)
		}
	})
}

// TestCheckParentsAs covers the walk over the parents of the pins directory,
// with an injected uid for a foreign owner.
func TestCheckParentsAs(t *testing.T) {
	t.Parallel()
	me := os.Geteuid()
	tests := []struct {
		name       string
		parentMode os.FileMode
		foreign    bool // check as another user, so the parent has a foreign owner
		missing    bool // the pins directory and two levels above it do not exist (a first run)
		relative   bool // pass the pins directory as a path relative to the working directory
		want       []string
	}{
		{"0700", 0o700, false, false, false, nil},
		{"0755", 0o755, false, false, false, nil},
		{"1777 sticky", 0o777 | os.ModeSticky, false, false, false, nil},
		{"0777", 0o777, false, false, false, []string{"mode 0777", msgWritable, msgChmod}},
		{"0775", 0o775, false, false, false, []string{"mode 0775", msgWritable, msgChmod}},
		{"foreign 0700", 0o700, true, false, false, []string{"mode 0700", msgForeign}},
		{"foreign 1777 sticky", 0o777 | os.ModeSticky, true, false, false, []string{"mode 1777", msgForeign}},
		{"first run, nearest ancestor 0755", 0o755, false, true, false, nil},
		{"first run, nearest ancestor 0777", 0o777, false, true, false, []string{"mode 0777", msgWritable, msgChmod}},
		{"relative, 0755", 0o755, false, false, true, nil},
		{"relative, 0777", 0o777, false, false, true, []string{"mode 0777", msgWritable, msgChmod}},
		{"relative first run, 0777", 0o777, false, true, true, []string{"mode 0777", msgWritable, msgChmod}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			uid := me
			if tt.foreign {
				if me == 0 {
					t.Skip("a parent owned by root is trusted, so root cannot fake a foreign owner")
				}
				uid = me + 1
			}
			parent := newNamedPinsDir(t, "cfg", 0o700)
			dir := filepath.Join(parent, "mcpmoat")
			if tt.missing {
				dir = filepath.Join(parent, "a", "b", "mcpmoat")
			} else if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
			chmodForTest(t, parent, tt.parentMode)
			arg := dir
			if tt.relative {
				wd, err := os.Getwd()
				if err != nil {
					t.Fatalf("Getwd() error = %v", err)
				}
				if arg, err = filepath.Rel(wd, dir); err != nil {
					t.Fatalf("Rel() error = %v", err)
				}
			}

			err := checkParentsAs(arg, uid)
			if tt.want == nil {
				if err != nil {
					t.Errorf("checkParentsAs(%q) error = %v, want nil", arg, err)
				}
				return
			}
			wantInsecure(t, err, parent, append(tt.want, "pins parent directory {path} is not safe")...)
		})
	}

	// checkParentsAs does not check the owner and the mode of the pins
	// directory itself: checkDirHandle does that. It checks only the symlink
	// rule there (TestCheckParentsAsSymlinks).
	t.Run("mode of the pins directory itself is not checked", func(t *testing.T) {
		t.Parallel()
		dir := newPinsDir(t, 0o777)
		if err := checkParentsAs(dir, me); err != nil {
			t.Errorf("checkParentsAs() error = %v, want nil", err)
		}
	})
}

// TestCheckSymlinkOwner covers the owner rule for a symlink on the path to the
// pins directory. The owner is faked with a Stat_t, so no test needs root.
func TestCheckSymlinkOwner(t *testing.T) {
	t.Parallel()
	me := os.Geteuid()
	const other = 4242 // a non-root owner that is not the current user
	if me == other {
		t.Skip("the current user has the uid of the fake owner")
	}
	meOwner := uint32(me) //nolint:gosec // G115: a uid from Geteuid fits in the uint32 of Stat_t.
	base := t.TempDir()
	link := filepath.Join(base, "link")
	if err := os.Symlink(base, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}

	tests := []struct {
		name string
		sys  any    // what info.Sys returns
		want string // the exact error text, {path} for link; "" means no error
	}{
		{"own", &syscall.Stat_t{Uid: meOwner}, ""},
		{"root", &syscall.Stat_t{Uid: 0}, ""},
		{"foreign", &syscall.Stat_t{Uid: other},
			"pins parent directory {path} is not safe: a symlink owned by another user (fix: ask the owner or root to remove or replace the symlink, or use a private XDG_CONFIG_HOME): insecure permissions"},
		{"unknown owner fails closed", nil,
			"pins parent directory {path} is not safe: the owner of the symlink is unknown: insecure permissions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checkSymlinkOwner(link, "pins parent directory", fakeInfo{info, tt.sys}, me)
			if tt.want == "" {
				if err != nil {
					t.Errorf("checkSymlinkOwner() error = %v, want nil", err)
				}
				return
			}
			wantInsecure(t, err, link)
			if want := strings.ReplaceAll(tt.want, "{path}", link); err.Error() != want {
				t.Errorf("error = %q\nwant    %q", err, want)
			}
		})
	}
}

// TestCheckParentsAsSymlinks covers the symlink rule of the parent walk: a
// symlink on the path to the pins directory, or the pins directory itself as
// a symlink, must belong to the current user or root. Each symlink is made
// by the test, so the current user owns it. A foreign owner is faked with
// another uid: checkParentsAs then sees the symlink as owned by someone else.
func TestCheckParentsAsSymlinks(t *testing.T) {
	t.Parallel()
	me := os.Geteuid()
	tests := []struct {
		name    string
		foreign bool // check as another user, so the symlink has a foreign owner
		leaf    bool // the pins directory itself is the symlink, not a component above it
		missing bool // the pins directory below the symlink does not exist (a first run)
		want    string
	}{
		{name: "own symlink component"},
		{name: "own symlink component, first run", missing: true},
		{name: "own symlink as the pins directory", leaf: true},
		{name: "foreign symlink component", foreign: true,
			want: "pins parent directory {path} is not safe: a symlink owned by another user"},
		{name: "foreign symlink component, first run", foreign: true, missing: true,
			want: "pins parent directory {path} is not safe: a symlink owned by another user"},
		{name: "foreign symlink as the pins directory", foreign: true, leaf: true,
			want: "pins directory {path} is not safe: a symlink owned by another user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			uid := me
			if tt.foreign {
				if me == 0 {
					t.Skip("a symlink owned by root is trusted, so root cannot fake a foreign owner")
				}
				uid = me + 1
			}
			// base/real is the target, base/link the symlink to it, as when
			// another user made /tmp/cfg a symlink to a directory we own.
			base := newNamedPinsDir(t, "base", 0o700)
			realDir := filepath.Join(base, "real")
			if err := os.Mkdir(realDir, 0o700); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
			link := filepath.Join(base, "link")
			if err := os.Symlink(realDir, link); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
			dir := filepath.Join(link, "mcpmoat")
			switch {
			case tt.leaf:
				dir = link
			case !tt.missing:
				if err := os.Mkdir(filepath.Join(realDir, "mcpmoat"), 0o700); err != nil {
					t.Fatalf("Mkdir() error = %v", err)
				}
			}

			err := checkParentsAs(dir, uid)
			if tt.want == "" {
				if err != nil {
					t.Errorf("checkParentsAs(%q) error = %v, want nil", dir, err)
				}
				return
			}
			wantInsecure(t, err, link, tt.want, "ask the owner or root to remove or replace the symlink", privateConfigHint)
		})
	}
}

// TestLoadThroughOwnSymlink runs Load, LoadLocked and Save through a config
// directory that is a symlink the current user owns. The symlink rule must
// let it pass, and a missing pins directory below it is still a first run.
func TestLoadThroughOwnSymlink(t *testing.T) {
	t.Parallel()
	base := newNamedPinsDir(t, "base", 0o700)
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	link := filepath.Join(base, "cfg")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	path := filepath.Join(link, "mcpmoat", "pins.json")

	s, err := Load(path)
	if err != nil || s.Existed() {
		t.Fatalf("Load() = %v, %v, want an empty store for a first run", s, err)
	}
	ls, release, err := LoadLocked(t.Context(), path, 0)
	if err != nil || ls.Existed() {
		release()
		t.Fatalf("LoadLocked() = %v, %v, want an empty store for a first run", ls, err)
	}
	if err := ls.Save(); err != nil {
		t.Errorf("Save() error = %v", err)
	}
	release()
	if s, err = Load(path); err != nil || !s.Existed() {
		t.Fatalf("Load() after Save = %v, %v, want the saved store", s, err)
	}
}

// newSymlinkedConfig builds base/real/cfg/mcpmoat/pins.json and a symlink
// base/link to base/real/cfg, as when ~/.config is a symlink. It sets the mode
// of base/real to realMode and returns the pins path through the link and the
// resolved path of base/real.
func newSymlinkedConfig(t *testing.T, realMode os.FileMode) (pinsPath, realResolved string) {
	t.Helper()
	realDir := newNamedPinsDir(t, "real", 0o700)
	pinsDir := filepath.Join(realDir, "cfg", "mcpmoat")
	if err := os.MkdirAll(pinsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	seedPins(t, pinsDir, 0o600)
	link := filepath.Join(filepath.Dir(realDir), "link")
	if err := os.Symlink(filepath.Join(realDir, "cfg"), link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	resolved, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}
	chmodForTest(t, realDir, realMode)
	return filepath.Join(link, "mcpmoat", "pins.json"), resolved
}

// TestLoadChecksParents runs the parent check through Load and LoadLocked on
// real directories (#207).
func TestLoadChecksParents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		parentMode os.FileMode
		missing    bool // a first run: the pins directory and one level above it do not exist
		want       []string
	}{
		{"0700", 0o700, false, nil},
		{"0755", 0o755, false, nil},
		{"1777 sticky", 0o777 | os.ModeSticky, false, nil},
		{"0777", 0o777, false, []string{"mode 0777", msgWritable, msgChmod, privateConfigHint}},
		{"0775", 0o775, false, []string{"mode 0775", msgWritable, msgChmod}},
		{"first run, nearest ancestor 0755", 0o755, true, nil},
		{"first run, nearest ancestor 0777", 0o777, true, []string{"mode 0777", msgWritable, msgChmod}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parent := newNamedPinsDir(t, "cfg", 0o700)
			pinsDir := filepath.Join(parent, "mcpmoat")
			if tt.missing {
				pinsDir = filepath.Join(parent, "sub", "mcpmoat")
			} else {
				if err := os.Mkdir(pinsDir, 0o700); err != nil {
					t.Fatalf("Mkdir() error = %v", err)
				}
				seedPins(t, pinsDir, 0o600)
			}
			path := filepath.Join(pinsDir, "pins.json")
			chmodForTest(t, parent, tt.parentMode)

			s, err := Load(path)
			if tt.want == nil {
				if err != nil || s == nil || s.Existed() == tt.missing {
					t.Errorf("Load() = %v, %v, want a store (existed = %v)", s, err, !tt.missing)
				}
			} else {
				if s != nil {
					t.Errorf("Load() store = %v, want nil", s)
				}
				wantInsecure(t, err, parent, append(tt.want, "read "+path, "pins parent directory {path} is not safe")...)
			}

			// LoadLocked checks the parents before it creates a missing pins
			// directory, so a refused run leaves nothing behind.
			ls, release, lerr := LoadLocked(t.Context(), path, 0)
			release()
			if tt.want == nil {
				if lerr != nil || ls == nil {
					t.Errorf("LoadLocked() = %v, %v, want a store", ls, lerr)
				}
				return
			}
			wantInsecure(t, lerr, parent, tt.want...)
			if tt.missing {
				if _, err := os.Lstat(filepath.Dir(pinsDir)); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("Lstat(%q) error = %v, want not exist: a refused LoadLocked must not create it", filepath.Dir(pinsDir), err)
				}
			}
			wantPerm(t, parent, tt.parentMode.Perm()) // refusing never changes the mode
		})
	}

	// A symlinked config directory is followed, and the walk over the resolved
	// path checks the parents of the target too. The lexical walk alone sees
	// only safe directories here.
	t.Run("symlinked config, real parent", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []os.FileMode{0o700, 0o755, 0o777, 0o775} {
			path, realDir := newSymlinkedConfig(t, mode)
			_, err := Load(path)
			if mode&0o022 == 0 {
				if err != nil {
					t.Errorf("real parent %04o: Load() error = %v, want nil", mode, err)
				}
				continue
			}
			wantInsecure(t, err, realDir, "pins parent directory {path} is not safe", fmt.Sprintf("mode %04o", mode), msgChmod)
		}
	})
}

// TestResolveExisting covers the resolved path of the parent walk.
func TestResolveExisting(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	baseReal, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}
	if err := os.Mkdir(filepath.Join(base, "real"), 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "link")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	loopA, loopB := filepath.Join(base, "loop-a"), filepath.Join(base, "loop-b")
	for _, l := range [][2]string{{loopB, loopA}, {loopA, loopB}} {
		if err := os.Symlink(l[0], l[1]); err != nil {
			t.Fatalf("Symlink() error = %v", err)
		}
	}

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"existing", base, baseReal, false},
		{"missing tail", filepath.Join(base, "a", "b"), filepath.Join(baseReal, "a", "b"), false},
		{"link with missing tail", filepath.Join(base, "link", "x", "y"), filepath.Join(baseReal, "real", "x", "y"), false},
		{"existing link", filepath.Join(base, "link"), filepath.Join(baseReal, "real"), false},
		{"symlink loop", filepath.Join(loopA, "x"), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveExisting(tt.in)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("resolveExisting(%q) = %q, %v, want %q, error %v", tt.in, got, err, tt.want, tt.wantErr)
			}
		})
	}
}
