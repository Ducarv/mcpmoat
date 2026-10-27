//go:build darwin

package pins

// These tests cover the macOS ACL check (checkACL). The integration tests set
// real ACLs with chmod +a; the parser tests use hand-built byte slices.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// aclAdd adds the ACL entry to path with chmod +a. It removes the whole ACL
// with chmod -N at the end, because an ACL (for example deny delete) can block
// the removal of t.TempDir. When chmod +a fails (a file system without ACLs, a
// sandbox), the test is skipped.
func aclAdd(t *testing.T, path, entry string) {
	t.Helper()
	t.Cleanup(func() { _ = exec.Command("chmod", "-N", path).Run() })                      //nolint:gosec // G204: fixed command, the test builds path under t.TempDir().
	if out, err := exec.Command("chmod", "+a", entry, path).CombinedOutput(); err != nil { //nolint:gosec // G204: fixed command, the entry is a test constant.
		t.Skipf("chmod +a %q: %v: %s", entry, err, out)
	}
}

// aclClear removes the ACL of path with chmod -N and fails the test on an
// error.
func aclClear(t *testing.T, path string) {
	t.Helper()
	if out, err := exec.Command("chmod", "-N", path).CombinedOutput(); err != nil { //nolint:gosec // G204: fixed command, the test builds path under t.TempDir().
		t.Fatalf("chmod -N: %v: %s", err, out)
	}
}

// aclCheckPath opens path and runs checkACL on it.
func aclCheckPath(t *testing.T, path, kind string) error {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: the test builds path under t.TempDir().
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = f.Close() }()
	return checkACL(path, kind, f)
}

// aclWantRefused fails the test unless err is the ACL refusal for path.
func aclWantRefused(t *testing.T, err error, path string) {
	t.Helper()
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("checkACL() error = %v, want it to wrap ErrInsecurePermissions", err)
	}
	for _, want := range []string{path, "ACL", "chmod -N -- " + shellQuote(path)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("checkACL() error = %q, want it to contain %q", err, want)
		}
	}
}

// aclTarget makes a pins directory or a pins.json in a pins directory.
func aclTarget(t *testing.T, kind string) string {
	t.Helper()
	dir := newPinsDir(t, 0o700)
	if kind == kindFile {
		return seedPins(t, dir, 0o600)
	}
	return dir
}

func TestCheckACLIntegration(t *testing.T) {
	t.Parallel()
	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current() error = %v", err)
	}
	tests := []struct {
		name    string
		entries []string // added in this order with chmod +a
		dirOnly bool
		refused bool
	}{
		{"no ACL", nil, false, false},
		{"everyone allow write", []string{"everyone allow write,append,delete"}, false, true},
		{"everyone deny delete", []string{"everyone deny delete"}, false, false},
		{"everyone allow read only", []string{"everyone allow read,readattr,readextattr,readsecurity"}, false, false},
		{"deny write then allow write", []string{"everyone deny write", "everyone allow write"}, false, true},
		{"allow writeattr", []string{"everyone allow writeattr"}, false, true},
		{"allow writesecurity", []string{"everyone allow writesecurity"}, false, true},
		{"allow chown", []string{"everyone allow chown"}, false, true},
		{"allow add_file", []string{"everyone allow add_file"}, true, true},
		{"allow add_subdirectory", []string{"everyone allow add_subdirectory"}, true, true},
		{"allow delete_child", []string{"everyone allow delete_child"}, true, true},
		// The check cannot map the GUID of an ACE to a uid without cgo, so an
		// entry for the owner itself is refused too: it fails closed by design.
		{"current user allow write", []string{"user:" + me.Username + " allow write"}, false, true},
	}
	for _, tt := range tests {
		for _, kind := range []string{kindDir, kindFile} {
			if tt.dirOnly && kind == kindFile {
				continue
			}
			t.Run(tt.name+"/"+kind, func(t *testing.T) {
				t.Parallel()
				path := aclTarget(t, kind)
				for _, e := range tt.entries {
					aclAdd(t, path, e)
				}
				err := aclCheckPath(t, path, kind)
				if !tt.refused {
					if err != nil {
						t.Errorf("checkACL() error = %v, want nil", err)
					}
					return
				}
				aclWantRefused(t, err, path)

				// After chmod -N the path has no ACL and passes again.
				aclClear(t, path)
				if err := aclCheckPath(t, path, kind); err != nil {
					t.Errorf("checkACL() after chmod -N error = %v, want nil", err)
				}
			})
		}
	}
}

// TestLoadRefusesACL checks that Load runs the ACL check on the pins directory
// and on pins.json.
func TestLoadRefusesACL(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{kindDir, kindFile} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			dir := newPinsDir(t, 0o700)
			path := seedPins(t, dir, 0o600)
			target, entry := dir, "everyone allow add_file"
			if kind == kindFile {
				target, entry = path, "everyone allow write"
			}
			aclAdd(t, target, entry)

			s, err := Load(path)
			if s != nil {
				t.Errorf("Load() store = %v, want nil", s)
			}
			aclWantRefused(t, err, target)
			if !strings.Contains(err.Error(), "pins "+kind+" "+target) {
				t.Errorf("Load() error = %q, want it to name the pins %s", err, kind)
			}
		})
	}
}

// TestCheckACLNoFile checks that checkACL fails closed without a usable file.
func TestCheckACLNoFile(t *testing.T) {
	t.Parallel()
	path := seedPins(t, newPinsDir(t, 0o700), 0o600)
	f, err := os.Open(path) //nolint:gosec // G304: the test builds path under t.TempDir().
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	_ = f.Close()
	for name, file := range map[string]*os.File{"nil file": nil, "closed file": f} {
		err := checkACL(path, kindFile, file)
		if !errors.Is(err, ErrInsecurePermissions) || !strings.Contains(err.Error(), "cannot read the ACL of the pins file "+path) {
			t.Errorf("%s: checkACL() error = %v, want a fail-closed ErrInsecurePermissions", name, err)
		}
	}
}

// aclACE is one struct kauth_ace for aclFilesec: the flags and the rights. The
// GUID stays zero.
type aclACE struct{ flags, rights uint32 }

// aclFilesec builds a struct kauth_filesec with the given magic, entry count
// and entries, in native byte order, and adds extra bytes at the end.
func aclFilesec(magic, count uint32, aces []aclACE, extra int) []byte {
	b := make([]byte, filesecHeaderSize+len(aces)*aceSize+extra)
	binary.NativeEndian.PutUint32(b, magic)
	binary.NativeEndian.PutUint32(b[filesecEntryCountOff:], count)
	for i, a := range aces {
		e := b[filesecHeaderSize+i*aceSize:]
		binary.NativeEndian.PutUint32(e[aceFlagsOff:], a.flags)
		binary.NativeEndian.PutUint32(e[aceRightsOff:], a.rights)
	}
	return b
}

// aclEntries builds a valid filesec with the given entries.
func aclEntries(aces ...aclACE) []byte {
	return aclFilesec(kauthFilesecMagic, uint32(len(aces)), aces, 0) //nolint:gosec // G115: tests use a few entries.
}

func TestACLAllowsWrite(t *testing.T) {
	t.Parallel()
	// Values from <sys/kauth.h> that acl_darwin.go does not name.
	const (
		aceDeny        = 2       // KAUTH_ACE_DENY
		aceAudit       = 3       // KAUTH_ACE_AUDIT
		aceAlarm       = 4       // KAUTH_ACE_ALARM
		aceInherited   = 1 << 4  // KAUTH_ACE_INHERITED
		aceFileInherit = 1 << 5  // KAUTH_ACE_FILE_INHERIT
		aceOnlyInherit = 1 << 8  // KAUTH_ACE_ONLY_INHERIT
		vnodeReadData  = 1 << 1  // KAUTH_VNODE_READ_DATA
		vnodeExecute   = 1 << 3  // KAUTH_VNODE_EXECUTE
		vnodeReadAttrs = 1 << 7  // KAUTH_VNODE_READ_ATTRIBUTES
		vnodeReadSec   = 1 << 11 // KAUTH_VNODE_READ_SECURITY
		genericRead    = 1 << 24 // KAUTH_ACE_GENERIC_READ
		readOnlyRights = vnodeReadData | vnodeExecute | vnodeReadAttrs | vnodeReadSec | genericRead
	)
	permitWrite := aclACE{kauthACEPermit, kauthVnodeWriteData}
	tests := []struct {
		name    string
		in      []byte
		want    bool
		wantErr bool
	}{
		{"nil", nil, false, false},
		{"empty", []byte{}, false, false},
		{"short", make([]byte, filesecHeaderSize-1), false, true},
		{"bad magic", aclFilesec(0x12345678, 0, nil, 0), false, true},
		{"NOACL", aclFilesec(kauthFilesecMagic, kauthFilesecNoACL, nil, 0), false, false},
		{"NOACL with trailing bytes", aclFilesec(kauthFilesecMagic, kauthFilesecNoACL, nil, aceSize), false, true},
		{"zero entries", aclEntries(), false, false},
		{"count too large for the data", aclFilesec(kauthFilesecMagic, 2, []aclACE{permitWrite}, 0), false, true},
		{"count 0xfffffffe", aclFilesec(kauthFilesecMagic, 0xfffffffe, []aclACE{permitWrite}, 0), false, true},
		{"trailing bytes after the entries", aclFilesec(kauthFilesecMagic, 1, []aclACE{permitWrite}, 4), false, true},
		{"one permit write entry", aclEntries(permitWrite), true, false},
		{"inherited permit write", aclEntries(aclACE{kauthACEPermit | aceInherited, kauthVnodeWriteData}), true, false},
		{"only-inherit permit write", aclEntries(aclACE{kauthACEPermit | aceFileInherit | aceOnlyInherit, kauthVnodeWriteData}), true, false},
		{"deny write", aclEntries(aclACE{aceDeny, aclWriteRights}), false, false},
		{"audit write", aclEntries(aclACE{aceAudit, aclWriteRights}), false, false},
		{"alarm write", aclEntries(aclACE{aceAlarm, aclWriteRights}), false, false},
		{"permit read only", aclEntries(aclACE{kauthACEPermit, readOnlyRights}), false, false},
		{"permit no rights", aclEntries(aclACE{kauthACEPermit, 0}), false, false},
		{"GENERIC_WRITE", aclEntries(aclACE{kauthACEPermit, kauthACEGenericWrite}), true, false},
		{"GENERIC_ALL", aclEntries(aclACE{kauthACEPermit, kauthACEGenericAll}), true, false},
		{"write as the second of two", aclEntries(aclACE{kauthACEPermit, readOnlyRights}, permitWrite), true, false},
		{"deny then permit write", aclEntries(aclACE{aceDeny, aclWriteRights}, permitWrite), true, false},
	}
	// Each write right alone is enough.
	for _, r := range []uint32{kauthVnodeWriteData, kauthVnodeDelete, kauthVnodeAppendData, kauthVnodeDeleteChild,
		kauthVnodeWriteAttributes, kauthVnodeWriteExtattributes, kauthVnodeWriteSecurity, kauthVnodeTakeOwnership} {
		tests = append(tests, struct {
			name    string
			in      []byte
			want    bool
			wantErr bool
		}{fmt.Sprintf("permit right %#x", r), aclEntries(aclACE{kauthACEPermit, r}), true, false})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := aclAllowsWrite(tt.in)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("aclAllowsWrite() = %v, %v, want %v, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

// aclReply builds an fgetattrlist(2) reply: the total length, the returned
// common attributes, the attrreference_t (offset and length) and data after
// it. The total length field holds the length of the result.
func aclReply(returned, off, length uint32, data []byte) []byte {
	b := make([]byte, replyFixedSize, replyFixedSize+len(data))
	binary.NativeEndian.PutUint32(b[replyReturnedCommonOff:], returned)
	binary.NativeEndian.PutUint32(b[replyRefOff:], off)
	binary.NativeEndian.PutUint32(b[replyRefOff+4:], length)
	b = append(b, data...)
	binary.NativeEndian.PutUint32(b, uint32(len(b))) //nolint:gosec // G115: test replies are small.
	return b
}

func TestParseAttrReply(t *testing.T) {
	t.Parallel()
	// dataOff is the offset of data that starts right after the
	// attrreference_t: the offset counts from the attrreference_t.
	const dataOff = replyFixedSize - replyRefOff
	const sec uint32 = attrCmnExtendedSecurity
	data := []byte("ABCDEFGH")
	tests := []struct {
		name    string
		in      []byte
		want    []byte
		wantErr bool
	}{
		{"empty", nil, nil, true},
		{"4 bytes", []byte{1, 2, 3, 4}, nil, true},
		{"one byte short of the returned attributes", make([]byte, replyRefOff-1), nil, true},
		{"attribute not returned", aclReply(0, dataOff, 4, data)[:replyRefOff], nil, false},
		{"attribute not returned, other bits set", aclReply(^sec, dataOff, 4, data), nil, false},
		{"returned but too short", aclReply(sec, 0, 0, nil)[:replyFixedSize-1], nil, true},
		{"zero length", aclReply(sec, dataOff, 0, nil), nil, false},
		{"valid", aclReply(sec, dataOff, 4, data), []byte("ABCD"), false},
		{"valid, all data", aclReply(sec, dataOff, 8, data), data, false},
		{"valid, later offset", aclReply(sec, dataOff+4, 4, data), []byte("EFGH"), false},
		{"negative offset", aclReply(sec, 0xfffffff0, 4, data), nil, true},
		{"offset into the header", aclReply(sec, 0, 4, data), nil, true},
		{"offset one byte into the header", aclReply(sec, dataOff-1, 4, data), nil, true},
		{"offset past the end", aclReply(sec, dataOff+8, 1, data), nil, true},
		{"length one byte past the end", aclReply(sec, dataOff, 9, data), nil, true},
		{"huge offset", aclReply(sec, 0x7fffffff, 4, data), nil, true},
		{"huge length", aclReply(sec, dataOff, 0xffffffff, data), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseAttrReply(tt.in)
			if (err != nil) != tt.wantErr || !bytes.Equal(got, tt.want) || (got == nil) != (tt.want == nil) {
				t.Errorf("parseAttrReply() = %q, %v, want %q, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

// TestReadFilesecReal checks the system call on a real file: a path without an
// ACL gives no filesec, and a path with an ACL gives one that parses.
func TestReadFilesecReal(t *testing.T) {
	t.Parallel()
	path := filepath.Join(newPinsDir(t, 0o700), "f")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	read := func() []byte {
		f, err := os.Open(path) //nolint:gosec // G304: the test builds path under t.TempDir().
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer func() { _ = f.Close() }()
		sec, err := readFilesec(f)
		if err != nil {
			t.Fatalf("readFilesec() error = %v", err)
		}
		return sec
	}
	if sec := read(); len(sec) != 0 {
		if w, err := aclAllowsWrite(sec); err != nil || w {
			t.Errorf("no ACL: aclAllowsWrite() = %v, %v, want false, nil", w, err)
		}
	}
	aclAdd(t, path, "everyone allow write")
	sec := read()
	if w, err := aclAllowsWrite(sec); err != nil || !w {
		t.Errorf("allow write: aclAllowsWrite() = %v, %v, want true, nil", w, err)
	}
}

// aclParentSetup makes base/cfg/mcpmoat/pins.json with private modes and
// returns the parent directory cfg, the pins directory and the pins file.
func aclParentSetup(t *testing.T) (parent, pinsDir, path string) {
	t.Helper()
	parent = newNamedPinsDir(t, "cfg", 0o700)
	pinsDir = filepath.Join(parent, "mcpmoat")
	if err := os.Mkdir(pinsDir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	return parent, pinsDir, seedPins(t, pinsDir, 0o600)
}

// aclWantParentRefused fails the test unless err is the ACL refusal of the
// parent directory parent (a real path) for the entry index, with the chmod
// -a# hint for the owner and without "--" or chmod -N.
func aclWantParentRefused(t *testing.T, err error, parent string, index int) {
	t.Helper()
	cmd := fmt.Sprintf("chmod -a# %d %s", index, shellQuote(parent))
	wantInsecure(t, err, parent,
		"pins parent directory {path} is not safe",
		fmt.Sprintf("its ACL entry %d lets a user or group change it", index),
		"(fix: "+cmd+", "+privateConfigHint,
		"ls -led "+shellQuote(parent))
	for _, bad := range []string{"chmod -N", fmt.Sprintf("chmod -a# %d -- ", index)} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("error = %q, must not contain %q", err, bad)
		}
	}
}

// TestParentACL checks that the parent walk refuses a parent directory whose
// ACL has an allow entry with a write-class right (#217), through
// checkParents, Load and LoadLocked, and that deny entries pass.
func TestParentACL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entries []string // added in this order with chmod +a
		index   int      // the index in the hint; -1 means no refusal
	}{
		{"no ACL", nil, -1},
		{"allow delete_child", []string{"everyone allow delete_child"}, 0},
		{"allow add_subdirectory", []string{"everyone allow add_subdirectory"}, 0},
		{"allow add_file", []string{"everyone allow add_file"}, 0},
		{"allow writesecurity", []string{"everyone allow writesecurity"}, 0},
		{"allow write", []string{"everyone allow write"}, 0},
		{"allow delete", []string{"everyone allow delete"}, 0},
		{"allow chown", []string{"everyone allow chown"}, 0},
		{"allow read only", []string{"everyone allow list,search,readattr,readextattr,readsecurity"}, -1},
		{"deny delete", []string{"everyone deny delete"}, -1},
		{"deny delete, then allow delete_child", []string{"everyone deny delete", "everyone allow delete_child"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parent, pinsDir, path := aclParentSetup(t)
			for _, e := range tt.entries {
				aclAdd(t, parent, e)
			}
			resolved := realPath(t, parent)

			checkErr := checkParents(pinsDir)
			s, loadErr := Load(path)
			ls, release, lockErr := LoadLocked(t.Context(), path, 0)
			release()
			if tt.index < 0 {
				if checkErr != nil || loadErr != nil || lockErr != nil {
					t.Errorf("checkParents, Load, LoadLocked errors = %v, %v, %v, want nil", checkErr, loadErr, lockErr)
				}
				return
			}
			for name, err := range map[string]error{"checkParents": checkErr, "Load": loadErr, "LoadLocked": lockErr} {
				t.Run(name, func(t *testing.T) { aclWantParentRefused(t, err, resolved, tt.index) })
			}
			if s != nil || ls != nil {
				t.Errorf("Load() and LoadLocked() stores = %v, %v, want nil", s, ls)
			}
			// LoadLocked checks the parents before it opens the lock file.
			if _, err := os.Lstat(path + lockSuffix); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Lstat(lock file) error = %v, want not exist after a refusal", err)
			}
		})
	}

	// An ACL on the pins directory itself is not a parent ACL: the check of
	// the pins directory handle (checkACL) refuses it, with its own hint.
	t.Run("ACL on the pins directory only", func(t *testing.T) {
		t.Parallel()
		_, pinsDir, path := aclParentSetup(t)
		aclAdd(t, pinsDir, "everyone allow add_file")
		if err := checkParents(pinsDir); err != nil {
			t.Errorf("checkParents() error = %v, want nil: the pins directory is not its own parent", err)
		}
		_, err := Load(path)
		aclWantRefused(t, err, pinsDir)
		if !strings.Contains(err.Error(), "pins directory "+pinsDir) || strings.Contains(err.Error(), "parent") {
			t.Errorf("Load() error = %q, want the pins directory check, not the parent check", err)
		}
	})
}

// TestCheckParentACLHint covers the owner variants of the checkParentACL hint.
// The owner comes from info, so a faked Stat_t covers root and another user.
func TestCheckParentACLHint(t *testing.T) {
	t.Parallel()
	me := os.Geteuid()
	meOwner := uint32(me) //nolint:gosec // G115: a uid from Geteuid fits in the uint32 of Stat_t.
	dir := newNamedPinsDir(t, "my parent'dir", 0o700)
	aclAdd(t, dir, "everyone allow delete_child")
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	cmd := "chmod -a# 0 " + shellQuote(dir)
	tests := []struct {
		name string
		info fs.FileInfo
		uid  int
		fix  string
	}{
		{"own, real info", info, me, "(fix: " + cmd + ", "},
		{"own, faked", fakeInfo{info, &syscall.Stat_t{Uid: meOwner}}, me, "(fix: " + cmd + ", "},
		{"root owns it", fakeInfo{info, &syscall.Stat_t{Uid: 0}}, me + 1, "(fix: ask root to run " + cmd + ", "},
		{"another user owns it", fakeInfo{info, &syscall.Stat_t{Uid: 4242}}, me + 1, "(fix: ask the owner or root to run " + cmd + ", "},
		{"unknown owner", fakeInfo{info, nil}, me, "(fix: ask the owner or root to run " + cmd + ", "},
		{"no info", nil, me, "(fix: ask the owner or root to run " + cmd + ", "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checkParentACL(dir, tt.info, tt.uid)
			wantInsecure(t, err, dir, tt.fix, "pins parent directory {path} is not safe")
			if strings.Contains(err.Error(), "chmod -N") || strings.Contains(err.Error(), "-- ") {
				t.Errorf("checkParentACL() error = %q, want no chmod -N and no --", err)
			}
		})
	}

	t.Run("exact text", func(t *testing.T) {
		t.Parallel()
		want := "pins parent directory " + dir + " is not safe: its ACL entry 0 lets a user or group change it (fix: " +
			cmd + ", or use a private XDG_CONFIG_HOME; ls -led " + shellQuote(dir) + " shows the entries): insecure permissions"
		if err := checkParentACL(dir, info, me); err == nil || err.Error() != want {
			t.Errorf("error = %v\nwant    %q", err, want)
		}
	})

	t.Run("no ACL passes", func(t *testing.T) {
		t.Parallel()
		clean := newNamedPinsDir(t, "clean", 0o700)
		if err := checkParentACL(clean, nil, me); err != nil {
			t.Errorf("checkParentACL() error = %v, want nil", err)
		}
	})

	t.Run("missing path fails closed", func(t *testing.T) {
		t.Parallel()
		missing := filepath.Join(t.TempDir(), "missing")
		err := checkParentACL(missing, nil, me)
		wantInsecure(t, err, missing, "cannot read the ACL of the pins parent directory {path}")
	})
}

func TestFirstPermitACE(t *testing.T) {
	t.Parallel()
	// Values from <sys/kauth.h> that acl_darwin.go does not name.
	const (
		aceDeny        = 2       // KAUTH_ACE_DENY
		vnodeReadAttrs = 1 << 7  // KAUTH_VNODE_READ_ATTRIBUTES
		vnodeReadSec   = 1 << 11 // KAUTH_VNODE_READ_SECURITY
	)
	permit := func(r uint32) aclACE { return aclACE{kauthACEPermit, r} }
	write, open := uint32(aclWriteRights), uint32(lockOpenRights)
	tests := []struct {
		name      string
		in        []byte
		rights    uint32
		wantIndex int
		wantFound bool
		wantErr   bool
	}{
		{"nil", nil, open, 0, false, false},
		{"short", make([]byte, filesecHeaderSize-1), open, 0, false, true},
		{"bad magic", aclFilesec(0x12345678, 0, nil, 0), open, 0, false, true},
		{"read data opens the lock file", aclEntries(permit(kauthVnodeReadData)), open, 0, true, false},
		{"read data is not a write right", aclEntries(permit(kauthVnodeReadData)), write, 0, false, false},
		{"execute opens the lock file", aclEntries(permit(kauthVnodeExecute)), open, 0, true, false},
		{"execute is not a write right", aclEntries(permit(kauthVnodeExecute)), write, 0, false, false},
		{"generic read", aclEntries(permit(kauthACEGenericRead)), open, 0, true, false},
		{"generic execute", aclEntries(permit(kauthACEGenericExecute)), open, 0, true, false},
		{"write data opens the lock file", aclEntries(permit(kauthVnodeWriteData)), open, 0, true, false},
		{"read attributes and security only", aclEntries(permit(vnodeReadAttrs | vnodeReadSec)), open, 0, false, false},
		{"deny read", aclEntries(aclACE{aceDeny, open}), open, 0, false, false},
		{"index of the first match, open", aclEntries(aclACE{aceDeny, open}, permit(vnodeReadAttrs), permit(kauthVnodeReadData), permit(kauthVnodeWriteData)), open, 2, true, false},
		{"index of the first match, write", aclEntries(aclACE{aceDeny, open}, permit(vnodeReadAttrs), permit(kauthVnodeReadData), permit(kauthVnodeDeleteChild)), write, 3, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			index, found, err := firstPermitACE(tt.in, tt.rights)
			if (err != nil) != tt.wantErr || found != tt.wantFound || index != tt.wantIndex {
				t.Errorf("firstPermitACE() = %d, %v, %v, want %d, %v, error %v", index, found, err, tt.wantIndex, tt.wantFound, tt.wantErr)
			}
			if tt.rights != write {
				return
			}
			// firstWriteACE is firstPermitACE with aclWriteRights.
			wi, wf, werr := firstWriteACE(tt.in)
			if wi != index || wf != found || (werr != nil) != (err != nil) {
				t.Errorf("firstWriteACE() = %d, %v, %v, want the result of firstPermitACE", wi, wf, werr)
			}
		})
	}
}

// TestCheckLockFileACL checks that a lock file with an allow entry that lets a
// user or group open it is refused, with the rm hint, and that deny entries
// and read-attribute entries pass.
func TestCheckLockFileACL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entries []string
		refused bool
	}{
		{"no ACL", nil, false},
		{"allow read", []string{"everyone allow read"}, true},
		{"allow execute", []string{"everyone allow execute"}, true},
		{"allow write", []string{"everyone allow write"}, true},
		{"allow readattr only", []string{"everyone allow readattr,readsecurity"}, false},
		// A deny entry for everyone would lock the test out too, so it names nobody.
		{"deny read", []string{"user:nobody deny read,execute,write"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(newPinsDir(t, 0o700), "pins.json"+lockSuffix)
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			for _, e := range tt.entries {
				aclAdd(t, path, e)
			}
			check := func() error {
				f, err := os.Open(path) //nolint:gosec // G304: the test builds path under t.TempDir().
				if err != nil {
					t.Fatalf("Open() error = %v", err)
				}
				defer func() { _ = f.Close() }()
				return checkLockFileACL(path, f)
			}
			err := check()
			if !tt.refused {
				if err != nil {
					t.Errorf("checkLockFileACL() error = %v, want nil", err)
				}
				return
			}
			aclWantLockRefused(t, err, path)

			// LoadLocked refuses it too, and does not remove the ACL.
			_, release, err := LoadLocked(t.Context(), filepath.Join(filepath.Dir(path), "pins.json"), 0)
			release()
			aclWantLockRefused(t, err, path)
			aclWantLockRefused(t, check(), path)
		})
	}

	t.Run("no usable file fails closed", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(newPinsDir(t, 0o700), "pins.json"+lockSuffix)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		f, err := os.Open(path) //nolint:gosec // G304: the test builds path under t.TempDir().
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		_ = f.Close()
		for name, file := range map[string]*os.File{"nil file": nil, "closed file": f} {
			t.Run(name, func(t *testing.T) {
				wantInsecure(t, checkLockFileACL(path, file), path, "cannot read the ACL of the pins lock file {path}")
			})
		}
	})
}

// aclWantLockRefused fails the test unless err is the ACL refusal of the lock
// file path, with the rm hint and never chmod.
func aclWantLockRefused(t *testing.T, err error, path string) {
	t.Helper()
	wantInsecure(t, err, path, "pins lock file {path} is not safe: its ACL entry 0 lets a user or group open it",
		"(fix: rm -- "+shellQuote(path)+";")
	if strings.Contains(err.Error(), "chmod") {
		t.Errorf("error = %q, the fix must be rm, never chmod", err)
	}
}
