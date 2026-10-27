//go:build darwin

package pins

// These tests cover the macOS ACL check (checkACL). The integration tests set
// real ACLs with chmod +a; the parser tests use hand-built byte slices.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
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
