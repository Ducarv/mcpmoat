//go:build darwin

package pins

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"syscall"
	"unsafe"
)

// Values from the macOS SDK headers <sys/attr.h> and <sys/kauth.h>. The
// comment after each value gives the header name.
const (
	attrBitMapCount         = 5          // ATTR_BIT_MAP_COUNT
	attrCmnExtendedSecurity = 0x00400000 // ATTR_CMN_EXTENDED_SECURITY
	attrCmnReturnedAttrs    = 0x80000000 // ATTR_CMN_RETURNED_ATTRS
	fsoptReportFullsize     = 0x00000004 // FSOPT_REPORT_FULLSIZE

	kauthFilesecMagic = 0x012cc16d // KAUTH_FILESEC_MAGIC
	kauthFilesecNoACL = 0xffffffff // KAUTH_FILESEC_NOACL
	kauthACEKindMask  = 0xf        // KAUTH_ACE_KINDMASK
	kauthACEPermit    = 1          // KAUTH_ACE_PERMIT

	kauthVnodeWriteData          = 1 << 2  // KAUTH_VNODE_WRITE_DATA, also KAUTH_VNODE_ADD_FILE
	kauthVnodeDelete             = 1 << 4  // KAUTH_VNODE_DELETE
	kauthVnodeAppendData         = 1 << 5  // KAUTH_VNODE_APPEND_DATA, also KAUTH_VNODE_ADD_SUBDIRECTORY
	kauthVnodeDeleteChild        = 1 << 6  // KAUTH_VNODE_DELETE_CHILD
	kauthVnodeWriteAttributes    = 1 << 8  // KAUTH_VNODE_WRITE_ATTRIBUTES
	kauthVnodeWriteExtattributes = 1 << 10 // KAUTH_VNODE_WRITE_EXTATTRIBUTES
	kauthVnodeWriteSecurity      = 1 << 12 // KAUTH_VNODE_WRITE_SECURITY
	kauthVnodeTakeOwnership      = 1 << 13 // KAUTH_VNODE_TAKE_OWNERSHIP, also KAUTH_VNODE_CHANGE_OWNER
	kauthACEGenericAll           = 1 << 21 // KAUTH_ACE_GENERIC_ALL
	kauthACEGenericWrite         = 1 << 23 // KAUTH_ACE_GENERIC_WRITE
)

// aclWriteRights is the ACE rights that let a principal change the path, its
// entries, its attributes, its ACL or its owner. kauth.h says that the kernel
// never tests the generic bits, but it also defines how they expand to the
// write bits. So they count too: the check fails closed.
const aclWriteRights = kauthVnodeWriteData | kauthVnodeDelete | kauthVnodeAppendData |
	kauthVnodeDeleteChild | kauthVnodeWriteAttributes | kauthVnodeWriteExtattributes |
	kauthVnodeWriteSecurity | kauthVnodeTakeOwnership | kauthACEGenericAll | kauthACEGenericWrite

// Sizes and offsets of the reply of fgetattrlist(2) and of struct
// kauth_filesec, from <sys/attr.h> and <sys/kauth.h>.
const (
	// The reply starts with a u_int32_t total length, then attribute_set_t
	// (ATTR_CMN_RETURNED_ATTRS, five u_int32_t), then attrreference_t
	// (ATTR_CMN_EXTENDED_SECURITY: int32_t attr_dataoffset, u_int32_t
	// attr_length). attr_dataoffset counts from the attrreference_t.
	replyReturnedCommonOff = 4
	replyRefOff            = 4 + 5*4
	replyFixedSize         = replyRefOff + 8

	// struct kauth_filesec: u_int32_t fsec_magic, guid_t fsec_owner (16
	// bytes), guid_t fsec_group (16 bytes), then struct kauth_acl:
	// u_int32_t acl_entrycount, u_int32_t acl_flags, then the entries.
	filesecEntryCountOff = 4 + 16 + 16
	filesecHeaderSize    = filesecEntryCountOff + 4 + 4

	// struct kauth_ace: guid_t ace_applicable (16 bytes), u_int32_t
	// ace_flags, kauth_ace_rights_t (u_int32_t) ace_rights.
	aceFlagsOff  = 16
	aceRightsOff = 20
	aceSize      = 24
)

// The size of the first reply buffer, and the largest buffer that checkACL
// accepts. 4 KiB holds more than KAUTH_ACL_MAX_ENTRIES (128) entries.
const (
	aclBufInitial = 4 << 10
	aclBufMax     = 64 << 10
)

// attrList is struct attrlist of <sys/attr.h>: u_short bitmapcount, u_int16_t
// reserved, then five attrgroup_t (u_int32_t). The Go layout is the same, 24
// bytes with no padding.
type attrList struct {
	bitmapCount uint16
	reserved    uint16
	commonAttr  uint32
	volAttr     uint32
	dirAttr     uint32
	fileAttr    uint32
	forkAttr    uint32
}

// checkACL returns an error that wraps ErrInsecurePermissions when the
// extended ACL of the open file f lets a principal write the pins path. On
// macOS an ACL is separate from the mode bits, so checkOwnerAndMode does not
// see it: chmod +a "everyone allow write" passes the mode check. path and kind
// are for the error text only; f is the open pins directory or pins.json.
//
// The path fails when any ACE of kind KAUTH_ACE_PERMIT holds a write right:
// write data or add file, append data or add subdirectory, delete, delete
// child, write attributes, write extended attributes, write security, take
// ownership, or a generic all or generic write right. This is true for every
// principal, also the owner of the path: to map the GUID of an ACE to a uid or
// a group needs the membership calls of libSystem, which a build without cgo
// cannot call. An ACE with inherit flags counts too, also when it applies only
// to new children: it gives other users write access to new files. Deny ACEs
// pass, for example the "everyone deny delete" that macOS puts on home
// directories. The fix hint is chmod -N, which removes the whole ACL.
//
// It fails closed: when it cannot read or parse the ACL, it returns an error
// that wraps ErrInsecurePermissions. A file system that does not report ACLs
// at all (the kernel does not return the attribute) passes, because then no
// ACL can exist.
//
// It checks only f. It does not check the ACLs of the parent directories.
//
// It reads the ACL with the fgetattrlist(2) system call and
// ATTR_CMN_EXTENDED_SECURITY, through f.SyscallConn, so the descriptor stays
// open during the call. Reading the com.apple.system.Security extended
// attribute fails with EPERM, and golang.org/x/sys/unix has no getattrlist
// wrapper. On darwin, syscall.Syscall6 is a direct kernel trap (svc or
// syscall instruction) and does not go through libc. Apple does not promise a
// stable system call interface. syscall.SYS_FGETATTRLIST (228) is the value
// in <sys/syscall.h> of the macOS SDK. If a later macOS changes it, the call
// fails or returns a reply that does not parse, and checkACL fails closed.
func checkACL(path, kind string, f *os.File) error {
	filesec, err := readFilesec(f)
	if err != nil {
		return aclReadError(path, kind, err)
	}
	writable, err := aclAllowsWrite(filesec)
	if err != nil {
		return aclReadError(path, kind, err)
	}
	if !writable {
		return nil
	}
	return fmt.Errorf("pins %s %s is not safe: its ACL lets a user or group write it (fix: chmod -N -- %s): %w",
		kind, path, shellQuote(path), ErrInsecurePermissions)
}

// aclReadError is the fail-closed error of checkACL when it cannot read or
// parse the ACL. It wraps ErrInsecurePermissions.
func aclReadError(path, kind string, err error) error {
	return fmt.Errorf("cannot read the ACL of the pins %s %s: %w: %w", kind, path, err, ErrInsecurePermissions)
}

// readFilesec returns the struct kauth_filesec of the open file f, as
// fgetattrlist(2) reports it for ATTR_CMN_EXTENDED_SECURITY. It returns nil
// and no error when f has no ACL, or when the file system does not report
// ACLs. The result is a slice of a buffer of at most aclBufMax bytes.
func readFilesec(f *os.File) ([]byte, error) {
	if f == nil {
		return nil, errors.New("no open file")
	}
	al := attrList{
		bitmapCount: attrBitMapCount,
		commonAttr:  attrCmnReturnedAttrs | attrCmnExtendedSecurity,
	}
	size := aclBufInitial
	// Two tries: the first with aclBufInitial bytes, the second with the
	// size that the kernel reported. If the ACL grows again between the two
	// calls, fail closed.
	for range 2 {
		buf := make([]byte, size)
		if err := fgetattrlist(f, &al, buf); err != nil {
			return nil, err
		}
		// FSOPT_REPORT_FULLSIZE: the first u_int32_t is the size that the
		// whole reply needs, also when it did not fit in buf.
		total := uint64(binary.NativeEndian.Uint32(buf))
		if total <= uint64(len(buf)) {
			return parseAttrReply(buf[:total])
		}
		if total > aclBufMax {
			return nil, fmt.Errorf("the ACL needs %d bytes, more than the limit of %d", total, aclBufMax)
		}
		size = int(total)
	}
	return nil, errors.New("the ACL changed while it was read")
}

// fgetattrlist calls fgetattrlist(2) on f with the request al and the reply
// buffer buf. buf must not be empty. It retries on EINTR.
func fgetattrlist(f *os.File, al *attrList, buf []byte) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return fmt.Errorf("fgetattrlist: %w", err)
	}
	var errno syscall.Errno
	ctrlErr := rc.Control(func(fd uintptr) {
		for {
			// The pointer conversions must stay in the call expression, so
			// the compiler keeps al and buf alive during the call.
			_, _, errno = syscall.Syscall6(syscall.SYS_FGETATTRLIST, fd,
				uintptr(unsafe.Pointer(al)),      //nolint:gosec // G103: fgetattrlist(2) reads struct attrlist; attrList has the same layout.
				uintptr(unsafe.Pointer(&buf[0])), //nolint:gosec // G103: the kernel writes at most len(buf) bytes; the reply is parsed with bounds checks.
				uintptr(len(buf)), fsoptReportFullsize, 0)
			if errno != syscall.EINTR {
				return
			}
		}
	})
	if ctrlErr != nil {
		return fmt.Errorf("fgetattrlist: %w", ctrlErr)
	}
	if errno != 0 {
		return fmt.Errorf("fgetattrlist: %w", errno)
	}
	return nil
}

// parseAttrReply returns the attribute data of ATTR_CMN_EXTENDED_SECURITY in
// the fgetattrlist(2) reply buf, which is cut to the reported length. It
// returns nil and no error when the kernel did not return the attribute or
// returned it with length 0: the file has no ACL, or the file system does not
// report ACLs. It returns an error for a reply that is short or that points
// outside buf.
func parseAttrReply(buf []byte) ([]byte, error) {
	if len(buf) < replyRefOff {
		return nil, fmt.Errorf("the reply has %d bytes, too short", len(buf))
	}
	returned := binary.NativeEndian.Uint32(buf[replyReturnedCommonOff:])
	if returned&attrCmnExtendedSecurity == 0 {
		return nil, nil
	}
	if len(buf) < replyFixedSize {
		return nil, fmt.Errorf("the reply has %d bytes, too short", len(buf))
	}
	// attr_dataoffset is an int32_t. Read it as a uint32: a value above
	// math.MaxInt32 is a negative offset, which this code refuses.
	off := binary.NativeEndian.Uint32(buf[replyRefOff:])
	length := int64(binary.NativeEndian.Uint32(buf[replyRefOff+4:]))
	if length == 0 {
		return nil, nil
	}
	if off > math.MaxInt32 {
		return nil, fmt.Errorf("the ACL data has the negative offset %d", int64(off)-(1<<32))
	}
	start := replyRefOff + int64(off)
	end := start + length
	if start < replyFixedSize || end > int64(len(buf)) {
		return nil, fmt.Errorf("the ACL data (offset %d, length %d) is outside the reply of %d bytes", off, length, len(buf))
	}
	return buf[start:end], nil
}

// aclAllowsWrite reports whether the struct kauth_filesec in filesec has a
// KAUTH_ACE_PERMIT entry with a right in aclWriteRights, for any principal.
// A nil or empty filesec, and an ACL with the entry count KAUTH_FILESEC_NOACL,
// mean no ACL. It returns an error for a filesec that is short, has the wrong
// magic number, or whose size does not match its entry count.
func aclAllowsWrite(filesec []byte) (bool, error) {
	if len(filesec) == 0 {
		return false, nil
	}
	if len(filesec) < filesecHeaderSize {
		return false, fmt.Errorf("the ACL data has %d bytes, too short", len(filesec))
	}
	if magic := binary.NativeEndian.Uint32(filesec); magic != kauthFilesecMagic {
		return false, fmt.Errorf("the ACL data has the magic number %#x, not %#x", magic, kauthFilesecMagic)
	}
	count := binary.NativeEndian.Uint32(filesec[filesecEntryCountOff:])
	if count == kauthFilesecNoACL {
		count = 0
	}
	// Compare in uint64, so count*aceSize cannot overflow. The size must
	// match exactly: other bytes would mean a layout that this code does not
	// know.
	if want := uint64(filesecHeaderSize) + uint64(count)*aceSize; uint64(len(filesec)) != want {
		return false, fmt.Errorf("the ACL data has %d bytes, but %d entries need %d", len(filesec), count, want)
	}
	for ace := filesec[filesecHeaderSize:]; len(ace) >= aceSize; ace = ace[aceSize:] {
		flags := binary.NativeEndian.Uint32(ace[aceFlagsOff:])
		rights := binary.NativeEndian.Uint32(ace[aceRightsOff:])
		if flags&kauthACEKindMask == kauthACEPermit && rights&aclWriteRights != 0 {
			return true, nil
		}
	}
	return false, nil
}
