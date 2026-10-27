package pins

import (
	"cmp"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/safefile"
)

// CurrentVersion is the format version of pins.json that this mcpmoat reads
// and writes.
//
// The shape of version 1 changed in place before the first release, so no
// released file has an older v1 shape. Any change of the shape after the first
// release needs a version bump.
const CurrentVersion = 1

// MaxFileSize is the largest pins.json that Load reads and Save writes, in
// bytes of indented JSON: 32 MiB. It is a ceiling for the whole file. Set
// refuses a server whose entry would make the file larger than this
// (ErrStoreFull), so the servers that fit are still saved and only the refused
// server is not pinned (see maxServerSize). It is exported so that the
// messages of the CLI show the same limit.
const MaxFileSize = 32 << 20

// MaxFileSizeMiB is MaxFileSize in MiB (1 MiB is 1<<20 bytes, so the shift
// divides by 1<<20). The error texts of the store and the messages of the CLI
// use it, so they show the same limit.
const MaxFileSizeMiB = MaxFileSize >> 20

// maxServerSize is the largest entry of one server that Load and Set accept,
// in bytes of compact JSON. Each tool stores its canonical text next to its
// hash, so a server with 100 tools needs about 100 KiB or more. A server sends
// its own tool names and schemas, so this cap stops one server from filling
// the file alone.
//
// The cap does not stop several servers together: MaxFileSize divided by
// maxServerSize is 16, so about 16 servers at full size fill the file. Set
// then refuses the next server that does not fit with ErrStoreFull, and the
// servers that are already in the store are still saved. The caller must
// report the refused server: it is not pinned, and that is a known ceiling,
// not a silent loss. projectShare stops the project servers from using up
// the whole file.
const maxServerSize = 2 << 20

// projectShare is the largest number of bytes that the entries of all project
// servers together may take in the file that Save writes: half of
// MaxFileSize, 16 MiB. A project server is a server whose Identity has a
// ProjectPath (see isProjectServer). The size is the sum of entrySize of
// those entries, the same measure as the file limit, so the two limits agree.
//
// The share exists because a project config can come from a repository that
// the user cloned and does not control. Such a config can declare many
// servers that return large tools, and scan pins a new server on its first
// run. Without the share, these servers could fill pins.json, and then every
// new server, also one from the user's own config, would be refused
// (ErrStoreFull) and never pinned. With the share, the servers of the user
// scope (an empty ProjectPath) always have the other half of the file.
//
// The share does not protect one project from another: all project servers
// together share the 16 MiB. The servers of the user scope may use the whole
// file, so they can still fill it.
const projectShare = MaxFileSize / 2

// ProjectShareMiB is projectShare in MiB, the share of the pins file that the
// project servers may use together (16). The error texts of the store and the
// messages of the CLI use it, so they show the same limit (see
// MaxFileSizeMiB).
const ProjectShareMiB = projectShare >> 20

// indent is the indent of one level of the JSON that Save writes.
const indent = "  "

// saveOptions are the JSON options of Save. entrySize uses them too, so the
// size that Set tracks is the size that Save writes. Deterministic sorts the
// map keys. encoding/json/v2 does not escape <, > and &, so such a tool name
// keeps its size in the file.
//
// json.JoinOptions joins several options into one value. It is a var, not a
// const: an option is a value of an interface type, and Go has no constant of
// such a type.
var saveOptions = json.JoinOptions(jsontext.WithIndent(indent), json.Deterministic(true))

// ErrUnsupportedVersion means that pins.json has a format version that this
// mcpmoat does not know, because the file is newer. Load never reads such a
// file, so an old binary cannot overwrite it. Test for it with errors.Is.
var ErrUnsupportedVersion = errors.New("unsupported pins.json version")

// ErrStoreFull means that Set refused a server because its entry would make
// the pins file larger than MaxFileSize (32 MiB). The store did not change, so
// the other servers can still be saved. The refused server is not pinned, and
// the caller must report it. Test for it with errors.Is.
var ErrStoreFull = errors.New("the pins file would be too large")

// ErrProjectShareFull means that Set refused a project server (a server whose
// Identity has a ProjectPath) because the entries of all project servers
// together would take more than their share of the pins file, ProjectShareMiB
// (16 MiB, half of MaxFileSize). An error with ErrProjectShareFull also wraps
// ErrStoreFull, so a caller that tests only for ErrStoreFull still sees a full
// store. A caller that wants to say that the project share is full tests for
// ErrProjectShareFull first. As with ErrStoreFull, the store did not change,
// the other servers can still be saved, and the refused server is not pinned:
// the caller must report it. Test for it with errors.Is.
var ErrProjectShareFull = errors.New("the project servers would use more than their share of the pins file")

// ErrPinsDirChanged means that Save found, right before the rename, that the
// path of the pins directory no longer names the directory that the Store
// opened: something moved, removed or replaced it while the command ran. Save
// then wrote nothing (the temp file is removed), so no pin is lost to a
// directory that the next run does not read, and two runs that hold the locks
// of two different lock files (one in the old directory, one in the new) cannot
// both write. The error text names the directory. Test for it with errors.Is.
var ErrPinsDirChanged = errors.New("the pins directory changed")

// Identity names one MCP server in the pins store.
//
// The fields hold the client, the config file, the project path and the
// server name only. They never hold a secret: no args, URL, env, headers or
// command. ProjectPath is empty for a global server.
//
// All fields are strings, so Identity is comparable and a valid map key.
type Identity struct {
	// Client is the client that owns the config, for example "claude-code".
	Client string
	// Source is the path of the config file that declares the server.
	Source string
	// ProjectPath is the project that the server belongs to. It is empty for a
	// global server.
	ProjectPath string
	// Name is the name of the server in the config. It must not be empty.
	Name string
}

// Pin is the stored state of one tool: its hash and its canonical text. The
// text lets a later run show a diff of a changed tool.
//
// Both fields are required and not empty. The store does not check their
// format: the hashing code owns it. The canonical text comes from a server that
// we do not trust, so code that prints it must escape it (internal/termsafe).
type Pin struct {
	// Hash is the hash of the tool, as Hash returns it, for example
	// "sha256-v1:...".
	Hash string `json:"hash"`
	// Canonical is the canonical JSON text of the tool, as Canonical returns it.
	// It is the input of Hash.
	Canonical string `json:"canonical"`
}

// ServerPins maps a tool name to the Pin of that tool.
//
// The server chose the tool names, and they can hold control characters. Code
// that prints a name from the store must escape it (internal/termsafe), as it
// does for a name from a live server.
type ServerPins map[string]Pin

// Store holds the pins of all servers and the path of the pins file.
//
// A Store is safe for use by several goroutines. Two processes that save to
// the same path do not corrupt the file (the write is atomic), but without a
// lock the last writer wins. So a run can drop the first pins that a parallel
// run saved, and the next run then sees that server as new, with no alert. A
// run that loads with LoadLocked, saves, and only then releases the lock
// cannot lose the update of another such run (see LoadLocked for the limits).
//
// A Store from LoadLocked keeps the pins directory open: the os.Root, a handle
// of the directory and its file info. Save writes through them, so it writes
// to the directory that LoadLocked checked, and whose lock file it locked, not
// to whatever the path names at that time. The release function of
// LoadLocked closes them and the lock file. A Store from Load keeps nothing
// open.
//
// The Store knows the size of the file that Save would write. Set uses it to
// refuse a server that would make the file larger than MaxFileSize
// (ErrStoreFull), so one large server cannot stop the others from being
// saved: only the refused server is not pinned. The Store also knows how many
// of these bytes the project servers use (the servers whose Identity has a
// ProjectPath). Set refuses a project server that would make them larger than
// their share, ProjectShareMiB (ErrProjectShareFull, which also wraps
// ErrStoreFull), so the servers of a project config cannot fill the file and
// starve the servers of the user scope.
type Store struct {
	// path, existed, ranWithoutLock, root, dir and dirInfo are set once,
	// before Load or LoadLocked returns the Store, and never change after
	// that. So they need no mutex.
	path           string // the pins file (see Path)
	existed        bool   // the pins file was on disk (see Existed)
	ranWithoutLock bool   // LoadLocked ran without the lock (see RanWithoutLock)

	// root, dir and dirInfo are the pins directory that LoadLocked opened
	// and checked, and whose lock file it locked: the os.Root that Save
	// writes through, the handle of the directory itself (root.Open(".")),
	// which Save checks again and syncs, and the result of dir.Stat, which
	// Save compares with the path before the rename (os.SameFile). All three
	// are nil for a Store from Load and for a zero-value Store. The Store does
	// not keep the lock file: the release function of LoadLocked owns it. That
	// function closes the lock file, dir and root; a Save after that fails
	// with an error.
	root    *os.Root
	dir     *os.File
	dirInfo fs.FileInfo

	mu      sync.Mutex // guards servers, sizes, entryBytes and projectBytes
	servers map[Identity]ServerPins

	// sizes holds, for each key of servers, the bytes that the entry of that
	// server takes in the file that Save writes (see entrySize). entryBytes
	// is the sum of all values in sizes. fileSize adds the fixed bytes around
	// the entries, so the Store knows the size of the file without encoding
	// it. projectBytes is the sum of the values in sizes whose key is a
	// project server (see projectPart), for the project share (projectShare).
	// Load and Set keep sizes, entryBytes and projectBytes up to date, and
	// Clone copies them.
	//
	// The ProjectPath is part of the key, so a key is a project server or a
	// user server for its whole life. So Set can subtract the old project
	// part of a key and add the new one, and projectBytes never drifts from
	// the sum. It is never negative, and never larger than entryBytes.
	sizes        map[Identity]int
	entryBytes   int
	projectBytes int
}

// Path returns the path of the pins file: the path that Load or LoadLocked
// read from, and that Save writes to. The CLI uses it, for example, in the
// notice that Save created a new pins file. A zero-value Store returns "".
func (s *Store) Path() string {
	return s.path
}

// Existed reports whether Load or LoadLocked found the pins file on disk. It is
// false when the Store is new and empty because there was no file: a first
// run, or a file that was deleted. The two look the same to Load, so the CLI
// uses Existed to print a notice when Save creates a new pins file. A deleted
// file is then not silent: every server would look new, with no alert. A
// zero-value Store returns false.
func (s *Store) Existed() bool {
	return s.existed
}

// RanWithoutLock reports whether LoadLocked went on without the lock. It is
// true when the operating system or the file system could not take the lock on
// the pins lock file, and the run went on without it. Then a parallel run can
// still lose an update, and the CLI prints one warning. A Store from Load
// returns false, because Load takes no lock at all.
func (s *Store) RanWithoutLock() bool {
	return s.ranWithoutLock
}

// fileFormat is the shape of pins.json, version 1. Every key is required and
// must not be null. encoding/json/v2 has no option for a required key, so the
// fields are pointers: a missing key or a null leaves the pointer nil, and
// Load refuses it. Version is a plain int, because Load checks it first with
// its own decode (checkVersion).
type fileFormat struct {
	Version int           `json:"version"`
	Servers *[]fileServer `json:"servers"`
}

// fileServer is one server entry in pins.json.
type fileServer struct {
	Client      *string     `json:"client"`
	Source      *string     `json:"source"`
	ProjectPath *string     `json:"project_path"`
	Name        *string     `json:"name"`
	Tools       *ServerPins `json:"tools"`
}

// DefaultPath returns the path of pins.json.
//
// It is $XDG_CONFIG_HOME/mcpmoat/pins.json when XDG_CONFIG_HOME is set to an
// absolute path, and ~/.config/mcpmoat/pins.json otherwise. The XDG
// specification says that a relative value is invalid and must be ignored. We
// do not use os.UserConfigDir, because on macOS it returns
// ~/Library/Application Support and the PRD (FR-11) fixes ~/.config.
//
// The caller passes the environment and the home directory (os.Getenv and
// os.UserHomeDir in production), so the package reads no process state.
// homeDir runs only when XDG_CONFIG_HOME is not used.
func DefaultPath(getenv func(string) string, homeDir func() (string, error)) (string, error) {
	base := getenv("XDG_CONFIG_HOME")
	if base == "" || !filepath.IsAbs(base) {
		home, err := homeDir()
		if err != nil {
			return "", fmt.Errorf("find the home directory for pins.json: %w", err)
		}
		// A relative home would put pins.json under the working directory, which
		// can be a cloned repository.
		if !filepath.IsAbs(home) {
			return "", fmt.Errorf("the home directory %q for pins.json is not an absolute path", home)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "mcpmoat", "pins.json"), nil
}

// Load reads the pins file at path. It takes no lock, so it is for a run that
// only reads. A run that reads, changes and saves the pins must use
// LoadLocked, or a parallel run can lose its update (the last writer wins).
//
// A missing file (or a missing directory) is the first run: Load returns an
// empty Store that saves to path, and Store.Existed returns false. Load does
// not create the directory.
//
// Load refuses an unsafe path with an error that wraps ErrInsecurePermissions
// (see Save). Such an error names the unsafe path and has no "read <path>"
// prefix. A file with a newer format version gives an error that wraps
// ErrUnsupportedVersion and starts with the path itself. Every other error
// starts with "read <path>" or "parse <path>". The checks run in this order:
//   - The path to the pins directory, resolved one component at a time
//     (checkParents): the owner of every symlink on it, also a symlink that
//     is reached only through the target of another symlink, and the owner
//     and the mode of every directory above the pins directory that the walk
//     crosses, for example ~/.config. This check is by path, by design: when
//     no other user can write such a directory or owns such a symlink, no
//     other user can swap the path.
//   - The pins directory, on the handle of the directory that Load reads from
//     (checkDirHandle): another owner, a mode that lets the group or others
//     write, or (macOS only) an ACL that lets a user or group write.
//   - pins.json, on the open file (checkFileHandle), with the same rules as
//     the directory. This runs before the type and size checks and before the
//     read, so Load never reads the bytes of an unsafe file.
//
// The directory is opened once, as an os.Root, and the file is opened through
// it, so the checked directory and file are the ones that Load reads. A pins
// directory or a pins.json that the user may not open gets the owner check by
// path (checkDirPerm through dirOpenError, or checkFilePermByPath), so that
// another owner shows as ErrInsecurePermissions and not as "permission denied".
//
// Any other problem is an error, also a missing or null key or a server that
// ValidateServer refuses (the per-server rules of Set). Load does not apply
// the project share (ProjectShareMiB): a file from an older mcpmoat, or a
// hand-edited one, can have project servers over the share, and Load reads it
// with no error. Load computes how many bytes the project servers use, so a
// later Set refuses a project server that makes them larger, and accepts one
// that does not. Load never replaces a bad file with an empty store,
// because that would pin a poisoned server as trusted. The errors name the
// path and the position of the problem, and never hold file content. A file
// with a newer format version gives an error that wraps ErrUnsupportedVersion.
//
// A pins.json that is a symlink is refused with an error that wraps
// ErrInsecurePermissions, also when its target is in the pins directory. A
// symlink that is absolute or leaves the directory is refused before that
// (safefile.ErrOutsideRoot). A symlink with a missing target (the file, its
// directory or a parent of the directory) and a directory path that is not a
// directory are errors, not a first run. A symlink to the pins directory, or a
// symlink in a parent, is followed: the checks above see the target. Such a
// symlink must belong to the current user or root (checkParents), or Load
// refuses it with an error that wraps ErrInsecurePermissions.
func Load(path string) (*Store, error) {
	dir, name := filepath.Dir(path), filepath.Base(path)

	root, d, missing, err := openCheckedDir("read", path, dir)
	if missing {
		return firstRun(newStore(path), path)
	}
	if err != nil {
		return nil, err
	}
	defer closeDir(root, d)

	s, err := loadFromRoot(path, root, name)
	if err != nil {
		return nil, err
	}
	if !s.existed {
		// The directory may have changed since it was opened, so check the
		// path as a first run (see checkFirstRun).
		return firstRun(s, path)
	}
	return s, nil
}

// LoadLocked is Load with an exclusive lock, for a run that reads, changes and
// saves the pins. It returns the Store, a release function and an error. The
// caller must hold the lock from the load through Save, and call release after
// Save (or when it decides not to save):
//
//	store, release, err := pins.LoadLocked(ctx, path, wait)
//	defer release()
//
// release is never nil, also when err is not nil (then it does nothing), so
// the caller can always defer it. Calling it twice is safe. It releases the
// lock, then closes the lock file, then the directory handle, then the os.Root
// of the directory. A Save after release fails with an error (the directory is
// closed).
//
// The Store keeps the pins directory open until release: Save writes through
// the os.Root that LoadLocked opened and checked, not by path. Before the
// rename, Save checks that the path still names that directory, and otherwise
// fails with ErrPinsDirChanged and writes nothing (see Save).
//
// What is locked: the pins lock file, pins.json.lock in the pins directory
// (the pins file name plus lockSuffix), with an advisory flock(2) on its open
// handle. The pins directory itself is not locked: flock needs only a
// read-only descriptor, and the pins directory may have mode 0755, so another
// user could hold a lock on it and block every save. LoadLocked opens the
// lock file through the os.Root of the pins directory, creates it with mode
// 0o600 when it is missing, and refuses it with an error that wraps
// ErrInsecurePermissions when it is a symlink, not a regular file, owned by
// another user, open to the group or others in any way (mode 0600 passes,
// 0644 is refused), or (macOS only) has an ACL entry that lets a user or group
// open it. It never changes the mode of an existing lock file; the fix hint is
// to remove it. See openLockFile.
//
// LoadLocked creates a missing pins directory (mode 0o700) first, so it has a
// directory for the lock file. The lock file stays in the pins directory after
// the run, also after a run that saves nothing. So a first run that saves
// nothing leaves a private pins directory with only pins.json.lock in it. The
// content of the lock file has no meaning.
//
// A read-only pins directory (for example mode 0500) works only when the lock
// file already exists: LoadLocked opens it with no create and locks it, and a
// later Save fails, because it cannot write to the directory. When the lock
// file is missing, LoadLocked cannot create it and returns an error that names
// the lock file and the reason, for example "read <path>: create the pins
// lock file <path>.lock: permission denied". That error does not wrap
// ErrLocked: no other process holds the lock.
//
// While another run holds the lock, LoadLocked tries again until wait has
// passed, and then returns an error that wraps ErrLocked. A wait of zero or
// less tries once. When ctx ends first, the error wraps ctx.Err(), for example
// context.Canceled. Test both with errors.Is.
//
// Limits of the lock:
//   - It is advisory: it stops only other runs that lock too. Load takes no
//     lock, and mcpmoat v0.1.0 does not lock at all, so a run of v0.1.0 in
//     parallel with this version can still lose an update.
//   - The current user and root can still hold the lock, for example with a
//     process that opened the lock file and hangs. Another user cannot, as
//     long as the lock file passes the checks above.
//   - It belongs to the open file description, not to the process. So one
//     process must not call LoadLocked twice at the same time: the second call
//     waits for the first, until wait has passed, and then returns ErrLocked.
//   - When the operating system or the file system cannot lock the lock file
//     (for example some network file systems, or Windows), LoadLocked goes on
//     without the lock and Store.RanWithoutLock returns true. The caller must
//     warn the user once.
//
// The checks, the errors and the first run are the same as in Load, with these
// differences:
//   - LoadLocked checks the parent directories (checkParents) twice: before it
//     creates a missing pins directory, so it never creates one under an
//     unsafe parent, and again after that. The parents check skips a missing
//     ancestor, and MkdirAll uses an ancestor that another user created in
//     the meantime, so the second check sees what MkdirAll used.
//   - A missing pins.json in the directory (which exists now) is always a
//     first run or a deleted file, so Store.Existed returns false and there
//     is no error.
//   - LoadLocked opens and checks the lock file after the checks of the pins
//     directory and before it reads pins.json, and it reads pins.json only
//     after it holds the lock (see openLockFile for the errors).
func LoadLocked(ctx context.Context, path string, wait time.Duration) (*Store, func(), error) {
	return loadLocked(ctx, path, locker{wait: wait})
}

// loadLocked is LoadLocked with the locker l, so a test can inject a busy or
// an unsupported lock.
//
// The results are named, so the deferred cleanup below can see whether the
// function returns an error.
func loadLocked(ctx context.Context, path string, l locker) (s *Store, release func(), err error) {
	// Every error return below gives noop as the release function, so the
	// caller can defer release before it checks err.
	root, d, dirInfo, err := openPinsDir("read", path, l.afterEnsureDir)
	if err != nil {
		return nil, noop, err
	}

	// lockFile is the open pins lock file, and unlockFile releases the lock on
	// it. Both start empty (nil and a no-op) and are set below, when the lock
	// file is open and when the lock is taken. releaseAll is a closure: it
	// reads the two variables when it runs, so it sees those later values.
	var lockFile *os.File
	unlockFile := func() {}
	// releaseAll undoes the steps in reverse order: first the lock, then the
	// lock file that holds it, then the directory handle and the root.
	// sync.OnceFunc makes a second call do nothing, so the caller can call
	// release twice. The Store keeps root and d for Save, so a Save after
	// releaseAll fails on the closed root.
	releaseAll := sync.OnceFunc(func() {
		unlockFile()
		if lockFile != nil {
			// Closing the file also releases the lock. The file is empty and
			// never written, so a close error is not useful.
			_ = lockFile.Close()
		}
		closeDir(root, d)
	})
	// On any error below, release everything before the return, so no handle
	// or lock leaks. The deferred function runs after the return statement
	// has set err.
	defer func() {
		if err != nil {
			releaseAll()
		}
	}()

	// Lock a file in the directory, not the directory itself: another user
	// who can read the directory could hold a lock on it (see lockSuffix).
	// The lock file is opened through root, so it is in the directory that
	// was checked above.
	lockFile, err = openLockFile(root, path)
	if err != nil {
		// A refusal names the lock file and has no "read <path>" prefix.
		return nil, noop, prefixUnlessRefusal("read", path, err)
	}

	unlockFn, locked, err := l.lock(ctx, lockFile)
	// lock never returns a nil function, so unlockFile is always callable.
	unlockFile = unlockFn
	if err != nil {
		// Wrap with %w, so errors.Is still finds ErrLocked or context.Canceled.
		return nil, noop, fmt.Errorf("read %s: %w", path, err)
	}

	// Read pins.json only now, under the lock, so no other locking run can
	// save between this read and the Save of the caller.
	s, err = loadFromRoot(path, root, filepath.Base(path))
	if err != nil {
		return nil, noop, err
	}
	// locked is false with no error when the lock file cannot be locked: the
	// run goes on without the lock.
	s.ranWithoutLock = !locked
	// Save writes through the directory that was checked here.
	s.root, s.dir, s.dirInfo = root, d, dirInfo
	return s, releaseAll, nil
}

// openPinsDir opens the pins directory of the pins file path for a write: it
// creates the directory when it is missing, opens it and checks it. LoadLocked
// and Save (of a Store from Load) share it, so the two check the directory in
// the same way. op is "read" for LoadLocked and "save" for Save: it is the
// prefix of the errors (see prefixUnlessRefusal). afterEnsureDir, when not
// nil, runs after ensurePinsDir (a test hook of locker).
//
// It returns the os.Root of the directory, a handle of the directory itself
// and the file info of that handle. The caller owns root and d and must close
// both (closeDir). On an error, nothing stays open.
func openPinsDir(op, path string, afterEnsureDir func()) (root *os.Root, d *os.File, info fs.FileInfo, err error) {
	dir := filepath.Dir(path)

	// Check the parents before ensurePinsDir, so it never creates a directory
	// under an unsafe parent. A refusal names the unsafe path itself (see
	// openCheckedDir).
	if err := checkParents(dir); err != nil {
		return nil, nil, nil, prefixUnlessRefusal(op, path, err)
	}
	if err := ensurePinsDir(op, path, dir); err != nil {
		return nil, nil, nil, err
	}
	if afterEnsureDir != nil {
		afterEnsureDir()
	}

	// openCheckedDir runs checkParents a second time, on purpose. The first
	// check skips an ancestor that is missing. ensurePinsDir then creates the
	// missing ancestors with MkdirAll, but MkdirAll uses a directory that
	// another user created a moment before, with any owner and mode. The
	// second check sees each ancestor as it is now, before the lock, the read
	// or the write.
	root, d, missing, err := openCheckedDir(op, path, dir)
	if missing {
		// The directory exists after ensurePinsDir, so a missing one here was
		// removed or replaced meanwhile, or it is not a directory. checkFirstRun
		// gives the better text for a path that is not a directory.
		if frErr := checkFirstRun(op, path); frErr != nil {
			return nil, nil, nil, frErr
		}
	}
	if err != nil {
		return nil, nil, nil, err
	}

	// checkDirHandle in openCheckedDir has already called Stat on d, but it
	// does not return the result. A second Stat on the same handle describes
	// the same directory.
	info, err = d.Stat()
	if err != nil {
		closeDir(root, d)
		return nil, nil, nil, fmt.Errorf("%s %s: %w", op, path, err)
	}
	return root, d, info, nil
}

// ensurePinsDir creates the pins directory dir of the pins file path when it
// is missing, so LoadLocked always has a directory for the lock file and Save
// a directory to write to. It runs checkFirstRun first: a missing directory
// must be a real first run, not, for example, a symlink with a missing target
// or a path below a regular file. op is the prefix of the errors ("read" or
// "save"), and the errors name path. MkdirAll uses mode 0o700, and the umask
// can only remove bits from it. checkDirHandle checks the result.
func ensurePinsDir(op, path, dir string) error {
	_, err := os.Stat(dir)
	if !safefile.IsMissing(err) {
		// The directory exists, or Stat failed for another reason. Then
		// OpenRoot reports the problem with the right text.
		return nil
	}
	if err := checkFirstRun(op, path); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("%s %s: create the pins directory: %w", op, path, err)
	}
	return nil
}

// openCheckedDir opens and checks the pins directory dir of the pins file
// path. Load, LoadLocked and Save share it, so they check the directory in the
// same way. The steps are:
//   - checkParents: the parent directories of dir, by path.
//   - safefile.OpenRoot(dir): the os.Root that the pins file is opened through.
//   - root.Open("."): a handle of the root directory itself. The checks see
//     the directory that the file is opened from, not whatever the path names
//     now.
//   - checkDirHandle: the owner, the mode and (macOS only) the ACL of that
//     handle.
//
// On success, the caller owns root and d and must close both. Closing root
// does not close d. On an error, openCheckedDir closes what it opened, and
// root and d are nil.
//
// missing is true only when OpenRoot found no directory at dir. Then err is
// not nil either, and the caller decides what a missing directory means: Load
// treats it as a first run, LoadLocked and Save as a directory that changed
// after they created it. A missing directory at a later step is a plain
// error.
//
// The errors name path. A refusal (ErrInsecurePermissions) names the unsafe
// path itself and has no "<op> <path>" prefix; every other error has it (see
// prefixUnlessRefusal). op is "read" for Load and LoadLocked and "save" for
// Save. A permission error of OpenRoot or root.Open gets the owner check by
// path (dirOpenError).
func openCheckedDir(op, path, dir string) (root *os.Root, d *os.File, missing bool, err error) {
	if parentErr := checkParents(dir); parentErr != nil {
		// checkParents can also fail for a reason that is not a refusal, for
		// example a Readlink error or too many symlinks. That error gets the
		// "<op> <path>" prefix.
		return nil, nil, false, prefixUnlessRefusal(op, path, parentErr)
	}

	root, err = safefile.OpenRoot(dir)
	if err != nil {
		return nil, nil, safefile.IsMissing(err), dirOpenError(op, path, dir, err)
	}

	// "." is the root directory itself.
	d, err = root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, nil, false, dirOpenError(op, path, dir, err)
	}

	if checkErr := checkDirHandle(dir, d); checkErr != nil {
		closeDir(root, d)
		return nil, nil, false, prefixUnlessRefusal(op, path, checkErr)
	}
	return root, d, false, nil
}

// prefixUnlessRefusal returns err with the prefix "<op> <path>: ", for
// example "read /home/u/.config/mcpmoat/pins.json: ". A refusal of an unsafe
// path (an error that wraps ErrInsecurePermissions) is returned as it is: it
// names the unsafe path itself. The wrap uses %w, so errors.Is and errors.As
// still see err.
func prefixUnlessRefusal(op, path string, err error) error {
	if errors.Is(err, ErrInsecurePermissions) {
		return err
	}
	return fmt.Errorf("%s %s: %w", op, path, err)
}

// noop is a function that does nothing. A release function is never nil, so
// loadLocked returns noop as the release function on an error, and
// locker.lock returns it when it holds no lock.
func noop() {}

// closeDir closes d, the handle of the pins directory, and root, the os.Root
// that d was opened through. Closing root does not close the files opened
// through it, so both need a close. Both are read-only, so a close error is not
// useful and is ignored.
func closeDir(root *os.Root, d *os.File) {
	_ = d.Close()
	_ = root.Close()
}

// newStore returns an empty Store that saves to path. existed and
// ranWithoutLock are false: the caller sets them when it read a file or ran
// without a lock.
func newStore(path string) *Store {
	return &Store{
		path:    path,
		servers: make(map[Identity]ServerPins),
		sizes:   make(map[Identity]int),
	}
}

// dirOpenError wraps err, the error from opening the pins directory dir (with
// safefile.OpenRoot or root.Open(".")), for the pins file path.
//
// A pins directory that another user owns, with mode 0700, cannot be opened,
// and err is only "permission denied". The owner problem has a fix hint, so
// for a permission error dirOpenError runs checkDirPerm, by path, only to get
// a better error text. checkFilePermByPath does the same for pins.json. When
// checkDirPerm finds no refusal, also when its own Stat fails, the original
// error is returned with the "<op> <path>" prefix, where op is "read" or
// "save".
func dirOpenError(op, path, dir string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		if permErr := checkDirPerm(dir); errors.Is(permErr, ErrInsecurePermissions) {
			// A refusal names its own path, so it gets no "<op> <path>" prefix.
			return permErr
		}
	}
	return fmt.Errorf("%s %s: %w", op, path, err)
}

// loadFromRoot reads and decodes the pins file name in root, the os.Root of
// the pins directory. path is the full path of the file, for the Store and the
// error texts. The caller has already checked the directory (checkParents and
// checkDirHandle) and closes root. Load and LoadLocked share this function, so
// the two cannot read the file in different ways.
//
// A missing file gives an empty Store with existed set to false and no error.
// The caller decides whether that is a first run. A pins.json symlink with a
// missing target is an error, not a missing file: the real file is gone, and
// Save would replace the symlink. A file that is found gives a Store with
// existed set to true. See Load for the checks and the errors.
func loadFromRoot(path string, root *os.Root, name string) (*Store, error) {
	s := newStore(path)

	// The name file, not f: f is the decoded fileFormat below.
	file, found, err := safefile.OpenIfExistsInRoot(root, name)
	if err != nil {
		// A pins.json that another user owns, with mode 0600, cannot be opened.
		// The owner problem has a fix hint, so report it before "permission denied".
		if errors.Is(err, fs.ErrPermission) {
			if permErr := checkFilePermByPath(path, os.Geteuid()); permErr != nil {
				return nil, permErr
			}
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if !found {
		// os.Root reports a symlink with a missing target as not found. Lstat
		// does not follow the symlink, so it sees the entry itself. Any other
		// Lstat result means that nothing is there: a missing file. This is
		// the same check and text as in checkFirstRunWith, done on root.
		if fi, lerr := root.Lstat(name); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("read %s: the target of the symlink is missing", path)
		}
		return s, nil
	}
	defer func() {
		// The file is read-only, so a close error is not useful.
		_ = file.Close()
	}()

	data, err := readChecked(path, root, name, file)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(path, data); err != nil {
		return nil, err
	}

	// Strict decode: an unknown field is an error, so a typo or a field from a
	// different format is not dropped silently.
	var f fileFormat
	if err := json.Unmarshal(data, &f, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("parse %s: %s", path, describeJSONError(err))
	}

	if f.Servers == nil {
		return nil, fmt.Errorf("parse %s: servers field is missing or null", path)
	}
	for i, srv := range *f.Servers {
		if srv.Client == nil || srv.Source == nil || srv.ProjectPath == nil || srv.Name == nil || srv.Tools == nil {
			return nil, fmt.Errorf("parse %s: servers[%d]: a field is missing or null", path, i)
		}
		id := Identity{Client: *srv.Client, Source: *srv.Source, ProjectPath: *srv.ProjectPath, Name: *srv.Name}
		// ValidateServer and entrySize below both encode the entry, on
		// purpose: compact JSON for the per-server limit, and the indented
		// form for the file size that Set tracks (see Set).
		if err := ValidateServer(id, *srv.Tools); err != nil {
			return nil, fmt.Errorf("parse %s: servers[%d]: %w", path, i, err)
		}
		if _, dup := s.servers[id]; dup {
			return nil, fmt.Errorf("parse %s: servers[%d]: duplicate server identity", path, i)
		}
		size, err := entrySize(id, *srv.Tools)
		if err != nil {
			return nil, fmt.Errorf("parse %s: servers[%d]: %w", path, i, err)
		}
		// The decoder made this map, and nothing else holds it.
		s.servers[id] = *srv.Tools
		s.sizes[id] = size
		s.entryBytes += size
		// No check of the project share here: a file from an older mcpmoat,
		// or a hand-edited one, can be over it, and Load must still read it
		// (Set refuses only growth).
		s.projectBytes += projectPart(id, size)
	}
	s.existed = true
	return s, nil
}

// firstRun returns s, the empty Store, when the missing pins file is a real
// first run (see checkFirstRun). Otherwise it returns the error of
// checkFirstRun and no Store.
func firstRun(s *Store, path string) (*Store, error) {
	if err := checkFirstRun("read", path); err != nil {
		return nil, err
	}
	return s, nil
}

// readChecked checks the open pins.json file and then reads it. file was
// opened as name through root, the os.Root of the pins directory, and path is
// for the error texts only. The caller closes file.
//
// The checks run in this order:
//   - file must be the directory entry name itself: a symlink, or an entry
//     that changed after the open, gives an error that wraps
//     ErrInsecurePermissions. The owner of a symlink target is not relevant,
//     so this check runs first.
//   - The owner, the mode and (macOS only) the ACL of file (checkFileHandle).
//     This runs before the type and size checks, so an unsafe file that is
//     also too large gives ErrInsecurePermissions and not ErrTooLarge.
//   - The type and the size, then the bounded read (safefile.ReadOpened).
func readChecked(path string, root *os.Root, name string, file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// os.Root follows a symlink that stays in the directory, so file can be
	// the target of a pins.json symlink. Lstat does not follow a symlink at
	// the end of the name: it describes the directory entry itself.
	// os.SameFile compares the identity of the files (the device and inode
	// numbers on Unix), not their names. So the two differ when the entry is
	// a symlink (the link and its target are two files), or when another
	// file replaced the entry after the open. An entry that is gone was
	// swapped too.
	entry, err := root.Lstat(name)
	if safefile.IsMissing(err) {
		return nil, swappedError(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if !os.SameFile(info, entry) {
		return nil, swappedError(path)
	}

	if err := checkFileHandle(path, file, info); err != nil {
		return nil, err
	}
	data, err := safefile.ReadOpened(file, MaxFileSize)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

// swappedError is the error of readChecked when the open pins file path is not
// the directory entry itself: a symlink, or a file that changed after the
// open. It wraps ErrInsecurePermissions.
func swappedError(path string) error {
	return fmt.Errorf("pins file %s is a symlink or was swapped while it was opened (fix: replace the symlink with the file): %w",
		path, ErrInsecurePermissions)
}

// checkFirstRun is checkFirstRunWith with os.Lstat and os.Stat. Load calls it
// when it did not find the pins file, and LoadLocked and Save before they
// create a missing pins directory.
func checkFirstRun(op, path string) error {
	return checkFirstRunWith(op, path, os.Lstat, os.Stat)
}

// checkFirstRunWith returns an error when safefile did not find the pins file
// but the path is not simply missing. safefile reports a symlink with a
// missing target, and a directory path that is not a directory, as not found.
// Then the real file is gone, which is not a first run, and Save would replace
// the link or fail after the scan.
//
// op is the prefix of the errors: "read" for Load and LoadLocked, "save" for
// Save. lstat and stat are os.Lstat and os.Stat in production. They are
// parameters, so a test can fake a file system state that is hard to make, for
// example a path where nothing exists.
//
// It walks up from the directory of path to the nearest part of the path that
// exists. Then:
//   - It is a directory, or a symlink to a directory: a first run, no error.
//     Save creates the missing directories under it.
//   - It is a file, or a symlink with a missing target: an error that names
//     that part, "... is not a directory, or it is a symlink with a missing
//     target". The text is the same when the pins directory itself is a file
//     and when a parent of it is a file.
//   - Nothing on the path exists: an error. A real first run always has an
//     existing ancestor, for example the home directory.
//
// The path can change between the read and these checks. Only a process that
// can write the directory or one of its parents can do that, and it could
// change pins.json directly, so the race is accepted.
func checkFirstRunWith(op, path string, lstat, stat func(string) (fs.FileInfo, error)) error {
	if fi, err := lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %s: the target of the symlink is missing", op, path)
	}
	// Find the nearest part of the path that exists. Lstat does not follow a
	// symlink at the end, so a dangling symlink (for example ~/.config to a
	// volume that is not mounted) is found here, and the stat below refuses
	// it. A part below a file gives ENOTDIR, not "not exist": safefile.IsMissing
	// accepts both, so the walk goes on up to the file, and the stat below
	// names the file.
	dir := filepath.Dir(path)
	for {
		_, err := lstat(dir)
		if err == nil {
			break
		}
		if !safefile.IsMissing(err) {
			return fmt.Errorf("%s %s: %w", op, path, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// filepath.Dir of the root directory is the root directory, so the
			// walk is at the top and nothing on the path exists.
			return fmt.Errorf("%s %s: no directory on the path exists", op, path)
		}
		dir = parent
	}
	if fi, err := stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s %s: %s is not a directory, or it is a symlink with a missing target", op, path, dir)
	}
	return nil
}

// checkVersion reads the version first with a loose decode. A future version
// may change the rest of the shape, and the user must then see the version
// error and not a shape error. This holds while the top level stays an object
// with an integer "version", so a format change must keep that.
// json.Unmarshal (encoding/json/v2) rejects trailing data, duplicate keys and
// invalid UTF-8, and it matches key names with their exact case.
func checkVersion(path string, data []byte) error {
	var probe struct {
		Version *int `json:"version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("parse %s: %s", path, describeJSONError(err))
	}
	switch {
	case probe.Version == nil:
		return fmt.Errorf("parse %s: version field is missing", path)
	case *probe.Version < 1:
		return fmt.Errorf("parse %s: invalid version %d", path, *probe.Version)
	case *probe.Version > CurrentVersion:
		return fmt.Errorf("%s has version %d, newer than this mcpmoat supports (%d); upgrade mcpmoat: %w",
			path, *probe.Version, CurrentVersion, ErrUnsupportedVersion)
	}
	return nil
}

// Get returns a copy of the pins of the server id. The bool is false when the
// store has no entry for the server. An entry with an empty map is a server
// that was pinned with no tools. Changing the returned map does not change
// the Store. A Pin holds only strings, so the copy shares nothing with the
// Store.
func (s *Store) Get(id Identity) (ServerPins, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.servers[id]
	if !ok {
		return nil, false
	}
	return maps.Clone(p), true
}

// Set stores a copy of p as the pins of the server id. It replaces the pins of
// that server only. A nil or empty p pins the server with no tools. Set does
// not write the file: call Save.
//
// Set refuses a server that Load would refuse: an empty server name, an empty
// tool name, an empty hash, an empty canonical text, text that is not valid
// UTF-8, or an entry larger than maxServerSize (2 MiB) as compact JSON.
//
// Then Set refuses a server whose entry would make the file that Save writes
// larger than MaxFileSize (32 MiB), with an error that wraps ErrStoreFull. A
// change that does not make the file larger is always accepted, for example a
// smaller replacement of a server. So one large server cannot stop the others
// from being saved: the servers that fit are saved, and the refused server is
// not pinned.
//
// Then Set refuses a project server (an Identity with a ProjectPath) whose
// entry would make the entries of all project servers together larger than
// their share, ProjectShareMiB (16 MiB, half of MaxFileSize). The error wraps
// both ErrProjectShareFull and ErrStoreFull. The share has the same rule as
// the file limit: it refuses only growth, so a replacement that is not larger
// than the old entry is accepted, also when a loaded file is already over the
// share. A server of the user scope (an empty ProjectPath) does not count
// toward the share and is never refused by it. So the servers of a project
// config, which can come from a cloned repository, cannot use up the whole
// file: the user scope always keeps the other half.
//
// Every error from Set is such a refusal. Then the store does not change, and
// the caller can still save the other servers. The errors hold no tool names,
// because the server chose them, and no server context: the caller adds it.
//
// The server chose the data that Set refuses, so a hostile server can make
// itself impossible to pin. The caller must report a refused server (for
// example as a finding), never skip it silently: a server that is never
// pinned looks new on each run, and its changes are never reported.
func (s *Store) Set(id Identity, p ServerPins) error {
	// Check the copy that is stored, so a caller that changes p later cannot
	// change what was checked.
	c := cloneOrEmpty(p)
	// The entry is encoded twice, on purpose: ValidateServer measures compact
	// JSON for the per-server limit (maxServerSize), and entrySize measures
	// the indented form that Save writes, for the file limit (MaxFileSize).
	// One encode for both is a possible later optimisation.
	if err := ValidateServer(id, c); err != nil {
		return err
	}
	size, err := entrySize(id, c)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Compute the size of the file with the new entry before the store
	// changes. A replaced server gives back the bytes of its old entry. A
	// missing key in sizes gives 0.
	_, replaced := s.servers[id]
	count := len(s.servers)
	if !replaced {
		count++
	}
	entries := s.entryBytes - s.sizes[id] + size
	before := fileSize(len(s.servers), s.entryBytes)
	after := fileSize(count, entries)
	// Refuse only growth: a Store that Load read from a compact file near the
	// limit can already be over it, and a change that makes it smaller must
	// still be possible.
	if after > MaxFileSize && after > before {
		return fmt.Errorf("%w: %d bytes with this server, more than the %d MiB limit",
			ErrStoreFull, after, MaxFileSizeMiB)
	}

	// The project share, with the same measure and the same rule: refuse only
	// growth. The ProjectPath is part of the key, so the old entry of id (if
	// any) has the same scope as the new one, and projectPart gives the old
	// and the new part with one rule. For a server of the user scope both
	// parts are 0, so projects equals s.projectBytes and the check never
	// refuses it.
	projects := s.projectBytes - projectPart(id, s.sizes[id]) + projectPart(id, size)
	if isProjectServer(id) && projects > projectShare && projects > s.projectBytes {
		// Two %w: the error wraps both sentinels, so errors.Is finds
		// ErrProjectShareFull and ErrStoreFull. Sizes only, no names or
		// paths: the caller adds the server context.
		return fmt.Errorf("%w: %w: %d bytes of project servers with this server, more than the %d MiB share",
			ErrProjectShareFull, ErrStoreFull, projects, ProjectShareMiB)
	}

	// A zero-value Store has nil maps, and writing to a nil map panics.
	if s.servers == nil {
		s.servers = make(map[Identity]ServerPins)
	}
	if s.sizes == nil {
		s.sizes = make(map[Identity]int)
	}
	s.servers[id] = c
	s.sizes[id] = size
	s.entryBytes = entries
	s.projectBytes = projects
	return nil
}

// Clone returns a copy of s. Set on the copy never changes s. The scan uses it
// to test, before it prints the report, whether a server still fits in the
// file (Set returns ErrStoreFull when not, and also ErrProjectShareFull when
// the project share is full), without a change to the real store.
//
// Clone copies the servers map and the sizes map, because Set writes to
// them: with shared maps, a Set on the copy would change s too. It copies the
// size totals too (all entries, and the entries of the project servers), so
// the copy applies the file limit and the project share from the same state
// as s. The pins map
// of each server is shared, not copied. That is safe, because the Store never
// changes such a map in place: Set stores a new copy, Get returns a copy, and
// Save only reads it.
//
// The copy has the same path, Existed and RanWithoutLock as s, and a mutex of
// its own. It does not hold a lock of LoadLocked: that lock belongs to the
// caller.
//
// For a Store from LoadLocked, the copy shares the open pins directory of s
// (the os.Root, the directory handle and its file info), so a Save of the copy
// also writes through the directory that LoadLocked opened and checked. The
// copy does not own the directory, and it has no lock file of its own: the
// release function of LoadLocked closes them for both, and a Save of either
// after release fails. A Save of the copy writes the same file as a Save of s,
// so save only one of them.
func (s *Store) Clone() *Store {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A struct literal, not *s: a copy of s would copy the mutex too, and go
	// vet (copylocks) refuses that. The new mutex is the zero value, unlocked.
	return &Store{
		path:           s.path,
		existed:        s.existed,
		ranWithoutLock: s.ranWithoutLock,
		root:           s.root,
		dir:            s.dir,
		dirInfo:        s.dirInfo,
		servers:        maps.Clone(s.servers),
		sizes:          maps.Clone(s.sizes),
		entryBytes:     s.entryBytes,
		projectBytes:   s.projectBytes,
	}
}

// fileSize returns the number of bytes that Save writes for count servers
// whose entries take entryBytes together (see entrySize).
//
// Save encodes fileFormat with an indent of two spaces per level and adds a
// newline at the end. With servers, the file is:
//
//	{
//	  "version": 1,
//	  "servers": [
//	    {
//	      ...
//	    },
//	    {
//	      ...
//	    }
//	  ]
//	}
//
// With no server, the array is empty and stays on one line:
//
//	{
//	  "version": 1,
//	  "servers": []
//	}
//
// The texts below are these lines, so the sum is exact.
func fileSize(count, entryBytes int) int {
	// `{`, then the version member, then the start of the servers member, up
	// to its "[".
	head := len("{\n"+indent+`"version": `) + len(strconv.Itoa(CurrentVersion)) +
		len(",\n"+indent+`"servers": `)
	if count == 0 {
		return head + len("[]\n}\n")
	}
	// entryBytes counts ",\n" after each entry, but the last entry has no
	// comma: it is followed by "\n  ]". So one byte comes off.
	return head + len("[\n") + entryBytes - len(",") + len(indent+"]\n}\n")
}

// entrySize returns the bytes that the entry of the server id takes in the
// file that Save writes: the indent of depth 2 before its "{", the encoded
// entry, and the ",\n" after it (fileSize corrects the last entry).
//
// The entry is encoded with the options of Save (saveOptions). In the file,
// every line of the entry after the first starts with the indent of depth 2
// (two levels). WithIndentPrefix adds that prefix after each newline of the
// entry, but not before the first line, so entrySize adds the indent before
// the "{" itself. A newline in a JSON string is written as \n, so it gets no
// prefix.
//
// The encoder writes to a byteCounter, so a large entry is counted and not
// kept in memory.
func entrySize(id Identity, tools ServerPins) (int, error) {
	var w byteCounter
	err := json.MarshalWrite(&w, newFileServer(id, tools), saveOptions, jsontext.WithIndentPrefix(indent+indent))
	if err != nil {
		// Not wrapped: the error text of encoding/json can hold a tool name.
		return 0, errors.New("the server pins cannot be encoded as JSON")
	}
	return len(indent+indent) + w.n + len(",\n"), nil
}

// isProjectServer reports whether id is a project server: a server whose
// Identity has a ProjectPath. Discover gives a ProjectPath to every server of
// the project scope, for example from a project .mcp.json, from
// .cursor/mcp.json or from the projects.<path> key of ~/.claude.json. Such
// servers count toward the project share (projectShare).
func isProjectServer(id Identity) bool {
	return id.ProjectPath != ""
}

// projectPart returns the part of size, the entry size of the server id, that
// counts toward the project share: all of it for a project server, 0 for a
// server of the user scope. Load and Set both use it, so projectBytes always
// follows the same rule.
func projectPart(id Identity, size int) int {
	if isProjectServer(id) {
		return size
	}
	return 0
}

// byteCounter is an io.Writer that counts the bytes written to it and drops
// them.
type byteCounter struct {
	n int
}

// Write adds len(p) to the count. It never fails.
func (c *byteCounter) Write(p []byte) (int, error) {
	c.n += len(p)
	return len(p), nil
}

// cloneOrEmpty returns a copy of p. A nil p gives an empty map, not nil.
func cloneOrEmpty(p ServerPins) ServerPins {
	c := maps.Clone(p)
	if c == nil {
		c = ServerPins{}
	}
	return c
}

// Save writes the store to its path, atomically, with file mode 0o600. A new
// directory gets mode 0o700. The servers and the tool names are sorted, so the
// same store always gives the same bytes.
//
// Save writes through an open os.Root of the pins directory, never by path. It
// has two cases:
//   - A Store from LoadLocked (or a Clone of it) keeps the directory that
//     LoadLocked opened and checked (the directory of the lock file that
//     LoadLocked locked). Save checks that handle again (checkDirHandle), so
//     a directory that became unsafe since the load is refused, and writes
//     through it.
//   - A Store from Load keeps no directory. Save opens the directory again
//     with the same steps as LoadLocked (see openPinsDir): it checks the
//     parent directories (checkParents), creates a missing pins directory,
//     opens it, checks the handle (checkDirHandle), writes through it and
//     closes it.
//
// In both cases Save checks, right before the rename, that the path still
// names the directory that it writes to (os.SameFile with the file info of the
// handle). When the directory was moved, removed or replaced, Save writes
// nothing and returns an error that wraps ErrPinsDirChanged. A small window
// remains between that check and the rename. Only the current user or root
// can move the pins directory then, because the parent check refuses a parent
// that another user can write.
//
// Save refuses an unsafe path with an error that wraps ErrInsecurePermissions:
// a pins directory that another user owns, that its group or others can write,
// or (macOS only) whose ACL lets a user or group write it, and for a Store from
// Load also an unsafe parent directory. Such an error names the unsafe path and
// has no "save <path>" prefix; every other error has it. Save never changes
// the mode of an existing directory. Save does not check the old pins.json,
// because the rename replaces it: callers read the file with Load or
// LoadLocked first, so the file check has run, and a pins.json symlink has
// made the read fail.
//
// Load and Set check each server, so Save checks only the whole file: it
// refuses data larger than MaxFileSize (32 MiB), the limit of Load, and the old
// file stays.
//
// The limit is a ceiling for all servers together. Set already refuses a
// server that would push the file over it (ErrStoreFull), so one large server
// cannot stop the others from being saved: the refused server is simply not
// pinned, and the caller reports it. The check in Save is a backstop.
//
// Save writes indented JSON, so the limit applies to that form. A compact file
// near the limit, for example from a hand edit, loads but cannot be saved. Then
// Save fails for the whole file. The caller must report the error and must not
// treat the run as pinned.
//
// Save takes no lock itself. It is safe against a parallel run only when the
// Store came from LoadLocked and the caller still holds that lock: then no
// other locking run can read or save between the load and this write. A Store
// from Load, or from LoadLocked when Store.RanWithoutLock is true, can still
// lose a parallel update (the last writer wins). A Save after the release
// function of LoadLocked fails, because the directory is closed.
//
// Save of a zero-value Store is an error, because it has no path: make a
// Store with Load or LoadLocked.
func (s *Store) Save() error {
	return s.saveWith(atomicWriter{})
}

// saveWith is Save with the atomic writer w, so a test can add hooks to the
// write (see atomicWriter).
func (s *Store) saveWith(w atomicWriter) error {
	// The lock also covers the write, so two Saves of one Store run one at a
	// time and the last call writes the last state.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.path == "" {
		return errors.New("save pins: the store has no path (make it with Load or LoadLocked)")
	}
	ids := slices.SortedFunc(maps.Keys(s.servers), compareIdentity)
	servers := make([]fileServer, 0, len(ids))
	for _, id := range ids {
		servers = append(servers, newFileServer(id, s.servers[id]))
	}
	f := fileFormat{Version: CurrentVersion, Servers: &servers}

	data, err := json.Marshal(f, saveOptions)
	if err != nil {
		// Not wrapped: the error text of encoding/json can hold a tool name.
		return fmt.Errorf("save %s: the pins cannot be encoded as JSON", s.path)
	}
	data = append(data, '\n')
	// Check the size before the write, so the old file stays valid.
	if len(data) > MaxFileSize {
		return fmt.Errorf("save %s: pins data is %d bytes, larger than the %d MiB limit",
			s.path, len(data), MaxFileSizeMiB)
	}

	// Case 1: the Store came from LoadLocked (or is a Clone of such a Store).
	// Write through the directory that LoadLocked opened and checked, and
	// whose lock file it locked.
	// Check the handle again first: the owner or the mode can have changed
	// since the load. After release, the handle is closed, so this check (or
	// the write) fails with an error.
	if s.root != nil {
		if err := checkDirHandle(filepath.Dir(s.path), s.dir); err != nil {
			// A refusal names the unsafe path itself, so it gets no "save
			// <path>" prefix (the same rule as in Load).
			return prefixUnlessRefusal("save", s.path, err)
		}
		return writePins(w, s.path, s.root, s.dir, s.dirInfo, data)
	}

	// Case 2: the Store came from Load and holds no directory. Open the
	// directory again, with the same checks as LoadLocked, write through it and
	// close it. The errors of openPinsDir already have the "save <path>"
	// prefix, or are refusals that name the unsafe path.
	root, d, info, err := openPinsDir("save", s.path, nil)
	if err != nil {
		return err
	}
	defer closeDir(root, d)
	return writePins(w, s.path, root, d, info, data)
}

// writePins writes data as the pins file path through root, the open pins
// directory, with w (see atomicWriter.writeFile). d is the handle of the same
// directory and info its file info, from d.Stat. Before the rename, the write
// checks that the path of the directory still names that directory
// (verifyPinsDir). Every error gets the "save <path>" prefix.
func writePins(w atomicWriter, path string, root *os.Root, d *os.File, info fs.FileInfo, data []byte) error {
	verify := verifyPinsDir(filepath.Dir(path), info)
	if err := w.writeFile(root, d, filepath.Base(path), data, verify); err != nil {
		return prefixUnlessRefusal("save", path, err)
	}
	return nil
}

// verifyPinsDir returns the verifyDir function of atomicWriter.writeFile for
// the pins directory dir, which was opened as the directory with the file
// info want. The function stats dir by path (os.Stat follows symlinks, as the
// open of the directory did) and compares the result with want (os.SameFile:
// the device and inode numbers on Unix). When dir is gone or names another
// directory, it returns an error that wraps ErrPinsDirChanged: the write
// would go to a directory that the next run does not read, or to a directory
// that another run may lock. Any other Stat error is returned with a short
// context.
//
// A small window remains between this check and the rename. Only the current
// user or root can move or replace the pins directory in that window: the
// parent check (checkParents) refuses a parent directory that another user
// can write, so the race does not help another user.
func verifyPinsDir(dir string, want fs.FileInfo) func() error {
	return func() error {
		got, err := os.Stat(dir)
		if safefile.IsMissing(err) || (err == nil && !os.SameFile(got, want)) {
			return fmt.Errorf("the pins directory %s was moved or removed while this command ran, and nothing was saved: %w",
				dir, ErrPinsDirChanged)
		}
		if err != nil {
			return fmt.Errorf("check the pins directory %s: %w", dir, err)
		}
		return nil
	}
}

// newFileServer returns the file entry of the server id. The pointers point
// to the parameters, which are copies. The tools map itself is shared, and
// the encoder only reads it.
func newFileServer(id Identity, tools ServerPins) fileServer {
	return fileServer{
		Client:      &id.Client,
		Source:      &id.Source,
		ProjectPath: &id.ProjectPath,
		Name:        &id.Name,
		Tools:       &tools,
	}
}

// compareIdentity orders identities by Client, Source, ProjectPath and Name.
func compareIdentity(a, b Identity) int {
	return cmp.Or(
		cmp.Compare(a.Client, b.Client),
		cmp.Compare(a.Source, b.Source),
		cmp.Compare(a.ProjectPath, b.ProjectPath),
		cmp.Compare(a.Name, b.Name),
	)
}

// ValidateServer checks the rules that Load and Set share, also the size cap
// of one server (maxServerSize). It returns the error that Set would return for
// the same pins, so a caller can learn whether a server can be pinned without a
// store. It does not check the size of the whole file (ErrStoreFull) or the
// project share (ErrProjectShareFull): they need the store, so use Set on a
// Clone of the store for them. The errors do not
// hold tool names, because a server that we do not trust chose them.
func ValidateServer(id Identity, tools ServerPins) error {
	if id.Name == "" {
		return errors.New("the server name is empty")
	}
	// The file must be valid UTF-8, and Load refuses a file that is not. Only
	// Set can hit this check: Load has already refused such text. Checking
	// here gives an error with no content, before the store changes.
	if !utf8.ValidString(id.Client) || !utf8.ValidString(id.Source) ||
		!utf8.ValidString(id.ProjectPath) || !utf8.ValidString(id.Name) {
		return errors.New("the server identity is not valid UTF-8")
	}
	for name, pin := range tools {
		if name == "" {
			return errors.New("a tool name is empty")
		}
		// A missing key or a null in pins.json gives an empty string, so Load
		// refuses it here too.
		if pin.Hash == "" {
			return errors.New("a tool hash is empty or missing")
		}
		if pin.Canonical == "" {
			return errors.New("a tool canonical text is empty or missing")
		}
		if !utf8.ValidString(name) {
			return errors.New("a tool name is not valid UTF-8")
		}
		if !utf8.ValidString(pin.Hash) {
			return errors.New("a tool hash is not valid UTF-8")
		}
		if !utf8.ValidString(pin.Canonical) {
			return errors.New("a tool canonical text is not valid UTF-8")
		}
	}
	// Encode to a byteCounter: only the size of the compact JSON is needed, so
	// the entry is counted and not kept in memory.
	var w byteCounter
	if err := json.MarshalWrite(&w, newFileServer(id, tools)); err != nil {
		// Not wrapped: the error text of encoding/json can hold a tool name.
		return errors.New("the server pins cannot be encoded as JSON")
	}
	if w.n > maxServerSize {
		return fmt.Errorf("server pins are %d bytes as JSON, larger than the %d byte limit",
			w.n, maxServerSize)
	}
	return nil
}

// describeJSONError turns a decode error into text with a position and no file
// content. The text of an encoding/json error can hold input, for example an
// unknown or a duplicate key, so we write our own text.
func describeJSONError(err error) string {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "unexpected end of the JSON data"
	}
	if se, ok := errors.AsType[*jsontext.SyntacticError](err); ok {
		if errors.Is(err, jsontext.ErrDuplicateName) {
			return fmt.Sprintf("duplicate key at byte %d", se.ByteOffset)
		}
		return fmt.Sprintf("invalid JSON at byte %d", se.ByteOffset)
	}
	if se, ok := errors.AsType[*json.SemanticError](err); ok {
		if errors.Is(err, json.ErrUnknownName) {
			return fmt.Sprintf("unknown field at byte %d", se.ByteOffset)
		}
		// A wrong type, or a number that is not an integer or is too large.
		return fmt.Sprintf("invalid value at byte %d", se.ByteOffset)
	}
	return "invalid JSON"
}
