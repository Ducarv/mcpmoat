package rules

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	builtinrules "github.com/Ducarv/mcpmoat/rules"
)

// maxRuleFiles is the largest number of candidate rule files (names that end
// in .yaml or .yml) that one directory may hold. A rules directory can come
// from a cloned repository, so the cap stops a directory with millions of
// files from using all time and memory. LoadDir lists the directory in batches
// and stops at the cap, see listRuleFiles.
const maxRuleFiles = 1000

// maxDirEntries is the largest number of entries, with any name, that LoadDir
// reads from one directory. Without it, a directory with millions of entries
// that are not rule files would still be read in full.
const maxDirEntries = 10 * maxRuleFiles

// dirBatch is the number of directory entries that LoadDir reads in one call.
const dirBatch = 256

// maxFolderErrors is the number of errors after which the loader stops to read
// more files of a directory. Every file can give up to maxErrorsPerFile+1
// errors, and a directory can hold maxRuleFiles files, so without the cap a
// hostile directory could give about 21000 errors and use much time and memory. The loader adds
// one last ReasonTooManyErrors error, so a result has at most maxFolderErrors+1
// errors.
const maxFolderErrors = 100

// builtinLabel is the File of the errors that are about the built-in rules as
// a whole and not about one file.
const builtinLabel = "builtin rules"

// loadOptions holds the settings that Option values change.
type loadOptions struct {
	compiler Compiler
}

// Option changes how rules are loaded. Pass options to Builtin and LoadDir.
// This is the "functional options" pattern: each option is a small function
// that changes the settings before loading starts.
type Option func(*loadOptions)

// WithCompiler makes the loader compile the Match section of every rule it
// parses, and report a compile failure as a LoadError for that rule. The
// Matcher that the compiler returns is discarded for now. A nil Compiler (the
// default) means that the loader does not compile.
func WithCompiler(c Compiler) Option {
	return func(o *loadOptions) { o.compiler = c }
}

// newLoadOptions applies opts to a new set of default settings.
func newLoadOptions(opts []Option) loadOptions {
	var o loadOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// Builtin loads the built-in rules that are embedded in the binary. Rule.Source
// and the File of an error are the bare file names, for example
// "MOAT-T1-003.yaml". The rules come in the order of the file names, which is
// the same on every run. It returns the rules and nil, or nil and the errors
// found (at most maxFolderErrors, then one ReasonTooManyErrors error). A
// built-in rule that fails is a bug in mcpmoat, and the caller must treat it as
// a fatal error.
func Builtin(opts ...Option) ([]Rule, []*LoadError) {
	o := newLoadOptions(opts)
	entries, lerr := listRuleFiles(builtinrules.FS, builtinLabel, maxDirEntries, maxRuleFiles)
	if lerr != nil {
		return nil, []*LoadError{lerr}
	}
	return loadEntries(builtinrules.FS, builtinLabel, entries, o, func(name string) string { return name })
}

// LoadDir loads the rule files in the directory dir. It is not recursive. dir
// is untrusted input: the loader opens it with os.OpenRoot, so a read cannot
// leave the directory. Rule.Source and the File of an error are
// filepath.Join(dir, name). The rules come in the order of the file names,
// which is the same on every run.
//
// Only regular files whose names end in .yaml or .yml, in any case, are rules.
// Other files and subdirectories are ignored. A symlink with such a name is
// refused with ReasonNotRegular, also when it points to a regular file. This
// check uses the directory listing. A file that someone swaps for a symlink
// after the listing, while the scan runs, is opened, but the open cannot leave
// dir. A directory with no such file gives ReasonNoRuleFiles. LoadDir collects
// the errors of all files. A file with an error gives no rule. It returns the
// rules and nil, or nil and the errors found. LoadDir stops after
// maxFolderErrors errors; then the last error has ReasonTooManyErrors and says
// how many files it did not fully check. A directory with more than
// maxRuleFiles candidate files, or more than maxDirEntries entries, gives
// ReasonTooManyFiles.
func LoadDir(dir string, opts ...Option) ([]Rule, []*LoadError) {
	o := newLoadOptions(opts)

	// os.OpenRoot opens dir with a plain open(2), which blocks on a FIFO until
	// a writer appears. A FIFO, or a symlink to one, as the --rules path would
	// hang the scan. os.Stat does not block and follows symlinks. A swap to a
	// FIFO between this check and the open is a local race that we accept.
	info, err := os.Stat(dir)
	if err != nil {
		return nil, []*LoadError{newLoadError(dir, ReasonDirUnreadable).wrap(err)}
	}
	if !info.IsDir() {
		err = &fs.PathError{Op: "open", Path: dir, Err: syscall.ENOTDIR}
		return nil, []*LoadError{newLoadError(dir, ReasonDirUnreadable).wrap(err)}
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, []*LoadError{newLoadError(dir, ReasonDirUnreadable).wrap(err)}
	}
	defer func() {
		// The directory is read-only, so a close error is not useful.
		_ = root.Close()
	}()

	fsys := nonBlockFS{root}
	entries, lerr := listRuleFiles(fsys, dir, maxDirEntries, maxRuleFiles)
	if lerr != nil {
		return nil, []*LoadError{lerr}
	}
	// The user named this folder for its rules. A folder with none, or one
	// whose files all have another extension, would give a scan that looks as
	// if it used extra rules and does not.
	if len(entries) == 0 {
		return nil, []*LoadError{newLoadError(dir, ReasonNoRuleFiles)}
	}
	return loadEntries(fsys, dir, entries, o, func(name string) string { return filepath.Join(dir, name) })
}

// nonBlockFS is a read-only fs.FS on an os.Root that opens every file with
// O_NONBLOCK. Opening a FIFO that a writer swapped in after the directory
// listing then returns at once and readRuleFile refuses it, where a plain open
// would block until a writer appears and hang the scan.
type nonBlockFS struct{ root *os.Root }

// Open opens name, relative to the root, for reading without blocking.
func (n nonBlockFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	f, err := n.root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		// Return an untyped nil here. A nil *os.File inside an fs.File value is
		// not equal to nil, and the caller would try to use it.
		return nil, err
	}
	return f, nil
}

// listRuleFiles returns the candidate rule files of the root of fsys, sorted by
// file name. A candidate is a name that ends in .yaml or .yml and is not a
// directory. It reads the directory in batches of dirBatch entries and stops
// at once when the directory has more than maxEntries entries, or more than
// maxFiles candidates, so a hostile directory cannot make it read and sort
// millions of names. dirName is the File of the error it returns.
func listRuleFiles(fsys fs.FS, dirName string, maxEntries, maxFiles int) ([]fs.DirEntry, *LoadError) {
	d, err := fsys.Open(".")
	if err != nil {
		return nil, newLoadError(dirName, ReasonDirUnreadable).wrap(err)
	}
	defer func() {
		// The directory is read-only, so a close error is not useful.
		_ = d.Close()
	}()
	rd, ok := d.(fs.ReadDirFile)
	if !ok {
		return nil, newLoadError(dirName, ReasonDirUnreadable).wrap(errors.New("not a directory"))
	}

	var candidates []fs.DirEntry
	seen := 0
	for {
		batch, err := rd.ReadDir(dirBatch)
		for _, e := range batch {
			seen++
			if isCandidate(e) {
				candidates = append(candidates, e)
			}
		}
		if seen > maxEntries || len(candidates) > maxFiles {
			return nil, newLoadError(dirName, ReasonTooManyFiles)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, newLoadError(dirName, ReasonDirUnreadable).wrap(err)
		}
		if len(batch) == 0 {
			// The fs.ReadDirFile contract says an empty batch comes with an
			// error. Without this check, a file that breaks it would loop forever.
			return nil, newLoadError(dirName, ReasonDirUnreadable).wrap(io.ErrNoProgress)
		}
	}
	slices.SortFunc(candidates, func(a, b fs.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return candidates, nil
}

// isCandidate reports whether e may be a rule file: a name that ends in .yaml
// or .yml. A subdirectory is not a candidate, also when its name ends in .yaml.
func isCandidate(e fs.DirEntry) bool {
	return !e.IsDir() && isRuleName(e.Name())
}

// isRuleName reports whether name looks like a rule file: it ends in .yaml or
// .yml, in any case. The case does not matter, so a file called Rule.YAML is
// loaded and not skipped without a word.
func isRuleName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}

// loadEntries loads the rule files in candidates, which listRuleFiles returned
// for the root of fsys, sorted by file name. dirName is the File of a
// directory-level error. display maps a file name to the name that Rule.Source
// and errors show. It stops to read files when it has maxFolderErrors errors.
func loadEntries(fsys fs.FS, dirName string, candidates []fs.DirEntry, o loadOptions, display func(name string) string) ([]Rule, []*LoadError) {

	var rules []Rule
	var errs []*LoadError
	notChecked := 0 // files not read after the cap, and files whose errors were cut
	for i, e := range candidates {
		if len(errs) >= maxFolderErrors {
			notChecked += len(candidates) - i
			break
		}
		name := display(e.Name())
		// The type comes from the directory listing and does not follow
		// symlinks. A symlink, a FIFO or a device is refused before any open.
		if !e.Type().IsRegular() {
			errs = append(errs, newLoadError(name, ReasonNotRegular))
			continue
		}
		rule, fileErrs := loadFile(fsys, e.Name(), name, o)
		if len(fileErrs) > 0 {
			room := maxFolderErrors - len(errs)
			if len(fileErrs) > room {
				// Keep the total at maxFolderErrors. This file counts as not
				// fully shown.
				fileErrs = fileErrs[:room]
				notChecked++
			}
			errs = append(errs, fileErrs...)
			continue
		}
		rules = append(rules, rule)
	}
	if notChecked > 0 {
		// Only ints in the text: no untrusted text.
		stop := fmt.Errorf("stopped after %d errors; %d files not fully checked", maxFolderErrors, notChecked)
		errs = append(errs, newLoadError(dirName, ReasonTooManyErrors).wrap(stop))
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return rules, nil
}

// loadFile reads, parses and (with a compiler) compiles the rule file called
// name in fsys. display is the name for Rule.Source and for errors.
func loadFile(fsys fs.FS, name, display string, o loadOptions) (Rule, []*LoadError) {
	data, lerr := readRuleFile(fsys, name, display)
	if lerr != nil {
		return Rule{}, []*LoadError{lerr}
	}
	rule, errs := Parse(display, data)
	if len(errs) > 0 {
		return Rule{}, errs
	}
	if o.compiler != nil {
		// The Matcher is discarded in this version; issue #35 will use it.
		if _, err := o.compiler(rule.Match, rule.Target); err != nil {
			return Rule{}, []*LoadError{newLoadError(display, ReasonInvalidValue).inField("match").wrap(err)}
		}
	}
	return rule, nil
}

// readRuleFile reads the file called name in fsys with a hard size cap. It
// opens the file first and checks the open handle, so the checks and the read
// use the same file. display is the name for errors.
func readRuleFile(fsys fs.FS, name, display string) ([]byte, *LoadError) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, newLoadError(display, ReasonUnreadable).wrap(err)
	}
	defer func() {
		// The file is read-only, so a close error is not useful.
		_ = f.Close()
	}()

	info, err := f.Stat()
	if err != nil {
		return nil, newLoadError(display, ReasonUnreadable).wrap(err)
	}
	if !info.Mode().IsRegular() {
		return nil, newLoadError(display, ReasonNotRegular)
	}
	if info.Size() > maxFileBytes {
		return nil, newLoadError(display, ReasonTooLarge)
	}

	// Read one byte more than the cap, so we can tell if the file grew after
	// Stat.
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, newLoadError(display, ReasonUnreadable).wrap(err)
	}
	if len(data) > maxFileBytes {
		return nil, newLoadError(display, ReasonTooLarge)
	}
	return data, nil
}
