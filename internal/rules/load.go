package rules

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	builtinrules "github.com/Ducarv/mcpmoat/rules"
)

// maxRuleFiles is the largest number of candidate rule files (names that end
// in .yaml or .yml) that one directory may hold. A rules directory can come
// from a cloned repository, so the cap stops a directory with millions of
// files from using all time and memory.
const maxRuleFiles = 1000

// maxFolderErrors is the number of errors after which the loader stops to read
// more files of a directory. Every file can give up to 21 errors, and a
// directory can hold maxRuleFiles files, so without the cap a hostile directory
// could give about 20000 errors and use much time and memory. The loader adds
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
	// fs.ReadDir returns the entries sorted by file name.
	entries, err := fs.ReadDir(builtinrules.FS, ".")
	if err != nil {
		return nil, []*LoadError{newLoadError(builtinLabel, ReasonDirUnreadable).wrap(err)}
	}
	return loadEntries(builtinrules.FS, builtinLabel, entries, o, func(name string) string { return name })
}

// LoadDir loads the rule files in the directory dir. It is not recursive. dir
// is untrusted input: the loader opens it with os.OpenRoot, so a read cannot
// leave the directory. Rule.Source and the File of an error are
// filepath.Join(dir, name). The rules come in the order of the file names,
// which is the same on every run.
//
// Only regular files whose names end in .yaml or .yml are rules. Other files
// and subdirectories are ignored. A symlink with such a name is refused with
// ReasonNotRegular, also when it points to a regular file. LoadDir collects the
// errors of all files. A file with an error gives no rule. It returns the rules
// and nil, or nil and the errors found. LoadDir stops after maxFolderErrors
// errors; then the last error has ReasonTooManyErrors and says how many files
// it did not check.
func LoadDir(dir string, opts ...Option) ([]Rule, []*LoadError) {
	o := newLoadOptions(opts)

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, []*LoadError{newLoadError(dir, ReasonDirUnreadable).wrap(err)}
	}
	defer func() {
		// The directory is read-only, so a close error is not useful.
		_ = root.Close()
	}()

	fsys := nonBlockFS{root}
	// fs.ReadDir returns the entries sorted by file name. It fails when dir is
	// not a directory.
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, []*LoadError{newLoadError(dir, ReasonDirUnreadable).wrap(err)}
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
		return nil, err
	}
	return f, nil
}

// isRuleName reports whether name looks like a rule file. The check is
// case-sensitive.
func isRuleName(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

// loadEntries loads the rule files among entries, which are the sorted
// entries of the root of fsys. dirName is the File of a directory-level error.
// display maps a file name to the name that Rule.Source and errors show. It
// stops to read files when it has maxFolderErrors errors.
func loadEntries(fsys fs.FS, dirName string, entries []fs.DirEntry, o loadOptions, display func(name string) string) ([]Rule, []*LoadError) {
	var candidates []fs.DirEntry
	for _, e := range entries {
		// A subdirectory is ignored, also when its name ends in .yaml.
		if e.IsDir() || !isRuleName(e.Name()) {
			continue
		}
		candidates = append(candidates, e)
	}
	if len(candidates) > maxRuleFiles {
		return nil, []*LoadError{newLoadError(dirName, ReasonTooManyFiles)}
	}

	var rules []Rule
	var errs []*LoadError
	notChecked := 0 // files left out after the cap
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
		stop := fmt.Errorf("stopped after %d errors; %d files not checked", maxFolderErrors, notChecked)
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
