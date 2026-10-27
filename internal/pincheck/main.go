// Command pincheck checks that the GoReleaser and govulncheck versions are
// pinned the same way in the GitHub workflows and in CONTRIBUTING.md. It reads
// the workflows with a YAML parser and fails closed on any form it cannot
// read. It is a CI tool only, not part of the mcpmoat binary:
// .github/scripts/check-tool-pins.sh runs it.
//
// Usage:
//
//	go run ./internal/pincheck [-root DIR]
//
// Exit codes: 0 when there is no problem, 1 when there is at least one
// problem, 2 on a usage or setup error (a bad flag, or a root that cannot be
// opened). Through .github/scripts/check-tool-pins.sh (go run), every non-zero
// exit shows as exit 1. See CONTRIBUTING.md.
//
// When the environment variable GITHUB_ACTIONS is exactly "true", as GitHub
// Actions sets it, each problem is an ::error:: workflow command on stdout.
// Any other value, such as "1" or "TRUE", or no value, gives plain
// "check-tool-pins: <problem>" lines on stderr.
//
// It writes at most 50 problem lines, and then one line "and N more
// problems". Each message cuts a key, a value or a name from a workflow to
// 80 bytes.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// The exit codes of run.
const (
	exitOK       = 0 // no problem
	exitProblems = 1 // at least one problem
	exitUsage    = 2 // a bad flag or a setup error
)

// githubDir is the .github directory, relative to the root.
const githubDir = ".github"

// workflowDir is the directory of the GitHub workflows, relative to the root.
const workflowDir = githubDir + "/workflows"

// The files that the rules read, as slash paths relative to the root. Every
// list of files is built from these names, so a name is written only once.
// ciName is the base name of ciPath, for a message.
const (
	ciName      = "ci.yml"
	ciPath      = workflowDir + "/" + ciName       // holds the reference pins
	releasePath = workflowDir + "/release.yml"     // the release workflow
	weeklyPath  = workflowDir + "/govulncheck.yml" // the weekly govulncheck run
	docPath     = "CONTRIBUTING.md"                // names the GoReleaser version
)

// maxFileBytes is the largest file that the check reads (1 MiB): a workflow,
// CONTRIBUTING.md or a file under .github/actions. The real files are about
// 10 KiB each, so the limit is far above real use. A larger file fails
// closed, before any YAML decoding.
const maxFileBytes = 1 << 20

// fullVersion matches a full version, such as v2.19.0 or v2.19.0-rc.1+build.5.
// A short one such as v2.19 is a query, and Go picks the newest version that
// matches it, so it is not a pin. In Go regexp, $ matches only at the end of
// the text, so a trailing newline does not match. A *regexp.Regexp is safe
// for use by many goroutines, so one package variable serves every rule.
var fullVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// msgPrefix starts each problem line outside GitHub Actions. People run the
// check with .github/scripts/check-tool-pins.sh, so each line names that
// script.
const msgPrefix = "check-tool-pins: "

// maxProblems is the most problem lines that run writes. A hostile or broken
// workflow can give one problem for each of its lines, so a 1 MiB file could
// flood the log with tens of thousands of lines. After maxProblems lines, run
// writes one line with the count of the rest, and still exits with 1.
const maxProblems = 50

// requiredFiles returns the files that must exist: the rules read each of
// them. It is a function and not a package variable, so that no code can
// change the list at run time.
func requiredFiles() []string {
	return []string{ciPath, releasePath, weeklyPath, docPath}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

// run is the whole program without os.Exit, so that tests can call it. args
// are the command-line arguments without the program name. getenv reads an
// environment variable (os.Getenv in main). It returns the exit code.
func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	out := newReporter(stdout, stderr, getenv("GITHUB_ACTIONS") == "true")

	// A FlagSet of its own, with ContinueOnError, returns an error instead of
	// calling os.Exit, and does not touch the global flag.CommandLine.
	flags := flag.NewFlagSet("pincheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "the root directory of the repository")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK // -h or -help: the FlagSet printed the usage
		}
		return exitUsage // the FlagSet printed the error and the usage
	}
	if flags.NArg() > 0 {
		out.problem(fmt.Sprintf("unexpected argument %s. Usage: pincheck [-root DIR]", termsafe.QuoteIf(flags.Arg(0), true)))
		return exitUsage
	}

	problems, err := checkRoot(*root)
	if err != nil {
		out.problem(err.Error())
		return exitUsage
	}
	return report(out, problems)
}

// report writes the first maxProblems problems with out, in their order, and
// then one line that counts the problems it did not write. It returns
// exitProblems when there is at least one problem, else exitOK.
func report(out reporter, problems []string) int {
	for i, p := range problems {
		if i == maxProblems {
			out.problem(moreProblems(len(problems) - maxProblems))
			break
		}
		out.problem(p)
	}
	if len(problems) > 0 {
		return exitProblems
	}
	return exitOK
}

// moreProblems returns the last line of a cut report: "and N more problems",
// or "and 1 more problem".
func moreProblems(n int) string {
	if n == 1 {
		return "and 1 more problem"
	}
	return fmt.Sprintf("and %d more problems", n)
}

// checkRoot opens the directory dir as an os.Root and checks it. An os.Root
// keeps every read inside dir: a path with .. or a symlink cannot leave it.
// The error is for a root that cannot be opened.
func checkRoot(dir string) ([]string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		// noPath keeps the host path of the root out of the message.
		return nil, fmt.Errorf("open the repository root: %w", noPath(err))
	}
	// The root is only read, so a Close error tells nothing new. The blank
	// identifier _ drops it on purpose.
	defer func() { _ = root.Close() }()
	return check(root.FS()), nil
}

// check runs every rule on the repository in fsys and returns the problems,
// without duplicates. The required-file and the parse problems come first,
// then the env problems of every workflow, then those of the GoReleaser and
// the govulncheck rules, in the order the rules return them. A required
// workflow that did not load gets exactly one problem, here: the rules skip
// it without a message.
func check(fsys fs.FS) []string {
	problems := checkRequired(fsys)
	wfs, parseProblems := loadWorkflows(fsys)
	problems = append(problems, parseProblems...)
	problems = append(problems, notLoaded(wfs, problems)...)
	problems = append(problems, checkEnv(wfs)...)
	problems = append(problems, checkGoreleaser(fsys, wfs)...)
	problems = append(problems, checkGovulncheck(wfs)...)
	return dedupe(problems)
}

// checkEnv returns the envProblems of every workflow in wfs, in the sorted
// order of the paths. The rule runs on every workflow, so it does not depend
// on which tool rule reads a file. Go visits a map in a random order, so
// slices.Sorted(maps.Keys(wfs)) makes the output stable. maps.Keys returns an
// iterator over the keys, and slices.Sorted collects them into a sorted slice.
func checkEnv(wfs map[string]*workflow) []string {
	var problems []string
	for _, p := range slices.Sorted(maps.Keys(wfs)) {
		problems = append(problems, wfs[p].envProblems()...)
	}
	return problems
}

// checkRequired returns one problem for each file of requiredFiles that is
// missing or is not a regular file. fs.Stat follows a symlink, so a required
// file can be a symlink to a regular file inside the root (the os.Root of
// checkRoot stops a link that leaves the root). A symlinked CONTRIBUTING.md
// is a normal file for its readers. loadWorkflows still fails a symlinked
// workflow, because this check does not follow symlinks in workflowDir.
func checkRequired(fsys fs.FS) []string {
	var problems []string
	for _, name := range requiredFiles() {
		info, err := fs.Stat(fsys, name)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			problems = append(problems, name+": the file is missing")
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: %v", name, noPath(err)))
		case !info.Mode().IsRegular():
			problems = append(problems, notRegular(name))
		}
	}
	return problems
}

// notRegular returns the problem for the path p that is not a regular file.
// checkRequired and loadWorkflows both use it, so a required workflow that is
// a directory gives the same text twice, and dedupe keeps one copy.
func notRegular(p string) string {
	return p + ": is not a regular file"
}

// notLoaded returns one problem for each required workflow that is not in
// wfs and that no problem in earlier names yet. checkRequired and
// loadWorkflows report almost every such case: a missing file, a file that
// is not regular, a symlink or a file that did not parse. One case is left:
// fs.Stat finds the file, but the listing of workflowDir has no entry with
// this exact name. That happens on a file system that ignores case, with
// CI.yml in place of ci.yml, or when the directory cannot be read in full.
// The rules skip a workflow that is not in wfs, so without this problem the
// check could pass. Each problem from checkRequired and loadWorkflows starts
// with the path and a colon, so the prefix finds them.
func notLoaded(wfs map[string]*workflow, earlier []string) []string {
	var problems []string
	for _, p := range requiredFiles() {
		if path.Dir(p) != workflowDir || wfs[p] != nil {
			continue
		}
		reported := slices.ContainsFunc(earlier, func(m string) bool {
			return strings.HasPrefix(m, p+":")
		})
		if !reported {
			problems = append(problems, p+": the pin checks need this workflow, but it is not in the listing of "+workflowDir)
		}
	}
	return problems
}

// loadWorkflows reads and parses every workflow file in workflowDir. The map
// key is the slash path relative to the root, such as
// ".github/workflows/ci.yml". A file that cannot be read or parsed gives one
// problem and is not in the map. A missing workflowDir gives no problem,
// because checkRequired reports the missing workflows.
//
// Every value in the map is a non-nil *workflow with a non-nil top node,
// because parseWorkflow returns an error for any file it cannot load. So the
// rules do not test a value for nil: a missing key is the only "not loaded"
// state.
func loadWorkflows(fsys fs.FS) (map[string]*workflow, []string) {
	wfs := make(map[string]*workflow)
	var problems []string
	// fs.ReadDir returns the entries it could read and the error, so a read
	// error does not hide the other files.
	entries, err := fs.ReadDir(fsys, workflowDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		problems = append(problems, fmt.Sprintf("%s: read the directory: %v", workflowDir, noPath(err)))
	}
	for _, e := range entries {
		if !isWorkflowName(e.Name()) {
			continue
		}
		p := path.Join(workflowDir, e.Name())
		// The type comes from the directory entry, so a symlink is not
		// followed. GitHub reads only the files of the repository, and this
		// check fails closed on anything else.
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			problems = append(problems, p+": is a symlink. This check does not follow symlinks in "+workflowDir)
			continue
		case !e.Type().IsRegular():
			problems = append(problems, notRegular(p))
			continue
		}
		w, err := readWorkflow(fsys, p)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		wfs[p] = w
	}
	return wfs, problems
}

// isWorkflowName reports whether name ends in .yml or .yaml, in any case. A
// name that starts with a dot, and the names .yml and .yaml themselves,
// count too: GitHub runs such a file, so the check must read it.
func isWorkflowName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

// readWorkflow reads the file p of fsys with readLimited and parses it.
func readWorkflow(fsys fs.FS, p string) (*workflow, error) {
	data, err := readLimited(fsys, p, maxFileBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return parseWorkflow(p, data)
}

// readLimited reads the file name of fsys. It fails when the file has more
// than limit bytes. io.LimitReader stops after one byte more than the limit,
// so a large file is never read in full. The error does not name the file:
// the caller adds the name. noPath removes the path of the file system error.
func readLimited(fsys fs.FS, name string, limit int64) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open: %w", noPath(err))
	}
	// The file is only read, so a Close error tells nothing new.
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", noPath(err))
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("the file has more than %d bytes, so the check does not read it", limit)
	}
	return data, nil
}

// noPath returns the inner error of the first *fs.PathError in the chain of
// err, or err itself when there is none. A file of an os.Root keeps the
// absolute host path in its name, so a read error can hold that path, such
// as "read /home/me/repo/CONTRIBUTING.md: is a directory". A message must
// name only the path relative to the root, and the caller adds that. The
// inner error is an error value such as syscall.EISDIR, so errors.Is still
// finds fs.ErrNotExist or fs.ErrPermission in it. errors.As looks through
// every wrapped error and sets pe when it finds a *fs.PathError.
func noPath(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// onlyVersion looks for exactly one distinct version in versions (the same
// version may repeat). When there is one, it returns it, and found is "".
// Otherwise version is "" and found tells what there is, for a message:
// "none", or the distinct versions in sorted order, joined with ", " and cut
// to maxShown bytes (a file can hold many long versions).
func onlyVersion(versions []string) (version, found string) {
	seen := make(map[string]bool)
	for _, v := range versions {
		seen[v] = true
	}
	// Go visits a map in a random order, so sort for a stable message.
	distinct := slices.Sorted(maps.Keys(seen))
	switch len(distinct) {
	case 0:
		return "", "none"
	case 1:
		return distinct[0], ""
	default:
		return "", cutText(strings.Join(distinct, ", "), maxShown)
	}
}

// dedupe returns msgs without repeated messages, and keeps the first of each
// in its place. Two rules can find the same problem, such as a job that is
// not a mapping. They build its text with one shared helper, so the two
// copies are equal and dedupe keeps one.
func dedupe(msgs []string) []string {
	seen := make(map[string]bool, len(msgs))
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

// reporter writes problem lines. In GitHub Actions (actions is true) a line
// is an ::error:: workflow command on stdout, because GitHub reads workflow
// commands there and shows each as an annotation. Otherwise it is
// "check-tool-pins: <message>" on stderr, because a problem is a log line
// for a person, not data.
type reporter struct {
	stdout, stderr io.Writer
	actions        bool
}

// newReporter returns a reporter that writes to stdout and stderr.
func newReporter(stdout, stderr io.Writer, actions bool) reporter {
	return reporter{stdout: stdout, stderr: stderr, actions: actions}
}

// problem writes one problem line. The message can hold text from a workflow
// file or a file name, so safeText first makes every control character
// visible. A message then has no line break, and cannot start a second log
// line or a second workflow command.
func (r reporter) problem(msg string) {
	msg = safeText(msg)
	// A write error to stdout or stderr cannot be reported anywhere else, and
	// the exit code still tells the result. The blank identifier drops it.
	if r.actions {
		_, _ = fmt.Fprintln(r.stdout, "::error::"+escapeCommandData(msg))
		return
	}
	_, _ = fmt.Fprintln(r.stderr, msgPrefix+msg)
}

// safeText returns s with each unsafe rune escaped, as termsafe.Escape does.
// It does not use termsafe.Quote, which adds quotes and writes a newline as \n.
func safeText(s string) string {
	return termsafe.Escape(s)
}

// escapeCommandData escapes s for the data part of a GitHub workflow command,
// such as ::error::<data>. GitHub decodes %25, %0D and %0A back to %, \r and
// \n. A strings.Replacer makes all the replacements in one pass, so the % of
// a new %0A is not escaped again. problem calls safeText first, so s has no
// \r or \n; the two escapes are a second guard.
func escapeCommandData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}
