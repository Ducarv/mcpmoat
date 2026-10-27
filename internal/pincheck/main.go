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
// opened).
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
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// The exit codes of run.
const (
	exitOK       = 0 // no problem
	exitProblems = 1 // at least one problem
	exitUsage    = 2 // a bad flag or a setup error
)

// workflowDir is the directory of the GitHub workflows, relative to the root.
const workflowDir = ".github/workflows"

// msgPrefix starts each problem line outside GitHub Actions. It is the name of
// the old script, so the output stays the same for the people who read it.
const msgPrefix = "check-tool-pins: "

// maxProblems is the most problem lines that run writes. A hostile or broken
// workflow can give one problem for each of its lines, so a 1 MiB file could
// flood the log with tens of thousands of lines. After maxProblems lines, run
// writes one line with the count of the rest, and still exits with 1.
const maxProblems = 50

// requiredFiles returns the files that must exist, as the old
// check-tool-pins.sh required them. It is a function and not a package
// variable, so that no code can change the list at run time.
func requiredFiles() []string {
	return []string{
		workflowDir + "/ci.yml",
		workflowDir + "/release.yml",
		workflowDir + "/govulncheck.yml",
		"CONTRIBUTING.md",
	}
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
		return nil, fmt.Errorf("open the repository root: %w", err)
	}
	// The root is only read, so a Close error tells nothing new. The blank
	// identifier _ drops it on purpose.
	defer func() { _ = root.Close() }()
	return check(root.FS()), nil
}

// check runs every rule on the repository in fsys and returns the problems,
// without duplicates. The required-file and the parse problems come first,
// then the env problems of every workflow, then those of the GoReleaser and
// the govulncheck rules, in the order the rules return them.
func check(fsys fs.FS) []string {
	problems := checkRequired(fsys)
	wfs, parseProblems := loadWorkflows(fsys)
	problems = append(problems, parseProblems...)
	problems = append(problems, checkEnv(wfs)...)
	problems = append(problems, checkGoreleaser(fsys, wfs)...)
	problems = append(problems, checkGovulncheck(fsys, wfs)...)
	return dedupe(problems)
}

// checkEnv returns the envProblems of every workflow in wfs, in the sorted
// order of the paths. The rule runs on every workflow, so it does not depend
// on which tool rule reads a file. Go visits a map in a random order, so
// slices.Sorted(maps.Keys(wfs)) makes the output stable.
func checkEnv(wfs map[string]*workflow) []string {
	var problems []string
	for _, p := range slices.Sorted(maps.Keys(wfs)) {
		problems = append(problems, wfs[p].envProblems()...)
	}
	return problems
}

// checkRequired returns one problem for each file of requiredFiles that is
// missing or is not a regular file. fs.Stat follows a symlink inside the
// root, as the old script did; loadWorkflows fails a symlinked workflow.
func checkRequired(fsys fs.FS) []string {
	var problems []string
	for _, name := range requiredFiles() {
		info, err := fs.Stat(fsys, name)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			problems = append(problems, name+": the file is missing")
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
		case !info.Mode().IsRegular():
			problems = append(problems, name+": is not a regular file")
		}
	}
	return problems
}

// loadWorkflows reads and parses every workflow file in workflowDir. The map
// key is the slash path relative to the root, such as
// ".github/workflows/ci.yml". A file that cannot be read or parsed gives one
// problem and is not in the map. A missing workflowDir gives no problem,
// because checkRequired reports the missing workflows.
func loadWorkflows(fsys fs.FS) (map[string]*workflow, []string) {
	wfs := make(map[string]*workflow)
	var problems []string
	// fs.ReadDir returns the entries it could read and the error, so a read
	// error does not hide the other files.
	entries, err := fs.ReadDir(fsys, workflowDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		problems = append(problems, fmt.Sprintf("%s: read the directory: %v", workflowDir, err))
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
			problems = append(problems, p+": is not a regular file")
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
// count too, as in the old script.
func isWorkflowName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

// readWorkflow reads the file p of fsys and parses it. It reads at most
// maxWorkflowBytes+1 bytes, so a large file is never read in full, and
// parseWorkflow rejects it.
func readWorkflow(fsys fs.FS, p string) (*workflow, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, fmt.Errorf("%s: open: %w", p, err)
	}
	// The file is only read, so a Close error tells nothing new.
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxWorkflowBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s: read: %w", p, err)
	}
	return parseWorkflow(p, data)
}

// dedupe returns msgs without repeated messages, and keeps the first of each
// in its place. Both rule sets can report the same structure error for the
// same job.
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
// is an ::error:: workflow command on stdout, so GitHub shows it as an
// annotation. Otherwise it is "check-tool-pins: <message>" on stderr. These
// are the streams and the formats of the old script.
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

// safeText returns s with each rune that is not safe to print replaced by a
// visible escape: \xNN for an invalid UTF-8 byte or an ASCII control
// character (such as a newline or ESC), and \uXXXX or \UXXXXXXXX for any
// other rune for which termsafe.NeedsEscape is true (C1 controls, bidi and
// zero-width characters). All other text stays as it is.
func safeText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			_, _ = fmt.Fprintf(&b, `\x%02x`, s[i]) // a strings.Builder write never fails
		case r < utf8.RuneSelf && termsafe.NeedsEscape(r):
			_, _ = fmt.Fprintf(&b, `\x%02x`, r)
		case r > 0xffff && termsafe.NeedsEscape(r):
			_, _ = fmt.Fprintf(&b, `\U%08x`, r)
		case termsafe.NeedsEscape(r):
			_, _ = fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// escapeCommandData escapes s for the data part of a GitHub workflow command,
// such as ::error::<data>. GitHub decodes %25, %0D and %0A back to %, \r and
// \n. A strings.Replacer makes all the replacements in one pass, so the % of
// a new %0A is not escaped again. problem calls safeText first, so s has no
// \r or \n; the two escapes are a second guard.
func escapeCommandData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}
