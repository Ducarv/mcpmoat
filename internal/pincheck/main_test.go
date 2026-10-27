package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// repoFiles are the real files that repoCopyFS copies, as slash paths
// relative to the repository root.
var repoFiles = []string{ciPath, releasePath, weeklyPath, docPath}

// readRepoFiles reads repoFiles from the real repository once. sync.OnceValues
// runs the function on the first call only and returns the same results to
// every later call, also from parallel tests.
var readRepoFiles = sync.OnceValues(func() (map[string][]byte, error) {
	out := make(map[string][]byte, len(repoFiles))
	for _, name := range repoFiles {
		data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
		if err != nil {
			return nil, err
		}
		out[name] = data
	}
	return out, nil
})

// repoCopyFS returns a new MapFS with a copy of the real workflows and
// CONTRIBUTING.md. check gives zero problems for it. Each call returns a new
// map, so a test can change its copy.
func repoCopyFS(t *testing.T) fstest.MapFS {
	t.Helper()
	files, err := readRepoFiles()
	if err != nil {
		t.Fatalf("read the repository files: %v", err)
	}
	fsys := make(fstest.MapFS, len(files))
	for name, data := range files {
		fsys[name] = &fstest.MapFile{Data: bytes.Clone(data), Mode: 0o644}
	}
	return fsys
}

// writeTree writes the regular files of fsys below dir.
func writeTree(t *testing.T, dir string, fsys fstest.MapFS) {
	t.Helper()
	for name, f := range fsys {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, f.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// repoCopyDir returns a new temporary directory with a copy of repoCopyFS.
func repoCopyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, repoCopyFS(t))
	return dir
}

// env returns a getenv function that reads vars.
func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

// wf returns the slash path of the workflow file name.
func wf(name string) string { return path.Join(workflowDir, name) }

// countPrefix returns how many problems start with prefix.
func countPrefix(problems []string, prefix string) int {
	n := 0
	for _, p := range problems {
		if strings.HasPrefix(p, prefix) {
			n++
		}
	}
	return n
}

// assertNoRawControl fails when out has a byte below 0x20 other than a
// newline, a DEL, an invalid UTF-8 byte or the U+202E bidi control.
func assertNoRawControl(t *testing.T, out string) {
	t.Helper()
	for i := 0; i < len(out); i++ {
		c := out[i]
		if (c < 0x20 && c != '\n') || c == 0x7f {
			t.Errorf("output has the raw control byte %#x at %d: %q", c, i, out)
		}
	}
	if !utf8.ValidString(out) {
		t.Errorf("output has invalid UTF-8: %q", out)
	}
	if strings.ContainsRune(out, '\u202e') {
		t.Errorf("output has a raw U+202E: %q", out)
	}
}

func TestRunExitCodes(t *testing.T) {
	t.Parallel()
	missingRoot := filepath.Join(t.TempDir(), "does-not-exist")
	emptyRoot := t.TempDir()
	tests := []struct {
		name       string
		args       []string
		want       int
		wantStdout bool
		wantStderr string // a substring of stderr; "" means stderr must be empty
	}{
		{name: "real repo", args: []string{"-root", "../.."}, want: exitOK},
		{name: "real repo with = form", args: []string{"-root=../.."}, want: exitOK},
		{name: "problems", args: []string{"-root", emptyRoot}, want: exitProblems, wantStderr: msgPrefix + ".github/workflows/ci.yml: the file is missing"},
		{name: "unknown flag", args: []string{"-nope"}, want: exitUsage, wantStderr: "flag provided but not defined: -nope"},
		{name: "flag without value", args: []string{"-root"}, want: exitUsage, wantStderr: "flag needs an argument"},
		{name: "extra argument", args: []string{"-root", "../..", "extra"}, want: exitUsage, wantStderr: msgPrefix + "unexpected argument"},
		{name: "argument without flag", args: []string{"extra"}, want: exitUsage, wantStderr: "unexpected argument"},
		{name: "missing root", args: []string{"-root", missingRoot}, want: exitUsage, wantStderr: msgPrefix + "open the repository root"},
		{name: "help -h", args: []string{"-h"}, want: exitOK, wantStderr: "Usage of pincheck"},
		{name: "help -help", args: []string{"-help"}, want: exitOK, wantStderr: "Usage of pincheck"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			got := run(tt.args, &stdout, &stderr, env(nil))
			if got != tt.want {
				t.Errorf("run(%q) = %d, want %d; stderr:\n%s", tt.args, got, tt.want, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("run(%q) stdout = %q, want empty", tt.args, stdout.String())
			}
			if tt.wantStderr == "" {
				if stderr.Len() != 0 {
					t.Errorf("run(%q) stderr = %q, want empty", tt.args, stderr.String())
				}
			} else if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("run(%q) stderr = %q, want it to contain %q", tt.args, stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestRunOutputFormat(t *testing.T) {
	t.Parallel()
	root := repoCopyDir(t)
	if err := os.Remove(filepath.Join(root, "CONTRIBUTING.md")); err != nil {
		t.Fatal(err)
	}
	const msg = "CONTRIBUTING.md: the file is missing"
	tests := []struct {
		name          string
		vars          map[string]string
		wantInStdout  bool
		wantLinePrefx string
	}{
		{name: "github actions", vars: map[string]string{"GITHUB_ACTIONS": "true"}, wantInStdout: true, wantLinePrefx: "::error::"},
		{name: "no env", vars: nil, wantLinePrefx: msgPrefix},
		{name: "GITHUB_ACTIONS=1 is plain", vars: map[string]string{"GITHUB_ACTIONS": "1"}, wantLinePrefx: msgPrefix},
		{name: "GITHUB_ACTIONS=TRUE is plain", vars: map[string]string{"GITHUB_ACTIONS": "TRUE"}, wantLinePrefx: msgPrefix},
		{name: "other variable", vars: map[string]string{"CI": "true"}, wantLinePrefx: msgPrefix},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if got := run([]string{"-root", root}, &stdout, &stderr, env(tt.vars)); got != exitProblems {
				t.Fatalf("run() = %d, want %d", got, exitProblems)
			}
			out, quiet := stderr.String(), stdout.String()
			if tt.wantInStdout {
				out, quiet = quiet, out
			}
			if quiet != "" {
				t.Errorf("the other stream = %q, want empty", quiet)
			}
			if !strings.HasSuffix(out, "\n") {
				t.Fatalf("output %q does not end in a newline", out)
			}
			lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
			for _, l := range lines {
				if !strings.HasPrefix(l, tt.wantLinePrefx) {
					t.Errorf("line %q does not start with %q", l, tt.wantLinePrefx)
				}
			}
			if lines[0] != tt.wantLinePrefx+msg {
				t.Errorf("first line = %q, want %q", lines[0], tt.wantLinePrefx+msg)
			}
		})
	}
}

// hostileName is a workflow file name with a line break that starts a second
// workflow command, a %0A that GitHub decodes, a CR, an ESC and a bidi
// control.
const hostileName = "x\n::warning::y%0A\r\x1b\u202e.yml"

func TestRunInjectionInFileName(t *testing.T) {
	t.Parallel()
	root := repoCopyDir(t)
	if err := os.WriteFile(filepath.Join(root, ".github", "workflows", hostileName), []byte("a: [\n"), 0o600); err != nil {
		t.Skipf("the file system does not allow the file name: %v", err)
	}
	tests := []struct {
		name      string
		actions   bool
		wantLine  string // a prefix of the only line
		wantEsced string // the escaped name in the line
	}{
		{name: "github actions", actions: true, wantLine: "::error::.github/workflows/", wantEsced: `x\x0a::warning::y%250A\x0d\x1b\u202e.yml`},
		{name: "plain", actions: false, wantLine: msgPrefix + ".github/workflows/", wantEsced: `x\x0a::warning::y%0A\x0d\x1b\u202e.yml`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vars := map[string]string{}
			if tt.actions {
				vars["GITHUB_ACTIONS"] = "true"
			}
			var stdout, stderr bytes.Buffer
			if got := run([]string{"-root", root}, &stdout, &stderr, env(vars)); got != exitProblems {
				t.Fatalf("run() = %d, want %d; stdout %q, stderr %q", got, exitProblems, stdout.String(), stderr.String())
			}
			out := stderr.String() + stdout.String()
			assertNoRawControl(t, out)
			if strings.Count(out, "\n") != 1 {
				t.Fatalf("output has %d lines, want 1 (the parse problem): %q", strings.Count(out, "\n"), out)
			}
			if !strings.HasPrefix(out, tt.wantLine) || !strings.Contains(out, tt.wantEsced) {
				t.Errorf("output = %q, want a line that starts with %q and holds %q", out, tt.wantLine, tt.wantEsced)
			}
		})
	}
}

func TestRunReporterInjection(t *testing.T) {
	t.Parallel()
	const msg = "a\n::warning::x %0A b\rc\x1bd\u202ee\xfff\u0085\x7fg"
	tests := []struct {
		name       string
		actions    bool
		wantStdout string
		wantStderr string
	}{
		{
			name:       "github actions",
			actions:    true,
			wantStdout: `::error::a\x0a::warning::x %250A b\x0dc\x1bd\u202ee\xfff\u0085\x7fg` + "\n",
		},
		{
			name:       "plain",
			actions:    false,
			wantStderr: msgPrefix + `a\x0a::warning::x %0A b\x0dc\x1bd\u202ee\xfff\u0085\x7fg` + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			reporter{stdout: &stdout, stderr: &stderr, actions: tt.actions}.problem(msg)
			if stdout.String() != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}
			if stderr.String() != tt.wantStderr {
				t.Errorf("stderr = %q, want %q", stderr.String(), tt.wantStderr)
			}
			assertNoRawControl(t, stdout.String()+stderr.String())
		})
	}
}

func TestEscapeCommandData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "plain", in: "ci.yml: ok", want: "ci.yml: ok"},
		{name: "colons stay", in: "::warning::x", want: "::warning::x"},
		{name: "percent", in: "100%", want: "100%25"},
		{name: "encoded newline is not decoded later", in: "%0A", want: "%250A"},
		{name: "newline", in: "a\nb", want: "a%0Ab"},
		{name: "carriage return", in: "a\rb", want: "a%0Db"},
		{name: "one pass, no double escape", in: "%\n%\r", want: "%25%0A%25%0D"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := escapeCommandData(tt.in); got != tt.want {
				t.Errorf("escapeCommandData(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDedupe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "nil", in: nil, want: []string{}},
		{name: "no duplicates keeps order", in: []string{"b", "a", "c"}, want: []string{"b", "a", "c"}},
		{name: "first occurrence wins", in: []string{"a", "b", "a", "c", "b"}, want: []string{"a", "b", "c"}},
		{name: "all the same", in: []string{"x", "x", "x"}, want: []string{"x"}},
		{name: "empty strings", in: []string{"", "a", ""}, want: []string{"", "a"}},
		{name: "case matters", in: []string{"A", "a"}, want: []string{"A", "a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := dedupe(tt.in); !slices.Equal(got, tt.want) {
				t.Errorf("dedupe(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsWorkflowName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want bool
	}{
		{name: "ci.yml", want: true},
		{name: "a.yaml", want: true},
		{name: "CI.YML", want: true},
		{name: "Ci.Yaml", want: true},
		{name: ".yml", want: true},
		{name: ".yaml", want: true},
		{name: ".hidden.yml", want: true},
		{name: "a.yml.bak", want: false},
		{name: "yml", want: false},
		{name: "yaml", want: false},
		{name: "ayml", want: false},
		{name: "a.yml~", want: false},
		{name: "README.md", want: false},
		{name: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isWorkflowName(tt.name); got != tt.want {
				t.Errorf("isWorkflowName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestCheckGoodRepo(t *testing.T) {
	t.Parallel()
	if got := check(repoCopyFS(t)); len(got) != 0 {
		t.Fatalf("check(repoCopyFS) = %q, want no problem", got)
	}
}

// TestCheckRequiredFiles checks each required file. It reads the list from
// repoFiles, not from requiredFiles, so a file that drops out of
// requiredFiles fails the test. A missing file gives exactly one problem that
// names it: the rules that need it do not repeat it.
func TestCheckRequiredFiles(t *testing.T) {
	t.Parallel()
	for _, name := range repoFiles {
		t.Run("missing "+name, func(t *testing.T) {
			t.Parallel()
			fsys := repoCopyFS(t)
			delete(fsys, name)
			got := check(fsys)
			want := name + ": the file is missing"
			if !slices.Equal(got, []string{want}) {
				t.Errorf("check() = %q, want only %q", got, want)
			}
		})
		t.Run("directory "+name, func(t *testing.T) {
			t.Parallel()
			fsys := repoCopyFS(t)
			delete(fsys, name)
			fsys[name+"/inner"] = &fstest.MapFile{Data: []byte("x")}
			got := check(fsys)
			want := name + ": is not a regular file"
			if len(got) == 0 || got[0] != want {
				t.Errorf("check() = %q, want %q first", got, want)
			}
		})
	}
	t.Run("all missing", func(t *testing.T) {
		t.Parallel()
		got := check(fstest.MapFS{})
		if len(got) != len(repoFiles) {
			t.Errorf("check(empty) = %q, want %d problems", got, len(repoFiles))
		}
		for i, name := range repoFiles {
			want := name + ": the file is missing"
			if i >= len(got) || got[i] != want {
				t.Errorf("check(empty)[%d] = %q, want %q; all: %q", i, got, want, got)
			}
		}
	})
}

func TestCheckParseProblem(t *testing.T) {
	t.Parallel()
	fsys := repoCopyFS(t)
	fsys[wf("bad.yml")] = &fstest.MapFile{Data: []byte("a: [\n")}
	// other.yml parses and names govulncheck, so the govulncheck rules must
	// still run on it after the parse problem.
	fsys[wf("other.yml")] = &fstest.MapFile{Data: []byte("jobs: {}\nrun: govulncheck ./...\n")}
	got := check(fsys)
	if n := countPrefix(got, wf("bad.yml")); n != 1 {
		t.Errorf("check() has %d problems for bad.yml, want 1: %q", n, got)
	}
	if len(got) == 0 || !strings.HasPrefix(got[0], wf("bad.yml")) {
		t.Errorf("check() = %q, want the parse problem first", got)
	}
	if n := countPrefix(got, wf("other.yml")+":2: the workflow names govulncheck"); n != 1 {
		t.Errorf("check() has %d govulncheck problems for other.yml, want 1: %q", n, got)
	}
	if len(got) != 2 {
		t.Errorf("check() = %q, want exactly 2 problems", got)
	}
}

func TestCheckRequiredWorkflowDoesNotParse(t *testing.T) {
	t.Parallel()
	fsys := repoCopyFS(t)
	fsys[wf("release.yml")] = &fstest.MapFile{Data: []byte("a: [\n")}
	got := check(fsys)
	// The parse problem is the only one: the rules that need release.yml do
	// not repeat it.
	if len(got) != 1 || !strings.HasPrefix(got[0], wf("release.yml")+": parse YAML: ") {
		t.Fatalf("check() = %q, want only the parse problem of release.yml", got)
	}
}

// hideEntryFS is a MapFS whose directory listing leaves out the file hide.
// fs.Stat still finds the file. A file system that ignores case does the
// same: Stat finds ci.yml, but the listing holds CI.yml.
type hideEntryFS struct {
	fstest.MapFS
	hide string
}

// ReadDir returns the entries of the directory name without hide. fs.ReadDir
// calls this method, because hideEntryFS implements fs.ReadDirFS.
func (h hideEntryFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := h.MapFS.ReadDir(name)
	return slices.DeleteFunc(entries, func(e fs.DirEntry) bool {
		return path.Join(name, e.Name()) == h.hide
	}), err
}

func TestCheckNotLoaded(t *testing.T) {
	t.Parallel()
	for _, p := range []string{ciPath, releasePath, weeklyPath} {
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			got := check(hideEntryFS{MapFS: repoCopyFS(t), hide: p})
			want := []string{p + ": the pin checks need this workflow, but it is not in the listing of .github/workflows"}
			if !slices.Equal(got, want) {
				t.Errorf("check() = %q, want %q", got, want)
			}
		})
	}
}

// renamedEntry is a directory entry with another name. The data is the same.
type renamedEntry struct {
	fs.DirEntry
	name string
}

// Name returns the name of the entry that nameFoldFS shows.
func (e renamedEntry) Name() string { return e.name }

// nameFoldFS is a file system that ignores case for ci.yml, as macOS does. Stat
// and Open find ci.yml, but the listing of workflowDir shows the entry CI.yml.
type nameFoldFS struct {
	fstest.MapFS
}

// fold returns the name of the file that the case-folded name CI.yml stands for.
func (f nameFoldFS) fold(name string) string {
	if name == wf("CI.yml") {
		return ciPath
	}
	return name
}

// Open opens the file that name stands for.
func (f nameFoldFS) Open(name string) (fs.File, error) { return f.MapFS.Open(f.fold(name)) }

// ReadFile reads the file that name stands for.
func (f nameFoldFS) ReadFile(name string) ([]byte, error) {
	return f.MapFS.ReadFile(f.fold(name))
}

// Stat returns the info of the file that name stands for.
func (f nameFoldFS) Stat(name string) (fs.FileInfo, error) {
	return f.MapFS.Stat(f.fold(name))
}

// ReadDir returns the entries of name, with ci.yml shown as CI.yml.
func (f nameFoldFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := f.MapFS.ReadDir(name)
	for i, e := range entries {
		if path.Join(name, e.Name()) == ciPath {
			entries[i] = renamedEntry{DirEntry: e, name: "CI.yml"}
		}
	}
	return entries, err
}

// notInListing is the notLoaded problem for the required workflow p.
func notInListing(p string) string {
	return p + ": the pin checks need this workflow, but it is not in the listing of " + workflowDir
}

// TestNotLoaded checks notLoaded alone. A required workflow gets a problem only
// when it is not in wfs and no loader put its path in reported. The text of a
// message in an earlier problem does not matter.
func TestNotLoaded(t *testing.T) {
	t.Parallel()
	loaded := mustParse(t, ciPath, "on: push\n")
	tests := []struct {
		name     string
		loaded   []string // the paths that wfs holds
		reported []string // the paths that a loader or checkRequired reported
		want     []string // the problems, in the order of requiredFiles
	}{
		{
			name: "nothing loaded or reported",
			want: []string{notInListing(ciPath), notInListing(releasePath), notInListing(weeklyPath)},
		},
		{
			name:   "a loaded workflow gives no problem",
			loaded: []string{ciPath},
			want:   []string{notInListing(releasePath), notInListing(weeklyPath)},
		},
		{
			name:     "a path reported by a loader gives no problem",
			reported: []string{releasePath},
			want:     []string{notInListing(ciPath), notInListing(weeklyPath)},
		},
		{
			name:     "a path reported by checkRequired gives no problem",
			loaded:   []string{ciPath, releasePath},
			reported: []string{weeklyPath},
		},
		{
			name:     "a reported path that is not a workflow is ignored",
			loaded:   []string{ciPath, releasePath, weeklyPath},
			reported: []string{docPath},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			wfs := make(map[string]*workflow)
			for _, p := range tt.loaded {
				wfs[p] = loaded
			}
			reported := make(map[string]bool)
			for _, p := range tt.reported {
				reported[p] = true
			}
			got := notLoaded(wfs, reported)
			if !slices.Equal(got, tt.want) {
				t.Errorf("notLoaded() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCheckNotLoadedCaseFold checks a file system that ignores case. The file
// ci.yml is found but listed as CI.yml. It is loaded under that name, so
// notLoaded gives one problem for ci.yml, and no other problem says so.
func TestCheckNotLoadedCaseFold(t *testing.T) {
	t.Parallel()
	got := check(nameFoldFS{MapFS: repoCopyFS(t)})
	var notListed []string
	for _, p := range got {
		if strings.Contains(p, "not in the listing of") {
			notListed = append(notListed, p)
		}
	}
	if want := []string{notInListing(ciPath)}; !slices.Equal(notListed, want) {
		t.Errorf("check() problems %q, want exactly %q", notListed, want)
	}
}

// TestCheckNotLoadedAfterRequired checks a path that checkRequired reports and
// that the listing does not show. The problem is the one of checkRequired, and
// notLoaded adds no second problem for the same file.
func TestCheckNotLoadedAfterRequired(t *testing.T) {
	t.Parallel()
	fsys := repoCopyFS(t)
	delete(fsys, ciPath)
	fsys[ciPath+"/inner"] = &fstest.MapFile{Data: []byte("x")}
	got := check(hideEntryFS{MapFS: fsys, hide: ciPath})
	want := []string{ciPath + ": is not a regular file"}
	if !slices.Equal(got, want) {
		t.Errorf("check() = %q, want only %q", got, want)
	}
}

// TestCheckLoaderReportedNotRepeated checks a workflow that does not parse.
// loadWorkflows reports it, so notLoaded must not report it again.
func TestCheckLoaderReportedNotRepeated(t *testing.T) {
	t.Parallel()
	for _, p := range []string{ciPath, releasePath, weeklyPath} {
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			fsys := repoCopyFS(t)
			fsys[p] = &fstest.MapFile{Data: []byte("a: [\n")}
			got := check(fsys)
			if len(got) != 1 || !strings.HasPrefix(got[0], p+": parse YAML: ") {
				t.Errorf("check() = %q, want only the parse problem of %s", got, p)
			}
		})
	}
}

func TestCheckWorkflowNames(t *testing.T) {
	t.Parallel()
	// Each file names govulncheck, so a file that check reads gives one
	// problem with its path, and a file that check skips gives none.
	content := []byte("jobs: {}\nrun: govulncheck ./...\n")
	tests := []struct {
		file     string
		wantRead bool
	}{
		{file: "Other.YML", wantRead: true},
		{file: "other.yaml", wantRead: true},
		{file: "OTHER.YAML", wantRead: true},
		{file: ".hidden.yml", wantRead: true},
		{file: ".yml", wantRead: true},
		{file: "notes.txt", wantRead: false},
		{file: "other.yml.bak", wantRead: false},
		{file: "yml", wantRead: false},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			t.Parallel()
			fsys := repoCopyFS(t)
			fsys[wf(tt.file)] = &fstest.MapFile{Data: content}
			got := check(fsys)
			want := []string{}
			if tt.wantRead {
				want = []string{wf(tt.file) + ":2: the workflow names govulncheck. Only ci.yml, release.yml and govulncheck.yml may. To add a workflow, add it to gvListedPaths in internal/pincheck/govulncheck.go"}
			}
			if !slices.Equal(got, want) {
				t.Errorf("check() = %q, want %q", got, want)
			}
		})
	}
	t.Run("non-workflow file with bad YAML is ignored", func(t *testing.T) {
		t.Parallel()
		fsys := repoCopyFS(t)
		fsys[wf("README.md")] = &fstest.MapFile{Data: []byte("a: [\n")}
		if got := check(fsys); len(got) != 0 {
			t.Errorf("check() = %q, want no problem", got)
		}
	})
}

func TestCheckNotRegularWorkflow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		file *fstest.MapFile
		key  string // the MapFS key to add
		want string
	}{
		{
			name: "directory named x.yml",
			key:  wf("x.yml/inner.txt"),
			file: &fstest.MapFile{Data: []byte("x")},
			want: wf("x.yml") + ": is not a regular file",
		},
		{
			name: "symlink in MapFS",
			key:  wf("link.yml"),
			file: &fstest.MapFile{Data: []byte("ci.yml"), Mode: fs.ModeSymlink | 0o777},
			want: wf("link.yml") + ": is a symlink. This check does not follow symlinks in " + workflowDir,
		},
		{
			name: "named pipe",
			key:  wf("pipe.yml"),
			file: &fstest.MapFile{Mode: fs.ModeNamedPipe | 0o644},
			want: wf("pipe.yml") + ": is not a regular file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fsys := repoCopyFS(t)
			fsys[tt.key] = tt.file
			got := check(fsys)
			if !slices.Equal(got, []string{tt.want}) {
				t.Errorf("check() = %q, want %q", got, []string{tt.want})
			}
		})
	}
}

func TestCheckDedupesSameProblem(t *testing.T) {
	t.Parallel()
	// Both the GoReleaser and the govulncheck rules read release.yml, and
	// both report a jobs value that is not a mapping with the same text.
	fsys := repoCopyFS(t)
	fsys[wf("release.yml")] = &fstest.MapFile{Data: []byte("name: r\non: push\njobs: 5\n")}
	got := check(fsys)
	if len(got) == 0 {
		t.Fatal("check() = no problem, want the jobs problem")
	}
	seen := make(map[string]bool)
	for _, p := range got {
		if seen[p] {
			t.Errorf("check() has %q more than once: %q", p, got)
		}
		seen[p] = true
	}
	if countPrefix(got, wf("release.yml")+":3:") == 0 {
		t.Errorf("check() = %q, want a problem at release.yml:3", got)
	}
}

// TestCheckSameProblemOneLine checks that a problem that two rules find gives
// one line. The rules build the text with one shared helper (wrongKind, or
// jobsAndProblems for a job), and dedupe keeps one copy. A rule that wrote
// its own text would give a second line here.
func TestCheckSameProblemOneLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		old   string // the text in the real release.yml
		repl  string
		about string // a text that every line about the problem holds
		want  string // the one line, after the file name and the line
	}{
		{
			// The GoReleaser rule and the govulncheck rule both read every
			// job of release.yml with jobsAndProblems.
			name:  "job that is not a mapping",
			old:   "jobs:\n",
			repl:  "jobs:\n  broken: text\n",
			about: `the job "broken"`,
			want:  `the job "broken" must be a mapping, found a scalar`,
		},
		{
			// The GoReleaser rule (grJobPins) and the env rule (envProblems)
			// read the env of a job.
			name:  "job env that is not a mapping",
			old:   "jobs:\n",
			repl:  "jobs:\n  broken:\n    env: ${{ fromJSON(vars.X) }}\n",
			about: `the value of "env"`,
			want:  `the value of "env" must be a mapping, found a scalar`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fsys := repoCopyFS(t)
			rel := fsys[releasePath]
			src := string(rel.Data)
			if n := strings.Count(src, tt.old); n != 1 {
				t.Fatalf("release.yml has %d copies of %q, want 1", n, tt.old)
			}
			rel.Data = []byte(strings.Replace(src, tt.old, tt.repl, 1))
			var lines []string // the problems of release.yml about this problem
			for _, p := range check(fsys) {
				if strings.HasPrefix(p, releasePath+":") && strings.Contains(p, tt.about) {
					lines = append(lines, p)
				}
			}
			if len(lines) != 1 || !strings.HasSuffix(lines[0], ": "+tt.want) {
				t.Errorf("check() lines with %q = %q, want one line that ends in %q", tt.about, lines, tt.want)
			}
		})
	}
}

// lineOf returns the 1-based line of the first copy of sub in src. It fails
// the test when src does not hold sub.
func lineOf(t *testing.T, src, sub string) int {
	t.Helper()
	i := strings.Index(src, sub)
	if i < 0 {
		t.Fatalf("the text has no %q", sub)
	}
	return strings.Count(src[:i], "\n") + 1
}

func TestCheckBadJobKeepsGoodJobs(t *testing.T) {
	t.Parallel()
	// A job that is not a mapping must not hide the other jobs of the file
	// from the GoReleaser rules. If the walk stopped at the first bad job, the
	// rules would read no job, and the scalar scan would fail the pin, the uses
	// value and the version input of the good release job.
	const (
		oldJobs  = "jobs:\n"
		badJobs  = "jobs:\n  bad: 1\n"
		input    = "version: ${{ env.GORELEASER_VERSION }}"
		badInput = "version: latest"
		badJob   = `the job "bad" must be a mapping, found a scalar`
	)
	tests := []struct {
		name     string
		badInput bool // put badInput in place of input
	}{
		{name: "good job is still clean"},
		{name: "good job after the bad job is still checked", badInput: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fsys := repoCopyFS(t)
			rel := fsys[releasePath]
			src := string(rel.Data)
			for _, old := range []string{oldJobs, input} {
				if n := strings.Count(src, old); n != 1 {
					t.Fatalf("release.yml has %d copies of %q, want 1", n, old)
				}
			}
			src = strings.Replace(src, oldJobs, badJobs, 1)
			want := []string{fmt.Sprintf("%s:%d: %s", releasePath, lineOf(t, src, "  bad: 1"), badJob)}
			if tt.badInput {
				src = strings.Replace(src, input, badInput, 1)
				want = append(want, fmt.Sprintf(`%s:%d: the goreleaser-action step "Run GoReleaser" has a version input that is not %s`,
					releasePath, lineOf(t, src, badInput), grVersionInput))
			}
			rel.Data = []byte(src)
			if got := check(fsys); !slices.Equal(got, want) {
				t.Errorf("check() = %q, want %q", got, want)
			}
		})
	}
}

// assertNoHostPath fails when a problem holds the root dir, its real path or
// the macOS /private prefix of a temporary directory. A message must name
// only paths relative to the root.
func assertNoHostPath(t *testing.T, problems []string, root string) {
	t.Helper()
	hostPaths := []string{root, "/" + "private"}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		hostPaths = append(hostPaths, resolved)
	}
	for _, p := range problems {
		for _, h := range hostPaths {
			if strings.Contains(p, h) {
				t.Errorf("problem %q holds the host path %q", p, h)
			}
		}
	}
}

func TestCheckRootDocDirectory(t *testing.T) {
	t.Parallel()
	// A CONTRIBUTING.md that is a directory gives one line, from
	// checkRequired. The GoReleaser rule gives no second line with the read
	// error of the os.Root file, which holds the absolute host path.
	root := repoCopyDir(t)
	doc := filepath.Join(root, docPath)
	if err := os.Remove(doc); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(doc, 0o750); err != nil {
		t.Fatal(err)
	}
	got, err := checkRoot(root)
	if err != nil {
		t.Fatalf("checkRoot() error = %v", err)
	}
	if want := []string{notRegular(docPath)}; !slices.Equal(got, want) {
		t.Errorf("checkRoot() = %q, want %q", got, want)
	}
	assertNoHostPath(t, got, root)
}

// unreadable makes the file p unreadable and restores it at the end of the
// test. It skips the test when the file stays readable, as for root or on a
// file system without Unix modes.
func unreadable(t *testing.T, p string) {
	t.Helper()
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	if f, err := os.Open(filepath.Clean(p)); err == nil {
		_ = f.Close()
		t.Skip("the file is still readable after chmod 000 (root, or no Unix modes)")
	}
}

func TestCheckRootDocUnreadable(t *testing.T) {
	t.Parallel()
	root := repoCopyDir(t)
	unreadable(t, filepath.Join(root, docPath))
	got, err := checkRoot(root)
	if err != nil {
		t.Fatalf("checkRoot() error = %v", err)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], docPath+": ") {
		t.Errorf("checkRoot() = %q, want one problem for %s", got, docPath)
	}
	assertNoHostPath(t, got, root)
}

func TestReadLimitedNoHostPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "locked.yml")
	if err := os.WriteFile(locked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	t.Run("directory", func(t *testing.T) {
		_, err := readLimited(root.FS(), "sub", maxFileBytes)
		if err == nil {
			t.Fatal("readLimited() error = nil, want an error for a directory")
		}
		assertNoHostPath(t, []string{err.Error()}, dir)
	})
	t.Run("missing", func(t *testing.T) {
		_, err := readLimited(root.FS(), "nope.yml", maxFileBytes)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("readLimited() error = %v, want it to wrap fs.ErrNotExist", err)
		}
		assertNoHostPath(t, []string{err.Error()}, dir)
	})
	t.Run("unreadable", func(t *testing.T) {
		unreadable(t, locked)
		_, err := readLimited(root.FS(), "locked.yml", maxFileBytes)
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("readLimited() error = %v, want it to wrap fs.ErrPermission", err)
		}
		assertNoHostPath(t, []string{err.Error()}, dir)
	})
}

func TestNoPath(t *testing.T) {
	t.Parallel()
	inner := errors.New("inner")
	pe := &fs.PathError{Op: "read", Path: "/abs/host/path", Err: inner}
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "path error", err: pe, want: inner},
		{name: "wrapped path error", err: fmt.Errorf("walk: %w", pe), want: inner},
		{name: "other error", err: inner, want: inner},
		{name: "nil", err: nil, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := noPath(tt.err); fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("noPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckStepEnvNotMapping(t *testing.T) {
	t.Parallel()
	// A step env that is an expression can set GORELEASER_VERSION=latest over
	// the job env, and no rule can read the name. The copy of ci.yml differs
	// from the real file only in the value of the first step env with TMPDIR.
	const (
		old  = "        env:\n          TMPDIR: ${{ runner.temp }}\n"
		expr = "        env: ${{ fromJSON(format('{{\"{0}_VERSION\":\"latest\"}}', 'GORELEASER')) }}\n"
	)
	fsys := repoCopyFS(t)
	ci := fsys[wf("ci.yml")]
	src := string(ci.Data)
	at := strings.Index(src, old)
	if at < 0 {
		t.Fatalf("ci.yml has no step env %q", old)
	}
	ci.Data = []byte(src[:at] + expr + src[at+len(old):])
	line := strings.Count(src[:at], "\n") + 1
	want := fmt.Sprintf("%s:%d: the value of \"env\" must be a mapping, found a scalar", wf("ci.yml"), line)

	got := check(fsys)
	if !slices.Contains(got, want) {
		t.Errorf("check() = %q, want it to contain %q", got, want)
	}

	dir := t.TempDir()
	writeTree(t, dir, fsys)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-root", dir}, &stdout, &stderr, env(nil)); code != exitProblems {
		t.Errorf("run() = %d, want %d; stderr:\n%s", code, exitProblems, stderr.String())
	}
	if !strings.Contains(stderr.String(), msgPrefix+want+"\n") {
		t.Errorf("run() stderr = %q, want the line %q", stderr.String(), msgPrefix+want)
	}
}

func TestCheckStableOrder(t *testing.T) {
	t.Parallel()
	fsys := repoCopyFS(t)
	delete(fsys, "CONTRIBUTING.md")
	fsys[wf("bad.yml")] = &fstest.MapFile{Data: []byte("a: [\n")}
	for _, name := range []string{"z.yml", "a.yml", "m.yaml", "b.YML"} {
		fsys[wf(name)] = &fstest.MapFile{Data: []byte("run: govulncheck\n")}
	}
	first := check(fsys)
	if len(first) < 3 {
		t.Fatalf("check() = %q, want at least 3 problems", first)
	}
	if first[0] != "CONTRIBUTING.md: the file is missing" {
		t.Errorf("check()[0] = %q, want the required-file problem", first[0])
	}
	if !strings.HasPrefix(first[1], wf("bad.yml")) {
		t.Errorf("check()[1] = %q, want the parse problem of bad.yml", first[1])
	}
	for range 5 {
		if again := check(fsys); !slices.Equal(again, first) {
			t.Fatalf("check() changed between runs:\n%q\n%q", first, again)
		}
	}
}

func TestCheckRootCopy(t *testing.T) {
	t.Parallel()
	got, err := checkRoot(repoCopyDir(t))
	if err != nil {
		t.Fatalf("checkRoot() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("checkRoot() = %q, want no problem", got)
	}
}

func TestCheckRootMissingDir(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "nope")
	got, err := checkRoot(dir)
	if err == nil {
		t.Fatalf("checkRoot() = %q, nil; want an error", got)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("checkRoot() error = %v, want it to wrap fs.ErrNotExist", err)
	}
	if want := "open the repository root: no such file or directory"; err.Error() != want {
		t.Errorf("checkRoot() error = %q, want %q", err, want)
	}
}

// TestCheckRootErrorHidesDir checks that the error of a root that cannot be
// opened holds no part of the directory. The message goes to stderr and to
// CI logs, so a host path such as /home/user/repo must not show. Each part
// of at least three bytes is checked, so the test name in t.TempDir shows too.
func TestCheckRootErrorHidesDir(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		dir  string
	}{
		{name: "missing directory", dir: filepath.Join(t.TempDir(), "missing-repo")},
		{name: "missing nested directory", dir: filepath.Join(t.TempDir(), "a", "b", "missing-repo")},
		{name: "regular file", dir: file},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := checkRoot(tt.dir)
			if err == nil {
				t.Fatalf("checkRoot(%q) error = nil, want an error", tt.dir)
			}
			msg := err.Error()
			if !strings.HasPrefix(msg, "open the repository root: ") {
				t.Errorf("checkRoot() error = %q, want the open prefix", msg)
			}
			if strings.Contains(msg, tt.dir) {
				t.Errorf("checkRoot() error = %q holds the directory %q", msg, tt.dir)
			}
			for _, part := range strings.Split(filepath.ToSlash(tt.dir), "/") {
				if len(part) >= 3 && strings.Contains(msg, part) {
					t.Errorf("checkRoot() error = %q holds the path part %q of %q", msg, part, tt.dir)
				}
			}
		})
	}
}

func TestCheckRootSymlinkWorkflow(t *testing.T) {
	t.Parallel()
	const marker = "PINCHECK-OUTSIDE-MARKER-7f3a"
	outside := filepath.Join(t.TempDir(), "target.yml")
	// If check read the target, the govulncheck rules would report the file.
	if err := os.WriteFile(outside, []byte("name: "+marker+"\nrun: govulncheck "+marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		target func(root string) string
	}{
		{name: "target outside the root", target: func(string) string { return outside }},
		{name: "relative target outside the root", target: func(root string) string {
			rel, err := filepath.Rel(filepath.Join(root, ".github", "workflows"), outside)
			if err != nil {
				t.Fatal(err)
			}
			return rel
		}},
		{name: "target inside the root", target: func(string) string { return "ci.yml" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := repoCopyDir(t)
			link := filepath.Join(root, ".github", "workflows", "evil.yml")
			if err := os.Symlink(tt.target(root), link); err != nil {
				t.Skipf("symlinks are not supported: %v", err)
			}
			got, err := checkRoot(root)
			if err != nil {
				t.Fatalf("checkRoot() error = %v", err)
			}
			want := []string{wf("evil.yml") + ": is a symlink. This check does not follow symlinks in " + workflowDir}
			if !slices.Equal(got, want) {
				t.Errorf("checkRoot() = %q, want %q", got, want)
			}
			for _, p := range got {
				if strings.Contains(p, marker) {
					t.Errorf("checkRoot() read the symlink target: %q", p)
				}
			}
		})
	}
}

func TestLoadWorkflowsMissingDir(t *testing.T) {
	t.Parallel()
	reported := make(map[string]bool)
	wfs, problems := loadWorkflows(fstest.MapFS{"CONTRIBUTING.md": {Data: []byte("x")}}, reported)
	if len(wfs) != 0 || len(problems) != 0 || len(reported) != 0 {
		t.Errorf("loadWorkflows(no dir) = %v, %q, reported %v; want no workflow, no problem and no reported path", wfs, problems, reported)
	}
}

func TestLoadWorkflowsKeys(t *testing.T) {
	t.Parallel()
	reported := make(map[string]bool)
	wfs, problems := loadWorkflows(repoCopyFS(t), reported)
	if len(problems) != 0 {
		t.Fatalf("loadWorkflows() problems = %q, want none", problems)
	}
	if len(reported) != 0 {
		t.Errorf("loadWorkflows() reported %v, want no path", reported)
	}
	for _, name := range []string{"ci.yml", "release.yml", "govulncheck.yml"} {
		if wfs[wf(name)] == nil {
			t.Errorf("loadWorkflows() has no %s; keys: %v", wf(name), wfs)
		}
	}
	if len(wfs) != 3 {
		t.Errorf("loadWorkflows() has %d workflows, want 3", len(wfs))
	}
}

func TestLoadWorkflowsTooLarge(t *testing.T) {
	t.Parallel()
	fsys := repoCopyFS(t)
	fsys[wf("big.yml")] = &fstest.MapFile{Data: bytes.Repeat([]byte("#"), maxFileBytes+1)}
	reported := make(map[string]bool)
	wfs, problems := loadWorkflows(fsys, reported)
	if wfs[wf("big.yml")] != nil {
		t.Error("loadWorkflows() loaded a file over the size limit")
	}
	if countPrefix(problems, wf("big.yml")) != 1 {
		t.Errorf("loadWorkflows() problems = %q, want one for big.yml", problems)
	}
	if !reported[wf("big.yml")] {
		t.Errorf("loadWorkflows() reported = %v, want big.yml", reported)
	}
}

func TestCheckRootSandboxRequiredSymlink(t *testing.T) {
	t.Parallel()
	// checkRequired and the GoReleaser rule follow a symlinked CONTRIBUTING.md.
	// Only the os.Root keeps them inside the root: without it, the rule reads
	// the target and shows its version text in a message.
	const marker = "PINCHECK-OUTSIDE-MARKER-c91e"
	outside := filepath.Join(t.TempDir(), "CONTRIBUTING.md")
	if err := os.WriteFile(outside, []byte("go install github.com/goreleaser/goreleaser/v2@"+marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := repoCopyDir(t)
	link := filepath.Join(root, "CONTRIBUTING.md")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks are not supported: %v", err)
	}
	got, err := checkRoot(root)
	if err != nil {
		t.Fatalf("checkRoot() error = %v", err)
	}
	if countPrefix(got, "CONTRIBUTING.md: ") == 0 {
		t.Errorf("checkRoot() = %q, want a problem for CONTRIBUTING.md", got)
	}
	for _, p := range got {
		if strings.Contains(p, marker) {
			t.Errorf("checkRoot() read the symlink target outside the root: %q", p)
		}
	}
}

// manyProblemsFS returns a repository with only a ci.yml that has n steps.
// Each step names GORELEASER_VERSION in a form that the check does not allow,
// so check gives one problem for each step, and more for the missing files.
func manyProblemsFS(n int) fstest.MapFS {
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n")
	for i := range n {
		// A strings.Builder write never fails.
		_, _ = fmt.Fprintf(&b, "      - run: echo GORELEASER_VERSION %d\n", i)
	}
	return fstest.MapFS{wf("ci.yml"): {Data: []byte(b.String())}}
}

// reportLines runs report on problems in one output mode and returns the
// exit code and the output lines without the line prefix of the mode.
func reportLines(t *testing.T, problems []string, actions bool) (int, []string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := report(reporter{stdout: &stdout, stderr: &stderr, actions: actions}, problems)
	out, prefix, other := stderr.String(), msgPrefix, stdout.String()
	if actions {
		out, prefix, other = stdout.String(), "::error::", stderr.String()
	}
	if other != "" {
		t.Errorf("report() wrote %q to the other stream, want nothing", other)
	}
	assertNoRawControl(t, out)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if out == "" {
		lines = nil
	}
	for i, l := range lines {
		rest, ok := strings.CutPrefix(l, prefix)
		if !ok {
			t.Errorf("line %d = %q, want the prefix %q", i, l, prefix)
		}
		lines[i] = rest
	}
	return code, lines
}

func TestReportCapsProblems(t *testing.T) {
	t.Parallel()
	msgs := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("p%d", i)
		}
		return out
	}
	tests := []struct {
		name     string
		n        int
		wantCode int
		wantLast string // the last line; "" for no line
		wantN    int    // the number of lines
	}{
		{name: "no problem", n: 0, wantCode: exitOK, wantN: 0},
		{name: "one problem", n: 1, wantCode: exitProblems, wantLast: "p0", wantN: 1},
		{name: "exactly the cap", n: maxProblems, wantCode: exitProblems, wantLast: fmt.Sprintf("p%d", maxProblems-1), wantN: maxProblems},
		{name: "one over the cap", n: maxProblems + 1, wantCode: exitProblems, wantLast: "and 1 more problem", wantN: maxProblems + 1},
		{name: "many over the cap", n: 40004, wantCode: exitProblems, wantLast: fmt.Sprintf("and %d more problems", 40004-maxProblems), wantN: maxProblems + 1},
	}
	for _, tt := range tests {
		for _, actions := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s actions=%v", tt.name, actions), func(t *testing.T) {
				t.Parallel()
				code, lines := reportLines(t, msgs(tt.n), actions)
				if code != tt.wantCode {
					t.Errorf("report() = %d, want %d", code, tt.wantCode)
				}
				if len(lines) != tt.wantN {
					t.Fatalf("report() wrote %d lines, want %d", len(lines), tt.wantN)
				}
				if tt.wantN > 0 && lines[len(lines)-1] != tt.wantLast {
					t.Errorf("last line = %q, want %q", lines[len(lines)-1], tt.wantLast)
				}
				// The lines before the summary are the first problems, in order.
				for i := 0; i < min(len(lines), maxProblems, tt.n); i++ {
					if want := fmt.Sprintf("p%d", i); lines[i] != want {
						t.Errorf("line %d = %q, want %q", i, lines[i], want)
					}
				}
			})
		}
	}
}

func TestCheckManyProblemsAreCapped(t *testing.T) {
	t.Parallel()
	problems := check(manyProblemsFS(200))
	if len(problems) <= maxProblems+100 {
		t.Fatalf("check() gives %d problems, want more than %d", len(problems), maxProblems+100)
	}
	for _, actions := range []bool{false, true} {
		t.Run(fmt.Sprintf("actions=%v", actions), func(t *testing.T) {
			t.Parallel()
			code, lines := reportLines(t, problems, actions)
			if code != exitProblems {
				t.Errorf("report() = %d, want %d", code, exitProblems)
			}
			if len(lines) != maxProblems+1 {
				t.Fatalf("report() wrote %d lines, want %d", len(lines), maxProblems+1)
			}
			for i := range maxProblems {
				if want := termsafe.Escape(problems[i]); lines[i] != want {
					t.Errorf("line %d = %q, want %q", i, lines[i], want)
				}
			}
			want := fmt.Sprintf("and %d more problems", len(problems)-maxProblems)
			if got := lines[maxProblems]; got != want {
				t.Errorf("last line = %q, want %q", got, want)
			}
		})
	}
}

// TestCheckLongTextIsCut checks that a 100 KB text in a workflow gives a
// short message: each message cuts the text to maxShown bytes. YAML limits
// an implicit key to 1024 characters, so the long keys are explicit (? key).
func TestCheckLongTextIsCut(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 100<<10)
	// other.yml gets src. It is not a listed workflow.
	other := wf("other.yml")
	tests := []struct {
		name string
		src  string
		want string // a text that one problem holds, to show that the case hits
	}{
		{name: "duplicate key", src: "on: push\njobs: {}\n? k" + long + "\n: 1\n? K" + long + "\n: 2\n", want: "is a duplicate"},
		{name: "non-ASCII key", src: "on: push\njobs: {}\n? \u00e9" + long + "\n: 1\n", want: "has a non-ASCII character"},
		{name: "job ID of a job that is not a mapping", src: "on: push\njobs:\n  ? j" + long + "\n  : x\n", want: "must be a mapping, found a scalar"},
		{name: "job ID of a step that is not a mapping", src: "on: push\njobs:\n  ? j" + long + "\n  : {steps: [x]}\n", want: "a step of the job"},
		{name: "scalar value", src: "on: push\njobs: {}\nrun: echo GORELEASER_VERSION " + long + "\n", want: "mentions GORELEASER_VERSION"},
		{name: "anchor name", src: "on: push\njobs: {}\na: &" + long + " 1\n", want: "an anchor (&"},
		{name: "tag", src: "on: push\njobs: {}\na: !" + long + " 1\n", want: "an explicit tag (!"},
		{name: "unknown alias in a decoder error", src: "on: push\njobs: {}\na: *" + long + "\n", want: "parse YAML: yaml: unknown anchor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fsys := repoCopyFS(t)
			fsys[other] = &fstest.MapFile{Data: []byte(tt.src)}
			problems := check(fsys)
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tt.want) }) {
				t.Fatalf("check() = %.400q, want a problem with %q", problems, tt.want)
			}
			for _, actions := range []bool{false, true} {
				_, lines := reportLines(t, problems, actions)
				for _, l := range lines {
					if len(l) >= 400 {
						t.Errorf("line has %d bytes, want under 400: %.120q...", len(l), l)
					}
				}
			}
		})
	}
}
