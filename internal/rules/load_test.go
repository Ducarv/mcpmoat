package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// validRuleYAML returns a small valid rule file with the given ID.
func validRuleYAML(id string) string {
	return "id: " + id + `
title: Test rule
severity: low
target: description
match:
  keywords:
    - marker
risk: A test risk.
remediation: A test remediation.
references:
  - https://example.com/test
should_match:
  - a marker here
should_not_match:
  - nothing to see
`
}

// badRuleYAML returns a rule file that fails validation (bad severity on
// line 3).
func badRuleYAML(id string) string {
	return strings.Replace(validRuleYAML(id), "severity: low", "severity: urgent", 1)
}

// writeFile writes content to name in dir.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %q: %v", p, err)
	}
	return p
}

// wantOneError fails unless errs holds exactly one error with the given file
// and reason.
func wantOneError(t *testing.T, errs []*LoadError, file string, reason Reason) {
	t.Helper()
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(errs), errs)
	}
	if errs[0].File != file || errs[0].Reason != reason {
		t.Fatalf("error = {File: %q, Reason: %q}, want {File: %q, Reason: %q}", errs[0].File, errs[0].Reason, file, reason)
	}
}

// assertSafeText fails if errs is empty or if any error message holds a rune
// that noRawControls refuses.
func assertSafeText(t *testing.T, errs []*LoadError) {
	t.Helper()
	if len(errs) == 0 {
		t.Fatal("got no errors, want at least one")
	}
	for _, e := range errs {
		noRawControls(t, e.Error())
	}
}

// hangTimeout is how long a call that could block may take before a test
// decides that it hangs. A call that works takes milliseconds.
const hangTimeout = 10 * time.Second

// within runs f in a goroutine and returns its result. It fails the test if f
// does not return within hangTimeout. A hung goroutine stays behind, but the
// test already fails.
func within[T any](t *testing.T, what string, f func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- f() }()
	select {
	case v := <-done:
		return v
	case <-time.After(hangTimeout):
		t.Fatalf("%s did not return within %v", what, hangTimeout)
		var zero T // not reached: t.Fatalf stops the test
		return zero
	}
}

// loadDirWithin calls LoadDir and fails the test if it does not return in time.
func loadDirWithin(t *testing.T, dir string) ([]Rule, []*LoadError) {
	t.Helper()
	type result struct {
		rules []Rule
		errs  []*LoadError
	}
	r := within(t, "LoadDir", func() result {
		rules, errs := LoadDir(dir)
		return result{rules, errs}
	})
	return r.rules, r.errs
}

// Builtin and LoadDir share loadEntries, so the folder cap (maxFolderErrors)
// is tested through LoadDir (TestLoadDirFolderCap and
// TestLoadDirFolderCapBoundary). The embedded file system cannot get extra
// files, so Builtin has no cap test of its own.
func TestBuiltin(t *testing.T) {
	t.Parallel()

	rules, errs := Builtin()
	if len(errs) > 0 {
		t.Fatalf("Builtin() errors = %v, want none", errs)
	}
	if len(rules) == 0 {
		t.Fatal("Builtin() returned no rules")
	}

	var found bool
	for _, r := range rules {
		if r.Source != r.ID+".yaml" {
			t.Errorf("rule %q: Source = %q, want %q", r.ID, r.Source, r.ID+".yaml")
		}
		if r.ID == "MOAT-T1-003" {
			found = true
			if r.Source != "MOAT-T1-003.yaml" {
				t.Errorf("MOAT-T1-003 Source = %q, want the bare file name", r.Source)
			}
		}
	}
	if !found {
		t.Errorf("Builtin() IDs = %v, want MOAT-T1-003", ruleIDs(rules))
	}

	set, serrs := NewSet(rules, nil)
	if len(serrs) > 0 || set == nil {
		t.Fatalf("NewSet(builtin, nil) = %v, %v, want a set", set, serrs)
	}
	if set.Len() != len(rules) {
		t.Errorf("set.Len() = %d, want %d", set.Len(), len(rules))
	}
}

func TestBuiltinWithCompiler(t *testing.T) {
	t.Parallel()

	t.Run("compiler failure names the bare file", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("boom")
		rules, errs := Builtin(WithCompiler(func(Match, Target) (Matcher, error) { return nil, boom }))
		if rules != nil {
			t.Errorf("rules = %v, want nil", rules)
		}
		if len(errs) == 0 {
			t.Fatal("errs = none, want one per built-in rule")
		}
		for _, e := range errs {
			if e.Reason != ReasonInvalidValue || e.Field != "match" || !errors.Is(e, boom) {
				t.Errorf("error = %+v, want invalid value in field match wrapping boom", e)
			}
			if filepath.Base(e.File) != e.File || !strings.HasSuffix(e.File, ".yaml") {
				t.Errorf("File = %q, want a bare .yaml file name", e.File)
			}
		}
	})

	t.Run("nil option is ignored", func(t *testing.T) {
		t.Parallel()
		if _, errs := Builtin(nil); len(errs) > 0 {
			t.Errorf("Builtin(nil) errors = %v", errs)
		}
	})
}

func TestLoadDirFixtures(t *testing.T) {
	t.Parallel()

	builtin, errs := Builtin()
	if len(errs) > 0 {
		t.Fatalf("Builtin() errors = %v", errs)
	}

	t.Run("extra adds rules", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join("..", "..", "testdata", "rules", "extra")
		rules, errs := LoadDir(dir)
		if len(errs) > 0 {
			t.Fatalf("LoadDir() errors = %v", errs)
		}
		if got := ruleIDs(rules); !slices.Equal(got, []string{"MOAT-X-001"}) {
			t.Fatalf("IDs = %v, want [MOAT-X-001]", got)
		}
		if want := filepath.Join(dir, "MOAT-X-001.yaml"); rules[0].Source != want {
			t.Errorf("Source = %q, want %q", rules[0].Source, want)
		}
		set, serrs := NewSet(builtin, rules)
		if len(serrs) > 0 {
			t.Fatalf("NewSet() errors = %v", serrs)
		}
		for _, id := range []string{"MOAT-T1-003", "MOAT-X-001"} {
			if _, ok := set.Get(id); !ok {
				t.Errorf("set has no rule %q", id)
			}
		}
	})

	t.Run("invalid names the file and the field", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join("..", "..", "testdata", "rules", "invalid")
		rules, errs := LoadDir(dir)
		if rules != nil {
			t.Errorf("rules = %v, want nil", rules)
		}
		wantOneError(t, errs, filepath.Join(dir, "bad-severity.yaml"), ReasonInvalidValue)
		e := errs[0]
		if e.Field != "severity" || e.Line != 4 {
			t.Errorf("Field = %q, Line = %d, want severity, 4", e.Field, e.Line)
		}
		if !strings.Contains(e.Error(), "bad-severity.yaml") {
			t.Errorf("Error() = %q, want the file name", e.Error())
		}
	})

	t.Run("collision with a built-in ID", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join("..", "..", "testdata", "rules", "collide")
		rules, errs := LoadDir(dir)
		if len(errs) > 0 {
			t.Fatalf("LoadDir() errors = %v", errs)
		}
		set, serrs := NewSet(builtin, rules)
		if set != nil {
			t.Error("set is not nil, want nil on a clash")
		}
		wantOneError(t, serrs, filepath.Join(dir, "MOAT-T1-003.yaml"), ReasonBuiltinIDClash)
		e := serrs[0]
		if !strings.Contains(e.Error(), "MOAT-T1-003.yaml") {
			t.Errorf("Error() = %q, want the built-in file named", e.Error())
		}
	})
}

func TestLoadDirDuplicateID(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", validRuleYAML("DUP-1"))
	writeFile(t, dir, "b.yaml", validRuleYAML("DUP-1"))

	rules, errs := LoadDir(dir)
	if len(errs) > 0 {
		t.Fatalf("LoadDir() errors = %v, want none (the clash is for NewSet)", errs)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	_, serrs := NewSet(nil, rules)
	wantOneError(t, serrs, filepath.Join(dir, "b.yaml"), ReasonDuplicateID)
	e := serrs[0]
	if !strings.Contains(e.Error(), "a.yaml") {
		t.Errorf("Error() = %q, want the first file named", e.Error())
	}
}

func TestLoadDirCollectsAllErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "a-good.yaml", validRuleYAML("GOOD-1"))
	writeFile(t, dir, "b-bad.yaml", badRuleYAML("BAD-1"))
	writeFile(t, dir, "c-bad.yaml", "not: [valid")

	rules, errs := LoadDir(dir)
	if rules != nil {
		t.Errorf("rules = %v, want nil when any file fails", ruleIDs(rules))
	}
	if len(errs) != 2 {
		t.Fatalf("got %d errors, want 2: %v", len(errs), errs)
	}
	for i, name := range []string{"b-bad.yaml", "c-bad.yaml"} {
		if want := filepath.Join(dir, name); errs[i].File != want {
			t.Errorf("errs[%d].File = %q, want %q", i, errs[i].File, want)
		}
	}
	if errs[0].Reason != ReasonInvalidValue || errs[1].Reason != ReasonInvalidYAML {
		t.Errorf("reasons = %q, %q, want invalid value, invalid YAML", errs[0].Reason, errs[1].Reason)
	}
}

func TestLoadDirFileFiltering(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Rules that must load. Names are written out of order on purpose.
	writeFile(t, dir, "b.yml", validRuleYAML("R-B"))
	writeFile(t, dir, "a.yaml", validRuleYAML("R-A"))
	// The extension is not case sensitive, so these load too.
	writeFile(t, dir, "c.YAML", validRuleYAML("R-C"))
	writeFile(t, dir, "bb.Yml", validRuleYAML("R-BB"))
	// Files that must be ignored. Each one would load or fail if it counted.
	writeFile(t, dir, "d.txt", validRuleYAML("R-D"))
	writeFile(t, dir, "e.yaml.bak", validRuleYAML("R-E"))
	writeFile(t, dir, ".hidden", validRuleYAML("R-H"))
	writeFile(t, dir, "badname.yaml.YML.txt", "not: [valid")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "sub"), "inner.yaml", validRuleYAML("R-S"))
	if err := os.Mkdir(filepath.Join(dir, "dir.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "dir.yaml"), "inner.yaml", validRuleYAML("R-I"))

	rules, errs := LoadDir(dir)
	if len(errs) > 0 {
		t.Fatalf("LoadDir() errors = %v", errs)
	}
	if got := ruleIDs(rules); !slices.Equal(got, []string{"R-A", "R-B", "R-BB", "R-C"}) {
		t.Errorf("IDs = %v, want [R-A R-B R-BB R-C] sorted by file name", got)
	}
}

func TestLoadDirExtensionCase(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// "A.YAML" sorts before "b.Yml" (upper case letters come first), and the
	// order of the IDs is the reverse of the order of the names, so only a
	// sort by file name gives R-1 then R-2.
	writeFile(t, dir, "b.Yml", validRuleYAML("R-2"))
	writeFile(t, dir, "A.YAML", validRuleYAML("R-1"))
	rules, errs := LoadDir(dir)
	if len(errs) > 0 {
		t.Fatalf("LoadDir() errors = %v", errs)
	}
	if got := ruleIDs(rules); !slices.Equal(got, []string{"R-1", "R-2"}) {
		t.Errorf("IDs = %v, want [R-1 R-2] sorted by file name", got)
	}
	if rules[0].Source != filepath.Join(dir, "A.YAML") {
		t.Errorf("Source = %q, want the full path of A.YAML", rules[0].Source)
	}

	// A bad file with an upper case extension is an error, not skipped.
	bad := writeFile(t, dir, "C.YML", badRuleYAML("R-3"))
	_, errs = LoadDir(dir)
	wantOneError(t, errs, bad, ReasonInvalidValue)
}

func TestLoadDirNoRuleFiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{name: "empty folder", setup: func(*testing.T, string) {}},
		{name: "only other names and a folder named like a rule", setup: func(t *testing.T, dir string) {
			writeFile(t, dir, "a.txt", validRuleYAML("R-A"))
			writeFile(t, dir, "b.yaml.bak", validRuleYAML("R-B"))
			if err := os.Mkdir(filepath.Join(dir, "x.yaml"), 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(dir, "x.yaml"), "inner.yaml", validRuleYAML("R-X"))
		}},
		{name: "only a subfolder with rules", setup: func(t *testing.T, dir string) {
			sub := filepath.Join(dir, "sub")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, sub, "inner.yaml", validRuleYAML("R-S"))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			tt.setup(t, dir)
			rules, errs := LoadDir(dir)
			if rules != nil {
				t.Errorf("got %d rules, want nil", len(rules))
			}
			wantOneError(t, errs, dir, ReasonNoRuleFiles)
			if errs[0].Err != nil || errs[0].Line != 0 || errs[0].Field != "" {
				t.Errorf("error = %+v, want only File and Reason", *errs[0])
			}
		})
	}
}

func TestLoadDirBadDirectory(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	notDir := writeFile(t, base, "file.txt", "hello")

	tests := []struct {
		name string
		dir  string
	}{
		{name: "missing", dir: filepath.Join(base, "missing")},
		{name: "regular file", dir: notDir},
		{name: "empty path", dir: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rules, errs := LoadDir(tt.dir)
			if rules != nil {
				t.Errorf("rules = %v, want nil", rules)
			}
			wantOneError(t, errs, tt.dir, ReasonDirUnreadable)
		})
	}
}

func TestLoadDirSymlinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "rules")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{dir, outside} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, dir, "real.txt", validRuleYAML("LINK-1"))
	target := writeFile(t, outside, "secret.yaml", validRuleYAML("OUT-1"))

	tests := []struct {
		name   string
		link   string
		target string
	}{
		{name: "inside the dir", link: "x.yaml", target: "real.txt"},
		{name: "outside the dir", link: "y.yml", target: target},
		{name: "dangling", link: "z.yaml", target: filepath.Join(root, "nothing")},
	}
	for _, tt := range tests {
		if err := os.Symlink(tt.target, filepath.Join(dir, tt.link)); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
	}

	rules, errs := LoadDir(dir)
	if rules != nil {
		t.Errorf("rules = %v, want none", ruleIDs(rules))
	}
	if len(errs) != len(tests) {
		t.Fatalf("got %d errors, want %d: %v", len(errs), len(tests), errs)
	}
	for i, tt := range tests {
		wantOneError(t, errs[i:i+1], filepath.Join(dir, tt.link), ReasonNotRegular)
	}
}

func TestLoadDirSymlinkToRuleInSameDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "real.yaml", validRuleYAML("REAL-1"))

	// Before the link, the target loads.
	rules, errs := LoadDir(dir)
	if len(errs) > 0 || !slices.Equal(ruleIDs(rules), []string{"REAL-1"}) {
		t.Fatalf("LoadDir() = %v, %v, want REAL-1 and no errors", ruleIDs(rules), errs)
	}

	if err := os.Symlink("real.yaml", filepath.Join(dir, "link.yaml")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	// The link is refused, also when it points to a valid rule in the same
	// directory. The target is not read twice through the link.
	rules, errs = LoadDir(dir)
	if rules != nil {
		t.Errorf("rules = %v, want nil when a file fails", ruleIDs(rules))
	}
	wantOneError(t, errs, filepath.Join(dir, "link.yaml"), ReasonNotRegular)
}

func TestLoadDirSymlinkedDirectory(t *testing.T) {
	t.Parallel()
	// The rules directory itself may be a symlink: the user chose that path.
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, target, "a.yaml", validRuleYAML("R-A"))
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	rules, errs := LoadDir(link)
	if len(errs) > 0 || len(rules) != 1 {
		t.Errorf("LoadDir(symlinked dir) = %v, %v, want one rule", ruleIDs(rules), errs)
	}
}

func TestLoadDirFileSize(t *testing.T) {
	t.Parallel()

	// padded returns a valid rule followed by a comment, at exactly n bytes.
	padded := func(n int) string {
		base := validRuleYAML("PAD-1") + "#"
		return base + strings.Repeat("x", n-len(base))
	}

	tests := []struct {
		name   string
		size   int
		reason Reason // empty means the file must load
	}{
		{name: "exactly the cap loads", size: maxFileBytes},
		{name: "one byte over the cap", size: maxFileBytes + 1, reason: ReasonTooLarge},
		{name: "far over the cap", size: 4 * maxFileBytes, reason: ReasonTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			content := padded(tt.size)
			if len(content) != tt.size {
				t.Fatalf("test bug: content is %d bytes, want %d", len(content), tt.size)
			}
			name := writeFile(t, dir, "big.yaml", content)
			rules, errs := LoadDir(dir)
			if tt.reason == "" {
				if len(errs) > 0 || len(rules) != 1 {
					t.Fatalf("LoadDir() = %v, %v, want one rule", ruleIDs(rules), errs)
				}
				return
			}
			if rules != nil {
				t.Errorf("rules = %v, want nil", ruleIDs(rules))
			}
			wantOneError(t, errs, name, tt.reason)
		})
	}

	t.Run("comment-only oversize file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		name := writeFile(t, dir, "big.yaml", "#"+strings.Repeat("x", maxFileBytes))
		_, errs := LoadDir(dir)
		wantOneError(t, errs, name, ReasonTooLarge)
	})
}

func TestLoadDirFileCount(t *testing.T) {
	t.Parallel()

	t.Run("one over the cap", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for i := range maxRuleFiles + 1 {
			writeFile(t, dir, "r"+strconv.Itoa(i)+".yaml", "x")
		}
		rules, errs := LoadDir(dir)
		if rules != nil {
			t.Errorf("got %d rules, want nil", len(rules))
		}
		// One directory-level error, not one per file.
		wantOneError(t, errs, dir, ReasonTooManyFiles)
	})

	t.Run("files that are not candidates do not count", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for i := range maxRuleFiles + 1 {
			writeFile(t, dir, "r"+strconv.Itoa(i)+".txt", "x")
		}
		rules, errs := LoadDir(dir)
		if rules != nil {
			t.Errorf("got %d rules, want nil", len(rules))
		}
		wantOneError(t, errs, dir, ReasonNoRuleFiles)
	})

	t.Run("exactly the cap", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for i := range maxRuleFiles {
			writeFile(t, dir, "r"+strconv.Itoa(i)+".yaml", validRuleYAML("R-"+strconv.Itoa(i)))
		}
		rules, errs := LoadDir(dir)
		if len(errs) > 0 {
			t.Fatalf("LoadDir() errors = %v (first: %v)", len(errs), errs[0])
		}
		if len(rules) != maxRuleFiles {
			t.Errorf("got %d rules, want %d", len(rules), maxRuleFiles)
		}
	})
}

// openTestFS returns a nonBlockFS on a new temporary directory and the path of
// that directory. It closes the root when the test ends.
func openTestFS(t *testing.T) (nonBlockFS, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return nonBlockFS{root}, dir
}

func TestListRuleFiles(t *testing.T) {
	t.Parallel()

	t.Run("more than one batch is read and sorted", func(t *testing.T) {
		t.Parallel()
		fsys, dir := openTestFS(t)
		// Zero-padded names sort in number order. 300 is more than dirBatch,
		// so the listing needs at least two ReadDir calls.
		total := dirBatch + 44
		var want []string
		for i := range total {
			name := fmt.Sprintf("r%04d.yaml", i)
			writeFile(t, dir, name, "x")
			want = append(want, name)
		}
		entries, lerr := listRuleFiles(fsys, dir, maxDirEntries, maxRuleFiles)
		if lerr != nil {
			t.Fatalf("listRuleFiles() error = %v", lerr)
		}
		var got []string
		for _, e := range entries {
			got = append(got, e.Name())
		}
		if !slices.Equal(got, want) {
			t.Errorf("got %d names (first %q), want %d sorted names", len(got), got[:min(len(got), 3)], len(want))
		}
	})

	t.Run("only files with a rule name are candidates", func(t *testing.T) {
		t.Parallel()
		fsys, dir := openTestFS(t)
		for _, name := range []string{"a.txt", "b.YAML", "c.yaml.bak", "d.yaml.", "z.yml", "m.yaml"} {
			writeFile(t, dir, name, "x")
		}
		for _, name := range []string{"x.yaml", "sub", "y.yml"} {
			if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		entries, lerr := listRuleFiles(fsys, dir, maxDirEntries, maxRuleFiles)
		if lerr != nil {
			t.Fatalf("listRuleFiles() error = %v", lerr)
		}
		var got []string
		for _, e := range entries {
			got = append(got, e.Name())
		}
		if want := []string{"b.YAML", "m.yaml", "z.yml"}; !slices.Equal(got, want) {
			t.Errorf("names = %v, want %v", got, want)
		}
	})

	t.Run("entry cap counts every name", func(t *testing.T) {
		t.Parallel()
		const maxEntries = 5
		tests := []struct {
			name    string
			entries int
			wantErr bool
		}{
			{name: "at the cap", entries: maxEntries, wantErr: false},
			{name: "one over the cap", entries: maxEntries + 1, wantErr: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				fsys, dir := openTestFS(t)
				for i := range tt.entries {
					// None of the names is a candidate: only the entry count can trip the cap.
					writeFile(t, dir, "f"+strconv.Itoa(i)+".txt", "x")
				}
				entries, lerr := listRuleFiles(fsys, dir, maxEntries, maxRuleFiles)
				if !tt.wantErr {
					if lerr != nil || len(entries) != 0 {
						t.Fatalf("listRuleFiles() = %d entries, %v, want none and no error", len(entries), lerr)
					}
					return
				}
				if entries != nil {
					t.Errorf("entries = %d, want nil", len(entries))
				}
				wantOneError(t, []*LoadError{lerr}, dir, ReasonTooManyFiles)
			})
		}
	})

	t.Run("candidate cap counts only candidates", func(t *testing.T) {
		t.Parallel()
		const maxFiles = 3
		tests := []struct {
			name       string
			candidates int
			wantErr    bool
		}{
			{name: "at the cap", candidates: maxFiles, wantErr: false},
			{name: "one over the cap", candidates: maxFiles + 1, wantErr: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				fsys, dir := openTestFS(t)
				for i := range tt.candidates {
					writeFile(t, dir, "r"+strconv.Itoa(i)+".yaml", "")
				}
				// These names are not candidates, so they must not count.
				for i := range maxFiles + 2 {
					writeFile(t, dir, "o"+strconv.Itoa(i)+".txt", "")
				}
				entries, lerr := listRuleFiles(fsys, dir, maxDirEntries, maxFiles)
				if !tt.wantErr {
					if lerr != nil || len(entries) != maxFiles {
						t.Fatalf("listRuleFiles() = %d entries, %v, want %d and no error", len(entries), lerr, maxFiles)
					}
					return
				}
				if entries != nil {
					t.Errorf("entries = %d, want nil", len(entries))
				}
				wantOneError(t, []*LoadError{lerr}, dir, ReasonTooManyFiles)
			})
		}
	})
}

// emptyBatchFS is an fs.FS whose root directory breaks the fs.ReadDirFile
// contract: ReadDir(n) with n > 0 returns no entries and a nil error.
type emptyBatchFS struct{}

func (emptyBatchFS) Open(name string) (fs.File, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return emptyBatchDir{}, nil
}

type emptyBatchDir struct{}

func (emptyBatchDir) Stat() (fs.FileInfo, error)         { return nil, errors.New("not used") }
func (emptyBatchDir) Read([]byte) (int, error)           { return 0, errors.New("not used") }
func (emptyBatchDir) Close() error                       { return nil }
func (emptyBatchDir) ReadDir(int) ([]fs.DirEntry, error) { return nil, nil }

func TestListRuleFilesEmptyBatchWithoutError(t *testing.T) {
	t.Parallel()
	type result struct {
		entries []fs.DirEntry
		lerr    *LoadError
	}
	r := within(t, "listRuleFiles on an empty batch", func() result {
		entries, lerr := listRuleFiles(emptyBatchFS{}, "fake dir", maxDirEntries, maxRuleFiles)
		return result{entries, lerr}
	})
	if r.entries != nil {
		t.Errorf("entries = %d, want nil", len(r.entries))
	}
	wantOneError(t, []*LoadError{r.lerr}, "fake dir", ReasonDirUnreadable)
	if !errors.Is(r.lerr, io.ErrNoProgress) {
		t.Errorf("error = %v, want it to wrap io.ErrNoProgress", r.lerr)
	}
}

// TestLoadDirManyFilesInOrder loads more files than one directory batch and
// checks that the rules come back in file name order.
func TestLoadDirManyFilesInOrder(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	total := dirBatch + 44
	want := make([]string, 0, total)
	// Write in reverse so the order on disk is not the name order.
	for i := total - 1; i >= 0; i-- {
		id := fmt.Sprintf("R-%04d", i)
		writeFile(t, dir, fmt.Sprintf("r%04d.yaml", i), validRuleYAML(id))
	}
	for i := range total {
		want = append(want, fmt.Sprintf("R-%04d", i))
	}
	rules, errs := LoadDir(dir)
	if len(errs) > 0 {
		t.Fatalf("LoadDir() errors = %d (first: %v)", len(errs), errs[0])
	}
	if got := ruleIDs(rules); !slices.Equal(got, want) {
		t.Errorf("got %d IDs, want %d in file name order", len(got), len(want))
	}
}

// recordingCompiler records the calls it gets and returns err.
type recordingCompiler struct {
	matches []Match
	targets []Target
	err     error
}

func (c *recordingCompiler) compile(m Match, t Target) (Matcher, error) {
	c.matches = append(c.matches, m)
	c.targets = append(c.targets, t)
	return nil, c.err
}

func TestLoadDirWithCompiler(t *testing.T) {
	t.Parallel()

	t.Run("called once per good rule with Match and Target", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, dir, "a.yaml", validRuleYAML("R-A"))
		writeFile(t, dir, "b.yaml", strings.Replace(validRuleYAML("R-B"), "target: description", "target: schema", 1))
		rc := &recordingCompiler{}

		rules, errs := LoadDir(dir, WithCompiler(rc.compile))
		if len(errs) > 0 {
			t.Fatalf("LoadDir() errors = %v", errs)
		}
		if len(rules) != 2 || len(rc.matches) != 2 {
			t.Fatalf("rules = %d, compiler calls = %d, want 2 and 2", len(rules), len(rc.matches))
		}
		for i, r := range rules {
			if rc.targets[i] != r.Target || len(rc.matches[i].Keywords) != 1 || rc.matches[i].Keywords[0] != "marker" {
				t.Errorf("call %d = (%+v, %q), want rule %s's match and target %q", i, rc.matches[i], rc.targets[i], r.ID, r.Target)
			}
		}
		if rc.targets[0] != TargetDescription || rc.targets[1] != TargetSchema {
			t.Errorf("targets = %v, want [description schema]", rc.targets)
		}
	})

	t.Run("compiler error is invalid value in match", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, dir, "a.yaml", validRuleYAML("R-A"))
		boom := errors.New("bad pattern")
		rc := &recordingCompiler{err: boom}

		rules, errs := LoadDir(dir, WithCompiler(rc.compile))
		if rules != nil {
			t.Errorf("rules = %v, want nil", ruleIDs(rules))
		}
		wantOneError(t, errs, filepath.Join(dir, "a.yaml"), ReasonInvalidValue)
		e := errs[0]
		if e.Field != "match" || !errors.Is(e, boom) {
			t.Errorf("Field = %q, Is(boom) = %v, want match and true", e.Field, errors.Is(e, boom))
		}
	})

	t.Run("not called for a file that fails to parse", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, dir, "a.yaml", badRuleYAML("R-A"))
		rc := &recordingCompiler{}
		_, errs := LoadDir(dir, WithCompiler(rc.compile))
		wantOneError(t, errs, filepath.Join(dir, "a.yaml"), ReasonInvalidValue)
		if len(rc.matches) != 0 {
			t.Errorf("compiler called %d times, want 0", len(rc.matches))
		}
	})

	t.Run("nil compiler and nil option skip compiling", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, dir, "a.yaml", validRuleYAML("R-A"))
		for _, opts := range [][]Option{{WithCompiler(nil)}, {nil}} {
			rules, errs := LoadDir(dir, opts...)
			if len(errs) > 0 || len(rules) != 1 {
				t.Errorf("LoadDir() = %v, %v, want one rule", ruleIDs(rules), errs)
			}
		}
	})

	t.Run("returned matcher is discarded", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, dir, "a.yaml", validRuleYAML("R-A"))
		compile := func(Match, Target) (Matcher, error) { return nil, nil }
		rules, errs := LoadDir(dir, WithCompiler(compile))
		if len(errs) > 0 || len(rules) != 1 {
			t.Errorf("LoadDir() = %v, %v, want one rule", ruleIDs(rules), errs)
		}
	})
}

func TestLoadDirUnreadableFile(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("chmod does not block reads on Windows")
	}
	dir := t.TempDir()
	name := writeFile(t, dir, "a.yaml", validRuleYAML("R-A"))
	if err := os.Chmod(name, 0); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read a file with mode 0")
	}

	rules, errs := LoadDir(dir)
	if rules != nil {
		t.Errorf("rules = %v, want nil", ruleIDs(rules))
	}
	wantOneError(t, errs, name, ReasonUnreadable)
}

func TestLoadDirUntrustedNames(t *testing.T) {
	t.Parallel()

	t.Run("file name with ESC and newline", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		hostile := "a\x1b[31m\nfake: line.yaml"
		if err := os.WriteFile(filepath.Join(dir, hostile), []byte(badRuleYAML("R-A")), 0o600); err != nil {
			t.Skipf("file system refuses the name: %v", err)
		}
		_, errs := LoadDir(dir)
		assertSafeText(t, errs)
	})

	t.Run("not-regular file with a hostile name", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		hostile := "\x1b]0;title\x07.yaml"
		if err := os.Symlink("nowhere", filepath.Join(dir, hostile)); err != nil {
			t.Skipf("cannot create the link: %v", err)
		}
		_, errs := LoadDir(dir)
		wantOneError(t, errs, filepath.Join(dir, hostile), ReasonNotRegular)
		assertSafeText(t, errs)
	})

	t.Run("directory path with ESC and newline", func(t *testing.T) {
		t.Parallel()
		hostile := filepath.Join(t.TempDir(), "d\x1b[2J\nx\x7f")
		if err := os.Mkdir(hostile, 0o700); err != nil {
			t.Skipf("file system refuses the name: %v", err)
		}
		writeFile(t, hostile, "a.yaml", badRuleYAML("R-A"))
		_, errs := LoadDir(hostile)
		assertSafeText(t, errs)
		if got := errs[0].File; !bytes.Contains([]byte(got), []byte("\x1b")) {
			t.Errorf("File = %q, want the raw path kept in the field", got)
		}
	})

	// Unicode controls and format characters that a terminal or a viewer can
	// act on. The names use Go escapes on purpose (Trojan Source linters).
	unicodeNames := []struct{ name, text string }{
		{name: "C1 CSI U+009B", text: "x\u009b31m"},
		{name: "bidi override U+202E", text: "x\u202eyaml.exe"},
		{name: "zero-width space U+200B", text: "x\u200bx"},
		{name: "line separator U+2028", text: "x\u2028y"},
		{name: "paragraph separator U+2029", text: "x\u2029y"},
	}
	for _, u := range unicodeNames {
		t.Run("file name with "+u.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			hostile := u.text + ".yaml"
			if err := os.WriteFile(filepath.Join(dir, hostile), []byte(badRuleYAML("R-A")), 0o600); err != nil {
				t.Skipf("file system refuses the name: %v", err)
			}
			_, errs := LoadDir(dir)
			assertSafeText(t, errs)
			if got := errs[0].File; !strings.Contains(got, u.text) {
				t.Errorf("File = %q, want the raw name kept in the field", got)
			}
		})
		t.Run("directory path with "+u.name, func(t *testing.T) {
			t.Parallel()
			hostile := filepath.Join(t.TempDir(), "d"+u.text)
			if err := os.Mkdir(hostile, 0o700); err != nil {
				t.Skipf("file system refuses the name: %v", err)
			}
			writeFile(t, hostile, "a.yaml", badRuleYAML("R-A"))
			_, errs := LoadDir(hostile)
			assertSafeText(t, errs)
		})
		t.Run("missing directory with "+u.name, func(t *testing.T) {
			t.Parallel()
			hostile := filepath.Join(t.TempDir(), "gone"+u.text)
			_, errs := LoadDir(hostile)
			wantOneError(t, errs, hostile, ReasonDirUnreadable)
			assertSafeText(t, errs)
		})
	}

	t.Run("directory path in the too-many-errors entry", func(t *testing.T) {
		t.Parallel()
		hostile := filepath.Join(t.TempDir(), "d\x1b[2J\u009b\u202e\u200b")
		if err := os.Mkdir(hostile, 0o700); err != nil {
			t.Skipf("file system refuses the name: %v", err)
		}
		for i := range maxFolderErrors + 1 {
			writeFile(t, hostile, fmt.Sprintf("r%03d.yaml", i), badRuleYAML("R-A"))
		}
		_, errs := LoadDir(hostile)
		last := errs[len(errs)-1]
		if last.Reason != ReasonTooManyErrors || last.File != hostile {
			t.Fatalf("last error = {File: %q, Reason: %q}, want the directory and too many errors", last.File, last.Reason)
		}
		assertSafeText(t, errs)
	})

	t.Run("missing directory with a hostile name", func(t *testing.T) {
		t.Parallel()
		hostile := filepath.Join(t.TempDir(), "gone\x1b[2J\n")
		_, errs := LoadDir(hostile)
		wantOneError(t, errs, hostile, ReasonDirUnreadable)
		assertSafeText(t, errs)
	})
}

// hostileFiles writes n files into dir, named f0000.yaml and so on, and returns
// their count. Even files give maxErrorsPerFile+1 errors each through 9970 null
// list items; odd files give the same through 4985 unknown keys. Each content is
// built once and shared, so the helper is cheap.
func hostileFiles(t *testing.T, dir string, n int) {
	t.Helper()
	// Keep the rule up to its should_match key: the header is valid.
	header, _, _ := strings.Cut(validRuleYAML("HOSTILE-1"), "should_match:")
	nulls := header + "should_match:\n" + strings.Repeat("  -\n", 9970)
	var keys strings.Builder
	keys.WriteString(header)
	for i := range 4985 {
		keys.WriteString("k" + strconv.Itoa(i) + ": 1\n")
	}
	unknown := keys.String()
	for _, c := range []string{nulls, unknown} {
		if len(c) > maxFileBytes {
			t.Fatalf("test bug: hostile file is %d bytes, over the cap %d", len(c), maxFileBytes)
		}
	}
	for i := range n {
		content := nulls
		if i%2 == 1 {
			content = unknown
		}
		writeFile(t, dir, fmt.Sprintf("f%04d.yaml", i), content)
	}
}

// tooManyErrorsEntry fails unless the last of errs is the folder entry for dir,
// and returns the number of files it says were not checked.
func tooManyErrorsEntry(t *testing.T, errs []*LoadError, dir string) int {
	t.Helper()
	if len(errs) == 0 {
		t.Fatal("got no errors, want a too-many-errors entry")
	}
	last := errs[len(errs)-1]
	if last.Reason != ReasonTooManyErrors || last.File != dir {
		t.Fatalf("last error = {File: %q, Reason: %q}, want {File: %q, Reason: %q}", last.File, last.Reason, dir, ReasonTooManyErrors)
	}
	msg := last.Error()
	if !strings.Contains(msg, "stopped after 100 errors") || !strings.Contains(msg, "files not fully checked") {
		t.Fatalf("Error() = %q, want the stop text and the count", msg)
	}
	_, after, _ := strings.Cut(msg, "errors; ")
	num, _, _ := strings.Cut(after, " files not fully checked")
	n, err := strconv.Atoi(num)
	if err != nil {
		t.Fatalf("Error() = %q: cannot read the count: %v", msg, err)
	}
	return n
}

// distinctFiles returns the number of different File values in errs.
func distinctFiles(errs []*LoadError) int {
	seen := map[string]bool{}
	for _, e := range errs {
		seen[e.File] = true
	}
	return len(seen)
}

func TestLoadDirFolderCap(t *testing.T) {
	t.Parallel()
	const total = 1000
	dir := t.TempDir()
	hostileFiles(t, dir, total)

	start := time.Now()
	rules, errs := LoadDir(dir)
	elapsed := time.Since(start)

	// The attack used 2.2 GB and 47 s. A generous guard: the shown run is far faster.
	if elapsed > 5*time.Second {
		t.Errorf("LoadDir took %v, want under 5s", elapsed)
	}
	if rules != nil {
		t.Errorf("got %d rules, want nil", len(rules))
	}
	if len(errs) > maxFolderErrors+1 {
		t.Fatalf("got %d errors, want at most %d", len(errs), maxFolderErrors+1)
	}
	n := tooManyErrorsEntry(t, errs, dir)
	if n <= 0 || n >= total {
		t.Errorf("files not fully checked = %d, want between 1 and %d", n, total-1)
	}
	shown := errs[:len(errs)-1]
	if len(shown) != maxFolderErrors {
		t.Errorf("got %d errors before the last, want exactly %d (the last file is cut to fit)", len(shown), maxFolderErrors)
	}
	// Every file gives errors, so the files read are the files with errors.
	// The last file read is cut to fit, so it counts as not checked too.
	if want := total - distinctFiles(shown) + 1; n != want {
		t.Errorf("files not fully checked = %d, want %d (total minus files read, plus the cut file)", n, want)
	}
	// Errors come in file-name order, and no file comes back after another.
	for i := 1; i < len(shown); i++ {
		if shown[i].File < shown[i-1].File {
			t.Fatalf("errs[%d].File = %q comes before errs[%d].File = %q", i, shown[i].File, i-1, shown[i-1].File)
		}
	}
	if first := filepath.Join(dir, "f0000.yaml"); shown[0].File != first {
		t.Errorf("first error file = %q, want %q", shown[0].File, first)
	}

	// The result is the same on a second call.
	rules2, errs2 := LoadDir(dir)
	if rules2 != nil || len(errs2) != len(errs) {
		t.Fatalf("second call = %d rules, %d errors, want nil and %d", len(rules2), len(errs2), len(errs))
	}
	for i := range errs {
		if errs[i].Error() != errs2[i].Error() {
			t.Fatalf("errs[%d] differs between calls: %q and %q", i, errs[i].Error(), errs2[i].Error())
		}
	}
}

func TestLoadDirFolderCapBoundary(t *testing.T) {
	t.Parallel()

	t.Run("exactly the cap has no final entry", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for i := range maxFolderErrors {
			writeFile(t, dir, fmt.Sprintf("r%03d.yaml", i), badRuleYAML("R-A"))
		}
		rules, errs := LoadDir(dir)
		if rules != nil {
			t.Errorf("got %d rules, want nil", len(rules))
		}
		if len(errs) != maxFolderErrors {
			t.Fatalf("got %d errors, want %d", len(errs), maxFolderErrors)
		}
		for _, e := range errs {
			if e.Reason == ReasonTooManyErrors {
				t.Fatalf("error %v, want no too-many-errors entry at exactly the cap", e)
			}
		}
	})

	t.Run("one file over the cap", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for i := range maxFolderErrors + 1 {
			writeFile(t, dir, fmt.Sprintf("r%03d.yaml", i), badRuleYAML("R-A"))
		}
		_, errs := LoadDir(dir)
		if len(errs) != maxFolderErrors+1 {
			t.Fatalf("got %d errors, want %d", len(errs), maxFolderErrors+1)
		}
		if n := tooManyErrorsEntry(t, errs, dir); n != 1 {
			t.Errorf("files not fully checked = %d, want 1", n)
		}
		// The unread file is the last by name.
		if last := errs[len(errs)-2].File; last != filepath.Join(dir, "r099.yaml") {
			t.Errorf("last real error file = %q, want r099.yaml", last)
		}
		want := "stopped after 100 errors; 1 files not fully checked"
		if got := errs[len(errs)-1].Error(); !strings.HasSuffix(got, want) {
			t.Errorf("Error() = %q, want the suffix %q", got, want)
		}
	})

	t.Run("good files after the cap are not read", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for i := range maxFolderErrors {
			writeFile(t, dir, fmt.Sprintf("a%03d.yaml", i), badRuleYAML("R-A"))
		}
		writeFile(t, dir, "z-good.yaml", validRuleYAML("GOOD-1"))
		rules, errs := LoadDir(dir)
		if rules != nil {
			t.Errorf("got %d rules, want nil", len(rules))
		}
		if n := tooManyErrorsEntry(t, errs, dir); n != 1 {
			t.Errorf("files not fully checked = %d, want 1", n)
		}
	})

	t.Run("not-regular files count as errors", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for i := range maxFolderErrors + 1 {
			if err := os.Symlink("nowhere", filepath.Join(dir, fmt.Sprintf("l%03d.yaml", i))); err != nil {
				t.Skipf("cannot create symlink: %v", err)
			}
		}
		_, errs := LoadDir(dir)
		if len(errs) != maxFolderErrors+1 {
			t.Fatalf("got %d errors, want %d", len(errs), maxFolderErrors+1)
		}
		if n := tooManyErrorsEntry(t, errs, dir); n != 1 {
			t.Errorf("files not fully checked = %d, want 1", n)
		}
	})

	t.Run("30 files with 21 errors each are cut to fit", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		hostileFiles(t, dir, 30)
		rules, errs := LoadDir(dir)
		if rules != nil {
			t.Errorf("got %d rules, want nil", len(rules))
		}
		if len(errs) != maxFolderErrors+1 {
			t.Fatalf("got %d errors, want %d", len(errs), maxFolderErrors+1)
		}
		n := tooManyErrorsEntry(t, errs, dir)
		read := distinctFiles(errs[:len(errs)-1])
		// The files not read, plus the fifth file that is cut to fit.
		if read >= 30 || n != 30-read+1 {
			t.Errorf("read %d files, not checked = %d, want not checked = %d", read, n, 30-read+1)
		}
		// 4 whole files (4*21 errors) and the first 16 errors of the fifth.
		if read != 5 {
			t.Errorf("read %d files, want 5", read)
		}
	})

	t.Run("one file cut at the very end", func(t *testing.T) {
		t.Parallel()
		// The last file is read but its errors do not fit.
		dir := t.TempDir()
		hostileFiles(t, dir, 5)
		_, errs := LoadDir(dir)
		if len(errs) != maxFolderErrors+1 {
			t.Fatalf("got %d errors, want %d", len(errs), maxFolderErrors+1)
		}
		if n := tooManyErrorsEntry(t, errs, dir); n != 1 {
			t.Errorf("files not fully checked = %d, want 1 (the cut file is not fully shown)", n)
		}
	})
}

// TestLoadDirNotCheckedCountsCutAndUnread covers a folder where one file is cut
// at the cap and more files are never read. The count must hold both: the cut
// file and the unread files.
func TestLoadDirNotCheckedCountsCutAndUnread(t *testing.T) {
	t.Parallel()
	const (
		total   = 10
		perFile = maxErrorsPerFile + 1 // a hostile file gives 21 errors
	)
	// Files that fit whole: 100 / 21 = 4. The fifth file has 16 errors of room
	// left, so it is cut. The other 5 files are never read.
	whole := maxFolderErrors / perFile
	if maxFolderErrors%perFile == 0 {
		t.Fatal("test bug: the cap is a multiple of the errors per file, so no file is cut")
	}
	const cut = 1
	unread := total - whole - cut
	want := cut + unread // 1 + 5 = 6; an assignment instead of += would give 5

	dir := t.TempDir()
	hostileFiles(t, dir, total)
	_, errs := LoadDir(dir)
	if n := tooManyErrorsEntry(t, errs, dir); n != want {
		t.Errorf("files not fully checked = %d, want %d (1 cut + %d unread)", n, want, unread)
	}
	wantText := fmt.Sprintf("stopped after %d errors; %d files not fully checked", maxFolderErrors, want)
	if got := errs[len(errs)-1].Error(); !strings.HasSuffix(got, wantText) {
		t.Errorf("Error() = %q, want the suffix %q", got, wantText)
	}
}
