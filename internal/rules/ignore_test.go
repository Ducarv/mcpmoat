package rules

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// badMarker is a distinctive text in malformed lines. No warning and no error
// may contain it, because the ignore file is untrusted.
const badMarker = "ZQXMARKERQXZ"

func TestValidRuleID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id   string
		want bool
	}{
		{id: "MOAT-T1-003", want: true},
		{id: "X", want: true},
		{id: "a.b_c-1", want: true},
		{id: "A" + strings.Repeat("a", maxRuleIDBytes-1), want: true}, // 64 bytes
		{id: "", want: false},
		{id: "-A", want: false},
		{id: "1ABC", want: false},
		{id: "A--B", want: false},
		{id: "A-", want: false},
		{id: "A B", want: false},
		{id: "MOAT/T1", want: false},
		{id: "A" + strings.Repeat("a", maxRuleIDBytes), want: false}, // 65 bytes
		{id: "MOAT-\u00C9", want: false},
		{id: "A\x1b", want: false},
		{id: "A\n", want: false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.id), func(t *testing.T) {
			t.Parallel()
			if got := ValidRuleID(tt.id); got != tt.want {
				t.Errorf("ValidRuleID(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

func TestIgnoreWarningString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		w    IgnoreWarning
		want string
	}{
		{name: "line", w: IgnoreWarning{Line: 3, Reason: "invalid rule ID"}, want: ".mcpmoat-ignore:3: invalid rule ID"},
		{name: "summary", w: IgnoreWarning{Reason: "5 more malformed lines"}, want: ".mcpmoat-ignore: 5 more malformed lines"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.w.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseIgnore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		data         string
		wantEntries  []IgnoreEntry
		wantWarnings []IgnoreWarning
	}{
		{name: "empty"},
		{name: "comments and blank lines", data: "# a comment\n\n   \n\t# indented comment\n"},
		{
			name:        "rule only",
			data:        "MOAT-T1-003\n",
			wantEntries: []IgnoreEntry{{RuleID: "MOAT-T1-003", Line: 1}},
		},
		{
			name:        "no final newline",
			data:        "MOAT-T1-003",
			wantEntries: []IgnoreEntry{{RuleID: "MOAT-T1-003", Line: 1}},
		},
		{
			name: "scopes",
			data: "R1 srv\nR2 srv/tool\nR3 a/b/c\nR4 a/b/\nR5 srv#x\n",
			wantEntries: []IgnoreEntry{
				{RuleID: "R1", Server: "srv", Line: 1},
				{RuleID: "R2", Server: "srv", Tool: "tool", Line: 2},
				{RuleID: "R3", Server: "a/b", Tool: "c", Line: 3},
				{RuleID: "R4", Server: "a/b", Line: 4},
				{RuleID: "R5", Server: "srv#x", Line: 5},
			},
		},
		{
			name: "trailing comment field",
			data: "R1 srv # why\nR2 # srv/tool\nR3\t#\nR4 srv #note x\n#nospace\n",
			wantEntries: []IgnoreEntry{
				{RuleID: "R1", Server: "srv", Line: 1},
				{RuleID: "R2", Line: 2},
				{RuleID: "R3", Line: 3},
				{RuleID: "R4", Server: "srv", Line: 4},
			},
		},
		{
			// A scope that starts with '#' must be exactly "#", so a missing
			// space never makes a rule-wide entry.
			name: "hash in the scope position",
			data: "R1 #srv\nR1 #srv/tool\nR1 #srv # c\nR1 #srv extra\nR1 #\nR1 srv/tool # x\n",
			wantEntries: []IgnoreEntry{
				{RuleID: "R1", Line: 5},
				{RuleID: "R1", Server: "srv", Tool: "tool", Line: 6},
			},
			wantWarnings: []IgnoreWarning{
				{Line: 1, Reason: reasonHashScope},
				{Line: 2, Reason: reasonHashScope},
				{Line: 3, Reason: reasonHashScope},
				{Line: 4, Reason: reasonHashScope},
			},
		},
		{
			name: "CRLF and BOM",
			data: "\xEF\xBB\xBFR1 srv\r\n\r\nR2 srv/tool\r\n",
			wantEntries: []IgnoreEntry{
				{RuleID: "R1", Server: "srv", Line: 1},
				{RuleID: "R2", Server: "srv", Tool: "tool", Line: 3},
			},
		},
		{
			name: "malformed lines with line numbers",
			data: "# header\n" + // 1
				"R1 /tool\n" + // 2
				"R1 /\n" + // 3
				"R1 srv extra\n" + // 4
				"1BAD srv\n" + // 5
				"R1 " + strings.Repeat("x", maxIgnoreLineBytes) + "\n" + // 6
				"R1 \xff\xfe\n" + // 7
				"R9 ok\n", // 8
			wantEntries: []IgnoreEntry{{RuleID: "R9", Server: "ok", Line: 8}},
			wantWarnings: []IgnoreWarning{
				{Line: 2, Reason: reasonEmptyServer},
				{Line: 3, Reason: reasonEmptyServer},
				{Line: 4, Reason: reasonTooManyFields},
				{Line: 5, Reason: reasonInvalidRuleID},
				{Line: 6, Reason: reasonLineTooLong},
				{Line: 7, Reason: reasonInvalidUTF8},
			},
		},
		{
			name:        "line of exactly the maximum length",
			data:        "R1 " + strings.Repeat("x", maxIgnoreLineBytes-3) + "\r\n",
			wantEntries: []IgnoreEntry{{RuleID: "R1", Server: strings.Repeat("x", maxIgnoreLineBytes-3), Line: 1}},
		},
		{
			name: "BOM only at the start is removed",
			data: "R1\n\xEF\xBB\xBFR2\n",
			wantEntries: []IgnoreEntry{
				{RuleID: "R1", Line: 1},
			},
			wantWarnings: []IgnoreWarning{{Line: 2, Reason: reasonHiddenRune}},
		},
		{
			// A CR in the middle of a line moves the cursor back, so a
			// terminal shows only the comment, not the rule-wide entry. The
			// check also applies to comment lines.
			name: "hidden runes",
			data: "R1\r# scoped to srv only\n" + // 1
				"R2\vsrv\n" + // 2
				"R3\u0085srv\n" + // 3
				"R4\u2028srv\n" + // 4
				"R5\u00a0srv\n" + // 5
				"R6 srv # \u202e evil\n" + // 6
				"# note \u200b\n" + // 7
				"R7 s\x1bv\n" + // 8
				"R8\tsrv\t# tab is fine\n", // 9
			wantEntries: []IgnoreEntry{{RuleID: "R8", Server: "srv", Line: 9}},
			wantWarnings: []IgnoreWarning{
				{Line: 1, Reason: reasonHiddenRune},
				{Line: 2, Reason: reasonHiddenRune},
				{Line: 3, Reason: reasonHiddenRune},
				{Line: 4, Reason: reasonHiddenRune},
				{Line: 5, Reason: reasonHiddenRune},
				{Line: 6, Reason: reasonHiddenRune},
				{Line: 7, Reason: reasonHiddenRune},
				{Line: 8, Reason: reasonHiddenRune},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			list, warnings := ParseIgnore([]byte(tt.data))
			if !reflect.DeepEqual(list.entries, tt.wantEntries) {
				t.Errorf("entries = %+v, want %+v", list.entries, tt.wantEntries)
			}
			if !reflect.DeepEqual(warnings, tt.wantWarnings) {
				t.Errorf("warnings = %+v, want %+v", warnings, tt.wantWarnings)
			}
		})
	}
}

func TestParseIgnoreWarningCap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		bad         int
		wantSummary string // "" means no summary warning
	}{
		{name: "at the cap", bad: MaxIgnoreWarnings},
		{name: "one more", bad: MaxIgnoreWarnings + 1, wantSummary: ".mcpmoat-ignore: 1 more malformed line"},
		{name: "ten more", bad: MaxIgnoreWarnings + 10, wantSummary: ".mcpmoat-ignore: 10 more malformed lines"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			for range tt.bad {
				b.WriteString("1" + badMarker + "\n")
			}
			b.WriteString("R1 srv\n")
			list, warnings := ParseIgnore([]byte(b.String()))

			if list.Len() != 1 {
				t.Errorf("Len() = %d, want 1: a good line after bad lines must be kept", list.Len())
			}
			wantLen := min(tt.bad, MaxIgnoreWarnings)
			if tt.wantSummary != "" {
				wantLen++
			}
			if len(warnings) != wantLen {
				t.Fatalf("len(warnings) = %d, want %d", len(warnings), wantLen)
			}
			for i := range min(tt.bad, MaxIgnoreWarnings) {
				want := IgnoreWarning{Line: i + 1, Reason: reasonInvalidRuleID}
				if warnings[i] != want {
					t.Errorf("warnings[%d] = %+v, want %+v", i, warnings[i], want)
				}
			}
			if tt.wantSummary != "" {
				last := warnings[len(warnings)-1]
				if last.Line != 0 || last.String() != tt.wantSummary {
					t.Errorf("summary = %+v (%q), want Line 0 and %q", last, last.String(), tt.wantSummary)
				}
			}
		})
	}
}

func TestParseIgnoreEntryCap(t *testing.T) {
	t.Parallel()

	entries := func(n int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "R%d\n", i)
		}
		return b.String()
	}

	t.Run("exactly at the cap", func(t *testing.T) {
		t.Parallel()
		// Comments and blank lines after the last entry do not count.
		list, warnings := ParseIgnore([]byte(entries(maxIgnoreEntries) + "# end\n\n"))
		if list.Len() != maxIgnoreEntries {
			t.Errorf("Len() = %d, want %d", list.Len(), maxIgnoreEntries)
		}
		if warnings != nil {
			t.Errorf("warnings = %+v, want nil", warnings)
		}
	})

	t.Run("one over the cap stops the parse", func(t *testing.T) {
		t.Parallel()
		// The bad line after the extra entry must not be read.
		data := entries(maxIgnoreEntries+1) + "1" + badMarker + "\n"
		list, warnings := ParseIgnore([]byte(data))
		if list.Len() != maxIgnoreEntries {
			t.Errorf("Len() = %d, want %d", list.Len(), maxIgnoreEntries)
		}
		want := []IgnoreWarning{{Line: maxIgnoreEntries + 1, Reason: reasonTooManyEntries}}
		if !reflect.DeepEqual(warnings, want) {
			t.Errorf("warnings = %+v, want %+v", warnings, want)
		}
	})

	t.Run("cap warning is kept after the summary", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		for range MaxIgnoreWarnings + 2 {
			b.WriteString("1" + badMarker + "\n")
		}
		b.WriteString(entries(maxIgnoreEntries + 1))
		_, warnings := ParseIgnore([]byte(b.String()))
		if len(warnings) != MaxIgnoreWarnings+2 {
			t.Fatalf("len(warnings) = %d, want %d", len(warnings), MaxIgnoreWarnings+2)
		}
		summary := warnings[MaxIgnoreWarnings]
		if summary.Line != 0 || summary.Reason != "2 more malformed lines" {
			t.Errorf("summary = %+v, want Line 0 and %q", summary, "2 more malformed lines")
		}
		capWarn := warnings[MaxIgnoreWarnings+1]
		wantCap := IgnoreWarning{Line: MaxIgnoreWarnings + 2 + maxIgnoreEntries + 1, Reason: reasonTooManyEntries}
		if capWarn != wantCap {
			t.Errorf("cap warning = %+v, want %+v", capWarn, wantCap)
		}
	})
}

// TestParseIgnoreWarningsHideContent checks that no warning shows text of the
// malformed line.
func TestParseIgnoreWarningsHideContent(t *testing.T) {
	t.Parallel()

	m := badMarker
	lines := []string{
		"R1 /" + m,
		"R1 " + m + " extra",
		m + "-",
		"1" + m,
		"R1 " + m + strings.Repeat("x", maxIgnoreLineBytes),
		"R1 " + m + "\xff",
		"\x1b[31m" + m,
	}
	// Repeat so the summary warning is made too.
	var b strings.Builder
	for range 5 {
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
	}
	_, warnings := ParseIgnore([]byte(b.String()))
	if len(warnings) != MaxIgnoreWarnings+1 {
		t.Fatalf("len(warnings) = %d, want %d", len(warnings), MaxIgnoreWarnings+1)
	}
	for _, w := range warnings {
		s := w.String()
		if strings.Contains(s, m) || strings.Contains(s, "xxxx") || strings.ContainsRune(s, 0x1b) {
			t.Errorf("warning %q shows content of the file", s)
		}
	}
}

// writeIgnore writes data to the ignore file in dir.
func writeIgnore(t *testing.T, dir string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, IgnoreFileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadIgnoreFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup returns the directory to read.
		setup        func(t *testing.T) string
		wantEntries  []IgnoreEntry
		wantWarnings []IgnoreWarning
		wantErr      error // the error that the result must wrap
		wantAnyErr   bool  // any error is correct
	}{
		{
			name:  "missing file",
			setup: func(t *testing.T) string { return t.TempDir() },
		},
		{
			name:  "missing directory",
			setup: func(t *testing.T) string { return filepath.Join(t.TempDir(), "nope") },
		},
		{
			name: "valid file",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeIgnore(t, dir, []byte("# c\nMOAT-T1-003 srv/tool\n1BAD\n"))
				return dir
			},
			wantEntries:  []IgnoreEntry{{RuleID: "MOAT-T1-003", Server: "srv", Tool: "tool", Line: 2}},
			wantWarnings: []IgnoreWarning{{Line: 3, Reason: reasonInvalidRuleID}},
		},
		{
			name: "file of exactly the maximum size",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				data := append([]byte("R1\n"), bytes.Repeat([]byte("\n"), MaxIgnoreFileBytes-3)...)
				writeIgnore(t, dir, data)
				return dir
			},
			wantEntries: []IgnoreEntry{{RuleID: "R1", Line: 1}},
		},
		{
			name: "directory with the ignore file name",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				if err := os.Mkdir(filepath.Join(dir, IgnoreFileName), 0o700); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			wantErr: errIgnoreNotRegular,
		},
		{
			name: "file one byte over the maximum size",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				data := append([]byte("R1 "+badMarker+"\n"), bytes.Repeat([]byte("#"), MaxIgnoreFileBytes)...)
				writeIgnore(t, dir, data[:MaxIgnoreFileBytes+1])
				return dir
			},
			wantErr: errIgnoreTooLarge,
		},
		{
			name: "symlink to a file outside the directory",
			setup: func(t *testing.T) string {
				outside := filepath.Join(t.TempDir(), "secret")
				if err := os.WriteFile(outside, []byte("R1 "+badMarker+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				if err := os.Symlink(outside, filepath.Join(dir, IgnoreFileName)); err != nil {
					t.Skipf("symlinks not supported: %v", err)
				}
				return dir
			},
			wantAnyErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := tt.setup(t)
			list, warnings, err := ReadIgnoreFile(dir)
			switch {
			case tt.wantAnyErr:
				if err == nil {
					t.Fatal("ReadIgnoreFile() error = nil, want an error")
				}
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ReadIgnoreFile() error = %v, want %v", err, tt.wantErr)
				}
			case err != nil:
				t.Fatalf("ReadIgnoreFile() error = %v, want nil", err)
			}
			if err != nil && strings.Contains(err.Error(), badMarker) {
				t.Errorf("error %q shows content of the file", err)
			}
			if !reflect.DeepEqual(list.entries, tt.wantEntries) {
				t.Errorf("entries = %+v, want %+v", list.entries, tt.wantEntries)
			}
			if !reflect.DeepEqual(warnings, tt.wantWarnings) {
				t.Errorf("warnings = %+v, want %+v", warnings, tt.wantWarnings)
			}
		})
	}
}

// TestReadIgnoreFileFIFO checks that a named pipe with no writer does not
// block the read and is refused.
func TestReadIgnoreFileFIFO(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("no named pipes in the file system on windows")
	}
	// The mkfifo program is used because syscall.Mkfifo does not exist on every
	// OS, and a call to it would stop the package from compiling there.
	mkfifo, err := exec.LookPath("mkfifo")
	if err != nil {
		t.Skip("mkfifo not available")
	}
	dir := t.TempDir()
	if out, err := exec.CommandContext(t.Context(), mkfifo, filepath.Join(dir, IgnoreFileName)).CombinedOutput(); err != nil { //nolint:gosec // G204: mkfifo is found by LookPath, the path is under t.TempDir()
		t.Skipf("mkfifo failed: %v: %s", err, out)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := ReadIgnoreFile(dir)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errIgnoreNotRegular) {
			t.Errorf("ReadIgnoreFile() error = %v, want %v", err, errIgnoreNotRegular)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadIgnoreFile blocked on a FIFO")
	}
}

func TestIgnored(t *testing.T) {
	t.Parallel()

	const rule = "MOAT-T1-003"
	tests := []struct {
		name  string
		entry IgnoreEntry
		key   FindingKey
		want  bool
	}{
		{name: "rule-wide, tool", entry: IgnoreEntry{RuleID: rule}, key: FindingKey{rule, "a", "t"}, want: true},
		{name: "rule-wide, other server", entry: IgnoreEntry{RuleID: rule}, key: FindingKey{rule, "b", "u"}, want: true},
		{name: "rule-wide, server-level", entry: IgnoreEntry{RuleID: rule}, key: FindingKey{rule, "a", ""}, want: true},
		{name: "rule-wide, other rule", entry: IgnoreEntry{RuleID: rule}, key: FindingKey{"MOAT-T1-004", "a", "t"}, want: false},
		{name: "rule is case-sensitive", entry: IgnoreEntry{RuleID: "moat-t1-003"}, key: FindingKey{rule, "a", "t"}, want: false},
		{name: "server, its tool", entry: IgnoreEntry{RuleID: rule, Server: "a"}, key: FindingKey{rule, "a", "t"}, want: true},
		{name: "server, server-level", entry: IgnoreEntry{RuleID: rule, Server: "a"}, key: FindingKey{rule, "a", ""}, want: true},
		{name: "server, other server", entry: IgnoreEntry{RuleID: rule, Server: "a"}, key: FindingKey{rule, "b", "t"}, want: false},
		{name: "server is case-sensitive", entry: IgnoreEntry{RuleID: rule, Server: "A"}, key: FindingKey{rule, "a", "t"}, want: false},
		{name: "tool, that tool", entry: IgnoreEntry{RuleID: rule, Server: "a", Tool: "t"}, key: FindingKey{rule, "a", "t"}, want: true},
		{name: "tool, other tool", entry: IgnoreEntry{RuleID: rule, Server: "a", Tool: "t"}, key: FindingKey{rule, "a", "u"}, want: false},
		{name: "tool, server-level", entry: IgnoreEntry{RuleID: rule, Server: "a", Tool: "t"}, key: FindingKey{rule, "a", ""}, want: false},
		{name: "tool, same tool on other server", entry: IgnoreEntry{RuleID: rule, Server: "a", Tool: "t"}, key: FindingKey{rule, "b", "t"}, want: false},
		{name: "tool, other rule", entry: IgnoreEntry{RuleID: rule, Server: "a", Tool: "t"}, key: FindingKey{"R2", "a", "t"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var l IgnoreList
			l.Add(IgnoreEntry{RuleID: "OTHER"}) // a non-matching entry first
			l.Add(tt.entry)
			if got := l.Ignored(tt.key); got != tt.want {
				t.Errorf("Ignored(%+v) with entry %+v = %v, want %v", tt.key, tt.entry, got, tt.want)
			}
		})
	}
}

func TestIgnoreListNilAndLen(t *testing.T) {
	t.Parallel()

	var nilList *IgnoreList
	if nilList.Len() != 0 {
		t.Errorf("nil Len() = %d, want 0", nilList.Len())
	}
	if nilList.Ignored(FindingKey{RuleID: "R1"}) {
		t.Error("nil Ignored() = true, want false")
	}

	var l IgnoreList
	if l.Len() != 0 || l.Ignored(FindingKey{RuleID: "R1"}) {
		t.Errorf("zero list: Len() = %d, Ignored() = %v, want 0 and false", l.Len(), l.Ignored(FindingKey{RuleID: "R1"}))
	}
	l.Add(IgnoreEntry{RuleID: "R1"})
	l.Add(IgnoreEntry{RuleID: "R2", Server: "s"})
	if l.Len() != 2 {
		t.Errorf("Len() = %d, want 2", l.Len())
	}
}

func TestFilterIgnored(t *testing.T) {
	t.Parallel()

	type finding struct {
		key FindingKey
		n   int
	}
	keyOf := func(f finding) FindingKey { return f.key }
	items := []finding{
		{FindingKey{"R1", "a", "t"}, 1},
		{FindingKey{"R2", "a", "t"}, 2},
		{FindingKey{"R1", "b", ""}, 3},
		{FindingKey{"R3", "a", "t"}, 4},
		{FindingKey{"R2", "b", "t"}, 5},
	}

	var list IgnoreList
	list.Add(IgnoreEntry{RuleID: "R1"})
	list.Add(IgnoreEntry{RuleID: "R2", Server: "a", Tool: "t"})

	tests := []struct {
		name        string
		list        *IgnoreList
		wantN       []int
		wantIgnored int
	}{
		{name: "nil list", list: nil, wantN: []int{1, 2, 3, 4, 5}},
		{name: "empty list", list: &IgnoreList{}, wantN: []int{1, 2, 3, 4, 5}},
		{name: "some ignored", list: &list, wantN: []int{4, 5}, wantIgnored: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := append([]finding(nil), items...)
			kept, ignored := FilterIgnored(tt.list, in, keyOf)
			if ignored != tt.wantIgnored {
				t.Errorf("ignored = %d, want %d", ignored, tt.wantIgnored)
			}
			gotN := make([]int, 0, len(kept))
			for _, f := range kept {
				gotN = append(gotN, f.n)
			}
			if !reflect.DeepEqual(gotN, tt.wantN) {
				t.Errorf("kept = %v, want %v (same order as the input)", gotN, tt.wantN)
			}
			// kept must not share memory with the input.
			for i := range kept {
				kept[i].n = -1
			}
			if !reflect.DeepEqual(in, items) {
				t.Errorf("input changed after a change to kept: %+v", in)
			}
		})
	}

	t.Run("nil items", func(t *testing.T) {
		t.Parallel()
		kept, ignored := FilterIgnored(&list, nil, keyOf)
		if kept == nil || len(kept) != 0 || ignored != 0 {
			t.Errorf("FilterIgnored(nil) = %v, %d, want empty non-nil slice and 0", kept, ignored)
		}
	})
}
