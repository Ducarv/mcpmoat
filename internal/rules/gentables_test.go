package rules

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"

	udiff "github.com/aymanbagabas/go-udiff"
	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/unicode/runenames"
)

// The flags of TestGenTables. The rules test binary holds both test packages
// (rules and rules_test), so no other test file of this directory may declare
// a flag named "confusables" or "update".
var (
	confusablesPath = flag.String("confusables", "", "TestGenTables: path of a local copy of Unicode TR39 confusables.txt")
	update          = flag.Bool("update", false, "TestGenTables: rewrite skeletonTable and edgeLookalikes from -confusables")
)

// TestGenTables makes skeletonTable (confusables.go) and edgeLookalikes
// (mixedscript.go) again from a local copy of Unicode TR39 confusables.txt,
// with the rules of the comments of the two tables. Run it when
// confusablesVersion or scriptTablesVersion changes:
//
//	go test ./internal/rules/ -run TestGenTables -args -confusables=PATH
//	go test ./internal/rules/ -run TestGenTables -args -confusables=PATH -update
//
// PATH is a local copy of the confusables.txt data file of Unicode TR39
// (https://www.unicode.org/reports/tr39/), version confusablesVersion. The test
// never downloads the file, and the file is not part of the repository: do not
// commit it. With no -confusables flag the test skips, so CI does not run it.
//
// The first command compares the generated tables with the committed ones and
// fails with a diff when they differ. The second command (-update) writes the
// generated tables into the two files. Then review the diff, and update
// skeletonTableSize and edgeLookalikesSize when the counts change.
//
// The test fails when the "# Version:" line of the file is not
// confusablesVersion, or when the Go unicode tables or the golang.org/x/text
// tables (norm, runenames) are not scriptTablesVersion: update the constants
// first.
//
// Each entry comment is the Unicode name from the comment field of
// confusables.txt. A form of edgeLookalikes that TR39 does not list gets its
// name from golang.org/x/text/unicode/runenames. The label after the name of
// an edgeLookalikes entry follows the rule in the comment of edgeLookalikes:
// the TR39 letter when TR39 maps the rune to one Latin letter alone; else
// "NFKD U+XXXX" for a form that is not in the first group, or for a form whose
// NFKD decomposition is the other letter and only marks, such as U+FE83; else
// the TR39 letter.
func TestGenTables(t *testing.T) {
	if *confusablesPath == "" {
		t.Skip("set -confusables=PATH to a local copy of TR39 confusables.txt to run the table generator (see the doc comment of TestGenTables)")
	}
	if unicode.Version != scriptTablesVersion || norm.Version != scriptTablesVersion || runenames.UnicodeVersion != scriptTablesVersion {
		t.Fatalf("unicode.Version = %s, norm.Version = %s, runenames.UnicodeVersion = %s, want all %s (scriptTablesVersion): update scriptTablesVersion first",
			unicode.Version, norm.Version, runenames.UnicodeVersion, scriptTablesVersion)
	}
	data, err := os.ReadFile(filepath.Clean(*confusablesPath))
	if err != nil {
		t.Fatalf("read -confusables file: %v", err)
	}
	version, lines, err := parseConfusables(data)
	if err != nil {
		t.Fatalf("parse %s: %v", *confusablesPath, err)
	}
	if version != confusablesVersion {
		t.Fatalf("%s has \"# Version: %s\", want %s (confusablesVersion): update confusablesVersion first, or use the file of that version",
			*confusablesPath, version, confusablesVersion)
	}
	for _, l := range lines {
		// runenames gives a range label such as "<CJK Ideograph>" for a
		// name that Unicode makes from the code point, so skip those.
		if want := runenames.Name(l.from); want != "" && !strings.HasPrefix(want, "<") && want != l.name {
			t.Errorf("TR39 name of U+%04X = %q, runenames.Name = %q: check the parser", l.from, l.name, want)
		}
	}

	skel := genSkeletonTable(lines)
	edge := genEdgeLookalikes(t, lines)
	if t.Failed() {
		t.FailNow() // do not write tables from a file that the checks above reject
	}
	checkGenBlock(t, "confusables.go", "var skeletonTable = [...]confusable{\n", skel)
	checkGenBlock(t, "mixedscript.go", "var edgeLookalikes = [...]rune{\n", edge)
}

// tr39Line is one line of confusables.txt whose source is one rune.
type tr39Line struct {
	from rune
	to   []rune // the target: one or more runes
	name string // the Unicode name of from, from the comment field
}

// parseConfusables returns the version from the "# Version:" line of
// confusables.txt and its lines whose source is one rune.
func parseConfusables(data []byte) (string, []tr39Line, error) {
	var version string
	var lines []tr39Line
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimPrefix(sc.Text(), "\uFEFF") // the file starts with a byte order mark
		if v, ok := strings.CutPrefix(line, "# Version:"); ok {
			version = strings.TrimSpace(v)
			continue
		}
		fields, comment, _ := strings.Cut(line, "#")
		if strings.TrimSpace(fields) == "" {
			continue // a comment line or an empty line
		}
		parts := strings.Split(fields, ";")
		if len(parts) != 3 {
			return "", nil, fmt.Errorf("line %d: want 3 fields, got %d", n, len(parts))
		}
		from, err := parseCodePoints(parts[0])
		if err != nil {
			return "", nil, fmt.Errorf("line %d: source: %w", n, err)
		}
		to, err := parseCodePoints(parts[1])
		if err != nil {
			return "", nil, fmt.Errorf("line %d: target: %w", n, err)
		}
		if len(from) != 1 {
			continue // the tables use one-rune sources only
		}
		name, err := tr39SourceName(comment)
		if err != nil {
			return "", nil, fmt.Errorf("line %d: %w", n, err)
		}
		lines = append(lines, tr39Line{from: from[0], to: to, name: name})
	}
	if err := sc.Err(); err != nil {
		return "", nil, err
	}
	if version == "" {
		return "", nil, fmt.Errorf("no \"# Version:\" line")
	}
	return version, lines, nil
}

// parseCodePoints parses a list of hex code points such as "006F 0308".
func parseCodePoints(s string) ([]rune, error) {
	var rs []rune
	for _, f := range strings.Fields(s) {
		v, err := strconv.ParseUint(f, 16, 32)
		if err != nil || v > unicode.MaxRune {
			return nil, fmt.Errorf("bad code point %q", f)
		}
		rs = append(rs, rune(v))
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("no code point")
	}
	return rs, nil
}

// tr39SourceName returns the name of the source rune from the comment field
// of a confusables.txt line: " ( x -> y ) SOURCE NAME -> TARGET NAME\t# chain"
// (with U+2192 for each arrow). Unicode names hold no ")" and no arrow, so the
// name starts after the last ")" before the chain.
func tr39SourceName(comment string) (string, error) {
	names, _, _ := strings.Cut(comment, "\t#")
	i := strings.LastIndex(names, ")")
	if i < 0 {
		return "", fmt.Errorf("no name in comment %q", comment)
	}
	name, _, ok := strings.Cut(names[i+1:], "\u2192")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return "", fmt.Errorf("no source name in comment %q", comment)
	}
	return name, nil
}

// commonName replaces the word before "MARBUTA" with "TAA", the common name
// of the letter: the misspell linter rejects the word of the Unicode name. It
// reports whether it changed the name.
func commonName(name string) (string, bool) {
	words := strings.Fields(name)
	changed := false
	for i := 0; i+1 < len(words); i++ {
		if words[i+1] == "MARBUTA" && words[i] != "TAA" {
			words[i] = "TAA"
			changed = true
		}
	}
	return strings.Join(words, " "), changed
}

// estimatedSymbol is U+212E ESTIMATED SYMBOL, the one symbol of skeletonTable.
const estimatedSymbol = '\u212E'

// genSkeletonTable returns the source of the skeletonTable block, with the
// rules of the comment of skeletonTable.
func genSkeletonTable(lines []tr39Line) string {
	type entry struct {
		to   rune // an ASCII letter
		tr39 bool // the target is "I" but TR39 gives "l"
		name string
	}
	table := map[rune]entry{}
	for _, l := range lines {
		r := l.from
		if r <= unicode.MaxASCII || !isASCIILetterRune(l.to[0]) {
			continue
		}
		if slices.ContainsFunc(l.to[1:], func(m rune) bool { return !unicode.Is(unicode.Mn, m) }) {
			continue // a rune after the letter that is not an Mn mark
		}
		if !unicode.IsLetter(r) && !unicode.Is(unicode.Mc, r) && r != estimatedSymbol {
			continue
		}
		if unicode.Is(unicode.Han, r) {
			continue
		}
		if f := foldMarks(string(r)); f != "" && isASCII(f) {
			continue // the fold maps it to ASCII already
		}
		e := entry{to: l.to[0], name: l.name}
		if e.to == 'l' && (unicode.IsUpper(r) || r == latinILonga) {
			e.to, e.tr39 = 'I', true
		}
		table[r] = e
	}
	// Drop a rune whose fold is one other rune of the table with the same
	// target: foldSkeleton maps the fold.
	keep := map[rune]entry{}
	for r, e := range table {
		f := []rune(foldMarks(string(r)))
		if len(f) == 1 && f[0] != r {
			if g, ok := table[f[0]]; ok && g.to == e.to {
				continue
			}
		}
		keep[r] = e
	}

	var b strings.Builder
	b.WriteString("var skeletonTable = [...]confusable{\n")
	for _, r := range slices.Sorted(maps.Keys(keep)) {
		e := keep[r]
		name, common := commonName(e.name)
		switch {
		case common:
			name += " (common name: misspell rejects the Unicode name)"
		case e.tr39:
			name += " (TR39: l)"
		case unicode.Is(unicode.Mc, r):
			name += " (spacing mark)"
		}
		fmt.Fprintf(&b, "\t{0x%04X, '%c'}, // %s\n", r, e.to, name)
	}
	b.WriteString("}\n")
	return b.String()
}

// genEdgeLookalikes returns the source of the edgeLookalikes block, with the
// rules of the comment of edgeLookalikes.
func genEdgeLookalikes(t *testing.T, lines []tr39Line) string {
	t.Helper()
	isEdgeLetter := func(r rune) bool {
		i := scriptOf(r)
		return unicode.IsLetter(r) && i >= 0 && lookalikeScripts[i].tier == edgeTier
	}
	tr39 := map[rune][]rune{}
	for _, l := range lines {
		tr39[l.from] = l.to
	}

	// The first group: TR39 maps the letter to one Latin letter, alone or
	// followed only by Mn marks or U+0674.
	first := map[rune]rune{} // the letter to its TR39 Latin letter
	for _, l := range lines {
		if !isEdgeLetter(l.from) || !isASCIILetterRune(l.to[0]) {
			continue
		}
		if slices.ContainsFunc(l.to[1:], func(m rune) bool { return m != arabicHighHamza && !unicode.Is(unicode.Mn, m) }) {
			continue
		}
		first[l.from] = l.to[0]
	}

	// The second group: the NFKD decomposition, with its marks and U+0674
	// removed, is one other letter of the first group.
	table := map[rune]string{} // the letter to the label of its comment
	for r, c := range first {
		table[r] = string(c)
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !isEdgeLetter(r) {
			continue
		}
		base, strict := nfkdBase(r)
		if base < 0 || base == r {
			continue
		}
		if _, ok := first[base]; !ok || twoLatinOrSpacing(tr39[r]) {
			continue
		}
		label := fmt.Sprintf("NFKD U+%04X", base)
		if l, ok := table[r]; ok && (len(tr39[r]) == 1 || !strict) {
			label = l // TR39 maps it to one letter alone, or it is no plain form
		}
		table[r] = label
	}

	names := map[rune]string{}
	for _, l := range lines {
		names[l.from] = l.name
	}
	var b strings.Builder
	b.WriteString("var edgeLookalikes = [...]rune{\n")
	for _, r := range slices.Sorted(maps.Keys(table)) {
		name, ok := names[r]
		if !ok {
			name = runenames.Name(r)
		}
		if name == "" {
			t.Errorf("no name for U+%04X", r)
		}
		name, _ = commonName(name)
		fmt.Fprintf(&b, "\t0x%04X, // %s: %s\n", r, name, table[r])
	}
	b.WriteString("}\n")
	return b.String()
}

// nfkdBase returns the one rune that is left of the NFKD decomposition of r
// when its marks (Mn, Mc and Me) and U+0674 are removed, or -1 when no rune
// or more than one is left. strict is true when the marks alone leave that
// one rune, so the decomposition holds no U+0674.
func nfkdBase(r rune) (base rune, strict bool) {
	var rest []rune
	strict = true
	for _, d := range norm.NFKD.String(string(r)) {
		switch {
		case unicode.In(d, unicode.Mn, unicode.Mc, unicode.Me):
		case d == arabicHighHamza:
			strict = false
		default:
			rest = append(rest, d)
		}
	}
	if len(rest) != 1 {
		return -1, false
	}
	return rest[0], strict
}

// twoLatinOrSpacing reports whether the TR39 target to holds two or more
// ASCII letters, such as "ol" for U+1EE64, or an ASCII letter and a spacing
// mark (Mc), such as "o" + U+102C for U+1010. edgeLookalikes leaves out such
// a letter.
func twoLatinOrSpacing(to []rune) bool {
	letters, spacing := 0, false
	for _, r := range to {
		if isASCIILetterRune(r) {
			letters++
		}
		spacing = spacing || unicode.Is(unicode.Mc, r)
	}
	return letters >= 2 || (letters == 1 && spacing)
}

// isASCIILetterRune reports whether r is a-z or A-Z.
func isASCIILetterRune(r rune) bool {
	return 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z'
}

// checkGenBlock compares the generated block gen with the block of file that
// starts with header and ends at the first "}" line. With -update it writes
// gen into file instead.
func checkGenBlock(t *testing.T, file, header, gen string) {
	t.Helper()
	// The root keeps the read and the write in the package directory.
	root, err := os.OpenRoot(".")
	if err != nil {
		t.Fatalf("open the package directory: %v", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Errorf("close the package directory: %v", err)
		}
	}()
	src, err := root.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	start := bytes.Index(src, []byte(header))
	if start < 0 {
		t.Fatalf("%s has no line %q", file, strings.TrimSpace(header))
	}
	n := bytes.Index(src[start:], []byte("\n}\n"))
	if n < 0 {
		t.Fatalf("%s: no end of the block %q", file, strings.TrimSpace(header))
	}
	end := start + n + len("\n}\n")
	got := string(src[start:end])

	formatted, err := format.Source([]byte("package rules\n\n" + gen))
	if err != nil {
		t.Fatalf("format the generated block of %s: %v", file, err)
	}
	want := strings.TrimPrefix(string(formatted), "package rules\n\n")
	if got == want {
		return
	}
	if !*update {
		t.Errorf("the block %q of %s is not the generated one (run with -update to rewrite it). Diff, with line numbers in the block:\n%s",
			strings.TrimSpace(header), file, udiff.Unified(file+" (committed)", file+" (generated)", got, want))
		return
	}
	out := slices.Concat(src[:start], []byte(want), src[end:])
	out, err = format.Source(out)
	if err != nil {
		t.Fatalf("format %s: %v", file, err)
	}
	if err := root.WriteFile(file, out, 0o600); err != nil {
		t.Fatalf("write %s: %v", file, err)
	}
	t.Logf("rewrote the block %q of %s", strings.TrimSpace(header), file)
}
