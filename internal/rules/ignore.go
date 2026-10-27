package rules

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/safefile"
)

// IgnoreFileName is the name of the ignore file (FR-10). mcpmoat scan reads it
// from the working directory only with the flag --use-ignore-file. Without the
// flag, scan does not read it. The opt-in is there because the working
// directory can be an untrusted checkout.
//
// The file is untrusted: a cloned repository can ship one. So ParseIgnore
// never fails, caps what it keeps, and its warnings never echo file content.
const IgnoreFileName = ".mcpmoat-ignore"

// Limits for the ignore file. They stop a hostile file from using all memory
// or flooding the terminal with warnings.
const (
	// MaxIgnoreFileBytes is the largest ignore file that ReadIgnoreFile
	// reads: 1 MiB.
	MaxIgnoreFileBytes = 1 << 20
	// maxIgnoreLineBytes is the longest line that ParseIgnore accepts, after
	// the "\r" of a CRLF line end is removed.
	maxIgnoreLineBytes = 4096
	// maxIgnoreEntries is the largest number of entries that ParseIgnore
	// keeps. Ignored compares a finding with each entry, so the cap also
	// bounds that cost.
	maxIgnoreEntries = 1000
	// MaxIgnoreWarnings is the largest number of malformed-line warnings
	// that ParseIgnore returns. After that, one summary warning gives the
	// number of the other malformed lines.
	MaxIgnoreWarnings = 20
)

// maxRuleIDBytes is the longest rule ID that ValidRuleID accepts.
const maxRuleIDBytes = 64

// Warning reasons. They are fixed text, so a warning never shows content of
// the untrusted file.
const (
	reasonLineTooLong    = "line too long"
	reasonInvalidUTF8    = "invalid UTF-8"
	reasonHiddenRune     = "control, invisible or non-space white-space character"
	reasonInvalidRuleID  = "invalid rule ID"
	reasonEmptyServer    = "empty server name in scope"
	reasonHashScope      = "a server name cannot start with #; put a space after # for a comment"
	reasonTooManyFields  = "too many fields (want RULE-ID [server[/tool]])"
	reasonTooManyEntries = "too many entries, the rest of the file is not read"
)

// utf8BOM is the UTF-8 byte order mark. Some Windows editors write it at the
// start of a text file.
const utf8BOM = "\xEF\xBB\xBF"

// ruleIDPattern is the syntax of a rule ID. It is compiled once and never
// changes, so it is safe to share.
var ruleIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)*$`)

// Errors that ReadIgnoreFile wraps. They hold no file content.
// errIgnoreNotRegular is safefile.ErrNotRegular, which readIgnoreData passes
// on as it is; the name only gives the tests one name per ignore error.
// errIgnoreTooLarge replaces safefile.ErrTooLarge, so the warning gives the cap.
var (
	errIgnoreNotRegular = safefile.ErrNotRegular
	errIgnoreTooLarge   = fmt.Errorf("larger than %d bytes", MaxIgnoreFileBytes)
)

// ValidRuleID reports whether id is a valid rule ID: a letter, then letters
// and digits, in groups that one '-', '_' or '.' separates (for example
// "MOAT-T1-003"). The ID has at most 64 bytes. The check is case-sensitive.
//
// The rule loader must use ValidRuleID for the ID of every rule, so a rule ID
// and an ignore entry always follow the same syntax.
func ValidRuleID(id string) bool {
	return len(id) <= maxRuleIDBytes && ruleIDPattern.MatchString(id)
}

// FindingKey is the minimal identity of a finding that the ignore list needs.
// Tool is "" for a server-level finding (for example a finding of a config
// rule).
type FindingKey struct {
	RuleID string
	Server string
	Tool   string
}

// IgnoreEntry is one entry of the ignore list: from a line of
// .mcpmoat-ignore or from one --ignore flag.
type IgnoreEntry struct {
	// RuleID is the rule to ignore. It is required.
	RuleID string
	// Server limits the entry to one server. "" means every server.
	Server string
	// Tool limits the entry to one tool of Server. "" means every tool of
	// Server and the server-level findings of Server. ParseIgnore sets Tool
	// only together with Server.
	Tool string
	// Line is the 1-based line of the entry in .mcpmoat-ignore, or 0 for an
	// entry from --ignore.
	Line int
}

// IgnoreList is the set of ignore entries. The zero value is an empty list
// that is ready to use.
type IgnoreList struct {
	entries []IgnoreEntry
}

// Add appends e to the list. Add does not check e: check e.RuleID with
// ValidRuleID first. l must not be nil.
func (l *IgnoreList) Add(e IgnoreEntry) {
	l.entries = append(l.entries, e)
}

// Len returns the number of entries in the list. A nil list has 0 entries.
func (l *IgnoreList) Len() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}

// Ignored reports whether an entry of the list matches the finding k. The
// comparison is exact and case-sensitive. An entry matches when its RuleID
// is k.RuleID, its Server is "" or k.Server, and its Tool is "" or k.Tool.
// So an entry with a Tool does not match a server-level finding (k.Tool ==
// ""). A nil list ignores nothing.
func (l *IgnoreList) Ignored(k FindingKey) bool {
	if l == nil {
		return false
	}
	for _, e := range l.entries {
		if e.RuleID != k.RuleID {
			continue
		}
		if e.Server != "" && e.Server != k.Server {
			continue
		}
		if e.Tool != "" && e.Tool != k.Tool {
			continue
		}
		return true
	}
	return false
}

// FilterIgnored splits items into the items that l does not ignore (kept, in
// the same order as in items) and the number of ignored items. key returns
// the FindingKey of one item and must not be nil. A nil list ignores nothing.
// kept is always a new slice, so a change to kept does not change items.
// FilterIgnored works on a slice of any finding type.
func FilterIgnored[T any](l *IgnoreList, items []T, key func(T) FindingKey) (kept []T, ignored int) {
	kept = make([]T, 0, len(items))
	for _, item := range items {
		if l.Ignored(key(item)) {
			ignored++
			continue
		}
		kept = append(kept, item)
	}
	return kept, ignored
}

// IgnoreWarning is a malformed line of .mcpmoat-ignore. Reason is fixed text
// from this package. It never shows content of the file.
//
// Line is 0 for the summary warning that ParseIgnore adds when there are
// more than MaxIgnoreWarnings malformed lines.
type IgnoreWarning struct {
	Line   int
	Reason string
}

// String returns the warning as ".mcpmoat-ignore:3: invalid rule ID", or
// ".mcpmoat-ignore: 5 more malformed lines" for a warning with Line 0.
func (w IgnoreWarning) String() string {
	if w.Line <= 0 {
		return fmt.Sprintf("%s: %s", IgnoreFileName, w.Reason)
	}
	return fmt.Sprintf("%s:%d: %s", IgnoreFileName, w.Line, w.Reason)
}

// ParseIgnore parses the content of a .mcpmoat-ignore file. It never fails:
// it skips a malformed line and returns a warning for it.
//
// The format:
//
//   - One entry on each line: RULE-ID [server[/tool]]. Only spaces and tabs
//     separate the fields, so a server or tool name cannot hold a space.
//   - A blank line is skipped, and so is a line whose first non-space
//     character is '#' (a comment line).
//   - After the rule ID, a field that starts with '#' starts a comment that
//     runs to the end of the line. Only in the scope position (the second
//     field) must this field be exactly "#": a scope such as "#srv" gets a
//     warning, so a missing space never makes an entry apply to every server.
//   - The scope (the second field) is split at its last '/': "srv" is every
//     tool of server srv, "srv/tool" is one tool, "a/b/c" is tool "c" of
//     server "a/b", and "a/b/" is every tool of server "a/b" (write a server
//     name that holds a '/' this way).
//   - One leading UTF-8 byte order mark is removed, and so is the "\r" of a
//     CRLF line end.
//
// A line gets a warning and is skipped when it is longer than 4096 bytes, is
// not valid UTF-8, holds a hidden rune (see hasHiddenRune; this also applies
// to a comment), has an invalid rule ID (see ValidRuleID), has a scope
// that starts with '#' but is not exactly "#", has an empty server name
// ("/tool" or "/"), or has more than two fields.
//
// ParseIgnore returns at most MaxIgnoreWarnings line warnings. When there are
// more, it adds one summary warning with Line 0. When the list has 1000
// entries and the file holds one more entry line, ParseIgnore adds one
// warning for that line (never dropped into the summary) and stops. So there
// are at most MaxIgnoreWarnings+2 warnings. warnings is nil when the file has
// no problems.
func ParseIgnore(data []byte) (IgnoreList, []IgnoreWarning) {
	var (
		list     IgnoreList
		warnings []IgnoreWarning
		dropped  int // malformed lines after the first MaxIgnoreWarnings
		limit    *IgnoreWarning
	)
	warn := func(line int, reason string) {
		if len(warnings) < MaxIgnoreWarnings {
			warnings = append(warnings, IgnoreWarning{Line: line, Reason: reason})
			return
		}
		dropped++
	}

	rest := bytes.TrimPrefix(data, []byte(utf8BOM))
	// Read line by line with bytes.Cut, not with bufio.Scanner: a Scanner
	// stops at the first line that is longer than its buffer, and a long
	// line must only skip that line.
	for lineNo := 1; len(rest) > 0; lineNo++ {
		var raw []byte
		raw, rest, _ = bytes.Cut(rest, []byte("\n"))
		raw = bytes.TrimSuffix(raw, []byte("\r"))

		if len(raw) > maxIgnoreLineBytes {
			warn(lineNo, reasonLineTooLong)
			continue
		}
		if !utf8.Valid(raw) {
			warn(lineNo, reasonInvalidUTF8)
			continue
		}

		line := string(raw)
		if hasHiddenRune(line) {
			warn(lineNo, reasonHiddenRune)
			continue
		}

		fields := withoutComment(strings.FieldsFunc(line, isIgnoreSpace))
		if len(fields) == 0 {
			continue // a blank line or a comment line
		}
		entry, reason := parseIgnoreFields(fields)
		if reason != "" {
			warn(lineNo, reason)
			continue
		}
		if list.Len() >= maxIgnoreEntries {
			limit = &IgnoreWarning{Line: lineNo, Reason: reasonTooManyEntries}
			break
		}
		entry.Line = lineNo
		list.Add(entry)
	}

	if dropped > 0 {
		warnings = append(warnings, IgnoreWarning{Reason: moreMalformedLines(dropped)})
	}
	if limit != nil {
		warnings = append(warnings, *limit)
	}
	return list, warnings
}

// hasHiddenRune reports whether s holds a rune that can hide or move text
// when the file is shown in a terminal or an editor: a control character
// other than tab (a CR in the middle of a line moves the cursor back over
// the rule ID), an invisible rune (see isInvisible) such as a bidi control,
// or white space other than space and tab.
func hasHiddenRune(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		if isIgnoreSpace(r) {
			return false
		}
		return unicode.IsControl(r) || unicode.IsSpace(r) || isInvisible(r)
	})
}

// isIgnoreSpace reports whether r separates the fields of a line: a space or
// a tab.
func isIgnoreSpace(r rune) bool {
	return r == ' ' || r == '\t'
}

// withoutComment returns fields up to the comment. The comment starts at the
// first field that starts with '#', but a scope field (index 1) starts it
// only when it is exactly "#". parseIgnoreFields refuses a scope such as
// "#srv", so a missing space cannot make a rule-wide entry.
func withoutComment(fields []string) []string {
	for i, f := range fields {
		if strings.HasPrefix(f, "#") && (i != 1 || f == "#") {
			return fields[:i]
		}
	}
	return fields
}

// parseIgnoreFields makes an entry from the fields of one line (one or more,
// without comment). It returns a warning reason, or "" when the fields are
// valid. It does not set Line.
func parseIgnoreFields(fields []string) (IgnoreEntry, string) {
	if len(fields) > 1 && strings.HasPrefix(fields[1], "#") {
		return IgnoreEntry{}, reasonHashScope
	}
	if len(fields) > 2 {
		return IgnoreEntry{}, reasonTooManyFields
	}
	if !ValidRuleID(fields[0]) {
		return IgnoreEntry{}, reasonInvalidRuleID
	}
	entry := IgnoreEntry{RuleID: fields[0]}
	if len(fields) == 1 {
		return entry, ""
	}

	scope := fields[1]
	if i := strings.LastIndexByte(scope, '/'); i >= 0 {
		entry.Server, entry.Tool = scope[:i], scope[i+1:]
	} else {
		entry.Server = scope
	}
	if entry.Server == "" {
		return IgnoreEntry{}, reasonEmptyServer
	}
	return entry, ""
}

// moreMalformedLines returns the reason of the summary warning.
func moreMalformedLines(n int) string {
	if n == 1 {
		return "1 more malformed line"
	}
	return fmt.Sprintf("%d more malformed lines", n)
}

// ReadIgnoreFile reads and parses the file IgnoreFileName in the directory
// dir (normally the working directory). mcpmoat scan calls it only with the
// flag --use-ignore-file. See ParseIgnore for the format and the warnings.
//
// When the file or dir does not exist, or dir or a parent in the path is not a
// directory, ReadIgnoreFile returns an empty list, nil warnings and a nil
// error.
//
// The read uses package safefile: a symlink that leaves dir, a file that is
// not a regular file and a file larger than MaxIgnoreFileBytes are refused
// with an error, and a FIFO does not block the scan.
//
// The errors wrap the OS error with %w. They hold the path, but never file
// content. The path comes from the caller and can hold any character, so
// escape the error text with termsafe before you print it.
func ReadIgnoreFile(dir string) (IgnoreList, []IgnoreWarning, error) {
	data, found, err := readIgnoreData(dir)
	if err != nil {
		return IgnoreList{}, nil, fmt.Errorf("read ignore file %s: %w", filepath.Join(dir, IgnoreFileName), err)
	}
	if !found {
		return IgnoreList{}, nil, nil
	}
	list, warnings := ParseIgnore(data)
	return list, warnings, nil
}

// readIgnoreData reads the ignore file in dir with safefile. found is false,
// with a nil error, when the file or dir does not exist, or dir or a parent in
// the path is not a directory. ReadIgnoreFile adds the path to the error.
func readIgnoreData(dir string) (data []byte, found bool, err error) {
	data, found, err = safefile.ReadBoundedRegularFile(dir, IgnoreFileName, MaxIgnoreFileBytes)
	switch {
	case errors.Is(err, safefile.ErrTooLarge):
		return nil, false, errIgnoreTooLarge
	case err != nil:
		return nil, false, err
	}
	return data, found, nil
}
