package report

import (
	"io"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// maxDiffLineRunes is the cap for the text of one diff line, in runes of raw
// text, not counting the prefix. A tool description or schema comes from a
// server and has no length limit, and one line of it can be very long. The cap
// stops one line from flooding the terminal. It is larger than the cap of a
// table cell on purpose: a diff is how a reviewer reads what a server changed,
// so a real description line should show in full. A cut line ends with
// [termsafe.CutMarker], so a cut is never silent.
const maxDiffLineRunes = 2000

// diffPrefixes lists the prefixes of a unified diff line that WriteDiffs keeps
// outside the escape. The longer prefixes come first, so "@@", "---" and "+++"
// win over the single character "-" and "+".
var diffPrefixes = []string{"@@", "---", "+++", "+", "-", " "}

// noDiffNote is the line that WriteDiffs writes under the header of a tool
// whose Diff has no content. It is a fixed text and never comes from a server.
// It tells the reviewer that the tool changed and that no diff text is
// available, so an empty diff is not mistaken for an error in the report.
const noDiffNote = "  (no diff text available)"

// ToolDiff is the unified diff of one changed, new or not verified tool, as the
// report prints it. The caller builds Diff from the pinned tool and the tool
// that the server offers now.
type ToolDiff struct {
	// Server is the name of the server that offers the tool.
	Server string
	// Tool is the name of the tool.
	Tool string
	// Diff is the unified diff text. Each line starts with "---", "+++",
	// "@@", "+", "-" or " ", or it is a marker line such as
	// "\ No newline at end of file". Lines end with "\n". The text comes from a
	// server, so WriteDiffs escapes it. When Diff is empty or holds only
	// whitespace, WriteDiffs writes a fixed note in its place.
	Diff string
	// Kind says what the diff shows, and so its header. The zero value is
	// DiffChanged.
	Kind DiffKind
	// Truncated is true when the stored diff was cut, so Diff is not the whole
	// diff. WriteDiffs does not use it. The JSON report shows it.
	Truncated bool
}

// DiffKind is the kind of tool that a ToolDiff shows.
type DiffKind int

// The kinds of ToolDiff.
const (
	// DiffChanged is a changed tool: the diff of the pinned and the current
	// text.
	DiffChanged DiffKind = iota
	// DiffNew is a tool that is new on a pinned server: the server offers it,
	// but the pins do not hold it. Its Diff has only added lines.
	DiffNew
	// DiffUnverified is a pinned tool whose pin cannot be checked (see
	// pins.Change.Diff). Its Diff has only added lines: the whole current
	// tool.
	DiffUnverified
)

// String returns the fixed name of k: "changed", "new" or "unverified". The
// JSON report uses these names. They are a stable contract. Any other value
// gives "unknown".
func (k DiffKind) String() string {
	switch k {
	case DiffChanged:
		return "changed"
	case DiffNew:
		return "new"
	case DiffUnverified:
		return "unverified"
	default:
		return "unknown"
	}
}

// WriteDiffs writes one unified diff for each element of diffs to w, in the
// given order. When diffs is empty it writes nothing and returns nil.
//
// Each diff starts with one blank line and a header line:
//
//	Changed tool <tool> on server <server>:
//
// When Kind is DiffNew, the header says that the tool is new:
//
//	New tool <tool> on server <server>:
//
// When Kind is DiffUnverified, the header says that the diff is the current
// text:
//
//	Not verified tool <tool> on server <server> (current text):
//
// The diff lines follow, one output line for each line of Diff.
//
// When Diff is empty, or holds only whitespace and newlines, the reviewer would
// see a changed tool with no content. So WriteDiffs writes one fixed note line
// under the header instead of diff lines. The line is two spaces and the text
// "(no diff text available)". The note is a constant of this package. It is
// never server text.
//
// The tool and server names go through findingCell, like the cells of
// WriteFindings: an empty name shows as "-", and a name is escaped and cut at
// maxShortCellRunes.
//
// The text of a diff comes from untrusted servers: it is the first place where
// a tool description reaches the terminal. Each line is split in two parts. The
// leading unified prefix ("@@", "---", "+++", "+", "-" or " ") is written as it
// is, so the diff keeps its shape. The rest of the line goes through
// [termsafe.QuoteCut] with the cap maxDiffLineRunes. So a control character,
// an ANSI escape sequence, a bidi override, a zero-width character and
// invalid UTF-8 show as visible escapes such as \x1b or U+202E, and never
// reach the terminal raw.
//
// termsafe.QuoteCut keeps a safe text as it is, and it writes an unsafe text
// as a quoted Go string. So a clean line reads like a normal diff line, and an
// escaped line shows its quotes, which tell the reader that escaping happened.
// A line whose text starts with a double quote is quoted too: this is the rule
// of termsafe.Quote, which keeps a plain text from looking like a quoted one.
//
// A line with an unknown prefix (a marker line) has no part that is kept
// outside the escape: the whole line goes through termsafe.QuoteCut. An empty
// line is written as an empty line. The final newline of Diff does not make an
// extra line. A "\r" is not a line end: it is escaped like any control
// character.
//
// WriteDiffs returns the first write error. Callers must check it: a failed
// write has to become exit code 2 in cmd/mcpmoat, and not look like a clean
// scan.
func WriteDiffs(w io.Writer, diffs []ToolDiff) error {
	for _, d := range diffs {
		var b strings.Builder

		// The blank line separates the diff from the output before it.
		switch d.Kind {
		case DiffNew:
			b.WriteString("\nNew tool ")
		case DiffUnverified:
			b.WriteString("\nNot verified tool ")
		default:
			b.WriteString("\nChanged tool ")
		}
		b.WriteString(findingCell(d.Tool))
		b.WriteString(" on server ")
		b.WriteString(findingCell(d.Server))
		if d.Kind == DiffUnverified {
			b.WriteString(" (current text)")
		}
		b.WriteString(":\n")

		if strings.TrimSpace(d.Diff) == "" {
			// No content: write the fixed note, so the header does not stand alone.
			b.WriteString(noDiffNote)
			b.WriteByte('\n')
		} else {
			// A final newline ends the last line. It does not start a new one.
			text := strings.TrimSuffix(d.Diff, "\n")
			for line := range strings.SplitSeq(text, "\n") {
				b.WriteString(diffLine(line))
				b.WriteByte('\n')
			}
		}

		// One write for each diff, so a failed write stops at a diff boundary
		// and the first error is the one we return.
		if _, err := io.WriteString(w, b.String()); err != nil {
			return err
		}
	}
	return nil
}

// diffLine returns one escaped line of a diff, without the newline. It keeps
// the unified prefix as it is and escapes and cuts the rest. A line with no
// known prefix is escaped as a whole.
func diffLine(line string) string {
	for _, p := range diffPrefixes {
		if rest, ok := strings.CutPrefix(line, p); ok {
			return p + termsafe.QuoteCut(rest, maxDiffLineRunes)
		}
	}
	return termsafe.QuoteCut(line, maxDiffLineRunes)
}
