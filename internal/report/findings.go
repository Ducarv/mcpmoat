package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// emptyCell is what WriteFindings prints for a cell with no text.
const emptyCell = "-"

// FindingRow is one config finding as the report prints it. It holds only
// names: rule IDs, a severity, a server name, a field name and a key name. It
// holds no value and no message. The caller fills Severity from the rule set,
// because this package does not know the rules.
type FindingRow struct {
	// RuleID is the ID of the rule that matched.
	RuleID string
	// Severity is the severity word of the rule, for example "high".
	Severity string
	// Server is the name of the server that the finding is about.
	Server string
	// Field is the config field that matched, for example "env" or "args".
	Field string
	// Key is the key name in Field, for example an env variable name.
	Key string
	// Related is a second name that the finding refers to, for example a
	// second server. WriteFindings shows it only when Key is empty.
	Related string
}

// WriteFindings writes the findings table to w. When rows is empty it writes
// nothing and returns nil. Otherwise it writes one blank line and then a table
// with one row per element of rows, in the given order.
//
// The columns are:
//
//	RULE          the rule ID
//	SEVERITY      the severity word
//	SERVER        the server name
//	FIELD         the config field
//	KEY/RELATED   Key when it is set, else Related, else "-"
//
// Any other empty cell shows "-". A name that is exactly "-" shows as "\"-\"".
//
// WriteFindings prints only rule IDs, severities, server names, field names
// and key names. It never prints a value, a URL, an arg or a finding message.
// This follows the project rule to print keys only.
//
// Every cell goes through cell, like the cells of WriteServers. Names come
// from untrusted config files, so cell escapes them and cuts them at
// maxShortCellRunes. The cut stops padding amplification: see
// maxShortCellRunes.
//
// WriteFindings returns the first write error, or the error of the final
// flush. Callers must check it: a failed write has to become exit code 2 in
// cmd/mcpmoat, and not look like a clean scan.
func WriteFindings(w io.Writer, rows []FindingRow) error {
	if len(rows) == 0 {
		return nil
	}

	// The blank line separates the table from the output before it.
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}

	// Same settings as WriteServers: minwidth 0, tabwidth 0, padding 3, pad
	// with spaces, no flags. Each cell ends with a tab, except the last cell in
	// a row.
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)

	// tabwriter buffers its output, so most write errors show only at Flush.
	// Keep the first error anyway and skip later writes after it.
	var firstErr error
	write := func(format string, args ...any) {
		if firstErr != nil {
			return
		}
		_, firstErr = fmt.Fprintf(tw, format, args...)
	}

	write("RULE\tSEVERITY\tSERVER\tFIELD\tKEY/RELATED\n")
	for _, r := range rows {
		keyOrRelated := r.Key
		if keyOrRelated == "" {
			keyOrRelated = r.Related
		}
		write("%s\t%s\t%s\t%s\t%s\n",
			findingCell(r.RuleID),
			findingCell(r.Severity),
			findingCell(r.Server),
			findingCell(r.Field),
			findingCell(keyOrRelated),
		)
	}

	if err := tw.Flush(); firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// findingCell returns one cell of the findings table: emptyCell for an empty
// s, else s through cell with the short cell cap. A name that is exactly
// emptyCell is quoted, so it does not read as an empty cell.
func findingCell(s string) string {
	switch s {
	case "":
		return emptyCell
	case emptyCell:
		return termsafe.QuoteIf(s, true)
	}
	return cell(s, maxShortCellRunes)
}
