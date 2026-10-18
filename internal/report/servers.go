package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// emptyServers is the line that WriteServers prints when there is no server.
const emptyServers = "No MCP servers found.\n"

// Caps on the padded columns, in runes of raw text.
//
// Why: tabwriter pads every row of a column to the widest cell. A config file
// is untrusted and its names and paths have no length limit. One very long
// cell plus many short rows would make the output as large as the long cell
// times the row count. A cap on every padded column bounds that amplification.
//
// The bound: a file can hold at most 10,000 servers, and auto-discovery reads
// up to 5 files, so the table has at most 50,000 rows. A padded row is at most
// 3 x (80+1) + 2 x (256+1) runes plus 5 x 3 bytes of padding, about 770 bytes
// for ASCII text ("+1" is the cut marker). So the padding stays near 40 MB in
// the worst case. Multi-byte runes and escaping make a cell longer (a control
// character becomes up to 10 bytes), so hostile text can reach a few hundred
// MB. That is still bounded, and a real config is far from it.
const (
	// maxNameRunes is the cap for NAME, CLIENT and TRANSPORT.
	maxNameRunes = 80

	// maxPathRunes is the cap for SCOPE and SOURCE, which hold file paths. 256
	// keeps a real path readable, so the reader can see which file a server came
	// from. A normal macOS temporary path or a deep project path is longer than
	// 80 runes.
	maxPathRunes = 256
)

// cutMarker ends a padded cell that was cut. It is added after escaping, so
// escaping never removes it and a cut cell always shows it. Content can also
// contain "…", so a cell that ends with it is not always cut; it can never
// hide text, though.
const cutMarker = "\u2026"

// WriteServers writes the server table to w, or the line "No MCP servers
// found." when servers is empty. Rows keep the order of servers.
//
// The columns are:
//
//	NAME          the server name in the config
//	CLIENT        the client whose config declared the server
//	SCOPE         "global", or "project:" and the project path
//	TRANSPORT     stdio, http or sse
//	SOURCE        the config file that declared the server
//	COMMAND/URL   the command line for stdio, the redacted URL for http and sse
//
// Every cell goes through [Escape]. Config files are untrusted, so a cell can
// hold terminal escape sequences, bidi characters or invalid UTF-8. A cell
// also must not hold a tab or a newline, because tabwriter uses the tab as the
// column separator and the newline as the row separator. Escape quotes such a
// cell, so the table keeps its shape.
//
// The padded columns are cut and a cut cell ends with "…". NAME, CLIENT and
// TRANSPORT are cut at 80 runes. SCOPE and SOURCE hold paths and are cut at 256
// runes. The cut is made on the raw text, before escaping, so an escaped cell
// can be longer than the cap. These limits stop padding amplification: see
// maxNameRunes and maxPathRunes. COMMAND/URL is the last column. tabwriter does
// not pad it, so it cannot amplify, and it is never cut. So no argument is
// hidden from a security review.
//
// WriteServers never reads Env or Headers values. It does not call Reveal on
// any value. The URL cell uses URL.String, which removes credentials.
//
// The table has no colour. The full coloured report comes in milestone M6.
//
// WriteServers returns the first write error, or the error of the final flush.
// Callers must check it: a failed write (for example a closed pipe) has to
// become exit code 2 in cmd/mcpmoat, and not look like a clean scan.
func WriteServers(w io.Writer, servers []discover.Server) error {
	if len(servers) == 0 {
		_, err := io.WriteString(w, emptyServers)
		return err
	}

	// minwidth 0, tabwidth 0, padding 3, pad with spaces, no flags. Each cell
	// ends with a tab, except the last cell in a row.
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

	write("NAME\tCLIENT\tSCOPE\tTRANSPORT\tSOURCE\tCOMMAND/URL\n")
	for _, s := range servers {
		write("%s\t%s\t%s\t%s\t%s\t%s\n",
			cell(s.Name, maxNameRunes),
			cell(string(s.Client), maxNameRunes),
			scopeCell(s),
			cell(string(s.Transport), maxNameRunes),
			cell(s.Source, maxPathRunes),
			commandCell(s),
		)
	}

	if err := tw.Flush(); firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// cell returns the text of one padded column cell: s cut at limit runes and
// escaped. A cut cell ends with "…", which is added after escaping.
func cell(s string, limit int) string {
	short, cut := cutRunes(s, limit)
	if cut {
		return Escape(short) + cutMarker
	}
	return Escape(short)
}

// cutRunes returns s cut to at most limit runes, and whether it cut anything.
// For invalid UTF-8 there are no reliable runes, so it cuts at limit bytes. That
// is fine: Escape quotes such a string anyway.
func cutRunes(s string, limit int) (string, bool) {
	if !utf8.ValidString(s) {
		if len(s) > limit {
			return s[:limit], true
		}
		return s, false
	}
	n := 0
	// Ranging over a string gives the byte index of each rune.
	for i := range s {
		if n == limit {
			return s[:i], true
		}
		n++
	}
	return s, false
}

// scopeCell returns the SCOPE cell for s.
func scopeCell(s discover.Server) string {
	if s.Scope == discover.ScopeProject {
		return cell("project:"+s.ProjectPath, maxPathRunes)
	}
	return cell(string(s.Scope), maxPathRunes)
}

// commandCell returns the escaped COMMAND/URL cell for s.
func commandCell(s discover.Server) string {
	if s.Transport.IsRemote() {
		// URL.String gives the redacted URL. Credentials never reach the table.
		return Escape(s.URL.String())
	}
	// stdio, and any unknown transport (defensive): show the command line.
	return Command(s.Command, s.Args)
}

// Command formats a command and its arguments for one table cell.
//
// Each part is escaped with [Escape]. A part that is empty or holds a space is
// also wrapped in double quotes (strconv.Quote), so the reader can still see
// where one argument ends and the next one starts. Parts are joined with one
// space. Nothing is cut: Command is used for the last column, which is never
// cut.
func Command(command string, args []string) string {
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, command)
	parts = append(parts, args...)

	for i, p := range parts {
		escaped := Escape(p)
		// If Escape changed the part, it is already quoted. Quote only a safe
		// part that would otherwise blur the argument boundaries.
		if escaped == p && (p == "" || strings.Contains(p, " ")) {
			escaped = strconv.Quote(p)
		}
		parts[i] = escaped
	}
	return strings.Join(parts, " ")
}
