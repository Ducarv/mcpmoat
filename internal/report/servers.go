package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
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
// 4 x (80+3) + 2 x (256+3) runes, plus 12 for the untrusted marker of SCOPE,
// plus 6 x 3 bytes of padding: about 880 bytes for ASCII text ("+3" is the cut
// marker). So the padding stays near 45 MB in the worst case. Multi-byte runes
// and escaping make a cell longer (a control character becomes up to 10
// bytes), so hostile text can reach a few hundred MB. That is still bounded,
// and a real config is far from it.
const (
	// maxShortCellRunes is the cap for the short cells: NAME, CLIENT,
	// TRANSPORT and STATE. 80 runes is more than any real server name, client,
	// transport or state needs.
	maxShortCellRunes = 80

	// maxPathRunes is the cap for SCOPE and SOURCE, which hold file paths. 256
	// keeps a real path readable, so the reader can see which file a server came
	// from. A normal macOS temporary path or a deep project path is longer than
	// 80 runes.
	maxPathRunes = 256
)

// untrustedMarker follows the SCOPE cell of a server from a project file
// (discover.Server.Untrusted), which a cloned repository can ship. It is added
// after the cut and the quoting, so it is never cut or escaped.
const untrustedMarker = " (untrusted)"

// WriteServers writes the server table to w, or the line "No MCP servers
// found." when servers is empty. Rows keep the order of servers.
//
// The columns are:
//
//	NAME          the server name in the config
//	CLIENT        the client whose config declared the server
//	SCOPE         "global", or "project:" and the project path; a server
//	              from a project file also shows " (untrusted)"
//	TRANSPORT     stdio, http or sse
//	STATE         enabled, disabled, unapproved or project-approved
//	              (discover.State.String); "unknown" for any other value
//	SOURCE        the config file that declared the server
//	COMMAND/URL   the redacted command line for stdio (see
//	              formatCommand), the redacted URL for http and sse
//
// Every cell goes through [termsafe.Quote]. Config files are untrusted, so a
// cell can hold terminal escape sequences, bidi characters or invalid UTF-8.
// A cell also must not hold a tab or a newline, because tabwriter uses the
// tab as the column separator and the newline as the row separator.
// termsafe.Quote quotes such a cell, so the table keeps its shape.
//
// The padded columns (all but COMMAND/URL) go through cell. It cuts them with
// [termsafe.Cut], and a cut cell ends with [termsafe.CutMarker]. NAME,
// CLIENT, TRANSPORT and STATE are cut at 80 runes. SCOPE and SOURCE hold paths and
// are cut at 256 runes, and an invalid UTF-8 byte counts as one rune. The cut
// is made on the raw text, before escaping, so an escaped cell can be longer
// than the cap. These limits stop padding amplification: see
// maxShortCellRunes and maxPathRunes. A padded cell that holds an ASCII space
// is also quoted, so a space cannot look like a column gap. COMMAND/URL is
// the last column. tabwriter does not pad it, so it cannot amplify, and it is
// never cut. So no argument is hidden from a security review.
//
// WriteServers never prints a value as written from Args, Env, Headers or
// URL. It never reads Env or Headers values and never calls Reveal. The
// COMMAND/URL cell shows the command and the args through the
// discover.RedactArgs allowlist (see formatCommand), and the URL through
// URL.String, which removes credentials.
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

	write("NAME\tCLIENT\tSCOPE\tTRANSPORT\tSTATE\tSOURCE\tCOMMAND/URL\n")
	for _, s := range servers {
		write("%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			cell(s.Name, maxShortCellRunes),
			cell(string(s.Client), maxShortCellRunes),
			scopeCell(s),
			cell(string(s.Transport), maxShortCellRunes),
			// The state text is a fixed mcpmoat string, but it goes through
			// cell like every padded cell.
			cell(s.State.String(), maxShortCellRunes),
			cell(s.Source, maxPathRunes),
			commandCell(s),
		)
	}

	if err := tw.Flush(); firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// cell returns the text of one padded column cell: s cut at limit runes with
// [termsafe.Cut], escaped, and ended with [termsafe.CutMarker] when it was
// cut. This is the order of [termsafe.QuoteCut]: cut, quote, marker.
//
// cell adds one report rule on top of termsafe: a cell that holds an ASCII
// space is quoted too ([termsafe.QuoteIf] with force). tabwriter pads with
// spaces, so a name such as "a   b" would otherwise look like two cells.
// termsafe.Quote keeps such a text as it is, because a space is safe in a
// message line. Only the shown part counts: a space after the cut does not
// make the cell quoted. CLIENT, TRANSPORT and STATE hold fixed values
// without a space, so the rule changes only NAME, SCOPE and SOURCE.
func cell(s string, limit int) string {
	short, cut := termsafe.Cut(s, limit)
	c := termsafe.QuoteIf(short, strings.Contains(short, " "))
	if cut {
		c += termsafe.CutMarker
	}
	return c
}

// scopeCell returns the SCOPE cell for s. For an untrusted server,
// untrustedMarker comes after the cut and quoted text.
func scopeCell(s discover.Server) string {
	text := string(s.Scope)
	if s.Scope == discover.ScopeProject {
		text = "project:" + s.ProjectPath
	}
	c := cell(text, maxPathRunes)
	if s.Untrusted {
		c += untrustedMarker
	}
	return c
}

// commandCell returns the escaped COMMAND/URL cell for s.
func commandCell(s discover.Server) string {
	if s.Transport.IsRemote() {
		// URL.String gives the redacted URL. Credentials never reach the table.
		return termsafe.Quote(s.URL.String())
	}
	// stdio, and any unknown transport (defensive): show the command line.
	return formatCommand(s.Command, s.Args)
}

// formatCommand formats the COMMAND/URL cell of a stdio server: a command
// and its arguments, as one table cell. It never shows an argument as
// written: the command and the args go through [discover.RedactArgs]
// together, as one command line. RedactArgs is an allowlist that fails
// closed, so every part with a shape that is not known to be safe shows as
// [discover.Mask]. The command goes through it too: Server.Command is plain
// text from an untrusted config, and the allowlist also stops a token in the
// command path. Because the command is the first part, a command that looks
// like a secret flag also masks the next part.
//
// Each redacted part is escaped with [termsafe.QuoteIf]. A part that is empty
// or holds a space is quoted even when it is safe, so the reader can still
// see where one argument ends and the next one starts.
// Parts are joined with one space. Nothing is cut: the COMMAND/URL cell is
// the last column, which is never cut.
func formatCommand(command string, args discover.Args) string {
	parts := redactedArgv(command, args)
	for i, p := range parts {
		parts[i] = termsafe.QuoteIf(p, p == "" || strings.Contains(p, " "))
	}
	return strings.Join(parts, " ")
}

// redactedArgv returns the command line of a stdio server as a list of parts,
// with the command first. The command and the args go through
// [discover.RedactArgs] together, so every part with an unknown shape is
// [discover.Mask]. Only this redacted form may reach a report.
func redactedArgv(command string, args discover.Args) []string {
	// Values gives the args as written. They go straight into RedactArgs and
	// nowhere else. Args.String is not enough here: it joins the parts with a
	// space, so an empty part would not show.
	return discover.RedactArgs(append([]string{command}, args.Values()...))
}
