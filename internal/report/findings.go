package report

import (
	"io"
	"strconv"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// emptyCell is what the report prints for a field with no text.
const emptyCell = "-"

// Caps on the rule text of a finding, in runes of raw text. A rule is a YAML
// file in rules/ and its text is one sentence, so a real rule is far below
// these caps. They stop a rule file with a huge text from flooding the screen.
const (
	maxTitleRunes    = 200
	maxRuleTextRunes = 500
)

// severityOrder lists the severity words in the order of the groups of
// WriteFindings: the worst first. A row with any other severity word goes to
// the first group, "critical" (fail closed, like findingSeverity in
// cmd/mcpmoat).
var severityOrder = []string{"critical", "high", "medium", "low"}

// ServerRef names one server and says which config it comes from. Two servers
// can have the same name in two clients or two scopes, so the name alone does
// not tell them apart. FindingRow and ServerStatus embed ServerRef, and both
// print it as "name (client, scope)".
//
// All strings come from untrusted config files. The report escapes and cuts
// them.
type ServerRef struct {
	// Name is the server name in the config.
	Name string
	// Client is the client whose config declared the server.
	Client discover.Client
	// Scope is discover.ScopeGlobal or discover.ScopeProject.
	Scope discover.Scope
	// ProjectPath is the project path of a server with project scope. It is
	// empty for a global server.
	ProjectPath string
	// Untrusted is true for a server from a project file, which a cloned
	// repository can ship (discover.Server.Untrusted).
	Untrusted bool
}

// NewServerRef returns the ServerRef of s.
func NewServerRef(s discover.Server) ServerRef {
	return ServerRef{
		Name:        s.Name,
		Client:      s.Client,
		Scope:       s.Scope,
		ProjectPath: s.ProjectPath,
		Untrusted:   s.Untrusted,
	}
}

// label returns the escaped text "name (client, scope)". The scope is the
// SCOPE cell of WriteServers: "global", or "project:" and the path, and then
// " (untrusted)" for an untrusted server. Name and client are cut at
// maxShortCellRunes and the path at maxPathRunes, so a hostile config cannot
// flood the screen.
func (r ServerRef) label() string {
	return findingCell(r.Name) + " (" + findingCell(string(r.Client)) + ", " +
		scopeCell(r.Scope, r.ProjectPath, r.Untrusted) + ")"
}

// FindingRow is one finding as the report prints it. It holds names and the
// text of the rule, never a value from a config. The caller fills Severity,
// Title, Risk and Remediation from the rule set, because this package does not
// know the rules.
type FindingRow struct {
	// ServerRef is the server that the finding is about.
	ServerRef

	// RuleID is the ID of the rule that matched.
	RuleID string
	// Severity is the severity word of the rule: "critical", "high", "medium"
	// or "low". Any other word is shown in the group "critical".
	Severity string
	// Title is the short title of the rule. WriteFindings leaves it out when
	// it is empty.
	Title string
	// Risk says why the finding matters. It is the text of the rule.
	Risk string
	// Remediation says how to fix the finding. It is the text of the rule.
	Remediation string

	// Field is the config field that matched, for example "env" or "args". A
	// pin row has the field "tool" and the tool name in Key.
	Field string
	// Key is the key name in Field, for example an env variable name.
	Key string
	// Related is a second name that the finding refers to, for example a
	// second server, or a fixed reason text. WriteFindings shows it alone when
	// Key is empty, and as "<key> (<related>)" when Key is set too.
	Related string
}

// fieldTool is the Field of a row about a tool (see rules.FieldTool). This
// package does not import rules, so it has its own copy of the word.
const fieldTool = "tool"

// WriteFindings writes the findings to w, in groups by severity. When rows is
// empty it writes nothing and returns nil. Otherwise it writes one blank line,
// the heading "FINDINGS" and then one group for each severity that has rows,
// from "critical" to "low". A row with an unknown severity word goes to the
// "critical" group. Inside a group, rows keep their input order.
//
// A group starts with the severity word in capitals and the row count, for
// example "HIGH (2)". Each finding is a block of lines:
//
//	MOAT-T4-001  <title>
//	  Server: github (claude-code, global)
//	  Where: env FOO
//	  Risk: <risk>
//	  Fix: <remediation>
//
// The title is left out when it is empty. Server is "name (client, scope)", so
// two servers with the same name in two scopes read differently (see
// ServerRef). Where is "<field> <key> (<related>)"; a missing part is left
// out, and the whole line is left out when Field, Key and Related are all
// empty. A row with the field "tool" has a line "Tool: <name>" in place of
// Where. An empty Risk or Remediation shows as "-".
//
// Names go through findingCell, so each is escaped, cut and quoted alone. Title,
// Risk and Remediation go through [termsafe.QuoteCut]: a rule file can hold
// control characters. WriteFindings prints only names and rule text. It never
// prints a value, a URL, an arg or a finding message. This follows the project
// rule to print keys only.
//
// The Style only colours the heading and the group lines, after the escape.
//
// WriteFindings builds the whole text first and writes it with one call, so it
// returns the first write error. Callers must check it: a failed write has to
// become exit code 2 in cmd/mcpmoat, and not look like a clean scan.
func WriteFindings(w io.Writer, rows []FindingRow, st Style) error {
	if len(rows) == 0 {
		return nil
	}

	// Sort the rows into groups. Appending keeps the input order inside a
	// group.
	groups := make(map[string][]FindingRow, len(severityOrder))
	for _, r := range rows {
		sev := r.Severity
		if sev != "high" && sev != "medium" && sev != "low" {
			sev = "critical"
		}
		groups[sev] = append(groups[sev], r)
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(st.heading("FINDINGS"))
	b.WriteString("\n")

	for _, sev := range severityOrder {
		group := groups[sev]
		if len(group) == 0 {
			continue
		}
		b.WriteString(st.severity(sev, strings.ToUpper(sev)+" ("+strconv.Itoa(len(group))+")"))
		b.WriteString("\n")
		for _, r := range group {
			writeFinding(&b, r)
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// writeFinding writes the block of lines of one finding to b.
func writeFinding(b *strings.Builder, r FindingRow) {
	b.WriteString("  ")
	b.WriteString(findingCell(r.RuleID))
	if r.Title != "" {
		b.WriteString("  ")
		b.WriteString(termsafe.QuoteCut(r.Title, maxTitleRunes))
	}
	b.WriteString("\n    Server: ")
	b.WriteString(r.label())
	b.WriteString("\n")

	switch {
	case r.Field == fieldTool:
		b.WriteString("    Tool: ")
		b.WriteString(keyRelatedCell(r.Key, r.Related))
		b.WriteString("\n")
	case r.Field != "" || r.Key != "" || r.Related != "":
		where := make([]string, 0, 2)
		if r.Field != "" {
			where = append(where, findingCell(r.Field))
		}
		if r.Key != "" || r.Related != "" {
			where = append(where, keyRelatedCell(r.Key, r.Related))
		}
		b.WriteString("    Where: ")
		b.WriteString(strings.Join(where, " "))
		b.WriteString("\n")
	}

	b.WriteString("    Risk: ")
	b.WriteString(ruleText(r.Risk))
	b.WriteString("\n    Fix: ")
	b.WriteString(ruleText(r.Remediation))
	b.WriteString("\n")
}

// ruleText returns the escaped and cut text of a rule field, or emptyCell
// when s is empty.
func ruleText(s string) string {
	if s == "" {
		return emptyCell
	}
	return termsafe.QuoteCut(s, maxRuleTextRunes)
}

// findingCell returns one name of a finding line: emptyCell for an empty
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

// keyRelatedCell returns the KEY/RELATED cell. With both key and related set
// it is "<key> (<related>)", and each part goes through findingCell. With one
// part set, it is that part. With none, it is emptyCell.
func keyRelatedCell(key, related string) string {
	if key != "" && related != "" {
		return findingCell(key) + " (" + findingCell(related) + ")"
	}
	if key == "" {
		return findingCell(related)
	}
	return findingCell(key)
}
