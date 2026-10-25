package report_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// Caps of the report package, in runes of raw text (see findings.go).
const (
	maxTitleRunes    = 200
	maxRuleTextRunes = 500
)

// plain is the Style with no colour.
var plain = report.Style{}

// globalRef is a global server of Claude Code.
func globalRef(name string) report.ServerRef {
	return report.ServerRef{Name: name, Client: discover.ClientClaudeCode, Scope: discover.ScopeGlobal}
}

// writeFindings returns the text that report.WriteFindings writes for rows.
// It fails the test if WriteFindings returns an error.
func writeFindings(t *testing.T, st report.Style, rows ...report.FindingRow) string {
	t.Helper()
	var sb strings.Builder
	if err := report.WriteFindings(&sb, rows, st); err != nil {
		t.Fatalf("WriteFindings() error = %v, want nil", err)
	}
	return sb.String()
}

// sevRow returns a minimal row with the given rule ID and severity word.
func sevRow(rule, severity string) report.FindingRow {
	return report.FindingRow{ServerRef: globalRef("s"), RuleID: rule, Severity: severity, Risk: "r", Remediation: "f"}
}

func TestWriteFindingsExact(t *testing.T) {
	t.Parallel()

	full := report.FindingRow{
		ServerRef:   globalRef("github"),
		RuleID:      "MOAT-T4-001",
		Severity:    "high",
		Title:       "Secret in env",
		Risk:        "A secret sits in the config.",
		Remediation: "Move it to a secret store.",
		Field:       "env",
		Key:         "FOO",
	}
	with := func(mod func(r *report.FindingRow)) report.FindingRow {
		r := full
		mod(&r)
		return r
	}

	tests := []struct {
		name string
		rows []report.FindingRow
		want string
	}{
		{name: "nil rows", rows: nil, want: ""},
		{name: "empty rows", rows: []report.FindingRow{}, want: ""},
		{
			name: "full row",
			rows: []report.FindingRow{full},
			want: "\nFINDINGS\n" +
				"HIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: github (claude-code, global)\n" +
				"    Where: env FOO\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
		{
			name: "empty title is left out",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Title = "" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001\n" +
				"    Server: github (claude-code, global)\n" +
				"    Where: env FOO\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
		{
			name: "empty risk and fix show a dash",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Risk, r.Remediation = "", "" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: github (claude-code, global)\n" +
				"    Where: env FOO\n" +
				"    Risk: -\n" +
				"    Fix: -\n",
		},
		{
			name: "no where line when field key and related are empty",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Field, r.Key, r.Related = "", "", "" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: github (claude-code, global)\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
		{
			name: "tool field gives a tool line and no where line",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Field, r.Key = "tool", "send_mail" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: github (claude-code, global)\n" +
				"    Tool: send_mail\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
		{
			name: "tool line with related",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Field, r.Key, r.Related = "tool", "send", "duplicate tool name" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: github (claude-code, global)\n" +
				"    Tool: send (\"duplicate tool name\")\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
		{
			name: "tool row with an empty key gives a reason line",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Field, r.Key, r.Related = "tool", "", "the server is listed twice" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: github (claude-code, global)\n" +
				"    Reason: \"the server is listed twice\"\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
		{
			name: "key and related",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Field, r.Key, r.Related = "args", "KEY", "REL" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: github (claude-code, global)\n" +
				"    Where: args KEY (REL)\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
		{
			name: "related alone",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Field, r.Key, r.Related = "args", "", "other" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: github (claude-code, global)\n" +
				"    Where: args other\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
		{
			name: "field alone",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Key = "" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: github (claude-code, global)\n" +
				"    Where: env\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
		{
			name: "key without field",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Field = "" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: github (claude-code, global)\n" +
				"    Where: FOO\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
		{
			// A name that is a dash must not look like an empty value.
			name: "dash name is quoted and empty name shows a dash",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Name, r.Key = "", "-" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: - (claude-code, global)\n" +
				"    Where: env \"-\"\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
		{
			name: "name with a space is quoted",
			rows: []report.FindingRow{with(func(r *report.FindingRow) { r.Name = "my server" })},
			want: "\nFINDINGS\nHIGH (1)\n" +
				"  MOAT-T4-001  Secret in env\n" +
				"    Server: \"my server\" (claude-code, global)\n" +
				"    Where: env FOO\n" +
				"    Risk: A secret sits in the config.\n" +
				"    Fix: Move it to a secret store.\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := writeFindings(t, plain, tt.rows...); got != tt.want {
				t.Errorf("WriteFindings() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

func TestWriteFindingsGroupsBySeverity(t *testing.T) {
	t.Parallel()

	// Input order is mixed on purpose. A and B are both high: B must not move
	// before A, or after A in a different order than the input.
	rows := []report.FindingRow{
		sevRow("LOW-1", "low"),
		sevRow("HIGH-A", "high"),
		sevRow("MED-1", "medium"),
		sevRow("CRIT-1", "critical"),
		sevRow("HIGH-B", "high"),
		sevRow("LOW-2", "low"),
	}
	out := writeFindings(t, plain, rows...)

	order := []string{
		"CRITICAL (1)", "CRIT-1",
		"HIGH (2)", "HIGH-A", "HIGH-B",
		"MEDIUM (1)", "MED-1",
		"LOW (2)", "LOW-1", "LOW-2",
	}
	prev := -1
	for _, want := range order {
		i := strings.Index(out, want)
		if i < 0 {
			t.Fatalf("output does not hold %q:\n%s", want, out)
		}
		if i <= prev {
			t.Errorf("%q is at %d, before the previous item (%d); want the order %v:\n%s", want, i, prev, order, out)
		}
		prev = i
	}
	if got := strings.Count(out, "FINDINGS"); got != 1 {
		t.Errorf("output has %d headings, want 1", got)
	}

	// Reverse the input of one group: the order inside the group follows it.
	rev := writeFindings(t, plain, sevRow("HIGH-B", "high"), sevRow("HIGH-A", "high"))
	if strings.Index(rev, "HIGH-B") > strings.Index(rev, "HIGH-A") {
		t.Errorf("rows of one group changed order:\n%s", rev)
	}
}

func TestWriteFindingsOnlyGroupsWithRows(t *testing.T) {
	t.Parallel()

	out := writeFindings(t, plain, sevRow("R", "medium"))
	for _, absent := range []string{"CRITICAL", "HIGH", "LOW"} {
		if strings.Contains(out, absent) {
			t.Errorf("output holds the empty group %q:\n%s", absent, out)
		}
	}
	if !strings.Contains(out, "MEDIUM (1)\n") {
		t.Errorf("output does not hold the group MEDIUM (1):\n%s", out)
	}
}

func TestWriteFindingsUnknownSeverityFoldsIntoCritical(t *testing.T) {
	t.Parallel()

	for _, sev := range []string{"", "bogus", "CRITICAL", "High", "a\x1b[0m"} {
		t.Run(sev, func(t *testing.T) {
			t.Parallel()
			out := writeFindings(t, plain, sevRow("X-1", sev), sevRow("C-1", "critical"), sevRow("H-1", "high"))
			if !strings.Contains(out, "CRITICAL (2)\n") {
				t.Errorf("unknown severity %q is not in the CRITICAL group:\n%s", sev, out)
			}
			// Fold keeps input order inside the group.
			if strings.Index(out, "X-1") > strings.Index(out, "C-1") {
				t.Errorf("rows of the CRITICAL group changed order:\n%s", out)
			}
			if strings.Index(out, "C-1") > strings.Index(out, "HIGH (1)") {
				t.Errorf("CRITICAL group is not before HIGH:\n%s", out)
			}
		})
	}
}

func TestWriteFindingsSameNameInTwoScopes(t *testing.T) {
	t.Parallel()

	rows := []report.FindingRow{
		{ServerRef: report.ServerRef{Name: "dup", Client: discover.ClientClaudeCode, Scope: discover.ScopeGlobal}, RuleID: "R-1", Severity: "low"},
		{ServerRef: report.ServerRef{Name: "dup", Client: discover.ClientCursor, Scope: discover.ScopeProject, ProjectPath: "/p", Untrusted: true}, RuleID: "R-1", Severity: "low"},
		{ServerRef: report.ServerRef{Name: "dup", Client: discover.ClientClaudeCode, Scope: discover.ScopeProject, ProjectPath: "/p"}, RuleID: "R-1", Severity: "low"},
	}
	out := writeFindings(t, plain, rows...)

	labels := []string{
		"Server: dup (claude-code, global)\n",
		"Server: dup (cursor, project:/p (untrusted))\n",
		"Server: dup (claude-code, project:/p)\n",
	}
	for _, l := range labels {
		if got := strings.Count(out, l); got != 1 {
			t.Errorf("output holds the label %q %d times, want 1:\n%s", l, got, out)
		}
	}
	// "(untrusted)" shows only for the untrusted server.
	if got := strings.Count(out, "(untrusted)"); got != 1 {
		t.Errorf("output holds (untrusted) %d times, want 1:\n%s", got, out)
	}
}

func TestWriteFindingsLongTextIsCut(t *testing.T) {
	t.Parallel()

	x := func(n int) string { return strings.Repeat("x", n) }
	tests := []struct {
		name  string
		limit int
		row   func(v string) report.FindingRow
	}{
		{"name", maxShortCellRunes, func(v string) report.FindingRow {
			return report.FindingRow{ServerRef: globalRef(v), Severity: "low"}
		}},
		{"client", maxShortCellRunes, func(v string) report.FindingRow {
			r := globalRef("s")
			r.Client = discover.Client(v)
			return report.FindingRow{ServerRef: r, Severity: "low"}
		}},
		{"rule id", maxShortCellRunes, func(v string) report.FindingRow {
			return report.FindingRow{ServerRef: globalRef("s"), RuleID: v, Severity: "low"}
		}},
		{"field", maxShortCellRunes, func(v string) report.FindingRow {
			return report.FindingRow{ServerRef: globalRef("s"), Severity: "low", Field: v}
		}},
		{"title", maxTitleRunes, func(v string) report.FindingRow {
			return report.FindingRow{ServerRef: globalRef("s"), Severity: "low", Title: v}
		}},
		{"risk", maxRuleTextRunes, func(v string) report.FindingRow {
			return report.FindingRow{ServerRef: globalRef("s"), Severity: "low", Risk: v}
		}},
		{"remediation", maxRuleTextRunes, func(v string) report.FindingRow {
			return report.FindingRow{ServerRef: globalRef("s"), Severity: "low", Remediation: v}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := writeFindings(t, plain, tt.row(x(tt.limit*3)))
			if want := x(tt.limit) + termsafe.CutMarker; !strings.Contains(out, want) {
				t.Errorf("output does not hold the cut text (%d runes + marker):\n%s", tt.limit, out)
			}
			if strings.Contains(out, x(tt.limit+1)) {
				t.Errorf("output holds more than %d runes of one text", tt.limit)
			}

			// Exactly at the limit: nothing is cut.
			out = writeFindings(t, plain, tt.row(x(tt.limit)))
			if strings.Contains(out, termsafe.CutMarker) {
				t.Errorf("text of exactly %d runes was cut:\n%s", tt.limit, out)
			}
		})
	}

	t.Run("project path", func(t *testing.T) {
		t.Parallel()
		r := globalRef("s")
		r.Scope, r.ProjectPath = discover.ScopeProject, "/"+x(maxPathRunes*3)
		out := writeFindings(t, plain, report.FindingRow{ServerRef: r, Severity: "low"})
		want := ("project:/" + x(maxPathRunes))[:maxPathRunes] + termsafe.CutMarker
		if !strings.Contains(out, want) {
			t.Errorf("output does not hold the cut path:\n%s", out)
		}
		if strings.Contains(out, x(maxPathRunes)) {
			t.Errorf("output holds more path than %d runes", maxPathRunes)
		}
	})

	t.Run("key and related are cut apart", func(t *testing.T) {
		t.Parallel()
		long := x(maxShortCellRunes * 3)
		out := writeFindings(t, plain, report.FindingRow{ServerRef: globalRef("s"), Severity: "low", Field: "f", Key: long, Related: long})
		cut := x(maxShortCellRunes) + termsafe.CutMarker
		if want := "Where: f " + cut + " (" + cut + ")\n"; !strings.Contains(out, want) {
			t.Errorf("output does not hold %q:\n%s", want, out)
		}
	})

	t.Run("a cut marker follows the closing quote", func(t *testing.T) {
		t.Parallel()
		long := strings.Repeat("\x1b", maxShortCellRunes*2)
		out := writeFindings(t, plain, report.FindingRow{ServerRef: globalRef("s"), Severity: "low", RuleID: long})
		want := termsafe.Quote(strings.Repeat("\x1b", maxShortCellRunes)) + termsafe.CutMarker
		if !strings.Contains(out, want) {
			t.Errorf("output does not hold %s:\n%s", want, out)
		}
	})
}

func TestWriteFindingsWriteError(t *testing.T) {
	t.Parallel()

	errBoom := errors.New("boom")
	rows := []report.FindingRow{sevRow("R", "high")}

	tests := []struct {
		name string
		w    func() *failingWriter
	}{
		{name: "fails at once", w: func() *failingWriter { return &failingWriter{limit: 0, err: errBoom} }},
		{name: "short write", w: func() *failingWriter { return &failingWriter{limit: 5, err: errBoom} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := report.WriteFindings(tt.w(), rows, plain)
			if !errors.Is(err, errBoom) {
				t.Errorf("WriteFindings() error = %v, want %v", err, errBoom)
			}
		})
	}

	t.Run("empty rows never write", func(t *testing.T) {
		t.Parallel()
		if err := report.WriteFindings(&failingWriter{err: errBoom}, nil, plain); err != nil {
			t.Errorf("WriteFindings(nil) error = %v, want nil", err)
		}
	})
}

// TestFieldToolMatchesRules checks that the copy of the "tool" field word in
// this package is the same word as rules.FieldTool.
func TestFieldToolMatchesRules(t *testing.T) {
	t.Parallel()

	if report.FieldTool != rules.FieldTool {
		t.Errorf("report fieldTool = %q, want rules.FieldTool = %q", report.FieldTool, rules.FieldTool)
	}
}

// TestSeverityWordsMatchRules checks that the severity words of report, worst
// first, are the words of rules. A word that drifts apart would move every
// finding of that severity into the critical group.
func TestSeverityWordsMatchRules(t *testing.T) {
	t.Parallel()

	want := [...]string{
		string(rules.SeverityCritical), string(rules.SeverityHigh),
		string(rules.SeverityMedium), string(rules.SeverityLow),
	}
	if report.SeverityOrder != want {
		t.Errorf("report severityOrder = %q, want the rules words %q", report.SeverityOrder, want)
	}
}
