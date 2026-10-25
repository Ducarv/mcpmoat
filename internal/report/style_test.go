package report_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// The SGR sequences of style.go. They are copied on purpose: the test must
// fail if the package starts to write a different sequence.
const (
	sgrReset   = "\x1b[0m"
	sgrBold    = "\x1b[1m"
	sgrBoldRed = "\x1b[1;31m"
	sgrRed     = "\x1b[31m"
	sgrGreen   = "\x1b[32m"
	sgrYellow  = "\x1b[33m"
	sgrCyan    = "\x1b[36m"
)

var stripSGR = strings.NewReplacer(
	sgrReset, "", sgrBold, "", sgrBoldRed, "", sgrRed, "",
	sgrGreen, "", sgrYellow, "", sgrCyan, "",
)

var colour = report.Style{Color: true}

// hostile lists texts that must never reach the output as raw bytes.
var hostile = []struct {
	name  string
	value string
}{
	{"ANSI colour", "a\x1b[31mb"},
	{"OSC link", "a\x1b]8;;http://evil\x07b"},
	{"reset", "a\x1b[0mb"},
	{"bidi override", "a\u202eb"},
	{"bidi isolate", "a\u2066b"},
	{"newline", "a\nb"},
	{"carriage return", "a\rb"},
	{"invalid UTF-8", "a\xffb"},
}

// place puts a hostile value into one field and says how the report shows it.
type place struct {
	name string
	// out renders the report for v in the given style.
	out func(t *testing.T, st report.Style, v string) string
	// want is the escaped text that the output must hold for v.
	want func(v string) string
}

func findingPlace(name string, set func(r *report.FindingRow, v string), want func(v string) string) place {
	return place{
		name: "findings/" + name,
		out: func(t *testing.T, st report.Style, v string) string {
			r := report.FindingRow{ServerRef: globalRef("s"), RuleID: "R", Severity: "high", Title: "t", Risk: "r", Remediation: "f", Field: "f", Key: "k"}
			set(&r, v)
			return writeFindings(t, st, r)
		},
		want: want,
	}
}

func summaryPlace(name string, set func(s *report.ServerStatus, v string), want func(v string) string) place {
	return place{
		name: "summary/" + name,
		out: func(t *testing.T, st report.Style, v string) string {
			s := status("s", report.StatusFailed)
			set(&s, v)
			return writeSummary(t, st, s)
		},
		want: want,
	}
}

func quote(v string) string { return termsafe.Quote(v) }

func places() []place {
	return []place{
		findingPlace("name", func(r *report.FindingRow, v string) { r.Name = v }, quote),
		findingPlace("client", func(r *report.FindingRow, v string) { r.Client = discover.Client(v) }, quote),
		findingPlace("project path", func(r *report.FindingRow, v string) {
			r.Scope, r.ProjectPath = discover.ScopeProject, v
		}, func(v string) string { return quote("project:" + v) }),
		findingPlace("rule id", func(r *report.FindingRow, v string) { r.RuleID = v }, quote),
		findingPlace("title", func(r *report.FindingRow, v string) { r.Title = v }, quote),
		findingPlace("risk", func(r *report.FindingRow, v string) { r.Risk = v }, quote),
		findingPlace("remediation", func(r *report.FindingRow, v string) { r.Remediation = v }, quote),
		findingPlace("field", func(r *report.FindingRow, v string) { r.Field = v }, quote),
		findingPlace("key", func(r *report.FindingRow, v string) { r.Key = v }, quote),
		findingPlace("related", func(r *report.FindingRow, v string) { r.Key, r.Related = "", v }, quote),
		findingPlace("tool key", func(r *report.FindingRow, v string) { r.Field, r.Key = "tool", v }, quote),
		findingPlace("key and related", func(r *report.FindingRow, v string) { r.Key, r.Related = v, v },
			func(v string) string { return quote(v) + " (" + quote(v) + ")" }),
		summaryPlace("name", func(s *report.ServerStatus, v string) { s.Name = v }, quote),
		summaryPlace("client", func(s *report.ServerStatus, v string) { s.Client = discover.Client(v) }, quote),
		summaryPlace("project path", func(s *report.ServerStatus, v string) {
			s.Scope, s.ProjectPath = discover.ScopeProject, v
		}, func(v string) string { return quote("project:" + v) }),
		summaryPlace("status", func(s *report.ServerStatus, v string) { s.Status = v }, quote),
		summaryPlace("reason", func(s *report.ServerStatus, v string) { s.Reason = v }, quote),
		summaryPlace("header key", func(s *report.ServerStatus, v string) {
			s.Warnings = []inspect.Warning{{Kind: inspect.WarnCleartextSecrets, HeaderKeys: []string{v}}}
		}, quote),
		summaryPlace("warning kind", func(s *report.ServerStatus, v string) {
			s.Warnings = []inspect.Warning{{Kind: inspect.WarningKind(v)}}
		}, quote),
		summaryPlace("capability", func(s *report.ServerStatus, v string) {
			s.Warnings = []inspect.Warning{{Kind: inspect.WarnUndeclaredCapability, Capabilities: []string{v}}}
		}, quote),
	}
}

func TestHostileTextNeverReachesTheOutputRaw(t *testing.T) {
	t.Parallel()

	for _, p := range places() {
		for _, h := range hostile {
			t.Run(p.name+"/"+h.name, func(t *testing.T) {
				t.Parallel()
				baseline := strings.Count(p.out(t, plain, "x"), "\n")

				for _, st := range []report.Style{plain, colour} {
					out := p.out(t, st, h.value)

					if want := p.want(h.value); !strings.Contains(out, want) {
						t.Errorf("Color=%v: output does not hold the escaped text %s:\n%q", st.Color, want, out)
					}
					// A raw newline would add a line.
					if got := strings.Count(out, "\n"); got != baseline {
						t.Errorf("Color=%v: output has %d newlines, want %d:\n%q", st.Color, got, baseline, out)
					}
					if !st.Color && strings.ContainsRune(out, 0x1b) {
						t.Errorf("Color=false: output holds an ESC byte:\n%q", out)
					}
					// With colour, only the package's own SGR sequences may
					// hold an ESC.
					rest := stripSGR.Replace(out)
					if strings.ContainsRune(rest, 0x1b) {
						t.Errorf("Color=%v: output holds an ESC that is not an own SGR sequence:\n%q", st.Color, out)
					}
					for i := range len(rest) {
						if c := rest[i]; (c < 0x20 && c != '\n') || c == 0x7f {
							t.Errorf("Color=%v: output holds raw control byte 0x%02x:\n%q", st.Color, c, out)
							break
						}
					}
					for _, r := range []rune{'\u202e', '\u2066'} {
						if strings.ContainsRune(out, r) {
							t.Errorf("Color=%v: output holds raw %U:\n%q", st.Color, r, out)
						}
					}
					if !utf8.ValidString(out) {
						t.Errorf("Color=%v: output is not valid UTF-8:\n%q", st.Color, out)
					}
				}
			})
		}
	}
}

func TestColourOffIsColourOnWithoutSGR(t *testing.T) {
	t.Parallel()

	rows := []report.FindingRow{
		sevRow("A", "low"), sevRow("B", "critical"), sevRow("C", "high"),
		sevRow("D", "medium"), sevRow("E", "weird"),
	}
	servers := []report.ServerStatus{
		{ServerRef: globalRef("a"), Status: report.StatusOK, Tools: 2, Findings: 1},
		{ServerRef: globalRef("b"), Status: report.StatusTimeout, Reason: "slow"},
		{ServerRef: globalRef("c"), Status: report.StatusFailed, Reason: "boom"},
		{ServerRef: globalRef("d"), Status: report.StatusNotInspected},
		{ServerRef: globalRef("e"), Status: "odd\x1b[31m", Warnings: []inspect.Warning{{Kind: inspect.WarnDNSPinUnavailable}}},
	}

	t.Run("findings", func(t *testing.T) {
		t.Parallel()
		off, on := writeFindings(t, plain, rows...), writeFindings(t, colour, rows...)
		if strings.ContainsRune(off, 0x1b) {
			t.Errorf("Color=false output holds an ESC byte:\n%q", off)
		}
		if on == off {
			t.Error("Color=true output is the same as Color=false output, want SGR codes")
		}
		if got := stripSGR.Replace(on); got != off {
			t.Errorf("colour output without SGR =\n%q\nwant\n%q", got, off)
		}
	})
	t.Run("summary", func(t *testing.T) {
		t.Parallel()
		off, on := writeSummary(t, plain, servers...), writeSummary(t, colour, servers...)
		if strings.ContainsRune(off, 0x1b) {
			t.Errorf("Color=false output holds an ESC byte:\n%q", off)
		}
		if on == off {
			t.Error("Color=true output is the same as Color=false output, want SGR codes")
		}
		if got := stripSGR.Replace(on); got != off {
			t.Errorf("colour output without SGR =\n%q\nwant\n%q", got, off)
		}
	})
	t.Run("empty input stays empty with colour", func(t *testing.T) {
		t.Parallel()
		if got := writeFindings(t, colour); got != "" {
			t.Errorf("WriteFindings(nil) = %q, want empty", got)
		}
		if got := writeSummary(t, colour); got != "" {
			t.Errorf("WriteSummary(nil) = %q, want empty", got)
		}
	})
}

func TestFindingsColours(t *testing.T) {
	t.Parallel()

	tests := []struct {
		severity string
		want     string
	}{
		{"critical", sgrBoldRed + "CRITICAL (1)" + sgrReset},
		{"high", sgrRed + "HIGH (1)" + sgrReset},
		{"medium", sgrYellow + "MEDIUM (1)" + sgrReset},
		{"low", sgrCyan + "LOW (1)" + sgrReset},
		// An unknown severity looks like critical, never harmless.
		{"bogus", sgrBoldRed + "CRITICAL (1)" + sgrReset},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			t.Parallel()
			out := writeFindings(t, colour, sevRow("R", tt.severity))
			if want := "\n" + sgrBold + "FINDINGS" + sgrReset + "\n" + tt.want + "\n"; !strings.HasPrefix(out, want) {
				t.Errorf("output starts with\n%q\nwant prefix\n%q", out, want)
			}
		})
	}
}

func TestSummaryColours(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status string
		want   string
	}{
		{report.StatusOK, sgrGreen + "ok" + sgrReset},
		{report.StatusTimeout, sgrYellow + "timeout" + sgrReset},
		{report.StatusFailed, sgrYellow + "failed" + sgrReset},
		{report.StatusNotInspected, "not inspected"},
		{"other", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			t.Parallel()
			out := writeSummary(t, colour, status("s", tt.status))
			if !strings.HasPrefix(out, "\n"+sgrBold+"SUMMARY"+sgrReset+"\n") {
				t.Errorf("output does not start with the bold heading:\n%q", out)
			}
			if want := "(claude-code, global): " + tt.want; !strings.Contains(out, want) {
				t.Errorf("output does not hold %q:\n%q", want, out)
			}
			if tt.status == "not inspected" || tt.status == "other" {
				// Plain statuses: the only SGR codes are the heading ones.
				if got := strings.Count(out, "\x1b"); got != 2 {
					t.Errorf("output has %d ESC bytes, want 2 (the heading):\n%q", got, out)
				}
			}
		})
	}
}

func ExampleStyle() {
	var sb strings.Builder
	_ = report.WriteSummary(&sb, []report.ServerStatus{{ServerRef: globalRef("github"), Status: report.StatusOK, Tools: 1}}, report.Style{})
	fmt.Print(sb.String())
	// Output:
	//
	// SUMMARY
	//   github (claude-code, global): ok, 1 tool, 0 findings
}
