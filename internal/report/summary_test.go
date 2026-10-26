package report_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// Caps of the summary (see summary.go).
const (
	maxReasonRunes       = 500
	maxSummaryNameRunes  = 100
	maxSummaryHeaderKeys = 10
)

// headerKeys returns the keys "H1", "H2" and so on, n of them.
func headerKeys(n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("H%d", i+1)
	}
	return keys
}

// writeSummary returns the text that report.WriteSummary writes. It fails the
// test if WriteSummary returns an error.
func writeSummary(t *testing.T, st report.Style, servers ...report.ServerStatus) string {
	t.Helper()
	var sb strings.Builder
	if err := report.WriteSummary(&sb, servers, st); err != nil {
		t.Fatalf("WriteSummary() error = %v, want nil", err)
	}
	return sb.String()
}

// status returns a status for the global server name.
func status(name, st string) report.ServerStatus {
	return report.ServerStatus{ServerRef: globalRef(name), Status: st}
}

func TestWriteSummaryExact(t *testing.T) {
	t.Parallel()

	ok := func(tools, findings int) report.ServerStatus {
		s := status("github", report.StatusOK)
		s.Tools, s.Findings = tools, findings
		return s
	}
	other := func(st, reason string, findings int) report.ServerStatus {
		s := status("srv", st)
		s.Reason, s.Findings = reason, findings
		return s
	}
	warn := func(w ...inspect.Warning) report.ServerStatus {
		s := ok(1, 0)
		s.Warnings = w
		return s
	}

	tests := []struct {
		name    string
		servers []report.ServerStatus
		want    string
	}{
		{name: "nil servers", servers: nil, want: ""},
		{name: "empty servers", servers: []report.ServerStatus{}, want: ""},
		{
			name:    "ok with tools and findings",
			servers: []report.ServerStatus{ok(3, 2)},
			want:    "\nSUMMARY\n  github (claude-code, global): ok, 3 tools, 2 findings\n",
		},
		{
			name:    "singular tool and finding",
			servers: []report.ServerStatus{ok(1, 1)},
			want:    "\nSUMMARY\n  github (claude-code, global): ok, 1 tool, 1 finding\n",
		},
		{
			name:    "zero is plural",
			servers: []report.ServerStatus{ok(0, 0)},
			want:    "\nSUMMARY\n  github (claude-code, global): ok, 0 tools, 0 findings\n",
		},
		{
			name:    "ok never shows a reason",
			servers: []report.ServerStatus{func() report.ServerStatus { s := ok(2, 0); s.Reason = "stale"; return s }()},
			want:    "\nSUMMARY\n  github (claude-code, global): ok, 2 tools, 0 findings\n",
		},
		{
			name:    "timeout hides tools",
			servers: []report.ServerStatus{func() report.ServerStatus { s := other(report.StatusTimeout, "", 0); s.Tools = 5; return s }()},
			want:    "\nSUMMARY\n  srv (claude-code, global): timeout, 0 findings\n",
		},
		{
			name:    "failed with reason",
			servers: []report.ServerStatus{other(report.StatusFailed, "connection refused", 0)},
			want:    "\nSUMMARY\n  srv (claude-code, global): failed, 0 findings (connection refused)\n",
		},
		{
			name:    "timeout with reason",
			servers: []report.ServerStatus{other(report.StatusTimeout, "no answer in 30s", 1)},
			want:    "\nSUMMARY\n  srv (claude-code, global): timeout, 1 finding (no answer in 30s)\n",
		},
		{
			// The reason comes after the real count, so a reason that looks
			// like a count cannot hide it.
			name:    "reason cannot fake the count",
			servers: []report.ServerStatus{other(report.StatusFailed, "x), 0 findings", 3)},
			want:    "\nSUMMARY\n  srv (claude-code, global): failed, 3 findings (x), 0 findings)\n",
		},
		{
			name:    "not inspected",
			servers: []report.ServerStatus{other(report.StatusNotInspected, "", 1)},
			want:    "\nSUMMARY\n  srv (claude-code, global): not inspected, 1 finding\n",
		},
		{
			name: "project untrusted server and order is kept",
			servers: []report.ServerStatus{
				{ServerRef: report.ServerRef{Name: "b", Client: discover.ClientCursor, Scope: discover.ScopeProject, ProjectPath: "/x", Untrusted: true}, Status: report.StatusFailed, Reason: "bad"},
				ok(0, 0),
			},
			want: "\nSUMMARY\n" +
				"  b (cursor, project:/x (untrusted)): failed, 0 findings (bad)\n" +
				"  github (claude-code, global): ok, 0 tools, 0 findings\n",
		},
		{
			name: "same name in two scopes reads as two servers",
			servers: []report.ServerStatus{
				{ServerRef: globalRef("dup"), Status: report.StatusOK, Tools: 1},
				{ServerRef: report.ServerRef{Name: "dup", Client: discover.ClientCodex, Scope: discover.ScopeProject, ProjectPath: "/p", Untrusted: true}, Status: report.StatusOK, Tools: 1},
			},
			want: "\nSUMMARY\n" +
				"  dup (claude-code, global): ok, 1 tool, 0 findings\n" +
				"  dup (codex, project:/p (untrusted)): ok, 1 tool, 0 findings\n",
		},
		{
			name: "cleartext secrets names header keys only",
			servers: []report.ServerStatus{warn(inspect.Warning{
				Kind: inspect.WarnCleartextSecrets, HeaderKeys: []string{"Authorization", "X-Api-Key"},
				URLUserInfo: true, URLSecrets: true,
			})},
			want: "\nSUMMARY\n  github (claude-code, global): ok, 1 tool, 0 findings\n" +
				"    warning: cleartext-secrets: secrets go over plain http to a host that is not loopback: " +
				"header Authorization, header X-Api-Key, the user info of the URL, secret parts of the URL\n",
		},
		{
			name:    "cleartext secrets with one header key",
			servers: []report.ServerStatus{warn(inspect.Warning{Kind: inspect.WarnCleartextSecrets, HeaderKeys: []string{"Authorization"}})},
			want: "\nSUMMARY\n  github (claude-code, global): ok, 1 tool, 0 findings\n" +
				"    warning: cleartext-secrets: secrets go over plain http to a host that is not loopback: header Authorization\n",
		},
		{
			name:    "cleartext secrets with the most header keys",
			servers: []report.ServerStatus{warn(inspect.Warning{Kind: inspect.WarnCleartextSecrets, HeaderKeys: headerKeys(maxSummaryHeaderKeys)})},
			want: "\nSUMMARY\n  github (claude-code, global): ok, 1 tool, 0 findings\n" +
				"    warning: cleartext-secrets: secrets go over plain http to a host that is not loopback: " +
				"header H1, header H2, header H3, header H4, header H5, header H6, header H7, header H8, header H9, header H10\n",
		},
		{
			name:    "cleartext secrets with too many header keys",
			servers: []report.ServerStatus{warn(inspect.Warning{Kind: inspect.WarnCleartextSecrets, HeaderKeys: headerKeys(12), URLSecrets: true})},
			want: "\nSUMMARY\n  github (claude-code, global): ok, 1 tool, 0 findings\n" +
				"    warning: cleartext-secrets: secrets go over plain http to a host that is not loopback: " +
				"header H1, header H2, header H3, header H4, header H5, header H6, header H7, header H8, header H9, header H10, " +
				"and 2 more header keys, secret parts of the URL\n",
		},
		{
			name:    "cleartext secrets with one header key over the limit",
			servers: []report.ServerStatus{warn(inspect.Warning{Kind: inspect.WarnCleartextSecrets, HeaderKeys: headerKeys(maxSummaryHeaderKeys + 1)})},
			want: "\nSUMMARY\n  github (claude-code, global): ok, 1 tool, 0 findings\n" +
				"    warning: cleartext-secrets: secrets go over plain http to a host that is not loopback: " +
				"header H1, header H2, header H3, header H4, header H5, header H6, header H7, header H8, header H9, header H10, " +
				"and 1 more header key\n",
		},
		{
			name:    "undeclared capability",
			servers: []report.ServerStatus{warn(inspect.Warning{Kind: inspect.WarnUndeclaredCapability, Capabilities: []string{"tools", "resource-templates"}})},
			want: "\nSUMMARY\n  github (claude-code, global): ok, 1 tool, 0 findings\n" +
				"    warning: undeclared-capability: the server answered lists that it did not declare " +
				"(it can show other lists to other clients): tools, resource-templates\n",
		},
		{
			name:    "dns pin unavailable",
			servers: []report.ServerStatus{warn(inspect.Warning{Kind: inspect.WarnDNSPinUnavailable})},
			want: "\nSUMMARY\n  github (claude-code, global): ok, 1 tool, 0 findings\n" +
				"    warning: dns-pin-unavailable: a proxy from the environment resolves the host, " +
				"so the DNS pin and the address checks do not apply\n",
		},
		{
			name:    "unknown warning kind",
			servers: []report.ServerStatus{warn(inspect.Warning{Kind: "future-kind"})},
			want: "\nSUMMARY\n  github (claude-code, global): ok, 1 tool, 0 findings\n" +
				"    warning: future-kind: unknown warning\n",
		},
		{
			name: "several warnings keep their order, one line each",
			servers: []report.ServerStatus{warn(
				inspect.Warning{Kind: inspect.WarnDNSPinUnavailable},
				inspect.Warning{Kind: inspect.WarnUndeclaredCapability, Capabilities: []string{"prompts"}},
			)},
			want: "\nSUMMARY\n  github (claude-code, global): ok, 1 tool, 0 findings\n" +
				"    warning: dns-pin-unavailable: a proxy from the environment resolves the host, " +
				"so the DNS pin and the address checks do not apply\n" +
				"    warning: undeclared-capability: the server answered lists that it did not declare " +
				"(it can show other lists to other clients): prompts\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := writeSummary(t, plain, tt.servers...); got != tt.want {
				t.Errorf("WriteSummary() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

// TestWriteSummaryHeaderKeyWithSpaceIsQuoted checks that a header key with a
// space and a comma is quoted, so it cannot make the list of keys look like
// other keys.
func TestWriteSummaryHeaderKeyWithSpaceIsQuoted(t *testing.T) {
	t.Parallel()

	s := status("api", report.StatusOK)
	s.Warnings = []inspect.Warning{{
		Kind: inspect.WarnCleartextSecrets, HeaderKeys: []string{"X, header Authorization"},
	}}
	out := writeSummary(t, plain, s)
	if want := `: header "X, header Authorization"` + "\n"; !strings.HasSuffix(out, want) {
		t.Errorf("output does not end with %q:\n%s", want, out)
	}
}

func TestWriteSummaryLongTextIsCut(t *testing.T) {
	t.Parallel()

	x := func(n int) string { return strings.Repeat("x", n) }
	tests := []struct {
		name  string
		limit int
		set   func(s *report.ServerStatus, v string)
	}{
		{"name", maxShortCellRunes, func(s *report.ServerStatus, v string) { s.Name = v }},
		{"client", maxShortCellRunes, func(s *report.ServerStatus, v string) { s.Client = discover.Client(v) }},
		{"status", maxShortCellRunes, func(s *report.ServerStatus, v string) { s.Status = v }},
		{"reason", maxReasonRunes, func(s *report.ServerStatus, v string) { s.Status, s.Reason = report.StatusFailed, v }},
		{"header key", maxSummaryNameRunes, func(s *report.ServerStatus, v string) {
			s.Warnings = []inspect.Warning{{Kind: inspect.WarnCleartextSecrets, HeaderKeys: []string{v}}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := status("s", report.StatusOK)
			tt.set(&s, x(tt.limit*3))
			out := writeSummary(t, plain, s)
			if want := x(tt.limit) + termsafe.CutMarker; !strings.Contains(out, want) {
				t.Errorf("output does not hold the cut text (%d runes + marker):\n%s", tt.limit, out)
			}
			if strings.Contains(out, x(tt.limit+1)) {
				t.Errorf("output holds more than %d runes of one text", tt.limit)
			}

			s = status("s", report.StatusOK)
			tt.set(&s, x(tt.limit))
			if out = writeSummary(t, plain, s); strings.Contains(out, termsafe.CutMarker) {
				t.Errorf("text of exactly %d runes was cut:\n%s", tt.limit, out)
			}
		})
	}

	t.Run("project path", func(t *testing.T) {
		t.Parallel()
		s := status("s", report.StatusOK)
		s.Scope, s.ProjectPath = discover.ScopeProject, "/"+x(maxPathRunes*3)
		out := writeSummary(t, plain, s)
		if want := ("project:/" + x(maxPathRunes))[:maxPathRunes] + termsafe.CutMarker; !strings.Contains(out, want) {
			t.Errorf("output does not hold the cut path:\n%s", out)
		}
		if strings.Contains(out, x(maxPathRunes)) {
			t.Errorf("output holds more path than %d runes", maxPathRunes)
		}
	})
}

func TestWriteSummaryWriteError(t *testing.T) {
	t.Parallel()

	errBoom := errors.New("boom")
	servers := []report.ServerStatus{status("s", report.StatusOK)}

	for _, limit := range []int{0, 5} {
		w := &failingWriter{limit: limit, err: errBoom}
		if err := report.WriteSummary(w, servers, plain); !errors.Is(err, errBoom) {
			t.Errorf("limit %d: WriteSummary() error = %v, want %v", limit, err, errBoom)
		}
	}

	t.Run("empty servers never write", func(t *testing.T) {
		t.Parallel()
		if err := report.WriteSummary(&failingWriter{err: errBoom}, nil, plain); err != nil {
			t.Errorf("WriteSummary(nil) error = %v, want nil", err)
		}
	})
}

// TestWarningText checks the one-line text of each inspection warning: keys
// and fixed names only, escaped.
func TestWarningText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		w    inspect.Warning
		want string
	}{
		{
			"cleartext secrets",
			inspect.Warning{Kind: inspect.WarnCleartextSecrets, HeaderKeys: []string{"Authorization", "X-Key\x1b[2J"}, URLUserInfo: true, URLSecrets: true},
			`cleartext-secrets: secrets go over plain http to a host that is not loopback: header Authorization, header "X-Key\x1b[2J", the user info of the URL, secret parts of the URL`,
		},
		{
			"undeclared capability",
			inspect.Warning{Kind: inspect.WarnUndeclaredCapability, Capabilities: []string{"tools", "prompts"}},
			"undeclared-capability: the server answered lists that it did not declare (it can show other lists to other clients): tools, prompts",
		},
		{
			"dns pin unavailable",
			inspect.Warning{Kind: inspect.WarnDNSPinUnavailable},
			"dns-pin-unavailable: a proxy from the environment resolves the host, so the DNS pin and the address checks do not apply",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := report.WarningText(tt.w); got != tt.want {
				t.Errorf("WarningText() = %q, want %q", got, tt.want)
			}
		})
	}
}
