package rules

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"unicode/utf8"

	builtinrules "github.com/Ducarv/mcpmoat/rules"
)

// builtinCompiler returns the Compiler that runs the cases of the built-in
// rules.
func builtinCompiler() Compiler {
	return func(m Match, _ Target) (*Matcher, error) { return m.Compile() }
}

// documentedProblems runs CheckDocumented on each rule and returns all the
// problems. Each problem starts with the rule ID.
func documentedProblems(rs []Rule) []string {
	var problems []string
	for _, r := range rs {
		problems = append(problems, CheckDocumented(r)...)
	}
	return problems
}

// builtinCaseFailures compiles each rule with c, runs its cases and returns
// the text of every failure. A compile error is a failure too.
func builtinCaseFailures(rs []Rule, c Compiler) []string {
	var out []string
	for _, r := range rs {
		m, err := c(r.Match, r.Target)
		if err != nil {
			out = append(out, displayText(r.ID)+": compile: "+displayText(err.Error()))
			continue
		}
		for _, f := range RunCases(r, m) {
			out = append(out, f.String())
		}
	}
	return out
}

// runBuiltinCases reports every failed case of rs as a test error.
func runBuiltinCases(t *testing.T, rs []Rule, c Compiler) {
	t.Helper()
	for _, f := range builtinCaseFailures(rs, c) {
		t.Errorf("%s", f)
	}
}

// mustBuiltin loads the built-in rules and fails the test on any error.
func mustBuiltin(t *testing.T, opts ...Option) []Rule {
	t.Helper()
	rs, errs := Builtin(opts...)
	for _, e := range errs {
		t.Errorf("Builtin() error: %v", e)
	}
	if len(errs) > 0 {
		t.FailNow()
	}
	return rs
}

func TestBuiltinRulesLoad(t *testing.T) {
	t.Parallel()
	rs := mustBuiltin(t)
	// FR-09 wants 15 rules. The other rule issues add them, so this test
	// does not assert 15 yet.
	if len(rs) < 1 {
		t.Fatal("Builtin() returned no rules, want at least 1")
	}
	if _, errs := NewSet(rs, nil); len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("NewSet(builtin) error (duplicate ID?): %v", e)
		}
	}
}

func TestBuiltinRulesDocumented(t *testing.T) {
	t.Parallel()
	rs := mustBuiltin(t)
	for _, p := range documentedProblems(rs) {
		t.Errorf("built-in rule is not documented: %s", p)
	}
}

func TestDocumentedProblemsCatchesMissingParts(t *testing.T) {
	t.Parallel()
	rs := mustBuiltin(t)
	if len(rs) == 0 {
		t.Fatal("Builtin() returned no rules")
	}
	tests := []struct {
		name   string
		mutate func(r *Rule)
		want   string
	}{
		{"no should_not_match", func(r *Rule) { r.ShouldNotMatch = nil }, "no should_not_match case"},
		{"empty should_not_match", func(r *Rule) { r.ShouldNotMatch = []Case{} }, "no should_not_match case"},
		{"no should_match", func(r *Rule) { r.ShouldMatch = nil }, "no should_match case"},
		{"empty risk", func(r *Rule) { r.Risk = "" }, "risk is empty"},
		{"empty remediation", func(r *Rule) { r.Remediation = "" }, "remediation is empty"},
	}
	for _, r := range rs {
		for _, tt := range tests {
			t.Run(r.ID+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				// A copy, so mutate breaks this subtest's rule and not the shared one.
				rule := r
				if got := CheckDocumented(rule); len(got) != 0 {
					t.Fatalf("unbroken rule %s has problems: %v", rule.ID, got)
				}
				tt.mutate(&rule)
				problems := documentedProblems([]Rule{rule})
				found := false
				for _, p := range problems {
					if !strings.HasPrefix(p, rule.ID+": ") {
						t.Errorf("problem %q does not start with the rule ID %q", p, rule.ID)
					}
					if strings.Contains(p, tt.want) {
						found = true
					}
				}
				if !found {
					t.Errorf("problems = %q, want one that contains %q", problems, tt.want)
				}
			})
		}
	}
}

func TestBuiltinRulesCases(t *testing.T) {
	t.Parallel()
	c := builtinCompiler()
	// WithCompiler also checks that the Match section of every rule compiles.
	rs := mustBuiltin(t, WithCompiler(c))
	runBuiltinCases(t, rs, c)
}

// fixedCompiler returns a Compiler that ignores the rule and compiles m.
func fixedCompiler(t *testing.T, m Match) Compiler {
	matcher := mustCompileMatch(t, m)
	return func(Match, Target) (*Matcher, error) { return matcher, nil }
}

func TestRunBuiltinCasesWithWrongMatcher(t *testing.T) {
	t.Parallel()
	rs := mustBuiltin(t)
	if len(rs) == 0 {
		t.Fatal("Builtin() returned no rules")
	}
	sm, snm := rs[0].ShouldMatch[0], rs[0].ShouldNotMatch[0]

	wrong := []struct {
		name string
		c    Compiler
		want []string // all must be in one failure line
	}{
		{
			name: "matches nothing",
			c:    fixedCompiler(t, Match{AnyRegex: []string{`[^\s\S]`}}),
			want: []string{rs[0].ID, string(KindShouldMatch), sm.Text},
		},
		{
			name: "matches everything",
			c:    fixedCompiler(t, Match{AnyRegex: []string{`(?s).`}}),
			want: []string{rs[0].ID, string(KindShouldNotMatch), snm.Text},
		},
		{
			name: "compile error",
			c:    func(Match, Target) (*Matcher, error) { return nil, errors.New("bad pattern") },
			want: []string{rs[0].ID, "bad pattern"},
		},
	}
	for _, tt := range wrong {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			failures := builtinCaseFailures(rs, tt.c)
			if len(failures) == 0 {
				t.Fatal("a wrong matcher gave no failure")
			}
			// One failure line must hold all the wanted parts.
			for _, f := range failures {
				all := true
				for _, w := range tt.want {
					all = all && strings.Contains(f, w)
				}
				if all {
					return
				}
			}
			t.Errorf("no failure contains all of %q; failures: %q", tt.want, failures)
		})
	}
}

// TestBuiltinRulesASCII checks that every built-in rule file is ASCII. A rule
// writes a special rune as an escape, so an invisible or look-alike rune
// cannot hide in a pattern or a case, and a case tests the escape it names.
func TestBuiltinRulesASCII(t *testing.T) {
	t.Parallel()

	entries, err := fs.ReadDir(builtinrules.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := fs.ReadFile(builtinrules.FS, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for i, c := range b {
			if c >= utf8.RuneSelf {
				t.Errorf("%s: byte %d is 0x%02X; write a non-ASCII rune as an escape", e.Name(), i, c)
				break
			}
		}
	}
}
