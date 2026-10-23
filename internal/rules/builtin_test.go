package rules

import (
	"errors"
	"strings"
	"testing"
)

// builtinCompiler returns the Compiler that runs the cases of the built-in
// rules. It is nil while the matchers do not exist.
//
// Issue #35 provides rules.Compile; return it here and the case execution
// test below starts to run.
func builtinCompiler() Compiler {
	return nil
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
			out = append(out, r.ID+": compile: "+err.Error())
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
				// Each subtest breaks its own copy of the struct. The mutate
				// functions replace fields and never write into shared slices.
				r := r
				if got := CheckDocumented(r); len(got) != 0 {
					t.Fatalf("unbroken rule %s has problems: %v", r.ID, got)
				}
				tt.mutate(&r)
				problems := documentedProblems([]Rule{r})
				found := false
				for _, p := range problems {
					if !strings.HasPrefix(p, r.ID+": ") {
						t.Errorf("problem %q does not start with the rule ID %q", p, r.ID)
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
	if c == nil {
		t.Skip("matchers are not implemented yet: issue #35")
	}
	// WithCompiler also checks that the Match section of every rule compiles.
	rs := mustBuiltin(t, WithCompiler(c))
	runBuiltinCases(t, rs, c)
}

// textSetMatcher reports a match for the texts in its set and for no other text.
type textSetMatcher map[string]bool

func (f textSetMatcher) Match(text string) (bool, error) { return f[text], nil }

// builtinShouldMatchTexts collects the should_match texts of rs.
func builtinShouldMatchTexts(rs []Rule) textSetMatcher {
	m := textSetMatcher{}
	for _, r := range rs {
		for _, c := range r.ShouldMatch {
			m[c.Text] = true
		}
	}
	return m
}

// builtinFuncMatcher turns a function into a Matcher, for the fake compilers below.
type builtinFuncMatcher func(string) (bool, error)

func (f builtinFuncMatcher) Match(text string) (bool, error) { return f(text) }

func TestRunBuiltinCasesWithFakeMatcher(t *testing.T) {
	t.Parallel()
	good := func(rs []Rule) Compiler {
		m := builtinShouldMatchTexts(rs)
		return func(Match, Target) (Matcher, error) { return m, nil }
	}

	t.Run("right fake gives no failure", func(t *testing.T) {
		t.Parallel()
		// Builtin(WithCompiler) runs the fake once per rule, as #35 will.
		rs := mustBuiltin(t)
		rs = mustBuiltin(t, WithCompiler(good(rs)))
		runBuiltinCases(t, rs, good(rs))
	})

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
			c:    func(Match, Target) (Matcher, error) { return textSetMatcher{}, nil },
			want: []string{rs[0].ID, string(KindShouldMatch), sm.Text},
		},
		{
			name: "matches everything",
			c: func(Match, Target) (Matcher, error) {
				return builtinFuncMatcher(func(string) (bool, error) { return true, nil }), nil
			},
			want: []string{rs[0].ID, string(KindShouldNotMatch), snm.Text},
		},
		{
			name: "matcher error",
			c: func(Match, Target) (Matcher, error) {
				return builtinFuncMatcher(func(string) (bool, error) { return false, errors.New("boom") }), nil
			},
			want: []string{rs[0].ID, "boom"},
		},
		{
			name: "compile error",
			c:    func(Match, Target) (Matcher, error) { return nil, errors.New("bad pattern") },
			want: []string{rs[0].ID, "bad pattern"},
		},
	}
	for _, tt := range wrong {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			failures := builtinCaseFailures(rs, tt.c)
			if len(failures) == 0 {
				t.Fatal("a wrong fake matcher gave no failure")
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
