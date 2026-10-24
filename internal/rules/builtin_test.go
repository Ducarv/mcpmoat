package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
	builtinrules "github.com/Ducarv/mcpmoat/rules"
)

// builtinCompiler returns the Compiler that runs the cases of the built-in
// rules.
func builtinCompiler() Compiler {
	return func(m Match, t Target) (*Matcher, error) { return m.CompileFor(t) }
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
		target Target // when set, the case runs only on the rules with this target
		mutate func(r *Rule)
		want   string
	}{
		{"no should_not_match", "", func(r *Rule) { r.ShouldNotMatch = nil }, "no should_not_match case"},
		{"empty should_not_match", "", func(r *Rule) { r.ShouldNotMatch = []Case{} }, "no should_not_match case"},
		{"no should_match", "", func(r *Rule) { r.ShouldMatch = nil }, "no should_match case"},
		{"empty risk", "", func(r *Rule) { r.Risk = "" }, "risk is empty"},
		{"empty remediation", "", func(r *Rule) { r.Remediation = "" }, "remediation is empty"},
		{
			name:   "schema case not JSON",
			target: TargetSchema,
			mutate: func(r *Rule) {
				// A new slice, so the shared rule keeps its cases.
				r.ShouldMatch = append([]Case{{Text: "{not json"}}, r.ShouldMatch...)
			},
			want: "should_match[0] is not valid JSON",
		},
	}
	schemaRules := 0
	for _, r := range rs {
		if r.Target == TargetSchema {
			schemaRules++
		}
		for _, tt := range tests {
			if tt.target != "" && r.Target != tt.target {
				continue
			}
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
	if schemaRules == 0 {
		t.Error("no built-in schema rule, so the JSON case check ran on no rule")
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

// TestShadowingRegexesInStep checks that the two MOAT-T3-001 patterns share
// the tool-name group and the keyword tail, so the active and the passive form
// accept the same tool names and keywords.
func TestShadowingRegexesInStep(t *testing.T) {
	t.Parallel()
	var patterns []string
	for _, r := range mustBuiltin(t) {
		if r.ID == RuleShadowing {
			patterns = r.Match.AnyRegex
		}
	}
	if len(patterns) != 2 {
		t.Fatalf("%s has %d any_regex patterns, want 2", RuleShadowing, len(patterns))
	}
	// The name group runs from its first "(?:`" to the first "`?)" after it.
	// The keyword tail starts at the window [\s\S]{0,80}.
	parts := func(re string) (name, tail string) {
		start := strings.Index(re, "(?:`")
		end := strings.Index(re[max(start, 0):], "`?)")
		window := strings.Index(re, `[\s\S]{0,80}`)
		if start < 0 || end < 0 || window < 0 {
			t.Fatalf("pattern %q has no name group or keyword window", re)
		}
		return re[start : start+end+len("`?)")], re[window:]
	}
	name0, tail0 := parts(patterns[0])
	name1, tail1 := parts(patterns[1])
	if name0 != name1 {
		t.Errorf("name groups differ:\n%s\n%s", name0, name1)
	}
	if tail0 != tail1 {
		t.Errorf("keyword tails differ:\n%s\n%s", tail0, tail1)
	}
}

// TestBuiltinRulesASCII checks that every built-in rule file is ASCII. A rule
// writes a special rune as an escape, so an invisible or look-alike rune
// cannot hide in a pattern or a case, and a case tests the escape it names.
func TestBuiltinRulesASCII(t *testing.T) {
	t.Parallel()

	// The embed pattern in rules/embed.go is *.yaml, so every entry is a file.
	entries, err := fs.ReadDir(builtinrules.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := fs.ReadFile(builtinrules.FS, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for i, c := range b {
			if c >= utf8.RuneSelf {
				line := bytes.Count(b[:i], []byte("\n")) + 1
				col := i - bytes.LastIndexByte(b[:i], '\n')
				t.Errorf("%s:%d:%d: byte 0x%02X; write a non-ASCII rune as an escape", e.Name(), line, col, c)
				break
			}
		}
	}
}

// schemaWithDescription returns a schema with one property whose description
// is text. It encodes the schema as inspect.marshalSchema does: encoding/json
// with no HTML escapes and no final newline.
func schemaWithDescription(t *testing.T, text string) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	schema := map[string]any{"properties": map[string]any{"x": map[string]any{"type": "string", "description": text}}}
	if err := enc.Encode(schema); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// isT1004WordPattern reports whether re is one of the MOAT-T1-004 word
// patterns (keychain, credentials store or file). MOAT-T1-010 leaves them out
// on purpose (see its header comment).
func isT1004WordPattern(re string) bool {
	return strings.Contains(re, "keychain") || strings.Contains(re, `credentials?\s+`)
}

// schemaCopy names a rule with target schema and the description rules whose
// match block it copies. An attacker can hide a prompt in the input schema as
// well as in the description, so most description rules have a schema copy (see
// noSchemaCopy).
type schemaCopy struct {
	schema  string   // the ID of the schema rule
	sources []string // the IDs of the description rules it copies, in order
}

// schemaCopies lists every schema copy of a description rule.
var schemaCopies = []schemaCopy{
	{"MOAT-T1-009", []string{"MOAT-T1-001", "MOAT-T1-003"}},
	{"MOAT-T1-010", []string{"MOAT-T1-004"}}, // without the word patterns
	{"MOAT-T1-011", []string{"MOAT-T1-002"}},
	{"MOAT-T1-012", []string{"MOAT-T1-005"}},
	{"MOAT-T1-013", []string{"MOAT-T1-006"}},
	{"MOAT-T1-014", []string{"MOAT-T1-008"}},
	{"MOAT-T1-016", []string{"MOAT-T1-015"}},
	{"MOAT-T1-019", []string{"MOAT-T1-017"}},
	{"MOAT-T1-020", []string{"MOAT-T1-018"}},
}

// noSchemaCopy holds the T1 description rules that have no schema copy.
// MOAT-T1-007 is low severity and checks the length only.
var noSchemaCopy = map[string]bool{"MOAT-T1-007": true}

// copiedMatch returns the part of the match block of r that its schema copy
// holds. That is the full block, except for MOAT-T1-004: MOAT-T1-010 leaves
// out its word patterns.
func copiedMatch(r Rule) Match {
	if r.ID != "MOAT-T1-004" {
		return r.Match
	}
	var m Match
	for _, re := range r.Match.AnyRegex {
		if !isT1004WordPattern(re) {
			m.AnyRegex = append(m.AnyRegex, re)
		}
	}
	return m
}

// TestSchemaRuleCopiesDescriptionRules checks that each schema rule in
// schemaCopies stays in sync with the description rules it copies:
//   - its match block is the copied match blocks of the sources, joined in
//     order;
//   - its severity is the severity of each source;
//   - put in a schema as a property description, every should_match case of
//     a source matches the schema rule, and no should_not_match case does.
//
// A MOAT-T1-004 should_match case that only its word patterns match is
// skipped, because MOAT-T1-010 leaves those patterns out.
func TestSchemaRuleCopiesDescriptionRules(t *testing.T) {
	t.Parallel()

	byID := make(map[string]Rule)
	for _, r := range mustBuiltin(t, WithCompiler(builtinCompiler())) {
		byID[r.ID] = r
	}
	// loaded returns the rule id with the target want, or stops the test.
	loaded := func(t *testing.T, id string, want Target) Rule {
		t.Helper()
		r, ok := byID[id]
		if !ok {
			t.Fatalf("%s is not loaded", id)
		}
		if r.Target != want {
			t.Fatalf("%s target = %s, want %s", id, r.Target, want)
		}
		return r
	}
	compile := func(t *testing.T, id string, m Match, tg Target) *Matcher {
		t.Helper()
		c, err := m.CompileFor(tg)
		if err != nil {
			t.Fatalf("%s: compile: %v", id, err)
		}
		return c
	}
	// short returns a quoted prefix of a case text for a failure message.
	short := func(s string) string { return termsafe.QuoteCut(s, 40) }

	r004 := loaded(t, "MOAT-T1-004", TargetDescription)
	if len(copiedMatch(r004).AnyRegex) == len(r004.Match.AnyRegex) {
		t.Fatal("MOAT-T1-004 has no word pattern; update isT1004WordPattern")
	}

	for _, tt := range schemaCopies {
		t.Run(tt.schema, func(t *testing.T) {
			t.Parallel()
			dst := loaded(t, tt.schema, TargetSchema)
			schemaRule := compile(t, dst.ID, dst.Match, TargetSchema)

			var want Match
			for _, id := range tt.sources {
				src := loaded(t, id, TargetDescription)
				if dst.Severity != src.Severity {
					t.Errorf("%s severity = %s, want %s like %s", dst.ID, dst.Severity, src.Severity, id)
				}
				part := copiedMatch(src)
				want.AnyRegex = append(want.AnyRegex, part.AnyRegex...)
				want.AllRegex = append(want.AllRegex, part.AllRegex...)
				want.Keywords = append(want.Keywords, part.Keywords...)
				if part.Heuristic != "" {
					if want.Heuristic != "" {
						t.Fatalf("%s joins two heuristic sources; a match block has one heuristic", dst.ID)
					}
					want.Heuristic, want.Params = part.Heuristic, part.Params
				}

				copied := compile(t, id, part, TargetDescription)
				for i, c := range src.ShouldMatch {
					if id == "MOAT-T1-004" && len(copied.Match(c.Text)) == 0 {
						continue // only a word pattern matches, and MOAT-T1-010 leaves those out
					}
					if len(schemaRule.Match(schemaWithDescription(t, c.Text))) == 0 {
						t.Errorf("%s does not match %s should_match[%d] in a schema: %s", dst.ID, id, i, short(c.Text))
					}
				}
				for i, c := range src.ShouldNotMatch {
					if len(schemaRule.Match(schemaWithDescription(t, c.Text))) > 0 {
						t.Errorf("%s matches %s should_not_match[%d] in a schema: %s", dst.ID, id, i, short(c.Text))
					}
				}
			}
			// reflect.DeepEqual compares the lists item by item, in order,
			// and the params map key by key.
			if !reflect.DeepEqual(dst.Match, want) {
				t.Errorf("%s match block is not the copy of %v:\n got: %+v\nwant: %+v", dst.ID, tt.sources, dst.Match, want)
			}
		})
	}
}

// TestEveryT1DescriptionRuleHasSchemaCopy checks that schemaCopies or
// noSchemaCopy names every T1 description rule. So a new description rule
// cannot lose its schema copy.
func TestEveryT1DescriptionRuleHasSchemaCopy(t *testing.T) {
	t.Parallel()
	copied := make(map[string]bool)
	for _, c := range schemaCopies {
		for _, id := range c.sources {
			copied[id] = true
		}
	}
	for _, r := range mustBuiltin(t) {
		if r.Target != TargetDescription || !strings.HasPrefix(r.ID, "MOAT-T1-") {
			continue
		}
		if !copied[r.ID] && !noSchemaCopy[r.ID] {
			t.Errorf("%s has no schema copy: add the copy to rules/ and to schemaCopies, or add %s to noSchemaCopy with a reason", r.ID, r.ID)
		}
	}
}
