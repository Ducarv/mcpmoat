package rules

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// testRule returns a minimal rule with the given ID and source file.
func testRule(id, source string) Rule {
	return Rule{ID: id, Title: "title " + id, Source: source}
}

// ruleIDs returns the IDs of rules, in order.
func ruleIDs(rules []Rule) []string {
	ids := make([]string, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	return ids
}

// mustNewSet calls NewSet and fails the test if it returns errors.
func mustNewSet(t *testing.T, builtin, external []Rule) *Set {
	t.Helper()
	s, errs := NewSet(builtin, external)
	if len(errs) != 0 {
		t.Fatalf("NewSet() errors = %v, want none", errs)
	}
	if s == nil {
		t.Fatal("NewSet() set = nil, want non-nil")
	}
	return s
}

// requireOneError fails the test unless errs has exactly one error with the
// given reason, file and field "id", and a nil set. It returns that error.
func requireOneError(t *testing.T, s *Set, errs []*LoadError, reason Reason, file string) *LoadError {
	t.Helper()
	if s != nil {
		t.Errorf("NewSet() set = %v, want nil when there are errors", s)
	}
	if len(errs) != 1 {
		t.Fatalf("NewSet() returned %d errors (%v), want 1", len(errs), errs)
	}
	var le *LoadError
	if !errors.As(error(errs[0]), &le) {
		t.Fatalf("errors.As(%T, *LoadError) = false", errs[0])
	}
	if le.Reason != reason {
		t.Errorf("Reason = %q, want %q", le.Reason, reason)
	}
	if le.File != file {
		t.Errorf("File = %q, want %q", le.File, file)
	}
	if le.Field != "id" {
		t.Errorf("Field = %q, want %q", le.Field, "id")
	}
	if le.Err == nil {
		t.Fatal("Err = nil, want an error that names the first source")
	}
	return le
}

func TestNewSetEmptyInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		builtin  []Rule
		external []Rule
	}{
		{name: "both nil"},
		{name: "both empty", builtin: []Rule{}, external: []Rule{}},
		{name: "nil builtin, empty external", external: []Rule{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, errs := NewSet(tt.builtin, tt.external)
			if len(errs) != 0 {
				t.Fatalf("NewSet() errors = %v, want none", errs)
			}
			if s == nil {
				t.Fatal("NewSet() set = nil, want non-nil empty set")
			}
			if got := s.Len(); got != 0 {
				t.Errorf("Len() = %d, want 0", got)
			}
			if got := s.Rules(); len(got) != 0 {
				t.Errorf("Rules() = %v, want empty", got)
			}
			if _, ok := s.Get("MOAT-X-001"); ok {
				t.Error("Get() on empty set found a rule")
			}
		})
	}
}

func TestNewSetSortsByID(t *testing.T) {
	t.Parallel()
	builtin := []Rule{
		testRule("MOAT-T2-001", "b2.yaml"),
		testRule("MOAT-T1-002", "b1.yaml"),
	}
	external := []Rule{
		testRule("MOAT-T3-001", "e3.yaml"),
		testRule("MOAT-T1-001", "e1.yaml"),
		testRule("MOAT-T1-012", "e10.yaml"),
	}
	want := []string{"MOAT-T1-001", "MOAT-T1-002", "MOAT-T1-012", "MOAT-T2-001", "MOAT-T3-001"}

	s := mustNewSet(t, builtin, external)
	if got := ruleIDs(s.Rules()); !slices.Equal(got, want) {
		t.Errorf("Rules() IDs = %v, want %v", got, want)
	}
	if got := s.Len(); got != len(want) {
		t.Errorf("Len() = %d, want %d", got, len(want))
	}
}

func TestNewSetOrderIndependentOfInput(t *testing.T) {
	t.Parallel()
	all := []Rule{
		testRule("MOAT-A-001", "a.yaml"),
		testRule("MOAT-B-001", "b.yaml"),
		testRule("MOAT-C-001", "c.yaml"),
		testRule("MOAT-D-001", "d.yaml"),
		testRule("MOAT-E-001", "e.yaml"),
		testRule("MOAT-F-001", "f.yaml"),
	}
	want := mustNewSet(t, nil, all).Rules()
	if got := ruleIDs(want); !slices.IsSorted(got) {
		t.Fatalf("baseline IDs %v are not sorted", got)
	}

	for i := range uint32(20) {
		t.Run(fmt.Sprintf("permutation %d", i), func(t *testing.T) {
			t.Parallel()
			shuffled := slices.Clone(all)
			// Deterministic Fisher-Yates driven by a tiny linear congruential generator,
			// so each permutation number i gives the same order on every run.
			state := i*2654435761 + 1
			next := func(n int) int {
				state = state*1664525 + 1013904223
				return int(state>>16) % n
			}
			for j := len(shuffled) - 1; j > 0; j-- {
				k := next(j + 1)
				shuffled[j], shuffled[k] = shuffled[k], shuffled[j]
			}
			// Also move a varying cut of the rules into the built-in list.
			cut := next(len(shuffled) + 1)
			s := mustNewSet(t, shuffled[:cut], shuffled[cut:])
			if got := s.Rules(); !reflect.DeepEqual(got, want) {
				t.Errorf("Rules() = %v, want %v", ruleIDs(got), ruleIDs(want))
			}
		})
	}
}

func TestSetGet(t *testing.T) {
	t.Parallel()
	s := mustNewSet(t,
		[]Rule{testRule("MOAT-X-001", "builtin.yaml")},
		[]Rule{testRule("MOAT-X-002", "external.yaml")},
	)
	tests := []struct {
		name       string
		id         string
		wantOK     bool
		wantSource string
	}{
		{name: "builtin hit", id: "MOAT-X-001", wantOK: true, wantSource: "builtin.yaml"},
		{name: "external hit", id: "MOAT-X-002", wantOK: true, wantSource: "external.yaml"},
		{name: "miss", id: "MOAT-X-003"},
		{name: "empty id", id: ""},
		{name: "lower case is a different id", id: "moat-x-001"},
		{name: "prefix is not a hit", id: "MOAT-X-00"},
		{name: "trailing space is not a hit", id: "MOAT-X-001 "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := s.Get(tt.id)
			if ok != tt.wantOK {
				t.Fatalf("Get(%q) ok = %v, want %v", tt.id, ok, tt.wantOK)
			}
			if !ok {
				if !reflect.DeepEqual(got, Rule{}) {
					t.Errorf("Get(%q) = %+v on a miss, want zero Rule", tt.id, got)
				}
				return
			}
			if got.ID != tt.id || got.Source != tt.wantSource {
				t.Errorf("Get(%q) = {ID:%q Source:%q}, want Source %q", tt.id, got.ID, got.Source, tt.wantSource)
			}
		})
	}
}

// TestNewSetDuplicatesAreCaseSensitive checks that IDs that differ only in
// case are different IDs, except for an external ID against a built-in ID.
func TestNewSetDuplicatesAreCaseSensitive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		builtin  []Rule
		external []Rule
	}{
		{
			name:     "two external IDs",
			external: []Rule{testRule("x-1", "a.yaml"), testRule("X-1", "b.yaml")},
		},
		{
			name:    "two built-in IDs",
			builtin: []Rule{testRule("x-1", "a.yaml"), testRule("X-1", "b.yaml")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := mustNewSet(t, tt.builtin, tt.external)
			if got := s.Len(); got != 2 {
				t.Errorf("Len() = %d, want 2 (IDs differ by case)", got)
			}
			for _, id := range []string{"x-1", "X-1"} {
				if _, ok := s.Get(id); !ok {
					t.Errorf("Get(%q) ok = false, want true", id)
				}
			}
		})
	}
}

func TestNewSetDuplicateID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		builtin    []Rule
		external   []Rule
		wantReason Reason
		wantFile   string
		wantFirst  string
	}{
		{
			name: "duplicate inside external",
			external: []Rule{
				testRule("MOAT-X-001", "first.yaml"),
				testRule("MOAT-X-002", "other.yaml"),
				testRule("MOAT-X-001", "second.yaml"),
			},
			wantReason: ReasonDuplicateID,
			wantFile:   "second.yaml",
			wantFirst:  "first.yaml",
		},
		{
			name: "duplicate inside builtin",
			builtin: []Rule{
				testRule("MOAT-X-001", "first.yaml"),
				testRule("MOAT-X-001", "second.yaml"),
			},
			external:   []Rule{testRule("MOAT-X-002", "other.yaml")},
			wantReason: ReasonDuplicateID,
			wantFile:   "second.yaml",
			wantFirst:  "first.yaml",
		},
		{
			name:       "external id equals builtin id",
			builtin:    []Rule{testRule("MOAT-X-001", "builtin.yaml")},
			external:   []Rule{testRule("MOAT-X-001", "external.yaml")},
			wantReason: ReasonBuiltinIDClash,
			wantFile:   "external.yaml",
			wantFirst:  "builtin.yaml",
		},
		{
			name:       "external id equals builtin id in lower case",
			builtin:    []Rule{testRule("MOAT-T1-003", "builtin.yaml")},
			external:   []Rule{testRule("moat-t1-003", "external.yaml")},
			wantReason: ReasonBuiltinIDClash,
			wantFile:   "external.yaml",
			wantFirst:  "builtin.yaml",
		},
		{
			name:       "external id equals builtin id in mixed case",
			builtin:    []Rule{testRule("MOAT-T1-003", "builtin.yaml")},
			external:   []Rule{testRule("Moat-T1-003", "external.yaml")},
			wantReason: ReasonBuiltinIDClash,
			wantFile:   "external.yaml",
			wantFirst:  "builtin.yaml",
		},
		{
			name:       "builtin id in lower case, external id in upper case",
			builtin:    []Rule{testRule("moat-t1-003", "builtin.yaml")},
			external:   []Rule{testRule("MOAT-T1-003", "external.yaml")},
			wantReason: ReasonBuiltinIDClash,
			wantFile:   "external.yaml",
			wantFirst:  "builtin.yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, errs := NewSet(tt.builtin, tt.external)
			le := requireOneError(t, s, errs, tt.wantReason, tt.wantFile)
			if !strings.Contains(le.Err.Error(), tt.wantFirst) {
				t.Errorf("Err = %q, want it to name %q", le.Err, tt.wantFirst)
			}
			if strings.Contains(le.Err.Error(), tt.wantFile) {
				t.Errorf("Err = %q, must not name the second file %q", le.Err, tt.wantFile)
			}
			if !errors.Is(errs[0], le.Err) {
				t.Error("errors.Is(error, Err) = false, want true (Unwrap)")
			}
			if msg := errs[0].Error(); !strings.Contains(msg, tt.wantFile) || !strings.Contains(msg, string(tt.wantReason)) {
				t.Errorf("Error() = %q, want it to hold the file and the reason", msg)
			}
		})
	}
}

func TestNewSetSeveralErrorsInFixedOrder(t *testing.T) {
	t.Parallel()
	builtin := []Rule{
		testRule("B-1", "b1.yaml"),
		testRule("B-2", "b2.yaml"),
		testRule("B-1", "b1dup.yaml"), // builtin duplicate
		testRule("B-2", "b2dup.yaml"), // builtin duplicate
	}
	external := []Rule{
		testRule("E-1", "e1.yaml"),
		testRule("B-2", "clash.yaml"), // clash with builtin
		testRule("E-1", "e1dup.yaml"), // external duplicate
		testRule("E-2", "e2.yaml"),
	}
	want := []struct {
		file   string
		reason Reason
	}{
		{"b1dup.yaml", ReasonDuplicateID},
		{"b2dup.yaml", ReasonDuplicateID},
		{"clash.yaml", ReasonBuiltinIDClash},
		{"e1dup.yaml", ReasonDuplicateID},
	}

	var previous []string
	for run := range 2 {
		s, errs := NewSet(builtin, external)
		if s != nil {
			t.Fatalf("run %d: set = %v, want nil", run, s)
		}
		if len(errs) != len(want) {
			t.Fatalf("run %d: got %d errors (%v), want %d", run, len(errs), errs, len(want))
		}
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
			if e.File != want[i].file || e.Reason != want[i].reason {
				t.Errorf("run %d: errs[%d] = {File:%q Reason:%q}, want {File:%q Reason:%q}",
					run, i, e.File, e.Reason, want[i].file, want[i].reason)
			}
		}
		if run > 0 && !slices.Equal(msgs, previous) {
			t.Errorf("run %d: messages %v differ from run 0: %v", run, msgs, previous)
		}
		previous = msgs
	}
}

func TestSetRulesReturnsCopy(t *testing.T) {
	t.Parallel()
	s := mustNewSet(t, []Rule{testRule("MOAT-A-001", "a.yaml")}, []Rule{
		testRule("MOAT-B-001", "b.yaml"),
		testRule("MOAT-C-001", "c.yaml"),
	})
	want := []string{"MOAT-A-001", "MOAT-B-001", "MOAT-C-001"}

	got := s.Rules()
	slices.Reverse(got)
	got[0].ID = "CHANGED"

	if after := ruleIDs(s.Rules()); !slices.Equal(after, want) {
		t.Errorf("Rules() after caller reordered the copy = %v, want %v", after, want)
	}
	if _, ok := s.Get("MOAT-C-001"); !ok {
		t.Error("Get(MOAT-C-001) = false after caller changed the copy")
	}
	if _, ok := s.Get("CHANGED"); ok {
		t.Error("Get(CHANGED) = true: caller change reached the set")
	}

	// Truncating the copy must not change the set either.
	short := s.Rules()[:1]
	if len(short) != 1 || s.Len() != 3 {
		t.Errorf("after truncating a copy: Len() = %d, want 3", s.Len())
	}
	if got := len(s.Rules()); got != 3 {
		t.Errorf("len(Rules()) = %d, want 3", got)
	}
}

func TestSetNilIsSafe(t *testing.T) {
	t.Parallel()
	var s *Set
	if got := s.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
	if got := s.Rules(); got != nil {
		t.Errorf("Rules() = %v, want nil", got)
	}
	r, ok := s.Get("MOAT-X-001")
	if ok {
		t.Error("Get() ok = true, want false")
	}
	if !reflect.DeepEqual(r, Rule{}) {
		t.Errorf("Get() = %+v, want zero Rule", r)
	}
}

// manyRules returns n rules with unique IDs that start with prefix.
func manyRules(prefix string, n int) []Rule {
	rules := make([]Rule, n)
	for i := range rules {
		rules[i] = testRule(fmt.Sprintf("%s-%05d", prefix, i), "f.yaml")
	}
	return rules
}

func TestNewSetRuleLimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		builtinN, extN  int
		wantTooMany     bool
		wantLen         int
		duplicateAlsoIn bool
	}{
		{name: "exactly at the limit", builtinN: 2500, extN: 2500, wantLen: 5000},
		{name: "one over the limit", builtinN: 2500, extN: 2501, wantTooMany: true},
		{name: "all external over the limit", builtinN: 0, extN: 5001, wantTooMany: true},
		{name: "all builtin over the limit", builtinN: 5001, extN: 0, wantTooMany: true},
		{name: "limit beats duplicate check", builtinN: 5000, extN: 1, wantTooMany: true, duplicateAlsoIn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			builtin := manyRules("B", tt.builtinN)
			external := manyRules("E", tt.extN)
			if tt.duplicateAlsoIn {
				external[0].ID = builtin[0].ID
			}
			s, errs := NewSet(builtin, external)
			if !tt.wantTooMany {
				if len(errs) != 0 || s == nil {
					t.Fatalf("NewSet() = (%v, %v), want a set and no errors", s, errs)
				}
				if got := s.Len(); got != tt.wantLen {
					t.Errorf("Len() = %d, want %d", got, tt.wantLen)
				}
				return
			}
			if s != nil {
				t.Errorf("set = non-nil, want nil")
			}
			if len(errs) != 1 {
				t.Fatalf("got %d errors, want exactly 1", len(errs))
			}
			if errs[0].Reason != ReasonTooManyRules {
				t.Errorf("Reason = %q, want %q", errs[0].Reason, ReasonTooManyRules)
			}
			if errs[0].File != "rule set" {
				t.Errorf("File = %q, want %q", errs[0].File, "rule set")
			}
			if got, want := errs[0].Error(), "rule set: too many rules"; got != want {
				t.Errorf("Error() = %q, want %q", got, want)
			}
		})
	}
}

func TestNewSetErrorMessagesEscapeUntrustedSources(t *testing.T) {
	t.Parallel()
	const evil = "evil\x1b[31m\nfile.yaml"
	const evil2 = "worse\x07\r\x7f.yaml"
	tests := []struct {
		name     string
		builtin  []Rule
		external []Rule
		wantN    int
	}{
		{
			name: "duplicate in external, evil second file",
			external: []Rule{
				testRule("MOAT-X-001", "ok.yaml"),
				testRule("MOAT-X-001", evil),
			},
			wantN: 1,
		},
		{
			name: "duplicate in external, evil first file",
			external: []Rule{
				testRule("MOAT-X-001", evil),
				testRule("MOAT-X-001", "ok.yaml"),
			},
			wantN: 1,
		},
		{
			name:     "builtin clash, both files evil",
			builtin:  []Rule{testRule("MOAT-X-001", evil2)},
			external: []Rule{testRule("MOAT-X-001", evil)},
			wantN:    1,
		},
		{
			name:     "builtin clash in other case, both files evil",
			builtin:  []Rule{testRule("MOAT-X-001", evil2)},
			external: []Rule{testRule("moat-x-001", evil)},
			wantN:    1,
		},
		{
			name: "duplicate in builtin",
			builtin: []Rule{
				testRule("MOAT-X-001", evil),
				testRule("MOAT-X-001", evil2),
			},
			wantN: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, errs := NewSet(tt.builtin, tt.external)
			if s != nil {
				t.Errorf("set = non-nil, want nil")
			}
			if len(errs) != tt.wantN {
				t.Fatalf("got %d errors, want %d", len(errs), tt.wantN)
			}
			for _, e := range errs {
				noRawControls(t, e.Error())
				// The raw name stays in File for programs; only the message is escaped.
				if strings.Contains(e.Error(), "\x1b") {
					t.Errorf("Error() = %q holds a raw ESC byte", e.Error())
				}
			}
		})
	}
}

// capClashRules returns one built-in rule and n external rules that all reuse
// its ID. The external sources are ext0000.yaml, ext0001.yaml and so on, so
// NewSet returns n ReasonBuiltinIDClash errors in this order.
func capClashRules(n int) (builtin, external []Rule) {
	builtin = []Rule{testRule("B-1", "builtin.yaml")}
	external = make([]Rule, n)
	for i := range external {
		external[i] = testRule("B-1", fmt.Sprintf("ext%04d.yaml", i))
	}
	return builtin, external
}

// errorMessages returns the Error() text of each error.
func errorMessages(errs []*LoadError) []string {
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	return msgs
}

// requireCapSummary fails the test unless e is the summary error of NewSet that
// says that more errors were not shown.
func requireCapSummary(t *testing.T, e *LoadError, more int) {
	t.Helper()
	if e.File != "rule set" {
		t.Errorf("summary File = %q, want %q", e.File, "rule set")
	}
	if e.Reason != ReasonTooManyErrors {
		t.Errorf("summary Reason = %q, want %q", e.Reason, ReasonTooManyErrors)
	}
	want := fmt.Sprintf("rule set: too many errors: %d more errors not shown", more)
	if got := e.Error(); got != want {
		t.Errorf("summary Error() = %q, want %q", got, want)
	}
}

func TestNewSetErrorCap(t *testing.T) {
	t.Parallel()

	// The run with exactly maxSetErrors errors has no summary. The longer runs
	// must start with the same errors.
	base, baseErrs := NewSet(capClashRules(100))
	if base != nil || len(baseErrs) != 100 {
		t.Fatalf("baseline NewSet() = (%v, %d errors), want nil and 100 errors", base, len(baseErrs))
	}
	baseMsgs := errorMessages(baseErrs)

	tests := []struct {
		name     string
		n        int
		wantErrs int // length of the returned slice
		wantMore int // 0 means no summary entry
	}{
		{name: "below the cap", n: 99, wantErrs: 99},
		{name: "exactly at the cap", n: 100, wantErrs: 100},
		{name: "one over the cap", n: 101, wantErrs: 101, wantMore: 1},
		{name: "far over the cap", n: 1000, wantErrs: 101, wantMore: 900},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			builtin, external := capClashRules(tt.n)
			s, errs := NewSet(builtin, external)
			if s != nil {
				t.Errorf("set = non-nil, want nil")
			}
			if len(errs) != tt.wantErrs {
				t.Fatalf("got %d errors, want %d", len(errs), tt.wantErrs)
			}
			shown := min(tt.n, 100)
			for i, e := range errs[:shown] {
				wantFile := fmt.Sprintf("ext%04d.yaml", i)
				if e.File != wantFile || e.Reason != ReasonBuiltinIDClash {
					t.Fatalf("errs[%d] = {File:%q Reason:%q}, want {File:%q Reason:%q}",
						i, e.File, e.Reason, wantFile, ReasonBuiltinIDClash)
				}
			}
			if tt.wantMore == 0 {
				for _, e := range errs {
					if e.Reason == ReasonTooManyErrors {
						t.Errorf("unexpected summary error %q", e.Error())
					}
				}
			} else {
				requireCapSummary(t, errs[len(errs)-1], tt.wantMore)
			}

			msgs := errorMessages(errs)
			if !slices.Equal(msgs[:shown], baseMsgs[:shown]) {
				t.Error("the first 100 errors differ from the run with exactly 100 errors")
			}
			for _, m := range msgs {
				noRawControls(t, m)
			}

			// A second call gives the same messages.
			_, again := NewSet(builtin, external)
			if !slices.Equal(errorMessages(again), msgs) {
				t.Error("second call returned different messages")
			}
		})
	}

	t.Run("cap counts both kinds of error together", func(t *testing.T) {
		t.Parallel()
		const builtinDups = 30
		builtin := []Rule{testRule("B-1", "builtin.yaml")}
		for i := range builtinDups {
			builtin = append(builtin, testRule("B-1", fmt.Sprintf("bdup%04d.yaml", i)))
		}
		// External: the first E-1, then clashes and E-1 duplicates in turn.
		external := []Rule{testRule("E-1", "first.yaml")}
		const pairs = 60
		for i := range pairs {
			external = append(external,
				testRule("B-1", fmt.Sprintf("extc%04d.yaml", i)),
				testRule("E-1", fmt.Sprintf("extd%04d.yaml", i)),
			)
		}
		// 30 + 120 = 150 problems; neither kind alone reaches 100.
		type fileReason struct {
			file   string
			reason Reason
		}
		var want []fileReason
		for i := range builtinDups {
			want = append(want, fileReason{fmt.Sprintf("bdup%04d.yaml", i), ReasonDuplicateID})
		}
		for i := range pairs {
			want = append(want,
				fileReason{fmt.Sprintf("extc%04d.yaml", i), ReasonBuiltinIDClash},
				fileReason{fmt.Sprintf("extd%04d.yaml", i), ReasonDuplicateID},
			)
		}
		const more = builtinDups + 2*pairs - 100

		s, errs := NewSet(builtin, external)
		if s != nil {
			t.Errorf("set = non-nil, want nil")
		}
		if len(errs) != 101 {
			t.Fatalf("got %d errors, want 101", len(errs))
		}
		for i, e := range errs[:100] {
			if e.File != want[i].file || e.Reason != want[i].reason {
				t.Fatalf("errs[%d] = {File:%q Reason:%q}, want {File:%q Reason:%q}",
					i, e.File, e.Reason, want[i].file, want[i].reason)
			}
		}
		requireCapSummary(t, errs[100], more)
		msgs := errorMessages(errs)
		for _, m := range msgs {
			noRawControls(t, m)
		}
		_, again := NewSet(builtin, external)
		if !slices.Equal(errorMessages(again), msgs) {
			t.Error("second call returned different messages")
		}
	})
}

// reservedIDText is the documented Error() text of a ReasonReservedID error
// for the external rule file ext.yaml.
const reservedIDText = "ext.yaml: field id: rule ID is reserved for a native mcpmoat rule"

func TestReservedRuleID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		id   string
		want bool
	}{
		// The rule analysis budget finding: one exact ID, in any case.
		{id: "MOAT-T1-023", want: true},
		{id: "moat-t1-023", want: true},
		{id: "Moat-T1-023", want: true},
		// The tool finding cap finding: one exact ID, in any case.
		{id: "MOAT-T1-024", want: true},
		{id: "moat-t1-024", want: true},
		{id: "Moat-T1-024", want: true},
		// The config finding cap finding: one exact ID, in any case.
		{id: "MOAT-T4-005", want: true},
		{id: "moat-t4-005", want: true},
		{id: "Moat-T4-005", want: true},
		// The pin findings: the whole MOAT-T2- family, in any case.
		{id: "MOAT-T2-001", want: true},
		{id: "MOAT-T2-002", want: true},
		{id: "MOAT-T2-003", want: true},
		{id: "MOAT-T2-004", want: true},
		{id: "MOAT-T2-999", want: true},
		{id: "MOAT-T2-", want: true},
		{id: "moat-t2-001", want: true},
		{id: "Moat-t2-004", want: true},
		// The LLM findings: the whole MOAT-LLM- family, in any case.
		{id: "MOAT-LLM-001", want: true},
		{id: "MOAT-LLM-002", want: true},
		{id: "MOAT-LLM-003", want: true},
		{id: "moat-llm-001", want: true},
		{id: "Moat-Llm-002", want: true},
		// IDs that only look close to a reserved ID.
		{id: ""},
		{id: "MOAT-T1-001"},
		{id: "MOAT-T1-022"},
		{id: "MOAT-T1-025"},
		{id: "MOAT-T1-0240"},
		{id: "MOAT-T1-024-x"},
		{id: "MOAT-T1-0230"},
		{id: "MOAT-T1-023-x"},
		{id: "MOAT-T4-004"},
		{id: "MOAT-T4-006"},
		{id: "MOAT-T4-0050"},
		{id: "MOAT-T4-005-x"},
		{id: "MOAT-T2"},
		{id: "MOAT-T3-001"},
		{id: "MOAT-T12-001"},
		{id: "MOAT-LLM"},
		{id: "XMOAT-T2-001"},
		{id: "ACME-T2-001"},
		{id: "ACME-LLM-001"},
		{id: "MOAT_T2_001"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			t.Parallel()
			if got := ReservedRuleID(tt.id); got != tt.want {
				t.Errorf("ReservedRuleID(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

// TestNewSetReservedID checks that NewSet refuses an external rule with a
// reserved ID, in any case, with the documented error, and that it accepts a
// normal external ID.
func TestNewSetReservedID(t *testing.T) {
	t.Parallel()
	builtin := []Rule{testRule("MOAT-T1-001", "builtin.yaml")}
	tests := []struct {
		id       string
		reserved bool
	}{
		{id: RuleAnalysisBudget, reserved: true},
		{id: "moat-t1-023", reserved: true},
		{id: "Moat-T1-023", reserved: true},
		{id: RuleToolFindingCap, reserved: true},
		{id: "moat-t1-024", reserved: true},
		{id: "Moat-T1-024", reserved: true},
		{id: RuleConfigFindingCap, reserved: true},
		{id: "moat-t4-005", reserved: true},
		{id: "Moat-T4-005", reserved: true},
		{id: "MOAT-T2-001", reserved: true},
		{id: "MOAT-T2-002", reserved: true},
		{id: "MOAT-T2-003", reserved: true},
		{id: "MOAT-T2-004", reserved: true},
		{id: "moat-t2-001", reserved: true},
		{id: "mOaT-T2-003", reserved: true},
		{id: "MOAT-T2-077", reserved: true},
		{id: "MOAT-LLM-001", reserved: true},
		{id: "MOAT-LLM-002", reserved: true},
		{id: "moat-llm-002", reserved: true},
		{id: "Moat-Llm-001", reserved: true},
		{id: "ACME-001"},
		{id: "MOAT-T1-025"},
		{id: "MOAT-T4-006"},
		{id: "MOAT-T3-777"},
		{id: "acme.t2-001"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			t.Parallel()
			external := []Rule{testRule("ACME-OK-1", "ok.yaml"), testRule(tt.id, "ext.yaml")}
			s, errs := NewSet(builtin, external)
			if !tt.reserved {
				if len(errs) != 0 || s == nil {
					t.Fatalf("NewSet() = (%v, %v), want a set and no errors", s, errs)
				}
				if _, ok := s.Get(tt.id); !ok {
					t.Errorf("Get(%q) ok = false, want true", tt.id)
				}
				return
			}
			if s != nil {
				t.Errorf("NewSet() set = %v, want nil when there are errors", s)
			}
			if _, ok := s.Get(tt.id); ok {
				t.Errorf("Get(%q) ok = true, want false for a reserved ID", tt.id)
			}
			if len(errs) != 1 {
				t.Fatalf("NewSet() returned %d errors (%v), want 1", len(errs), errs)
			}
			e := errs[0]
			if e.Reason != ReasonReservedID || e.File != "ext.yaml" || e.Field != "id" || e.Err != nil {
				t.Errorf("error = {File:%q Field:%q Reason:%q Err:%v}, want {File:%q Field:%q Reason:%q Err:<nil>}",
					e.File, e.Field, e.Reason, e.Err, "ext.yaml", "id", ReasonReservedID)
			}
			if got := e.Error(); got != reservedIDText {
				t.Errorf("Error() = %q, want %q", got, reservedIDText)
			}
		})
	}
}

// TestNewSetReservedIDOrder checks that a reserved ID error comes in input
// order among the other errors, and that a reserved ID used twice gives two
// reserved ID errors and no duplicate ID error.
func TestNewSetReservedIDOrder(t *testing.T) {
	t.Parallel()
	builtin := []Rule{testRule("B-1", "b1.yaml"), testRule("B-1", "b1dup.yaml")}
	external := []Rule{
		testRule("E-1", "e1.yaml"),
		testRule("MOAT-T2-001", "pin1.yaml"),
		testRule("B-1", "clash.yaml"),
		testRule("moat-t2-001", "pin2.yaml"),
		testRule("E-1", "e1dup.yaml"),
		testRule("MOAT-T2-001", "pin3.yaml"),
	}
	want := []struct {
		file   string
		reason Reason
	}{
		{"b1dup.yaml", ReasonDuplicateID},
		{"pin1.yaml", ReasonReservedID},
		{"clash.yaml", ReasonBuiltinIDClash},
		{"pin2.yaml", ReasonReservedID},
		{"e1dup.yaml", ReasonDuplicateID},
		{"pin3.yaml", ReasonReservedID},
	}
	s, errs := NewSet(builtin, external)
	if s != nil {
		t.Errorf("set = %v, want nil", s)
	}
	if len(errs) != len(want) {
		t.Fatalf("got %d errors (%v), want %d", len(errs), errs, len(want))
	}
	for i, e := range errs {
		if e.File != want[i].file || e.Reason != want[i].reason {
			t.Errorf("errs[%d] = {File:%q Reason:%q}, want {File:%q Reason:%q}",
				i, e.File, e.Reason, want[i].file, want[i].reason)
		}
	}
}

// TestNewSetReservedIDErrorCap checks that the reserved ID errors count
// toward maxSetErrors, alone and together with the clash errors.
func TestNewSetReservedIDErrorCap(t *testing.T) {
	t.Parallel()
	reservedIDs := []string{RuleAnalysisBudget, "MOAT-T2-001", "moat-llm-002"}

	tests := []struct {
		name      string
		n         int  // number of external rules
		withClash bool // every second external rule clashes with a built-in rule
		wantErrs  int  // length of the returned slice
		wantMore  int  // 0 means no summary entry
	}{
		{name: "reserved only, at the cap", n: 100, wantErrs: 100},
		{name: "reserved only, over the cap", n: 150, wantErrs: 101, wantMore: 50},
		{name: "reserved and clash, over the cap", n: 160, withClash: true, wantErrs: 101, wantMore: 60},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			builtin := []Rule{testRule("B-1", "builtin.yaml")}
			external := make([]Rule, tt.n)
			wantReasons := make([]Reason, tt.n)
			for i := range external {
				file := fmt.Sprintf("ext%04d.yaml", i)
				if tt.withClash && i%2 == 1 {
					external[i] = testRule("B-1", file)
					wantReasons[i] = ReasonBuiltinIDClash
					continue
				}
				external[i] = testRule(reservedIDs[i%len(reservedIDs)], file)
				wantReasons[i] = ReasonReservedID
			}

			s, errs := NewSet(builtin, external)
			if s != nil {
				t.Errorf("set = non-nil, want nil")
			}
			if len(errs) != tt.wantErrs {
				t.Fatalf("got %d errors, want %d", len(errs), tt.wantErrs)
			}
			shown := min(tt.n, maxSetErrors)
			for i, e := range errs[:shown] {
				wantFile := fmt.Sprintf("ext%04d.yaml", i)
				if e.File != wantFile || e.Reason != wantReasons[i] {
					t.Fatalf("errs[%d] = {File:%q Reason:%q}, want {File:%q Reason:%q}",
						i, e.File, e.Reason, wantFile, wantReasons[i])
				}
			}
			if tt.wantMore == 0 {
				if errs[len(errs)-1].Reason == ReasonTooManyErrors {
					t.Errorf("unexpected summary error %q", errs[len(errs)-1].Error())
				}
				return
			}
			requireCapSummary(t, errs[len(errs)-1], tt.wantMore)
		})
	}
}
