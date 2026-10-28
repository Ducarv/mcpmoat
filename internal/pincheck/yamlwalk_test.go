package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// testFile is the file name that the tests give to parseWorkflow.
const testFile = "wf.yml"

// mustParse parses src as the workflow file p and stops the test on an
// error.
func mustParse(t *testing.T, p, src string) *workflow {
	t.Helper()
	w, err := parseWorkflow(p, []byte(src))
	if err != nil {
		t.Fatalf("parseWorkflow(%q) error = %v, want nil", p, err)
	}
	return w
}

// wantErr fails the test unless err is not nil and its text has sub.
func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want an error with %q", sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), sub)
	}
}

// nested returns a flow value of n nested sequences, such as "[[]]" for 2.
func nested(n int) string {
	return strings.Repeat("[", n) + strings.Repeat("]", n)
}

func TestParseWorkflowFailClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string // a substring of the error, or "" for no error
	}{
		// Size limit. The check runs before any decoding.
		{name: "over the size limit", in: "a: 1\n#" + strings.Repeat("x", maxFileBytes), want: "more than the limit of 1048576"},
		{name: "at the size limit", in: "a: 1\n#" + strings.Repeat("x", maxFileBytes-6), want: ""},

		// Documents.
		{name: "two documents", in: "a: 1\n---\nb: 2\n", want: "more than one YAML document"},
		{name: "two separators", in: "---\na: 1\n---\nb: 2\n", want: "more than one YAML document"},
		{name: "trailing separator", in: "a: 1\n---\n", want: "more than one YAML document"},
		{name: "leading separator only", in: "---\na: 1\n", want: ""},
		{name: "document end marker", in: "a: 1\n...\n", want: ""},
		{name: "empty file", in: "", want: "no YAML document"},
		{name: "comments only", in: "# one\n# two\n", want: "no YAML document"},

		// Top level.
		{name: "top level sequence", in: "- a\n- b\n", want: "top level of the workflow must be a mapping"},
		{name: "top level scalar", in: "hello\n", want: "top level of the workflow must be a mapping"},

		// Parse errors.
		{name: "unclosed quote", in: "a: \"x\n", want: "parse YAML: yaml: line"},
		{name: "tab indent", in: "a:\n\tb: 1\n", want: "parse YAML: yaml: line 2"},

		// Aliases, anchors, merge keys.
		{name: "anchor on value", in: "a: &x 1\n", want: "an anchor (&x) is not allowed"},
		{name: "anchor on mapping", in: "a: &m\n  b: 1\n", want: "an anchor (&m) is not allowed"},
		{name: "alias as key", in: "a: &x k\n*x : 1\n", want: "an alias (*x) is not allowed"},
		{name: "anchor on key", in: "&k a: 1\n", want: "an anchor (&k) is not allowed"},
		{name: "merge key plain", in: "<<: {b: 1}\n", want: "a merge key (<<) is not allowed"},
		{name: "merge key quoted", in: "\"<<\": {b: 1}\n", want: "a merge key (<<) is not allowed"},
		{name: "merge key single quoted nested", in: "a:\n  '<<': x\n", want: "a merge key (<<) is not allowed"},

		// Explicit tags.
		{name: "str tag on value", in: "a: !!str 1\n", want: "an explicit tag (!!str) is not allowed"},
		{name: "custom tag on value", in: "a: !foo x\n", want: "an explicit tag (!foo) is not allowed"},
		{name: "tag on key", in: "!!str a: 1\n", want: "an explicit tag (!!str) is not allowed"},
		{name: "tag on sequence", in: "a: !!seq [1]\n", want: "an explicit tag (!!seq) is not allowed"},
		// The non-specific tag "!" leaves no mark in the node (documented in
		// parseWorkflow), and it cannot change the value.
		{name: "non-specific tag accepted", in: "a: ! x\n", want: ""},

		// Keys.
		{name: "sequence key", in: "? [a, b]\n: 1\n", want: "a mapping key must be a scalar, found a sequence"},
		{name: "mapping key", in: "? {a: 1}\n: 1\n", want: "a mapping key must be a scalar, found a mapping"},
		{name: "duplicate key exact", in: "runs-on: a\nruns-on: b\n", want: "the key \"runs-on\" is a duplicate (case-insensitive) of the key on line 1"},
		{name: "duplicate key case variant", in: "runs-on: a\nRuns-On: b\n", want: "the key \"Runs-On\" is a duplicate"},
		{name: "duplicate key quoted variant", in: "env: 1\n\"ENV\": 2\n", want: "the key \"ENV\" is a duplicate"},
		{name: "duplicate key nested", in: "jobs:\n  a:\n    x: 1\n    X: 2\n", want: "the key \"X\" is a duplicate"},
		{name: "non-ASCII key", in: "ﬆeps: 1\n", want: "has a non-ASCII character"},
		{name: "non-ASCII escaped key", in: "\"st\\u0065ps\\u017f\": 1\n", want: "has a non-ASCII character"},
		{name: "non-ASCII value accepted", in: "name: café\n", want: ""},

		// Depth. The value of a has depth 2, so n brackets reach depth n+1.
		{name: "depth at the limit", in: "a: " + nested(maxNodeDepth-1) + "\n", want: ""},
		{name: "depth over the limit", in: "a: " + nested(maxNodeDepth) + "\n", want: "the YAML nesting is deeper than 64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w, err := parseWorkflow(testFile, []byte(tt.in))
			if tt.want == "" {
				if err != nil {
					t.Fatalf("parseWorkflow() error = %v, want nil", err)
				}
				if w == nil || w.top == nil || w.top.Kind != yaml.MappingNode {
					t.Fatalf("parseWorkflow() top = %v, want a mapping", w)
				}
				return
			}
			if w != nil {
				t.Errorf("parseWorkflow() workflow = %v, want nil on error", w)
			}
			wantErr(t, err, tt.want)
			if !strings.HasPrefix(err.Error(), testFile+":") {
				t.Errorf("error = %q, want the prefix %q", err.Error(), testFile+":")
			}
			var ne *nodeError
			if !errors.As(err, &ne) {
				t.Errorf("error type = %T, want *nodeError", err)
			}
		})
	}
}

func TestParseWorkflowErrorLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		in       string
		wantLine int
		wantMsg  string // the start of nodeError.msg
		prefix   string // the start of Error()
	}{
		{name: "duplicate key", in: "on: push\njobs:\n  a: {}\n  A: {}\n", wantLine: 4, wantMsg: "the key \"A\" is a duplicate", prefix: "wf.yml:4: "},
		{name: "anchor", in: "a: 1\nb:\n  c: &x 2\n", wantLine: 3, wantMsg: "an anchor (&x)", prefix: "wf.yml:3: "},
		{name: "second document", in: "a: 1\n---\nb: 2\n", wantLine: 2, wantMsg: "the file has more than one", prefix: "wf.yml:2: "},
		{name: "no line for size", in: strings.Repeat("#", maxFileBytes+1), wantLine: 0, wantMsg: "the file has", prefix: "wf.yml: the file has"},
		{name: "no line for no document", in: "", wantLine: 0, wantMsg: "the file has no YAML document", prefix: "wf.yml: the file has no"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseWorkflow(testFile, []byte(tt.in))
			var ne *nodeError
			if !errors.As(err, &ne) {
				t.Fatalf("parseWorkflow() error = %v (%T), want *nodeError", err, err)
			}
			if ne.file != testFile {
				t.Errorf("file = %q, want %q", ne.file, testFile)
			}
			if ne.line != tt.wantLine {
				t.Errorf("line = %d, want %d", ne.line, tt.wantLine)
			}
			if !strings.HasPrefix(ne.msg, tt.wantMsg) {
				t.Errorf("msg = %q, want the prefix %q", ne.msg, tt.wantMsg)
			}
			if !strings.HasPrefix(err.Error(), tt.prefix) {
				t.Errorf("Error() = %q, want the prefix %q", err.Error(), tt.prefix)
			}
		})
	}
}

func TestParseWorkflowParseErrorWraps(t *testing.T) {
	t.Parallel()
	_, err := parseWorkflow(testFile, []byte("a:\n\tb: 1\n"))
	var ne *nodeError
	if !errors.As(err, &ne) {
		t.Fatalf("error = %v (%T), want *nodeError", err, err)
	}
	if ne.err == nil || !errors.Is(err, ne.err) {
		t.Errorf("errors.Is(err, cause) = false, cause = %v", ne.err)
	}
	if ne.msg != "parse YAML" || ne.line != 0 {
		t.Errorf("msg, line = %q, %d, want %q, 0", ne.msg, ne.line, "parse YAML")
	}
}

func TestWalkNodeErrorText(t *testing.T) {
	t.Parallel()
	cause := errors.New("boom")
	tests := []struct {
		name string
		e    *nodeError
		want string
	}{
		{name: "line and cause", e: &nodeError{file: "f", line: 7, msg: "bad", err: cause}, want: "f:7: bad: boom"},
		{name: "line only", e: &nodeError{file: "f", line: 1, msg: "bad"}, want: "f:1: bad"},
		{name: "no line", e: &nodeError{file: "f", msg: "bad"}, want: "f: bad"},
		{name: "no line with cause", e: &nodeError{file: "f", msg: "bad", err: cause}, want: "f: bad: boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.e.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseWorkflowAccepted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		path []string // keys from the top mapping to a scalar
		want string   // the decoded Value of that scalar
	}{
		{name: "flow mapping", in: "jobs: {a: {runs-on: x}}\n", path: []string{"jobs", "a", "runs-on"}, want: "x"},
		{name: "quoted keys", in: "\"jobs\":\n  'a':\n    \"runs-on\": y\n", path: []string{"jobs", "a", "runs-on"}, want: "y"},
		{name: "hex escape in value", in: "run: \"go\\x6eow\"\n", path: []string{"run"}, want: "gonow"},
		{name: "unicode escape in value", in: "run: \"\\u0067o\"\n", path: []string{"run"}, want: "go"},
		{name: "block scalar", in: "run: |\n  echo one\n  echo two\n", path: []string{"run"}, want: "echo one\necho two\n"},
		{name: "folded scalar", in: "run: >\n  a\n  b\n", path: []string{"run"}, want: "a b\n"},
		{name: "same key in two mappings", in: "a:\n  env: 1\nb:\n  env: 2\n", path: []string{"b", "env"}, want: "2"},
		{name: "case-insensitive path", in: "Jobs:\n  A:\n    Steps: s\n", path: []string{"jobs", "a", "steps"}, want: "s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := mustParse(t, testFile, tt.in)
			n := w.top
			for i, key := range tt.path {
				var err error
				if i == len(tt.path)-1 {
					n, err = w.scalarAt(n, key)
				} else {
					n, err = w.mappingAt(n, key)
				}
				if err != nil || n == nil {
					t.Fatalf("path %v at %q: node = %v, error = %v", tt.path, key, n, err)
				}
			}
			if n.Value != tt.want {
				t.Errorf("Value = %q, want %q", n.Value, tt.want)
			}
		})
	}
}

func TestParseWorkflowFlowSequence(t *testing.T) {
	t.Parallel()
	w := mustParse(t, testFile, "steps: [{run: a}, {run: b}]\n")
	seq, err := w.sequenceAt(w.top, "steps")
	if err != nil || seq == nil || len(seq.Content) != 2 {
		t.Fatalf("sequenceAt() = %v, %v, want a sequence of 2", seq, err)
	}
	v, err := w.scalarAt(seq.Content[1], "run")
	if err != nil || v == nil || v.Value != "b" {
		t.Errorf("second item run = %v, %v, want \"b\"", v, err)
	}
}

func TestWalkLookup(t *testing.T) {
	t.Parallel()
	w := mustParse(t, testFile, "Name: x\nlist: [1]\n")
	top := w.top
	list := top.Content[3]

	tests := []struct {
		name    string
		m       *yaml.Node
		key     string
		wantKey string // "" for no key node
		wantVal string
		wantErr string
	}{
		{name: "case-insensitive hit", m: top, key: "NAME", wantKey: "Name", wantVal: "x"},
		{name: "exact hit", m: top, key: "list", wantKey: "list"},
		{name: "miss", m: top, key: "nope"},
		{name: "sequence is not a mapping", m: list, key: "a", wantErr: "wf.yml:2: looking for \"a\": want a mapping, found a sequence"},
		{name: "nil node", m: nil, key: "a", wantErr: "wf.yml: looking for \"a\": want a mapping, found nothing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			k, v, err := w.lookup(tt.m, tt.key)
			if tt.wantErr != "" {
				wantErr(t, err, tt.wantErr)
				if k != nil || v != nil {
					t.Errorf("lookup() nodes = %v, %v, want nil, nil", k, v)
				}
				return
			}
			if err != nil {
				t.Fatalf("lookup() error = %v", err)
			}
			if tt.wantKey == "" {
				if k != nil || v != nil {
					t.Errorf("lookup() nodes = %v, %v, want nil, nil", k, v)
				}
				return
			}
			if k == nil || k.Value != tt.wantKey || v == nil {
				t.Fatalf("lookup() key = %v, value = %v, want key %q", k, v, tt.wantKey)
			}
			if tt.wantVal != "" && v.Value != tt.wantVal {
				t.Errorf("lookup() value = %q, want %q", v.Value, tt.wantVal)
			}
		})
	}
}

func TestWalkValueOfKind(t *testing.T) {
	t.Parallel()
	w := mustParse(t, testFile, "m: {a: 1}\ns: [1]\nv: text\nenv:\nnull_v: null\n")
	top := w.top

	type getter func(*yaml.Node, string) (*yaml.Node, error)
	tests := []struct {
		name     string
		get      getter
		m        *yaml.Node
		key      string
		wantKind yaml.Kind // 0 for a nil node
		wantErr  string
	}{
		{name: "mapping ok", get: w.mappingAt, m: top, key: "m", wantKind: yaml.MappingNode},
		{name: "sequence ok", get: w.sequenceAt, m: top, key: "s", wantKind: yaml.SequenceNode},
		{name: "scalar ok", get: w.scalarAt, m: top, key: "v", wantKind: yaml.ScalarNode},
		{name: "mapping missing", get: w.mappingAt, m: top, key: "nope"},
		{name: "sequence missing", get: w.sequenceAt, m: top, key: "nope"},
		{name: "scalar missing", get: w.scalarAt, m: top, key: "nope"},
		{name: "mapping wrong kind", get: w.mappingAt, m: top, key: "s", wantErr: "wf.yml:2: the value of \"s\" must be a mapping, found a sequence"},
		{name: "sequence wrong kind", get: w.sequenceAt, m: top, key: "v", wantErr: "wf.yml:3: the value of \"v\" must be a sequence, found a scalar"},
		{name: "scalar wrong kind", get: w.scalarAt, m: top, key: "m", wantErr: "wf.yml:1: the value of \"m\" must be a scalar, found a mapping"},
		{name: "empty value is not a mapping", get: w.mappingAt, m: top, key: "env", wantErr: "the value of \"env\" must be a mapping, found an empty value"},
		{name: "null is not a sequence", get: w.sequenceAt, m: top, key: "null_v", wantErr: "found an empty value"},
		{name: "key name from file", get: w.mappingAt, m: top, key: "ENV", wantErr: "the value of \"env\" must be"},
		{name: "receiver not a mapping", get: w.scalarAt, m: top.Content[3], key: "a", wantErr: "want a mapping, found a sequence"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			n, err := tt.get(tt.m, tt.key)
			if tt.wantErr != "" {
				wantErr(t, err, tt.wantErr)
				if n != nil {
					t.Errorf("node = %v, want nil on error", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if tt.wantKind == 0 {
				if n != nil {
					t.Errorf("node = %v, want nil for a missing key", n)
				}
				return
			}
			if n == nil || n.Kind != tt.wantKind {
				t.Errorf("node = %v, want kind %s", n, kindWord(tt.wantKind))
			}
		})
	}
}

func TestWalkJobs(t *testing.T) {
	t.Parallel()
	t.Run("file order", func(t *testing.T) {
		t.Parallel()
		w := mustParse(t, testFile, "on: push\njobs:\n  zeta: {}\n  alpha:\n    runs-on: x\n  mid: {a: 1}\n")
		jobs, problems := w.jobsAndProblems()
		if len(problems) != 0 {
			t.Fatalf("jobsAndProblems() problems = %q, want none", problems)
		}
		var ids []string
		for _, j := range jobs {
			ids = append(ids, j.id)
			if j.key == nil || j.key.Value != j.id || j.body == nil || j.body.Kind != yaml.MappingNode {
				t.Errorf("job %q: key = %v, body = %v", j.id, j.key, j.body)
			}
		}
		if want := []string{"zeta", "alpha", "mid"}; !reflect.DeepEqual(ids, want) {
			t.Errorf("job IDs = %v, want %v", ids, want)
		}
		if jobs[1].key.Line != 4 {
			t.Errorf("alpha key line = %d, want 4", jobs[1].key.Line)
		}
	})
	t.Run("empty jobs mapping", func(t *testing.T) {
		t.Parallel()
		w := mustParse(t, testFile, "jobs: {}\n")
		jobs, problems := w.jobsAndProblems()
		if len(problems) != 0 || len(jobs) != 0 {
			t.Errorf("jobsAndProblems() = %v, %q, want no jobs and no problem", jobs, problems)
		}
	})

	// A bad shape gives a problem. The good jobs of the file are still returned.
	errTests := []struct {
		name    string
		in      string
		wantIDs []string // the good jobs that are still returned
		want    string   // a fragment of the first problem
	}{
		{name: "jobs missing", in: "on: push\n", want: "wf.yml:1: the workflow has no jobs mapping"},
		{name: "jobs a sequence", in: "jobs: [a]\n", want: "the value of \"jobs\" must be a mapping, found a sequence"},
		{name: "jobs empty", in: "jobs:\n", want: "found an empty value"},
		{name: "job a scalar", in: "jobs:\n  a: {}\n  b: text\n", wantIDs: []string{"a"}, want: "wf.yml:3: the job \"b\" must be a mapping, found a scalar"},
		{name: "job empty", in: "jobs:\n  a:\n", want: "the job \"a\" must be a mapping, found an empty value"},
	}
	for _, tt := range errTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := mustParse(t, testFile, tt.in)
			jobs, problems := w.jobsAndProblems()
			if len(problems) == 0 {
				t.Fatalf("jobsAndProblems() problems = none, want one with %q", tt.want)
			}
			wantErr(t, problems[0], tt.want)
			var ids []string
			for _, j := range jobs {
				ids = append(ids, j.id)
			}
			if !reflect.DeepEqual(ids, tt.wantIDs) {
				t.Errorf("job IDs = %q, want %q", ids, tt.wantIDs)
			}
		})
	}
}

func TestJobsAndProblems(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		in       string
		wantIDs  []string // the good jobs, in file order
		wantErrs []string // the text of each problem, in file order
	}{
		{name: "all good", in: "jobs:\n  a: {}\n  b: {x: 1}\n", wantIDs: []string{"a", "b"}},
		{name: "a bad job between two good ones", in: "jobs:\n  a: {}\n  b: text\n  c: {}\n", wantIDs: []string{"a", "c"}, wantErrs: []string{`wf.yml:3: the job "b" must be a mapping, found a scalar`}},
		{name: "two bad jobs", in: "jobs:\n  a: []\n  b:\n", wantErrs: []string{`wf.yml:2: the job "a" must be a mapping, found a sequence`, `wf.yml:3: the job "b" must be a mapping, found an empty value`}},
		{name: "jobs missing", in: "on: push\n", wantErrs: []string{"wf.yml:1: the workflow has no jobs mapping"}},
		{name: "jobs a sequence", in: "jobs: [a]\n", wantErrs: []string{`wf.yml:1: the value of "jobs" must be a mapping, found a sequence`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := mustParse(t, testFile, tt.in)
			jobs, problems := w.jobsAndProblems()
			var ids, errs []string
			for _, j := range jobs {
				ids = append(ids, j.id)
			}
			for _, err := range problems {
				var ne *nodeError
				if !errors.As(err, &ne) {
					t.Errorf("problem %v has the type %T, want *nodeError", err, err)
				}
				errs = append(errs, err.Error())
			}
			if !reflect.DeepEqual(ids, tt.wantIDs) {
				t.Errorf("job IDs = %q, want %q", ids, tt.wantIDs)
			}
			if !reflect.DeepEqual(errs, tt.wantErrs) {
				t.Errorf("problems = %q, want %q", errs, tt.wantErrs)
			}
		})
	}
}

// onlyJob parses src and returns its only job. It stops the test when src has
// a problem or does not have exactly one job.
func onlyJob(t *testing.T, src string) (*workflow, job) {
	t.Helper()
	w := mustParse(t, testFile, src)
	jobs, problems := w.jobsAndProblems()
	if len(problems) != 0 || len(jobs) != 1 {
		t.Fatalf("jobsAndProblems() = %v, %q, want one job and no problem", jobs, problems)
	}
	return w, jobs[0]
}

func TestWalkSteps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		in       string
		wantRuns []string // the run value of each step, in order
		wantErr  string
	}{
		{name: "steps in order", in: "jobs:\n  a:\n    steps:\n      - run: one\n      - run: two\n      - run: three\n", wantRuns: []string{"one", "two", "three"}},
		{name: "no steps key", in: "jobs:\n  a:\n    uses: ./.github/workflows/x.yml\n"},
		{name: "steps a mapping", in: "jobs:\n  a:\n    steps: {run: x}\n", wantErr: "the value of \"steps\" must be a sequence, found a mapping"},
		{name: "steps empty", in: "jobs:\n  a:\n    steps:\n", wantErr: "found an empty value"},
		{name: "step a scalar", in: "jobs:\n  a:\n    steps:\n      - run: x\n      - echo\n", wantErr: "wf.yml:5: a step of the job \"a\" must be a mapping, found a scalar"},
		{name: "step a sequence", in: "jobs:\n  a:\n    steps:\n      - [x]\n", wantErr: "a step of the job \"a\" must be a mapping, found a sequence"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w, j := onlyJob(t, tt.in)
			steps, err := w.steps(j)
			if tt.wantErr != "" {
				wantErr(t, err, tt.wantErr)
				if steps != nil {
					t.Errorf("steps() = %v, want nil on error", steps)
				}
				return
			}
			if err != nil {
				t.Fatalf("steps() error = %v", err)
			}
			var runs []string
			for _, s := range steps {
				v, err := w.scalarAt(s, "run")
				if err != nil || v == nil {
					t.Fatalf("step run = %v, %v", v, err)
				}
				runs = append(runs, v.Value)
			}
			if !reflect.DeepEqual(runs, tt.wantRuns) {
				t.Errorf("step runs = %v, want %v", runs, tt.wantRuns)
			}
		})
	}
}

func TestWalkJobEnv(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		wantLen int // the number of env keys; -1 for a nil env
		wantErr string
	}{
		{name: "env mapping", in: "jobs:\n  a:\n    env:\n      A: 1\n      B: 2\n", wantLen: 2},
		{name: "env missing", in: "jobs:\n  a:\n    runs-on: x\n", wantLen: -1},
		{name: "env expression", in: "jobs:\n  a:\n    env: ${{ fromJSON(x) }}\n", wantErr: "wf.yml:3: the value of \"env\" must be a mapping, found a scalar"},
		{name: "env empty", in: "jobs:\n  a:\n    env:\n", wantErr: "found an empty value"},
		{name: "env sequence", in: "jobs:\n  a:\n    env: [A]\n", wantErr: "found a sequence"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w, j := onlyJob(t, tt.in)
			env, err := w.mappingAt(j.body, "env")
			if tt.wantErr != "" {
				wantErr(t, err, tt.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("mappingAt() error = %v", err)
			}
			if tt.wantLen < 0 {
				if env != nil {
					t.Errorf("mappingAt() = %v, want nil", env)
				}
				return
			}
			if env == nil || len(env.Content)/2 != tt.wantLen {
				t.Errorf("mappingAt() = %v, want %d keys", env, tt.wantLen)
			}
		})
	}
}

func TestWalkEnvProblems(t *testing.T) {
	t.Parallel()
	// step returns a workflow with one job and one step. body is the text after
	// the run key of the step, at the indent of the step keys, so its first
	// line is line 5.
	step := func(body string) string {
		return "jobs:\n  a:\n    steps:\n      - run: x\n        " + body
	}
	const notMap = "the value of \"env\" must be a mapping, found "
	tests := []struct {
		name string
		in   string
		want []string // nil means no problem
	}{
		// Each negative case differs from the positive case above it by one change.
		{name: "workflow env mapping", in: "env:\n  A: 1\njobs: {}\n"},
		{name: "workflow env expression", in: "env: ${{ fromJSON(x) }}\njobs: {}\n", want: []string{"wf.yml:1: " + notMap + "a scalar"}},
		{name: "job env mapping", in: "jobs:\n  a:\n    env:\n      A: 1\n"},
		{name: "job env expression", in: "jobs:\n  a:\n    env: ${{ fromJSON(x) }}\n", want: []string{"wf.yml:3: " + notMap + "a scalar"}},
		{name: "step env mapping", in: step("env:\n          A: 1\n")},
		{name: "step env expression", in: step("env: ${{ fromJSON(x) }}\n"), want: []string{"wf.yml:5: " + notMap + "a scalar"}},
		{name: "step env empty", in: step("env:\n"), want: []string{"wf.yml:5: " + notMap + "an empty value"}},
		{name: "step env flow mapping", in: step("env: {A: 1}\n")},
		{name: "step env flow sequence", in: step("env: [A]\n"), want: []string{"wf.yml:5: " + notMap + "a sequence"}},
		{name: "step env block mapping on the next line", in: step("env:\n          A: x\n")},
		{name: "step env plain text on the next line", in: step("env:\n          A x\n"), want: []string{"wf.yml:6: " + notMap + "a scalar"}},
		{name: "step env block scalar", in: step("env: >-\n          A: x\n"), want: []string{"wf.yml:5: " + notMap + "a scalar"}},
		{name: "step env quoted key, mapping", in: step("\"env\": {A: 1}\n")},
		{name: "step env quoted key", in: step("\"env\": x\n"), want: []string{"wf.yml:5: " + notMap + "a scalar"}},
		{name: "step env explicit key, mapping", in: step("? env\n        : {A: 1}\n")},
		{name: "step env explicit key", in: step("? env\n        : x\n"), want: []string{"wf.yml:6: " + notMap + "a scalar"}},
		{name: "step ENV mapping", in: step("ENV: {A: 1}\n")},
		{name: "step ENV scalar", in: step("ENV: x\n"), want: []string{"wf.yml:5: the value of \"ENV\" must be a mapping, found a scalar"}},
		{name: "env mapping nested in a flow mapping", in: step("with: {env: {A: 1}}\n")},
		{name: "env scalar nested in a flow mapping", in: step("with: {env: x}\n"), want: []string{"wf.yml:5: " + notMap + "a scalar"}},
		{name: "other key with a scalar", in: step("environment: x\n")},
		{name: "env as a value, not a key", in: step("name: env\n")},
		{name: "two problems in file order", in: "env: x\njobs:\n  a:\n    env: y\n", want: []string{"wf.yml:1: " + notMap + "a scalar", "wf.yml:4: " + notMap + "a scalar"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mustParse(t, testFile, tt.in).envProblems()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("envProblems() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWalkScalars(t *testing.T) {
	t.Parallel()
	src := "# a comment\n" +
		"name: ci\n" +
		"on: [push, pull_request]\n" +
		"jobs:\n" +
		"  a:\n" +
		"    steps:\n" +
		"      - run: |\n" +
		"          go test\n" +
		"      - uses: x@v1 # trailing comment\n"
	w := mustParse(t, testFile, src)
	var got []string
	var lines []int
	for _, n := range w.scalars() {
		got = append(got, n.Value)
		lines = append(lines, n.Line)
	}
	want := []string{"name", "ci", "on", "push", "pull_request", "jobs", "a", "steps", "run", "go test\n", "uses", "x@v1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scalars() values = %q, want %q", got, want)
	}
	wantLines := []int{2, 2, 3, 3, 3, 4, 5, 6, 7, 7, 9, 9}
	if !reflect.DeepEqual(lines, wantLines) {
		t.Errorf("scalars() lines = %v, want %v", lines, wantLines)
	}
}

func TestWalkVisitsInFileOrder(t *testing.T) {
	t.Parallel()
	w := mustParse(t, testFile, "a: [x, {b: y}]\nc: z\n")
	var got []string
	walk(w.top, func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode {
			got = append(got, n.Value)
		} else {
			got = append(got, kindWord(n.Kind))
		}
	})
	want := []string{"a mapping", "a", "a sequence", "x", "a mapping", "b", "y", "c", "z"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("walk() visits %q, want %q", got, want)
	}
	walk(nil, func(*yaml.Node) { t.Error("walk(nil) called visit") })
}

// allPairsSrc has mappings at the top, below a key, and in a sequence. Its
// keys in file order are the value of allPairsKeys.
const allPairsSrc = "name: CI\njobs:\n  a:\n    steps:\n      - run: echo\n        env: {A: b}\nlast: 1\n"

// allPairsKeys is the key of each pair of allPairsSrc, in file order. A
// mapping comes before the mappings below it, so last follows jobs.
var allPairsKeys = []string{"name", "jobs", "last", "a", "steps", "run", "env", "A"}

// TestAllPairsFileOrder checks that allPairs gives every pair of every mapping
// in file order: top-level keys, nested mappings and mappings in a sequence.
func TestAllPairsFileOrder(t *testing.T) {
	t.Parallel()
	w := mustParse(t, testFile, allPairsSrc)
	var got []string
	for k := range w.allPairs() {
		got = append(got, k.Value)
	}
	if !reflect.DeepEqual(got, allPairsKeys) {
		t.Errorf("allPairs() keys = %q, want %q", got, allPairsKeys)
	}
}

// TestAllPairsBreak checks that a break in the range loop stops allPairs. The
// pairs after the break are in other mappings, so a walk that went on would
// yield them, and the range loop would panic.
func TestAllPairsBreak(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 4, 7} {
		t.Run(allPairsKeys[n-1], func(t *testing.T) {
			t.Parallel()
			w := mustParse(t, testFile, allPairsSrc)
			var got []string
			for k := range w.allPairs() {
				got = append(got, k.Value)
				if len(got) == n {
					break
				}
			}
			if want := allPairsKeys[:n]; !reflect.DeepEqual(got, want) {
				t.Errorf("allPairs() with a break after %d pairs gave %q, want %q", n, got, want)
			}
		})
	}
}

func TestWalkDepthBound(t *testing.T) {
	t.Parallel()
	// A hand-built chain of nodes, deeper than parseWorkflow allows: each
	// node has one child. walk must stop at maxNodeDepth levels below the
	// start node, so it visits maxNodeDepth+1 nodes.
	root := &yaml.Node{Kind: yaml.SequenceNode}
	n := root
	for range maxNodeDepth + 10 {
		child := &yaml.Node{Kind: yaml.SequenceNode}
		n.Content = []*yaml.Node{child}
		n = child
	}
	visits := 0
	walk(root, func(*yaml.Node) { visits++ })
	if visits != maxNodeDepth+1 {
		t.Errorf("walk() visited %d nodes, want %d", visits, maxNodeDepth+1)
	}
}

func TestErrorAt(t *testing.T) {
	t.Parallel()
	w := &workflow{file: "f.yml"}
	tests := []struct {
		name string
		n    *yaml.Node
		want string
	}{
		{name: "nil node", n: nil, want: "f.yml: bad 3"},
		{name: "node with line", n: &yaml.Node{Line: 12}, want: "f.yml:12: bad 3"},
		{name: "node with line 0", n: &yaml.Node{}, want: "f.yml: bad 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := w.errorAt(tt.n, "bad %d", 3)
			if err == nil || err.Error() != tt.want {
				t.Errorf("errorAt() = %v, want %q", err, tt.want)
			}
			if errors.Unwrap(err) != nil {
				t.Errorf("Unwrap() = %v, want nil", errors.Unwrap(err))
			}
		})
	}
}

func TestKindName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		n    *yaml.Node
		want string
	}{
		{name: "nil", n: nil, want: "nothing"},
		{name: "null tag", n: &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null"}, want: "an empty value"},
		{name: "empty plain scalar", n: &yaml.Node{Kind: yaml.ScalarNode, Value: ""}, want: "an empty value"},
		{name: "tilde", n: &yaml.Node{Kind: yaml.ScalarNode, Value: "~"}, want: "an empty value"},
		{name: "quoted empty string", n: &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: ""}, want: "a scalar"},
		{name: "scalar", n: &yaml.Node{Kind: yaml.ScalarNode, Value: "x"}, want: "a scalar"},
		{name: "mapping", n: &yaml.Node{Kind: yaml.MappingNode}, want: "a mapping"},
		{name: "sequence", n: &yaml.Node{Kind: yaml.SequenceNode}, want: "a sequence"},
		{name: "document", n: &yaml.Node{Kind: yaml.DocumentNode}, want: "a document"},
		{name: "alias", n: &yaml.Node{Kind: yaml.AliasNode}, want: "an alias"},
		{name: "unknown", n: &yaml.Node{Kind: 0}, want: "an unknown node"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := kindName(tt.n); got != tt.want {
				t.Errorf("kindName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsASCII(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{in: "", want: true},
		{in: "runs-on", want: true},
		{in: "\x7f", want: true},
		{in: "\x80", want: false},
		{in: "steps\u017f", want: false},
	}
	for _, tt := range tests {
		if got := isASCII(tt.in); got != tt.want {
			t.Errorf("isASCII(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestCutText(t *testing.T) {
	t.Parallel()
	a := func(n int) string { return strings.Repeat("a", n) }
	tests := []struct {
		name, in, want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "short", in: "govulncheck", want: "govulncheck"},
		{name: "exactly the limit", in: a(80), want: a(80)},
		{name: "one byte over", in: a(81), want: a(80) + "..."},
		{name: "character across the limit", in: a(79) + "é" + "b", want: a(79) + "..."},
		{name: "character ends at the limit", in: a(78) + "é" + "bb", want: a(78) + "é" + "..."},
		{name: "invalid bytes count as characters", in: strings.Repeat("\x80", 100), want: strings.Repeat("\x80", 80) + "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := cutText(tt.in, maxShown)
			if got != tt.want {
				t.Errorf("cutText(%q, %d) = %q, want %q", tt.in, maxShown, got, tt.want)
			}
			if utf8.ValidString(tt.in) && !utf8.ValidString(got) {
				t.Errorf("cutText(%q, %d) = %q, not valid UTF-8", tt.in, maxShown, got)
			}
		})
	}
}

func TestShow(t *testing.T) {
	t.Parallel()
	a := func(n int) string { return strings.Repeat("a", n) }
	tests := []struct {
		name, in, want string
	}{
		{name: "empty", in: "", want: `""`},
		{name: "short", in: "release", want: `"release"`},
		{name: "control characters are escapes", in: "a\nb\x1b", want: `"a\nb\x1b"`},
		{name: "exactly the limit", in: a(80), want: `"` + a(80) + `"`},
		{name: "one byte over: the marker follows the quote", in: a(81), want: `"` + a(80) + `"...`},
		{name: "character across the limit", in: a(79) + "é" + "b", want: `"` + a(79) + `"...`},
		{name: "100 KB text", in: a(100 << 10), want: `"` + a(80) + `"...`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := show(tt.in); got != tt.want {
				t.Errorf("show(%.20q...) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestKeyIs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		key  string // the text of the key node
		want bool
	}{
		{name: "exact", key: "needs", want: true},
		{name: "upper case", key: "NEEDS", want: true},
		{name: "mixed case", key: "Needs", want: true},
		{name: "padded with spaces", key: " needs ", want: true},
		{name: "padded and upper case", key: "  NEEDS  ", want: true},
		{name: "longer key", key: "needs2", want: false},
		{name: "shorter key", key: "need", want: false},
		{name: "other key", key: "gate", want: false},
		{name: "name inside the key", key: "needs-check", want: false},
		{name: "empty key", key: "", want: false},
		{name: "spaces only", key: "   ", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			k := &yaml.Node{Kind: yaml.ScalarNode, Value: tt.key}
			if got := keyIs(k, "needs"); got != tt.want {
				t.Errorf("keyIs(%q, needs) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestErrorStrings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		errs []error
		want []string
	}{
		{name: "nil", errs: nil, want: nil},
		{name: "empty", errs: []error{}, want: nil},
		{name: "one", errs: []error{errors.New("a: first")}, want: []string{"a: first"}},
		{
			name: "many in order",
			errs: []error{errors.New("b: second"), errors.New("a: first"), errors.New("c: third")},
			want: []string{"b: second", "a: first", "c: third"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := errorStrings(tt.errs)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("errorStrings() = %q, want %q", got, tt.want)
			}
		})
	}
}
