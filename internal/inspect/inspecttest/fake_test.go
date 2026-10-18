package inspecttest_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// sampleResult returns a new Result with every slice filled, so that tests
// can check that each slice is cloned.
func sampleResult() inspect.Result {
	return inspect.Result{
		ProtocolVersion: "2025-06-18",
		ServerName:      "sample",
		ServerVersion:   "1.0.0",
		Instructions:    "Use the tools.",
		Tools: []inspect.Tool{
			{
				Name:        "read_file",
				Description: "Reads a file.",
				InputSchema: json.RawMessage(`{"type":"object"}`),
				Annotations: &inspect.ToolAnnotations{Title: "Read file", ReadOnlyHint: &readOnly},
			},
			{Name: "write_file", Description: "Writes a file."},
		},
		Prompts: []inspect.Prompt{
			{Name: "summary", Arguments: []inspect.PromptArgument{{Name: "topic", Required: true}}},
		},
		Resources: []inspect.Resource{
			{URI: "file:///tmp/a.txt", Name: "a", MIMEType: "text/plain"},
		},
		ResourceTemplates: []inspect.ResourceTemplate{
			{URITemplate: "file:///tmp/{name}", Name: "tmp", MIMEType: "text/plain"},
		},
		Warnings: []inspect.Warning{
			{Kind: inspect.WarnCleartextSecrets, HeaderKeys: []string{"Authorization", "X-Api-Key"}},
			{Kind: inspect.WarnCleartextSecrets, URLUserInfo: true},
		},
	}
}

// readOnly is the value of the ReadOnlyHint in sampleResult. Tests must not
// change it.
var readOnly = true

func server(name string) discover.Server {
	return discover.Server{Name: name, Transport: discover.TransportStdio}
}

func TestFakeInspect(t *testing.T) {
	t.Parallel()

	errBoom := errors.New("boom")

	tests := []struct {
		name       string
		results    map[string]inspect.Result
		errs       map[string]error
		server     string
		cancel     bool
		wantResult inspect.Result
		wantErr    error // nil means no error
	}{
		{
			name:       "result by name",
			results:    map[string]inspect.Result{"a": sampleResult(), "b": {ServerName: "other"}},
			server:     "a",
			wantResult: sampleResult(),
		},
		{
			name:       "result with nil slices stays equal",
			results:    map[string]inspect.Result{"a": {ServerName: "only-name"}},
			server:     "a",
			wantResult: inspect.Result{ServerName: "only-name"},
		},
		{
			name: "result with empty slices stays empty, not nil",
			results: map[string]inspect.Result{"a": {
				ResourceTemplates: []inspect.ResourceTemplate{},
				Warnings:          []inspect.Warning{{Kind: inspect.WarnCleartextSecrets, HeaderKeys: []string{}}},
			}},
			server: "a",
			wantResult: inspect.Result{
				ResourceTemplates: []inspect.ResourceTemplate{},
				Warnings:          []inspect.Warning{{Kind: inspect.WarnCleartextSecrets, HeaderKeys: []string{}}},
			},
		},
		{
			name:    "error by name",
			errs:    map[string]error{"a": errBoom},
			server:  "a",
			wantErr: errBoom,
		},
		{
			name:    "wrapped error by name",
			errs:    map[string]error{"a": fmt.Errorf("%w: exit 1", errBoom)},
			server:  "a",
			wantErr: errBoom,
		},
		{
			name:    "error wins over result",
			results: map[string]inspect.Result{"a": sampleResult()},
			errs:    map[string]error{"a": errBoom},
			server:  "a",
			wantErr: errBoom,
		},
		{
			name:       "nil error falls through to result",
			results:    map[string]inspect.Result{"a": sampleResult()},
			errs:       map[string]error{"a": nil},
			server:     "a",
			wantResult: sampleResult(),
		},
		{
			name:    "nil error without result is no entry",
			errs:    map[string]error{"a": nil},
			server:  "a",
			wantErr: inspecttest.ErrNoResult,
		},
		{
			name:       "error of other name is not used",
			results:    map[string]inspect.Result{"a": sampleResult()},
			errs:       map[string]error{"b": errBoom},
			server:     "a",
			wantResult: sampleResult(),
		},
		{
			name:    "unknown name",
			results: map[string]inspect.Result{"a": sampleResult()},
			errs:    map[string]error{"b": errBoom},
			server:  "c",
			wantErr: inspecttest.ErrNoResult,
		},
		{
			name:    "empty name unknown",
			results: map[string]inspect.Result{"a": sampleResult()},
			server:  "",
			wantErr: inspecttest.ErrNoResult,
		},
		{
			name:    "zero value fake",
			server:  "a",
			wantErr: inspecttest.ErrNoResult,
		},
		{
			name:    "canceled context wins over result",
			results: map[string]inspect.Result{"a": sampleResult()},
			server:  "a",
			cancel:  true,
			wantErr: context.Canceled,
		},
		{
			name:    "canceled context wins over error",
			errs:    map[string]error{"a": errBoom},
			server:  "a",
			cancel:  true,
			wantErr: context.Canceled,
		},
		{
			name:    "canceled context on zero value fake",
			server:  "a",
			cancel:  true,
			wantErr: context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := &inspecttest.Fake{Results: tt.results, Errors: tt.errs}
			ctx := t.Context()
			if tt.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			got, err := f.Inspect(ctx, server(tt.server))

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Inspect(%q) error = %v, want nil", tt.server, err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Inspect(%q) error = %v, want errors.Is %v", tt.server, err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.wantResult) {
				t.Errorf("Inspect(%q) result = %+v, want %+v", tt.server, got, tt.wantResult)
			}
			if want := []string{tt.server}; !slices.Equal(f.Calls(), want) {
				t.Errorf("Calls() = %q, want %q", f.Calls(), want)
			}
		})
	}
}

func TestFakeInspectErrNoResultNamesServer(t *testing.T) {
	t.Parallel()

	var f inspecttest.Fake
	_, err := f.Inspect(t.Context(), server("missing-server"))
	if err == nil {
		t.Fatal("Inspect() error = nil, want error")
	}
	if want := `"missing-server"`; !strings.Contains(err.Error(), want) {
		t.Errorf("Inspect() error = %q, want it to contain %s", err, want)
	}
}

func TestFakeCalls(t *testing.T) {
	t.Parallel()

	f := &inspecttest.Fake{
		Results: map[string]inspect.Result{"a": sampleResult()},
		Errors:  map[string]error{"b": errors.New("boom")},
	}
	if got := f.Calls(); len(got) != 0 {
		t.Fatalf("Calls() before any call = %q, want empty", got)
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	calls := []struct {
		ctx  context.Context
		name string
	}{
		{t.Context(), "a"},
		{t.Context(), "b"},
		{t.Context(), "unknown"},
		{canceled, "a"},
		{t.Context(), "a"},
	}
	for _, c := range calls {
		_, _ = f.Inspect(c.ctx, server(c.name))
	}

	want := []string{"a", "b", "unknown", "a", "a"}
	got := f.Calls()
	if !slices.Equal(got, want) {
		t.Fatalf("Calls() = %q, want %q", got, want)
	}

	// Calls returns a copy: a change to it must not show in the next call.
	got[0] = "changed"
	_ = append(got[:1], "appended")
	if again := f.Calls(); !slices.Equal(again, want) {
		t.Errorf("Calls() after change of earlier result = %q, want %q", again, want)
	}

	// A new call after Calls must not change an earlier returned slice.
	before := f.Calls()
	_, _ = f.Inspect(t.Context(), server("late"))
	if !slices.Equal(before, want) {
		t.Errorf("earlier Calls() result = %q after new call, want %q", before, want)
	}
}

func TestFakeInspectClonesSlices(t *testing.T) {
	t.Parallel()

	// Each case changes the returned Result in one way. The change must not
	// reach the entry in Results or the Result of the next call.
	tests := []struct {
		name   string
		change func(r *inspect.Result)
	}{
		{name: "tool element", change: func(r *inspect.Result) { r.Tools[0].Name = "changed" }},
		{name: "tool append", change: func(r *inspect.Result) { r.Tools = append(r.Tools, inspect.Tool{Name: "extra"}) }},
		{name: "prompt element", change: func(r *inspect.Result) { r.Prompts[0].Name = "changed" }},
		{name: "prompt append", change: func(r *inspect.Result) { r.Prompts = append(r.Prompts, inspect.Prompt{Name: "extra"}) }},
		{name: "resource element", change: func(r *inspect.Result) { r.Resources[0].URI = "changed" }},
		{name: "resource append", change: func(r *inspect.Result) {
			r.Resources = append(r.Resources, inspect.Resource{URI: "extra"})
		}},
		{name: "resource template element", change: func(r *inspect.Result) {
			r.ResourceTemplates[0].URITemplate = "changed"
		}},
		{name: "resource template append", change: func(r *inspect.Result) {
			r.ResourceTemplates = append(r.ResourceTemplates, inspect.ResourceTemplate{URITemplate: "extra"})
		}},
		{name: "warning kind", change: func(r *inspect.Result) { r.Warnings[0].Kind = "changed" }},
		{name: "warning user info", change: func(r *inspect.Result) { r.Warnings[1].URLUserInfo = false }},
		{name: "warning header keys replaced", change: func(r *inspect.Result) { r.Warnings[0].HeaderKeys = nil }},
		{name: "warning header key element", change: func(r *inspect.Result) { r.Warnings[0].HeaderKeys[0] = "changed" }},
		{name: "warning header key append", change: func(r *inspect.Result) {
			r.Warnings[0].HeaderKeys = append(r.Warnings[0].HeaderKeys, "Extra")
		}},
		{name: "warning append", change: func(r *inspect.Result) {
			r.Warnings = append(r.Warnings, inspect.Warning{Kind: "extra"})
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := &inspecttest.Fake{Results: map[string]inspect.Result{"a": sampleResult()}}

			got, err := f.Inspect(t.Context(), server("a"))
			if err != nil {
				t.Fatalf("Inspect() error = %v", err)
			}
			tt.change(&got)

			if entry := f.Results["a"]; !reflect.DeepEqual(entry, sampleResult()) {
				t.Errorf("Results[\"a\"] after change of returned Result = %+v, want %+v", entry, sampleResult())
			}
			again, err := f.Inspect(t.Context(), server("a"))
			if err != nil {
				t.Fatalf("second Inspect() error = %v", err)
			}
			if !reflect.DeepEqual(again, sampleResult()) {
				t.Errorf("second Inspect() = %+v, want %+v", again, sampleResult())
			}
		})
	}
}

func TestFakeInspectConcurrent(t *testing.T) {
	t.Parallel()

	const n = 50
	f := &inspecttest.Fake{Results: map[string]inspect.Result{}}
	names := make([]string, n)
	for i := range n {
		names[i] = fmt.Sprintf("server-%02d", i)
		if i%2 == 0 {
			f.Results[names[i]] = inspect.Result{ServerName: names[i], Tools: []inspect.Tool{{Name: "t"}}}
		}
	}

	errs := make([]error, n)
	results := make([]inspect.Result, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			results[i], errs[i] = f.Inspect(t.Context(), server(names[i]))
		})
	}
	wg.Wait()

	for i := range n {
		if i%2 == 0 {
			if errs[i] != nil || results[i].ServerName != names[i] {
				t.Errorf("Inspect(%q) = (%+v, %v), want ServerName %q and nil error", names[i], results[i], errs[i], names[i])
			}
		} else if !errors.Is(errs[i], inspecttest.ErrNoResult) {
			t.Errorf("Inspect(%q) error = %v, want ErrNoResult", names[i], errs[i])
		}
	}

	got := f.Calls()
	if len(got) != n {
		t.Fatalf("len(Calls()) = %d, want %d", len(got), n)
	}
	slices.Sort(got)
	if !slices.Equal(got, names) {
		t.Errorf("sorted Calls() = %q, want %q", got, names)
	}
}
