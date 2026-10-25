package pins

import (
	"errors"
	"maps"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// snapshotCanary is a distinctive text that the tests put in tool names,
// descriptions and schemas. No error from Snapshot may contain it, because the
// server chose that text.
const snapshotCanary = "CANARY-9f3a"

func snapshotTools() []inspect.Tool {
	yes := true
	return []inspect.Tool{
		{Name: "read_file", Description: "Read a file.", InputSchema: []byte(`{"type":"object","properties":{"path":{"type":"string"}}}`)},
		{Name: "delete_file", Title: "Delete", Description: "Delete a file.", Annotations: &inspect.ToolAnnotations{DestructiveHint: &yes}},
		{Name: "list", OutputSchema: []byte(`{"type":"array"}`)},
	}
}

func TestSnapshotPins(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		tools []inspect.Tool
		want  int
	}{
		{name: "nil list", tools: nil, want: 0},
		{name: "empty list", tools: []inspect.Tool{}, want: 0},
		{name: "one tool", tools: snapshotTools()[:1], want: 1},
		{name: "three tools", tools: snapshotTools(), want: 3},
		{name: "same text, different names", tools: []inspect.Tool{{Name: "a", Description: "x"}, {Name: "b", Description: "x"}}, want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Snapshot(tt.tools)
			if err != nil {
				t.Fatalf("Snapshot() error = %v, want nil", err)
			}
			if got == nil {
				t.Fatal("Snapshot() = nil, want a non-nil map")
			}
			if len(got) != tt.want {
				t.Fatalf("Snapshot() has %d pins, want %d", len(got), tt.want)
			}
			for _, tool := range tt.tools {
				pin, ok := got[tool.Name]
				if !ok {
					t.Errorf("no pin for tool %q", tool.Name)
					continue
				}
				if want := mustHash(t, tool); pin.Hash != want {
					t.Errorf("pin %q Hash = %q, want %q", tool.Name, pin.Hash, want)
				}
				if !strings.HasPrefix(pin.Hash, HashVersion+":") {
					t.Errorf("pin %q Hash = %q, want prefix %q", tool.Name, pin.Hash, HashVersion+":")
				}
				if want := mustCanonical(t, tool); pin.Canonical != want {
					t.Errorf("pin %q Canonical = %q, want %q", tool.Name, pin.Canonical, want)
				}
			}
		})
	}
}

func mustHash(t testing.TB, tool inspect.Tool) string {
	t.Helper()
	h, err := Hash(tool)
	if err != nil {
		t.Fatalf("Hash() error = %v, want nil", err)
	}
	return h
}

// TestSnapshotOrderIndependent checks that the order of the tools does not
// change the pins: they are keyed by name.
func TestSnapshotOrderIndependent(t *testing.T) {
	t.Parallel()
	tools := snapshotTools()
	rev := []inspect.Tool{tools[2], tools[1], tools[0]}
	a, err := Snapshot(tools)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Snapshot(rev)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("Snapshot() differs for reversed tools:\n%v\n%v", a, b)
	}
}

func TestSnapshotErrors(t *testing.T) {
	t.Parallel()
	ok := snapshotTools()
	tests := []struct {
		name  string
		tools []inspect.Tool
		want  error
		// wantIndex is the position that the error text must name.
		wantIndex string
	}{
		{
			name:      "empty name first",
			tools:     []inspect.Tool{{Name: "", Description: snapshotCanary}},
			want:      ErrEmptyName,
			wantIndex: "tool 0:",
		},
		{
			name:      "empty name last",
			tools:     []inspect.Tool{ok[0], ok[1], {Description: snapshotCanary}},
			want:      ErrEmptyName,
			wantIndex: "tool 2:",
		},
		{
			name: "duplicate name at the end",
			tools: []inspect.Tool{
				{Name: "a"}, {Name: "b"}, {Name: "a" + snapshotCanary, Description: snapshotCanary},
				{Name: "a" + snapshotCanary, Description: "other"},
			},
			want:      ErrDuplicateTool,
			wantIndex: "tool 3:",
		},
		{
			name:      "duplicate name, third of three",
			tools:     []inspect.Tool{{Name: snapshotCanary}, {Name: "b"}, {Name: snapshotCanary}},
			want:      ErrDuplicateTool,
			wantIndex: "tool 2:",
		},
		{
			name:      "invalid UTF-8 in the name",
			tools:     []inspect.Tool{ok[0], {Name: snapshotCanary + "\xff"}},
			want:      ErrInvalidTool,
			wantIndex: "tool 1:",
		},
		{
			name:      "invalid UTF-8 in the description",
			tools:     []inspect.Tool{{Name: "a", Description: snapshotCanary + "\xff"}},
			want:      ErrInvalidTool,
			wantIndex: "tool 0:",
		},
		{
			name:      "invalid UTF-8 in the title",
			tools:     []inspect.Tool{{Name: "a", Title: snapshotCanary + "\xc3"}},
			want:      ErrInvalidTool,
			wantIndex: "tool 0:",
		},
		{
			name:      "invalid UTF-8 in the annotations title",
			tools:     []inspect.Tool{{Name: "a", Annotations: &inspect.ToolAnnotations{Title: snapshotCanary + "\xff"}}},
			want:      ErrInvalidTool,
			wantIndex: "tool 0:",
		},
		{
			name:      "invalid input schema",
			tools:     []inspect.Tool{ok[0], ok[1], {Name: "a", Description: snapshotCanary, InputSchema: []byte(`{"` + snapshotCanary + `":`)}},
			want:      ErrInvalidTool,
			wantIndex: "tool 2:",
		},
		{
			name:      "invalid output schema",
			tools:     []inspect.Tool{{Name: "a", OutputSchema: []byte(`not json ` + snapshotCanary)}},
			want:      ErrInvalidTool,
			wantIndex: "tool 0:",
		},
		{
			name:      "duplicate key in a schema",
			tools:     []inspect.Tool{{Name: "a", InputSchema: []byte(`{"` + snapshotCanary + `":1,"` + snapshotCanary + `":2}`)}},
			want:      ErrInvalidTool,
			wantIndex: "tool 0:",
		},
		{
			name:      "number out of range in a schema",
			tools:     []inspect.Tool{{Name: "a", InputSchema: []byte(`{"maximum":1e400}`)}},
			want:      ErrInvalidTool,
			wantIndex: "tool 0:",
		},
		{
			name:      "invalid tool after a valid duplicate-free prefix",
			tools:     []inspect.Tool{ok[0], ok[1], ok[2], {Name: "z", Title: "\xff"}},
			want:      ErrInvalidTool,
			wantIndex: "tool 3:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Snapshot(tt.tools)
			if err == nil {
				t.Fatal("Snapshot() error = nil, want an error")
			}
			if got != nil {
				t.Errorf("Snapshot() = %v with an error, want nil (no partial result)", got)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("Snapshot() error = %v, want errors.Is %v", err, tt.want)
			}
			// The two sentinels are different errors.
			for _, other := range []error{ErrInvalidTool, ErrDuplicateTool} {
				if !errors.Is(other, tt.want) && errors.Is(err, other) {
					t.Errorf("Snapshot() error = %v, must not wrap %v", err, other)
				}
			}
			if !strings.Contains(err.Error(), tt.wantIndex) {
				t.Errorf("Snapshot() error = %q, want it to hold %q", err, tt.wantIndex)
			}
			for _, secret := range []string{snapshotCanary, "CANARY"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("Snapshot() error = %q, must not hold server text %q", err, secret)
				}
			}
		})
	}
}

// TestSnapshotRoundTrip checks that the store accepts a snapshot, and gives
// the same pins back, after a save and a load too.
func TestSnapshotRoundTrip(t *testing.T) {
	t.Parallel()
	id := Identity{Client: "claude-code", Source: "/home/u/.claude.json", Name: "srv"}
	tests := []struct {
		name  string
		tools []inspect.Tool
	}{
		{name: "no tools", tools: nil},
		{name: "three tools", tools: snapshotTools()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			snap, err := Snapshot(tt.tools)
			if err != nil {
				t.Fatalf("Snapshot() error = %v, want nil", err)
			}
			path := filepath.Join(t.TempDir(), "pins.json")
			s, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}
			if err := s.Set(id, snap); err != nil {
				t.Fatalf("Set(Snapshot()) error = %v, want nil", err)
			}
			got, ok := s.Get(id)
			if !ok || !maps.Equal(got, snap) {
				t.Errorf("Get() = %v, %v, want %v, true", got, ok, snap)
			}
			if err := s.Save(); err != nil {
				t.Fatalf("Save() error = %v, want nil", err)
			}
			s2, err := Load(path)
			if err != nil {
				t.Fatalf("Load() after Save error = %v, want nil", err)
			}
			got, ok = s2.Get(id)
			if !ok || !maps.Equal(got, snap) {
				t.Errorf("Get() after reload = %v, %v, want %v, true", got, ok, snap)
			}
		})
	}
}

// TestSnapshotDoesNotChangeInput checks that Snapshot leaves the tools as
// they were.
func TestSnapshotDoesNotChangeInput(t *testing.T) {
	t.Parallel()
	tools := snapshotTools()
	want := snapshotTools()
	if _, err := Snapshot(tools); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tools, want) {
		t.Errorf("Snapshot() changed its input:\n%v\nwant\n%v", tools, want)
	}
}
