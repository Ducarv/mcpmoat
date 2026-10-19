package discover

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// claudeStateView is a comparable view of a claudeProjectState: the names of
// each list in sorted order (nil when the list is empty or absent), and
// enableAll as "" (absent), "true" or "false".
type claudeStateView struct {
	Enabled     []string
	Disabled    []string
	DisabledMcp []string
	EnableAll   string
}

// viewState returns the view of st.
func viewState(st claudeProjectState) claudeStateView {
	v := claudeStateView{
		Enabled:     sortedNames(st.enabledMcpjson),
		Disabled:    sortedNames(st.disabledMcpjson),
		DisabledMcp: sortedNames(st.disabledMcp),
	}
	if st.enableAll != nil {
		v.EnableAll = strconv.FormatBool(*st.enableAll)
	}
	return v
}

// sortedNames returns the names in s in sorted order, or nil when s is empty.
func sortedNames(s nameSet) []string {
	if len(s) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(s))
}

// nameSetOf returns a nameSet with the given names.
func nameSetOf(ns ...string) nameSet {
	s := make(nameSet, len(ns))
	for _, n := range ns {
		s[n] = struct{}{}
	}
	return s
}

// decodeObject decodes the JSON object text into a map, as the readers do
// before they call decodeClaudeState. It fails the test on bad JSON.
func decodeObject(t testing.TB, text string) map[string]json.RawMessage {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		t.Fatalf("test input is not a JSON object: %v", err)
	}
	return obj
}

// TestDecodeClaudeState checks the exact keys, the types and the bad names.
// On any problem, the state must be zero: a half-read state could approve a
// server that a later key of the same place rejects.
func TestDecodeClaudeState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		obj        string
		want       claudeStateView
		wantReason reason
	}{
		{name: "empty object", obj: `{}`},
		{
			name: "all four keys",
			obj: `{"enabledMcpjsonServers":["a","b"],"disabledMcpjsonServers":["c"],` +
				`"disabledMcpServers":["d","e"],"enableAllProjectMcpServers":true}`,
			want: claudeStateView{
				Enabled: []string{"a", "b"}, Disabled: []string{"c"},
				DisabledMcp: []string{"d", "e"}, EnableAll: "true",
			},
		},
		{
			name: "enableAll false is kept, not absent",
			obj:  `{"enableAllProjectMcpServers":false}`,
			want: claudeStateView{EnableAll: "false"},
		},
		{
			name: "null values give no setting",
			obj: `{"enabledMcpjsonServers":null,"disabledMcpjsonServers":null,` +
				`"disabledMcpServers":null,"enableAllProjectMcpServers":null}`,
		},
		{name: "empty lists", obj: `{"enabledMcpjsonServers":[],"disabledMcpServers":[]}`},
		{
			name: "duplicate names in a list",
			obj:  `{"enabledMcpjsonServers":["a","a"]}`,
			want: claudeStateView{Enabled: []string{"a"}},
		},
		{
			name: "other keys are ignored",
			obj:  `{"mcpServers":5,"permissions":{"allow":[]},"model":"x","enabledMcpjsonServers":["a"]}`,
			want: claudeStateView{Enabled: []string{"a"}},
		},
		{
			// Claude Code reads the keys exactly, so a case variant is
			// ignored: it does not approve or disable anything, and its
			// wrong type is no error.
			name: "case variants are ignored",
			obj: `{"EnabledMcpjsonServers":["a"],"DISABLEDMCPJSONSERVERS":["b"],` +
				`"disabledmcpservers":["c"],"EnableAllProjectMcpServers":true,"enableAllProjectMCPServers":true}`,
		},
		{
			name: "case variant with a wrong type is ignored",
			obj:  `{"DisabledMcpServers":5,"enableallprojectmcpservers":"yes","enabledMcpjsonServers":["a"]}`,
			want: claudeStateView{Enabled: []string{"a"}},
		},
		{
			// encoding/json keeps the last value, as JSON.parse does.
			name: "duplicate key keeps the last value",
			obj:  `{"enabledMcpjsonServers":["a"],"enabledMcpjsonServers":["b"]}`,
			want: claudeStateView{Enabled: []string{"b"}},
		},
		{
			name: "escaped names are decoded",
			obj:  `{"enabledMcpjsonServers":["café","😀","a\"b"]}`,
			want: claudeStateView{Enabled: []string{"a\"b", "café", "😀"}},
		},
		{
			name: "U+FFFD written as text is a valid name",
			obj:  `{"enabledMcpjsonServers":["a` + "�" + `"]}`,
			want: claudeStateView{Enabled: []string{"a�"}},
		},

		// Wrong types of each list.
		{name: "enabled list is a string", obj: `{"enabledMcpjsonServers":"a"}`, wantReason: reasonBadServerState},
		{name: "disabled list is a number", obj: `{"disabledMcpjsonServers":5}`, wantReason: reasonBadServerState},
		{name: "disabledMcpServers is an object", obj: `{"disabledMcpServers":{"a":true}}`, wantReason: reasonBadServerState},
		{name: "enabled list is a boolean", obj: `{"enabledMcpjsonServers":true}`, wantReason: reasonBadServerState},
		{name: "null item", obj: `{"disabledMcpServers":["a",null]}`, wantReason: reasonBadServerState},
		{name: "number item", obj: `{"enabledMcpjsonServers":["a",1]}`, wantReason: reasonBadServerState},
		{name: "boolean item", obj: `{"disabledMcpjsonServers":[false]}`, wantReason: reasonBadServerState},
		{name: "array item", obj: `{"enabledMcpjsonServers":[["a"]]}`, wantReason: reasonBadServerState},
		{name: "object item", obj: `{"disabledMcpServers":[{"name":"a"}]}`, wantReason: reasonBadServerState},

		// Wrong types of enableAllProjectMcpServers.
		{name: "enableAll is the string true", obj: `{"enableAllProjectMcpServers":"true"}`, wantReason: reasonBadServerState},
		{name: "enableAll is a number", obj: `{"enableAllProjectMcpServers":1}`, wantReason: reasonBadServerState},
		{name: "enableAll is an array", obj: `{"enableAllProjectMcpServers":[true]}`, wantReason: reasonBadServerState},
		{name: "enableAll is an object", obj: `{"enableAllProjectMcpServers":{}}`, wantReason: reasonBadServerState},

		// One bad key gives a zero state, also when the other keys are good.
		{
			name: "good lists and a bad enableAll",
			obj: `{"enabledMcpjsonServers":["a"],"disabledMcpjsonServers":["b"],` +
				`"disabledMcpServers":["c"],"enableAllProjectMcpServers":"yes"}`,
			wantReason: reasonBadServerState,
		},
		{
			name:       "good enableAll and a bad list",
			obj:        `{"enableAllProjectMcpServers":true,"disabledMcpServers":"c"}`,
			wantReason: reasonBadServerState,
		},

		// Bad strings: encoding/json would change these names.
		{name: "lone high surrogate", obj: `{"enabledMcpjsonServers":["a\ud800"]}`, wantReason: reasonBadString},
		{name: "lone low surrogate", obj: `{"disabledMcpjsonServers":["\udc00b"]}`, wantReason: reasonBadString},
		{name: "invalid UTF-8", obj: "{\"disabledMcpServers\":[\"a\xffb\"]}", wantReason: reasonBadString},
		{
			name:       "bad string next to good keys",
			obj:        `{"enableAllProjectMcpServers":true,"enabledMcpjsonServers":["ok","\ud800"]}`,
			wantReason: reasonBadString,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st, r := decodeClaudeState(decodeObject(t, tt.obj))
			if r != tt.wantReason {
				t.Errorf("reason = %q, want %q", r, tt.wantReason)
			}
			// On a reason the want view is the zero view.
			if got := viewState(st); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("state = %+v, want %+v", got, tt.want)
			}
		})
	}

	t.Run("nil map", func(t *testing.T) {
		t.Parallel()
		st, r := decodeClaudeState(nil)
		if r != "" {
			t.Errorf("reason = %q, want none", r)
		}
		if got := viewState(st); !reflect.DeepEqual(got, claudeStateView{}) {
			t.Errorf("state = %+v, want zero", got)
		}
	})
}

// TestNameSet checks has on a nil set, an empty set and a filled set. Names
// are compared exactly.
func TestNameSet(t *testing.T) {
	t.Parallel()

	var nilSet nameSet
	if nilSet.has("a") || nilSet.has("") {
		t.Error("nil nameSet.has() = true, want false")
	}
	s := nameSetOf("a", "B")
	tests := []struct {
		name string
		want bool
	}{
		{name: "a", want: true},
		{name: "B", want: true},
		{name: "A", want: false},
		{name: "b", want: false},
		{name: "a ", want: false},
		{name: "", want: false},
	}
	for _, tt := range tests {
		if got := s.has(tt.name); got != tt.want {
			t.Errorf("has(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestMcpjsonState checks the merge rule for one .mcp.json server called
// "srv". The sources are in the order local, project, user, legacy (the
// projects.<WorkDir> object of ~/.claude.json). local and project are files
// of the repository (untrusted): an approval only from them gives
// StateProjectApproved. user and legacy are trusted: their approval gives
// StateEnabled.
func TestMcpjsonState(t *testing.T) {
	t.Parallel()

	const srv = "srv"
	var zero claudeProjectState
	enabled := claudeProjectState{enabledMcpjson: nameSetOf(srv)}
	rejected := claudeProjectState{disabledMcpjson: nameSetOf(srv)}
	off := claudeProjectState{disabledMcp: nameSetOf(srv)}
	// new(true) (Go 1.26+) returns a pointer to a new bool set to true.
	allTrue := claudeProjectState{enableAll: new(true)}
	allFalse := claudeProjectState{enableAll: new(false)}
	other := claudeProjectState{
		enabledMcpjson: nameSetOf("other"), disabledMcpjson: nameSetOf("other2"), disabledMcp: nameSetOf("other3"),
	}

	tests := []struct {
		name    string
		sources []claudeProjectState
		want    State
	}{
		{name: "no sources", sources: nil, want: StateUnapproved},
		{name: "four zero sources", sources: []claudeProjectState{zero, zero, zero, zero}, want: StateUnapproved},
		{name: "only other names", sources: []claudeProjectState{other, other, other, other}, want: StateUnapproved},
		{
			name:    "name in another letter case",
			sources: []claudeProjectState{{enabledMcpjson: nameSetOf("SRV")}, zero, zero, zero},
			want:    StateUnapproved,
		},

		// Step 2: an enabled list at each level approves. Only a trusted
		// list gives StateEnabled.
		{name: "enabled in local", sources: []claudeProjectState{enabled, zero, zero, zero}, want: StateProjectApproved},
		{name: "enabled in project", sources: []claudeProjectState{zero, enabled, zero, zero}, want: StateProjectApproved},
		{name: "enabled in user", sources: []claudeProjectState{zero, zero, enabled, zero}, want: StateEnabled},
		{name: "enabled in legacy", sources: []claudeProjectState{zero, zero, zero, enabled}, want: StateEnabled},

		// Step 1: a disabled list wins over every approval, at any level.
		{name: "rejected in local", sources: []claudeProjectState{rejected, zero, zero, zero}, want: StateDisabled},
		{name: "rejected in legacy", sources: []claudeProjectState{zero, zero, zero, rejected}, want: StateDisabled},
		{
			name:    "rejected in legacy wins over enabled in local",
			sources: []claudeProjectState{enabled, zero, zero, rejected},
			want:    StateDisabled,
		},
		{
			name:    "rejected in user wins over enableAll true in local",
			sources: []claudeProjectState{allTrue, zero, rejected, zero},
			want:    StateDisabled,
		},
		// A repository file can reject a server that the user approved.
		{
			name:    "rejected in project wins over enabled in user",
			sources: []claudeProjectState{zero, rejected, enabled, zero},
			want:    StateDisabled,
		},
		{
			name:    "rejected in local wins over enableAll true in legacy",
			sources: []claudeProjectState{rejected, zero, zero, allTrue},
			want:    StateDisabled,
		},
		{
			name:    "enabled and rejected in one place",
			sources: []claudeProjectState{{enabledMcpjson: nameSetOf(srv), disabledMcpjson: nameSetOf(srv)}},
			want:    StateDisabled,
		},

		// Step 2: enableAll true at each level approves.
		{name: "enableAll true in local", sources: []claudeProjectState{allTrue, zero, zero, zero}, want: StateProjectApproved},
		{name: "enableAll true in project", sources: []claudeProjectState{zero, allTrue, zero, zero}, want: StateProjectApproved},
		{name: "enableAll true in user", sources: []claudeProjectState{zero, zero, allTrue, zero}, want: StateEnabled},
		{name: "enableAll true in legacy", sources: []claudeProjectState{zero, zero, zero, allTrue}, want: StateEnabled},

		// enableAll false alone does not approve.
		{name: "enableAll false in local", sources: []claudeProjectState{allFalse, zero, zero, zero}, want: StateUnapproved},
		{name: "enableAll false in legacy", sources: []claudeProjectState{zero, zero, zero, allFalse}, want: StateUnapproved},

		// The first source with the key decides, in the order local,
		// project, user, legacy.
		{
			name:    "local false wins over project true",
			sources: []claudeProjectState{allFalse, allTrue, zero, zero},
			want:    StateUnapproved,
		},
		{
			name:    "local true wins over project false",
			sources: []claudeProjectState{allTrue, allFalse, zero, zero},
			want:    StateProjectApproved,
		},
		{
			name:    "project false wins over user true",
			sources: []claudeProjectState{zero, allFalse, allTrue, zero},
			want:    StateUnapproved,
		},
		{
			name:    "project true wins over user false",
			sources: []claudeProjectState{zero, allTrue, allFalse, zero},
			want:    StateProjectApproved,
		},
		{
			name:    "user false wins over legacy true",
			sources: []claudeProjectState{zero, zero, allFalse, allTrue},
			want:    StateUnapproved,
		},
		{
			name:    "user true wins over legacy false",
			sources: []claudeProjectState{zero, zero, allTrue, allFalse},
			want:    StateEnabled,
		},

		// A first true from a repository file does not hide a trusted true
		// that comes later in the order.
		{
			name:    "project true and user true",
			sources: []claudeProjectState{zero, allTrue, allTrue, zero},
			want:    StateEnabled,
		},
		{
			name:    "local true and legacy true",
			sources: []claudeProjectState{allTrue, zero, zero, allTrue},
			want:    StateEnabled,
		},
		{
			name:    "local true, user false and legacy true",
			sources: []claudeProjectState{allTrue, zero, allFalse, allTrue},
			want:    StateEnabled,
		},
		{
			name:    "local false and user true",
			sources: []claudeProjectState{allFalse, zero, allTrue, zero},
			want:    StateUnapproved,
		},

		// An enabled list approves the name even when enableAll is false.
		{
			name:    "enabled in legacy and enableAll false in local",
			sources: []claudeProjectState{allFalse, zero, zero, enabled},
			want:    StateEnabled,
		},
		{
			name:    "enabled in local and enableAll false in the same place",
			sources: []claudeProjectState{{enabledMcpjson: nameSetOf(srv), enableAll: new(false)}},
			want:    StateProjectApproved,
		},

		// Trusted and untrusted approvals together: a trusted approval of
		// any kind gives StateEnabled.
		{
			name:    "enabled in user and in local",
			sources: []claudeProjectState{enabled, zero, enabled, zero},
			want:    StateEnabled,
		},
		{
			name:    "enabled in local and in project",
			sources: []claudeProjectState{enabled, enabled, zero, zero},
			want:    StateProjectApproved,
		},
		{
			name:    "enabled in user and enableAll true in local",
			sources: []claudeProjectState{allTrue, zero, enabled, zero},
			want:    StateEnabled,
		},
		{
			name:    "enabled in legacy and enableAll true in project",
			sources: []claudeProjectState{zero, allTrue, zero, enabled},
			want:    StateEnabled,
		},
		{
			name:    "enabled in local and enableAll true in user",
			sources: []claudeProjectState{enabled, zero, allTrue, zero},
			want:    StateEnabled,
		},
		{
			name:    "enabled in project and enableAll true in legacy",
			sources: []claudeProjectState{zero, enabled, zero, allTrue},
			want:    StateEnabled,
		},
		{
			name:    "enabled in local and enableAll false in user",
			sources: []claudeProjectState{enabled, zero, allFalse, zero},
			want:    StateProjectApproved,
		},
		{
			name:    "enabled in project and enableAll false in local",
			sources: []claudeProjectState{allFalse, enabled, zero, zero},
			want:    StateProjectApproved,
		},
		{
			name:    "local true wins over user false",
			sources: []claudeProjectState{allTrue, zero, allFalse, zero},
			want:    StateProjectApproved,
		},
		{
			name:    "project true and legacy true",
			sources: []claudeProjectState{zero, allTrue, zero, allTrue},
			want:    StateEnabled,
		},

		// An untrusted enableAll false hides a trusted true, as in Claude
		// Code: the first source with the key decides.
		{
			name:    "local false wins over user true",
			sources: []claudeProjectState{allFalse, zero, allTrue, zero},
			want:    StateUnapproved,
		},
		{
			name:    "local false wins over legacy true",
			sources: []claudeProjectState{allFalse, zero, zero, allTrue},
			want:    StateUnapproved,
		},
		{
			name:    "project false wins over user and legacy true",
			sources: []claudeProjectState{zero, allFalse, allTrue, allTrue},
			want:    StateUnapproved,
		},

		// A source after legacy has no trusted position, so it fails closed.
		{
			name:    "enabled in a fifth source",
			sources: []claudeProjectState{zero, zero, zero, zero, enabled},
			want:    StateProjectApproved,
		},
		{
			name:    "enableAll true in a fifth source",
			sources: []claudeProjectState{zero, zero, zero, zero, allTrue},
			want:    StateProjectApproved,
		},
		// With fewer sources, the positions keep their meaning.
		{name: "enabled in user, three sources", sources: []claudeProjectState{zero, zero, enabled}, want: StateEnabled},
		{name: "enabled in project, two sources", sources: []claudeProjectState{zero, enabled}, want: StateProjectApproved},

		// Step 4: disabledMcpServers wins over all, at any level.
		{name: "turned off only", sources: []claudeProjectState{zero, zero, zero, off}, want: StateDisabled},
		{name: "turned off in local", sources: []claudeProjectState{off, zero, zero, zero}, want: StateDisabled},
		{
			name:    "turned off in legacy wins over enabled in local",
			sources: []claudeProjectState{enabled, zero, zero, off},
			want:    StateDisabled,
		},
		{
			name:    "turned off in user wins over enableAll true in local",
			sources: []claudeProjectState{allTrue, zero, off, zero},
			want:    StateDisabled,
		},
		{
			name:    "turned off in project wins over enabled in legacy",
			sources: []claudeProjectState{zero, off, zero, enabled},
			want:    StateDisabled,
		},
		{
			name:    "turned off and enabled in one place",
			sources: []claudeProjectState{{enabledMcpjson: nameSetOf(srv), disabledMcp: nameSetOf(srv), enableAll: new(true)}},
			want:    StateDisabled,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := mcpjsonState(srv, tt.sources...); got != tt.want {
				t.Errorf("mcpjsonState(%q) = %v, want %v", srv, got, tt.want)
			}
		})
	}
}

// TestTrustedSource checks that only the user's own places are trusted, and
// that any other position, also one outside the four sources, is untrusted.
func TestTrustedSource(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		i    int
		want bool
	}{
		{name: "local", i: sourceLocal, want: false},
		{name: "project", i: sourceProject, want: false},
		{name: "user", i: sourceUser, want: true},
		{name: "legacy", i: sourceLegacy, want: true},
		{name: "after legacy", i: sourceLegacy + 1, want: false},
		{name: "negative", i: -1, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := trustedSource(tt.i); got != tt.want {
				t.Errorf("trustedSource(%d) = %v, want %v", tt.i, got, tt.want)
			}
		})
	}
}

// TestApplyMcpjsonStates checks that each server gets its own state from its
// name, in place, and that no other field changes.
func TestApplyMcpjsonStates(t *testing.T) {
	t.Parallel()

	local := claudeProjectState{
		enabledMcpjson:  nameSetOf("approved", "both"),
		disabledMcpjson: nameSetOf("rejected", "both"),
	}
	legacy := claudeProjectState{disabledMcp: nameSetOf("approved-off"), enabledMcpjson: nameSetOf("legacy-ok")}
	user := claudeProjectState{enabledMcpjson: nameSetOf("approved-off", "user-ok")}

	servers := []Server{
		{Name: "approved", Command: "a", Untrusted: true, Scope: ScopeProject},
		{Name: "rejected", Command: "r", Untrusted: true, Scope: ScopeProject},
		{Name: "both", Command: "b", Untrusted: true, Scope: ScopeProject},
		{Name: "pending", Command: "p", Untrusted: true, Scope: ScopeProject},
		{Name: "approved-off", Command: "o", Untrusted: true, Scope: ScopeProject},
		{Name: "user-ok", Command: "u", Untrusted: true, Scope: ScopeProject},
		{Name: "legacy-ok", Command: "l", Untrusted: true, Scope: ScopeProject},
	}
	applyMcpjsonStates(servers, local, claudeProjectState{}, user, legacy)

	checkStates(t, servers, map[string]State{
		// Only the untrusted local file approves it.
		"approved":     StateProjectApproved,
		"rejected":     StateDisabled,
		"both":         StateDisabled,
		"pending":      StateUnapproved,
		"approved-off": StateDisabled,
		"user-ok":      StateEnabled,
		"legacy-ok":    StateEnabled,
	})
	wantCommands := []string{"a", "r", "b", "p", "o", "u", "l"}
	for i, s := range servers {
		if s.Command != wantCommands[i] || !s.Untrusted || s.Scope != ScopeProject {
			t.Errorf("servers[%d] = %+v, want only State changed", i, s)
		}
	}

	t.Run("no sources make every server unapproved", func(t *testing.T) {
		t.Parallel()
		ss := []Server{{Name: "a"}, {Name: "b"}}
		applyMcpjsonStates(ss)
		checkStates(t, ss, map[string]State{"a": StateUnapproved, "b": StateUnapproved})
	})

	t.Run("nil servers", func(t *testing.T) {
		t.Parallel()
		applyMcpjsonStates(nil, local) // must not panic
	})
}

// TestApplyDisabledServers checks that only the names in disabledMcpServers
// become StateDisabled and that every other server keeps its State.
func TestApplyDisabledServers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		st   claudeProjectState
		in   []State // State of servers a, b, c before the call
		want map[string]State
	}{
		{
			name: "one name turned off",
			st:   claudeProjectState{disabledMcp: nameSetOf("b")},
			in:   []State{StateEnabled, StateEnabled, StateEnabled},
			want: map[string]State{"b": StateDisabled},
		},
		{
			name: "other states are kept",
			st:   claudeProjectState{disabledMcp: nameSetOf("a")},
			in:   []State{StateUnapproved, StateUnapproved, StateDisabled},
			want: map[string]State{"a": StateDisabled, "b": StateUnapproved, "c": StateDisabled},
		},
		{
			name: "an unapproved server becomes disabled",
			st:   claudeProjectState{disabledMcp: nameSetOf("c")},
			in:   []State{StateEnabled, StateEnabled, StateUnapproved},
			want: map[string]State{"c": StateDisabled},
		},
		{
			name: "a disabled server stays disabled",
			st:   claudeProjectState{disabledMcp: nameSetOf("a")},
			in:   []State{StateDisabled, StateEnabled, StateEnabled},
			want: map[string]State{"a": StateDisabled},
		},
		{
			name: "zero state changes nothing",
			in:   []State{StateEnabled, StateUnapproved, StateDisabled},
			want: map[string]State{"b": StateUnapproved, "c": StateDisabled},
		},
		{
			// Only disabledMcpServers counts here. The .mcp.json lists are
			// for applyMcpjsonStates.
			name: "mcpjson lists and enableAll are ignored",
			st: claudeProjectState{
				enabledMcpjson: nameSetOf("a"), disabledMcpjson: nameSetOf("b"), enableAll: new(false),
			},
			in:   []State{StateEnabled, StateEnabled, StateEnabled},
			want: nil,
		},
		{
			name: "names are exact",
			st:   claudeProjectState{disabledMcp: nameSetOf("A", "b ", "")},
			in:   []State{StateEnabled, StateEnabled, StateEnabled},
			want: nil,
		},
		{
			name: "unknown names change nothing",
			st:   claudeProjectState{disabledMcp: nameSetOf("x", "y")},
			in:   []State{StateEnabled, StateEnabled, StateEnabled},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			servers := []Server{
				{Name: "a", State: tt.in[0], Command: "ca"},
				{Name: "b", State: tt.in[1], Command: "cb"},
				{Name: "c", State: tt.in[2], Command: "cc"},
			}
			applyDisabledServers(servers, tt.st)
			checkStates(t, servers, tt.want)
			if got := serverNames(servers); !slices.Equal(got, []string{"a", "b", "c"}) {
				t.Errorf("server names = %v, want [a b c]", got)
			}
			for i, s := range servers {
				if s.Command != "c"+s.Name {
					t.Errorf("servers[%d].Command = %q, want %q", i, s.Command, "c"+s.Name)
				}
			}
		})
	}
}

// settingsPath returns dir/.claude/<file>.
func settingsPath(dir, file string) string {
	return filepath.Join(dir, claudeDir, file)
}

// TestReadClaudeSettingsContent checks readClaudeSettings on each kind of
// file content. Every case runs twice: as the trusted home file (root "")
// and as a project file confined to its directory. Only the project errors
// have Untrusted set.
func TestReadClaudeSettingsContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    claudeStateView
		// wantErr is the error, or nil when the read must succeed.
		wantErr *errWant
		// canaries is set when content holds every canary, which must not
		// appear in the error.
		canaries bool
	}{
		{
			name: "all keys",
			content: `{"enabledMcpjsonServers":["a"],"disabledMcpjsonServers":["b"],` +
				`"disabledMcpServers":["c"],"enableAllProjectMcpServers":false,"permissions":{}}`,
			want: claudeStateView{
				Enabled: []string{"a"}, Disabled: []string{"b"}, DisabledMcp: []string{"c"}, EnableAll: "false",
			},
		},
		{name: "empty file", content: ""},
		{name: "white space only", content: " \n\t\r\n"},
		{name: "empty object", content: "{}"},
		{name: "no state keys", content: `{"model":"x","env":{"K":"` + discovertest.CanaryEnv + `"}}`},
		{
			name:    "malformed JSON",
			content: "{\n  \"enabledMcpjsonServers\": [\"" + discovertest.CanaryEnv + "\"\n  " + discovertest.CanaryHeader + "\n}",
			wantErr: &errWant{Reason: reasonInvalidJSON, Line: 3},
		},
		{name: "top-level null", content: "null", wantErr: &errWant{Reason: reasonBadShape}},
		{name: "top-level array", content: `[{"enabledMcpjsonServers":["a"]}]`, wantErr: &errWant{Reason: reasonBadShape}},
		{name: "top-level string", content: `"a"`, wantErr: &errWant{Reason: reasonBadShape}},
		{name: "top-level number", content: "5", wantErr: &errWant{Reason: reasonBadShape}},
		{
			name: "wrong type with canaries",
			content: `{"enabledMcpjsonServers":["ok"],"enableAllProjectMcpServers":"` + discovertest.CanaryEnv + `",` +
				`"x":["` + discovertest.CanaryHeader + `","` + discovertest.CanaryURL + `","` + discovertest.CanaryArgs + `"]}`,
			wantErr:  &errWant{Reason: reasonBadServerState},
			canaries: true,
		},
		{
			name: "list with canaries",
			content: `{"disabledMcpServers":"` + discovertest.CanaryEnv + discovertest.CanaryHeader +
				discovertest.CanaryURL + discovertest.CanaryArgs + `"}`,
			wantErr:  &errWant{Reason: reasonBadServerState},
			canaries: true,
		},
		{name: "null item", content: `{"disabledMcpjsonServers":[null]}`, wantErr: &errWant{Reason: reasonBadServerState}},
		{name: "lone surrogate", content: `{"enabledMcpjsonServers":["\ud800"]}`, wantErr: &errWant{Reason: reasonBadString}},
		{name: "invalid UTF-8", content: "{\"enabledMcpjsonServers\":[\"\xff\"]}", wantErr: &errWant{Reason: reasonBadString}},
		{
			// A bad string outside the state keys is not read, so it is no
			// error here.
			name:    "bad string in another key",
			content: "{\"model\":\"\xff\",\"enabledMcpjsonServers\":[\"a\"]}",
			want:    claudeStateView{Enabled: []string{"a"}},
		},
		{
			name:    "case variant key is ignored",
			content: `{"EnabledMcpjsonServers":["a"],"enableAllProjectMcpServers":true}`,
			want:    claudeStateView{EnableAll: "true"},
		},
	}
	for _, tt := range tests {
		for _, project := range []bool{false, true} {
			kind := "home"
			if project {
				kind = "project"
			}
			t.Run(tt.name+"/"+kind, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				path := writeFile(t, dir, claudeDir+"/"+claudeSettingsFile, []byte(tt.content))
				root := ""
				if project {
					root = dir
				}

				st, fe := readClaudeSettings(t.Context(), path, root)

				var errs []*FileError
				var want []errWant
				if fe != nil {
					errs = []*FileError{fe}
				}
				if tt.wantErr != nil {
					want = []errWant{*tt.wantErr}
				}
				checkFileErrors(t, path, errs, want)
				checkErrorsUntrusted(t, errs, project)
				if got := viewState(st); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("state = %+v, want %+v", got, tt.want)
				}
				if tt.canaries {
					for _, c := range discovertest.Canaries() {
						if !bytes.Contains([]byte(tt.content), []byte(c)) {
							t.Fatalf("test content does not hold canary %q", c)
						}
					}
				}
				assertNoLeakErrors(t, errs)
			})
		}
	}
}

// TestReadClaudeSettingsFileSystem checks the file system cases of
// readClaudeSettings: missing files, special files, size caps, symlinks and
// confinement, and a canceled context.
func TestReadClaudeSettingsFileSystem(t *testing.T) {
	t.Parallel()
	skipOnWindows(t)

	const approved = `{"enabledMcpjsonServers":["a"]}`
	approvedView := claudeStateView{Enabled: []string{"a"}}

	// read runs readClaudeSettings and returns the view and the errors as
	// a list, for checkFileErrors.
	read := func(t *testing.T, ctx context.Context, path, root string) (claudeStateView, []*FileError) {
		t.Helper()
		st, fe := readClaudeSettings(ctx, path, root)
		if fe == nil {
			return viewState(st), nil
		}
		if got := viewState(st); !reflect.DeepEqual(got, claudeStateView{}) {
			t.Errorf("state with an error = %+v, want zero", got)
		}
		return viewState(st), []*FileError{fe}
	}

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		for _, project := range []bool{false, true} {
			dir := t.TempDir()
			root := ""
			if project {
				root = dir
			}
			path := settingsPath(dir, claudeSettingsFile)
			got, errs := read(t, t.Context(), path, root)
			checkFileErrors(t, path, errs, nil)
			if !reflect.DeepEqual(got, claudeStateView{}) {
				t.Errorf("project %v: state = %+v, want zero", project, got)
			}
		}
	})

	t.Run("missing project directory", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "gone")
		path := settingsPath(dir, claudeSettingsFile)
		got, errs := read(t, t.Context(), path, dir)
		checkFileErrors(t, path, errs, nil)
		if !reflect.DeepEqual(got, claudeStateView{}) {
			t.Errorf("state = %+v, want zero", got)
		}
	})

	t.Run("dangling symlink is missing", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := symlinkTo(t, "nowhere.json", dir, claudeDir+"/"+claudeSettingsFile)
		for _, root := range []string{"", dir} {
			got, errs := read(t, t.Context(), path, root)
			checkFileErrors(t, path, errs, nil)
			if !reflect.DeepEqual(got, claudeStateView{}) {
				t.Errorf("root %q: state = %+v, want zero", root, got)
			}
		}
	})

	t.Run("directory at the path", func(t *testing.T) {
		t.Parallel()
		for _, project := range []bool{false, true} {
			dir := t.TempDir()
			path := settingsPath(dir, claudeSettingsFile)
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
			root := ""
			if project {
				root = dir
			}
			_, errs := read(t, t.Context(), path, root)
			checkFileErrors(t, path, errs, []errWant{{Reason: reasonNotRegular}})
			checkErrorsUntrusted(t, errs, project)
		}
	})

	t.Run("project file over the project cap", func(t *testing.T) {
		t.Parallel()
		// A valid file one byte over maxProjectConfigSize: refused in a
		// project, read from home (whose cap is maxConfigSize).
		data := append([]byte(approved), bytes.Repeat([]byte(" "), maxProjectConfigSize+1-len(approved))...)

		dir := t.TempDir()
		path := writeFile(t, dir, claudeDir+"/"+claudeSettingsFile, data)
		_, errs := read(t, t.Context(), path, dir)
		checkFileErrors(t, path, errs, []errWant{{Reason: reasonTooLarge}})
		checkErrorsUntrusted(t, errs, true)

		got, errs := read(t, t.Context(), path, "")
		checkFileErrors(t, path, errs, nil)
		if !reflect.DeepEqual(got, approvedView) {
			t.Errorf("home state = %+v, want %+v", got, approvedView)
		}
	})

	t.Run("home file over the home cap", func(t *testing.T) {
		t.Parallel()
		// A sparse file: Truncate sets the size without writing the data.
		dir := t.TempDir()
		path := writeFile(t, dir, claudeDir+"/"+claudeSettingsFile, nil)
		if err := os.Truncate(path, maxConfigSize+1); err != nil {
			t.Fatal(err)
		}
		_, errs := read(t, t.Context(), path, "")
		checkFileErrors(t, path, errs, []errWant{{Reason: reasonTooLarge}})
		checkErrorsUntrusted(t, errs, false)
	})

	t.Run("project symlink out of the project is refused", func(t *testing.T) {
		t.Parallel()
		outside := writeFile(t, t.TempDir(), "settings.json", []byte(approved))
		dir := t.TempDir()
		path := symlinkTo(t, outside, dir, claudeDir+"/"+claudeSettingsFile)
		got, errs := read(t, t.Context(), path, dir)
		checkFileErrors(t, path, errs, []errWant{{Reason: reasonOutsideProject}})
		checkErrorsUntrusted(t, errs, true)
		if !reflect.DeepEqual(got, claudeStateView{}) {
			t.Errorf("state = %+v, want zero", got)
		}
	})

	t.Run("project .claude directory symlink out of the project is refused", func(t *testing.T) {
		t.Parallel()
		outsideDir := t.TempDir()
		writeFile(t, outsideDir, claudeSettingsFile, []byte(approved))
		dir := t.TempDir()
		symlinkTo(t, outsideDir, dir, claudeDir)
		path := settingsPath(dir, claudeSettingsFile)
		_, errs := read(t, t.Context(), path, dir)
		checkFileErrors(t, path, errs, []errWant{{Reason: reasonOutsideProject}})
		checkErrorsUntrusted(t, errs, true)
	})

	t.Run("project symlink with dot-dot out of the project is refused", func(t *testing.T) {
		t.Parallel()
		parent := t.TempDir()
		writeFile(t, parent, "settings.json", []byte(approved))
		dir := makeDir(t, parent, "work")
		path := symlinkTo(t, "../../settings.json", dir, claudeDir+"/"+claudeSettingsFile)
		_, errs := read(t, t.Context(), path, dir)
		checkFileErrors(t, path, errs, []errWant{{Reason: reasonOutsideProject}})
	})

	t.Run("project symlink inside the project is read", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, dir, "shared/settings.json", []byte(approved))
		path := symlinkTo(t, "../shared/settings.json", dir, claudeDir+"/"+claudeSettingsFile)
		got, errs := read(t, t.Context(), path, dir)
		checkFileErrors(t, path, errs, nil)
		if !reflect.DeepEqual(got, approvedView) {
			t.Errorf("state = %+v, want %+v", got, approvedView)
		}
	})

	t.Run("project path outside the root is refused", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, t.TempDir(), claudeDir+"/"+claudeSettingsFile, []byte(approved))
		_, errs := read(t, t.Context(), path, t.TempDir())
		checkFileErrors(t, path, errs, []errWant{{Reason: reasonOutsideProject}})
		checkErrorsUntrusted(t, errs, true)
	})

	t.Run("home symlink out of home is followed", func(t *testing.T) {
		t.Parallel()
		// The user's own file is trusted: dotfile managers link it from
		// another directory.
		outside := writeFile(t, t.TempDir(), "dotfiles/settings.json", []byte(approved))
		home := t.TempDir()
		path := symlinkTo(t, outside, home, claudeDir+"/"+claudeSettingsFile)
		got, errs := read(t, t.Context(), path, "")
		checkFileErrors(t, path, errs, nil)
		if !reflect.DeepEqual(got, approvedView) {
			t.Errorf("state = %+v, want %+v", got, approvedView)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		for _, project := range []bool{false, true} {
			dir := t.TempDir()
			path := writeFile(t, dir, claudeDir+"/"+claudeSettingsFile, []byte(approved))
			root := ""
			if project {
				root = dir
			}
			got, errs := read(t, ctx, path, root)
			checkFileErrors(t, path, errs, []errWant{{Reason: reasonCanceled, HasErr: true}})
			checkErrorsUntrusted(t, errs, project)
			if !reflect.DeepEqual(got, claudeStateView{}) {
				t.Errorf("state = %+v, want zero", got)
			}
		}
	})
}

// settingsDirs makes a home and a work directory. Each non-empty content is
// written to its settings file: home/.claude/settings.json,
// work/.claude/settings.json and work/.claude/settings.local.json.
func settingsDirs(t *testing.T, homeContent, projectContent, localContent string) (home, work string) {
	t.Helper()
	home, work = t.TempDir(), t.TempDir()
	if homeContent != "" {
		writeFile(t, home, claudeDir+"/"+claudeSettingsFile, []byte(homeContent))
	}
	if projectContent != "" {
		writeFile(t, work, claudeDir+"/"+claudeSettingsFile, []byte(projectContent))
	}
	if localContent != "" {
		writeFile(t, work, claudeDir+"/"+claudeLocalSettingsFile, []byte(localContent))
	}
	return home, work
}

// TestReadClaudeSettingsFilesOrder checks readClaudeSettingsFiles: the
// states come back in the order local, project, user, and the errors in the
// order home, project, local.
func TestReadClaudeSettingsFilesOrder(t *testing.T) {
	t.Parallel()

	const (
		homeJSON    = `{"enabledMcpjsonServers":["from-home"]}`
		projectJSON = `{"disabledMcpjsonServers":["from-project"]}`
		localJSON   = `{"disabledMcpServers":["from-local"],"enableAllProjectMcpServers":true}`
		badJSON     = `{"enabledMcpjsonServers":`
		wrongType   = `{"enableAllProjectMcpServers":"yes"}`
	)
	homeView := claudeStateView{Enabled: []string{"from-home"}}
	projectView := claudeStateView{Disabled: []string{"from-project"}}
	localView := claudeStateView{DisabledMcp: []string{"from-local"}, EnableAll: "true"}

	// file names an error by the file it is for.
	type file int
	const (
		homeFile file = iota
		projectFile
		localFile
	)

	tests := []struct {
		name                 string
		home, project, local string
		want                 []claudeStateView // local, project, user
		wantErrFiles         []file
		wantErrs             []errWant
	}{
		{
			name: "all three files",
			home: homeJSON, project: projectJSON, local: localJSON,
			want: []claudeStateView{localView, projectView, homeView},
		},
		{
			name: "no files",
			want: []claudeStateView{{}, {}, {}},
		},
		{
			name: "only the home file",
			home: homeJSON,
			want: []claudeStateView{{}, {}, homeView},
		},
		{
			name: "errors come in the order home, project, local",
			home: badJSON, project: wrongType, local: badJSON,
			want:         []claudeStateView{{}, {}, {}},
			wantErrFiles: []file{homeFile, projectFile, localFile},
			wantErrs: []errWant{
				{Reason: reasonInvalidJSON, Line: 1},
				{Reason: reasonBadServerState},
				{Reason: reasonInvalidJSON, Line: 1},
			},
		},
		{
			name: "a bad file gives a zero state only for itself",
			home: homeJSON, project: wrongType, local: localJSON,
			want:         []claudeStateView{localView, {}, homeView},
			wantErrFiles: []file{projectFile},
			wantErrs:     []errWant{{Reason: reasonBadServerState}},
		},
		{
			name: "a bad local file keeps the others",
			home: homeJSON, project: projectJSON, local: wrongType,
			want:         []claudeStateView{{}, projectView, homeView},
			wantErrFiles: []file{localFile},
			wantErrs:     []errWant{{Reason: reasonBadServerState}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := settingsDirs(t, tt.home, tt.project, tt.local)
			paths := map[file]string{
				homeFile:    settingsPath(home, claudeSettingsFile),
				projectFile: settingsPath(work, claudeSettingsFile),
				localFile:   settingsPath(work, claudeLocalSettingsFile),
			}

			states, errs := readClaudeSettingsFiles(t.Context(), home, work)

			if len(states) != 3 {
				t.Fatalf("got %d states, want 3", len(states))
			}
			got := make([]claudeStateView, 0, len(states))
			for _, st := range states {
				got = append(got, viewState(st))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("states (local, project, user) =\n got  %+v\n want %+v", got, tt.want)
			}
			if len(errs) != len(tt.wantErrs) {
				t.Fatalf("got %d errors, want %d: %v", len(errs), len(tt.wantErrs), errs)
			}
			for i, f := range tt.wantErrFiles {
				checkFileErrors(t, paths[f], errs[i:i+1], tt.wantErrs[i:i+1])
				checkErrorsUntrusted(t, errs[i:i+1], f != homeFile)
			}
		})
	}

	// The states feed mcpjsonState: local enableAll false hides project and
	// user true.
	t.Run("precedence through mcpjsonState", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name                 string
			home, project, local string
			legacy               claudeProjectState
			want                 State
		}{
			{
				name: "local false wins over project and user true",
				home: `{"enableAllProjectMcpServers":true}`, project: `{"enableAllProjectMcpServers":true}`,
				local: `{"enableAllProjectMcpServers":false}`,
				want:  StateUnapproved,
			},
			{
				name: "project true wins over user false",
				home: `{"enableAllProjectMcpServers":false}`, project: `{"enableAllProjectMcpServers":true}`,
				want: StateProjectApproved,
			},
			{
				name:  "local true gives only project-approved",
				local: `{"enableAllProjectMcpServers":true}`,
				want:  StateProjectApproved,
			},
			{
				name:    "local and project lists give only project-approved",
				project: `{"enabledMcpjsonServers":["srv"]}`, local: `{"enabledMcpjsonServers":["srv"]}`,
				want: StateProjectApproved,
			},
			{
				name: "user list wins over project true",
				home: `{"enabledMcpjsonServers":["srv"]}`, project: `{"enableAllProjectMcpServers":true}`,
				want: StateEnabled,
			},
			{
				name: "user list approves when local is false",
				home: `{"enabledMcpjsonServers":["srv"]}`, local: `{"enableAllProjectMcpServers":false}`,
				want: StateEnabled,
			},
			{
				name: "user true approves a local list",
				home: `{"enableAllProjectMcpServers":true}`, local: `{"enabledMcpjsonServers":["srv"]}`,
				want: StateEnabled,
			},
			{
				name:    "project false hides legacy true",
				project: `{"enableAllProjectMcpServers":false}`,
				legacy:  claudeProjectState{enableAll: new(true)},
				want:    StateUnapproved,
			},
			{
				name:   "user false wins over legacy true",
				home:   `{"enableAllProjectMcpServers":false}`,
				legacy: claudeProjectState{enableAll: new(true)},
				want:   StateUnapproved,
			},
			{
				name:   "legacy true when no file has the key",
				legacy: claudeProjectState{enableAll: new(true)},
				want:   StateEnabled,
			},
			{
				name: "user file rejection wins over local approval",
				home: `{"disabledMcpjsonServers":["srv"]}`, local: `{"enabledMcpjsonServers":["srv"]}`,
				want: StateDisabled,
			},
			{
				name:   "legacy disabledMcpServers wins over a local approval",
				local:  `{"enabledMcpjsonServers":["srv"],"enableAllProjectMcpServers":true}`,
				legacy: claudeProjectState{disabledMcp: nameSetOf("srv")},
				want:   StateDisabled,
			},
			{
				name:    "project disabledMcpServers turns the server off",
				project: `{"disabledMcpServers":["srv"]}`, local: `{"enabledMcpjsonServers":["srv"]}`,
				want: StateDisabled,
			},
			{name: "no setting anywhere", want: StateUnapproved},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				home, work := settingsDirs(t, tt.home, tt.project, tt.local)
				states, errs := readClaudeSettingsFiles(t.Context(), home, work)
				if len(errs) != 0 {
					t.Fatalf("errors = %v, want none", errs)
				}
				if got := mcpjsonState("srv", append(states, tt.legacy)...); got != tt.want {
					t.Errorf("mcpjsonState() = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("project symlink out of the work directory is refused", func(t *testing.T) {
		t.Parallel()
		skipOnWindows(t)
		outside := writeFile(t, t.TempDir(), "settings.json", []byte(`{"enabledMcpjsonServers":["srv"]}`))
		home, work := settingsDirs(t, "", "", "")
		local := symlinkTo(t, outside, work, claudeDir+"/"+claudeLocalSettingsFile)

		states, errs := readClaudeSettingsFiles(t.Context(), home, work)

		checkFileErrors(t, local, errs, []errWant{{Reason: reasonOutsideProject}})
		checkErrorsUntrusted(t, errs, true)
		if got := mcpjsonState("srv", states...); got != StateUnapproved {
			t.Errorf("mcpjsonState() = %v, want %v: an outside file must not approve", got, StateUnapproved)
		}
	})

	t.Run("canceled context stops after the first error", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		home, work := settingsDirs(t, homeJSON, projectJSON, localJSON)

		states, errs := readClaudeSettingsFiles(ctx, home, work)

		checkFileErrors(t, settingsPath(home, claudeSettingsFile), errs, []errWant{{Reason: reasonCanceled, HasErr: true}})
		checkErrorsUntrusted(t, errs, false)
		for i, st := range states {
			if got := viewState(st); !reflect.DeepEqual(got, claudeStateView{}) {
				t.Errorf("states[%d] = %+v, want zero", i, got)
			}
		}
	})

	t.Run("canceled context without home stops at the project file", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, work := settingsDirs(t, "", projectJSON, localJSON)

		_, errs := readClaudeSettingsFiles(ctx, "", work)

		checkFileErrors(t, settingsPath(work, claudeSettingsFile), errs, []errWant{{Reason: reasonCanceled, HasErr: true}})
		checkErrorsUntrusted(t, errs, true)
	})
}

// TestReadClaudeSettingsFilesEmptyDirs checks that an empty home or workDir
// skips its files. Without the skip, filepath.Join would give the relative
// path .claude/settings.json, read from the current directory, and an empty
// workDir would also read it without confinement. So the test runs in a
// directory that has those files. t.Chdir does not allow t.Parallel.
func TestReadClaudeSettingsFilesEmptyDirs(t *testing.T) {
	cwd := t.TempDir()
	writeFile(t, cwd, claudeDir+"/"+claudeSettingsFile, []byte(`{"enabledMcpjsonServers":["cwd"]}`))
	writeFile(t, cwd, claudeDir+"/"+claudeLocalSettingsFile, []byte(`{"enableAllProjectMcpServers":true}`))
	t.Chdir(cwd)

	home, work := settingsDirs(t,
		`{"enabledMcpjsonServers":["from-home"]}`,
		`{"enabledMcpjsonServers":["from-project"]}`,
		`{"enabledMcpjsonServers":["from-local"]}`)

	tests := []struct {
		name       string
		home, work string
		want       []claudeStateView // local, project, user
	}{
		{
			name: "empty home",
			work: work,
			want: []claudeStateView{
				{Enabled: []string{"from-local"}}, {Enabled: []string{"from-project"}}, {},
			},
		},
		{
			name: "empty workDir",
			home: home,
			want: []claudeStateView{{}, {}, {Enabled: []string{"from-home"}}},
		},
		{
			name: "both empty",
			want: []claudeStateView{{}, {}, {}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			states, errs := readClaudeSettingsFiles(t.Context(), tt.home, tt.work)
			if len(errs) != 0 {
				t.Errorf("errors = %v, want none", errs)
			}
			if len(states) != 3 {
				t.Fatalf("got %d states, want 3", len(states))
			}
			got := make([]claudeStateView, 0, len(states))
			for _, st := range states {
				got = append(got, viewState(st))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("states (local, project, user) =\n got  %+v\n want %+v", got, tt.want)
			}
		})
	}
}

// TestReadClaudeSettingsFilesSameDir checks the case where workDir is home.
// Then WorkDir/.claude/settings.json is the user file: it must be read once,
// as the trusted user file, so a bad file gives one FileError without
// Untrusted. The project slot gets a zero state. settings.local.json is still
// read from workDir.
func TestReadClaudeSettingsFilesSameDir(t *testing.T) {
	t.Parallel()

	const (
		userJSON  = `{"enabledMcpjsonServers":["from-user"]}`
		localJSON = `{"enabledMcpjsonServers":["from-local"]}`
		wrongType = `{"enableAllProjectMcpServers":"yes"}`
	)
	userView := claudeStateView{Enabled: []string{"from-user"}}
	localView := claudeStateView{Enabled: []string{"from-local"}}

	tests := []struct {
		name        string
		user, local string
		// workSuffix is added to home to make workDir, to check that the
		// compare uses the cleaned paths.
		workSuffix string
		want       []claudeStateView // local, project, user
		wantErrs   []errWant         // all for the user file
	}{
		{
			name: "good user file fills only the user slot",
			user: userJSON, local: localJSON,
			want: []claudeStateView{localView, {}, userView},
		},
		{
			name:     "bad user file gives one trusted error",
			user:     wrongType,
			want:     []claudeStateView{{}, {}, {}},
			wantErrs: []errWant{{Reason: reasonBadServerState}},
		},
		{
			name: "bad user file keeps the local file",
			user: wrongType, local: localJSON,
			want:     []claudeStateView{localView, {}, {}},
			wantErrs: []errWant{{Reason: reasonBadServerState}},
		},
		{
			name: "workDir with a trailing separator",
			user: wrongType, workSuffix: string(filepath.Separator),
			want:     []claudeStateView{{}, {}, {}},
			wantErrs: []errWant{{Reason: reasonBadServerState}},
		},
		{
			name: "workDir with a dot part",
			user: userJSON, workSuffix: string(filepath.Separator) + ".",
			want: []claudeStateView{{}, {}, userView},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			if tt.user != "" {
				writeFile(t, home, claudeDir+"/"+claudeSettingsFile, []byte(tt.user))
			}
			if tt.local != "" {
				writeFile(t, home, claudeDir+"/"+claudeLocalSettingsFile, []byte(tt.local))
			}

			states, errs := readClaudeSettingsFiles(t.Context(), home, home+tt.workSuffix)

			got := make([]claudeStateView, 0, len(states))
			for _, st := range states {
				got = append(got, viewState(st))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("states (local, project, user) =\n got  %+v\n want %+v", got, tt.want)
			}
			checkFileErrors(t, settingsPath(home, claudeSettingsFile), errs, tt.wantErrs)
			checkErrorsUntrusted(t, errs, false)
		})
	}

	t.Run("bad local file is untrusted", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		writeFile(t, home, claudeDir+"/"+claudeLocalSettingsFile, []byte(wrongType))

		_, errs := readClaudeSettingsFiles(t.Context(), home, home)

		checkFileErrors(t, settingsPath(home, claudeLocalSettingsFile), errs, []errWant{{Reason: reasonBadServerState}})
		checkErrorsUntrusted(t, errs, true)
	})
}

// TestSetMcpjsonStates checks that the .mcp.json step fails closed: when a
// settings source failed, no server gets StateEnabled from approval, and
// StateDisabled stays. A missing file is normal and does not count.
func TestSetMcpjsonStates(t *testing.T) {
	t.Parallel()

	const (
		approveAll = `{"enableAllProjectMcpServers":true}`
		wrongType  = `{"disabledMcpjsonServers":"srv"}`
		badJSON    = `{"enabledMcpjsonServers":`
	)

	tests := []struct {
		name                 string
		home, project, local string
		legacy               claudeProjectState
		legacyFailed         bool
		want                 map[string]State
		wantErrs             int
	}{
		{
			name: "no failure keeps the approval",
			home: approveAll, local: `{"disabledMcpjsonServers":["off"]}`,
			want: map[string]State{"srv": StateEnabled, "off": StateDisabled},
		},
		{
			name:    "no failure keeps a project approval",
			project: approveAll, local: `{"disabledMcpjsonServers":["off"]}`,
			want: map[string]State{"srv": StateProjectApproved, "off": StateDisabled},
		},
		{
			name: "a bad user file revokes a project approval",
			home: wrongType, project: approveAll,
			want:     map[string]State{"srv": StateUnapproved, "off": StateUnapproved},
			wantErrs: 1,
		},
		{
			name:   "legacy failure revokes a trusted approval",
			legacy: claudeProjectState{enabledMcpjson: nameSetOf("srv")}, home: `{"enabledMcpjsonServers":["off"]}`,
			legacyFailed: true,
			want:         map[string]State{"srv": StateUnapproved, "off": StateUnapproved},
		},
		{
			name:   "missing files do not count",
			legacy: claudeProjectState{enableAll: new(true)},
			want:   map[string]State{"srv": StateEnabled, "off": StateEnabled},
		},
		{
			// Before the fix, the lost list of the bad project file let the
			// user file approve every server.
			name: "a wrong-type project file revokes the approval of the user file",
			home: approveAll, project: wrongType,
			want:     map[string]State{"srv": StateUnapproved, "off": StateUnapproved},
			wantErrs: 1,
		},
		{
			name:    "invalid JSON in the local file revokes the approval",
			project: approveAll, local: badJSON,
			want:     map[string]State{"srv": StateUnapproved, "off": StateUnapproved},
			wantErrs: 1,
		},
		{
			name: "a bad user file revokes the approval of the local file",
			home: badJSON, local: `{"enabledMcpjsonServers":["srv","off"]}`,
			want:     map[string]State{"srv": StateUnapproved, "off": StateUnapproved},
			wantErrs: 1,
		},
		{
			name: "disabled stays disabled",
			home: `{"disabledMcpjsonServers":["off"],"enableAllProjectMcpServers":true}`, project: wrongType,
			want:     map[string]State{"srv": StateUnapproved, "off": StateDisabled},
			wantErrs: 1,
		},
		{
			name:  "legacy failure revokes the approval of a settings file",
			local: approveAll, legacyFailed: true,
			want: map[string]State{"srv": StateUnapproved, "off": StateUnapproved},
		},
		{
			name:  "legacy failure keeps a disabled server",
			local: `{"enableAllProjectMcpServers":true,"disabledMcpServers":["off"]}`, legacyFailed: true,
			want: map[string]State{"srv": StateUnapproved, "off": StateDisabled},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := settingsDirs(t, tt.home, tt.project, tt.local)
			servers := []Server{{Name: "srv"}, {Name: "off"}}

			errs := setMcpjsonStates(t.Context(), servers, home, work, tt.legacy, tt.legacyFailed)

			if len(errs) != tt.wantErrs {
				t.Errorf("got %d errors, want %d: %v", len(errs), tt.wantErrs, errs)
			}
			checkStates(t, servers, tt.want)
		})
	}

	t.Run("canceled context revokes the approval", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		home, work := settingsDirs(t, "", "", "")
		servers := []Server{{Name: "srv"}}

		errs := setMcpjsonStates(ctx, servers, home, work, claudeProjectState{enableAll: new(true)}, false)

		checkFileErrors(t, settingsPath(home, claudeSettingsFile), errs, []errWant{{Reason: reasonCanceled, HasErr: true}})
		checkStates(t, servers, map[string]State{"srv": StateUnapproved})
	})

	t.Run("bad file when workDir is home gives one error and revokes", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		writeFile(t, home, claudeDir+"/"+claudeSettingsFile, []byte(wrongType))
		servers := []Server{{Name: "srv"}}

		errs := setMcpjsonStates(t.Context(), servers, home, home, claudeProjectState{enableAll: new(true)}, false)

		checkFileErrors(t, settingsPath(home, claudeSettingsFile), errs, []errWant{{Reason: reasonBadServerState}})
		checkErrorsUntrusted(t, errs, false)
		checkStates(t, servers, map[string]State{"srv": StateUnapproved})
	})
}

// TestRevokeApprovals checks that only StateEnabled and StateProjectApproved
// change, and that no other field changes.
func TestRevokeApprovals(t *testing.T) {
	t.Parallel()
	servers := []Server{
		{Name: "on", State: StateEnabled, Command: "c"},
		{Name: "off", State: StateDisabled, Command: "c"},
		{Name: "pending", State: StateUnapproved, Command: "c"},
		{Name: "repo", State: StateProjectApproved, Command: "c"},
		// A value after the constants is not an approval: it keeps its State.
		{Name: "unknown", State: StateProjectApproved + 1, Command: "c"},
	}
	revokeApprovals(servers)
	checkStates(t, servers, map[string]State{
		"on": StateUnapproved, "off": StateDisabled, "pending": StateUnapproved,
		"repo": StateUnapproved, "unknown": StateProjectApproved + 1,
	})
	for i, s := range servers {
		if s.Command != "c" {
			t.Errorf("servers[%d].Command = %q, want %q", i, s.Command, "c")
		}
	}
	revokeApprovals(nil) // must not panic
}

// failedClaudeJSON returns a ~/.claude.json with the top-level server "top"
// and a "projects" section that maps each key of projects to its raw JSON
// value. extra, when it is not empty, is more top-level server entries.
func failedClaudeJSON(t *testing.T, extra string, projects map[string]string) []byte {
	t.Helper()
	raw := make(map[string]json.RawMessage, len(projects))
	for k, v := range projects {
		raw[k] = json.RawMessage(v)
	}
	section, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	servers := `"top":{"command":"t"}`
	if extra != "" {
		servers += "," + extra
	}
	return []byte(`{"mcpServers":{` + servers + `},"projects":` + string(section) + `}`)
}

// TestReadGlobalClaudeCodeStateFailed checks the failed result of
// readGlobalClaudeCodeState with real files: it is true only when the
// projects section was not read to the end with an error, or when the
// projects.<workDir> object or its state has an error. When it is true, every
// top-level server with StateEnabled becomes StateUnapproved.
func TestReadGlobalClaudeCodeStateFailed(t *testing.T) {
	t.Parallel()

	const (
		goodState = `{"enabledMcpjsonServers":["srv"]}`
		badState  = `{"enabledMcpjsonServers":"srv"}`
		// loneSurrogate is a server whose command holds a lone UTF-16
		// surrogate escape. JSON text, so the backslash stays.
		loneSurrogate = `{"mcpServers":{"evil":{"command":"\ud800"}}}`
	)

	tests := []struct {
		name string
		// data builds the file from the work directory. nil means that the
		// file is missing.
		data     func(t *testing.T, work string) []byte
		canceled bool
		want     bool
		// wantTop tells that the top-level server "top" is in the result.
		wantTop bool
	}{
		{
			name: "good state",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, "", map[string]string{work: goodState})
			},
			wantTop: true,
		},
		{
			name: "no workDir project",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, "", map[string]string{work + "-other": goodState})
			},
			wantTop: true,
		},
		{
			name: "projects is null",
			data: func(*testing.T, string) []byte {
				return []byte(`{"mcpServers":{"top":{"command":"t"}},"projects":null}`)
			},
			wantTop: true,
		},
		{
			name:    "no projects key",
			data:    func(*testing.T, string) []byte { return []byte(`{"mcpServers":{"top":{"command":"t"}}}`) },
			wantTop: true,
		},
		{
			name: "bad state of the work project",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, "", map[string]string{work: badState})
			},
			want:    true,
			wantTop: true,
		},
		{
			name: "work project that is not an object",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, "", map[string]string{work: `[]`})
			},
			want:    true,
			wantTop: true,
		},
		{
			name: "work project with a case variant of mcpServers",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, "", map[string]string{work: `{"mcpServers":{},"MCPServers":{}}`})
			},
			want:    true,
			wantTop: true,
		},
		{
			name: "bad name string in the state of the work project",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, "", map[string]string{work: `{"disabledMcpServers":["\udc00"]}`})
			},
			want:    true,
			wantTop: true,
		},
		{
			// Only the state of the work project matters.
			name: "bad state of another project",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, "", map[string]string{work: goodState, work + "-other": badState})
			},
			wantTop: true,
		},
		{
			name: "bad server of the work project",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, "", map[string]string{work: `{"mcpServers":{"bad":{"command":5}}}`})
			},
			wantTop: true,
		},
		{
			name: "bad top-level server",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, `"bad":{"command":5}`, map[string]string{work: goodState})
			},
			wantTop: true,
		},
		{
			// The review case: the bad string is in another project, but the
			// file is refused as a whole, so the work project is lost too.
			name: "lone surrogate in another project's servers",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, "", map[string]string{work: goodState, work + "-other": loneSurrogate})
			},
			want: true,
		},
		{
			name: "lone surrogate in a top-level server",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, `"evil":{"command":"\ud800"}`, map[string]string{work: goodState})
			},
			want: true,
		},
		{
			name: "too many entries",
			data: func(t *testing.T, work string) []byte {
				projects := map[string]string{work: goodState}
				for i := range maxServersPerFile {
					projects["/z"+strconv.Itoa(i)] = `{}`
				}
				return failedClaudeJSON(t, "", projects)
			},
			want: true,
		},
		{
			name:    "projects is not an object",
			data:    func(*testing.T, string) []byte { return []byte(`{"mcpServers":{"top":{"command":"t"}},"projects":[]}`) },
			want:    true,
			wantTop: true,
		},
		{
			name: "case variant of projects",
			data: func(*testing.T, string) []byte {
				return []byte(`{"mcpServers":{"top":{"command":"t"}},"projects":{},"Projects":{}}`)
			},
			want:    true,
			wantTop: true,
		},
		{
			name: "invalid JSON",
			data: func(*testing.T, string) []byte { return []byte(`{"projects":`) },
			want: true,
		},
		{
			name: "file is not an object",
			data: func(*testing.T, string) []byte { return []byte(`null`) },
			want: true,
		},
		{
			name: "canceled",
			data: func(t *testing.T, work string) []byte {
				return failedClaudeJSON(t, "", map[string]string{work: goodState})
			},
			canceled: true,
			want:     true,
		},
		{
			name: "empty file",
			data: func(*testing.T, string) []byte { return []byte(" \n\t") },
		},
		{
			name: "missing file",
			data: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := t.TempDir(), t.TempDir()
			path := filepath.Join(home, ".claude.json")
			if tt.data != nil {
				writeFile(t, home, ".claude.json", tt.data(t, work))
			}
			ctx := t.Context()
			if tt.canceled {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}

			res, _, failed := readGlobalClaudeCodeState(ctx, path, work)

			if failed != tt.want {
				t.Errorf("failed = %v, want %v; errors: %v", failed, tt.want, res.Errors)
			}
			// A failure must show as an error, so the scan fails.
			if failed && len(res.Errors) == 0 {
				t.Error("failed = true with no error")
			}
			wantTop := StateEnabled
			if tt.want {
				wantTop = StateUnapproved
			}
			var sawTop bool
			for _, s := range res.Servers {
				if s.Scope != ScopeGlobal || s.Name != "top" {
					continue
				}
				sawTop = true
				if s.State != wantTop {
					t.Errorf("top-level server State = %v, want %v", s.State, wantTop)
				}
			}
			if sawTop != tt.wantTop {
				t.Errorf("top-level server in the result = %v, want %v; servers: %v", sawTop, tt.wantTop, serverNames(res.Servers))
			}
		})
	}

	t.Run("failure keeps the state of the project servers", func(t *testing.T) {
		t.Parallel()
		home, work := t.TempDir(), t.TempDir()
		data := failedClaudeJSON(t, "", map[string]string{
			work:            badState,
			work + "-other": `{"mcpServers":{"p-on":{"command":"p"},"p-off":{"command":"p"}},"disabledMcpServers":["p-off"]}`,
		})
		path := writeFile(t, home, ".claude.json", data)

		res, _, failed := readGlobalClaudeCodeState(t.Context(), path, work)

		if !failed {
			t.Fatalf("failed = false, want true; errors: %v", res.Errors)
		}
		checkProjectStates(t, res.Servers, map[projectServer]State{
			{"", "top"}:                StateUnapproved,
			{work + "-other", "p-on"}:  StateEnabled,
			{work + "-other", "p-off"}: StateDisabled,
		})
	})

}

// TestLegacyFailureRevokesSettingsApproval is the review case end to end: a
// lone surrogate in the servers of another project refuses the whole
// ~/.claude.json, so the projects.<WorkDir> state is lost. Its
// disabledMcpjsonServers list could reject the server, so the approval from
// the trusted user settings file must not hold.
func TestLegacyFailureRevokesSettingsApproval(t *testing.T) {
	t.Parallel()
	home, work := settingsDirs(t, `{"enabledMcpjsonServers":["srv"]}`, "", `{"enabledMcpjsonServers":["repo"]}`)
	data := failedClaudeJSON(t, "", map[string]string{
		work:            `{"disabledMcpjsonServers":["srv"]}`,
		work + "-other": `{"mcpServers":{"evil":{"command":"\ud800"}}}`,
	})
	path := writeFile(t, home, ".claude.json", data)

	res, legacy, failed := readGlobalClaudeCodeState(t.Context(), path, work)

	if !failed {
		t.Fatalf("failed = false, want true; errors: %v", res.Errors)
	}
	checkFileErrors(t, path, res.Errors, []errWant{{ProjectPath: work + "-other", Reason: reasonBadString, Line: 1}})
	if len(res.Servers) != 0 {
		t.Errorf("servers = %v, want none from a refused file", serverNames(res.Servers))
	}
	if got := viewState(legacy); !reflect.DeepEqual(got, claudeStateView{}) {
		t.Errorf("legacy state = %+v, want zero", got)
	}

	servers := []Server{{Name: "srv"}, {Name: "repo"}, {Name: "other"}}
	errs := setMcpjsonStates(t.Context(), servers, home, work, legacy, failed)

	if len(errs) != 0 {
		t.Errorf("settings errors = %v, want none", errs)
	}
	checkStates(t, servers, map[string]State{
		"srv":   StateUnapproved,
		"repo":  StateUnapproved,
		"other": StateUnapproved,
	})

	// Without the failure, the same settings approve: so the check above
	// fails only because of the failed flag.
	control := []Server{{Name: "srv"}, {Name: "repo"}}
	setMcpjsonStates(t.Context(), control, home, work, legacy, false)
	checkStates(t, control, map[string]State{"srv": StateEnabled, "repo": StateProjectApproved})
}
