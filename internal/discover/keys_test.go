package discover

import (
	"encoding/json"
	"testing"
)

func TestIsCaseVariant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		known []string
		want  bool
	}{
		{name: "exact match", key: "args", known: []string{"args"}, want: false},
		{name: "upper case", key: "ARGS", known: []string{"args"}, want: true},
		{name: "mixed case", key: "Command", known: []string{"command"}, want: true},
		// U+017F (long s) folds to "s" in Unicode case folding.
		{name: "unicode fold", key: "argſ", known: []string{"args"}, want: true},
		// U+212A (Kelvin sign) folds to "k".
		{name: "kelvin sign", key: "Key", known: []string{"key"}, want: true},
		{name: "unrelated key", key: "argv", known: []string{"args"}, want: false},
		{name: "longer key", key: "argss", known: []string{"args"}, want: false},
		{name: "empty key", key: "", known: []string{"args"}, want: false},
		{name: "no known keys", key: "args", want: false},
		{name: "second known key", key: "ENV", known: []string{"args", "env"}, want: true},
		{name: "exact match of one, other known", key: "env", known: []string{"args", "env"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isCaseVariant(tt.key, tt.known...); got != tt.want {
				t.Errorf("isCaseVariant(%q, %q) = %v, want %v", tt.key, tt.known, got, tt.want)
			}
		})
	}
}

func TestHasCaseVariant(t *testing.T) {
	t.Parallel()

	// keysOf returns a map with the given keys. The values do not matter.
	keysOf := func(keys ...string) map[string]json.RawMessage {
		m := make(map[string]json.RawMessage, len(keys))
		for _, k := range keys {
			m[k] = json.RawMessage(`null`)
		}
		return m
	}

	tests := []struct {
		name  string
		obj   map[string]json.RawMessage
		known []string
		want  bool
	}{
		{name: "nil map", obj: nil, known: []string{"command"}, want: false},
		{name: "exact keys only", obj: keysOf("command", "args"), known: []string{"command", "args"}, want: false},
		{name: "exact key and its variant", obj: keysOf("command", "Command"), known: []string{"command"}, want: true},
		{name: "variant alone", obj: keysOf("ENV"), known: []string{"env"}, want: true},
		{name: "unicode fold", obj: keysOf("argſ"), known: []string{"args"}, want: true},
		{name: "unrelated keys", obj: keysOf("disabled", "argv"), known: []string{"args"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasCaseVariant(tt.obj, tt.known...); got != tt.want {
				t.Errorf("hasCaseVariant(keys %v, %q) = %v, want %v", keysList(tt.obj), tt.known, got, tt.want)
			}
		})
	}

	// hasCaseVariant is generic: it works for any map value type, for
	// example the TOML values of the Codex reader.
	t.Run("other value type", func(t *testing.T) {
		t.Parallel()
		if !hasCaseVariant(map[string]int{"URL": 1}, "url") {
			t.Error("hasCaseVariant(map[string]int{URL}, url) = false, want true")
		}
		if hasCaseVariant(map[string]int{"url": 1}, "url") {
			t.Error("hasCaseVariant(map[string]int{url}, url) = true, want false")
		}
		if !hasCaseVariant(map[string]struct{}{"Headers": {}}, "headers") {
			t.Error("hasCaseVariant(map[string]struct{}{Headers}, headers) = false, want true")
		}
	})
}

// keysList returns the keys of m, for a failure message.
func keysList[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
