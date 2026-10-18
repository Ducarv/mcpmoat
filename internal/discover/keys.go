package discover

import "strings"

// The clients match config keys exactly: "Command" is not "command". A key
// that differs from a known key only by letter case is ambiguous: the client
// ignores it, but a reader that folds case would use it. So the readers reject
// it with reasonAmbiguousKey. These helpers find such keys.

// isCaseVariant reports whether key differs from one of known only by letter
// case: strings.EqualFold is true, but the strings are not equal. EqualFold
// uses Unicode case folding, so "ARGſ" (with U+017F, a long s) is a case
// variant of "args" too.
func isCaseVariant(key string, known ...string) bool {
	for _, k := range known {
		if key != k && strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

// hasCaseVariant reports whether obj has a key that is a case variant (see
// isCaseVariant) of one of known. It is generic in the value type, so it
// works for a decoded JSON object (map[string]json.RawMessage) and for a
// decoded TOML table (map[string]toml.Primitive).
func hasCaseVariant[V any](obj map[string]V, known ...string) bool {
	for key := range obj {
		if isCaseVariant(key, known...) {
			return true
		}
	}
	return false
}
