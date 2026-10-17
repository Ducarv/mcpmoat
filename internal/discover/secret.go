package discover

import (
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
)

// Mask is the text that replaces a secret value in all output.
const Mask = "********"

// Compile-time interface checks. Each line assigns a value to the blank
// identifier "_" with an interface type, so the build fails if Secret stops
// implementing that interface. Nothing runs at run time.
var (
	_ fmt.Formatter            = Secret{}
	_ fmt.Stringer             = Secret{}
	_ fmt.GoStringer           = Secret{}
	_ json.Marshaler           = Secret{}
	_ encoding.TextMarshaler   = Secret{}
	_ encoding.TextUnmarshaler = (*Secret)(nil)
	_ slog.LogValuer           = Secret{}
)

// Secret holds a sensitive value from a client config, such as an env value or a
// header value. Printing, logging or encoding a Secret always gives Mask; only
// Reveal returns the value. The zero value is an empty secret. Secrets cannot be
// compared with ==; use Reveal or reflect.DeepEqual.
//
// reflect.DeepEqual tells the zero Secret (unset, for example decoded from a
// JSON null) apart from NewSecret(""): the first holds a nil pointer, the
// second a pointer to "". Reveal gives "" for both. Compare the Reveal
// results if that difference does not matter.
//
// Secret is a struct and not "type Secret string", so code cannot get the
// value with a plain string(s) conversion.
//
// The print and marshal methods use value receivers (s Secret), so both a
// Secret and a *Secret have them and both give Mask. UnmarshalText uses a
// pointer receiver (s *Secret) because it must change the receiver.
type Secret struct {
	// _ makes Secret not comparable: func values cannot be compared, so
	// s1 == s2 is a compile error. An array of length 0 takes no memory.
	// Without it, == would compare the pointers below (identity), not the
	// values. reflect.DeepEqual still compares the values behind the pointers.
	_ [0]func()

	// v is a pointer on purpose. When fmt prints a struct that holds a Secret
	// in an unexported field, it cannot call Format or String on that field
	// (reflect CanInterface is false, see handleMethods in fmt/print.go), so
	// it prints the raw field contents by reflection. With a pointer, fmt
	// prints only an address, never the value.
	v *string
}

// NewSecret returns a Secret that holds value.
func NewSecret(value string) Secret {
	return Secret{v: &value}
}

// Reveal returns the secret value, or "" for the zero Secret.
//
// Call Reveal only where the value is used: in the environment of a child
// process, in an HTTP header or in a config rule. Never pass the result to
// fmt, a logger, an error or an encoder.
func (s Secret) Reveal() string {
	if s.v == nil {
		return ""
	}
	return *s.v
}

// String returns Mask. It implements fmt.Stringer.
func (s Secret) String() string {
	return Mask
}

// GoString returns Mask, so the %#v verb does not show the value. It
// implements fmt.GoStringer.
func (s Secret) GoString() string {
	return Mask
}

// Format writes Mask for every verb and flag (%v, %+v, %#v, %s, %q, %x and
// all others). It implements fmt.Formatter, which fmt checks before String.
func (s Secret) Format(f fmt.State, _ rune) {
	// fmt.State is an io.Writer. fmt has no way to report a write error from
	// Format, so the result is discarded on purpose.
	_, _ = io.WriteString(f, Mask)
}

// MarshalJSON returns Mask as a JSON string. It implements json.Marshaler.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + Mask + `"`), nil
}

// MarshalText returns Mask. It implements encoding.TextMarshaler, which
// encoding/xml and most text encoders (such as TOML and YAML encoders) use,
// and which encoding/json uses for map keys.
//
// encoding/gob does not use MarshalText: it checks only GobEncoder and
// BinaryMarshaler. Secret has no exported fields, so gob refuses to encode
// it ("gob: type discover.Secret has no exported fields") and cannot leak
// the value. Do not add GobEncode or MarshalBinary.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(Mask), nil
}

// UnmarshalText stores a copy of text as the secret value. It never fails.
// It implements encoding.TextUnmarshaler, so JSON and TOML strings decode
// straight into a Secret.
//
// Marshalling gives Mask, so a round trip is one-way: decoding the output of
// MarshalText or MarshalJSON gives Mask, not the original value.
func (s *Secret) UnmarshalText(text []byte) error {
	// string(text) copies the bytes, so later changes to the decoder's buffer
	// do not change the stored value.
	value := string(text)
	s.v = &value
	return nil
}

// LogValue returns Mask as a string value. It implements slog.LogValuer, so
// log/slog handlers never see the secret value.
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(Mask)
}

// SecretMap maps a name (env var name or header name) to its secret value.
// Keys are not secret.
type SecretMap map[string]Secret

// Keys returns the names in m in sorted order. It is safe to call on a nil
// map. For a nil or empty map it returns a non-nil empty slice, so JSON
// output gives [] and not null.
func (m SecretMap) Keys() []string {
	// maps.Keys returns an iterator; AppendSeq collects it into a slice
	// whose capacity is set up front. This is not
	// slices.Sorted(maps.Keys(m)) because that returns nil for an empty
	// map, and Keys must return a non-nil slice (JSON [] and not null).
	keys := slices.AppendSeq(make([]string, 0, len(m)), maps.Keys(m))
	slices.Sort(keys)
	return keys
}
