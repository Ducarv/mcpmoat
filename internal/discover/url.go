package discover

import (
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

// Compile-time interface checks, as for Secret.
var (
	_ fmt.Formatter            = URL{}
	_ fmt.Stringer             = URL{}
	_ fmt.GoStringer           = URL{}
	_ json.Marshaler           = URL{}
	_ encoding.TextMarshaler   = URL{}
	_ encoding.TextUnmarshaler = (*URL)(nil)
	_ slog.LogValuer           = URL{}
)

// URL holds a remote server endpoint as written in a client config. The
// endpoint can contain credentials (userinfo, a token in the query or the
// fragment), so printing, logging or encoding a URL always gives
// [RedactURL] of the value. Only Reveal returns the value as written.
// The zero value is an empty URL and prints as "". URLs cannot be compared
// with ==; use Reveal or reflect.DeepEqual.
//
// URL is built like [Secret]; see the Secret comments for the idioms (struct
// and not a string type, the [0]func() field, the pointer field, value and
// pointer receivers).
type URL struct {
	_ [0]func() // not comparable with ==, zero size (same idiom as Secret)
	v *string   // pointer, so fmt's reflection fallback prints only an address
}

// NewURL returns a URL that holds raw.
func NewURL(raw string) URL {
	return URL{v: &raw}
}

// Reveal returns the URL as written in the config, or "" for the zero URL.
//
// Call Reveal only where the value is used: in internal/inspect, to connect
// to the server, and in internal/rules, for config rules. Never pass the
// result to fmt, a logger, an error or an encoder; use String instead.
func (u URL) Reveal() string {
	if u.v == nil {
		return ""
	}
	return *u.v
}

// String returns RedactURL of the value. It implements fmt.Stringer.
func (u URL) String() string {
	return RedactURL(u.Reveal())
}

// GoString returns the same text as String (not quoted), so the %#v verb
// does not show credentials. It implements fmt.GoStringer.
func (u URL) GoString() string {
	return u.String()
}

// Format writes the String result for every verb and flag, so no verb can
// show credentials. It implements fmt.Formatter.
func (u URL) Format(f fmt.State, _ rune) {
	// fmt has no way to report a write error from Format (see Secret.Format).
	_, _ = io.WriteString(f, u.String())
}

// MarshalJSON returns the String result as a JSON string. It implements
// json.Marshaler.
func (u URL) MarshalJSON() ([]byte, error) {
	// json.Marshal quotes and escapes the text, so the result is always a
	// valid JSON string, even if the redacted URL holds a quote or a
	// backslash.
	return json.Marshal(u.String())
}

// MarshalText returns the String result. It implements
// encoding.TextMarshaler (see Secret.MarshalText for the encoders that use it).
func (u URL) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

// UnmarshalText stores a copy of text as the URL. It never fails. It
// implements encoding.TextUnmarshaler.
//
// Marshalling gives the redacted form, so a round trip is one-way, as for
// Secret.
func (u *URL) UnmarshalText(text []byte) error {
	raw := string(text) // copies the bytes
	u.v = &raw
	return nil
}

// LogValue returns the String result as a string value. It implements
// slog.LogValuer, so log/slog handlers never see the raw URL.
func (u URL) LogValue() slog.Value {
	return slog.StringValue(u.String())
}
