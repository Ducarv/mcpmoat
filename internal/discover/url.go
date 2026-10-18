package discover

import (
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
)

// The build fails if URL stops implementing one of these interfaces.
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
// See the package doc, Secrets.
//
// URL is built like [Secret]; the Secret comments give the reasons for the
// struct type, the fields and the value receivers.
type URL struct {
	// _ makes u1 == u2 a compile error, as in Secret.
	_ [0]func()

	// v is a pointer so that fmt prints only an address when it cannot call
	// Format (see Secret.v).
	v *string
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

// GoString returns the same text as String. It implements fmt.GoStringer
// for code that calls it directly; fmt itself calls Format for %#v.
func (u URL) GoString() string {
	return u.String()
}

// Format passes the verb and flags to the String result, so only the
// redacted URL reaches fmt: %q quotes and escapes it, a width pads it. It
// implements fmt.Formatter.
func (u URL) Format(f fmt.State, verb rune) {
	// fmt has no way to report a write error from Format (see Secret.Format).
	_, _ = fmt.Fprintf(f, fmt.FormatString(f, verb), u.String())
}

// MarshalJSON returns the String result as a JSON string. It implements
// json.Marshaler.
func (u URL) MarshalJSON() ([]byte, error) {
	// The redacted URL can hold a quote or a backslash, so it must be
	// escaped to give valid JSON.
	return json.Marshal(u.String())
}

// MarshalText returns the String result. It implements
// encoding.TextMarshaler (see Secret.MarshalText for the encoders that use
// it).
func (u URL) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

// UnmarshalText stores a copy of text as the URL. It never fails. It
// implements encoding.TextUnmarshaler.
//
// Marshalling gives the redacted form, so a round trip is one-way, as for
// Secret.
func (u *URL) UnmarshalText(text []byte) error {
	raw := string(text) // copy: the decoder may reuse the text buffer
	u.v = &raw
	return nil
}

// LogValue returns the String result as a string value. It implements
// slog.LogValuer, so log/slog handlers never see the raw URL.
func (u URL) LogValue() slog.Value {
	return slog.StringValue(u.String())
}
