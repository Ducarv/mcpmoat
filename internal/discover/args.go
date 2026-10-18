package discover

import (
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
)

// The build fails if Args stops implementing one of these interfaces.
var (
	_ fmt.Formatter          = Args{}
	_ fmt.Stringer           = Args{}
	_ fmt.GoStringer         = Args{}
	_ json.Marshaler         = Args{}
	_ encoding.TextMarshaler = Args{}
	_ slog.LogValuer         = Args{}
)

// Args holds the arguments of a stdio server command as written in a client
// config. Real configs often put tokens in args, so printing, logging or
// encoding Args always gives [RedactArgs] of the values. Only Values returns
// the args as written. See the package doc, Secrets.
//
// The zero value holds no args and prints as "" (String) or [] (%v). Args
// cannot be compared with ==; use Values or reflect.DeepEqual.
// reflect.DeepEqual tells the zero Args (from NewArgs(nil)) apart from
// NewArgs([]string{}), as it does for a nil and an empty slice.
//
// Args is built like [Secret]; the Secret comments give the reasons for the
// struct type, the fields and the value receivers.
type Args struct {
	// _ makes a1 == a2 a compile error, as in Secret.
	_ [0]func()

	// v is a pointer to a pointer on purpose. fmt cannot call Format on Args
	// in an unexported field (see Secret.v), so it prints v by reflection.
	// A plain []string would print every arg. A *[]string is not enough
	// either: for a verb that is bad for a pointer (%s, %q), fmt prints the
	// pointer again from the top (badVerb in fmt/print.go), and at the top
	// it follows a pointer to a slice and prints the args. It never follows
	// a pointer to a pointer, so only an address shows.
	// reflect.DeepEqual still follows both pointers and compares the args.
	//
	// v is nil for the zero Args. Otherwise *v is never nil.
	v **[]string
}

// NewArgs returns Args that hold a copy of args, so a later change to args
// does not change the result. NewArgs(nil) gives the zero Args.
func NewArgs(args []string) Args {
	if args == nil {
		return Args{}
	}
	c := slices.Clone(args)
	p := &c
	return Args{v: &p}
}

// Values returns a copy of the args as written in the config, or nil for the
// zero Args. A change to the result does not change a.
//
// Call Values only where the args are used: in internal/inspect, to run the
// exact configured command (NFR-04), and in internal/rules, for config
// rules. Never pass the result to fmt, a logger, an error or an encoder; use
// String or print a itself instead.
func (a Args) Values() []string {
	return slices.Clone(a.raw())
}

// Len returns the number of args.
func (a Args) Len() int {
	return len(a.raw())
}

// raw returns the stored slice without a copy. Only the methods in this file
// use it, and none of them changes the slice or gives it to a caller.
func (a Args) raw() []string {
	if a.v == nil {
		return nil
	}
	return **a.v
}

// display returns the form of the args that all output methods use:
// RedactArgs of the values, or nil for the zero Args.
func (a Args) display() []string {
	if a.v == nil {
		return nil
	}
	// RedactArgs returns a new slice and does not change its input, so it
	// can read the stored slice directly.
	return RedactArgs(a.raw())
}

// String returns the RedactArgs result joined by one space, or "" for no
// args. It implements fmt.Stringer.
func (a Args) String() string {
	return strings.Join(a.display(), " ")
}

// GoString returns the RedactArgs result in Go syntax, as %#v prints a
// []string. It implements fmt.GoStringer for code that calls it directly;
// fmt itself calls Format for %#v.
func (a Args) GoString() string {
	return fmt.Sprintf("%#v", a.display())
}

// Format passes the verb and flags to the RedactArgs result, a []string, so
// only the redacted args reach fmt: %v gives [a ********], %q quotes each
// arg and a width pads each arg. It implements fmt.Formatter.
func (a Args) Format(f fmt.State, verb rune) {
	// fmt has no way to report a write error from Format (see Secret.Format).
	_, _ = fmt.Fprintf(f, fmt.FormatString(f, verb), a.display())
}

// MarshalJSON returns the RedactArgs result as a JSON array of strings, or
// null for the zero Args (as for a nil []string). It implements
// json.Marshaler.
func (a Args) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.display())
}

// MarshalText returns the String result. It implements
// encoding.TextMarshaler (see Secret.MarshalText for the encoders that use it).
func (a Args) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// LogValue returns the RedactArgs result as a value. It implements
// slog.LogValuer, so log/slog handlers never see the args as written.
func (a Args) LogValue() slog.Value {
	return slog.AnyValue(a.display())
}
