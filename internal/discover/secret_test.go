package discover_test

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// The wrapper types below hold a discover.Secret in different ways, so the
// tests can check how fmt and the encoders treat each one.

// withExported holds a Secret in an exported field. fmt and the encoders can
// call the field's methods, so they print Mask.
type withExported struct {
	Name string
	S    discover.Secret
}

// withExportedPtr holds a *Secret in an exported field.
type withExportedPtr struct {
	P *discover.Secret
}

// withUnexported holds a Secret in an unexported field. fmt cannot call
// methods on unexported fields (reflect CanInterface is false), so it prints
// the raw struct contents. Secret keeps its value behind a pointer, so fmt
// prints an address and not the value.
type withUnexported struct {
	s discover.Secret
}

// withUnexportedMap holds a SecretMap in an unexported field.
type withUnexportedMap struct {
	m discover.SecretMap
}

// withUnexportedPtr holds a *Secret in an unexported field.
type withUnexportedPtr struct {
	p *discover.Secret
}

// TestSecretFormatVerbs prints many shapes of Secret with many fmt verbs and
// checks that the canary value never appears in the output.
func TestSecretFormatVerbs(t *testing.T) {
	t.Parallel()

	canary := discovertest.CanaryEnv
	val := discover.NewSecret(canary)

	values := []struct {
		name string
		arg  any
		// direct is true when fmt can call the Secret methods, so the
		// output must contain Mask formatted with the same verb (except
		// for %T and %p, see below).
		direct bool
	}{
		{name: "Secret", arg: val, direct: true},
		{name: "*Secret", arg: &val, direct: true},
		{name: "[]Secret", arg: []discover.Secret{val, val}, direct: true},
		{name: "map[string]Secret", arg: map[string]discover.Secret{"API_KEY": val}, direct: true},
		{name: "SecretMap", arg: discover.SecretMap{"API_KEY": val}, direct: true},
		{name: "exported field", arg: withExported{Name: "n", S: val}, direct: true},
		{name: "exported pointer field", arg: withExportedPtr{P: &val}, direct: true},
		{name: "unexported field", arg: withUnexported{s: val}},
		{name: "unexported map field", arg: withUnexportedMap{m: discover.SecretMap{"API_KEY": val}}},
		{name: "unexported pointer field", arg: withUnexportedPtr{p: &val}},
		{name: "pointer to unexported field", arg: &withUnexported{s: val}},
	}

	for _, v := range values {
		for _, verb := range fmtVerbs() {
			t.Run(v.name+"/"+verb, func(t *testing.T) {
				t.Parallel()
				got := fmt.Sprintf(verb, v.arg)
				discovertest.AssertNoLeak(t, "fmt.Sprintf("+verb+")", got, canary)

				// Neither %T nor %p calls the Secret methods. %T prints
				// only the type name. For a pointer, slice or map, %p
				// prints an address. For a struct, %p is a bad verb: fmt
				// skips Format and prints the struct fields by reflection
				// ("%!p(discover.Secret={[] 0xc000...})"). That is safe
				// only because Secret.v is a *string, so only an address
				// shows. Do not change v to a string.
				if !v.direct || verb == "%T" || verb == "%p" {
					return
				}
				if want := fmt.Sprintf(verb, discover.Mask); !strings.Contains(got, want) {
					t.Errorf("fmt.Sprintf(%q, %s) = %q, want it to contain %q", verb, v.name, got, want)
				}
			})
		}
	}
}

// TestSecretFormatFlags checks that Format passes the verb and flags on to
// Mask.
func TestSecretFormatFlags(t *testing.T) {
	t.Parallel()

	val := discover.NewSecret(discovertest.CanaryEnv)
	tests := []struct {
		format string
		want   string
	}{
		{format: "%q", want: `"********"`},
		{format: "%#v", want: `"********"`},
		{format: "%-10v", want: "********  "},
		{format: "%10s", want: "  ********"},
		{format: "%x", want: "2a2a2a2a2a2a2a2a"},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			t.Parallel()
			got := fmt.Sprintf(tt.format, val)
			discovertest.AssertNoLeak(t, "fmt.Sprintf("+tt.format+")", got, discovertest.CanaryEnv)
			if got != tt.want {
				t.Errorf("fmt.Sprintf(%q) = %q, want %q", tt.format, got, tt.want)
			}
		})
	}
}

// TestSecretPrintFuncs checks the fmt functions that take no format string
// and errors built from a Secret.
func TestSecretPrintFuncs(t *testing.T) {
	t.Parallel()

	canary := discovertest.CanaryEnv
	val := discover.NewSecret(canary)

	inner := fmt.Errorf("x: %v", val)
	wrapped := fmt.Errorf("outer: %w", inner)
	joined := errors.Join(inner, fmt.Errorf("y: %s", &val))

	tests := []struct {
		name string
		got  string
	}{
		{name: "Sprint", got: fmt.Sprint(val)},
		{name: "Sprint pointer", got: fmt.Sprint(&val)},
		{name: "Sprint several", got: fmt.Sprint("a", val, 1, val)},
		{name: "Sprintln", got: fmt.Sprintln(val, &val)},
		{name: "Errorf %v", got: inner.Error()},
		{name: "Errorf %w", got: wrapped.Error()},
		{name: "errors.Join", got: joined.Error()},
		{name: "wrapped error %+v", got: fmt.Sprintf("%+v", wrapped)},
		{name: "wrapped error %#v", got: fmt.Sprintf("%#v", wrapped)},
		{name: "joined error %#v", got: fmt.Sprintf("%#v", joined)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			discovertest.AssertNoLeak(t, tt.name, tt.got, canary)
		})
	}

	// The error chain must still work: errors.Is finds the inner error.
	if !errors.Is(wrapped, inner) {
		t.Errorf("errors.Is(wrapped, inner) = false, want true")
	}
	for _, err := range []error{inner, wrapped, joined} {
		if !strings.Contains(err.Error(), discover.Mask) {
			t.Errorf("error %q does not contain %q", err.Error(), discover.Mask)
		}
	}
}

// TestSecretMarshalJSON checks the exact JSON form of a Secret.
func TestSecretMarshalJSON(t *testing.T) {
	t.Parallel()

	val := discover.NewSecret(discovertest.CanaryEnv)
	want := `"` + discover.Mask + `"`

	tests := []struct {
		name string
		arg  any
	}{
		{name: "Secret", arg: val},
		{name: "*Secret", arg: &val},
		{name: "zero Secret", arg: discover.Secret{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tt.arg)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if string(got) != want {
				t.Errorf("json.Marshal() = %s, want %s", got, want)
			}
		})
	}
}

// TestSecretMethods calls each output method of Secret directly. fmt calls
// Format first, so a bug in String or GoString would not show in the
// fmt tests above.
func TestSecretMethods(t *testing.T) {
	t.Parallel()

	val := discover.NewSecret(discovertest.CanaryEnv)
	tests := []struct {
		name string
		call func() (string, error)
	}{
		{name: "String", call: noErr(val.String)},
		{name: "GoString", call: noErr(val.GoString)},
		{name: "LogValue", call: noErr(func() string { return val.LogValue().String() })},
		{name: "MarshalText", call: textOf(val)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.call()
			if err != nil {
				t.Fatalf("%s() error = %v", tt.name, err)
			}
			if got != discover.Mask {
				t.Errorf("%s() = %q, want %q", tt.name, got, discover.Mask)
			}
		})
	}
}

// TestSecretEncoders encodes values that hold a Secret with the standard
// library encoders. The output must not contain the canary, and keys or
// field names must still appear.
func TestSecretEncoders(t *testing.T) {
	t.Parallel()

	canary := discovertest.CanaryHeader
	val := discover.NewSecret(canary)

	tests := []struct {
		name     string
		encode   func() ([]byte, error)
		wantKeys []string
	}{
		{
			name: "json SecretMap",
			encode: func() ([]byte, error) {
				return json.Marshal(discover.SecretMap{"Authorization": val, "X_API_KEY": val})
			},
			wantKeys: []string{`"Authorization"`, `"X_API_KEY"`, discover.Mask},
		},
		{
			name:     "json exported field",
			encode:   func() ([]byte, error) { return json.Marshal(withExported{Name: "n", S: val}) },
			wantKeys: []string{`"Name"`, `"S"`, discover.Mask},
		},
		{
			name:     "json slice",
			encode:   func() ([]byte, error) { return json.Marshal([]discover.Secret{val}) },
			wantKeys: []string{discover.Mask},
		},
		{
			name:     "json indent",
			encode:   func() ([]byte, error) { return json.MarshalIndent(withExportedPtr{P: &val}, "", "  ") },
			wantKeys: []string{`"P"`, discover.Mask},
		},
		{
			name:     "xml exported field",
			encode:   func() ([]byte, error) { return xml.Marshal(withExported{Name: "n", S: val}) },
			wantKeys: []string{"<S>", discover.Mask},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.encode()
			if err != nil {
				t.Fatalf("encode error = %v", err)
			}
			discovertest.AssertNoLeak(t, tt.name, string(got), canary)
			for _, k := range tt.wantKeys {
				if !bytes.Contains(got, []byte(k)) {
					t.Errorf("output %q does not contain %q", got, k)
				}
			}
		})
	}
}

// TestSecretGob encodes a struct with an exported Secret field with
// encoding/gob. gob does not use MarshalText (only GobEncoder and
// BinaryMarshaler), and Secret has no exported fields, so today gob returns an
// error. That is safe. The test accepts an error or a masked encoding, but
// neither the bytes nor the error text may contain the canary.
func TestSecretGob(t *testing.T) {
	t.Parallel()

	canary := discovertest.CanaryEnv
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(withExported{Name: "n", S: discover.NewSecret(canary)})
	discovertest.AssertNoLeak(t, "gob output", buf.String(), canary)
	if err != nil {
		discovertest.AssertNoLeak(t, "gob error", err.Error(), canary)
		return
	}
	if !strings.Contains(buf.String(), discover.Mask) {
		t.Errorf("gob output %q does not contain %q", buf.String(), discover.Mask)
	}
}

// TestSecretSlog logs Secrets with the slog text and JSON handlers.
func TestSecretSlog(t *testing.T) {
	t.Parallel()

	canary := discovertest.CanaryEnv
	val := discover.NewSecret(canary)

	attrs := []struct {
		name     string
		attr     slog.Attr
		wantMask bool
	}{
		{name: "Secret", attr: slog.Any("value", val), wantMask: true},
		{name: "*Secret", attr: slog.Any("value", &val), wantMask: true},
		{name: "SecretMap", attr: slog.Any("env", discover.SecretMap{"API_KEY": val}), wantMask: true},
		{name: "group", attr: slog.Group("g", slog.Any("value", val)), wantMask: true},
		{name: "exported field", attr: slog.Any("server", withExported{Name: "n", S: val}), wantMask: true},
		{name: "unexported field", attr: slog.Any("server", withUnexported{s: val})},
	}
	for _, h := range slogHandlers() {
		for _, a := range attrs {
			t.Run(h.name+"/"+a.name, func(t *testing.T) {
				t.Parallel()
				var buf bytes.Buffer
				logger := slog.New(h.newHandler(&buf))
				logger.Info("msg", a.attr)
				got := buf.String()
				discovertest.AssertNoLeak(t, "slog "+h.name, got, canary)
				if a.wantMask && !strings.Contains(got, discover.Mask) {
					t.Errorf("log output %q does not contain %q", got, discover.Mask)
				}
			})
		}
	}
}

// TestSecretMapUnmarshalJSON decodes JSON strings into a SecretMap.
func TestSecretMapUnmarshalJSON(t *testing.T) {
	t.Parallel()

	input := `{"API_KEY":"` + discovertest.CanaryEnv + `","Authorization":"` + discovertest.CanaryHeader + `"}`
	var m discover.SecretMap
	if err := json.Unmarshal([]byte(input), &m); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got := m["API_KEY"].Reveal(); got != discovertest.CanaryEnv {
		t.Errorf(`m["API_KEY"].Reveal() = %q, want %q`, got, discovertest.CanaryEnv)
	}
	if got := m["Authorization"].Reveal(); got != discovertest.CanaryHeader {
		t.Errorf(`m["Authorization"].Reveal() = %q, want %q`, got, discovertest.CanaryHeader)
	}
	if got, want := m.Keys(), []string{"API_KEY", "Authorization"}; !slices.Equal(got, want) {
		t.Errorf("Keys() = %v, want %v", got, want)
	}
}

// TestSecretMapUnmarshalJSONErrors checks that a bad JSON value fails and
// that the error text does not repeat the value.
func TestSecretMapUnmarshalJSONErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		literal string
	}{
		{name: "number", input: `{"A":12345}`, literal: "12345"},
		{name: "bool", input: `{"A":true}`, literal: "true"},
		{name: "object", input: `{"A":{"x":"98765"}}`, literal: "98765"},
		{name: "array", input: `{"A":["54321"]}`, literal: "54321"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var m discover.SecretMap
			err := json.Unmarshal([]byte(tt.input), &m)
			if err == nil {
				t.Fatalf("json.Unmarshal(%s) error = nil, want error", tt.input)
			}
			if strings.Contains(err.Error(), tt.literal) {
				t.Errorf("error %q contains the value %q", err.Error(), tt.literal)
			}
		})
	}
}

// TestSecretZero checks the zero Secret and an empty Secret.
func TestSecretZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    discover.Secret
	}{
		{name: "zero value", s: discover.Secret{}},
		{name: "NewSecret empty", s: discover.NewSecret("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.s.Reveal(); got != "" {
				t.Errorf("Reveal() = %q, want empty", got)
			}
			// An empty value must also print Mask, so the output does not
			// show whether a value is set.
			if got := tt.s.String(); got != discover.Mask {
				t.Errorf("String() = %q, want %q", got, discover.Mask)
			}
			if got := fmt.Sprintf("%v", tt.s); got != discover.Mask {
				t.Errorf("Sprintf(%%v) = %q, want %q", got, discover.Mask)
			}
		})
	}
}

// TestSecretUnmarshalTextCopies checks that UnmarshalText keeps its own copy
// of the input bytes.
func TestSecretUnmarshalTextCopies(t *testing.T) {
	t.Parallel()

	buf := []byte("abc")
	var s discover.Secret
	if err := s.UnmarshalText(buf); err != nil {
		t.Fatalf("UnmarshalText() error = %v", err)
	}
	buf[0] = 'X'
	if got := s.Reveal(); got != "abc" {
		t.Errorf("Reveal() after the input changed = %q, want %q", got, "abc")
	}
}

// TestSecretMapKeys checks that Keys is sorted and never nil.
func TestSecretMapKeys(t *testing.T) {
	t.Parallel()

	val := discover.NewSecret(discovertest.CanaryEnv)
	tests := []struct {
		name string
		m    discover.SecretMap
		want []string
	}{
		{name: "nil", m: nil, want: []string{}},
		{name: "empty", m: discover.SecretMap{}, want: []string{}},
		{name: "one", m: discover.SecretMap{"A": val}, want: []string{"A"}},
		{
			name: "sorted",
			m:    discover.SecretMap{"Z": val, "a": val, "B": val, "M_1": val, "M_0": val},
			// Sorting is by byte value, so upper case comes before lower case.
			want: []string{"B", "M_0", "M_1", "Z", "a"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.m.Keys()
			if got == nil {
				t.Fatalf("Keys() = nil, want a non-nil slice")
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Keys() = %v, want %v", got, tt.want)
			}
			// The keys are not secret, but the values must not appear.
			discovertest.AssertNoLeak(t, "Keys()", strings.Join(got, ","), discovertest.CanaryEnv)
		})
	}

	// A nil map must encode as [] in JSON, not null.
	got, err := json.Marshal(discover.SecretMap(nil).Keys())
	if err != nil {
		t.Fatalf("json.Marshal(Keys()) error = %v", err)
	}
	if string(got) != "[]" {
		t.Errorf("json.Marshal(nil Keys()) = %s, want []", got)
	}
}

// TestSecretDeepEqual checks that reflect.DeepEqual compares the values,
// because == does not compile for Secret.
func TestSecretDeepEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b any
		want bool
	}{
		{name: "same value", a: discover.NewSecret("a"), b: discover.NewSecret("a"), want: true},
		{name: "different value", a: discover.NewSecret("a"), b: discover.NewSecret("b"), want: false},
		{name: "zero and zero", a: discover.Secret{}, b: discover.Secret{}, want: true},
		// The zero Secret holds a nil pointer and NewSecret("") a pointer
		// to "", so DeepEqual tells them apart. Both Reveal "" (see
		// TestSecretZero).
		{name: "zero vs empty", a: discover.Secret{}, b: discover.NewSecret(""), want: false},
		{
			name: "same SecretMap",
			a:    discover.SecretMap{"A": discover.NewSecret("1"), "B": discover.NewSecret("2")},
			b:    discover.SecretMap{"A": discover.NewSecret("1"), "B": discover.NewSecret("2")},
			want: true,
		},
		{
			name: "different SecretMap",
			a:    discover.SecretMap{"A": discover.NewSecret("1")},
			b:    discover.SecretMap{"A": discover.NewSecret("2")},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := reflect.DeepEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("reflect.DeepEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSecretMapUnmarshalJSONNull records what a JSON null value does:
// encoding/json gives no error, the key is present and the value is the zero
// Secret, so Reveal gives "".
func TestSecretMapUnmarshalJSONNull(t *testing.T) {
	t.Parallel()

	var m discover.SecretMap
	if err := json.Unmarshal([]byte(`{"K":null}`), &m); err != nil {
		t.Fatalf(`json.Unmarshal({"K":null}) error = %v, want nil`, err)
	}
	s, ok := m["K"]
	if !ok {
		t.Fatalf(`m["K"] is missing, want the key present`)
	}
	if got := s.Reveal(); got != "" {
		t.Errorf(`m["K"].Reveal() = %q, want empty`, got)
	}
	if !reflect.DeepEqual(s, discover.Secret{}) {
		t.Errorf(`m["K"] is not the zero Secret`)
	}
}

// TestMinSecretBytes pins the length threshold of secret values. The docs
// (docs/PRD.md and docs/ARCHITECTURE.md) promise 8 bytes: a shorter value is not
// removed from output or tool text, because it would also match ordinary
// words. A change of the number changes that promise, so it must be deliberate.
func TestMinSecretBytes(t *testing.T) {
	t.Parallel()
	if discover.MinSecretBytes != 8 {
		t.Errorf("MinSecretBytes = %d, want 8 (the docs promise 8 bytes)", discover.MinSecretBytes)
	}
}

// ExampleSecret shows that a Secret prints as Mask and that only Reveal gives
// the value.
func ExampleSecret() {
	s := discover.NewSecret("example-value")
	fmt.Println(s)
	fmt.Printf("%+v\n", s)
	fmt.Println(s.Reveal())
	// Output:
	// ********
	// ********
	// example-value
}
