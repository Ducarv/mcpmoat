package discover_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// argsCanary is the secret in leakyArgs. discovertest has no args canary,
// so the tests use the env canary.
const argsCanary = discovertest.CanaryEnv

// leakyArgs returns args with argsCanary after "--token". Each call returns
// a new slice, so tests can change it safely.
func leakyArgs() []string {
	return []string{"-y", "mcp-remote", "--token", argsCanary}
}

// withExportedArgs holds Args in an exported field. fmt and the encoders can
// call the field's methods, so they print the redacted args.
type withExportedArgs struct {
	A discover.Args
}

// withUnexportedArgs holds Args in an unexported field. fmt cannot call its
// methods, so it prints the raw struct contents. Args keeps its values
// behind a pointer, so fmt prints an address and not the values.
type withUnexportedArgs struct {
	a discover.Args
}

// TestArgsFormatVerbs prints many shapes of Args with many fmt verbs and
// checks that the canary after "--token" never appears in the output.
func TestArgsFormatVerbs(t *testing.T) {
	t.Parallel()

	a := discover.NewArgs(leakyArgs())
	redacted := discover.RedactArgs(leakyArgs())

	values := []struct {
		name string
		arg  any
		// direct is true when fmt can call the Args methods, so the output
		// must contain the redacted []string formatted with the same verb
		// (except for %T and %p).
		direct bool
	}{
		{name: "Args", arg: a, direct: true},
		{name: "*Args", arg: &a, direct: true},
		{name: "exported field", arg: withExportedArgs{A: a}, direct: true},
		{name: "unexported field", arg: withUnexportedArgs{a: a}},
		{name: "pointer to unexported field", arg: &withUnexportedArgs{a: a}},
	}

	for _, v := range values {
		for _, verb := range fmtVerbs() {
			t.Run(v.name+"/"+verb, func(t *testing.T) {
				t.Parallel()
				got := fmt.Sprintf(verb, v.arg)
				discovertest.AssertNoLeak(t, "fmt.Sprintf("+verb+")", got, argsCanary)

				// %T prints only the type name. %p prints an address, or for
				// a struct it is a bad verb that prints the fields by
				// reflection (only the Args pointer shows).
				if !v.direct || verb == "%T" || verb == "%p" {
					return
				}
				if want := fmt.Sprintf(verb, redacted); !strings.Contains(got, want) {
					t.Errorf("fmt.Sprintf(%q, %s) = %q, want it to contain %q", verb, v.name, got, want)
				}
			})
		}
	}
}

// TestArgsFormatFlags checks that Format prints a []string: %v gives the
// brackets, %q quotes each arg and a width pads each arg.
func TestArgsFormatFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		format string
		want   string
	}{
		{format: "%v", want: "[-y mcp-remote --token " + discover.Mask + "]"},
		{format: "%q", want: `["-y" "mcp-remote" "--token" "` + discover.Mask + `"]`},
		{format: "%#v", want: `[]string{"-y", "mcp-remote", "--token", "` + discover.Mask + `"}`},
		// fmt pads each element inside the brackets: "-y" is shorter than 3.
		{format: "%3v", want: "[ -y mcp-remote --token " + discover.Mask + "]"},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			t.Parallel()
			got := fmt.Sprintf(tt.format, discover.NewArgs(leakyArgs()))
			discovertest.AssertNoLeak(t, "fmt.Sprintf("+tt.format+")", got, argsCanary)
			if got != tt.want {
				t.Errorf("fmt.Sprintf(%q) = %q, want %q", tt.format, got, tt.want)
			}
		})
	}
}

// TestArgsMethods calls each output method of Args directly. fmt calls
// Format first, so a bug in String or GoString would not show in the fmt
// tests.
func TestArgsMethods(t *testing.T) {
	t.Parallel()

	a := discover.NewArgs(leakyArgs())
	redacted := discover.RedactArgs(leakyArgs())
	joined := strings.Join(redacted, " ")
	tests := []struct {
		name string
		call func() (string, error)
		want string
	}{
		{name: "String", call: noErr(a.String), want: joined},
		{name: "GoString", call: noErr(a.GoString), want: fmt.Sprintf("%#v", redacted)},
		{name: "MarshalText", call: func() (string, error) {
			b, err := a.MarshalText()
			return string(b), err
		}, want: joined},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.call()
			if err != nil {
				t.Fatalf("%s() error = %v", tt.name, err)
			}
			discovertest.AssertNoLeak(t, tt.name+"()", got, argsCanary)
			if got != tt.want {
				t.Errorf("%s() = %q, want %q", tt.name, got, tt.want)
			}
		})
	}

	if got := a.LogValue().Any(); !reflect.DeepEqual(got, redacted) {
		t.Errorf("LogValue().Any() = %#v, want %#v", got, redacted)
	}
	if got := a.Len(); got != len(redacted) {
		t.Errorf("Len() = %d, want %d", got, len(redacted))
	}
}

// TestArgsValues checks that Values returns the args as written and that
// both NewArgs and Values copy, so no caller can change the stored args.
func TestArgsValues(t *testing.T) {
	t.Parallel()

	in := leakyArgs()
	a := discover.NewArgs(in)
	if got := a.Values(); !slices.Equal(got, leakyArgs()) {
		t.Fatalf("Values() = %q, want %q", got, leakyArgs())
	}

	in[0] = "changed-input"
	if got := a.Values(); !slices.Equal(got, leakyArgs()) {
		t.Errorf("Values() after the NewArgs input changed = %q, want %q", got, leakyArgs())
	}

	out := a.Values()
	out[0] = "changed-output"
	if got := a.Values(); !slices.Equal(got, leakyArgs()) {
		t.Errorf("Values() after a Values result changed = %q, want %q", got, leakyArgs())
	}
}

// TestArgsZero checks the zero Args, NewArgs(nil) and an empty Args: all
// hold no args and print as empty.
func TestArgsZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		a          discover.Args
		wantValues []string
		wantJSON   string
	}{
		{name: "zero value", a: discover.Args{}, wantValues: nil, wantJSON: "null"},
		{name: "NewArgs nil", a: discover.NewArgs(nil), wantValues: nil, wantJSON: "null"},
		{name: "NewArgs empty", a: discover.NewArgs([]string{}), wantValues: []string{}, wantJSON: "[]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.a.Len(); got != 0 {
				t.Errorf("Len() = %d, want 0", got)
			}
			// reflect.DeepEqual, not slices.Equal: nil and an empty slice
			// must stay apart.
			if got := tt.a.Values(); !reflect.DeepEqual(got, tt.wantValues) {
				t.Errorf("Values() = %#v, want %#v", got, tt.wantValues)
			}
			if got := tt.a.String(); got != "" {
				t.Errorf("String() = %q, want empty", got)
			}
			if got := fmt.Sprintf("%v", tt.a); got != "[]" {
				t.Errorf("Sprintf(%%v) = %q, want %q", got, "[]")
			}
			got, err := json.Marshal(tt.a)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if string(got) != tt.wantJSON {
				t.Errorf("json.Marshal() = %s, want %s", got, tt.wantJSON)
			}
		})
	}
}

// TestArgsMarshalJSON checks that json.Marshal gives a JSON array of the
// redacted args.
func TestArgsMarshalJSON(t *testing.T) {
	t.Parallel()

	a := discover.NewArgs(leakyArgs())
	redacted := discover.RedactArgs(leakyArgs())

	tests := []struct {
		name string
		arg  any
		// array gets the JSON array out of the decoded output.
		array func(t *testing.T, out []byte) []string
	}{
		{name: "Args", arg: a, array: decodeArray},
		{name: "*Args", arg: &a, array: decodeArray},
		{name: "exported field", arg: withExportedArgs{A: a}, array: func(t *testing.T, out []byte) []string {
			t.Helper()
			var w struct{ A []string }
			if err := json.Unmarshal(out, &w); err != nil {
				t.Fatalf("json.Unmarshal(%s) error = %v", out, err)
			}
			return w.A
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tt.arg)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			discovertest.AssertNoLeak(t, "json.Marshal()", string(got), argsCanary)
			if arr := tt.array(t, got); !slices.Equal(arr, redacted) {
				t.Errorf("json.Marshal() = %s, want the array %q", got, redacted)
			}
		})
	}
}

// decodeArray decodes out as a JSON array of strings.
func decodeArray(t *testing.T, out []byte) []string {
	t.Helper()
	var arr []string
	if err := json.Unmarshal(out, &arr); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v, want a JSON array of strings", out, err)
	}
	return arr
}

// TestArgsSlog logs Args with the slog text and JSON handlers.
func TestArgsSlog(t *testing.T) {
	t.Parallel()

	a := discover.NewArgs(leakyArgs())
	attrs := []struct {
		name string
		attr slog.Attr
	}{
		{name: "Args", attr: slog.Any("args", a)},
		{name: "*Args", attr: slog.Any("args", &a)},
		{name: "exported field", attr: slog.Any("server", withExportedArgs{A: a})},
	}
	for _, h := range slogHandlers() {
		for _, at := range attrs {
			t.Run(h.name+"/"+at.name, func(t *testing.T) {
				t.Parallel()
				var buf bytes.Buffer
				slog.New(h.newHandler(&buf)).Info("msg", at.attr)
				got := buf.String()
				discovertest.AssertNoLeak(t, "slog "+h.name, got, argsCanary)
				for _, want := range []string{"mcp-remote", discover.Mask} {
					if !strings.Contains(got, want) {
						t.Errorf("log output %q does not contain %q", got, want)
					}
				}
			})
		}
	}
}

// TestArgsDeepEqual checks that reflect.DeepEqual compares the values,
// because == does not compile for Args. Each NewArgs call stores a new
// pointer, so DeepEqual must follow it.
func TestArgsDeepEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b discover.Args
		want bool
	}{
		{name: "same values", a: discover.NewArgs(leakyArgs()), b: discover.NewArgs(leakyArgs()), want: true},
		{name: "different values", a: discover.NewArgs([]string{"a"}), b: discover.NewArgs([]string{"b"}), want: false},
		{name: "zero and NewArgs nil", a: discover.Args{}, b: discover.NewArgs(nil), want: true},
		// As for a nil and an empty []string, DeepEqual tells them apart.
		{name: "zero vs empty", a: discover.Args{}, b: discover.NewArgs([]string{}), want: false},
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

// ExampleArgs shows that Args print redacted and that only Values gives the
// args as written.
func ExampleArgs() {
	a := discover.NewArgs([]string{"mcp-remote", "--token", "abc"})
	fmt.Println(a)
	fmt.Println(a.String())
	fmt.Println(a.Values())
	// Output:
	// [mcp-remote --token ********]
	// mcp-remote --token ********
	// [mcp-remote --token abc]
}
