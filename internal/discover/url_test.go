package discover_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// withExportedURL holds a URL in an exported field. fmt and the encoders can
// call the field's methods, so they print the redacted URL.
type withExportedURL struct {
	U discover.URL
}

// withUnexportedURL holds a URL in an unexported field. fmt cannot call its
// methods, so it prints the raw struct contents. URL keeps its value behind a
// pointer, so fmt prints an address and not the value.
type withUnexportedURL struct {
	u discover.URL
}

// TestURLFormatVerbs prints many shapes of URL with many fmt verbs and checks
// that the URL canary never appears in the output.
func TestURLFormatVerbs(t *testing.T) {
	t.Parallel()

	u := discover.NewURL(leakyURL)
	redacted := discover.RedactURL(leakyURL)

	values := []struct {
		name string
		arg  any
		// direct is true when fmt can call the URL methods, so the output
		// must contain the redacted URL formatted with the same verb
		// (except for %T and %p).
		direct bool
	}{
		{name: "URL", arg: u, direct: true},
		{name: "*URL", arg: &u, direct: true},
		{name: "exported field", arg: withExportedURL{U: u}, direct: true},
		{name: "unexported field", arg: withUnexportedURL{u: u}},
	}

	for _, v := range values {
		for _, verb := range fmtVerbs() {
			t.Run(v.name+"/"+verb, func(t *testing.T) {
				t.Parallel()
				got := fmt.Sprintf(verb, v.arg)
				discovertest.AssertNoLeak(t, "fmt.Sprintf("+verb+")", got, discovertest.CanaryURL)

				// %T prints only the type name. %p prints an address, or for
				// a struct it is a bad verb that prints the fields by
				// reflection (only the URL pointer shows).
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

// TestURLMethods calls each output method of URL directly. fmt calls Format
// first, so a bug in String or GoString would not show in the fmt tests.
func TestURLMethods(t *testing.T) {
	t.Parallel()

	u := discover.NewURL(leakyURL)
	want := discover.RedactURL(leakyURL)
	tests := []struct {
		name string
		call func() (string, error)
	}{
		{name: "String", call: noErr(u.String)},
		{name: "GoString", call: noErr(u.GoString)},
		{name: "LogValue", call: noErr(func() string { return u.LogValue().String() })},
		{name: "MarshalText", call: textOf(u)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.call()
			if err != nil {
				t.Fatalf("%s() error = %v", tt.name, err)
			}
			discovertest.AssertNoLeak(t, tt.name+"()", got, discovertest.CanaryURL)
			if got != want {
				t.Errorf("%s() = %q, want %q", tt.name, got, want)
			}
		})
	}

	if got := u.Reveal(); got != leakyURL {
		t.Errorf("Reveal() = %q, want %q", got, leakyURL)
	}
}

// TestURLFormatFlags checks that Format passes the verb and flags on to the
// redacted URL: %q quotes and escapes it, and a width pads it.
func TestURLFormatFlags(t *testing.T) {
	t.Parallel()

	// shortURL is shorter than the widths below, so the padding shows.
	const shortURL = "https://a.example"
	tests := []struct {
		name   string
		format string
		raw    string
		want   string
	}{
		{name: "q", format: "%q", raw: leakyURL, want: strconv.Quote(discover.RedactURL(leakyURL))},
		{
			// RedactURL keeps a printable query key as written, so %q must
			// escape the quote and the backslash in it.
			name:   "q escapes",
			format: "%q",
			raw:    `https://example.com/mcp?a"b\c=` + discovertest.CanaryURL,
			want:   `"https://example.com/mcp?a\"b\\c=` + discover.Mask + `"`,
		},
		{name: "left pad", format: "%-20v", raw: shortURL, want: shortURL + "   "},
		{name: "right pad", format: "%20s", raw: shortURL, want: "   " + shortURL},
		{name: "wide redacted", format: "%-70v", raw: leakyURL, want: fmt.Sprintf("%-70s", discover.RedactURL(leakyURL))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := fmt.Sprintf(tt.format, discover.NewURL(tt.raw))
			discovertest.AssertNoLeak(t, "fmt.Sprintf("+tt.format+")", got, discovertest.CanaryURL)
			if got != tt.want {
				t.Errorf("fmt.Sprintf(%q) = %q, want %q", tt.format, got, tt.want)
			}
		})
	}
}

// TestURLMarshalJSON checks that json.Marshal gives a valid JSON string equal
// to the JSON encoding of the redacted URL.
func TestURLMarshalJSON(t *testing.T) {
	t.Parallel()

	u := discover.NewURL(leakyURL)
	want, err := json.Marshal(discover.RedactURL(leakyURL))
	if err != nil {
		t.Fatalf("json.Marshal(RedactURL) error = %v", err)
	}

	tests := []struct {
		name string
		arg  any
		want string
	}{
		{name: "URL", arg: u, want: string(want)},
		{name: "*URL", arg: &u, want: string(want)},
		{name: "exported field", arg: withExportedURL{U: u}, want: `{"U":` + string(want) + `}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tt.arg)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if !json.Valid(got) {
				t.Errorf("json.Marshal() = %s, not valid JSON", got)
			}
			discovertest.AssertNoLeak(t, "json.Marshal()", string(got), discovertest.CanaryURL)
			if string(got) != tt.want {
				t.Errorf("json.Marshal() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestURLSlog logs URLs with the slog text and JSON handlers.
func TestURLSlog(t *testing.T) {
	t.Parallel()

	u := discover.NewURL(leakyURL)
	attrs := []struct {
		name string
		attr slog.Attr
	}{
		{name: "URL", attr: slog.Any("url", u)},
		{name: "*URL", attr: slog.Any("url", &u)},
		{name: "exported field", attr: slog.Any("server", withExportedURL{U: u})},
	}
	for _, h := range slogHandlers() {
		for _, a := range attrs {
			t.Run(h.name+"/"+a.name, func(t *testing.T) {
				t.Parallel()
				var buf bytes.Buffer
				slog.New(h.newHandler(&buf)).Info("msg", a.attr)
				got := buf.String()
				discovertest.AssertNoLeak(t, "slog "+h.name, got, discovertest.CanaryURL)
				for _, want := range []string{"example.com", discover.Mask} {
					if !strings.Contains(got, want) {
						t.Errorf("log output %q does not contain %q", got, want)
					}
				}
			})
		}
	}
}

// TestURLUnmarshalJSON decodes a JSON string into a URL field. UnmarshalText
// keeps the value as written, so Reveal gives the raw URL.
func TestURLUnmarshalJSON(t *testing.T) {
	t.Parallel()

	input, err := json.Marshal(map[string]string{"u": leakyURL})
	if err != nil {
		t.Fatalf("json.Marshal(input) error = %v", err)
	}
	var got struct{ U discover.URL }
	if err := json.Unmarshal(input, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got.U.Reveal() != leakyURL {
		t.Errorf("U.Reveal() = %q, want %q", got.U.Reveal(), leakyURL)
	}
}

// TestURLUnmarshalJSONErrors checks that a JSON value that is not a string
// fails and that the error text does not repeat the value.
func TestURLUnmarshalJSONErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		literal string
	}{
		{name: "number", input: `{"U":12345}`, literal: "12345"},
		{name: "object", input: `{"U":{"x":"98765"}}`, literal: "98765"},
		{name: "array", input: `{"U":["54321"]}`, literal: "54321"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got struct{ U discover.URL }
			err := json.Unmarshal([]byte(tt.input), &got)
			if err == nil {
				t.Fatalf("json.Unmarshal(%s) error = nil, want error", tt.input)
			}
			if strings.Contains(err.Error(), tt.literal) {
				t.Errorf("error %q contains the value %q", err.Error(), tt.literal)
			}
		})
	}
}

// TestURLZero checks the zero URL and an empty URL: both are empty in every
// form.
func TestURLZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		u    discover.URL
	}{
		{name: "zero value", u: discover.URL{}},
		{name: "NewURL empty", u: discover.NewURL("")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.u.Reveal(); got != "" {
				t.Errorf("Reveal() = %q, want empty", got)
			}
			if got := tt.u.String(); got != "" {
				t.Errorf("String() = %q, want empty", got)
			}
			if got := fmt.Sprintf("%v", tt.u); got != "" {
				t.Errorf("Sprintf(%%v) = %q, want empty", got)
			}
			got, err := json.Marshal(tt.u)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if string(got) != `""` {
				t.Errorf(`json.Marshal() = %s, want ""`, got)
			}
		})
	}
}

// TestURLDeepEqual checks that reflect.DeepEqual compares the values, because
// == does not compile for URL.
func TestURLDeepEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b discover.URL
		want bool
	}{
		{name: "same value", a: discover.NewURL("https://a.example"), b: discover.NewURL("https://a.example"), want: true},
		{name: "different value", a: discover.NewURL("https://a.example"), b: discover.NewURL("https://b.example"), want: false},
		{name: "zero and zero", a: discover.URL{}, b: discover.URL{}, want: true},
		// As for Secret: the zero URL holds a nil pointer and NewURL("") a
		// pointer to "", so DeepEqual tells them apart. Both Reveal "".
		{name: "zero vs empty", a: discover.URL{}, b: discover.NewURL(""), want: false},
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

// TestURLUnmarshalTextCopies checks that UnmarshalText keeps its own copy of
// the input bytes.
func TestURLUnmarshalTextCopies(t *testing.T) {
	t.Parallel()

	buf := []byte("https://example.com/a")
	var u discover.URL
	if err := u.UnmarshalText(buf); err != nil {
		t.Fatalf("UnmarshalText() error = %v", err)
	}
	buf[len(buf)-1] = 'X'
	if got, want := u.Reveal(), "https://example.com/a"; got != want {
		t.Errorf("Reveal() after the input changed = %q, want %q", got, want)
	}
}

// ExampleURL shows that a URL prints redacted and that only Reveal gives the
// raw URL.
func ExampleURL() {
	u := discover.NewURL("https://user:pw@example.com/mcp?key=abc")
	fmt.Println(u)
	fmt.Printf("%+v\n", u)
	fmt.Println(u.Reveal())
	// Output:
	// https://********@example.com/mcp?key=********
	// https://********@example.com/mcp?key=********
	// https://user:pw@example.com/mcp?key=abc
}
