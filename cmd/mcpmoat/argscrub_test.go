package main

import (
	"flag"
	"io"
	"strings"
	"testing"
	"time"
)

// TestHideUserinfo checks which parts of a text hideUserinfo hides: the user
// info of each URL, and nothing in a path, a query, a fragment or plain text.
func TestHideUserinfo(t *testing.T) {
	t.Parallel()

	const passCanary = "CANARYPASS7"
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "user and password", in: "https://user:" + passCanary + "@host", want: "https://(hidden)@host"},
		{name: "upper case", in: "HTTPS://U:" + passCanary + "@HOST/x", want: "HTTPS://(hidden)@HOST/x"},
		{name: "token only", in: "https://" + passCanary + "@host", want: "https://(hidden)@host"},
		{name: "at sign in the path", in: "https://host/a@b", want: "https://host/a@b"},
		{name: "at sign in the query", in: "https://host?q=a@b", want: "https://host?q=a@b"},
		{name: "at sign in the fragment", in: "https://host#a@b", want: "https://host#a@b"},
		{name: "empty user info", in: "https://@host", want: "https://@host"},
		{name: "no user info", in: "https://host", want: "https://host"},
		{name: "no URL", in: "no url a@b", want: "no url a@b"},
		{name: "scheme only", in: "x://", want: "x://"},
		{name: "empty", in: "", want: ""},
		{name: "flag error quote",
			in:   `invalid value "https://u:` + passCanary + `@h" for flag -llm: parse error`,
			want: `invalid value "https://(hidden)@h" for flag -llm: parse error`},
		{name: "escaped quote form", in: `\"https://u\\\"` + passCanary + `@h\"`, want: `\"https://(hidden)@h\"`},
		{name: "two URLs",
			in:   "a https://u:" + passCanary + "@h1/p b http://v:" + passCanary + "@h2",
			want: "a https://(hidden)@h1/p b http://(hidden)@h2"},
		{name: "last at sign of the authority", in: "https://u:p@" + passCanary + "@host/p", want: "https://(hidden)@host/p"},
		// A later '@' with no '/', '?' or '#' between hides the text up to it.
		// That fails safe.
		{name: "at sign later in the text", in: "https://h:" + passCanary + " x@y", want: "https://(hidden)@y"},
		// Known limit: a raw '/', '?' or '#' in a password ends the authority.
		// RFC 3986 says the user info must percent-encode them, so the text
		// does not change.
		{name: "raw slash in the password", in: "https://u:p/x@host", want: "https://u:p/x@host"},
		{name: "percent-encoded slash", in: "https://u:p%2F" + passCanary + "@host", want: "https://(hidden)@host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := hideUserinfo(tt.in)
			if strings.Contains(got, passCanary) {
				t.Errorf("hideUserinfo(%q) = %q, which holds the password %q", tt.in, got, passCanary)
			}
			if got != tt.want {
				t.Errorf("hideUserinfo(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestHideUserinfoLongInput checks that hideUserinfo stays linear on a long,
// hostile argument. A quadratic loop takes many seconds on 1 MB. The bound is
// wide, so that a slow machine does not fail the test.
func TestHideUserinfoLongInput(t *testing.T) {
	t.Parallel()

	const size = 1 << 20
	tests := []struct {
		name  string
		chunk string
		want  string // the output for one chunk
	}{
		{name: "no URL", chunk: ":/", want: ":/"},
		{name: "many URLs", chunk: "://a", want: "://a"},
		{name: "many user infos", chunk: "://a@", want: "://(hidden)@"},
		{name: "one long authority", chunk: "a@", want: "a@"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			n := size / len(tt.chunk)
			in := strings.Repeat(tt.chunk, n)
			start := time.Now()
			got := hideUserinfo(in)
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("hideUserinfo on %d bytes took %v, want linear time", len(in), d)
			}
			if want := strings.Repeat(tt.want, n); got != want {
				t.Errorf("hideUserinfo on %d bytes: got %d bytes, want %d", len(in), len(got), len(want))
			}
		})
	}
}

// TestHideUserinfoLongAuthority checks one URL with a long authority and many
// '@' in it: only the text before the last '@' is hidden.
func TestHideUserinfoLongAuthority(t *testing.T) {
	t.Parallel()

	in := "https://" + strings.Repeat("a@", 1<<20) + "host"
	if got, want := hideUserinfo(in), "https://(hidden)@host"; got != want {
		t.Errorf("hideUserinfo(long authority) = %.40q..., want %q", got, want)
	}
}

// flagErrorText returns the error text of the flag package for args, with
// flags like those of mcpmoat scan. It fails the test when args parse.
func flagErrorText(t *testing.T, args []string) string {
	t.Helper()
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Bool("llm", false, "")
	fs.Duration("timeout", time.Second, "")
	fs.String(flagLLMBaseURL, "", "")
	err := fs.Parse(args)
	if err == nil {
		t.Fatalf("Parse(%q) error = nil, want an error", args)
	}
	return err.Error()
}

// TestArgErrorText checks that argErrorText hides the password of a base URL
// in the error text about args, with or without a scheme, and in the shapes
// that the flag package quotes whole.
func TestArgErrorText(t *testing.T) {
	t.Parallel()

	const passCanary = "CANARYPASS7"
	const canaryURL = "https://user:" + passCanary + "@host"
	const canaryNoScheme = "user:" + passCanary + "@host"
	tests := []struct {
		name string
		args []string
		text string // "" means the flag package error for args
		want string
	}{
		{name: "inline value with a scheme", args: []string{"--llm-base-url=" + canaryURL, "extra"},
			text: "unexpected arguments [--llm-base-url=" + canaryURL + "]",
			want: "unexpected arguments [--llm-base-url=(hidden)]"},
		{name: "inline value without a scheme", args: []string{"--llm-base-url=" + canaryNoScheme, "extra"},
			text: "bad value " + canaryNoScheme,
			want: "bad value (hidden)"},
		{name: "next argument without a scheme", args: []string{"--llm-base-url", canaryNoScheme},
			text: "bad value " + canaryNoScheme,
			want: "bad value (hidden)"},
		{name: "three dashes", args: []string{"---llm-base-url=" + canaryURL},
			want: "bad flag syntax: ---llm-base-url=(hidden)"},
		{name: "three dashes without a scheme", args: []string{"---llm-base-url=" + canaryNoScheme},
			want: "bad flag syntax: ---llm-base-url=(hidden)"},
		{name: "URL as a bool value", args: []string{"--llm=" + canaryURL},
			want: `invalid boolean value "https://(hidden)@host" for -llm: parse error`},
		{name: "flag name without a dash in another value", args: []string{"--timeout=llm-base-url=" + canaryURL},
			want: `invalid value "llm-base-url=https://(hidden)@host" for flag -timeout: parse error`},
		{name: "flag in another value without a scheme", args: []string{"--timeout=--llm-base-url=" + canaryNoScheme},
			want: `invalid value "--llm-base-url=(hidden)" for flag -timeout: parse error`},
		{name: "URL as the next argument of another flag", args: []string{"--timeout", canaryURL},
			want: `invalid value "https://(hidden)@host" for flag -timeout: parse error`},
		{name: "unknown command", args: []string{canaryURL}, text: canaryURL, want: "https://(hidden)@host"},
		{name: "no secret", args: []string{"--timeout=x"},
			want: `invalid value "x" for flag -timeout: parse error`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			text := tt.text
			if text == "" {
				text = flagErrorText(t, tt.args)
			}
			got := argErrorText(tt.args, text)
			if strings.Contains(got, passCanary) {
				t.Errorf("argErrorText(%q, %q) = %q, which holds the password %q", tt.args, text, got, passCanary)
			}
			if got != tt.want {
				t.Errorf("argErrorText(%q, %q) = %q, want %q", tt.args, text, got, tt.want)
			}
		})
	}
}
