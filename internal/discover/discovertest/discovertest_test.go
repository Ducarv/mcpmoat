package discovertest_test

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// Test values for the encoding cases. The expected encodings are written out
// by hand, so a bug in the encoding code cannot hide in the test.
//
// Leaks searches for hex and base64 only for values of at least 8 bytes (the
// unexported minEncodedLen). So every value used in a hex or base64 case has
// at least 8 bytes, and the boundary values below pin the limit.
const (
	// quoteValue needs escaping: strconv.Quote gives `a\"b\n` inside the quotes.
	quoteValue = "a\"b\n"
	// hexValue has letters in its hex form, so lower and upper case differ.
	// Hex lower: 76616c75652d7a7a. Hex upper: 76616C75652D7A7A.
	hexValue = "value-zz"
	// b64Value encodes with "+/" (standard) or "-_" (URL-safe) and has padding.
	//   StdEncoding:    Pz8+Pz8/Pj8=
	//   RawStdEncoding: Pz8+Pz8/Pj8
	//   URLEncoding:    Pz8-Pz8_Pj8=
	//   RawURLEncoding: Pz8-Pz8_Pj8
	b64Value = "??>???>?"
	// b64LongValue gives '+' (standard) or '-' (URL-safe) in every group.
	// In "x" + b64LongValue + "yz", the value starts at byte 1 of a group:
	//   StdEncoding: eD8/Pj8/Pj8/Pj95eg==
	//   URLEncoding: eD8_Pj8_Pj8_Pj95eg==
	b64LongValue = "??>??>??>?"
	// shortValue is too short for any hex or base64 search.
	// Hex: 6162. RawStdEncoding: YWI.
	shortValue = "ab"
	// belowMinValue has 7 bytes, one less than minEncodedLen.
	// Hex: 61626364656667. RawStdEncoding: YWJjZGVmZw.
	belowMinValue = "abcdefg"
	// atMinValue has exactly 8 bytes, the same as minEncodedLen.
	// Hex: 6162636465666768. RawStdEncoding: YWJjZGVmZ2g.
	// In "user:" + atMinValue: StdEncoding dXNlcjphYmNkZWZnaA==.
	atMinValue = "abcdefgh"
)

// stdB64 returns s in the standard base64 alphabet, with padding. It encodes
// the whole string at once, as a real program would, so it does not share
// code with the search in Leaks.
func stdB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// urlB64 returns s in the URL-safe base64 alphabet, with padding.
func urlB64(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) }

// TestLeaks checks which secrets Leaks finds, in plain and encoded forms.
func TestLeaks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		output string
		values []string
		want   []string
	}{
		{
			name:   "raw value",
			output: "env FOO=" + discovertest.CanaryEnv + "\n",
			values: []string{discovertest.CanaryEnv},
			want:   []string{discovertest.CanaryEnv},
		},
		{
			// For values that need no escaping, the quoted form is the same
			// as the raw form. This case checks the raw form on its own.
			name:   "raw value that needs escaping",
			output: "value: " + quoteValue,
			values: []string{quoteValue},
			want:   []string{quoteValue},
		},
		{
			name: "go-quoted value",
			// The output holds the escaped form only, not the raw quote and
			// newline. The value sits inside a longer string, so there is no
			// '"' just before or after it.
			output: `{"msg":"bad value a\"b\n here"}`,
			values: []string{quoteValue},
			want:   []string{quoteValue},
		},
		{
			name:   "hex lower case",
			output: "dump: 76616c75652d7a7a",
			values: []string{hexValue},
			want:   []string{hexValue},
		},
		{
			name:   "hex upper case",
			output: "dump: 76616C75652D7A7A",
			values: []string{hexValue},
			want:   []string{hexValue},
		},
		{
			name:   "base64 standard with padding",
			output: "auth=Pz8+Pz8/Pj8=;",
			values: []string{b64Value},
			want:   []string{b64Value},
		},
		{
			name:   "base64 standard without padding",
			output: "auth=Pz8+Pz8/Pj8;",
			values: []string{b64Value},
			want:   []string{b64Value},
		},
		{
			name:   "base64 URL-safe with padding",
			output: "auth=Pz8-Pz8_Pj8=;",
			values: []string{b64Value},
			want:   []string{b64Value},
		},
		{
			name:   "base64 URL-safe without padding",
			output: "auth=Pz8-Pz8_Pj8;",
			values: []string{b64Value},
			want:   []string{b64Value},
		},
		{
			name:   "base64 standard of Basic auth user:value",
			output: "Authorization: Basic " + stdB64("user:"+discovertest.CanaryEnv),
			values: []string{discovertest.CanaryEnv},
			want:   []string{discovertest.CanaryEnv},
		},
		{
			name:   "base64 URL-safe of Basic auth user:value",
			output: "auth=" + urlB64("user:"+discovertest.CanaryEnv),
			values: []string{discovertest.CanaryEnv},
			want:   []string{discovertest.CanaryEnv},
		},
		{
			name:   "base64 standard of value:p",
			output: "Basic " + stdB64(discovertest.CanaryEnv+":p"),
			values: []string{discovertest.CanaryEnv},
			want:   []string{discovertest.CanaryEnv},
		},
		{
			name:   "base64 URL-safe of value:p",
			output: "Basic " + urlB64(discovertest.CanaryEnv+":p"),
			values: []string{discovertest.CanaryEnv},
			want:   []string{discovertest.CanaryEnv},
		},
		{
			name:   "base64 standard of value after two bytes",
			output: "x=" + stdB64("ab"+discovertest.CanaryHeader),
			values: []string{discovertest.CanaryHeader},
			want:   []string{discovertest.CanaryHeader},
		},
		{
			name:   "base64 URL-safe of value after two bytes",
			output: "x=" + urlB64("ab"+discovertest.CanaryHeader),
			values: []string{discovertest.CanaryHeader},
			want:   []string{discovertest.CanaryHeader},
		},
		{
			name:   "base64 standard of value after one byte with a suffix",
			output: "x=" + stdB64("x"+discovertest.CanaryURL+"yz"),
			values: []string{discovertest.CanaryURL},
			want:   []string{discovertest.CanaryURL},
		},
		{
			name:   "base64 URL-safe of value after one byte with a suffix",
			output: "x=" + urlB64("x"+discovertest.CanaryURL+"yz"),
			values: []string{discovertest.CanaryURL},
			want:   []string{discovertest.CanaryURL},
		},
		{
			// The canaries encode without '+' or '/', so their two alphabets
			// give the same output. This value checks the alphabets apart.
			name:   "embedded base64 standard alphabet",
			output: "auth=eD8/Pj8/Pj8/Pj95eg==",
			values: []string{b64LongValue},
			want:   []string{b64LongValue},
		},
		{
			name:   "embedded base64 URL-safe alphabet",
			output: "auth=eD8_Pj8_Pj8_Pj95eg==",
			values: []string{b64LongValue},
			want:   []string{b64LongValue},
		},
		{
			name:   "short value as written",
			output: "x=" + shortValue,
			values: []string{shortValue},
			want:   []string{shortValue},
		},
		{
			// "eGFieQ==" is base64 of "xaby". The value starts at byte 1 of
			// a group, so it has no full group and its core is empty. An
			// empty core would match every output.
			name:   "short value has no base64 false positive",
			output: "auth=eGFieQ==",
			values: []string{shortValue},
			want:   nil,
		},
		{
			name:   "short value in hex is not reported",
			output: "dump: 6162",
			values: []string{shortValue},
			want:   nil,
		},
		{
			name:   "short value in base64 is not reported",
			output: "auth=YWI=",
			values: []string{shortValue},
			want:   nil,
		},
		{
			name:   "value one byte below the limit in hex is not reported",
			output: "dump: 61626364656667",
			values: []string{belowMinValue},
			want:   nil,
		},
		{
			name:   "value one byte below the limit in base64 is not reported",
			output: "auth=YWJjZGVmZw==",
			values: []string{belowMinValue},
			want:   nil,
		},
		{
			name:   "value one byte below the limit as written",
			output: "x=" + belowMinValue,
			values: []string{belowMinValue},
			want:   []string{belowMinValue},
		},
		{
			name:   "value at the limit in hex",
			output: "dump: 6162636465666768",
			values: []string{atMinValue},
			want:   []string{atMinValue},
		},
		{
			name:   "value at the limit in base64 alone",
			output: "auth=YWJjZGVmZ2g=",
			values: []string{atMinValue},
			want:   []string{atMinValue},
		},
		{
			name:   "value at the limit in embedded base64",
			output: "Authorization: Basic dXNlcjphYmNkZWZnaA==",
			values: []string{atMinValue},
			want:   []string{atMinValue},
		},
		{
			name:   "empty value is ignored",
			output: "any output at all",
			values: []string{""},
			want:   nil,
		},
		{
			name:   "empty value is ignored next to a real leak",
			output: "x=" + discovertest.CanaryEnv,
			values: []string{"", discovertest.CanaryEnv, ""},
			want:   []string{discovertest.CanaryEnv},
		},
		{
			name:   "clean output",
			output: "server github: env keys [GITHUB_TOKEN], headers [Authorization]",
			values: discovertest.Canaries(),
			want:   nil,
		},
		{
			name: "part of a value is not a leak",
			// Only the canary prefix is in the output, not the full value.
			output: "mcpmoat-canary-env-",
			values: []string{discovertest.CanaryEnv},
			want:   nil,
		},
		{
			name:   "empty output",
			output: "",
			values: discovertest.Canaries(),
			want:   nil,
		},
		{
			name:   "no values",
			output: discovertest.CanaryEnv,
			values: nil,
			want:   nil,
		},
		{
			name: "order follows values, not output",
			// CanaryURL comes first in the output, but CanaryEnv comes first
			// in the values argument.
			output: discovertest.CanaryURL + " " + discovertest.CanaryEnv,
			values: []string{discovertest.CanaryEnv, discovertest.CanaryURL},
			want:   []string{discovertest.CanaryEnv, discovertest.CanaryURL},
		},
		{
			name:   "reversed values give reversed result",
			output: discovertest.CanaryURL + " " + discovertest.CanaryEnv,
			values: []string{discovertest.CanaryURL, discovertest.CanaryEnv},
			want:   []string{discovertest.CanaryURL, discovertest.CanaryEnv},
		},
		{
			name:   "duplicate value is reported once",
			output: discovertest.CanaryHeader + " and " + discovertest.CanaryHeader,
			values: []string{discovertest.CanaryHeader, discovertest.CanaryHeader},
			want:   []string{discovertest.CanaryHeader},
		},
		{
			name: "multiple leaks in different forms",
			// CanaryEnv as written, CanaryHeader as hex, b64Value as base64.
			// CanaryURL is not in the output.
			output: "env=" + discovertest.CanaryEnv +
				" hdr=6d63706d6f61742d63616e6172792d6865616465722d345662385274" +
				" auth=Pz8+Pz8/Pj8=",
			values: []string{
				discovertest.CanaryEnv,
				discovertest.CanaryHeader,
				discovertest.CanaryURL,
				b64Value,
			},
			want: []string{discovertest.CanaryEnv, discovertest.CanaryHeader, b64Value},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := discovertest.Leaks(tt.output, tt.values...)
			// slices.Equal treats a nil slice and an empty slice as equal.
			if !slices.Equal(got, tt.want) {
				t.Errorf("Leaks(%q, %q) = %q, want %q", tt.output, tt.values, got, tt.want)
			}
		})
	}
}

// TestCanaries checks that Canaries returns every canary value.
func TestCanaries(t *testing.T) {
	t.Parallel()

	want := []string{
		discovertest.CanaryEnv,
		discovertest.CanaryHeader,
		discovertest.CanaryURL,
		discovertest.CanaryArgs,
	}

	t.Run("returns the four constants", func(t *testing.T) {
		t.Parallel()
		got := discovertest.Canaries()
		if !slices.Equal(got, want) {
			t.Errorf("Canaries() = %q, want %q", got, want)
		}
	})

	t.Run("values are non-empty and distinct", func(t *testing.T) {
		t.Parallel()
		seen := make(map[string]bool)
		for _, canary := range discovertest.Canaries() {
			if canary == "" {
				t.Error("Canaries() has an empty value")
			}
			if seen[canary] {
				t.Errorf("Canaries() has %q more than once", canary)
			}
			seen[canary] = true
		}
	})

	t.Run("no value is a substring of another", func(t *testing.T) {
		t.Parallel()
		canaries := discovertest.Canaries()
		for i, a := range canaries {
			for j, b := range canaries {
				if i != j && strings.Contains(b, a) {
					t.Errorf("canary %q is a substring of canary %q", a, b)
				}
			}
		}
	})

	t.Run("values need no escaping", func(t *testing.T) {
		t.Parallel()
		for _, canary := range discovertest.Canaries() {
			if got, want := strconv.Quote(canary), `"`+canary+`"`; got != want {
				t.Errorf("strconv.Quote(%q) = %s, want %s", canary, got, want)
			}
		}
	})

	t.Run("returns a new slice on each call", func(t *testing.T) {
		t.Parallel()
		first := discovertest.Canaries()
		for i := range first {
			first[i] = "changed"
		}
		if got := discovertest.Canaries(); !slices.Equal(got, want) {
			t.Errorf("Canaries() after change to an earlier result = %q, want %q", got, want)
		}
	})
}

// fakeTB records the calls that AssertNoLeak makes.
//
// testing.TB has an unexported method, so other packages cannot implement it
// from scratch. Embedding the interface gives fakeTB all the methods; we then
// override Helper and Errorf. The embedded value is nil, so a call to any other
// method panics. That proves AssertNoLeak calls only Helper and Errorf.
type fakeTB struct {
	testing.TB
	helperCalls int
	messages    []string
}

func (f *fakeTB) Helper() { f.helperCalls++ }

func (f *fakeTB) Errorf(format string, args ...any) {
	f.messages = append(f.messages, fmt.Sprintf(format, args...))
}

// TestAssertNoLeak checks the messages that AssertNoLeak reports with Errorf.
func TestAssertNoLeak(t *testing.T) {
	t.Parallel()

	// nothingChecked is part of the message for a call with only empty values.
	const nothingChecked = "nothing was checked"

	tests := []struct {
		name   string
		what   string
		output string
		values []string
		// wantNamed lists the values that the leak messages name, in order.
		wantNamed []string
		// wantNothingChecked is true if the only message reports that every
		// value was empty.
		wantNothingChecked bool
	}{
		{
			name:      "clean output",
			what:      "stdout",
			output:    "server github: env keys [GITHUB_TOKEN]",
			values:    discovertest.Canaries(),
			wantNamed: nil,
		},
		{
			name:      "one leak",
			what:      "stderr",
			output:    "error: bad value " + discovertest.CanaryHeader,
			values:    discovertest.Canaries(),
			wantNamed: []string{discovertest.CanaryHeader},
		},
		{
			name:   "every canary leaks",
			what:   "json report",
			output: strings.Join(discovertest.Canaries(), ","),
			values: discovertest.Canaries(),
			wantNamed: []string{
				discovertest.CanaryEnv,
				discovertest.CanaryHeader,
				discovertest.CanaryURL,
				discovertest.CanaryArgs,
			},
		},
		{
			name:      "duplicate value gives one call",
			what:      "error",
			output:    discovertest.CanaryEnv,
			values:    []string{discovertest.CanaryEnv, discovertest.CanaryEnv},
			wantNamed: []string{discovertest.CanaryEnv},
		},
		{
			name:      "no values checks the canaries",
			what:      "stdout",
			output:    "env FOO=" + discovertest.CanaryEnv,
			values:    nil,
			wantNamed: []string{discovertest.CanaryEnv},
		},
		{
			name:      "no values and clean output",
			what:      "stdout",
			output:    "server github: env keys [GITHUB_TOKEN]",
			values:    nil,
			wantNamed: nil,
		},
		{
			// The output holds a canary, but the caller passed no real
			// value, so the call must fail instead of passing silently.
			name:               "only empty values reports that nothing was checked",
			what:               "stdout",
			output:             "env FOO=" + discovertest.CanaryEnv,
			values:             []string{"", ""},
			wantNothingChecked: true,
		},
		{
			name:               "one empty value reports that nothing was checked",
			what:               "error",
			output:             "server github: env keys [GITHUB_TOKEN]",
			values:             []string{""},
			wantNothingChecked: true,
		},
		{
			name:      "empty and real values with clean output",
			what:      "stdout",
			output:    "server github: env keys [GITHUB_TOKEN]",
			values:    []string{"", discovertest.CanaryEnv, ""},
			wantNamed: nil,
		},
		{
			name:      "empty and real values with a leak",
			what:      "stderr",
			output:    "error: bad value " + discovertest.CanaryEnv,
			values:    []string{"", discovertest.CanaryEnv, ""},
			wantNamed: []string{discovertest.CanaryEnv},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeTB{}
			discovertest.AssertNoLeak(fake, tt.what, tt.output, tt.values...)

			if fake.helperCalls == 0 {
				t.Error("AssertNoLeak did not call t.Helper")
			}
			wantCalls := len(tt.wantNamed)
			if tt.wantNothingChecked {
				wantCalls = 1
			}
			if len(fake.messages) != wantCalls {
				t.Fatalf("AssertNoLeak made %d Errorf calls, want %d: %q",
					len(fake.messages), wantCalls, fake.messages)
			}
			for i, msg := range fake.messages {
				if !strings.Contains(msg, tt.what) {
					t.Errorf("message %d = %q, want it to contain %q", i, msg, tt.what)
				}
				if tt.wantNothingChecked {
					if !strings.Contains(msg, nothingChecked) {
						t.Errorf("message %d = %q, want it to contain %q", i, msg, nothingChecked)
					}
					continue
				}
				// Each message names the value that leaked, in values order.
				if !strings.Contains(msg, strconv.Quote(tt.wantNamed[i])) {
					t.Errorf("message %d = %q, want it to name %q", i, msg, tt.wantNamed[i])
				}
			}
		})
	}
}
