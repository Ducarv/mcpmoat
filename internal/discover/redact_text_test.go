package discover

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// secretCanary is a FAKE secret value that the tests put in the text.
const secretCanary = "sk-CANARY-1234567890"

// ffd is U+FFFD, the rune that a JSON decoder writes for each byte that is not
// valid UTF-8.
const ffd = string(utf8.RuneError)

// newSecrets returns one Secret for each value.
func newSecrets(values ...string) []Secret {
	secrets := make([]Secret, len(values))
	for i, v := range values {
		secrets[i] = NewSecret(v)
	}
	return secrets
}

// cutUTF8 is a copy of the rune-boundary cut of internal/llm (which this
// package cannot import): s cut to at most limit bytes at the start of a rune,
// and whether it cut. A negative limit counts as 0. The redactTextPrefix
// contract promises the same cut for its result and for redactText.
func cutUTF8(s string, limit int) (string, bool) {
	limit = max(limit, 0)
	if len(s) <= limit {
		return s, false
	}
	for i := limit; i >= 0 && i > limit-utf8.UTFMax; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i], true
		}
	}
	return s[:limit], true
}

// redactText replaces each occurrence of each value in values with Mask in
// all of s, and reports whether it wrote a Mask. The values normally come
// from secretTextValues. See redactWindow for how the occurrences are found
// and replaced.
//
// redactText reads all of s. The values must not be empty (secretTextValues
// gives only values of at least MinSecretBytes bytes). An empty value is
// skipped.
//
// Only the tests use it, as the reference for redactTextPrefix and
// TextRedactor. It builds the search tables of the values on each call. Code
// outside the tests uses a TextRedactor, which builds the tables once.
func redactText(s string, values []string) (string, bool) {
	if len(values) == 0 || s == "" {
		return s, false
	}
	return redactWindow(s, values, nil, len(s), -1)
}

// redactOracle is a slow, plain form of redactText for the tests. It tries
// each value at each start position, marks the bytes of each occurrence, and
// writes one Mask for each run of marked bytes.
func redactOracle(s string, values []string) (string, bool) {
	out, starts := redactOracleStarts(s, values)
	return out, len(starts) > 0
}

// redactOracleStarts is redactOracle that also returns the byte offset in the
// result of each Mask that it wrote. A Mask in the text or a value with "*"
// makes a search for Mask in the result give other offsets, so the tests use
// these.
func redactOracleStarts(s string, values []string) (string, []int) {
	marked := make([]bool, len(s))
	for i := range len(s) {
		for _, v := range values {
			if v != "" && strings.HasPrefix(s[i:], v) {
				for j := i; j < i+len(v); j++ {
					marked[j] = true
				}
			}
		}
	}
	var b strings.Builder
	var starts []int
	for i := range len(s) {
		switch {
		case !marked[i]:
			b.WriteByte(s[i])
		case i == 0 || !marked[i-1]:
			starts = append(starts, b.Len())
			b.WriteString(Mask)
		}
	}
	return b.String(), starts
}

// wantRedactedFlag is the redacted rule of redactTextPrefix: true when a Mask
// of the whole result starts in its first limit+1 bytes.
func wantRedactedFlag(starts []int, limit int) bool {
	return slices.ContainsFunc(starts, func(at int) bool { return at <= limit })
}

// FuzzRedactText compares redactText with redactOracle. The result also
// never holds a value with no "*" byte: such a value cannot cross a Mask, and
// every unmarked run is free of occurrences.
func FuzzRedactText(f *testing.F) {
	f.Add("abcdefghXXXXXXXXX", "abcdefgh", "hXXXXXXXXX")
	f.Add("a xxCANARY12yy b CANARY12", "CANARY12", "xxCANARY12yy")
	f.Add("ababababab", "abababab", "")
	f.Add("\xff"+secretCanary+"\xc3", secretCanary, "1234567")
	f.Add("x abcdefg y", "abcdefg", "abcdefg")
	f.Add("x abc��defgh y", "abc\xff\xfedefgh", "")
	f.Add("���", "\xff\xfe\xfd", "")
	f.Fuzz(func(t *testing.T, s, v1, v2 string) {
		// Small inputs only: redactOracle is quadratic on purpose (the simple
		// reference), and the fuzzer's minimizer tries O(n^2) cuts of each new
		// input, so long inputs stall the run. TestRedactLongPeriodicSecret
		// covers long input.
		if len(s) > 512 || len(v1) > 64 || len(v2) > 64 {
			t.Skip("input too long for the quadratic oracle")
		}
		// The contract: values of 8 bytes or more and, for such a value that
		// is not valid UTF-8, its form after a JSON decode (one U+FFFD for
		// each invalid byte). The minimum applies to the raw value only, so a
		// value of 7 bytes or less gives no decoded form either.
		var values []string
		for _, v := range []string{v1, v2} {
			if len(v) < 8 {
				continue
			}
			values = append(values, v)
			if utf8.ValidString(v) {
				continue
			}
			var b strings.Builder
			for i := 0; i < len(v); {
				r, size := utf8.DecodeRuneInString(v[i:])
				b.WriteRune(r) // RuneError, size 1, for each invalid byte
				i += size
			}
			values = append(values, b.String())
		}
		got, ok := redactText(s, secretTextValues(newSecrets(v1, v2)))
		want, wantOK := redactOracle(s, values)
		if got != want || ok != wantOK {
			t.Fatalf("redactText(%q, %q, %q) = (%q, %v), want (%q, %v)", s, v1, v2, got, ok, want, wantOK)
		}
		for _, v := range values {
			if !strings.Contains(v, "*") && strings.Contains(got, v) {
				t.Errorf("redactText(%q) = %q holds %q", s, got, v)
			}
		}
	})
}

// TestDecodedPerByte checks that decodedPerByte gives one U+FFFD for each
// invalid byte, and the same text as encoding/json gives when it decodes the
// bytes in a JSON string.
func TestDecodedPerByte(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "abc", want: "abc"},
		{in: "é€😀", want: "é€😀"},
		{in: ffd, want: ffd},
		{in: "\xff", want: ffd},
		{in: "a\xff\xfeb", want: "a" + ffd + ffd + "b"},
		{in: "\xff\xfe\xfd", want: ffd + ffd + ffd},
		{in: "\xe2\x82", want: ffd + ffd},           // a 3-byte rune without its last byte
		{in: "\xed\xa0\x80", want: ffd + ffd + ffd}, // a UTF-16 surrogate
	}
	for _, tt := range tests {
		got := decodedPerByte(tt.in)
		if got != tt.want {
			t.Errorf("decodedPerByte(%q) = %q, want %q", tt.in, got, tt.want)
		}
		var decoded string
		if err := json.Unmarshal([]byte(`"`+tt.in+`"`), &decoded); err != nil || decoded != got {
			t.Errorf("json.Unmarshal(%q) = %q, %v; want decodedPerByte() = %q", tt.in, decoded, err, got)
		}
	}
}

// TestPerByteForm checks that PerByteForm gives the decoded form only for a
// value that is not valid UTF-8.
func TestPerByteForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{in: "", want: "", wantOK: false},
		{in: "abc", want: "", wantOK: false},
		{in: "é€😀", want: "", wantOK: false},
		{in: ffd, want: "", wantOK: false},
		{in: "\xff", want: ffd, wantOK: true},
		{in: "a\xff\xfeb", want: "a" + ffd + ffd + "b", wantOK: true},
		{in: "\xe2\x82", want: ffd + ffd, wantOK: true},
	}
	for _, tt := range tests {
		got, ok := PerByteForm(tt.in)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("PerByteForm(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}

// TestSecretTextValues pins which values secretTextValues gives: each value of
// at least MinSecretBytes bytes and, for a value that is not valid UTF-8, its
// decoded form. MinSecretBytes applies to the raw value only, so a short value
// gives no decoded form, even when that form has 8 bytes or more.
func TestSecretTextValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		secrets []string
		want    []string
	}{
		{name: "no secrets", secrets: nil, want: nil},
		{name: "short value", secrets: []string{"abcdefg"}, want: nil},
		{name: "valid UTF-8 has no decoded form", secrets: []string{"abcdéfgh"}, want: []string{"abcdéfgh"}},
		{name: "same value twice", secrets: []string{"abcdefgh", "abcdefgh"}, want: []string{"abcdefgh"}},
		{name: "one invalid byte", secrets: []string{"abcd\xffefgh"}, want: []string{"abcd\xffefgh", "abcd" + ffd + "efgh"}},
		{name: "run of three invalid bytes", secrets: []string{"ab\xff\xfe\xfdcdefgh"}, want: []string{"ab\xff\xfe\xfdcdefgh", "ab" + ffd + ffd + ffd + "cdefgh"}},
		// 7 raw bytes are too short, so the decoded form of 9 is not added.
		{name: "7 bytes with a decoded form of 9", secrets: []string{"abcdef\xff"}, want: nil},
		// 3 raw bytes are too short. The decoded form (three U+FFFD, 9 bytes)
		// would hide any run of three U+FFFD in the tool text.
		{name: "3 invalid bytes", secrets: []string{"\xff\xfe\xfd"}, want: nil},
		{name: "8 bytes with an invalid byte", secrets: []string{"abcdefg\xff"}, want: []string{"abcdefg\xff", "abcdefg" + ffd}},
		{name: "7 bytes with two invalid bytes", secrets: []string{"abcde\xff\xfe"}, want: nil},
		{name: "5 bytes with a decoded form of 7", secrets: []string{"ab\xffcd"}, want: nil},
		{name: "decoded form is another secret", secrets: []string{"abc\xffdefgh", "abc" + ffd + "defgh"}, want: []string{"abc\xffdefgh", "abc" + ffd + "defgh"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := secretTextValues(newSecrets(tt.secrets...)); !slices.Equal(got, tt.want) {
				t.Errorf("secretTextValues(%q) = %q, want %q", tt.secrets, got, tt.want)
			}
		})
	}
}

// TestSecretTextValuesLarge checks secretTextValues with many secrets: 50,000
// unique values of 16 bytes (some not valid UTF-8), then each of them again
// and the decoded forms as secrets of their own. The result must hold each
// value and decoded form once, in the order of the first occurrence. The time
// bound is very loose: it only catches a dedupe that is quadratic (seconds for
// this list). The count and the order are the real check.
func TestSecretTextValuesLarge(t *testing.T) {
	t.Parallel()

	const count = 50000
	var raw, want []string
	for i := range count {
		v := fmt.Sprintf("value-%010d", i) // 16 bytes
		if i%7 == 0 {
			v = fmt.Sprintf("value\xff%010d", i) // 16 bytes, not valid UTF-8
		}
		raw = append(raw, v)
		want = append(want, v)
		if i%7 == 0 {
			want = append(want, decodedPerByte(v))
		}
	}
	// Duplicates: every value again in reverse order, then each decoded form
	// as a secret. None of them may change the result or its order.
	secrets := slices.Clone(raw)
	for _, v := range slices.Backward(raw) {
		secrets = append(secrets, v)
	}
	for _, v := range raw {
		if !utf8.ValidString(v) {
			secrets = append(secrets, decodedPerByte(v))
		}
	}

	start := time.Now()
	got := secretTextValues(newSecrets(secrets...))
	elapsed := time.Since(start)

	// The failure messages give counts and indexes only: the list is long.
	if wantLen := count + (count+6)/7; len(want) != wantLen {
		t.Fatalf("test setup: %d wanted values, want %d", len(want), wantLen)
	}
	if len(got) != len(want) {
		t.Fatalf("secretTextValues() gives %d values, want %d", len(got), len(want))
	}
	seen := make(map[string]int, len(got))
	for i, v := range got {
		if j, ok := seen[v]; ok {
			t.Fatalf("secretTextValues() value %d is the same as value %d", i, j)
		}
		seen[v] = i
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("secretTextValues() value %d is not in first-occurrence order", i)
		}
	}
	if elapsed > 2*time.Second {
		t.Errorf("secretTextValues() took %v for %d secrets, want less than 2s (a quadratic dedupe?)", elapsed, len(secrets))
	}
}

// secretValuesReference is a plain reference for secretTextValues: the same
// rules, with a linear search for the dedupe. It is slow for many values, so
// use it only with short lists.
func secretValuesReference(secrets []Secret) []string {
	var values []string
	add := func(v string) {
		if !slices.Contains(values, v) {
			values = append(values, v)
		}
	}
	for _, s := range secrets {
		v := s.Reveal()
		if len(v) < MinSecretBytes {
			continue
		}
		add(v)
		if !utf8.ValidString(v) {
			add(decodedPerByte(v))
		}
	}
	return values
}

// TestSecretTextValuesMatchesReference compares secretTextValues with
// secretValuesReference for random lists of secrets. A small set of pieces
// makes duplicates, values near MinSecretBytes and invalid UTF-8 frequent.
// Some secrets repeat an earlier secret or its decoded form. The seed is
// fixed, so a failure repeats.
func TestSecretTextValuesMatchesReference(t *testing.T) {
	t.Parallel()

	pieces := []string{"a", "b", "ab", "\xff", "\xfe", ffd, "é"}
	rng := rand.New(rand.NewPCG(211, 2026)) //nolint:gosec // G404: fixed seed for a reproducible test, not for security
	var dups, decoded int
	for range 3000 {
		var values []string
		for n := rng.IntN(20); n > 0; n-- {
			switch k := rng.IntN(10); {
			case k == 0 && len(values) > 0:
				values = append(values, values[rng.IntN(len(values))])
			case k == 1 && len(values) > 0:
				values = append(values, decodedPerByte(values[rng.IntN(len(values))]))
			default:
				var b strings.Builder
				for m := 4 + rng.IntN(6); m > 0; m-- {
					b.WriteString(pieces[rng.IntN(len(pieces))])
				}
				values = append(values, b.String())
			}
		}
		secrets := newSecrets(values...)
		got, want := secretTextValues(secrets), secretValuesReference(secrets)
		if !slices.Equal(got, want) {
			t.Fatalf("secretTextValues(%q) = %q, want %q", values, got, want)
		}

		// Count the paths that the lists reach.
		long := 0
		for _, v := range values {
			if len(v) >= MinSecretBytes {
				long++
				if !utf8.ValidString(v) {
					long++
				}
			}
		}
		if len(want) < long {
			dups++
		}
		for _, v := range want {
			if strings.Contains(v, ffd) {
				decoded++
				break
			}
		}
	}
	// The generator must reach each path often, or the test checks little.
	if dups < 500 || decoded < 1000 {
		t.Errorf("lists with a duplicate %d, with a U+FFFD value %d of 3000: too few", dups, decoded)
	}
}

// checkPrefixIdentity checks the contract of redactTextPrefix for one input
// against the reference redaction of all of s (redactText and
// redactOracleStarts): the result is a prefix of the reference, it is the
// whole reference or longer than limit, the cut gives the same text and flag,
// and redacted follows the rule of wantRedactedFlag. It returns the reference
// and the Mask offsets for counts.
func checkPrefixIdentity(t *testing.T, s string, values []string, limit int) (string, []int) {
	t.Helper()

	out, redacted := redactTextPrefix(s, values, limit)
	ref, _ := redactText(s, values)
	oracle, starts := redactOracleStarts(s, values)
	if ref != oracle {
		t.Fatalf("redactText(%q) = %q, want the oracle %q", s, ref, oracle)
	}
	if !strings.HasPrefix(ref, out) {
		t.Fatalf("redactTextPrefix(%q, %d) = %q, not a prefix of %q", s, limit, out, ref)
	}
	if len(out) <= max(limit, 0) && out != ref {
		t.Fatalf("redactTextPrefix(%q, %d) = %q, want more than %d bytes or all of %q", s, limit, out, limit, ref)
	}
	got, gotCut := cutUTF8(out, limit)
	want, wantCut := cutUTF8(ref, limit)
	if got != want || gotCut != wantCut {
		t.Fatalf("cut of redactTextPrefix(%q, %d) = (%q, %v), want (%q, %v)", s, limit, got, gotCut, want, wantCut)
	}
	if wantFlag := wantRedactedFlag(starts, max(limit, 0)); redacted != wantFlag {
		t.Fatalf("redactTextPrefix(%q, %d) redacted = %v, want %v (Masks at %v)", s, limit, redacted, wantFlag, starts)
	}
	return ref, starts
}

// TestRedactTextPrefix pins the result and the redacted flag of
// redactTextPrefix with a small limit, at the window end and around it.
func TestRedactTextPrefix(t *testing.T) {
	t.Parallel()

	m := Mask
	const sec = "SECRETxy" // 8 bytes
	one := []string{sec}
	a := strings.Repeat
	tests := []struct {
		name     string
		s        string
		values   []string
		limit    int
		want     string
		wantFlag bool
	}{
		{name: "empty text", s: "", values: one, limit: 10, want: ""},
		{name: "no values", s: a("a", 30), values: nil, limit: 10, want: a("a", 30)},
		{name: "short text, no secret", s: "short", values: one, limit: 10, want: "short"},
		{name: "long text, no secret", s: a("a", 30), values: one, limit: 10, want: a("a", 11)},
		{name: "secret far after the window", s: a("a", 20) + sec, values: one, limit: 10, want: a("a", 11)},
		// The window is the first limit+1 bytes: a Mask at offset 11 is not
		// written and does not set the flag.
		{name: "secret starts at limit+1", s: a("a", 11) + sec, values: one, limit: 10, want: a("a", 11)},
		// A Mask at offset 10 starts in the window: the flag is true, also
		// when the cut to 10 bytes then removes the Mask.
		{name: "secret starts at limit", s: a("a", 10) + sec, values: one, limit: 10, want: a("a", 10) + m, wantFlag: true},
		{name: "secret crosses the window end", s: a("a", 6) + sec + "zz", values: one, limit: 10, want: a("a", 6) + m, wantFlag: true},
		// Masks make the result shorter than the window, so the window grows
		// to all of s.
		{name: "copies of the secret, then a short tail", s: a(sec, 20) + " t", values: one, limit: 10, want: m + " t", wantFlag: true},
		{name: "copies of the secret, then a long tail", s: a(sec, 20) + " 0123456789", values: one, limit: 10, want: m + " 01", wantFlag: true},
		{name: "limit 0, secret first", s: sec + "x", values: one, limit: 0, want: m, wantFlag: true},
		{name: "limit 0, text first", s: "x" + sec, values: one, limit: 0, want: "x"},
		{name: "negative limit is 0", s: "x" + sec, values: one, limit: -5, want: "x"},
		{name: "empty value is skipped", s: a("a", 30), values: []string{""}, limit: 10, want: a("a", 11)},
		{name: "empty value next to a secret", s: "aa" + sec, values: []string{"", sec}, limit: 10, want: "aa" + m, wantFlag: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, flag := redactTextPrefix(tt.s, tt.values, tt.limit)
			if got != tt.want || flag != tt.wantFlag {
				t.Errorf("redactTextPrefix(%q, %d) = (%q, %v), want (%q, %v)", tt.s, tt.limit, got, flag, tt.want, tt.wantFlag)
			}
			if strings.Contains(got, "SEC") {
				t.Errorf("redactTextPrefix(%q, %d) = %q holds a part of the secret", tt.s, tt.limit, got)
			}
			checkPrefixIdentity(t, tt.s, tt.values, tt.limit)
		})
	}
}

// TestRedactWindowEmptyValue checks that redactWindow skips an empty value: no
// Mask, no flag and no panic, alone or next to a real value.
func TestRedactWindowEmptyValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		values   []string
		want     string
		wantFlag bool
	}{
		{values: []string{""}, want: "abcdefghij"},
		{values: []string{"", ""}, want: "abcdefghij"},
		{values: []string{"", "cdefghij"}, want: "ab" + Mask, wantFlag: true},
	}
	for _, tt := range tests {
		// With no stop (-1) the result is all of it; with a stop after 5
		// bytes it is a prefix that still holds the Mask at offset 2.
		for _, limit := range []int{-1, 5} {
			got, flag := redactWindow("abcdefghij", tt.values, nil, 10, limit)
			if (limit < 0 && got != tt.want) || !strings.HasPrefix(tt.want, got) || flag != tt.wantFlag {
				t.Errorf("redactWindow(%q, %d) = (%q, %v), want a prefix of %q and %v", tt.values, limit, got, flag, tt.want, tt.wantFlag)
			}
		}
	}
}

// TestRedactTextMaskEdge pins the known limit in the doc of redactWindow: a
// value that ends with "*" can come back across a Mask, when the text holds
// the rest of the value just before another secret. The bytes next to the
// Mask are text that the server wrote itself.
func TestRedactTextMaskEdge(t *testing.T) {
	t.Parallel()

	values := []string{"abcdefg*", "SECRETxy"}
	got, flag := redactText("abcdefgSECRETxy", values)
	if want := "abcdefg" + Mask; got != want || !flag {
		t.Fatalf("redactText() = (%q, %v), want (%q, true)", got, flag, want)
	}
	if !strings.Contains(got, "abcdefg*") {
		t.Error("the known limit is gone: update the doc of redactWindow and this test")
	}
	if pGot, _ := redactTextPrefix("abcdefgSECRETxy", values, 100); pGot != got {
		t.Errorf("redactTextPrefix() = %q, want %q", pGot, got)
	}
}

// TestRedactTextPrefixRandomText compares redactTextPrefix with the reference
// redaction of the whole text, for random text from a small alphabet, the
// secrets and their decoded forms, and random small limits. The seed is fixed,
// so a failure repeats.
func TestRedactTextPrefixRandomText(t *testing.T) {
	t.Parallel()

	values := secretTextValues(newSecrets("abcabcab", "cabbacab", "ab\xffcabca"))
	if len(values) != 4 {
		t.Fatalf("secretTextValues() gives %d values, want 4 (with a decoded form)", len(values))
	}
	m := Mask
	pieces := []string{"a", "b", "c", "*", "\xff", ffd, "é", " ", m, "abcabcab", "cabbacab", "ab\xffcabca", "ab" + ffd + "cabca"}

	rng := rand.New(rand.NewPCG(186, 2026)) //nolint:gosec // G404: fixed seed for a reproducible test, not for security
	var beyond, inWindow, cut int
	for range 3000 {
		var b strings.Builder
		for n := rng.IntN(50); n > 0; n-- {
			b.WriteString(pieces[rng.IntN(len(pieces))])
		}
		s := b.String()
		limit := rng.IntN(40) - 2 // a few negative limits too

		ref, starts := checkPrefixIdentity(t, s, values, limit)
		if t.Failed() {
			return
		}
		switch {
		case wantRedactedFlag(starts, max(limit, 0)):
			inWindow++
		case len(starts) > 0:
			beyond++
		}
		if len(ref) > max(limit, 0) {
			cut++
		}
	}
	// The generator must reach each path often, or the test checks little.
	if beyond < 200 || inWindow < 500 || cut < 1000 {
		t.Errorf("Masks only after the window %d, in the window %d, cut %d of 3000: too few", beyond, inWindow, cut)
	}
}

// bordersReference is a plain form of borders for the tests: for each prefix
// v[:i+1] it tries every proper prefix length, longest first.
func bordersReference(v string) []int {
	out := make([]int, len(v))
	for i := range len(v) {
		p := v[:i+1]
		for k := i; k > 0; k-- {
			if p[:k] == p[len(p)-k:] {
				out[i] = k
				break
			}
		}
	}
	return out
}

// TestBorders compares borders with bordersReference for every string of 1 to
// 10 bytes over "ab", and a few other strings. It passes a dirty buffer that
// is too large, so a table that keeps old entries or reads them fails.
func TestBorders(t *testing.T) {
	t.Parallel()

	inputs := []string{"abcab", "aabaabaa", "abacabab", "a*a*a", strings.Repeat("a", 64)}
	// Each n in [0, 2^length) gives one string: bit j is 'b' when set, else 'a'.
	for length := 1; length <= 10; length++ {
		for n := range 1 << length {
			var b strings.Builder
			for j := range length {
				b.WriteByte("ab"[n>>j&1])
			}
			inputs = append(inputs, b.String())
		}
	}
	dirty := make([]int, 100)
	for _, v := range inputs {
		for i := range dirty {
			dirty[i] = 99
		}
		want := bordersReference(v)
		if got := borders(v, nil); !slices.Equal(got, want) {
			t.Fatalf("borders(%q, nil) = %v, want %v", v, got, want)
		}
		if got := borders(v, dirty); !slices.Equal(got, want) {
			t.Fatalf("borders(%q, dirty buffer) = %v, want %v", v, got, want)
		}
	}
}

// TestRedactPeriodicValues pins redactText for values that have a border (a
// prefix that is also a suffix), where the search must go on inside a match
// or a partial match. It also compares redactText and redactTextPrefix, for
// several limits, with the reference oracle (see checkPrefixIdentity).
func TestRedactPeriodicValues(t *testing.T) {
	t.Parallel()

	m := Mask
	tests := []struct {
		name     string
		s        string
		values   []string
		want     string
		wantFlag bool
	}{
		{name: "aaaa in aaaaaaa", s: "aaaaaaa", values: []string{"aaaa"}, want: m, wantFlag: true},
		{name: "aaaa inside other bytes", s: "baaaaaaab", values: []string{"aaaa"}, want: "b" + m + "b", wantFlag: true},
		{name: "aaaa in aaa", s: "aaa", values: []string{"aaaa"}, want: "aaa"},
		{name: "abab in abababab", s: "abababab", values: []string{"abab"}, want: m, wantFlag: true},
		{name: "abab in abababa", s: "abababa", values: []string{"abab"}, want: m + "a", wantFlag: true},
		{name: "aabaa in aabaabaa", s: "aabaabaa", values: []string{"aabaa"}, want: m, wantFlag: true},
		{name: "aabaa in aabaaba", s: "aabaaba", values: []string{"aabaa"}, want: m + "ba", wantFlag: true},
		{name: "value is the whole text", s: "abcabcab", values: []string{"abcabcab"}, want: m, wantFlag: true},
		{name: "value longer than the text", s: "abab", values: []string{"ababa"}, want: "abab"},
		{name: "match at the very end", s: "xyzabab", values: []string{"abab"}, want: "xyz" + m, wantFlag: true},
		{name: "match at the very start", s: "ababxyz", values: []string{"abab"}, want: m + "xyz", wantFlag: true},
		// A partial match fails and the search goes on from a border.
		{name: "fall back to a border", s: "abababac", values: []string{"abac"}, want: "abab" + m, wantFlag: true},
		{name: "fall back twice", s: "abcabcabd", values: []string{"abcabd"}, want: "abc" + m, wantFlag: true},
		{name: "near miss everywhere", s: "aaaaaaa", values: []string{"aaab"}, want: "aaaaaaa"},
		{name: "two matches with a gap", s: "ababXabab", values: []string{"abab"}, want: m + "X" + m, wantFlag: true},
		{name: "value with stars", s: "a*a*a*", values: []string{"a*a*"}, want: m, wantFlag: true},
		{name: "several values that touch", s: "aaaaabab", values: []string{"aaaa", "abab"}, want: m, wantFlag: true},
		{name: "value inside a longer value", s: "xaaaaaay", values: []string{"aa", "aaaaaa"}, want: "x" + m + "y", wantFlag: true},
		{name: "several values apart", s: "aaaa-abab-aabaa", values: []string{"aabaa", "abab", "aaaa"}, want: m + "-" + m + "-" + m, wantFlag: true},
		{name: "one value matches, one does not", s: "abababab", values: []string{"aaaa", "abab"}, want: m, wantFlag: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, flag := redactText(tt.s, tt.values)
			if got != tt.want || flag != tt.wantFlag {
				t.Errorf("redactText(%q, %q) = (%q, %v), want (%q, %v)", tt.s, tt.values, got, flag, tt.want, tt.wantFlag)
			}
			// -3 counts as 0. len(tt.s) and more give the whole result.
			for _, limit := range []int{-3, -1, 0, 1, 2, 3, 5, len(tt.s) - 1, len(tt.s), 100} {
				checkPrefixIdentity(t, tt.s, tt.values, limit)
			}
		})
	}
}

// TestRedactLongPeriodicSecret checks the case of issue #231 with an exact
// result: a periodic secret of 4096 bytes that the text repeats for 64 KiB.
// The oracle would be too slow here (it tries each value at each byte).
func TestRedactLongPeriodicSecret(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("a", 4096)
	values := []string{secret}
	text := "x" + strings.Repeat("a", 64<<10) + "y" // 64<<10 is 64 KiB
	want := "x" + Mask + "y"
	if got, flag := redactText(text, values); got != want || !flag {
		t.Errorf("redactText() = (%d bytes, %v), want (%q, true)", len(got), flag, want)
	}
	// With a limit of 4 the result stops after the Mask: it is a prefix of
	// want with more than 4 bytes.
	if got, flag := redactTextPrefix(text, values, 4); got != "x"+Mask || !flag {
		t.Errorf("redactTextPrefix(4) = (%d bytes, %v), want (%q, true)", len(got), flag, "x"+Mask)
	}
	if got, flag := redactTextPrefix(text, values, 100); got != want || !flag {
		t.Errorf("redactTextPrefix(100) = (%d bytes, %v), want (%q, true)", len(got), flag, want)
	}
	// One byte short of a match: the text stays as it is.
	short := strings.Repeat("a", 4095)
	if got, flag := redactText(short, values); got != short || flag {
		t.Errorf("redactText(4095 bytes) = (%d bytes, %v), want the text and false", len(got), flag)
	}
}

// TestRedactRandomPeriodic compares redactText and redactTextPrefix with the
// reference oracle for random text and random values over the small alphabet
// "ab*". TestRedactTextPrefixRandomText uses fixed values. Here the values are
// random too, and often a repeated unit ("abab", "aaa"), so the borders of the
// search get a wide mix. The values are short (1 to 6 bytes) so that they
// match often. The seed is fixed, so a failure repeats.
func TestRedactRandomPeriodic(t *testing.T) {
	t.Parallel()

	const alphabet = "ab*"
	rng := rand.New(rand.NewPCG(231, 2026)) //nolint:gosec // G404: fixed seed for a reproducible test, not for security
	randString := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return string(b)
	}
	var overlaps, inWindow int
	for range 5000 {
		values := make([]string, 1+rng.IntN(3))
		for i := range values {
			if rng.IntN(2) == 0 {
				unit := randString(1 + rng.IntN(2))
				values[i] = strings.Repeat(unit, 6)[:1+rng.IntN(6)]
			} else {
				values[i] = randString(1 + rng.IntN(6))
			}
		}
		s := randString(rng.IntN(40))
		limit := rng.IntN(44) - 2 // a few negative limits too
		_, starts := checkPrefixIdentity(t, s, values, limit)
		if t.Failed() {
			return
		}
		if wantRedactedFlag(starts, max(limit, 0)) {
			inWindow++
		}
		if hasOverlap(s, values) {
			overlaps++
		}
	}
	// The generator must reach each path often, or the test checks little.
	if overlaps < 300 || inWindow < 1500 {
		t.Errorf("texts with an overlapping match %d, with a Mask in the window %d of 5000: too few", overlaps, inWindow)
	}
}

// hasOverlap reports whether one of values matches s at two starts that are
// less than its length apart.
func hasOverlap(s string, values []string) bool {
	for _, v := range values {
		prev := -len(v)
		for i := range len(s) {
			if strings.HasPrefix(s[i:], v) {
				if i-prev < len(v) {
					return true
				}
				prev = i
			}
		}
	}
	return false
}

// benchSize is the length of the description in the redaction benchmarks.
const benchSize = 1 << 20 // 1 MiB

// BenchmarkRedactPeriodicSecret redacts a periodic secret (4096 times "a") in
// a description of 1 MiB of "a" (issue #231). Compare it with
// BenchmarkRedactNonPeriodicSecret: the times must be of the same order.
func BenchmarkRedactPeriodicSecret(b *testing.B) {
	values := []string{strings.Repeat("a", 4096)}
	text := strings.Repeat("a", benchSize)
	b.SetBytes(int64(len(text))) // the output then shows MB/s
	for b.Loop() {               // b.Loop (Go 1.24+) runs the body enough times and keeps the result alive
		redactText(text, values)
	}
}

// BenchmarkRedactNonPeriodicSecret redacts a random-looking secret of 4096
// bytes (FAKE, from a fixed seed) in a description of 1 MiB of random
// letters that holds the secret 8 times.
func BenchmarkRedactNonPeriodicSecret(b *testing.B) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rng := rand.New(rand.NewPCG(4096, 231)) //nolint:gosec // G404: fixed seed for fake benchmark data, not for security
	randLetters := func(n int) []byte {
		out := make([]byte, n)
		for i := range out {
			out[i] = letters[rng.IntN(len(letters))]
		}
		return out
	}
	secret := randLetters(4096)
	text := randLetters(benchSize)
	for i := range 8 {
		copy(text[i*(benchSize/8):], secret)
	}
	values := []string{string(secret)}
	s := string(text)
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		redactText(s, values)
	}
}

// TestTextRedactorMatchesReference compares TextRedactor.Text and
// TextRedactor.Prefix with the reference forms redactText and redactTextPrefix
// (which the tests above check against the oracle) for random secrets and
// random text. The secrets are periodic or random over a small alphabet with
// an invalid UTF-8 byte, so they match often, overlap, and get a decoded
// form. The seed is fixed, so a failure repeats.
func TestTextRedactorMatchesReference(t *testing.T) {
	t.Parallel()

	const alphabet = "ab*\xff"
	rng := rand.New(rand.NewPCG(2026, 10)) //nolint:gosec // G404: fixed seed for a reproducible test, not for security
	randString := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return string(b)
	}
	var masked int
	for range 3000 {
		// Values of 6 to 12 bytes: the ones under MinSecretBytes are skipped
		// by both forms.
		var raw []string
		for range 1 + rng.IntN(3) {
			n := 6 + rng.IntN(7)
			if rng.IntN(2) == 0 {
				raw = append(raw, strings.Repeat(randString(1+rng.IntN(3)), n)[:n])
			} else {
				raw = append(raw, randString(n))
			}
		}
		secrets := newSecrets(raw...)
		values := secretTextValues(secrets)
		r := NewTextRedactor(secrets)

		// The text is built from the values and their decoded forms, whole
		// or in part, so most texts hold a match or a near miss.
		var b strings.Builder
		for range rng.IntN(8) {
			switch {
			case len(values) == 0 || rng.IntN(3) == 0:
				b.WriteString(randString(rng.IntN(6)))
			case rng.IntN(2) == 0:
				b.WriteString(values[rng.IntN(len(values))]) // a whole value
			default:
				v := values[rng.IntN(len(values))]
				b.WriteString(v[rng.IntN(len(v)):]) // the end of a value
			}
		}
		s := b.String()

		want, wantFlag := redactText(s, values)
		if got := r.Text(s); got != want {
			t.Fatalf("Text(%q) with values %q = %q, want %q", s, values, got, want)
		}
		if wantFlag {
			masked++
		}
		limit := rng.IntN(len(s)+4) - 2 // a few negative limits too
		wantPrefix, wantPrefixFlag := redactTextPrefix(s, values, limit)
		if got, flag := r.Prefix(s, limit); got != wantPrefix || flag != wantPrefixFlag {
			t.Fatalf("Prefix(%q, %d) with values %q = (%q, %v), want (%q, %v)", s, limit, values, got, flag, wantPrefix, wantPrefixFlag)
		}
	}
	// The generator must reach a match often, or the test checks little.
	if masked < 1000 {
		t.Errorf("texts with a Mask %d of 3000: too few", masked)
	}
}

// TestTextRedactorEmpty checks that a TextRedactor with no value redacts
// nothing: a nil *TextRedactor, the zero TextRedactor, and the result of
// NewTextRedactor for no secrets or for values that are all too short.
func TestTextRedactorEmpty(t *testing.T) {
	t.Parallel()

	if r := NewTextRedactor(nil); r != nil {
		t.Errorf("NewTextRedactor(nil) = %v, want nil", r)
	}
	if r := NewTextRedactor(newSecrets("1234567", "", "short")); r != nil {
		t.Errorf("NewTextRedactor(values under %d bytes) = %v, want nil", MinSecretBytes, r)
	}
	text := "pin 1234567 and " + secretCanary
	for name, r := range map[string]*TextRedactor{"nil": nil, "zero": {}} {
		if got := r.Text(text); got != text {
			t.Errorf("%s Text(%q) = %q, want the text", name, text, got)
		}
		if got, flag := r.Prefix(text, 3); got != text || flag {
			t.Errorf("%s Prefix(%q, 3) = (%q, %v), want the text and false", name, text, got, flag)
		}
	}
}

// TestTextRedactorText pins a few results of Text and Prefix, also for an
// empty text and for a value that is not valid UTF-8 (its decoded form goes
// too).
func TestTextRedactorText(t *testing.T) {
	t.Parallel()

	r := NewTextRedactor(newSecrets(secretCanary, "short", "abc\xffdefgh"))
	tests := []struct {
		s    string
		want string
	}{
		{s: "", want: ""},
		{s: "no secret here", want: "no secret here"},
		{s: "key=" + secretCanary + ".", want: "key=" + Mask + "."},
		{s: "short", want: "short"}, // under MinSecretBytes
		{s: "raw abc\xffdefgh and decoded abc" + ffd + "defgh", want: "raw " + Mask + " and decoded " + Mask},
	}
	for _, tt := range tests {
		if got := r.Text(tt.s); got != tt.want {
			t.Errorf("Text(%q) = %q, want %q", tt.s, got, tt.want)
		}
		if got, _ := r.Prefix(tt.s, len(tt.s)); got != tt.want {
			t.Errorf("Prefix(%q, %d) = %q, want %q", tt.s, len(tt.s), got, tt.want)
		}
	}
	if got, flag := r.Prefix("x"+secretCanary+strings.Repeat("y", 100), 2); got != "x"+Mask || !flag {
		t.Errorf("Prefix(2) = (%q, %v), want (%q, true)", got, flag, "x"+Mask)
	}
}

// TestTextRedactorPrintsNoValue checks that fmt, log/slog and encoding/json
// never show a value of a TextRedactor: as a pointer, as a value, and as an
// unexported field of another struct, where fmt reads the fields by
// reflection. With %q or %s, fmt follows a pointer to a struct in such a
// field and prints its fields, so the state must not be such a pointer.
func TestTextRedactorPrintsNoValue(t *testing.T) {
	t.Parallel()

	r := NewTextRedactor(newSecrets(secretCanary))
	type holder struct {
		r  *TextRedactor
		rv TextRedactor
	}
	h := holder{r: r, rv: *r}
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%10v"} {
		out = append(out, fmt.Sprintf(verb, r), fmt.Sprintf(verb, *r), fmt.Sprintf(verb, h))
	}
	out = append(out, r.String(), r.GoString())
	// encoding/json skips unexported fields, so the check uses exported
	// ones: the TextRedactor encodes as "{}".
	exported := struct {
		R  *TextRedactor
		RV TextRedactor
	}{R: r, RV: *r}
	data, err := json.Marshal(exported)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	out = append(out, string(data))
	var logs strings.Builder
	slog.New(slog.NewTextHandler(&logs, nil)).Info("x", "r", r, "rv", *r, "h", h)
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("x", "r", r, "rv", *r, "h", h)
	out = append(out, logs.String())
	for _, s := range out {
		if strings.Contains(s, "CANARY") || strings.Contains(s, hex.EncodeToString([]byte("CANARY"))) {
			t.Errorf("output %q shows the secret value", s)
		}
	}
	if got := fmt.Sprint(r); got != Mask {
		t.Errorf("fmt.Sprint(r) = %q, want %q", got, Mask)
	}
}

// TestTextRedactorConcurrent shares one TextRedactor between parallel
// subtests. Run it with -race: a write to the shared tables or values would
// be a data race. Each subtest also checks its results.
func TestTextRedactorConcurrent(t *testing.T) {
	t.Parallel()

	values := []string{secretCanary, "abababab", "aaaaaaaaaa", "a*b*a*b*"}
	r := NewTextRedactor(newSecrets(values...))
	texts := []string{
		"x" + secretCanary + "y",
		strings.Repeat("ab", 100),
		strings.Repeat("a", 300) + "b",
		"a*b*a*b*a*b*",
		strings.Repeat("no secret ", 50),
	}
	for i := range 8 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			for range 50 {
				for _, s := range texts {
					want, _ := redactText(s, values)
					if got := r.Text(s); got != want {
						t.Fatalf("Text(%q) = %q, want %q", s, got, want)
					}
					wantPrefix, wantFlag := redactTextPrefix(s, values, 20)
					if got, flag := r.Prefix(s, 20); got != wantPrefix || flag != wantFlag {
						t.Fatalf("Prefix(%q, 20) = (%q, %v), want (%q, %v)", s, got, flag, wantPrefix, wantFlag)
					}
				}
			}
		})
	}
}

// TestTextRedactorBuildsTablesOnce checks that Text and Prefix do not build
// the border tables again: for a text with no secret they allocate nothing,
// while redactText allocates the border buffer on each call.
//
// No t.Parallel: testing.AllocsPerRun counts the allocations of the whole
// program, so other tests that run at the same time would add to the count.
func TestTextRedactorBuildsTablesOnce(t *testing.T) {
	values, texts := redactorBenchData(50, 1)
	r := NewTextRedactor(newSecrets(values...))
	s := texts[0]
	if strings.Contains(r.Text(s), Mask) {
		t.Fatal("the test text holds a secret; want a text with none")
	}
	if n := testing.AllocsPerRun(100, func() { r.Text(s) }); n != 0 {
		t.Errorf("Text() allocates %v times for each call, want 0 (are the tables built again?)", n)
	}
	if n := testing.AllocsPerRun(100, func() { r.Prefix(s, 10) }); n != 0 {
		t.Errorf("Prefix() allocates %v times for each call, want 0 (are the tables built again?)", n)
	}
	// The contrast: redactText builds a table on each call, so the check
	// above measures the right thing.
	if n := testing.AllocsPerRun(100, func() { redactText(s, values) }); n == 0 {
		t.Error("redactText() allocates nothing: the check above no longer shows a rebuild")
	}
}

// redactorBenchData returns n FAKE secret values of 24 random letters and m
// texts of 40 random letters, from a fixed seed. Every 100th text holds a
// value. A text is longer than a value, so a search of each value reads it.
func redactorBenchData(n, m int) (values, texts []string) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rng := rand.New(rand.NewPCG(500, 20000)) //nolint:gosec // G404: fixed seed for fake test data, not for security
	randLetters := func(k int) string {
		b := make([]byte, k)
		for i := range b {
			b[i] = letters[rng.IntN(len(letters))]
		}
		return string(b)
	}
	for range n {
		values = append(values, randLetters(24))
	}
	for i := range m {
		s := randLetters(40)
		if i%100 == 99 {
			s = s[:8] + values[i%n] + s[32:]
		}
		texts = append(texts, s)
	}
	return values, texts
}

// BenchmarkRedactManyShortTexts redacts 20,000 short texts (such as the JSON
// strings of a large enum) with the 500 values of one server, the case of
// the pin diffs. redactText builds the border table of each value for each
// text; a TextRedactor builds them once, outside the loop of texts.
func BenchmarkRedactManyShortTexts(b *testing.B) {
	values, texts := redactorBenchData(500, 20000)
	b.Run("redactText", func(b *testing.B) {
		for b.Loop() {
			for _, s := range texts {
				redactText(s, values)
			}
		}
	})
	b.Run("TextRedactor", func(b *testing.B) {
		for b.Loop() {
			// One TextRedactor for each server, so the build is in the loop.
			r := NewTextRedactor(newSecrets(values...))
			for _, s := range texts {
				r.Text(s)
			}
		}
	})
}
