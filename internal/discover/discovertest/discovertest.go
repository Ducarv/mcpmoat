// Package discovertest has test helpers that check output for leaked secrets.
//
// Fixtures put the canary values below in env and header fields. Tests then
// call AssertNoLeak on everything the code under test prints or returns
// (text, JSON, errors, logs) to prove that no value reached the output.
//
// Import this package only from _test.go files, so the testing package never
// reaches the mcpmoat binary.
package discovertest

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// Canary values are fake secrets for fixtures and tests. Each one is unique and needs
// no escaping in Go or JSON strings, so tests can search any output for it.
const (
	// CanaryEnv is the fake value for env entries in fixtures.
	CanaryEnv = "mcpmoat-canary-env-7Q2xK9"
	// CanaryHeader is the fake value for HTTP header entries in fixtures.
	CanaryHeader = "mcpmoat-canary-header-4Vb8Rt"
	// CanaryURL is the fake value for secrets embedded in server URLs in fixtures.
	CanaryURL = "mcpmoat-canary-url-9Jd3Wm"
)

// Canaries returns every canary value.
// It returns a new slice on each call, so callers can change it safely.
func Canaries() []string {
	return []string{CanaryEnv, CanaryHeader, CanaryURL}
}

// minEncodedLen is the shortest value, in bytes, that Leaks searches for in
// hex and base64. The hex and base64 strings of a shorter value are short
// enough to appear in unrelated output by chance. For example, "ab" is "6162"
// in hex and "YWI" in base64, and a false positive would fail a good test.
// Leaks searches for a shorter value only as written and Go-quoted.
const minEncodedLen = 8

// minBase64Core is the shortest base64 core that Leaks searches for. A shorter
// core could match unrelated text by chance and give a false positive.
const minBase64Core = 8

// Leaks returns each non-empty secret found in output. Empty secrets are ignored.
// Order follows secrets. Each secret appears at most once in the result.
//
// Leaks searches for these forms of each secret:
//   - as written, always;
//   - Go-quoted (strconv.Quote without the outer quotes), always;
//   - hex, lower or upper case, only if the secret has at least
//     minEncodedLen bytes;
//   - base64, standard ("+/") or URL-safe ("-_") alphabet, with or without "="
//     padding, alone or embedded in a longer encoded string (for example HTTP
//     Basic auth, base64("user:" + secret)), only if the secret has at least
//     minEncodedLen bytes.
//
// A shorter secret is not searched for in hex or base64, because its encoded
// forms are short enough to match unrelated output by chance.
//
// Leaks is made for canary-style values (letters, digits, "-") like the
// constants in this package. Use values of that style in fixtures.
func Leaks(output string, secrets ...string) []string {
	var found []string
	seen := make(map[string]bool)
	for _, s := range secrets {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		if containsAny(output, forms(s)) {
			found = append(found, s)
		}
	}
	return found
}

// AssertNoLeak calls t.Errorf once for each secret that Leaks finds in output.
// what names the output in the message (for example "stdout" or "error").
// If no secrets are passed, it checks every value from Canaries, so a call
// without secrets cannot pass by mistake. If secrets are passed but all of
// them are empty, Leaks has nothing to search for, so AssertNoLeak calls
// t.Errorf once to report that nothing was checked.
// It calls only t.Helper and t.Errorf.
func AssertNoLeak(t testing.TB, what, output string, secrets ...string) {
	// t.Helper makes the failure point at the caller's line, not this one.
	t.Helper()
	if len(secrets) == 0 {
		secrets = Canaries()
	}
	if allEmpty(secrets) {
		t.Errorf("%s: AssertNoLeak got only empty values; nothing was checked", what)
		return
	}
	for _, s := range Leaks(output, secrets...) {
		t.Errorf("%s leaks secret %q; output:\n%s", what, s, output)
	}
}

// allEmpty reports whether every value in values is the empty string.
func allEmpty(values []string) bool {
	for _, v := range values {
		if v != "" {
			return false
		}
	}
	return true
}

// forms returns every encoding of s that Leaks searches for. Values shorter
// than minEncodedLen bytes get only the raw and Go-quoted forms.
func forms(s string) []string {
	quoted := strconv.Quote(s)
	out := []string{
		s,
		// strconv.Quote always adds one '"' at each end; drop them so the
		// escaped form also matches inside a longer quoted string.
		quoted[1 : len(quoted)-1],
	}
	if len(s) < minEncodedLen {
		return out
	}
	hexLower := hex.EncodeToString([]byte(s))
	out = append(out, hexLower, strings.ToUpper(hexLower))
	return append(out, base64Forms(s)...)
}

// base64Forms returns the base64 strings that show s inside any base64 output.
// Leaks calls it only for values of at least minEncodedLen bytes.
//
// Base64 turns each group of 3 input bytes into 4 output characters. Each
// group is encoded on its own, so an output character depends only on the
// bytes of its own group. When s is part of a longer input, for example
// "user:" + s, the groups at the start and end of s also hold bytes that are
// not from s, and their characters change with those bytes. The groups that
// lie fully inside s do not change: their characters appear in the output
// exactly as if those bytes were encoded alone. We call them the core.
//
// Which bytes of s form full groups depends on where s starts inside a group:
// at byte 0, 1 or 2. So we compute one core for each of the 3 start offsets.
// With off bytes before s in its group, the first full group starts at byte
// (3-off)%3 of s.
//
// The cores use the raw (unpadded) encodings. "=" padding only goes at the
// very end of the output, and the raw form is a prefix of the padded form, so
// a search for the raw form also finds the padded one. We search both
// alphabets, because the standard and URL-safe alphabets differ in two
// characters ("+/" and "-_").
func base64Forms(s string) []string {
	encodings := []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding}
	var out []string
	for _, enc := range encodings {
		// s encoded alone, as one whole base64 string.
		out = append(out, enc.EncodeToString([]byte(s)))
		for off := range 3 {
			k := (3 - off) % 3
			if k >= len(s) {
				continue
			}
			n := (len(s) - k) / 3 // number of full groups inside s
			core := enc.EncodeToString([]byte(s[k : k+3*n]))
			// Skip short cores. An empty core would match every output.
			if len(core) < minBase64Core {
				continue
			}
			out = append(out, core)
		}
	}
	return out
}

// containsAny reports whether output contains at least one of subs.
func containsAny(output string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(output, sub) {
			return true
		}
	}
	return false
}
