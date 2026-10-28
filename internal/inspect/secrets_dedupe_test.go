package inspect

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// This file checks the duplicate checks of valueCredentials, cookieSecrets
// and headerSecrets. The config controls the value, and a large value has one
// piece per pair, so the check must not grow with the square of the number
// of pieces (NFR-03). The benchmarks show the cost; the tests show that the
// lists have each piece one time, in the order of first occurrence. They do
// not copy the parsers, so a change of a parser does not break them.

// manyPairs returns n pairs "<key>=<7 digits>", joined with sep. Each value
// differs, so no pair is a duplicate.
func manyPairs(key, sep string, n int) string {
	pairs := make([]string, n)
	for i := range pairs {
		pairs[i] = fmt.Sprintf("%s=%07d", key, i+1)
	}
	return strings.Join(pairs, sep)
}

// The values of the benchmarks are fake: no real credential.

func BenchmarkValueCredentialsManyPairs(b *testing.B) {
	value := manyPairs("pw", ";", 100_000)
	for b.Loop() {
		valueCredentials(value)
	}
}

func BenchmarkCookieSecretsManyPairs(b *testing.B) {
	value := manyPairs("sid", "; ", 100_000)
	for b.Loop() {
		cookieSecrets("Cookie", value)
	}
}

func BenchmarkHeaderSecretsManyPairs(b *testing.B) {
	value := manyPairs("sid", "; ", 100_000)
	for b.Loop() {
		headerSecrets("Cookie", value)
	}
}

// headersWithRepeats are header values that repeat pieces on purpose. They
// are fake values, not real credentials.
var headersWithRepeats = []struct{ key, value string }{
	{"Cookie", "sid=abcdefgh12; sid=abcdefgh12; theme=dark; a=b; a=b; q=\"quoted-value-1\"; x=sid=abcdefgh12"},
	{"Set-Cookie", "sid=abcdefgh12; Path=/; Domain=example.com"},
	{"Cookie2", "a=1;b=1;c=abcdefgh12;d=abcdefgh12"},
	{"Authorization", "Bearer tok_abcdefgh12345678"},
	{"Authorization", "Basic " + rmBasic("user", "password-123")},
	{"X-Db", "postgres://u:pw@h/db password=pw password=secret-12345 password=secret-12345"},
	{"X-Conn", "pw=abc;pw=abc;pw=abcdefgh12;pw=abcdefgh12"},
	{"Content-Type", "application/json"},
	{"Cookie", manyPairs("sid", "; ", 50) + "; " + manyPairs("sid", "; ", 50)},
	{"X-Many", manyPairs("pw", ";", 50) + ";" + manyPairs("pw", ";", 50)},
	{"Cookie", ""},
}

// TestDedupeLists checks the lists of valueCredentials, cookieSecrets and
// headerSecrets for the properties of a set that keeps its order: no piece
// twice, no empty piece, no piece that is the whole value, and each piece
// in the list of its size.
func TestDedupeLists(t *testing.T) {
	t.Parallel()
	noDups := func(t *testing.T, what string, lists ...[]string) {
		t.Helper()
		seen := make(map[string]struct{})
		for _, list := range lists {
			for _, v := range list {
				if _, dup := seen[v]; dup {
					t.Errorf("%s: a piece is in the lists twice", what)
				}
				seen[v] = struct{}{}
			}
		}
	}
	sizes := func(t *testing.T, what, value string, long, short []string) {
		t.Helper()
		for _, v := range long {
			if len(v) < discover.MinSecretBytes || v == "" || v == value {
				t.Errorf("%s: a piece of long has %d bytes or is the whole value", what, len(v))
			}
		}
		for _, v := range short {
			if len(v) >= discover.MinSecretBytes || v == "" || v == value {
				t.Errorf("%s: a piece of short has %d bytes or is the whole value", what, len(v))
			}
		}
	}
	for _, h := range headersWithRepeats {
		long, short := valueCredentials(h.value)
		noDups(t, "valueCredentials of "+h.key, long, short)
		sizes(t, "valueCredentials of "+h.key, h.value, long, short)

		long, short = cookieSecrets(h.key, h.value)
		noDups(t, "cookieSecrets of "+h.key, long, short)
		sizes(t, "cookieSecrets of "+h.key, h.value, long, short)

		noDups(t, "headerSecrets of "+h.key, headerSecrets(h.key, h.value))
	}
}

// TestDedupeOrder checks that valueCredentials keeps the order of first
// occurrence of the pieces that discover.ArgCredentials gives, and that
// cookieSecrets does so for a cookie with repeated pairs.
func TestDedupeOrder(t *testing.T) {
	t.Parallel()
	for _, h := range headersWithRepeats {
		var wantLong, wantShort []string
		seen := make(map[string]struct{})
		for _, v := range discover.ArgCredentials([]string{h.value}) {
			if _, dup := seen[v]; dup || v == "" || v == h.value {
				continue
			}
			seen[v] = struct{}{}
			if len(v) >= discover.MinSecretBytes {
				wantLong = append(wantLong, v)
			} else {
				wantShort = append(wantShort, v)
			}
		}
		gotLong, gotShort := valueCredentials(h.value)
		if !slices.Equal(gotLong, wantLong) || !slices.Equal(gotShort, wantShort) {
			t.Errorf("valueCredentials of the %s value: the lists differ from the pieces of discover.ArgCredentials", h.key)
		}
	}

	long, short := cookieSecrets("Cookie", "sid=abcdefgh12; sid=abcdefgh12; theme=dark; a=b; a=b")
	if want := []string{"sid=abcdefgh12", "abcdefgh12", "theme=dark"}; !slices.Equal(long, want) {
		t.Errorf("cookieSecrets() long = %q, want %q", long, want)
	}
	if want := []string{"dark", "a=b", "b"}; !slices.Equal(short, want) {
		t.Errorf("cookieSecrets() short = %q, want %q", short, want)
	}
}
