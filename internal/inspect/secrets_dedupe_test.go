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
// of pieces (NFR-03). The benchmarks show the cost; the test shows that the
// output is the same as the one of the old linear search.

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

// oldValueCredentials, oldCookieSecrets and oldHeaderSecrets are the old
// forms of the three functions, with a linear search in the lists. They are
// the reference for TestDedupeSameOutput.
func oldValueCredentials(value string) (long, short []string) {
	for _, v := range discover.ArgCredentials([]string{value}) {
		switch {
		case v == value, slices.Contains(long, v), slices.Contains(short, v):
		case len(v) >= discover.MinSecretBytes:
			long = append(long, v)
		case v != "":
			short = append(short, v)
		}
	}
	return long, short
}

func oldCookieSecrets(key, value string) (long, short []string) {
	if !isCookieHeader(key) {
		return nil, nil
	}
	add := func(piece string) {
		switch {
		case piece == "", piece == value, slices.Contains(long, piece), slices.Contains(short, piece):
		case len(piece) >= discover.MinSecretBytes:
			long = append(long, piece)
		default:
			short = append(short, piece)
		}
	}
	parts := strings.Split(value, ";")
	if strings.EqualFold(strings.TrimSpace(key), "set-cookie") {
		parts = parts[:1]
	}
	for _, part := range parts {
		pair := strings.TrimSpace(part)
		name, val, found := strings.Cut(pair, "=")
		if !found || strings.TrimSpace(name) == "" {
			continue
		}
		val = strings.TrimSpace(val)
		add(pair)
		add(val)
		if len(val) >= 2 && strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`) {
			add(val[1 : len(val)-1])
		}
	}
	return long, short
}

func oldHeaderSecrets(key, value string) []string {
	var secrets []string
	if value != "" {
		secrets = append(secrets, value)
	}
	if cred := credentialPart(value); cred != "" {
		secrets = append(secrets, cred)
	}
	secrets = append(secrets, basicSecrets(value)...)
	cookieLong, _ := oldCookieSecrets(key, value)
	innerLong, _ := oldValueCredentials(value)
	for _, piece := range slices.Concat(cookieLong, innerLong) {
		if !slices.Contains(secrets, piece) {
			secrets = append(secrets, piece)
		}
	}
	return secrets
}

// TestDedupeSameOutput checks that the seen-sets give the same lists, in the
// same order, as the old linear search. The values repeat pieces on purpose.
// They are fake values, not real credentials.
func TestDedupeSameOutput(t *testing.T) {
	t.Parallel()
	headers := []struct{ key, value string }{
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
	for _, h := range headers {
		gotLong, gotShort := valueCredentials(h.value)
		wantLong, wantShort := oldValueCredentials(h.value)
		if !slices.Equal(gotLong, wantLong) || !slices.Equal(gotShort, wantShort) {
			t.Errorf("valueCredentials of the %s value: the lists differ from the linear search", h.key)
		}
		gotLong, gotShort = cookieSecrets(h.key, h.value)
		wantLong, wantShort = oldCookieSecrets(h.key, h.value)
		if !slices.Equal(gotLong, wantLong) || !slices.Equal(gotShort, wantShort) {
			t.Errorf("cookieSecrets of the %s value: the lists differ from the linear search", h.key)
		}
		if got, want := headerSecrets(h.key, h.value), oldHeaderSecrets(h.key, h.value); !slices.Equal(got, want) {
			t.Errorf("headerSecrets of the %s value: the list differs from the linear search", h.key)
		}
	}
}
