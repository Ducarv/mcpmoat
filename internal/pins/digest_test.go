package pins

import (
	"strings"
	"testing"
)

// pinsOf builds a ServerPins from alternating tool names and hashes.
func pinsOf(t *testing.T, pairs ...string) ServerPins {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatal("pinsOf needs name and hash pairs")
	}
	p := make(ServerPins, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		p[pairs[i]] = Pin{Hash: pairs[i+1], Canonical: "{}"}
	}
	return p
}

func TestDigestOrderIndependent(t *testing.T) {
	t.Parallel()

	p := pinsOf(t, "a", "h1", "b", "h2", "c", "h3", "d", "h4", "e", "h5", "f", "h6")
	want := Digest(p)
	// Go randomises the map order on every range, so repeat the call.
	for range 50 {
		if got := Digest(p); got != want {
			t.Fatalf("Digest changed between calls: %q and %q", got, want)
		}
	}
	// The same set built in another insertion order has the same digest.
	q := pinsOf(t, "f", "h6", "e", "h5", "d", "h4", "c", "h3", "b", "h2", "a", "h1")
	if got := Digest(q); got != want {
		t.Errorf("Digest = %q for the reversed build, want %q", got, want)
	}
}

func TestDigestEmptySetStable(t *testing.T) {
	t.Parallel()

	const want = "pd1:e3b0c44298fc1c149afbf4c8996fb924" // first 16 bytes of SHA-256 of no bytes
	for name, p := range map[string]ServerPins{"nil": nil, "empty": {}} {
		if got := Digest(p); got != want {
			t.Errorf("%s: Digest = %q, want %q", name, got, want)
		}
	}
}

func TestDigestGolden(t *testing.T) {
	t.Parallel()

	// This pins the encoding. If it fails, the encoding changed: change
	// DigestVersion and update the value.
	p := pinsOf(t, "write", "sha256-v1:bb", "read", "sha256-v1:aa")
	const want = "pd1:da4d80c9661fbb08630769dc5e97be3b"
	if got := Digest(p); got != want {
		t.Errorf("Digest = %q, want %q", got, want)
	}
}

func TestDigestDiffers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b ServerPins
	}{
		{"name one char", pinsOf(t, "read", "h"), pinsOf(t, "reaD", "h")},
		{"hash one char", pinsOf(t, "read", "sha256-v1:aa"), pinsOf(t, "read", "sha256-v1:ab")},
		{"extra tool", pinsOf(t, "read", "h"), pinsOf(t, "read", "h", "write", "h")},
		{"empty against one tool", pinsOf(t), pinsOf(t, "a", "h")},
		{"hash moves between tools", pinsOf(t, "a", "h1", "b", "h2"), pinsOf(t, "a", "h2", "b", "h1")},
		{"empty name and hash", pinsOf(t, "", ""), pinsOf(t)},
		// Pairs that collide when the input is joined as "name\thash\n".
		{"newline in name", pinsOf(t, "a\th\nb", "x"), pinsOf(t, "a", "h", "b", "x")},
		{"tab and newline in name", pinsOf(t, "a", "h\nb\tx"), pinsOf(t, "a", "h", "b", "x")},
		{"boundary moves", pinsOf(t, "ab", "c"), pinsOf(t, "a", "bc")},
		{"colon in name", pinsOf(t, "a:b", "c"), pinsOf(t, "a", "b:c")},
		{"digits mimic a decimal prefix", pinsOf(t, "1:a", "b"), pinsOf(t, "1", "a1:b")},
		{"digits mimic a length", pinsOf(t, "3:abc", "h"), pinsOf(t, "3", "abch")},
		{"byte mimics a varint prefix", pinsOf(t, "\x01a", "h"), pinsOf(t, "", "\x01ah")},
		{"two tools against one name", pinsOf(t, "a", "h", "b", "k"), pinsOf(t, "a", "h\x01bk")},
		{"nul bytes", pinsOf(t, "a\x00", "b"), pinsOf(t, "a", "\x00b")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if a, b := Digest(tt.a), Digest(tt.b); a == b {
				t.Errorf("both sets have digest %q", a)
			}
		})
	}
}

func TestDigestFormat(t *testing.T) {
	t.Parallel()

	got := Digest(pinsOf(t, "read", "h"))
	if !ValidDigest(got) {
		t.Errorf("ValidDigest(Digest(...)) is false for %q", got)
	}
	if !strings.HasPrefix(got, DigestVersion+":") || len(got) != len(DigestVersion)+1+32 {
		t.Errorf("Digest = %q, want %q, a colon and 32 hex characters", got, DigestVersion)
	}
}

func TestValidDigest(t *testing.T) {
	t.Parallel()

	const hex32 = "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"valid", "pd1:" + hex32, true},
		{"all zero", "pd1:" + strings.Repeat("0", 32), true},
		{"empty", "", false},
		{"prefix only", "pd1:", false},
		{"upper case", "pd1:" + strings.ToUpper(hex32), false},
		{"one upper case char", "pd1:A123456789abcdef0123456789abcdef", false},
		{"too short", "pd1:" + hex32[:31], false},
		{"too long", "pd1:" + hex32 + "0", false},
		{"wrong prefix", "pd2:" + hex32, false},
		{"no prefix", hex32, false},
		{"no colon", "pd1" + hex32, false},
		{"upper case prefix", "PD1:" + hex32, false},
		{"non hex", "pd1:0123456789abcdef0123456789abcdeg", false},
		{"leading space", " pd1:" + hex32, false},
		{"trailing newline", "pd1:" + hex32 + "\n", false},
		{"non ASCII", "pd1:0123456789abcdef0123456789abcdé", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidDigest(tt.in); got != tt.want {
				t.Errorf("ValidDigest(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
