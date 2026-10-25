package pins

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand/v2"
	"regexp"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// hashFormat is the exact form of a hash of version HashVersion.
var hashFormat = regexp.MustCompile("^" + regexp.QuoteMeta(HashVersion) + ":[0-9a-f]{64}$")

func TestHashFormat(t *testing.T) {
	t.Parallel()
	for _, f := range loadHashFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			t.Parallel()
			h, err := Hash(f.Tool)
			if err != nil {
				t.Fatalf("Hash() error = %v", err)
			}
			if !hashFormat.MatchString(h) {
				t.Errorf("Hash() = %q, want %s:<64 lowercase hex digits>", h, HashVersion)
			}
			canon, err := Canonical(f.Tool)
			if err != nil {
				t.Fatalf("Canonical() error = %v", err)
			}
			sum := sha256.Sum256(canon)
			if want := HashVersion + ":" + hex.EncodeToString(sum[:]); h != want {
				t.Errorf("Hash() = %q, want HashVersion:hex(sha256(Canonical())) = %q", h, want)
			}
		})
	}
}

func TestHashKnownAnswer(t *testing.T) {
	t.Parallel()
	// Computed outside Go with:
	//   printf '%s' '{"annotations":{"destructiveHint":null,"idempotentHint":null,"openWorldHint":null,"readOnlyHint":null,"title":""},"description":"","inputSchema":null,"name":"x","outputSchema":null,"title":""}' | shasum -a 256
	const want = "sha256-v1:fc7144327c0193d2cddd15ff7bdd991773e2166f3b837e24ee1999631ff22423"
	got, err := Hash(inspect.Tool{Name: "x"})
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if got != want {
		t.Errorf("Hash(Tool{Name: \"x\"}) = %q, want %q", got, want)
	}
}

// TestHashKeyOrder checks that the hash does not depend on the key order or
// the whitespace of the schemas.
func TestHashKeyOrder(t *testing.T) {
	t.Parallel()
	for i, f := range loadHashFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			t.Parallel()
			want, err := Hash(f.Tool)
			if err != nil {
				t.Fatalf("Hash() error = %v", err)
			}
			r := rand.New(rand.NewPCG(58, uint64(i))) //nolint:gosec // G404: fixed seed for a reproducible test shuffle, not for security
			for n := range 200 {
				shuffled := f.Tool
				if shuffled.InputSchema != nil {
					shuffled.InputSchema = shuffleJSON(t, f.Tool.InputSchema, r)
				}
				if shuffled.OutputSchema != nil {
					shuffled.OutputSchema = shuffleJSON(t, f.Tool.OutputSchema, r)
				}
				got, err := Hash(shuffled)
				if err != nil {
					t.Fatalf("shuffle %d: Hash() error = %v", n, err)
				}
				if got != want {
					t.Fatalf("shuffle %d: Hash() = %q, want %q\ninputSchema: %q\noutputSchema: %q",
						n, got, want, shuffled.InputSchema, shuffled.OutputSchema)
				}
			}
		})
	}
}

// TestHashMutations checks that every small change to a tool changes its
// hash: one character in a text field or a schema, an invisible character,
// a hint, and the order of a schema array.
func TestHashMutations(t *testing.T) {
	t.Parallel()
	for _, f := range loadHashFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			t.Parallel()
			orig, err := Hash(f.Tool)
			if err != nil {
				t.Fatalf("Hash() error = %v", err)
			}
			for _, m := range hashMutations(t, f.Tool) {
				got, err := Hash(m.tool)
				if err != nil {
					t.Errorf("%s: Hash() error = %v", m.name, err)
					continue
				}
				if got == orig {
					t.Errorf("%s: Hash() = %q, the same as for the original tool", m.name, got)
				}
			}
			// The mutations must not change the fixture through shared memory.
			again, err := Hash(f.Tool)
			if err != nil {
				t.Fatalf("Hash() of the original tool: error = %v", err)
			}
			if again != orig {
				t.Errorf("Hash() of the original tool changed to %q, want %q", again, orig)
			}
		})
	}
}

// TestHashFalseHintIsNil checks that false and nil give the same hash for
// readOnlyHint and idempotentHint (see Canonical).
func TestHashFalseHintIsNil(t *testing.T) {
	t.Parallel()
	for _, f := range loadHashFixtures(t) {
		for _, h := range hashHints {
			if !h.falseIsNull {
				continue
			}
			t.Run(f.Name+"/"+h.field, func(t *testing.T) {
				t.Parallel()
				set := func(v *bool) string {
					m := hashMutated(f.Tool, "", func(c *inspect.Tool) { *h.ptr(hashAnnotations(c)) = v })
					got, err := Hash(m.tool)
					if err != nil {
						t.Fatalf("Hash() error = %v", err)
					}
					return got
				}
				if isNil, isFalse := set(nil), set(new(false)); isNil != isFalse {
					t.Errorf("Hash() with %s nil = %q, with false = %q, want equal", h.field, isNil, isFalse)
				}
			})
		}
	}
}
