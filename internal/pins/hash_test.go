package pins

import (
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
			r := rand.New(rand.NewPCG(testSeed, uint64(i))) //nolint:gosec // G404: fixed seed for a reproducible test shuffle, not for security
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

// TestHashRugPull checks threat T2 with the rugpull fixtures: the tool
// description changes after the pin, so the hash must change.
func TestHashRugPull(t *testing.T) {
	t.Parallel()
	hashes := map[string]string{}
	for _, f := range loadHashFixtures(t) {
		h, err := Hash(f.Tool)
		if err != nil {
			t.Fatalf("Hash(%s) error = %v", f.Name, err)
		}
		hashes[f.Name] = h
	}
	before, after := hashes["rugpull-before"], hashes["rugpull-after"]
	if before == "" || after == "" {
		t.Fatalf("tools.json must hold the fixtures rugpull-before and rugpull-after")
	}
	if before == after {
		t.Errorf("Hash() of rugpull-before and rugpull-after = %q, want different hashes", before)
	}
}

// TestHashSchemaMutationsKeyCollision checks that a changed key that matches
// a sibling key gives no mutation: a duplicate key has no hash.
func TestHashSchemaMutationsKeyCollision(t *testing.T) {
	t.Parallel()
	// The key "b" changes to "a", and "a" changes to "b".
	muts := hashSchemaMutations(t, []byte(`{"b":{},"a":{}}`))
	if len(muts) == 0 {
		t.Fatal("hashSchemaMutations() = no mutations, want the invisible-character ones")
	}
	for _, m := range muts {
		if _, err := Hash(inspect.Tool{Name: "x", InputSchema: m.schema}); err != nil {
			t.Errorf("%s: schema %s: Hash() error = %v", m.name, m.schema, err)
		}
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
// readOnlyHint and idempotentHint (see Canonical). TestCanonicalHints checks
// this on a minimal tool; this test goes through Hash, on every fixture, with
// the other annotations set.
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
					c := cloneTool(f.Tool)
					*h.ptr(ensureAnnotations(&c)) = v
					got, err := Hash(c)
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
