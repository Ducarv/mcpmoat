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
	//   printf '%s' '{"_meta":null,"annotations":{"destructiveHint":null,"idempotentHint":null,"openWorldHint":null,"readOnlyHint":null,"title":""},"description":"","icons":null,"inputSchema":null,"name":"x","outputSchema":null,"title":""}' | shasum -a 256
	const want = "sha256-v1:bfde9b2344b469ab8c510f3b0da09475d65f2ac4b2f8533b0173d748be4e256d"
	got, err := Hash(inspect.Tool{Name: "x"})
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if got != want {
		t.Errorf("Hash(Tool{Name: \"x\"}) = %q, want %q", got, want)
	}
}

// TestHashKeyOrder checks that the hash does not depend on the key order or
// the whitespace of the schemas and of _meta and icons.
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
				if shuffled.Meta != nil {
					shuffled.Meta = shuffleJSON(t, f.Tool.Meta, r)
				}
				if shuffled.Icons != nil {
					shuffled.Icons = shuffleJSON(t, f.Tool.Icons, r)
				}
				got, err := Hash(shuffled)
				if err != nil {
					t.Fatalf("shuffle %d: Hash() error = %v", n, err)
				}
				if got != want {
					t.Fatalf("shuffle %d: Hash() = %q, want %q\ninputSchema: %q\noutputSchema: %q\n_meta: %q\nicons: %q",
						n, got, want, shuffled.InputSchema, shuffled.OutputSchema, shuffled.Meta, shuffled.Icons)
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

// TestHashMetaIcons checks the acceptance rules for _meta and icons: a change
// only in _meta or only in icons changes the hash, and the key order inside
// _meta does not.
func TestHashMetaIcons(t *testing.T) {
	t.Parallel()
	base := inspect.Tool{Name: "ping"}
	withMeta := func(m string) inspect.Tool { c := base; c.Meta = []byte(m); return c }
	withIcons := func(i string) inspect.Tool { c := base; c.Icons = []byte(i); return c }

	t.Run("_meta only changes the hash", func(t *testing.T) {
		t.Parallel()
		if mustHash(t, base) == mustHash(t, withMeta(`{"ui":{"resourceUri":"ui://a"}}`)) {
			t.Error("adding _meta does not change the hash")
		}
		if mustHash(t, withMeta(`{"ui":{"resourceUri":"ui://a"}}`)) == mustHash(t, withMeta(`{"ui":{"resourceUri":"ui://b"}}`)) {
			t.Error("changing a _meta value does not change the hash")
		}
	})
	t.Run("icons only changes the hash", func(t *testing.T) {
		t.Parallel()
		if mustHash(t, base) == mustHash(t, withIcons(`[{"src":"a"}]`)) {
			t.Error("adding icons does not change the hash")
		}
		if mustHash(t, withIcons(`[{"src":"a"}]`)) == mustHash(t, withIcons(`[{"src":"b"}]`)) {
			t.Error("changing an icon src does not change the hash")
		}
		if mustHash(t, withIcons(`[{"src":"a"},{"src":"b"}]`)) == mustHash(t, withIcons(`[{"src":"b"},{"src":"a"}]`)) {
			t.Error("reordering icons does not change the hash")
		}
	})
	t.Run("_meta key order does not change the hash", func(t *testing.T) {
		t.Parallel()
		a := mustHash(t, withMeta(`{"a":1,"ui":{"resourceUri":"ui://a","visibility":["model"]}}`))
		b := mustHash(t, withMeta(`{ "ui": { "visibility": ["model"], "resourceUri": "ui://a" }, "a": 1 }`))
		if a != b {
			t.Errorf("Hash() = %q and %q, want equal for a different key order in _meta", a, b)
		}
	})
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
