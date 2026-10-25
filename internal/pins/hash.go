package pins

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// HashVersion names the hash algorithm and the canonical form that Hash uses.
// It is the prefix of every hash.
//
// Any change to the field set, the shape or the canonicalisation of the
// canonical form (see Canonical) needs a new version, because the same
// tool then gets a different hash. Hash computes only the current version,
// so a stored hash with another prefix cannot be compared. The store must
// then show the tool as not verified and pin it again. It must never accept
// the tool silently: a rug pull at the same time would become the new pin.
//
// The canonical form changed in place before the first release (issue #153
// added _meta and icons), so the version stays sha256-v1.
const HashVersion = "sha256-v1"

// Hash returns the pin hash of t: HashVersion, a colon, and the lowercase
// hex SHA-256 of Canonical(t). For example:
//
//	sha256-v1:<64 lowercase hex digits>
//
// Hash returns the error of Canonical when t has no canonical form. The error
// wraps ErrInvalidTool. A caller must then show the tool as not verified. It
// must never skip the tool: a server could then avoid the pin.
func Hash(t inspect.Tool) (string, error) {
	b, err := Canonical(t)
	if err != nil {
		return "", err
	}
	return hashCanonical(b), nil
}

// hashCanonical returns the pin hash of a canonical form: HashVersion, a
// colon, and the lowercase hex SHA-256 of canonical. Hash and the pin check in
// Compare both use it, so the algorithm is written once.
func hashCanonical(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return HashVersion + ":" + hex.EncodeToString(sum[:])
}
