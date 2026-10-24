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
// canonical form (see canonical.go) needs a new version, because the same
// tool then gets a different hash. A stored hash with another prefix means
// that the algorithm changed, not that the tool changed. The tool must then
// be pinned again. It is not a rug pull.
const HashVersion = "sha256-v1"

// Hash returns the pin hash of t: HashVersion, a colon, and the lowercase
// hex SHA-256 of Canonical(t). For example:
//
//	sha256-v1:<64 lowercase hex digits>
//
// Hash returns the error of Canonical when t has no canonical form. The error
// wraps ErrInvalidTool.
func Hash(t inspect.Tool) (string, error) {
	b, err := Canonical(t)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	// sum is an array, so sum[:] gives the slice that EncodeToString needs.
	return HashVersion + ":" + hex.EncodeToString(sum[:]), nil
}
