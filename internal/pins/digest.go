package pins

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
)

// DigestVersion names the encoding that Digest hashes. Change it whenever the
// encoding changes, so a digest from an old mcpmoat never matches a new one.
const DigestVersion = "pd1"

// digestBytes is the number of bytes of the SHA-256 sum that a digest keeps.
const digestBytes = 16

// digestHexLen is the length of the hex part of a digest.
const digestHexLen = digestBytes * 2

// Digest returns a short fingerprint of the tool set p: DigestVersion, a colon
// and 32 lowercase hex characters.
//
// The fingerprint binds a scan to a later pin --accept. A hostile server sees
// both runs and picks the tools that it shows in each, so it can search for two
// different tool sets with the same digest. A collision between two sets that
// the attacker chooses costs about 2^(n/2) work for an n-bit digest (the
// birthday bound). The digest keeps the first 128 bits of SHA-256, so that cost
// is about 2^64 and is out of reach.
//
// The input of SHA-256 is the tools sorted by name, in byte order. For each
// tool it holds the name and then the Pin.Hash, each as an unsigned varint
// (encoding/binary) with the length in bytes, followed by the bytes. A tool name
// comes from the server and may hold any byte, including a colon, a newline or
// a digit. Plain separators would let two different sets give the same input.
// A length prefix makes the encoding unambiguous: a reader always knows where a
// field ends. The map order does not matter. An empty or nil set has a defined
// digest: SHA-256 of no bytes.
//
// Digest uses Pin.Hash only. The hash already covers the whole tool, so the
// canonical text is not needed.
func Digest(p ServerPins) string {
	h := sha256.New()
	var prefix []byte
	for _, name := range slices.Sorted(maps.Keys(p)) {
		hash := p[name].Hash
		prefix = binary.AppendUvarint(prefix[:0], uint64(len(name)))
		h.Write(prefix)
		h.Write([]byte(name))
		prefix = binary.AppendUvarint(prefix[:0], uint64(len(hash)))
		h.Write(prefix)
		h.Write([]byte(hash))
	}
	sum := h.Sum(nil)
	return DigestVersion + ":" + hex.EncodeToString(sum[:digestBytes])
}

// ValidDigest reports whether s has the format that Digest returns:
// DigestVersion, a colon and exactly 32 lowercase hex characters. It does not
// check that any tool set has this digest.
func ValidDigest(s string) bool {
	rest, ok := strings.CutPrefix(s, DigestVersion+":")
	if !ok || len(rest) != digestHexLen {
		return false
	}
	for i := range len(rest) {
		c := rest[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
