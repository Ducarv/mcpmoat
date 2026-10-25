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

// digestHexLen is the length of the hex part of a digest: the whole SHA-256
// sum.
const digestHexLen = sha256.Size * 2

// Digest returns a fingerprint of the tool set p: DigestVersion, a colon and 64
// lowercase hex characters.
//
// The fingerprint binds a scan to a later pin --accept. A hostile server sees
// both runs and picks the tools that it shows in each, so it can search for two
// different tool sets with the same digest. A collision between two sets that
// the attacker chooses costs about 2^(n/2) work for an n-bit digest (the
// birthday bound). A digest of 128 bits would cost about 2^64, which a funded
// attacker can pay. So the digest keeps the whole 256-bit sum, and a collision
// costs about 2^128. The user pastes the digest and never types it, so the
// length costs nothing.
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
	return DigestVersion + ":" + hex.EncodeToString(sum)
}

// ValidDigest reports whether s has the format that Digest returns:
// DigestVersion, a colon and exactly 64 lowercase hex characters. It does not
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
