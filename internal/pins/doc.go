// Package pins stores the pins of MCP tools in pins.json, so that a changed
// tool (rug-pull) can be found on a later run.
//
// The store is a JSON file with a format version (CurrentVersion). A file with
// a newer version is refused with ErrUnsupportedVersion and is never
// overwritten. DefaultPath gives the path, Load reads the file, Get returns a
// copy of the pins of one server, Set checks and changes the pins of one
// server, and Save writes the file atomically.
//
// The file stores per tool the hash and the canonical text (see Pin). The text
// lets a later run show a diff of a changed tool. The store treats both as
// opaque strings. The file holds server identities (client, config path,
// project path, name), tool names, hashes and canonical texts. It holds no
// secret value: no env, headers, args or URLs. The servers chose the tool
// names and the canonical texts, so they are untrusted text (see ServerPins).
//
// Canonical hashing, change detection (Compare: new, removed, changed and
// unverified tools) and the unified diff of a changed tool live in this
// package. Compare trusts the hash for its verdict, and the stored canonical
// text only for the diff, after it checks that the text matches the hash.
//
// See docs/PRD.md, FR-11 to FR-13.
package pins
