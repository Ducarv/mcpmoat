// Package pins stores the pins of MCP tools in pins.json, so that a changed
// tool (rug-pull) can be found on a later run.
//
// The store is a JSON file with a format version (CurrentVersion). A file with
// a newer version is refused with ErrUnsupportedVersion and is never
// overwritten. DefaultPath gives the path, Load reads the file, Set checks and
// changes the pins of one server, and Save writes the file atomically.
//
// A hash is an opaque string for the store. The file holds server identities
// (client, config path, project path, name), tool names and hashes. It holds no
// secret value: no env, headers, args or URLs. The servers chose the tool
// names, so they are untrusted text (see ServerPins).
//
// Canonical hashing and change detection (new, removed and changed tools) are
// not part of the store yet.
//
// See docs/PRD.md, FR-11 to FR-13.
package pins
