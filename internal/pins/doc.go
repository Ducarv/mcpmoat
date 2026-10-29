// Package pins stores the pins of MCP tools in pins.json, so that a changed
// tool (rug-pull) can be found on a later run.
//
// The store is a JSON file with a format version (CurrentVersion). A file with
// a newer version is refused with ErrUnsupportedVersion and is never
// overwritten. DefaultPath gives the path, Load reads the file, Get returns a
// copy of the pins of one server, Set checks and changes the pins of one
// server, and Save writes the file atomically.
//
// Load only reads and takes no lock. A run that saves loads with LoadLocked
// and holds the lock until after Save. Clone gives a copy of the store, so a
// caller can test Set on the copy without a change to the store. Load and
// LoadLocked check the path to the pins file before they read it: see
// docs/pins.md and docs/ARCHITECTURE.md.
//
// The file has a size limit, MaxFileSize (32 MiB), and one server has a limit
// too. Set refuses a server that would make the file larger (ErrStoreFull).
// The project servers, the servers whose Identity has a ProjectPath (a
// project .mcp.json, .cursor/mcp.json or a projects.<path> key of
// ~/.claude.json), may use only half of the file together, ProjectShareMiB
// (16 MiB). Set refuses a project server past that share with an error that
// wraps both ErrProjectShareFull and ErrStoreFull. A project config can come
// from a cloned repository, so the share stops it from filling the file:
// the servers of the user scope (no ProjectPath) always keep the other half.
// Both limits refuse only growth. Load reads a file whose project servers are
// over the share, for example a file from an older mcpmoat.
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
