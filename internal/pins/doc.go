// Package pins stores the pins of MCP tools in pins.json, so that a changed
// tool (rug-pull) can be found on a later run.
//
// The store is a JSON file with a format version (CurrentVersion). A file with
// a newer version is refused with ErrUnsupportedVersion and is never
// overwritten. The file is $XDG_CONFIG_HOME/mcpmoat/pins.json when
// XDG_CONFIG_HOME is an absolute path, and ~/.config/mcpmoat/pins.json
// otherwise (DefaultPath). It is written atomically (temp file, sync, rename)
// with mode 0600 in a directory of mode 0700.
//
// A hash is an opaque string for the store. The file holds server identities
// (client, config path, project path, name), tool names and hashes. It holds no
// secret value: no env, headers, args or URLs.
//
// Canonical hashing and change detection (new, removed and changed tools) are
// not part of the store yet.
//
// See docs/PRD.md, FR-11 to FR-13.
package pins
