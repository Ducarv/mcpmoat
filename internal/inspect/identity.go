package inspect

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Client identities that mcpmoat sends in the MCP initialize request, one for
// each AI client (issue #97). The names are the ones that the real clients
// send. The versions are fixed values that look like a real release. mcpmoat
// cannot know the version that the user has installed, so they can be out of
// date.
const (
	// claudeCodeName and claudeCodeVersion are the identity of Claude Code.
	claudeCodeName    = "claude-code"
	claudeCodeVersion = "2.1.0"

	// cursorName and cursorVersion are the identity of Cursor.
	cursorName    = "cursor-vscode"
	cursorVersion = "1.0.0"

	// codexName, codexTitle and codexVersion are the identity of the Codex
	// CLI. Codex also sends a title.
	codexName    = "codex-mcp-client"
	codexTitle   = "Codex"
	codexVersion = "0.50.0"
)

// clientIdentity returns the client identity that mcpmoat sends to a server
// that c declared. It returns a new value on each call, so a caller can change
// it without an effect on other connections.
//
// mcpmoat sends the identity of the client that declared the server, not its
// own name. A hostile server can read the name in the initialize request (and,
// on the new protocol, in the _meta of every request). If it sees a scanner
// name, it can hide its tools or show a clean list, and show the poisoned list
// to the real client (threat T1). With the client's own name, the server sees
// what the real client sends.
//
// For a client that mcpmoat does not know, clientIdentity returns the neutral
// identity clientName and clientVersion. It never names mcpmoat.
//
// This does not stop all fingerprinting. A server can still tell mcpmoat from
// the real client by:
//   - the version, which is fixed and can differ from the installed release;
//   - the client capabilities, which are not the ones of the real client;
//   - the timing and the order of the requests (mcpmoat sends all the list
//     requests one after the other, right after the handshake);
//   - the HTTP User-Agent of a remote connection.
//
// See docs/PRD.md section 5.5.
func clientIdentity(c discover.Client) *mcp.Implementation {
	switch c {
	case discover.ClientClaudeCode:
		return &mcp.Implementation{Name: claudeCodeName, Version: claudeCodeVersion}
	case discover.ClientCursor:
		return &mcp.Implementation{Name: cursorName, Version: cursorVersion}
	case discover.ClientCodex:
		return &mcp.Implementation{Name: codexName, Title: codexTitle, Version: codexVersion}
	default:
		return &mcp.Implementation{Name: clientName, Version: clientVersion}
	}
}
