package inspect

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// identityVersion is the shape of a release version: three dot-separated
// numbers, as the real clients send.
var identityVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// TestClientIdentity checks the identity that mcpmoat sends for each client
// (issue #97). The names and titles are written out here, not read from the
// constants, so a change of a name fails the test: a server compares them
// with the names that the real clients send. The versions are fixed values
// that change with the releases of the clients, so the test reads them from
// the constants and checks only their shape.
func TestClientIdentity(t *testing.T) {
	t.Parallel()

	neutral := mcp.Implementation{Name: "mcp-client", Version: "1.0.0"}

	tests := []struct {
		name   string
		client discover.Client
		want   mcp.Implementation
	}{
		{
			name:   "claude code",
			client: discover.ClientClaudeCode,
			want:   mcp.Implementation{Name: "claude-code", Version: claudeCodeVersion},
		},
		{
			name:   "cursor",
			client: discover.ClientCursor,
			want:   mcp.Implementation{Name: "cursor-vscode", Version: cursorVersion},
		},
		{
			name:   "codex",
			client: discover.ClientCodex,
			want:   mcp.Implementation{Name: "codex-mcp-client", Title: "Codex", Version: codexVersion},
		},
		// Every other value gets the neutral identity. The match is exact:
		// a case or space variant is not a known client.
		{name: "unknown client", client: discover.Client("windsurf"), want: neutral},
		{name: "empty client", client: discover.Client(""), want: neutral},
		{name: "case variant", client: discover.Client("Claude-Code"), want: neutral},
		{name: "upper case cursor", client: discover.Client("CURSOR"), want: neutral},
		{name: "trailing space", client: discover.Client("codex "), want: neutral},
		{name: "mcpmoat", client: discover.Client("mcpmoat"), want: neutral},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := clientIdentity(tt.client)
			if got == nil {
				t.Fatalf("clientIdentity(%q) = nil", tt.client)
			}
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("clientIdentity(%q) = %+v, want %+v", tt.client, *got, tt.want)
			}
			if !identityVersion.MatchString(got.Version) {
				t.Errorf("clientIdentity(%q).Version = %q, want a version like 1.2.3", tt.client, got.Version)
			}
		})
	}
}

// TestClientIdentityNeverNamesMcpmoat checks that no identity, in no field,
// tells the server that the client is mcpmoat. A server that sees the
// scanner name can hide its tools (threat T1).
func TestClientIdentityNeverNamesMcpmoat(t *testing.T) {
	t.Parallel()

	clients := []discover.Client{
		discover.ClientClaudeCode,
		discover.ClientCursor,
		discover.ClientCodex,
		"",
		"unknown",
		"mcpmoat",
	}
	for _, c := range clients {
		id := clientIdentity(c)
		// The JSON form is what goes on the wire, so it covers every field.
		data, err := json.Marshal(id)
		if err != nil {
			t.Fatalf("json.Marshal(clientIdentity(%q)) error = %v", c, err)
		}
		if strings.Contains(strings.ToLower(string(data)), "mcpmoat") {
			t.Errorf("clientIdentity(%q) = %s, must not name mcpmoat", c, data)
		}
		if id.Name == "" {
			t.Errorf("clientIdentity(%q).Name is empty, want a client name", c)
		}
	}
}

// TestClientIdentityNewValue checks that each call returns a new value, so a
// change by one caller does not reach another connection.
func TestClientIdentityNewValue(t *testing.T) {
	t.Parallel()

	for _, c := range []discover.Client{discover.ClientClaudeCode, discover.ClientCursor, discover.ClientCodex, "other"} {
		first := clientIdentity(c)
		second := clientIdentity(c)
		if first == second {
			t.Errorf("clientIdentity(%q) returned the same pointer twice", c)
		}
		want := *second

		first.Name = "changed"
		first.Title = "changed"
		first.Version = "9.9.9"

		if !reflect.DeepEqual(*second, want) {
			t.Errorf("clientIdentity(%q): a change of the first value changed the second: %+v", c, *second)
		}
		if third := clientIdentity(c); !reflect.DeepEqual(*third, want) {
			t.Errorf("clientIdentity(%q) after a change = %+v, want %+v", c, *third, want)
		}
	}
}
