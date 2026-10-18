package discover_test

import (
	"bytes"
	"log/slog"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// leakyURL holds the URL canary in the userinfo and in a query value, so a
// test catches a leak of either part.
const leakyURL = "https://user:" + discovertest.CanaryURL +
	"@example.com/mcp?api_key=" + discovertest.CanaryURL

// slogHandlers are the log/slog handlers that the slog tests log through.
var slogHandlers = []struct {
	name string
	make func(*bytes.Buffer) slog.Handler
}{
	{name: "text", make: func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) }},
	{name: "json", make: func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) }},
}

// noErr adapts a method that cannot fail to the func() (string, error) shape
// of the method tables.
func noErr(f func() string) func() (string, error) {
	return func() (string, error) { return f(), nil }
}

// testServer is a Server fixture with the parts of it that must stay
// visible in output.
type testServer struct {
	name   string
	server discover.Server
	key    string // the env or header name that must stay visible
	host   string // the URL host that must stay visible, or "" for none
}

// testServers returns a stdio Server and a remote Server whose secret values
// are canaries. Each call returns new Servers, so tests can change them
// safely.
func testServers() []testServer {
	return []testServer{
		{name: "stdio", server: stdioServer(), key: "API_KEY"},
		{name: "http", server: httpServer(), key: "Authorization", host: "example.com"},
	}
}

// stdioServer returns a stdio Server whose env value is a canary.
func stdioServer() discover.Server {
	return discover.Server{
		Name:      "fs",
		Client:    discover.ClientClaudeCode,
		Scope:     discover.ScopeGlobal,
		Source:    "/tmp/x/.claude.json", // only a string: nothing reads this path
		Transport: discover.TransportStdio,
		Command:   "npx",
		Args:      []string{"-y", "pkg"},
		Env:       discover.SecretMap{"API_KEY": discover.NewSecret(discovertest.CanaryEnv)},
	}
}

// httpServer returns a remote Server whose URL (leakyURL) and header value
// contain canaries.
func httpServer() discover.Server {
	return discover.Server{
		Name:      "remote",
		Client:    discover.ClientCursor,
		Scope:     discover.ScopeProject,
		Source:    "/tmp/x/.cursor/mcp.json",
		Transport: discover.TransportHTTP,
		URL:       discover.NewURL(leakyURL),
		Headers: discover.SecretMap{
			"Authorization": discover.NewSecret("Bearer " + discovertest.CanaryHeader),
		},
	}
}
