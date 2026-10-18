package discover_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// leakyURL holds the URL canary in the userinfo and in a query value, so a
// test catches a leak of either part.
const leakyURL = "https://user:" + discovertest.CanaryURL +
	"@example.com/mcp?api_key=" + discovertest.CanaryURL

// fmtVerbs are the fmt verbs that the Secret and URL format tests print
// with. Secret and URL implement fmt.Formatter, so fmt passes every verb,
// even %d and %x, to their Format methods.
var fmtVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%p", "%T", "%10v", "%-10s"}

// slogHandlers are the log/slog handlers that the slog tests log through.
var slogHandlers = []struct {
	name       string
	newHandler func(*bytes.Buffer) slog.Handler
}{
	{name: "text", newHandler: func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) }},
	{name: "json", newHandler: func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) }},
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

// httpServer returns a remote project Server whose URL (leakyURL) and header
// value contain canaries.
func httpServer() discover.Server {
	return discover.Server{
		Name:        "remote",
		Client:      discover.ClientCursor,
		Scope:       discover.ScopeProject,
		ProjectPath: "/work/project", // only a string: nothing reads this path
		Source:      "/work/project/.cursor/mcp.json",
		Transport:   discover.TransportHTTP,
		URL:         discover.NewURL(leakyURL),
		Headers: discover.SecretMap{
			"Authorization": discover.NewSecret("Bearer " + discovertest.CanaryHeader),
		},
	}
}

// renderFunc turns a Server into the text a user could see.
type renderFunc func(t *testing.T, s discover.Server) string

// namedRender is a renderFunc with the subtest name that it runs under.
type namedRender struct {
	name   string
	render renderFunc
}

// serverHolder keeps a Server in an exported field. fmt walks into the field
// by reflection and, because every field on the path is exported, it can
// call the Format methods of the URL and Secret fields inside it.
type serverHolder struct {
	Server discover.Server
}

// formatRender prints the Server with fmt.Sprintf and verb.
func formatRender(verb string) renderFunc {
	return func(_ *testing.T, s discover.Server) string {
		return fmt.Sprintf(verb, s)
	}
}

// jsonRender encodes the Server with json.Marshal.
func jsonRender(t *testing.T, s discover.Server) string {
	t.Helper()
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(out)
}

// slogRender logs one attr with the handler that newHandler returns and
// gives the log text. value turns the Server into the attr value, so a test
// can log a Server (asValue) or a *Server (asPointer).
func slogRender(newHandler func(*bytes.Buffer) slog.Handler, value func(s discover.Server) any) renderFunc {
	return func(_ *testing.T, s discover.Server) string {
		var buf bytes.Buffer
		slog.New(newHandler(&buf)).Info("server found", slog.Any("server", value(s)))
		return buf.String()
	}
}

// asValue gives the Server itself as a slog attr value.
func asValue(s discover.Server) any { return s }

// asPointer gives a pointer to a copy of the Server as a slog attr value.
func asPointer(s discover.Server) any { return &s }

// serverRenders returns every way that TestServerNoLeak turns a Server into
// output: fmt verbs, JSON, fmt through containers and log/slog.
func serverRenders() []namedRender {
	renders := []namedRender{
		{name: "%v", render: formatRender("%v")},
		{name: "%+v", render: formatRender("%+v")},
		{name: "%#v", render: formatRender("%#v")},
		{name: "%s", render: formatRender("%s")},
		{name: "json", render: jsonRender},
		// A *Server goes through a different fmt path (fmt prints &{...}).
		{name: "pointer %+v", render: func(_ *testing.T, s discover.Server) string {
			return fmt.Sprintf("%+v", &s)
		}},
		{name: "error %+v", render: func(_ *testing.T, s discover.Server) string {
			return fmt.Errorf("x: %+v", s).Error()
		}},
		{name: "slice", render: func(_ *testing.T, s discover.Server) string {
			return fmt.Sprint([]discover.Server{s})
		}},
		{name: "map %+v", render: func(_ *testing.T, s discover.Server) string {
			return fmt.Sprintf("%+v", map[string]discover.Server{s.Name: s})
		}},
		{name: "exported field %+v", render: func(_ *testing.T, s discover.Server) string {
			return fmt.Sprintf("%+v", serverHolder{Server: s})
		}},
	}
	for _, h := range slogHandlers {
		renders = append(renders,
			namedRender{name: "slog " + h.name, render: slogRender(h.newHandler, asValue)},
			namedRender{name: "slog " + h.name + " pointer", render: slogRender(h.newHandler, asPointer)},
		)
	}
	return renders
}
