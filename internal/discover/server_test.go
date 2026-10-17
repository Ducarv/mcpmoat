package discover_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// stdioServer returns a stdio Server whose env value is a canary. Each call
// returns a new Server, so tests can change the result safely.
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

// remoteURL is the URL of httpServer. It holds the URL canary in the
// userinfo and in a query value, so a test catches a leak of either part.
const remoteURL = "https://user:" + discovertest.CanaryURL +
	"@example.com/mcp?api_key=" + discovertest.CanaryURL

// httpServer returns a remote Server whose URL and header value contain
// canaries.
func httpServer() discover.Server {
	return discover.Server{
		Name:      "remote",
		Client:    discover.ClientCursor,
		Scope:     discover.ScopeProject,
		Source:    "/tmp/x/.cursor/mcp.json",
		Transport: discover.TransportHTTP,
		URL:       discover.NewURL(remoteURL),
		Headers: discover.SecretMap{
			"Authorization": discover.NewSecret("Bearer " + discovertest.CanaryHeader),
		},
	}
}

// TestServerNoLeak checks the issue #16 acceptance criterion: printing,
// logging or encoding a Server never shows an env value, a header value or
// the credentials in its URL, but still shows the key name, the URL host and
// Mask in their place.
func TestServerNoLeak(t *testing.T) {
	t.Parallel()

	// Each render function turns a Server into the text a user could see.
	type render func(t *testing.T, s discover.Server) string

	formatRender := func(verb string) render {
		return func(_ *testing.T, s discover.Server) string {
			return fmt.Sprintf(verb, s)
		}
	}
	jsonRender := func(t *testing.T, s discover.Server) string {
		t.Helper()
		out, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		return string(out)
	}
	// slogRender logs one attr with the handler that newHandler returns and
	// gives the log text. value turns the Server into the attr value, so a
	// test can log a Server or a *Server.
	slogRender := func(
		newHandler func(*bytes.Buffer) slog.Handler,
		value func(s discover.Server) any,
	) render {
		return func(_ *testing.T, s discover.Server) string {
			var buf bytes.Buffer
			slog.New(newHandler(&buf)).Info("server found", slog.Any("server", value(s)))
			return buf.String()
		}
	}
	textHandler := func(buf *bytes.Buffer) slog.Handler { return slog.NewTextHandler(buf, nil) }
	jsonHandler := func(buf *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(buf, nil) }
	asValue := func(s discover.Server) any { return s }
	asPointer := func(s discover.Server) any { return &s }

	// holder keeps a Server in an exported field. fmt walks into the field
	// by reflection and, because every field on the path is exported, it can
	// call the Format methods of the URL and Secret fields inside it.
	type holder struct {
		Server discover.Server
	}

	servers := []struct {
		name   string
		server discover.Server
		key    string // the env or header name that must stay visible
		host   string // the URL host that must stay visible, or "" for none
	}{
		{name: "stdio", server: stdioServer(), key: "API_KEY"},
		{name: "http", server: httpServer(), key: "Authorization", host: "example.com"},
	}
	renders := []struct {
		name   string
		render render
	}{
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
			return fmt.Sprintf("%+v", holder{Server: s})
		}},
		{name: "slog text", render: slogRender(textHandler, asValue)},
		{name: "slog text pointer", render: slogRender(textHandler, asPointer)},
		{name: "slog json", render: slogRender(jsonHandler, asValue)},
		{name: "slog json pointer", render: slogRender(jsonHandler, asPointer)},
	}

	for _, sv := range servers {
		for _, r := range renders {
			t.Run(sv.name+"/"+r.name, func(t *testing.T) {
				t.Parallel()
				out := r.render(t, sv.server)

				discovertest.AssertNoLeak(t, r.name+" output", out)
				if !strings.Contains(out, sv.key) {
					t.Errorf("output does not contain key %q; output:\n%s", sv.key, out)
				}
				if !strings.Contains(out, discover.Mask) {
					t.Errorf("output does not contain Mask %q; output:\n%s", discover.Mask, out)
				}
				if sv.host != "" && !strings.Contains(out, sv.host) {
					t.Errorf("output does not contain host %q; output:\n%s", sv.host, out)
				}
			})
		}
	}
}

// TestServerUnexportedFieldNoLeak checks a Server held in an unexported
// field of another struct. fmt cannot call methods on an unexported field
// (reflect CanInterface is false), so it prints the Server fields by
// reflection. URL and Secret keep their values behind a pointer, so fmt
// prints only addresses and no canary appears.
func TestServerUnexportedFieldNoLeak(t *testing.T) {
	t.Parallel()

	type wrapper struct{ s discover.Server }

	verbs := []string{"%v", "%+v", "%#v"}
	servers := []struct {
		name   string
		server discover.Server
	}{
		{name: "stdio", server: stdioServer()},
		{name: "http", server: httpServer()},
	}
	for _, sv := range servers {
		for _, verb := range verbs {
			t.Run(sv.name+"/"+verb, func(t *testing.T) {
				t.Parallel()
				out := fmt.Sprintf(verb, wrapper{s: sv.server})
				discovertest.AssertNoLeak(t, "unexported field "+verb+" output", out)
			})
		}
	}
}

// TestServerBadVerbNoLeak checks the fmt paths that skip every method. %p on
// a struct and %w on a value that is not an error are bad verbs: fmt prints
// "%!p(...)" or "%!w(...)" and shows the fields by reflection without
// calling Format or String on them. Only the pointers inside URL and Secret
// show, so no canary appears. (%p with a *Server is valid and prints only an
// address.)
func TestServerBadVerbNoLeak(t *testing.T) {
	t.Parallel()

	// The formats are in a table on purpose: go vet's printf check reports a
	// constant "%p" or "%w" format with a Server argument, and here the bad
	// verb is what the test checks.
	formats := []string{"%p", "%w", "%+p", "%#w"}
	servers := []struct {
		name   string
		server discover.Server
	}{
		{name: "stdio", server: stdioServer()},
		{name: "http", server: httpServer()},
	}
	for _, sv := range servers {
		for _, format := range formats {
			t.Run(sv.name+"/"+format, func(t *testing.T) {
				t.Parallel()
				s := sv.server
				outputs := map[string]string{
					"Sprintf value":   fmt.Sprintf(format, s),
					"Sprintf pointer": fmt.Sprintf(format, &s),
					"Errorf value":    fmt.Errorf(format, s).Error(),
					"Errorf pointer":  fmt.Errorf(format, &s).Error(),
				}
				for name, out := range outputs {
					discovertest.AssertNoLeak(t, name+" "+format, out)
				}
			})
		}
	}
}

// TestServerEmbeddedNoLeak checks a Server embedded in another struct. fmt
// and encoding/json treat the embedded Server as a field (json promotes its
// fields), so the URL and Secret types still mask the values, and the outer
// field N must still appear.
func TestServerEmbeddedNoLeak(t *testing.T) {
	t.Parallel()

	type outer struct {
		discover.Server
		N int
	}

	tests := []struct {
		name   string
		render func() (string, error)
		wantIn []string
	}{
		{
			name:   "%+v",
			render: func() (string, error) { return fmt.Sprintf("%+v", outer{Server: httpServer(), N: 42}), nil },
			wantIn: []string{"N:42", "URL:" + discover.RedactURL(remoteURL), discover.Mask},
		},
		{
			name: "json",
			render: func() (string, error) {
				b, err := json.Marshal(outer{Server: httpServer(), N: 42})
				return string(b), err
			},
			wantIn: []string{`"N":42`, `"URL":`, "example.com", discover.Mask},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := tt.render()
			if err != nil {
				t.Fatalf("render error = %v", err)
			}
			discovertest.AssertNoLeak(t, tt.name+" output", out)
			for _, want := range tt.wantIn {
				if !strings.Contains(out, want) {
					t.Errorf("output does not contain %q; output:\n%s", want, out)
				}
			}
		})
	}
}

// TestServerSlogNilPointer logs a nil *Server. The handlers must not call a
// method on the nil pointer; slog reports a panic in a method as text that
// contains "panicked".
func TestServerSlogNilPointer(t *testing.T) {
	t.Parallel()

	handlers := []struct {
		name     string
		make     func(*bytes.Buffer) slog.Handler
		wantAttr string // how the handler shows the nil pointer
	}{
		{
			name:     "text",
			make:     func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
			wantAttr: "server=<nil>",
		},
		{
			name:     "json",
			make:     func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
			wantAttr: `"server":null`,
		},
	}
	for _, h := range handlers {
		t.Run(h.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			var s *discover.Server
			slog.New(h.make(&buf)).Info("server found", slog.Any("server", s))
			out := buf.String()
			if strings.Contains(out, "panicked") || strings.Contains(out, "PANIC") {
				t.Errorf("log output reports a panic; output:\n%s", out)
			}
			if !strings.Contains(out, h.wantAttr) {
				t.Errorf("log output does not contain %q; output:\n%s", h.wantAttr, out)
			}
		})
	}
}

// TestServerFieldNames checks how fmt's default struct printing shows a
// Server: %+v shows field names and %v does not. In both, the URL field
// type prints the redacted URL.
func TestServerFieldNames(t *testing.T) {
	t.Parallel()

	redactedURL := discover.RedactURL(remoteURL)
	tests := []struct {
		name      string
		verb      string
		wantIn    []string
		wantNotIn []string
	}{
		{
			name:   "plus flag shows field names",
			verb:   "%+v",
			wantIn: []string{"URL:" + redactedURL, "Name:remote"},
		},
		{
			name:      "no flag hides field names",
			verb:      "%v",
			wantIn:    []string{redactedURL},
			wantNotIn: []string{"URL:", "Name:"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := fmt.Sprintf(tt.verb, httpServer())
			discovertest.AssertNoLeak(t, "Sprintf("+tt.verb+")", out)
			for _, want := range tt.wantIn {
				if !strings.Contains(out, want) {
					t.Errorf("Sprintf(%q) does not contain %q; output:\n%s", tt.verb, want, out)
				}
			}
			for _, unwanted := range tt.wantNotIn {
				if strings.Contains(out, unwanted) {
					t.Errorf("Sprintf(%q) contains %q; output:\n%s", tt.verb, unwanted, out)
				}
			}
		})
	}
}

// TestConstantStrings pins the string values of Client, Scope and Transport.
// JSON output uses them, so a change breaks users' scripts.
func TestConstantStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "ClientClaudeCode", got: string(discover.ClientClaudeCode), want: "claude-code"},
		{name: "ClientCursor", got: string(discover.ClientCursor), want: "cursor"},
		{name: "ClientCodex", got: string(discover.ClientCodex), want: "codex"},
		{name: "ScopeGlobal", got: string(discover.ScopeGlobal), want: "global"},
		{name: "ScopeProject", got: string(discover.ScopeProject), want: "project"},
		{name: "TransportStdio", got: string(discover.TransportStdio), want: "stdio"},
		{name: "TransportHTTP", got: string(discover.TransportHTTP), want: "http"},
		{name: "TransportSSE", got: string(discover.TransportSSE), want: "sse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestTransportIsRemote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport discover.Transport
		want      bool
	}{
		{name: "stdio", transport: discover.TransportStdio, want: false},
		{name: "http", transport: discover.TransportHTTP, want: true},
		{name: "sse", transport: discover.TransportSSE, want: true},
		{name: "empty", transport: "", want: false},
		{name: "unknown", transport: discover.Transport("unknown"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.transport.IsRemote(); got != tt.want {
				t.Errorf("Transport(%q).IsRemote() = %v, want %v", tt.transport, got, tt.want)
			}
		})
	}
}

// TestServerDeepEqual checks that reflect.DeepEqual compares the values
// behind Secrets and URLs, not their addresses. Each NewSecret call stores
// its value at a new address, so a pointer comparison would report false for
// equal Servers.
func TestServerDeepEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(s *discover.Server)
		want   bool
	}{
		{
			name:   "same values",
			change: func(*discover.Server) {},
			want:   true,
		},
		{
			name: "different env value",
			change: func(s *discover.Server) {
				s.Env = discover.SecretMap{"API_KEY": discover.NewSecret("other-value")}
			},
			want: false,
		},
		{
			name: "same env value, new Secret",
			change: func(s *discover.Server) {
				s.Env = discover.SecretMap{"API_KEY": discover.NewSecret(discovertest.CanaryEnv)}
			},
			want: true,
		},
		{
			name: "different URL",
			change: func(s *discover.Server) {
				s.URL = discover.NewURL("https://example.com/mcp")
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := stdioServer()
			b := stdioServer()
			tt.change(&b)
			if got := reflect.DeepEqual(a, b); got != tt.want {
				t.Errorf("reflect.DeepEqual(a, b) = %v, want %v", got, tt.want)
			}
		})
	}
}
