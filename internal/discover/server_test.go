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

// TestServerNoLeak checks the issue #16 acceptance criterion: printing,
// logging or encoding a Server never shows an env value, a header value or
// the credentials in its URL, but still shows the key name, the URL host and
// Mask in their place. serverRenders (helpers_test.go) lists the outputs.
func TestServerNoLeak(t *testing.T) {
	t.Parallel()

	for _, sv := range testServers() {
		for _, r := range serverRenders() {
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
	for _, sv := range testServers() {
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
	for _, sv := range testServers() {
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
			wantIn: []string{"N:42", "URL:" + discover.RedactURL(leakyURL), discover.Mask},
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

	// wantAttr is how each handler shows the nil pointer.
	wantAttr := map[string]string{
		"text": "server=<nil>",
		"json": `"server":null`,
	}
	for _, h := range slogHandlers {
		t.Run(h.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			var s *discover.Server
			slog.New(h.newHandler(&buf)).Info("server found", slog.Any("server", s))
			out := buf.String()
			if strings.Contains(out, "panicked") || strings.Contains(out, "PANIC") {
				t.Errorf("log output reports a panic; output:\n%s", out)
			}
			want, ok := wantAttr[h.name]
			if !ok {
				t.Fatalf("no wantAttr for handler %q", h.name)
			}
			if !strings.Contains(out, want) {
				t.Errorf("log output does not contain %q; output:\n%s", want, out)
			}
		})
	}
}

// TestServerFieldNames checks how fmt's default struct printing shows a
// Server: %+v shows field names and %v does not. In both, the URL field
// type prints the redacted URL.
func TestServerFieldNames(t *testing.T) {
	t.Parallel()

	redactedURL := discover.RedactURL(leakyURL)
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

// TestTransportIsRemote checks that only the HTTP and SSE transports are remote.
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
