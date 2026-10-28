package inspect

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// The values in this file are fake test values, not real credentials.

// shortPasswordURL returns "https://u:pw12@h.example/mcp", a URL with a
// short password. url.UserPassword builds it, so no string literal holds
// the user info.
func shortPasswordURL() string {
	u := url.URL{Scheme: "https", User: url.UserPassword("u", "pw12"), Host: "h.example", Path: "/mcp"}
	return u.String()
}

// TestClassifyShortURLSecrets checks that a short secret of the configured
// URL goes from failure text also when the server echoes it alone, not in
// URL form: a query value, the value of a matrix parameter, the value inside
// a "key=value" path segment and a short password. Before the fix, only the
// password was in a list (userinfoSecrets), and the other values stayed.
func TestClassifyShortURLSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		raw   string
		value string
	}{
		{name: "query value", raw: "https://h.example/mcp?key=abc12", value: "abc12"},
		{name: "matrix parameter", raw: "https://h.example/mcp;token=abc12", value: "abc12"},
		{name: "key=value segment", raw: "https://h.example/apikey=abc12/mcp", value: "abc12"},
		{name: "user info password", raw: shortPasswordURL(), value: "pw12"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := discover.Server{Name: "remote", Transport: discover.TransportHTTP, URL: discover.NewURL(tt.raw)}
			u, err := url.Parse(tt.raw)
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			lists := remoteSecretLists(srv, u, secretLists{})

			ce := classify(errors.New("server said: abc12 pw12 is invalid"), srv, nil, lists)
			if strings.Contains(ce.Error(), tt.value) {
				t.Errorf("error text %q holds the URL value", ce.Error())
			}
			if cause := errors.Unwrap(ce); cause == nil || strings.Contains(cause.Error(), tt.value) {
				t.Errorf("cause %v holds the URL value, or is nil", cause)
			}
			// SDKInspector.Inspect gives showDiscoveredURL the list of
			// remoteShortSecrets, so it must hold the value too.
			if short := remoteShortSecrets(srv, secretLists{}); !slices.Contains(short, tt.value) && !slices.Contains(lists.long, tt.value) {
				t.Errorf("remoteShortSecrets() and the long list do not hold the URL value")
			}
		})
	}
}

// TestURLShortSecrets checks the list of urlShortSecrets: only the pieces
// under discover.MinSecretBytes, each one time, and nothing for a URL with
// no secret part.
func TestURLShortSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want []string
	}{
		{raw: "https://h.example/mcp?key=abc12", want: []string{"abc12"}},
		// The matrix parameter gives "abc12" twice; the list holds it once.
		{raw: "https://h.example/mcp;token=abc12", want: []string{"abc12"}},
		{raw: "https://h.example/apikey=abc12/mcp", want: []string{"abc12"}},
		{raw: shortPasswordURL(), want: []string{"u:pw12", "pw12"}},
		// A long value is in urlSecrets, not here.
		{raw: "https://h.example/mcp?key=abcdefgh12345", want: nil},
		{raw: "http://localhost:8080/sse", want: nil},
	}
	for _, tt := range tests {
		if got := urlShortSecrets(tt.raw); !slices.Equal(got, tt.want) {
			t.Errorf("urlShortSecrets(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

// TestScrubPerByteForm checks that a secret that is not valid UTF-8 also
// goes from failure text in the form that a JSON decoder gives: one U+FFFD
// for each invalid byte. A server that echoes the value in a JSON-RPC error
// sends that form.
func TestScrubPerByteForm(t *testing.T) {
	t.Parallel()

	value := "ab\xffcd\xfeefgh"
	// Decode the value as a JSON string, as the SDK decodes an error message.
	var decoded string
	if err := json.Unmarshal([]byte(`"`+value+`"`), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if want := "ab�cd�efgh"; decoded != want {
		t.Fatalf("decoded form = %q, want %q", decoded, want)
	}

	srv := discover.Server{Name: "remote", Transport: discover.TransportHTTP, URL: discover.NewURL("https://h.example/mcp")}
	lists := secretLists{long: []string{value}}
	for _, text := range []string{"invalid key " + decoded, "invalid key " + value} {
		ce := classify(errors.New(text), srv, nil, lists)
		want := "invalid key " + discover.Mask
		if ce.Reason != want {
			t.Errorf("Reason = %q, want %q", ce.Reason, want)
		}
		if cause := errors.Unwrap(ce); cause == nil || cause.Error() != want {
			t.Errorf("cause = %v, want %q", cause, want)
		}
	}
}

// TestShowDiscoveredURLKeepsFixedText checks that showDiscoveredURL scrubs
// only the text that came from the cause, not the fixed text of mcpmoat. The
// path is ${EP} with the value "sse", a short value, and the reason of an
// HTTP 404 ends with "set type = sse". Before the fix, the whole-word scrub
// of the whole Reason gave "set type = ********".
func TestShowDiscoveredURLKeepsFixedText(t *testing.T) {
	t.Parallel()

	expanded := discover.Server{Name: "remote", Transport: discover.TransportHTTP, URL: discover.NewURL("http://localhost:8080/sse")}
	discovered := discover.NewURL("http://localhost:8080/${EP}")
	lookedUp := secretLists{short: []string{"sse"}}
	u, err := url.Parse(expanded.URL.Reveal())
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	lists := remoteSecretLists(expanded, u, lookedUp)
	short := remoteShortSecrets(expanded, lookedUp)

	t.Run("fixed reason", func(t *testing.T) {
		t.Parallel()
		ce := classify(errors.New("HTTP 404"), expanded, &fakeEvents{status: http.StatusNotFound}, lists)
		want := "HTTP 404; the server may use the legacy SSE transport; set type = sse"
		if ce.Reason != want {
			t.Fatalf("Reason from classify = %q, want %q", ce.Reason, want)
		}
		showDiscoveredURL(ce, expanded.URL, discovered, short)
		if ce.Reason != want {
			t.Errorf("Reason = %q, want %q", ce.Reason, want)
		}
		if ce.URL != discovered.String() {
			t.Errorf("URL = %q, want the discovered URL %q", ce.URL, discovered.String())
		}
	})

	t.Run("text of the cause", func(t *testing.T) {
		t.Parallel()
		// The cause text still gets the URL replaced and the short value
		// masked.
		cause := &fakeNetError{text: "dial " + expanded.URL.String() + ": sse refused"}
		ce := classify(cause, expanded, nil, lists)
		showDiscoveredURL(ce, expanded.URL, discovered, short)
		want := "network error: dial " + discovered.String() + ": " + discover.Mask + " refused"
		if ce.Reason != want {
			t.Errorf("Reason = %q, want %q", ce.Reason, want)
		}
	})
}

// TestShowDiscoveredURLAfterCut checks that showDiscoveredURL finds an
// expanded URL that the cut of classify would have split. The text before the
// URL is long, so the 200-rune cut ends inside the host. Before the fix,
// showDiscoveredURL worked on the cut Reason and left the start of the host.
func TestShowDiscoveredURLAfterCut(t *testing.T) {
	t.Parallel()

	expanded := discover.Server{Name: "remote", Transport: discover.TransportHTTP, URL: discover.NewURL("https://internal-secret-host.corp.example/mcp")}
	discovered := discover.NewURL("https://${HOST}/mcp")
	cause := &fakeNetError{text: strings.Repeat("x", 170) + " Post " + expanded.URL.String() + ": boom"}

	ce := classify(cause, expanded, nil, secretLists{})
	showDiscoveredURL(ce, expanded.URL, discovered, nil)

	if strings.Contains(ce.Reason, "internal") || strings.Contains(ce.Reason, "corp.example") {
		t.Errorf("Reason = %q, want no part of the expanded host", ce.Reason)
	}
	if want := "network error: " + strings.Repeat("x", 170) + " Post " + discovered.String() + ": boom"; ce.Reason != want {
		t.Errorf("Reason = %q, want %q", ce.Reason, want)
	}
}
