package discover_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

func TestRedactURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		// URLs with nothing to hide stay the same.
		{
			name:  "https without credentials",
			input: "https://example.com/mcp",
			want:  "https://example.com/mcp",
		},
		{
			name:  "http with port and path",
			input: "http://localhost:8080/sse",
			want:  "http://localhost:8080/sse",
		},
		{
			name:  "IPv6 host with port",
			input: "http://[::1]:8080/sse",
			want:  "http://[::1]:8080/sse",
		},
		{
			name:  "empty query",
			input: "https://h/?",
			want:  "https://h/?",
		},
		{
			name:  "normal path segments are kept",
			input: "https://h/v1/messages",
			want:  "https://h/v1/messages",
		},
		{
			name:  "date segment is kept",
			input: "https://h/api/2024-11-05/x",
			want:  "https://h/api/2024-11-05/x",
		},
		{
			name:  "trailing and double slashes are kept",
			input: "https://h//mcp/",
			want:  "https://h//mcp/",
		},
		{
			name:  "token prefix alone is kept",
			input: "https://h/sk-/xox",
			want:  "https://h/sk-/xox",
		},
		{
			name:  "empty input",
			input: "",
			want:  "",
		},

		// Userinfo: the whole part before "@" is masked, username too.
		{
			name:  "username and password",
			input: "https://user:" + discovertest.CanaryURL + "@h/x",
			want:  "https://" + discover.Mask + "@h/x",
		},
		{
			name:  "username only",
			input: "https://" + discovertest.CanaryURL + "@h",
			want:  "https://" + discover.Mask + "@h",
		},
		{
			name:  "percent-encoded username",
			input: "https://u%2A:" + discovertest.CanaryURL + "@h",
			want:  "https://" + discover.Mask + "@h",
		},
		{
			name:  "scheme-relative URL with userinfo",
			input: "//u:" + discovertest.CanaryURL + "@h/x",
			want:  "//" + discover.Mask + "@h/x",
		},

		// Path: segments that look like credentials are masked, slashes
		// stay.
		{
			name:  "canary in path",
			input: "https://h/mcp/" + discovertest.CanaryURL + "/sse",
			want:  "https://h/mcp/" + discover.Mask + "/sse",
		},
		{
			name:  "Zapier-style key in path",
			input: "https://actions.zapier.com/mcp/sk-ak-" + discovertest.CanaryURL + "/sse",
			want:  "https://actions.zapier.com/mcp/" + discover.Mask + "/sse",
		},
		{
			name:  "short key with known prefix",
			input: "https://h/mcp/ghp_abc/sse",
			want:  "https://h/mcp/" + discover.Mask + "/sse",
		},
		{
			name:  "known prefix in upper case",
			input: "https://h/SK_live/x",
			want:  "https://h/" + discover.Mask + "/x",
		},
		{
			name:  "UUID segment",
			input: "https://mcp.composio.dev/partner/123e4567-e89b-12d3-a456-426614174000/mcp",
			want:  "https://mcp.composio.dev/partner/" + discover.Mask + "/mcp",
		},
		{
			name:  "JWT segment",
			input: "https://h/eyJhbGciOiJIUzI1NiJ9.e30.sig/sse",
			want:  "https://h/" + discover.Mask + "/sse",
		},
		{
			name:  "long segment of only letters",
			input: "https://h/" + strings.Repeat("a", 32),
			want:  "https://h/" + discover.Mask,
		},
		{
			name:  "letters and digits from 20 bytes",
			input: "https://h/abcdefghijklmnopqrs1/x",
			want:  "https://h/" + discover.Mask + "/x",
		},
		{
			name:  "letters only below 32 bytes is kept",
			input: "https://h/abcdefghijklmnopqrst",
			want:  "https://h/abcdefghijklmnopqrst",
		},
		{
			name:  "matrix parameter",
			input: "https://h/x;" + discovertest.CanaryURL + "/sse",
			want:  "https://h/x;" + discover.Mask + "/sse",
		},
		{
			name:  "matrix parameters with key and empty part",
			input: "https://h/x;k=v;;tok",
			want:  "https://h/x;" + discover.Mask + ";;" + discover.Mask,
		},
		{
			name:  "credential segment with matrix parameter",
			input: "https://h/" + discovertest.CanaryURL + ";a",
			want:  "https://h/" + discover.Mask + ";" + discover.Mask,
		},
		{
			name:  "escaped slash does not split a segment",
			input: "https://h/mcp/mcpmoat%2Fcanary%2Furl%2F9Jd3Wm",
			want:  "https://h/mcp/" + discover.Mask,
		},
		{
			name:  "non-ASCII segment is escaped, then masked",
			input: "https://h/é" + discovertest.CanaryURL,
			want:  "https://h/" + discover.Mask,
		},
		{
			name:  "path masked with userinfo, query and fragment",
			input: "https://u:p@h/mcp/" + discovertest.CanaryURL + "?k=v#f",
			want:  "https://" + discover.Mask + "@h/mcp/" + discover.Mask + "?k=" + discover.Mask + "#" + discover.Mask,
		},

		// Query: every value is masked, keys and separators stay.
		{
			name:  "at sign in a query value is masked with the value",
			input: "https://h/x?email=a@b",
			want:  "https://h/x?email=" + discover.Mask,
		},
		{
			name:  "query values",
			input: "https://h/x?api_key=" + discovertest.CanaryURL + "&profile=p",
			want:  "https://h/x?api_key=" + discover.Mask + "&profile=" + discover.Mask,
		},
		{
			name:  "bare query part",
			input: "https://h/?" + discovertest.CanaryURL,
			want:  "https://h/?" + discover.Mask,
		},
		{
			name:  "semicolon separator",
			input: "https://h/x?a=1;b=" + discovertest.CanaryURL,
			want:  "https://h/x?a=" + discover.Mask + ";b=" + discover.Mask,
		},
		{
			name:  "empty part between separators",
			input: "https://h/x?a=1&&b=" + discovertest.CanaryURL,
			want:  "https://h/x?a=" + discover.Mask + "&&b=" + discover.Mask,
		},
		{
			name:  "value with equals sign",
			input: "https://h/x?k=a=" + discovertest.CanaryURL,
			want:  "https://h/x?k=" + discover.Mask,
		},

		// Fragment: a non-empty fragment is masked.
		{
			name:  "fragment",
			input: "https://h/#" + discovertest.CanaryURL,
			want:  "https://h/#" + discover.Mask,
		},
		{
			name:  "escaped path is kept, query and fragment masked",
			input: "https://h/p%2Fq?a=1#f%20g",
			want:  "https://h/p%2Fq?a=" + discover.Mask + "#" + discover.Mask,
		},

		// Fail closed: input that we cannot split safely gives Mask.
		{
			name:  "parse error",
			input: "http://[::1",
			want:  discover.Mask,
		},
		{
			name:  "opaque URL",
			input: "mailto:x",
			want:  discover.Mask,
		},
		{
			name:  "host and port without scheme parses as opaque",
			input: "localhost:8080",
			want:  discover.Mask,
		},
		{
			name:  "path only has no host",
			input: "/sse",
			want:  discover.Mask,
		},
		{
			name:  "bare token",
			input: "abc" + discovertest.CanaryURL,
			want:  discover.Mask,
		},
		{
			name:  "host and path without scheme",
			input: "host/path/" + discovertest.CanaryURL,
			want:  discover.Mask,
		},
		{
			name:  "no scheme with at sign in path",
			input: discovertest.CanaryURL + "@host/x",
			want:  discover.Mask,
		},
		{
			name:  "no scheme with encoded at sign in path",
			input: discovertest.CanaryURL + "%40host/x",
			want:  discover.Mask,
		},
		{
			// An unescaped "/" in a userinfo token ends the authority
			// early: url.Parse sees host "tok" and path "/en@h/x", so part
			// of the token would print as the host. With no userinfo, an
			// "@" in the path gives Mask.
			name:  "slash in userinfo token",
			input: "https://tok/en@h/x",
			want:  discover.Mask,
		},
		{
			// The same rule also masks a real path with "@". Such paths
			// are rare in MCP URLs, so failing closed costs little.
			name:  "at sign in path without userinfo",
			input: "https://h/a@b",
			want:  discover.Mask,
		},
		{
			name:  "question mark in userinfo token",
			input: "https://tok?en@h/x",
			want:  discover.Mask,
		},
		{
			name:  "question mark in userinfo token with password",
			input: "https://tok?en:" + discovertest.CanaryURL + "@h/x",
			want:  discover.Mask,
		},
		{
			name:  "hash in userinfo token",
			input: "https://tok#en@h/x",
			want:  discover.Mask,
		},
		{
			name:  "escaped at sign in fragment without userinfo",
			input: "https://tok#en%40h/x",
			want:  discover.Mask,
		},
		{
			// url.Parse accepts a zone ID, and u.String writes it back as
			// written, so the zone could carry a secret.
			name:  "IPv6 zone ID",
			input: "http://[::1%25" + discovertest.CanaryURL + "]:80/",
			want:  discover.Mask,
		},
		{
			// A raw IDN host is not ASCII. Fail closed instead of
			// converting it.
			name:  "non-ASCII host",
			input: "https://bücher.example/",
			want:  discover.Mask,
		},
		{
			// url.Parse unescapes the host, so an escaped IDN host is also
			// non-ASCII after parsing.
			name:  "percent-encoded non-ASCII host",
			input: "https://b%C3%BCcher.example/",
			want:  discover.Mask,
		},

		// Output is ASCII: bytes outside printable ASCII are escaped.
		{
			name:  "non-ASCII path is escaped by url.URL.String",
			input: "https://h/a\u202eb",
			want:  "https://h/a%E2%80%AEb",
		},
		{
			name:  "bidi and C1 bytes in a query key are escaped",
			input: "https://h/?k\u202e\u009b=" + discovertest.CanaryURL,
			want:  "https://h/?k%E2%80%AE%C2%9B=" + discover.Mask,
		},
		{
			name:  "existing escapes in a query key are kept",
			input: "https://h/?a%20b=1",
			want:  "https://h/?a%20b=" + discover.Mask,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := discover.RedactURL(tt.input)
			discovertest.AssertNoLeak(t, "RedactURL", got, discovertest.CanaryURL)
			if got != tt.want {
				t.Errorf("RedactURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
			assertPrintableASCII(t, tt.input, got)
		})
	}
}

// FuzzRedactURL checks that RedactURL never panics and that its output is
// always printable ASCII, for any input. The seeds run as a normal test;
// "go test -fuzz=FuzzRedactURL ./internal/discover/" explores more inputs.
func FuzzRedactURL(f *testing.F) {
	for _, seed := range []string{
		"https://u:p@h/x?k=v#f",
		"http://[::1%25zone]:80/",
		"https://h/?k\u202e=v;\u009b",
		"https://bücher.example/",
		"//u@h/p%2Fq?a=1&&b",
		"https://actions.zapier.com/mcp/sk-ak-0123456789abcdef/sse",
		"https://h/123e4567-e89b-12d3-a456-426614174000/mcp",
		"https://h/eyJhbGciOiJIUzI1NiJ9.e30.sig;k=v;;t/sse",
		"https://tok/en@h/x?q#f",
		"https://h/\u00e9%2F;\u202e/x",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		assertPrintableASCII(t, raw, discover.RedactURL(raw))
	})
}

// assertPrintableASCII fails the test if got has a byte outside printable
// ASCII (0x20 to 0x7e), as promised by the RedactURL doc comment.
func assertPrintableASCII(t *testing.T, input, got string) {
	t.Helper()
	for i := 0; i < len(got); i++ {
		if c := got[i]; c < 0x20 || c > 0x7e {
			t.Errorf("RedactURL(%q) = %q, byte %d is 0x%02x, want printable ASCII", input, got, i, c)
			return
		}
	}
}

// TestRedactURLKnownLimits records cases that RedactURL does not mask today.
// The RedactURL doc comment lists them as known limits. The outputs below
// still contain the token, so this test does not call AssertNoLeak. If a
// future change masks these parts, update this test on purpose.
func TestRedactURLKnownLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			// The path rules need a known prefix, 20 or more bytes with a
			// digit, 32 or more bytes, or a UUID. A short token passes.
			name:  "short token in path is not masked",
			input: "https://h/mcp/a1b2c3d4e5/sse",
			want:  "https://h/mcp/a1b2c3d4e5/sse",
		},
		{
			// A token with only letters and fewer than 32 bytes passes.
			name:  "letters-only token in path is not masked",
			input: "https://h/mcp/QwErTyUiOpAsDfGhJkLz/sse",
			want:  "https://h/mcp/QwErTyUiOpAsDfGhJkLz/sse",
		},
		{
			// RedactURL keeps query keys, so a token used as a key stays.
			name:  "token as query key is kept",
			input: "https://h/?" + discovertest.CanaryURL + "=1",
			want:  "https://h/?" + discovertest.CanaryURL + "=" + discover.Mask,
		},
		{
			// RedactURL keeps the host, so a token in a subdomain stays.
			name:  "token in subdomain is not masked",
			input: "https://" + discovertest.CanaryURL + ".example.com/",
			want:  "https://" + discovertest.CanaryURL + ".example.com/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := discover.RedactURL(tt.input)
			if got != tt.want {
				t.Errorf("RedactURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
			assertPrintableASCII(t, tt.input, got)
		})
	}
}

func ExampleRedactURL() {
	fmt.Println(discover.RedactURL("https://user:pw@example.com/mcp?key=abc"))
	// Output: https://********@example.com/mcp?key=********
}
