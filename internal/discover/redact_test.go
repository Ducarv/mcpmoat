package discover_test

import (
	"fmt"
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
			name:  "at sign in path with a host is kept",
			input: "https://h/a@b",
			want:  "https://h/a@b",
		},
		{
			name:  "empty query",
			input: "https://h/?",
			want:  "https://h/?",
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

		// Query: every value is masked, keys and separators stay.
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := discover.RedactURL(tt.input)
			discovertest.AssertNoLeak(t, "RedactURL", got, discovertest.CanaryURL)
			if got != tt.want {
				t.Errorf("RedactURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestRedactURLKnownLimits records cases that RedactURL does not mask today.
// The RedactURL doc comment lists them as known limits. The outputs below
// still contain the URL canary, so this test does not call AssertNoLeak. If a
// future change masks these parts, update this test on purpose.
func TestRedactURLKnownLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			// RedactURL keeps the path, so a token in a path segment stays.
			name:  "token in path is not masked",
			input: "https://h/mcp/" + discovertest.CanaryURL + "/sse",
			want:  "https://h/mcp/" + discovertest.CanaryURL + "/sse",
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
		})
	}
}

func ExampleRedactURL() {
	fmt.Println(discover.RedactURL("https://user:pw@example.com/mcp?key=abc"))
	// Output: https://********@example.com/mcp?key=********
}
