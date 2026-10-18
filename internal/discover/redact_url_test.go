package discover_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// TestRedactURL checks the masked output of RedactURL for each URL part and
// for the inputs that fail closed.
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
			name:  "segment with escaped space is kept",
			input: "https://h/my%20server/sse",
			want:  "https://h/my%20server/sse",
		},
		{
			name:  "segment with equals sign is masked",
			input: "https://h/login/password=hunter2/x",
			want:  "https://h/login/" + discover.Mask + "/x",
		},
		{
			name:  "segment with comma is masked",
			input: "https://h/a,b/x",
			want:  "https://h/" + discover.Mask + "/x",
		},
		{
			name:  "segment with escaped equals sign is masked",
			input: "https://h/pw%3Dhunter2/x",
			want:  "https://h/" + discover.Mask + "/x",
		},
		{
			name:  "segment with escaped comma is masked",
			input: "https://h/a%2Cb",
			want:  "https://h/" + discover.Mask,
		},
		{
			name:  "segment with user:password is masked",
			input: "https://h/admin:" + "hunter2/x",
			want:  "https://h/" + discover.Mask + "/x",
		},
		{
			name:  "token prefix after a dot in a segment is masked",
			input: "https://h/v1.ghp_abc12/x",
			want:  "https://h/" + discover.Mask + "/x",
		},
		{
			// An escaped ";" is a matrix parameter that url.Parse does not
			// split, so it is masked as one.
			name:  "segment with escaped semicolon is masked",
			input: "https://h/x%3Bpw/sse",
			want:  "https://h/" + discover.Mask + "/sse",
		},
		{
			name:  "escaped token prefix is masked",
			input: "https://h/%67hp_abcdef/sse",
			want:  "https://h/" + discover.Mask + "/sse",
		},
		{
			name:  "token after an escaped slash is masked",
			input: "https://h/a%2Fghp_abcdef/b",
			want:  "https://h/" + discover.Mask + "/b",
		},
		{
			name:  "token before an escaped slash is masked",
			input: "https://h/ghp_abcdef%2Fa/b",
			want:  "https://h/" + discover.Mask + "/b",
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
			name:  "escaped at sign in a query value is masked with the value",
			input: "https://h/x?email=a%40b",
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
		{
			name:  "normal keys are kept",
			input: "https://h/x?api_key=1&token=2&k=3",
			want:  "https://h/x?api_key=" + discover.Mask + "&token=" + discover.Mask + "&k=" + discover.Mask,
		},
		{
			name:  "token with known prefix as key is masked",
			input: "https://h/x?ghp_abcdef123456=",
			want:  "https://h/x?" + discover.Mask + "=" + discover.Mask,
		},
		{
			name:  "escaped token prefix as key is masked",
			input: "https://h/?%67hp_abcdef=1&k=2",
			want:  "https://h/?" + discover.Mask + "=" + discover.Mask + "&k=" + discover.Mask,
		},
		{
			name:  "token after an escaped slash in a key is masked",
			input: "https://h/?a%2Fghp_abcdef=1",
			want:  "https://h/?" + discover.Mask + "=" + discover.Mask,
		},
		{
			name:  "key with a bad escape is masked",
			input: "https://h/?%zz=1",
			want:  "https://h/?" + discover.Mask + "=" + discover.Mask,
		},
		{
			name:  "key with plus and escaped slash is kept",
			input: "https://h/?a+b%2Fc=1",
			want:  "https://h/?a+b%2Fc=" + discover.Mask,
		},
		{
			name:  "long token as key is masked",
			input: "https://h/?" + discovertest.CanaryURL + "=1&k=2",
			want:  "https://h/?" + discover.Mask + "=" + discover.Mask + "&k=" + discover.Mask,
		},
		{
			// The key unescapes to "password=hunter2".
			name:  "key with escaped equals sign is masked",
			input: "https://h/x?password%3Dhunter2=",
			want:  "https://h/x?" + discover.Mask + "=" + discover.Mask,
		},
		{
			name:  "key with colon is masked",
			input: "https://h/x?admin:hunter2=1",
			want:  "https://h/x?" + discover.Mask + "=" + discover.Mask,
		},
		{
			name:  "key with escaped colon is masked",
			input: "https://h/x?admin%3Ahunter2=1",
			want:  "https://h/x?" + discover.Mask + "=" + discover.Mask,
		},
		{
			name:  "key with comma is masked",
			input: "https://h/x?pw,hunter2=x",
			want:  "https://h/x?" + discover.Mask + "=" + discover.Mask,
		},
		{
			name:  "key with escaped comma is masked",
			input: "https://h/x?pw%2Chunter2=x",
			want:  "https://h/x?" + discover.Mask + "=" + discover.Mask,
		},
		{
			name:  "key with escaped semicolon is masked",
			input: "https://h/x?pw%3Bhunter2=x",
			want:  "https://h/x?" + discover.Mask + "=" + discover.Mask,
		},
		{
			name:  "only the secret key is masked",
			input: "https://h/x?a=1&admin:hunter2=2&b=3",
			want: "https://h/x?a=" + discover.Mask + "&" + discover.Mask + "=" + discover.Mask +
				"&b=" + discover.Mask,
		},

		// Scheme: only schemes in the allowlist are kept.
		{
			name:  "ws scheme is kept",
			input: "ws://h/mcp",
			want:  "ws://h/mcp",
		},
		{
			name:  "wss scheme is kept",
			input: "wss://h/mcp",
			want:  "wss://h/mcp",
		},
		{
			name:  "upper-case scheme is kept in lower case",
			input: "HTTPS://h/mcp",
			want:  "https://h/mcp",
		},
		{
			name:  "DSN scheme is kept",
			input: "postgres://u:" + discovertest.CanaryURL + "@db:5432/app",
			want:  "postgres://" + discover.Mask + "@db:5432/app",
		},
		{
			name:  "DSN scheme with plus is kept",
			input: "mongodb+srv://h/app",
			want:  "mongodb+srv://h/app",
		},
		{
			name:  "scheme-relative URL is kept",
			input: "//h/mcp",
			want:  "//h/mcp",
		},
		{
			name:  "token as scheme gives Mask",
			input: "sk-proj-ABC123secretXYZ://host/x",
			want:  discover.Mask,
		},
		{
			name:  "short token as scheme gives Mask",
			input: "token123://h",
			want:  discover.Mask,
		},
		{
			name:  "canary as scheme gives Mask",
			input: "x" + discovertest.CanaryURL + "://h/mcp",
			want:  discover.Mask,
		},
		{
			name:  "unknown scheme gives Mask",
			input: "ftp://h/x",
			want:  discover.Mask,
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
			// With userinfo, a "/" in the password cuts the authority too:
			// url.Parse sees userinfo "user:p", host "ss" and path
			// "/word@h/mcp". The "@" in the path gives Mask.
			name:  "at sign and slash in password",
			input: "https://user:p@" + "ss/word@h/mcp",
			want:  discover.Mask,
		},
		{
			name:  "at sign and slash in username",
			input: "https://a@b/c@d/x",
			want:  discover.Mask,
		},
		{
			name:  "at sign in fragment with userinfo",
			input: "https://u:p@" + "h/x#a@b",
			want:  discover.Mask,
		},
		{
			// A "?" in the token puts the rest in the query, and the "@"
			// sits in a query value, after the first "=".
			name:  "question mark in token with equals sign before at sign",
			input: "https://ghp_abcdef123?x=y@h/mcp",
			want:  discover.Mask,
		},
		{
			// Any raw "@" in the query fails closed, so a real query value
			// with "@" also gives Mask. RedactURL documents this cost.
			name:  "at sign in a query value",
			input: "https://h/x?email=a@b",
			want:  discover.Mask,
		},
		{
			name:  "at sign in a query value with userinfo",
			input: "https://u:p@" + "h/x?email=a@b",
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
			if !isPrintableASCII(got) {
				t.Errorf("RedactURL(%q) = %q, want only printable ASCII", tt.input, got)
			}
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
		"https://user:p@ss/word@h/mcp",
		"https://ghp_abcdef123?x=y@h/mcp",
		"https://h/?ghp_abcdef123456=&k=v;" + strings.Repeat("a", 32),
		"https://h/login/password=hunter2/a,b/x%3By",
		"https://h/%67hp_abcdef/a%2Fghp_abcdef?%67hp_x=1&%zz=2",
		"sk-proj-ABC123secretXYZ://host/x",
		"HTTPS://h/mcp",
		"mongodb+srv://u:p@h/db",
		"https://h/x?password%3Dhunter2=&admin:hunter2=1;pw,hunter2=x",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		// The RedactURL doc comment promises printable ASCII output.
		if got := discover.RedactURL(raw); !isPrintableASCII(got) {
			t.Errorf("RedactURL(%q) = %q, want only printable ASCII", raw, got)
		}
	})
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
			// RedactURL unescapes once, so a token escaped twice is checked
			// as "%67hp_abcdef" and passes.
			name:  "token escaped twice in path is not masked",
			input: "https://h/%2567hp_abcdef/sse",
			want:  "https://h/%2567hp_abcdef/sse",
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
			if !isPrintableASCII(got) {
				t.Errorf("RedactURL(%q) = %q, want only printable ASCII", tt.input, got)
			}
		})
	}
}

// TestSecretPathSegments checks the list of path segments that RedactURL
// masks. Each segment comes in its escaped form and, when it differs, in its
// unescaped form, so that a caller can remove both from other text.
func TestSecretPathSegments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "token segment",
			input: "https://h/mcp/" + discovertest.CanaryURL + "/sse",
			want:  []string{discovertest.CanaryURL},
		},
		{
			name:  "token segment with user info, query and fragment",
			input: "https://user@h/mcp/ghp_abc/sse?k=v#f",
			want:  []string{"ghp_abc"},
		},
		{
			name:  "UUID segment",
			input: "https://mcp.composio.dev/partner/123e4567-e89b-12d3-a456-426614174000/mcp",
			want:  []string{"123e4567-e89b-12d3-a456-426614174000"},
		},
		{
			name:  "escaped token segment gives both forms",
			input: "https://h/%67hp_abcdef/sse",
			want:  []string{"%67hp_abcdef", "ghp_abcdef"},
		},
		{
			name:  "segment with equals sign",
			input: "https://h/key=v4lue/sse",
			want:  []string{"key=v4lue"},
		},
		{
			name:  "segment with escaped equals sign gives both forms",
			input: "https://h/key%3Dv4lue/sse",
			want:  []string{"key%3Dv4lue", "key=v4lue"},
		},
		{
			name:  "segment with colon",
			input: "https://h/user:p4ss/sse",
			want:  []string{"user:p4ss"},
		},
		{
			name:  "matrix parameter",
			input: "https://h/mcp;x=y/sse",
			want:  []string{"mcp;x=y", "x=y"},
		},
		{
			// A server can echo a matrix parameter alone, so it is listed
			// alone too. The part before ";" is not a secret here.
			name:  "matrix token alone",
			input: "https://h/x;" + discovertest.CanaryURL + "/sse",
			want:  []string{"x;" + discovertest.CanaryURL, discovertest.CanaryURL},
		},
		{
			name:  "credential segment with matrix parameter lists both parts",
			input: "https://h/" + discovertest.CanaryURL + ";a",
			want:  []string{discovertest.CanaryURL + ";a", discovertest.CanaryURL, "a"},
		},
		{
			name:  "matrix parameters skip the empty part",
			input: "https://h/x;k=v;;tok",
			want:  []string{"x;k=v;;tok", "k=v", "tok"},
		},
		{
			name:  "escaped matrix part gives both forms",
			input: "https://h/x;%67hp_abcdef/sse",
			want:  []string{"x;%67hp_abcdef", "x;ghp_abcdef", "%67hp_abcdef", "ghp_abcdef"},
		},
		{
			name:  "secret segment with trailing semicolon",
			input: "https://h/ghp_abc;/sse",
			want:  []string{"ghp_abc;", "ghp_abc"},
		},
		{
			name:  "several secret segments in path order",
			input: "https://h/ghp_abc/v1/key=v/" + discovertest.CanaryURL,
			want:  []string{"ghp_abc", "key=v", discovertest.CanaryURL},
		},
		{
			name:  "no secret segment",
			input: "https://h/v1/messages",
			want:  nil,
		},
		{
			name:  "escaped segment that is no secret",
			input: "https://h/p%2Fq/x",
			want:  nil,
		},
		{
			name:  "empty path",
			input: "https://h",
			want:  nil,
		},
		{
			name:  "root path only",
			input: "https://h/",
			want:  nil,
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "unparsable URL",
			input: "http://[::1/" + discovertest.CanaryURL,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := discover.SecretPathSegments(tt.input)
			if !slices.Equal(got, tt.want) || (got == nil) != (tt.want == nil) {
				t.Errorf("SecretPathSegments(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
			// Every returned segment is a part that RedactURL removes: a whole
			// segment after "/", or a matrix part after ";".
			redacted := discover.RedactURL(tt.input)
			for _, seg := range got {
				if strings.Contains(redacted, "/"+seg) || strings.Contains(redacted, ";"+seg) {
					t.Errorf("RedactURL(%q) = %q still holds segment %q", tt.input, redacted, seg)
				}
			}
		})
	}
}

// TestSecretQueryParts checks the list of query parts that RedactURL masks:
// every value, every bare part and every credential-shaped key, raw and
// unescaped, split on "&" and ";".
func TestSecretQueryParts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rawQuery string
		want     []string // in order; nil for none
	}{
		{name: "empty query", rawQuery: "", want: nil},
		{name: "values in order", rawQuery: "a=tok-one&b=tok-two", want: []string{"tok-one", "tok-two"}},
		{name: "repeated key gives every value", rawQuery: "t=tok-one&t=tok-two", want: []string{"tok-one", "tok-two"}},
		{name: "plain key is not listed", rawQuery: "api_key=v4lue-NOTREAL", want: []string{"v4lue-NOTREAL"}},
		{name: "bare part", rawQuery: discovertest.CanaryURL, want: []string{discovertest.CanaryURL}},
		{name: "bare part among pairs", rawQuery: "k=v4lue&tok-bare", want: []string{"v4lue", "tok-bare"}},
		{name: "empty value gives nothing", rawQuery: "k=", want: nil},
		{name: "empty value next to a value", rawQuery: "k=&j=v4lue", want: []string{"v4lue"}},
		{name: "equals sign alone", rawQuery: "=", want: nil},
		{name: "value keeps a later equals sign", rawQuery: "k=a=b-NOTREAL", want: []string{"a=b-NOTREAL"}},
		// Key shapes from the RedactURL query-key rows.
		{name: "token as key", rawQuery: "ghp_abcdef123456=1", want: []string{"ghp_abcdef123456", "1"}},
		{name: "token as key with empty value", rawQuery: "ghp_abcdef123456=", want: []string{"ghp_abcdef123456"}},
		{name: "long canary as key", rawQuery: discovertest.CanaryURL + "=1&k=2", want: []string{discovertest.CanaryURL, "1", "2"}},
		{name: "escaped token prefix as key gives both forms", rawQuery: "%67hp_abcdef=1", want: []string{"%67hp_abcdef", "ghp_abcdef", "1"}},
		{name: "key with escaped equals sign gives both forms", rawQuery: "password%3Dhunter2=", want: []string{"password%3Dhunter2", "password=hunter2"}},
		{name: "key with a bad escape is kept raw", rawQuery: "%zz=1", want: []string{"%zz", "1"}},
		{name: "semicolon separates parts", rawQuery: "a=tok-one;b=tok-two", want: []string{"tok-one", "tok-two"}},
		{name: "semicolon before a bare part", rawQuery: "a=tok-one;tok-bare", want: []string{"tok-one", "tok-bare"}},
		{name: "empty parts are skipped", rawQuery: "&&a=tok-one;;&", want: []string{"tok-one"}},
		{name: "escaped value in raw and unescaped form", rawQuery: "t=tok%2FNOT+REAL", want: []string{"tok%2FNOT+REAL", "tok/NOT REAL"}},
		{name: "escaped bare part in raw and unescaped form", rawQuery: "tok%2Dbare", want: []string{"tok%2Dbare", "tok-bare"}},
		{name: "bad escape in value kept raw only", rawQuery: "t=tok%zzNOTREAL", want: []string{"tok%zzNOTREAL"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := discover.SecretQueryParts(tt.rawQuery)
			if !slices.Equal(got, tt.want) {
				t.Errorf("SecretQueryParts(%q) = %#v, want %#v", tt.rawQuery, got, tt.want)
			}
			// Every returned part is a part that RedactURL removes.
			input := "https://h/p?" + tt.rawQuery
			redacted := discover.RedactURL(input)
			if redacted == discover.Mask {
				t.Fatalf("RedactURL(%q) = Mask; pick a query that RedactURL keeps in shape", input)
			}
			for _, part := range got {
				if strings.Contains(redacted, part) {
					t.Errorf("RedactURL(%q) = %q still holds part %q", input, redacted, part)
				}
			}
		})
	}
}

// ExampleRedactURL shows that the userinfo and the query values are masked.
func ExampleRedactURL() {
	fmt.Println(discover.RedactURL("https://user:pw@example.com/mcp?key=abc"))
	// Output: https://********@example.com/mcp?key=********
}
