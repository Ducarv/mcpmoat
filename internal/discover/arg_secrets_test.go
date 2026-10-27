package discover_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// argV is the long test value of the ArgSecrets cases. It looks like a token
// (long, letters and digits), so the token rules mask it too.
const argV = discovertest.CanaryArgs

// TestArgSecrets checks each shape of text that ArgSecrets returns: the
// pieces that RedactArgs masks, in the order of args, and the inner values of
// a header line or an auth value. want is written by hand, in order, with the
// duplicates and the short values that ArgSecrets keeps on purpose (the
// caller filters them).
func TestArgSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want []string
	}{
		// Nothing masked gives nil.
		{name: "nil", args: nil, want: nil},
		{name: "empty", args: []string{}, want: nil},
		{name: "package and path", args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/home/me/proj"}, want: nil},
		{name: "port flag", args: []string{"--port", "8080"}, want: nil},
		{name: "package version", args: []string{"pkg@1.2.3"}, want: nil},
		{name: "host port and plain env", args: []string{"localhost:8080", "-e", "LOG_LEVEL=debug"}, want: nil},
		// RedactArgs shows Mask for an empty value, but there is no secret.
		{name: "empty value after equals", args: []string{"--token="}, want: nil},
		{name: "empty value after flag", args: []string{"--token", ""}, want: nil},
		{name: "secret flag as the last argument", args: []string{"--token"}, want: nil},

		// Flag values.
		{name: "secret flag then value", args: []string{"--api-key", argV}, want: []string{argV}},
		{name: "secret flag after a boolean secret flag", args: []string{"--no-auth", "--api-key", argV}, want: []string{argV}},
		{name: "value after equals", args: []string{"--token=" + argV}, want: []string{argV}},
		{name: "env flag", args: []string{"-e", "GITHUB_TOKEN=" + argV}, want: []string{argV}},
		{
			// The whole token-like flag, and the next arg that can be its value.
			name: "token-like flag name",
			args: []string{"--ghp_abc123def456", "x"},
			want: []string{"--ghp_abc123def456", "x"},
		},

		// Header lines and auth values.
		{
			name: "authorization header",
			args: []string{"-H", "Authorization: Bearer " + argV},
			want: []string{"Authorization: Bearer " + argV, "Bearer " + argV, argV},
		},
		{
			name: "api key header",
			args: []string{"--header", "X-Api-Key: " + argV},
			want: []string{"X-Api-Key: " + argV, argV},
		},
		{
			name: "positional auth value",
			args: []string{"Bearer " + argV},
			want: []string{"Bearer " + argV, argV},
		},
		{
			name: "header parts are trimmed",
			args: []string{"-H", "Authorization: Bearer  tok  "},
			want: []string{"Authorization: Bearer  tok  ", "Bearer  tok", "tok"},
		},
		{
			// A credential has no space, so "a b" is not split off.
			name: "credential with a space",
			args: []string{"-H", "Authorization: Basic a b"},
			want: []string{"Authorization: Basic a b", "Basic a b"},
		},
		{name: "header with no value", args: []string{"-H", "Authorization:"}, want: []string{"Authorization:"}},
		{name: "header name that is not a name", args: []string{"-H", "a b: c"}, want: []string{"a b: c"}},
		{
			// Words of a path segment with spaces are not removed one by one.
			name: "text with spaces gives no credential part",
			args: []string{"pid file $HOME"},
			want: []string{"pid file $HOME"},
		},

		// Values masked whole.
		{name: "value glued to a short flag", args: []string{"-uadmin:" + argShort}, want: []string{"-uadmin:" + argShort, argShort}},
		{name: "padded base64", args: []string{"c2VjcmV0LXZhbHVlLTEyMzQ="}, want: []string{"c2VjcmV0LXZhbHVlLTEyMzQ="}},
		{name: "DSN", args: []string{"u:p@tcp(h)/db"}, want: []string{"u:p@tcp(h)/db", "p@tcp(h)/db"}},
		{name: "user and password", args: []string{"admin:" + argShort}, want: []string{"admin:" + argShort, argShort}},
		{name: "secret label", args: []string{"token:abc"}, want: []string{"token:abc", "abc"}},
		{name: "path segment", args: []string{"/data/ghp_abc123xyz/x"}, want: []string{"ghp_abc123xyz"}},

		// URLs: the parts that RedactURL masks.
		{
			// The user info as written, its value after ":" as a header
			// part, then the password.
			name: "URL user info with a password",
			args: []string{"postgres://u:" + argShort + "@h/db"},
			want: []string{"u:" + argShort, argShort, argShort},
		},
		{
			name: "URL password as written and unescaped",
			args: []string{"https://user:p%40ssword9@h/sse"},
			want: []string{"user:p%40ssword9", "p%40ssword9", "p%40ssword9", "p@ssword9"},
		},
		{name: "URL name with no password", args: []string{"https://" + argV + "@h/"}, want: []string{argV, argV}},
		{name: "URL name unescaped", args: []string{"https://ab%2Bcd@h/"}, want: []string{"ab%2Bcd", "ab%2Bcd", "ab+cd"}},
		{name: "URL path segment", args: []string{"https://actions.zapier.com/mcp/" + argV + "/sse"}, want: []string{argV}},
		{name: "URL query values", args: []string{"https://h/sse?api_key=" + argV + "&x=1"}, want: []string{argV, "1"}},
		{
			// The unescaped fragment has a space, so its last word is a
			// credential part.
			name: "URL fragment",
			args: []string{"https://h/#frag%20ment"},
			want: []string{"frag%20ment", "frag ment", "ment"},
		},
		{
			// RedactURL masks a URL with an unknown scheme whole. "ftp" is a
			// name before ":", so the rest is a header part.
			name: "URL masked whole",
			args: []string{"ftp://h/x"},
			want: []string{"ftp://h/x", "//h/x"},
		},
		{name: "URL value of an env name", args: []string{"U=https://h/?k=" + argV}, want: []string{argV}},

		// Several pieces keep the order of args.
		{
			name: "order of args",
			args: []string{"-y", "pkg", "--token", "first-value", "-H", "X-Key: second-value", "/data/ghp_third123/x"},
			want: []string{"first-value", "X-Key: second-value", "second-value", "ghp_third123"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			before := slices.Clone(tt.args)
			got := discover.ArgSecrets(tt.args)
			// The values are fake test secrets, so the message shows them.
			if !slices.Equal(got, tt.want) {
				t.Errorf("ArgSecrets(%q) = %q, want %q", tt.args, got, tt.want)
			}
			if tt.want == nil && got != nil {
				t.Errorf("ArgSecrets(%q) = %#v, want nil", tt.args, got)
			}
			if !slices.Equal(tt.args, before) {
				t.Errorf("ArgSecrets changed its input: now %q, was %q", tt.args, before)
			}
			checkArgSecretsConsistent(t, tt.args, got)
		})
	}
}

// checkArgSecretsConsistent checks how ArgSecrets(args) = secrets and
// RedactArgs(args) agree. Both run the same code, so these must hold for
// any args:
//
//  1. Each secret, as written or percent-decoded (see percentDecode), is a
//     substring of an arg, as written or percent-decoded with or without "+"
//     as a space. ArgSecrets keeps raw text, the trimmed inner parts of a
//     header line and URL parts, and nothing else. A URL part can be
//     unescaped (a password, a fragment, url.QueryUnescape of a query part)
//     or escaped again by url.URL (a path segment comes from EscapedPath, so
//     a space in the arg is "%20" in the part).
//  2. secrets is not empty only when the RedactArgs output holds Mask.
//  3. When the RedactArgs output of an arg is p + Mask, the arg starts with p
//     and the rest of the arg is not empty, that rest is in secrets. This
//     covers an arg masked whole (p is ""), a value after "=" and a last
//     path segment. Args with a "*" (the Mask byte) or a "//" (a URL, which
//     RedactURL can write back in another form) are skipped.
func checkArgSecretsConsistent(t *testing.T, args, secrets []string) {
	t.Helper()
	for _, s := range secrets {
		if s == "" {
			t.Errorf("ArgSecrets(%q) holds an empty string", args)
		}
		forms := []string{s, percentDecode(s, false)}
		if !slices.ContainsFunc(args, func(a string) bool {
			for _, arg := range []string{a, percentDecode(a, false), percentDecode(a, true)} {
				for _, f := range forms {
					if strings.Contains(arg, f) {
						return true
					}
				}
			}
			return false
		}) {
			t.Errorf("ArgSecrets(%q) holds %q, which is not in an arg or its decoded form", args, s)
		}
	}
	shown := discover.RedactArgs(args)
	if len(secrets) > 0 && !slices.ContainsFunc(shown, func(s string) bool { return strings.Contains(s, discover.Mask) }) {
		t.Errorf("ArgSecrets(%q) = %q, but RedactArgs masks nothing: %q", args, secrets, shown)
	}
	for i, out := range shown {
		arg := args[i]
		p, masked := strings.CutSuffix(out, discover.Mask)
		if !masked || strings.Contains(arg, "*") || strings.Contains(arg, "//") {
			continue
		}
		if rest, ok := strings.CutPrefix(arg, p); ok && rest != "" && !slices.Contains(secrets, rest) {
			t.Errorf("RedactArgs(%q)[%d] = %q masks %q, but ArgSecrets = %q does not hold it", args, i, out, rest, secrets)
		}
	}
}

// percentDecode decodes every valid "%XX" escape of s and keeps every other
// byte. When plus is true it also turns "+" into a space, as
// url.QueryUnescape does. It does not fail on a bad escape, so it decodes a
// whole arg even when only one part of it is a URL part that url.Parse,
// url.PathUnescape or url.QueryUnescape decoded. The decoded form of such a
// part is a substring of the result.
func percentDecode(s string, plus bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		case s[i] == '+' && plus:
			b.WriteByte(' ')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// isHex reports whether c is an ASCII hex digit.
func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// unhex returns the value of the hex digit c.
func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}

// TestPercentDecode checks the decoder of checkArgSecretsConsistent, so a
// bug there cannot make the consistency check pass or fail by mistake.
func TestPercentDecode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		plus bool
		want string
	}{
		{in: "", want: ""},
		{in: "p%40ss", want: "p@ss"},
		{in: "%2f%2F", want: "//"},
		{in: "a+b", want: "a+b"},
		{in: "a+b", plus: true, want: "a b"},
		{in: "%", want: "%"},
		{in: "%4", want: "%4"},
		{in: "%zz%41", want: "%zzA"},
		{in: "%%41", want: "%A"},
		{in: "x%41", want: "xA"},
	}
	for _, tt := range tests {
		if got := percentDecode(tt.in, tt.plus); got != tt.want {
			t.Errorf("percentDecode(%q, %v) = %q, want %q", tt.in, tt.plus, got, tt.want)
		}
	}
}

// FuzzArgSecrets checks, for any args, that ArgSecrets never panics, never
// changes its input, and agrees with RedactArgs (see
// checkArgSecretsConsistent). The fuzz strings are split on NUL bytes into
// arguments, as in FuzzRedactArgs.
func FuzzArgSecrets(f *testing.F) {
	f.Add("", "")
	f.Add("--no-auth\x00--api-key\x00v", "-e\x00GITHUB_TOKEN=x")
	f.Add("-H\x00Authorization: Bearer tok", "--header\x00X-Api-Key: v")
	f.Add("Bearer x\x00pid file $HOME", "-uadmin:pw\x00token:abc")
	f.Add("c2VjcmV0LXZhbHVlLTEyMzQ=\x00u:p@tcp(h)/db", "/data/ghp_abc123xyz/x")
	f.Add("https://user:p%40ss@h/x;m?k=v&b#f%20g", "https://ab%2Bcd@h/mcp/ghp_abc123/sse")
	f.Add("ftp://h/x\x00U=https://h/?k=a+b%41", "//u@h/?=&;x")
	f.Add("-y\x00@modelcontextprotocol/server-filesystem\x00/home/me/proj", "--port\x008080\x00pkg@1.2.3")
	f.Add("--token=\x00--token\x00", "-H\x00Authorization:\x00-H\x00a b: c")
	f.Add("--ghp_abc123def456\x00x", "/x/********\x00--flag=********")
	// A path segment comes back from EscapedPath with the space escaped.
	f.Add("///0\x00//0/?0", "//0/0,0 0")

	f.Fuzz(func(t *testing.T, before, after string) {
		args := append(strings.Split(before, "\x00"), strings.Split(after, "\x00")...)
		input := slices.Clone(args)

		got := discover.ArgSecrets(args)

		if !slices.Equal(args, input) {
			t.Fatalf("ArgSecrets changed its input: now %q, was %q", args, input)
		}
		checkArgSecretsConsistent(t, args, got)
	})
}
