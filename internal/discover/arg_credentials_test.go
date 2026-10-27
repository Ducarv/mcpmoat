package discover_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Fake test values for the ArgCredentials cases. None is a real secret.
const (
	// credTok looks like a token: 21 bytes with letters and digits.
	credTok = "FAKE-TOKEN-0123456789"
	// credPw is too short to look like a token, so only a secret-like name
	// next to it can make it a credential.
	credPw = "FAKEpw"
	// credGlued is glued to "-p" in a case. It has no secret-like word
	// ("TOKEN" in credTok would make the flag name secret-like), so only
	// the token rule masks "-p" + credGlued.
	credGlued = "FAKEvalue0123456789x"
	// credUUID is a fake UUID.
	credUUID = "0f8fad5b-d9cb-469f-a165-70867728950e" //nolint:gosec // G101: fake test value

	// mk is a short name for the mask, to keep the tables readable.
	mk = discover.Mask
)

// argCredentialsCase is one ArgCredentials input and what it must give.
type argCredentialsCase struct {
	name string
	args []string
	// want holds values that must be in ArgCredentials(args). A nil want
	// means ArgCredentials(args) must be nil.
	want []string
	// notWant holds values that must not be in ArgCredentials(args).
	notWant []string
	// redacted is RedactArgs(args). These values were checked against the
	// code before ArgCredentials was added, so ArgCredentials did not change
	// what RedactArgs shows.
	redacted []string
}

// argCredentialsCases is shared by TestArgCredentials and the seeds of
// FuzzArgCredentials. Do not change it in a test.
var argCredentialsCases = []argCredentialsCase{
	// Nothing to mask gives nil.
	{name: "nil", args: nil, want: nil, redacted: nil},
	{name: "empty", args: []string{}, want: nil, redacted: []string{}},

	// The value after a secret-like flag or key is a credential, whole,
	// even when it is short.
	{name: "secret flag then token", args: []string{"--api-key", credTok}, want: []string{credTok}, redacted: []string{"--api-key", mk}},
	{name: "secret flag then short value", args: []string{"--api-key", credPw}, want: []string{credPw}, redacted: []string{"--api-key", mk}},
	{name: "secret flag with equals", args: []string{"--token=" + credTok}, want: []string{credTok}, redacted: []string{"--token=" + mk}},
	{name: "secret flag with equals short value", args: []string{"--token=" + credPw}, want: []string{credPw}, redacted: []string{"--token=" + mk}},
	{name: "env flag", args: []string{"-e", "GITHUB_TOKEN=" + credPw}, want: []string{credPw}, redacted: []string{"-e", "GITHUB_TOKEN=" + mk}},
	{name: "env pair alone", args: []string{"GITHUB_TOKEN=" + credPw}, want: []string{credPw}, redacted: []string{"GITHUB_TOKEN=" + mk}},
	{name: "secret key and colon", args: []string{"token:" + credPw}, want: []string{credPw}, redacted: []string{mk}},

	// The security review probe: values that are not token-like count only
	// because their names are secret-like.
	{name: "passcode number", args: []string{"PASSCODE=48291736"}, want: []string{"48291736"}, redacted: []string{"PASSCODE=" + mk}},
	{name: "access code word", args: []string{"-e", "ACCESS_CODE=Summer2024!x"}, want: []string{"Summer2024!x"}, redacted: []string{"-e", "ACCESS_CODE=" + mk}},
	{name: "signing salt word", args: []string{"SIGNING_SALT=pepperpepper"}, want: []string{"pepperpepper"}, redacted: []string{"SIGNING_SALT=" + mk}},
	{name: "signature flag", args: []string{"--signature", credPw}, want: []string{credPw}, redacted: []string{"--signature", mk}},
	{name: "passcode in a query", args: []string{"https://example.com/mcp?passcode=" + credPw}, want: []string{credPw}, redacted: []string{"https://example.com/mcp?passcode=" + mk}},
	{
		// "SALTY_DOG_ENABLED" has no secret-like word, so "on" is no
		// credential.
		name:     "salty is not salt",
		args:     []string{"SALTY_DOG_ENABLED=on"},
		want:     nil,
		notWant:  []string{"on"},
		redacted: []string{"SALTY_DOG_ENABLED=on"},
	},

	// Token-like pieces fail closed.
	{name: "uuid path segment", args: []string{"/data/" + credUUID + "/x"}, want: []string{credUUID}, redacted: []string{"/data/" + mk + "/x"}},
	{name: "token prefix path segment", args: []string{"/data/ghp_FAKE0123/x"}, want: []string{"ghp_FAKE0123"}, redacted: []string{"/data/" + mk + "/x"}},
	{
		name:     "long random path segment",
		args:     []string{"/srv/FAKEabcdefghijklmnopqrstuvwxyz0123/x"},
		want:     []string{"FAKEabcdefghijklmnopqrstuvwxyz0123"},
		redacted: []string{"/srv/" + mk + "/x"},
	},

	// User flag values: the whole value and the password after ":".
	{name: "user flag with password", args: []string{"-u", "fakeuser:" + credPw}, want: []string{"fakeuser:" + credPw, credPw}, redacted: []string{"-u", mk}},
	{name: "long user flag", args: []string{"--user", "fakeuser"}, want: []string{"fakeuser"}, redacted: []string{"--user", mk}},
	{
		// The password ends at the last "@", not at a ":" of the port.
		name:     "user flag with a dsn",
		args:     []string{"-u", "fakeuser:" + credPw + "@tcp(db:3306)/x"},
		want:     []string{"fakeuser:" + credPw + "@tcp(db:3306)/x", credPw},
		redacted: []string{"-u", mk},
	},

	// A user and a password before an "@": the whole text and the password
	// alone.
	{
		name:     "dsn user and password",
		args:     []string{"app:hunter2hunter@tcp(db:3306)/x"},
		want:     []string{"app:hunter2hunter@tcp(db:3306)/x", "hunter2hunter"},
		notWant:  []string{"app", "3306"},
		redacted: []string{mk},
	},
	{name: "user and password at a host", args: []string{"app:hunter2hunter@db"}, want: []string{"app:hunter2hunter@db", "hunter2hunter"}, notWant: []string{"app"}, redacted: []string{mk}},
	{name: "password with an at sign", args: []string{"app:" + credPw + "@x@db"}, want: []string{credPw + "@x"}, redacted: []string{mk}},
	{
		// Oracle "user/password@tns". The whole text is token-like.
		name:     "oracle user and password",
		args:     []string{"scott/hunter2hunter@orcl"},
		want:     []string{"scott/hunter2hunter@orcl", "hunter2hunter"},
		notWant:  []string{"scott", "orcl"},
		redacted: []string{mk},
	},
	{
		// A positional "user:password" that is token-like: the whole text
		// and the password, as after "-u".
		name:     "token-like user and password positional",
		args:     []string{"admin:hunter2secretpw"},
		want:     []string{"admin:hunter2secretpw", "hunter2secretpw"},
		notWant:  []string{"admin"},
		redacted: []string{mk},
	},
	// An "@" before the ":", a mail address and a URL path have no password.
	{name: "ssh address", args: []string{"git@github.com:org/repo"}, want: nil, notWant: []string{"org/repo", "github.com"}, redacted: []string{mk}},
	{name: "mail address", args: []string{"user@example.com"}, want: nil, notWant: []string{"user", "example.com"}, redacted: []string{mk}},
	{name: "at sign in a url path", args: []string{"https://example.com/a@b"}, want: nil, notWant: []string{"//example.com/a", "a"}, redacted: []string{mk}},

	// Header values.
	{
		// The line, the value after the name and the credential, but not
		// the scheme word "Bearer".
		name:     "authorization bearer token",
		args:     []string{"-H", "Authorization: Bearer " + credTok},
		want:     []string{"Authorization: Bearer " + credTok, "Bearer " + credTok, credTok},
		notWant:  []string{"Bearer"},
		redacted: []string{"-H", mk},
	},
	{
		// The value after a secret-like header name counts even when it is
		// short. The line is not token-like and has a "Name:" form, so it is
		// not kept whole.
		name:     "authorization bearer short value",
		args:     []string{"-H", "Authorization: Bearer " + credPw},
		want:     []string{"Bearer " + credPw, credPw},
		notWant:  []string{"Bearer", "Authorization: Bearer " + credPw},
		redacted: []string{"-H", mk},
	},
	{name: "secret header name", args: []string{"-H", "X-Api-Key: " + credPw}, want: []string{credPw}, redacted: []string{"-H", mk}},
	{name: "token value after a plain header name", args: []string{"-H", "X-Custom: " + credTok}, want: []string{credTok}, redacted: []string{"-H", mk}},

	// URLs.
	{
		name:     "url user info",
		args:     []string{"https://fakeuser:" + credPw + "@example.com/mcp"},
		want:     []string{"fakeuser:" + credPw, credPw},
		redacted: []string{"https://" + mk + "@example.com/mcp"},
	},
	{
		name:     "url secret query value",
		args:     []string{"https://example.com/mcp?api_key=" + credPw},
		want:     []string{credPw},
		redacted: []string{"https://example.com/mcp?api_key=" + mk},
	},

	// Key=value and JSON text.
	{name: "json secret key", args: []string{`{"token":"` + credPw + `"}`}, want: []string{credPw}, redacted: []string{mk}},
	{name: "connection string password", args: []string{"Server=h;Password=" + credPw}, want: []string{credPw}, notWant: []string{"h"}, redacted: []string{"Server=" + mk}},

	// A value of a secret-like key is a credential whole, also when it is
	// quoted or holds a separator byte (see secretPairValues). An env
	// value goes through ArgCredentials as one arg, so these are the env
	// cases too.
	{
		name:     "libpq quoted password",
		args:     []string{"host=db password='correct horse battery'"},
		want:     []string{"correct horse battery", "'correct horse battery'"},
		notWant:  []string{"db", "correct"},
		redacted: []string{"host=" + mk},
	},
	{
		name:     "libpq quoted password with spaces around the equals sign",
		args:     []string{"host=db password = 'a b c d'"},
		want:     []string{"a b c d"},
		notWant:  []string{"db"},
		redacted: []string{"host=" + mk},
	},
	{
		// libpq writes a quote inside a quoted value as \'.
		name:     "libpq escaped quote",
		args:     []string{`password='it\'s ok' host=x`},
		want:     []string{"it's ok", `it\'s ok`, `'it\'s ok'`},
		notWant:  []string{"x"},
		redacted: []string{"password=" + mk},
	},
	{
		// ADO.NET and SQL write a quote inside a quoted value two times.
		name:     "doubled quote",
		args:     []string{"password='it''s ok'"},
		want:     []string{"it's ok", "it''s ok", "'it''s ok'"},
		redacted: []string{"password=" + mk},
	},
	{
		name:     "ado quoted password with a semicolon",
		args:     []string{`Server=db;Password="Ab;cdefgh"`},
		want:     []string{"Ab;cdefgh", `"Ab;cdefgh"`},
		notWant:  []string{"db", "Ab", "cdefgh"},
		redacted: []string{"Server=" + mk},
	},
	{
		name:     "ado password with a colon and a comma",
		args:     []string{"Server=h;User Id=sa;Password=Xy7:k9,Lm2Qq;"},
		want:     []string{"Xy7:k9,Lm2Qq"},
		notWant:  []string{"sa", "h"},
		redacted: []string{"Server=" + mk},
	},
	{
		name:     "ado password with spaces",
		args:     []string{"Server=h;Password=a b c d;Database=x"},
		want:     []string{"a b c d", "a"},
		notWant:  []string{"h", "x"},
		redacted: []string{"Server=" + mk},
	},
	{
		name:     "json password with a colon and a comma",
		args:     []string{`{"password":"Xy7:k9,Lm2Qq"}`},
		want:     []string{"Xy7:k9,Lm2Qq", `"Xy7:k9,Lm2Qq"`},
		redacted: []string{mk},
	},
	{
		name:     "json api key with spaces",
		args:     []string{`{"api_key":"abc def ghi jkl"}`},
		want:     []string{"abc def ghi jkl"},
		notWant:  []string{"def", "ghi", "jkl"},
		redacted: []string{mk},
	},
	{
		name:     "json escaped quote",
		args:     []string{`{"user":"u","token":"a\"b c"}`},
		want:     []string{`a"b c`, `a\"b c`},
		notWant:  []string{"u"},
		redacted: []string{mk},
	},
	{
		name:     "quoted value after a secret-like name",
		args:     []string{`pwd="a b c d e f g h"`},
		want:     []string{"a b c d e f g h", `"a b c d e f g h"`},
		redacted: []string{"pwd=" + mk},
	},
	{
		// No closing quote: the value runs to the end (fail closed).
		name:     "unterminated quote",
		args:     []string{"host=db password='a b c"},
		want:     []string{"a b c"},
		notWant:  []string{"db"},
		redacted: []string{"host=" + mk},
	},
	{
		// IsSecretName finds "password" in "notpassword", so its value is a
		// credential, whole and up to the first space.
		name:     "secret word inside a longer name",
		args:     []string{"notpassword=x y z"},
		want:     []string{"x y z", "x"},
		redacted: []string{"notpassword=" + mk},
	},
	{name: "empty password", args: []string{"password="}, want: nil, redacted: []string{"password=" + mk}},
	{name: "empty quoted password", args: []string{"host=db password=''"}, want: nil, redacted: []string{"host=" + mk}},
	{
		// A quoted value of a plain key is no credential.
		name:     "quoted plain value",
		args:     []string{"host='my db' dbname=x"},
		want:     nil,
		notWant:  []string{"my db", "'my db'"},
		redacted: []string{"host=" + mk},
	},
	{
		name:     "json plain value with spaces",
		args:     []string{`{"user":"a b c"}`},
		want:     nil,
		notWant:  []string{"a b c"},
		redacted: []string{mk},
	},

	// Plain words are not credentials, though RedactArgs masks them and
	// ArgSecrets returns them.
	{
		name:     "dsn words",
		args:     []string{"host=localhost dbname=production user=postgres"},
		want:     nil,
		notWant:  []string{"localhost", "production", "postgres"},
		redacted: []string{"host=" + mk},
	},
	{
		// "My" is not an auth scheme, so "Documents" is no credential.
		name:     "path segment with a space",
		args:     []string{"/Users/me/My Documents/x.js"},
		want:     nil,
		notWant:  []string{"Documents", "My Documents"},
		redacted: []string{"/Users/me/" + mk + "/x.js"},
	},
	{
		name:     "plain query value",
		args:     []string{"https://example.com/mcp?workspace=engineering"},
		want:     nil,
		notWant:  []string{"engineering"},
		redacted: []string{"https://example.com/mcp?workspace=" + mk},
	},
	{name: "content type header", args: []string{"-H", "Content-Type: application/json"}, want: nil, notWant: []string{"application/json"}, redacted: []string{"-H", mk}},
	{name: "user agent header", args: []string{"-H", "User-Agent: my-client/1.0"}, want: nil, notWant: []string{"my-client/1.0"}, redacted: []string{"-H", mk}},
	{
		// RedactArgs also masks the next arg (fail closed), and ArgSecrets
		// returns it, but "server.js" does not look like a token.
		name:     "arg after a token glued to a short flag",
		args:     []string{"-p" + credGlued, "server.js"},
		want:     []string{"-p" + credGlued, credGlued},
		notWant:  []string{"server.js"},
		redacted: []string{mk, mk},
	},

	// Ambiguous cases, pinned as the current behaviour.
	{
		// Current: a positional "user:password" is a credential only when
		// it is token-like (see "token-like user and password positional").
		name:     "plain user and password positional",
		args:     []string{"admin:plainpass"},
		want:     nil,
		notWant:  []string{"admin:plainpass", "plainpass"},
		redacted: []string{mk},
	},
	{
		// Current: the same for Oracle "user/password@tns", because
		// "owner/repo@ref" has the same shape.
		name:     "plain oracle user and password",
		args:     []string{"scott/tiger@orcl"},
		want:     nil,
		notWant:  []string{"scott/tiger@orcl", "tiger"},
		redacted: []string{mk},
	},
	{
		// The value of a secret-like name is a credential, even with spaces.
		name:     "seed phrase",
		args:     []string{"APP_SEED=correct horse battery staple"},
		want:     []string{"correct horse battery staple"},
		redacted: []string{"APP_SEED=" + mk},
	},
	{
		// Current: a short password glued to "-p" is shown, so it is no
		// credential (known limit of RedactArgs).
		name:     "short password glued to a short flag",
		args:     []string{"-phunter2"},
		want:     nil,
		redacted: []string{"-phunter2"},
	},
	{
		// Current: a flag name of 20+ bytes with letters and digits counts
		// as a token (fail closed).
		name:     "long flag name with a digit",
		args:     []string{"--use-v2-protocol-everywhere"},
		want:     []string{"--use-v2-protocol-everywhere", "use-v2-protocol-everywhere"},
		redacted: []string{mk},
	},
	{
		// Current: any word of 32+ bytes counts as a token (fail closed).
		name:     "long readable word",
		args:     []string{"abcdefghijklmnopqrstuvwxyzabcdefgh"},
		want:     []string{"abcdefghijklmnopqrstuvwxyzabcdefgh"},
		redacted: []string{mk},
	},
	{
		// Current: the value of "-u" is a credential, even with no ":".
		name:     "user flag with a name only",
		args:     []string{"-u", "admin"},
		want:     []string{"admin"},
		redacted: []string{"-u", mk},
	},
	{
		// Current: a secret-like name counts as an auth scheme.
		name:     "apikey scheme",
		args:     []string{"ApiKey " + credPw},
		want:     []string{credPw},
		notWant:  []string{"ApiKey"},
		redacted: []string{mk},
	},
	{
		// Current: "Session" is secret-like, so it counts as a scheme.
		name:     "session scheme",
		args:     []string{"Session " + credPw},
		want:     []string{credPw},
		notWant:  []string{"Session"},
		redacted: []string{mk},
	},
	{
		// Current: the scheme rule also works after a plain header name.
		name:     "apikey scheme after a plain header name",
		args:     []string{"-H", "X-Custom: ApiKey " + credPw},
		want:     []string{credPw},
		notWant:  []string{"ApiKey", "ApiKey " + credPw},
		redacted: []string{"-H", mk},
	},
	{name: "bearer scheme alone", args: []string{"Bearer " + credPw}, want: []string{credPw}, notWant: []string{"Bearer"}, redacted: []string{mk}},
}

// TestArgCredentials checks which pieces ArgCredentials returns, that they
// are a subset of ArgSecrets, and that RedactArgs shows the same output as
// before ArgCredentials was added.
func TestArgCredentials(t *testing.T) {
	t.Parallel()
	for _, tt := range argCredentialsCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Keep a copy, to check that ArgCredentials does not change its
			// input.
			before := slices.Clone(tt.args)
			got := discover.ArgCredentials(tt.args)

			if !slices.Equal(tt.args, before) {
				t.Errorf("ArgCredentials changed its input: now %q, was %q", tt.args, before)
			}
			if tt.want == nil && got != nil {
				t.Errorf("ArgCredentials(%q) = %q, want nil", tt.args, got)
			}
			for _, w := range tt.want {
				if !slices.Contains(got, w) {
					t.Errorf("ArgCredentials(%q) = %q, want it to hold %q", tt.args, got, w)
				}
			}
			for _, nw := range tt.notWant {
				if slices.Contains(got, nw) {
					t.Errorf("ArgCredentials(%q) = %q, want it not to hold %q", tt.args, got, nw)
				}
			}
			checkCredentialsSubset(t, tt.args, got)

			if shown := discover.RedactArgs(tt.args); !slices.Equal(shown, tt.redacted) {
				t.Errorf("RedactArgs(%q) = %q, want %q", tt.args, shown, tt.redacted)
			}
		})
	}
}

// checkCredentialsSubset checks that creds, the ArgCredentials result for
// args, has no empty string and that each value is also in ArgSecrets(args).
func checkCredentialsSubset(t *testing.T, args, creds []string) {
	t.Helper()
	secrets := discover.ArgSecrets(args)
	for _, c := range creds {
		if c == "" {
			t.Errorf("ArgCredentials(%q) holds an empty string", args)
		}
		if !slices.Contains(secrets, c) {
			t.Errorf("ArgCredentials(%q) holds %q, which ArgSecrets = %q does not hold", args, c, secrets)
		}
	}
}

// FuzzArgCredentials checks, for any args, that ArgCredentials never
// panics, never changes its input, and returns only non-empty values that
// ArgSecrets also returns. The fuzz strings are split on NUL bytes into
// arguments, as in FuzzArgSecrets.
func FuzzArgCredentials(f *testing.F) {
	for _, tt := range argCredentialsCases {
		// The NUL byte joins the args into one fuzz string.
		f.Add(strings.Join(tt.args, "\x00"), "")
	}
	f.Add("--conn\x00Server=h;Password=pw\x00host=h password=pw dbname=x", `{"token":"pw"}`)
	f.Add("-H\x00Authorization:\x00-H\x00a b: c", "Bearer\x00ApiKey  x y")
	// Users and passwords before an "@", and texts with an "@" and no
	// password.
	f.Add("app:pw@tcp(db:3306)/x\x00-u\x00u:p@w:rd@host", "scott/pw@//h:1521/orcl\x00u:@h")
	f.Add("git@github.com:org/repo\x00user@example.com", "https://example.com/a@b\x00a/b:c@d")
	// Quoted values, escapes, a missing closing quote and a "\" at the end
	// (see secretPairValues and quotedSpan).
	f.Add(`host=db password='a\'b c'`+"\x00"+`Server=h;Pwd="x;""y";`, `{"token":"a\"b","pin":'c d'}`+"\x00"+`password='a\`)
	f.Add(`x/password="a\/b"/y`+"\x00"+`--opt=password='a b'`, `token = "a b" : 'c'`+"\x00"+`'password'='x'`)

	f.Fuzz(func(t *testing.T, before, after string) {
		args := append(strings.Split(before, "\x00"), strings.Split(after, "\x00")...)
		input := slices.Clone(args)

		got := discover.ArgCredentials(args)

		if !slices.Equal(args, input) {
			t.Fatalf("ArgCredentials changed its input: now %q, was %q", args, input)
		}
		checkCredentialsSubset(t, args, got)
	})
}
