package discover_test

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// Test values for the RedactArgs cases.
const (
	argEnv    = discovertest.CanaryEnv
	argHeader = discovertest.CanaryHeader
	argURL    = discovertest.CanaryURL

	// argShort is a secret that is too short to look like a token, so only
	// the shape rules can mask it. The canaries above are long enough that
	// the token rules alone mask them; argShort checks the shape rules.
	argShort = "pw9Zq"
)

// redactArgsCase is one RedactArgs input and the output it must give.
type redactArgsCase struct {
	name string
	args []string
	want []string
}

// leakCheck tells runRedactArgsCases whether to check for leaks.
type leakCheck bool

const (
	// checkLeaks fails a case if a canary or argShort is in the output.
	checkLeaks leakCheck = true
	// skipLeakCheck is for cases that show a secret on purpose: the known
	// limits.
	skipLeakCheck leakCheck = false
)

// runRedactArgsCases runs each case as a parallel subtest. For each case it
// checks the output, that the output has only printable ASCII, that
// RedactArgs does not change its input and returns a non-nil slice, and, if
// leaks is checkLeaks, that no canary and no short secret leaks.
func runRedactArgsCases(t *testing.T, tests []redactArgsCase, leaks leakCheck) {
	t.Helper()
	secrets := append(discovertest.Canaries(), argShort)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Keep a copy, to check that RedactArgs does not change its input.
			before := slices.Clone(tt.args)
			got := discover.RedactArgs(tt.args)

			if leaks == checkLeaks {
				discovertest.AssertNoLeak(t, "RedactArgs", strings.Join(got, " "), secrets...)
			}
			for i, s := range got {
				if !isPrintableASCII(s) {
					t.Errorf("RedactArgs(%q)[%d] = %q, want only printable ASCII", tt.args, i, s)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("RedactArgs(%q) = %q, want %q", tt.args, got, tt.want)
			}
			if !slices.Equal(tt.args, before) {
				t.Errorf("RedactArgs changed its input: now %q, was %q", tt.args, before)
			}
			if got == nil {
				t.Errorf("RedactArgs(%q) = nil, want a non-nil slice", tt.args)
			}
		})
	}
}

// TestRedactArgsFlagValues checks that the value of a secret-like, header or
// user flag is always masked, and that a flag is never taken as the value of
// the flag before it.
func TestRedactArgsFlagValues(t *testing.T) {
	t.Parallel()
	runRedactArgsCases(t, []redactArgsCase{
		// Secret-like flags: the next argument or the part after "=".
		{
			name: "secret flag then value",
			args: []string{"--token", argShort},
			want: []string{"--token", discover.Mask},
		},
		{
			name: "secret flag with equals",
			args: []string{"--api-key=" + argEnv},
			want: []string{"--api-key=" + discover.Mask},
		},
		{
			name: "secret flag with empty equals value",
			args: []string{"--password="},
			want: []string{"--password=" + discover.Mask},
		},
		{
			name: "single-dash secret flag with underscores",
			args: []string{"-API_KEY", argShort},
			want: []string{"-API_KEY", discover.Mask},
		},
		{
			name: "camel case secret flag",
			args: []string{"--githubToken", argShort},
			want: []string{"--githubToken", discover.Mask},
		},
		{
			name: "value after a secret flag that does not parse as a flag",
			args: []string{"--secret", "-" + argShort + "!"},
			want: []string{"--secret", discover.Mask},
		},
		{
			name: "lone dash after a secret flag is a value",
			args: []string{"--token", "-"},
			want: []string{"--token", discover.Mask},
		},
		{
			name: "single-dash word that is not secret-like is a value",
			args: []string{"--password", "-x" + argShort},
			want: []string{"--password", discover.Mask},
		},
		{
			name: "secret flag as the last argument",
			args: []string{"--token"},
			want: []string{"--token"},
		},
		{
			name: "location flag value is masked, even a path or a URL",
			args: []string{"--key-file", "/etc/ssl/key.pem", "--token-url=https://h/?code=" + argURL},
			want: []string{"--key-file", discover.Mask, "--token-url=" + discover.Mask},
		},

		// Header flags: the whole header line is masked, name included.
		{
			name: "long header flag with authorization",
			args: []string{"--header", "Authorization: Bearer " + argShort},
			want: []string{"--header", discover.Mask},
		},
		{
			name: "short header flag with an api key header",
			args: []string{"-H", "X-Api-Key: " + argShort},
			want: []string{"-H", discover.Mask},
		},
		{
			name: "header flag with equals",
			args: []string{"--header=Authorization: Bearer " + argShort},
			want: []string{"--header=" + discover.Mask},
		},
		{
			name: "headers flag with JSON",
			args: []string{"--headers", `{"Authorization":"` + argShort + `"}`},
			want: []string{"--headers", discover.Mask},
		},

		// User flags (curl): the whole value is masked.
		{
			name: "user flag with user and password",
			args: []string{"-u", "admin:" + argShort},
			want: []string{"-u", discover.Mask},
		},
		{
			name: "user flag with a key and an empty password",
			args: []string{"-u", argShort + ":"},
			want: []string{"-u", discover.Mask},
		},
		{
			name: "user flag with equals",
			args: []string{"--user=admin:" + argShort},
			want: []string{"--user=" + discover.Mask},
		},

		// A flag is never the value of the flag before it.
		{
			name: "boolean secret-like flag does not use up the mask",
			args: []string{"--no-auth", "--token", argShort},
			want: []string{"--no-auth", "--token", discover.Mask},
		},
		{
			name: "single-dash secret-like flag after a boolean flag is masked with its value",
			args: []string{"--no-auth", "-token", argShort},
			want: []string{"--no-auth", discover.Mask, discover.Mask},
		},
		{
			name: "header flag after a boolean flag",
			args: []string{"--no-auth", "-H", "Authorization: Bearer " + argHeader},
			want: []string{"--no-auth", "-H", discover.Mask},
		},
		{
			name: "secret-like flag before another secret flag",
			args: []string{"--oauth", "--client-secret", argShort},
			want: []string{"--oauth", "--client-secret", discover.Mask},
		},
		{
			name: "header flag before a secret flag",
			args: []string{"-H", "--api-key", argShort},
			want: []string{"-H", "--api-key", discover.Mask},
		},
		{
			name: "user flag before a secret flag",
			args: []string{"-u", "--token", argShort},
			want: []string{"-u", "--token", discover.Mask},
		},
		{
			name: "user flag after a boolean flag",
			args: []string{"--no-auth", "-u", "admin:" + argShort},
			want: []string{"--no-auth", "-u", discover.Mask},
		},
		{
			name: "header flag with equals after a secret flag",
			args: []string{"--token", "-H=Authorization: Bearer " + argShort},
			want: []string{"--token", "-H=" + discover.Mask},
		},

		// After a secret flag, a single-dash argument other than "-H" and
		// "-u" is the value.
		{
			name: "one-letter dash argument after a secret flag is the value",
			args: []string{"--password", "-x"},
			want: []string{"--password", discover.Mask},
		},
		{
			name: "one-letter flag with equals after a secret flag is the value",
			args: []string{"--password", "-p=" + argShort},
			want: []string{"--password", discover.Mask},
		},
		{
			name: "argument after a one-letter value is a new argument",
			args: []string{"--password", "-v", "server.js"},
			want: []string{"--password", discover.Mask, "server.js"},
		},
		{
			name: "secret-like single-dash value masks the next argument too",
			args: []string{"--password", "-token", argShort, "server.js"},
			want: []string{"--password", discover.Mask, discover.Mask, "server.js"},
		},
		{
			name: "secret-like single-dash value with equals",
			args: []string{"--password", "-token=" + argShort, "server.js"},
			want: []string{"--password", discover.Mask, "server.js"},
		},
		{
			name: "single-dash value with a short form and a number masks the next argument too",
			args: []string{"--password", "-" + argShort, "server.js", "index.js"},
			want: []string{"--password", discover.Mask, discover.Mask, "index.js"},
		},
		{
			name: "plain flag after a secret flag is shown",
			args: []string{"--token", "--port", "8080"},
			want: []string{"--token", "--port", "8080"},
		},

		// A flag with a name that looks like a token is masked whole.
		{
			name: "token glued to a short flag",
			args: []string{"-p" + argEnv},
			want: []string{discover.Mask},
		},
		{
			name: "token that starts with two dashes after a secret flag",
			args: []string{"--password", "--ghp_" + argShort},
			want: []string{"--password", discover.Mask},
		},
		{
			name: "token glued to a short flag masks the next argument too",
			args: []string{"-p" + discovertest.CanaryArgs, argShort},
			want: []string{discover.Mask, discover.Mask},
		},

		// A long secret-like flag name looks like a token, so it is masked
		// whole. Its value must still be masked.
		{
			name: "long secret-like flag names mask the next argument",
			args: []string{
				"--s3-secret-access-key", argShort,
				"--google-oauth2-client-secret", argShort,
				"--database-admin-password-for-prod", argShort,
			},
			want: []string{discover.Mask, discover.Mask, discover.Mask, discover.Mask, discover.Mask, discover.Mask},
		},
		{
			name: "long secret-like flag with equals does not mask the next argument",
			args: []string{"--s3-secret-access-key=" + argShort, "server.js"},
			want: []string{discover.Mask, "server.js"},
		},
		{
			name: "long secret-like flag before another flag",
			args: []string{"--s3-secret-access-key", "--token", argShort},
			want: []string{discover.Mask, "--token", discover.Mask},
		},

		// A dash argument that is not a flag is masked whole.
		{
			name: "user and password glued to a short user flag",
			args: []string{"-uadmin:" + argShort, "-u" + argShort + ":"},
			want: []string{discover.Mask, discover.Mask},
		},
		{
			name: "header line glued to a short header flag",
			args: []string{"-HX-Custom:" + argShort, "-HX-Custom: " + argShort, "-HAuthorization:Bearer " + argShort},
			want: []string{discover.Mask, discover.Mask, discover.Mask},
		},
		{
			name: "other dash arguments that are not flags",
			args: []string{"--x:" + argShort, "-a/" + argShort, "-" + argShort + "@h", "--=" + argShort},
			want: []string{discover.Mask, discover.Mask, discover.Mask, discover.Mask},
		},
	}, checkLeaks)
}

// TestRedactArgsSecretNames checks which flag and variable names are
// secret-like.
func TestRedactArgsSecretNames(t *testing.T) {
	t.Parallel()
	runRedactArgsCases(t, []redactArgsCase{
		// Short forms match as a whole word.
		{
			name: "pass as a variable suffix",
			args: []string{"-e", "DB_PASS=" + argShort, "SMTP_PASS=" + argShort},
			want: []string{"-e", "DB_PASS=" + discover.Mask, "SMTP_PASS=" + discover.Mask},
		},
		{
			name: "pass as a flag name and a camel case word",
			args: []string{"--pass", argShort, "--dbPass=" + argShort, "--DBPass=" + argShort},
			want: []string{"--pass", discover.Mask, "--dbPass=" + discover.Mask, "--DBPass=" + discover.Mask},
		},
		{
			name: "jwt and pat as whole words",
			args: []string{"--jwt", argShort, "--github-pat", argShort, "GITHUB_PAT=" + argShort, "--githubPat=" + argShort},
			want: []string{"--jwt", discover.Mask, "--github-pat", discover.Mask, "GITHUB_PAT=" + discover.Mask, "--githubPat=" + discover.Mask},
		},

		// Short forms also match at the end of an all-caps glued word.
		{
			name: "all-caps glued pass",
			args: []string{"DBPASS=" + argShort, "PGPASS=" + argShort, "--MYJWT", argShort},
			want: []string{"DBPASS=" + discover.Mask, "PGPASS=" + discover.Mask, "--MYJWT", discover.Mask},
		},

		// A number at the end of a word does not hide a short form.
		{
			name: "short forms with a number at the end",
			args: []string{
				"--pass2", argShort, "--db-pw1", argShort, "--PIN4", argShort,
				"DB_PASS2=" + argShort, "REDIS_PASS1=" + argShort, "PGPASS12=" + argShort,
			},
			want: []string{
				"--pass2", discover.Mask, "--db-pw1", discover.Mask, "--PIN4", discover.Mask,
				"DB_PASS2=" + discover.Mask, "REDIS_PASS1=" + discover.Mask, "PGPASS12=" + discover.Mask,
			},
		},
		{
			name: "words with a number at the end that are not short forms",
			args: []string{"--opt2", "x", "--path2", "src", "--spin3", "y", "--v2", "z", "--top10", "t", "HTTP2=on"},
			want: []string{"--opt2", "x", "--path2", "src", "--spin3", "y", "--v2", "z", "--top10", "t", "HTTP2=on"},
		},

		// Words that only contain a short form are not secret-like.
		{
			name: "words that contain pass",
			args: []string{"--bypass", "x", "--compass", "north", "--passthrough", "on"},
			want: []string{"--bypass", "x", "--compass", "north", "--passthrough", "on"},
		},
		{
			name: "path, patch and pattern are not pat",
			args: []string{"--path", "src", "--patch", "fix.diff", "--pattern", "go", "PATH=bin"},
			want: []string{"--path", "src", "--patch", "fix.diff", "--pattern", "go", "PATH=bin"},
		},

		// More secret words: they match anywhere in the name.
		{
			name: "passphrase, mnemonic, private and credential",
			args: []string{
				"--passphrase", argShort, "--ssh-passphrase", argShort,
				"--mnemonic", argShort, "WALLET_MNEMONIC=" + argShort,
				"--private-key", argShort, "PRIVATE_KEY=" + argShort,
				"--credentials", argShort, "DB_CREDENTIAL=" + argShort,
			},
			want: []string{
				"--passphrase", discover.Mask, "--ssh-passphrase", discover.Mask,
				"--mnemonic", discover.Mask, "WALLET_MNEMONIC=" + discover.Mask,
				"--private-key", discover.Mask, "PRIVATE_KEY=" + discover.Mask,
				"--credentials", discover.Mask, "DB_CREDENTIAL=" + discover.Mask,
			},
		},

		// More short forms: they match as a whole word, or at the end of an
		// all-caps word.
		{
			name: "pw, pin, otp, cred and creds as whole words",
			args: []string{
				"--pw", argShort, "DB_PW=" + argShort, "--pin", argShort, "SIM_PIN=" + argShort,
				"--otp", argShort, "--cred", argShort, "--creds", argShort, "AWS_CREDS=" + argShort,
			},
			want: []string{
				"--pw", discover.Mask, "DB_PW=" + discover.Mask, "--pin", discover.Mask, "SIM_PIN=" + discover.Mask,
				"--otp", discover.Mask, "--cred", discover.Mask, "--creds", discover.Mask, "AWS_CREDS=" + discover.Mask,
			},
		},
		{
			name: "all-caps glued pw and otp",
			args: []string{"DBPW=" + argShort, "TOTP=" + argShort},
			want: []string{"DBPW=" + discover.Mask, "TOTP=" + discover.Mask},
		},
		{
			name: "words that contain pin, otp, opt, cred or priva",
			args: []string{
				"--spin", "x", "--pinned", "on", "--pinata", "y", "--option", "z",
				"--opt", "o", "--crediting", "c", "--credit", "d", "--privacy", "strict",
			},
			want: []string{
				"--spin", "x", "--pinned", "on", "--pinata", "y", "--option", "z",
				"--opt", "o", "--crediting", "c", "--credit", "d", "--privacy", "strict",
			},
		},

		// passcode, access code, salt and signature names. The first case
		// holds the fake values of the security review probe: a number, a
		// word with "!" and a plain word, which no token rule masks.
		{
			name: "passcode, access code and salt with values that are not token-like",
			args: []string{"PASSCODE=48291736", "ACCESS_CODE=Summer2024!x", "SIGNING_SALT=pepperpepper"},
			want: []string{"PASSCODE=" + discover.Mask, "ACCESS_CODE=" + discover.Mask, "SIGNING_SALT=" + discover.Mask},
		},
		{
			name: "passcode, access code, salt and signature flags",
			args: []string{
				"--passcode", argShort, "--pass-code=" + argShort, "--access-code", argShort,
				"--accessCode=" + argShort, "--salt", argShort, "--passwordSalt=" + argShort,
				"--signature", argShort, "--webhook-signature=" + argShort,
			},
			want: []string{
				"--passcode", discover.Mask, "--pass-code=" + discover.Mask, "--access-code", discover.Mask,
				"--accessCode=" + discover.Mask, "--salt", discover.Mask, "--passwordSalt=" + discover.Mask,
				"--signature", discover.Mask, "--webhook-signature=" + discover.Mask,
			},
		},
		{
			name: "all-caps words that start with PASS",
			args: []string{"DB_PASSWRD=" + argShort, "PASSCODE2=" + argShort, "--PASSKEY", argShort},
			want: []string{"DB_PASSWRD=" + discover.Mask, "PASSCODE2=" + discover.Mask, "--PASSKEY", discover.Mask},
		},
		{
			// Accepted false positives (fail closed): these names are not
			// credential names, but their values are masked.
			name: "names that look secret but are not",
			args: []string{"PASSIVE_MODE=on", "SIGNATURE_ALGORITHM=x", "SALT_ROUNDS=10"},
			want: []string{"PASSIVE_MODE=" + discover.Mask, "SIGNATURE_ALGORITHM=" + discover.Mask, "SALT_ROUNDS=" + discover.Mask},
		},
		{
			name: "words that contain salt, signing, access or a license",
			args: []string{
				"SALTY_DOG_ENABLED=on", "--basalt", "x", "--signing-method", "rs256",
				"ACCESS_LEVEL=read", "--assignee", "bob", "--license", "MIT", "--passive", "on",
			},
			want: []string{
				"SALTY_DOG_ENABLED=on", "--basalt", "x", "--signing-method", "rs256",
				"ACCESS_LEVEL=read", "--assignee", "bob", "--license", "MIT", "--passive", "on",
			},
		},
		{
			name: "lower case h is help, not a header flag",
			args: []string{"-h", "server"},
			want: []string{"-h", "server"},
		},
	}, checkLeaks)
}

// TestRedactArgsMasksUnknownShapes checks that values with no safe shape are
// masked. Each case is a shape that a denylist of secret shapes missed.
func TestRedactArgsMasksUnknownShapes(t *testing.T) {
	t.Parallel()
	runRedactArgsCases(t, []redactArgsCase{
		// Config and connection text.
		{
			name: "JSON config after a plain flag",
			args: []string{"--config", `{"apiKey":"` + argShort + `"}`},
			want: []string{"--config", discover.Mask},
		},
		{
			name: "DSN with user and password",
			args: []string{"--dsn", "user:" + argShort + "@tcp(db:3306)/app"},
			want: []string{"--dsn", discover.Mask},
		},
		{
			name: "user and password before a host",
			args: []string{"admin:" + argShort + "@db.example.com"},
			want: []string{discover.Mask},
		},
		{
			name: "user and password with a colon and no host",
			args: []string{"admin:" + argShort, "basic:" + argShort, "--auth-pair=x:" + argShort},
			want: []string{discover.Mask, discover.Mask, "--auth-pair=" + discover.Mask},
		},
		{
			name: "colon in a place that is not a port or a drive",
			args: []string{"host:123456", "host:", ":8080", "C:" + argShort, "a:1:2", "x/" + argShort + ":y"},
			want: []string{discover.Mask, discover.Mask, discover.Mask, discover.Mask, discover.Mask, discover.Mask},
		},
		{
			name: "Oracle connect strings",
			args: []string{"scott/" + argShort + "@orcl", "--dsn", "user/" + argShort + "@db"},
			want: []string{discover.Mask, "--dsn", discover.Mask},
		},
		{
			name: "at sign in a place that is not a scope or a version",
			args: []string{
				"user@" + argShort, argShort + "@host", "a@b@c", "x/pkg@1.0",
				"pkg@1.0/" + argShort, "@", "@/x", "@@x", "@a@1", "x@",
			},
			want: []string{
				discover.Mask, discover.Mask, discover.Mask, discover.Mask,
				discover.Mask, discover.Mask, discover.Mask, discover.Mask, discover.Mask, discover.Mask,
			},
		},
		{
			name: "version that is not numbers with a dot",
			args: []string{
				"scott@1tiger", "admin@1password", "user@1234", "pkg@1.", "pkg@.1",
				"pkg@1..2", "pkg@1.0-", "pkg@1.0+", "pkg@1.0-rc_1", "pkg@v", "pkg@1.0-" + argShort + "!",
			},
			want: []string{
				discover.Mask, discover.Mask, discover.Mask, discover.Mask, discover.Mask,
				discover.Mask, discover.Mask, discover.Mask, discover.Mask, discover.Mask, discover.Mask,
			},
		},
		{
			name: "semicolon list with a password",
			args: []string{"foo;Password=" + argShort},
			want: []string{discover.Mask},
		},
		{
			name: "connection string with a plain first key",
			args: []string{"Server=db;Password=" + argShort + ";Database=app"},
			want: []string{"Server=" + discover.Mask},
		},
		{
			name: "connection string with a secret first key",
			args: []string{"Password=ab;" + argShort + "=d"},
			want: []string{"Password=" + discover.Mask},
		},
		{
			name: "base64 text with padding",
			args: []string{
				"c2VjcmV0LXZhbHVlLTEyMzQ=", "dGhpc2lzYXNlY3JldGtleTEyMzQ1Ng==",
				base64.StdEncoding.EncodeToString([]byte(discovertest.CanaryArgs)),
				"abcdefghijklmnopq=", "abcdefghijklmnop==",
			},
			want: []string{discover.Mask, discover.Mask, discover.Mask, discover.Mask, discover.Mask},
		},
		{
			name: "token before an equals sign",
			args: []string{"ghp_abcdefghijklmnop1234=x", "sk-abc123=1", "-e", "ghp_abcdefghij=", "x.ghp_abc12=1"},
			want: []string{discover.Mask, discover.Mask, "-e", discover.Mask, discover.Mask},
		},
		{
			name: "flag value with base64 padding or a token before an equals sign",
			args: []string{"--opt=c2VjcmV0LXZhbHVlLTEyMzQ=", "--opt=abcdefghijklmnopqr==", "--env=sk-abc123=1"},
			want: []string{"--opt=" + discover.Mask, "--opt=" + discover.Mask, "--env=" + discover.Mask},
		},
		{
			name: "value with a second equals sign",
			args: []string{"--env=X=a=" + argShort},
			want: []string{"--env=X=" + discover.Mask},
		},

		// URLs keep their shape and lose the secret parts (see RedactURL).
		{
			name: "mcp-remote URL with a token in the query",
			args: []string{"-y", "mcp-remote", "https://host/sse?api_key=" + argURL},
			want: []string{"-y", "mcp-remote", "https://host/sse?api_key=" + discover.Mask},
		},
		{
			name: "URL with userinfo",
			args: []string{"https://u:" + argShort + "@host/mcp"},
			want: []string{"https://" + discover.Mask + "@host/mcp"},
		},
		{
			name: "variable with a URL and a semicolon query part",
			args: []string{"MCP_URL=https://h/x?a=1;sig=" + argShort},
			want: []string{"MCP_URL=https://h/x?a=" + discover.Mask + ";sig=" + discover.Mask},
		},
		{
			name: "variable with a URL and a matrix parameter",
			args: []string{"SERVER_URL=https://h/x;" + argShort},
			want: []string{"SERVER_URL=https://h/x;" + discover.Mask},
		},
		{
			name: "variable with a URL with userinfo",
			args: []string{"API_URL=https://u:" + argURL + "@host/"},
			want: []string{"API_URL=https://" + discover.Mask + "@host/"},
		},
		{
			name: "scheme-relative URL with userinfo",
			args: []string{"//u:" + argShort + "@host/mcp"},
			want: []string{"//" + discover.Mask + "@host/mcp"},
		},
		{
			name: "scheme-relative URL with a query token",
			args: []string{"//host/sse?key=" + argShort},
			want: []string{"//host/sse?key=" + discover.Mask},
		},

		// Tokens and auth values.
		{
			name: "bare GitHub token",
			args: []string{"ghp_" + argShort},
			want: []string{discover.Mask},
		},
		{
			name: "bare canary tokens",
			args: []string{argEnv, argHeader, argURL},
			want: []string{discover.Mask, discover.Mask, discover.Mask},
		},
		{
			name: "bearer and basic values",
			args: []string{"Bearer " + argShort, "Bearer\t" + argShort, "basic " + argShort},
			want: []string{discover.Mask, discover.Mask, discover.Mask},
		},
		{
			name: "header lines",
			args: []string{"Authorization: Bearer " + argShort, "Cookie: sid=" + argShort, "x-auth-token:" + argShort},
			want: []string{discover.Mask, discover.Mask, discover.Mask},
		},
		{
			name: "secret variable",
			args: []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN=" + argShort, "ghcr.io/github/github-mcp-server"},
			want: []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN=" + discover.Mask, "ghcr.io/github/github-mcp-server"},
		},
		{
			name: "env flag with equals and a secret variable",
			args: []string{"--env=API_KEY=" + argShort},
			want: []string{"--env=API_KEY=" + discover.Mask},
		},
		{
			name: "path with a token segment",
			args: []string{"/data/ghp_" + argShort + "/x"},
			want: []string{"/data/" + discover.Mask + "/x"},
		},
		{
			name: "token prefix after a dot, an at sign, a plus or a tilde",
			args: []string{"@ghp_abc12", "x.sk-abc123", "/data/v1.ghp_" + argShort + "/x", "~sk-" + argShort, "a+xoxb-1"},
			want: []string{discover.Mask, discover.Mask, "/data/" + discover.Mask + "/x", discover.Mask, discover.Mask},
		},
		{
			name: "flag name with a token prefix after a dot",
			args: []string{"--x.ghp_abc12", argShort},
			want: []string{discover.Mask, discover.Mask},
		},

		// Bytes that are not printable ASCII.
		{
			name: "non-ASCII, control and bidi characters",
			args: []string{"pässword", "a\x1bb", "x\u202ey", "/home/\u202e/x"},
			want: []string{discover.Mask, discover.Mask, discover.Mask, "/home/" + discover.Mask + "/x"},
		},
	}, checkLeaks)
}

// TestRedactArgsShowsSafeShapes checks that common MCP server arguments with
// nothing to hide are shown as written.
func TestRedactArgsShowsSafeShapes(t *testing.T) {
	t.Parallel()
	runRedactArgsCases(t, []redactArgsCase{
		// Real MCP server commands (the command itself is not in Args).
		{
			name: "npx package and a path",
			args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/home/me/proj"},
			want: []string{"-y", "@modelcontextprotocol/server-filesystem", "/home/me/proj"},
		},
		{
			name: "uvx package and a relative path",
			args: []string{"mcp-server-git", "--repository", "./repo"},
			want: []string{"mcp-server-git", "--repository", "./repo"},
		},
		{
			name: "node script and a port",
			args: []string{"dist/index.js", "--port", "8080", "--verbose", "-v"},
			want: []string{"dist/index.js", "--port", "8080", "--verbose", "-v"},
		},
		{
			name: "python module",
			args: []string{"-m", "server"},
			want: []string{"-m", "server"},
		},
		{
			name: "docker image names and env names",
			args: []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN", "-e", "LOG_LEVEL=debug", "mcp/github", "ghcr.io/github/github-mcp-server"},
			want: []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN", "-e", "LOG_LEVEL=debug", "mcp/github", "ghcr.io/github/github-mcp-server"},
		},

		// Plain tokens.
		{
			name: "host and port",
			args: []string{"localhost:8080", "127.0.0.1:3000", "--listen=0.0.0.0:80", "HOST=db:5432"},
			want: []string{"localhost:8080", "127.0.0.1:3000", "--listen=0.0.0.0:80", "HOST=db:5432"},
		},
		{
			name: "package versions",
			args: []string{
				"pkg@1.2.3", "pkg@latest", "pkg@v2.0", "pkg@1.0.0-rc.1", "pkg@v2.0.1-beta.1",
				"pkg@1.0.0+build.5", "pkg@1.0-rc.1+b5", "@scope/pkg@latest", "@scope/pkg@1.2.3", "1.5",
			},
			want: []string{
				"pkg@1.2.3", "pkg@latest", "pkg@v2.0", "pkg@1.0.0-rc.1", "pkg@v2.0.1-beta.1",
				"pkg@1.0.0+build.5", "pkg@1.0-rc.1+b5", "@scope/pkg@latest", "@scope/pkg@1.2.3", "1.5",
			},
		},
		{
			name: "dotted words with no token prefix",
			args: []string{"a.b.c", "my.pk", "x.sk-", "index.js", "v1.2.3"},
			want: []string{"a.b.c", "my.pk", "x.sk-", "index.js", "v1.2.3"},
		},
		{
			name: "scoped package in a node_modules path",
			args: []string{"/home/me/node_modules/@scope/pkg/dist/index.js"},
			want: []string{"/home/me/node_modules/@scope/pkg/dist/index.js"},
		},
		{
			name: "environment names, long or with an empty value",
			args: []string{"-e", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=grpc", "MY_VERY_LONG_ENV_NAME=", "DEBUG=", "--enable-feature="},
			want: []string{"-e", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=grpc", "MY_VERY_LONG_ENV_NAME=", "DEBUG=", "--enable-feature="},
		},
		{
			name: "flag with a plain value after equals",
			args: []string{"--log-level=debug", "--root=/srv/data"},
			want: []string{"--log-level=debug", "--root=/srv/data"},
		},
		{
			name: "URL without credentials",
			args: []string{"--url", "https://example.com/mcp"},
			want: []string{"--url", "https://example.com/mcp"},
		},

		// Path shapes.
		{
			name: "home, parent and Windows paths",
			args: []string{"~/keys/a.pem", "../x", `C:\Users\me\a.txt`, "C:/x", `C:\x`, "C:"},
			want: []string{"~/keys/a.pem", "../x", `C:\Users\me\a.txt`, "C:/x", `C:\x`, "C:"},
		},

		// Arguments with nothing in them.
		{
			name: "dash, double dash and empty arguments",
			args: []string{"-", "--", ""},
			want: []string{"-", "--", ""},
		},
		{
			name: "no arguments",
			args: []string{},
			want: []string{},
		},
	}, checkLeaks)
}

// TestRedactArgsNil checks that nil input gives nil, not an empty slice.
func TestRedactArgsNil(t *testing.T) {
	t.Parallel()
	if got := discover.RedactArgs(nil); got != nil {
		t.Errorf("RedactArgs(nil) = %q, want nil", got)
	}
}

// TestRedactArgsReturnsCopy checks that the result does not share memory
// with the input: changing the result must not change args.
func TestRedactArgsReturnsCopy(t *testing.T) {
	t.Parallel()
	args := []string{"-y", "pkg"}
	got := discover.RedactArgs(args)
	got[0] = "changed"
	if args[0] != "-y" {
		t.Errorf("changing the result changed the input: args[0] = %q", args[0])
	}
}

// TestRedactArgsKnownLimits records cases that RedactArgs gets wrong today.
// The RedactArgs doc comment lists them. If a future change fixes one,
// update this test on purpose.
func TestRedactArgsKnownLimits(t *testing.T) {
	t.Parallel()

	// weak is a secret with a plain shape: a short word.
	const weak = "hunter2"

	runRedactArgsCases(t, []redactArgsCase{
		// Misses: a secret with a plain shape is shown.
		{
			name: "plain word after a flag that is not secret-like",
			args: []string{"--db", weak},
			want: []string{"--db", weak},
		},
		{
			name: "positional plain word",
			args: []string{weak},
			want: []string{weak},
		},
		{
			name: "short path segment",
			args: []string{"/run/" + weak + "/x"},
			want: []string{"/run/" + weak + "/x"},
		},
		{
			name: "short value glued to a short flag",
			args: []string{"-p" + weak},
			want: []string{"-p" + weak},
		},
		{
			name: "number in the place of a port",
			args: []string{"admin:1234"},
			want: []string{"admin:1234"},
		},
		{
			name: "token split by slashes into short pieces",
			args: []string{"AbCdEfGh/IjKlMnOp"},
			want: []string{"AbCdEfGh/IjKlMnOp"},
		},
		{
			name: "secret value that starts with two dashes",
			args: []string{"--password", "--" + weak},
			want: []string{"--password", "--" + weak},
		},
		{
			name: "short base64 text with padding",
			args: []string{"abcdefgh=", "abcdefgh=="},
			want: []string{"abcdefgh=", "abcdefgh=" + discover.Mask},
		},
		{
			name: "base64 text with padding in the form of an environment name",
			args: []string{"ABCDEFGH_IJKLMNOP="},
			want: []string{"ABCDEFGH_IJKLMNOP="},
		},
		{
			name: "lower-case glued short form",
			args: []string{"--dbpass", weak},
			want: []string{"--dbpass", weak},
		},

		// False positives: a value that is not secret is masked.
		{
			name: "boolean secret-like flag masks the next positional argument",
			args: []string{"--no-auth", "server.js"},
			want: []string{"--no-auth", discover.Mask},
		},
		{
			name: "boolean secret-like flag with a new secret word",
			args: []string{"--private", "server.js"},
			want: []string{"--private", discover.Mask},
		},
		{
			name: "one-letter flag after a boolean secret-like flag",
			args: []string{"--no-auth", "-v", "server.js"},
			want: []string{"--no-auth", discover.Mask, "server.js"},
		},
		{
			name: "long name that is not an environment name",
			args: []string{"management.endpoints.web.exposure.include=x"},
			want: []string{discover.Mask},
		},
		{
			name: "boolean flag with a long token-like name masks the next argument",
			args: []string{"--use-v2-protocol-everywhere", "server.js"},
			want: []string{discover.Mask, discover.Mask},
		},
		{
			name: "docker user flag",
			args: []string{"-u", "1000:1000"},
			want: []string{"-u", discover.Mask},
		},
		{
			name: "glob, list and spaces",
			args: []string{"--pattern", "*.go", "a,b", "/Users/me/Library/Application Support/x"},
			want: []string{"--pattern", discover.Mask, discover.Mask, "/Users/me/Library/" + discover.Mask + "/x"},
		},
		{
			name: "long readable segment",
			args: []string{"@modelcontextprotocol/server-with-a-very-long-name-here"},
			want: []string{"@modelcontextprotocol/" + discover.Mask},
		},
		{
			name: "git SSH address",
			args: []string{"git@github.com:org/repo"},
			want: []string{discover.Mask},
		},
		{
			name: "dash argument that is not a flag",
			args: []string{"-javaagent:/x.jar"},
			want: []string{discover.Mask},
		},
		{
			name: "image with a tag",
			args: []string{"mcp/github:latest", "keycloak:latest"},
			want: []string{discover.Mask, discover.Mask},
		},
		{
			name: "IPv6 address with a port",
			args: []string{"[::1]:8080"},
			want: []string{discover.Mask},
		},
		{
			name: "mail address",
			args: []string{"me@example.com"},
			want: []string{discover.Mask},
		},
		{
			name: "version range",
			args: []string{"pkg@^1.2", "pkg@>=1"},
			want: []string{discover.Mask, discover.Mask},
		},
		{
			name: "version with no dot",
			args: []string{"pkg@2", "pkg@v2"},
			want: []string{discover.Mask, discover.Mask},
		},
		{
			name: "all-caps word that ends in a short form",
			args: []string{"BYPASS=1", "SPIN=1"},
			want: []string{"BYPASS=" + discover.Mask, "SPIN=" + discover.Mask},
		},
	}, skipLeakCheck)
}

// FuzzRedactArgs checks that RedactArgs never panics, never changes its
// input, keeps the length, gives only printable ASCII, and always masks the
// value after "--token", whatever comes before and after it. The fuzz
// strings are split on NUL bytes into arguments.
func FuzzRedactArgs(f *testing.F) {
	f.Add("", "")
	f.Add("--no-auth", "server.js")
	f.Add("-H\x00--header", "-u\x00a:b")
	f.Add("Server=x;Password=y", "Bearer\tz")
	f.Add("--key-file\x00/p", "//u:p@h/?k=v")
	f.Add("-\x00--", "-e\x00TOKEN=x")
	f.Add(`{"a":"b"}`, "u:p@tcp(h)/db")
	f.Add("C:\\x\\y", "~/a/b\x00x\u202ey")
	f.Add("--s3-secret-access-key\x00x", "-uadmin:x\x00scott/t@orcl")
	f.Add("@scope/pkg@1.2.3\x00localhost:8080", "a@b@c\x00-HX-K:v")
	f.Add("--password\x00-p=x\x00-token", "c2VjcmV0LXZhbHVlLTEyMzQ=\x00x.sk-abc123")
	f.Add("--pass2\x00-x", "scott@1tiger\x00pkg@v2.0.1-beta.1+b")

	f.Fuzz(func(t *testing.T, before, after string) {
		args := strings.Split(before, "\x00")
		tokenAt := len(args)
		args = append(args, "--token", discovertest.CanaryArgs)
		args = append(args, strings.Split(after, "\x00")...)
		input := slices.Clone(args)

		got := discover.RedactArgs(args)

		if !slices.Equal(args, input) {
			t.Fatalf("RedactArgs changed its input: now %q, was %q", args, input)
		}
		if len(got) != len(args) {
			t.Fatalf("len(RedactArgs(%q)) = %d, want %d", args, len(got), len(args))
		}
		if got[tokenAt] != "--token" || got[tokenAt+1] != discover.Mask {
			t.Fatalf("RedactArgs(%q)[%d:%d] = %q, want [--token %s]",
				args, tokenAt, tokenAt+2, got[tokenAt:tokenAt+2], discover.Mask)
		}
		for i, s := range got {
			if !isPrintableASCII(s) {
				t.Fatalf("RedactArgs(%q)[%d] = %q, want only printable ASCII", args, i, s)
			}
		}
		// The canary can reach the output only if the fuzz strings hold it.
		if !strings.Contains(before+after, discovertest.CanaryArgs) &&
			strings.Contains(strings.Join(got, "\x00"), discovertest.CanaryArgs) {
			t.Fatalf("RedactArgs(%q) = %q leaks the canary", args, got)
		}
	})
}

// ExampleRedactArgs shows a typical mcp-remote command with a token in the
// URL and in a header.
func ExampleRedactArgs() {
	args := []string{"-y", "mcp-remote", "https://host/sse?api_key=abc", "--header", "Authorization: Bearer abc"}
	fmt.Println(discover.RedactArgs(args))
	// Output: [-y mcp-remote https://host/sse?api_key=******** --header ********]
}
