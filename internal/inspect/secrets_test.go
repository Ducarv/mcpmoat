package inspect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// These tests cover Result.Secrets (issue #185): resultSecrets itself, and
// the values that Remote puts in Result.Secrets. The stdio side is in
// sdk_secrets_test.go, because it needs the fixture builds of inspecttest.

// TestResultSecrets checks the filter, the order and the duplicate check of
// resultSecrets, and that it does not change its input.
func TestResultSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		lists [][]string
		want  []string // nil means a nil result
	}{
		{name: "no lists", lists: nil, want: nil},
		{name: "nil list", lists: [][]string{nil}, want: nil},
		{name: "empty lists", lists: [][]string{{}, {}}, want: nil},
		{name: "empty value", lists: [][]string{{""}}, want: nil},
		{name: "all short", lists: [][]string{{"a", "1", "true", "json"}, {"1234567"}}, want: nil},
		{name: "7 bytes is dropped", lists: [][]string{{"1234567"}}, want: nil},
		{name: "8 bytes is kept", lists: [][]string{{"12345678"}}, want: []string{"12345678"}},
		{
			// The limit counts bytes, not runes: "é" has 2 bytes in UTF-8.
			name:  "bytes not runes",
			lists: [][]string{{"ééé", "éééé"}},
			want:  []string{"éééé"},
		},
		{
			name:  "short and long mixed",
			lists: [][]string{{"short", "long-enough-1", "1234567", "12345678"}},
			want:  []string{"long-enough-1", "12345678"},
		},
		{
			name:  "duplicates in one list",
			lists: [][]string{{"dup-value-1", "dup-value-1", "dup-value-1"}},
			want:  []string{"dup-value-1"},
		},
		{
			name:  "duplicates across lists",
			lists: [][]string{{"dup-value-1", "other-value"}, {"dup-value-1"}, {"other-value", "dup-value-1"}},
			want:  []string{"dup-value-1", "other-value"},
		},
		{
			name:  "longest first then by value",
			lists: [][]string{{"bbbbbbbb", "aaaaaaaaaa", "aaaaaaaa", "cccccccccc", "aaaaaaaaa"}},
			want:  []string{"aaaaaaaaaa", "cccccccccc", "aaaaaaaaa", "aaaaaaaa", "bbbbbbbb"},
		},
		{
			// cmp.Compare on strings is byte order: "Z" (0x5A) comes
			// before "a" (0x61).
			name:  "value order is byte order",
			lists: [][]string{{"aaaaaaaa", "Zzzzzzzz", "-zzzzzzz"}},
			want:  []string{"-zzzzzzz", "Zzzzzzzz", "aaaaaaaa"},
		},
		{
			// A shorter value that is part of a longer one comes after it,
			// so a consumer that replaces in order removes the longer one
			// whole.
			name:  "part of a longer value comes after it",
			lists: [][]string{{"tok-12345"}, {"Bearer tok-12345"}},
			want:  []string{"Bearer tok-12345", "tok-12345"},
		},
		{
			name: "multi-list",
			lists: [][]string{
				{"header-value-1", "short"},
				nil,
				{"query-value-22", "header-value-1"},
				{"expanded-3", ""},
			},
			want: []string{"header-value-1", "query-value-22", "expanded-3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// A deep copy that keeps nil as nil, so DeepEqual below sees
			// any change.
			before := slices.Clone(tt.lists)
			for i, l := range before {
				before[i] = slices.Clone(l)
			}

			got := resultSecrets(tt.lists...)

			checkSecrets(t, got, tt.want)
			if !reflect.DeepEqual(tt.lists, before) {
				t.Errorf("resultSecrets changed its input: %q, want %q", tt.lists, before)
			}
		})
	}
}

// assertResultMasked fails the test when one of values shows up when r is
// printed or encoded, or when r.Secrets is printed or encoded on its own. A
// discover.Secret prints and encodes as discover.Mask, so no way of output
// must show the value. r.Secrets must not be empty, so the check is not
// empty.
func assertResultMasked(t *testing.T, r Result, values ...string) {
	t.Helper()
	if len(r.Secrets) == 0 || len(values) == 0 {
		t.Fatalf("assertResultMasked got %d secrets and %d values; nothing to check", len(r.Secrets), len(values))
	}

	printed := fmt.Sprintf("%v %+v %#v %s %v", r, r, r, r.Secrets, r.Secrets)
	if !strings.Contains(printed, discover.Mask) {
		t.Errorf("printed Result has no %q; the check does not see Secrets", discover.Mask)
	}
	outputs := map[string]string{"fmt": printed}
	for name, v := range map[string]any{"json Secrets": r.Secrets, "json Result": r} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error = %v", name, err)
		}
		outputs[name] = string(b)
	}
	// gob refuses a Secret (it has no exported fields). An error is the
	// safe outcome; output, if any, must not hold a value.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(r.Secrets); err == nil {
		outputs["gob Secrets"] = buf.String()
	}

	for name, out := range outputs {
		for _, v := range values {
			if v == "" {
				t.Fatal("assertResultMasked got an empty value")
			}
			if strings.Contains(out, v) {
				t.Errorf("%s output holds the secret value %q", name, v)
			}
		}
	}
}

// rmBasic returns the "Basic" Authorization value for name and password.
func rmBasic(name, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+password))
}

// rmUserURL returns the fixture URL with user info in front of the host.
func rmUserURL(ts *httptest.Server, userinfo string) string {
	return "http://" + userinfo + "@" + strings.TrimPrefix(ts.URL, "http://") + "/mcp"
}

// TestRemoteResultSecrets checks that each source of secrets in a remote
// config reaches Result.Secrets on success, each source in its own case, so
// that a missing source fails one named case. It also checks the order, the
// duplicate check and the length filter, and that no value shows when the
// Result is printed or encoded.
func TestRemoteResultSecrets(t *testing.T) {
	t.Parallel()

	// pathSecret is a path segment that discover.RedactURL masks: a "="
	// marks a key=value pair.
	const pathSecret = "key=path-secret-1"

	tests := []struct {
		name    string
		headers map[string]string
		// url builds the configured URL. nil means fixtureURL.
		url     func(ts *httptest.Server) string
		wrap    func(http.Handler) http.Handler
		secrets []string // RemoteOptions.expanded.long, the expanded values
		want    []string
	}{
		{name: "no secrets", want: nil},
		{
			name:    "header value",
			headers: map[string]string{"X-Api-Key": "hdr-value-only-1"},
			want:    []string{"hdr-value-only-1"},
		},
		{
			name:    "bearer credential",
			headers: map[string]string{"Authorization": "Bearer bearer-cred-22"},
			want:    []string{"Bearer bearer-cred-22", "bearer-cred-22"},
		},
		{
			// The value, the base64 credential, the decoded name and the
			// decoded password. The name has 8 or more bytes and a digit, so
			// discover.IsSecretUserName counts it as a token (see
			// userinfoSecrets). "basic-name-1" sorts before "basic-pass-1".
			name:    "basic name and password",
			headers: map[string]string{"Authorization": rmBasic("basic-name-1", "basic-pass-1")},
			want: []string{
				rmBasic("basic-name-1", "basic-pass-1"),
				strings.TrimPrefix(rmBasic("basic-name-1", "basic-pass-1"), "Basic "),
				"basic-name-1",
				"basic-pass-1",
			},
		},
		{
			// A plain name (no digit, no token sign) next to a password is
			// not in the list, though it has 8 or more bytes.
			name:    "basic plain name and password",
			headers: map[string]string{"Authorization": rmBasic("readonly-user", "basic-pass-2")},
			want: []string{
				rmBasic("readonly-user", "basic-pass-2"),
				strings.TrimPrefix(rmBasic("readonly-user", "basic-pass-2"), "Basic "),
				"basic-pass-2",
			},
		},
		{
			// With no password, the decoded name is the credential.
			name:    "basic name only",
			headers: map[string]string{"Authorization": rmBasic("basic-name-only-1", "")},
			want: []string{
				rmBasic("basic-name-only-1", ""),
				strings.TrimPrefix(rmBasic("basic-name-only-1", ""), "Basic "),
				"basic-name-only-1",
			},
		},
		{
			name: "user info password",
			url:  func(ts *httptest.Server) string { return rmUserURL(ts, "user-name:userinfo-pw-1") },
			want: []string{
				rmBasic("user-name", "userinfo-pw-1"),
				strings.TrimPrefix(rmBasic("user-name", "userinfo-pw-1"), "Basic "),
				// The whole user info, from urlCredentials.
				"user-name:userinfo-pw-1",
				"userinfo-pw-1",
			},
		},
		{
			// https://<token>:x-oauth-basic@host/: the name has a token
			// prefix, so it is in the list next to the password.
			name: "user info token name with a password",
			url:  func(ts *httptest.Server) string { return rmUserURL(ts, "ghp_userinfo1:x-oauth-basic") },
			want: []string{
				rmBasic("ghp_userinfo1", "x-oauth-basic"),
				strings.TrimPrefix(rmBasic("ghp_userinfo1", "x-oauth-basic"), "Basic "),
				// The whole user info, from urlCredentials.
				"ghp_userinfo1:x-oauth-basic",
				"ghp_userinfo1",
				"x-oauth-basic",
			},
		},
		{
			name: "user info token as user name",
			url:  func(ts *httptest.Server) string { return rmUserURL(ts, "tok-as-username-1") },
			want: []string{
				rmBasic("tok-as-username-1", ""),
				strings.TrimPrefix(rmBasic("tok-as-username-1", ""), "Basic "),
				"tok-as-username-1",
			},
		},
		{
			name: "secret query value",
			url:  func(ts *httptest.Server) string { return fixtureURL(ts) + "?token=query-secret-1" },
			want: []string{"query-secret-1"},
		},
		{
			name: "secret path segment",
			url:  func(ts *httptest.Server) string { return ts.URL + "/" + pathSecret + "/mcp" },
			wrap: func(next http.Handler) http.Handler { return http.StripPrefix("/"+pathSecret, next) },
			// The value of the key=value segment, from urlCredentials.
			want: []string{pathSecret, "path-secret-1"},
		},
		{
			name:    "expanded values",
			secrets: []string{"expanded-value-1", "expanded-value-22"},
			want:    []string{"expanded-value-22", "expanded-value-1"},
		},
		{
			// One value in a header, the query and the expanded values is
			// in the list one time.
			name:    "duplicates once",
			headers: map[string]string{"X-Api-Key": "dup-secret-1", "X-Other": "dup-secret-1"},
			url:     func(ts *httptest.Server) string { return fixtureURL(ts) + "?token=dup-secret-1" },
			secrets: []string{"dup-secret-1"},
			want:    []string{"dup-secret-1"},
		},
		{
			// 7 bytes is under the limit, 8 bytes is at it.
			name:    "short values are dropped",
			headers: map[string]string{"X-Short": "SEVEN77", "X-Eight": "EIGHT888"},
			url:     func(ts *httptest.Server) string { return fixtureURL(ts) + "?token=QSEVEN7" },
			secrets: []string{"ESEVEN7"},
			want:    []string{"EIGHT888"},
		},
		{
			name:    "every source sorted",
			headers: map[string]string{"Authorization": "Bearer all-bearer-1", "X-Api-Key": "all-header-value-1"},
			url:     func(ts *httptest.Server) string { return rmUserURL(ts, "all-user-token-1") + "?token=all-query-1" },
			secrets: []string{"all-expanded-1"},
			want: []string{
				rmBasic("all-user-token-1", ""),
				strings.TrimPrefix(rmBasic("all-user-token-1", ""), "Basic "),
				"Bearer all-bearer-1",
				"all-header-value-1",
				"all-user-token-1",
				"all-expanded-1",
				"all-bearer-1",
				"all-query-1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ts, _ := startFixture(t, fixtureOpts{Wrap: tt.wrap})
			rawURL := fixtureURL(ts)
			if tt.url != nil {
				rawURL = tt.url(ts)
			}
			srv := rmServer(discover.TransportHTTP, rawURL, tt.headers)

			got, err := Remote(t.Context(), srv, RemoteOptions{expanded: secretLists{long: tt.secrets}})
			if err != nil {
				t.Fatalf("Remote() error = %v", err)
			}
			rmCheckResult(t, got, tt.want...)
			if len(tt.want) > 0 {
				assertResultMasked(t, got, tt.want...)
			}
		})
	}
}

// TestRemoteResultSecretsShortScrub checks that a short header value and a
// short URL password are not in Result.Secrets, while the scrub of error
// text still removes them when the server echoes them. A failed inspection
// returns the zero Result, so Secrets is nil.
func TestRemoteResultSecretsShortScrub(t *testing.T) {
	t.Parallel()

	const (
		shortHeader   = "SEVEN77"   // 7 bytes
		shortPassword = "pw7"       // 3 bytes
		longHeader    = "LONGHDR88" // 9 bytes, the control
		echoMarker    = "unknown credentials"
	)
	headers := map[string]string{"X-Short": shortHeader, "X-Long": longHeader}
	userinfo := "short-user:" + shortPassword

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		ts, _ := startFixture(t, fixtureOpts{})
		srv := rmServer(discover.TransportHTTP, rmUserURL(ts, userinfo), headers)

		got, err := Remote(t.Context(), srv, RemoteOptions{})
		if err != nil {
			t.Fatalf("Remote() error = %v", err)
		}
		basic := rmBasic("short-user", shortPassword)
		// The whole user info has more than 8 bytes, so it is in the list
		// (from urlCredentials). The short password alone is not.
		rmCheckResult(t, got, basic, strings.TrimPrefix(basic, "Basic "), userinfo, longHeader)
	})

	t.Run("failure echoes the values", func(t *testing.T) {
		t.Parallel()
		mcpSrv := newFixtureMCPServer()
		mcpSrv.AddReceivingMiddleware(onMethod(methodListTools, func(context.Context, string, mcp.Request) (mcp.Result, error) {
			return nil, fmt.Errorf("%s: %s %s %s", echoMarker, shortHeader, shortPassword, longHeader)
		}))
		ts, _ := startFixture(t, fixtureOpts{Server: mcpSrv})
		srv := rmServer(discover.TransportHTTP, rmUserURL(ts, userinfo), headers)

		got, err := Remote(t.Context(), srv, RemoteOptions{})
		ce := rmRequireConnectError(t, err, KindProtocol)
		// The echo must reach the error text, or the scrub check below
		// checks nothing.
		if !strings.Contains(err.Error(), echoMarker) {
			t.Fatalf("error %q does not hold the echo of the server; the test checks nothing", err.Error())
		}
		assertNoSecrets(t, err, shortHeader, shortPassword, longHeader)
		if ce.Reason == "" {
			t.Error("Reason is empty")
		}
		if got.Secrets != nil {
			t.Errorf("Result.Secrets = %q on failure, want nil", revealSecrets(got.Secrets))
		}
		if !reflect.DeepEqual(got, Result{}) {
			t.Errorf("Remote() Result = %+v on failure, want the zero Result", got)
		}
	})
}

// TestRemoteResultSecretsNilOnFailure checks that every failed Remote call
// returns a nil Result.Secrets, also when the config holds long secrets:
// before a request (a config error and the untrusted gate) and after one
// (an HTTP error).
func TestRemoteResultSecretsNilOnFailure(t *testing.T) {
	t.Parallel()

	notFound := func(t *testing.T) string {
		t.Helper()
		ts := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(ts.Close)
		return rmWithSecretQuery(ts.URL + "/mcp")
	}
	tests := []struct {
		name      string
		url       func(t *testing.T) string
		untrusted bool
		kinds     []ConnectKind
	}{
		{name: "config error", url: func(*testing.T) string { return "ftp://example.invalid/mcp?token=" + rmQuerySecret }, kinds: []ConnectKind{KindConfig}},
		{name: "untrusted gate", url: notFound, untrusted: true, kinds: []ConnectKind{KindConfig}},
		{name: "server answers 404", url: notFound, kinds: []ConnectKind{KindHTTP, KindProtocol}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := rmServer(discover.TransportHTTP, tt.url(t), rmHeaders())
			srv.Untrusted = tt.untrusted

			got, err := Remote(t.Context(), srv, RemoteOptions{expanded: secretLists{long: []string{"expanded-value-1"}}})
			if err == nil {
				t.Fatal("Remote() error = nil, want an error")
			}
			if ce, ok := errors.AsType[*ConnectError](err); !ok || !slices.Contains(tt.kinds, ce.Kind) {
				t.Errorf("Remote() error = %v (%T), want a *ConnectError of kind %v", err, err, tt.kinds)
			}
			if got.Secrets != nil {
				t.Errorf("Result.Secrets = %q on failure, want nil", revealSecrets(got.Secrets))
			}
			if !reflect.DeepEqual(got, Result{}) {
				t.Errorf("Remote() Result = %+v on failure, want the zero Result", got)
			}
		})
	}
}

// The tests below cover Result.Credentials (issues #229 and #235): the
// subset of Result.Secrets that looks like a credential. resultCredentials
// is the filter, and isCredential, envCredentials, argCredentials and
// lookupRecorder find the credential values of a stdio config. The remote
// side is in remote_test.go and the stdio Inspect side in
// sdk_secrets_test.go. All values are fake.

// credTok is a fake token: 21 bytes with letters and digits, so
// discover.TokenLike reports true for it whatever its name.
const credTok = "FAKE-TOKEN-0123456789"

// credDSN is a fake connection URL with a password. Its words are not
// token-like, so only discover.ArgCredentials, which finds the password,
// makes it a credential.
const credDSN = "postgres://app:hunter2pw@db/prod" //nolint:gosec // G101: fake test credential

// credDSNPort is a fake connection URL with a port and a password of 14
// bytes. Its inner pieces "app:S3cretPassw0rd" and "S3cretPassw0rd" are long
// enough for Result.Secrets.
const credDSNPort = "postgres://app:S3cretPassw0rd@db:5432/app" //nolint:gosec // G101: fake test credential

// credDSNShortPW is a fake connection URL with a password of 2 bytes. Its
// inner pieces are too short for Result.Secrets: they go to the whole-word
// list of the error scrub only. The whole URL is long enough.
const credDSNShortPW = "postgres://app:pw@db/app" //nolint:gosec // G101: fake test credential

// checkCredentials fails the test when the revealed values of r.Credentials
// are not want, in the same order, or when want is empty and r.Credentials is
// not nil. It also checks the subset rule: each value of r.Credentials is in
// r.Secrets, in the order of r.Secrets. The values are fake test secrets, so
// the messages show them.
func checkCredentials(t *testing.T, r Result, want []string) {
	t.Helper()
	got := revealSecrets(r.Credentials)
	if !slices.Equal(got, want) {
		t.Errorf("Result.Credentials = %q, want %q", got, want)
	}
	if len(want) == 0 && r.Credentials != nil {
		t.Errorf("Result.Credentials = %#v, want nil", r.Credentials)
	}
	// A subsequence check: walk Secrets one time and find each credential
	// after the one before it.
	secrets := revealSecrets(r.Secrets)
	i := 0
	for _, c := range got {
		for i < len(secrets) && secrets[i] != c {
			i++
		}
		if i == len(secrets) {
			t.Errorf("Result.Credentials = %q is not a subset of Result.Secrets = %q in its order", got, secrets)
			return
		}
		i++
	}
}

// TestResultCredentials checks the filter of resultCredentials: it keeps
// the values of secrets that are in a list, in the order of secrets, each
// one time, and it is nil when no value is kept.
func TestResultCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// secrets go through resultSecrets first, as in Inspect and Remote.
		secrets []string
		lists   [][]string
		want    []string // nil means a nil result
	}{
		{name: "no secrets", secrets: nil, lists: [][]string{{"some-value-1"}}, want: nil},
		{name: "no lists", secrets: []string{"some-value-1"}, lists: nil, want: nil},
		{name: "empty lists", secrets: []string{"some-value-1"}, lists: [][]string{nil, {}}, want: nil},
		{
			// A value that only the lists hold is never added.
			name:    "value not in secrets",
			secrets: []string{"some-value-1"},
			lists:   [][]string{{"other-value-2", credTok}},
			want:    nil,
		},
		{
			// resultSecrets drops the 7-byte value, so it cannot be a
			// credential either; the 8-byte one stays.
			name:    "8-byte minimum",
			secrets: []string{"SEVEN77", "EIGHT888"},
			lists:   [][]string{{"SEVEN77", "EIGHT888"}},
			want:    []string{"EIGHT888"},
		},
		{
			name:    "subset keeps the order of secrets",
			secrets: []string{"bbbbbbbb", "aaaaaaaaaa", "plain-value", "cccccccccc"},
			lists:   [][]string{{"bbbbbbbb", "cccccccccc"}, {"aaaaaaaaaa"}},
			want:    []string{"aaaaaaaaaa", "cccccccccc", "bbbbbbbb"},
		},
		{
			name:    "duplicates once",
			secrets: []string{credTok, "plain-value"},
			lists:   [][]string{{credTok, credTok}, {credTok}},
			want:    []string{credTok},
		},
		{
			name:    "every value is a credential",
			secrets: []string{credTok, credDSN},
			lists:   [][]string{{credDSN}, {credTok}},
			want:    []string{credDSN, credTok},
		},
		{
			// The plain words of issue #235 are in Secrets and not in the
			// lists, so only the token is kept.
			name:    "plain words dropped",
			secrets: []string{"production", "information", "application/json", credTok},
			lists:   [][]string{{credTok}},
			want:    []string{credTok},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			secrets := resultSecrets(tt.secrets)
			before := revealSecrets(secrets)

			got := resultCredentials(secrets, tt.lists...)

			checkCredentials(t, Result{Secrets: secrets, Credentials: got}, tt.want)
			if after := revealSecrets(secrets); !slices.Equal(after, before) {
				t.Errorf("resultCredentials changed secrets: %q, want %q", after, before)
			}
		})
	}
}

// TestIsCredential checks the name and value rules of isCredential, with the
// plain config words of issue #235 as cases that must not match.
func TestIsCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		varName  string
		value    string
		want     bool
		describe string
	}{
		// Must match.
		{varName: "API_KEY", value: "production", want: true, describe: "secret-like name, plain value"},
		{varName: "MCPMOAT_TEST_TOKEN", value: "production", want: true, describe: "token in the name"},
		{varName: "NODE_ENV", value: credTok, want: true, describe: "plain name, token-like value"},
		{varName: "", value: credTok, want: true, describe: "no name, token-like value"},
		{varName: "DATABASE_URL", value: credDSN, want: true, describe: "URL with a password"},
		{varName: "PGOPTS", value: "host=db password=hunter2pw", want: true, describe: "connection string with a password"},
		{varName: "X", value: "Bearer " + credTok, want: true, describe: "auth scheme and token"},
		{varName: "X", value: "ghp_FAKE0123", want: true, describe: "token prefix"},
		{varName: "X", value: "0f8fad5b-d9cb-469f-a165-70867728950e", want: true, describe: "UUID"},
		// Must not match.
		{varName: "NODE_ENV", value: "production", want: false, describe: "plain name, plain value"},
		{varName: "LOG_LEVEL", value: "information", want: false, describe: "log level"},
		{varName: "PGOPTS", value: "host=localhost dbname=production user=postgres", want: false, describe: "connection string with no password"},
		{varName: "Content-Type", value: "application/json", want: false, describe: "media type"},
		{varName: "User-Agent", value: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", want: false, describe: "browser User-Agent"},
		{varName: "User-Agent", value: "my-client/1.2.3", want: false, describe: "client User-Agent"},
		{varName: "X-Title", value: "My Documents", want: false, describe: "title of two words"},
		{varName: "Accept", value: "text/event-stream, application/json", want: false, describe: "media type list"},
		{varName: "", value: "", want: false, describe: "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.describe, func(t *testing.T) {
			t.Parallel()
			if got := isCredential(tt.varName, tt.value); got != tt.want {
				t.Errorf("isCredential(%q, %q) = %v, want %v", tt.varName, tt.value, got, tt.want)
			}
		})
	}
}

// TestEnvCredentials checks envCredentials: the env values of 8 bytes or
// more whose key is secret-like or that look like a credential, in the order
// of the sorted keys.
func TestEnvCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		want []string // nil means a nil result
	}{
		{name: "no env", env: nil, want: nil},
		{name: "plain values", env: map[string]string{"NODE_ENV": "production", "LOG_LEVEL": "information"}, want: nil},
		{name: "secret-like key", env: map[string]string{"API_KEY": "production"}, want: []string{"production"}},
		{name: "token-like value", env: map[string]string{"REGION": credTok}, want: []string{credTok}},
		// After the value, the credentials inside it (see valueCredentials).
		{name: "URL with a password", env: map[string]string{"DATABASE_URL": credDSN}, want: []string{credDSN, "app:hunter2pw", "hunter2pw"}},
		{
			name: "connection string with no password",
			env:  map[string]string{"PGOPTS": "host=localhost dbname=production user=postgres"},
			want: nil,
		},
		{
			// The value has 7 bytes: under discover.MinSecretBytes, though
			// the key is secret-like.
			name: "short value",
			env:  map[string]string{"API_KEY": "SEVEN77", "TOKEN": ""},
			want: nil,
		},
		{
			// The keys sort as A_TOKEN, B_PLAIN, C_URL, NODE_ENV.
			name: "mixed in key order",
			env:  map[string]string{"NODE_ENV": "production", "C_URL": credDSN, "B_PLAIN": "plain-value", "A_TOKEN": "EIGHT888"},
			want: []string{"EIGHT888", credDSN, "app:hunter2pw", "hunter2pw"},
		},
		{
			// resultCredentials removes the duplicate later.
			name: "same value twice",
			env:  map[string]string{"A_TOKEN": credTok, "B": credTok},
			want: []string{credTok, credTok},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := make(discover.SecretMap, len(tt.env))
			for k, v := range tt.env {
				env[k] = discover.NewSecret(v)
			}
			got := envCredentials(env)
			if !slices.Equal(got, tt.want) || (tt.want == nil && got != nil) {
				t.Errorf("envCredentials() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestInnerCredentialsEverySource checks that the credentials inside one
// config value (see valueCredentials) reach the same lists whether the value
// is an env value (envSecrets, envCredentials), the value of an expanded
// variable (lookupRecorder) or a header value (splitHeaders,
// headerCredentials, headerShortSecrets). A server can echo the password of a
// connection URL alone, so a long piece goes to Secrets and Credentials and a
// short piece to the whole-word list only. A value with no credential in it
// gets no inner piece.
func TestInnerCredentialsEverySource(t *testing.T) {
	t.Parallel()

	// lists are the lists of one source for one config value: the long list
	// for Result.Secrets, the credentials and the short whole-word list.
	type lists struct{ secrets, creds, short []string }
	// The env key, the variable name and the header key are plain, so only
	// the value can make it a credential.
	sources := map[string]func(value string) lists{
		"env value": func(value string) lists {
			env := discover.SecretMap{"MCPMOAT_TEST_VALUE": discover.NewSecret(value)}
			secrets, short := envSecrets(env)
			return lists{secrets, envCredentials(env), short}
		},
		"expanded variable": func(value string) lists {
			rec := &lookupRecorder{lookup: func(string) (string, bool) { return value, true }}
			rec.Lookup("MCPMOAT_TEST_VALUE")
			return lists{rec.values, rec.credentialList, rec.short}
		},
		"header value": func(value string) lists {
			cfg := discover.SecretMap{"X-Db": discover.NewSecret(value)}
			_, secrets := splitHeaders(cfg)
			return lists{secrets, headerCredentials(cfg), headerShortSecrets(cfg)}
		},
	}
	tests := []struct {
		name        string
		value       string
		wantSecrets []string // in the order of Result.Secrets
		wantCreds   []string // in the order of Result.Secrets
		wantShort   []string // sorted, each value one time
	}{
		{
			name:        "long password",
			value:       credDSNPort,
			wantSecrets: []string{credDSNPort, "app:S3cretPassw0rd", "S3cretPassw0rd"},
			wantCreds:   []string{credDSNPort, "app:S3cretPassw0rd", "S3cretPassw0rd"},
		},
		{
			name:        "short password",
			value:       credDSNShortPW,
			wantSecrets: []string{credDSNShortPW},
			wantCreds:   []string{credDSNShortPW},
			wantShort:   []string{"app:pw", "pw"},
		},
		// Must not match: a media type has no credential in it.
		{
			name:        "media type",
			value:       "application/json",
			wantSecrets: []string{"application/json"},
		},
	}
	for _, tt := range tests {
		for name, source := range sources {
			t.Run(tt.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				got := source(tt.value)
				// The same filters as Inspect and Remote.
				r := Result{Secrets: resultSecrets(got.secrets)}
				r.Credentials = resultCredentials(r.Secrets, got.creds)

				checkSecrets(t, r.Secrets, tt.wantSecrets)
				checkCredentials(t, r, tt.wantCreds)
				// slices.Sorted reads the values from the iterator that
				// slices.Values gives and returns them in a new sorted slice.
				if short := slices.Compact(slices.Sorted(slices.Values(got.short))); !slices.Equal(short, tt.wantShort) {
					t.Errorf("short list = %q, want %q", short, tt.wantShort)
				}
			})
		}
	}
}

// TestArgCredentials checks argCredentials: the pieces of the command line
// that discover.ArgCredentials finds, of 8 bytes or more. The command is part
// of the line.
func TestArgCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		args    []string
		want    []string // nil means a nil result
	}{
		{name: "no args", command: "server", want: nil},
		{name: "plain args", command: "npx", args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/home/me/proj", "--port", "8080"}, want: nil},
		{name: "secret flag, plain value", command: "server", args: []string{"--api-key", "plainvalue1"}, want: []string{"plainvalue1"}},
		{name: "token after equals", command: "server", args: []string{"--token=" + credTok}, want: []string{credTok}},
		{
			name:    "connection string with no password",
			command: "server",
			args:    []string{"--dsn", "host=localhost dbname=production"},
			want:    nil,
		},
		{name: "URL with a password", command: "server", args: []string{credDSN}, want: []string{"app:hunter2pw", "hunter2pw"}},
		{
			name:    "header line",
			command: "curl",
			args:    []string{"-H", "Authorization: Bearer " + credTok},
			want:    []string{"Authorization: Bearer " + credTok, "Bearer " + credTok, credTok},
		},
		{
			// "SEVEN77" has 7 bytes, under discover.MinSecretBytes.
			name:    "short value dropped",
			command: "server",
			args:    []string{"--token", "SEVEN77", "--api-key=EIGHT888"},
			want:    []string{"EIGHT888"},
		},
		{name: "token segment in the command", command: "/opt/ghp_FAKEcmd0123456/server", want: []string{"ghp_FAKEcmd0123456"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := discover.Server{Command: tt.command, Args: discover.NewArgs(tt.args)}
			got := argCredentials(s)
			if !slices.Equal(got, tt.want) || (tt.want == nil && got != nil) {
				t.Errorf("argCredentials() = %q, want %q", got, tt.want)
			}
			// Each credential is also an argv secret, so resultCredentials
			// can find it in Result.Secrets.
			long, _ := argSecrets(s)
			for _, c := range got {
				if !slices.Contains(long, c) {
					t.Errorf("argCredentials() value %q is not in argSecrets() %q", c, long)
				}
			}
		})
	}
}

// TestLookupRecorderCredentials checks the credentials that lookupRecorder
// keeps for the values of expanded variables: a value is a credential when
// one of the names it was looked up under is secret-like, whatever the order
// of the lookups, or when it looks like a credential.
func TestLookupRecorderCredentials(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"REGION":   "production",
		"API_KEY":  "production",
		"PLAIN":    credTok,
		"SHORT":    "SEVEN77",
		"PASSWORD": "SEVEN77",
		"OTHER":    "plain-value",
		"EMPTY":    "",
	}
	tests := []struct {
		name    string
		lookups []string
		want    []string // nil means no credential
	}{
		{name: "plain name, plain value", lookups: []string{"REGION"}, want: nil},
		{name: "secret-like name", lookups: []string{"API_KEY"}, want: []string{"production"}},
		{name: "token-like value", lookups: []string{"PLAIN"}, want: []string{credTok}},
		{name: "plain name first, then secret-like", lookups: []string{"REGION", "API_KEY"}, want: []string{"production"}},
		{name: "secret-like name first, then plain", lookups: []string{"API_KEY", "REGION"}, want: []string{"production"}},
		{name: "repeated lookups once", lookups: []string{"API_KEY", "API_KEY", "REGION", "PLAIN", "PLAIN"}, want: []string{"production", credTok}},
		{name: "plain name twice", lookups: []string{"REGION", "REGION", "OTHER"}, want: nil},
		{
			// A value under discover.MinSecretBytes never goes to Secrets,
			// so it is no credential, also under a secret-like name.
			name:    "short value",
			lookups: []string{"SHORT", "PASSWORD"},
			want:    nil,
		},
		{name: "missing and empty", lookups: []string{"MISSING", "EMPTY"}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := &lookupRecorder{lookup: func(name string) (string, bool) {
				v, ok := env[name]
				return v, ok
			}}
			for _, name := range tt.lookups {
				rec.Lookup(name)
			}
			if !slices.Equal(rec.credentialList, tt.want) {
				t.Errorf("credentials = %q, want %q", rec.credentialList, tt.want)
			}
			// Each credential is also a long value, so resultCredentials can
			// find it in Result.Secrets.
			for _, c := range rec.credentialList {
				if !slices.Contains(rec.values, c) {
					t.Errorf("credential %q is not in values %q", c, rec.values)
				}
			}
		})
	}
}
