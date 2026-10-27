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
		secrets []string // RemoteOptions.secrets, the expanded values
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
			want: []string{pathSecret},
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

			got, err := Remote(t.Context(), srv, RemoteOptions{secrets: tt.secrets})
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
		rmCheckResult(t, got, basic, strings.TrimPrefix(basic, "Basic "), longHeader)
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

			got, err := Remote(t.Context(), srv, RemoteOptions{secrets: []string{"expanded-value-1"}})
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
