package inspect

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// This file holds the unit tests of the unexported helpers of sdk.go.
// sdk_test.go is in package inspect_test and cannot reach them.

// TestLookupRecorder checks that lookupRecorder returns what the wrapped
// lookup returns, and records each value of at least minBareSecretLen bytes
// one time only, in the order of the first lookup.
func TestLookupRecorder(t *testing.T) {
	t.Parallel()

	long1 := "mcpmoat-recorder-canary-1aB2"
	long2 := "mcpmoat-recorder-canary-3cD4"
	atLimit := strings.Repeat("x", minBareSecretLen)
	belowLimit := strings.Repeat("y", minBareSecretLen-1)
	env := []string{
		"A=" + long1,
		"A_AGAIN=" + long1, // another variable with the same value
		"B=" + long2,
		"AT_LIMIT=" + atLimit,
		"SHORT=" + belowLimit,
		"EMPTY=",
	}

	tests := []struct {
		name    string
		lookups []string
		want    []string
	}{
		{name: "no lookup", lookups: nil, want: nil},
		{name: "one value", lookups: []string{"A"}, want: []string{long1}},
		{name: "same variable many times", lookups: []string{"A", "A", "A", "A"}, want: []string{long1}},
		{name: "same value from two variables", lookups: []string{"A", "A_AGAIN"}, want: []string{long1}},
		{name: "order of the first lookup", lookups: []string{"B", "A", "B", "A"}, want: []string{long2, long1}},
		{name: "value at the length limit", lookups: []string{"AT_LIMIT", "AT_LIMIT"}, want: []string{atLimit}},
		{name: "value below the length limit", lookups: []string{"SHORT", "SHORT"}, want: nil},
		{name: "empty value", lookups: []string{"EMPTY"}, want: nil},
		{name: "unset variable", lookups: []string{"UNSET", "UNSET"}, want: nil},
		{
			name:    "mixed",
			lookups: []string{"UNSET", "SHORT", "A", "AT_LIMIT", "A_AGAIN", "B", "A", "AT_LIMIT"},
			want:    []string{long1, atLimit, long2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lookup := environLookup(env)
			rec := &lookupRecorder{lookup: lookup}
			for _, name := range tt.lookups {
				gotV, gotOK := rec.Lookup(name)
				wantV, wantOK := lookup(name)
				if gotV != wantV || gotOK != wantOK {
					// Print the lengths only: the values stand for secrets.
					t.Errorf("Lookup(%q) = (len %d, %v), want (len %d, %v)", name, len(gotV), gotOK, len(wantV), wantOK)
				}
			}
			if !slices.Equal(rec.values, tt.want) {
				t.Errorf("values has %d entries, want %d (%d lookups); values equal = false",
					len(rec.values), len(tt.want), len(tt.lookups))
			}
		})
	}
}

// TestLookupRecorderZeroValue checks that a lookupRecorder with no seen map
// works: the first recorded value makes the map.
func TestLookupRecorderZeroValue(t *testing.T) {
	t.Parallel()
	const value = "mcpmoat-recorder-canary-5eF6"
	rec := lookupRecorder{lookup: func(string) (string, bool) { return value, true }}
	for range 3 {
		if v, ok := rec.Lookup("ANY"); v != value || !ok {
			t.Fatalf("Lookup() = (len %d, %v), want (len %d, true)", len(v), ok, len(value))
		}
	}
	if len(rec.values) != 1 || rec.values[0] != value {
		t.Errorf("values has %d entries, want 1 with the value", len(rec.values))
	}
}

// TestExpandPolicyHide checks that expandPolicy.hide refuses a hidden name,
// in any case, for every policy (trusted, untrusted stdio and untrusted
// remote), and keeps the other answers of the policy. It also checks that
// the recorder of Inspect never looks up a hidden variable, so it never
// records its value.
func TestExpandPolicyHide(t *testing.T) {
	t.Parallel()

	const hiddenValue = "mcpmoat-hidden-canary-7gH8"
	hidden := []string{"MCPMOAT_TEST_HIDDEN"}
	servers := map[string]discover.Server{
		"trusted stdio":    {Transport: discover.TransportStdio},
		"trusted remote":   {Transport: discover.TransportHTTP},
		"untrusted stdio":  {Transport: discover.TransportStdio, Untrusted: true},
		"untrusted remote": {Transport: discover.TransportHTTP, Untrusted: true},
	}
	for name, s := range servers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base := expandPolicyFor(s)
			policy := base.hide(hidden)
			for _, v := range []string{"MCPMOAT_TEST_HIDDEN", "mcpmoat_test_hidden", "Mcpmoat_Test_Hidden"} {
				if policy.allowed(v) {
					t.Errorf("allowed(%q) = true, want false for a hidden name", v)
				}
				if policy.hidden == nil || !policy.hidden(v) {
					t.Errorf("hidden(%q) = false, want true", v)
				}
			}
			for _, v := range []string{"HOME", "MCPMOAT_TEST_OTHER", "MCPMOAT_TEST_HIDDEN_2", ""} {
				if got, want := policy.allowed(v), base.allowed(v); got != want {
					t.Errorf("allowed(%q) = %v, want %v as without hide", v, got, want)
				}
				if policy.hidden(v) {
					t.Errorf("hidden(%q) = true, want false", v)
				}
			}
			if policy.note != base.note || policy.workspace != base.workspace {
				t.Errorf("hide changed the note or the workspace of the policy")
			}

			calls := 0
			inner := func(name string) (string, bool) {
				calls++
				return environLookup([]string{"MCPMOAT_TEST_HIDDEN=" + hiddenValue})(name)
			}
			rec := &lookupRecorder{lookup: filterLookup(inner, policy.allowed)}
			if v, ok := rec.Lookup("MCPMOAT_TEST_HIDDEN"); ok || v != "" {
				t.Errorf("Lookup() = (len %d, %v), want (0, false) for a hidden name", len(v), ok)
			}
			if calls != 0 || len(rec.values) != 0 {
				t.Errorf("the hidden variable was looked up %d times and %d values were recorded, want none", calls, len(rec.values))
			}
		})
	}

	// No names: hide returns the policy as it is.
	p := expandPolicyFor(discover.Server{})
	if got := p.hide(nil); got.hidden != nil || !got.allowed("MCPMOAT_TEST_HIDDEN") {
		t.Errorf("hide(nil) changed the policy")
	}
}

// TestEnvironLookup checks that environLookup reads "name=value" entries the
// way os.LookupEnv does on Unix: the first entry wins, an entry with no "="
// is skipped, and an empty name is never found.
func TestEnvironLookup(t *testing.T) {
	t.Parallel()

	env := []string{
		"DUP=first",
		"DUP=second",
		"NOEQUALS",
		"EMPTY=",
		"=C:=C:\\work", // a Windows entry for the work directory of drive C
		"WITH_EQ=a=b",
	}
	tests := []struct {
		name      string
		lookup    string
		wantValue string
		wantOK    bool
	}{
		{name: "duplicate name, first entry wins", lookup: "DUP", wantValue: "first", wantOK: true},
		{name: "entry without = is skipped", lookup: "NOEQUALS", wantValue: "", wantOK: false},
		{name: "set and empty", lookup: "EMPTY", wantValue: "", wantOK: true},
		{name: "value holds =", lookup: "WITH_EQ", wantValue: "a=b", wantOK: true},
		{name: "unset name", lookup: "MISSING", wantValue: "", wantOK: false},
		{name: "empty name", lookup: "", wantValue: "", wantOK: false},
	}
	lookup := environLookup(env)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotValue, gotOK := lookup(tt.lookup)
			if gotValue != tt.wantValue || gotOK != tt.wantOK {
				t.Errorf("lookup(%q) = (%q, %v), want (%q, %v)", tt.lookup, gotValue, gotOK, tt.wantValue, tt.wantOK)
			}
		})
	}
}

// TestShowDiscoveredURL checks that showDiscoveredURL replaces the expanded
// URL with the discovered one in the URL, the reason and the cause of a
// *ConnectError, also in the form without the query, then the expanded host
// (with and without the port), and leaves an error alone when both URLs are
// the same.
func TestShowDiscoveredURL(t *testing.T) {
	t.Parallel()

	t.Run("placeholders in the host", func(t *testing.T) {
		t.Parallel()
		// The discovered URL does not parse (its host holds "${"), so its
		// String is Mask, and Mask stands for its host too.
		discovered := discover.NewURL("https://${MCP_HOST}:${MCP_PORT}/v1?k=${MCP_KEY}")
		expanded := discover.NewURL("https://dev7.example:8443/v1?k=s3cr3t-value-123")
		exp, base := expanded.String(), urlBase(expanded.String())
		cause := errors.New("dial failed for " + base + " and " + exp + ": dial tcp dev7.example:8443: lookup dev7.example: no such host")

		ce := &ConnectError{
			Kind:   KindNetwork,
			Server: "srv",
			Reason: "cannot reach " + exp,
			URL:    exp,
			err:    cause,
		}
		showDiscoveredURL(ce, expanded, discovered)

		mask := discover.Mask
		if ce.URL != mask {
			t.Errorf("URL = %q, want %q", ce.URL, mask)
		}
		if want := "cannot reach " + mask; ce.Reason != want {
			t.Errorf("Reason = %q, want %q", ce.Reason, want)
		}
		if want := "dial failed for " + mask + " and " + mask + ": dial tcp " + mask + ": lookup " + mask + ": no such host"; ce.err.Error() != want {
			t.Errorf("cause = %q, want %q", ce.err.Error(), want)
		}
		for _, leak := range []string{"dev7", "8443", "s3cr3t"} {
			if strings.Contains(ce.Error(), leak) || strings.Contains(ce.err.Error(), leak) {
				t.Errorf("error %q or cause %q holds %q", ce.Error(), ce.err.Error(), leak)
			}
		}
	})

	t.Run("placeholder in the path", func(t *testing.T) {
		t.Parallel()
		// The host is the same in both URLs, so only the URL forms are
		// replaced and the host stays.
		discovered := discover.NewURL("https://api.example.test/${MCP_TENANT}/mcp")
		expanded := discover.NewURL("https://api.example.test/acme7/mcp")
		cause := errors.New("bad status from " + expanded.String() + " at api.example.test")
		ce := &ConnectError{Reason: "failed: " + expanded.String(), err: cause}

		showDiscoveredURL(ce, expanded, discovered)

		if want := "failed: " + discovered.String(); ce.Reason != want {
			t.Errorf("Reason = %q, want %q", ce.Reason, want)
		}
		if want := "bad status from " + discovered.String() + " at api.example.test"; ce.err.Error() != want {
			t.Errorf("cause = %q, want %q", ce.err.Error(), want)
		}
		if strings.Contains(ce.Error(), "acme7") || strings.Contains(ce.err.Error(), "acme7") {
			t.Errorf("error %q or cause %q holds the expanded path", ce.Error(), ce.err.Error())
		}
	})

	t.Run("a rewritten cause keeps its sentinels", func(t *testing.T) {
		t.Parallel()
		// Inspect promises errors.Is(err, context.DeadlineExceeded) for a
		// timeout, and errors.Is on the sentinels of the HTTP layer. The
		// rewrite of the text must keep them, and must keep no old text.
		discovered := discover.NewURL("https://${MCP_HOST}/mcp")
		expanded := discover.NewURL("https://dev7.example/mcp")
		tests := []struct {
			name  string
			cause error
			want  []error
		}{
			{
				name:  "deadline",
				cause: fmt.Errorf("%w: Post %q: i/o timeout", context.DeadlineExceeded, expanded.String()),
				want:  []error{context.DeadlineExceeded},
			},
			{
				name:  "canceled and a blocked sentinel",
				cause: fmt.Errorf("%w: %w: dial dev7.example", errAddrRefused, context.Canceled),
				want:  []error{errAddrRefused, context.Canceled},
			},
			{
				name:  "invalid proxy",
				cause: fmt.Errorf("%w: for dev7.example", errInvalidProxy),
				want:  []error{errInvalidProxy},
			},
		}
		for _, tt := range tests {
			ce := &ConnectError{Kind: KindTimeout, Reason: "timed out", err: tt.cause}
			showDiscoveredURL(ce, expanded, discovered)
			for _, w := range tt.want {
				if !errors.Is(ce, w) {
					t.Errorf("%s: errors.Is(err, %v) = false after the rewrite", tt.name, w)
				}
			}
			if errors.Is(ce, errOtherOrigin) {
				t.Errorf("%s: errors.Is(err, errOtherOrigin) = true, want false", tt.name)
			}
			if strings.Contains(ce.err.Error(), "dev7") {
				t.Errorf("%s: cause %q holds the expanded host", tt.name, ce.err.Error())
			}
		}
	})

	t.Run("same URL keeps the cause", func(t *testing.T) {
		t.Parallel()
		u := discover.NewURL("https://example.test/mcp")
		cause := errors.New("boom at " + u.String())
		ce := &ConnectError{Reason: "boom at " + u.String(), err: cause}
		showDiscoveredURL(ce, u, u)
		//nolint:errorlint // identity check: the cause must be the same value, not a new error
		if ce.URL != u.String() || ce.Reason != "boom at "+u.String() || ce.err != cause {
			t.Errorf("ConnectError = %+v, want the URL set and the rest unchanged", ce)
		}
	})
}
