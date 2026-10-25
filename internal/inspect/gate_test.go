package inspect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
)

// The helpers that only this file uses have the prefix "gt" (gate test).

// gtStates are the states that the gate tests use, with the error of the
// state gate without the opt-in. A state that inspect does not know fails
// closed with errDisabled.
var gtStates = []struct {
	name  string
	state discover.State
	// refuse is the error of the state gate without AllowDisabled. nil
	// means that the state gate lets the server through.
	refuse error
}{
	{name: "enabled", state: discover.StateEnabled, refuse: nil},
	{name: "disabled", state: discover.StateDisabled, refuse: errDisabled},
	{name: "unapproved", state: discover.StateUnapproved, refuse: errUnapproved},
	{name: "project-approved", state: discover.StateProjectApproved, refuse: errProjectApproved},
	{name: "unknown-4", state: discover.State(4), refuse: errDisabled},
	{name: "unknown-255", state: discover.State(255), refuse: errDisabled},
}

// TestCheckGates checks checkGates for each state, a trusted and an
// untrusted server, and each combination of the two opt-ins.
//
// The expected error follows the documented order: the state gate first
// (refused unless AllowDisabled), then the untrusted gate (refused unless
// AllowUntrusted). So when both gates refuse, the error of the state gate
// wins, and each opt-in opens only its own gate.
func TestCheckGates(t *testing.T) {
	t.Parallel()

	for _, st := range gtStates {
		for _, untrusted := range []bool{false, true} {
			for _, allowUntrusted := range []bool{false, true} {
				for _, allowDisabled := range []bool{false, true} {
					var want error
					switch {
					case st.refuse != nil && !allowDisabled:
						want = st.refuse
					case untrusted && !allowUntrusted:
						want = errUntrusted
					}

					name := fmt.Sprintf("%s/untrusted=%v/AllowUntrusted=%v/AllowDisabled=%v",
						st.name, untrusted, allowUntrusted, allowDisabled)
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						s := stdioServer("/opt/mcp/server")
						s.State = st.state
						s.Untrusted = untrusted
						got := checkGates(s, allowUntrusted, allowDisabled)
						// The errors are fixed sentinels: compare them with
						// ==, so a wrapped or a different error fails.
						if got != want { //nolint:errorlint // the gates return the sentinels themselves, not wrapped errors
							t.Errorf("checkGates(state %v, untrusted %v, %v, %v) = %v, want %v",
								st.state, untrusted, allowUntrusted, allowDisabled, got, want)
						}
					})
				}
			}
		}
	}
}

// TestCheckGatesAnchors pins a few cases of TestCheckGates with literal
// values, so that a mistake in the loop of that test cannot hide a wrong
// order.
func TestCheckGatesAnchors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		state          discover.State
		untrusted      bool
		allowUntrusted bool
		allowDisabled  bool
		want           error
	}{
		{name: "trusted enabled", state: discover.StateEnabled, want: nil},
		{name: "untrusted enabled", state: discover.StateEnabled, untrusted: true, want: errUntrusted},
		{name: "both refuse: state wins", state: discover.StateUnapproved, untrusted: true, want: errUnapproved},
		{name: "both refuse: project-approved wins", state: discover.StateProjectApproved, untrusted: true, want: errProjectApproved},
		{name: "both refuse: disabled wins", state: discover.StateDisabled, untrusted: true, want: errDisabled},
		{name: "AllowDisabled leaves the untrusted gate", state: discover.StateProjectApproved, untrusted: true, allowDisabled: true, want: errUntrusted},
		{name: "AllowUntrusted leaves the state gate", state: discover.StateProjectApproved, untrusted: true, allowUntrusted: true, want: errProjectApproved},
		{name: "both opt-ins", state: discover.StateProjectApproved, untrusted: true, allowUntrusted: true, allowDisabled: true, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := stdioServer("/opt/mcp/server")
			s.State = tt.state
			s.Untrusted = tt.untrusted
			got := checkGates(s, tt.allowUntrusted, tt.allowDisabled)
			if got != tt.want { //nolint:errorlint // the gates return the sentinels themselves, not wrapped errors
				t.Errorf("checkGates() = %v, want %v", got, tt.want)
			}
		})
	}
}

// gtServer returns a server with the transport tr. A remote server has a
// URL with a canary in the query, and every server has canaries in the
// fields that config text can fill, so the test can prove that the reason
// holds no config text.
func gtServer(tr discover.Transport) discover.Server {
	s := stdioServer("/opt/"+discovertest.CanaryArgs, discovertest.CanaryArgs)
	s.Transport = tr
	s.Env = secrets(map[string]string{"API_KEY": discovertest.CanaryEnv})
	s.Headers = secrets(map[string]string{"Authorization": "Bearer " + discovertest.CanaryHeader})
	if tr.IsRemote() {
		s.Command = ""
		s.Args = discover.Args{}
		s.URL = discover.NewURL("https://example.com/mcp?token=" + discovertest.CanaryURL)
	}
	return s
}

// TestGateError checks the *ConnectError that gateError makes for each gate
// error and each transport: KindConfig, the fixed reason, the server name,
// the redacted URL, and the gate error as the cause, so errors.Is works
// through the *ConnectError and through a wrap of it.
func TestGateError(t *testing.T) {
	t.Parallel()

	transports := []struct {
		name string
		tr   discover.Transport
		// untrustedReason is the reason for errUntrusted.
		untrustedReason string
	}{
		{name: "stdio", tr: discover.TransportStdio, untrustedReason: reasonUntrustedStdio},
		{name: "empty transport", tr: "", untrustedReason: reasonUntrustedStdio},
		{name: "http", tr: discover.TransportHTTP, untrustedReason: reasonUntrustedRemote},
		{name: "sse", tr: discover.TransportSSE, untrustedReason: reasonUntrustedRemote},
	}
	gates := []struct {
		name string
		err  error
		// reason is the reason for a stdio server; "" means the
		// untrustedReason of the transport.
		reason string
	}{
		{name: "disabled", err: errDisabled, reason: "server is turned off in the client config; inspecting it needs explicit opt-in"},
		{name: "unapproved", err: errUnapproved, reason: "server is not approved in the client config, or its state could not be read; inspecting it needs explicit opt-in"},
		{name: "project-approved", err: errProjectApproved, reason: "server is approved only by files from the repository; inspecting it needs explicit opt-in"},
		{name: "untrusted", err: errUntrusted},
	}
	others := []error{errDisabled, errUnapproved, errProjectApproved, errUntrusted}

	for _, tr := range transports {
		for _, g := range gates {
			t.Run(tr.name+"/"+g.name, func(t *testing.T) {
				t.Parallel()
				s := gtServer(tr.tr)
				ce := gateError(s, g.err)

				wantReason := g.reason
				if wantReason == "" {
					wantReason = tr.untrustedReason
				}
				if ce.Kind != KindConfig {
					t.Errorf("Kind = %v, want KindConfig", ce.Kind)
				}
				if ce.Reason != wantReason {
					t.Errorf("Reason = %q, want %q", ce.Reason, wantReason)
				}
				if strings.HasPrefix(ce.Reason, "inspect:") {
					t.Errorf("Reason = %q, want no %q prefix", ce.Reason, "inspect:")
				}
				if ce.Server != s.Name {
					t.Errorf("Server = %q, want %q", ce.Server, s.Name)
				}
				if ce.URL != s.URL.String() {
					t.Errorf("URL = %q, want the redacted URL %q", ce.URL, s.URL.String())
				}
				if ce.Status != 0 || len(ce.Warnings) != 0 {
					t.Errorf("Status = %d, Warnings = %+v, want 0 and none", ce.Status, ce.Warnings)
				}

				// The gate error is the cause, also through a wrap.
				var err error = ce
				wrapped := fmt.Errorf("scan: %w", err)
				for what, e := range map[string]error{"ConnectError": err, "wrapped": wrapped} {
					if !errors.Is(e, g.err) {
						t.Errorf("%s: errors.Is(err, %v) = false, want true", what, g.err)
					}
					for _, other := range others {
						if other != g.err && errors.Is(e, other) { //nolint:errorlint // compares two sentinels
							t.Errorf("%s: errors.Is(err, %v) = true, want false", what, other)
						}
					}
				}
				var got *ConnectError
				if !errors.As(wrapped, &got) || got != ce {
					t.Errorf("errors.As(wrapped, *ConnectError) = %v, want the same *ConnectError", got)
				}

				// The reason and the text hold no config text.
				discovertest.AssertNoLeak(t, "Reason", ce.Reason)
				discovertest.AssertNoLeak(t, "Error()", ce.Error())
			})
		}
	}
}

// TestGateErrorFromCheckGates checks the full path: the error of checkGates,
// turned into a *ConnectError by gateError, still matches the sentinel with
// errors.Is. This is what Inspect, Remote and stdioCommand return.
func TestGateErrorFromCheckGates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		tr         discover.Transport
		state      discover.State
		untrusted  bool
		want       error
		wantReason string
	}{
		{name: "stdio untrusted", tr: discover.TransportStdio, untrusted: true, want: errUntrusted, wantReason: reasonUntrustedStdio},
		{name: "http untrusted", tr: discover.TransportHTTP, untrusted: true, want: errUntrusted, wantReason: reasonUntrustedRemote},
		{name: "sse untrusted", tr: discover.TransportSSE, untrusted: true, want: errUntrusted, wantReason: reasonUntrustedRemote},
		{
			name: "stdio project-approved and untrusted", tr: discover.TransportStdio,
			state: discover.StateProjectApproved, untrusted: true, want: errProjectApproved,
			wantReason: strings.TrimPrefix(errProjectApproved.Error(), "inspect: "),
		},
		{
			name: "http project-approved and untrusted", tr: discover.TransportHTTP,
			state: discover.StateProjectApproved, untrusted: true, want: errProjectApproved,
			wantReason: strings.TrimPrefix(errProjectApproved.Error(), "inspect: "),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := gtServer(tt.tr)
			s.State = tt.state
			s.Untrusted = tt.untrusted
			gerr := checkGates(s, false, false)
			if gerr == nil {
				t.Fatal("checkGates() = nil, want an error")
			}
			err := error(gateError(s, gerr))
			if !errors.Is(err, tt.want) {
				t.Errorf("errors.Is(err, %v) = false, err = %v", tt.want, err)
			}
			ce, ok := errors.AsType[*ConnectError](err)
			if !ok {
				t.Fatalf("error = %T, want *ConnectError", err)
			}
			if ce.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", ce.Reason, tt.wantReason)
			}
		})
	}
}

// TestRefused checks that Refused finds each gate error, also through the
// *ConnectError that Inspect returns, and nothing else.
func TestRefused(t *testing.T) {
	t.Parallel()
	for _, err := range []error{errDisabled, errUnapproved, errProjectApproved, errUntrusted} {
		if !Refused(err) {
			t.Errorf("Refused(%v) = false, want true", err)
		}
		if ce := gateError(discover.Server{Name: "s"}, err); !Refused(ce) {
			t.Errorf("Refused(gateError(%v)) = false, want true", err)
		}
	}
	for _, err := range []error{nil, errors.New("boom"), context.DeadlineExceeded} {
		if Refused(err) {
			t.Errorf("Refused(%v) = true, want false", err)
		}
	}
}
