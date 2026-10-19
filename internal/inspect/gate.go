package inspect

import (
	"errors"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// The gates decide whether mcpmoat may start or connect to a server at all.
// See the package doc, Gates. The errors below have fixed text on purpose:
// they never hold config text.

// errDisabled reports that the client config turns the server off
// (discover.StateDisabled) and the user did not opt in to inspect it. A
// State value that this package does not know gets the same error, so an
// unknown state fails closed.
var errDisabled = errors.New("inspect: " + reasonDisabled)

// errUnapproved reports that the server has discover.StateUnapproved and the
// user did not opt in to inspect it. That state has two causes: the user did
// not approve the server in the client config, or discover could not read the
// state that approves it (for example the project state in ~/.claude.json).
// The text covers both causes.
var errUnapproved = errors.New("inspect: " + reasonUnapproved)

// errProjectApproved reports that only files from the repository approve
// the server (discover.StateProjectApproved), and the user did not opt in to
// inspect it. A cloned repository can approve its own servers, so that
// approval does not count as the approval of the user.
var errProjectApproved = errors.New("inspect: " + reasonProjectApproved)

// errUntrusted reports that the server comes from an untrusted project file
// and the user did not opt in to start such servers. See the discover
// package doc, Untrusted files.
var errUntrusted = errors.New("inspect: server from an untrusted project file needs an explicit opt-in to start")

// The reasons of the gates in a *ConnectError (see gateError). The state
// gate reasons are the texts of their errors without the "inspect: " prefix.
// The untrusted gate reasons name what the opt-in allows: to start a stdio
// server, or to connect to a remote one.
const (
	reasonDisabled        = "server is turned off in the client config; inspecting it needs explicit opt-in"
	reasonUnapproved      = "server is not approved in the client config, or its state could not be read; inspecting it needs explicit opt-in"
	reasonProjectApproved = "server is approved only by files from the repository; inspecting it needs explicit opt-in"
	reasonUntrustedStdio  = "untrusted project server; starting it needs explicit opt-in"
	reasonUntrustedRemote = "untrusted project server; connecting needs explicit opt-in"
)

// checkGates returns nil when mcpmoat may start or connect to the server s.
// allowUntrusted and allowDisabled are the explicit opt-ins of the user.
//
// The order is the same for every caller (SDKInspector.Inspect, Remote and
// stdioCommand), so the same server always gets the same error:
//
//  1. the state gate (stateGate): errDisabled, errUnapproved or
//     errProjectApproved, unless allowDisabled is set;
//  2. the untrusted gate: errUntrusted when s.Untrusted is set, unless
//     allowUntrusted is set.
//
// The two opt-ins are separate: a server that both gates refuse needs both.
// Every error is a fixed sentinel with no config text.
func checkGates(s discover.Server, allowUntrusted, allowDisabled bool) error {
	if err := stateGate(s.State, allowDisabled); err != nil {
		return err
	}
	if s.Untrusted && !allowUntrusted {
		return errUntrusted
	}
	return nil
}

// stateGate returns nil when a server with the given state may start or get
// a connection: the state is discover.StateEnabled, or allow (the opt-in of
// the user) is set. Otherwise it returns errUnapproved for
// discover.StateUnapproved, errProjectApproved for
// discover.StateProjectApproved, and errDisabled for any other state, so a
// state that this package does not know fails closed. All errors have fixed
// text.
func stateGate(state discover.State, allow bool) error {
	switch {
	case allow || state == discover.StateEnabled:
		return nil
	case state == discover.StateUnapproved:
		return errUnapproved
	case state == discover.StateProjectApproved:
		return errProjectApproved
	default:
		return errDisabled
	}
}

// gateError turns an error of checkGates into a KindConfig *ConnectError,
// with the error as the cause. The reason is one of the fixed gate reasons:
// for errUntrusted it is reasonUntrustedRemote for a remote server and
// reasonUntrustedStdio for any other server. Any other error, also one that
// checkGates does not return, gets reasonDisabled, so it fails closed with
// fixed text.
func gateError(s discover.Server, err error) *ConnectError {
	var reason string
	switch {
	case errors.Is(err, errUntrusted) && s.Transport.IsRemote():
		reason = reasonUntrustedRemote
	case errors.Is(err, errUntrusted):
		reason = reasonUntrustedStdio
	case errors.Is(err, errUnapproved):
		reason = reasonUnapproved
	case errors.Is(err, errProjectApproved):
		reason = reasonProjectApproved
	default:
		reason = reasonDisabled
	}
	return configErrorWithCause(s, reason, err)
}
