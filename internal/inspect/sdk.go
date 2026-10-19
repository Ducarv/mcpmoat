package inspect

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// SDKOptions configures SDKInspector. The zero value is ready to use.
type SDKOptions struct {
	// AllowUntrusted lets Inspect start or connect to a server from an
	// untrusted project file (discover.Server.Untrusted). The caller must
	// have the explicit opt-in of the user before it sets this.
	AllowUntrusted bool

	// AllowDisabled lets Inspect start or connect to a server whose State is
	// not discover.StateEnabled: the client config turns it off, the user
	// did not approve it, or only files from the repository approve it. The
	// caller must have the explicit opt-in of the user before it sets this.
	// It is separate from AllowUntrusted: an untrusted server that is also
	// off needs both.
	AllowDisabled bool
}

// SDKInspector is the [Inspector] that uses the official MCP Go SDK. It
// starts stdio servers itself (see Inspect) and gives remote servers to
// [Remote]. So it is the one Inspector that [Run] needs.
//
// SDKInspector holds no mutable state: each call to Inspect makes its own
// SDK client, process and connection. So one SDKInspector is safe for
// concurrent use by multiple goroutines.
type SDKInspector struct {
	opts SDKOptions

	// environ returns the environment of mcpmoat in the form of os.Environ:
	// the parent of the child environment (see buildEnv), and the source of
	// the variables that Inspect expands (see discover.Expand). runRoot returns
	// the directory for the work directories of servers without an absolute
	// Dir (see workDir). rawLimit is the raw size limit; 0 means
	// maxRawBytes. When a field is zero, as in New and in a zero
	// SDKInspector, Inspect uses the default. Tests set them, so that they
	// never read the real environment or write to the cache directory of
	// the user, and can go over a small limit.
	environ  func() []string
	runRoot  func() (string, error)
	rawLimit int64
}

var _ Inspector = (*SDKInspector)(nil)

// New returns an [SDKInspector] with the options opts.
func New(opts SDKOptions) *SDKInspector {
	return &SDKInspector{opts: opts}
}

// Inspect reads the tools, prompts and resources of the server s.
//
// First, for every transport, Inspect checks these in order, and starts
// nothing and sends nothing when one fails:
//
//  1. the state gate: a server whose State is not discover.StateEnabled
//     (turned off in the client config, not approved, or approved only by
//     files from the repository) is refused unless opts.AllowDisabled is set
//     (KindConfig, fixed reason);
//  2. the untrusted gate: a server from an untrusted file is refused unless
//     opts.AllowUntrusted is set (KindConfig, fixed reason);
//  3. the expansion: discover.Expand replaces the ${VAR} placeholders as the
//     client does, with the variables of the environ hook (os.Environ by
//     default). A placeholder that cannot be expanded, or an expanded text
//     over the size limit of discover.Expand, gives KindConfig with a
//     reason that holds the field and at most a plain variable name, never
//     a value.
//
// checkGates does steps 1 and 2. stdioCommand and [Remote] call it again
// with the same opt-ins, so they apply the same gates in the same order.
//
// Then a remote server (http or sse) goes to [Remote], with the expanded
// server, opts.AllowUntrusted and opts.AllowDisabled. A stdio server is
// started as a child process with the expanded server; see the rest of this
// comment. The expanded server stays inside Inspect: [Run] keeps the server
// as discovered in Outcome.Server, so no expanded value is shown.
//
// Every non-nil error is a *ConnectError; use errors.As to get it. Its text
// never holds a configured env value: mcpmoat puts none there, and Inspect
// removes from text that the server sent the configured values and the
// values of the expanded variables that have at least minBareSecretLen bytes
// (a server gets them and can echo them). Its URL is the redacted URL as
// discovered, not the expanded one. It can hold other text that the server
// controls, so callers must escape it with internal/termsafe before they
// print it. errors.Is(err, context.DeadlineExceeded) works for timeouts.
//
// For a stdio server, Inspect:
//
//   - builds the command with stdioCommand (NFR-04): no shell, a scrubbed
//     environment plus npm_config_yes=false, a bare command name looked up
//     in the PATH of the child, and on Unix a new session and process group;
//   - sends the identity of the client that declared the server (see
//     clientIdentity);
//   - runs the child in its configured work directory (projectRunDir: an
//     absolute Dir, or the project directory of a trusted project server),
//     or else in a new, empty directory below the run root (workDir), and
//     removes that directory at the end;
//   - refuses every request of the server except ping (refuseServerRequests);
//   - lists with listInto (tools, prompts, resources and resource
//     templates), and fails with KindTooLarge when the handshake and the
//     lists go over maxRawBytes (rawLimit), or when one JSON message from
//     the server goes over a shape limit (errJSONTooComplex: too deeply
//     nested, too many values or a too long string).
//
// Stop guarantee: when Inspect returns, on success and on every error, the
// child was stopped and reaped (see stdioProcess.stop): stdin closed, up to
// stopGrace to exit, SIGKILL to the process group before cmd.Wait, then
// Wait. When ctx ends, the process group gets SIGKILL at once. The
// exceptions: a process that left the group; a process that the operating
// system cannot kill, which blocks Wait; and a work directory that such a
// process still uses, which stays behind below the run root.
//
// Inspect stops the child before it closes the MCP session. The close of
// the session waits until the SDK has written its replies to the requests
// of the server, and a server that does not read its stdin blocks those
// writes until its stdin is closed. When that happens during the handshake,
// the SDK closes the session inside Client.Connect, so only ctx bounds it.
func (i *SDKInspector) Inspect(ctx context.Context, s discover.Server) (Result, error) {
	if err := checkGates(s, i.opts.AllowUntrusted, i.opts.AllowDisabled); err != nil {
		return Result{}, gateError(s, err)
	}

	environ := os.Environ
	if i.environ != nil {
		environ = i.environ
	}
	parent := environ()

	// The recorder keeps every value that Expand looks up (each value one
	// time), so that the scrub of error text removes them too: an expanded
	// value can stand in an arg or in the URL host, where no other scrub
	// list has it.
	rec := &lookupRecorder{lookup: environLookup(parent)}
	expanded, err := discover.Expand(s, rec.Lookup)
	if err != nil {
		return Result{}, expandError(s, err)
	}

	if s.Transport.IsRemote() {
		result, err := Remote(ctx, expanded, RemoteOptions{
			AllowUntrusted: i.opts.AllowUntrusted,
			AllowDisabled:  i.opts.AllowDisabled,
			secrets:        rec.values,
		})
		if ce, ok := errors.AsType[*ConnectError](err); ok {
			// The URL of the error must be the one as discovered: the
			// expanded URL can show values of variables.
			ce.URL = s.URL.String()
		}
		return result, err
	}
	return i.inspectStdio(ctx, expanded, parent, rec.values)
}

// inspectStdio is Inspect for a server that is not remote. s is the expanded
// server, parent is the environment for buildEnv, and lookedUp holds the
// values of the expanded variables, for the scrub of error text. Inspect
// checked the gates before, and stdioCommand checks them again.
func (i *SDKInspector) inspectStdio(ctx context.Context, s discover.Server, parent, lookedUp []string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, classify(err, s, nil, nil)
	}

	// The defers below run in this order: the stop of the process, the
	// removal of the work directory, then cancel. cancel ends ctx last, so
	// the kill on ctx (see startStdio) is already stopped then.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	runRoot, limit := defaultRunRoot, int64(maxRawBytes)
	if i.runRoot != nil {
		runRoot = i.runRoot
	}
	if i.rawLimit > 0 {
		limit = i.rawLimit
	}

	// projectRunDir is the same choice that stdioCommand makes, so the
	// fallback directory is made only when the child needs it.
	fallback, cleanup, err := workDir(projectRunDir(s, isExistingDir), runRoot)
	// cleanup is never nil, also on error, so it is safe to defer it before
	// the error check.
	defer cleanup()
	if err != nil {
		return Result{}, startFailure(s, "cannot make the work directory below the user cache directory", err)
	}

	cmd, err := stdioCommand(s, stdioOptions{
		Environ:        parent,
		FallbackDir:    fallback,
		AllowUntrusted: i.opts.AllowUntrusted,
		AllowDisabled:  i.opts.AllowDisabled,
	})
	if err != nil {
		return Result{}, commandError(s, err)
	}

	proc, err := startStdio(ctx, cmd)
	if err != nil {
		return Result{}, startError(ctx, s, err)
	}
	// This defer covers the paths where Client.Connect fails. On success,
	// the defer below stops the process first; stop is idempotent.
	defer proc.stop()

	secrets := slices.Concat(envSecrets(s.Env), lookedUp)
	raw, sizes := &rawLists{}, &rawLimit{limit: limit}
	// fail turns err into the *ConnectError that Inspect returns. The SDK
	// formats some errors with %v, which drops the context error from the
	// chain. When ctx has ended, fail puts its error first, so the kind is
	// KindTimeout and errors.Is(err, context.DeadlineExceeded) works.
	//
	// When the stdout of the server went over a JSON shape limit (see
	// stdioProcess.transport), fail puts errJSONTooComplex first, so that the
	// kind is KindTooLarge. The SDK reports the error of its reader only as a
	// generic "connection closed" error, so errJSONTooComplex is not in the
	// chain of err, and only proc knows about it. fail does this only when
	// ctx has not ended: an ended ctx still wins, as for the raw size limit.
	fail := func(err error) (Result, error) {
		ctxErr := ctx.Err()
		if ctxErr == nil && proc.shapeExceeded() && !errors.Is(err, errJSONTooComplex) {
			err = fmt.Errorf("%w: %w", errJSONTooComplex, err)
		}
		if ctxErr != nil && !errors.Is(err, ctxErr) {
			err = fmt.Errorf("%w: %w", ctxErr, err)
		}
		return Result{}, stdioFailure(s, err, secrets, sizes.exceeded())
	}

	client := newStdioClientFor(clientIdentity(s.Client), raw, sizes)
	cs, err := client.Connect(ctx, proc.transport(int(limit)), nil)
	if err != nil {
		return fail(err)
	}
	// Stop the process before cs.Close (see the doc of Inspect). The error
	// of Close does not change the result, so Inspect drops it.
	defer func() {
		proc.stop()
		_ = cs.Close()
	}()

	initRes := cs.InitializeResult()
	if initRes == nil {
		// The SDK always sets the result after a successful Connect. Guard
		// anyway: a nil would panic below.
		return fail(errors.New("no initialize result"))
	}
	result := resultFromInit(initRes)
	if err := listInto(ctx, cs, initRes.Capabilities, raw, &result); err != nil {
		return fail(err)
	}
	return result, nil
}

// newStdioClient is newStdioClientFor with the neutral identity (clientName
// and clientVersion).
func newStdioClient(raw *rawLists, limit *rawLimit) *mcp.Client {
	return newStdioClientFor(&mcp.Implementation{Name: clientName, Version: clientVersion}, raw, limit)
}

// newStdioClientFor returns a new SDK client for one stdio server, with the
// client identity id in the initialize request. Inspect passes
// clientIdentity of the client that declared the server, so a server cannot
// tell mcpmoat from that client by name. id must not name mcpmoat.
//
// The client offers no capabilities to the server, and it serves no request
// of the server except ping:
//
//   - Capabilities is set and empty. A nil Capabilities would advertise
//     "roots" for historical reasons.
//   - CreateMessageHandler, CreateMessageWithToolsHandler and
//     ElicitationHandler stay nil. Then the SDK does not advertise sampling
//     or elicitation.
//   - The receiving middleware refuseServerRequests answers every server
//     request except ping with "method not found", before the SDK handler
//     runs. Only a short allowlist of notifications passes; see
//     allowedServerMethod.
//   - The multi round-trip middleware is disabled. It answers input
//     requests from the server on tools/call, prompts/get and
//     resources/read, which mcpmoat never sends.
//
// The sending middleware of raw keeps the tools as the server sent them,
// for listAll, and the one of limit applies the raw size limit. The logger
// discards everything: SDK logs can hold untrusted server text.
func newStdioClientFor(id *mcp.Implementation, raw *rawLists, limit *rawLimit) *mcp.Client {
	c := mcp.NewClient(
		id,
		&mcp.ClientOptions{
			Capabilities:   &mcp.ClientCapabilities{},
			MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
			Logger:         slog.New(slog.DiscardHandler),
		},
	)
	c.AddReceivingMiddleware(refuseServerRequests)
	c.AddSendingMiddleware(raw.middleware(), limit.middleware)
	return c
}

// lookupRecorder wraps a variable lookup for discover.Expand. It keeps each
// value that the lookup returns with at least minBareSecretLen bytes, for
// classify to remove from error text. A shorter value is too likely to match
// ordinary words. It keeps each value one time only, so a config that reads
// the same variable many times does not make the scrub list long. It is
// used by one goroutine only.
type lookupRecorder struct {
	lookup func(string) (string, bool)
	// values holds raw values of the user's environment, each one time, in
	// the order of the first lookup. seen holds the same values, to find a
	// value that is already in values. Never print, log or encode them.
	values []string
	seen   map[string]struct{}
}

// Lookup returns the value of the variable name and whether it is set, and
// records the value if it is not recorded yet.
func (r *lookupRecorder) Lookup(name string) (string, bool) {
	value, ok := r.lookup(name)
	if !ok || len(value) < minBareSecretLen {
		return value, ok
	}
	if _, dup := r.seen[value]; dup {
		return value, ok
	}
	if r.seen == nil {
		r.seen = make(map[string]struct{})
	}
	r.seen[value] = struct{}{}
	r.values = append(r.values, value)
	return value, ok
}

// environLookup returns a lookup in env, which has the form of os.Environ:
// "name=value" entries. Entries with no "=" are skipped. If a name occurs
// more than once, the first entry wins, the same as os.LookupEnv on Unix and
// buildEnv. An empty name is never found: on Windows, entries such as
// "=C:=C:\work" start with "=", and an empty name must not match them.
func environLookup(env []string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if name == "" {
			return "", false
		}
		for _, entry := range env {
			if n, value, ok := strings.Cut(entry, "="); ok && n == name {
				return value, true
			}
		}
		return "", false
	}
}

// expandError turns an error of discover.Expand into a KindConfig
// *ConnectError. The reason holds the field and at most the variable name of
// the placeholder, never a value: the text of a *discover.ExpandError holds
// nothing else, and it shows a name only when the name is a plain variable
// name (see discover.ExpandError). Any other error gets a fixed reason.
func expandError(s discover.Server, err error) *ConnectError {
	reason := "cannot expand the variables in the server config"
	if ee, ok := errors.AsType[*discover.ExpandError](err); ok {
		reason = ee.Error()
	} else {
		// Keep no text of an unknown error.
		err = nil
	}
	ce := configError(s, reason)
	ce.err = err
	return ce
}

// envSecrets returns the configured env values of at least minBareSecretLen
// bytes, for classify to remove from error text. A shorter value is too
// likely to match ordinary words ("1", "true", "info"), and too short to be
// a token.
func envSecrets(env discover.SecretMap) []string {
	var secrets []string
	for _, key := range env.Keys() {
		if v := env[key].Reveal(); len(v) >= minBareSecretLen {
			secrets = append(secrets, v)
		}
	}
	return secrets
}

// stdioFailure turns err, from the MCP session of a stdio server, into a
// *ConnectError. classify gives KindTimeout for a context error and
// KindProtocol for the rest, with the secrets removed and the text cut.
//
// When errJSONTooComplex is in the chain (the server sent a JSON message over
// a shape limit), classify already gives KindTooLarge with the fixed reason
// of blockedKinds, the same as for a remote server. As for a remote server,
// this wins over a context error in the chain. stdioFailure then sets the
// cause to the sentinel, plus the context error if there is one, so that the
// cause holds no wrapped detail and errors.Is still finds the context error.
//
// Else, when the server went over the raw size limit (tooLarge, or
// errRawTooLarge in the chain), a KindProtocol error becomes KindTooLarge. A
// KindTimeout error stays as it is: an ended ctx wins.
//
// fail in inspectStdio adds errJSONTooComplex only when ctx has not ended, so
// for a shape violation that only the process knows about, an ended ctx wins
// too.
func stdioFailure(s discover.Server, err error, secrets []string, tooLarge bool) *ConnectError {
	ce := classify(err, s, nil, secrets)
	switch {
	case errors.Is(err, errJSONTooComplex):
		ce.err = errJSONTooComplex
		if ctxErr := contextErr(err); ctxErr != nil {
			ce.err = fmt.Errorf("%w: %w", errJSONTooComplex, ctxErr)
		}
	case ce.Kind == KindProtocol && (tooLarge || errors.Is(err, errRawTooLarge)):
		ce.Kind = KindTooLarge
		ce.Reason = errRawTooLarge.Error()
		ce.err = errRawTooLarge
	}
	return ce
}

// commandError turns an error of stdioCommand into a *ConnectError.
// stdioCommand returns fixed sentinels with no config text, so the reason
// is the sentinel text. A command that cannot be found or run, or a missing
// work directory, gives KindStart; any other error is a config that mcpmoat
// cannot use (KindConfig).
func commandError(s discover.Server, err error) *ConnectError {
	kind := KindConfig
	if errors.Is(err, errCommandNotFound) || errors.Is(err, errCommandNotRunnable) || errors.Is(err, errNoWorkDir) {
		kind = KindStart
	}
	return &ConnectError{
		Kind:   kind,
		Server: s.Name,
		Reason: strings.TrimPrefix(err.Error(), "inspect: "),
		err:    err,
	}
}

// startError turns err, the error of startStdio, into a *ConnectError. The
// error of cmd.Start can hold cmd.Path or cmd.Dir, which are untrusted config
// text (see stdioCommand), so the reason is fixed text, and the cause keeps
// only the class of err: fs.ErrNotExist, fs.ErrPermission or nothing. When
// ctx is done, the result is a timeout.
func startError(ctx context.Context, s discover.Server, err error) *ConnectError {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return classify(ctxErr, s, nil, nil)
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return startFailure(s, "the command or the work directory does not exist", fs.ErrNotExist)
	case errors.Is(err, fs.ErrPermission):
		return startFailure(s, "no permission to run the command or to use the work directory", fs.ErrPermission)
	}
	return startFailure(s, "the server process did not start", nil)
}

// startFailure returns a KindStart error for s with the fixed reason and the
// cause err. reason must not hold config text.
func startFailure(s discover.Server, reason string, err error) *ConnectError {
	return &ConnectError{
		Kind:   KindStart,
		Server: s.Name,
		Reason: reason,
		err:    err,
	}
}
