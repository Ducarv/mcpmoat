package inspect

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
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

	// environ returns the environment of mcpmoat in the form of os.Environ,
	// the parent of the child environment (see buildEnv). runRoot returns
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

// Inspect reads the tools, prompts and resources of the server s. A remote
// server (http or sse) goes to [Remote], with opts.AllowUntrusted. A stdio
// server is started as a child process; see the rest of this comment.
//
// Every non-nil error is a *ConnectError; use errors.As to get it. Its text
// never holds a configured env value: mcpmoat puts none there, and Inspect
// removes the configured values of at least minBareSecretLen bytes from text
// that the server sent (a server gets them and can echo them). It can hold
// other text that the server controls, so callers must escape it with
// internal/termsafe before they print it. errors.Is(err,
// context.DeadlineExceeded) works for timeouts.
//
// For a stdio server, Inspect:
//
//   - refuses a server from an untrusted file unless opts.AllowUntrusted is
//     set (KindConfig), and starts nothing then;
//   - builds the command with stdioCommand (NFR-04): no shell, a scrubbed
//     environment, a bare command name looked up in the PATH of the child,
//     and on Unix a new session and process group;
//   - runs the child in its absolute Dir, or else in a new, empty directory
//     below the run root (workDir), and removes that directory at the end;
//   - refuses every request of the server except ping (refuseServerRequests);
//   - lists with listAll, and fails with KindTooLarge when the handshake and
//     the lists go over maxRawBytes (rawLimit).
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
	if s.Transport.IsRemote() {
		return Remote(ctx, s, RemoteOptions{AllowUntrusted: i.opts.AllowUntrusted})
	}
	return i.inspectStdio(ctx, s)
}

// inspectStdio is Inspect for a server that is not remote.
func (i *SDKInspector) inspectStdio(ctx context.Context, s discover.Server) (Result, error) {
	if s.Untrusted && !i.opts.AllowUntrusted {
		return Result{}, configError(s, "untrusted project server; starting it needs explicit opt-in")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, classify(err, s, nil, nil)
	}

	// The defers below run in this order: the stop of the process, the
	// removal of the work directory, then cancel. cancel ends ctx last, so
	// the kill on ctx (see startStdio) is already stopped then.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	environ, runRoot, limit := os.Environ, defaultRunRoot, int64(maxRawBytes)
	if i.environ != nil {
		environ = i.environ
	}
	if i.runRoot != nil {
		runRoot = i.runRoot
	}
	if i.rawLimit > 0 {
		limit = i.rawLimit
	}

	fallback, cleanup, err := workDir(s.Dir, runRoot)
	// cleanup is never nil, also on error, so it is safe to defer it before
	// the error check.
	defer cleanup()
	if err != nil {
		return Result{}, startFailure(s, "cannot make the work directory below the user cache directory", err)
	}

	cmd, err := stdioCommand(s, stdioOptions{
		Environ:        environ(),
		FallbackDir:    fallback,
		AllowUntrusted: i.opts.AllowUntrusted,
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

	secrets := envSecrets(s.Env)
	raw, sizes := &rawLists{}, &rawLimit{limit: limit}
	// fail turns err into the *ConnectError that Inspect returns. The SDK
	// formats some errors with %v, which drops the context error from the
	// chain. When ctx has ended, fail puts its error first, so the kind is
	// KindTimeout and errors.Is(err, context.DeadlineExceeded) works.
	fail := func(err error) (Result, error) {
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
			err = fmt.Errorf("%w: %w", ctxErr, err)
		}
		return Result{}, stdioFailure(s, err, secrets, sizes.exceeded())
	}

	client := newStdioClient(raw, sizes)
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
	result.Tools, result.Prompts, result.Resources, err = listAll(ctx, cs, initRes.Capabilities, raw)
	if err != nil {
		return fail(err)
	}
	return result, nil
}

// newStdioClient returns a new SDK client for one stdio server.
//
// The client uses the same neutral identity as Remote (clientName and
// clientVersion), so a server cannot tell mcpmoat from another client by
// name. It offers no capabilities to the server, and it serves no request of
// the server except ping:
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
func newStdioClient(raw *rawLists, limit *rawLimit) *mcp.Client {
	c := mcp.NewClient(
		&mcp.Implementation{Name: clientName, Version: clientVersion},
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
// KindProtocol for the rest, with the secrets removed and the text cut. When
// the server went over the raw size limit (tooLarge, or errRawTooLarge in
// the chain), a KindProtocol error becomes KindTooLarge.
func stdioFailure(s discover.Server, err error, secrets []string, tooLarge bool) *ConnectError {
	ce := classify(err, s, nil, secrets)
	if ce.Kind == KindProtocol && (tooLarge || errors.Is(err, errRawTooLarge)) {
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
