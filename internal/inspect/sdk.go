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
	// have the explicit opt-in of the user before it sets this. The
	// placeholders of such a server read only the base environment
	// variables for a stdio server, and none for a remote server (see
	// Inspect).
	AllowUntrusted bool

	// AllowDisabled lets Inspect start or connect to a server whose State is
	// not discover.StateEnabled: the client config turns it off, the user
	// did not approve it, or only files from the repository approve it. The
	// caller must have the explicit opt-in of the user before it sets this.
	// It is separate from AllowUntrusted: an untrusted server that is also
	// off needs both.
	AllowDisabled bool

	// HiddenEnv holds the names of environment variables that no
	// placeholder can read, for any server: trusted or untrusted, stdio or
	// remote. A placeholder for one fails as if the variable were not set
	// (a default applies). The names compare without case, as on Windows,
	// so a name in other case is hidden too. mcpmoat hides the API key of
	// --llm, so that a server config cannot send it to a server.
	HiddenEnv []string

	// Dial is a test hook that records the connections to remote servers
	// (NFR-01). It is nil in production, and nil uses a net.Dialer. Dial
	// sees only the addresses after the DNS pin and the address guard. So
	// the guard still applies, and a refused address never reaches Dial.
	// With a proxy, Dial sees the address of the proxy. Dial must connect
	// to the address that it gets. It has no effect on stdio servers.
	Dial DialFunc
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
	// the variables that Inspect expands (see discover.Expand). runRoot
	// returns the directory for the work directories of servers with no
	// configured work directory (see projectRunDir and workDir). rawLimit is
	// the raw size limit; 0 means maxRawBytes. When a field is zero, as in
	// New and in a zero SDKInspector, Inspect uses the default. Tests set
	// them, so that they never read the real environment or write to the
	// cache directory of the user, and can go over a small limit.
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
// Every non-nil error is a *ConnectError; use errors.As to get it. mcpmoat
// puts no configured env value in its text, and Inspect removes from text that
// the server sent the configured values, the values of the expanded variables
// and, for a stdio server, the secrets in the argv (see argSecrets): a server
// gets them and can echo them. A value of at least discover.MinSecretBytes
// bytes goes wherever it stands. A shorter value goes only where it stands as
// a whole word (see replaceWords), so it stays when the text glues it to a
// letter, a digit or "_". Its URL is the redacted URL as discovered, not the
// expanded one. It can hold other text that the server controls, so callers
// must escape it with internal/termsafe before they print it. errors.Is(err,
// context.DeadlineExceeded) works for timeouts.
//
// On success, Result.Secrets holds the configured values, the expanded
// values, the credentials inside them (see valueCredentials) and, for a
// stdio server, the argv secrets that have at least discover.MinSecretBytes
// bytes (see Result.Secrets and resultSecrets). Result.Credentials holds the
// values of Result.Secrets that look like a credential (see
// Result.Credentials and resultCredentials). For a remote server, [Remote]
// sets both.
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

	// The placeholders of an untrusted server read less (see
	// expandPolicyFor and the package doc, Placeholder expansion). A server
	// without the workspace folder gets an empty ProjectPath for Expand
	// only, so ${workspaceFolder} fails; the expanded server keeps its
	// ProjectPath. No server reads a name of opts.HiddenEnv.
	policy := expandPolicyFor(s).hide(i.opts.HiddenEnv)
	toExpand := s
	if !policy.workspace {
		toExpand.ProjectPath = ""
	}
	// The recorder keeps every value that Expand looks up (each value one
	// time), so that the scrub of error text removes them too: an expanded
	// value can stand in an arg or in the URL host, where no other scrub
	// list has it. filterLookup refuses a name before the lookup, so the
	// value of a refused or hidden variable is never read or recorded.
	rec := &lookupRecorder{lookup: filterLookup(environLookup(parent), policy.allowed)}
	expanded, err := discover.Expand(toExpand, rec.Lookup)
	if err != nil {
		return Result{}, expandError(s, err, policy)
	}
	expanded.ProjectPath = s.ProjectPath

	if s.Transport.IsRemote() {
		lookedUp := rec.lists()
		result, err := Remote(ctx, expanded, RemoteOptions{
			AllowUntrusted: i.opts.AllowUntrusted,
			AllowDisabled:  i.opts.AllowDisabled,
			dial:           i.opts.Dial,
			lookedUp:       lookedUp,
		})
		if ce, ok := errors.AsType[*ConnectError](err); ok {
			// The same short list as the one that Remote gave classify.
			showDiscoveredURL(ce, expanded.URL, s.URL, remoteShortSecrets(expanded, lookedUp))
		}
		return result, err
	}
	return i.inspectStdio(ctx, expanded, parent, rec.lists())
}

// inspectStdio is Inspect for a server that is not remote. s is the expanded
// server, parent is the environment for buildEnv, and lookedUp holds the
// values of the expanded variables (see lookupRecorder.lists). inspectStdio
// adds the configured env values and the argv secrets of s to them (see
// stdioSecretLists). Inspect checked the gates before, and stdioCommand checks
// them again.
func (i *SDKInspector) inspectStdio(ctx context.Context, s discover.Server, parent []string, lookedUp secretLists) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, classify(err, s, nil, secretLists{})
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

	// The child gets all the values of lists and can echo them.
	lists := stdioSecretLists(s, lookedUp)
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
		return Result{}, stdioFailure(s, err, lists, sizes.exceeded())
	}

	client := newStdioClient(clientIdentity(s.Client), raw, sizes)
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
	// The configured env values, the expanded values and the argv secrets,
	// for consumers that remove them from the Result text (see
	// Result.Secrets). lists.long holds only values of at least
	// discover.MinSecretBytes bytes already. lists.short does not go there:
	// in ordinary text a short value would garble words.
	result.Secrets = resultSecrets(lists.long)
	// The values of Secrets that look like a credential, for scan --llm (see
	// Result.Credentials). resultCredentials only filters Secrets, so
	// Credentials is a subset of it.
	result.Credentials = resultCredentials(result.Secrets, lists.credentials)
	return result, nil
}

// stdioSecretLists returns the lists of inspectStdio for s, the expanded
// stdio server: lookedUp, the values of the expanded variables, plus the
// configured env values and the credentials inside them (see envSecrets and
// envCredentials) and the secrets in the argv (see argSecrets and
// argCredentials).
//
// The result holds raw values. Never print, log or encode them.
func stdioSecretLists(s discover.Server, lookedUp secretLists) secretLists {
	envLong, envShort := envSecrets(s.Env)
	argLong, argShort := argSecrets(s)
	return secretLists{
		long:        slices.Concat(envLong, lookedUp.long, argLong),
		short:       slices.Concat(envShort, lookedUp.short, argShort),
		credentials: slices.Concat(envCredentials(s.Env), lookedUp.credentials, argCredentials(s)),
	}
}

// newStdioClient returns a new SDK client for one stdio server, with the
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
func newStdioClient(id *mcp.Implementation, raw *rawLists, limit *rawLimit) *mcp.Client {
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
// non-empty value that the lookup returns, for classify to remove from error
// text: a value of at least discover.MinSecretBytes bytes in long, which
// classify removes wherever it stands, and a shorter one in short, which
// classify removes as a whole word only (see replaceWords). A short value is
// too likely to match ordinary words to remove it everywhere. It keeps each
// value one time only, so a config that reads the same variable many times
// does not make the scrub lists long. It is used by one goroutine only.
//
// It also reads the variable name next to each value, for
// Result.Credentials: a value of long is a credential when the name is
// secret-like or the value looks like a credential (see isCredential). The
// same value can come first from a plain name ("A=x") and then from a
// secret-like one ("TOKEN=x"), so a repeated lookup still checks the name.
//
// After each new value, it also records the credentials inside the value
// (see valueCredentials), such as the password of a connection URL: the
// server can echo the password alone. A long piece goes to long and to
// credentials, and a short piece goes to short, by the same length rule as
// a whole value.
//
// The three lists have the names and the meaning of the fields of
// secretLists, and lists returns them as one.
type lookupRecorder struct {
	lookup func(string) (string, bool)
	// long and short hold raw values of the user's environment and the
	// credentials inside them, each one time, in the order in which they
	// were recorded. credentials holds the strings of long that are
	// credentials, each one time, in the order in which they became one.
	// Never print, log or encode them.
	long        []string
	short       []string
	credentials []string
	// lookedUpSet holds the whole values that a lookup returned, to skip
	// the checks of a value that was checked already.
	lookedUpSet map[string]struct{}
	// listedSet holds every string of long and short, whole values and
	// pieces alike, to keep a string out of the lists the second time.
	listedSet map[string]struct{}
	// credentialSet holds the strings of credentials, to find one that is
	// already there.
	credentialSet map[string]struct{}
}

// lists returns the recorded values as a secretLists. The slices are the
// ones of r, not copies; the callers only read them.
func (r *lookupRecorder) lists() secretLists {
	return secretLists{long: r.long, short: r.short, credentials: r.credentials}
}

// Lookup returns the value of the variable name and whether it is set, and
// records the value and the credentials inside it if the value is not
// recorded yet.
func (r *lookupRecorder) Lookup(name string) (string, bool) {
	value, ok := r.lookup(name)
	if !ok || value == "" {
		return value, ok
	}
	if _, dup := r.lookedUpSet[value]; dup {
		// The value check (holdsCredential) and the pieces
		// (valueCredentials) ran at the first lookup and give the same
		// answer now. Only a secret-like name can make the value a
		// credential, and that check is cheap.
		if discover.IsSecretName(name) {
			r.addCredential(value)
		}
		return value, ok
	}
	if r.lookedUpSet == nil {
		r.lookedUpSet = make(map[string]struct{})
	}
	r.lookedUpSet[value] = struct{}{}
	r.record(value)
	if isCredential(name, value) {
		r.addCredential(value)
	}
	// Each piece is a credential by itself. addCredential drops the short
	// ones, so only the record call matters for them.
	innerLong, innerShort := valueCredentials(value)
	for _, piece := range slices.Concat(innerLong, innerShort) {
		r.record(piece)
		r.addCredential(piece)
	}
	return value, ok
}

// record keeps s in r.long when it has at least discover.MinSecretBytes
// bytes, or else in r.short, unless one of the lists has it already. A
// piece of one value can be the whole of another, so the check is on the
// lists (r.listedSet) and not on r.lookedUpSet.
func (r *lookupRecorder) record(s string) {
	if _, dup := r.listedSet[s]; dup {
		return
	}
	if r.listedSet == nil {
		r.listedSet = make(map[string]struct{})
	}
	r.listedSet[s] = struct{}{}
	if len(s) >= discover.MinSecretBytes {
		r.long = append(r.long, s)
	} else {
		r.short = append(r.short, s)
	}
}

// addCredential keeps value in r.credentials when it has at least
// discover.MinSecretBytes bytes and is not there yet. A shorter value never
// goes to Result.Secrets, so it cannot be a credential either.
func (r *lookupRecorder) addCredential(value string) {
	if len(value) < discover.MinSecretBytes {
		return
	}
	if _, dup := r.credentialSet[value]; dup {
		return
	}
	if r.credentialSet == nil {
		r.credentialSet = make(map[string]struct{})
	}
	r.credentialSet[value] = struct{}{}
	r.credentials = append(r.credentials, value)
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

// filterLookup returns a lookup that finds, through lookup, only the names
// that allowed accepts. Every other name is not set.
func filterLookup(lookup func(string) (string, bool), allowed func(string) bool) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if !allowed(name) {
			return "", false
		}
		return lookup(name)
	}
}

// expandPolicy is what the placeholders of one server may read (see
// expandPolicyFor).
type expandPolicy struct {
	// allowed reports whether the lookup may find the variable name.
	allowed func(name string) bool
	// workspace tells whether the Cursor workspace placeholders get the
	// ProjectPath of the server.
	workspace bool
	// note ends the reason of a placeholder that the policy refused (see
	// expandError): the variable can be set in the environment of the
	// user, so "not set" alone would be wrong. It is empty when the policy
	// refuses nothing.
	note string
	// hidden reports whether the variable name is hidden from every
	// placeholder (see hide). It is nil when no name is hidden.
	hidden func(name string) bool
}

// The notes of expandPolicy for the untrusted servers (see expandError).
const (
	reasonBaseOnly = "; a stdio server from an untrusted project file reads only the base environment variables"
	reasonNoEnv    = "; a remote server from an untrusted project file reads no environment variables and no workspace folder"
)

// errHiddenVariable is the end of the reason for a placeholder of a hidden
// variable, in place of discover.ErrMissingVariable (see expandError).
var errHiddenVariable = errors.New("hidden from placeholders")

// hide returns p with the variables in names refused for every server, on
// top of what p refuses already. The names compare without case (see
// SDKOptions.HiddenEnv). With no names, hide returns p as it is.
func (p expandPolicy) hide(names []string) expandPolicy {
	if len(names) == 0 {
		return p
	}
	hidden := func(name string) bool {
		return slices.ContainsFunc(names, func(h string) bool { return strings.EqualFold(h, name) })
	}
	allowed := p.allowed
	p.allowed = func(name string) bool { return !hidden(name) && allowed(name) }
	p.hidden = hidden
	return p
}

// expandPolicyFor returns what the placeholders of s may read. A server
// from an untrusted project file passed the gates only with an opt-in, and
// a cloned repository can ship its config, so it reads only what its config
// cannot use to send a secret, or the name of the user, to a URL or a
// header that the repository chose:
//
//   - a stdio server reads the base variables (see isBaseEnv), which its
//     child gets anyway, and the workspace folder, which is its work
//     directory;
//   - a remote server reads no variable and no workspace folder: even
//     USER, HOME or the project path tell the host who the user is.
//
// The State does not matter: every Cursor server is StateEnabled (mcpmoat
// cannot read the Cursor toggle), and a Claude Code approval by name applies
// to every repository that ships a server with that name. A trusted server
// reads the whole environment and the workspace folder, also when it is not
// enabled: its config is the user's own.
func expandPolicyFor(s discover.Server) expandPolicy {
	switch {
	case !s.Untrusted:
		return expandPolicy{allowed: func(string) bool { return true }, workspace: true}
	case s.Transport.IsRemote():
		return expandPolicy{allowed: func(string) bool { return false }, note: reasonNoEnv}
	default:
		return expandPolicy{allowed: isBaseEnv, workspace: true, note: reasonBaseOnly}
	}
}

// expandError turns an error of discover.Expand into a KindConfig
// *ConnectError. The reason holds the field and at most the variable name of
// the placeholder, never a value: the text of a *discover.ExpandError holds
// nothing else, and it shows a name only when the name is a plain variable
// name (see discover.ExpandError). Any other error gets a fixed reason.
// A placeholder that policy refused gets policy.note at the end: a missing
// variable that policy.allowed does not accept, or a missing workspace
// folder when policy.workspace is false and s has a ProjectPath. A name that
// is not a plain variable name is empty in the ExpandError; no filter but
// the one of a trusted server accepts it, and a trusted server has no note.
// A missing variable that policy.hidden reports gets its own reason, for
// every server: "cannot expand <field>: variable <name>: hidden from
// placeholders" (see errHiddenVariable). It has no policy.note, because the
// untrusted note would give the wrong cause, and no "variable is not set",
// because the variable can be set. So the reason never says whether a
// hidden variable is set. The cause still wraps discover.ErrMissingVariable.
func expandError(s discover.Server, err error, policy expandPolicy) *ConnectError {
	reason := "cannot expand the variables in the server config"
	if ee, ok := errors.AsType[*discover.ExpandError](err); ok {
		reason = ee.Error()
		missingVar := errors.Is(err, discover.ErrMissingVariable)
		hiddenVar := missingVar && policy.hidden != nil && policy.hidden(ee.Name)
		refusedVar := missingVar && !policy.allowed(ee.Name)
		refusedWorkspace := errors.Is(err, discover.ErrNoWorkspaceFolder) && !policy.workspace && s.ProjectPath != ""
		switch {
		case hiddenVar:
			hidden := discover.ExpandError{Field: ee.Field, Name: ee.Name, Err: errHiddenVariable}
			reason = hidden.Error()
		case refusedVar || refusedWorkspace:
			reason += policy.note
		}
	} else {
		// Keep no text of an unknown error.
		err = nil
	}
	return configErrorWithCause(s, reason, err)
}

// envSecrets returns the configured env values in two lists. secrets holds
// the values of at least discover.MinSecretBytes bytes, for classify to remove
// from error text wherever they stand and for Result.Secrets (see
// resultSecrets). short holds the other non-empty values, for classify to
// remove from error text as whole words only (see replaceWords): a shorter
// value is too likely to match ordinary words ("1", "true", "info"), but the
// child gets it and can echo it.
//
// After each value, the lists also get the credentials inside it (see
// valueCredentials), such as the password of
// "DATABASE_URL=postgres://u:pw@h/db": the child can echo the password alone.
// The long pieces go to secrets and the short ones to short, by the same
// length rule. Both lists are in the order of env.Keys.
//
// The results hold raw values. Never print, log or encode them.
func envSecrets(env discover.SecretMap) (secrets, short []string) {
	for _, key := range env.Keys() {
		v := env[key].Reveal()
		switch {
		case len(v) >= discover.MinSecretBytes:
			secrets = append(secrets, v)
		case v != "":
			short = append(short, v)
		}
		innerLong, innerShort := valueCredentials(v)
		secrets = append(secrets, innerLong...)
		short = append(short, innerShort...)
	}
	return secrets, short
}

// envCredentials returns the configured env values that are credentials, for
// Result.Credentials: the values of at least discover.MinSecretBytes bytes
// (the long list of envSecrets) whose key is secret-like or that look like a
// credential (see isCredential). So "API_KEY=production" gives "production",
// and "NODE_ENV=production" gives nothing. After each value, it also returns
// the long credentials inside the value (see valueCredentials), which
// envSecrets puts in its long list too. The list is in the order of
// env.Keys.
//
// The result holds raw values. Never print, log or encode them.
func envCredentials(env discover.SecretMap) []string {
	var credentials []string
	for _, key := range env.Keys() {
		v := env[key].Reveal()
		if len(v) >= discover.MinSecretBytes && isCredential(key, v) {
			credentials = append(credentials, v)
		}
		// The blank identifier _ drops the short pieces: a value under
		// discover.MinSecretBytes bytes never goes to Result.Secrets, so it
		// cannot be a credential either.
		innerLong, _ := valueCredentials(v)
		credentials = append(credentials, innerLong...)
	}
	return credentials
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
//
// lists are the values to remove from the error text (see classify).
func stdioFailure(s discover.Server, err error, lists secretLists, tooLarge bool) *ConnectError {
	ce := classify(err, s, nil, lists)
	switch {
	case errors.Is(err, errJSONTooComplex):
		ce.err = errJSONTooComplex
		if ctxErr := contextErr(err); ctxErr != nil {
			ce.err = fmt.Errorf("%w: %w", errJSONTooComplex, ctxErr)
		}
	case ce.Kind == KindProtocol && (tooLarge || errors.Is(err, errRawTooLarge)):
		ce.Kind = KindTooLarge
		ce.Reason = errRawTooLarge.Error()
		ce.fixed, ce.serverText = ce.Reason, "" // all of Reason is fixed text now
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
		return classify(ctxErr, s, nil, secretLists{})
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
