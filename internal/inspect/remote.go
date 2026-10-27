package inspect

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

const (
	// defaultConnectTimeout bounds one Remote call when the caller's
	// context has no deadline. It is a safety net only: the per-server
	// --timeout comes in issue #28.
	defaultConnectTimeout = 10 * time.Second

	// clientName and clientVersion are the neutral client identity in the
	// MCP initialize request, for a server of a client that clientIdentity
	// does not know. The SDK wants a non-empty name and version.
	//
	// They do not name mcpmoat on purpose, and neither does the default
	// User-Agent (the net/http one). A hostile server that recognises the
	// scanner could show it a clean tool list and show the real clients a
	// poisoned one, and the pins would never see the difference (threat T1,
	// FR-11). A server can still fingerprint a client in other ways; see
	// clientIdentity and docs/PRD.md section 5.5.
	clientName    = "mcp-client"
	clientVersion = "1.0.0"

	// minBareSecretLen is the shortest part of a secret that classify
	// removes wherever it stands in error text: a token after its auth
	// scheme, a token used as the URL user name, a query value or a secret
	// path segment. A server can echo such a part alone ("invalid token
	// <token>"). A shorter part is too likely to match ordinary words.
	minBareSecretLen = 8
)

// RemoteOptions configures Remote. The zero value is ready to use.
type RemoteOptions struct {
	// AllowUntrusted lets Remote connect even when the server comes from an
	// untrusted project file (discover.Server.Untrusted). The caller must have
	// the explicit opt-in of the user before it sets this.
	AllowUntrusted bool

	// AllowDisabled lets Remote connect even when the State of the server is
	// not discover.StateEnabled. See SDKOptions.AllowDisabled.
	AllowDisabled bool

	// UserAgent is sent unless the config sets a User-Agent header. Empty
	// means the net/http default, which does not name mcpmoat. Never set a
	// value that names mcpmoat: a server could then show the scanner a clean
	// tool list (see clientName). Set it only to match a real client.
	UserAgent string

	// MaxResponseBytes caps each HTTP response body (the whole SSE stream
	// counts as one body). Zero or less means the default of 8 MiB. A value
	// above the total budget for all bodies (64 MiB) is lowered to it.
	MaxResponseBytes int64

	// baseTransport replaces the base HTTP transport. Nil means a fresh
	// transport with TLS 1.2+, the pinned dialer and the proxy function
	// proxy. Only tests in this package set it. It is unexported so that no
	// caller can give a transport that skips the TLS checks; the origin pin
	// and the header rules apply to any transport.
	baseTransport http.RoundTripper

	// proxy is the proxy function of the base transport that Remote makes,
	// and the one that the DNS pin warning asks (see dnsPinWarning). Nil
	// means proxyFromEnvironment. Only tests in this package set it:
	// http.ProxyFromEnvironment reads the environment one time per process,
	// so t.Setenv cannot change its answer. With baseTransport set, the
	// warning still asks proxy, but the requests use the proxy setting of
	// baseTransport.
	proxy func(*http.Request) (*url.URL, error)

	// dial is the dial function of the pinned dialer in the base transport
	// that Remote makes. Nil means a net.Dialer. The pinned dialer calls it
	// only after the DNS pin and the address guard. It has no effect when
	// baseTransport is set. SDKInspector.Inspect passes SDKOptions.Dial.
	dial DialFunc

	// secrets are more strings that classify removes from error text, on
	// top of the ones that Remote finds in srv (header values, URL user
	// info, query and path parts). SDKInspector.Inspect passes the values of
	// the variables that it expanded in srv, because they can stand in any
	// part of the URL. They are never shown.
	secrets []string
}

// Remote connects to a remote MCP server (streamable HTTP or legacy SSE, from
// srv.Transport) and lists its tools, prompts and resources.
//
// Remote checks the gates first, in the order of checkGates. A server whose
// State is not discover.StateEnabled (the client config turns it off, the
// user did not approve it, or only files from the repository approve it) is
// refused unless opts.AllowDisabled is set. Then a server from an untrusted
// project file (srv.Untrusted) is refused unless opts.AllowUntrusted is set.
// A refused server gets no request at all.
//
// The headers from srv.Headers go to the origin of srv.URL only, exactly as
// srv has them. Remote does not expand ${VAR} placeholders itself:
// SDKInspector.Inspect expands them with discover.Expand (issue #88) and
// gives Remote the expanded server. A caller that calls Remote directly
// passes srv as it wants it sent. The user info of the URL (user:password@)
// is not given to the MCP SDK. Remote sends it as a Basic Authorization
// header instead, unless the config sets an Authorization header.
//
// The initialize request names the client that declared srv (see
// clientIdentity), not mcpmoat.
//
// Remote can add warnings about the connection, with no secret value in
// them:
//   - WarnCleartextSecrets, when Remote sends config headers, URL user info
//     or secrets in the URL query or path over plain http:// to a host that
//     is not loopback. Remote still connects. The warning holds keys only.
//   - WarnDNSPinUnavailable, when the host is a DNS name and the request
//     goes through a proxy, so the proxy resolves the name and the address
//     checks of the dialer do not apply (see dnsPinWarning).
//
// These connection warnings go to Result.Warnings on success, before the
// warnings that the lists add (see listInto), and to ConnectError.Warnings
// when the inspection fails after the connect started.
//
// If ctx has no deadline, Remote adds a 10 second one. Closing the session
// sends a DELETE request (streamable HTTP) that the SDK bounds to 5 seconds,
// so in the worst case Remote returns up to about 5 seconds after the
// deadline.
//
// Every non-nil error is a *ConnectError; use errors.As to get it. Its text
// never holds the raw URL or a header value. It can hold text that the server
// controls, so callers must escape it with internal/termsafe before they print
// it. errors.Is(err, context.DeadlineExceeded) works for timeouts.
func Remote(ctx context.Context, srv discover.Server, opts RemoteOptions) (Result, error) {
	// The client config turns the server off, or the user did not approve
	// it, or a cloned repository ships the server in a project file. Do not
	// connect to it, and so do not send its headers anywhere, without the
	// explicit opt-in of the user.
	if err := checkGates(srv, opts.AllowUntrusted, opts.AllowDisabled); err != nil {
		return Result{}, gateError(srv, err)
	}
	if !srv.Transport.IsRemote() {
		return Result{}, configError(srv, "not a remote server")
	}

	raw := srv.URL.Reveal()
	u, reason := parseEndpoint(raw)
	if reason != "" {
		return Result{}, configError(srv, reason)
	}
	// RedactURL masks the whole URL when it cannot show it safely, for
	// example when an unescaped "/", "?" or "#" in a credential ends the
	// authority early, so that part of the token becomes the host. Remote
	// would then send that part to the DNS resolver and put it in error
	// text. Refuse such a URL.
	if discover.RedactURL(raw) == discover.Mask {
		return Result{}, configError(srv, `URL cannot be shown safely; escape "@", "/", "?" and "#" in the user info, and write the host in ASCII (punycode)`)
	}

	endpointURL, user := splitUserinfo(u)
	endpoint := endpointURL.String()

	// secrets are all the strings that classify removes from error text.
	headers, secrets := splitHeaders(srv.Headers)
	secrets = append(secrets, userinfoSecrets(user)...)
	secrets = append(secrets, urlSecrets(u.RawQuery, raw)...)
	secrets = append(secrets, opts.secrets...)

	proxy := opts.proxy
	if proxy == nil {
		proxy = proxyFromEnvironment
	}
	base := opts.baseTransport
	if base == nil {
		// The same base transport that newHTTPClient makes for a nil Base,
		// with the proxy function above, so that the requests and the DNS
		// pin warning below use the same proxy setting.
		t := newBaseTransportDial(nil, opts.dial, endpointURL.Hostname())
		t.Proxy = proxy
		base = t
	}

	httpClient, ev, err := newHTTPClient(httpClientConfig{
		Endpoint:  &endpointURL,
		User:      user,
		Headers:   headers,
		Base:      base,
		UserAgent: opts.UserAgent,
		MaxBody:   opts.MaxResponseBytes,
	})
	if err != nil {
		if errors.Is(err, errReservedHeader) || errors.Is(err, errInvalidHeaderValue) {
			// The text holds the header key only, never a value.
			return Result{}, configError(srv, truncate(err.Error()))
		}
		return Result{}, configError(srv, "invalid HTTP client settings")
	}

	// warnings are the connection warnings. The cleartext ones tell the user
	// about secrets that go over plain http:// to a host that is not
	// loopback (issue #98). They hold keys only. They are computed after
	// newHTTPClient accepted the headers, as sentHeaders expects. The DNS pin
	// one tells that a proxy resolves the server name (issue #106). It holds
	// no URL. Remote returns them on success and with every error after a
	// request could have gone out (see fail), because by then the secrets
	// were sent.
	warnings := slices.Concat(cleartextWarnings(srv, u), dnsPinWarning(&endpointURL, proxy))

	// Always derive a context that this function can cancel, so that the
	// SDK work that uses ctx stops when Remote returns.
	// Defers run last-in, first-out (LIFO). cancel is registered first, so it
	// runs last: the session close below runs first, then the idle
	// connections close, then ctx is canceled. The SDK sends the session
	// DELETE on a context of its own, bounded to 5 seconds.
	//
	// One SDK goroutine can outlive Remote: after a call fails because ctx
	// ended, the SDK sends notifications/cancelled on a detached context,
	// also bounded to 5 seconds. That is one more request to the same origin,
	// and its connection can stay idle until idleConnTimeout. The detached
	// context keeps the record of the failed call, but that record is
	// finished, so the answer cannot change the label of the error (see
	// requestRecorder.finish).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, defaultConnectTimeout)
		defer cancelTimeout()
	}
	defer httpClient.CloseIdleConnections()

	// The SDK logger can print server text and URLs. mcpmoat must never log
	// them, so the logger discards everything.
	mcpClient := mcp.NewClient(
		clientIdentity(srv.Client),
		&mcp.ClientOptions{Logger: slog.New(slog.DiscardHandler)},
	)
	// The middleware keeps the tool lists as the server sent them, for the
	// checks in listAll. It must be added before Connect.
	rawTools := &rawLists{}
	mcpClient.AddSendingMiddleware(rawTools.middleware())
	// Each AddSendingMiddleware call wraps the handler built so far, so the
	// middleware added last runs first. callRecords is added last on purpose:
	// it sees every call, and it links the final error of the call to its
	// HTTP record.
	mcpClient.AddSendingMiddleware(callRecords(ev))

	// fail turns err into the *ConnectError that Remote returns. The SDK
	// formats some errors with %v, which drops the context error from the
	// chain (the legacy SSE transport does this when the endpoint event never
	// comes). When ctx has ended, fail puts its error first, so the kind is
	// KindTimeout and errors.Is(err, context.DeadlineExceeded) works. The
	// deferred cancel has not run yet, so ctx.Err is set only by the deadline
	// or by the caller.
	//
	// The *url.Error is stripped before the join (joinContextErr): classify
	// replaces an error that holds one with its inner error, and that would
	// drop ctxErr.
	//
	// fail also attaches warnings: the requests before the failure already
	// carried the secrets over plain HTTP. Every return after Connect starts
	// goes through fail, so no failure path loses the warnings.
	fail := func(err error) (Result, error) {
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
			err = joinContextErr(ctxErr, err)
		}
		ce := classify(err, srv, ev, secrets)
		ce.Warnings = warnings
		return Result{}, ce
	}

	cs, err := mcpClient.Connect(ctx, newRemoteTransport(srv.Transport, endpoint, httpClient), nil)
	if err != nil {
		return fail(err)
	}
	// The session is up: the SDK recovered from any request that the HTTP
	// layer blocked during the connect, and the server speaks the configured
	// transport (see httpEvents.markConnected).
	ev.markConnected()
	// Listing is finished when this runs, so the error from Close does not
	// matter. For streamable HTTP, Close sends a DELETE that the SDK bounds.
	defer func() { _ = cs.Close() }()

	initRes := cs.InitializeResult()
	if initRes == nil {
		// The SDK always sets the result after a successful Connect. Guard
		// anyway: a nil would panic below.
		return fail(errors.New("no initialize result"))
	}

	result := resultFromInit(initRes)
	if err := listInto(ctx, cs, initRes.Capabilities, rawTools, &result); err != nil {
		return fail(err)
	}
	// listInto can have added warnings about the lists. Keep them, after
	// the connection warnings. slices.Concat gives nil when both are empty.
	result.Warnings = slices.Concat(warnings, result.Warnings)
	return result, nil
}

// callRecords returns the sending middleware that gives each MCP call its own
// HTTP record (issue #100). It puts a new requestRecorder on the context of
// the call. The SDK sends the HTTP requests of the call with that context, so
// headerTransport writes the status and any blocked error of those requests
// to this record and not to a record that all requests share.
//
// When the call returns, the middleware stores the record as the last one in
// ev. If the call failed, it wraps the error in a *recordedError, so that
// classify finds the record of exactly this call. Once the server answered
// initialize (or server/discover), it speaks the configured transport, even
// if a later request of Connect fails, so a success of either marks the
// handshake.
func callRecords(ev *httpEvents) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			rec := &requestRecorder{}
			res, err := next(withRecorder(ctx, rec), method, req)
			ev.finishCall(rec)
			if err != nil {
				return res, &recordedError{err: err, rec: rec}
			}
			if method == methodInitialize || method == methodDiscover {
				ev.markHandshake()
			}
			return res, nil
		}
	}
}

// joinContextErr returns err with ctxErr first in its chain, for fail in
// Remote. It strips the *url.Error of err (see fail). That also drops the
// *recordedError above it, which links err to the record of its MCP call, so
// joinContextErr puts the link back. classify then reads the record of the
// call that failed, not of the call that finished last (see
// httpEvents.stateFor).
func joinContextErr(ctxErr, err error) error {
	joined := fmt.Errorf("%w: %w", ctxErr, stripURLError(err))
	var re *recordedError
	if errors.As(err, &re) {
		return &recordedError{err: joined, rec: re.rec}
	}
	return joined
}

// splitUserinfo returns u without its user info and fragment, and the user
// info. The SDK gets an endpoint without them, so no SDK error text can hold
// them. A fragment is never sent over HTTP, so dropping it changes no request.
// url.URL.String re-encodes the URL; this is acceptable, because the result is
// equivalent to the configured URL minus its user info and fragment.
func splitUserinfo(u *url.URL) (endpoint url.URL, user *url.Userinfo) {
	endpoint = *u
	endpoint.User = nil
	endpoint.Fragment = ""
	endpoint.RawFragment = ""
	return endpoint, u.User
}

// urlSecrets returns the secrets in rawQuery and in the path of raw, the
// configured URL, for classify to remove wherever they stand in error text:
// the parts that discover.RedactURL masks (discover.SecretQueryParts and
// discover.SecretPathSegments), with at least minBareSecretLen bytes. In URL
// form, classify removes the whole query and every secret segment anyway
// (replaceURLParts); this list is for a server that echoes a part alone.
func urlSecrets(rawQuery, raw string) []string {
	var secrets []string
	for _, s := range slices.Concat(discover.SecretQueryParts(rawQuery), discover.SecretPathSegments(raw)) {
		if len(s) >= minBareSecretLen {
			secrets = append(secrets, s)
		}
	}
	return secrets
}

// splitHeaders returns the config headers with their raw values, for the
// HTTP client, and the secrets in them, for classify to remove from error
// text: each non-empty value and, for a value with an auth scheme such as
// "Bearer <token>", the credential part alone (see credentialPart).
func splitHeaders(cfg discover.SecretMap) (headers map[string]string, secrets []string) {
	headers = make(map[string]string, len(cfg))
	for key, secret := range cfg {
		value := secret.Reveal()
		headers[key] = value
		if value != "" {
			secrets = append(secrets, value)
		}
		if cred := credentialPart(value); cred != "" {
			secrets = append(secrets, cred)
		}
		secrets = append(secrets, basicSecrets(value)...)
	}
	return headers, secrets
}

// basicSecrets returns the secrets inside a "Basic <base64>" value: the
// same strings that userinfoSecrets gives for the decoded name and password.
// A server can echo the decoded password alone ("invalid password <pw>"). It
// returns nil for any other value, and for a credential that does not decode.
func basicSecrets(value string) []string {
	scheme, cred, found := strings.Cut(value, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return nil
	}
	name, password, _ := strings.Cut(string(decoded), ":")
	return userinfoSecrets(url.UserPassword(name, password))
}

// credentialPart returns the part of value after an auth scheme, as in
// "Bearer <token>" or "Token <token>", when it has at least minBareSecretLen
// bytes. It returns "" when value has no scheme prefix. A scheme is one word
// of ASCII letters, digits, "-", "_" or ".", followed by a space.
func credentialPart(value string) string {
	scheme, rest, found := strings.Cut(value, " ")
	if !found || !isAuthScheme(scheme) {
		return ""
	}
	rest = strings.TrimSpace(rest)
	if len(rest) < minBareSecretLen {
		return ""
	}
	return rest
}

// isAuthScheme reports whether s can be an HTTP auth scheme name. RFC 9110
// (section 11.1) defines an auth-scheme as a token.
func isAuthScheme(s string) bool {
	return isHTTPToken(s)
}

// resultFromInit returns a Result with the fields from the initialize result
// set. The lists are not set.
func resultFromInit(initRes *mcp.InitializeResult) Result {
	result := Result{
		ProtocolVersion: initRes.ProtocolVersion,
		Instructions:    initRes.Instructions,
	}
	if initRes.ServerInfo != nil {
		result.ServerName = initRes.ServerInfo.Name
		result.ServerVersion = initRes.ServerInfo.Version
	}
	return result
}

// userinfoSecrets returns the secret strings that the user info of a URL
// adds: the password, and the Basic Authorization token and header value
// built from the name and the password. classify removes them from error
// text everywhere.
//
// The user name is in the list only when the URL has no password and the name
// has at least minBareSecretLen bytes: then the name is the credential, as in
// https://<token>@host/. Otherwise replaceUserinfo removes the name only where
// it stands in a URL, so that a short name does not garble other words.
//
// The password is in the list at any length, like a header value: a leak is
// worse than a garbled word, and a short password is the one most likely to be
// guessed from an echo. A nil user gives nil.
func userinfoSecrets(user *url.Userinfo) []string {
	if user == nil {
		return nil
	}
	name := user.Username()
	password, _ := user.Password()
	token := base64.StdEncoding.EncodeToString([]byte(name + ":" + password))

	secrets := []string{token, "Basic " + token}
	if password != "" {
		secrets = append(secrets, password)
	} else if len(name) >= minBareSecretLen {
		secrets = append(secrets, name)
	}
	return secrets
}

// parseEndpoint parses raw and checks that it is an http or https URL with a
// host. On failure it returns a fixed reason text and a nil URL. It returns
// no error value on purpose: url.Parse errors hold the raw URL, so they are
// never used.
func parseEndpoint(raw string) (*url.URL, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, "URL does not parse"
	}
	// url.Parse lowercases the scheme.
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "unsupported URL scheme; use http or https"
	}
	if strings.TrimSpace(u.Hostname()) == "" {
		return nil, "URL has no host"
	}
	return u, ""
}

// newRemoteTransport returns the SDK transport for kind. It uses endpoint, the
// configured URL without its user info.
func newRemoteTransport(kind discover.Transport, endpoint string, httpClient *http.Client) mcp.Transport {
	if kind == discover.TransportSSE {
		return &mcp.SSEClientTransport{Endpoint: endpoint, HTTPClient: httpClient}
	}
	return &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
		// A negative value turns reconnects off: a retry would send the
		// secret headers again to a server that already failed.
		MaxRetries: -1,
		// Listing needs no background GET stream for server messages.
		DisableStandaloneSSE: true,
	}
}
