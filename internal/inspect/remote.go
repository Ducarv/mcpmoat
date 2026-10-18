package inspect

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
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

	// clientName and clientVersion are the client identity in the MCP
	// initialize request. The SDK wants a non-empty name and version.
	//
	// They do not name mcpmoat on purpose, and neither does the default
	// User-Agent (the net/http one). A hostile server that recognises the
	// scanner could show it a clean tool list and show the real clients a
	// poisoned one, and the pins would never see the difference (threat T1,
	// FR-11). A server can still fingerprint a client in other ways; see
	// docs/PRD.md section 5.5.
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
	// transport with TLS 1.2+ and the proxy settings from the environment.
	// Only tests in this package set it. It is unexported so that no caller
	// can give a transport that skips the TLS checks; the origin pin and the
	// header rules apply to any transport.
	baseTransport http.RoundTripper
}

// Remote connects to a remote MCP server (streamable HTTP or legacy SSE, from
// srv.Transport) and lists its tools, prompts and resources.
//
// A server from an untrusted project file (srv.Untrusted) is refused unless
// opts.AllowUntrusted is set.
//
// The headers from srv.Headers go to the origin of srv.URL only, exactly as
// configured: Remote does not expand ${VAR} placeholders (issue #88). The user
// info of the URL (user:password@) is not given to the MCP SDK. Remote sends it
// as a Basic Authorization header instead, unless the config sets an
// Authorization header.
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
	// A cloned repository can ship a project file with a server entry. Do not
	// connect to it, and so do not send its headers anywhere, without the
	// explicit opt-in of the user.
	if srv.Untrusted && !opts.AllowUntrusted {
		return Result{}, configError(srv, "untrusted project server; connecting needs explicit opt-in")
	}
	if !srv.Transport.IsRemote() {
		return Result{}, configError(srv, "not a remote server")
	}

	raw := srv.URL.Reveal()
	u, reason := parseEndpoint(raw)
	if reason != "" {
		return Result{}, configError(srv, reason)
	}

	endpointURL, user := splitUserinfo(u)
	endpoint := endpointURL.String()

	// secrets are all the strings that classify removes from error text.
	headers, secrets := splitHeaders(srv.Headers)
	secrets = append(secrets, userinfoSecrets(user)...)
	secrets = append(secrets, urlSecrets(u)...)

	httpClient, rec, err := newHTTPClient(httpClientConfig{
		Endpoint:  &endpointURL,
		User:      user,
		Headers:   headers,
		Base:      opts.baseTransport,
		UserAgent: opts.UserAgent,
		MaxBody:   opts.MaxResponseBytes,
	})
	if err != nil {
		if errors.Is(err, errReservedHeader) {
			// The text holds the header key only, never a value.
			return Result{}, configError(srv, truncate(err.Error()))
		}
		return Result{}, configError(srv, "invalid HTTP client settings")
	}

	// Always derive a context that this function can cancel, so that a
	// background goroutine of the SDK cannot outlive the call.
	// Defers run last-in, first-out (LIFO). cancel is registered first, so it
	// runs last: the session close below runs first and can still use ctx for
	// its DELETE request, then the connections close, then ctx is canceled.
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
		&mcp.Implementation{Name: clientName, Version: clientVersion},
		&mcp.ClientOptions{Logger: slog.New(slog.DiscardHandler)},
	)
	// The middleware keeps the tool lists as the server sent them, for the
	// checks in listAll. It must be added before Connect.
	rawTools := &rawLists{}
	mcpClient.AddSendingMiddleware(rawTools.middleware())

	// fail turns err into the *ConnectError that Remote returns. The SDK
	// formats some errors with %v, which drops the context error from the
	// chain (the legacy SSE transport does this when the endpoint event never
	// comes). When ctx has ended, fail puts its error first, so the kind is
	// KindTimeout and errors.Is(err, context.DeadlineExceeded) works. The
	// deferred cancel has not run yet, so ctx.Err is set only by the deadline
	// or by the caller.
	//
	// The *url.Error is stripped before the join: classify replaces an error
	// that holds one with its inner error, and that would drop ctxErr.
	fail := func(err error) (Result, error) {
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
			err = fmt.Errorf("%w: %w", ctxErr, stripURLError(err))
		}
		return Result{}, classify(err, srv, rec, secrets)
	}

	cs, err := mcpClient.Connect(ctx, newRemoteTransport(srv.Transport, endpoint, httpClient), nil)
	if err != nil {
		return fail(err)
	}
	// The session is up: the SDK recovered from any request that the HTTP
	// layer blocked during the connect, and the server speaks the configured
	// transport (see requestRecorder.markConnected).
	rec.markConnected()
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
	result.Tools, result.Prompts, result.Resources, err = listAll(ctx, cs, initRes.Capabilities, rawTools)
	if err != nil {
		return fail(err)
	}
	return result, nil
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

// urlSecrets returns the secrets in the query and the path of u, for classify
// to remove wherever they stand in error text: every query value, every bare
// query part (a key with an empty value or no "="), and every path segment
// that discover.RedactURL masks (discover.SecretPathSegments). Query parts
// come in their raw form and, when it differs, unescaped. It keeps only parts
// with at least minBareSecretLen bytes. In URL form, classify removes the
// whole query and every secret segment anyway (replaceURLParts).
//
// It splits the raw query itself, on "&" and ";": url.ParseQuery drops a pair
// with a ";" or a bad escape, and such a value is still a secret.
func urlSecrets(u *url.URL) []string {
	var secrets []string
	add := func(s string) {
		if len(s) >= minBareSecretLen {
			secrets = append(secrets, s)
		}
	}
	isSep := func(r rune) bool { return r == '&' || r == ';' }
	for pair := range strings.FieldsFuncSeq(u.RawQuery, isSep) {
		key, value, _ := strings.Cut(pair, "=")
		part := value
		if part == "" {
			part = key
		}
		add(part)
		if plain, err := url.QueryUnescape(part); err == nil && plain != part {
			add(plain)
		}
	}
	for _, seg := range discover.SecretPathSegments(u.String()) {
		add(seg)
	}
	return secrets
}

// splitHeaders returns the config headers with their raw values, for the
// HTTP client, and the secrets in them, for classify to remove from error
// text: each non-empty value and, for a value with an auth scheme such as
// "Bearer <token>", the credential part alone (see credentialPart).
func splitHeaders(cfg discover.SecretMap) (headers map[string]string, values []string) {
	headers = make(map[string]string, len(cfg))
	for key, secret := range cfg {
		value := secret.Reveal()
		headers[key] = value
		if value != "" {
			values = append(values, value)
		}
		if cred := credentialPart(value); cred != "" {
			values = append(values, cred)
		}
	}
	return headers, values
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

// isAuthScheme reports whether s can be an HTTP auth scheme name.
func isAuthScheme(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.'
		if !ok {
			return false
		}
	}
	return true
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
// it stands in a URL, so that a short name does not garble other words. A nil
// user gives nil.
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
