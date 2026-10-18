package inspect

import (
	"context"
	"encoding/base64"
	"errors"
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

	// defaultUserAgent is the User-Agent header when the caller sets none.
	defaultUserAgent = "mcpmoat"

	// clientName and clientVersion identify mcpmoat in the MCP initialize
	// request. The SDK wants a non-empty name and version. cmd can pass the
	// real version later.
	clientName    = "mcpmoat"
	clientVersion = "dev"
)

// RemoteOptions configures Remote. The zero value is ready to use.
type RemoteOptions struct {
	// Transport is the base HTTP transport. Nil means a fresh transport with
	// TLS 1.2+ and the proxy settings from the environment. Intended for
	// tests. A custom transport bypasses the TLS settings of the default
	// transport; the origin pin and header rules still apply.
	Transport http.RoundTripper

	// AllowUntrusted lets Remote connect even when the server comes from an
	// untrusted project file (discover.Server.Untrusted). The caller must have
	// the explicit opt-in of the user before it sets this.
	AllowUntrusted bool

	// UserAgent is sent unless the config sets a User-Agent header. Empty
	// means "mcpmoat".
	UserAgent string

	// MaxResponseBytes caps each HTTP response body (the whole SSE stream
	// counts as one body). Zero or less means the default of 8 MiB.
	MaxResponseBytes int64
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
	u, reason := parseOrigin(raw)
	if reason != "" {
		return Result{}, configError(srv, reason)
	}

	// Take the user info and the fragment out of the URL. The SDK gets an
	// endpoint without them, so no SDK error text can hold them. A fragment is
	// never sent over HTTP, so dropping it changes no request. url.URL.String
	// re-encodes the URL; this is acceptable, because the result is equivalent
	// to the configured URL minus its user info and fragment.
	user := u.User
	origin := *u
	origin.User = nil
	origin.Fragment = ""
	origin.RawFragment = ""
	endpoint := origin.String()

	headers := make(map[string]string, len(srv.Headers))
	headerValues := make([]string, 0, len(srv.Headers)+4)
	for key, secret := range srv.Headers {
		value := secret.Reveal()
		headers[key] = value
		if value != "" {
			headerValues = append(headerValues, value)
		}
	}
	headerValues = append(headerValues, userinfoSecrets(user)...)

	ua := opts.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	httpClient, rec, err := newHTTPClient(httpClientConfig{
		Origin:    &origin,
		User:      user,
		Headers:   headers,
		Base:      opts.Transport,
		UserAgent: ua,
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
		// A safety net only. Issue #28 owns the real per-server timeout.
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

	cs, err := mcpClient.Connect(ctx, newRemoteTransport(srv.Transport, endpoint, httpClient), nil)
	if err != nil {
		return Result{}, classify(err, srv, rec, headerValues)
	}
	// Listing is finished when this runs, so the error from Close does not
	// matter. For streamable HTTP, Close sends a DELETE that the SDK bounds.
	defer func() { _ = cs.Close() }()

	initRes := cs.InitializeResult()
	if initRes == nil {
		// The SDK always sets the result after a successful Connect. Guard
		// anyway: a nil would panic below.
		return Result{}, classify(errors.New("no initialize result"), srv, rec, headerValues)
	}

	result := Result{
		ProtocolVersion: initRes.ProtocolVersion,
		Instructions:    initRes.Instructions,
	}
	if initRes.ServerInfo != nil {
		result.ServerName = initRes.ServerInfo.Name
		result.ServerVersion = initRes.ServerInfo.Version
	}

	result.Tools, result.Prompts, result.Resources, err = listAll(ctx, cs, initRes.Capabilities, rawTools)
	if err != nil {
		return Result{}, classify(err, srv, rec, headerValues)
	}
	return result, nil
}

// userinfoSecrets returns the secret strings that the user info of a URL
// adds: the user name, the password, and the Basic Authorization token and
// header value built from them. classify removes them from error text. A nil
// user gives nil.
func userinfoSecrets(user *url.Userinfo) []string {
	if user == nil {
		return nil
	}
	name := user.Username()
	password, _ := user.Password()
	token := base64.StdEncoding.EncodeToString([]byte(name + ":" + password))

	secrets := []string{token, "Basic " + token}
	if name != "" {
		secrets = append(secrets, name)
	}
	if password != "" {
		secrets = append(secrets, password)
	}
	return secrets
}

// parseOrigin parses raw and checks that it is an http or https URL with a
// host. On failure it returns a fixed reason text and a nil URL. It returns
// no error value on purpose: url.Parse errors hold the raw URL, so they are
// never used.
func parseOrigin(raw string) (*url.URL, string) {
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
