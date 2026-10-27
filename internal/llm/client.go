package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// MaxConcurrentRequests is the number of requests that a caller should run at
// the same time. The transport keeps one idle connection for each of them.
const MaxConcurrentRequests = 4

// Timeouts and limits of the client transport.
const (
	// requestTimeout bounds one whole request: connect, send and read.
	requestTimeout      = 30 * time.Second
	dialTimeout         = 10 * time.Second
	dialKeepAlive       = 30 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
	idleConnTimeout     = 30 * time.Second
	// maxResponseHeaderBytes caps the response headers.
	maxResponseHeaderBytes = 64 << 10
	// loopbackAddrTimeout bounds the dial of one loopback address when
	// another address is left to try (see loopbackDial).
	loopbackAddrTimeout = 2 * time.Second
)

// Errors of Classify. All of them have fixed text: no error from this file
// holds the API key, the URL, a header, a response body or model output, so
// the caller can print err.Error() as it is.
//
// Use errors.Is to sort an error of Classify:
//
//   - ErrInvalidOutput: the provider answered, but the model refused or its
//     output is not a valid verdict. The caller reports RuleIDInvalid.
//   - ErrProvider: the request failed (the provider refused the key, a
//     network error, a response that is too large or not valid, or a
//     *StatusError). The caller reports a scan error, and Reason gives its
//     fixed reason text.
//   - context.Canceled or context.DeadlineExceeded: the context of the
//     caller ended (for example a signal). Classify returns this only when
//     the context of the caller is done, never for its own timeout.
//
// Other errors (a request that is too large, a request that cannot be
// built) cannot happen with the caps of this package, but are checked.
var (
	// ErrProvider is the parent of every error that means the request to
	// the provider failed.
	ErrProvider = errors.New("LLM provider request failed")
)

// Fixed texts of Reason. authHint and redirectHint are the hints of a
// *StatusError (see StatusError.reason), and this is the only place of them.
const (
	// authHint is the hint for HTTP 401 and 403. errAuth uses it too.
	authHint = "the API key was refused"
	// redirectHint is the hint for a 3xx code.
	redirectHint = "redirect refused"
	// unknownReason is the text of Reason for an error that is not a known
	// provider error.
	unknownReason = "unknown error"
)

// Unexported errors. They have fixed text too. errAuth, errTransport,
// errTimeout, errProxyRefused, errCertificate, errTooLarge, errBadResponse and
// errNotLoopback wrap ErrProvider, and Reason knows each of them.
var (
	// errAuth means that the provider refused the API key (HTTP 401 or
	// 403). The error is also a *StatusError with the code.
	errAuth = fmt.Errorf("%w: %s", ErrProvider, authHint)
	// errTransport means a network, TLS, proxy or timeout error. The error
	// never wraps the net/http error, because that text holds the URL.
	errTransport = fmt.Errorf("%w: network error", ErrProvider)
	// errTimeout means that the request did not end in requestTimeout.
	errTimeout = fmt.Errorf("%w: timed out after %s", errTransport, requestTimeout)
	// errProxyRefused is errProxy as an error of a request. It wraps both
	// errTransport and errProxy.
	errProxyRefused = fmt.Errorf("%w: %w", errTransport, errProxy)
	// errCertificate means that the TLS certificate of the server is not
	// trusted.
	errCertificate = fmt.Errorf("%w: TLS certificate not trusted", errTransport)
	// errTooLarge means that the response body is larger than
	// MaxResponseBodyBytes.
	errTooLarge = fmt.Errorf("%w: response body larger than %d bytes", ErrProvider, MaxResponseBodyBytes)
	// errBadResponse means that a 2xx response body is not the JSON
	// envelope of the provider API. It is not about the model output.
	errBadResponse = fmt.Errorf("%w: response is not a valid API response", ErrProvider)
	// errProxy replaces any error of http.ProxyFromEnvironment. The proxy
	// setting can hold a user name and a password.
	errProxy = errors.New("proxy setting from HTTP_PROXY or HTTPS_PROXY refused")
	// errRequestTooLarge means that the request body is larger than
	// MaxRequestBodyBytes. The client does not send it.
	errRequestTooLarge = fmt.Errorf("LLM request body larger than %d bytes", MaxRequestBodyBytes)
	// errBuildRequest means that the request could not be built.
	errBuildRequest = errors.New("cannot build LLM request")
	// errNilClient means that Classify was called on a nil or zero Client.
	errNilClient = errors.New("LLM client not initialized, use llm.New")
	// errNotLoopback means that the host of an http base URL does not
	// resolve to loopback addresses only, so the client does not connect.
	// The text never holds the host or an address.
	errNotLoopback = fmt.Errorf("%w: host does not resolve to a loopback address", errTransport)
)

// StatusError means that the provider answered with a status code that is
// not 2xx. It holds only the code: the response body is never read. A 3xx
// code is an error too, because the client never follows a redirect (the
// API key must not go to another host).
//
// StatusError unwraps to an error for a refused API key for 401 and 403, and
// to ErrProvider for every other code, so errors.Is(err, ErrProvider) is true
// for all of them.
type StatusError struct {
	// Code is the HTTP status code.
	Code int
}

// Error returns a fixed text with the status code. It starts with the text of
// ErrProvider. A 3xx code has the redirect hint. A 401 or 403 code has no
// hint here (Reason adds it). A nil *StatusError gives the text of
// ErrProvider.
func (e *StatusError) Error() string {
	// A typed nil in an error interface must not panic.
	if e == nil {
		return ErrProvider.Error()
	}
	if e.authRefused() {
		return fmt.Sprintf("%s: HTTP %d", ErrProvider.Error(), e.Code)
	}
	return ErrProvider.Error() + ": " + e.reason()
}

// Unwrap returns errAuth for 401 and 403, and ErrProvider for other codes.
// A nil *StatusError unwraps to nil.
func (e *StatusError) Unwrap() error {
	// errors.Is and errors.As call Unwrap on a typed nil too.
	if e == nil {
		return nil
	}
	if e.authRefused() {
		return errAuth
	}
	return ErrProvider
}

// authRefused reports whether the code means that the provider refused the
// API key (401 or 403). It is false for a nil *StatusError.
func (e *StatusError) authRefused() bool {
	// Error, Unwrap and reason can get a typed nil.
	return e != nil && (e.Code == http.StatusUnauthorized || e.Code == http.StatusForbidden)
}

// reason returns "HTTP <code>" with a fixed hint: authHint for 401 and 403,
// and redirectHint for a 3xx code. Other codes have no hint. A nil
// *StatusError gives unknownReason.
func (e *StatusError) reason() string {
	// A typed nil must not panic. Reason checks for it too.
	if e == nil {
		return unknownReason
	}
	text := fmt.Sprintf("HTTP %d", e.Code)
	switch {
	case e.authRefused():
		return text + " (" + authHint + ")"
	case e.Code >= 300 && e.Code < 400:
		return text + " (" + redirectHint + ")"
	default:
		return text
	}
}

// Reason returns the fixed reason text of the provider failure err, without
// the text of ErrProvider at the start. For a *StatusError it is
// "HTTP <code>", with the hint "(the API key was refused)" for 401 and 403
// and "(redirect refused)" for a 3xx code. For another error of Classify that
// wraps ErrProvider, it is the fixed text of that error after the ErrProvider
// text, for example "network error" or "network error: TLS certificate not
// trusted". For any other error (also ErrProvider itself and nil), it is
// "unknown error".
//
// The text never comes from err.Error() of an unknown error, so it never
// holds the key, the URL, a response body or model output.
func Reason(err error) string {
	var status *StatusError
	if errors.As(err, &status) && status != nil {
		return status.reason()
	}
	// The more specific errors come first: errNotLoopback, errTimeout,
	// errProxyRefused and errCertificate wrap errTransport.
	known := []error{
		errNotLoopback,
		errTimeout,
		errProxyRefused,
		errCertificate,
		errTransport,
		errTooLarge,
		errBadResponse,
		errAuth,
	}
	for _, k := range known {
		if errors.Is(err, k) {
			return strings.TrimPrefix(k.Error(), ErrProvider.Error()+": ")
		}
	}
	return unknownReason
}

// api is the part of a request that depends on the provider. anthropic.go
// and openai.go implement it. Each implementation is stateless.
type api interface {
	// path is the API path, which the client adds to the base URL. It
	// starts with "/".
	path() string
	// requestBody returns the request value for model and the user
	// message. The client encodes it as JSON.
	requestBody(model, message string) any
	// setAuth sets the auth header and the other API headers. It is the
	// only place where the key is revealed.
	setAuth(h http.Header, key discover.Secret)
	// parseResponse reads a 2xx response body. Its errors wrap
	// ErrInvalidOutput or errBadResponse and have fixed text.
	parseResponse(body []byte) (Verdict, error)
}

// chatMessage is one message of a request, for both providers.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// DialFunc opens a network connection, as net.Dialer.DialContext does.
//
// DialFunc is the type of Config.Dial, which is a TEST HOOK: production code
// must not set it. A DialFunc must connect to the address that it is given
// and to no other address: the client gives it an address that it has
// checked (for an http base URL, a loopback address from loopbackDial).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// resolver looks up the IP addresses of a host name. *net.Resolver
// implements it. Tests use a fake.
type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Client rates tool descriptions with an LLM provider. Make one with New.
// A Client is safe for concurrent use: Classify does not change it.
//
// The client sends requests only to the configured base URL. It never
// follows a redirect, never retries, and logs nothing.
type Client struct {
	api   api
	url   string
	model string
	key   discover.Secret
	http  *http.Client
}

// New returns a Client for cfg. It calls cfg.Resolve, so the errors of
// Resolve (ErrUnknownProvider, ErrMissingKey, ErrInvalidKey,
// ErrInvalidBaseURL, ErrInvalidModel) come back as they are. New sends no
// request.
//
// The client uses its own http.Transport, never http.DefaultTransport. It
// uses TLS 1.2 or later and dials with cfg.Dial when it is not nil. For an
// https base URL, it honours HTTPS_PROXY and NO_PROXY. An http base URL is
// always a loopback host (see ValidateBaseURL): the client never sends it
// through a proxy, and connects only when the host resolves to loopback
// addresses only (see loopbackDial).
func New(cfg Config) (*Client, error) {
	return newClient(cfg, net.DefaultResolver)
}

// newClient is New with the resolver that an http base URL uses. Tests give
// a fake resolver.
func newClient(cfg Config, r resolver) (*Client, error) {
	cfg, err := cfg.Resolve()
	if err != nil {
		return nil, err
	}
	var a api
	switch cfg.Provider {
	case ProviderAnthropic:
		a = anthropicAPI{}
	case ProviderOpenAI:
		a = openAIAPI{}
	default:
		// Resolve refuses an unknown provider, so this is a guard only.
		return nil, unknownProviderError()
	}
	endpoint := cfg.BaseURL + a.path()
	// ValidateBaseURL parsed the base URL, and the path is fixed, so this
	// cannot fail. The error is fixed text: a url.Parse error quotes the URL.
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errBuildRequest
	}
	dial := cfg.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: dialTimeout, KeepAlive: dialKeepAlive}).DialContext
	}
	proxy := proxyFromEnvironment
	// url.Parse gives the scheme in lower case. https needs no loopback
	// check: TLS protects the key on any network.
	if u.Scheme == "http" {
		dial = loopbackDial(dial, r, loopbackAddrTimeout)
		// Never use a proxy for http. The key is in clear text, so it must
		// go only to the loopback server, never to a proxy.
		proxy = nil
	}
	return &Client{
		api:   a,
		url:   endpoint,
		model: cfg.Model,
		key:   cfg.APIKey,
		http:  newHTTPClient(dial, proxy),
	}, nil
}

// loopbackDial returns a dial function for an http base URL. Over http the
// API key crosses the connection in clear text, so ValidateBaseURL allows
// http only for a loopback host. But the name "localhost" is loopback only
// by its text: the system resolver can map it to any address, for example
// when /etc/hosts has no entry for it.
//
// So the returned function resolves the host (an IP literal is used as it
// is), requires that every address is a loopback address, and dials only
// those addresses, in order, with dial. Otherwise it returns errNotLoopback
// and opens no connection. The transport of an http base URL has no proxy
// (see newClient), so addr is always the host of the base URL.
//
// Each address except the last one gets at most addrTimeout. So when one
// address does not answer (for example a firewall drops packets to ::1), the
// next address is tried soon. The last address gets the time that is left.
func loopbackDial(dial DialFunc, r resolver, addrTimeout time.Duration) DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, errNotLoopback
		}
		ips, err := resolveLoopback(ctx, r, network, host)
		if err != nil {
			return nil, err
		}
		var dialErr error
		for i, ip := range ips {
			target := net.JoinHostPort(ip.String(), port)
			var conn net.Conn
			if i < len(ips)-1 {
				conn, err = dialWithTimeout(ctx, dial, network, target, addrTimeout)
			} else {
				conn, err = dial(ctx, network, target)
			}
			if err == nil {
				return conn, nil
			}
			dialErr = err
			// The caller gave up, so do not try the next address.
			if ctx.Err() != nil {
				break
			}
		}
		return nil, dialErr
	}
}

// dialWithTimeout calls dial with a context that ends after timeout. The end
// of that context does not close a connection that dial already opened.
func dialWithTimeout(ctx context.Context, dial DialFunc, network, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return dial(ctx, network, addr)
}

// resolveLoopback returns the addresses of host. It returns errNotLoopback
// when the lookup fails, gives no address, or gives one address that is not
// a loopback address. The lookup error is not wrapped: it holds the host.
func resolveLoopback(ctx context.Context, r resolver, network, host string) ([]netip.Addr, error) {
	var found []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		found = []netip.Addr{ip}
	} else {
		found, err = r.LookupNetIP(ctx, lookupNetwork(network), host)
		if err != nil {
			return nil, errNotLoopback
		}
	}
	if len(found) == 0 {
		return nil, errNotLoopback
	}
	ips := make([]netip.Addr, 0, len(found))
	for _, ip := range found {
		// Unmap turns ::ffff:127.0.0.1 into 127.0.0.1, so that IsLoopback
		// sees the IPv4 address.
		ip = ip.Unmap()
		if !ip.IsLoopback() {
			return nil, errNotLoopback
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// lookupNetwork returns the network name of LookupNetIP for a dial network.
func lookupNetwork(network string) string {
	switch network {
	case "tcp4":
		return "ip4"
	case "tcp6":
		return "ip6"
	default:
		return "ip"
	}
}

// newHTTPClient returns the HTTP client of a Client. Every connection uses
// dial. proxy picks the proxy of a request; nil means no proxy.
func newHTTPClient(dial DialFunc, proxy func(*http.Request) (*url.URL, error)) *http.Client {
	transport := &http.Transport{
		// For https, proxyFromEnvironment honours the user's HTTPS_PROXY and
		// NO_PROXY (NFR-01). For http, proxy is nil.
		Proxy:               proxy,
		DialContext:         dial,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: tlsHandshakeTimeout,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        MaxConcurrentRequests,
		MaxIdleConnsPerHost: MaxConcurrentRequests,
		IdleConnTimeout:     idleConnTimeout,
		// No gzip: the response is small, and so the body cap counts the
		// bytes on the wire.
		DisableCompression: true,
		// ResponseHeaderTimeout, http.Client.Timeout below and the context
		// deadline in send all use requestTimeout on purpose (see send).
		ResponseHeaderTimeout:  requestTimeout,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
	}
	return &http.Client{
		Transport: transport,
		// Never follow a redirect: the next request would carry the API key
		// to the new location. Classify turns the 3xx response into a
		// *StatusError.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// The same limit as the context deadline in send, on purpose: this
		// one also bounds the read of the response body.
		Timeout: requestTimeout,
	}
}

// proxyFromEnvironment is http.ProxyFromEnvironment with a fixed error text,
// the same as in internal/inspect.
func proxyFromEnvironment(req *http.Request) (*url.URL, error) {
	proxy, err := http.ProxyFromEnvironment(req)
	if err != nil {
		return nil, errProxy
	}
	return proxy, nil
}

// Classify sends one request that asks the model to rate in, and returns the
// verdict. It sends only the system prompt, the verdict schema and the tool
// message of in (see the package doc). It does not retry.
//
// The request has a timeout of requestTimeout. The verdict has Truncated
// set when toolMessage cut the tool name or description. On an error, only
// Truncated is set, and only when toolMessage succeeded: the caller can then
// still rate a cut tool when the answer is not usable (ErrInvalidOutput).
// Risk and Category stay zero on an error. See the error variables above for
// how to sort an error. Classify is safe for concurrent use.
func (c *Client) Classify(ctx context.Context, in Input) (Verdict, error) {
	if c == nil || c.api == nil || c.http == nil {
		return Verdict{}, errNilClient
	}
	if err := ctx.Err(); err != nil {
		return Verdict{}, stopped(err)
	}
	message, truncated, err := toolMessage(in)
	if err != nil {
		return Verdict{}, err
	}
	v, err := c.send(ctx, message)
	if err != nil {
		return Verdict{Truncated: truncated}, err
	}
	v.Truncated = truncated
	return v, nil
}

// send sends one request with the tool message message and returns the
// verdict of the model, without Truncated. Every error has fixed text (see
// Classify).
func (c *Client) send(ctx context.Context, message string) (Verdict, error) {
	body, err := encodeJSON(c.api.requestBody(c.model, message))
	if err != nil {
		return Verdict{}, err
	}
	if len(body) > MaxRequestBodyBytes {
		return Verdict{}, errRequestTooLarge
	}

	// The deadline is requestTimeout, the same as http.Client.Timeout and
	// ResponseHeaderTimeout (see newHTTPClient), on purpose: with the deadline
	// in reqCtx, transportError can see that the request timed out and give
	// the fixed timeout text.
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return Verdict{}, errBuildRequest
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.api.setAuth(req.Header, c.key)

	resp, err := c.http.Do(req)
	if err != nil {
		return Verdict{}, transportError(ctx, reqCtx, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The body is never read: it can echo the request or hold text
		// that must not reach the terminal.
		return Verdict{}, &StatusError{Code: resp.StatusCode}
	}
	if resp.ContentLength > MaxResponseBodyBytes {
		return Verdict{}, errTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes+1))
	if err != nil {
		return Verdict{}, transportError(ctx, reqCtx, err)
	}
	if len(data) > MaxResponseBodyBytes {
		return Verdict{}, errTooLarge
	}
	return c.api.parseResponse(data)
}

// CloseIdleConnections closes the idle connections of the client. Call it
// when the scan no longer needs the client.
func (c *Client) CloseIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

// transportError turns an error of Do or of the body read into an error with
// fixed text. When the context of the caller (parent) is done, it returns
// that context error, so the caller can tell a signal from a provider
// failure. Otherwise it returns an error that wraps errTransport. It never
// wraps err, because a *url.Error holds the URL.
func transportError(parent, reqCtx context.Context, err error) error {
	if perr := parent.Err(); perr != nil {
		return stopped(perr)
	}
	var (
		urlErr  *url.Error
		certErr *tls.CertificateVerificationError
	)
	switch {
	case errors.Is(err, errProxy):
		return errProxyRefused
	case errors.Is(reqCtx.Err(), context.DeadlineExceeded),
		errors.As(err, &urlErr) && urlErr.Timeout():
		return errTimeout
	case errors.Is(err, errNotLoopback):
		return errNotLoopback
	case errors.As(err, &certErr):
		return errCertificate
	default:
		return errTransport
	}
}

// stopped wraps the context error of the caller.
func stopped(err error) error {
	return fmt.Errorf("LLM request stopped: %w", err)
}

// encodeJSON encodes v without HTML escapes and without the final newline.
// With HTML escapes, each '<' of the tool text would grow to six bytes, and
// the body could pass MaxRequestBodyBytes. The error has fixed text.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, errBuildRequest
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// errorEnvelope is the top-level "error" key that both providers use for an
// error body.
type errorEnvelope struct {
	Error json.RawMessage `json:"error"`
}

// decodeEnvelope decodes a 2xx response body into v, the envelope struct of
// a provider. A body that is not one JSON object gives errBadResponse. The
// check comes first because json.Unmarshal accepts the literal null for a
// struct and leaves it unchanged, so a null body would look like an empty
// envelope. A body with a top-level "error" key that is not null gives
// errBadResponse too: it is an error from the API, sent with a 2xx status,
// not an answer of the model. The error is fixed text: the decoder error can
// quote the body.
func decodeEnvelope(body []byte, v any) error {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errBadResponse
	}
	if err := json.Unmarshal(body, v); err != nil {
		return errBadResponse
	}
	var e errorEnvelope
	if err := json.Unmarshal(body, &e); err != nil {
		return errBadResponse
	}
	if !jsonNull(e.Error) {
		return errBadResponse
	}
	return nil
}

// jsonNull reports whether raw is a missing field (empty) or the JSON
// literal null, with white space around it or not.
func jsonNull(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) == 0 || string(raw) == "null"
}
