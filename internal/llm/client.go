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
	"net/url"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Timeouts and pool size of the client transport.
const (
	// requestTimeout bounds one whole request: connect, send and read.
	requestTimeout      = 30 * time.Second
	dialTimeout         = 10 * time.Second
	dialKeepAlive       = 30 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
	idleConnTimeout     = 30 * time.Second
	// maxIdleConns lets the four scan workers keep one connection each.
	maxIdleConns = 4
	// maxResponseHeaderBytes caps the response headers.
	maxResponseHeaderBytes = 64 << 10
)

// Errors of Classify. All of them have fixed text: no error from this file
// holds the API key, the URL, a header, a response body or model output, so
// the caller can print err.Error() as it is.
//
// Use errors.Is to sort an error of Classify:
//
//   - ErrInvalidOutput: the provider answered, but the model refused or its
//     output is not a valid verdict. The caller reports RuleIDInvalid.
//   - ErrProvider: the request failed (ErrAuth, ErrTransport, ErrTooLarge,
//     ErrBadResponse or a *StatusError). The caller reports a scan error.
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
	// ErrAuth means that the provider refused the API key (HTTP 401 or
	// 403). The error is also a *StatusError with the code.
	ErrAuth = fmt.Errorf("%w: the API key was refused", ErrProvider)
	// ErrTransport means a network, TLS, proxy or timeout error. The error
	// never wraps the net/http error, because that text holds the URL.
	ErrTransport = fmt.Errorf("%w: network error", ErrProvider)
	// ErrTooLarge means that the response body is larger than
	// MaxResponseBodyBytes.
	ErrTooLarge = fmt.Errorf("%w: response body larger than %d bytes", ErrProvider, MaxResponseBodyBytes)
	// ErrBadResponse means that a 2xx response body is not the JSON
	// envelope of the provider API. It is not about the model output.
	ErrBadResponse = fmt.Errorf("%w: response is not a valid API response", ErrProvider)
)

// Unexported errors. They have fixed text too.
var (
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
)

// StatusError means that the provider answered with a status code that is
// not 2xx. It holds only the code: the response body is never read. A 3xx
// code is an error too, because the client never follows a redirect (the
// API key must not go to another host).
//
// StatusError unwraps to ErrAuth for 401 and 403, and to ErrProvider for
// every other code, so errors.Is(err, ErrProvider) is true for all of them.
type StatusError struct {
	// Code is the HTTP status code.
	Code int
}

// Error returns a fixed text with the status code.
func (e *StatusError) Error() string {
	if e.Code >= 300 && e.Code < 400 {
		return fmt.Sprintf("LLM provider request failed: HTTP %d (redirect refused)", e.Code)
	}
	return fmt.Sprintf("LLM provider request failed: HTTP %d", e.Code)
}

// Unwrap returns ErrAuth for 401 and 403, and ErrProvider for other codes.
func (e *StatusError) Unwrap() error {
	if e.Code == http.StatusUnauthorized || e.Code == http.StatusForbidden {
		return ErrAuth
	}
	return ErrProvider
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
	// ErrInvalidOutput or ErrBadResponse and have fixed text.
	parseResponse(body []byte) (Verdict, error)
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
// honours HTTP_PROXY, HTTPS_PROXY and NO_PROXY, uses TLS 1.2 or later, and
// dials with cfg.Dial when it is not nil.
func New(cfg Config) (*Client, error) {
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
		return nil, fmt.Errorf("%w: use %q or %q", ErrUnknownProvider, ProviderAnthropic, ProviderOpenAI)
	}
	endpoint := cfg.BaseURL + a.path()
	// ValidateBaseURL parsed the base URL, and the path is fixed, so this
	// cannot fail. The error is fixed text: a url.Parse error quotes the URL.
	if _, err := url.Parse(endpoint); err != nil {
		return nil, errBuildRequest
	}
	return &Client{
		api:   a,
		url:   endpoint,
		model: cfg.Model,
		key:   cfg.APIKey,
		http:  newHTTPClient(cfg.Dial),
	}, nil
}

// newHTTPClient returns the HTTP client of a Client. dial can be nil.
func newHTTPClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	if dial == nil {
		dial = (&net.Dialer{Timeout: dialTimeout, KeepAlive: dialKeepAlive}).DialContext
	}
	transport := &http.Transport{
		// Honour the user's HTTP_PROXY, HTTPS_PROXY and NO_PROXY (NFR-01).
		Proxy:               proxyFromEnvironment,
		DialContext:         dial,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: tlsHandshakeTimeout,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConns,
		IdleConnTimeout:     idleConnTimeout,
		// No gzip: the response is small, and so the body cap counts the
		// bytes on the wire.
		DisableCompression:     true,
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
// The request has a timeout of 30 seconds. See the error variables above
// for how to sort an error. Classify is safe for concurrent use.
func (c *Client) Classify(ctx context.Context, in Input) (Verdict, error) {
	if c == nil || c.api == nil || c.http == nil {
		return Verdict{}, errNilClient
	}
	if err := ctx.Err(); err != nil {
		return Verdict{}, stopped(err)
	}
	message, err := toolMessage(in)
	if err != nil {
		return Verdict{}, err
	}
	body, err := encodeJSON(c.api.requestBody(c.model, message))
	if err != nil {
		return Verdict{}, err
	}
	if len(body) > MaxRequestBodyBytes {
		return Verdict{}, errRequestTooLarge
	}

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
		return Verdict{}, ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes+1))
	if err != nil {
		return Verdict{}, transportError(ctx, reqCtx, err)
	}
	if len(data) > MaxResponseBodyBytes {
		return Verdict{}, ErrTooLarge
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
// failure. Otherwise it returns an error that wraps ErrTransport. It never
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
		return fmt.Errorf("%w: %w", ErrTransport, errProxy)
	case errors.Is(reqCtx.Err(), context.DeadlineExceeded),
		errors.As(err, &urlErr) && urlErr.Timeout():
		return fmt.Errorf("%w: timed out after %s", ErrTransport, requestTimeout)
	case errors.As(err, &certErr):
		return fmt.Errorf("%w: TLS certificate not trusted", ErrTransport)
	default:
		return ErrTransport
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

// decodeEnvelope decodes a 2xx response body into v, the envelope struct of
// a provider. A body that is not one JSON object gives ErrBadResponse. The
// check comes first because json.Unmarshal accepts the literal null for a
// struct and leaves it unchanged, so a null body would look like an empty
// envelope. The error is fixed text: the decoder error can quote the body.
func decodeEnvelope(body []byte, v any) error {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ErrBadResponse
	}
	if err := json.Unmarshal(body, v); err != nil {
		return ErrBadResponse
	}
	return nil
}
