package inspect

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Limits of the HTTP client.
const (
	// defaultMaxResponseBytes is the size cap for one HTTP response body, in
	// bytes (8 MiB). newHTTPClient uses it when MaxBody is not positive.
	defaultMaxResponseBytes int64 = 8 << 20

	// defaultMaxTotalBytes is the size cap for all response bodies of one
	// client together, in bytes (64 MiB). The per-body cap alone would let a
	// server send many bodies of 8 MiB. newHTTPClient uses it when MaxTotal
	// is not positive.
	defaultMaxTotalBytes int64 = 64 << 20

	// maxResponseHeaderBytes is the limit for the response headers of one
	// response, in bytes (64 KiB). The default of net/http is 1 MiB.
	maxResponseHeaderBytes = 64 << 10

	// maxRedirects is the number of redirects that the client follows. It
	// refuses the next one.
	maxRedirects = 3
)

// Timeouts and pool size of the base transport (newBaseTransport). None of
// them bounds a whole request: the context of the request does that.
const (
	dialTimeout         = 10 * time.Second
	dialKeepAlive       = 30 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
	idleConnTimeout     = 30 * time.Second
	maxIdleConns        = 4
)

// Sentinel errors of the HTTP layer. The round tripper, the redirect check and
// the body cap return them, and classify recognises them with errors.Is. Their
// texts hold no URL and no header value.
var (
	// errReservedHeader means the config sets a header that mcpmoat controls,
	// or a header with an empty or invalid name. The text that wraps it holds
	// the header name (a key) and never a header value.
	errReservedHeader = errors.New("header name not allowed")
	// errInvalidHeaderValue means a config header value has a control
	// character, which net/http refuses to send. The text that wraps it holds
	// the header name only.
	errInvalidHeaderValue = errors.New("header value not allowed: control character")
	// errInvalidProxy replaces any error of http.ProxyFromEnvironment with
	// fixed text (see proxyFromEnvironment).
	errInvalidProxy = errors.New("proxy setting from HTTP_PROXY or HTTPS_PROXY refused")
	// errOtherOrigin means a request went to an origin other than the
	// configured one.
	errOtherOrigin = errors.New("request to another origin refused")
	// errCrossOriginRedirect means the server redirected to another origin.
	errCrossOriginRedirect = errors.New("redirect to another origin refused")
	// errTooManyRedirects means the server redirected too many times.
	errTooManyRedirects = errors.New("too many redirects")
	// errBodyTooLarge means a response body is larger than the size cap.
	errBodyTooLarge = errors.New("response body too large")
)

// requestRecorder records what happened on the HTTP layer, because the MCP SDK
// drops it: the status code of the last response, and the error that this
// layer raised on purpose (a refused origin, a refused redirect or a body that
// is too large). classify reads both through the transportEvents interface.
//
// It is safe for concurrent use: the SDK can send requests from more than one
// goroutine.
type requestRecorder struct {
	// status is the status of the most recent request: the code of a non-2xx
	// response that was not a followed redirect, and 0 after a 2xx response or
	// after a request that got no response. An atomic value needs no mutex.
	//
	// It keeps the latest value and not the first one. The SDK can start with a
	// request that gets a 404 and then fall back to another request that works.
	// The 404 must not give a wrong label to a later, unrelated error.
	//
	// One value serves all requests of the client. If two requests run at the
	// same time, the label of an error can come from the other request. Today
	// the requests of one inspection run one after the other, apart from small
	// notifications; per-request status is tracked in issue #99. Only the label
	// can be wrong: the inspection still fails.
	status atomic.Int64

	// sessionUp is true after the server answered the MCP handshake
	// (markHandshake) or Remote connected the session (markConnected).
	sessionUp atomic.Bool

	// mu guards blocked.
	mu sync.Mutex
	// blocked is the first error that the HTTP layer raised on purpose since
	// the start or since the last forgetBlocked call, or nil.
	blocked error
}

// Compile-time check: *requestRecorder must implement transportEvents. The
// blank identifier _ throws the value away, so this line costs nothing at run
// time, but the build fails if the method set ever drifts.
var _ transportEvents = (*requestRecorder)(nil)

// lastStatus implements transportEvents.
func (r *requestRecorder) lastStatus() int {
	return int(r.status.Load())
}

// blockedErr implements transportEvents.
func (r *requestRecorder) blockedErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.blocked
}

// connected implements transportEvents.
func (r *requestRecorder) connected() bool {
	return r.sessionUp.Load()
}

// markHandshake records that the server answered initialize or
// server/discover, so it speaks the configured transport.
func (r *requestRecorder) markHandshake() {
	r.sessionUp.Store(true)
}

// markConnected records that the session is up. Remote calls it after a
// successful connect. It also calls forgetBlocked.
func (r *requestRecorder) markConnected() {
	r.markHandshake()
	r.forgetBlocked()
}

// forgetBlocked drops the stored blocked error. markConnected calls it: the
// SDK recovered from any request that was blocked before (for example, it
// falls back from server/discover to initialize after any error), so that
// error must not label a later, unrelated failure.
//
// A legacy SSE stream is read by a background goroutine. If it goes over the
// size cap in the short time between the last connect request and this call,
// the too-large error is dropped too, and the later error is labelled as a
// protocol error. The inspection still fails. Issue #99 tracks a per-request
// record that would close this window.
func (r *requestRecorder) forgetBlocked() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blocked = nil
}

// recordResponse stores the status of resp. A 2xx response stores 0, so it
// clears an earlier failure. A followed redirect changes nothing: it is not a
// final answer.
func (r *requestRecorder) recordResponse(resp *http.Response) {
	if isFollowedRedirect(resp) {
		return
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		r.status.Store(0)
		return
	}
	r.status.Store(int64(resp.StatusCode))
}

// recordNoResponse records a request that got no response (a transport error).
// It clears the status, so that an older non-2xx status cannot outrank this
// error.
func (r *requestRecorder) recordNoResponse() {
	r.status.Store(0)
}

// recordBlocked stores err if no blocked error was stored before. The first
// one wins, because a later error is often a result of the first one. It
// returns err, so a caller can write: return nil, rec.recordBlocked(err).
func (r *requestRecorder) recordBlocked(err error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blocked == nil {
		r.blocked = err
	}
	return err
}

// httpClientConfig is the input of newHTTPClient.
type httpClientConfig struct {
	// Endpoint is the configured endpoint URL, without user info. The client
	// sends requests only to its origin (scheme, host and port). It must not
	// be nil.
	Endpoint *url.URL
	// User is the user info from the configured URL, or nil. Endpoint has no
	// user info, so that no error text from the SDK can hold it; the client sends it
	// as a Basic Authorization header instead.
	User *url.Userinfo
	// Headers are the headers from the config, with raw values.
	Headers map[string]string
	// Base does the network I/O. A nil Base gives newBaseTransport(). Tests
	// pass their own.
	Base http.RoundTripper
	// UserAgent is the User-Agent, unless Headers sets one. Empty means the
	// net/http default ("Go-http-client/1.1" or "Go-http-client/2.0").
	UserAgent string
	// MaxBody is the size cap of one response body. A value that is not
	// positive gives defaultMaxResponseBytes.
	MaxBody int64
	// MaxTotal is the size cap of all response bodies of the client together.
	// A value that is not positive gives defaultMaxTotalBytes.
	MaxTotal int64
}

// newHTTPClient builds an HTTP client for the remote server at cfg.Endpoint.
//
// The client sends the config headers only to the origin. A request to another
// origin fails with errOtherOrigin before anything goes on the network, and a
// redirect to another origin fails with errCrossOriginRedirect. The client
// caps each response body at cfg.MaxBody bytes and all bodies together at
// cfg.MaxTotal bytes, and returns errBodyTooLarge beyond either cap.
//
// The returned requestRecorder holds the last failure status and the first
// error that the client raised on purpose (see requestRecorder).
//
// The error is for a config that mcpmoat cannot use. It wraps
// errReservedHeader or errInvalidHeaderValue and holds at most a header key,
// never a value, or it reports a nil Endpoint.
//
// The client has no Client.Timeout: that timeout also cuts the body read, so
// it would end a long SSE stream. The context of each request bounds the time.
func newHTTPClient(cfg httpClientConfig) (*http.Client, *requestRecorder, error) {
	endpoint := cfg.Endpoint
	if endpoint == nil {
		return nil, nil, errors.New("no endpoint for the HTTP client")
	}
	header, err := buildHeader(cfg.Headers, cfg.UserAgent)
	if err != nil {
		return nil, nil, err
	}
	base := cfg.Base
	if base == nil {
		base = newBaseTransport()
	}
	maxBody := cfg.MaxBody
	if maxBody <= 0 {
		maxBody = defaultMaxResponseBytes
	}
	maxTotal := cfg.MaxTotal
	if maxTotal <= 0 {
		maxTotal = defaultMaxTotalBytes
	}
	// cappedBody.Read computes remaining+1, which overflows at math.MaxInt64 and
	// would panic on a negative slice bound. Keep the caps below that value.
	// One body can never use more than the total budget, so clamp it too.
	if maxTotal > math.MaxInt64-1 {
		maxTotal = math.MaxInt64 - 1
	}
	if maxBody > maxTotal {
		maxBody = maxTotal
	}

	rec := &requestRecorder{}
	client := &http.Client{
		Transport: &headerTransport{
			endpoint: endpoint,
			user:     cfg.User,
			header:   header,
			base:     base,
			rec:      rec,
			maxBody:  maxBody,
			maxTotal: maxTotal,
		},
		// The client calls CheckRedirect before it follows a redirect. via
		// holds the requests made so far, oldest first, so len(via) is 1 on
		// the first redirect, so at most maxRedirects redirects are followed.
		// The headerTransport adds the config headers to every request it
		// gets, redirected ones too, so without the origin check a redirect
		// would send the secrets to another host.
		// The error is also stored in rec, because the SDK may hide it.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return rec.recordBlocked(errTooManyRedirects)
			}
			if !sameOrigin(req.URL, endpoint) {
				return rec.recordBlocked(errCrossOriginRedirect)
			}
			return nil
		},
	}
	return client, rec, nil
}

// newBaseTransport returns a new transport for the real network. It does not
// use http.DefaultTransport, so no other code can change its settings.
func newBaseTransport() *http.Transport {
	return &http.Transport{
		// Honour the user's HTTP_PROXY, HTTPS_PROXY and NO_PROXY variables. The
		// proxy is user-configured, and Go never uses it for localhost.
		Proxy: proxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: dialKeepAlive,
		}).DialContext,
		TLSHandshakeTimeout: tlsHandshakeTimeout,
		// No ResponseHeaderTimeout: an SSE server can wait a long time before
		// it sends the first byte.
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
		MaxIdleConns:      maxIdleConns,
		IdleConnTimeout:   idleConnTimeout,
		// Limit the size of the response headers. A server must not make
		// mcpmoat read a huge header block.
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
	}
}

// proxyFromEnvironment is http.ProxyFromEnvironment with a fixed error text.
// The proxy setting can hold a user name and a password, and classify does not
// know that secret, so no error text from the proxy code may reach a report.
// With Go 1.27 the only error is the refusal of HTTP_PROXY in a CGI
// environment, and a setting that does not parse is ignored. Older x/net code
// quoted the whole setting in its error, and that can come back.
func proxyFromEnvironment(req *http.Request) (*url.URL, error) {
	proxy, err := http.ProxyFromEnvironment(req)
	if err != nil {
		return nil, errInvalidProxy
	}
	return proxy, nil
}

// buildHeader checks the config headers and returns them as an http.Header
// with canonical keys, plus a User-Agent (ua) if the config has none and ua is
// not empty. It returns an error that wraps errReservedHeader if a key is
// empty or reserved.
//
// It sets the keys in sorted order, so two keys that differ only in case
// (x-key and X-Key) always give the same result: the last one wins.
func buildHeader(headers map[string]string, ua string) (http.Header, error) {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	header := make(http.Header, len(headers)+1)
	for _, key := range keys {
		if key == "" {
			return nil, fmt.Errorf("%w: empty", errReservedHeader)
		}
		if !isHTTPToken(key) {
			// The key is not printed: a key that holds a pasted header line
			// ("Authorization: Bearer <token>") would show the token.
			return nil, fmt.Errorf("%w: a key is not a valid HTTP token (the key is not shown, it may hold a value)", errReservedHeader)
		}
		canonical := http.CanonicalHeaderKey(key)
		if isReservedHeader(canonical) {
			return nil, fmt.Errorf("%w: %q", errReservedHeader, key)
		}
		if !validHeaderValue(headers[key]) {
			return nil, fmt.Errorf("%w: %q", errInvalidHeaderValue, key)
		}
		header.Set(canonical, headers[key])
	}
	if _, ok := header["User-Agent"]; !ok && ua != "" {
		if !validHeaderValue(ua) {
			return nil, fmt.Errorf("%w: %q", errInvalidHeaderValue, "User-Agent")
		}
		header.Set("User-Agent", ua)
	}
	return header, nil
}

// isHTTPToken reports whether s is an HTTP token (RFC 9110, section 5.6.2),
// as net/http requires for a header name. An auth scheme is a token too.
func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}

// validHeaderValue reports whether value has no control character other than
// a horizontal tab, as net/http requires for a header value.
func validHeaderValue(value string) bool {
	for i := range len(value) {
		if c := value[i]; c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

// sendsBasicAuth reports whether a request with header, the built config
// headers, gets a Basic Authorization header from user, the URL user info. A
// non-empty Authorization header from the config wins; an empty one counts as
// absent, as in net/http. RoundTrip and sentHeaderNames both use it.
func sendsBasicAuth(header http.Header, user *url.Userinfo) bool {
	return user != nil && header.Get("Authorization") == ""
}

// isReservedHeader reports whether name, in canonical form, is a header that
// the MCP transport or net/http controls. A config must not set these.
//
//   - Accept-Encoding: if the caller sets it, net/http stops to decompress the
//     body by itself, so the size cap would count compressed bytes and a small
//     compressed body could grow without limit later.
//
//   - Upgrade, Expect, Te and Trailer change how the connection or the body
//     works; Connection and Transfer-Encoding do the same.
//
//   - Every name with the prefix "Mcp-": the MCP SDK owns the protocol headers.
//
//   - Proxy-Authorization: over HTTPS through a CONNECT proxy, a request header
//     goes to the origin and not to the proxy, so a proxy credential would leak
//     to the server. Header values go only to the configured server. Proxy
//     credentials belong in the proxy URL (HTTPS_PROXY).
func isReservedHeader(name string) bool {
	if strings.HasPrefix(name, "Mcp-") {
		return true
	}
	switch name {
	case "Content-Type", "Content-Length", "Accept", "Host", "Last-Event-Id",
		"Connection", "Transfer-Encoding", "Accept-Encoding", "Upgrade",
		"Expect", "Te", "Trailer", "Proxy-Authorization":
		return true
	}
	return false
}

// headerTransport is an http.RoundTripper that adds the config headers to each
// request, but only for requests to the configured origin. It also records the
// status of each response and caps the size of the response bodies.
type headerTransport struct {
	// endpoint is the configured endpoint URL. Only its origin gets requests.
	endpoint *url.URL
	// user is the user info of the configured URL, or nil.
	user *url.Userinfo
	// header holds the config headers and the User-Agent, in canonical form.
	header http.Header
	// base does the network I/O.
	base http.RoundTripper
	// rec records statuses and the errors raised on purpose.
	rec *requestRecorder
	// maxBody is the size cap of one response body, in bytes. It is positive.
	maxBody int64
	// maxTotal is the size cap of all bodies together, in bytes. It is positive.
	maxTotal int64
	// used is the number of body bytes handed out so far, over all bodies. The
	// bodies can be read from different goroutines, so it is atomic.
	used atomic.Int64
}

// RoundTrip sends req to base with the config headers added. It refuses a
// request to another origin and sends nothing in that case.
func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !sameOrigin(req.URL, t.endpoint) {
		// The RoundTripper contract says that RoundTrip closes the request
		// body, also when it returns an error.
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, t.rec.recordBlocked(errOtherOrigin)
	}

	// A RoundTripper must not change the request that the caller gave it: the
	// caller can still use or retry that request, and its Header map is shared.
	// Clone makes a copy with its own Header map, so the header changes below touch
	// only the copy.
	out := req.Clone(req.Context())
	if out.Header == nil {
		// http.Client always sets a Header, but a direct caller may not.
		out.Header = make(http.Header, len(t.header))
	}
	for key, values := range t.header {
		out.Header[key] = slices.Clone(values)
	}
	// The configured URL had user info, and newHTTPClient got it separately so
	// that the SDK never sees it. net/http would turn URL user info into a Basic
	// header, so do the same here. A non-empty Authorization header from the
	// config wins: the user chose it on purpose, and one request must not
	// carry two (see sendsBasicAuth).
	if sendsBasicAuth(out.Header, t.user) {
		password, _ := t.user.Password()
		out.SetBasicAuth(t.user.Username(), password)
	}

	// The SDK sends DELETE only to close the session, and it ignores the
	// answer. It closes the session after a failed initialize too, and a
	// server that never kept the session answers 404. The outcome of that
	// DELETE must not change the label of the error that made the SDK close.
	record := out.Method != http.MethodDelete

	resp, err := t.base.RoundTrip(out)
	if err != nil {
		// No response came back. Clear an older status, so that it cannot
		// outrank this transport error in classify.
		if record {
			t.rec.recordNoResponse()
		}
		// Return the error as is. classify unwraps the *url.Error that the
		// http.Client adds.
		return nil, err
	}

	if record {
		t.rec.recordResponse(resp)
	}
	if resp.Body != nil {
		resp.Body = &cappedBody{
			r:         resp.Body,
			remaining: t.maxBody,
			used:      &t.used,
			maxTotal:  t.maxTotal,
			rec:       t.rec,
		}
	}
	return resp, nil
}

// CloseIdleConnections closes the idle connections of the base transport.
// http.Client.CloseIdleConnections calls it only when the transport of the
// client has this method, so without it the idle connections would stay open
// until the idle timeout.
func (t *headerTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// isFollowedRedirect reports whether the http.Client will follow resp: a
// redirect status with a Location header that parses. Such a response is not
// a failure, so the recorder ignores it. If the redirect is refused, the
// error from CheckRedirect tells why. For a Location that does not parse, the
// http.Client returns an error instead of following it, so the recorder keeps
// the redirect status as the label of that error.
func isFollowedRedirect(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		// Location resolves the header against resp.Request.URL, as the
		// http.Client does. An empty header gives http.ErrNoLocation.
		_, err := resp.Location()
		return err == nil
	}
	return false
}

// sameOrigin reports whether u and origin have the same scheme, host name and
// port. Scheme and host name compare without case. A missing port is the
// default port of the scheme (80 for http, 443 for https). A nil URL is never
// the same origin.
func sameOrigin(u, origin *url.URL) bool {
	if u == nil || origin == nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != strings.ToLower(origin.Scheme) {
		return false
	}
	if !equalFoldASCII(u.Hostname(), origin.Hostname()) {
		return false
	}
	return portOrDefault(u, scheme) == portOrDefault(origin, scheme)
}

// equalFoldASCII reports whether a and b are equal when ASCII letters are
// compared without case. Other bytes must match exactly. strings.EqualFold
// folds Unicode too, and IDNA keeps some of those letters apart, so two
// different host names could compare equal.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

// lowerASCII returns c in lower case if it is an ASCII letter.
func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// portOrDefault returns the port of u, or the default port of scheme if u has
// none. A scheme without a default port gives an empty string.
func portOrDefault(u *url.URL, scheme string) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// cappedBody wraps a response body and returns errBodyTooLarge when the body
// has more than the allowed number of bytes, or when all bodies of the client
// together have more than the total budget.
type cappedBody struct {
	// r is the wrapped body.
	r io.ReadCloser
	// remaining is the number of bytes that Read may still return for this body.
	remaining int64
	// used counts the bytes handed out by all bodies of the client. It is shared
	// with the other bodies.
	used *atomic.Int64
	// maxTotal is the budget for used, in bytes.
	maxTotal int64
	// rec stores the error that Read returns.
	rec *requestRecorder
	// err is set when a cap was exceeded. Every later Read returns it again.
	err error
}

// Read reads from the wrapped body. It asks for at most remaining+1 bytes: the
// one extra byte shows that the body is larger than the cap. Read returns the
// bytes up to the cap, and errBodyTooLarge with the first byte beyond it. The
// same happens when the shared budget runs out.
func (c *cappedBody) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p)) > c.remaining+1 {
		p = p[:c.remaining+1]
	}
	n, err := c.r.Read(p)
	if int64(n) > c.remaining {
		// n is remaining+1: one byte is beyond the cap. Hand back only the
		// bytes within the cap.
		n = int(c.remaining)
		c.remaining = 0
		c.fail()
		// The same read can also use up the shared budget. Hand back only the
		// bytes within both caps.
		return n - int(c.charge(n)), c.err
	}
	c.remaining -= int64(n)
	if over := c.charge(n); over > 0 {
		// The shared budget ran out. Hand back only the bytes within it.
		c.fail()
		return n - int(over), c.err
	}
	return n, err
}

// charge adds n bytes to the shared counter. It returns how many of the n
// bytes are beyond the total budget (0 if all fit). Add is atomic, so two
// bodies that read at the same time cannot both use the same bytes of budget.
func (c *cappedBody) charge(n int) int64 {
	total := c.used.Add(int64(n))
	over := total - c.maxTotal
	if over <= 0 {
		return 0
	}
	return min(over, int64(n))
}

// fail stores the too-large error, in the body and in the recorder.
func (c *cappedBody) fail() {
	c.err = c.rec.recordBlocked(fmt.Errorf("read response body: %w", errBodyTooLarge))
}

// Close closes the wrapped body.
func (c *cappedBody) Close() error {
	return c.r.Close()
}
