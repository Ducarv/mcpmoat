package inspect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Limits of the HTTP client. The size caps count wire bytes. The limits on
// the shape of the decoded JSON (depth, values, string length) are in
// jsonshape.go: maxJSONDepth, maxJSONValues and maxJSONStringBytes.
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

// requestRecorder records what happened on the HTTP layer for one MCP call,
// because the MCP SDK drops it: the status code of the last response, and the
// error that this layer raised on purpose (a refused origin, a refused
// redirect or a body that is too large). classify reads both through
// httpEvents.stateFor.
//
// Each MCP call gets its own record (see callRecords in remote.go), so a
// request that runs at the same time as another one cannot change the label
// of its error. httpEvents embeds one more record, the fallback, for the
// requests that belong to no call.
//
// It is safe for concurrent use: a response body can be read on another
// goroutine than the one that sent the request.
type requestRecorder struct {
	// status is the status of the most recent request of the record: the code
	// of a non-2xx response that was not a followed redirect, and 0 after a
	// 2xx response or after a request that got no response. An atomic value
	// needs no mutex.
	//
	// It keeps the latest value and not the first one. The SDK can start with
	// a request that gets a 404 and then fall back to another request that
	// works. The 404 must not give a wrong label to a later, unrelated error.
	status atomic.Int64

	// mu guards blocked.
	mu sync.Mutex
	// blocked is the first error that the HTTP layer raised on purpose for
	// this record, or nil.
	blocked error
}

// lastStatus returns the status of the most recent request of the record (see
// the status field).
func (r *requestRecorder) lastStatus() int {
	return int(r.status.Load())
}

// blockedErr returns the first error that the HTTP layer raised on purpose
// for this record, or nil.
func (r *requestRecorder) blockedErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.blocked
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

// recorderKey is the context key for the record of one MCP call. A context
// key must not collide with keys of other packages. An unexported type does
// that: no other package can name recorderKey, so no other package can make
// an equal key. The empty struct takes no memory.
type recorderKey struct{}

// withRecorder returns a copy of ctx that carries rec. The SDK passes the
// context of a call down to http.NewRequestWithContext, so headerTransport
// finds rec again in req.Context().
func withRecorder(ctx context.Context, rec *requestRecorder) context.Context {
	return context.WithValue(ctx, recorderKey{}, rec)
}

// recorderFrom returns the record that withRecorder put on ctx, or nil if
// there is none. The two-value type assertion gives nil instead of a panic
// when the key is absent.
func recorderFrom(ctx context.Context) *requestRecorder {
	rec, _ := ctx.Value(recorderKey{}).(*requestRecorder)
	return rec
}

// httpEvents reports what the HTTP layer saw during one inspection. It
// implements transportEvents for classify.
//
// The record of each MCP call travels on the context of its requests (see
// withRecorder). The embedded requestRecorder is the fallback record: it gets
// the requests that carry no record of their own. These are the legacy SSE
// GET stream (the SDK opens it with the context of Client.Connect, before any
// call), the DELETE that closes a streamable session, and requests from a
// direct caller such as a test. Because the record is embedded, its methods
// (lastStatus, blockedErr and the record methods) are methods of httpEvents
// too, and they read or write the fallback record.
//
// It is safe for concurrent use. Use it through a pointer only: it holds a
// mutex, which must not be copied.
type httpEvents struct {
	// requestRecorder is the fallback record (see the type doc).
	requestRecorder

	// sessionUp is true after the server answered the MCP handshake
	// (markHandshake) or Remote connected the session (markConnected).
	sessionUp atomic.Bool

	// lastCall is the record of the MCP call that finished last, or nil. An
	// atomic.Pointer loads and stores a pointer in one step, so the
	// goroutines of the SDK can use it without a mutex. stateFor uses it for
	// an error that is linked to no call (see stateFor).
	lastCall atomic.Pointer[requestRecorder]

	// connectDone is true after markConnected: Client.Connect succeeded.
	connectDone atomic.Bool

	// connectBlocked is the record of the first call that finished with a
	// blocked error during the connect (before markConnected), or nil.
	// stateFor uses it to label a failed connect only. Two cases need it:
	//
	//   - A failed write breaks the whole legacy SSE connection. When the
	//     server/discover POST goes to another origin, the initialize call
	//     after it fails before it sends any request, so its own record is
	//     empty.
	//   - A server that redirects server/discover to another origin and then
	//     never answers initialize tried to send the secrets elsewhere. The
	//     report must show that, not only a timeout.
	connectBlocked atomic.Pointer[requestRecorder]
}

// Compile-time check: *httpEvents must implement transportEvents. The blank
// identifier _ throws the value away, so this line costs nothing at run time,
// but the build fails if the method set ever drifts.
var _ transportEvents = (*httpEvents)(nil)

// markHandshake records that the server answered initialize or
// server/discover, so it speaks the configured transport.
func (ev *httpEvents) markHandshake() {
	ev.sessionUp.Store(true)
}

// markConnected records that the session is up. Remote calls it after a
// successful connect. From now on stateFor ignores connectBlocked: the SDK
// recovered from any call that was blocked during the connect (for example,
// it falls back from server/discover to initialize after any error), so that
// error must not label a later, unrelated failure. Nothing is cleared: a
// blocked error in the fallback record (for example a legacy SSE stream that
// went over the size cap at any time) still explains later failures.
func (ev *httpEvents) markConnected() {
	ev.sessionUp.Store(true)
	ev.connectDone.Store(true)
}

// connected implements transportEvents.
func (ev *httpEvents) connected() bool {
	return ev.sessionUp.Load()
}

// finishCall stores rec as the record of the call that finished last.
// During the connect, it also keeps the first record with a blocked error in
// connectBlocked. callRecords calls it when a call returns. A nil rec changes
// nothing.
func (ev *httpEvents) finishCall(rec *requestRecorder) {
	if rec == nil {
		return
	}
	ev.lastCall.Store(rec)
	if !ev.connectDone.Load() && rec.blockedErr() != nil {
		// CompareAndSwap stores rec only if the pointer is still nil, in one
		// atomic step, so the first blocked call wins.
		ev.connectBlocked.CompareAndSwap(nil, rec)
	}
}

// recorderFor returns the record for req: the record of its MCP call, or the
// fallback record when the request belongs to no call.
func (ev *httpEvents) recorderFor(req *http.Request) *requestRecorder {
	if rec := recorderFrom(req.Context()); rec != nil {
		return rec
	}
	return &ev.requestRecorder
}

// stateFor implements transportEvents. It finds the call record for err: the
// record in a *recordedError in the chain of err, or else the record of the
// call that finished last (for an error that mcpmoat made itself after a
// call, or a chain that lost the *recordedError). Then it picks blocked, in
// this order:
//
//  1. the blocked error of the call record;
//  2. else the blocked error of the fallback record, because a blocked
//     legacy SSE stream breaks every call after it;
//  3. else, while the connect is not done, the blocked error of
//     connectBlocked (see the field doc).
//
// status is the status of the call record if there is one, else the status
// of the fallback record.
func (ev *httpEvents) stateFor(err error) (status int, blocked error) {
	call := ev.lastCall.Load()
	// errors.As walks the chain of err and stops at the first *recordedError.
	// It needs a pointer to the target variable (&re), so that it can set re.
	var re *recordedError
	if errors.As(err, &re) && re.rec != nil {
		call = re.rec
	}

	if call != nil {
		blocked = call.blockedErr()
	}
	// ev.blockedErr and ev.lastStatus are the methods of the embedded
	// requestRecorder, so they read the fallback record.
	if blocked == nil {
		blocked = ev.blockedErr()
	}
	if blocked == nil && !ev.connectDone.Load() {
		if rec := ev.connectBlocked.Load(); rec != nil {
			blocked = rec.blockedErr()
		}
	}

	if call != nil {
		status = call.lastStatus()
	} else {
		status = ev.lastStatus()
	}
	return status, blocked
}

// recordedError links the error of one MCP call to the record of that call.
// callRecords wraps each failed call in it, so that stateFor can find the
// record later. The SDK does not return the request or the response with its
// errors, so there is no other link.
//
// Its text is the text of err, so the wrap changes no message. Unwrap returns
// err, so errors.Is and errors.As still see the whole chain below, as the SDK
// and classify expect.
type recordedError struct {
	// err is the error of the call.
	err error
	// rec is the record of the call.
	rec *requestRecorder
}

// Error returns the text of the wrapped error.
func (e *recordedError) Error() string {
	return e.err.Error()
}

// Unwrap returns the wrapped error. errors.Is and errors.As call it to walk
// the chain.
func (e *recordedError) Unwrap() error {
	return e.err
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
	// Base does the network I/O. A nil Base gives newBaseTransport(nil). Tests
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
// cfg.MaxTotal bytes, and returns errBodyTooLarge beyond either cap. It also
// checks the JSON shape of the 2xx bodies that the SDK decodes, and returns
// an error that wraps errJSONTooComplex for a message that is too deep, has
// too many values or has a too long string (see shapeBody).
//
// The returned httpEvents holds what the HTTP layer saw: a record per MCP
// call, a fallback record for the other requests, and whether the session
// is up (see httpEvents).
//
// The error is for a config that mcpmoat cannot use. It wraps
// errReservedHeader or errInvalidHeaderValue and holds at most a header key,
// never a value, or it reports a nil Endpoint.
//
// The client has no Client.Timeout: that timeout also cuts the body read, so
// it would end a long SSE stream. The context of each request bounds the time.
func newHTTPClient(cfg httpClientConfig) (*http.Client, *httpEvents, error) {
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
		base = newBaseTransport(nil)
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

	ev := &httpEvents{}
	client := &http.Client{
		Transport: &headerTransport{
			endpoint: endpoint,
			user:     cfg.User,
			header:   header,
			base:     base,
			events:   ev,
			maxBody:  maxBody,
			maxTotal: maxTotal,
		},
		// The client calls CheckRedirect before it follows a redirect. via
		// holds the requests made so far, oldest first, so len(via) is 1 on
		// the first redirect, so at most maxRedirects redirects are followed.
		// The headerTransport adds the config headers to every request it
		// gets, redirected ones too, so without the origin check a redirect
		// would send the secrets to another host.
		// The error is also stored in the record of the request, because the
		// SDK may hide it. The redirected request keeps the context of the
		// first one, so it finds the same record.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return ev.recorderFor(req).recordBlocked(errTooManyRedirects)
			}
			if !sameOrigin(req.URL, endpoint) {
				return ev.recorderFor(req).recordBlocked(errCrossOriginRedirect)
			}
			return nil
		},
	}
	return client, ev, nil
}

// newBaseTransport returns a new transport for the real network. It does not
// use http.DefaultTransport, so no other code can change its settings.
//
// The transport dials through a new pinnedDialer, which keeps the first IP
// address that each host name connects to (DNS rebinding, issue #102). Remote
// makes one transport, and so one pin table, for each call, so a pin lasts
// for one inspection only. The pin changes only the IP address: TLS still
// uses the URL host for SNI and for the certificate check. With HTTP_PROXY or
// HTTPS_PROXY, the transport dials the proxy, so the pinned address is the
// address of the proxy, and the proxy resolves the server name itself.
//
// A nil lookup uses the system resolver. Tests give a stub lookup.
func newBaseTransport(lookup lookupFunc) *http.Transport {
	return &http.Transport{
		// Honour the user's HTTP_PROXY, HTTPS_PROXY and NO_PROXY variables. The
		// proxy is user-configured, and Go never uses it for localhost.
		Proxy:               proxyFromEnvironment,
		DialContext:         newPinnedDialer(lookup, nil).DialContext,
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
// absent, as in net/http. RoundTrip and sentHeaders both use it.
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
// status of each response, caps the size of the response bodies and checks
// the JSON shape of the 2xx bodies that the SDK decodes.
type headerTransport struct {
	// endpoint is the configured endpoint URL. Only its origin gets requests.
	endpoint *url.URL
	// user is the user info of the configured URL, or nil.
	user *url.Userinfo
	// header holds the config headers and the User-Agent, in canonical form.
	header http.Header
	// base does the network I/O.
	base http.RoundTripper
	// events holds the records of statuses and of the errors raised on
	// purpose. Each request writes to its own record (see
	// httpEvents.recorderFor).
	events *httpEvents
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
//
// It wraps the response body twice. cappedBody limits the wire bytes of the
// body and of all bodies together. On a body that the SDK decodes as JSON
// (see shapeFor), a shapeReader then limits the depth, the number of values and
// the string length of each JSON message (see shapeBody and jsonshape.go), so
// that a small body cannot decode to a huge amount of memory. Both store
// their error in the record of the request.
func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get the record once: every step below writes to the same one.
	rec := t.events.recorderFor(req)
	if !sameOrigin(req.URL, t.endpoint) {
		// The RoundTripper contract says that RoundTrip closes the request
		// body, also when it returns an error.
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, rec.recordBlocked(errOtherOrigin)
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
			rec.recordNoResponse()
		}
		// Return the error as is. classify unwraps the *url.Error that the
		// http.Client adds.
		return nil, err
	}

	if record {
		rec.recordResponse(resp)
	}
	if resp.Body != nil {
		resp.Body = &cappedBody{
			r:         resp.Body,
			remaining: t.maxBody,
			used:      &t.used,
			maxTotal:  t.maxTotal,
			rec:       rec,
		}
		// The shape check wraps the capped body, so it sees only the bytes
		// within the size caps. Closing the shape reader closes the capped
		// body, which closes the real body.
		resp.Body = shapeBody(resp.Body, out, resp, rec)
	}
	return resp, nil
}

// bodyShape tells which shape check a response body gets (see shapeBody).
type bodyShape int

// The shape checks of a response body.
const (
	// bodyShapeNone: no shape check. The SDK does not decode the body as
	// JSON.
	bodyShapeNone bodyShape = iota
	// bodyShapeJSON: the body is one JSON-RPC message (for a non-2xx
	// status, a JSON-RPC error).
	bodyShapeJSON
	// bodyShapeSSE: the body is a Server-Sent Events stream of JSON-RPC
	// messages.
	bodyShapeSSE
)

// shapeBody wraps body, the capped body of resp, in a shapeReader that
// checks the JSON shape (jsonLimits, defaultJSONLimits in jsonshape.go)
// before the SDK decodes it. It returns body unchanged when the SDK does not
// decode it as JSON (see shapeFor). The SDK decodes a 2xx body as MCP
// messages, and most non-2xx bodies as a JSON-RPC error.
//
// The size caps of cappedBody count wire bytes, and that is not enough. The
// SDK decodes a message into Go values, and a small JSON text can decode to
// much more memory: "[{},{},...]" uses 3 bytes on the wire for each empty
// object, but each decoded object needs about 60 bytes. So a body of 8 MiB
// can become more than 100 MiB of decoded data. The shape check limits the
// depth, the number of values and the string length of each message, which
// bounds the decoded size.
//
// At the first violation, the reader stores the error in rec, because the
// SDK can hide the error of a body (for example, it puts only the text in a
// new error). The error wraps errJSONTooComplex, so classify and errors.Is
// find it.
func shapeBody(body io.ReadCloser, req *http.Request, resp *http.Response, rec *requestRecorder) io.ReadCloser {
	onFail := func(err error) error {
		return rec.recordBlocked(fmt.Errorf("read response body: %w", err))
	}
	switch shapeFor(req, resp) {
	case bodyShapeJSON:
		return newJSONShapeReader(body, defaultJSONLimits(), onFail)
	case bodyShapeSSE:
		return newSSEShapeReader(body, defaultJSONLimits(), onFail)
	}
	return body
}

// shapeFor returns the shape check for resp, the response to req. It
// follows how the SDK (go-sdk v1.8.0) reads a body:
//
//   - A non-2xx body gets the JSON check, whatever the Content-Type and the
//     method (see shapeForError). The streamable transport reads such a body
//     completely and decodes it as one JSON-RPC message to find a JSON-RPC
//     error (checkResponse in mcp/streamable.go). It ignores the
//     Content-Type, and the decode builds Go values for every part of the
//     message, for example a deep "id". The check costs nothing when nobody
//     reads the body.
//   - A 2xx GET is an SSE stream. The legacy SSE transport parses its GET
//     stream as SSE whatever the Content-Type (mcp/sse.go). The streamable
//     transport reads its GET stream only when the type is
//     text/event-stream.
//   - For a 2xx response to another method, the SDK picks the parser by the
//     base media type of the Content-Type (mime.ParseMediaType, as in
//     mcp/streamable.go): application/json is one JSON message,
//     text/event-stream is SSE. It refuses any other type without reading
//     the body, so no check is needed. (The legacy SSE transport never reads
//     a POST body.)
//
// The method is the method of the first request of a redirect chain,
// because the SDK chose its parser for that request. A 303 redirect turns a
// POST into a GET, and the SDK then still picks the parser by the
// Content-Type. A server must not escape the JSON check that way.
func shapeFor(req *http.Request, resp *http.Response) bodyShape {
	first := firstRequest(req)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return shapeForError(first, resp)
	}
	if first.Method == http.MethodGet {
		return bodyShapeSSE
	}
	// ParseMediaType returns the media type in lower case, without the
	// parameters such as "; charset=utf-8". An empty or malformed value is
	// an error: the SDK refuses that body too.
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return bodyShapeNone
	}
	switch mediaType {
	case "application/json":
		return bodyShapeJSON
	case "text/event-stream":
		return bodyShapeSSE
	}
	return bodyShapeNone
}

// shapeForError returns the shape check for resp, a non-2xx response to a
// request whose redirect chain starts with first. It is bodyShapeJSON,
// except when the SDK (go-sdk v1.8.0) verifiably never decodes the body:
//
//   - The first request is a DELETE. The SDK sends DELETE only to close the
//     session, and it closes the answer without reading it.
//   - The status is 429, 500, 502, 503 or 504. checkResponse in
//     mcp/streamable.go treats these as transient (isTransientHTTPStatus)
//     and returns before it reads the body.
//   - resp is a redirect that the http.Client follows (isFollowedRedirect).
//     The client reads at most a few KiB of that body and throws them away;
//     the SDK never gets it.
//
// Every other non-2xx body gets the JSON check, also for a GET: the
// streamable transport decodes the body of a failed GET stream reconnect,
// and of a failed standalone GET stream in strict mode, in the same way.
// The legacy SSE transport and the standalone GET stream in non-strict mode
// do not read a non-2xx body, and an unread check costs nothing.
func shapeForError(first *http.Request, resp *http.Response) bodyShape {
	if first.Method == http.MethodDelete || isFollowedRedirect(resp) {
		return bodyShapeNone
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return bodyShapeNone
	}
	return bodyShapeJSON
}

// firstRequest returns the first request of the redirect chain of req, or
// req itself if it is not a redirect. On a redirect, http.Client sets
// req.Response to the redirect response, and the transport sets the Request
// of that response to the request that got it. The loop stops after
// maxRedirects+1 steps, which is more than the client follows, so a chain
// that a caller built by hand cannot make it loop forever.
func firstRequest(req *http.Request) *http.Request {
	for range maxRedirects + 1 {
		if req.Response == nil || req.Response.Request == nil {
			break
		}
		req = req.Response.Request
	}
	return req
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
	// rec is the record of the request that got this body. It stores the
	// error that Read returns.
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
