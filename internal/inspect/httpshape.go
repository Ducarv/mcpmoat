package inspect

import (
	"fmt"
	"io"
	"mime"
	"net/http"
)

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
	if isSessionDelete(first) || isFollowedRedirect(resp) {
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

// isSessionDelete reports whether req belongs to the DELETE that closes a
// streamable session: the first request of its redirect chain is a DELETE.
// The SDK sends DELETE for nothing else. The method of req alone is not
// enough: http.Client turns a DELETE into a GET on a 301, 302 or 303.
// CheckRedirect, RoundTrip and shapeForError all use it, so they agree.
func isSessionDelete(req *http.Request) bool {
	return firstRequest(req).Method == http.MethodDelete
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
