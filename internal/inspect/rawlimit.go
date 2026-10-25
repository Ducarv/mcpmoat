package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxRawBytes is the limit for the JSON size of the handshake result and of
// all list pages (tools, prompts, resources and resource templates) of one
// stdio server, as the SDK decoded them. It is also the frame limit of the
// stdio transport (see stdioProcess), so one frame cannot be larger either.
//
// The page cap and the item cap of listAll bound the number of requests and
// items, not the bytes: each page can be one very large frame, and the SDK
// keeps the fields that mcpmoat drops in its decoded page (_meta and icons of
// prompts and resources). Tools keep _meta and icons, and they count toward
// the limit like all other bytes. So rawLimit measures each result before
// listAll converts it.
//
// It counts JSON bytes, not memory. Decoded JSON can need many times its
// size in memory: a page of many small empty objects needs about 20 times
// its JSON size. Why 8 MiB: a large real server with about 100 tools sends
// well under 1 MiB, so a normal server is far below the limit, and a low
// value keeps the decoded data that it allows small.
const maxRawBytes = 8 << 20 // 8 MiB

// errRawTooLarge means that the server sent more than the raw limit of
// handshake and list data. Its text is fixed and holds no server data.
var errRawTooLarge = errors.New("server sent more handshake and list data than the size limit")

// rawLimit measures the handshake result and each tools/list, prompts/list,
// resources/list and resources/templates/list result that the server sends,
// as the MCP SDK decoded it, before it is converted. It adds the JSON size
// of each result to used, for all of them together. When used goes over
// limit, the middleware returns an error that wraps errRawTooLarge, so the
// call fails at once and no more pages are requested.
//
// The size is that of the decoded result, not the exact bytes on the wire:
// fields that the SDK does not know are dropped at decode, so they are not
// held in memory either.
//
// The middleware reads only sizes. It never keeps or prints the items,
// because they are untrusted server text.
//
// A rawLimit is for one client and one session. It is safe for concurrent
// use: used is atomic, and limit does not change.
type rawLimit struct {
	// limit is the most bytes that the server can send in one session.
	// Inspect uses maxRawBytes; tests use a small limit.
	limit int64

	// used is the JSON size of all measured results so far.
	used atomic.Int64
}

// middleware is an [mcp.Middleware] for the sending side of the client. It
// finds a result by its type, not by the method name, and passes every
// request and every other result on unchanged.
func (r *rawLimit) middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil {
			return res, err
		}
		if !measured(res) {
			return res, nil
		}
		if err := r.spend(res); err != nil {
			return nil, err
		}
		return res, nil
	}
}

// exceeded reports whether the server went over the limit in this session.
// The SDK does not always return the error of the middleware: when the
// server/discover result is over the limit, it falls back to initialize, and
// the error of that call replaces ours. So the caller asks rawLimit.
func (r *rawLimit) exceeded() bool {
	return r.used.Load() > r.limit
}

// measured reports whether res is a result that rawLimit measures: a
// non-nil handshake (server/discover or initialize), tools, prompts,
// resources or resource templates result.
func measured(res mcp.Result) bool {
	switch v := res.(type) {
	case *mcp.DiscoverResult:
		return v != nil
	case *mcp.InitializeResult:
		return v != nil
	case *mcp.ListToolsResult:
		return v != nil
	case *mcp.ListPromptsResult:
		return v != nil
	case *mcp.ListResourcesResult:
		return v != nil
	case *mcp.ListResourceTemplatesResult:
		return v != nil
	}
	return false
}

// spend adds the JSON size of res to used. It returns an error that wraps
// errRawTooLarge when the total goes over limit. A result that cannot be
// encoded counts as too large: a result that the SDK decoded from JSON
// always encodes, so this is a guard, not a normal path. The error texts
// give counts only, never server text.
func (r *rawLimit) spend(res mcp.Result) error {
	n, err := jsonSize(res)
	if err != nil {
		// Only the type of the error: its text can quote a value, which
		// could be server text.
		return fmt.Errorf("%w: cannot measure a result: %T", errRawTooLarge, err)
	}
	if total := r.used.Add(n); total > r.limit {
		return fmt.Errorf("%w (%d bytes)", errRawTooLarge, r.limit)
	}
	return nil
}

// jsonSize returns the size of v as JSON, with HTML escaping off, the same
// as marshalSchema. So "<", ">" and "&" in plain strings count one byte
// each, as a server sends them, not six. A field type with its own
// MarshalJSON that calls json.Marshal (for example the tool annotations of
// the SDK) still gets HTML escapes, so it can count a little more than the
// server sent; the error is on the safe side. The encoder builds the JSON in
// an internal buffer for a short time, so for one page the memory is about
// twice its size; countWriter keeps none of it.
func jsonSize(v any) (int64, error) {
	var c countWriter
	enc := json.NewEncoder(&c)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return 0, err
	}
	// Encode adds a newline after the value; the JSON does not have it.
	return c.n - 1, nil
}

// countWriter is an io.Writer that counts the bytes written to it and keeps
// none of them.
type countWriter struct {
	n int64
}

var _ io.Writer = (*countWriter)(nil)

// Write counts p and never fails.
func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
