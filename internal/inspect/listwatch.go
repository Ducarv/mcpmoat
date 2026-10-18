package inspect

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// listWatch looks at each tools/list, prompts/list and resources/list page
// that the server sends, as the MCP SDK decoded it, before the SDK filters
// or caches it. It does two jobs.
//
// Job 1, the raw byte limit. The byte budget of collect (maxBytes) counts
// only the text that mcpmoat keeps. But the SDK client keeps the full
// decoded page, also the fields that mcpmoat drops (_meta, icons), in its
// list cache until the session closes. So listWatch measures each page as
// JSON (see jsonSize) and adds the size to rawBytes,
// for all three kinds together. When rawBytes goes over rawLimit, the
// middleware returns an error that wraps [ErrTooManyItems]. Then the list
// call fails at once: the SDK does not cache that page, and collect requests
// no more pages. The size is that of the decoded page, not the exact bytes
// on the wire: fields that the SDK does not know are dropped at decode, so
// they are not held in memory either.
//
// Job 2, dropped tools. In the SDK (v1.8.0), ClientSession.ListTools runs
// filterValidTools on each page. That function silently removes nil tools
// and tools with invalid x-mcp-header annotations. It reports the removal
// only to the client logger, and mcpmoat sets no logger. So a hostile server
// could add one bad annotation to a poisoned tool, and the tool would never
// reach the rules or the pins, while other MCP clients may still load it.
// listWatch adds the number of tools of each page to sentTools. After
// inspectSession, inspectWatched compares sentTools with the number of tools
// in the Result. If the Result has fewer tools, the SDK dropped some, and
// inspectWatched returns an error.
//
// How: the SDK calls the sending middleware of the client around each
// request. It filters and caches the page only after the middleware returns.
// So the middleware sees the full, decoded page.
//
// This depends on where the SDK filters, which is not part of its API. If a
// new SDK version filters before the sending middleware, or no longer
// filters, TestInspectWatchedDroppedTools fails. Then check this file again.
//
// The middleware reads only sizes and counts. It never keeps or prints the
// items, because they are untrusted server text.
//
// A listWatch is for one client and one session. It is safe for concurrent
// use: its counters are atomic, and rawLimit does not change after
// newListWatch.
type listWatch struct {
	// rawLimit is the most bytes of list pages that the server can send in
	// one session. Inspect uses maxRawBytes; tests use a small limit.
	rawLimit int64

	// rawBytes is the JSON size of all list pages that the server sent.
	rawBytes atomic.Int64

	// sentTools is the number of tools in all tools/list results that the
	// server sent, before the SDK filtered them. A nil tool counts too.
	sentTools atomic.Int64
}

// newListWatch returns a listWatch with the raw byte limit rawLimit.
func newListWatch(rawLimit int64) *listWatch {
	return &listWatch{rawLimit: rawLimit}
}

// newWatchedClient returns the client of newClient, with a new listWatch on
// it that has the raw byte limit rawLimit. Make a new pair for each call to
// Inspect.
func (i *SDKInspector) newWatchedClient(rawLimit int64) (*mcp.Client, *listWatch) {
	c := i.newClient()
	w := newListWatch(rawLimit)
	c.AddSendingMiddleware(w.middleware)
	return c, w
}

// middleware is an [mcp.Middleware] that measures each tools/list,
// prompts/list and resources/list result that the server sends, and counts
// the tools. It finds a list result by its type, not by the method name.
//
// It passes every request on unchanged, and every result too, except in two
// cases. It returns a nil result and an error:
//
//   - that wraps [ErrTooManyItems] when the pages of the session go over
//     rawLimit;
//   - that wraps [ErrProtocol] when the result cannot be encoded as JSON.
//
// The SDK returns the error of a sending middleware unchanged from ListTools,
// ListPrompts and ListResources, so errors.Is works on it.
func (w *listWatch) middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil {
			return res, err
		}

		var tools int
		switch r := res.(type) {
		case *mcp.ListToolsResult:
			if r == nil {
				return res, nil
			}
			tools = len(r.Tools)
		case *mcp.ListPromptsResult:
			if r == nil {
				return res, nil
			}
		case *mcp.ListResourcesResult:
			if r == nil {
				return res, nil
			}
		default:
			return res, nil
		}

		if err := w.spendRaw(res); err != nil {
			return nil, err
		}
		w.sentTools.Add(int64(tools))
		return res, nil
	}
}

// spendRaw adds the JSON size of res to rawBytes. It returns an error that
// wraps [ErrTooManyItems] when the total goes over rawLimit, and an error
// that wraps [ErrProtocol] when res cannot be encoded. The error texts give
// counts only, never server text.
func (w *listWatch) spendRaw(res mcp.Result) error {
	n, err := jsonSize(res)
	if err != nil {
		// Only the type of the error: its text can quote a value, which
		// could be server text. A page that the SDK decoded from JSON
		// always encodes, so this is a guard, not a normal path.
		return fmt.Errorf("%w: measure list page: %T", ErrProtocol, err)
	}
	if total := w.rawBytes.Add(n); total > w.rawLimit {
		return fmt.Errorf("%w: server sent more than %d bytes of list data", ErrTooManyItems, w.rawLimit)
	}
	return nil
}

// jsonSize returns the size of v as JSON. HTML escaping is off, so "<", ">"
// and "&" count one byte each, as a server sends them, not six. rawJSON in
// convert.go encodes with the same settings. The encoder
// builds the JSON in an internal buffer for a short time, so for one page
// the memory is about twice its size; countWriter keeps none of it.
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

// Write counts p and never fails.
func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// checkDroppedTools returns an error that wraps [ErrProtocol] when kept, the
// number of tools in the Result, is less than the number of tools that the
// server sent. The error text gives the count only, never a tool name or an
// annotation, because those are untrusted server text.
//
// kept can be more than sentTools only if the SDK answered a tools/list
// request from its cache, without a request to the server. That does not
// happen in one inspectSession, because collect never requests the same
// cursor twice. checkDroppedTools returns nil for it.
func (w *listWatch) checkDroppedTools(kept int) error {
	dropped := w.sentTools.Load() - int64(kept)
	if dropped <= 0 {
		return nil
	}
	return fmt.Errorf("%w: list tools: server sent %d tools that the MCP SDK refused", ErrProtocol, dropped)
}

// inspectWatched runs inspectSession on cs, and then fails if the SDK
// dropped tools that the server sent (see listWatch). w must be the
// listWatch of the client of cs.
//
// On an error, the Result is zero. An error of inspectSession comes first:
// then inspectWatched does not check w. An error of the middleware of w
// reaches the caller through inspectSession and sessionError, so an
// over-limit error wraps [ErrTooManyItems] only.
func inspectWatched(ctx context.Context, cs *mcp.ClientSession, w *listWatch) (Result, error) {
	res, err := inspectSession(ctx, cs)
	if err != nil {
		return Result{}, err
	}
	if err := w.checkDroppedTools(len(res.Tools)); err != nil {
		return Result{}, err
	}
	return res, nil
}
