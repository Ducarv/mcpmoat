package inspect

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// allowedServerMethod reports whether a server can call method on the mcpmoat
// client. It is an allowlist: refuseServerRequests answers every other
// method with "method not found".
//
// mcpmoat only reads lists from the server. It needs no request from the
// server, except ping. The notifications here have no reply and do almost
// nothing in the SDK client (v1.8.0), so they can pass.
//
// A method that is not in the list is refused, also a method that a new SDK
// version adds. To allow a method, read its SDK handler first: the handler
// runs on untrusted params.
//
// It is a switch, not a map, so that the list cannot change at run time.
func allowedServerMethod(method string) bool {
	switch method {
	case
		// A liveness check. The SDK answers it at once with an empty
		// result.
		"ping",

		// The server cancels one of its own requests. The jsonrpc2 layer
		// of the SDK handles cancellation; the SDK handler for it does
		// nothing.
		"notifications/cancelled",

		// The list of tools, prompts or resources changed. The SDK only
		// clears its list cache. mcpmoat sets no handler for them.
		"notifications/tools/list_changed",
		"notifications/prompts/list_changed",
		"notifications/resources/list_changed",

		// A resource changed. The SDK clears one cache entry, after it
		// checks that the params are not nil.
		"notifications/resources/updated",

		// A log message. mcpmoat sets no logging handler, so the SDK
		// drops it.
		"notifications/message",

		// Progress of a request. mcpmoat sets no progress handler, so
		// the SDK drops it.
		"notifications/progress",

		// The server acknowledges a subscription. The SDK handler does
		// nothing.
		"notifications/subscriptions/acknowledged":
		return true
	}
	// Not allowed, on purpose: "notifications/elicitation/complete". In the
	// SDK (v1.8.0) its handler reads req.Params without a nil check, and the
	// params are optional. So a server that sends it without params makes
	// the handler panic, and the panic stops mcpmoat. mcpmoat never asks for
	// an elicitation, so it does not need this notification.
	return false
}

// refuseServerRequests is the receiving [mcp.Middleware] of the mcpmoat
// client. It passes a method that allowedServerMethod allows on to next,
// unchanged. For every other method, for example completion/complete,
// roots/list, sampling/createMessage or elicitation/create, it returns a
// JSON-RPC "method not found" error. Then it does not call next and does not
// read or keep the request.
//
// Why: without it, the SDK client serves every method that it knows. For
// completion/complete it sends the same request back to the server, and
// waits for the answer in a new goroutine. A hostile server can send many
// such requests and never answer them, so the goroutines and their params
// add up without a limit. With this middleware, the client answers at once
// and never sends a request back to the server.
//
// The residual: the SDK decodes the frame and the params of a request
// before the middleware runs, and it does not limit how many requests wait
// in its queue. The SDK must also write each "method not found" reply to the
// stdin of the server. If the server floods requests and stops reading its
// stdin, those writes block, and each blocked request keeps its goroutine and
// its params, until Inspect stops the child (which closes its stdin) or ctx
// ends. Inspect stops the child before it closes the session, because the
// close of the session waits for those writes. A per-server timeout (issue
// #28) or a custom transport is the real fix.
func refuseServerRequests(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if allowedServerMethod(method) {
			return next(ctx, method, req)
		}
		// A new error for each call, so that no error value is shared.
		// The SDK adds the method name to the message on the wire; that
		// text goes back to the server only, never to the terminal.
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not found"}
	}
}
