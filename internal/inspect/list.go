package inspect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file reads the tools, prompts, resources and resource templates of a
// connected server and converts them to the SDK-independent types in types.go.
//
// The SDK has iterators (ClientSession.Tools and similar) but they have no
// page cap and no check for a repeated cursor. A hostile server can page
// forever, so listAll runs its own bounded cursor loop.

const (
	// maxPages is the largest number of pages that listAll reads for one list.
	maxPages = 100

	// maxItems is the largest number of items that listAll reads for one
	// list. It counts every item that the server sends.
	maxItems = 10000
)

// Sentinel errors for the limits. Their texts are fixed and hold no server
// data, so it is safe to print them. classify reports them as KindProtocol
// with their text; tests recognise them with errors.Is.
var (
	// errTooManyPages means a list has more than maxPages pages.
	errTooManyPages = errors.New("too many pages")
	// errTooManyItems means a list has more than maxItems items.
	errTooManyItems = errors.New("too many items")
	// errRepeatedCursor means the server sent the same cursor twice in one
	// list, so paging would never end.
	errRepeatedCursor = errors.New("repeated cursor")
	// errRawListMissing means the raw tools of a page were not captured, so
	// listAll cannot prove that the SDK kept every tool.
	errRawListMissing = errors.New("raw tools list not captured")
	// errLaterPage marks an error from a page after the first. listAll never
	// reads such an error as "the server has no such list", because earlier
	// pages already held items.
	errLaterPage = errors.New("error on a later page")
)

// JSON-RPC methods that this package watches in sending middleware.
const (
	// methodListTools is the method of a tools/list request.
	methodListTools = "tools/list"
	// methodInitialize and methodDiscover are the handshake methods. The SDK
	// tries server/discover first and falls back to initialize.
	methodInitialize = "initialize"
	methodDiscover   = "server/discover"
)

// rawLists keeps the tools lists exactly as the server sent them, before the
// SDK filters them.
//
// A scanner must see what the server sent, not what the SDK accepted. Since
// SDK v1.8.0, ClientSession.ListTools drops, without a word, every tool whose
// inputSchema has an invalid "x-mcp-header" annotation, and every nil entry.
// A hostile server can use this to hide a malicious tool from mcpmoat while a
// client that does not check the annotation still shows the tool to the model.
//
// ListTools calls the sending middleware first and filters the result after
// the middleware returns, and it filters by assigning a new slice to
// res.Tools on the same *mcp.ListToolsResult. So the middleware copies the
// slice and keys the copy by the result pointer. listAll then reads the copy
// for the page that ListTools returned. Prompts and resources need no capture:
// the SDK does not filter them.
//
// On a session that negotiated protocol 2026-07-28 or later, the SDK may serve
// a repeated cursor from its own cache and skip the middleware. The middleware
// sets TTLMs to 0 on every tools result, so the SDK never caches it.
//
// A rawLists is safe for concurrent use.
type rawLists struct {
	mu    sync.Mutex
	tools map[*mcp.ListToolsResult][]*mcp.Tool
}

// middleware returns an SDK sending middleware that records the raw tools of
// every successful tools/list result. Add it with
// Client.AddSendingMiddleware before the client connects.
func (r *rawLists) middleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if err != nil || method != methodListTools {
				return res, err
			}
			if lt, ok := res.(*mcp.ListToolsResult); ok && lt != nil {
				r.put(lt)
				// Keep the SDK from caching this result (see the rawLists doc).
				lt.TTLMs = 0
			}
			return res, err
		}
	}
}

// put stores a copy of the tools of res, before the SDK filters them.
func (r *rawLists) put(res *mcp.ListToolsResult) {
	tools := slices.Clone(res.Tools)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tools == nil {
		r.tools = make(map[*mcp.ListToolsResult][]*mcp.Tool)
	}
	r.tools[res] = tools
}

// take returns the raw tools that were recorded for res and forgets them. The
// bool is false when nothing was recorded for res.
func (r *rawLists) take(res *mcp.ListToolsResult) ([]*mcp.Tool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tools, ok := r.tools[res]
	delete(r.tools, res)
	return tools, ok
}

// sessionLister is the part of *mcp.ClientSession that listAll uses. Tests
// pass a fake.
type sessionLister interface {
	ListTools(context.Context, *mcp.ListToolsParams) (*mcp.ListToolsResult, error)
	ListPrompts(context.Context, *mcp.ListPromptsParams) (*mcp.ListPromptsResult, error)
	ListResources(context.Context, *mcp.ListResourcesParams) (*mcp.ListResourcesResult, error)
}

// The SDK session must satisfy sessionLister. This line fails to compile if
// an SDK update changes a method signature.
var _ sessionLister = (*mcp.ClientSession)(nil)

// listAll reads every tool, prompt and resource that the server offers.
//
// A scanner lists what the server answers, not only what it declares. A
// hostile server can leave a capability out of caps and still answer the list
// request of a client that does not check caps. So listAll sends the list
// request for tools, prompts and resources always.
//
//   - If caps declares the capability, any error is an error.
//   - If caps does not declare it (caps is nil, or the field is nil), a
//     JSON-RPC error response on the first page ("method not found" for
//     example) means the list is empty, and listAll goes on. Any other error is
//     still an error: a transport failure, a limit breach, a missing raw list
//     or a canceled context. An error response on a later page is also an
//     error, because the earlier pages held items that we must not drop.
//
// listAll does not list resource templates (resources/templates/list). Use
// listInto, which calls listAll and then lists the templates too.
//
// A list that is too long, or that never ends, is an error. listAll never
// returns a cut list, because the cut part could hide a malicious tool.
//
// raw holds the tools lists as the server sent them, and must not be nil. A
// scanner must see what the server sent, not what the SDK accepted: the SDK
// silently drops tools with an invalid "x-mcp-header" annotation (see
// rawLists). listAll reads the tools of each page from raw, and it fails if a
// page was not captured.
//
// A list is nil when the server did not declare the capability and refused
// the list request (see tolerateUndeclared). It is empty but not nil when the
// server answered with an empty list.
func listAll(ctx context.Context, cs sessionLister, caps *mcp.ServerCapabilities, raw *rawLists) (tools []Tool, prompts []Prompt, resources []Resource, err error) {
	var declTools, declPrompts, declResources bool
	if caps != nil {
		declTools = caps.Tools != nil
		declPrompts = caps.Prompts != nil
		declResources = caps.Resources != nil
	}

	tools, err = listTools(ctx, cs, raw)
	if err = tolerateUndeclared(err, declTools); err != nil {
		return nil, nil, nil, err
	}
	prompts, err = listPrompts(ctx, cs)
	if err = tolerateUndeclared(err, declPrompts); err != nil {
		return nil, nil, nil, err
	}
	resources, err = listResources(ctx, cs)
	if err = tolerateUndeclared(err, declResources); err != nil {
		return nil, nil, nil, err
	}
	return tools, prompts, resources, nil
}

// templateLister is the part of *mcp.ClientSession that listResourceTemplates
// uses. It is separate from sessionLister so that the existing fakes for
// sessionLister stay valid. Tests pass a fake.
type templateLister interface {
	ListResourceTemplates(context.Context, *mcp.ListResourceTemplatesParams) (*mcp.ListResourceTemplatesResult, error)
}

// The SDK session must satisfy templateLister. This is a compile-time check:
// it converts a typed nil pointer to the interface and throws the value away
// (the blank identifier _). It costs nothing at run time, and the build fails
// if an SDK update changes the method signature.
var _ templateLister = (*mcp.ClientSession)(nil)

// fullLister is everything that listInto needs: the three lists of
// sessionLister and the templates list of templateLister. Go lets an
// interface embed other interfaces; the method sets are joined.
// *mcp.ClientSession satisfies it, because it satisfies both parts.
type fullLister interface {
	sessionLister
	templateLister
}

// listInto reads every tool, prompt, resource and resource template that the
// server offers and stores them in result. It sets result.Tools,
// result.Prompts, result.Resources and result.ResourceTemplates, and no other
// field. On error it changes nothing in result.
//
// Tools, prompts and resources follow listAll (see there). Templates follow
// the same rules as resources, because the resources capability covers both:
// listInto always sends resources/templates/list, and tolerateUndeclared
// decides what an error means when caps does not declare resources.
//
// There is one more case. A server can declare the resources capability and
// still not support templates: the spec makes resources/templates/list
// optional. So when caps declares resources and the server answers the first
// page with a JSON-RPC "method not found" error (-32601), the template list is
// empty but not nil (see isMethodNotFound). Any other error is still an
// error.
func listInto(ctx context.Context, cs fullLister, caps *mcp.ServerCapabilities, raw *rawLists, result *Result) error {
	tools, prompts, resources, err := listAll(ctx, cs, caps, raw)
	if err != nil {
		return err
	}

	declResources := caps != nil && caps.Resources != nil
	templates, err := listResourceTemplates(ctx, cs)
	switch {
	case err == nil:
	case declResources && isMethodNotFound(err):
		templates = []ResourceTemplate{}
	default:
		if err = tolerateUndeclared(err, declResources); err != nil {
			return err
		}
		// tolerateUndeclared returned nil, so templates is nil, as for
		// the other lists of a server without the capability.
	}

	result.Tools = tools
	result.Prompts = prompts
	result.Resources = resources
	result.ResourceTemplates = templates
	return nil
}

// sdkErrorCodes are the JSON-RPC error codes that the SDK uses for its own
// failures (SDK v1.8.0, internal/jsonrpc2): -32001 unknown error, -32003
// client closing, -32004 server closing and -32005 "rejected by transport".
// The SDK wraps every failed HTTP request, and HTTP 429, 500, 502, 503 and
// 504, with -32005. Such an error is a *jsonrpc.Error too, but no server sent it.
var sdkErrorCodes = []int64{-32001, -32003, -32004, -32005}

// tolerateUndeclared decides what a failed list means. It returns nil when the
// server did not declare the capability and answered the first page with a
// JSON-RPC error response, whatever its code: the list is then empty.
// Otherwise it returns err unchanged.
//
// An SDK failure (sdkErrorCodes) stays an error, although it is a
// *jsonrpc.Error too: a failed request must not look like a server without
// the capability, or the scan would report an empty list as clean. This also
// covers a JSON-RPC error that comes with a non-2xx HTTP status, because the
// SDK adds -32005 to it. Such an answer fails the scan: failing closed is the
// safe choice when the server's answer is not a plain JSON-RPC error.
// jsonrpc.Error.Is compares only the code, so errors.Is finds such a code
// anywhere in the chain.
func tolerateUndeclared(err error, declared bool) error {
	if err == nil || declared || errors.Is(err, errLaterPage) || hasSDKErrorCode(err) {
		return err
	}
	var rpcErr *jsonrpc.Error
	if errors.As(err, &rpcErr) {
		return nil
	}
	return err
}

// hasSDKErrorCode reports whether err holds, anywhere in its chain, a
// *jsonrpc.Error with one of the sdkErrorCodes. jsonrpc.Error.Is compares only
// the code, so errors.Is with a bare &jsonrpc.Error{Code: code} finds it.
func hasSDKErrorCode(err error) bool {
	for _, code := range sdkErrorCodes {
		if errors.Is(err, &jsonrpc.Error{Code: code}) {
			return true
		}
	}
	return false
}

// isMethodNotFound reports whether err is a JSON-RPC "method not found" error
// (jsonrpc.CodeMethodNotFound, -32601) that the server sent for the first page
// of a list. It uses the same errors.Is code match as hasSDKErrorCode.
//
// It is false for an error on a later page (errLaterPage), because earlier
// pages held items that we must not drop. It is also false when the chain
// holds an SDK error code. For example, the SDK adds -32005 when the JSON-RPC
// error came with a non-2xx HTTP status. This is the same fail-closed choice
// as in tolerateUndeclared.
func isMethodNotFound(err error) bool {
	if err == nil || errors.Is(err, errLaterPage) || hasSDKErrorCode(err) {
		return false
	}
	return errors.Is(err, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound})
}

// listTools reads all pages of tools/list and converts the tools. It reads
// the raw tools of each page from raw (see listAll).
func listTools(ctx context.Context, cs sessionLister, raw *rawLists) ([]Tool, error) {
	return paginate(ctx, "tools",
		func(ctx context.Context, cursor string) ([]*mcp.Tool, string, error) {
			res, err := cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
			if err != nil {
				return nil, "", err
			}
			if res == nil {
				return nil, "", nil
			}
			page, ok := raw.take(res)
			if !ok {
				return nil, "", errRawListMissing
			}
			return page, res.NextCursor, nil
		},
		func(t *mcp.Tool) (Tool, error) {
			in, err := marshalSchema(t.InputSchema)
			if err != nil {
				return Tool{}, fmt.Errorf("input schema: %w", err)
			}
			out, err := marshalSchema(t.OutputSchema)
			if err != nil {
				return Tool{}, fmt.Errorf("output schema: %w", err)
			}
			return Tool{
				Name:         t.Name,
				Title:        t.Title,
				Description:  t.Description,
				InputSchema:  in,
				OutputSchema: out,
				Annotations:  toolAnnotations(t.Annotations),
			}, nil
		})
}

// toolAnnotations converts the SDK annotations of a tool. It returns nil when
// a is nil.
//
// The result never shares memory with a. The SDK owns its values, so every
// hint gets a new *bool. In SDK v1.8.0, ReadOnlyHint and IdempotentHint are
// plain bool, so absent and false look the same. For these two hints, the
// result is a pointer to true when the SDK has true, and nil when it has
// false (see ToolAnnotations). DestructiveHint and OpenWorldHint are *bool in
// the SDK, so nil stays nil and a set value is copied.
func toolAnnotations(a *mcp.ToolAnnotations) *ToolAnnotations {
	if a == nil {
		return nil
	}
	return &ToolAnnotations{
		Title:           a.Title,
		ReadOnlyHint:    trueOrNil(a.ReadOnlyHint),
		DestructiveHint: copyBool(a.DestructiveHint),
		IdempotentHint:  trueOrNil(a.IdempotentHint),
		OpenWorldHint:   copyBool(a.OpenWorldHint),
	}
}

// trueOrNil returns a new pointer to true when b is true, and nil when b is
// false.
func trueOrNil(b bool) *bool {
	if !b {
		return nil
	}
	v := true
	return &v
}

// copyBool returns a new pointer to the value of p, or nil when p is nil. The
// result never aliases p.
func copyBool(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// listPrompts reads all pages of prompts/list and converts the prompts.
func listPrompts(ctx context.Context, cs sessionLister) ([]Prompt, error) {
	return paginate(ctx, "prompts",
		func(ctx context.Context, cursor string) ([]*mcp.Prompt, string, error) {
			res, err := cs.ListPrompts(ctx, &mcp.ListPromptsParams{Cursor: cursor})
			if err != nil {
				return nil, "", err
			}
			if res == nil {
				return nil, "", nil
			}
			return res.Prompts, res.NextCursor, nil
		},
		func(p *mcp.Prompt) (Prompt, error) {
			prompt := Prompt{
				Name:        p.Name,
				Title:       p.Title,
				Description: p.Description,
			}
			for _, a := range p.Arguments {
				if a == nil {
					continue
				}
				prompt.Arguments = append(prompt.Arguments, PromptArgument{
					Name:        a.Name,
					Description: a.Description,
					Required:    a.Required,
				})
			}
			return prompt, nil
		})
}

// listResources reads all pages of resources/list and converts the resources.
func listResources(ctx context.Context, cs sessionLister) ([]Resource, error) {
	return paginate(ctx, "resources",
		func(ctx context.Context, cursor string) ([]*mcp.Resource, string, error) {
			res, err := cs.ListResources(ctx, &mcp.ListResourcesParams{Cursor: cursor})
			if err != nil {
				return nil, "", err
			}
			if res == nil {
				return nil, "", nil
			}
			return res.Resources, res.NextCursor, nil
		},
		func(r *mcp.Resource) (Resource, error) {
			return Resource{
				URI:         r.URI,
				Name:        r.Name,
				Title:       r.Title,
				Description: r.Description,
				MIMEType:    r.MIMEType,
			}, nil
		})
}

// listResourceTemplates reads all pages of resources/templates/list and
// converts the templates. It never expands a URI template and never fetches a
// resource.
func listResourceTemplates(ctx context.Context, cs templateLister) ([]ResourceTemplate, error) {
	return paginate(ctx, "resource templates",
		func(ctx context.Context, cursor string) ([]*mcp.ResourceTemplate, string, error) {
			res, err := cs.ListResourceTemplates(ctx, &mcp.ListResourceTemplatesParams{Cursor: cursor})
			if err != nil {
				return nil, "", err
			}
			if res == nil {
				return nil, "", nil
			}
			return res.ResourceTemplates, res.NextCursor, nil
		},
		func(r *mcp.ResourceTemplate) (ResourceTemplate, error) {
			return ResourceTemplate{
				URITemplate: r.URITemplate,
				Name:        r.Name,
				Title:       r.Title,
				Description: r.Description,
				MIMEType:    r.MIMEType,
			}, nil
		})
}

// paginate runs the cursor loop for one list and returns the converted items.
//
// S and T are type parameters (a Go "generic"). S is the SDK item type and T
// is our own type. One loop serves tools, prompts, resources and resource
// templates: the caller picks S and T, and the compiler checks that fetch and
// convert agree. what names the list ("tools") in error texts.
//
// fetch reads one page for a cursor and returns the items and the next
// cursor. An empty next cursor ends the loop. convert turns one non-nil SDK
// item into a T. paginate converts each page before it fetches the next one,
// so only the compact converted values stay in memory across pages. The
// decoded SDK page (with its schemas as any trees, many times larger than the
// wire bytes) can be collected at once.
//
// paginate fails when the list has more than maxPages pages or maxItems items,
// or when the server repeats a cursor. The item cap counts every item that
// the server sends, nil entries too, and paginate checks it before it converts
// a page. Error texts hold no cursor, because the server controls it.
//
// An error from fetch on a page after the first also wraps errLaterPage.
func paginate[S, T any](
	ctx context.Context,
	what string,
	fetch func(ctx context.Context, cursor string) (items []*S, next string, err error),
	convert func(*S) (T, error),
) ([]T, error) {
	all := []T{} // a list that the server answers empty is empty, not nil
	count := 0   // raw items seen so far, nil entries included
	seen := make(map[string]struct{})
	cursor := ""

	for page := 1; ; page++ {
		if page > maxPages {
			return nil, fmt.Errorf("list %s: more than %d pages: %w", what, maxPages, errTooManyPages)
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("list %s: %w", what, err)
		}

		items, next, err := fetch(ctx, cursor)
		if err != nil {
			if page > 1 {
				return nil, fmt.Errorf("list %s: %w: %w", what, errLaterPage, err)
			}
			return nil, fmt.Errorf("list %s: %w", what, err)
		}

		// Count before we convert, so a huge page cannot grow memory first.
		count += len(items)
		if count > maxItems {
			return nil, fmt.Errorf("list %s: more than %d items: %w", what, maxItems, errTooManyItems)
		}
		for _, item := range items {
			if item == nil { // server data may be odd: skip, never panic
				continue
			}
			v, err := convert(item)
			if err != nil {
				return nil, fmt.Errorf("list %s: %w", what, err)
			}
			all = append(all, v)
		}

		if next == "" {
			return all, nil
		}
		if _, dup := seen[next]; dup {
			return nil, fmt.Errorf("list %s: %w", what, errRepeatedCursor)
		}
		seen[next] = struct{}{}
		cursor = next
	}
}

// marshalSchema encodes a schema value as raw JSON. The SDK decodes the
// server's schema into an any, so this encodes it again. It returns nil for a
// nil value.
//
// The encoder does not escape HTML. json.Marshal would write "<", ">" and "&"
// as \u003c, \u003e and \u0026, and a rule that looks for a payload such as
// "<IMPORTANT>" in the schema text would miss it. Rules must see the text the
// server sent.
func marshalSchema(v any) (json.RawMessage, error) {
	if v == nil {
		return nil, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode adds a trailing newline. It is not part of the schema.
	return json.RawMessage(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))), nil
}
