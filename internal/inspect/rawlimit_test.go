package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// testRawLimit is the small raw size limit of these tests, so that they go
// over it without sending maxRawBytes through the SDK.
const testRawLimit = 16 << 10 // 16 KiB

// bigField is the size of the _meta value or icon source of one item. It is
// much larger than the names and descriptions, which listAll keeps, so these
// tests show that the limit counts the fields that listAll drops.
const bigField = 4 << 10 // 4 KiB

// poisonText stands for untrusted server text that must never reach an
// error text.
const poisonText = "HIDDEN-POISON"

// endlessPages returns a handler that counts its requests in calls and
// answers each one with page(next), where next is a new cursor each time.
// So only a limit of mcpmoat stops the listing.
func endlessPages(calls *atomic.Int64, page func(next string) mcp.Result) mcp.MethodHandler {
	return func(context.Context, string, mcp.Request) (mcp.Result, error) {
		n := calls.Add(1)
		return page("c" + strconv.FormatInt(n, 10)), nil
	}
}

func bigMeta() mcp.Meta {
	return mcp.Meta{"x": strings.Repeat("m", bigField)}
}

func bigIcons() []mcp.Icon {
	return []mcp.Icon{{Source: "data:image/png;base64," + strings.Repeat("A", bigField), MIMEType: "image/png"}}
}

// rawServer returns a server that declares tools, prompts and resources.
func rawServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "raw", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "t", InputSchema: objectSchema()}, noopTool)
	server.AddPrompt(&mcp.Prompt{Name: "p"}, noopPrompt)
	server.AddResource(&mcp.Resource{URI: "file:///r", Name: "r"}, noopResource)
	return server
}

// listWithLimit connects the stdio client with the raw size limit limit to
// server and lists everything with listAll.
func listWithLimit(t *testing.T, server *mcp.Server, limit int64) (tools []Tool, prompts []Prompt, resources []Resource, used int64, err error) {
	t.Helper()
	cs, raw, lim := connectStdio(t, server, limit)
	tools, prompts, resources, err = listAll(t.Context(), cs, cs.InitializeResult().Capabilities, raw)
	return tools, prompts, resources, lim.used.Load(), err
}

// TestRawLimitStopsEndlessPages checks that pages with large fields that
// listAll drops (_meta, icons) stop at the raw size limit, for each kind,
// long before maxPages.
func TestRawLimitStopsEndlessPages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		page   func(next string) mcp.Result
	}{
		{"tools _meta", "tools/list", func(next string) mcp.Result {
			return &mcp.ListToolsResult{Tools: []*mcp.Tool{{Meta: bigMeta(), Name: "t", InputSchema: objectSchema()}}, NextCursor: next}
		}},
		{"tools icons", "tools/list", func(next string) mcp.Result {
			return &mcp.ListToolsResult{Tools: []*mcp.Tool{{Icons: bigIcons(), Name: "t", InputSchema: objectSchema()}}, NextCursor: next}
		}},
		{"prompts _meta", "prompts/list", func(next string) mcp.Result {
			return &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{{Meta: bigMeta(), Name: "p"}}, NextCursor: next}
		}},
		{"prompts icons", "prompts/list", func(next string) mcp.Result {
			return &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{{Icons: bigIcons(), Name: "p"}}, NextCursor: next}
		}},
		{"resources _meta", "resources/list", func(next string) mcp.Result {
			return &mcp.ListResourcesResult{Resources: []*mcp.Resource{{Meta: bigMeta(), URI: "file:///r", Name: "r"}}, NextCursor: next}
		}},
		{"resources icons", "resources/list", func(next string) mcp.Result {
			return &mcp.ListResourcesResult{Resources: []*mcp.Resource{{Icons: bigIcons(), URI: "file:///r", Name: "r"}}, NextCursor: next}
		}},
		// listAll keeps the annotation title, but the limit must count it
		// all the same: a server can hide a large payload there.
		{"tools annotations title", "tools/list", func(next string) mcp.Result {
			return &mcp.ListToolsResult{Tools: []*mcp.Tool{{
				Name:        "t",
				InputSchema: objectSchema(),
				Annotations: &mcp.ToolAnnotations{Title: strings.Repeat("a", bigField)},
			}}, NextCursor: next}
		}},
	}
	// Each page has more than bigField bytes, so the limit is over after at
	// most this many pages. Without the limit, only maxPages would stop the
	// listing.
	const maxCalls = testRawLimit/bigField + 1

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int64
			server := rawServer()
			server.AddReceivingMiddleware(onMethod(tt.method, endlessPages(&calls, tt.page)))

			_, _, _, _, err := listWithLimit(t, server, testRawLimit)
			if !errors.Is(err, errRawTooLarge) {
				t.Fatalf("listAll() error = %v, want errRawTooLarge", err)
			}
			if n := calls.Load(); n < 2 || n > maxCalls {
				t.Errorf("%s requests = %d, want 2 to %d", tt.method, n, maxCalls)
			}
		})
	}
}

// TestRawLimitShared checks that the three kinds share one raw limit: the
// tools fit, but the tools and the prompts together do not.
func TestRawLimitShared(t *testing.T) {
	t.Parallel()

	var toolCalls, promptCalls atomic.Int64
	server := rawServer()
	server.AddReceivingMiddleware(
		// Three tool pages of about bigField each, then the end.
		onMethod("tools/list", func(context.Context, string, mcp.Request) (mcp.Result, error) {
			n := toolCalls.Add(1)
			next := ""
			if n < 3 {
				next = "c" + strconv.FormatInt(n, 10)
			}
			return &mcp.ListToolsResult{Tools: []*mcp.Tool{{Meta: bigMeta(), Name: "t", InputSchema: objectSchema()}}, NextCursor: next}, nil
		}),
		// One prompt page of about bigField: together over the limit.
		onMethod("prompts/list", func(context.Context, string, mcp.Request) (mcp.Result, error) {
			promptCalls.Add(1)
			return &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{{Meta: bigMeta(), Name: "p"}}}, nil
		}),
	)

	_, _, _, _, err := listWithLimit(t, server, testRawLimit)
	if !errors.Is(err, errRawTooLarge) {
		t.Fatalf("listAll() error = %v, want errRawTooLarge", err)
	}
	if !strings.Contains(err.Error(), "list prompts") {
		t.Errorf("listAll() error = %q, want it to name the prompts list", err)
	}
	if n := toolCalls.Load(); n != 3 {
		t.Errorf("tools/list requests = %d, want 3", n)
	}
	if n := promptCalls.Load(); n != 1 {
		t.Errorf("prompts/list requests = %d, want 1", n)
	}
}

// TestRawLimitUnderLimit checks that results with large fields pass when
// they stay under the limit together, and that the handshake counts too.
func TestRawLimitUnderLimit(t *testing.T) {
	t.Parallel()

	server := rawServer()
	server.AddReceivingMiddleware(
		onMethod("tools/list", func(context.Context, string, mcp.Request) (mcp.Result, error) {
			return &mcp.ListToolsResult{Tools: []*mcp.Tool{{Meta: bigMeta(), Name: "t", InputSchema: objectSchema()}}}, nil
		}),
		onMethod("prompts/list", func(context.Context, string, mcp.Request) (mcp.Result, error) {
			return &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{{Icons: bigIcons(), Name: "p"}}}, nil
		}),
		onMethod("resources/list", func(context.Context, string, mcp.Request) (mcp.Result, error) {
			return &mcp.ListResourcesResult{Resources: []*mcp.Resource{{Meta: bigMeta(), URI: "file:///r", Name: "r"}}}, nil
		}),
	)

	tools, prompts, resources, used, err := listWithLimit(t, server, testRawLimit)
	if err != nil {
		t.Fatalf("listAll() error = %v", err)
	}
	if len(tools) != 1 || len(prompts) != 1 || len(resources) != 1 {
		t.Errorf("listAll() = %d tools, %d prompts, %d resources, want 1 each", len(tools), len(prompts), len(resources))
	}
	if used < 3*bigField || used > testRawLimit {
		t.Errorf("used = %d, want %d to %d", used, 3*bigField, testRawLimit)
	}
}

// TestRawLimitHandshake checks that a large handshake result counts against
// the limit: instructions above the limit fail the connect. The SDK falls
// back from server/discover to initialize on any error, so the error of the
// connect need not wrap errRawTooLarge; rawLimit.exceeded tells.
func TestRawLimitHandshake(t *testing.T) {
	t.Parallel()

	server := mcp.NewServer(
		&mcp.Implementation{Name: "chatty", Version: "1"},
		&mcp.ServerOptions{Instructions: strings.Repeat("i", testRawLimit)},
	)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	lim := &rawLimit{limit: testRawLimit}
	cs, err := newStdioClient(&rawLists{}, lim).Connect(t.Context(), ct, nil)
	if err == nil {
		_ = cs.Close()
		t.Fatal("client.Connect() error = nil, want an error")
	}
	if !lim.exceeded() {
		t.Errorf("rawLimit.exceeded() = false after a handshake of %d bytes, want true", lim.used.Load())
	}
	ce := stdioFailure(stdioServer("/bin/true"), err, nil, lim.exceeded())
	if ce.Kind != KindTooLarge || !errors.Is(ce, errRawTooLarge) {
		t.Errorf("stdioFailure() = %v (kind %q), want KindTooLarge wrapping errRawTooLarge", ce, ce.Kind)
	}
}

// TestStdioFailureJSONShape checks stdioFailure for a JSON shape violation:
// KindTooLarge with the same fixed reason as for a remote server, the
// sentinel as the cause, and a context error of the chain kept in the cause.
// The shape violation also wins over the raw size limit.
func TestStdioFailureJSONShape(t *testing.T) {
	t.Parallel()
	closed := errors.New("connection closed: server text {},{},{}")
	tests := []struct {
		name     string
		err      error
		tooLarge bool
		wantCtx  error // context error that must stay in the chain, or nil
	}{
		{name: "shape violation", err: fmt.Errorf("%w: %w", errJSONTooComplex, closed)},
		{name: "shape violation over the raw limit too", err: fmt.Errorf("%w: %w", errJSONTooComplex, closed), tooLarge: true},
		{name: "shape violation and an ended ctx", err: fmt.Errorf("%w: %w: %w", context.DeadlineExceeded, errJSONTooComplex, closed), wantCtx: context.DeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ce := stdioFailure(stdioServer("/bin/true"), tt.err, nil, tt.tooLarge)
			if ce.Kind != KindTooLarge {
				t.Errorf("Kind = %q, want %q", ce.Kind, KindTooLarge)
			}
			if ce.Reason != jsonTooComplexReason {
				t.Errorf("Reason = %q, want %q", ce.Reason, jsonTooComplexReason)
			}
			if !errors.Is(ce, errJSONTooComplex) {
				t.Errorf("errors.Is(ce, errJSONTooComplex) = false: %v", ce)
			}
			if errors.Is(ce, closed) {
				t.Errorf("the cause holds the wrapped detail: %v", errors.Unwrap(ce))
			}
			if tt.wantCtx == nil {
				if cause := errors.Unwrap(ce); cause != errJSONTooComplex { //nolint:errorlint // identity check: the cause must be the sentinel itself
					t.Errorf("errors.Unwrap(ce) = %v, want errJSONTooComplex", cause)
				}
			} else if !errors.Is(ce, tt.wantCtx) {
				t.Errorf("errors.Is(ce, %v) = false, want the context error kept", tt.wantCtx)
			}
		})
	}
}

func TestRawLimitMiddleware(t *testing.T) {
	t.Parallel()

	page := &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{{Name: "p", Description: "d"}}}
	b, err := json.Marshal(page)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	size := int64(len(b))
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) { return page, nil }

	tests := []struct {
		name    string
		limit   int64
		pages   int  // pages before the one under test
		wantErr bool // false means the page passes
	}{
		{"first page under the limit", 2 * size, 0, false},
		{"exactly at the limit", 2 * size, 1, false},
		{"one byte over", 2*size - 1, 1, true},
		{"first page over", size - 1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := (&rawLimit{limit: tt.limit}).middleware(next)
			for range tt.pages {
				if _, err := h(t.Context(), "prompts/list", nil); err != nil {
					t.Fatalf("earlier page: error = %v", err)
				}
			}
			res, err := h(t.Context(), "prompts/list", nil)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("middleware error = %v, want nil", err)
				}
				if res != page {
					t.Errorf("middleware result = %#v, want the page unchanged", res)
				}
				return
			}
			if !errors.Is(err, errRawTooLarge) {
				t.Fatalf("middleware error = %v, want errRawTooLarge", err)
			}
			if res != nil {
				t.Errorf("middleware result = %#v, want nil", res)
			}
		})
	}
}

// TestRawLimitMiddlewareSkipsOtherResults checks that a result of another
// type passes unmeasured.
func TestRawLimitMiddlewareSkipsOtherResults(t *testing.T) {
	t.Parallel()

	other := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", 100)}}}
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) { return other, nil }

	lim := &rawLimit{limit: 1}
	res, err := lim.middleware(next)(t.Context(), "tools/call", nil)
	if err != nil || res != other {
		t.Errorf("middleware = %#v, %v, want the result unchanged", res, err)
	}
	if n := lim.used.Load(); n != 0 {
		t.Errorf("used = %d, want 0", n)
	}
}

// TestRawLimitNoHTMLEscape checks that "<", ">" and "&" count one byte each,
// as a server sends them. json.Marshal would write each one as a 6-byte
// escape, so this page would go over the limit.
func TestRawLimitNoHTMLEscape(t *testing.T) {
	t.Parallel()

	const markup = 1 << 10
	page := &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{{
		Name:        "p",
		Description: strings.Repeat("<>&", markup/3),
	}}}
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) { return page, nil }

	lim := &rawLimit{limit: 2 * markup}
	if _, err := lim.middleware(next)(t.Context(), "prompts/list", nil); err != nil {
		t.Fatalf("middleware error = %v, want nil", err)
	}
	if n := lim.used.Load(); n < markup || n > markup+100 {
		t.Errorf("used = %d, want about %d (no HTML escapes)", n, markup)
	}
}

func TestRawLimitMiddlewareMarshalError(t *testing.T) {
	t.Parallel()

	// A decoded page always encodes; a func value is the simplest way to
	// make the encoder fail. The key stands for server text.
	page := &mcp.ListToolsResult{Tools: []*mcp.Tool{{
		Name:        poisonText,
		InputSchema: map[string]any{poisonText: func() {}},
	}}}
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) { return page, nil }

	res, err := (&rawLimit{limit: maxRawBytes}).middleware(next)(t.Context(), "tools/list", nil)
	if !errors.Is(err, errRawTooLarge) {
		t.Fatalf("middleware error = %v, want errRawTooLarge", err)
	}
	if res != nil {
		t.Errorf("middleware result = %#v, want nil", res)
	}
	if strings.Contains(err.Error(), poisonText) {
		t.Errorf("middleware error = %q, must not contain server text", err)
	}
}

// TestRawLimitStopsEndlessTemplatePages checks that resource template pages
// count against the raw size limit, so listInto stops long before maxPages.
func TestRawLimitStopsEndlessTemplatePages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		page func(next string) mcp.Result
	}{
		{"templates _meta", func(next string) mcp.Result {
			return &mcp.ListResourceTemplatesResult{ResourceTemplates: []*mcp.ResourceTemplate{{
				Meta: bigMeta(), URITemplate: "file:///{name}", Name: "t",
			}}, NextCursor: next}
		}},
		{"templates description", func(next string) mcp.Result {
			return &mcp.ListResourceTemplatesResult{ResourceTemplates: []*mcp.ResourceTemplate{{
				URITemplate: "file:///{name}", Name: "t", Description: strings.Repeat("d", bigField),
			}}, NextCursor: next}
		}},
	}
	const maxCalls = testRawLimit/bigField + 1

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int64
			server := rawServer()
			server.AddReceivingMiddleware(onMethod("resources/templates/list", endlessPages(&calls, tt.page)))

			cs, raw, _ := connectStdio(t, server, testRawLimit)
			var result Result
			err := listInto(t.Context(), cs, cs.InitializeResult().Capabilities, raw, &result)
			if !errors.Is(err, errRawTooLarge) {
				t.Fatalf("listInto() error = %v, want errRawTooLarge", err)
			}
			if n := calls.Load(); n < 2 || n > maxCalls {
				t.Errorf("resources/templates/list requests = %d, want 2 to %d", n, maxCalls)
			}
		})
	}
}

// TestRawLimitMeasured checks which results rawLimit measures: every
// non-nil handshake and list result, and nothing else.
func TestRawLimitMeasured(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  mcp.Result
		want bool
	}{
		{"discover", &mcp.DiscoverResult{}, true},
		{"initialize", &mcp.InitializeResult{}, true},
		{"tools", &mcp.ListToolsResult{}, true},
		{"prompts", &mcp.ListPromptsResult{}, true},
		{"resources", &mcp.ListResourcesResult{}, true},
		{"resource templates", &mcp.ListResourceTemplatesResult{}, true},
		{"nil discover", (*mcp.DiscoverResult)(nil), false},
		{"nil initialize", (*mcp.InitializeResult)(nil), false},
		{"nil tools", (*mcp.ListToolsResult)(nil), false},
		{"nil prompts", (*mcp.ListPromptsResult)(nil), false},
		{"nil resources", (*mcp.ListResourcesResult)(nil), false},
		{"nil resource templates", (*mcp.ListResourceTemplatesResult)(nil), false},
		{"nil interface", nil, false},
		{"call tool", &mcp.CallToolResult{}, false},
		{"read resource", &mcp.ReadResourceResult{}, false},
		{"get prompt", &mcp.GetPromptResult{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := measured(tt.res); got != tt.want {
				t.Errorf("measured(%T) = %v, want %v", tt.res, got, tt.want)
			}
		})
	}
}

// TestRawLimitMiddlewareCountsTemplatesAndAnnotations checks that the
// middleware counts a resource templates result, and the annotation title of
// a tool, against the limit. Each pair has the same item with and without
// the large text: only the large one goes over.
func TestRawLimitMiddlewareCountsTemplatesAndAnnotations(t *testing.T) {
	t.Parallel()

	big := strings.Repeat("x", bigField)
	tests := []struct {
		name  string
		small mcp.Result
		large mcp.Result
	}{
		{
			name: "resource templates",
			small: &mcp.ListResourceTemplatesResult{ResourceTemplates: []*mcp.ResourceTemplate{{
				URITemplate: "file:///{name}", Name: "t",
			}}},
			large: &mcp.ListResourceTemplatesResult{ResourceTemplates: []*mcp.ResourceTemplate{{
				URITemplate: "file:///{name}", Name: "t", Description: big,
			}}},
		},
		{
			name: "tool annotations title",
			small: &mcp.ListToolsResult{Tools: []*mcp.Tool{{
				Name: "t", InputSchema: objectSchema(),
				Annotations: &mcp.ToolAnnotations{Title: "T"},
			}}},
			large: &mcp.ListToolsResult{Tools: []*mcp.Tool{{
				Name: "t", InputSchema: objectSchema(),
				Annotations: &mcp.ToolAnnotations{Title: big},
			}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			smallSize, err := jsonSize(tt.small)
			if err != nil {
				t.Fatalf("jsonSize(small) error = %v", err)
			}
			// Room for the small result and half of the large text.
			limit := smallSize + bigField/2

			small := &rawLimit{limit: limit}
			if _, err := small.middleware(func(context.Context, string, mcp.Request) (mcp.Result, error) {
				return tt.small, nil
			})(t.Context(), "", nil); err != nil {
				t.Fatalf("small result: middleware error = %v, want nil", err)
			}
			if n := small.used.Load(); n != smallSize {
				t.Errorf("small result: used = %d, want %d", n, smallSize)
			}

			large := &rawLimit{limit: limit}
			res, err := large.middleware(func(context.Context, string, mcp.Request) (mcp.Result, error) {
				return tt.large, nil
			})(t.Context(), "", nil)
			if !errors.Is(err, errRawTooLarge) {
				t.Fatalf("large result: middleware error = %v, want errRawTooLarge", err)
			}
			if res != nil {
				t.Errorf("large result: middleware result = %#v, want nil", res)
			}
			if !large.exceeded() {
				t.Error("large result: exceeded() = false, want true")
			}
		})
	}
}
