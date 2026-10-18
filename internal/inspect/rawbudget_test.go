package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// testRawLimit is the small raw byte limit of these tests, so that they go
// over it without sending maxRawBytes through the SDK.
const testRawLimit = 16 << 10 // 16 KiB

// bigField is the size of the _meta value or icon source of one item. It is
// much larger than the names and descriptions, so the byte budget of collect
// (which does not count _meta or icons) stays far from its limit.
const bigField = 4 << 10 // 4 KiB

// onMethod returns a receiving middleware that answers method with h and
// passes every other method on.
func onMethod(method string, h mcp.MethodHandler) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, m string, req mcp.Request) (mcp.Result, error) {
			if m == method {
				return h(ctx, m, req)
			}
			return next(ctx, m, req)
		}
	}
}

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

// rawServer returns a server that advertises tools, prompts and resources.
func rawServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "raw", Version: "1"}, nil)
	server.AddTool(valid("t"), noopTool)
	server.AddPrompt(&mcp.Prompt{Name: "p"}, noopPrompt)
	server.AddResource(&mcp.Resource{URI: "file:///r", Name: "r"}, noopResource)
	return server
}

func TestInspectWatchedRawLimit(t *testing.T) {
	t.Parallel()

	toolsMeta := func(next string) mcp.Result {
		return &mcp.ListToolsResult{Tools: []*mcp.Tool{{
			Meta: bigMeta(), Name: "t", InputSchema: map[string]any{"type": "object"},
		}}, NextCursor: next}
	}
	toolsIcons := func(next string) mcp.Result {
		return &mcp.ListToolsResult{Tools: []*mcp.Tool{{
			Icons: bigIcons(), Name: "t", InputSchema: map[string]any{"type": "object"},
		}}, NextCursor: next}
	}
	promptsMeta := func(next string) mcp.Result {
		return &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{{Meta: bigMeta(), Name: "p"}}, NextCursor: next}
	}
	promptsIcons := func(next string) mcp.Result {
		return &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{{Icons: bigIcons(), Name: "p"}}, NextCursor: next}
	}
	resourcesMeta := func(next string) mcp.Result {
		return &mcp.ListResourcesResult{Resources: []*mcp.Resource{{Meta: bigMeta(), URI: "file:///r", Name: "r"}}, NextCursor: next}
	}
	resourcesIcons := func(next string) mcp.Result {
		return &mcp.ListResourcesResult{Resources: []*mcp.Resource{{Icons: bigIcons(), URI: "file:///r", Name: "r"}}, NextCursor: next}
	}

	tests := []struct {
		name   string
		method string
		page   func(next string) mcp.Result
	}{
		{"tools _meta", "tools/list", toolsMeta},
		{"tools icons", "tools/list", toolsIcons},
		{"prompts _meta", "prompts/list", promptsMeta},
		{"prompts icons", "prompts/list", promptsIcons},
		{"resources _meta", "resources/list", resourcesMeta},
		{"resources icons", "resources/list", resourcesIcons},
	}
	// Each page has more than bigField bytes, so the limit is over after at
	// most this many pages. Without the limit, only maxPages would stop
	// the listing.
	const maxCalls = testRawLimit/bigField + 1

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int64
			server := rawServer()
			server.AddReceivingMiddleware(onMethod(tt.method, endlessPages(&calls, tt.page)))

			cs, w := connectWatchedLimit(t, server, testRawLimit)

			got, err := inspectWatched(t.Context(), cs, w)
			if !errors.Is(err, ErrTooManyItems) {
				t.Fatalf("inspectWatched() error = %v, want ErrTooManyItems", err)
			}
			if errors.Is(err, ErrProtocol) {
				t.Errorf("inspectWatched() error = %v, must not wrap ErrProtocol", err)
			}
			if !reflect.DeepEqual(got, Result{}) {
				t.Errorf("inspectWatched() result = %+v, want zero Result", got)
			}
			want := "server sent more than " + strconv.Itoa(testRawLimit) + " bytes of list data"
			if !strings.Contains(err.Error(), want) {
				t.Errorf("inspectWatched() error = %q, want it to contain %q", err, want)
			}
			if n := calls.Load(); n < 2 || n > maxCalls {
				t.Errorf("%s requests = %d, want 2 to %d", tt.method, n, maxCalls)
			}
		})
	}
}

// TestInspectWatchedRawLimitShared checks that the three kinds share one
// raw limit: the tools fit, but the tools and the prompts together do not.
func TestInspectWatchedRawLimitShared(t *testing.T) {
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
			return &mcp.ListToolsResult{Tools: []*mcp.Tool{{
				Meta: bigMeta(), Name: "t", InputSchema: map[string]any{"type": "object"},
			}}, NextCursor: next}, nil
		}),
		// One prompt page of about bigField: together over the limit.
		onMethod("prompts/list", func(context.Context, string, mcp.Request) (mcp.Result, error) {
			promptCalls.Add(1)
			return &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{{Meta: bigMeta(), Name: "p"}}}, nil
		}),
	)

	cs, w := connectWatchedLimit(t, server, testRawLimit)

	got, err := inspectWatched(t.Context(), cs, w)
	if !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("inspectWatched() error = %v, want ErrTooManyItems", err)
	}
	if !strings.Contains(err.Error(), "list prompts") {
		t.Errorf("inspectWatched() error = %q, want it to name the prompts list", err)
	}
	if !reflect.DeepEqual(got, Result{}) {
		t.Errorf("inspectWatched() result = %+v, want zero Result", got)
	}
	if n := toolCalls.Load(); n != 3 {
		t.Errorf("tools/list requests = %d, want 3", n)
	}
	if n := promptCalls.Load(); n != 1 {
		t.Errorf("prompts/list requests = %d, want 1", n)
	}
}

func TestInspectWatchedUnderRawLimit(t *testing.T) {
	t.Parallel()

	// One page of each kind, each with a big _meta or icons, under the
	// limit together.
	server := rawServer()
	server.AddReceivingMiddleware(
		onMethod("tools/list", func(context.Context, string, mcp.Request) (mcp.Result, error) {
			return &mcp.ListToolsResult{Tools: []*mcp.Tool{{
				Meta: bigMeta(), Name: "t", InputSchema: map[string]any{"type": "object"},
			}}}, nil
		}),
		onMethod("prompts/list", func(context.Context, string, mcp.Request) (mcp.Result, error) {
			return &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{{Icons: bigIcons(), Name: "p"}}}, nil
		}),
		onMethod("resources/list", func(context.Context, string, mcp.Request) (mcp.Result, error) {
			return &mcp.ListResourcesResult{Resources: []*mcp.Resource{{Meta: bigMeta(), URI: "file:///r", Name: "r"}}}, nil
		}),
	)

	cs, w := connectWatchedLimit(t, server, testRawLimit)

	got, err := inspectWatched(t.Context(), cs, w)
	if err != nil {
		t.Fatalf("inspectWatched() error = %v", err)
	}
	if len(got.Tools) != 1 || len(got.Prompts) != 1 || len(got.Resources) != 1 {
		t.Errorf("inspectWatched() = %d tools, %d prompts, %d resources, want 1 each",
			len(got.Tools), len(got.Prompts), len(got.Resources))
	}
	if n := w.rawBytes.Load(); n < 3*bigField || n > testRawLimit {
		t.Errorf("rawBytes = %d, want %d to %d", n, 3*bigField, testRawLimit)
	}
}

func TestListWatchMiddlewareRawLimit(t *testing.T) {
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
		pages   int   // pages before the one under test
		wantErr error // nil means the page passes
	}{
		{"first page under the limit", 2 * size, 0, nil},
		{"exactly at the limit", 2 * size, 1, nil},
		{"one byte over", 2*size - 1, 1, ErrTooManyItems},
		{"first page over", size - 1, 0, ErrTooManyItems},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newListWatch(tt.limit)
			h := w.middleware(next)
			for range tt.pages {
				if _, err := h(t.Context(), "prompts/list", nil); err != nil {
					t.Fatalf("earlier page: error = %v", err)
				}
			}
			res, err := h(t.Context(), "prompts/list", nil)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("middleware error = %v, want nil", err)
				}
				if res != page {
					t.Errorf("middleware result = %#v, want the page unchanged", res)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("middleware error = %v, want %v", err, tt.wantErr)
			}
			if errors.Is(err, ErrProtocol) {
				t.Errorf("middleware error = %v, must not wrap ErrProtocol", err)
			}
			if res != nil {
				t.Errorf("middleware result = %#v, want nil", res)
			}
		})
	}
}

func TestListWatchMiddlewareMarshalError(t *testing.T) {
	t.Parallel()

	// A decoded page always marshals; a func value is the simplest way to
	// make json.Marshal fail. The key stands for server text.
	page := &mcp.ListToolsResult{Tools: []*mcp.Tool{{
		Name:        secret,
		InputSchema: map[string]any{secret: func() {}},
	}}}
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) { return page, nil }

	w := newListWatch(maxRawBytes)
	res, err := w.middleware(next)(t.Context(), "tools/list", nil)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("middleware error = %v, want ErrProtocol", err)
	}
	if res != nil {
		t.Errorf("middleware result = %#v, want nil", res)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("middleware error = %q, must not contain server text", err)
	}
	if n := w.sentTools.Load(); n != 0 {
		t.Errorf("sentTools = %d, want 0", n)
	}
}
