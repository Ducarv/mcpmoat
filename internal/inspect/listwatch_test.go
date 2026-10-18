package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectWatched connects a client, made with the same constructor as
// Inspect (newWatchedClient) and the raw byte limit of Inspect, to server
// over in-memory transports. No process and no network are involved.
// t.Cleanup closes both sessions.
func connectWatched(t *testing.T, server *mcp.Server) (*mcp.ClientSession, *listWatch) {
	t.Helper()
	return connectWatchedLimit(t, server, maxRawBytes)
}

// connectWatchedLimit is connectWatched with the raw byte limit rawLimit.
func connectWatchedLimit(t *testing.T, server *mcp.Server, rawLimit int64) (*mcp.ClientSession, *listWatch) {
	t.Helper()
	client, w := New(Options{}).newWatchedClient(rawLimit)
	return connectClient(t, server, client), w
}

// headerSchema returns an object input schema with one property p of type
// typ that carries the x-mcp-header annotation header.
func headerSchema(typ string, header any) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"p": map[string]any{"type": typ, "x-mcp-header": header},
		},
	}
}

// pagedTools returns a tools/list handler that answers with pages, one page
// for each request. The cursor of page n is "p<n>"; the last page has no
// next cursor.
func pagedTools(pages ...[]*mcp.Tool) mcp.MethodHandler {
	return func(_ context.Context, _ string, req mcp.Request) (mcp.Result, error) {
		n := 0
		if p, ok := req.GetParams().(*mcp.ListToolsParams); ok && p != nil && p.Cursor != "" {
			if _, err := fmt.Sscanf(p.Cursor, "p%d", &n); err != nil {
				return nil, fmt.Errorf("bad cursor: %w", err)
			}
		}
		if n >= len(pages) {
			return nil, errors.New("no such page")
		}
		next := ""
		if n+1 < len(pages) {
			next = fmt.Sprintf("p%d", n+1)
		}
		return &mcp.ListToolsResult{Tools: pages[n], NextCursor: next}, nil
	}
}

// poisonText is text in the refused tools that must never reach an error text:
// it stands for untrusted server text.
const poisonText = "HIDDEN-POISON"

// validTool returns a tool that the SDK accepts.
func validTool(name string) *mcp.Tool {
	return &mcp.Tool{Name: name, InputSchema: objectSchema()}
}

func TestInspectWatchedDroppedTools(t *testing.T) {
	t.Parallel()

	// Each refused tool is invalid for one reason that filterValidTools
	// checks in SDK v1.8.0 (streamable_headers.go).
	nonPrimitive := &mcp.Tool{Name: poisonText, Description: poisonText, InputSchema: headerSchema("object", "X-"+poisonText)}
	emptyHeader := &mcp.Tool{Name: poisonText, InputSchema: headerSchema("string", "")}
	notString := &mcp.Tool{Name: poisonText, InputSchema: headerSchema("string", 42)}
	badChar := &mcp.Tool{Name: poisonText, InputSchema: headerSchema("string", "X "+poisonText)}
	duplicate := &mcp.Tool{Name: poisonText, InputSchema: map[string]any{
		"type": "object",
		"properties": map[string]any{
			"a": map[string]any{"type": "string", "x-mcp-header": "X-" + poisonText},
			"b": map[string]any{"type": "string", "x-mcp-header": "x-" + strings.ToLower(poisonText)},
		},
	}}
	nested := &mcp.Tool{Name: poisonText, InputSchema: map[string]any{
		"type": "object",
		"properties": map[string]any{
			"outer": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"inner": map[string]any{"type": "array", "x-mcp-header": "X-" + poisonText},
				},
			},
		},
	}}

	tests := []struct {
		name        string
		pages       [][]*mcp.Tool
		wantDropped int
	}{
		{"header on non-primitive", [][]*mcp.Tool{{validTool("ok"), nonPrimitive}}, 1},
		{"empty header name", [][]*mcp.Tool{{emptyHeader, validTool("ok")}}, 1},
		{"header name not a string", [][]*mcp.Tool{{validTool("ok"), notString}}, 1},
		{"invalid header character", [][]*mcp.Tool{{validTool("ok"), badChar}}, 1},
		{"duplicate header name", [][]*mcp.Tool{{validTool("ok"), duplicate}}, 1},
		{"nested header on array", [][]*mcp.Tool{{validTool("ok"), nested}}, 1},
		{"nil tool", [][]*mcp.Tool{{validTool("ok"), nil}}, 1},
		{"only refused tools", [][]*mcp.Tool{{nonPrimitive, badChar}}, 2},
		{"drops on a later page", [][]*mcp.Tool{{validTool("a")}, {validTool("b"), duplicate, nil}, {validTool("c")}}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := mcp.NewServer(&mcp.Implementation{Name: "dropper", Version: "1"}, nil)
			server.AddTool(validTool("ok"), noopTool) // advertises the tools capability
			server.AddReceivingMiddleware(onMethod("tools/list", pagedTools(tt.pages...)))

			cs, w := connectWatched(t, server)

			got, err := inspectWatched(t.Context(), cs, w)
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("inspectWatched() error = %v, want ErrProtocol; "+
					"did the SDK stop filtering tools in ListTools, or filter before the sending middleware?", err)
			}
			if errors.Is(err, ErrTooManyItems) {
				t.Errorf("inspectWatched() error = %v, must not wrap ErrTooManyItems", err)
			}
			if !reflect.DeepEqual(got, Result{}) {
				t.Errorf("inspectWatched() result = %+v, want zero Result", got)
			}
			want := fmt.Sprintf("server sent %d tools that the MCP SDK refused", tt.wantDropped)
			if !strings.Contains(err.Error(), want) {
				t.Errorf("inspectWatched() error = %q, want it to contain %q", err, want)
			}
			if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(poisonText)) {
				t.Errorf("inspectWatched() error = %q, must not contain server text", err)
			}
		})
	}
}

// TestSDKStillDropsTools documents the SDK behavior that listWatch exists
// for: without the watch, the refused tool is silently gone. If this test
// fails after an SDK upgrade, the SDK no longer drops such tools: check
// listWatch and the "Known limits" in doc.go again.
func TestSDKStillDropsTools(t *testing.T) {
	t.Parallel()

	server := mcp.NewServer(&mcp.Implementation{Name: "dropper", Version: "1"}, nil)
	server.AddTool(validTool("ok"), noopTool)
	server.AddReceivingMiddleware(onMethod("tools/list", pagedTools(
		[]*mcp.Tool{validTool("ok"), {Name: poisonText, InputSchema: headerSchema("object", "X-P")}},
	)))

	cs := connectInMemory(t, server)

	got, err := inspectSession(t.Context(), cs)
	if err != nil {
		t.Fatalf("inspectSession() error = %v", err)
	}
	if len(got.Tools) != 1 || got.Tools[0].Name != "ok" {
		t.Errorf("Tools = %+v, want only the tool %q (the SDK drops the other one)", got.Tools, "ok")
	}
}

func TestInspectWatchedValidTools(t *testing.T) {
	t.Parallel()

	// A valid x-mcp-header annotation must not count as a drop.
	withHeader := &mcp.Tool{Name: "with-header", InputSchema: headerSchema("string", "X-Region")}

	tests := []struct {
		name      string
		pages     [][]*mcp.Tool
		wantNames []string
	}{
		{"one page", [][]*mcp.Tool{{validTool("a"), withHeader}}, []string{"a", "with-header"}},
		{"two pages", [][]*mcp.Tool{{validTool("a")}, {validTool("b")}}, []string{"a", "b"}},
		{"empty page", [][]*mcp.Tool{{}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := mcp.NewServer(&mcp.Implementation{Name: "valid", Version: "1"}, nil)
			server.AddTool(validTool("ok"), noopTool)
			server.AddReceivingMiddleware(onMethod("tools/list", pagedTools(tt.pages...)))

			cs, w := connectWatched(t, server)

			got, err := inspectWatched(t.Context(), cs, w)
			if err != nil {
				t.Fatalf("inspectWatched() error = %v", err)
			}
			var names []string
			for _, tool := range got.Tools {
				names = append(names, tool.Name)
			}
			if !reflect.DeepEqual(names, tt.wantNames) {
				t.Errorf("tool names = %q, want %q", names, tt.wantNames)
			}
		})
	}
}

func TestInspectWatchedNoToolsCapability(t *testing.T) {
	t.Parallel()

	// A server without tools is never asked for tools/list.
	server := mcp.NewServer(&mcp.Implementation{Name: "prompts", Version: "1"}, nil)
	server.AddPrompt(&mcp.Prompt{Name: "p"}, noopPrompt)

	cs, w := connectWatched(t, server)

	got, err := inspectWatched(t.Context(), cs, w)
	if err != nil {
		t.Fatalf("inspectWatched() error = %v", err)
	}
	if got.Tools != nil {
		t.Errorf("Tools = %+v, want nil", got.Tools)
	}
	if n := w.sentTools.Load(); n != 0 {
		t.Errorf("sentTools = %d, want 0", n)
	}
}

func TestListWatchMiddleware(t *testing.T) {
	t.Parallel()

	errNext := errors.New("next failed")

	tests := []struct {
		name      string
		res       mcp.Result
		err       error
		wantTools int64
		// wantRaw is true when the middleware must add the JSON size of
		// res to rawBytes.
		wantRaw bool
	}{
		{"tools page", &mcp.ListToolsResult{Tools: []*mcp.Tool{validTool("a"), nil, validTool("b")}}, nil, 3, true},
		{"empty tools page", &mcp.ListToolsResult{}, nil, 0, true},
		{"prompts page", &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{{Name: "p"}}}, nil, 0, true},
		{"resources page", &mcp.ListResourcesResult{Resources: []*mcp.Resource{{URI: "file:///x"}}}, nil, 0, true},
		{"nil tools result", (*mcp.ListToolsResult)(nil), nil, 0, false},
		{"nil prompts result", (*mcp.ListPromptsResult)(nil), nil, 0, false},
		{"nil resources result", (*mcp.ListResourcesResult)(nil), nil, 0, false},
		{"nil result", nil, nil, 0, false},
		// Results that are not list pages are not measured or counted.
		{"call tool result", &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "x"}}}, nil, 0, false},
		{"get prompt result", &mcp.GetPromptResult{Description: "d"}, nil, 0, false},
		{"initialize result", &mcp.InitializeResult{Instructions: "i"}, nil, 0, false},
		{"resource templates page", &mcp.ListResourceTemplatesResult{
			ResourceTemplates: []*mcp.ResourceTemplate{{URITemplate: "file:///{x}"}},
		}, nil, 0, false},
		{"error", &mcp.ListToolsResult{Tools: []*mcp.Tool{validTool("a")}}, errNext, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newListWatch(maxRawBytes)
			next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
				return tt.res, tt.err
			}
			res, err := w.middleware(next)(t.Context(), "tools/list", nil)
			if !errors.Is(err, tt.err) || (tt.err == nil && err != nil) {
				t.Errorf("middleware error = %v, want %v", err, tt.err)
			}
			// The middleware passes the result on unchanged.
			if !reflect.DeepEqual(res, tt.res) {
				t.Errorf("middleware result = %#v, want %#v", res, tt.res)
			}
			if got := w.sentTools.Load(); got != tt.wantTools {
				t.Errorf("sentTools = %d, want %d", got, tt.wantTools)
			}
			var wantRaw int64
			if tt.wantRaw {
				b, err := json.Marshal(tt.res)
				if err != nil {
					t.Fatalf("json.Marshal() error = %v", err)
				}
				wantRaw = int64(len(b))
			}
			if got := w.rawBytes.Load(); got != wantRaw {
				t.Errorf("rawBytes = %d, want %d", got, wantRaw)
			}
		})
	}
}

func TestListWatchCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		sent        int64
		kept        int
		wantDropped int // 0 means no error
	}{
		{"nothing sent", 0, 0, 0},
		{"all kept", 5, 5, 0},
		{"one dropped", 5, 4, 1},
		{"all dropped", 3, 0, 3},
		{"more kept than sent (cache hit)", 1, 2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newListWatch(maxRawBytes)
			w.sentTools.Store(tt.sent)
			err := w.check(tt.kept)
			if tt.wantDropped == 0 {
				if err != nil {
					t.Errorf("check(%d) error = %v, want nil", tt.kept, err)
				}
				return
			}
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("check(%d) error = %v, want ErrProtocol", tt.kept, err)
			}
			want := fmt.Sprintf("server sent %d tools that the MCP SDK refused", tt.wantDropped)
			if !strings.Contains(err.Error(), want) {
				t.Errorf("check(%d) error = %q, want it to contain %q", tt.kept, err, want)
			}
		})
	}
}
