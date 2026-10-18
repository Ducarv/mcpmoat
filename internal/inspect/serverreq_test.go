package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeResult is the result that the next handler of the middleware tests
// returns, so that a test can see that the middleware passed it on.
type fakeResult struct{ mcp.Result }

// assertMethodNotFound fails t when err is not a JSON-RPC "method not found"
// error.
func assertMethodNotFound(t *testing.T, err error) {
	t.Helper()
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) {
		t.Fatalf("error = %v (%T), want a *jsonrpc.Error", err, err)
	}
	if werr.Code != jsonrpc.CodeMethodNotFound {
		t.Errorf("error code = %d, want %d (method not found)", werr.Code, jsonrpc.CodeMethodNotFound)
	}
}

func TestRefuseServerRequests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method   string
		wantNext bool
	}{
		// Allowed: ping and the harmless notifications.
		{method: "ping", wantNext: true},
		{method: "notifications/cancelled", wantNext: true},
		{method: "notifications/tools/list_changed", wantNext: true},
		{method: "notifications/prompts/list_changed", wantNext: true},
		{method: "notifications/resources/list_changed", wantNext: true},
		{method: "notifications/resources/updated", wantNext: true},
		{method: "notifications/message", wantNext: true},
		{method: "notifications/progress", wantNext: true},
		{method: "notifications/subscriptions/acknowledged", wantNext: true},

		// Refused: every request that the SDK client knows, except ping.
		{method: "completion/complete"},
		{method: "roots/list"},
		{method: "sampling/createMessage"},
		{method: "elicitation/create"},

		// Refused: the notification whose SDK handler can panic.
		{method: "notifications/elicitation/complete"},

		// Refused: unknown methods, also look-alikes of allowed ones.
		{method: "x/unknown"},
		{method: "notifications/x"},
		{method: "tools/list"},
		{method: ""},
		{method: "Ping"},
		{method: "ping "},
		{method: "notifications/"},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()

			var calls int
			want := &fakeResult{}
			next := func(_ context.Context, method string, _ mcp.Request) (mcp.Result, error) {
				calls++
				if method != tt.method {
					t.Errorf("next got method %q, want %q", method, tt.method)
				}
				return want, nil
			}

			// The request is nil: the middleware must not read it.
			res, err := refuseServerRequests(next)(t.Context(), tt.method, nil)

			if !tt.wantNext {
				if calls != 0 {
					t.Errorf("next called %d times, want 0", calls)
				}
				if res != nil {
					t.Errorf("result = %v, want nil", res)
				}
				assertMethodNotFound(t, err)
				return
			}
			if calls != 1 {
				t.Errorf("next called %d times, want 1", calls)
			}
			if err != nil {
				t.Errorf("error = %v, want nil", err)
			}
			if res != want {
				t.Errorf("result = %v, want the result of next", res)
			}
		})
	}
}

// TestRefuseServerRequestsErrorNotShared checks that each refusal returns a
// new error value, so that no caller can change the error of another.
func TestRefuseServerRequestsErrorNotShared(t *testing.T) {
	t.Parallel()

	h := refuseServerRequests(func(context.Context, string, mcp.Request) (mcp.Result, error) {
		t.Fatal("next called")
		return nil, nil
	})
	_, err1 := h(t.Context(), "roots/list", nil)
	_, err2 := h(t.Context(), "roots/list", nil)
	var w1, w2 *jsonrpc.Error
	if !errors.As(err1, &w1) || !errors.As(err2, &w2) {
		t.Fatalf("errors = %v, %v, want two *jsonrpc.Error", err1, err2)
	}
	if w1 == w2 {
		t.Error("two refusals returned the same *jsonrpc.Error")
	}
}

// TestServerPingSDK connects a real SDK server to the client of Inspect
// (newClient) in memory. The server pings the client after the handshake:
// the middleware must pass ping on, and the client must send nothing back
// except the handshake.
//
// The SDK server API for roots/list (ServerSession.ListRoots) is deprecated,
// so the linter refuses it. TestServerRequestsRefusedRaw sends roots/list
// and the other refused requests on a raw connection instead.
func TestServerPingSDK(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var mu sync.Mutex
	var received []string
	server := mcp.NewServer(&mcp.Implementation{Name: "caller", Version: "1"}, nil)
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			mu.Lock()
			received = append(received, method)
			mu.Unlock()
			return next(ctx, method, req)
		}
	})

	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	cs, err := newStdioClient(&rawLists{}, &rawLimit{limit: maxRawBytes}).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	if err := ss.Ping(ctx, nil); err != nil {
		t.Errorf("Ping() error = %v, want nil", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, m := range received {
		switch m {
		case "server/discover", "initialize", "notifications/initialized":
			// The handshake. The SDK client tries server/discover first.
		default:
			t.Errorf("server received %q from the client, want only the handshake", m)
		}
	}
}

// The request IDs of TestServerRequestsRefusedRaw, one for each request.
const (
	rawIDComplete = iota + 1
	rawIDRoots
	rawIDSampling
	rawIDElicit
	rawIDUnknown
	rawIDPing
)

// TestServerRequestsRefusedRaw plays a hostile server on a raw in-memory
// connection, so that it can send requests that the SDK server API cannot
// send (completion/complete to a client, unknown methods, a notification
// without its params). It checks the answer to each request, and that the
// client never sends a request back to the server.
func TestServerRequestsRefusedRaw(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	ct, st := mcp.NewInMemoryTransports()
	conn, err := st.Connect(ctx)
	if err != nil {
		t.Fatalf("server transport Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	// A Read does not end with ctx; closing the connection ends it.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	// The handshake runs in its own goroutine: client.Connect waits for the
	// answer to initialize, which the test writes below.
	type connected struct {
		cs  *mcp.ClientSession
		err error
	}
	done := make(chan connected, 1)
	go func() {
		cs, err := newStdioClient(&rawLists{}, &rawLimit{limit: maxRawBytes}).Connect(ctx, ct, nil)
		done <- connected{cs, err}
	}()

	rawHandshake(ctx, t, conn)
	c := <-done
	if c.err != nil {
		t.Fatalf("client.Connect() error = %v", c.err)
	}
	t.Cleanup(func() { _ = c.cs.Close() })

	completeParams := `{"ref":{"type":"ref/prompt","name":"p"},"argument":{"name":"a","value":"v"}}`
	send := []*jsonrpc.Request{
		rawCall(t, rawIDComplete, "completion/complete", completeParams),
		rawCall(t, rawIDRoots, "roots/list", ""),
		rawCall(t, rawIDSampling, "sampling/createMessage", `{"messages":[],"maxTokens":1}`),
		rawCall(t, rawIDElicit, "elicitation/create", `{"message":"m","requestedSchema":{"type":"object"}}`),
		rawCall(t, rawIDUnknown, "x/unknown", `{}`),
		// No params: the SDK handler of this notification would panic.
		{Method: "notifications/elicitation/complete"},
		// The client handles requests in order, so the answer to ping
		// comes after the notification above was handled.
		rawCall(t, rawIDPing, "ping", ""),
	}
	for _, msg := range send {
		if err := conn.Write(ctx, msg); err != nil {
			t.Fatalf("Write(%s) error = %v", msg.Method, err)
		}
	}

	answers := map[int64]*jsonrpc.Response{}
	for len(answers) < rawIDPing {
		msg, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("Read() error = %v; answers so far: %d", err, len(answers))
		}
		switch m := msg.(type) {
		case *jsonrpc.Request:
			t.Errorf("client sent %q to the server, want no request", m.Method)
		case *jsonrpc.Response:
			id, ok := m.ID.Raw().(int64)
			if !ok {
				t.Fatalf("response ID = %v (%T), want an int64", m.ID.Raw(), m.ID.Raw())
			}
			answers[id] = m
		}
	}

	for _, id := range []int64{rawIDComplete, rawIDRoots, rawIDSampling, rawIDElicit, rawIDUnknown} {
		r := answers[id]
		if r == nil {
			t.Errorf("no answer for ID %d", id)
			continue
		}
		if len(r.Result) != 0 {
			t.Errorf("ID %d: result = %s, want none", id, r.Result)
		}
		assertMethodNotFound(t, r.Error)
	}
	if r := answers[rawIDPing]; r == nil || r.Error != nil {
		t.Errorf("ping answer = %+v, want a result without error", r)
	}
}

// rawCall returns a JSON-RPC request with the ID id. Empty params means no
// params.
func rawCall(t *testing.T, id int64, method, params string) *jsonrpc.Request {
	t.Helper()
	jid, err := jsonrpc.MakeID(float64(id))
	if err != nil {
		t.Fatalf("MakeID(%d) error = %v", id, err)
	}
	req := &jsonrpc.Request{ID: jid, Method: method}
	if params != "" {
		req.Params = json.RawMessage(params)
	}
	return req
}

// rawHandshake plays the server side of the handshake on conn. The SDK
// client first tries server/discover (the stateless protocol); rawHandshake
// refuses it, so that the client falls back to initialize. It answers
// initialize, and reads the notifications/initialized that follows.
func rawHandshake(ctx context.Context, t *testing.T, conn mcp.Connection) {
	t.Helper()

	msg, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read first message: %v", err)
	}
	if req, ok := msg.(*jsonrpc.Request); ok && req.Method == "server/discover" {
		refuse := &jsonrpc.Response{
			ID:    req.ID,
			Error: &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not found"},
		}
		if err := conn.Write(ctx, refuse); err != nil {
			t.Fatalf("write discover error: %v", err)
		}
		if msg, err = conn.Read(ctx); err != nil {
			t.Fatalf("read initialize: %v", err)
		}
	}
	req, ok := msg.(*jsonrpc.Request)
	if !ok || req.Method != "initialize" {
		t.Fatalf("first message = %+v, want the initialize request", msg)
	}
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		t.Fatalf("decode initialize params: %v", err)
	}
	result, err := json.Marshal(map[string]any{
		"protocolVersion": params.ProtocolVersion,
		"capabilities":    map[string]any{},
		"serverInfo":      map[string]any{"name": "raw", "version": "1"},
	})
	if err != nil {
		t.Fatalf("encode initialize result: %v", err)
	}
	if err := conn.Write(ctx, &jsonrpc.Response{ID: req.ID, Result: result}); err != nil {
		t.Fatalf("write initialize result: %v", err)
	}

	msg, err = conn.Read(ctx)
	if err != nil {
		t.Fatalf("read initialized: %v", err)
	}
	if n, ok := msg.(*jsonrpc.Request); !ok || n.Method != "notifications/initialized" {
		t.Fatalf("second message = %+v, want notifications/initialized", msg)
	}
}
