package inspect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// These tests prove the acceptance criteria of issue #101 for remote
// servers: a tools/list reply of about 8 MiB whose schema holds millions of
// empty objects ("[{},{},...]") makes Remote fail with KindTooLarge, for an
// application/json body and for a text/event-stream body, and the memory
// that one such inspection allocates stays below a fixed bound.
//
// The server is written by hand, not with the SDK, because the SDK server
// would decode and encode the huge schema itself. It writes the prebuilt
// bytes as they are.

const (
	// rsHugeElems is the number of empty objects in the huge schema. The
	// array text "[{},{},...]" is 3*rsHugeElems bytes, about 8 MiB, so the
	// whole reply is a little more than the default body cap of 8 MiB
	// (defaultMaxResponseBytes). The tests raise the cap (rsMaxBody), so
	// only the JSON shape check can stop the reply.
	rsHugeElems = (8 << 20) / 3

	// rsMaxBody is the body cap that the tests set in RemoteOptions. It is
	// twice the size of the huge reply, so the size cap is never the cause
	// of the failure.
	rsMaxBody int64 = 16 << 20

	// rsMemBound is the most memory that one inspection of the huge server
	// may allocate (issue #101 acceptance). Without the shape check, the
	// SDK decodes about 2.8 million empty objects, which needs hundreds of
	// MB, far above this bound.
	rsMemBound uint64 = 64 << 20

	// rsReason is the fixed reason of a shape violation (blockedKinds in
	// errors.go).
	rsReason = "response JSON too large: too deep, too many values or a too long string"
)

// rsHugeArray returns the elements of the huge array: "{},{},...,{}," with
// rsHugeElems objects and a trailing comma that rsHugeSchema drops. It is
// one allocation of about 8 MiB. Call it once per test, before any memory
// measurement.
func rsHugeArray() []byte {
	return bytes.Repeat([]byte("{},"), rsHugeElems)
}

// rsHugeSchema returns the parts of an input schema whose "blob" property
// holds the huge array. The parts share the memory of array: nothing is
// copied, so the server writes the 8 MiB without a new allocation.
func rsHugeSchema(array []byte) [][]byte {
	return [][]byte{
		[]byte(`{"type":"object","properties":{"blob":[`),
		array[:len(array)-1], // drop the trailing comma
		[]byte(`]}}`),
	}
}

// rsSmallSchema returns a normal input schema, for the control case.
func rsSmallSchema() [][]byte {
	return [][]byte{[]byte(`{"type":"object","properties":{"blob":{"type":"string"}}}`)}
}

// rsServer is a hand-written streamable HTTP MCP server with one tool. It
// answers each POST with one JSON-RPC message, as an application/json body
// or, when sse is set, as one event of a text/event-stream body. It sends no
// session ID, so the client sends no DELETE when it closes.
type rsServer struct {
	// sse selects a text/event-stream reply instead of application/json.
	sse bool
	// schema holds the parts of the input schema of the tool, written in
	// order.
	schema [][]byte
	// listed counts the tools/list requests.
	listed atomic.Int32
}

// rsStart starts s on an httptest server and returns its URL. The server
// closes when the test ends.
func rsStart(tb testing.TB, s *rsServer) string {
	tb.Helper()
	ts := httptest.NewServer(s)
	// Cleanups run last-in, first-out. CloseClientConnections runs first,
	// so a handler that still writes the huge reply to a client that went
	// away cannot make Close wait.
	tb.Cleanup(ts.Close)
	tb.Cleanup(ts.CloseClientConnections)
	return ts.URL + "/mcp"
}

// ServeHTTP answers the MCP requests of the client.
func (s *rsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// The client turns off the standalone GET stream, and the server
		// sends no session ID, so no GET or DELETE is expected.
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"params"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&msg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if msg.ID == nil {
		// A notification, such as notifications/initialized.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch msg.Method {
	case "initialize":
		// json.Marshal quotes the version that the client sent, so the
		// reply echoes it as valid JSON.
		version, err := json.Marshal(msg.Params.ProtocolVersion)
		if err != nil {
			http.Error(w, "bad version", http.StatusBadRequest)
			return
		}
		s.reply(w, fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":%s,"capabilities":{"tools":{}},"serverInfo":{"name":"shape","version":"1.0.0"}}}`, msg.ID, version))
	case "tools/list":
		s.listed.Add(1)
		parts := make([][]byte, 0, len(s.schema)+2)
		parts = append(parts, fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"huge","description":"A tool with a schema.","inputSchema":`, msg.ID))
		parts = append(parts, s.schema...)
		parts = append(parts, []byte(`}]}}`))
		s.reply(w, parts...)
	default:
		// server/discover and any other method. The client then falls back
		// from server/discover to initialize.
		s.reply(w, fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`, msg.ID))
	}
}

// reply writes one JSON-RPC message, given in parts, in the format of s.
// The parts must hold no newline, so that in SSE mode the message is one
// data line.
func (s *rsServer) reply(w http.ResponseWriter, parts ...[]byte) {
	if s.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		parts = append([][]byte{[]byte("data: ")}, parts...)
		parts = append(parts, []byte("\n\n"))
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	for _, p := range parts {
		if _, err := w.Write(p); err != nil {
			// The client stopped reading, as it must for the huge reply.
			return
		}
	}
}

// rsRemote runs Remote against the server at url with the raised body cap.
func rsRemote(ctx context.Context, url string) (Result, error) {
	srv := rmServer(discover.TransportHTTP, url, nil)
	return Remote(ctx, srv, RemoteOptions{MaxResponseBytes: rsMaxBody})
}

// rsRequireShapeError checks that err is the shape error of issue #101: a
// *ConnectError of kind KindTooLarge whose chain holds errJSONTooComplex
// and no context error, and that res has no tools.
func rsRequireShapeError(t *testing.T, res Result, err error) {
	t.Helper()
	ce := rmRequireConnectError(t, err, KindTooLarge)
	if !errors.Is(err, errJSONTooComplex) {
		t.Errorf("errors.Is(err, errJSONTooComplex) = false, want true (err = %v)", err)
	}
	// errBodyTooLarge would mean that the size cap, not the shape check,
	// stopped the reply.
	if errors.Is(err, errBodyTooLarge) {
		t.Errorf("err = %v, want the shape error, not the size cap", err)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want no context error in the chain", err)
	}
	if ce.Reason != rsReason {
		t.Errorf("Reason = %q, want %q", ce.Reason, rsReason)
	}
	// The error text is fixed and holds no server data.
	if msg := err.Error(); strings.Contains(msg, "{},{}") || len(msg) > 512 {
		t.Errorf("error text has %d bytes and must not hold server data: %.200q", len(msg), msg)
	}
	if res.Tools != nil {
		t.Errorf("Result.Tools = %d tools, want nil on error", len(res.Tools))
	}
}

// TestRemoteShapeHugeSchema checks that Remote refuses a tools/list reply of
// about 8 MiB that is small JSON text with very many values, as an
// application/json body and as a text/event-stream body (issue #101). The
// body cap is 16 MiB, so only the JSON shape check can stop it.
func TestRemoteShapeHugeSchema(t *testing.T) {
	t.Parallel()

	// The subtests only read the array, so they can share it.
	array := rsHugeArray()
	for _, tc := range []struct {
		name string
		sse  bool
	}{
		{name: "application/json", sse: false},
		{name: "text/event-stream", sse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &rsServer{sse: tc.sse, schema: rsHugeSchema(array)}
			url := rsStart(t, s)

			res, err := rsRemote(t.Context(), url)
			if s.listed.Load() == 0 {
				t.Fatalf("the client never sent tools/list; the test checks nothing (err = %v)", err)
			}
			rsRequireShapeError(t, res, err)
		})
	}
}

// TestRemoteShapeControl runs the same server with a small schema. Remote
// must succeed, so the failure in TestRemoteShapeHugeSchema comes from the
// shape of the schema, not from the server.
func TestRemoteShapeControl(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		sse  bool
	}{
		{name: "application/json", sse: false},
		{name: "text/event-stream", sse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &rsServer{sse: tc.sse, schema: rsSmallSchema()}
			url := rsStart(t, s)

			res, err := rsRemote(t.Context(), url)
			if err != nil {
				t.Fatalf("Remote() error = %v, want nil", err)
			}
			if len(res.Tools) != 1 || res.Tools[0].Name != "huge" {
				t.Fatalf("Result.Tools = %+v, want the one tool %q", res.Tools, "huge")
			}
			if !strings.Contains(string(res.Tools[0].InputSchema), `"blob"`) {
				t.Errorf("InputSchema = %s, want the blob property", res.Tools[0].InputSchema)
			}
		})
	}
}

// TestRemoteHugeSchemaMemory checks the memory bound of issue #101: one
// inspection of the huge server, as an application/json body, allocates
// less than rsMemBound.
//
// It measures runtime.MemStats.TotalAlloc, the total of all heap bytes
// allocated since the process started. It only grows: memory that the GC
// frees is not subtracted. So the delta over the inspection is the sum of
// all its allocations, and the peak heap of the inspection can never be
// higher than that sum. It is a conservative upper bound for the peak heap.
// It also counts the allocations of the test server and of any background
// goroutine, which can only make the number higher.
//
// The test does not call t.Parallel, so that no parallel test allocates
// during the measurement: Go runs the parallel tests only after all
// sequential top-level tests are done. The huge array is built before the
// first reading, so its 8 MiB are not counted.
func TestRemoteHugeSchemaMemory(t *testing.T) {
	array := rsHugeArray()
	s := &rsServer{schema: rsHugeSchema(array)}
	url := rsStart(t, s)
	ctx := t.Context()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res, err := rsRemote(ctx, url)
	runtime.GC()
	runtime.ReadMemStats(&after)

	if s.listed.Load() == 0 {
		t.Fatalf("the client never sent tools/list; the test measures nothing (err = %v)", err)
	}
	// Check the bound before the error, so that the test reports the
	// measured number also when the shape check is gone and Remote
	// succeeds.
	delta := after.TotalAlloc - before.TotalAlloc
	t.Logf("TotalAlloc delta = %d bytes (%.2f MiB), bound %d MiB", delta, float64(delta)/(1<<20), rsMemBound>>20)
	if delta >= rsMemBound {
		t.Errorf("one inspection allocated %d bytes, want less than %d (64 MiB)", delta, rsMemBound)
	}
	rsRequireShapeError(t, res, err)
}

// BenchmarkRemoteHugeSchema measures one inspection of the huge server as
// an application/json body. Each iteration must fail with the shape error.
func BenchmarkRemoteHugeSchema(b *testing.B) {
	array := rsHugeArray()
	s := &rsServer{schema: rsHugeSchema(array)}
	url := rsStart(b, s)
	ctx := b.Context()

	b.ReportAllocs()
	for b.Loop() {
		_, err := rsRemote(ctx, url)
		if !errors.Is(err, errJSONTooComplex) {
			b.Fatalf("Remote() error = %v, want the shape error", err)
		}
	}
}

// rsStatusServer answers every request with the same status, Content-Type
// and body, as a server that rejects the client does. It counts the POST
// requests.
type rsStatusServer struct {
	status int
	ct     string // no Content-Type header when empty
	body   string
	posted atomic.Int32
}

// ServeHTTP writes the fixed answer.
func (s *rsStatusServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.posted.Add(1)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	if s.ct != "" {
		w.Header().Set("Content-Type", s.ct)
	}
	w.WriteHeader(s.status)
	_, _ = io.WriteString(w, s.body)
}

// TestRemoteShapeErrorStatus checks the shape check on the body of a non-2xx
// answer, through the real SDK (issue #101). The SDK reads such a body and
// decodes it as one JSON-RPC message whatever the Content-Type
// (checkResponse in mcp/streamable.go), so a deep "id" must give
// KindTooLarge. A normal JSON-RPC error body must still give KindHTTP with
// its status, and a transient status, whose body the SDK never reads, too.
func TestRemoteShapeErrorStatus(t *testing.T) {
	t.Parallel()

	deepOver := hcRPCDeepID(maxJSONValues - hcDeepIDEnvelopeValues + 1)
	tests := []struct {
		name       string
		status     int
		ct         string
		body       string
		wantShape  bool // KindTooLarge from the shape check
		wantStatus int  // the status of KindHTTP when wantShape is false
	}{
		{name: "400 json deep id", status: 400, ct: "application/json", body: deepOver, wantShape: true},
		{name: "400 text/plain deep id", status: 400, ct: "text/plain", body: deepOver, wantShape: true},
		{name: "404 without Content-Type deep id", status: 404, body: deepOver, wantShape: true},
		{name: "401 small JSON-RPC error", status: 401, ct: "application/json", body: hcRPCUnauthorized, wantStatus: 401},
		{name: "503 deep id is never read", status: 503, ct: "application/json", body: deepOver, wantStatus: 503},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &rsStatusServer{status: tt.status, ct: tt.ct, body: tt.body}
			ts := httptest.NewServer(s)
			t.Cleanup(ts.Close)
			t.Cleanup(ts.CloseClientConnections)

			res, err := rsRemote(t.Context(), ts.URL+"/mcp")
			if s.posted.Load() == 0 {
				t.Fatalf("the client never sent a POST; the test checks nothing (err = %v)", err)
			}
			if tt.wantShape {
				rsRequireShapeError(t, res, err)
				return
			}
			ce := rmRequireConnectError(t, err, KindHTTP)
			if ce.Status != tt.wantStatus {
				t.Errorf("Status = %d, want %d (error: %v)", ce.Status, tt.wantStatus, err)
			}
			if errors.Is(err, errJSONTooComplex) {
				t.Errorf("err = %v, want no shape error", err)
			}
		})
	}
}
