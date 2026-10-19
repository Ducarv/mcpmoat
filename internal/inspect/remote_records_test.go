package inspect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// These tests cover issue #100: the HTTP status and the blocked error that
// label a failed inspection come from the request that failed, not from
// whatever request the client sent last.

// rrRPC is the part of a JSON-RPC message that the hand-written test servers
// read.
type rrRPC struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		ProtocolVersion string `json:"protocolVersion"`
	} `json:"params"`
}

// rrReadRPC reads the JSON-RPC message in the body of r and puts the body
// back, so that a later handler can read it too.
func rrReadRPC(t *testing.T, r *http.Request) rrRPC {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("read request body: %v", err)
		return rrRPC{}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var msg rrRPC
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Errorf("decode request body %q: %v", body, err)
	}
	return msg
}

// rrRPCError returns a JSON-RPC error response for the request id.
func rrRPCError(id json.RawMessage, code int, message string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q}}`, id, code, message)
}

// rrWriteJSON writes body as an application/json response with status.
func rrWriteJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// rrSession connects an MCP client session to endpoint the way Remote does:
// newHTTPClient, the rawLists middleware, callRecords added last (so it runs
// first) and the transport from newRemoteTransport. It calls markConnected
// after the connect, as Remote does. The session closes when the test ends.
func rrSession(ctx context.Context, t *testing.T, kind discover.Transport, endpoint string) (*mcp.ClientSession, *httpEvents) {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	httpClient, ev, err := newHTTPClient(httpClientConfig{Endpoint: u})
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	t.Cleanup(httpClient.CloseIdleConnections)

	client := mcp.NewClient(
		&mcp.Implementation{Name: clientName, Version: clientVersion},
		&mcp.ClientOptions{Logger: slog.New(slog.DiscardHandler)},
	)
	client.AddSendingMiddleware((&rawLists{}).middleware())
	client.AddSendingMiddleware(callRecords(ev))

	cs, err := client.Connect(ctx, newRemoteTransport(kind, endpoint, httpClient), nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	ev.markConnected()
	t.Cleanup(func() { _ = cs.Close() })
	return cs, ev
}

// rrClassifyServer is the server entry that the unit tests give classify.
func rrClassifyServer() discover.Server {
	return rmServer(discover.TransportHTTP, "http://127.0.0.1:1/mcp", nil)
}

// TestOverlappingRequestsKeepTheirOwnRecord is the first acceptance test of
// issue #100. Two calls run on one session at the same time. One gets HTTP
// 500, the other a JSON-RPC error in a 200 response. Each error must keep the
// label of its own request, whatever request finished last. With one record
// for the whole client, the request that finished last decides the status
// for both errors.
func TestOverlappingRequestsKeepTheirOwnRecord(t *testing.T) {
	t.Parallel()

	const (
		toolsList   = methodListTools
		promptsList = "prompts/list"
	)
	tests := []struct {
		name string
		// first is answered first. held waits until the call of first has
		// returned on the client, so its request is in flight the whole time.
		first, held string
	}{
		{name: "prompts gets 500 while tools/list waits", first: promptsList, held: toolsList},
		{name: "tools/list gets its error while prompts waits", first: toolsList, held: promptsList},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// heldArrived closes when the held request reaches the server.
			// firstReturned closes when the client call of first returns.
			heldArrived := make(chan struct{})
			firstReturned := make(chan struct{})
			var heldOnce sync.Once

			// answer writes the final answer for method: HTTP 500 with a
			// JSON-RPC error body for prompts/list (the body keeps the SDK
			// session alive), and a JSON-RPC error in a 200 response for
			// tools/list.
			answer := func(w http.ResponseWriter, msg rrRPC) {
				if msg.Method == promptsList {
					rrWriteJSON(w, http.StatusInternalServerError, rrRPCError(msg.ID, -32603, "prompts backend broke"))
					return
				}
				rrWriteJSON(w, http.StatusOK, rrRPCError(msg.ID, -32603, "tools backend broke"))
			}
			wrap := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost {
						next.ServeHTTP(w, r)
						return
					}
					msg := rrReadRPC(t, r)
					switch msg.Method {
					case tt.first:
						select {
						case <-heldArrived:
						case <-r.Context().Done():
							return
						}
						answer(w, msg)
					case tt.held:
						heldOnce.Do(func() { close(heldArrived) })
						select {
						case <-firstReturned:
						case <-r.Context().Done():
							return
						}
						answer(w, msg)
					default:
						next.ServeHTTP(w, r)
					}
				})
			}
			ts, _ := startFixture(t, fixtureOpts{Wrap: wrap})

			// The timeout only stops a broken test from hanging; the channels
			// above order the requests.
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cs, ev := rrSession(ctx, t, discover.TransportHTTP, fixtureURL(ts))

			var toolsErr, promptsErr error
			var wg sync.WaitGroup
			wg.Go(func() {
				_, toolsErr = cs.ListTools(ctx, nil)
				if tt.first == toolsList {
					close(firstReturned)
				}
			})
			wg.Go(func() {
				_, promptsErr = cs.ListPrompts(ctx, nil)
				if tt.first == promptsList {
					close(firstReturned)
				}
			})
			wg.Wait()

			if toolsErr == nil || promptsErr == nil {
				t.Fatalf("ListTools error = %v, ListPrompts error = %v; want both to fail", toolsErr, promptsErr)
			}
			if ctx.Err() != nil {
				t.Fatalf("the calls ended at the safety timeout, not in the planned order: tools %v, prompts %v", toolsErr, promptsErr)
			}

			srv := rrClassifyServer()
			pce := classify(promptsErr, srv, ev, nil)
			if pce.Kind != KindHTTP || pce.Status != http.StatusInternalServerError {
				t.Errorf("classify(prompts error) = Kind %q, Status %d, want %q, 500 (error: %v)", pce.Kind, pce.Status, KindHTTP, pce)
			}
			tce := classify(toolsErr, srv, ev, nil)
			if tce.Kind != KindProtocol || tce.Status != 0 {
				t.Errorf("classify(tools error) = Kind %q, Status %d, want %q, 0 (error: %v)", tce.Kind, tce.Status, KindProtocol, tce)
			}
			if !strings.Contains(tce.Reason, "tools backend broke") {
				t.Errorf("classify(tools error).Reason = %q, want the JSON-RPC message of tools/list", tce.Reason)
			}
			// The JSON-RPC error of tools/list is still in the chain under
			// the *recordedError.
			var wire *jsonrpc.Error
			if !errors.As(toolsErr, &wire) {
				t.Errorf("errors.As(tools error, *jsonrpc.Error) = false, error: %v", toolsErr)
			}
		})
	}
}

// rrSSE is a hand-written legacy SSE server. The GET stream sends the
// endpoint event and then every event that a POST handler queues. It answers
// server/discover with "method not found", initialize with a result and
// tools/list with an empty list. When the request of method overCapOn
// arrives, it queues overCap after the normal answer, and for tools/list
// instead of it.
type rrSSE struct {
	t         *testing.T
	overCapOn string
	overCap   string
	// events holds the events for the GET stream.
	events chan string
	// redirectDiscover, when set, answers the server/discover POST with a
	// redirect to this URL instead.
	redirectDiscover string
	// discovered counts the server/discover POSTs.
	discovered atomic.Int32
	// triggered is true once overCap was queued.
	triggered atomic.Bool
}

// ServeHTTP implements http.Handler.
func (s *rrSSE) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "event: endpoint\ndata: /mcp?sessionid=rr\n\n")
		if f != nil {
			f.Flush()
		}
		for {
			select {
			case ev := <-s.events:
				if _, err := io.WriteString(w, ev); err != nil {
					return
				}
				if f != nil {
					f.Flush()
				}
			case <-r.Context().Done():
				return
			}
		}
	case http.MethodPost:
		msg := rrReadRPC(s.t, r)
		if msg.Method == methodDiscover {
			s.discovered.Add(1)
			if s.redirectDiscover != "" {
				http.Redirect(w, r, s.redirectDiscover, http.StatusTemporaryRedirect)
				return
			}
		}
		var answer string
		switch msg.Method {
		case methodDiscover:
			answer = rrRPCError(msg.ID, -32601, "Method not found")
		case methodInitialize:
			answer = fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":%q,"capabilities":{"tools":{}},"serverInfo":{"name":"rr","version":"1"}}}`,
				msg.ID, msg.Params.ProtocolVersion)
		case methodListTools:
			answer = fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}`, msg.ID)
		}
		trigger := msg.Method == s.overCapOn
		// For tools/list, the over-cap event replaces the answer.
		replace := trigger && msg.Method == methodListTools
		if answer != "" && !replace {
			s.events <- sseMessageEvent(answer)
		}
		if trigger && s.triggered.CompareAndSwap(false, true) {
			s.events <- s.overCap
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// startRRSSE starts s on a new test server and returns the configured URL
// of the SSE endpoint. The server closes when the test ends.
func startRRSSE(t *testing.T, s *rrSSE) string {
	t.Helper()
	s.t = t
	if s.events == nil {
		// The buffer is larger than the number of events of one session, so
		// a POST handler never waits for the GET stream.
		s.events = make(chan string, 16)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return ts.URL + "/mcp"
}

// TestRemoteSSEOverCapRecordedDuringConnect is the second acceptance test of
// issue #100. The legacy SSE stream is read by a goroutine of the SDK, so the
// stream can go over the size cap at any time: with the initialize answer,
// between initialize and the end of the connect, or later. The error must be
// labelled too-large in every case. Before issue #100, markConnected cleared
// the blocked error, and a stream that went over the cap just before it gave
// a protocol error.
func TestRemoteSSEOverCapRecordedDuringConnect(t *testing.T) {
	t.Parallel()

	const (
		maxBody = 2048
		// runs repeats each case, because the order of the SDK goroutines
		// differs between runs.
		runs = 5
	)
	// overCap is one event that is larger than maxBody alone. Its data is
	// valid JSON with a short enough string, so only the body cap trips.
	overCap := sseMessageEvent(`{"jsonrpc":"2.0","method":"notifications/message","params":{"pad":"` +
		strings.Repeat("x", 4*maxBody) + `"}}`)

	tests := []struct {
		name      string
		overCapOn string
	}{
		{name: "with the initialize answer", overCapOn: methodInitialize},
		{name: "on notifications/initialized", overCapOn: "notifications/initialized"},
		{name: "instead of the tools/list answer", overCapOn: methodListTools},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for run := range runs {
				t.Run(fmt.Sprintf("run %d", run), func(t *testing.T) {
					s := &rrSSE{overCapOn: tt.overCapOn, overCap: overCap}
					endpoint := startRRSSE(t, s)
					srv := rmServer(discover.TransportSSE, rmWithSecretQuery(endpoint), rmHeaders())

					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					_, err := Remote(ctx, srv, RemoteOptions{MaxResponseBytes: maxBody})

					if !s.triggered.Load() {
						t.Fatalf("the server never sent the over-cap event; Remote error: %v", err)
					}
					_ = rmRequireConnectError(t, err, KindTooLarge)
					if !errors.Is(err, errBodyTooLarge) {
						t.Errorf("errors.Is(err, errBodyTooLarge) = false, error: %v", err)
					}
					if ctx.Err() != nil {
						t.Errorf("Remote ended at the safety timeout, want an early failure: %v", err)
					}
				})
			}
		})
	}
}

// TestRemoteDeleteRedirectKeepsConnectLabel runs the attack of a server that
// answers the session DELETE with a redirect to another origin. The server
// fails notifications/initialized with HTTP 401, so Client.Connect fails and
// the SDK closes the session (a DELETE) before Remote classifies the error.
// The 401 must keep its label: the refused DELETE redirect must not turn it
// into KindRedirect.
func TestRemoteDeleteRedirectKeepsConnectLabel(t *testing.T) {
	t.Parallel()
	var deletes atomic.Int32
	ts, _ := wnStartServer(t, false, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodDelete:
				deletes.Add(1)
				http.Redirect(w, r, "http://evil.test/mcp", http.StatusTemporaryRedirect)
			case r.Method == http.MethodPost && rmBodyHas(t, r, `"notifications/initialized"`):
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			default:
				next.ServeHTTP(w, r)
			}
		})
	})
	srv := rmServer(discover.TransportHTTP, rmWithSecretQuery(ts.URL+"/mcp"), rmHeaders())

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	_, err := Remote(ctx, srv, RemoteOptions{})

	if deletes.Load() == 0 {
		t.Fatalf("the SDK sent no session DELETE, so the test does not cover the attack; Remote error: %v", err)
	}
	ce := rmRequireConnectError(t, err, KindHTTP)
	if ce.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", ce.Status, http.StatusUnauthorized)
	}
	if errors.Is(err, errCrossOriginRedirect) {
		t.Errorf("errors.Is(err, errCrossOriginRedirect) = true, want the 401 only: %v", err)
	}
}

// TestJoinContextErr checks that joinContextErr puts the context error first,
// strips the *url.Error and keeps the link to the record of the call. Without
// the link, classify reads the record of the call that finished last: here a
// call with a blocked error, which would turn the timeout into KindOrigin.
func TestJoinContextErr(t *testing.T) {
	t.Parallel()
	inner := errors.New("unexpected EOF")
	urlErr := &url.Error{Op: "Post", URL: "http://127.0.0.1:1/mcp?token=" + rmQuerySecret, Err: inner}

	t.Run("keeps the record link", func(t *testing.T) {
		t.Parallel()
		failed := &requestRecorder{}
		err := joinContextErr(context.DeadlineExceeded, &recordedError{err: urlErr, rec: failed})

		var re *recordedError
		if !errors.As(err, &re) || re.rec != failed {
			t.Fatalf("errors.As(*recordedError) gives %v, want the record of the failed call", re)
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			t.Errorf("the chain still holds the *url.Error: %v", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, inner) {
			t.Errorf("errors.Is: want both the context error and the inner error in %v", err)
		}

		// Another call finished later with a blocked error.
		var ev httpEvents
		ev.markConnected()
		other := &requestRecorder{}
		_ = other.recordBlocked(errOtherOrigin)
		ev.finishCall(failed)
		ev.finishCall(other)
		if ce := classify(err, rrClassifyServer(), &ev, nil); ce.Kind != KindTimeout {
			t.Errorf("classify Kind = %q, want %q (reason %q)", ce.Kind, KindTimeout, ce.Reason)
		}
	})

	t.Run("no record link", func(t *testing.T) {
		t.Parallel()
		err := joinContextErr(context.Canceled, urlErr)
		var re *recordedError
		if errors.As(err, &re) {
			t.Errorf("joinContextErr added a *recordedError to a chain without one: %v", err)
		}
		if !errors.Is(err, context.Canceled) || !errors.Is(err, inner) {
			t.Errorf("errors.Is: want both the context error and the inner error in %v", err)
		}
	})
}

// TestFinishedRecordIgnoresLateRequests checks that a call record changes no
// more after finishCall. The SDK sends notifications/cancelled on the context
// of a call that timed out, so its request finds the record of that call. A
// server that answers it with a refused redirect, a non-2xx status or a
// transport error must not change the label of the timeout.
func TestFinishedRecordIgnoresLateRequests(t *testing.T) {
	t.Parallel()
	var ev httpEvents
	ev.markConnected()
	rec := rrRec(http.StatusBadGateway, nil)
	ev.finishCall(rec)

	if got := rec.recordBlocked(errCrossOriginRedirect); got != errCrossOriginRedirect { //nolint:errorlint // identity check: recordBlocked must return its argument
		t.Errorf("recordBlocked() = %v, want its argument back", got)
	}
	rec.recordResponse(hcRecordResp(http.StatusUnauthorized, nil))
	if got := rec.lastStatus(); got != http.StatusBadGateway {
		t.Errorf("lastStatus() = %d after a late response, want %d", got, http.StatusBadGateway)
	}
	rec.recordNoResponse()
	if got := rec.lastStatus(); got != http.StatusBadGateway {
		t.Errorf("lastStatus() = %d after a late transport error, want %d", got, http.StatusBadGateway)
	}

	err := &recordedError{err: fmt.Errorf("%w: calling %q", context.DeadlineExceeded, methodListTools), rec: rec}
	if status, blocked := ev.stateFor(err); blocked != nil || status != http.StatusBadGateway {
		t.Errorf("stateFor() = (%d, %v), want (%d, nil)", status, blocked, http.StatusBadGateway)
	}
	if ce := classify(err, rrClassifyServer(), &ev, nil); ce.Kind != KindTimeout {
		t.Errorf("classify Kind = %q, want %q (reason %q)", ce.Kind, KindTimeout, ce.Reason)
	}
}

// errRRCall, errRRFallback, errRRConnect and errRROther are distinct blocked
// errors for the stateFor table. Each wraps a different sentinel, and the
// table compares them by identity.
var (
	errRRCall     = fmt.Errorf("call: %w", errOtherOrigin)
	errRRFallback = fmt.Errorf("fallback: %w", errBodyTooLarge)
	errRRConnect  = fmt.Errorf("connect: %w", errCrossOriginRedirect)
	errRROther    = fmt.Errorf("other: %w", errTooManyRedirects)
)

// rrRec returns a record with status and, if blocked is not nil, a blocked
// error.
func rrRec(status int, blocked error) *requestRecorder {
	rec := &requestRecorder{}
	rec.status.Store(int64(status))
	if blocked != nil {
		_ = rec.recordBlocked(blocked)
	}
	return rec
}

// TestStateFor checks the order in which httpEvents.stateFor picks the
// blocked error and the status for an error.
func TestStateFor(t *testing.T) {
	t.Parallel()

	errCall := errors.New("call failed")
	tests := []struct {
		name string
		// setup prepares ev and returns the error to ask about.
		setup       func(ev *httpEvents) error
		wantStatus  int
		wantBlocked error
	}{
		{
			name:  "zero value and nil error",
			setup: func(*httpEvents) error { return nil },
		},
		{
			name: "call record blocked wins over fallback and connect record",
			setup: func(ev *httpEvents) error {
				ev.finishCall(rrRec(0, errRRConnect))
				_ = ev.fallback.recordBlocked(errRRFallback)
				rec := rrRec(0, errRRCall)
				ev.finishCall(rec)
				return &recordedError{err: errCall, rec: rec}
			},
			wantBlocked: errRRCall,
		},
		{
			name: "fallback blocked when the call record has none",
			setup: func(ev *httpEvents) error {
				_ = ev.fallback.recordBlocked(errRRFallback)
				rec := rrRec(http.StatusInternalServerError, nil)
				ev.finishCall(rec)
				return &recordedError{err: errCall, rec: rec}
			},
			wantStatus:  http.StatusInternalServerError,
			wantBlocked: errRRFallback,
		},
		{
			name: "fallback blocked wins over the connect record",
			setup: func(ev *httpEvents) error {
				ev.finishCall(rrRec(0, errRRConnect))
				_ = ev.fallback.recordBlocked(errRRFallback)
				rec := rrRec(0, nil)
				ev.finishCall(rec)
				return &recordedError{err: errCall, rec: rec}
			},
			wantBlocked: errRRFallback,
		},
		{
			name: "fallback blocked stays after markConnected",
			setup: func(ev *httpEvents) error {
				_ = ev.fallback.recordBlocked(errRRFallback)
				ev.markConnected()
				rec := rrRec(0, nil)
				ev.finishCall(rec)
				return &recordedError{err: errCall, rec: rec}
			},
			wantBlocked: errRRFallback,
		},
		{
			name: "connect record used before markConnected",
			setup: func(ev *httpEvents) error {
				ev.finishCall(rrRec(0, errRRConnect))
				rec := rrRec(0, nil)
				ev.finishCall(rec)
				return &recordedError{err: errCall, rec: rec}
			},
			wantBlocked: errRRConnect,
		},
		{
			name: "connect record used for an unlinked error before markConnected",
			setup: func(ev *httpEvents) error {
				ev.finishCall(rrRec(0, errRRConnect))
				ev.finishCall(rrRec(0, nil))
				return errCall
			},
			wantBlocked: errRRConnect,
		},
		{
			name: "first blocked call of the connect wins",
			setup: func(ev *httpEvents) error {
				ev.finishCall(rrRec(0, errRRConnect))
				ev.finishCall(rrRec(0, errRROther))
				rec := rrRec(0, nil)
				ev.finishCall(rec)
				return &recordedError{err: errCall, rec: rec}
			},
			wantBlocked: errRRConnect,
		},
		{
			name: "stale connect record ignored after markConnected",
			setup: func(ev *httpEvents) error {
				ev.finishCall(rrRec(0, errRRConnect))
				ev.markConnected()
				rec := rrRec(0, nil)
				ev.finishCall(rec)
				return &recordedError{err: errCall, rec: rec}
			},
		},
		{
			name: "stale connect record ignored after markConnected for an unlinked error",
			setup: func(ev *httpEvents) error {
				ev.finishCall(rrRec(0, errRRConnect))
				ev.markConnected()
				ev.finishCall(rrRec(0, nil))
				return errCall
			},
		},
		{
			name: "markHandshake alone keeps the connect record",
			setup: func(ev *httpEvents) error {
				ev.finishCall(rrRec(0, errRRConnect))
				ev.markHandshake()
				rec := rrRec(0, nil)
				ev.finishCall(rec)
				return &recordedError{err: errCall, rec: rec}
			},
			wantBlocked: errRRConnect,
		},
		{
			name: "status from the call record, not the fallback",
			setup: func(ev *httpEvents) error {
				ev.fallback.status.Store(http.StatusNotFound)
				rec := rrRec(http.StatusServiceUnavailable, nil)
				ev.finishCall(rec)
				return &recordedError{err: errCall, rec: rec}
			},
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "call record status 0 is not replaced by the fallback status",
			setup: func(ev *httpEvents) error {
				ev.fallback.status.Store(http.StatusNotFound)
				rec := rrRec(0, nil)
				ev.finishCall(rec)
				return &recordedError{err: errCall, rec: rec}
			},
		},
		{
			name: "status from the fallback when there is no call record",
			setup: func(ev *httpEvents) error {
				ev.fallback.status.Store(http.StatusBadGateway)
				return errCall
			},
			wantStatus: http.StatusBadGateway,
		},
		{
			name: "unlinked error uses the call that finished last",
			setup: func(ev *httpEvents) error {
				ev.finishCall(rrRec(http.StatusUnauthorized, nil))
				ev.finishCall(rrRec(http.StatusInternalServerError, errRRCall))
				return errors.New("no initialize result")
			},
			wantStatus:  http.StatusInternalServerError,
			wantBlocked: errRRCall,
		},
		{
			name: "linked error beats the call that finished last",
			setup: func(ev *httpEvents) error {
				// After the connect, so that connectBlocked plays no part.
				ev.markConnected()
				rec := rrRec(http.StatusUnauthorized, nil)
				ev.finishCall(rec)
				ev.finishCall(rrRec(http.StatusInternalServerError, errRRCall))
				return &recordedError{err: errCall, rec: rec}
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "record found under a wrap",
			setup: func(ev *httpEvents) error {
				rec := rrRec(http.StatusForbidden, nil)
				ev.finishCall(rec)
				ev.finishCall(rrRec(http.StatusInternalServerError, nil))
				return fmt.Errorf("%w: %w", context.DeadlineExceeded, &recordedError{err: errCall, rec: rec})
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "record found in a joined error",
			setup: func(ev *httpEvents) error {
				rec := rrRec(http.StatusForbidden, nil)
				ev.finishCall(rec)
				ev.finishCall(rrRec(http.StatusInternalServerError, nil))
				return errors.Join(errors.New("first"), &recordedError{err: errCall, rec: rec})
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "recordedError with a nil record falls back to the last call",
			setup: func(ev *httpEvents) error {
				ev.finishCall(rrRec(http.StatusTeapot, nil))
				return &recordedError{err: errCall}
			},
			wantStatus: http.StatusTeapot,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ev := &httpEvents{}
			err := tt.setup(ev)
			status, blocked := ev.stateFor(err)
			if status != tt.wantStatus {
				t.Errorf("stateFor() status = %d, want %d", status, tt.wantStatus)
			}
			// The errors are compared by identity: the table must get the
			// exact error that the expected record holds.
			if blocked != tt.wantBlocked { //nolint:errorlint // identity check on purpose
				t.Errorf("stateFor() blocked = %v, want %v", blocked, tt.wantBlocked)
			}
		})
	}
}

// TestFinishCallConnectBlocked checks when finishCall keeps a record in
// connectBlocked.
func TestFinishCallConnectBlocked(t *testing.T) {
	t.Parallel()

	t.Run("nil record changes nothing", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		prev := rrRec(0, nil)
		ev.finishCall(prev)
		ev.finishCall(nil)
		if got := ev.lastCall.Load(); got != prev {
			t.Errorf("lastCall = %p after finishCall(nil), want %p", got, prev)
		}
	})

	t.Run("record without a blocked error is not kept", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		ev.finishCall(rrRec(http.StatusNotFound, nil))
		if got := ev.connectBlocked.Load(); got != nil {
			t.Errorf("connectBlocked = %p, want nil", got)
		}
	})

	t.Run("first blocked record during the connect is kept", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		first := rrRec(0, errRRConnect)
		ev.finishCall(first)
		ev.finishCall(rrRec(0, errRROther))
		if got := ev.connectBlocked.Load(); got != first {
			t.Errorf("connectBlocked = %p, want the first blocked record %p", got, first)
		}
	})

	t.Run("blocked record after markConnected is not kept", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		ev.markConnected()
		ev.finishCall(rrRec(0, errRRCall))
		if got := ev.connectBlocked.Load(); got != nil {
			t.Errorf("connectBlocked = %p after markConnected, want nil", got)
		}
	})

	t.Run("markConnected keeps an earlier connect record", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		rec := rrRec(0, errRRConnect)
		ev.finishCall(rec)
		ev.markConnected()
		if got := ev.connectBlocked.Load(); got != rec {
			t.Errorf("connectBlocked = %p after markConnected, want %p (nothing is cleared)", got, rec)
		}
	})

	t.Run("concurrent blocked calls keep exactly one", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		const n = 32
		recs := make([]*requestRecorder, n)
		for i := range recs {
			recs[i] = rrRec(0, fmt.Errorf("call %d: %w", i, errOtherOrigin))
		}
		var wg sync.WaitGroup
		for _, rec := range recs {
			wg.Go(func() { ev.finishCall(rec) })
		}
		wg.Wait()
		got := ev.connectBlocked.Load()
		found := false
		for _, rec := range recs {
			found = found || rec == got
		}
		if !found {
			t.Errorf("connectBlocked = %p, want one of the finished records", got)
		}
	})
}

// rrCallKey is a context key that proves callRecords keeps the values of
// the context it gets.
type rrCallKey struct{}

// TestCallRecords checks the sending middleware that gives each MCP call its
// own record.
func TestCallRecords(t *testing.T) {
	t.Parallel()

	t.Run("failed call returns a recordedError around the inner error", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		inner := fmt.Errorf("calling %q: %w", methodListTools, &jsonrpc.Error{Code: -32603, Message: "backend broke"})
		var seen *requestRecorder
		next := func(ctx context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
			seen = recorderFrom(ctx)
			return nil, inner
		}
		_, err := callRecords(ev)(next)(t.Context(), methodListTools, nil)

		re, ok := err.(*recordedError) //nolint:errorlint // the middleware must return this exact type
		if !ok {
			t.Fatalf("error = %T (%v), want *recordedError", err, err)
		}
		if seen == nil {
			t.Fatal("next got no record on its context")
		}
		if re.rec != seen {
			t.Errorf("recordedError.rec = %p, want the record that next saw %p", re.rec, seen)
		}
		if err.Error() != inner.Error() {
			t.Errorf("Error() = %q, want the inner text %q", err.Error(), inner.Error())
		}
		if !errors.Is(err, inner) {
			t.Error("errors.Is(err, inner) = false, want true")
		}
		var wire *jsonrpc.Error
		if !errors.As(err, &wire) || wire.Message != "backend broke" {
			t.Errorf("errors.As(err, *jsonrpc.Error) = %v, want the inner JSON-RPC error", wire)
		}
		if got := ev.lastCall.Load(); got != seen {
			t.Errorf("lastCall = %p, want the record of the call %p", got, seen)
		}
	})

	t.Run("context sentinel survives the wrap", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
			return nil, fmt.Errorf("calling: %w", context.DeadlineExceeded)
		}
		_, err := callRecords(ev)(next)(t.Context(), methodListTools, nil)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("errors.Is(err, context.DeadlineExceeded) = false, error: %v", err)
		}
	})

	t.Run("successful call returns the result and stores lastCall", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		want := &mcp.ListToolsResult{}
		var seen *requestRecorder
		next := func(ctx context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
			seen = recorderFrom(ctx)
			return want, nil
		}
		res, err := callRecords(ev)(next)(t.Context(), methodListTools, nil)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if res != want {
			t.Errorf("result = %v, want the result of next", res)
		}
		if seen == nil || ev.lastCall.Load() != seen {
			t.Errorf("lastCall = %p, want the record of the call %p", ev.lastCall.Load(), seen)
		}
	})

	t.Run("each call gets a new record and keeps context values", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		var seen []*requestRecorder
		next := func(ctx context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
			if got, _ := ctx.Value(rrCallKey{}).(string); got != "kept" {
				t.Errorf("ctx value = %q, want %q", got, "kept")
			}
			seen = append(seen, recorderFrom(ctx))
			return nil, nil
		}
		h := callRecords(ev)(next)
		ctx := context.WithValue(t.Context(), rrCallKey{}, "kept")
		for range 2 {
			if _, err := h(ctx, methodListTools, nil); err != nil {
				t.Fatalf("error = %v", err)
			}
		}
		if len(seen) != 2 || seen[0] == nil || seen[1] == nil || seen[0] == seen[1] {
			t.Fatalf("records = %p, want two different records", seen)
		}
		if seen[0] == &ev.fallback || seen[1] == &ev.fallback {
			t.Error("a call got the fallback record, want its own")
		}
		if got := ev.lastCall.Load(); got != seen[1] {
			t.Errorf("lastCall = %p, want the record of the second call %p", got, seen[1])
		}
	})

	t.Run("HTTP request inside the call writes to the call record", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		t.Cleanup(ts.Close)
		u, err := url.Parse(ts.URL + "/mcp")
		if err != nil {
			t.Fatal(err)
		}
		client, ev, err := newHTTPClient(httpClientConfig{Endpoint: u})
		if err != nil {
			t.Fatalf("newHTTPClient: %v", err)
		}
		t.Cleanup(client.CloseIdleConnections)

		next := func(ctx context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader("{}"))
			if err != nil {
				return nil, err
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			_ = resp.Body.Close()
			return nil, errors.New("server failed")
		}
		_, callErr := callRecords(ev)(next)(t.Context(), methodListTools, nil)
		if callErr == nil {
			t.Fatal("error = nil, want the call error")
		}
		var re *recordedError
		if !errors.As(callErr, &re) {
			t.Fatalf("error = %T, want a *recordedError", callErr)
		}
		if got := re.rec.lastStatus(); got != http.StatusServiceUnavailable {
			t.Errorf("call record status = %d, want 503", got)
		}
		if got := ev.fallback.lastStatus(); got != 0 {
			t.Errorf("fallback record status = %d, want 0 (the request belongs to the call)", got)
		}
	})

	t.Run("handshake", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			method        string
			fail          bool
			wantConnected bool
		}{
			{method: methodInitialize, wantConnected: true},
			{method: methodDiscover, wantConnected: true},
			{method: methodInitialize, fail: true},
			{method: methodDiscover, fail: true},
			{method: methodListTools},
			{method: "notifications/initialized"},
			{method: "ping"},
		}
		for _, tt := range tests {
			name := tt.method
			if tt.fail {
				name += " fails"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				ev := &httpEvents{}
				next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
					if tt.fail {
						return nil, errors.New("refused")
					}
					return nil, nil
				}
				_, _ = callRecords(ev)(next)(t.Context(), tt.method, nil)
				if got := ev.connected(); got != tt.wantConnected {
					t.Errorf("connected() = %v, want %v", got, tt.wantConnected)
				}
				if ev.connectDone.Load() {
					t.Error("connectDone = true, want false: only markConnected sets it")
				}
			})
		}
	})
}

// rrCall runs one call through callRecords. block, when not nil, is stored
// as the blocked error of the call record, as headerTransport does for a
// refused request. callErr is the error of the call, nil for success.
func rrCall(t *testing.T, ev *httpEvents, method string, block, callErr error) error {
	t.Helper()
	next := func(ctx context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
		if block != nil {
			_ = recorderFrom(ctx).recordBlocked(block)
		}
		return nil, callErr
	}
	_, err := callRecords(ev)(next)(t.Context(), method, nil)
	return err
}

// TestConnectBlockedFlows checks the connect-phase record through
// callRecords and classify. The SDK falls back from server/discover to
// initialize after any error. A blocked server/discover must label a failed
// connect, and must not label a failure after a successful connect.
func TestConnectBlockedFlows(t *testing.T) {
	t.Parallel()

	redirect := fmt.Errorf("redirect: %w", errCrossOriginRedirect)
	srv := rrClassifyServer()

	t.Run("blocked during the connect then the connect fails", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		_ = rrCall(t, ev, methodDiscover, redirect, errors.New("discover refused"))
		// The broken connection makes initialize fail before it sends a
		// request, so its own record is empty.
		err := rrCall(t, ev, methodInitialize, nil, errors.New("connection closed"))
		ce := classify(err, srv, ev, nil)
		if ce.Kind != KindRedirect {
			t.Errorf("Kind = %q, want %q (error: %v)", ce.Kind, KindRedirect, ce)
		}
		if !errors.Is(ce, errCrossOriginRedirect) {
			t.Errorf("errors.Is(err, errCrossOriginRedirect) = false, error: %v", ce)
		}
	})

	t.Run("blocked during the connect then markConnected then a later failure", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		_ = rrCall(t, ev, methodDiscover, redirect, errors.New("discover refused"))
		if err := rrCall(t, ev, methodInitialize, nil, nil); err != nil {
			t.Fatalf("initialize error = %v", err)
		}
		ev.markConnected()
		err := rrCall(t, ev, methodListTools, nil, &jsonrpc.Error{Code: -32603, Message: "tools backend broke"})
		ce := classify(err, srv, ev, nil)
		if ce.Kind != KindProtocol {
			t.Errorf("Kind = %q, want %q: the blocked server/discover is stale (error: %v)", ce.Kind, KindProtocol, ce)
		}
		if errors.Is(ce, errCrossOriginRedirect) {
			t.Errorf("error wraps the stale errCrossOriginRedirect: %v", ce)
		}
	})

	t.Run("blocked during the connect then markConnected then an unlinked failure", func(t *testing.T) {
		t.Parallel()
		ev := &httpEvents{}
		_ = rrCall(t, ev, methodDiscover, redirect, errors.New("discover refused"))
		if err := rrCall(t, ev, methodInitialize, nil, nil); err != nil {
			t.Fatalf("initialize error = %v", err)
		}
		ev.markConnected()
		ce := classify(errors.New("no initialize result"), srv, ev, nil)
		if ce.Kind != KindProtocol {
			t.Errorf("Kind = %q, want %q (error: %v)", ce.Kind, KindProtocol, ce)
		}
	})

	// The legacy SSE transport: a failed POST breaks the whole connection,
	// so initialize fails right after the refused server/discover redirect.
	t.Run("legacy SSE: server/discover redirected to another origin", func(t *testing.T) {
		t.Parallel()
		victim := startVictim(t)
		s := &rrSSE{redirectDiscover: victim.URL + "/steal"}
		endpoint := startRRSSE(t, s)
		srv := rmServer(discover.TransportSSE, rmWithSecretQuery(endpoint), rmHeaders())

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		_, err := Remote(ctx, srv, RemoteOptions{})

		victim.assertUntouched(t)
		if s.discovered.Load() == 0 {
			t.Fatalf("the client sent no server/discover request; the test blocks nothing during the connect: %v", err)
		}
		_ = rmRequireConnectError(t, err, KindRedirect)
		if ctx.Err() != nil {
			t.Errorf("Remote ended at the safety timeout, want an early failure: %v", err)
		}
	})
}
