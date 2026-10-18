package inspect

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
)

// requestRecorder records what happened on the HTTP layer for one MCP call,
// because the MCP SDK drops it: the status code of the last response, and the
// error that this layer raised on purpose (a refused origin, a refused
// redirect or a body that is too large). classify reads both through
// httpEvents.stateFor.
//
// Each MCP call gets its own record (see callRecords in remote.go), so a
// request that runs at the same time as another one cannot change the label
// of its error. httpEvents holds one more record, the fallback, for the
// requests that belong to no call.
//
// A call record stops changing when its call returns (see finish).
//
// It is safe for concurrent use: a response body can be read on another
// goroutine than the one that sent the request.
type requestRecorder struct {
	// status is the status of the most recent request of the record: the code
	// of a non-2xx response that was not a followed redirect, and 0 after a
	// 2xx response or after a request that got no response. An atomic value
	// needs no mutex.
	//
	// It keeps the latest value and not the first one. The SDK can start with
	// a request that gets a 404 and then fall back to another request that
	// works. The 404 must not give a wrong label to a later, unrelated error.
	status atomic.Int64

	// finished is true after the call of the record returned (see finish).
	finished atomic.Bool

	// mu guards blocked.
	mu sync.Mutex
	// blocked is the first error that the HTTP layer raised on purpose for
	// this record, or nil.
	blocked error
}

// finish marks the call of the record as returned. After it, the record
// takes no new writes. The SDK can still send a request on the context of a
// returned call: after a call fails because ctx ended, it sends
// notifications/cancelled on context.WithoutCancel of that ctx, and so with
// the same record. An answer to that request that comes after finish cannot
// change the label of the error that the call returned.
//
// This is best effort, in three ways:
//
//   - The SDK starts that request just before the call returns, so an answer
//     within that short window can still be recorded. It needs a full
//     network round trip first.
//   - With MCPGODEBUG=blockingcancelnotify=1 in the environment of mcpmoat,
//     the SDK sends the notification before the call returns, so its answer
//     is always recorded. A blocked error in that answer then wins over the
//     context error in classify. The inspection still fails.
//   - The record methods check finished and then write, in two steps, so a
//     write that runs at the same time as finish can still land.
func (r *requestRecorder) finish() {
	r.finished.Store(true)
}

// lastStatus returns the status of the most recent request of the record (see
// the status field).
func (r *requestRecorder) lastStatus() int {
	return int(r.status.Load())
}

// blockedErr returns the first error that the HTTP layer raised on purpose
// for this record, or nil.
func (r *requestRecorder) blockedErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.blocked
}

// recordResponse stores the status of resp. A 2xx response stores 0, so it
// clears an earlier failure. A followed redirect changes nothing: it is not a
// final answer.
func (r *requestRecorder) recordResponse(resp *http.Response) {
	if r.finished.Load() || isFollowedRedirect(resp) {
		return
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		r.status.Store(0)
		return
	}
	r.status.Store(int64(resp.StatusCode))
}

// recordNoResponse records a request that got no response (a transport error).
// It clears the status, so that an older non-2xx status cannot outrank this
// error.
func (r *requestRecorder) recordNoResponse() {
	if r.finished.Load() {
		return
	}
	r.status.Store(0)
}

// recordBlocked stores err if no blocked error was stored before and the
// record is not finished. The first one wins, because a later error is often
// a result of the first one. It always returns err, so a caller can write:
// return nil, rec.recordBlocked(err).
func (r *requestRecorder) recordBlocked(err error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blocked == nil && !r.finished.Load() {
		r.blocked = err
	}
	return err
}

// recorderKey is the context key for the record of one MCP call. A context
// key must not collide with keys of other packages. An unexported type does
// that: no other package can name recorderKey, so no other package can make
// an equal key. The empty struct takes no memory.
type recorderKey struct{}

// withRecorder returns a copy of ctx that carries rec. The SDK passes the
// context of a call down to http.NewRequestWithContext, so headerTransport
// finds rec again in req.Context().
func withRecorder(ctx context.Context, rec *requestRecorder) context.Context {
	return context.WithValue(ctx, recorderKey{}, rec)
}

// recorderFrom returns the record that withRecorder put on ctx, or nil if
// there is none. The two-value type assertion gives nil instead of a panic
// when the key is absent.
func recorderFrom(ctx context.Context) *requestRecorder {
	rec, _ := ctx.Value(recorderKey{}).(*requestRecorder)
	return rec
}

// httpEvents reports what the HTTP layer saw during one inspection. It
// implements transportEvents for classify.
//
// The record of each MCP call travels on the context of its requests (see
// withRecorder). The fallback field is the fallback record: it gets the
// requests that carry no record of their own. These are the legacy SSE
// GET stream (the SDK opens it with the context of Client.Connect, before any
// call), the DELETE that closes a streamable session, and requests from a
// direct caller such as a test.
//
// It is safe for concurrent use. Use it through a pointer only: it holds a
// mutex, which must not be copied.
type httpEvents struct {
	// fallback is the record for the requests of no MCP call (see the type
	// doc).
	fallback requestRecorder

	// sessionUp is true after the server answered the MCP handshake
	// (markHandshake) or Remote connected the session (markConnected).
	sessionUp atomic.Bool

	// lastCall is the record of the MCP call that finished last, or nil. An
	// atomic.Pointer loads and stores a pointer in one step, so the
	// goroutines of the SDK can use it without a mutex. stateFor uses it for
	// an error that is linked to no call (see stateFor).
	lastCall atomic.Pointer[requestRecorder]

	// connectDone is true after markConnected: Client.Connect succeeded.
	connectDone atomic.Bool

	// connectBlocked is the record of the first call that finished with a
	// blocked error during the connect (before markConnected), or nil.
	// stateFor uses it to label a failed connect only. Two cases need it:
	//
	//   - A failed write breaks the whole legacy SSE connection. When the
	//     server/discover POST goes to another origin, the initialize call
	//     after it fails before it sends any request, so its own record is
	//     empty.
	//   - A server that redirects server/discover to another origin and then
	//     never answers initialize tried to send the secrets elsewhere. The
	//     report must show that, not only a timeout.
	connectBlocked atomic.Pointer[requestRecorder]
}

// Compile-time check: *httpEvents must implement transportEvents (see the
// templateLister check in list.go for how such a check works).
var _ transportEvents = (*httpEvents)(nil)

// markHandshake records that the server answered initialize or
// server/discover, so it speaks the configured transport.
func (ev *httpEvents) markHandshake() {
	ev.sessionUp.Store(true)
}

// markConnected records that the session is up. Remote calls it after a
// successful connect. From now on stateFor ignores connectBlocked: the SDK
// recovered from any call that was blocked during the connect (for example,
// it falls back from server/discover to initialize after any error), so that
// error must not label a later, unrelated failure. Nothing is cleared: a
// blocked error in the fallback record (for example a legacy SSE stream that
// went over the size cap at any time) still explains later failures.
func (ev *httpEvents) markConnected() {
	ev.sessionUp.Store(true)
	ev.connectDone.Store(true)
}

// connected implements transportEvents.
func (ev *httpEvents) connected() bool {
	return ev.sessionUp.Load()
}

// finishCall finishes rec (see requestRecorder.finish) and stores it as the
// record of the call that finished last. During the connect, it also keeps
// the first record with a blocked error in connectBlocked. callRecords calls
// it when a call returns. A nil rec changes nothing.
func (ev *httpEvents) finishCall(rec *requestRecorder) {
	if rec == nil {
		return
	}
	rec.finish()
	ev.lastCall.Store(rec)
	if !ev.connectDone.Load() && rec.blockedErr() != nil {
		// CompareAndSwap stores rec only if the pointer is still nil, in one
		// atomic step, so the first blocked call wins.
		ev.connectBlocked.CompareAndSwap(nil, rec)
	}
}

// recorderFor returns the record for req: the record of its MCP call, or the
// fallback record when the request belongs to no call.
func (ev *httpEvents) recorderFor(req *http.Request) *requestRecorder {
	if rec := recorderFrom(req.Context()); rec != nil {
		return rec
	}
	return &ev.fallback
}

// stateFor implements transportEvents. It finds the call record for err: the
// record in a *recordedError in the chain of err, or else the record of the
// call that finished last (for an error that mcpmoat made itself after a
// call, or a chain that lost the *recordedError). Then it picks blocked, in
// this order:
//
//  1. the blocked error of the call record;
//  2. else the blocked error of the fallback record, because a blocked
//     legacy SSE stream breaks every call after it;
//  3. else, while the connect is not done, the blocked error of
//     connectBlocked (see the field doc).
//
// status is the status of the call record if there is one, else the status
// of the fallback record.
func (ev *httpEvents) stateFor(err error) (status int, blocked error) {
	call := ev.lastCall.Load()
	// errors.As walks the chain of err and stops at the first *recordedError.
	// It needs a pointer to the target variable (&re), so that it can set re.
	var re *recordedError
	if errors.As(err, &re) && re.rec != nil {
		call = re.rec
	}

	if call != nil {
		blocked = call.blockedErr()
	}
	if blocked == nil {
		blocked = ev.fallback.blockedErr()
	}
	if blocked == nil && !ev.connectDone.Load() {
		if rec := ev.connectBlocked.Load(); rec != nil {
			blocked = rec.blockedErr()
		}
	}

	if call != nil {
		status = call.lastStatus()
	} else {
		status = ev.fallback.lastStatus()
	}
	return status, blocked
}

// recordedError links the error of one MCP call to the record of that call.
// callRecords wraps each failed call in it, so that stateFor can find the
// record later. The SDK does not return the request or the response with its
// errors, so there is no other link.
//
// Its text is the text of err, so the wrap changes no message. Unwrap returns
// err, so errors.Is and errors.As still see the whole chain below, as the SDK
// and classify expect.
type recordedError struct {
	// err is the error of the call.
	err error
	// rec is the record of the call.
	rec *requestRecorder
}

// Error returns the text of the wrapped error.
func (e *recordedError) Error() string {
	return e.err.Error()
}

// Unwrap returns the wrapped error. errors.Is and errors.As call it to walk
// the chain.
func (e *recordedError) Unwrap() error {
	return e.err
}
