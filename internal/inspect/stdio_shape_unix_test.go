//go:build unix

package inspect_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// shapeReason is the fixed text of errJSONTooComplex (jsonshape.go). The
// sentinel is not exported, so this external test cannot use errors.Is on
// it. It checks the fixed reason and the unwrapped cause instead.
const shapeReason = "server sent JSON that is too deeply nested, has too many values or has a too long string"

// TestSDKInspectHugeSchema checks that the stdio inspector refuses a server
// whose tools/list reply is small JSON text with very many values
// (issue #101).
//
// The huge-schema helper mode (helpermodes_unix_test.go) sends one reply
// line of about 7.5 MiB: a tool whose input schema holds an array of about
// 2.6 million empty objects, "[{},{},...]". That line is below the 8 MiB
// frame limit of the stdio transport and below the 8 MiB raw cap of the
// handshake and the lists (rawlimit.go), so the size caps let it through.
// Each empty object costs 3 bytes of JSON text but tens of bytes after the
// SDK decodes it, so without the JSON shape check (jsonshape.go) this one
// message would decode to hundreds of MB. Only the value count of the shape
// check stops it, so the test fails if that check is gone.
//
// A normal stdio server still passes the shape check: TestSDKInspectBenign
// (sdk_test.go) shows that.
//
// The test does not call t.Parallel: helperprocess_unix_test.go explains
// why. After the violation, the stop of the child can wait one stopGrace
// before the group kill, so the ctx is generous and the test has no tight
// time bound.
func TestSDKInspectHugeSchema(t *testing.T) {
	server := helperServer(t, "huge", "huge-schema")
	inspector := sdkNew(t, inspect.SDKOptions{})
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	start := time.Now()
	res, err := inspector.Inspect(ctx, server)
	elapsed := time.Since(start)
	t.Logf("Inspect returned after %v", elapsed)

	if err == nil {
		t.Fatalf("Inspect() error = nil, want a KindTooLarge error; got %d tools", len(res.Tools))
	}
	var ce *inspect.ConnectError
	if !errors.As(err, &ce) {
		t.Fatalf("Inspect() error = %v (%T), want a *inspect.ConnectError", err, err)
	}
	if ce.Kind != inspect.KindTooLarge {
		t.Errorf("ConnectError.Kind = %q, want %q (err = %v)", ce.Kind, inspect.KindTooLarge, err)
	}
	if ce.Server != "huge" {
		t.Errorf("ConnectError.Server = %q, want %q", ce.Server, "huge")
	}
	// The reason must name the shape limit, not the raw size limit or a
	// generic "connection closed".
	if ce.Reason != shapeReason {
		t.Errorf("ConnectError.Reason = %q, want %q", ce.Reason, shapeReason)
	}
	// The cause is the sentinel itself (stdioFailure sets it), so its text
	// is the same fixed text.
	if cause := errors.Unwrap(ce); cause == nil || cause.Error() != shapeReason {
		t.Errorf("errors.Unwrap(ConnectError) = %v, want the shape sentinel %q", cause, shapeReason)
	}
	// An ended ctx would win over the shape error (KindTimeout), so these
	// must not be in the chain.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Errorf("Inspect() error = %v, want no context error in the chain", err)
	}
	// The error text is fixed and holds no server data.
	if msg := err.Error(); strings.Contains(msg, "{},{}") || len(msg) > 512 {
		t.Errorf("Inspect() error text has %d bytes and must not hold server data: %.200q", len(msg), msg)
	}
	if res.Tools != nil {
		t.Errorf("Inspect() Tools = %d tools, want nil on error", len(res.Tools))
	}
}
