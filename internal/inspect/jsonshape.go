package inspect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
)

// MaxJSONDepth is the deepest nesting of objects and arrays that one JSON
// message from a server can have. The JSON-RPC envelope uses about 5 levels
// and real tool schemas use fewer than 25, so 64 leaves a wide margin. The
// SDK itself refuses only more than 1000 levels, and that check bounds the
// stack, not the memory.
const MaxJSONDepth = 64

// MaxJSONValues is the most JSON values (objects, arrays, strings, object
// keys, numbers, true, false and null) that one JSON message from a server
// can have. A large real server with about 100 tools sends about 10,000 to
// 20,000 values in one tools/list page. The smallest value, an empty object,
// needs about 60 bytes in memory after decoding, so 100,000 values are about
// 6 to 10 MiB of decoded data: well below 64 MiB for one message, even in the
// worst case.
const MaxJSONValues = 100_000

// maxJSONStringBytes is the longest string (or number or literal) that one
// JSON message from a server can have, in raw bytes as sent. A string decodes
// to about its raw size: escapes only make it shorter, and an invalid UTF-8
// byte becomes the 3-byte replacement character, so at most 3 times. 1 MiB is
// about 100 times a large tool description.
const maxJSONStringBytes = 1 << 20 // 1 MiB

// errJSONTooComplex means that a server sent a JSON message that goes over
// one of the shape limits (jsonLimits). Its text is fixed and holds no server
// data.
var errJSONTooComplex = errors.New("server sent JSON that is too deeply nested, has too many values or has a too long string")

// jsonLimits holds the shape limits for one JSON message. All limits must be
// positive. A limit of 0 or less does not refuse every message:
//
//   - values refuses every message, because each message has a value.
//   - depth refuses every object and array, but a top-level string, number
//     or literal still passes.
//   - stringBytes refuses every number, literal and non-empty string, but an
//     empty string ("") still passes, because it has no bytes between its
//     quotes.
type jsonLimits struct {
	// depth is the deepest nesting of objects and arrays.
	depth int
	// values is the most values in one message, object keys included.
	values int
	// stringBytes is the longest string, number or literal, in raw bytes.
	stringBytes int
}

// defaultJSONLimits returns the limits that the inspector uses:
// MaxJSONDepth, MaxJSONValues and maxJSONStringBytes.
func defaultJSONLimits() jsonLimits {
	return jsonLimits{
		depth:       MaxJSONDepth,
		values:      MaxJSONValues,
		stringBytes: maxJSONStringBytes,
	}
}

// shapeChecker gets the bytes of a stream, chunk by chunk, and returns an
// error when the data goes over a shape limit. jsonShape checks a stream of
// JSON values; sseShape checks the JSON in the data fields of a Server-Sent
// Events stream.
type shapeChecker interface {
	write(p []byte) error
}

// Compile-time checks: both types must implement shapeChecker (see the
// templateLister check in list.go for how such a check works).
var (
	_ shapeChecker = (*jsonShape)(nil)
	_ shapeChecker = (*sseShape)(nil)
)

// jsonShape is a small state machine that counts the shape of a stream of
// JSON values, byte by byte, without decoding it. It keeps no data, only
// counters, so its memory is constant whatever the input.
//
// It does not validate the JSON. Its rule is to never count less than a
// decoder would build, on any input, valid or not:
//
//   - '{' and '[' add one value and one level of depth.
//   - '}' and ']' remove one level. Depth never goes below 0, so extra closing
//     brackets cannot make room for more levels.
//   - Each string adds one value, object keys too. Its raw bytes are counted
//     from the opening quote to the closing quote. A backslash escapes the
//     next byte, so an escaped quote does not end the string.
//   - Outside strings, a run of bytes that are not whitespace, ',', ':', '"'
//     or brackets is a number or a literal (true, false, null, or garbage).
//     The start of each run adds one value, and its bytes count as a string.
//
// The counters are per message. A message ends when a top-level value ends:
// when depth goes back to 0 after a closing bracket, or when a string or a
// run ends at depth 0. Then the counters start again. This is how the SDK
// reads its input: the stdio transport decodes one value after another, and
// for an HTTP body or an SSE event it decodes only the first value.
//
// Once a limit is exceeded, jsonShape stays failed: every later write and
// reset keeps the same error. It is not safe for concurrent use.
type jsonShape struct {
	// limits are the limits for one message.
	limits jsonLimits
	// depth is the current nesting of objects and arrays.
	depth int
	// values is the number of values in the current message.
	values int
	// inString is true between the quotes of a string.
	inString bool
	// escape is true when the previous byte in a string was a backslash, so
	// this byte is part of an escape sequence.
	escape bool
	// inScalar is true inside a run of number or literal bytes.
	inScalar bool
	// runBytes is the raw byte length of the current string or run.
	runBytes int
	// err is set at the first exceeded limit. Every later call returns it.
	err error
}

// newJSONShape returns a jsonShape that checks against limits.
func newJSONShape(limits jsonLimits) *jsonShape {
	return &jsonShape{limits: limits}
}

// write checks the next bytes of the stream. p can end anywhere, also in the
// middle of a string or an escape: the state carries over to the next call.
// It returns an error that wraps errJSONTooComplex at the first exceeded
// limit, and the same error on every later call.
func (s *jsonShape) write(p []byte) error {
	for _, b := range p {
		if err := s.writeByte(b); err != nil {
			return err
		}
	}
	return s.err
}

// writeByte checks one more byte of the stream, as write does.
func (s *jsonShape) writeByte(b byte) error {
	if s.err != nil {
		return s.err
	}
	if err := s.step(b); err != nil {
		s.err = err
		return err
	}
	return nil
}

// reset forgets the current message and starts at depth 0 outside any
// string, as at the start of a stream. sseShape calls it at the end of each
// event. A failed jsonShape stays failed.
func (s *jsonShape) reset() {
	s.depth = 0
	s.values = 0
	s.inString = false
	s.escape = false
	s.inScalar = false
	s.runBytes = 0
}

// step reads one byte. It returns a non-nil error when a limit is exceeded.
func (s *jsonShape) step(b byte) error {
	if s.inString {
		return s.stringByte(b)
	}
	switch b {
	case '"':
		s.endScalar()
		s.inString = true
		s.runBytes = 0
		return s.addValue()
	case '{', '[':
		s.endScalar()
		if err := s.addValue(); err != nil {
			return err
		}
		s.depth++
		if s.depth > s.limits.depth {
			return fmt.Errorf("%w (more than %d levels)", errJSONTooComplex, s.limits.depth)
		}
		return nil
	case '}', ']':
		s.endScalar()
		if s.depth > 0 {
			s.depth--
			if s.depth == 0 {
				s.endMessage()
			}
		}
		return nil
	case ' ', '\t', '\n', '\r', ',', ':':
		s.endScalar()
		return nil
	}
	// Any other byte is part of a number or a literal. Only the first byte
	// of a run adds a value.
	if !s.inScalar {
		s.inScalar = true
		s.runBytes = 0
		if err := s.addValue(); err != nil {
			return err
		}
	}
	return s.addRunByte()
}

// stringByte reads one byte inside a string.
func (s *jsonShape) stringByte(b byte) error {
	switch {
	case s.escape:
		// This byte belongs to the escape, so even a '"' does not end the
		// string.
		s.escape = false
	case b == '\\':
		s.escape = true
	case b == '"':
		s.inString = false
		s.runBytes = 0
		if s.depth == 0 {
			s.endMessage()
		}
		return nil
	}
	return s.addRunByte()
}

// addValue counts one more value in the current message.
func (s *jsonShape) addValue() error {
	s.values++
	if s.values > s.limits.values {
		return fmt.Errorf("%w (more than %d values)", errJSONTooComplex, s.limits.values)
	}
	return nil
}

// addRunByte counts one more raw byte of the current string or run.
func (s *jsonShape) addRunByte() error {
	s.runBytes++
	if s.runBytes > s.limits.stringBytes {
		return fmt.Errorf("%w (more than %d bytes)", errJSONTooComplex, s.limits.stringBytes)
	}
	return nil
}

// endScalar ends the current run of number or literal bytes, if there is
// one. A run at depth 0 is a whole top-level value, so it ends the message.
func (s *jsonShape) endScalar() {
	if !s.inScalar {
		return
	}
	s.inScalar = false
	s.runBytes = 0
	if s.depth == 0 {
		s.endMessage()
	}
}

// endMessage starts the counters of a new message. It is called only at
// depth 0, outside any string or run.
func (s *jsonShape) endMessage() {
	s.values = 0
	s.runBytes = 0
}

// sseLineState tells which part of an SSE line sseShape is in.
type sseLineState int

// The parts of an SSE line.
const (
	// sseName: the field name, before the first ':'.
	sseName sseLineState = iota
	// sseData: the value of a "data" field, after the first ':'.
	sseData
	// sseSkip: the value of any other field, or the rest of a line without
	// a ':'. sseShape ignores it.
	sseSkip
)

// sseDataKey is the only SSE field name whose value the SDK decodes as JSON.
// It is a constant string, not a []byte, so nothing can change it.
const sseDataKey = "data"

// sseShape checks a Server-Sent Events stream. It feeds only the values of
// the data fields to a jsonShape, with the same framing as the SDK SSE
// scanner (scanEventsLimited in the SDK file mcp/event.go):
//
//   - Lines end at '\n'. Trailing '\r' bytes are not part of the line.
//   - The field name is the bytes before the first ':'. Only a name that is
//     exactly "data" counts.
//   - The SDK trims the spaces around a data value and joins the data lines
//     of an event with '\n'. sseShape feeds the value untrimmed and a '\n'
//     after each data line. The extra bytes are only whitespace, which can
//     only make the counts higher, never lower.
//   - A line that is empty (or only '\r' bytes) ends the event. The SDK
//     decodes each event on its own, so the jsonShape is reset there.
//
// sseShape streams the data bytes into the jsonShape as they arrive. It
// keeps no line buffer: a few counters are enough to match the field name,
// so lines and names can be split across write calls at any byte.
//
// It is not safe for concurrent use.
type sseShape struct {
	// json checks the data values of the current event.
	json *jsonShape
	// state is the part of the current line.
	state sseLineState
	// nameLen is the number of field name bytes read so far. It stops at
	// len(sseDataKey)+1, which is enough to know that the name is too long.
	nameLen int
	// nameIsData is true while the name bytes so far are a prefix of
	// sseDataKey.
	nameIsData bool
	// onlyCR is true while the current line has only '\r' bytes (or none),
	// so a '\n' now makes it an empty line.
	onlyCR bool
}

// newSSEShape returns an sseShape whose data values are checked against
// limits.
func newSSEShape(limits jsonLimits) *sseShape {
	s := &sseShape{json: newJSONShape(limits)}
	s.newLine()
	return s
}

// newLine starts a new line.
func (s *sseShape) newLine() {
	s.state = sseName
	s.nameLen = 0
	s.nameIsData = true
	s.onlyCR = true
}

// write checks the next bytes of the stream. p can end anywhere. It returns
// an error that wraps errJSONTooComplex when a data value goes over a limit,
// and the same error on every later call.
func (s *sseShape) write(p []byte) error {
	if s.json.err != nil {
		return s.json.err
	}
	for len(p) > 0 {
		switch s.state {
		case sseData:
			// Feed the data bytes up to the end of the line in one call.
			// bytes.IndexByte returns -1 when there is no '\n' in p.
			i := bytes.IndexByte(p, '\n')
			if i < 0 {
				return s.json.write(p)
			}
			if err := s.json.write(p[:i]); err != nil {
				return err
			}
			// The SDK joins the data lines of an event with a '\n'.
			if err := s.json.writeByte('\n'); err != nil {
				return err
			}
			s.newLine()
			p = p[i+1:]
		case sseSkip:
			i := bytes.IndexByte(p, '\n')
			if i < 0 {
				return nil
			}
			s.newLine()
			p = p[i+1:]
		default: // sseName
			s.nameByte(p[0])
			p = p[1:]
		}
	}
	return nil
}

// nameByte reads one byte of the field name part of a line.
func (s *sseShape) nameByte(b byte) {
	switch b {
	case '\n':
		// A line without a ':'. If it is empty, the event ends. Else the SDK
		// stops at a malformed line; there is nothing to count.
		if s.onlyCR {
			s.json.reset()
		}
		s.newLine()
	case ':':
		if s.nameIsData && s.nameLen == len(sseDataKey) {
			s.state = sseData
		} else {
			s.state = sseSkip
		}
	default:
		if b != '\r' {
			s.onlyCR = false
		}
		if s.nameLen >= len(sseDataKey) || b != sseDataKey[s.nameLen] {
			s.nameIsData = false
		}
		// Stop counting one past the key length, so the counter cannot
		// grow on a very long name.
		if s.nameLen <= len(sseDataKey) {
			s.nameLen++
		}
	}
}

// shapeReader wraps a response body or a stdio stream and checks each chunk
// that Read returns with a shapeChecker before the SDK sees it. When a chunk
// goes over a limit, Read returns 0 bytes and the error, and the same error
// on every later Read, so the SDK never decodes the message that is too
// complex.
//
// Read must be called from one goroutine at a time, as for any io.Reader.
// exceeded can be called from any goroutine at any time.
type shapeReader struct {
	// rc is the wrapped stream.
	rc io.ReadCloser
	// check counts the shape of the bytes read so far.
	check shapeChecker
	// onFail, if not nil, is called once, at the first violation, with the
	// error of check. If it returns a non-nil error, Read returns that
	// error instead. For example, an HTTP client can store the error in its
	// request record, because the SDK can hide the error of a body.
	onFail func(error) error
	// err is the error that Read returns after a violation. Only Read uses
	// it, so it needs no lock.
	err error
	// failed is set after a violation. It is an atomic.Bool, because
	// exceeded can run in another goroutine than Read: an atomic value can
	// be read and written by many goroutines at once without a data race.
	failed atomic.Bool
}

// The compiler checks that shapeReader implements io.ReadCloser.
var _ io.ReadCloser = (*shapeReader)(nil)

// newJSONShapeReader returns a shapeReader that checks rc as a stream of
// JSON values (an HTTP application/json body or the stdout of a stdio
// server). onFail can be nil.
func newJSONShapeReader(rc io.ReadCloser, limits jsonLimits, onFail func(error) error) *shapeReader {
	return &shapeReader{rc: rc, check: newJSONShape(limits), onFail: onFail}
}

// newSSEShapeReader returns a shapeReader that checks rc as a Server-Sent
// Events stream (an HTTP text/event-stream body). onFail can be nil.
func newSSEShapeReader(rc io.ReadCloser, limits jsonLimits, onFail func(error) error) *shapeReader {
	return &shapeReader{rc: rc, check: newSSEShape(limits), onFail: onFail}
}

// Read reads from the wrapped stream and checks the bytes. It returns the
// bytes and the error of the wrapped Read unchanged, unless the bytes go
// over a limit. Then it returns 0 and an error that wraps errJSONTooComplex
// (or the error from onFail), now and on every later call.
func (r *shapeReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.rc.Read(p)
	if n > 0 {
		if cerr := r.check.write(p[:n]); cerr != nil {
			r.fail(cerr)
			return 0, r.err
		}
	}
	return n, err
}

// fail stores the error that Read returns from now on and sets the flag
// for exceeded. It calls onFail only here, and Read calls fail at most once
// because r.err is set afterwards.
func (r *shapeReader) fail(cerr error) {
	r.err = cerr
	if r.onFail != nil {
		if ferr := r.onFail(cerr); ferr != nil {
			r.err = ferr
		}
	}
	r.failed.Store(true)
}

// exceeded reports whether the stream went over a shape limit. It is safe to
// call from any goroutine.
func (r *shapeReader) exceeded() bool {
	return r.failed.Load()
}

// Close closes the wrapped stream.
func (r *shapeReader) Close() error {
	return r.rc.Close()
}
