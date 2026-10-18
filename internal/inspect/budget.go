package inspect

import "fmt"

// maxBytes is the byte budget for the converted text of one server, shared by
// its tools, prompts and resources.
//
// The budget counts the bytes of the text that mcpmoat keeps in a [Result]:
// the strings of the handshake (protocol version, instructions, server name
// and version), and the names, titles, descriptions, URIs, MIME types,
// schemas and prompt arguments of the lists (see toolSize, promptSize and
// resourceSize).
//
// A page cap and an item cap alone do not bound the data: each page can be
// one very large frame. The budget bounds the text that mcpmoat keeps.
// Because collect stops at the first page that goes over the budget, it also
// bounds how many pages the SDK decodes and caches for the session: at most
// the budget plus one frame (the residual in the package doc, Limits).
//
// The budget counts bytes of text, not memory. The Go values that hold the
// text need more memory than the text, and the SDK holds its own decoded
// copy of each page too.
//
// Why 4 MiB: a large real server with about 100 tools sends well under
// 1 MiB of text, so a normal server is far below the budget. A low budget
// keeps the decoded data that it allows small, because decoded data can
// need many times more memory than its bytes.
//
// The budget does not count fields that mcpmoat drops, such as _meta or
// icons. maxRawBytes bounds those.
const maxBytes = 4 << 20 // 4 MiB

// maxRawBytes is the limit for the JSON size of all list pages (tools,
// prompts and resources) of one server, as the SDK decoded them. The
// sending middleware of listWatch measures each page before the SDK caches
// it, and fails the list call when the total goes over this limit.
//
// It bounds the JSON bytes of what the SDK client decodes and keeps in its
// list cache for the session, also the fields that mcpmoat drops (_meta,
// icons): at most this limit plus one frame, the frame that goes over it.
//
// It counts JSON bytes, not memory. Decoded JSON can need many times its
// size in memory: a page of many small empty objects, for example, needs
// about 20 times its JSON size. The SDK caches every page of the session,
// so the memory that this limit allows is many times the limit.
//
// Why 8 MiB: raw JSON has more bytes than the text that maxBytes counts
// (keys, quotes, escapes, and the fields that mcpmoat drops), so the limit is
// higher than maxBytes. It is set on its own, not as a multiple of maxBytes,
// because it bounds a different thing: the data that the SDK holds, not
// the text that mcpmoat keeps. A low value keeps the memory of the cached
// pages low, also in the worst case of about 20 times. The larger residual
// is one frame that the SDK decodes before listWatch can measure it (the
// package doc, Limits). A normal server is far below both limits.
const maxRawBytes = 8 << 20 // 8 MiB

// byteBudget is the number of bytes that one call to Inspect can still keep.
// inspectSession makes one byteBudget for each server and gives it to each
// call to collect, so tools, prompts and resources share it.
//
// A byteBudget is not safe for concurrent use. inspectSession lists one kind
// at a time, so it needs no mutex.
type byteBudget struct {
	total int // the budget at the start, for the error text
	left  int // the bytes that are still free
}

// newByteBudget returns a budget of n bytes.
func newByteBudget(n int) *byteBudget {
	return &byteBudget{total: n, left: n}
}

// spend takes n bytes from b. When n is more than what is left, spend
// returns an error that wraps [ErrTooManyItems] and b does not change. To
// use the budget exactly to zero is allowed.
//
// The error text gives the budget only, never server text.
func (b *byteBudget) spend(n int) error {
	if n > b.left {
		return fmt.Errorf("%w: more than %d bytes", ErrTooManyItems, b.total)
	}
	b.left -= n
	return nil
}

// toolSize returns the number of bytes of text in t.
func toolSize(t Tool) int {
	return len(t.Name) + len(t.Title) + len(t.Description) +
		len(t.InputSchema) + len(t.OutputSchema)
}

// promptSize returns the number of bytes of text in p, with its arguments.
func promptSize(p Prompt) int {
	n := len(p.Name) + len(p.Title) + len(p.Description)
	for _, a := range p.Arguments {
		n += len(a.Name) + len(a.Title) + len(a.Description)
	}
	return n
}

// resourceSize returns the number of bytes of text in r.
func resourceSize(r Resource) int {
	return len(r.URI) + len(r.Name) + len(r.Title) + len(r.Description) +
		len(r.MIMEType)
}
