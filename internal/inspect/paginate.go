package inspect

import (
	"context"
	"fmt"
)

// Limits for one list kind (tools, prompts or resources) of one server.
//
// A hostile server can send a next cursor forever, or very long pages. The
// list iterators of the MCP SDK have no cap, so collect applies these limits.
// The page cap bounds the number of requests, and the item cap bounds the
// number of items. Neither bounds the bytes: for that, collect also takes a
// byte budget that all kinds of one server share (see maxBytes).
const (
	// maxPages is the maximum number of pages that collect requests.
	maxPages = 100

	// maxItems is the maximum number of items that collect keeps in total.
	maxItems = 10_000
)

// collect requests pages from fetch until the server sends an empty next
// cursor, and returns all items in the order that the server sent them.
//
// The same loop lists tools, prompts and resources: the caller picks the item
// type through the fetch and size functions that it gives.
//
// The first call to fetch gets the cursor "". Each next call gets the next
// cursor of the previous page.
//
// After each page, before collect keeps the items, it takes the size of the
// page (the sum of size for each item) from budget. The caller gives the
// same budget to each call of collect for one server, so the budget is for
// the server, not for one kind. collect stops at the first page that goes
// over the budget, so it never requests the page after it.
//
// collect returns an error that wraps [ErrTooManyItems] when the server sends
// more than maxPages pages or more than maxItems items, sends more bytes than
// budget has left, or sends a cursor that it sent before. It returns the
// context error when ctx is done before a page, and the error of fetch,
// wrapped, when fetch fails. On an error, the items are nil. On success, the
// items are never nil, also when the server lists no items: a nil slice in a
// [Result] means that the server does not advertise the kind.
//
// The error text never contains a cursor: a cursor is untrusted text from the
// server and can be very long. The text gives counts only.
func collect[T any](
	ctx context.Context,
	budget *byteBudget,
	size func(T) int,
	fetch func(ctx context.Context, cursor string) (items []T, next string, err error),
) ([]T, error) {
	all := []T{}
	seen := make(map[string]struct{}) // non-empty cursors that the server sent
	cursor := ""

	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if page > maxPages {
			return nil, fmt.Errorf("%w: more than %d pages", ErrTooManyItems, maxPages)
		}

		items, next, err := fetch(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", page, err)
		}
		if len(all)+len(items) > maxItems {
			return nil, fmt.Errorf("%w: more than %d items", ErrTooManyItems, maxItems)
		}
		n := 0
		for _, item := range items {
			n += size(item)
		}
		if err := budget.spend(n); err != nil {
			return nil, fmt.Errorf("page %d: %w", page, err)
		}
		all = append(all, items...)

		if next == "" {
			return all, nil
		}
		if _, ok := seen[next]; ok {
			return nil, fmt.Errorf("%w: page %d repeats an earlier cursor", ErrTooManyItems, page)
		}
		seen[next] = struct{}{}
		cursor = next
	}
}
