package inspect

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// page is one response of a fake fetch function.
type page struct {
	items []int
	next  string
	err   error
}

// fakeFetch returns a fetch function that answers call i with pages[i]. It
// records the cursor of each call in *cursors. A call past the end of pages
// fails the test.
func fakeFetch(t *testing.T, pages []page, cursors *[]string) func(context.Context, string) ([]int, string, error) {
	t.Helper()
	return func(_ context.Context, cursor string) ([]int, string, error) {
		i := len(*cursors)
		*cursors = append(*cursors, cursor)
		if i >= len(pages) {
			t.Errorf("fetch called %d times, want at most %d", i+1, len(pages))
			return nil, "", errors.New("unexpected call")
		}
		p := pages[i]
		return p.items, p.next, p.err
	}
}

// seq returns the ints from start to start+n-1.
func seq(start, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = start + i
	}
	return out
}

// unitSize is the size function of the tests: each int costs one byte.
func unitSize(int) int { return 1 }

// longCursor is a distinctive cursor value. No error text may contain it.
var longCursor = "CURSOR-" + strings.Repeat("x9", 200) + "-END"

func TestCollect(t *testing.T) {
	t.Parallel()

	errFetch := errors.New("fetch failed")

	tests := []struct {
		name        string
		pages       []page
		budget      int // 0 means maxBytes
		want        []int
		wantErr     error // nil means no error
		wantCursors []string
	}{
		{
			name:        "single page",
			pages:       []page{{items: []int{1, 2, 3}}},
			want:        []int{1, 2, 3},
			wantCursors: []string{""},
		},
		{
			name: "three pages in order",
			pages: []page{
				{items: []int{1, 2}, next: "c1"},
				{items: []int{3}, next: "c2"},
				{items: []int{4, 5}},
			},
			want:        []int{1, 2, 3, 4, 5},
			wantCursors: []string{"", "c1", "c2"},
		},
		{
			// Empty, not nil: a nil slice in a Result means that the
			// server does not advertise the kind.
			name:        "zero items",
			pages:       []page{{}},
			want:        []int{},
			wantCursors: []string{""},
		},
		{
			name: "empty middle page",
			pages: []page{
				{items: []int{1}, next: "c1"},
				{next: "c2"},
				{items: []int{2}},
			},
			want:        []int{1, 2},
			wantCursors: []string{"", "c1", "c2"},
		},
		{
			name: "repeated cursor",
			pages: []page{
				{items: []int{1}, next: longCursor},
				{items: []int{2}, next: "c2"},
				{items: []int{3}, next: longCursor},
			},
			wantErr:     ErrTooManyItems,
			wantCursors: []string{"", longCursor, "c2"},
		},
		{
			name: "same cursor twice in a row",
			pages: []page{
				{items: []int{1}, next: longCursor},
				{items: []int{2}, next: longCursor},
			},
			wantErr:     ErrTooManyItems,
			wantCursors: []string{"", longCursor},
		},
		{
			name:        "item cap in one page",
			pages:       []page{{items: seq(0, maxItems+1)}},
			wantErr:     ErrTooManyItems,
			wantCursors: []string{""},
		},
		{
			name: "item cap over two pages",
			pages: []page{
				{items: seq(0, maxItems), next: longCursor},
				{items: []int{maxItems}},
			},
			wantErr:     ErrTooManyItems,
			wantCursors: []string{"", longCursor},
		},
		{
			name: "exactly maxItems is allowed",
			pages: []page{
				{items: seq(0, maxItems-1), next: "c1"},
				{items: []int{maxItems - 1}},
			},
			want:        seq(0, maxItems),
			wantCursors: []string{"", "c1"},
		},
		{
			name: "byte budget exceeded on page 2",
			pages: []page{
				{items: []int{1, 2}, next: longCursor},
				{items: []int{3, 4}, next: "c2"},
				{items: []int{5}},
			},
			budget:      3,
			wantErr:     ErrTooManyItems,
			wantCursors: []string{"", longCursor},
		},
		{
			name: "byte budget exceeded on page 1",
			pages: []page{
				{items: []int{1, 2, 3}, next: longCursor},
			},
			budget:      2,
			wantErr:     ErrTooManyItems,
			wantCursors: []string{""},
		},
		{
			name: "exactly the byte budget is allowed",
			pages: []page{
				{items: []int{1, 2}, next: "c1"},
				{items: []int{3, 4}},
			},
			budget:      4,
			want:        []int{1, 2, 3, 4},
			wantCursors: []string{"", "c1"},
		},
		{
			name: "fetch error on page 2",
			pages: []page{
				{items: []int{1}, next: longCursor},
				{items: []int{2}, next: "c2", err: errFetch},
			},
			wantErr:     errFetch,
			wantCursors: []string{"", longCursor},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			budget := tt.budget
			if budget == 0 {
				budget = maxBytes
			}

			var cursors []string
			got, err := collect(t.Context(), newByteBudget(budget), unitSize, fakeFetch(t, tt.pages, &cursors))

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("collect() error = %v, want errors.Is %v", err, tt.wantErr)
				}
				if got != nil {
					t.Errorf("collect() items = %d items, want nil on error", len(got))
				}
				if strings.Contains(err.Error(), longCursor) {
					t.Errorf("collect() error text contains the cursor: %q", err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("collect() error = %v, want nil", err)
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("collect() = %v, want %v", got, tt.want)
				}
			}

			if !reflect.DeepEqual(cursors, tt.wantCursors) {
				t.Errorf("cursors passed to fetch = %q, want %q", cursors, tt.wantCursors)
			}
		})
	}
}

// TestCollectPageCap checks that a server that always sends a new cursor gets
// exactly maxPages requests and then an error.
func TestCollectPageCap(t *testing.T) {
	t.Parallel()

	calls := 0
	fetch := func(_ context.Context, _ string) ([]int, string, error) {
		calls++
		return []int{calls}, fmt.Sprintf("%s-%d", longCursor, calls), nil
	}

	got, err := collect(t.Context(), newByteBudget(maxBytes), unitSize, fetch)
	if !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("collect() error = %v, want errors.Is ErrTooManyItems", err)
	}
	if got != nil {
		t.Errorf("collect() items = %d items, want nil on error", len(got))
	}
	if calls != maxPages {
		t.Errorf("fetch calls = %d, want %d", calls, maxPages)
	}
	if strings.Contains(err.Error(), longCursor) {
		t.Errorf("collect() error text contains the cursor: %q", err.Error())
	}
}

// TestCollectExactlyMaxPages checks that maxPages pages, the last with an
// empty next cursor, is allowed.
func TestCollectExactlyMaxPages(t *testing.T) {
	t.Parallel()

	calls := 0
	fetch := func(_ context.Context, _ string) ([]int, string, error) {
		calls++
		if calls == maxPages {
			return []int{calls}, "", nil
		}
		return []int{calls}, fmt.Sprintf("c%d", calls), nil
	}

	got, err := collect(t.Context(), newByteBudget(maxBytes), unitSize, fetch)
	if err != nil {
		t.Fatalf("collect() error = %v, want nil", err)
	}
	if want := seq(1, maxPages); !reflect.DeepEqual(got, want) {
		t.Errorf("collect() = %v, want %v", got, want)
	}
	if calls != maxPages {
		t.Errorf("fetch calls = %d, want %d", calls, maxPages)
	}
}

func TestCollectContext(t *testing.T) {
	t.Parallel()

	t.Run("cancelled before first page", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		calls := 0
		fetch := func(_ context.Context, _ string) ([]int, string, error) {
			calls++
			return []int{1}, "", nil
		}

		got, err := collect(ctx, newByteBudget(maxBytes), unitSize, fetch)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("collect() error = %v, want errors.Is context.Canceled", err)
		}
		if got != nil {
			t.Errorf("collect() = %v, want nil", got)
		}
		if calls != 0 {
			t.Errorf("fetch calls = %d, want 0", calls)
		}
	})

	t.Run("cancelled by fetch on page 1", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		calls := 0
		fetch := func(_ context.Context, _ string) ([]int, string, error) {
			calls++
			cancel()
			return []int{calls}, longCursor, nil
		}

		got, err := collect(ctx, newByteBudget(maxBytes), unitSize, fetch)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("collect() error = %v, want errors.Is context.Canceled", err)
		}
		if got != nil {
			t.Errorf("collect() = %v, want nil", got)
		}
		if calls != 1 {
			t.Errorf("fetch calls = %d, want 1", calls)
		}
	})

	t.Run("fetch gets the context", func(t *testing.T) {
		t.Parallel()

		type key struct{}
		ctx := context.WithValue(t.Context(), key{}, "marker")

		var gotValue any
		fetch := func(ctx context.Context, _ string) ([]int, string, error) {
			gotValue = ctx.Value(key{})
			return nil, "", nil
		}

		if _, err := collect(ctx, newByteBudget(maxBytes), unitSize, fetch); err != nil {
			t.Fatalf("collect() error = %v, want nil", err)
		}
		if gotValue != "marker" {
			t.Errorf("fetch context value = %v, want %q", gotValue, "marker")
		}
	})
}

// TestCollectSharedBudget checks that two calls to collect with the same
// budget share it: the second call fails when the first used most of it.
func TestCollectSharedBudget(t *testing.T) {
	t.Parallel()

	budget := newByteBudget(5)

	var firstCursors []string
	first, err := collect(t.Context(), budget, unitSize, fakeFetch(t, []page{
		{items: []int{1, 2}, next: "c1"},
		{items: []int{3, 4}},
	}, &firstCursors))
	if err != nil {
		t.Fatalf("first collect() error = %v, want nil", err)
	}
	if want := []int{1, 2, 3, 4}; !reflect.DeepEqual(first, want) {
		t.Errorf("first collect() = %v, want %v", first, want)
	}

	// One byte is left. The second call fits one item on page 1, and page 2
	// goes over the budget.
	var secondCursors []string
	second, err := collect(t.Context(), budget, unitSize, fakeFetch(t, []page{
		{items: []int{5}, next: longCursor},
		{items: []int{6}},
	}, &secondCursors))
	if !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("second collect() error = %v, want errors.Is ErrTooManyItems", err)
	}
	if second != nil {
		t.Errorf("second collect() items = %d items, want nil on error", len(second))
	}
	if want := []string{"", longCursor}; !reflect.DeepEqual(secondCursors, want) {
		t.Errorf("second cursors = %q, want %q", secondCursors, want)
	}
	if strings.Contains(err.Error(), longCursor) {
		t.Errorf("second collect() error text contains the cursor: %q", err.Error())
	}
}

// TestCollectSizeFunc checks that collect uses the size function of the
// caller, not the number of items.
func TestCollectSizeFunc(t *testing.T) {
	t.Parallel()

	// Each int costs its own value in bytes: 10 + 20 = 30 > 29.
	valueSize := func(n int) int { return n }

	var cursors []string
	got, err := collect(t.Context(), newByteBudget(29), valueSize, fakeFetch(t, []page{
		{items: []int{10, 20}},
	}, &cursors))
	if !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("collect() error = %v, want errors.Is ErrTooManyItems", err)
	}
	if got != nil {
		t.Errorf("collect() items = %d items, want nil on error", len(got))
	}
}
