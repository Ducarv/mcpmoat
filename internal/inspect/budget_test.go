package inspect

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestByteBudgetSpend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		total    int
		spends   []int
		wantErrs []bool // one for each spend: true means an error
		wantLeft int
	}{
		{
			name:     "under the budget",
			total:    10,
			spends:   []int{3, 4},
			wantErrs: []bool{false, false},
			wantLeft: 3,
		},
		{
			name:     "exactly the budget",
			total:    10,
			spends:   []int{4, 6},
			wantErrs: []bool{false, false},
			wantLeft: 0,
		},
		{
			name:     "over the budget leaves it unchanged",
			total:    10,
			spends:   []int{8, 3, 2},
			wantErrs: []bool{false, true, false},
			wantLeft: 0,
		},
		{
			name:     "zero bytes from an empty budget",
			total:    0,
			spends:   []int{0},
			wantErrs: []bool{false},
			wantLeft: 0,
		},
		{
			name:     "one byte from an empty budget",
			total:    0,
			spends:   []int{1},
			wantErrs: []bool{true},
			wantLeft: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := newByteBudget(tt.total)
			for i, n := range tt.spends {
				err := b.spend(n)
				if gotErr := err != nil; gotErr != tt.wantErrs[i] {
					t.Fatalf("spend #%d (%d) error = %v, want error %t", i, n, err, tt.wantErrs[i])
				}
				if err == nil {
					continue
				}
				if !errors.Is(err, ErrTooManyItems) {
					t.Errorf("spend #%d error = %v, want errors.Is ErrTooManyItems", i, err)
				}
				if want := strconv.Itoa(tt.total) + " bytes"; !strings.Contains(err.Error(), want) {
					t.Errorf("spend #%d error = %q, want the budget %q in the text", i, err, want)
				}
			}
			if b.left != tt.wantLeft {
				t.Errorf("left = %d, want %d", b.left, tt.wantLeft)
			}
		})
	}
}

func TestToolSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tool Tool
		want int
	}{
		{name: "zero tool", tool: Tool{}, want: 0},
		{
			name: "all fields",
			tool: Tool{
				Name:         "ab",                                 // 2
				Title:        "cde",                                // 3
				Description:  "fghi",                               // 4
				InputSchema:  json.RawMessage(`{"type":"object"}`), // 17
				OutputSchema: json.RawMessage(`{}`),                // 2
			},
			want: 2 + 3 + 4 + 17 + 2,
		},
		{
			// len counts bytes, not runes: "é" is 2 bytes in UTF-8.
			name: "multibyte text",
			tool: Tool{Name: "é"},
			want: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := toolSize(tt.tool); got != tt.want {
				t.Errorf("toolSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPromptSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prompt Prompt
		want   int
	}{
		{name: "zero prompt", prompt: Prompt{}, want: 0},
		{
			name:   "no arguments",
			prompt: Prompt{Name: "ab", Title: "cde", Description: "fghi"},
			want:   2 + 3 + 4,
		},
		{
			name: "with arguments",
			prompt: Prompt{
				Name: "p", // 1
				Arguments: []PromptArgument{
					{Name: "ab", Title: "c", Description: "def", Required: true}, // 6
					{Name: "gh"}, // 2
				},
			},
			want: 1 + 6 + 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := promptSize(tt.prompt); got != tt.want {
				t.Errorf("promptSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestResourceSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resource Resource
		want     int
	}{
		{name: "zero resource", resource: Resource{}, want: 0},
		{
			name: "all fields",
			resource: Resource{
				URI:         "file:///a",  // 9
				Name:        "a",          // 1
				Title:       "bc",         // 2
				Description: "def",        // 3
				MIMEType:    "text/plain", // 10
			},
			want: 9 + 1 + 2 + 3 + 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resourceSize(tt.resource); got != tt.want {
				t.Errorf("resourceSize() = %d, want %d", got, tt.want)
			}
		})
	}
}
