package inspect_test

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

func TestDefaultOptions(t *testing.T) {
	t.Parallel()

	got := inspect.DefaultOptions()

	want := inspect.Options{Timeout: 10 * time.Second, Concurrency: 4}
	if got != want {
		t.Errorf("DefaultOptions() = %+v, want %+v", got, want)
	}
	if got.Timeout != inspect.DefaultTimeout {
		t.Errorf("DefaultOptions().Timeout = %s, want DefaultTimeout %s", got.Timeout, inspect.DefaultTimeout)
	}
	if got.Concurrency != inspect.DefaultConcurrency {
		t.Errorf("DefaultOptions().Concurrency = %d, want DefaultConcurrency %d", got.Concurrency, inspect.DefaultConcurrency)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("DefaultOptions().Validate() = %v, want nil", err)
	}
}

func TestOptionsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts inspect.Options
		// wantErr lists substrings that the error text must contain.
		// An empty list means Validate must return nil.
		wantErr []string
		// notErr lists substrings that the error text must not contain.
		notErr []string
		// wantIs, if not nil, is the sentinel error that the error must wrap.
		wantIs error
	}{
		{name: "defaults", opts: inspect.DefaultOptions()},
		{name: "minimum valid values", opts: inspect.Options{Timeout: time.Nanosecond, Concurrency: 1}},
		{name: "large concurrency", opts: inspect.Options{Timeout: time.Second, Concurrency: 1_000_000}},
		{name: "max concurrency", opts: inspect.Options{Timeout: time.Second, Concurrency: math.MaxInt}},
		{name: "max timeout", opts: inspect.Options{Timeout: time.Duration(math.MaxInt64), Concurrency: 1}},
		{
			name:    "zero timeout",
			wantIs:  inspect.ErrInvalidTimeout,
			opts:    inspect.Options{Timeout: 0, Concurrency: 4},
			wantErr: []string{"timeout"},
			notErr:  []string{"concurrency"},
		},
		{
			name:    "negative timeout",
			wantIs:  inspect.ErrInvalidTimeout,
			opts:    inspect.Options{Timeout: -time.Second, Concurrency: 4},
			wantErr: []string{"timeout"},
			notErr:  []string{"concurrency"},
		},
		{
			name:    "zero concurrency",
			wantIs:  inspect.ErrInvalidConcurrency,
			opts:    inspect.Options{Timeout: 10 * time.Second, Concurrency: 0},
			wantErr: []string{"concurrency"},
			notErr:  []string{"timeout"},
		},
		{
			name:    "negative concurrency",
			wantIs:  inspect.ErrInvalidConcurrency,
			opts:    inspect.Options{Timeout: 10 * time.Second, Concurrency: -1},
			wantErr: []string{"concurrency"},
			notErr:  []string{"timeout"},
		},
		{
			// The timeout check runs first, so a bad timeout is reported.
			name:    "both bad",
			wantIs:  inspect.ErrInvalidTimeout,
			opts:    inspect.Options{Timeout: -time.Second, Concurrency: -1},
			wantErr: []string{"timeout"},
		},
		{
			name:    "zero value Options",
			wantIs:  inspect.ErrInvalidTimeout,
			opts:    inspect.Options{},
			wantErr: []string{"timeout"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.opts.Validate()
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("Validate(%+v) = %v, want nil", tt.opts, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate(%+v) = nil, want an error", tt.opts)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("Validate(%+v) error %v, want it to wrap %v", tt.opts, err, tt.wantIs)
			}
			msg := strings.ToLower(err.Error())
			for _, s := range tt.wantErr {
				if !strings.Contains(msg, s) {
					t.Errorf("Validate(%+v) error %q does not name %q", tt.opts, err, s)
				}
			}
			for _, s := range tt.notErr {
				if strings.Contains(msg, s) {
					t.Errorf("Validate(%+v) error %q names %q, want only the bad field", tt.opts, err, s)
				}
			}
		})
	}
}

// TestStatusValues pins the Status strings. They are a contract for the JSON
// output, so a change here is a breaking change.
func TestStatusValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  inspect.Status
		want string
	}{
		{name: "ok", got: inspect.StatusOK, want: "ok"},
		{name: "timeout", got: inspect.StatusTimeout, want: "timeout"},
		{name: "failed", got: inspect.StatusFailed, want: "failed"},
	}
	seen := make(map[inspect.Status]string, len(tests))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if string(tt.got) != tt.want {
				t.Errorf("Status %s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
		if prev, dup := seen[tt.got]; dup {
			t.Errorf("Status %s has the same value as %s", tt.name, prev)
		}
		seen[tt.got] = tt.name
	}
}
