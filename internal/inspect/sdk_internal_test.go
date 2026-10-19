package inspect

import (
	"slices"
	"strings"
	"testing"
)

// This file holds the unit tests of the unexported helpers of sdk.go.
// sdk_test.go is in package inspect_test and cannot reach them.

// TestLookupRecorder checks that lookupRecorder returns what the wrapped
// lookup returns, and records each value of at least minBareSecretLen bytes
// one time only, in the order of the first lookup.
func TestLookupRecorder(t *testing.T) {
	t.Parallel()

	long1 := "mcpmoat-recorder-canary-1aB2"
	long2 := "mcpmoat-recorder-canary-3cD4"
	atLimit := strings.Repeat("x", minBareSecretLen)
	belowLimit := strings.Repeat("y", minBareSecretLen-1)
	env := []string{
		"A=" + long1,
		"A_AGAIN=" + long1, // another variable with the same value
		"B=" + long2,
		"AT_LIMIT=" + atLimit,
		"SHORT=" + belowLimit,
		"EMPTY=",
	}

	tests := []struct {
		name    string
		lookups []string
		want    []string
	}{
		{name: "no lookup", lookups: nil, want: nil},
		{name: "one value", lookups: []string{"A"}, want: []string{long1}},
		{name: "same variable many times", lookups: []string{"A", "A", "A", "A"}, want: []string{long1}},
		{name: "same value from two variables", lookups: []string{"A", "A_AGAIN"}, want: []string{long1}},
		{name: "order of the first lookup", lookups: []string{"B", "A", "B", "A"}, want: []string{long2, long1}},
		{name: "value at the length limit", lookups: []string{"AT_LIMIT", "AT_LIMIT"}, want: []string{atLimit}},
		{name: "value below the length limit", lookups: []string{"SHORT", "SHORT"}, want: nil},
		{name: "empty value", lookups: []string{"EMPTY"}, want: nil},
		{name: "unset variable", lookups: []string{"UNSET", "UNSET"}, want: nil},
		{
			name:    "mixed",
			lookups: []string{"UNSET", "SHORT", "A", "AT_LIMIT", "A_AGAIN", "B", "A", "AT_LIMIT"},
			want:    []string{long1, atLimit, long2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lookup := environLookup(env)
			rec := &lookupRecorder{lookup: lookup}
			for _, name := range tt.lookups {
				gotV, gotOK := rec.Lookup(name)
				wantV, wantOK := lookup(name)
				if gotV != wantV || gotOK != wantOK {
					// Print the lengths only: the values stand for secrets.
					t.Errorf("Lookup(%q) = (len %d, %v), want (len %d, %v)", name, len(gotV), gotOK, len(wantV), wantOK)
				}
			}
			if !slices.Equal(rec.values, tt.want) {
				t.Errorf("values has %d entries, want %d (%d lookups); values equal = false",
					len(rec.values), len(tt.want), len(tt.lookups))
			}
		})
	}
}

// TestLookupRecorderZeroValue checks that a lookupRecorder with no seen map
// works: the first recorded value makes the map.
func TestLookupRecorderZeroValue(t *testing.T) {
	t.Parallel()
	const value = "mcpmoat-recorder-canary-5eF6"
	rec := lookupRecorder{lookup: func(string) (string, bool) { return value, true }}
	for range 3 {
		if v, ok := rec.Lookup("ANY"); v != value || !ok {
			t.Fatalf("Lookup() = (len %d, %v), want (len %d, true)", len(v), ok, len(value))
		}
	}
	if len(rec.values) != 1 || rec.values[0] != value {
		t.Errorf("values has %d entries, want 1 with the value", len(rec.values))
	}
}

// TestEnvironLookup checks that environLookup reads "name=value" entries the
// way os.LookupEnv does on Unix: the first entry wins, an entry with no "="
// is skipped, and an empty name is never found.
func TestEnvironLookup(t *testing.T) {
	t.Parallel()

	env := []string{
		"DUP=first",
		"DUP=second",
		"NOEQUALS",
		"EMPTY=",
		"=C:=C:\\work", // a Windows entry for the work directory of drive C
		"WITH_EQ=a=b",
	}
	tests := []struct {
		name      string
		lookup    string
		wantValue string
		wantOK    bool
	}{
		{name: "duplicate name, first entry wins", lookup: "DUP", wantValue: "first", wantOK: true},
		{name: "entry without = is skipped", lookup: "NOEQUALS", wantValue: "", wantOK: false},
		{name: "set and empty", lookup: "EMPTY", wantValue: "", wantOK: true},
		{name: "value holds =", lookup: "WITH_EQ", wantValue: "a=b", wantOK: true},
		{name: "unset name", lookup: "MISSING", wantValue: "", wantOK: false},
		{name: "empty name", lookup: "", wantValue: "", wantOK: false},
	}
	lookup := environLookup(env)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotValue, gotOK := lookup(tt.lookup)
			if gotValue != tt.wantValue || gotOK != tt.wantOK {
				t.Errorf("lookup(%q) = (%q, %v), want (%q, %v)", tt.lookup, gotValue, gotOK, tt.wantValue, tt.wantOK)
			}
		})
	}
}
