package pins

import (
	"encoding/json/v2"
	"testing"
)

// Exports of package pins for the project share tests in
// store_share_test.go.

// ProjectBytes returns the bytes that the project servers use, as the Store
// tracks them (projectBytes).
func (s *Store) ProjectBytes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.projectBytes
}

// ProjectEntrySum returns the sum of entrySize over the entries of s whose
// Identity has a ProjectPath. It measures the servers map again and does not
// use isProjectServer or projectPart, so it is a check of projectBytes that
// does not share their rule.
func (s *Store) ProjectEntrySum(t testing.TB) int {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	sum := 0
	for id, p := range s.servers {
		if id.ProjectPath == "" {
			continue
		}
		size, err := entrySize(id, p)
		if err != nil {
			t.Fatalf("entrySize() error = %v", err)
		}
		sum += size
	}
	return sum
}

// EntrySize is entrySize: the bytes of one entry in the file that Save
// writes, the measure of the file limit and of the project share.
func EntrySize(t testing.TB, id Identity, p ServerPins) int {
	t.Helper()
	size, err := entrySize(id, p)
	if err != nil {
		t.Fatalf("entrySize() error = %v", err)
	}
	return size
}

// CompactSize returns the size of the entry of id as compact JSON, the
// measure of the per-server limit (MaxServerSize) in ValidateServer.
func CompactSize(t testing.TB, id Identity, p ServerPins) int {
	t.Helper()
	data, err := json.Marshal(newFileServer(id, p))
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return len(data)
}
