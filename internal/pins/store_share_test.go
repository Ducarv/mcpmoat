package pins_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/pins"
)

// shareBytes is the project share in bytes (16 MiB).
const shareBytes = pins.ProjectShareMiB << 20

// shareServers is the number of large servers that fillEntries sets. With 9,
// each entry is about 1.8 MiB, below the limit of one server (2 MiB).
const shareServers = 9

// shareFiller is the canonical text of the large test servers. Each server
// uses a prefix of it, so all of them share one allocation and the fixtures
// stay cheap.
var shareFiller = strings.Repeat("a", pins.MaxServerSize)

// shareProjectID returns the identity of the project server i, a server of
// the projects.<path> key of ~/.claude.json. The names have the same length,
// so all entries have the same fixed bytes. Every field holds leakToken, so a
// test can check that an error names none of them.
func shareProjectID(i int) pins.Identity {
	return pins.Identity{
		Client:      "claude-code",
		Source:      "/home/" + leakToken + "/.claude.json",
		ProjectPath: "/work/" + leakToken,
		Name:        fmt.Sprintf("%s-p%02d", leakToken, i),
	}
}

// shareUserID returns the identity of the user-scope server i: as
// shareProjectID, with an empty ProjectPath.
func shareUserID(i int) pins.Identity {
	id := shareProjectID(i)
	id.ProjectPath = ""
	id.Name = fmt.Sprintf("%s-u%02d", leakToken, i)
	return id
}

// sharePins returns the pins of one tool whose canonical text is n bytes.
// hash is one byte, so two pins of the same n with another hash have the same
// size and other content.
func sharePins(n int, hash string) pins.ServerPins {
	return pins.ServerPins{leakToken + "-tool": {Hash: hash, Canonical: shareFiller[:n]}}
}

// fillEntries sets shareServers servers id(0) to id(shareServers-1) in s, so
// that their entries take exactly total bytes together. It returns the
// canonical length of each server. Each byte of the canonical text is one byte
// of the entry, so the sizes are exact without a search.
func fillEntries(t *testing.T, s *pins.Store, id func(int) pins.Identity, total int) []int {
	t.Helper()
	base := pins.EntrySize(t, id(0), sharePins(0, "h"))
	lens := make([]int, shareServers)
	for i := range lens {
		lens[i] = total/shareServers - base
	}
	lens[shareServers-1] += total % shareServers
	for i, n := range lens {
		storeTestMustSet(t, s, id(i), sharePins(n, "h"))
	}
	return lens
}

// newFullShare returns a new Store whose project servers use exactly the
// project share, and the canonical length of each of them.
func newFullShare(t *testing.T) (*pins.Store, []int) {
	t.Helper()
	s := storeTestMustLoad(t, storeTestPath(t))
	lens := fillEntries(t, s, shareProjectID, shareBytes)
	wantProjectBytes(t, s, shareBytes)
	if got := s.ProjectEntrySum(t); got != shareBytes {
		t.Fatalf("setup: project entries = %d bytes, want %d", got, shareBytes)
	}
	return s, lens
}

// wantProjectBytes checks that s tracks want bytes of project servers.
func wantProjectBytes(t *testing.T, s *pins.Store, want int) {
	t.Helper()
	if got := s.ProjectBytes(); got != want {
		t.Errorf("ProjectBytes() = %d, want %d", got, want)
	}
}

// wantShareRefusal checks that err is a refusal by the project share, with
// projects bytes of project servers, and that its text names no server, tool
// or path.
func wantShareRefusal(t *testing.T, err error, projects int) {
	t.Helper()
	if !errors.Is(err, pins.ErrProjectShareFull) || !errors.Is(err, pins.ErrStoreFull) {
		t.Fatalf("Set() error = %v, want errors.Is ErrProjectShareFull and ErrStoreFull", err)
	}
	if strings.Contains(err.Error(), leakToken) {
		t.Errorf("Set() error = %q, want no names or paths", err)
	}
	want := fmt.Sprintf("%d bytes of project servers with this server, more than the %d MiB share", projects, pins.ProjectShareMiB)
	if !strings.Contains(err.Error(), want) {
		t.Errorf("Set() error = %q, want text %q", err, want)
	}
}

func TestProjectShareLimits(t *testing.T) {
	t.Parallel()
	if pins.ProjectShareMiB != 16 || shareBytes != pins.MaxFileSize/2 {
		t.Errorf("ProjectShareMiB = %d, want 16, half of MaxFileSize", pins.ProjectShareMiB)
	}
}

// TestProjectShareBytesTrackEntries checks with small servers that the tracked
// bytes of the project servers are the sum of their entry sizes after each
// step, and that only an identity with a ProjectPath counts.
func TestProjectShareBytesTrackEntries(t *testing.T) {
	t.Parallel()
	claudeProject := pins.Identity{Client: "claude-code", Source: "/home/u/.claude.json", ProjectPath: "/work/p", Name: "a"}
	mcpProject := pins.Identity{Client: "claude-code", Source: "/work/p/.mcp.json", ProjectPath: "/work/p", Name: "b"}
	cursorProject := pins.Identity{Client: "cursor", Source: "/work/q/.cursor/mcp.json", ProjectPath: "/work/q", Name: "c"}
	claudeUser := pins.Identity{Client: "claude-code", Source: "/home/u/.claude.json", Name: "a"}
	cursorUser := pins.Identity{Client: "cursor", Source: "/home/u/.cursor/mcp.json", Name: "c"}

	steps := []struct {
		name string
		id   pins.Identity
		p    pins.ServerPins
	}{
		{"projects.<path> of ~/.claude.json", claudeProject, storeTestPins("t", "h")},
		{"user server of ~/.claude.json", claudeUser, storeTestPins("t", "h", "u", "h2")},
		{"project .mcp.json, no tools", mcpProject, nil},
		{"cursor project", cursorProject, storeTestPins("t", "h")},
		{"cursor user", cursorUser, storeTestPins("t", "h")},
		{"larger project replacement", claudeProject, storeTestPins("t", "h", "v", "h3", "w", "h4")},
		{"smaller project replacement", cursorProject, nil},
		{"user replacement", claudeUser, nil},
		{"project tools added", mcpProject, storeTestPins("x", "h5")},
	}
	s := storeTestMustLoad(t, storeTestPath(t))
	for _, st := range steps {
		before := s.ProjectBytes()
		storeTestMustSet(t, s, st.id, st.p)
		if got, want := s.ProjectBytes(), s.ProjectEntrySum(t); got != want {
			t.Errorf("after %s: ProjectBytes() = %d, want the sum of the project entries %d", st.name, got, want)
		}
		if st.id.ProjectPath == "" && s.ProjectBytes() != before {
			t.Errorf("after %s: ProjectBytes() = %d, want %d: a user server must not count", st.name, s.ProjectBytes(), before)
		}
	}
	if s.ProjectBytes() == 0 {
		t.Fatal("ProjectBytes() = 0, want the project servers counted")
	}

	// Load counts the same bytes as the Sets.
	storeTestMustSave(t, s)
	wantProjectBytes(t, storeTestMustLoad(t, s.Path()), s.ProjectBytes())
}

// TestProjectShare fills the project share once and runs each case on a
// Clone, so the 16 MiB fixture is built once.
func TestProjectShare(t *testing.T) {
	t.Parallel()
	full, lens := newFullShare(t)
	id0 := shareProjectID(0)
	newID := shareProjectID(shareServers)

	t.Run("new project server is refused", func(t *testing.T) {
		t.Parallel()
		s := full.Clone()
		tracked := s.TrackedFileSize()
		for _, p := range []pins.ServerPins{nil, sharePins(1, "h")} {
			err := s.Set(newID, p)
			wantShareRefusal(t, err, shareBytes+pins.EntrySize(t, newID, p))
		}
		if _, ok := s.Get(newID); ok {
			t.Error("Get() of the refused server ok = true, want false")
		}
		wantProjectBytes(t, s, shareBytes)
		if got := s.TrackedFileSize(); got != tracked {
			t.Errorf("TrackedFileSize() = %d after the refusal, want %d", got, tracked)
		}
	})

	t.Run("replacements when the share is full", func(t *testing.T) {
		t.Parallel()
		s := full.Clone()
		tracked := s.TrackedFileSize()

		// One byte larger is refused, and the store does not change.
		wantShareRefusal(t, s.Set(id0, sharePins(lens[0]+1, "h")), shareBytes+1)
		storeTestWantPins(t, s, id0, sharePins(lens[0], "h"))
		wantProjectBytes(t, s, shareBytes)
		if got := s.TrackedFileSize(); got != tracked {
			t.Errorf("TrackedFileSize() = %d after the refusal, want %d", got, tracked)
		}

		// The same size with other content is accepted.
		storeTestMustSet(t, s, id0, sharePins(lens[0], "g"))
		wantProjectBytes(t, s, shareBytes)

		// A smaller one is accepted and gives back its bytes. A new project
		// server then fits exactly, and one byte more does not.
		free := pins.EntrySize(t, newID, sharePins(10, "h"))
		storeTestMustSet(t, s, id0, sharePins(lens[0]-free, "g"))
		wantProjectBytes(t, s, shareBytes-free)
		wantShareRefusal(t, s.Set(newID, sharePins(11, "h")), shareBytes+1)
		storeTestMustSet(t, s, newID, sharePins(10, "h"))
		wantProjectBytes(t, s, shareBytes)
	})

	t.Run("user server of full size fits", func(t *testing.T) {
		t.Parallel()
		s := full.Clone()
		uid := shareUserID(0)
		n := pins.MaxServerSize - pins.CompactSize(t, uid, sharePins(0, "h"))
		storeTestMustSet(t, s, uid, sharePins(n, "h"))
		wantProjectBytes(t, s, shareBytes)
		// n is the largest size of one server: one byte more fails the
		// per-server limit, not a store limit.
		if err := s.Set(uid, sharePins(n+1, "h")); err == nil || errors.Is(err, pins.ErrStoreFull) {
			t.Errorf("Set() one byte over the server limit error = %v, want the per-server error", err)
		}
		// The share is still full for project servers.
		wantShareRefusal(t, s.Set(newID, nil), shareBytes+pins.EntrySize(t, newID, nil))
	})

	t.Run("file limit wins for user servers", func(t *testing.T) {
		t.Parallel()
		s := full.Clone()
		fillEntries(t, s, shareUserID, pins.MaxFileSize-s.TrackedFileSize())
		if got := s.TrackedFileSize(); got != pins.MaxFileSize {
			t.Fatalf("setup: TrackedFileSize() = %d, want %d", got, pins.MaxFileSize)
		}
		wantProjectBytes(t, s, shareBytes)
		err := s.Set(shareUserID(shareServers), nil)
		if !errors.Is(err, pins.ErrStoreFull) || errors.Is(err, pins.ErrProjectShareFull) {
			t.Errorf("Set() of a user server error = %v, want ErrStoreFull and not ErrProjectShareFull", err)
		}
		if err != nil && strings.Contains(err.Error(), leakToken) {
			t.Errorf("Set() error = %q, want no names or paths", err)
		}
	})

	t.Run("Clone keeps the share", func(t *testing.T) {
		t.Parallel()
		orig := full.Clone()
		c := orig.Clone()
		wantProjectBytes(t, c, shareBytes)
		wantShareRefusal(t, c.Set(newID, nil), shareBytes+pins.EntrySize(t, newID, nil))

		// Free bytes on the clone only: the clone accepts the new server, and
		// the original still refuses it.
		free := pins.EntrySize(t, newID, nil)
		storeTestMustSet(t, c, id0, sharePins(lens[0]-free, "h"))
		storeTestMustSet(t, c, newID, nil)
		wantProjectBytes(t, c, shareBytes)

		wantProjectBytes(t, orig, shareBytes)
		storeTestWantPins(t, orig, id0, sharePins(lens[0], "h"))
		if _, ok := orig.Get(newID); ok {
			t.Error("original Get() of the server set on the clone ok = true, want false")
		}
		wantShareRefusal(t, orig.Set(newID, nil), shareBytes+free)
	})
}

// TestLoadOverProjectShare checks that Load reads a file whose project servers
// use more than the share, and that Set then refuses only growth.
func TestLoadOverProjectShare(t *testing.T) {
	t.Parallel()
	// The servers of fillEntries (one byte under the share, as the share is
	// not a multiple of shareServers) and one small project server, so the
	// file is just over the share. Set cannot build such a store, so the test
	// writes the file. Each Load of 16 MiB is slow under -race, so the file is
	// as small as it can be.
	const servers = shareServers + 1
	n := shareBytes/shareServers - pins.EntrySize(t, shareProjectID(0), sharePins(0, "h"))
	var b strings.Builder
	b.Grow(shareBytes)
	b.WriteString(`{"version":1,"servers":[`)
	for i := range servers {
		if i > 0 {
			b.WriteByte(',')
		}
		size := n
		if i == shareServers {
			size = 1
		}
		id := shareProjectID(i)
		fmt.Fprintf(&b, `{"client":%q,"source":%q,"project_path":%q,"name":%q,"tools":{"%s-tool":{"hash":"h","canonical":"%s"}}}`,
			id.Client, id.Source, id.ProjectPath, id.Name, leakToken, shareFiller[:size])
	}
	b.WriteString("]}")
	s := storeTestMustLoad(t, storeTestWrite(t, b.String()))

	over := s.ProjectBytes()
	if over <= shareBytes {
		t.Fatalf("setup: ProjectBytes() = %d, want more than the share %d", over, shareBytes)
	}
	if got := s.ProjectEntrySum(t); got != over {
		t.Fatalf("ProjectBytes() = %d after Load, want the sum of the project entries %d", over, got)
	}

	id0, id1, newID := shareProjectID(0), shareProjectID(1), shareProjectID(servers)
	storeTestMustSet(t, s, id0, sharePins(n, "g")) // same size, other content
	wantProjectBytes(t, s, over)

	wantShareRefusal(t, s.Set(id0, sharePins(n+1, "h")), over+1)
	storeTestWantPins(t, s, id0, sharePins(n, "g"))
	wantShareRefusal(t, s.Set(newID, nil), over+pins.EntrySize(t, newID, nil))
	if _, ok := s.Get(newID); ok {
		t.Error("Get() of the refused server ok = true, want false")
	}
	wantProjectBytes(t, s, over)

	// Smaller is accepted, also while still over the share.
	storeTestMustSet(t, s, id1, sharePins(n-1, "h"))
	wantProjectBytes(t, s, over-1)

	// A user server does not count.
	storeTestMustSet(t, s, shareUserID(0), sharePins(10, "h"))
	wantProjectBytes(t, s, over-1)
}
