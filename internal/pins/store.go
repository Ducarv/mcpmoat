package pins

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/safefile"
)

// CurrentVersion is the format version of pins.json that this mcpmoat reads
// and writes.
const CurrentVersion = 1

// maxFileSize is the largest pins.json that Load reads, in bytes.
const maxFileSize = 8 << 20

// maxServerSize is the largest entry of one server that Set accepts, in bytes
// of compact JSON. A server with 100 tools needs about 10 KiB. A server sends
// its own tool names, so this cap stops one server from filling the file
// alone and making Save fail for all servers.
const maxServerSize = 256 << 10

// ErrUnsupportedVersion means that pins.json has a format version that this
// mcpmoat does not know, because the file is newer. Load never reads such a
// file, so an old binary cannot overwrite it. Test for it with errors.Is.
var ErrUnsupportedVersion = errors.New("unsupported pins.json version")

// Identity names one MCP server in the pins store.
//
// The fields hold the client, the config file and the server name only. They
// never hold a secret: no args, URL, env, headers or command. ProjectPath is
// empty for a global server.
//
// All fields are strings, so Identity is comparable and a valid map key.
type Identity struct {
	// Client is the client that owns the config, for example "claude-code".
	Client string
	// Source is the path of the config file that declares the server.
	Source string
	// ProjectPath is the project that the server belongs to. It is empty for a
	// global server.
	ProjectPath string
	// Name is the name of the server in the config. It must not be empty.
	Name string
}

// ServerPins maps a tool name to the hash of that tool. A hash is an opaque
// non-empty string here: the hashing code owns its format.
//
// The server chose the tool names, and they can hold control characters. Code
// that prints a name from the store must escape it (internal/termsafe), as it
// does for a name from a live server.
type ServerPins map[string]string

// Store holds the pins of all servers and the path of the pins file.
//
// A Store is safe for use by several goroutines. Two processes that save to
// the same path do not corrupt the file (the write is atomic), but the last
// writer wins. So a run can drop the first pins that a parallel run saved,
// and the next run then sees that server as new, with no alert.
type Store struct {
	path string

	mu sync.Mutex
	// servers is keyed by server identity.
	servers map[Identity]ServerPins
}

// fileFormat is the shape of pins.json, version 1. Every key is required and
// must not be null. encoding/json/v2 has no option for a required key, so the
// fields are pointers: a missing key or a null leaves the pointer nil, and
// Load refuses it.
type fileFormat struct {
	Version int           `json:"version"`
	Servers *[]fileServer `json:"servers"`
}

// fileServer is one server entry in pins.json.
type fileServer struct {
	Client      *string     `json:"client"`
	Source      *string     `json:"source"`
	ProjectPath *string     `json:"project_path"`
	Name        *string     `json:"name"`
	Tools       *ServerPins `json:"tools"`
}

// DefaultPath returns the path of pins.json.
//
// It is $XDG_CONFIG_HOME/mcpmoat/pins.json when XDG_CONFIG_HOME is set to an
// absolute path, and ~/.config/mcpmoat/pins.json otherwise. The XDG
// specification says that a relative value is invalid and must be ignored. We
// do not use os.UserConfigDir, because on macOS it returns
// ~/Library/Application Support and the PRD (FR-11) fixes ~/.config.
//
// The caller passes the environment and the home directory (os.Getenv and
// os.UserHomeDir in production), so the package reads no process state.
// homeDir runs only when XDG_CONFIG_HOME is not used.
func DefaultPath(getenv func(string) string, homeDir func() (string, error)) (string, error) {
	base := getenv("XDG_CONFIG_HOME")
	if base == "" || !filepath.IsAbs(base) {
		home, err := homeDir()
		if err != nil {
			return "", fmt.Errorf("find the home directory for pins.json: %w", err)
		}
		// A relative home would put pins.json under the working directory, which
		// can be a cloned repository.
		if !filepath.IsAbs(home) {
			return "", errors.New("the home directory for pins.json is not an absolute path")
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "mcpmoat", "pins.json"), nil
}

// Load reads the pins file at path.
//
// A missing file (or a missing directory) is the first run: Load returns an
// empty Store that saves to path. Any other problem is an error, also a
// missing or null key, and Load never replaces a bad file with an empty store,
// because that would pin a poisoned server as trusted. The errors name the path and the position of the
// problem, and never hold file content. A file with a newer format version
// gives an error that wraps ErrUnsupportedVersion. A pins.json symlink is
// refused (safefile.ErrOutsideRoot) when it is absolute or leaves its
// directory, and it is an error when its target is missing. Save replaces a
// symlink with a regular file.
func Load(path string) (*Store, error) {
	s := &Store{path: path, servers: make(map[Identity]ServerPins)}

	data, found, err := safefile.ReadBoundedRegularFile(filepath.Dir(path), filepath.Base(path), maxFileSize)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if !found {
		// safefile reports a symlink with a missing target as not found. Then
		// the real file is gone, which is not a first run, and Save would
		// replace the link.
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("read %s: the target of the symlink is missing", path)
		}
		return s, nil
	}

	// Read the version first with a loose decode. A future version may change
	// the rest of the shape, and the user must then see the version error and
	// not a shape error. This holds while the top level stays an object with an
	// integer "version", so a format change must keep that. json.Unmarshal
	// (encoding/json/v2) rejects trailing data, duplicate keys and invalid
	// UTF-8, and it matches key names with their exact case.
	var probe struct {
		Version *int `json:"version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse %s: %s", path, describeJSONError(err))
	}
	switch {
	case probe.Version == nil:
		return nil, fmt.Errorf("parse %s: version field is missing", path)
	case *probe.Version < 1:
		return nil, fmt.Errorf("parse %s: invalid version %d", path, *probe.Version)
	case *probe.Version > CurrentVersion:
		return nil, fmt.Errorf("%s has version %d, newer than this mcpmoat supports (%d); upgrade mcpmoat: %w",
			path, *probe.Version, CurrentVersion, ErrUnsupportedVersion)
	}

	// Strict decode: an unknown field is an error, so a typo or a field from a
	// different format is not dropped silently.
	var f fileFormat
	if err := json.Unmarshal(data, &f, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("parse %s: %s", path, describeJSONError(err))
	}

	if f.Servers == nil {
		return nil, fmt.Errorf("parse %s: servers field is missing or null", path)
	}
	for i, srv := range *f.Servers {
		if srv.Client == nil || srv.Source == nil || srv.ProjectPath == nil || srv.Name == nil || srv.Tools == nil {
			return nil, fmt.Errorf("parse %s: servers[%d]: a field is missing or null", path, i)
		}
		id := Identity{Client: *srv.Client, Source: *srv.Source, ProjectPath: *srv.ProjectPath, Name: *srv.Name}
		if err := validateServer(id, *srv.Tools); err != nil {
			return nil, fmt.Errorf("parse %s: servers[%d]: %w", path, i, err)
		}
		if _, dup := s.servers[id]; dup {
			return nil, fmt.Errorf("parse %s: servers[%d]: duplicate server identity", path, i)
		}
		// The decoder made this map, and nothing else holds it.
		s.servers[id] = *srv.Tools
	}
	return s, nil
}

// Get returns a copy of the pins of the server id. The bool is false when the
// store has no entry for the server. An entry with an empty map is a server
// that was pinned with no tools. Changing the returned map does not change
// the Store.
func (s *Store) Get(id Identity) (ServerPins, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.servers[id]
	if !ok {
		return nil, false
	}
	return maps.Clone(p), true
}

// Set stores a copy of p as the pins of the server id. It replaces the pins of
// that server only. A nil or empty p pins the server with no tools. Set does
// not write the file: call Save.
//
// Set refuses a server that Load would refuse: an empty server name, an empty
// tool name, an empty hash or text that is not valid UTF-8. It also refuses a
// server whose entry is larger than 256 KiB as compact JSON. Then the store
// does not change, and the caller can skip that one server and still save the
// others. The errors hold no tool names, because the server chose them.
func (s *Store) Set(id Identity, p ServerPins) error {
	if err := validateServer(id, p); err != nil {
		return err
	}
	entry, err := json.Marshal(newFileServer(id, p))
	if err != nil {
		// Not wrapped: the error text of encoding/json can hold a tool name.
		return errors.New("encode server pins: the pins cannot be encoded as JSON")
	}
	if len(entry) > maxServerSize {
		return fmt.Errorf("server pins are %d bytes as JSON, larger than the %d byte limit",
			len(entry), maxServerSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// A zero-value Store has a nil map, and writing to a nil map panics.
	if s.servers == nil {
		s.servers = make(map[Identity]ServerPins)
	}
	s.servers[id] = cloneOrEmpty(p)
	return nil
}

// cloneOrEmpty returns a copy of p. A nil p gives an empty map, not nil.
func cloneOrEmpty(p ServerPins) ServerPins {
	c := maps.Clone(p)
	if c == nil {
		c = ServerPins{}
	}
	return c
}

// Save writes the store to its path, atomically, with file mode 0o600. A new
// directory gets mode 0o700. The servers and the tool names are sorted, so the
// same store always gives the same bytes.
//
// Load and Set check each server, so Save checks only the whole file: it
// refuses data larger than the size limit of Load, and the old file stays.
// Save of a zero-value Store is an error, because it has no path: make a
// Store with Load.
func (s *Store) Save() error {
	// The lock also covers the write, so two Saves of one Store run one at a
	// time and the last call writes the last state.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.path == "" {
		return errors.New("save pins: the store has no path (make it with Load)")
	}
	ids := slices.SortedFunc(maps.Keys(s.servers), compareIdentity)
	servers := make([]fileServer, 0, len(ids))
	for _, id := range ids {
		servers = append(servers, newFileServer(id, s.servers[id]))
	}
	f := fileFormat{Version: CurrentVersion, Servers: &servers}

	// Deterministic sorts the map keys. encoding/json/v2 does not escape <, >
	// and &, so such a tool name keeps its size in the file.
	data, err := json.Marshal(f, jsontext.WithIndent("  "), json.Deterministic(true))
	if err != nil {
		// Not wrapped: the error text of encoding/json can hold a tool name.
		return fmt.Errorf("save %s: the pins cannot be encoded as JSON", s.path)
	}
	data = append(data, '\n')
	// Check the size before the write, so the old file stays valid.
	if len(data) > maxFileSize {
		return fmt.Errorf("save %s: pins data is %d bytes, larger than the %d byte limit",
			s.path, len(data), maxFileSize)
	}

	if err := writeFileAtomic(s.path, data); err != nil {
		return fmt.Errorf("save %s: %w", s.path, err)
	}
	return nil
}

// newFileServer returns the file entry of the server id. The pointers point
// to the parameters, which are copies. The tools map itself is shared, and
// the encoder only reads it.
func newFileServer(id Identity, tools ServerPins) fileServer {
	return fileServer{
		Client:      &id.Client,
		Source:      &id.Source,
		ProjectPath: &id.ProjectPath,
		Name:        &id.Name,
		Tools:       &tools,
	}
}

// compareIdentity orders identities by Client, Source, ProjectPath and Name.
func compareIdentity(a, b Identity) int {
	return cmp.Or(
		cmp.Compare(a.Client, b.Client),
		cmp.Compare(a.Source, b.Source),
		cmp.Compare(a.ProjectPath, b.ProjectPath),
		cmp.Compare(a.Name, b.Name),
	)
}

// validateServer checks the rules that Load and Set share. The errors do not
// hold tool names, because a server that we do not trust chose them.
func validateServer(id Identity, tools ServerPins) error {
	if id.Name == "" {
		return errors.New("the server name is empty")
	}
	// The file must be valid UTF-8, and Load refuses a file that is not. Only
	// Set can hit this check: Load has already refused such text. Checking
	// here gives an error with no content, before the store changes.
	if !utf8.ValidString(id.Client) || !utf8.ValidString(id.Source) ||
		!utf8.ValidString(id.ProjectPath) || !utf8.ValidString(id.Name) {
		return errors.New("the server identity is not valid UTF-8")
	}
	for name, hash := range tools {
		if name == "" {
			return errors.New("a tool name is empty")
		}
		if hash == "" {
			return errors.New("a tool hash is empty")
		}
		if !utf8.ValidString(name) {
			return errors.New("a tool name is not valid UTF-8")
		}
		if !utf8.ValidString(hash) {
			return errors.New("a tool hash is not valid UTF-8")
		}
	}
	return nil
}

// describeJSONError turns a decode error into text with a position and no file
// content. The text of an encoding/json error can hold input, for example an
// unknown or a duplicate key, so we write our own text.
func describeJSONError(err error) string {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "unexpected end of the JSON data"
	}
	if se, ok := errors.AsType[*jsontext.SyntacticError](err); ok {
		if errors.Is(err, jsontext.ErrDuplicateName) {
			return fmt.Sprintf("duplicate key at byte %d", se.ByteOffset)
		}
		return fmt.Sprintf("invalid JSON at byte %d", se.ByteOffset)
	}
	if se, ok := errors.AsType[*json.SemanticError](err); ok {
		if errors.Is(err, json.ErrUnknownName) {
			return fmt.Sprintf("unknown field at byte %d", se.ByteOffset)
		}
		// A wrong type, or a number that is not an integer or is too large.
		return fmt.Sprintf("invalid value at byte %d", se.ByteOffset)
	}
	return "invalid JSON"
}
