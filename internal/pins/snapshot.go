package pins

import (
	"errors"
	"fmt"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// ErrDuplicateTool is the error that Snapshot wraps when two tools in the
// list have the same name. The pins are keyed by tool name, so one of the two
// tools would replace the other.
var ErrDuplicateTool = errors.New("duplicate tool name")

// Snapshot returns the pins of a server: for each tool, the Hash and the
// Canonical form, stored under the tool name.
//
// Snapshot fails instead of skipping a tool that it cannot pin. A server
// could use a skipped tool to avoid detection: the tool would be in no pin,
// so a later change to it would never show in a diff. Snapshot returns no
// partial result with an error, so a caller cannot save half of a snapshot by
// mistake. The caller must show the server as not verified.
//
// Snapshot returns an error in these cases:
//   - A tool name is empty. The error wraps ErrInvalidTool.
//   - Two tools have the same name. The error wraps ErrDuplicateTool.
//   - Canonical or Hash fails for a tool. The error wraps ErrInvalidTool.
//
// Tool names, descriptions and schemas come from the server and are not
// trusted. The error text never includes them. It names the tool only by its
// position in tools (zero-based), which the caller can look up.
//
// An empty list gives an empty, non-nil ServerPins and no error: a server
// with no tools is valid to pin.
func Snapshot(tools []inspect.Tool) (ServerPins, error) {
	pinned := make(ServerPins, len(tools))
	for i, t := range tools {
		if t.Name == "" {
			return nil, fmt.Errorf("tool %d: the name is empty: %w", i, ErrInvalidTool)
		}
		if _, ok := pinned[t.Name]; ok {
			return nil, fmt.Errorf("tool %d: %w", i, ErrDuplicateTool)
		}

		canonical, err := Canonical(t)
		if err != nil {
			return nil, fmt.Errorf("tool %d: %w", i, err)
		}
		hash, err := Hash(t)
		if err != nil {
			return nil, fmt.Errorf("tool %d: %w", i, err)
		}
		pinned[t.Name] = Pin{Hash: hash, Canonical: string(canonical)}
	}
	return pinned, nil
}
