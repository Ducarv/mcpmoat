package discover

import (
	"cmp"
	"slices"
	"strings"
)

// This file holds the helpers that put the servers and errors of a Result in
// a fixed order. The JSON and Codex readers both use them.

// sortServers sorts servers by (ProjectPath, Name). The sort is stable: servers
// with the same key keep their input order, so a top-level server comes before
// a project server of the same name and path.
func sortServers(servers []Server) {
	slices.SortStableFunc(servers, func(a, b Server) int {
		return cmp.Or(
			strings.Compare(a.ProjectPath, b.ProjectPath),
			strings.Compare(a.Name, b.Name),
		)
	})
}

// sortErrors puts file-level errors (empty Server) first, then sorts by Server
// name. Empty sorts before every other string, so comparing the names is
// enough. The sort is stable: errors with the same name keep their order.
func sortErrors(errs []*FileError) {
	slices.SortStableFunc(errs, func(a, b *FileError) int {
		return strings.Compare(a.Server, b.Server)
	})
}
