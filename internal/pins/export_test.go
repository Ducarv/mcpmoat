package pins

// Exports of package pins for the external test package pins_test.
const (
	MaxFileSize   = maxFileSize
	MaxServerSize = maxServerSize
)

// WantPerm checks the mode bits of a path (see wantPerm in atomic_test.go).
var WantPerm = wantPerm
