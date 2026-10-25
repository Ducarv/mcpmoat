package pins

// Exports of package pins for the external test package pins_test.
const (
	MaxFileSize   = maxFileSize
	MaxServerSize = maxServerSize
)

// Test helpers from atomic_test.go, shared with the external test package.
var (
	WantPerm = wantPerm
	ReadFile = readFile
	DirNames = dirNames
)
