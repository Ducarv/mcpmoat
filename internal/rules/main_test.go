package rules_test

import (
	"os"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// TestMain removes the fixture server builds of inspecttest after all tests
// of the package. Both test packages (rules and rules_test) share this one
// TestMain, because Go allows only one for the test binary.
func TestMain(m *testing.M) {
	code := m.Run()
	inspecttest.RemoveBuilds()
	os.Exit(code)
}
