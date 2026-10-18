package inspect_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// TestMain is the only TestMain of the test binary of package inspect: the
// internal tests (package inspect) and the external tests (package
// inspect_test) are compiled into one binary, and only one TestMain is
// allowed. It is here because only the external package can import
// inspecttest.
//
// It implements the "re-exec the test binary" pattern of main_test.go. A
// test starts the compiled test binary (os.Executable) as a child process
// with EnvDumpArg as its first argument. The child sees the trigger here and
// acts as a fixture instead of a test runner. The check must come before
// m.Run, because the testing flag parser rejects the unknown flag. The dump
// branch calls os.Exit so that no test runs in the child.
//
// After the tests, it removes the fixture builds of inspecttest.
func TestMain(m *testing.M) {
	if len(os.Args) >= 2 && os.Args[1] == inspect.EnvDumpArg {
		if err := inspect.WriteEnvDump(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "env dump: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	code := m.Run()
	inspecttest.RemoveBuilds()
	os.Exit(code)
}
