//go:build unix

package inspect

import (
	"reflect"
	"syscall"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// TestDetachSysProcAttr checks that detachSysProcAttr asks for a new session
// (Setsid) and sets no other field. Other fields would change the start of
// the child: for example, Setpgid after Setsid makes setpgid(2) fail, and
// Setctty needs a terminal that the child must not have.
func TestDetachSysProcAttr(t *testing.T) {
	t.Parallel()

	got := detachSysProcAttr()
	if got == nil {
		t.Fatal("detachSysProcAttr() = nil, want a non-nil *syscall.SysProcAttr")
	}
	if !got.Setsid {
		t.Error("detachSysProcAttr().Setsid = false, want true")
	}
	want := &syscall.SysProcAttr{Setsid: true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("detachSysProcAttr() = %+v, want %+v", got, want)
	}
}

// TestStdioCommandSetsSetsid checks that every successful stdioCommand puts
// the attributes of detachSysProcAttr into cmd.SysProcAttr. The cases cover
// the three command path branches of commandPath, because each one returns
// through the same final lines and a later change could add an early return.
func TestStdioCommandSetsSetsid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup returns the server config and the options for stdioCommand.
		setup func(t *testing.T) (discover.Server, stdioOptions)
	}{
		{
			name: "absolute command",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				return stdioServer("/opt/mcp/server", "--stdio"),
					stdioOptions{FallbackDir: t.TempDir()}
			},
		},
		{
			name: "bare name found in the child PATH",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				bin := t.TempDir() + "/bin"
				mustExecutable(t, bin, "mcp-server")
				return stdioServer("mcp-server"),
					stdioOptions{Environ: []string{"PATH=" + bin}, FallbackDir: t.TempDir()}
			},
		},
		{
			name: "relative command with an absolute config Dir",
			setup: func(t *testing.T) (discover.Server, stdioOptions) {
				s := stdioServer("./server")
				s.Dir = t.TempDir()
				return s, stdioOptions{}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s, opts := tt.setup(t)
			cmd, err := stdioCommand(s, opts)
			if err != nil {
				t.Fatalf("stdioCommand() error = %v", err)
			}
			if cmd.SysProcAttr == nil {
				t.Fatal("cmd.SysProcAttr = nil, want Setsid true")
			}
			if !cmd.SysProcAttr.Setsid {
				t.Error("cmd.SysProcAttr.Setsid = false, want true")
			}
		})
	}
}
