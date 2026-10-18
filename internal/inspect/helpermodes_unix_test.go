//go:build unix

package inspect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// This file holds the fixture servers for the process tests of Run and of the
// process-group helpers. A fixture "server" is the test binary itself,
// started again with helperModeArg and a mode (see TestMain). The tests that
// use the modes are in helperprocess_unix_test.go, proctree_unix_test.go,
// run_process_unix_test.go and proctree_stdio_test.go. The huge-schema mode
// is a hostile MCP server for the JSON shape test of the stdio inspector
// (stdio_shape_unix_test.go).

// runHelperMode runs a helper mode when args (os.Args[1:]) start with
// helperModeArg. It returns the exit code and true, or 0 and false when args
// do not ask for a helper mode.
func runHelperMode(args []string) (int, bool) {
	if len(args) == 0 || args[0] != helperModeArg {
		return 0, false
	}
	return helperMain(args[1:]), true
}

// helperMain runs one helper mode and returns the process exit code.
func helperMain(args []string) int {
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "hang":
		// A hung server never answers. Block until a kill ends the process.
		return hangForever()
	case "crash":
		// A server that fails on start.
		fmt.Fprintln(os.Stderr, "helper: crash on start")
		return 3
	case "slow":
		// This sleep is simulated start-up work inside the fixture. It is not
		// test synchronisation.
		time.Sleep(time.Second)
		fmt.Println("ready")
		return 0
	case "grandchild":
		// A grandchild that stays in the process group. Its stdout is
		// /dev/null (exec.Command with a nil Stdout).
		if code := startGrandchild(nil); code != 0 {
			return code
		}
		return hangForever()
	case "escape":
		// A hostile grandchild: it leaves the process group with a new
		// session, so the group kill misses it, and it keeps the stdout pipe
		// of the server open.
		code := startGrandchild(func(gc *exec.Cmd) {
			gc.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			gc.Stdout = os.Stdout
		})
		if code != 0 {
			return code
		}
		return hangForever()
	case "daemon":
		// A server that leaves a daemon behind: the grandchild stays in the
		// process group, and the server exits at once with success.
		return startGrandchild(nil)
	case "huge-schema":
		// A hostile MCP server whose tools/list reply is small JSON text
		// that decodes to very many values (issue #101).
		return runHugeSchema(os.Stdin, os.Stdout)
	default:
		return 2
	}
}

// startGrandchild starts the test binary again in "hang" mode as a
// grandchild and prints "PID <n>" on stdout. setup, if not nil, changes the
// grandchild command before it starts. It returns 0, or an exit code for an
// error.
func startGrandchild(setup func(gc *exec.Cmd)) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper: executable:", err)
		return 1
	}
	// Plain exec.Command, not CommandContext: the grandchild must live on
	// unless a kill reaches it.
	gc := exec.Command(exe, helperModeArg, "hang") //nolint:gosec // G204: the helper starts its own test binary as a fixture grandchild
	if setup != nil {
		setup(gc)
	}
	if err := gc.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "helper: start grandchild:", err)
		return 1
	}
	// os.Stdout is not buffered, so the parent sees the line at once. We do
	// not Wait for the grandchild: only a kill may end it.
	fmt.Printf("PID %d\n", gc.Process.Pid)
	return 0
}

// hangForever blocks until the process is killed.
//
// A bare select{} does not work here: with no other goroutine the Go runtime
// sees a deadlock and exits with code 2. A pending timer avoids that.
func hangForever() int {
	for {
		time.Sleep(time.Hour)
	}
}

// hugeSchemaElems is the number of empty objects in the array of the
// huge-schema mode. The array text "[{},{},...]" is 3*hugeSchemaElems+1
// bytes: 7.5 MiB. The whole reply line stays below maxRawBytes (8 MiB), the
// frame limit of the stdio transport, so the size caps do not stop it. Only
// a check of the JSON shape (number of values) can stop it.
const hugeSchemaElems = (15 << 19) / 3

// runHugeSchema is the huge-schema mode. It speaks newline-delimited
// JSON-RPC by hand, without the SDK, so it can send a reply that a normal
// server would never build. It refuses server/discover with "method not
// found", so the client falls back to initialize. It answers initialize
// with the tools capability and the protocol version that the client asked
// for, and ignores notifications. It answers tools/list with one line: one
// tool whose input schema has a property with a 7.5 MiB array of empty
// objects. Each empty object costs the client much more memory than its 3
// bytes of JSON text. Other requests get "method not found". It returns
// when stdin closes.
func runHugeSchema(stdin io.Reader, stdout io.Writer) int {
	// Build the array once: "[{},{},...,{}]". bytes.Repeat makes one
	// allocation of the full size.
	array := make([]byte, 0, 3*hugeSchemaElems+1)
	array = append(array, '[')
	array = append(array, bytes.Repeat([]byte("{},"), hugeSchemaElems-1)...)
	array = append(array, "{}]"...)

	in := bufio.NewScanner(stdin)
	in.Buffer(make([]byte, 0, 64<<10), 1<<20)
	out := bufio.NewWriter(stdout)
	for in.Scan() {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"params"`
		}
		if err := json.Unmarshal(in.Bytes(), &msg); err != nil || msg.ID == nil {
			continue // a notification, or not JSON
		}
		switch msg.Method {
		case "initialize":
			// json.Marshal quotes the version that the client sent, so a
			// strange value cannot break the JSON of the reply.
			version, err := json.Marshal(msg.Params.ProtocolVersion)
			if err != nil {
				fmt.Fprintln(os.Stderr, "helper: encode version:", err)
				return 1
			}
			// out is a bufio.Writer: it keeps the first write error, and the
			// Flush below returns it, so the error of Fprintf can be ignored.
			_, _ = fmt.Fprintf(out, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":%s,"capabilities":{"tools":{}},"serverInfo":{"name":"huge-schema","version":"1.0.0"}}}`+"\n", msg.ID, version)
		case "tools/list":
			// Splice the request id and the array into the reply. The line
			// is built in full first, so its size can be checked.
			var line bytes.Buffer
			line.Grow(len(array) + 256)
			fmt.Fprintf(&line, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"huge","description":"A tool with a huge schema.","inputSchema":{"type":"object","properties":{"blob":`, msg.ID)
			line.Write(array)
			line.WriteString("}}}]}}\n")
			if line.Len() >= maxRawBytes {
				fmt.Fprintln(os.Stderr, "helper: huge-schema line is not below the frame limit")
				return 2
			}
			if _, err := out.Write(line.Bytes()); err != nil {
				fmt.Fprintln(os.Stderr, "helper: write:", err)
				return 1
			}
		default:
			// The Flush below returns any write error (see initialize).
			_, _ = fmt.Fprintf(out, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`+"\n", msg.ID)
		}
		if err := out.Flush(); err != nil {
			// The client closed the pipe. This is a normal end.
			return 0
		}
	}
	return 0
}
