package inspect

import (
	"context"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// stopGrace is how long stdioProcess.stop waits for the server to exit after
// it closes the stdin of the server. Then it kills the process group.
const stopGrace = 2 * time.Second

// stdioProcess is the child process of one stdio server and the pipes to it.
// It follows the stop rules of the [Inspector] contract: it kills the process
// group before cmd.Wait, and it closes its own ends of the pipes when ctx
// ends, so that a blocked read or write of the SDK returns.
//
// It does not use mcp.CommandTransport: that transport calls cmd.Wait
// itself, so the group kill could only come after the reap, when the PID of
// the child can already belong to another process.
//
// A stdioProcess is used by one call to Inspect. Only stop and the SDK
// reads and writes run in other goroutines than the caller, and they touch
// only the pipes, the eof channel and the state of shape.
type stdioProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser

	// eof is closed when a read on stdout returns an error, usually io.EOF
	// when the server exits.
	eof     chan struct{}
	eofOnce sync.Once

	// stopKill stops the kill on ctx (see startStdio).
	stopKill func() bool

	// stopped is true after the first call to stop.
	stopped bool

	// shape checks the shape of every JSON message on stdout (see
	// transport). It is nil until transport runs.
	shape *shapeReader
}

// startStdio starts cmd, which stdioCommand built, with pipes for its stdin
// and stdout. Its stderr stays os.DevNull (cmd.Stderr is nil), so server
// output never reaches the terminal.
//
// When ctx ends while the process runs, the process group of the child gets
// SIGKILL at once, and both pipes are closed. cmd comes from exec.Command,
// not exec.CommandContext, so os/exec would not do this.
//
// The error is the error of a pipe or of cmd.Start. Its text can hold
// cmd.Path or cmd.Dir, so the caller must not print it (see startFailure).
func startStdio(ctx context.Context, cmd *exec.Cmd) (*stdioProcess, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	// Start closes both pipes when it fails.
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &stdioProcess{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
		eof:    make(chan struct{}),
	}
	// Start set cmd.Process before this AfterFunc exists, so kill reads it
	// without a race.
	p.stopKill = context.AfterFunc(ctx, p.kill)
	return p, nil
}

// transport returns the SDK transport over the pipes of p. maxLine bounds
// the size of one JSON-RPC frame from the server.
//
// The SDK reads stdout through a shapeReader, so a message that is too
// deeply nested, has too many values or has a too long string fails before
// the SDK decodes it (errJSONTooComplex, see jsonshape.go). The raw size
// limit alone does not stop this: a small message such as [{},{},...] can
// decode to many times its size in memory. The SDK reads all messages as one
// stream, and the shapeReader counts each top-level value on its own.
//
// eofReader has both Read and Close, so it is an io.ReadCloser, which
// newJSONShapeReader needs. The Close of the shapeReader calls the Close of
// eofReader, so the SDK still closes the stdout pipe when it closes the
// connection. transport stores the shapeReader in p.shape for shapeExceeded.
func (p *stdioProcess) transport(maxLine int) mcp.Transport {
	p.shape = newJSONShapeReader(eofReader{p}, defaultJSONLimits(), nil)
	return &mcp.IOTransport{
		Reader:        p.shape,
		Writer:        p.stdin,
		MaxLineLength: maxLine,
	}
}

// shapeExceeded reports whether the server sent a JSON message over a shape
// limit (see transport). It is false before transport runs. Call it from the
// goroutine that called transport; it is safe while the SDK reads stdout in
// another goroutine, because shapeReader.exceeded reads an atomic flag.
func (p *stdioProcess) shapeExceeded() bool {
	return p.shape != nil && p.shape.exceeded()
}

// kill sends SIGKILL to the process group of the child and closes both
// pipes. It runs when ctx ends. stop stops this kill before it calls
// cmd.Wait, so the kill does not start while the child is reaped. A kill
// that already runs then can meet the reap; killProcessGroup checks the
// process handle first and sends nothing once Wait has reaped the child.
func (p *stdioProcess) kill() {
	_ = killProcessGroup(p.cmd)
	_ = p.stdout.Close()
	_ = p.stdin.Close()
}

// stop stops the process and reaps it. A second call does nothing.
//
// The steps:
//
//  1. Close the stdin of the server. A server reads EOF and exits; a
//     launcher such as "docker run -i --rm" stops its container then. The
//     close also ends a write of the SDK that blocks because the server does
//     not read its stdin.
//  2. Wait up to stopGrace for EOF on stdout, the sign that the server has
//     exited.
//  3. Kill the process group with SIGKILL, before cmd.Wait: until Wait
//     reaps the child, its PID stays taken, so the kill cannot reach another
//     process. It stops the processes that the child started and that stayed
//     in its group. Then stop the kill on ctx (see kill).
//  4. Close the read end of stdout, so that a read of the SDK returns even
//     when a process that left the group still holds the write end.
//  5. cmd.Wait reaps the child.
//
// A process that left the group lives on: this is not a sandbox. A process
// that the operating system cannot kill blocks cmd.Wait.
func (p *stdioProcess) stop() {
	if p.stopped {
		return
	}
	p.stopped = true

	_ = p.stdin.Close()
	timer := time.NewTimer(stopGrace)
	select {
	case <-p.eof:
	case <-timer.C:
	}
	timer.Stop()

	_ = killProcessGroup(p.cmd)
	p.stopKill()
	_ = p.stdout.Close()
	_ = p.cmd.Wait()
}

// eofReader is the stdout of a stdioProcess for the SDK. It closes eof when
// a read fails, so that stop knows when the server has exited.
type eofReader struct {
	p *stdioProcess
}

// Read reads from the stdout pipe of the child.
func (r eofReader) Read(b []byte) (int, error) {
	n, err := r.p.stdout.Read(b)
	if err != nil {
		r.p.eofOnce.Do(func() { close(r.p.eof) })
	}
	return n, err
}

// Close closes the read end of the stdout pipe.
func (r eofReader) Close() error {
	return r.p.stdout.Close()
}
