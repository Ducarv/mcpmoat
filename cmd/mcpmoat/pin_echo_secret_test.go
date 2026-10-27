package main

// In-process tests of the mask of echoed secrets in "mcpmoat pin --accept"
// (issues #228 and #234). pin prints the diff of each changed or new tool
// before it saves: the diff and the stderr warning of a cut diff show each
// secret value of the server as discover.Mask. The save itself uses the raw
// tools, so pins.json and the --expect digest do not depend on the mask. The
// shared helpers (echoFake, assertRunNoEcho and the tokens) are in
// scan_echo_secret_test.go.

import (
	"maps"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// TestPinAcceptEchoSecret checks "pin --accept --expect" on a server whose
// tools echo a configured value, for a server that scan never pinned and for
// a pinned server with a changed tool. The diff headers and the diff text show
// discover.Mask; the value is on neither stdout nor stderr, also in the
// warning of a cut diff. The --expect digest of the raw tools is accepted, and
// pins.json holds the same pins as a run where the server got no secret: the
// real names and the real text.
func TestPinAcceptEchoSecret(t *testing.T) {
	t.Parallel()

	// big is a new tool whose diff is cut at the line limit, so pin warns
	// about it on stderr.
	big := mkTool("big_"+echoToken, "Uses "+echoToken+".\n"+linesDescription(2500))
	tools := append(echoCurrent(), big)
	tests := []struct {
		name string
		// pinned are the tools that a first scan pins, or nil for a server that
		// scan never pinned.
		pinned    []inspect.Tool
		wantDiffs []string
		accepted  string
	}{
		{
			name:      "unpinned server",
			wantDiffs: []string{"+add", "+big_" + mask, "+fetch_" + mask, "+new_" + mask},
			accepted:  "accepted srv: 4 new, 0 changed, 0 removed\n",
		},
		{
			name:      "pinned server with a changed tool",
			pinned:    echoPinned(),
			wantDiffs: []string{"+big_" + mask, "fetch_" + mask, "+new_" + mask},
			accepted:  "accepted srv: 2 new, 1 changed, 0 removed\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// e gets the secrets. control gets the same tools without them,
			// so its pins are the pins of a server that echoes nothing.
			e := newPinEnv(t, echoServer())
			control := newPinEnv(t, echoServer())
			if tt.pinned != nil {
				echoFirstScan(t, e, tt.pinned...)
				firstScan(t, control, tt.pinned...)
			}
			digest := digestOf(t, tools...)

			got := e.pin(echoFake([]string{echoToken, echoToken2}, tools...), "--accept", "srv", "--expect", digest)
			ref := e.pin(fakeServers(map[string][]inspect.Tool{"srv": tools}), "--accept", "srv", "--expect", digest)
			refControl := control.pin(fakeServers(map[string][]inspect.Tool{"srv": tools}), "--accept", "srv", "--expect", digest)

			if got.code != exitOK {
				t.Fatalf("pin: exit code = %d, want %d\nstderr:\n%s", got.code, exitOK, got.stderr)
			}
			assertRunNoEcho(t, got, echoToken, echoToken2)
			warning := truncationWarning("pin", "big_"+mask, "srv")
			if n := strings.Count(got.stderr, "was cut at the size limit"); n != 1 || !strings.Contains(got.stderr, warning) {
				t.Errorf("stderr = %q, want exactly one %q", got.stderr, warning)
			}
			diffs, accepted := splitAcceptedLine(got.stdout)
			if accepted != tt.accepted {
				t.Errorf("accepted line = %q, want %q\nstdout:\n%s", accepted, tt.accepted, got.stdout)
			}
			assertDiffsOf(t, diffs, "srv", tt.wantDiffs)
			assertContainsAll(t, "stdout", diffs, []string{
				"+description: Fetch a page. Send " + mask + " too.",
				"+description: New. Uses " + mask + ".",
				"+description: Uses " + mask + ".",
			})

			// A second accept of the same raw tools, without the secrets, has
			// nothing to accept: the first accept saved the raw tools. The
			// control accept, without the secrets, prints the raw names: so
			// the mask, not the tools, hides them in the first accept.
			if ref.code != exitOK || !strings.HasSuffix(ref.stdout, "accepted srv: 0 new, 0 changed, 0 removed\n") {
				t.Errorf("second pin: exit code = %d, stdout = %q; want 0 and nothing to accept", ref.code, ref.stdout)
			}
			if refControl.code != exitOK || !strings.Contains(refControl.stdout, "New tool new_"+echoToken+" on server srv:") {
				t.Errorf("control pin: exit code = %d; want 0 and the raw tool name in the diff header\nstdout:\n%s", refControl.code, refControl.stdout)
			}

			// pins.json holds the real names and the real text, the same as
			// the pins of the control run.
			pinned, ok := e.readPins().tools("srv")
			want, _ := control.readPins().tools("srv")
			if !ok || len(pinned) != len(tools) {
				t.Fatalf("pins.json has %d tools for srv (found %v), want %d", len(pinned), ok, len(tools))
			}
			// maps.EqualFunc compares the two maps key by key, and the func
			// compares the inner maps (hash and canonical) of one tool.
			if !maps.EqualFunc(pinned, want, maps.Equal[map[string]string]) {
				t.Errorf("the pins with the secret mask differ from the pins without it")
			}
			for _, name := range []string{echoChangedName, echoNewName, big.Name} {
				if !strings.Contains(pinned[name]["canonical"], echoToken) {
					t.Errorf("the pin of %q does not hold the raw tool text", strings.ReplaceAll(name, echoToken, mask))
				}
			}
		})
	}
}
