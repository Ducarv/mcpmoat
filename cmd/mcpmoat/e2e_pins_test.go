package main

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// e2eNewPinsFileNotice returns the stderr line, without the newline, that the
// command cmd ("scan" or "pin") prints when its save creates a new pins.json,
// for a run of runBin with this home: newPinsNoticeLine for the pins file of
// home.
func e2eNewPinsFileNotice(cmd, home string) string {
	return newPinsNoticeLine(cmd, pinsPath(home))
}

// TestE2EScanNewPinsFileNotice checks the new pins file notice on the real
// binary, for scan and for pin --accept. The first run has no pins.json: it
// creates the file and prints the notice once, after the save and before the
// pinned lines. A second run reads the file and prints no notice. When the
// user then removes pins.json, the next run prints the notice again, because
// that is the case the notice warns about.
func TestE2EScanNewPinsFileNotice(t *testing.T) {
	t.Parallel()
	const name = "benign-srv"
	noExpect := exactLine("mcpmoat pin: " + strings.TrimSuffix(pinNoExpectNote, "\n"))
	tests := []struct {
		name string
		args []string
		cmd  string // the command name in the notice
		// before and after are the stderr lines before and after the notice
		// on a run that creates pins.json. A run that finds pins.json prints
		// laterStderr.
		before, after, laterStderr []lineWant
		// firstStdout and laterStdout are the ends of stdout.
		firstStdout, laterStdout string
	}{
		{
			name:  "scan",
			args:  []string{"scan"},
			cmd:   "scan",
			after: []lineWant{exactLine("mcpmoat scan: pinned 2 tools for " + name)},
		},
		{
			name:        "pin --accept",
			args:        []string{"pin", "--accept", name},
			cmd:         "pin",
			before:      []lineWant{noExpect},
			laterStderr: []lineWant{noExpect},
			firstStdout: "accepted " + name + ": 2 new, 0 changed, 0 removed\n",
			laterStdout: "accepted " + name + ": 0 new, 0 changed, 0 removed\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home, work := benignHome(t, name)
			notice := exactLine(e2eNewPinsFileNotice(tt.cmd, home))
			firstStderr := slices.Concat(tt.before, []lineWant{notice}, tt.after)

			// run runs the command once and checks the result.
			run := func(t *testing.T, step string, wantStderr []lineWant, wantStdout string) {
				t.Helper()
				stdout, stderr, code := runBin(t, home, work, tt.args...)
				if code != exitOK {
					t.Fatalf("%s: exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", step, code, exitOK, stdout, stderr)
				}
				assertStderrLines(t, stderr, wantStderr)
				if !strings.HasSuffix(stdout, wantStdout) {
					t.Errorf("%s: stdout does not end with %q\nstdout:\n%s", step, wantStdout, stdout)
				}
				if tt.cmd == "scan" {
					assertServerNames(t, stdout, name)
				}
				assertNoLeakBoth(t, stdout, stderr)
				assertContainsNone(t, step+" output", stdout+stderr, []string{pinEnvCanary})
				if _, err := os.Stat(pinsPath(home)); err != nil {
					t.Fatalf("%s: pins.json after the run: %v", step, err)
				}
			}

			assertNoPinsFile(t, home)
			run(t, "first run", firstStderr, tt.firstStdout)
			run(t, "second run", tt.laterStderr, tt.laterStdout)

			// The user removes pins.json: the next run pins again and warns.
			if err := os.Remove(pinsPath(home)); err != nil {
				t.Fatal(err)
			}
			run(t, "run after pins.json was removed", firstStderr, tt.firstStdout)
		})
	}
}
