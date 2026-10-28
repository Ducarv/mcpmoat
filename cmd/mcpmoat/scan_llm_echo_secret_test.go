package main

// In-process test of the mask of an echoed secret in the Key of an LLM row
// (issues #228 and #234). It is in a file of its own, so that a later change
// of the LLM tests can move it as one piece. The shared helpers (echoFake,
// assertRunNoEcho and the tokens) are in scan_echo_secret_test.go.

import (
	"slices"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
)

// TestScanLLMEchoSecretKey checks that an LLM row of a tool whose name echoes
// a configured value shows the name with discover.Mask, in the "Tool:" line
// and in the --json "key", and that the value is on neither stdout nor
// stderr. The fake classifier rates the tool high (llmMarkHigh), so the tool
// gets a row. It gets the raw input: the request redaction is not part of
// this test.
func TestScanLLMEchoSecretKey(t *testing.T) {
	t.Parallel()

	tools := map[string][]inspect.Tool{"srv": {mkTool("fetch_"+echoToken, "Read keys. "+llmMarkHigh)}}
	want := []llmHit{{llm.RuleID, "high", "srv", "fetch_" + echoMask}}
	for _, jsonOut := range []bool{false, true} {
		name := "terminal"
		args := []string{"--llm"}
		if jsonOut {
			name = "json"
			args = append(args, "--json")
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := llmEnv(t, tools)
			c, stdout, stderr := llmCLI(e, echoFake([]string{echoToken}, tools["srv"]...), &llmFactory{t: t, cl: &llmFake{}})

			r := llmRun(t, e, c, stdout, stderr, args...)

			if r.code != exitFindings {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
			}
			assertRunNoEcho(t, r, echoToken)
			// llmJSONOrTerminalRows reads the --json document with
			// json.Unmarshal, or the terminal "Tool:" line up to its first
			// space (the category follows the name).
			if got := llmJSONOrTerminalRows(t, r.stdout, jsonOut); !slices.Equal(got, want) {
				t.Errorf("LLM rows = %+v, want %+v\nstdout:\n%s", got, want, r.stdout)
			}
		})
	}
}
