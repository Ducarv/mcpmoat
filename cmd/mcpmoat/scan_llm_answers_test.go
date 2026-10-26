package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
)

// This file tests how scan --llm (FR-17, FR-16) handles each kind of answer of
// the classifier: a provider failure, invalid model output, any other error,
// a tool with an empty name, and a signal that comes with the last answer.
// The tests use the fake classifier of scan_llm_test.go.

// llmReply is one answer of the fake classifier: a verdict or an error.
type llmReply struct {
	v   llm.Verdict
	err error
}

// llmByTool returns an answer function for llmFake that gives each tool the
// reply in replies, by tool name. A tool that replies does not name gets
// risk none.
func llmByTool(replies map[string]llmReply) func(llm.Input) (llm.Verdict, error) {
	return func(in llm.Input) (llm.Verdict, error) {
		r, ok := replies[in.ToolName]
		if !ok {
			return llm.Verdict{Risk: llm.RiskNone, Category: llm.CategoryOther}, nil
		}
		return r.v, r.err
	}
}

// TestScanLLMErrorSorting checks how scan sorts the errors of the classifier.
// Only an error that wraps llm.ErrProvider is a provider failure: it stops
// the LLM step, scan exits with 2, the JSON complete field is false and
// stderr has the "LLM provider failed" line. llm.ErrInvalidOutput and any
// other error (for example a local error such as a request that is too large)
// give that tool one MOAT-LLM-002 finding (medium) and the other tools still
// get their answer: the step is complete and the exit code follows the
// findings. The text of such an error never shows.
func TestScanLLMErrorSorting(t *testing.T) {
	t.Parallel()

	// genericCanary is the text of the generic error. No output may hold it.
	const genericCanary = "local-error-canary-Rw4Tn7"
	errGeneric := errors.New(genericCanary)
	high := llmReply{v: llm.Verdict{Risk: llm.RiskHigh, Category: llm.CategoryCredentialAccess}}
	invalid := llmReply{err: fmt.Errorf("%w: test", llm.ErrInvalidOutput)}
	generic := llmReply{err: errGeneric}
	status503 := llmReply{err: &llm.StatusError{Code: http.StatusServiceUnavailable}}
	wrappedProvider := llmReply{err: fmt.Errorf("test: %w", llm.ErrProvider)}

	tests := []struct {
		name    string
		tools   []string            // the tool names of the one server "srv", in order
		replies map[string]llmReply // by tool name; a tool not named gets risk none
		// provider is true when the step must stop with a provider failure.
		// wantReason is then the reason in the failure line.
		provider   bool
		wantReason string
		// wantRows are the LLM findings. For a provider failure, the other
		// tools can end before or after the cancel, so the rows must only be
		// a part of wantRows, in order.
		wantRows []llmHit
		// wantCode is the exit code at the default --fail-on high, and
		// wantMedium the exit code with --fail-on medium.
		wantCode, wantMedium int
		// wantCalls is the exact number of Classify calls; 0 means any.
		wantCalls int32
	}{
		{
			name:       "provider error that wraps ErrProvider",
			tools:      []string{"t1"},
			replies:    map[string]llmReply{"t1": wrappedProvider},
			provider:   true,
			wantReason: "test: LLM provider request failed",
			wantCode:   exitError,
			wantMedium: exitError,
			wantCalls:  1,
		},
		{
			name:       "provider status 503",
			tools:      []string{"t1"},
			replies:    map[string]llmReply{"t1": status503},
			provider:   true,
			wantReason: "HTTP 503",
			wantCode:   exitError,
			wantMedium: exitError,
			wantCalls:  1,
		},
		{
			name:       "invalid output",
			tools:      []string{"t1"},
			replies:    map[string]llmReply{"t1": invalid},
			wantRows:   []llmHit{{llm.RuleIDInvalid, "medium", "srv", "t1"}},
			wantCode:   exitOK,
			wantMedium: exitFindings,
			wantCalls:  1,
		},
		{
			name:       "generic error",
			tools:      []string{"t1"},
			replies:    map[string]llmReply{"t1": generic},
			wantRows:   []llmHit{{llm.RuleIDInvalid, "medium", "srv", "t1"}},
			wantCode:   exitOK,
			wantMedium: exitFindings,
			wantCalls:  1,
		},
		{
			// A generic error does not cancel the other jobs: every tool is
			// sent and every tool gets its own row.
			name:    "generic error on every tool",
			tools:   []string{"t1", "t2", "t3", "t4", "t5", "t6"},
			replies: map[string]llmReply{"t1": generic, "t2": generic, "t3": generic, "t4": generic, "t5": generic, "t6": generic},
			wantRows: []llmHit{
				{llm.RuleIDInvalid, "medium", "srv", "t1"},
				{llm.RuleIDInvalid, "medium", "srv", "t2"},
				{llm.RuleIDInvalid, "medium", "srv", "t3"},
				{llm.RuleIDInvalid, "medium", "srv", "t4"},
				{llm.RuleIDInvalid, "medium", "srv", "t5"},
				{llm.RuleIDInvalid, "medium", "srv", "t6"},
			},
			wantCode:   exitOK,
			wantMedium: exitFindings,
			wantCalls:  6,
		},
		{
			name:    "mixed tools without a provider failure",
			tools:   []string{"t1", "t2", "t3", "t4"},
			replies: map[string]llmReply{"t1": high, "t2": invalid, "t3": generic},
			wantRows: []llmHit{
				{llm.RuleID, "high", "srv", "t1"},
				{llm.RuleIDInvalid, "medium", "srv", "t2"},
				{llm.RuleIDInvalid, "medium", "srv", "t3"},
			},
			wantCode:   exitFindings,
			wantMedium: exitFindings,
			wantCalls:  4,
		},
		{
			// The provider failure wins over the generic error of another
			// tool. That tool can still get its row when it ended first.
			name:       "mixed tools with a provider failure",
			tools:      []string{"t1", "t2"},
			replies:    map[string]llmReply{"t1": generic, "t2": status503},
			provider:   true,
			wantReason: "HTTP 503",
			wantRows:   []llmHit{{llm.RuleIDInvalid, "medium", "srv", "t1"}},
			wantCode:   exitError,
			wantMedium: exitError,
		},
	}
	for _, tt := range tests {
		for _, jsonOut := range []bool{false, true} {
			for _, failOn := range []string{"", "medium"} {
				t.Run(fmt.Sprintf("%s/json=%v/fail-on=%s", tt.name, jsonOut, failOn), func(t *testing.T) {
					t.Parallel()
					list := make([]inspect.Tool, len(tt.tools))
					for i, name := range tt.tools {
						list[i] = mkTool(name, "Text.")
					}
					tools := map[string][]inspect.Tool{"srv": list}
					args := []string{"--llm"}
					wantCode := tt.wantCode
					if failOn != "" {
						args = append(args, "--fail-on", failOn)
						wantCode = tt.wantMedium
					}
					if jsonOut {
						args = append(args, "--json")
					}
					fake := &llmFake{answer: llmByTool(tt.replies)}

					r := llmScan(t, llmEnv(t, tools), tools, fake, args...)

					if r.code != wantCode {
						t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, wantCode, r.stdout, r.stderr)
					}
					if tt.wantCalls != 0 {
						if got := fake.calls.Load(); got != tt.wantCalls {
							t.Errorf("Classify calls = %d, want %d", got, tt.wantCalls)
						}
					}

					m := llmNotClassified.FindAllStringSubmatch(r.stderr, -1)
					if tt.provider {
						if len(m) != 1 {
							t.Fatalf("stderr has %d LLM failure lines, want 1:\n%s", len(m), r.stderr)
						}
						if m[0][1] != tt.wantReason {
							t.Errorf("failure reason = %q, want %q", m[0][1], tt.wantReason)
						}
					} else if len(m) != 0 || strings.Contains(r.stderr, "provider failed") {
						t.Errorf("stderr reports a provider failure, want none:\n%s", r.stderr)
					}
					for _, out := range []string{r.stdout, r.stderr} {
						if strings.Contains(out, genericCanary) {
							t.Errorf("output holds the text of the generic error:\n%s", out)
						}
					}

					var got []llmHit
					if jsonOut {
						doc := decodeScanJSON(t, r.stdout)
						if doc.Complete == tt.provider {
							t.Errorf("complete = %v, want %v", doc.Complete, !tt.provider)
						}
						got = llmJSONRows(t, doc)
					} else {
						if !strings.Contains(r.stdout, summaryHeading) {
							t.Errorf("stdout has no SUMMARY block\nstdout:\n%s", r.stdout)
						}
						got = llmRowsOf(t, parseFindings(t, r.stdout))
					}
					if tt.provider {
						if !llmIsSubsequence(got, tt.wantRows) {
							t.Errorf("LLM findings = %+v, want a part of %+v", got, tt.wantRows)
						}
					} else if !slices.Equal(got, tt.wantRows) {
						t.Errorf("LLM findings = %+v, want %+v\nstdout:\n%s", got, tt.wantRows, r.stdout)
					}
				})
			}
		}
	}
}

// llmIsSubsequence reports whether every element of got is in want, in the
// same order as in want.
func llmIsSubsequence(got, want []llmHit) bool {
	i := 0
	for _, g := range got {
		for i < len(want) && want[i] != g {
			i++
		}
		if i == len(want) {
			return false
		}
		i++
	}
	return true
}

// TestScanLLMNoToolName checks the LLM findings of a tool with an empty name,
// which a hostile server can list. The finding gets the fixed key "(no name)":
// the terminal shows a Tool line with it (never a Reason line with the
// category), and the JSON finding has it as its key. The classifier still
// gets the real, empty name.
func TestScanLLMNoToolName(t *testing.T) {
	t.Parallel()

	tools := map[string][]inspect.Tool{
		"alpha": {mkTool("", "Read keys. "+llmMarkHigh)},
		"beta":  {mkTool("", "Odd. "+llmMarkInvalid), mkTool("t1", "Notes. "+llmMarkMedium)},
	}
	// The key has a space, so the terminal quotes it.
	const quotedKey = `"(no name)"`

	t.Run("terminal", func(t *testing.T) {
		t.Parallel()
		fake := &llmFake{}
		r := llmScan(t, llmEnv(t, tools), tools, fake, "--llm")

		if r.code != exitFindings {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
		}
		llmRows, _ := llmSplitFindings(parseFindings(t, r.stdout))
		llmRowsOf(t, llmRows) // checks the fixed texts of each LLM finding
		type view struct{ rule, server, tool, reason string }
		var got []view
		for _, f := range llmRows {
			got = append(got, view{f.RuleID, f.Name, f.Tool, f.Reason})
		}
		want := []view{
			{llm.RuleID, "alpha", quotedKey + " (credential-access)", ""},
			{llm.RuleIDInvalid, "beta", quotedKey, ""},
			{llm.RuleID, "beta", "t1 (hidden-instructions)", ""},
		}
		if !slices.Equal(got, want) {
			t.Errorf("LLM findings = %+v, want %+v\nstdout:\n%s", got, want, r.stdout)
		}
		// Raw checks on the text: the exact Tool lines, and no Reason line
		// that shows the category as the reason of a server finding.
		assertContainsAll(t, "stdout", r.stdout, []string{
			"\n    Tool: " + quotedKey + " (credential-access)\n",
			"\n    Tool: " + quotedKey + "\n",
		})
		assertContainsNone(t, "stdout", r.stdout, []string{"Reason: credential-access", "Reason: " + string(llm.CategoryCredentialAccess)})

		// The request carries the real, empty name.
		wantIn := []llm.Input{
			{ToolName: "", Description: "Odd. " + llmMarkInvalid},
			{ToolName: "", Description: "Read keys. " + llmMarkHigh},
			{ToolName: "t1", Description: "Notes. " + llmMarkMedium},
		}
		gotIn := fake.received()
		slices.SortStableFunc(gotIn, func(a, b llm.Input) int {
			return strings.Compare(a.ToolName+"\x00"+a.Description, b.ToolName+"\x00"+b.Description)
		})
		if !slices.Equal(gotIn, wantIn) {
			t.Errorf("classifier inputs = %+v, want %+v", gotIn, wantIn)
		}
	})

	t.Run("json", func(t *testing.T) {
		t.Parallel()
		r := llmScan(t, llmEnv(t, tools), tools, &llmFake{}, "--llm", "--json")

		if r.code != exitFindings {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
		}
		doc := decodeScanJSON(t, r.stdout)
		type view struct{ rule, server, key, related string }
		var got []view
		for _, f := range doc.Findings {
			if strings.HasPrefix(f.RuleID, "MOAT-LLM-") {
				got = append(got, view{f.RuleID, f.Server, f.Key, f.Related})
			}
		}
		want := []view{
			{llm.RuleID, "alpha", noToolNameKey, string(llm.CategoryCredentialAccess)},
			{llm.RuleIDInvalid, "beta", noToolNameKey, ""},
			{llm.RuleID, "beta", "t1", string(llm.CategoryHiddenInstructions)},
		}
		if !slices.Equal(got, want) {
			t.Errorf("LLM findings = %+v, want %+v\nstdout:\n%s", got, want, r.stdout)
		}
		if noToolNameKey != "(no name)" {
			t.Errorf("noToolNameKey = %q, want %q", noToolNameKey, "(no name)")
		}
	})

	// classifyTools matches the ignore list with the real tool name, which is
	// empty here, and not with "(no name)". A tool entry can name no empty
	// tool, and an entry cannot hold "(no name)" (it has a space, so the line
	// has too many fields). So only a rule entry or a server entry drops such
	// a finding.
	ignoreTests := []struct {
		name       string
		args       []string
		ignoreFile string
		want       []llmHit
		wantStderr []string
	}{
		{
			name:       "server entry",
			ignoreFile: "MOAT-LLM-001 alpha\n",
			want:       []llmHit{{llm.RuleIDInvalid, "medium", "beta", noToolNameKey}, {llm.RuleID, "medium", "beta", "t1"}},
			wantStderr: []string{"mcpmoat scan: 1 finding ignored: MOAT-LLM-001 (1)\n"},
		},
		{
			name:       "tool entry for another tool",
			ignoreFile: "MOAT-LLM-001 alpha/t1\n",
			want: []llmHit{
				{llm.RuleID, "high", "alpha", noToolNameKey},
				{llm.RuleIDInvalid, "medium", "beta", noToolNameKey},
				{llm.RuleID, "medium", "beta", "t1"},
			},
		},
		{
			name:       "entry with the placeholder is malformed",
			ignoreFile: "MOAT-LLM-001 alpha/(no name)\n",
			want: []llmHit{
				{llm.RuleID, "high", "alpha", noToolNameKey},
				{llm.RuleIDInvalid, "medium", "beta", noToolNameKey},
				{llm.RuleID, "medium", "beta", "t1"},
			},
			wantStderr: []string{".mcpmoat-ignore:1: too many fields (want RULE-ID [server[/tool]])\n"},
		},
		{
			name:       "--ignore rule",
			args:       []string{"--ignore", llm.RuleIDInvalid},
			want:       []llmHit{{llm.RuleID, "high", "alpha", noToolNameKey}, {llm.RuleID, "medium", "beta", "t1"}},
			wantStderr: []string{"mcpmoat scan: 1 finding ignored: MOAT-LLM-002 (1)\n"},
		},
	}
	for _, tt := range ignoreTests {
		t.Run("ignore/"+tt.name, func(t *testing.T) {
			t.Parallel()
			e := llmEnv(t, tools)
			if tt.ignoreFile != "" {
				writeTestFile(t, e.work, ".mcpmoat-ignore", tt.ignoreFile)
			}
			r := llmScan(t, e, tools, &llmFake{}, append([]string{"--llm", "--json"}, tt.args...)...)

			if r.code != exitFindings {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
			}
			if got := llmJSONRows(t, decodeScanJSON(t, r.stdout)); !slices.Equal(got, tt.want) {
				t.Errorf("LLM findings = %+v, want %+v", got, tt.want)
			}
			assertContainsAll(t, "stderr", r.stderr, tt.wantStderr)
			if len(tt.wantStderr) == 0 && strings.Contains(r.stderr, "ignored") {
				t.Errorf("stderr counts ignored findings, want none:\n%s", r.stderr)
			}
		})
	}
}

// TestScanLLMInterruptedAfterLastAnswer checks a signal that comes while the
// last Classify call returns its verdict: every tool has an answer, but the
// context ended. scan must still print interruptedText, exit with 2, print no
// report and save no pins.
func TestScanLLMInterruptedAfterLastAnswer(t *testing.T) {
	t.Parallel()

	for _, jsonOut := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", jsonOut), func(t *testing.T) {
			t.Parallel()
			const nTools = 3
			tools := map[string][]inspect.Tool{"srv": {mkTool("t1", llmMarkHigh), mkTool("t2", "Add."), mkTool("t3", llmMarkLow)}}
			e := llmEnv(t, tools)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var answered atomic.Int32
			fake := &llmFake{}
			fake.answer = func(in llm.Input) (llm.Verdict, error) {
				// The fake checks the context before it calls answer, so
				// this call returns its verdict after the cancel.
				if answered.Add(1) == nTools {
					cancel()
				}
				return llmAnswerFor(in)
			}
			f := &llmFactory{t: t, cl: fake}
			c, stdout, stderr := llmCLI(e, fakeServers(tools), f)
			c.ctx = ctx
			args := []string{"--llm"}
			if jsonOut {
				args = append(args, "--json")
			}

			r := llmRun(t, e, c, stdout, stderr, args...)

			if got := answered.Load(); got != nTools {
				t.Errorf("answers = %d, want %d (every tool answered)", got, nTools)
			}
			if r.code != exitError {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitError, r.stderr)
			}
			assertEmptyStdout(t, r.stdout)
			assertContainsAll(t, "stderr", r.stderr, []string{scanPrefix + interruptedText + "\n"})
			if llmNotClassified.MatchString(r.stderr) {
				t.Errorf("stderr reports a provider failure for a signal:\n%s", r.stderr)
			}
			e.assertNoPinsFile(t, "a signal with the last LLM answer")
		})
	}
}
