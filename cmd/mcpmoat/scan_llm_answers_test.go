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
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/report"
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

// TestScanLLMErrorSorting checks how scan sorts the errors of the classifier
// (see sortAnswer). It fails closed:
//
//   - llm.ErrInvalidOutput gives that tool one MOAT-LLM-002 finding (medium).
//     The other tools still get their answer, the step is complete and the
//     exit code follows the findings.
//   - An error that wraps llm.ErrProvider stops the LLM step with the line
//     "the LLM provider failed (<reason>); N tools were not classified".
//   - Any other error (a local error, an unknown error) stops the step too,
//     with the line "the LLM step failed (internal error); N tools were not
//     classified". It gives no MOAT-LLM-002 finding.
//
// A step that stops still prints the report, the JSON complete field is
// false and scan exits with 2. The text of a generic error never shows.
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

	// stepFailure is how the LLM step must end.
	type stepFailure int
	const (
		noFailure       stepFailure = iota // the step is complete
		providerFailure                    // the provider line
		internalFailure                    // the internal error line
		eitherFailure                      // the first failure decides the line
	)

	tests := []struct {
		name    string
		tools   []string            // the tool names of the one server "srv", in order
		replies map[string]llmReply // by tool name; a tool not named gets risk none
		failure stepFailure
		// wantReason is the reason in the provider line, for a provider
		// failure (or eitherFailure when the provider line shows).
		wantReason string
		// wantCount is the count of tools that were not classified in the
		// failure line; "" means any count of 1 or more.
		wantCount string
		// wantRows are the LLM findings. When the step fails, the other
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
			name:    "provider error that wraps ErrProvider",
			tools:   []string{"t1"},
			replies: map[string]llmReply{"t1": wrappedProvider},
			failure: providerFailure,
			// llm.Reason does not know this error, so the reason is the
			// fixed "unknown error", never the text of the error.
			wantReason: "unknown error",
			wantCount:  "1",
			wantCode:   exitError,
			wantMedium: exitError,
			wantCalls:  1,
		},
		{
			name:       "provider status 503",
			tools:      []string{"t1"},
			replies:    map[string]llmReply{"t1": status503},
			failure:    providerFailure,
			wantReason: "HTTP 503",
			wantCount:  "1",
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
			// Fail closed: an unknown error is not a MOAT-LLM-002 finding.
			name:       "generic error",
			tools:      []string{"t1"},
			replies:    map[string]llmReply{"t1": generic},
			failure:    internalFailure,
			wantCount:  "1",
			wantCode:   exitError,
			wantMedium: exitError,
			wantCalls:  1,
		},
		{
			// The first generic error stops the step. No tool gets a row,
			// and every tool counts as not classified.
			name:       "generic error on every tool",
			tools:      []string{"t1", "t2", "t3", "t4", "t5", "t6"},
			replies:    map[string]llmReply{"t1": generic, "t2": generic, "t3": generic, "t4": generic, "t5": generic, "t6": generic},
			failure:    internalFailure,
			wantCount:  "6",
			wantCode:   exitError,
			wantMedium: exitError,
		},
		{
			name:    "mixed tools without a failure",
			tools:   []string{"t1", "t2", "t3", "t4"},
			replies: map[string]llmReply{"t1": high, "t2": invalid},
			wantRows: []llmHit{
				{llm.RuleID, "high", "srv", "t1"},
				{llm.RuleIDInvalid, "medium", "srv", "t2"},
			},
			wantCode:   exitFindings,
			wantMedium: exitFindings,
			wantCalls:  4,
		},
		{
			// The generic error stops the step. The other tools can still
			// get their row when they ended first.
			name:    "mixed tools with a generic error",
			tools:   []string{"t1", "t2", "t3", "t4"},
			replies: map[string]llmReply{"t1": high, "t2": invalid, "t3": generic},
			failure: internalFailure,
			wantRows: []llmHit{
				{llm.RuleID, "high", "srv", "t1"},
				{llm.RuleIDInvalid, "medium", "srv", "t2"},
			},
			wantCode:   exitError,
			wantMedium: exitError,
		},
		{
			// Both errors stop the step. The first failure decides the
			// line, and the order of the requests is not fixed.
			name:       "mixed tools with a generic error and a provider failure",
			tools:      []string{"t1", "t2"},
			replies:    map[string]llmReply{"t1": generic, "t2": status503},
			failure:    eitherFailure,
			wantReason: "HTTP 503",
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

					provider := llmNotClassified.FindAllStringSubmatch(r.stderr, -1)
					internal := llmInternalFailed.FindAllStringSubmatch(r.stderr, -1)
					var count string
					switch tt.failure {
					case noFailure:
						if len(provider)+len(internal) != 0 || strings.Contains(r.stderr, "LLM provider failed") || strings.Contains(r.stderr, "LLM step failed") {
							t.Errorf("stderr reports a failure of the LLM step, want none:\n%s", r.stderr)
						}
					case providerFailure:
						if len(provider) != 1 || len(internal) != 0 {
							t.Fatalf("stderr has %d provider lines and %d internal lines, want 1 and 0:\n%s", len(provider), len(internal), r.stderr)
						}
						count = provider[0][2]
						if provider[0][1] != tt.wantReason {
							t.Errorf("failure reason = %q, want %q", provider[0][1], tt.wantReason)
						}
					case internalFailure:
						if len(internal) != 1 || len(provider) != 0 {
							t.Fatalf("stderr has %d internal lines and %d provider lines, want 1 and 0:\n%s", len(internal), len(provider), r.stderr)
						}
						count = internal[0][1]
					case eitherFailure:
						if len(provider)+len(internal) != 1 {
							t.Fatalf("stderr has %d provider lines and %d internal lines, want 1 in total:\n%s", len(provider), len(internal), r.stderr)
						}
						if len(provider) == 1 {
							count = provider[0][2]
							if provider[0][1] != tt.wantReason {
								t.Errorf("failure reason = %q, want %q", provider[0][1], tt.wantReason)
							}
						} else {
							count = internal[0][1]
						}
					}
					if tt.failure != noFailure {
						if tt.wantCount != "" && count != tt.wantCount {
							t.Errorf("not classified count = %s, want %s", count, tt.wantCount)
						}
						if count == "0" {
							t.Errorf("not classified count = 0, want at least 1")
						}
					}
					for _, out := range []string{r.stdout, r.stderr} {
						if strings.Contains(out, genericCanary) {
							t.Errorf("output holds the text of the generic error:\n%s", out)
						}
					}

					var got []llmHit
					if jsonOut {
						doc := decodeScanJSON(t, r.stdout)
						if wantComplete := tt.failure == noFailure; doc.Complete != wantComplete {
							t.Errorf("complete = %v, want %v", doc.Complete, wantComplete)
						}
						if len(doc.Servers) != 1 {
							t.Errorf("JSON has %d servers, want 1: the report must still print", len(doc.Servers))
						}
						got = llmJSONRows(t, doc)
					} else {
						if !strings.Contains(r.stdout, summaryHeading) {
							t.Errorf("stdout has no SUMMARY block\nstdout:\n%s", r.stdout)
						}
						got = llmRowsOf(t, parseFindings(t, r.stdout))
					}
					if tt.failure != noFailure {
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
		if !slices.EqualFunc(gotIn, wantIn, llmSameInput) {
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

	// classifyPlan matches the ignore list with the real tool name, which is
	// empty here, and not with "(no name)". A tool entry can name no empty
	// tool, and an entry cannot hold "(no name)" (it has a space, so the line
	// has too many fields). .mcpmoat-ignore cannot ignore the LLM rules (see
	// scanIgnores), so a file entry never drops such a finding: a server entry
	// matches it and gives the warning, and a tool entry does not match it.
	// --ignore drops it.
	ignoreTests := []struct {
		name       string
		args       []string
		ignoreFile string
		want       []llmHit
		wantStderr []string
		noStderr   []string
	}{
		{
			name:       "server entry",
			ignoreFile: "MOAT-LLM-001 alpha\n",
			want: []llmHit{
				{llm.RuleID, "high", "alpha", noToolNameKey},
				{llm.RuleIDInvalid, "medium", "beta", noToolNameKey},
				{llm.RuleID, "medium", "beta", "t1"},
			},
			wantStderr: []string{llmFileWarning(llm.RuleID)},
		},
		{
			name:       "tool entry for another tool",
			ignoreFile: "MOAT-LLM-001 alpha/t1\n",
			want: []llmHit{
				{llm.RuleID, "high", "alpha", noToolNameKey},
				{llm.RuleIDInvalid, "medium", "beta", noToolNameKey},
				{llm.RuleID, "medium", "beta", "t1"},
			},
			noStderr: []string{"cannot ignore"},
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
			args := append([]string{"--llm", "--json"}, tt.args...)
			if tt.ignoreFile != "" {
				writeTestFile(t, e.work, ".mcpmoat-ignore", tt.ignoreFile)
				// scan reads the file only with --use-ignore-file.
				args = append(args, "--use-ignore-file")
			}
			r := llmScan(t, e, tools, &llmFake{}, args...)

			if r.code != exitFindings {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
			}
			if got := llmJSONRows(t, decodeScanJSON(t, r.stdout)); !slices.Equal(got, tt.want) {
				t.Errorf("LLM findings = %+v, want %+v", got, tt.want)
			}
			assertContainsAll(t, "stderr", r.stderr, tt.wantStderr)
			if !slices.ContainsFunc(tt.wantStderr, func(s string) bool { return strings.Contains(s, "ignored") }) &&
				strings.Contains(r.stderr, "ignored") {
				t.Errorf("stderr counts ignored findings, want none:\n%s", r.stderr)
			}
			for _, s := range tt.noStderr {
				if strings.Contains(r.stderr, s) {
					t.Errorf("stderr holds %q, want not:\n%s", s, r.stderr)
				}
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
			if llmNotClassified.MatchString(r.stderr) || llmInternalFailed.MatchString(r.stderr) {
				t.Errorf("stderr reports a failure of the LLM step for a signal:\n%s", r.stderr)
			}
			e.assertNoPinsFile(t, "a signal with the last LLM answer")
		})
	}
}

// TestSortAnswer lists every error class that the LLM client can return, and
// the answerKind that sortAnswer must give it. A new error class must get its
// own row here, so its kind is a conscious decision. sortAnswer fails closed:
// only llm.ErrInvalidOutput and llm.ErrRejected (HTTP 400, 413 and 422, per
// tool) give a MOAT-LLM-002 row, and an error that it does not know stops the
// step as an internal failure. llm.ErrRejected wraps llm.ErrProvider, so the
// rows check that the per-tool codes do not fall into the provider case, and
// that every other code stays a global failure. The provider errors of
// package llm (a refused key, a network error, a response that is too large
// or not valid) are unexported, so the rows use what the client gives: a
// *llm.StatusError, or an error that wraps llm.ErrProvider. The unexported
// local errors of package llm (a request that is too large, a request that
// cannot be built, a nil client, a refused proxy setting) wrap nothing, so
// the "unknown error" row covers them.
func TestSortAnswer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		want      answerKind
		wantStops bool // answerKind.stepFails
	}{
		{"nil", nil, answerVerdict, false},
		{"invalid output", llm.ErrInvalidOutput, answerUnusable, false},
		{"wrapped invalid output", fmt.Errorf("test: %w", llm.ErrInvalidOutput), answerUnusable, false},
		{"context canceled", context.Canceled, answerStopped, false},
		{"context deadline exceeded", context.DeadlineExceeded, answerStopped, false},
		{"wrapped context canceled", fmt.Errorf("test: stopped: %w", context.Canceled), answerStopped, false},
		{"auth 403", &llm.StatusError{Code: http.StatusForbidden}, answerProviderFailed, true},
		{"wrapped auth 401", fmt.Errorf("test: %w", &llm.StatusError{Code: http.StatusUnauthorized}), answerProviderFailed, true},
		{"status 401", &llm.StatusError{Code: http.StatusUnauthorized}, answerProviderFailed, true},
		{"status 429", &llm.StatusError{Code: http.StatusTooManyRequests}, answerProviderFailed, true},
		{"status 503", &llm.StatusError{Code: http.StatusServiceUnavailable}, answerProviderFailed, true},
		{"status 307 redirect", &llm.StatusError{Code: http.StatusTemporaryRedirect}, answerProviderFailed, true},
		{"status 404", &llm.StatusError{Code: http.StatusNotFound}, answerProviderFailed, true},
		{"status 500", &llm.StatusError{Code: http.StatusInternalServerError}, answerProviderFailed, true},
		{"wrapped status 503", fmt.Errorf("test: %w", &llm.StatusError{Code: http.StatusServiceUnavailable}), answerProviderFailed, true},
		// The neighbours of the per-tool codes stay global.
		{"status 412", &llm.StatusError{Code: http.StatusPreconditionFailed}, answerProviderFailed, true},
		{"status 414", &llm.StatusError{Code: http.StatusRequestURITooLong}, answerProviderFailed, true},
		{"status 421", &llm.StatusError{Code: http.StatusMisdirectedRequest}, answerProviderFailed, true},
		{"status 423", &llm.StatusError{Code: http.StatusLocked}, answerProviderFailed, true},
		// The per-tool codes: the provider refused this one tool. They do not
		// stop the step.
		{"status 400", &llm.StatusError{Code: http.StatusBadRequest}, answerRejected, false},
		{"status 413", &llm.StatusError{Code: http.StatusRequestEntityTooLarge}, answerRejected, false},
		{"status 422", &llm.StatusError{Code: http.StatusUnprocessableEntity}, answerRejected, false},
		{"wrapped status 400", fmt.Errorf("test: %w", &llm.StatusError{Code: http.StatusBadRequest}), answerRejected, false},
		{"wrapped status 413", fmt.Errorf("test: %w", &llm.StatusError{Code: http.StatusRequestEntityTooLarge}), answerRejected, false},
		{"wrapped status 422", fmt.Errorf("test: %w", &llm.StatusError{Code: http.StatusUnprocessableEntity}), answerRejected, false},
		{"rejected", llm.ErrRejected, answerRejected, false},
		{"wrapped rejected", fmt.Errorf("test: %w", llm.ErrRejected), answerRejected, false},
		// A canceled context wins over a refusal in the same chain: the
		// request did not end with an answer of the provider.
		{"rejected and canceled", errors.Join(llm.ErrRejected, context.Canceled), answerStopped, false},
		// Invalid output wins too: it comes from a 2xx body.
		{"rejected and invalid output", errors.Join(llm.ErrRejected, llm.ErrInvalidOutput), answerUnusable, false},
		{"transport", fmt.Errorf("%w: network error", llm.ErrProvider), answerProviderFailed, true},
		{"response too large", fmt.Errorf("%w: response body too large", llm.ErrProvider), answerProviderFailed, true},
		{"bad response", fmt.Errorf("%w: response is not valid", llm.ErrProvider), answerProviderFailed, true},
		{"provider", llm.ErrProvider, answerProviderFailed, true},
		{"wrapped provider", fmt.Errorf("test: %w", llm.ErrProvider), answerProviderFailed, true},
		{"unknown error", errors.New("local-error-canary"), answerInternalFailed, true},
		{"wrapped unknown error", fmt.Errorf("test: %w", errors.New("inner")), answerInternalFailed, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sortAnswer(tt.err)
			if got != tt.want {
				t.Errorf("sortAnswer(%v) = %v, want %v", tt.err, got, tt.want)
			}
			if stops := got.stepFails(); stops != tt.wantStops {
				t.Errorf("sortAnswer(%v).stepFails() = %v, want %v", tt.err, stops, tt.wantStops)
			}
		})
	}
}

// TestAnswerKindAnswered checks which kinds count as an answer: a verdict,
// an answer that cannot be used and a refusal of the tool (answerRejected).
// A tool with any other kind is counted as not classified: also a tool whose
// request the step deadline stopped (answerDeadline). The table lists every
// kind up to answerDeadline, so a new kind fails the test until it gets a
// row.
func TestAnswerKindAnswered(t *testing.T) {
	t.Parallel()

	want := map[answerKind]bool{
		answerNotRun:         false,
		answerVerdict:        true,
		answerUnusable:       true,
		answerRejected:       true,
		answerStopped:        false,
		answerProviderFailed: false,
		answerInternalFailed: false,
		answerDeadline:       false,
	}
	for k := answerNotRun; k <= answerDeadline; k++ {
		w, ok := want[k]
		if !ok {
			t.Errorf("%v has no row in the table", k)
			continue
		}
		if got := k.answered(); got != w {
			t.Errorf("%v.answered() = %v, want %v", k, got, w)
		}
	}
}

// TestAnswerKindGot2xx checks which kinds mean a 2xx answer of the provider:
// only a verdict and an answer that cannot be used. A refusal is an answer
// (see TestAnswerKindAnswered) but not a 2xx answer, so the fail-closed check
// of rejectedFailure does not count it. stepFails is in the same table: a
// refusal does not stop the step at once.
func TestAnswerKindGot2xx(t *testing.T) {
	t.Parallel()

	tests := map[answerKind]struct{ got2xx, stepFails bool }{
		answerNotRun:         {false, false},
		answerVerdict:        {true, false},
		answerUnusable:       {true, false},
		answerRejected:       {false, false},
		answerStopped:        {false, false},
		answerProviderFailed: {false, true},
		answerInternalFailed: {false, true},
		// The step deadline stops the step like a provider failure, and the
		// stopped request got no 2xx answer.
		answerDeadline: {false, true},
	}
	for k := answerNotRun; k <= answerDeadline; k++ {
		w, ok := tests[k]
		if !ok {
			t.Errorf("%v has no row in the table", k)
			continue
		}
		if got := k.got2xx(); got != w.got2xx {
			t.Errorf("%v.got2xx() = %v, want %v", k, got, w.got2xx)
		}
		if got := k.stepFails(); got != w.stepFails {
			t.Errorf("%v.stepFails() = %v, want %v", k, got, w.stepFails)
		}
		// A 2xx answer is always an answer.
		if k.got2xx() && !k.answered() {
			t.Errorf("%v.got2xx() is true but answered() is false", k)
		}
	}
}

// rowWant is the row that llmRow must give in one case. ok false means no
// row, and the other fields are then not compared.
type rowWant struct {
	ok                            bool
	rule, severity, risk, related string
}

// TestLLMRowUnrated checks llmRow directly for each combination of a cut and a
// redacted tool text (llm.Verdict.Truncated and llm.Verdict.Redacted) with
// each kind of answer. An unrated text (cut or redacted) gets the MOAT-LLM-001
// floor row, of medium with the category other, when the model rated it none
// or low, when it gave an answer that cannot be used, or when the provider
// refused it. A refused or unusable answer that is not unrated keeps its
// MOAT-LLM-002 row, with llm.RejectedText or llm.InvalidText. A medium or high
// verdict keeps its own rating. A cut text wins over a redacted one, since
// the cut is the larger gap. A job without an answer gives no row.
func TestLLMRowUnrated(t *testing.T) {
	t.Parallel()

	cred := llm.CategoryCredentialAccess
	floorCut := rowWant{true, llm.RuleID, "medium", llm.TruncatedText, string(llm.CategoryOther)}
	floorRed := rowWant{true, llm.RuleID, "medium", llm.RedactedText, string(llm.CategoryOther)}
	kept := func(sev string) rowWant {
		return rowWant{true, llm.RuleID, sev, cred.Text(), string(cred)}
	}
	invalid := rowWant{true, llm.RuleIDInvalid, "medium", llm.InvalidText, ""}
	rejected := rowWant{true, llm.RuleIDInvalid, "medium", llm.RejectedText, ""}
	none := rowWant{}

	tests := []struct {
		name   string
		answer llmAnswer
		// plain, cut, redacted and both are the rows for no flag, a cut text,
		// a redacted text and a text both cut and redacted.
		plain, cut, redacted, both rowWant
	}{
		{name: "verdict none", answer: llmAnswer{kind: answerVerdict, verdict: llm.Verdict{Risk: llm.RiskNone, Category: cred}},
			plain: none, cut: floorCut, redacted: floorRed, both: floorCut},
		{name: "verdict low", answer: llmAnswer{kind: answerVerdict, verdict: llm.Verdict{Risk: llm.RiskLow, Category: cred}},
			plain: kept("low"), cut: floorCut, redacted: floorRed, both: floorCut},
		// A risk that is not valid fails closed: an unrated tool gets the
		// floor row, a rated one the invalid row.
		{name: "verdict invalid risk", answer: llmAnswer{kind: answerVerdict, verdict: llm.Verdict{Risk: "critical", Category: cred}},
			plain: invalid, cut: floorCut, redacted: floorRed, both: floorCut},
		{name: "verdict medium", answer: llmAnswer{kind: answerVerdict, verdict: llm.Verdict{Risk: llm.RiskMedium, Category: cred}},
			plain: kept("medium"), cut: kept("medium"), redacted: kept("medium"), both: kept("medium")},
		{name: "verdict high", answer: llmAnswer{kind: answerVerdict, verdict: llm.Verdict{Risk: llm.RiskHigh, Category: cred}},
			plain: kept("high"), cut: kept("high"), redacted: kept("high"), both: kept("high")},
		{name: "unusable", answer: llmAnswer{kind: answerUnusable},
			plain: invalid, cut: floorCut, redacted: floorRed, both: floorCut},
		{name: "rejected", answer: llmAnswer{kind: answerRejected},
			plain: rejected, cut: floorCut, redacted: floorRed, both: floorCut},
		// The error of the refusal changes nothing in the row.
		{name: "rejected with status error", answer: llmAnswer{kind: answerRejected, err: &llm.StatusError{Code: http.StatusUnprocessableEntity}},
			plain: rejected, cut: floorCut, redacted: floorRed, both: floorCut},
		// A job without an answer gives no row, also when its text is unrated.
		{name: "not run", answer: llmAnswer{kind: answerNotRun}, plain: none, cut: none, redacted: none, both: none},
		{name: "stopped", answer: llmAnswer{kind: answerStopped}, plain: none, cut: none, redacted: none, both: none},
		{name: "provider failed", answer: llmAnswer{kind: answerProviderFailed}, plain: none, cut: none, redacted: none, both: none},
		{name: "internal failed", answer: llmAnswer{kind: answerInternalFailed}, plain: none, cut: none, redacted: none, both: none},
		// A request that the step deadline stopped got no answer.
		{name: "deadline", answer: llmAnswer{kind: answerDeadline}, plain: none, cut: none, redacted: none, both: none},
	}
	job := llmJob{in: llm.Input{ToolName: "t1"}}
	for _, tt := range tests {
		flags := []struct {
			name          string
			cut, redacted bool
			want          rowWant
		}{
			{"plain", false, false, tt.plain},
			{"cut", true, false, tt.cut},
			{"redacted", false, true, tt.redacted},
			{"cut and redacted", true, true, tt.both},
		}
		for _, f := range flags {
			t.Run(tt.name+"/"+f.name, func(t *testing.T) {
				t.Parallel()
				answer := tt.answer
				answer.verdict.Truncated = f.cut
				answer.verdict.Redacted = f.redacted
				row, ok := llmRow(job, answer)
				if ok != f.want.ok {
					t.Fatalf("llmRow() ok = %v, want %v", ok, f.want.ok)
				}
				if !ok {
					if row != (report.FindingRow{}) {
						t.Errorf("llmRow() row = %+v, want the zero row", row)
					}
					return
				}
				if row.RuleID != f.want.rule || row.Severity != f.want.severity || row.Risk != f.want.risk || row.Related != f.want.related {
					t.Errorf("llmRow() = %s %s %q %q, want %s %s %q %q",
						row.RuleID, row.Severity, row.Risk, row.Related, f.want.rule, f.want.severity, f.want.risk, f.want.related)
				}
				// The title and the fix are the fixed texts of the rule.
				wantTitle, wantFix := llm.Title, llm.Remediation
				if f.want.rule == llm.RuleIDInvalid {
					wantTitle, wantFix = llm.InvalidTitle, llm.InvalidRemediation
				}
				if row.Title != wantTitle || row.Remediation != wantFix {
					t.Errorf("llmRow() title, fix = %q, %q; want %q, %q", row.Title, row.Remediation, wantTitle, wantFix)
				}
				if row.Source != report.SourceLLM || row.Key != "t1" {
					t.Errorf("llmRow() source, key = %q, %q; want %q, %q", row.Source, row.Key, report.SourceLLM, "t1")
				}
			})
		}
	}
}

// verdictClassifier is a toolClassifier that returns its own verdict, with no
// error, for every tool.
type verdictClassifier llm.Verdict

// Classify implements toolClassifier.
func (v verdictClassifier) Classify(context.Context, llm.Input) (llm.Verdict, error) {
	return llm.Verdict(v), nil
}

// TestClassifyToolsInvalidVerdict checks that a verdict with a risk or a
// category that is not valid fails closed, like an answer that cannot be
// used: a MOAT-LLM-002 row, or the MOAT-LLM-001 floor row for a cut tool
// text. parseVerdict refuses such a verdict, so only a fake classifier can
// return one. A valid verdict keeps its own row, as a control.
func TestClassifyToolsInvalidVerdict(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"}
	outcomes := []inspect.Outcome{{Server: srv, Status: inspect.StatusOK, Result: inspect.Result{Tools: []inspect.Tool{mkTool("t1", "Add.")}}}}
	tests := []struct {
		name         string
		verdict      llm.Verdict
		wantRule     string
		wantSeverity string
		wantRisk     string
		wantRelated  string
	}{
		{name: "invalid risk", verdict: llm.Verdict{Risk: "critical", Category: llm.CategoryCredentialAccess},
			wantRule: llm.RuleIDInvalid, wantSeverity: "medium", wantRisk: llm.InvalidText},
		{name: "empty risk", verdict: llm.Verdict{Category: llm.CategoryOther},
			wantRule: llm.RuleIDInvalid, wantSeverity: "medium", wantRisk: llm.InvalidText},
		{name: "invalid category, risk high", verdict: llm.Verdict{Risk: llm.RiskHigh, Category: "bogus"},
			wantRule: llm.RuleIDInvalid, wantSeverity: "medium", wantRisk: llm.InvalidText},
		{name: "invalid category, risk none", verdict: llm.Verdict{Risk: llm.RiskNone, Category: ""},
			wantRule: llm.RuleIDInvalid, wantSeverity: "medium", wantRisk: llm.InvalidText},
		{name: "invalid risk, cut", verdict: llm.Verdict{Risk: "critical", Category: llm.CategoryCredentialAccess, Truncated: true},
			wantRule: llm.RuleID, wantSeverity: "medium", wantRisk: llm.TruncatedText, wantRelated: string(llm.CategoryOther)},
		{name: "invalid category, risk high, cut", verdict: llm.Verdict{Risk: llm.RiskHigh, Category: "bogus", Truncated: true},
			wantRule: llm.RuleID, wantSeverity: "medium", wantRisk: llm.TruncatedText, wantRelated: string(llm.CategoryOther)},
		{name: "valid verdict", verdict: llm.Verdict{Risk: llm.RiskHigh, Category: llm.CategoryCredentialAccess},
			wantRule: llm.RuleID, wantSeverity: "high", wantRisk: llm.CategoryCredentialAccess.Text(), wantRelated: string(llm.CategoryCredentialAccess)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, err := classifyTools(t.Context(), outcomes, verdictClassifier(tt.verdict), &scanIgnores{})
			if err != nil {
				t.Fatalf("classifyTools() error = %v", err)
			}
			if res.incomplete() {
				t.Errorf("classifyTools() result is incomplete: %+v", res)
			}
			if len(res.rows) != 1 {
				t.Fatalf("classifyTools() rows = %+v, want one row", res.rows)
			}
			row := res.rows[0]
			if row.RuleID != tt.wantRule || row.Severity != tt.wantSeverity || row.Risk != tt.wantRisk || row.Related != tt.wantRelated {
				t.Errorf("row = %s %s %q %q, want %s %s %q %q",
					row.RuleID, row.Severity, row.Risk, row.Related, tt.wantRule, tt.wantSeverity, tt.wantRisk, tt.wantRelated)
			}
			if row.Source != report.SourceLLM || row.Key != "t1" {
				t.Errorf("row source, key = %q, %q; want %q, %q", row.Source, row.Key, report.SourceLLM, "t1")
			}
		})
	}
}

// TestNewLLMAnswer checks what newLLMAnswer keeps of the verdict: all of it
// for a verdict, only Truncated for an answer that cannot be used and for a
// refused tool (so that llmRow can give a cut tool the floor row), and
// nothing for the kinds without an answer. It keeps the error of Classify
// only for a refusal (answerRejected), for the reason of rejectedFailure:
// for every other kind the error is dropped, so its text can never be
// printed.
func TestNewLLMAnswer(t *testing.T) {
	t.Parallel()

	full := llm.Verdict{Risk: llm.RiskHigh, Category: llm.CategoryCredentialAccess, Truncated: true}
	notCut := llm.Verdict{Risk: llm.RiskHigh, Category: llm.CategoryCredentialAccess}
	// classifyErr is the error that Classify returned with the verdict. Each
	// kind gets the same error, so only the kind decides whether it is kept.
	classifyErr := fmt.Errorf("%w: test refusal", llm.ErrRejected)
	tests := map[answerKind]struct{ cut, notCut llm.Verdict }{
		answerNotRun:         {},
		answerVerdict:        {full, notCut},
		answerUnusable:       {llm.Verdict{Truncated: true}, llm.Verdict{}},
		answerRejected:       {llm.Verdict{Truncated: true}, llm.Verdict{}},
		answerStopped:        {},
		answerProviderFailed: {},
		answerInternalFailed: {},
		answerDeadline:       {},
	}
	for k := answerNotRun; k <= answerDeadline; k++ {
		w, ok := tests[k]
		if !ok {
			t.Errorf("%v has no row in the table", k)
			continue
		}
		var wantErr error
		if k == answerRejected {
			wantErr = classifyErr
		}
		for _, in := range []struct{ v, want llm.Verdict }{{full, w.cut}, {notCut, w.notCut}} {
			got := newLLMAnswer(k, in.v, classifyErr)
			if got.kind != k || got.verdict != in.want {
				t.Errorf("newLLMAnswer(%v, %+v) = %v %+v, want %v %+v", k, in.v, got.kind, got.verdict, k, in.want)
			}
			// Compare the error values, not with errors.Is: the answer must
			// hold the very error of Classify, or nil.
			if got.err != wantErr { //nolint:errorlint // identity check: newLLMAnswer must keep the same error value
				t.Errorf("newLLMAnswer(%v, %+v).err = %v, want %v", k, in.v, got.err, wantErr)
			}
		}
	}
}

// TestAnswerKindString checks that every answerKind up to the last one
// (answerDeadline) has a name. A new kind without a case in String gives the
// numeric fallback and fails this test. Add the new kind here when it comes
// after answerDeadline.
func TestAnswerKindString(t *testing.T) {
	t.Parallel()

	const last = answerDeadline
	seen := make(map[string]answerKind)
	for k := answerNotRun; k <= last; k++ {
		got := k.String()
		if fallback := fmt.Sprintf("answerKind(%d)", int(k)); got == fallback {
			t.Errorf("answerKind %d has no name in String", int(k))
		}
		if other, dup := seen[got]; dup {
			t.Errorf("answerKind %d and %d have the same name %q", int(other), int(k), got)
		}
		seen[got] = k
	}
	if got, want := (last + 1).String(), fmt.Sprintf("answerKind(%d)", int(last+1)); got != want {
		t.Errorf("answerKind %d String() = %q, want the fallback %q: update last", int(last+1), got, want)
	}
	// Each name is the name of the constant, so a failure message names the
	// kind that a reader finds in scan_llm.go.
	names := map[answerKind]string{
		answerNotRun:         "answerNotRun",
		answerVerdict:        "answerVerdict",
		answerUnusable:       "answerUnusable",
		answerRejected:       "answerRejected",
		answerStopped:        "answerStopped",
		answerProviderFailed: "answerProviderFailed",
		answerInternalFailed: "answerInternalFailed",
		answerDeadline:       "answerDeadline",
	}
	for k, want := range names {
		if got := k.String(); got != want {
			t.Errorf("answerKind %d String() = %q, want %q", int(k), got, want)
		}
	}
	if len(names) != int(last)+1 {
		t.Errorf("the name table has %d kinds, want %d: add the new kind", len(names), int(last)+1)
	}
}

// TestCloseClassifierNil checks that closeClassifier does nothing for a nil
// classifier (scan without --llm) and for a nil *llm.Client.
func TestCloseClassifierNil(t *testing.T) {
	t.Parallel()

	closeClassifier(nil)
	var client *llm.Client
	closeClassifier(client)
}

// TestLLMFailureLine checks the start of the stderr line of a failed LLM step:
// only a provider failure names the provider, and an internal failure has
// fixed text. A status code gets a fixed hint for 401 and 403 (the key), for
// a 3xx (the redirect) and for 400, 413 and 422 (the provider refused the
// tool), and no hint for other codes. Package llm keeps its other provider
// errors unexported, so a provider error made here is not one that
// llm.Reason knows: its reason is the fixed "unknown error", never the text
// of the error.
//
// The refusal of every answered tool (kind answerRejected, see
// rejectedFailure) is a provider failure too, with the reason of
// rejectedReason: "HTTP <code>, the provider refused every tool", with no
// nested parentheses. A 400 can only reach the global line (kind
// answerProviderFailed) from a classifier that wraps it in a way that
// sortAnswer does not see as a refusal; the line then shows the text of
// llm.Reason.
func TestLLMFailureLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		failure *llmFailure
		want    string
	}{
		{"no failure", nil, llmInternalText},
		{"internal", &llmFailure{kind: answerInternalFailed}, llmInternalText},
		{"provider without error", &llmFailure{kind: answerProviderFailed}, llmInternalText},
		{"provider status", &llmFailure{kind: answerProviderFailed, err: &llm.StatusError{Code: http.StatusServiceUnavailable}}, "the LLM provider failed (HTTP 503)"},
		{"provider status 429", &llmFailure{kind: answerProviderFailed, err: &llm.StatusError{Code: http.StatusTooManyRequests}}, "the LLM provider failed (HTTP 429)"},
		{"provider status 401", &llmFailure{kind: answerProviderFailed, err: &llm.StatusError{Code: http.StatusUnauthorized}}, "the LLM provider failed (HTTP 401 (the API key was refused))"},
		{"provider status 403", &llmFailure{kind: answerProviderFailed, err: &llm.StatusError{Code: http.StatusForbidden}}, "the LLM provider failed (HTTP 403 (the API key was refused))"},
		{"provider status 401 wrapped", &llmFailure{kind: answerProviderFailed, err: fmt.Errorf("test: %w", &llm.StatusError{Code: http.StatusUnauthorized})}, "the LLM provider failed (HTTP 401 (the API key was refused))"},
		{"provider status 302", &llmFailure{kind: answerProviderFailed, err: &llm.StatusError{Code: http.StatusFound}}, "the LLM provider failed (HTTP 302 (redirect refused))"},
		{"provider status 307", &llmFailure{kind: answerProviderFailed, err: &llm.StatusError{Code: http.StatusTemporaryRedirect}}, "the LLM provider failed (HTTP 307 (redirect refused))"},
		{"provider status 400", &llmFailure{kind: answerRejected, err: &llm.StatusError{Code: http.StatusBadRequest}}, "the LLM provider failed (HTTP 400, the provider refused every tool)"},
		{"provider status 413", &llmFailure{kind: answerRejected, err: &llm.StatusError{Code: http.StatusRequestEntityTooLarge}}, "the LLM provider failed (HTTP 413, the provider refused every tool)"},
		{"provider status 422", &llmFailure{kind: answerRejected, err: &llm.StatusError{Code: http.StatusUnprocessableEntity}}, "the LLM provider failed (HTTP 422, the provider refused every tool)"},
		{"provider status 400 wrapped", &llmFailure{kind: answerRejected, err: fmt.Errorf("test: %w", &llm.StatusError{Code: http.StatusBadRequest})}, "the LLM provider failed (HTTP 400, the provider refused every tool)"},
		{"rejected bare", &llmFailure{kind: answerRejected, err: llm.ErrRejected}, "the LLM provider failed (the provider refused every tool)"},
		{"rejected with a canary", &llmFailure{kind: answerRejected, err: fmt.Errorf("%w: reason-canary-Z5", llm.ErrRejected)}, "the LLM provider failed (the provider refused every tool)"},
		// A refusal failure without an error is a guard: it never blames the
		// provider.
		{"rejected without error", &llmFailure{kind: answerRejected}, llmInternalText},
		// The global line for a 400 shows the text of llm.Reason, with its
		// own hint in parentheses.
		{"provider status 400 global", &llmFailure{kind: answerProviderFailed, err: &llm.StatusError{Code: http.StatusBadRequest}}, "the LLM provider failed (" + llm.Reason(&llm.StatusError{Code: http.StatusBadRequest}) + ")"},
		{"provider status 400 global text", &llmFailure{kind: answerProviderFailed, err: &llm.StatusError{Code: http.StatusBadRequest}}, "the LLM provider failed (HTTP 400 (the provider refused this tool))"},
		{"provider status 404", &llmFailure{kind: answerProviderFailed, err: &llm.StatusError{Code: http.StatusNotFound}}, "the LLM provider failed (HTTP 404)"},
		// Other kinds never name the provider, whatever the error.
		{"verdict with error", &llmFailure{kind: answerVerdict, err: &llm.StatusError{Code: http.StatusBadRequest}}, llmInternalText},
		{"stopped with error", &llmFailure{kind: answerStopped, err: &llm.StatusError{Code: http.StatusBadRequest}}, llmInternalText},
		{"provider bare", &llmFailure{kind: answerProviderFailed, err: llm.ErrProvider}, "the LLM provider failed (unknown error)"},
		{"provider not known", &llmFailure{kind: answerProviderFailed, err: fmt.Errorf("%w: network error", llm.ErrProvider)}, "the LLM provider failed (unknown error)"},
		{"provider not known with a canary", &llmFailure{kind: answerProviderFailed, err: fmt.Errorf("%w: reason-canary-Q8", llm.ErrProvider)}, "the LLM provider failed (unknown error)"},
		// The step deadline (answerDeadline) names the time limit and never
		// the provider. It needs no error, and the text of an error never
		// shows (the field stays nil in production, see runLLMJobs).
		{"deadline 10 minutes", &llmFailure{kind: answerDeadline, timeout: 10 * time.Minute}, "the LLM step stopped after 10 minutes"},
		{"deadline 1 minute", &llmFailure{kind: answerDeadline, timeout: time.Minute}, "the LLM step stopped after 1 minute"},
		{"deadline 30 seconds", &llmFailure{kind: answerDeadline, timeout: 30 * time.Second}, "the LLM step stopped after 30 seconds"},
		{"deadline 50ms", &llmFailure{kind: answerDeadline, timeout: 50 * time.Millisecond}, "the LLM step stopped after 50ms"},
		{"deadline with a canary error", &llmFailure{kind: answerDeadline, timeout: time.Minute, err: fmt.Errorf("%w: reason-canary-D4", llm.ErrProvider)}, "the LLM step stopped after 1 minute"},
		// A timeout on another kind changes nothing.
		{"provider with a timeout", &llmFailure{kind: answerProviderFailed, err: &llm.StatusError{Code: http.StatusServiceUnavailable}, timeout: time.Minute}, "the LLM provider failed (HTTP 503)"},
		{"internal with a timeout", &llmFailure{kind: answerInternalFailed, timeout: time.Minute}, llmInternalText},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := llmFailureLine(tt.failure); got != tt.want {
				t.Errorf("llmFailureLine() = %q, want %q", got, tt.want)
			}
		})
	}
	if llmInternalText != "the LLM step failed (internal error)" {
		t.Errorf("llmInternalText = %q, want %q", llmInternalText, "the LLM step failed (internal error)")
	}
}

// TestLLMStepStopped checks the guard of llmStep. classifyPlan fails only
// when the context ended, so the fake classifier cannot reach the guard
// through llmStep: the test calls llmStepStopped directly. An error while the
// context is alive must give one fixed line, never the text of the error.
// When the context ended and the error is not nil, the line is
// interruptedText, as for a signal. With no error, the step is done.
func TestLLMStepStopped(t *testing.T) {
	t.Parallel()

	const canary = "guard-error-canary-Kp3Zv8"
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name       string
		ctx        context.Context
		err        error
		want       bool
		wantStderr string
	}{
		{"alive without error", t.Context(), nil, false, ""},
		{"alive with error", t.Context(), errors.New(canary), true, scanPrefix + llmInternalText + "\n"},
		{"ended with context error", canceled, context.Canceled, true, scanPrefix + interruptedText + "\n"},
		{"ended without error", canceled, nil, false, ""},
		{"ended with other error", canceled, errors.New(canary), true, scanPrefix + interruptedText + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			c := &cli{stdout: &stdout, stderr: &stderr}
			if got := c.llmStepStopped(tt.ctx, tt.err); got != tt.want {
				t.Errorf("llmStepStopped() = %v, want %v", got, tt.want)
			}
			if stderr.String() != tt.wantStderr {
				t.Errorf("stderr = %q, want %q", stderr.String(), tt.wantStderr)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if strings.Contains(stderr.String(), canary) {
				t.Errorf("stderr holds the text of the error: %q", stderr.String())
			}
		})
	}
}
