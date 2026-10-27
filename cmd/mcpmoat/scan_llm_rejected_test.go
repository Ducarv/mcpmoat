package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// This file tests how "mcpmoat scan --llm" (FR-17, FR-16, issue #184)
// handles a provider that refuses one tool with HTTP 400, 413 or 422
// (llm.ErrRejected). A refused tool gets a MOAT-LLM-002 row with
// llm.RejectedText (a cut tool gets the MOAT-LLM-001 floor row), the other
// requests go on, and the step stays complete. When no answered tool got a
// 2xx answer, the step fails closed: exit 2, complete false, no LLM row and
// the line "the LLM provider failed (HTTP <code>, the provider refused every
// tool); N tools were not classified". A global failure (401, 403, 404, 5xx)
// or a signal wins over that check.

// llmRejectBodyCanary is in the body and in a header of every refusal of
// llmRejectAPI. The client never reads them, so it must show in no output.
const llmRejectBodyCanary = "mcpmoat-reject-body-canary-Hs4Qm8"

// llmMarkStatus returns the marker that makes llmRejectAPI answer a tool with
// the HTTP status code. The marker must be in the first part of a long
// description, before the cut of llm.MaxDescriptionBytes.
func llmMarkStatus(code int) string { return fmt.Sprintf("llm:http%d", code) }

// llmRejectStatus finds the marker of llmMarkStatus in a description.
var llmRejectStatus = regexp.MustCompile(`llm:http(\d{3})`)

// llmRejectAPI is a fake LLM provider on a loopback httptest server. It
// speaks the Anthropic Messages API or the OpenAI Chat Completions API, as
// provider says. A tool whose description holds llmMarkStatus(code) gets that
// status, with llmRejectBodyCanary in the body and in a header. Any other
// tool gets the answer of llmAnswerFor: a verdict, or a 2xx answer that
// cannot be used for llmMarkInvalid.
type llmRejectAPI struct {
	srv      *httptest.Server
	provider llm.Provider

	// requests counts every request. bad counts the requests that the fake
	// could not read: it answers them with a global failure, and the test
	// fails.
	requests atomic.Int32
	bad      atomic.Int32

	mu    sync.Mutex
	tools []string // the tool name of each request, in the order of arrival
}

// newLLMRejectAPI starts a fake provider of the given flavour.
func newLLMRejectAPI(t *testing.T, provider llm.Provider) *llmRejectAPI {
	t.Helper()
	a := &llmRejectAPI{provider: provider}
	a.srv = httptest.NewServer(http.HandlerFunc(a.handle))
	t.Cleanup(a.srv.Close)
	return a
}

// path returns the API path of the provider.
func (a *llmRejectAPI) path() string {
	if a.provider == llm.ProviderOpenAI {
		return "/chat/completions"
	}
	return "/v1/messages"
}

// handle answers one request.
func (a *llmRejectAPI) handle(w http.ResponseWriter, r *http.Request) {
	a.requests.Add(1)
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var content string
	if err == nil {
		content, err = llmSecretUserMessage(body)
	}
	var p llmSecretPayload
	if err == nil {
		p, err = llmSecretDecodePayload(content)
	}
	if err != nil || r.URL.Path != a.path() {
		a.bad.Add(1)
		// 418 is a global failure: the scan fails, and so does the test.
		w.WriteHeader(http.StatusTeapot)
		return
	}
	a.mu.Lock()
	a.tools = append(a.tools, p.ToolName)
	a.mu.Unlock()

	if m := llmRejectStatus.FindStringSubmatch(p.ToolDescription); m != nil {
		code, _ := strconv.Atoi(m[1])
		a.writeStatus(w, code)
		return
	}
	v, verr := llmAnswerFor(llm.Input{ToolName: p.ToolName, Description: p.ToolDescription})
	switch {
	case errors.Is(verr, llm.ErrInvalidOutput):
		a.writeUnusable(w)
	case verr != nil:
		// Use llmMarkStatus for a status code in this file.
		a.bad.Add(1)
		w.WriteHeader(http.StatusTeapot)
	default:
		a.writeVerdict(w, v)
	}
}

// writeStatus writes an error answer with code. The body is JSON with the
// canary and a raw escape byte, the error shape of the provider, so a client
// that printed it would fail the test.
func (a *llmRejectAPI) writeStatus(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", llmRejectBodyCanary)
	w.WriteHeader(code)
	msg := llmRejectBodyCanary + " \x1b[31mrefused\x1b[0m"
	if a.provider == llm.ProviderOpenAI {
		_, _ = io.WriteString(w, `{"error":{"message":"`+msg+`","type":"invalid_request_error","code":null}}`)
		return
	}
	_, _ = io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","message":"`+msg+`"}}`)
}

// writeUnusable writes a 2xx answer with no usable verdict: a refusal of the
// model. The client gives llm.ErrInvalidOutput.
func (a *llmRejectAPI) writeUnusable(w http.ResponseWriter) {
	if a.provider == llm.ProviderOpenAI {
		writeLLMJSON(w, map[string]any{
			"id":     "chatcmpl-test",
			"object": "chat.completion",
			"model":  "m1",
			"choices": []any{map[string]any{
				"index":         0,
				"finish_reason": "content_filter",
				"message":       map[string]any{"role": "assistant", "content": ""},
			}},
		})
		return
	}
	writeLLMJSON(w, map[string]any{
		"id":          "msg_test",
		"type":        "message",
		"role":        "assistant",
		"model":       "claude-test",
		"stop_reason": "refusal",
		"content":     []any{},
	})
}

// writeVerdict writes the 2xx answer of the provider for the verdict v.
func (a *llmRejectAPI) writeVerdict(w http.ResponseWriter, v llm.Verdict) {
	if a.provider != llm.ProviderOpenAI {
		writeLLMVerdict(w, v)
		return
	}
	content, _ := json.Marshal(map[string]string{"risk": string(v.Risk), "category": string(v.Category)})
	writeLLMJSON(w, map[string]any{
		"id":     "chatcmpl-test",
		"object": "chat.completion",
		"model":  "m1",
		"choices": []any{map[string]any{
			"index":         0,
			"finish_reason": "stop",
			"message":       map[string]any{"role": "assistant", "content": string(content)},
		}},
	})
}

// sentTools returns the sorted tool names of the requests so far.
func (a *llmRejectAPI) sentTools() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := slices.Clone(a.tools)
	slices.Sort(out)
	return out
}

// llmRejectScan runs "mcpmoat scan --llm" on the servers of tools with the
// real LLM client against api.
func llmRejectScan(t *testing.T, api *llmRejectAPI, tools map[string][]inspect.Tool, jsonOut bool, extra ...string) pinRunResult {
	t.Helper()
	e := llmEnv(t, tools)
	// A factory with no classifier fails the test when it is called, so the
	// scan must use the real client below.
	c, stdout, stderr := llmCLI(e, fakeServers(tools), &llmFactory{t: t})
	c.newClassifier = newLLMClassifier

	args := []string{"--llm", "--llm-base-url", api.srv.URL}
	if api.provider == llm.ProviderOpenAI {
		args = append(args, "--llm-provider", "openai", "--llm-model", "m1")
	}
	if jsonOut {
		args = append(args, "--json")
	}
	return llmRun(t, e, c, stdout, stderr, append(args, extra...)...)
}

// llmRejectRow is the part of an LLM finding that the tests of this file
// compare. risk is the Risk line of the terminal report; the JSON report has
// no risk text, so it is "" there.
type llmRejectRow struct {
	rule, severity, server, tool, related, risk string
}

// The rows that the tests of this file expect.
func rejectedRow002(tool string) llmRejectRow {
	return llmRejectRow{llm.RuleIDInvalid, "medium", "srv", tool, "", llm.RejectedText}
}

func unusableRow002(tool string) llmRejectRow {
	return llmRejectRow{llm.RuleIDInvalid, "medium", "srv", tool, "", llm.InvalidText}
}

func floorRow001(tool string) llmRejectRow {
	return llmRejectRow{llm.RuleID, "medium", "srv", tool, string(llm.CategoryOther), llm.TruncatedText}
}

func highRow001(tool string) llmRejectRow {
	return llmRejectRow{llm.RuleID, "high", "srv", tool, string(llm.CategoryCredentialAccess), llm.CategoryCredentialAccess.Text()}
}

// llmRejectRows returns the LLM findings of stdout, sorted by server, tool
// and rule. For the terminal report it also checks the fixed title and fix
// of each finding. llmRowsOf cannot read these rows: it wants llm.InvalidText
// for every MOAT-LLM-002 row.
func llmRejectRows(t *testing.T, stdout string, jsonOut bool) []llmRejectRow {
	t.Helper()
	var rows []llmRejectRow
	if jsonOut {
		for _, h := range llmJSONRows(t, decodeScanJSON(t, stdout)) {
			rows = append(rows, llmRejectRow{rule: h.rule, severity: h.severity, server: h.server, tool: h.tool})
		}
		// llmJSONRows drops Related: read it again.
		i := 0
		for _, f := range decodeScanJSON(t, stdout).Findings {
			if strings.HasPrefix(f.RuleID, "MOAT-LLM-") {
				rows[i].related = f.Related
				i++
			}
		}
	} else {
		for _, f := range parseFindings(t, stdout) {
			if !f.LLM {
				continue
			}
			wantTitle, wantFix := llm.Title, llm.Remediation
			if f.RuleID == llm.RuleIDInvalid {
				wantTitle, wantFix = llm.InvalidTitle, llm.InvalidRemediation
			}
			if f.Title != wantTitle || f.Fix != wantFix {
				t.Errorf("%s title, fix = %q, %q; want %q, %q", f.RuleID, f.Title, f.Fix, wantTitle, wantFix)
			}
			if f.Source != llmSourceTxt {
				t.Errorf("%s source = %q, want %q", f.RuleID, f.Source, llmSourceTxt)
			}
			tool, related, _ := strings.Cut(f.Tool, " ")
			related = strings.TrimSuffix(strings.TrimPrefix(related, "("), ")")
			rows = append(rows, llmRejectRow{f.RuleID, f.Severity, f.Name, tool, related, f.Risk})
		}
	}
	slices.SortFunc(rows, compareRejectRows)
	return rows
}

// compareRejectRows orders rows by server, tool and rule.
func compareRejectRows(a, b llmRejectRow) int {
	return strings.Compare(a.server+"\x00"+a.tool+"\x00"+a.rule, b.server+"\x00"+b.tool+"\x00"+b.rule)
}

// forOutput returns want as llmRejectRows gives it for the output: sorted,
// and with no risk text for --json.
func forOutput(want []llmRejectRow, jsonOut bool) []llmRejectRow {
	out := slices.Clone(want)
	if jsonOut {
		for i := range out {
			out[i].risk = ""
		}
	}
	slices.SortFunc(out, compareRejectRows)
	return out
}

// notClassifiedText returns "1 tool was not classified" or "N tools were not
// classified". It is a copy of the text of printLLMProblems, so a change of
// it fails the tests.
func notClassifiedText(n int) string {
	if n == 1 {
		return "1 tool was not classified"
	}
	return fmt.Sprintf("%d tools were not classified", n)
}

// rejectedGuardLine returns the exact stderr line of the fail-closed check
// when every answered tool was refused: code is the status of the refused
// tool with the lowest job index, and n the number of tools.
func rejectedGuardLine(code, n int) string {
	return fmt.Sprintf("%sthe LLM provider failed (HTTP %d, the provider refused every tool); %s\n", scanPrefix, code, notClassifiedText(n))
}

// llmStepFailureLines returns the lines of stderr that report a failure of
// the LLM step: a provider failure or an internal error.
func llmStepFailureLines(stderr string) []string {
	var out []string
	for line := range strings.Lines(stderr) {
		if strings.HasPrefix(line, scanPrefix+"the LLM provider failed") || strings.HasPrefix(line, scanPrefix+"the LLM step failed") {
			out = append(out, line)
		}
	}
	return out
}

// TestScanLLMRejected runs scan --llm with the real client against a fake
// provider that refuses some tools, for both provider flavours and for the
// terminal report and --json.
//
//   - A refusal (400, 413, 422) of one tool gives that tool a MOAT-LLM-002 row
//     with llm.RejectedText, or the MOAT-LLM-001 floor row when its
//     description was cut. The other tools are classified, nothing is
//     cancelled (one request for each tool), the step is complete, stderr has
//     no failure line and the exit code follows the rows.
//   - When every tool is refused, the step fails closed: exit 2, complete
//     false, no LLM row (also no floor row), and the guard line with the code
//     of the first tool. One tool with a 2xx answer (a verdict or an answer
//     that cannot be used) is enough to keep the step complete.
//   - A global failure (401, 403, 404, 503) wins over the check. These
//     requests run at the same time, so a request after the failure can be
//     cancelled: those cases only check that the rows are a part of the rows
//     that a full run gives.
//
// The body and a header of every refusal hold a canary and raw escape bytes.
// The client never reads them, so they show in no output.
func TestScanLLMRejected(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", 20<<10) // over llm.MaxDescriptionBytes
	tool := func(name, desc string) inspect.Tool { return mkTool(name, desc) }
	refused := func(name string, code int) inspect.Tool {
		return tool(name, "Read a file. "+llmMarkStatus(code))
	}

	tests := []struct {
		name  string
		tools []inspect.Tool // the tools of the one server "srv", in order
		args  []string
		// wantCode is the exit code.
		wantCode int
		// wantRows are the LLM rows of a full run. With wantReason set, the
		// rows must only be a part of them.
		wantRows []llmRejectRow
		// wantLine is the exact failure line of a step that fails closed;
		// "" means none.
		wantLine string
		// wantReason is the reason of a global failure line; "" means none.
		// The count of that line is from 1 to the number of tools.
		wantReason string
		// wantStderr are lines that stderr must hold.
		wantStderr []string
	}{
		{
			name:     "one tool 400, the others classified",
			tools:    []inspect.Tool{refused("t1", 400), tool("t2", "Read keys. "+llmMarkHigh), tool("t3", "Add.")},
			wantCode: exitFindings,
			wantRows: []llmRejectRow{rejectedRow002("t1"), highRow001("t2")},
		},
		{
			name:     "one tool 413, the others classified",
			tools:    []inspect.Tool{tool("t1", "Read keys. "+llmMarkHigh), refused("t2", 413), tool("t3", "Add.")},
			wantCode: exitFindings,
			wantRows: []llmRejectRow{highRow001("t1"), rejectedRow002("t2")},
		},
		{
			name:     "one tool 422, the others classified",
			tools:    []inspect.Tool{tool("t1", "Add."), tool("t2", "Read keys. "+llmMarkHigh), refused("t3", 422)},
			wantCode: exitFindings,
			wantRows: []llmRejectRow{highRow001("t2"), rejectedRow002("t3")},
		},
		{
			// The refusal row is medium: below the default --fail-on high.
			name:     "one tool 400, the other none",
			tools:    []inspect.Tool{refused("t1", 400), tool("t2", "Add.")},
			wantCode: exitOK,
			wantRows: []llmRejectRow{rejectedRow002("t1")},
		},
		{
			name:     "one tool 400, the other none, fail-on medium",
			tools:    []inspect.Tool{refused("t1", 400), tool("t2", "Add.")},
			args:     []string{"--fail-on", "medium"},
			wantCode: exitFindings,
			wantRows: []llmRejectRow{rejectedRow002("t1")},
		},
		{
			name:     "refused tool with a cut description gets the floor row",
			tools:    []inspect.Tool{tool("t1", llmMarkStatus(400)+" "+long), tool("t2", "Read keys. "+llmMarkHigh)},
			wantCode: exitFindings,
			wantRows: []llmRejectRow{floorRow001("t1"), highRow001("t2")},
		},
		{
			name:       "--ignore drops the refusal row",
			tools:      []inspect.Tool{refused("t1", 400), tool("t2", "Read keys. "+llmMarkHigh)},
			args:       []string{"--ignore", llm.RuleIDInvalid},
			wantCode:   exitFindings,
			wantRows:   []llmRejectRow{highRow001("t2")},
			wantStderr: []string{scanPrefix + "1 finding ignored: MOAT-LLM-002 (1)\n"},
		},
		{
			name:     "every tool refused with 400",
			tools:    []inspect.Tool{refused("t1", 400), refused("t2", 400), refused("t3", 400)},
			wantCode: exitError,
			wantLine: rejectedGuardLine(400, 3),
		},
		{
			// The reason is the code of the first tool, whatever the order
			// in which the answers come.
			name:     "every tool refused, the first tool gives the code",
			tools:    []inspect.Tool{refused("t1", 413), refused("t2", 400), refused("t3", 422)},
			wantCode: exitError,
			wantLine: rejectedGuardLine(413, 3),
		},
		{
			name:     "one tool, refused with 422",
			tools:    []inspect.Tool{refused("t1", 422)},
			wantCode: exitError,
			wantLine: rejectedGuardLine(422, 1),
		},
		{
			// Fail closed: a cut tool gets no floor row either.
			name:     "every tool refused, one cut",
			tools:    []inspect.Tool{tool("t1", llmMarkStatus(400)+" "+long), refused("t2", 400)},
			wantCode: exitError,
			wantLine: rejectedGuardLine(400, 2),
		},
		{
			// --ignore cannot turn the failed step into a clean scan.
			name:     "every tool refused, --ignore MOAT-LLM-002",
			tools:    []inspect.Tool{refused("t1", 400), refused("t2", 400)},
			args:     []string{"--ignore", llm.RuleIDInvalid},
			wantCode: exitError,
			wantLine: rejectedGuardLine(400, 2),
		},
		{
			name:     "every tool refused but one rated none",
			tools:    []inspect.Tool{refused("t1", 400), refused("t2", 422), tool("t3", "Add.")},
			wantCode: exitOK,
			wantRows: []llmRejectRow{rejectedRow002("t1"), rejectedRow002("t2")},
		},
		{
			// An answer that cannot be used is a 2xx answer too.
			name:     "every tool refused but one unusable",
			tools:    []inspect.Tool{refused("t1", 400), tool("t2", "Odd. "+llmMarkInvalid)},
			args:     []string{"--fail-on", "medium"},
			wantCode: exitFindings,
			wantRows: []llmRejectRow{rejectedRow002("t1"), unusableRow002("t2")},
		},
		{
			name:       "one tool 400 and one 503: the global failure wins",
			tools:      []inspect.Tool{refused("t1", 400), refused("t2", 503)},
			wantCode:   exitError,
			wantRows:   []llmRejectRow{rejectedRow002("t1")},
			wantReason: "HTTP 503",
		},
		{
			name:       "one tool 401 stays global",
			tools:      []inspect.Tool{refused("t1", 401), tool("t2", "Read keys. "+llmMarkHigh), tool("t3", "Add.")},
			wantCode:   exitError,
			wantRows:   []llmRejectRow{highRow001("t2")},
			wantReason: "HTTP 401 (the API key was refused)",
		},
		{
			name:       "one tool 400 and one 401: the global failure wins",
			tools:      []inspect.Tool{refused("t1", 400), refused("t2", 401)},
			wantCode:   exitError,
			wantRows:   []llmRejectRow{rejectedRow002("t1")},
			wantReason: "HTTP 401 (the API key was refused)",
		},
		{
			name:       "one tool 403 stays global",
			tools:      []inspect.Tool{refused("t1", 403)},
			wantCode:   exitError,
			wantReason: "HTTP 403 (the API key was refused)",
		},
		{
			name:       "one tool 404 stays global",
			tools:      []inspect.Tool{refused("t1", 404), refused("t2", 400)},
			wantCode:   exitError,
			wantRows:   []llmRejectRow{rejectedRow002("t2")},
			wantReason: "HTTP 404",
		},
	}
	for _, tt := range tests {
		for _, provider := range []llm.Provider{llm.ProviderAnthropic, llm.ProviderOpenAI} {
			for _, jsonOut := range []bool{false, true} {
				out := "terminal"
				if jsonOut {
					out = "json"
				}
				t.Run(tt.name+"/"+string(provider)+"/"+out, func(t *testing.T) {
					t.Parallel()
					api := newLLMRejectAPI(t, provider)
					tools := map[string][]inspect.Tool{"srv": tt.tools}

					r := llmRejectScan(t, api, tools, jsonOut, tt.args...)

					if r.code != tt.wantCode {
						t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, tt.wantCode, r.stdout, r.stderr)
					}
					if n := api.bad.Load(); n != 0 {
						t.Errorf("the fake provider could not read %d requests", n)
					}

					// The requests: one for each tool, unless a global
					// failure cancelled the rest.
					n := int(api.requests.Load())
					switch {
					case tt.wantReason == "" && n != len(tt.tools):
						t.Errorf("the provider got %d requests, want %d (one for each tool, nothing cancelled)", n, len(tt.tools))
					case tt.wantReason != "" && (n < 1 || n > len(tt.tools)):
						t.Errorf("the provider got %d requests, want 1 to %d", n, len(tt.tools))
					}
					if tt.wantReason == "" {
						var want []string
						for _, tl := range tt.tools {
							want = append(want, tl.Name)
						}
						slices.Sort(want)
						if got := api.sentTools(); !slices.Equal(got, want) {
							t.Errorf("the provider got the tools %q, want %q", got, want)
						}
					}

					// The failure line of the LLM step.
					lines := llmStepFailureLines(r.stderr)
					complete := true
					switch {
					case tt.wantLine != "":
						complete = false
						if !slices.Equal(lines, []string{tt.wantLine}) {
							t.Errorf("LLM failure lines = %q, want %q\nstderr:\n%s", lines, []string{tt.wantLine}, r.stderr)
						}
					case tt.wantReason != "":
						complete = false
						assertGlobalFailureLine(t, lines, tt.wantReason, 1, len(tt.tools))
					default:
						if len(lines) != 0 || strings.Contains(r.stderr, "not classified") {
							t.Errorf("stderr reports a failure of the LLM step, want none:\n%s", r.stderr)
						}
					}
					assertContainsAll(t, "stderr", r.stderr, tt.wantStderr)
					// Fail closed: the guard never counts ignored rows.
					if tt.wantLine != "" && strings.Contains(r.stderr, "MOAT-LLM-002 (") {
						t.Errorf("stderr counts ignored LLM rows for a step that failed closed:\n%s", r.stderr)
					}

					// The report still prints, with its complete field.
					if jsonOut {
						doc := decodeScanJSON(t, r.stdout)
						if doc.Complete != complete {
							t.Errorf("complete = %v, want %v", doc.Complete, complete)
						}
						if len(doc.Servers) != 1 {
							t.Errorf("JSON has %d servers, want 1: the report must still print", len(doc.Servers))
						}
					} else if !strings.Contains(r.stdout, summaryHeading) {
						t.Errorf("stdout has no SUMMARY block: the report must still print\nstdout:\n%s", r.stdout)
					}

					got := llmRejectRows(t, r.stdout, jsonOut)
					want := forOutput(tt.wantRows, jsonOut)
					if tt.wantReason != "" {
						if !rejectRowsSubset(got, want) {
							t.Errorf("LLM findings = %+v, want a part of %+v", got, want)
						}
					} else if !slices.Equal(got, want) {
						t.Errorf("LLM findings = %+v\nwant %+v\nstdout:\n%s\nstderr:\n%s", got, want, r.stdout, r.stderr)
					}

					// The body and the headers of a refusal are never read.
					for name, text := range map[string]string{"stdout": r.stdout, "stderr": r.stderr} {
						if strings.Contains(text, llmRejectBodyCanary) {
							t.Errorf("%s holds the canary of the refusal body:\n%s", name, text)
						}
						if strings.Contains(text, "refused\\x1b") || strings.Contains(text, "invalid_request_error") {
							t.Errorf("%s holds a part of the refusal body:\n%s", name, text)
						}
					}
					assertNoLeakBoth(t, r.stdout, r.stderr)
				})
			}
		}
	}
}

// assertGlobalFailureLine checks that lines is one provider failure line with
// reason, whose count of tools that were not classified is from minN to
// maxN, with the right singular or plural.
func assertGlobalFailureLine(t *testing.T, lines []string, reason string, minN, maxN int) {
	t.Helper()
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(scanPrefix+"the LLM provider failed ("+reason+"); ") + `(\d+) (tool was|tools were) not classified\n$`)
	if len(lines) != 1 {
		t.Errorf("LLM failure lines = %q, want one line with the reason %q", lines, reason)
		return
	}
	m := re.FindStringSubmatch(lines[0])
	if m == nil {
		t.Errorf("LLM failure line = %q, want the reason %q", lines[0], reason)
		return
	}
	n, _ := strconv.Atoi(m[1])
	if n < minN || n > maxN {
		t.Errorf("not classified count = %d, want %d to %d", n, minN, maxN)
	}
	if want := notClassifiedText(n); !strings.HasSuffix(lines[0], "; "+want+"\n") {
		t.Errorf("LLM failure line = %q, want it to end with %q", lines[0], want)
	}
}

// rejectRowsSubset reports whether every row of got is in want, and no row
// is in got twice. Both are sorted.
func rejectRowsSubset(got, want []llmRejectRow) bool {
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

// llmFuncClassifier is a toolClassifier that calls its function. A test uses
// it when it needs the context of the call.
type llmFuncClassifier func(ctx context.Context, in llm.Input) (llm.Verdict, error)

// Classify implements toolClassifier.
func (f llmFuncClassifier) Classify(ctx context.Context, in llm.Input) (llm.Verdict, error) {
	return f(ctx, in)
}

// TestScanLLMRejectedThenGlobalFailure runs a full scan where the provider
// refuses t1 (HTTP 400) and then fails for t2 (HTTP 503). The fake makes the
// order fixed: t2 answers only after t1 answered. The global failure wins:
// exit 2, complete false and the line of the 503 with one tool that was not
// classified. The refused tool that was answered before the failure keeps
// its MOAT-LLM-002 row (this is what classifyTools does: see sortAnswer).
func TestScanLLMRejectedThenGlobalFailure(t *testing.T) {
	t.Parallel()

	for _, jsonOut := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", jsonOut), func(t *testing.T) {
			t.Parallel()
			tools := map[string][]inspect.Tool{"srv": {mkTool("t1", "Read a file."), mkTool("t2", "Add.")}}
			refusedOnce := make(chan struct{})
			var calls atomic.Int32
			cl := llmFuncClassifier(func(ctx context.Context, in llm.Input) (llm.Verdict, error) {
				calls.Add(1)
				switch in.ToolName {
				case "t1":
					defer close(refusedOnce)
					return llm.Verdict{}, &llm.StatusError{Code: http.StatusBadRequest}
				default:
					select {
					case <-refusedOnce:
					case <-ctx.Done():
						return llm.Verdict{}, ctx.Err()
					}
					return llm.Verdict{}, &llm.StatusError{Code: http.StatusServiceUnavailable}
				}
			})
			args := []string{"--llm", "--fail-on", "medium"}
			if jsonOut {
				args = append(args, "--json")
			}

			r := llmScan(t, llmEnv(t, tools), tools, cl, args...)

			if r.code != exitError {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitError, r.stderr)
			}
			if got := calls.Load(); got != 2 {
				t.Errorf("Classify calls = %d, want 2", got)
			}
			want := []string{scanPrefix + "the LLM provider failed (HTTP 503); 1 tool was not classified\n"}
			if got := llmStepFailureLines(r.stderr); !slices.Equal(got, want) {
				t.Errorf("LLM failure lines = %q, want %q\nstderr:\n%s", got, want, r.stderr)
			}
			if jsonOut && decodeScanJSON(t, r.stdout).Complete {
				t.Errorf("complete = true, want false")
			}
			if got, want := llmRejectRows(t, r.stdout, jsonOut), forOutput([]llmRejectRow{rejectedRow002("t1")}, jsonOut); !slices.Equal(got, want) {
				t.Errorf("LLM findings = %+v, want %+v\nstdout:\n%s", got, want, r.stdout)
			}
		})
	}
}

// rejectOutcomes returns the outcomes of one inspected server "srv" with the
// tools.
func rejectOutcomes(tools ...inspect.Tool) []inspect.Outcome {
	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"}
	return []inspect.Outcome{{Server: srv, Status: inspect.StatusOK, Result: inspect.Result{Tools: tools}}}
}

// statusCode returns the code of the *llm.StatusError in the chain of err,
// or 0.
func statusCode(err error) int {
	var status *llm.StatusError
	if errors.As(err, &status) && status != nil {
		return status.Code
	}
	return 0
}

// TestClassifyToolsRejected checks classifyTools directly with a fake
// classifier, so the order of the answers is under control.
func TestClassifyToolsRejected(t *testing.T) {
	t.Parallel()

	status := func(code int) llmReply { return llmReply{err: &llm.StatusError{Code: code}} }
	names := []string{"t1", "t2", "t3", "t4", "t5", "t6"}
	toolsOf := func(names ...string) []inspect.Tool {
		var out []inspect.Tool
		for _, n := range names {
			out = append(out, mkTool(n, "Text."))
		}
		return out
	}

	t.Run("every tool refused fails closed", func(t *testing.T) {
		t.Parallel()
		// The calls end in a random order. The reason is always the error
		// of t1, the lowest job index.
		replies := map[string]llmReply{
			"t1": status(http.StatusRequestEntityTooLarge),
			"t2": status(http.StatusBadRequest),
			"t3": status(http.StatusUnprocessableEntity),
			"t4": {err: llm.ErrRejected},
			"t5": status(http.StatusBadRequest),
			// A cut tool that was refused gets no floor row either.
			"t6": {v: llm.Verdict{Truncated: true}, err: status(http.StatusBadRequest).err},
		}
		for i := range 20 {
			fake := &llmFake{shuffle: true, answer: llmByTool(replies)}
			res, err := classifyTools(t.Context(), rejectOutcomes(toolsOf(names...)...), fake, &scanIgnores{})
			if err != nil {
				t.Fatalf("run %d: classifyTools() error = %v", i, err)
			}
			if got := int(fake.calls.Load()); got != len(names) {
				t.Errorf("run %d: Classify calls = %d, want %d (nothing cancelled)", i, got, len(names))
			}
			if res.failure == nil || res.failure.kind != answerRejected {
				t.Fatalf("run %d: failure = %+v, want kind answerRejected", i, res.failure)
			}
			if code := statusCode(res.failure.err); code != http.StatusRequestEntityTooLarge {
				t.Errorf("run %d: failure error has code %d, want 413 (the code of t1)", i, code)
			}
			if res.rows != nil || res.counts != nil || res.ignored != nil || res.fileBlocked != nil {
				t.Errorf("run %d: result has rows, counts or ignores, want none: %+v", i, res)
			}
			if res.skipped != len(names) || res.tools != len(names) || res.overCap != 0 {
				t.Errorf("run %d: skipped, tools, overCap = %d, %d, %d; want %d, %d, 0", i, res.skipped, res.tools, res.overCap, len(names), len(names))
			}
			if !res.incomplete() {
				t.Errorf("run %d: incomplete() = false, want true", i)
			}
		}
	})

	t.Run("every tool refused, an ignore list does not change it", func(t *testing.T) {
		t.Parallel()
		// The same lists as "--ignore MOAT-LLM-002 --ignore MOAT-LLM-001".
		ignore := &scanIgnores{}
		for _, id := range []string{llm.RuleIDInvalid, llm.RuleID} {
			entry := rules.IgnoreEntry{RuleID: id}
			ignore.all.Add(entry)
			ignore.flags.Add(entry)
		}
		fake := &llmFake{answer: llmByTool(map[string]llmReply{"t1": status(http.StatusBadRequest), "t2": status(http.StatusBadRequest)})}
		res, err := classifyTools(t.Context(), rejectOutcomes(toolsOf("t1", "t2")...), fake, ignore)
		if err != nil {
			t.Fatalf("classifyTools() error = %v", err)
		}
		if res.failure == nil || res.failure.kind != answerRejected || res.skipped != 2 || res.rows != nil || res.ignored != nil {
			t.Errorf("result = %+v, want the refusal failure, 2 skipped, no rows and no ignored count", res)
		}
	})

	t.Run("one 2xx answer keeps the step complete", func(t *testing.T) {
		t.Parallel()
		for _, ok := range []llmReply{
			{v: llm.Verdict{Risk: llm.RiskNone, Category: llm.CategoryOther}},
			{err: fmt.Errorf("%w: test", llm.ErrInvalidOutput)},
		} {
			replies := map[string]llmReply{"t1": status(http.StatusBadRequest), "t2": ok, "t3": status(http.StatusUnprocessableEntity)}
			res, err := classifyTools(t.Context(), rejectOutcomes(toolsOf("t1", "t2", "t3")...), &llmFake{answer: llmByTool(replies)}, &scanIgnores{})
			if err != nil {
				t.Fatalf("classifyTools() error = %v", err)
			}
			if res.failure != nil || res.skipped != 0 || res.incomplete() {
				t.Errorf("reply %+v: failure, skipped = %+v, %d; want nil, 0", ok, res.failure, res.skipped)
			}
			var rules []string
			for _, row := range res.rows {
				rules = append(rules, row.Key+" "+row.RuleID+" "+row.Risk)
			}
			want := []string{"t1 " + llm.RuleIDInvalid + " " + llm.RejectedText}
			if ok.err != nil {
				want = append(want, "t2 "+llm.RuleIDInvalid+" "+llm.InvalidText)
			}
			want = append(want, "t3 "+llm.RuleIDInvalid+" "+llm.RejectedText)
			if !slices.Equal(rules, want) {
				t.Errorf("reply %+v: rows = %q, want %q", ok, rules, want)
			}
			if res.counts[0] != len(want) {
				t.Errorf("reply %+v: counts = %v, want %d rows for server 0", ok, res.counts, len(want))
			}
		}
	})

	t.Run("a global failure wins over the check", func(t *testing.T) {
		t.Parallel()
		// t2 answers only after t1 answered, so t1 always has its refusal.
		refused := make(chan struct{})
		cl := llmFuncClassifier(func(_ context.Context, in llm.Input) (llm.Verdict, error) {
			if in.ToolName == "t1" {
				defer close(refused)
				return llm.Verdict{}, &llm.StatusError{Code: http.StatusBadRequest}
			}
			<-refused
			return llm.Verdict{}, &llm.StatusError{Code: http.StatusServiceUnavailable}
		})
		res, err := classifyTools(t.Context(), rejectOutcomes(toolsOf("t1", "t2")...), cl, &scanIgnores{})
		if err != nil {
			t.Fatalf("classifyTools() error = %v", err)
		}
		if res.failure == nil || res.failure.kind != answerProviderFailed || statusCode(res.failure.err) != http.StatusServiceUnavailable {
			t.Fatalf("failure = %+v, want the provider failure of the 503", res.failure)
		}
		if res.skipped != 1 {
			t.Errorf("skipped = %d, want 1 (only t2)", res.skipped)
		}
		if len(res.rows) != 1 || res.rows[0].Key != "t1" || res.rows[0].RuleID != llm.RuleIDInvalid || res.rows[0].Risk != llm.RejectedText {
			t.Errorf("rows = %+v, want the refusal row of t1", res.rows)
		}
	})

	t.Run("a refusal that ends after the global failure keeps its row", func(t *testing.T) {
		t.Parallel()
		// t1 answers only after the 503 of t2 cancelled the step. Its
		// answer is still a refusal of the provider, so it keeps its row.
		cl := llmFuncClassifier(func(ctx context.Context, in llm.Input) (llm.Verdict, error) {
			if in.ToolName == "t2" {
				return llm.Verdict{}, &llm.StatusError{Code: http.StatusServiceUnavailable}
			}
			<-ctx.Done()
			return llm.Verdict{}, &llm.StatusError{Code: http.StatusBadRequest}
		})
		res, err := classifyTools(t.Context(), rejectOutcomes(toolsOf("t1", "t2")...), cl, &scanIgnores{})
		if err != nil {
			t.Fatalf("classifyTools() error = %v", err)
		}
		if res.failure == nil || res.failure.kind != answerProviderFailed {
			t.Fatalf("failure = %+v, want the provider failure", res.failure)
		}
		if res.skipped != 1 || len(res.rows) != 1 || res.rows[0].Key != "t1" || res.rows[0].Risk != llm.RejectedText {
			t.Errorf("skipped, rows = %d, %+v; want 1 and the refusal row of t1", res.skipped, res.rows)
		}
	})

	t.Run("an internal failure wins over the check", func(t *testing.T) {
		t.Parallel()
		refused := make(chan struct{})
		cl := llmFuncClassifier(func(_ context.Context, in llm.Input) (llm.Verdict, error) {
			if in.ToolName == "t1" {
				defer close(refused)
				return llm.Verdict{}, llm.ErrRejected
			}
			<-refused
			return llm.Verdict{}, errors.New("local-error-canary-Np2")
		})
		res, err := classifyTools(t.Context(), rejectOutcomes(toolsOf("t1", "t2")...), cl, &scanIgnores{})
		if err != nil {
			t.Fatalf("classifyTools() error = %v", err)
		}
		if res.failure == nil || res.failure.kind != answerInternalFailed || res.failure.err != nil {
			t.Fatalf("failure = %+v, want an internal failure without an error", res.failure)
		}
		if llmFailureLine(res.failure) != llmInternalText {
			t.Errorf("llmFailureLine() = %q, want %q", llmFailureLine(res.failure), llmInternalText)
		}
	})

	t.Run("a signal wins over the check", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var answered atomic.Int32
		cl := llmFuncClassifier(func(_ context.Context, _ llm.Input) (llm.Verdict, error) {
			// The last refusal comes with the signal.
			if answered.Add(1) == 3 {
				cancel()
			}
			return llm.Verdict{}, &llm.StatusError{Code: http.StatusBadRequest}
		})
		res, err := classifyTools(ctx, rejectOutcomes(toolsOf("t1", "t2", "t3")...), cl, &scanIgnores{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("classifyTools() error = %v, want context.Canceled", err)
		}
		if res.failure != nil || res.rows != nil || res.skipped != 0 {
			t.Errorf("result = %+v, want the zero result", res)
		}
	})
}

// TestRejectedFailure checks the fail-closed check after all the answers: it
// gives a failure only when at least one answer is a refusal and no answer is
// a 2xx answer (a verdict or an answer that cannot be used). Jobs without an
// answer do not count. The failure holds the error of the refusal with the
// lowest index. rejectedFailure does not look for a global failure: the
// caller calls it only when there is none (see TestClassifyToolsRejected).
func TestRejectedFailure(t *testing.T) {
	t.Parallel()

	e400 := &llm.StatusError{Code: http.StatusBadRequest}
	e413 := &llm.StatusError{Code: http.StatusRequestEntityTooLarge}
	e422 := &llm.StatusError{Code: http.StatusUnprocessableEntity}
	rej := func(err error) llmAnswer { return llmAnswer{kind: answerRejected, err: err} }
	of := func(k answerKind) llmAnswer { return llmAnswer{kind: k} }

	tests := []struct {
		name    string
		answers []llmAnswer
		want    bool  // a failure
		wantErr error // the error of the failure
	}{
		{name: "nil", answers: nil},
		{name: "empty", answers: []llmAnswer{}},
		{name: "one refused", answers: []llmAnswer{rej(e400)}, want: true, wantErr: e400},
		{name: "all refused", answers: []llmAnswer{rej(e400), rej(e413), rej(e422)}, want: true, wantErr: e400},
		{name: "lowest index wins", answers: []llmAnswer{rej(e422), rej(e400), rej(e413)}, want: true, wantErr: e422},
		{name: "bare ErrRejected", answers: []llmAnswer{rej(llm.ErrRejected), rej(e400)}, want: true, wantErr: llm.ErrRejected},
		{name: "verdict first", answers: []llmAnswer{of(answerVerdict), rej(e400)}},
		{name: "verdict last", answers: []llmAnswer{rej(e400), rej(e413), of(answerVerdict)}},
		{name: "unusable first", answers: []llmAnswer{of(answerUnusable), rej(e400)}},
		{name: "unusable last", answers: []llmAnswer{rej(e400), of(answerUnusable)}},
		{name: "not run and stopped do not count", answers: []llmAnswer{of(answerNotRun), of(answerStopped), rej(e413), rej(e400)}, want: true, wantErr: e413},
		{name: "refused after not run and stopped", answers: []llmAnswer{rej(e422), of(answerNotRun), of(answerStopped)}, want: true, wantErr: e422},
		{name: "only not run and stopped", answers: []llmAnswer{of(answerNotRun), of(answerStopped)}},
		{name: "only verdicts", answers: []llmAnswer{of(answerVerdict), of(answerVerdict)}},
		// Failed requests are not answers, so they do not count. The caller
		// handles a global failure first.
		{name: "failed requests do not count", answers: []llmAnswer{of(answerProviderFailed), of(answerInternalFailed), rej(e400)}, want: true, wantErr: e400},
		{name: "only failed requests", answers: []llmAnswer{of(answerProviderFailed), of(answerInternalFailed)}},
		// A refusal without an error still fails closed. llmFailureLine then
		// prints llmInternalText (see TestLLMFailureLine).
		{name: "refused without error", answers: []llmAnswer{rej(nil)}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := rejectedFailure(tt.answers)
			if (got != nil) != tt.want {
				t.Fatalf("rejectedFailure() = %+v, want a failure: %v", got, tt.want)
			}
			if got == nil {
				return
			}
			if got.kind != answerRejected {
				t.Errorf("rejectedFailure().kind = %v, want %v", got.kind, answerRejected)
			}
			if got.err != tt.wantErr { //nolint:errorlint // the test checks the identity of the error
				t.Errorf("rejectedFailure().err = %v, want %v", got.err, tt.wantErr)
			}
		})
	}
}

// TestRejectedReason checks the reason of the fail-closed line: "HTTP <code>,
// the provider refused every tool" for an *llm.StatusError anywhere in the
// chain, else the fixed hint alone. The text never holds the text of the
// error (it can come from anywhere in a test), so it holds no server data,
// and it is safe for the terminal: termsafe.Quote keeps it as it is.
func TestRejectedReason(t *testing.T) {
	t.Parallel()

	const canary = "reason-canary-Wd7Lx"
	hint := "the provider refused every tool"
	if rejectedHintText != hint {
		t.Errorf("rejectedHintText = %q, want %q", rejectedHintText, hint)
	}

	tests := []struct {
		name string
		err  error
		want string
	}{
		{"status 400", &llm.StatusError{Code: http.StatusBadRequest}, "HTTP 400, " + hint},
		{"status 413", &llm.StatusError{Code: http.StatusRequestEntityTooLarge}, "HTTP 413, " + hint},
		{"status 422", &llm.StatusError{Code: http.StatusUnprocessableEntity}, "HTTP 422, " + hint},
		{"wrapped status", fmt.Errorf("test: %w", &llm.StatusError{Code: http.StatusBadRequest}), "HTTP 400, " + hint},
		{"twice wrapped status", fmt.Errorf("a: %w", fmt.Errorf("b: %w", &llm.StatusError{Code: http.StatusUnprocessableEntity})), "HTTP 422, " + hint},
		{"joined status", errors.Join(errors.New(canary), &llm.StatusError{Code: http.StatusRequestEntityTooLarge}), "HTTP 413, " + hint},
		{"status in an error with a canary and escapes", fmt.Errorf("\x1b[31m%s\u202e: %w", canary, &llm.StatusError{Code: http.StatusBadRequest}), "HTTP 400, " + hint},
		{"bare ErrRejected", llm.ErrRejected, hint},
		{"wrapped ErrRejected", fmt.Errorf("test: %w", llm.ErrRejected), hint},
		{"ErrRejected with a canary", fmt.Errorf("%w: %s\x1b[0m", llm.ErrRejected, canary), hint},
		{"typed nil status", fmt.Errorf("test: %w", (*llm.StatusError)(nil)), hint},
		{"nil", nil, hint},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := rejectedReason(tt.err)
			if got != tt.want {
				t.Errorf("rejectedReason() = %q, want %q", got, tt.want)
			}
			if termsafe.Quote(got) != got {
				t.Errorf("rejectedReason() = %q is not safe for the terminal", got)
			}
			if strings.Contains(got, canary) || strings.ContainsAny(got, "\x1b\u202e\"()") {
				t.Errorf("rejectedReason() = %q holds the text of the error, a quote or a parenthesis", got)
			}
			// The whole line, as llmFailureLine gives it.
			line := llmFailureLine(&llmFailure{kind: answerRejected, err: tt.err})
			if tt.err == nil {
				if line != llmInternalText {
					t.Errorf("llmFailureLine() = %q, want %q", line, llmInternalText)
				}
				return
			}
			if want := "the LLM provider failed (" + tt.want + ")"; line != want {
				t.Errorf("llmFailureLine() = %q, want %q", line, want)
			}
		})
	}
}

// Compile-time check: the fake of this file is a toolClassifier.
var _ toolClassifier = llmFuncClassifier(nil)
