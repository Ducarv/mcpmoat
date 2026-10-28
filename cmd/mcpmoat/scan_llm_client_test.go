package main

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
)

// This file tests "mcpmoat scan --llm" (FR-17) in process with the real LLM
// client (llm.New). The client sends its requests to fakeProvider
// (llm_fake_provider_test.go) in its Anthropic flavour. scan_llm_test.go holds
// the tests with a fake classifier, and network_test.go uses fakeProvider for
// the no-network proof (NFR-01).

// llmSyncLog is the stdout and the stderr of a cli that a request handler
// reads while the scan runs. It keeps the writes of both streams in order.
// It is safe for concurrent use.
type llmSyncLog struct {
	mu     sync.Mutex
	out    strings.Builder
	err    strings.Builder
	events []llmEvent
}

// llmEvent is one write to the log.
type llmEvent struct {
	stdout bool
	text   string
}

// llmLogWriter writes to one stream of an llmSyncLog.
type llmLogWriter struct {
	log    *llmSyncLog
	stdout bool
}

// Write implements io.Writer.
func (w llmLogWriter) Write(p []byte) (int, error) {
	w.log.mu.Lock()
	defer w.log.mu.Unlock()
	if w.stdout {
		w.log.out.Write(p)
	} else {
		w.log.err.Write(p)
	}
	w.log.events = append(w.log.events, llmEvent{stdout: w.stdout, text: string(p)})
	return len(p), nil
}

// stderr returns the text written to stderr so far.
func (l *llmSyncLog) stderr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err.String()
}

// snapshot returns the two texts and the events so far.
func (l *llmSyncLog) snapshot() (stdout, stderr string, events []llmEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.out.String(), l.err.String(), slices.Clone(l.events)
}

// TestScanLLMRealClient runs scan --llm with the real client against a fake
// API on a loopback server. It checks that the warning is printed before the
// configs are read, before the client is built and before the first request
// (the handler checks the stderr text when the request arrives), that it is
// printed once and before the report, also with --json, and what the
// requests hold: the key only in the x-api-key header, and in the body only
// the name and the description of each tool (no config or schema canary).
func TestScanLLMRealClient(t *testing.T) {
	t.Parallel()

	const toolCanary = "mcpmoat-tool-canary-Jk8Rf3"
	tool := func(name, desc string) inspect.Tool {
		tl := mkTool(name, desc)
		tl.InputSchema = json.RawMessage(`{"type":"object","description":"` + toolCanary + `"}`)
		tl.Meta = json.RawMessage(`{"k":"` + toolCanary + `"}`)
		return tl
	}
	tools := map[string][]inspect.Tool{"alpha": {tool("t1", "Read keys. "+llmMarkHigh), tool("t2", "Add two numbers.")}}
	servers := map[string]any{"alpha": map[string]any{
		"command": "npx",
		"args":    []string{"@acme/fixture-clean@2.0.0", "--token", discovertest.CanaryArgs},
		"env":     map[string]string{"FIXTURE_MODE": discovertest.CanaryEnv},
	}}
	canaries := append(discovertest.Canaries(), toolCanary)

	tests := []struct {
		name     string
		json     bool
		status   int
		wantCode int
	}{
		{name: "terminal", wantCode: exitFindings},
		{name: "json", json: true, wantCode: exitFindings},
		{name: "HTTP 503", status: http.StatusServiceUnavailable, wantCode: exitError},
		{name: "HTTP 503 json", json: true, status: http.StatusServiceUnavailable, wantCode: exitError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			api := newFakeProvider(t, llm.ProviderAnthropic)
			api.status = tt.status
			warning := llmWarning("anthropic", api.host)
			log := &llmSyncLog{}
			// sawWarning checks that stderr already holds the warning when
			// the hook runs. It counts the hooks that ran without it.
			var early atomic.Int32
			sawWarning := func() {
				if !strings.Contains(log.stderr(), warning+"\n") {
					early.Add(1)
				}
			}
			api.onRequest = sawWarning

			home := t.TempDir()
			writeServers(t, home, ".claude.json", servers)
			xdg := t.TempDir()
			c, _, _ := dirsCLI(t, home, t.TempDir())
			c.stdout = llmLogWriter{log: log, stdout: true}
			c.stderr = llmLogWriter{log: log}
			c.homeDir = func() (string, error) { sawWarning(); return home, nil }
			c.getenv = fakeGetenv(map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": home, llm.KeyEnv: llmTestKey})
			c.inspector = fakeServers(tools)
			var builds atomic.Int32
			c.newClassifier = func(cfg llm.Config) (toolClassifier, error) {
				builds.Add(1)
				sawWarning()
				if cfg.APIKey.Reveal() != llmTestKey || cfg.Provider != llm.ProviderAnthropic || cfg.BaseURL != api.srv.URL || cfg.Model != llm.DefaultAnthropicModel {
					t.Errorf("newClassifier config = %+v, want the key from %s, anthropic, the base URL and the default model", cfg, llm.KeyEnv)
				}
				return newLLMClassifier(cfg)
			}
			args := []string{"scan", "--llm", "--llm-base-url", api.srv.URL}
			if tt.json {
				args = append(args, "--json")
			}

			code := c.dispatch(args)

			stdout, stderr, events := log.snapshot()
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, stdout, stderr)
			}
			if n := early.Load(); n != 0 {
				t.Errorf("%d steps (config read, client build or request) ran before the warning", n)
			}
			if builds.Load() != 1 {
				t.Errorf("newClassifier calls = %d, want 1", builds.Load())
			}
			// One request for each tool. With HTTP 503 the client tries each
			// tool 3 times in total (the fake sends "Retry-After: 0"). The
			// tool whose last try fails first stops the step, so it got
			// exactly 3 requests, and the other tool got 0 to 3: its
			// requests that the stop cancelled can end before they reach
			// the fake.
			reqs := api.snapshot()
			perTool := api.perTool()
			if tt.status == 0 {
				if want := map[string]int{"t1": 1, "t2": 1}; !maps.Equal(perTool, want) {
					t.Errorf("requests for each tool = %v, want %v", perTool, want)
				}
			} else {
				full := 0
				for name, n := range perTool {
					if n > llm.RetryMaxTries {
						t.Errorf("tool %s got %d requests, want at most %d", name, n, llm.RetryMaxTries)
					}
					if n == llm.RetryMaxTries {
						full++
					}
				}
				if full == 0 {
					t.Errorf("requests for each tool = %v, want one tool with %d (the retries of the failed tool)", perTool, llm.RetryMaxTries)
				}
			}
			// The warning is the first line on stderr, it shows once, and no
			// stdout write comes before it.
			lines := nonEmptyLines(stderr)
			if len(lines) == 0 || lines[0] != warning {
				t.Errorf("first stderr line = %q, want the warning %q", lines, warning)
			}
			if n := strings.Count(stderr, "leaves your machine"); n != 1 {
				t.Errorf("stderr holds the warning %d times, want 1", n)
			}
			if len(events) == 0 || events[0].stdout || !strings.Contains(events[0].text, warning) {
				t.Errorf("first write = %+v, want the warning on stderr before any stdout", events[:min(len(events), 1)])
			}
			if tt.json {
				doc := decodeScanJSON(t, stdout)
				if doc.Complete != (tt.status == 0) {
					t.Errorf("complete = %v, want %v", doc.Complete, tt.status == 0)
				}
			} else if !strings.Contains(stdout, summaryHeading) {
				t.Errorf("stdout has no SUMMARY block\nstdout:\n%s", stdout)
			}
			if tt.status != 0 {
				m := llmNotClassified.FindStringSubmatch(stderr)
				if m == nil || m[1] != "HTTP 503" || m[2] != "2" {
					t.Errorf("stderr has no line \"the LLM provider failed (HTTP 503); 2 tools were not classified\":\n%s", stderr)
				}
			} else {
				rows := llmJSONOrTerminalRows(t, stdout, tt.json)
				if want := []llmHit{{llm.RuleID, "high", "alpha", "t1"}}; !slices.Equal(rows, want) {
					t.Errorf("LLM findings = %+v, want %+v", rows, want)
				}
			}
			llmAssertNoKey(t, llmTestKey, stdout, stderr)
			assertNoLeakBoth(t, stdout, stderr)

			var got []llm.Input
			for i, req := range reqs {
				if req.path != "/v1/messages" {
					t.Errorf("request path = %q, want /v1/messages", req.path)
				}
				if req.header.Get("x-api-key") != llmTestKey {
					t.Errorf("request %d has no x-api-key header with the key", i)
				}
				for name, values := range req.header {
					if name == "X-Api-Key" {
						continue
					}
					llmAssertNoKey(t, llmTestKey, strings.Join(values, ","))
				}
				llmAssertNoKey(t, llmTestKey, string(req.body))
				for _, c := range canaries {
					if bytes.Contains(req.body, []byte(c)) {
						t.Errorf("request %d body holds the canary %q", i, c)
					}
				}
				if req.err != nil {
					t.Errorf("request %d: %v\nbody: %s", i, req.err, req.body)
					continue
				}
				got = append(got, req.payload.input())
			}
			slices.SortFunc(got, func(a, b llm.Input) int { return strings.Compare(a.ToolName, b.ToolName) })
			want := []llm.Input{{ToolName: "t1", Description: "Read keys. " + llmMarkHigh}, {ToolName: "t2", Description: "Add two numbers."}}
			if tt.status == 0 && !slices.EqualFunc(got, want, llmSameInput) {
				t.Errorf("tool messages = %+v, want %+v", got, want)
			}
			for _, in := range got {
				if !slices.ContainsFunc(want, func(w llm.Input) bool { return llmSameInput(w, in) }) {
					t.Errorf("tool message %+v is not one of %+v", in, want)
				}
			}
		})
	}
}

// TestScanLLMRealClientTruncated runs scan --llm with the real client on a
// tool whose description is over llm.MaxDescriptionBytes. The fake API rates
// it none, but the client sends a cut text, so the tool gets one MOAT-LLM-001
// row with severity medium and the fixed text llm.TruncatedText. A short tool
// that the API rates none gets no row.
func TestScanLLMRealClientTruncated(t *testing.T) {
	t.Parallel()

	api := newFakeProvider(t, llm.ProviderAnthropic)
	cl, err := newLLMClassifier(llm.Config{Provider: llm.ProviderAnthropic, BaseURL: api.srv.URL, APIKey: discover.NewSecret(llmTestKey)})
	if err != nil {
		t.Fatalf("newLLMClassifier() error = %v", err)
	}
	t.Cleanup(func() { closeClassifier(cl) })
	tools := map[string][]inspect.Tool{"alpha": {
		mkTool("t1", "Reads a file. "+strings.Repeat("a", 20<<10)),
		mkTool("t2", "Add two numbers."),
	}}

	r := llmScan(t, llmEnv(t, tools), tools, cl, "--llm")

	llmRows, _ := llmSplitFindings(parseFindings(t, r.stdout))
	if got, want := llmRowsOf(t, llmRows), []llmHit{{llm.RuleID, "medium", "alpha", "t1"}}; !slices.Equal(got, want) {
		t.Fatalf("LLM findings = %+v, want %+v\nstdout:\n%s\nstderr:\n%s", got, want, r.stdout, r.stderr)
	}
	if f := llmRows[0]; f.Risk != llm.TruncatedText || f.Tool != "t1 (other)" {
		t.Errorf("t1 Risk, Tool = %q, %q; want %q, %q", f.Risk, f.Tool, llm.TruncatedText, "t1 (other)")
	}
	truncated := map[string]bool{}
	for _, req := range api.snapshot() {
		if req.err != nil {
			t.Fatalf("request: %v", req.err)
		}
		truncated[req.payload.ToolName] = req.payload.Truncated
	}
	if want := map[string]bool{"t1": true, "t2": false}; !maps.Equal(truncated, want) {
		t.Errorf("truncated of each request = %v, want %v", truncated, want)
	}
}

// llmRetryCodes are the HTTP status codes that the client of package llm
// tries again: 429, 502, 503, 504 and 529 (the overload code of the Anthropic
// API, which net/http has no name for). It is the one list of these codes in
// the tests of this package. For such a code the client sends at most
// llm.RetryMaxTries requests for one tool (the first request and 2 retries);
// the tests use that constant, and TestRetryPolicyDefaults in internal/llm
// pins its value.
var llmRetryCodes = []int{
	http.StatusTooManyRequests,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
	529,
}

// llmJSONOrTerminalRows returns the LLM findings of stdout, from the JSON
// document or from the terminal report.
func llmJSONOrTerminalRows(t *testing.T, stdout string, jsonOut bool) []llmHit {
	t.Helper()
	if jsonOut {
		return llmJSONRows(t, decodeScanJSON(t, stdout))
	}
	return llmRowsOf(t, parseFindings(t, stdout))
}
