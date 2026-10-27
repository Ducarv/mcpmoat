package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
)

// This file tests that "mcpmoat scan --llm" removes the secret values of a
// server from its tool text before the text goes to the LLM provider (FR-17,
// issue #185). A server gets its env and header values, so a malicious server
// can echo a token in a tool name or description. The tests give the fake
// inspector a Result with Secrets, run the real LLM client (llm.New) against
// a fake provider on a loopback httptest server, and read the raw request
// bodies that the provider got.

// llmEchoCanary is the secret value of the tests, which a server echoes in
// its tool text. It is long enough for llm (8 bytes or more) and holds no
// word, so no part of it shows by chance.
const llmEchoCanary = "mcpmoat-llm-secret-Vb6Lr9QzT3"

// llmSecretPayload is the user message of a request, with every key that the
// client may send, "redacted" too. It is comparable, so a test can compare
// maps of it.
type llmSecretPayload struct {
	ToolName        string `json:"tool_name"`
	ToolDescription string `json:"tool_description"`
	Truncated       bool   `json:"truncated"`
	Redacted        bool   `json:"redacted"`
}

// llmSecretRequest is one request that llmSecretAPI got.
type llmSecretRequest struct {
	path string
	// body is the raw request body.
	body []byte
	// content is the user message of the body, decoded from its JSON
	// string. It is "" when the body has no single user message.
	content string
}

// llmSecretAPI is a fake LLM provider on a loopback httptest server. It
// speaks the Anthropic Messages API or the OpenAI Chat Completions API, as
// the provider says. It answers each request with the verdict of llmAnswerFor
// for the tool in the request, and records each request.
type llmSecretAPI struct {
	srv      *httptest.Server
	provider llm.Provider

	mu       sync.Mutex
	requests []llmSecretRequest
}

// newLLMSecretAPI starts a fake provider of the given flavour.
func newLLMSecretAPI(t *testing.T, provider llm.Provider) *llmSecretAPI {
	t.Helper()
	a := &llmSecretAPI{provider: provider}
	a.srv = httptest.NewServer(http.HandlerFunc(a.handle))
	t.Cleanup(a.srv.Close)
	return a
}

// handle answers one request.
func (a *llmSecretAPI) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	req := llmSecretRequest{path: r.URL.Path, body: body}
	var p llmSecretPayload
	if err == nil {
		req.content, err = llmSecretUserMessage(body)
	}
	if err == nil {
		p, err = llmSecretDecodePayload(req.content)
	}
	a.mu.Lock()
	a.requests = append(a.requests, req)
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	v, verr := llmAnswerFor(llm.Input{ToolName: p.ToolName, Description: p.ToolDescription})
	if verr != nil {
		http.Error(w, "test: no verdict", http.StatusBadRequest)
		return
	}
	if a.provider == llm.ProviderOpenAI {
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
		return
	}
	writeLLMVerdict(w, v)
}

// snapshot returns a copy of the recorded requests.
func (a *llmSecretAPI) snapshot() []llmSecretRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.requests)
}

// llmSecretUserMessage returns the content of the one user message of a
// request body. Both APIs put the messages in "messages"; the OpenAI request
// also has a system message there.
func llmSecretUserMessage(body []byte) (string, error) {
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", err
	}
	var user []string
	for _, m := range req.Messages {
		if m.Role == "user" {
			user = append(user, m.Content)
		}
	}
	if len(user) != 1 {
		return "", errors.New("want one user message")
	}
	return user[0], nil
}

// llmSecretDecodePayload decodes a user message. It must have only the keys
// of llmSecretPayload.
func llmSecretDecodePayload(content string) (llmSecretPayload, error) {
	dec := json.NewDecoder(strings.NewReader(content))
	dec.DisallowUnknownFields()
	var p llmSecretPayload
	if err := dec.Decode(&p); err != nil {
		return llmSecretPayload{}, err
	}
	return p, nil
}

// llmSecretServer is one server of a test: its tools, and the secret values
// that Inspect gave it (inspect.Result.Secrets).
type llmSecretServer struct {
	name    string
	secrets []string
	tools   []inspect.Tool
}

// TestScanLLMRedactsSecrets checks that scan --llm replaces each secret value
// of a server with discover.Mask in the tool name and the tool description
// before the request, and marks the message with "redacted": true. The
// secret value must be in no request body, and in neither stdout nor stderr,
// for the terminal report and for --json, with both provider flavours.
//
// The negative control ("no secrets") sends the same text without Secrets:
// the canary then reaches the provider, so the check on the bodies is not
// vacuous.
func TestScanLLMRedactsSecrets(t *testing.T) {
	t.Parallel()

	const (
		canary = llmEchoCanary
		mask   = discover.Mask
		// short7 has 7 bytes: below the 8-byte floor of llm, so it is
		// sent as it is (documented limit). short8 has 8 bytes: the
		// shortest value that llm removes.
		short7 = "Pq4Wz7K"
		short8 = "Pq4Wz7Kd"
	)
	// A tool that the provider rates high, so every scan has a normal LLM
	// row and exits with exitFindings.
	highTool := mkTool("keys", "Read keys. "+llmMarkHigh)
	highSent := llmSecretPayload{ToolName: "keys", ToolDescription: "Read keys. " + llmMarkHigh}
	highRow := func(server string) llmHit { return llmHit{llm.RuleID, "high", server, "keys"} }

	// long is a 100 KiB description with the canary across the cut of
	// llm.MaxDescriptionBytes: 10 bytes of the canary are before the cut.
	// A cut before the redaction would send those 10 bytes.
	before := llm.MaxDescriptionBytes - 10
	long := strings.Repeat("a", before) + canary + strings.Repeat("b", 100<<10-before-len(canary))
	longSent := (strings.Repeat("a", before) + mask + strings.Repeat("b", 100<<10))[:llm.MaxDescriptionBytes]

	descText := "Fetch a page. The token is " + canary + "; send " + canary + " again."
	descMasked := "Fetch a page. The token is " + mask + "; send " + mask + " again."

	tests := []struct {
		name    string
		canary  string // the secret value that must not leak
		servers []llmSecretServer
		// want is the payload of each request, keyed by the tool name that
		// the provider gets.
		want map[string]llmSecretPayload
		rows []llmHit
	}{
		{
			name:   "description",
			canary: canary,
			servers: []llmSecretServer{{name: "alpha", secrets: []string{canary},
				tools: []inspect.Tool{mkTool("fetch", descText), highTool}}},
			want: map[string]llmSecretPayload{
				"fetch": {ToolName: "fetch", ToolDescription: descMasked, Redacted: true},
				"keys":  highSent,
			},
			rows: []llmHit{highRow("alpha")},
		},
		{
			// The tool with the canary in its name is rated none on
			// purpose. The local report does not scrub server text
			// (see inspect.Result.Secrets), so a row for this tool
			// would print its raw name, canary included, in the Tool
			// line and in the JSON "key". This test is about the
			// request only.
			name:   "tool name",
			canary: canary,
			servers: []llmSecretServer{{name: "alpha", secrets: []string{canary},
				tools: []inspect.Tool{mkTool("fetch_"+canary, "Fetch a page."), highTool}}},
			want: map[string]llmSecretPayload{
				"fetch_" + mask: {ToolName: "fetch_" + mask, ToolDescription: "Fetch a page.", Redacted: true},
				"keys":          highSent,
			},
			rows: []llmHit{highRow("alpha")},
		},
		{
			name:   "tool name and description",
			canary: canary,
			servers: []llmSecretServer{{name: "alpha", secrets: []string{canary},
				tools: []inspect.Tool{mkTool(canary+"_fetch", descText), highTool}}},
			want: map[string]llmSecretPayload{
				mask + "_fetch": {ToolName: mask + "_fetch", ToolDescription: descMasked, Redacted: true},
				"keys":          highSent,
			},
			rows: []llmHit{highRow("alpha")},
		},
		{
			// A secret belongs to its own server: the secret of alpha is
			// not removed from the text of beta, which got no secret.
			// beta's text goes out unchanged, canary included.
			name:   "two servers, secret on the first only",
			canary: canary,
			servers: []llmSecretServer{
				{name: "alpha", secrets: []string{canary},
					tools: []inspect.Tool{mkTool("a1", "Token "+canary+" here."), highTool}},
				{name: "beta",
					tools: []inspect.Tool{mkTool("b1", "Token "+canary+" here.")}},
			},
			want: map[string]llmSecretPayload{
				"a1":   {ToolName: "a1", ToolDescription: "Token " + mask + " here.", Redacted: true},
				"b1":   {ToolName: "b1", ToolDescription: "Token " + canary + " here."},
				"keys": highSent,
			},
			rows: []llmHit{highRow("alpha")},
		},
		{
			// Documented limit: llm removes only values of 8 bytes or
			// more. inspect never gives a shorter value, but llm checks
			// it again.
			name:   "secret of 7 bytes is sent",
			canary: short7,
			servers: []llmSecretServer{{name: "alpha", secrets: []string{short7},
				tools: []inspect.Tool{mkTool("fetch", "Code "+short7+" here."), highTool}}},
			want: map[string]llmSecretPayload{
				"fetch": {ToolName: "fetch", ToolDescription: "Code " + short7 + " here."},
				"keys":  highSent,
			},
			rows: []llmHit{highRow("alpha")},
		},
		{
			name:   "secret of 8 bytes is removed",
			canary: short8,
			servers: []llmSecretServer{{name: "alpha", secrets: []string{short8},
				tools: []inspect.Tool{mkTool("fetch", "Code "+short8+" here."), highTool}}},
			want: map[string]llmSecretPayload{
				"fetch": {ToolName: "fetch", ToolDescription: "Code " + mask + " here.", Redacted: true},
				"keys":  highSent,
			},
			rows: []llmHit{highRow("alpha")},
		},
		{
			// The redaction comes before the cut, so the cut cannot
			// leave a part of the canary. The cut text gets the
			// truncated floor (medium).
			name:   "100 KiB description with the secret across the cut",
			canary: canary,
			servers: []llmSecretServer{{name: "alpha", secrets: []string{canary},
				tools: []inspect.Tool{mkTool("big", long), highTool}}},
			want: map[string]llmSecretPayload{
				"big":  {ToolName: "big", ToolDescription: longSent, Truncated: true, Redacted: true},
				"keys": highSent,
			},
			// The rule rows MOAT-T1-017 and MOAT-T1-007 of the long text
			// are not LLM rows.
			rows: []llmHit{{llm.RuleID, "medium", "alpha", "big"}, highRow("alpha")},
		},
		{
			// Negative control: the same text with no Secrets. The
			// canary reaches the provider.
			name:   "no secrets",
			canary: canary,
			servers: []llmSecretServer{{name: "alpha",
				tools: []inspect.Tool{mkTool("fetch", descText), highTool}}},
			want: map[string]llmSecretPayload{
				"fetch": {ToolName: "fetch", ToolDescription: descText},
				"keys":  highSent,
			},
			rows: []llmHit{highRow("alpha")},
		},
	}
	providers := []llm.Provider{llm.ProviderAnthropic, llm.ProviderOpenAI}
	for _, tt := range tests {
		for _, provider := range providers {
			for _, jsonOut := range []bool{false, true} {
				name := tt.name + "/" + string(provider) + "/terminal"
				if jsonOut {
					name = tt.name + "/" + string(provider) + "/json"
				}
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					api := newLLMSecretAPI(t, provider)

					r := llmSecretScan(t, api, tt.servers, jsonOut)

					// The scan completes with the normal rows.
					wantCode := exitOK
					for _, row := range tt.rows {
						if row.severity == "high" {
							wantCode = exitFindings
						}
					}
					if r.code != wantCode {
						t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, wantCode, r.stdout, r.stderr)
					}
					if jsonOut && !decodeScanJSON(t, r.stdout).Complete {
						t.Errorf("JSON complete = false, want true")
					}
					// The terminal report groups the rows by severity and
					// --json does not, so compare them in a fixed order.
					got := llmJSONOrTerminalRows(t, r.stdout, jsonOut)
					slices.SortFunc(got, llmSecretCompareHits)
					if !slices.Equal(got, tt.rows) {
						t.Errorf("LLM findings = %+v, want %+v\nstdout:\n%s\nstderr:\n%s", got, tt.rows, r.stdout, r.stderr)
					}

					// The canary is in neither output. llmRun checked the
					// API key already.
					llmSecretAssertAbsent(t, tt.canary, "stdout", r.stdout)
					llmSecretAssertAbsent(t, tt.canary, "stderr", r.stderr)
					assertNoLeakBoth(t, r.stdout, r.stderr)

					llmSecretAssertRequests(t, api, provider, tt.canary, tt.want)
				})
			}
		}
	}
}

// llmSecretScan runs "mcpmoat scan --llm" on one stdio server for each entry
// of servers, with the real LLM client against api. The fake inspector gives
// each server its tools and its Secrets.
func llmSecretScan(t *testing.T, api *llmSecretAPI, servers []llmSecretServer, jsonOut bool) pinRunResult {
	t.Helper()
	tools := make(map[string][]inspect.Tool, len(servers))
	for _, s := range servers {
		tools[s.name] = s.tools
	}
	insp := fakeServers(tools)
	for _, s := range servers {
		res := insp.Results[s.name]
		for _, v := range s.secrets {
			res.Secrets = append(res.Secrets, discover.NewSecret(v))
		}
		insp.Results[s.name] = res
	}
	e := llmEnv(t, tools)
	// A factory with no classifier fails the test when it is called, so
	// the scan must use the real client below.
	c, stdout, stderr := llmCLI(e, insp, &llmFactory{t: t})
	c.newClassifier = newLLMClassifier

	args := []string{"--llm", "--llm-base-url", api.srv.URL}
	if api.provider == llm.ProviderOpenAI {
		args = append(args, "--llm-provider", "openai", "--llm-model", "m1")
	}
	if jsonOut {
		args = append(args, "--json")
	}
	return llmRun(t, e, c, stdout, stderr, args...)
}

// llmSecretAssertRequests checks the requests that api got: one for each
// tool, at the path of the provider, each with the payload of want. A body
// holds canary only when its payload in want holds it. A body with a redacted
// payload holds discover.Mask and "redacted":true in its user message.
func llmSecretAssertRequests(t *testing.T, api *llmSecretAPI, provider llm.Provider, canary string, want map[string]llmSecretPayload) {
	t.Helper()
	wantPath := "/v1/messages"
	if provider == llm.ProviderOpenAI {
		wantPath = "/chat/completions"
	}
	got := map[string]llmSecretPayload{}
	reqs := api.snapshot()
	if len(reqs) != len(want) {
		t.Errorf("the provider got %d requests, want %d (one for each tool)", len(reqs), len(want))
	}
	for i, req := range reqs {
		if req.path != wantPath {
			t.Errorf("request %d path = %q, want %q", i, req.path, wantPath)
		}
		p, err := llmSecretDecodePayload(req.content)
		if err != nil {
			t.Errorf("request %d: %v", i, err)
			continue
		}
		got[p.ToolName] = p

		w, ok := want[p.ToolName]
		if !ok {
			continue // maps.Equal below reports it
		}
		mayHold := strings.Contains(w.ToolName+"\x00"+w.ToolDescription, canary)
		if holds := bytes.Contains(req.body, []byte(canary)); holds != mayHold {
			t.Errorf("request %d (tool %q) body holds the secret = %v, want %v", i, p.ToolName, holds, mayHold)
		}
		if !mayHold {
			// No part of 8 bytes or more either, so a cut cannot leave a
			// piece of the secret.
			if part, leak := secretPartLeak(canary, string(req.body)); leak {
				t.Errorf("request %d (tool %q) body holds a part of the secret (%q)", i, p.ToolName, part)
			}
		}
		// The system prompt holds discover.Mask too, so the check reads
		// the user message, not the whole body.
		if w.Redacted {
			if !strings.Contains(req.content, discover.Mask) || !strings.Contains(req.content, `"redacted":true`) {
				t.Errorf("request %d (tool %q) user message has no %q or no \"redacted\":true:\n%.300s", i, p.ToolName, discover.Mask, req.content)
			}
			// The body carries the user message as a JSON string.
			if !bytes.Contains(req.body, []byte(`\"redacted\":true`)) {
				t.Errorf("request %d (tool %q) raw body has no \\\"redacted\\\":true", i, p.ToolName)
			}
		} else if strings.Contains(req.content, `"redacted"`) {
			t.Errorf("request %d (tool %q) user message has a \"redacted\" key, want none:\n%.300s", i, p.ToolName, req.content)
		}
	}
	if !maps.Equal(got, want) {
		for k, w := range want {
			if g, ok := got[k]; !ok || g != w {
				t.Errorf("tool %.80q: payload = %.300v, want %.300v", k, g, w)
			}
		}
		for k := range got {
			if _, ok := want[k]; !ok {
				t.Errorf("unexpected request for tool %.80q", k)
			}
		}
	}
}

// llmSecretCompareHits orders LLM rows by server, tool and rule.
func llmSecretCompareHits(a, b llmHit) int {
	return strings.Compare(a.server+"\x00"+a.tool+"\x00"+a.rule, b.server+"\x00"+b.tool+"\x00"+b.rule)
}

// llmSecretAssertAbsent fails the test when out holds secret.
func llmSecretAssertAbsent(t *testing.T, secret, what, out string) {
	t.Helper()
	if strings.Contains(out, secret) {
		t.Errorf("%s holds the secret value", what)
	}
}
