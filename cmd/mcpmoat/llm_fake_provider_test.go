package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
)

// This file holds the fakes of the LLM step (FR-17) that the tests of this
// package share:
//
//   - fakeProvider: a fake LLM provider on a loopback httptest server, for
//     the tests that run the real client (llm.New). It speaks the Anthropic
//     Messages API or the OpenAI Chat Completions API.
//   - providerPayload and decodeProviderRequest: the tool message of one
//     provider request. The E2E tests (e2e_network_test.go) use them too.
//   - writeProviderVerdict: the 2xx answer of a provider for one verdict.
//   - llmFake: a fake classifier (cli.newClassifier) for the tests that send
//     no request.

// llmErrorBodyCanary is in the body and in a header of every error answer of
// fakeProvider (see writeProviderStatus). The client never reads them, so it
// must show in no output.
const llmErrorBodyCanary = "mcpmoat-reject-body-canary-Hs4Qm8"

// llmMarkStatus returns the marker that makes fakeProvider answer a tool with
// the HTTP status code. The marker must be in the first part of a long
// description, before the cut of llm.MaxDescriptionBytes.
func llmMarkStatus(code int) string { return fmt.Sprintf("llm:http%d", code) }

// llmStatusMarker finds the marker of llmMarkStatus in a description.
var llmStatusMarker = regexp.MustCompile(`llm:http(\d{3})`)

// providerPayload is the user message of one provider request: a JSON object
// with every key that the client may send. It is comparable, so a test can
// compare maps of it with maps.Equal.
type providerPayload struct {
	ToolName        string `json:"tool_name"`
	ToolDescription string `json:"tool_description"`
	Truncated       bool   `json:"truncated"`
	Redacted        bool   `json:"redacted"`
}

// input returns the name and the description of the tool as an llm.Input.
func (p providerPayload) input() llm.Input {
	return llm.Input{ToolName: p.ToolName, Description: p.ToolDescription}
}

// decodeProviderRequest reads a request body of the provider flavour. It
// returns the payload and the raw text of the user message. An Anthropic
// body must have exactly one message, from the user: the system prompt is a
// key of its own. An OpenAI body must have exactly one user message: its
// system prompt is a message too. The user message must have only the keys
// of providerPayload.
func decodeProviderRequest(provider llm.Provider, body []byte) (providerPayload, string, error) {
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return providerPayload{}, "", err
	}
	var user []string
	for _, m := range req.Messages {
		if m.Role == "user" {
			user = append(user, m.Content)
		}
	}
	if len(user) != 1 || (provider != llm.ProviderOpenAI && len(req.Messages) != 1) {
		return providerPayload{}, "", errors.New("want one user message")
	}
	dec := json.NewDecoder(strings.NewReader(user[0]))
	// A key that providerPayload does not know is an error, so a test sees
	// every new key that the client sends.
	dec.DisallowUnknownFields()
	var p providerPayload
	if err := dec.Decode(&p); err != nil {
		return providerPayload{}, "", err
	}
	return p, user[0], nil
}

// writeProviderJSON writes v as a JSON answer.
func writeProviderJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeProviderVerdict writes the 2xx answer of the provider for the verdict
// v. Anthropic: one tool_use block named classify, whose input is the risk
// and the category of v. OpenAI: one choice whose content is that JSON.
func writeProviderVerdict(w http.ResponseWriter, provider llm.Provider, v llm.Verdict) {
	risk := map[string]string{"risk": string(v.Risk), "category": string(v.Category)}
	if provider == llm.ProviderOpenAI {
		content, _ := json.Marshal(risk)
		writeOpenAIChoice(w, "stop", string(content))
		return
	}
	writeProviderJSON(w, map[string]any{
		"id":          "msg_test",
		"type":        "message",
		"role":        "assistant",
		"model":       "claude-test",
		"stop_reason": "tool_use",
		"content": []any{map[string]any{
			"type":  "tool_use",
			"id":    "toolu_test",
			"name":  "classify",
			"input": risk,
		}},
		"usage": map[string]int{"input_tokens": 1, "output_tokens": 1},
	})
}

// writeProviderUnusable writes a 2xx answer with no usable verdict: a refusal
// of the model. The client gives llm.ErrInvalidOutput.
func writeProviderUnusable(w http.ResponseWriter, provider llm.Provider) {
	if provider == llm.ProviderOpenAI {
		writeOpenAIChoice(w, "content_filter", "")
		return
	}
	writeProviderJSON(w, map[string]any{
		"id":          "msg_test",
		"type":        "message",
		"role":        "assistant",
		"model":       "claude-test",
		"stop_reason": "refusal",
		"content":     []any{},
	})
}

// writeOpenAIChoice writes an OpenAI Chat Completions answer with one choice.
func writeOpenAIChoice(w http.ResponseWriter, finish, content string) {
	writeProviderJSON(w, map[string]any{
		"id":     "chatcmpl-test",
		"object": "chat.completion",
		"model":  "m1",
		"choices": []any{map[string]any{
			"index":         0,
			"finish_reason": finish,
			"message":       map[string]any{"role": "assistant", "content": content},
		}},
	})
}

// writeProviderStatus writes an error answer with code. The body is JSON with
// llmErrorBodyCanary and a raw escape byte, in the error shape of the
// provider, so a client that printed it would fail the test.
//
// Every error answer has "Retry-After: 0". For a code that the client tries
// again (llmRetryCodes) it makes the client wait 0 s instead of its backoff
// of 1 s and more, which cmd/mcpmoat cannot change. For a refusal (400, 413,
// 422) and the other codes it changes nothing: the client sends one request
// for that tool (see TestScanLLMRejected).
func writeProviderStatus(w http.ResponseWriter, provider llm.Provider, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", llmErrorBodyCanary)
	w.Header().Set("Retry-After", "0")
	w.WriteHeader(code)
	msg := llmErrorBodyCanary + " \x1b[31mrefused\x1b[0m"
	if provider == llm.ProviderOpenAI {
		_, _ = io.WriteString(w, `{"error":{"message":"`+msg+`","type":"invalid_request_error","code":null}}`)
		return
	}
	_, _ = io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","message":"`+msg+`"}}`)
}

// providerStep is one scripted answer of fakeProvider: the status code and
// the Retry-After header ("" means none), with no body. When hold is true,
// the answer is held as fakeProvider.hold does; code and retryAfter are then
// not used.
type providerStep struct {
	code       int
	retryAfter string
	hold       bool
}

// providerRequest is one request that fakeProvider got.
type providerRequest struct {
	path   string
	header http.Header
	// body is the raw request body.
	body []byte
	// content is the raw text of the user message, and payload its decoded
	// form. err is the error of the read or of decodeProviderRequest.
	content string
	payload providerPayload
	err     error
}

// fakeProvider is a fake LLM provider on a loopback httptest server, for the
// real client. It records each request. Each request gets the first answer
// of this list that applies:
//
//  1. A request that it cannot read, or with the wrong path, gets HTTP 418,
//     a global failure without a retry, and counts in bad: the scan fails,
//     and so does the test.
//  2. With hold, or a hold step of the script, it answers nothing: it holds
//     the request until the client closes it (one value on closed) or the
//     test ends.
//  3. The next step of the script of the tool, one step for each request.
//  4. With status, every request gets that error answer.
//  5. A tool whose description holds llmMarkStatus(code) gets that error.
//  6. Else the answer of llmAnswerFor: a verdict, the 503 of llmMark503, or
//     a 2xx answer that cannot be used for llmMarkInvalid.
//
// The error answers of 4 to 6 come from writeProviderStatus.
type fakeProvider struct {
	srv *httptest.Server
	// host is the host and port of the server.
	host     string
	provider llm.Provider

	// Set these fields before the first request.
	status    int
	script    map[string][]providerStep
	hold      bool
	onRequest func() // runs first for each request, in the handler goroutine

	// newConns counts the new connections (see countNewConns), requests
	// every request, and bad the requests of rule 1.
	newConns *atomic.Int32
	requests atomic.Int32
	bad      atomic.Int32
	// release ends every held request at the end of the test, so that the
	// server can close. closed gets one value for each held request that
	// the client closed.
	release chan struct{}
	closed  chan struct{}

	mu    sync.Mutex
	reqs  []providerRequest
	tries map[string]int // the requests for each tool name that it could read
}

// newFakeProvider starts a fake provider of the given flavour.
func newFakeProvider(t *testing.T, provider llm.Provider) *fakeProvider {
	t.Helper()
	a := &fakeProvider{
		provider: provider,
		release:  make(chan struct{}),
		closed:   make(chan struct{}, 64),
		tries:    make(map[string]int),
	}
	a.srv = httptest.NewUnstartedServer(http.HandlerFunc(a.handle))
	a.newConns = countNewConns(a.srv)
	a.srv.Start()
	// t.Cleanup runs its functions in the reverse order: the held requests
	// end first, then the server closes.
	t.Cleanup(a.srv.Close)
	t.Cleanup(func() { close(a.release) })
	a.host = a.srv.Listener.Addr().String()
	return a
}

// path returns the API path of the provider.
func (a *fakeProvider) path() string {
	if a.provider == llm.ProviderOpenAI {
		return "/chat/completions"
	}
	return "/v1/messages"
}

// handle answers one request.
func (a *fakeProvider) handle(w http.ResponseWriter, r *http.Request) {
	a.requests.Add(1)
	if a.onRequest != nil {
		a.onRequest()
	}
	req := providerRequest{path: r.URL.Path, header: r.Header.Clone()}
	req.body, req.err = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if req.err == nil {
		req.payload, req.content, req.err = decodeProviderRequest(a.provider, req.body)
	}
	name := req.payload.ToolName
	a.mu.Lock()
	a.reqs = append(a.reqs, req)
	try := a.tries[name]
	if req.err == nil {
		a.tries[name]++
	}
	a.mu.Unlock()

	var step providerStep
	if steps := a.script[name]; try < len(steps) {
		step = steps[try]
	}
	switch {
	case req.err != nil || r.URL.Path != a.path():
		a.bad.Add(1)
		w.WriteHeader(http.StatusTeapot)
	case a.hold || step.hold:
		select {
		case <-r.Context().Done():
			a.closed <- struct{}{}
		case <-a.release:
		}
	case step.code != 0:
		if step.retryAfter != "" {
			w.Header().Set("Retry-After", step.retryAfter)
		}
		w.WriteHeader(step.code)
	case a.status != 0:
		writeProviderStatus(w, a.provider, a.status)
	default:
		a.answer(w, req.payload)
	}
}

// answer writes the answer of rules 5 and 6 of fakeProvider.
func (a *fakeProvider) answer(w http.ResponseWriter, p providerPayload) {
	if m := llmStatusMarker.FindStringSubmatch(p.ToolDescription); m != nil {
		code, _ := strconv.Atoi(m[1])
		writeProviderStatus(w, a.provider, code)
		return
	}
	v, err := llmAnswerFor(p.input())
	var se *llm.StatusError
	switch {
	case errors.As(err, &se):
		writeProviderStatus(w, a.provider, se.Code)
	case errors.Is(err, llm.ErrInvalidOutput):
		writeProviderUnusable(w, a.provider)
	case err != nil:
		a.bad.Add(1)
		w.WriteHeader(http.StatusTeapot)
	default:
		writeProviderVerdict(w, a.provider, v)
	}
}

// snapshot returns a copy of the recorded requests.
func (a *fakeProvider) snapshot() []providerRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.reqs)
}

// perTool returns the number of requests for each tool name so far. A
// request that the fake could not read does not count.
func (a *fakeProvider) perTool() map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return maps.Clone(a.tries)
}

// llmRealScan runs "mcpmoat scan --llm" on the config of e with the inspector
// insp and the real LLM client against api. timeout is cli.llmStepTimeout (0:
// the default). extra comes after the LLM flags.
func llmRealScan(t *testing.T, api *fakeProvider, e *pinEnv, insp inspect.Inspector, timeout time.Duration, jsonOut bool, extra ...string) pinRunResult {
	t.Helper()
	// A factory with no classifier fails the test when it is called, so the
	// scan must use the real client below.
	c, stdout, stderr := llmCLI(e, insp, &llmFactory{t: t})
	c.newClassifier = newLLMClassifier
	c.llmStepTimeout = timeout
	args := []string{"--llm", "--llm-base-url", api.srv.URL}
	if api.provider == llm.ProviderOpenAI {
		args = append(args, "--llm-provider", "openai", "--llm-model", "m1")
	}
	if jsonOut {
		args = append(args, "--json")
	}
	return llmRun(t, e, c, stdout, stderr, append(args, extra...)...)
}

// llmAnswerFunc gives the answer of llmFake for one call, with the context of
// the call.
type llmAnswerFunc func(ctx context.Context, in llm.Input) (llm.Verdict, error)

// llmUnlessStopped returns an llmAnswerFunc that gives a stop error when the
// context of the call has ended, as the real client does, and else the
// answer of answer.
func llmUnlessStopped(answer func(llm.Input) (llm.Verdict, error)) llmAnswerFunc {
	return func(ctx context.Context, in llm.Input) (llm.Verdict, error) {
		if err := ctx.Err(); err != nil {
			return llm.Verdict{}, fmt.Errorf("test: stopped: %w", err)
		}
		return answer(in)
	}
}

// llmFake is the fake toolClassifier of the tests. It records each input and
// counts the calls that run at the same time. It is safe for concurrent use.
type llmFake struct {
	// answer gives the answer of each call. It runs also when the context of
	// the call has ended. Nil means llmUnlessStopped(llmAnswerFor).
	answer llmAnswerFunc
	// shuffle makes each call yield the processor a random number of times
	// before it answers, so the calls end in a random order.
	shuffle bool

	calls       atomic.Int32
	inFlight    atomic.Int32
	maxInFlight atomic.Int32

	mu     sync.Mutex
	inputs []llm.Input
}

// Classify implements toolClassifier.
func (f *llmFake) Classify(ctx context.Context, in llm.Input) (llm.Verdict, error) {
	f.calls.Add(1)
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	// Raise maxInFlight to n. CompareAndSwap fails when another call
	// changed it after the Load, so the loop tries again.
	for {
		m := f.maxInFlight.Load()
		if n <= m || f.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}
	f.mu.Lock()
	f.inputs = append(f.inputs, in)
	f.mu.Unlock()

	if f.shuffle {
		for range rand.IntN(200) { //nolint:gosec // G404: test order noise, not security
			runtime.Gosched()
		}
	}
	if f.answer != nil {
		return f.answer(ctx, in)
	}
	return llmUnlessStopped(llmAnswerFor)(ctx, in)
}

// received returns the inputs so far, sorted by tool name.
func (f *llmFake) received() []llm.Input {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.inputs)
	slices.SortFunc(out, func(a, b llm.Input) int { return strings.Compare(a.ToolName, b.ToolName) })
	return out
}

// Compile-time check: llmFake is a toolClassifier.
var _ toolClassifier = (*llmFake)(nil)
