package main

// End-to-end tests of the network rules of scan (NFR-01) and of scan --llm
// (FR-17). They run the real binary (see runBinEnv in e2e_test.go) against
// loopback servers of the test: a recording HTTP proxy and a fake LLM
// provider. No test opens a connection outside the loopback interface, except
// the DNS lookup of the .invalid fixture host in the run without a proxy.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/report"
)

const (
	// e2eLLMKey is the API key canary. It is visible ASCII, so llm.ValidateKey
	// accepts it. It may only show in the x-api-key header of a request to
	// the fake provider. It holds no word, so no part of it shows in an output
	// by chance: llmAssertNoKey looks for every part of 8 bytes.
	e2eLLMKey = "sk-Rv5yM2wQ9cXh4Tn7Bd3Kz8Lp"
	// e2eNetRemoteHost is the host of the remote fixture server. The .invalid
	// top-level domain never resolves (RFC 6761).
	e2eNetRemoteHost = "mcp.fixture.invalid"
	// e2eNetSettlePath is the path of the request that e2eNetServer.settle
	// sends to its own server.
	e2eNetSettlePath = "/e2e-settle"
	// e2eNetMaxBody caps the request body that an e2eNetServer reads.
	e2eNetMaxBody = 1 << 20
)

// e2eNetRequest is one request that an e2eNetServer got.
type e2eNetRequest struct {
	method string
	// host is the target host: the Host of an absolute-URI request or of a
	// CONNECT request (a proxy request), else the Host header.
	host   string
	path   string
	url    string
	header http.Header
	body   string
	// dump is the whole request: request line, headers and body.
	dump string
}

// e2eNetServer is a loopback HTTP server that counts its connections and
// records every request. It serves as a forward proxy too: an absolute-URI
// request and a CONNECT request reach the handler like any other request.
type e2eNetServer struct {
	srv *httptest.Server
	// conns counts the new connections, the ones of settle included (see
	// countNewConns).
	conns *atomic.Int32

	mu      sync.Mutex
	reqs    []e2eNetRequest
	settles int32
}

// e2eNetStart starts an e2eNetServer that records each request and then
// answers it with respond. The test stops the server at its end.
func e2eNetStart(t *testing.T, respond func(w http.ResponseWriter, body []byte)) *e2eNetServer {
	t.Helper()
	s := &e2eNetServer{}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == e2eNetSettlePath && !r.URL.IsAbs() && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, e2eNetMaxBody))
		head, _ := httputil.DumpRequest(r, false)
		host := r.Host
		if r.URL.IsAbs() {
			host = r.URL.Host
		}
		// Record before the answer: the binary waits for the answer, so the
		// record exists when the binary exits.
		s.mu.Lock()
		s.reqs = append(s.reqs, e2eNetRequest{
			method: r.Method,
			host:   host,
			path:   r.URL.Path,
			url:    r.URL.String(),
			header: r.Header.Clone(),
			body:   string(body),
			dump:   string(head) + string(body),
		})
		s.mu.Unlock()
		respond(w, body)
	}))
	s.conns = countNewConns(s.srv)
	s.srv.Start()
	t.Cleanup(s.srv.Close)
	return s
}

// settle returns the number of connections and the requests that the server
// got from others than settle. It first sends one request of its own on a new
// connection and waits for the answer. The server accepts connections in
// order and counts each one before it serves it, so every connection that the
// binary opened before it exited is counted, also one that sent nothing.
func (s *e2eNetServer) settle(t *testing.T) (conns int32, reqs []e2eNetRequest) {
	t.Helper()
	// No proxy and no keep-alive: the request goes straight to the server on
	// one new connection.
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, s.srv.URL+e2eNetSettlePath, nil)
	if err != nil {
		t.Fatalf("settle request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("settle request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("settle request: status %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settles++
	return s.conns.Load() - s.settles, slices.Clone(s.reqs)
}

// e2eNetAssertNoKey fails the test when a request holds the API key canary
// anywhere: request line, headers or body.
func e2eNetAssertNoKey(t *testing.T, who string, reqs []e2eNetRequest) {
	t.Helper()
	for i, r := range reqs {
		if strings.Contains(r.dump, e2eLLMKey) {
			t.Errorf("%s request %d (%s %s) holds the API key", who, i, r.method, r.url)
		}
	}
}

// e2eNetAssertNoKeyOutput fails the test when stdout or stderr holds the API
// key canary or a part of it of 8 bytes or more (see llmAssertNoKey), a raw
// escape byte, or any canary of discovertest.
func e2eNetAssertNoKeyOutput(t *testing.T, stdout, stderr string) {
	t.Helper()
	llmAssertNoKey(t, e2eLLMKey, stdout, stderr)
	assertNoLeakBoth(t, stdout, stderr)
	assertNoEscape(t, stdout, stderr)
}

// e2eNetAssertMarker checks whether the marker file of writeMarkerScript
// exists.
func e2eNetAssertMarker(t *testing.T, marker string, want bool) {
	t.Helper()
	_, err := os.Stat(marker)
	switch {
	case want && err != nil:
		t.Errorf("marker file is missing (err = %v): the server did not start", err)
	case !want && !os.IsNotExist(err):
		t.Errorf("marker file exists or cannot be checked (err = %v): mcpmoat started a server", err)
	}
}

// TestE2ENoNetworkWithoutLLM proves NFR-01 and the first FR-17 criterion on
// the real binary: without --llm, scan connects to nothing but the configured
// servers.
//
// The environment holds the API key and points ANTHROPIC_BASE_URL and
// OPENAI_BASE_URL (the variables of the provider SDKs) to a fake provider. No
// mcpmoat flag names that provider, so it must get no connection. HTTP_PROXY
// and HTTPS_PROXY point to a recording proxy, which must see the configured
// remote server only: this also proves that scan honours the proxy for a
// configured server. The proxy answers 502, so the remote server fails, and a
// server failure alone keeps the exit code.
func TestE2ENoNetworkWithoutLLM(t *testing.T) {
	t.Parallel()
	proxy := e2eNetStart(t, func(w http.ResponseWriter, _ []byte) { w.WriteHeader(http.StatusBadGateway) })
	provider := e2eNetStart(t, func(w http.ResponseWriter, _ []byte) { w.WriteHeader(http.StatusServiceUnavailable) })

	home, work := t.TempDir(), t.TempDir()
	requirePrivateChain(t, home)
	script, marker := writeMarkerScript(t, t.TempDir())
	writeServers(t, home, ".claude.json", map[string]any{
		"benign-net": map[string]any{"command": inspecttest.Fixture(t, "benign")},
		"remote-net": map[string]any{"type": "http", "url": "http://" + e2eNetRemoteHost + "/mcp"},
		"marker-net": map[string]any{"command": script},
	})
	baseEnv := []string{
		llm.KeyEnv + "=" + e2eLLMKey,
		"ANTHROPIC_BASE_URL=" + provider.srv.URL,
		"OPENAI_BASE_URL=" + provider.srv.URL,
	}
	proxyEnv := append(slices.Clone(baseEnv), "HTTP_PROXY="+proxy.srv.URL, "HTTPS_PROXY="+proxy.srv.URL)

	// checkRun checks what holds for every run: the exit code, the servers
	// in the table, no key in the output, and no connection to the provider.
	checkRun := func(t *testing.T, stdout, stderr string, code int) {
		t.Helper()
		// The plain http URL of remote-net is a high config finding
		// (MOAT-T4-001), so the exit code is 1 in every mode.
		if code != exitFindings {
			t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFindings, stdout, stderr)
		}
		names := column(tableRows(t, stdout), 0)
		slices.Sort(names)
		if want := []string{"benign-net", "marker-net", "remote-net"}; !slices.Equal(names, want) {
			t.Errorf("server names = %v, want %v\nstdout:\n%s", names, want, stdout)
		}
		e2eNetAssertNoKeyOutput(t, stdout, stderr)
		conns, reqs := provider.settle(t)
		if conns != 0 || len(reqs) != 0 {
			t.Errorf("the LLM provider got %d connections and %d requests, want none", conns, len(reqs))
		}
	}

	// Step 1: --no-connect starts no server and opens no connection (FR-05).
	stdout, stderr, code := runBinEnv(t, home, work, proxyEnv, "scan", "--no-connect")
	checkRun(t, stdout, stderr, code)
	e2eNetAssertMarker(t, marker, false)
	if conns, reqs := proxy.settle(t); conns != 0 || len(reqs) != 0 {
		t.Errorf("--no-connect: the proxy got %d connections and %d requests, want none", conns, len(reqs))
	}

	// Step 2: a full scan through the proxy.
	stdout, stderr, code = runBinEnv(t, home, work, proxyEnv, "scan")
	checkRun(t, stdout, stderr, code)
	// The marker proves that this run starts the stdio servers, so the check
	// of step 1 can fail.
	e2eNetAssertMarker(t, marker, true)
	_, proxied := proxy.settle(t)
	if len(proxied) == 0 {
		t.Fatal("the proxy got no request: scan did not use HTTP_PROXY for the remote server")
	}
	for i, r := range proxied {
		if r.host != e2eNetRemoteHost {
			t.Errorf("proxy request %d goes to %q (%s %s), want only %q", i, r.host, r.method, r.url, e2eNetRemoteHost)
		}
	}
	e2eNetAssertNoKey(t, "proxy", proxied)

	// Step 3: the same scan without the proxy variables still ends, and
	// still makes no connection to the provider or to the proxy.
	stdout, stderr, code = runBinEnv(t, home, work, baseEnv, "scan")
	checkRun(t, stdout, stderr, code)
	if _, reqs := proxy.settle(t); len(reqs) != len(proxied) {
		t.Errorf("the proxy got %d new requests without the proxy variables, want none", len(reqs)-len(proxied))
	}
}

// e2eLLMMissingKeyCases are the environments of TestE2ELLMMissingKey. The
// leak strings are parts of a key that stderr must not show.
var e2eLLMMissingKeyCases = []struct {
	name    string
	env     []string
	wantErr error
	leak    []string
}{
	{name: "no key", wantErr: llm.ErrMissingKey},
	{name: "empty key", env: []string{llm.KeyEnv + "="}, wantErr: llm.ErrMissingKey},
	{
		// The key comes only from llm.KeyEnv, never from the variables of the
		// provider SDKs.
		name:    "key in other variables",
		env:     []string{"ANTHROPIC_API_KEY=" + e2eLLMKey, "OPENAI_API_KEY=" + e2eLLMKey},
		wantErr: llm.ErrMissingKey,
		leak:    []string{e2eLLMKey},
	},
	{
		name:    "key with a space",
		env:     []string{llm.KeyEnv + "=sk-e2e-bad canary-key-6Rt1"},
		wantErr: llm.ErrInvalidKey,
		leak:    []string{"sk-e2e-bad", "canary-key-6Rt1"},
	},
}

// TestE2ELLMMissingKey checks that scan --llm without a usable key in
// llm.KeyEnv stops before it reads a config: exit code 2, no stdout, a stderr
// that names the variable and never the key, no server started, no pins.json
// and no connection to the provider.
func TestE2ELLMMissingKey(t *testing.T) {
	t.Parallel()
	for _, tt := range e2eLLMMissingKeyCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			provider := e2eNetStart(t, func(w http.ResponseWriter, _ []byte) { w.WriteHeader(http.StatusServiceUnavailable) })
			home, work := t.TempDir(), t.TempDir()
			script, marker := writeMarkerScript(t, t.TempDir())
			writeServers(t, home, ".claude.json", map[string]any{"marker-llm": map[string]any{"command": script}})

			stdout, stderr, code := runBinEnv(t, home, work, tt.env, "scan", "--llm", "--llm-base-url", provider.srv.URL)

			if code != exitError {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitError, stderr)
			}
			assertEmptyStdout(t, stdout)
			lines := nonEmptyLines(stderr)
			if len(lines) != 2 || !strings.HasPrefix(lines[0], scanPrefix+"--llm: "+tt.wantErr.Error()) ||
				!strings.Contains(lines[0], llm.KeyEnv) || lines[1] != usageHint {
				t.Errorf("stderr = %q, want the line %q with the reason, then %q", stderr, scanPrefix+"--llm: "+tt.wantErr.Error(), usageHint)
			}
			assertContainsNone(t, "stderr", stderr, tt.leak)
			e2eNetAssertNoKeyOutput(t, stdout, stderr)
			e2eNetAssertMarker(t, marker, false)
			assertNoPinsFile(t, home)
			if conns, reqs := provider.settle(t); conns != 0 || len(reqs) != 0 {
				t.Errorf("the LLM provider got %d connections and %d requests, want none", conns, len(reqs))
			}
		})
	}
}

// The tools of the benign fixture (testdata/servers/benign), with their
// descriptions. The fixture is package main in its own directory, so the
// test keeps a copy of the text.
var e2eLLMBenignTools = map[string]string{
	"add":  "Add two numbers and return the sum.",
	"echo": "Return the input text unchanged.",
}

// e2eLLMRiskyTool is the tool that the fake provider rates high. It rates the
// other tools none.
const e2eLLMRiskyTool = "echo"

// e2eLLMAnthropic answers like the Anthropic Messages API: one tool_use block
// named classify. It rates e2eLLMRiskyTool high (hidden-instructions) and
// every other tool none. A body that it cannot read (see llmRequestPayload)
// gets 400, which fails the scan with exit code 2.
func e2eLLMAnthropic(w http.ResponseWriter, body []byte) {
	msg, err := llmRequestPayload(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	verdict := `{"risk":"none","category":"other"}`
	if msg.ToolName == e2eLLMRiskyTool {
		verdict = `{"risk":"high","category":"hidden-instructions"}`
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"id":"msg_e2e","type":"message","role":"assistant","model":"claude-e2e",`+
		`"content":[{"type":"tool_use","id":"toolu_e2e","name":"classify","input":`+verdict+`}],`+
		`"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`)
}

// e2eLLMWarning returns the warning line that scan --llm prints first on
// stderr, for the fake provider at url.
func e2eLLMWarning(t *testing.T, url string) string {
	t.Helper()
	host, ok := strings.CutPrefix(url, "http://")
	if !ok {
		t.Fatalf("provider URL %q is not http", url)
	}
	return llmWarning("anthropic", host)
}

// e2eLLMAssertRequests checks every request to the fake provider: the
// Anthropic endpoint and headers, the key only in x-api-key, and a body that
// holds the name and description of one benign tool and none of forbidden
// (text from the config). It returns the tool names, sorted.
func e2eLLMAssertRequests(t *testing.T, reqs []e2eNetRequest, forbidden []string) []string {
	t.Helper()
	var tools []string
	for i, r := range reqs {
		if r.method != http.MethodPost || r.path != "/v1/messages" {
			t.Errorf("request %d: %s %s, want POST /v1/messages", i, r.method, r.url)
		}
		if got := r.header.Get("X-Api-Key"); got != e2eLLMKey {
			t.Errorf("request %d: x-api-key header is %d bytes, want the key", i, len(got))
		}
		if got := r.header.Get("Anthropic-Version"); got == "" {
			t.Errorf("request %d: no anthropic-version header", i)
		}
		if strings.Contains(r.url, e2eLLMKey) || strings.Contains(r.body, e2eLLMKey) {
			t.Errorf("request %d: the URL or the body holds the API key", i)
		}
		for name, values := range r.header {
			if name == "X-Api-Key" {
				continue
			}
			for _, v := range values {
				if strings.Contains(v, e2eLLMKey) {
					t.Errorf("request %d: header %s holds the API key", i, name)
				}
			}
		}
		for _, bad := range forbidden {
			if strings.Contains(r.body, bad) {
				t.Errorf("request %d: body holds %q from the config:\n%s", i, bad, r.body)
			}
		}
		msg, err := llmRequestPayload([]byte(r.body))
		if err != nil {
			t.Errorf("request %d: body is not a Messages request with one tool message (%v):\n%s", i, err, r.body)
			continue
		}
		if want, known := e2eLLMBenignTools[msg.ToolName]; !known || msg.ToolDescription != want || msg.Truncated {
			t.Errorf("request %d: tool message %+v, want a benign tool with its description", i, msg)
		}
		tools = append(tools, msg.ToolName)
	}
	slices.Sort(tools)
	return tools
}

// TestE2ELLMFindings runs scan --llm against a fake Anthropic provider on
// loopback. It checks the warning, what each request holds and does not hold,
// the [LLM] finding in the terminal and in the JSON report, the exit code, that
// the rule finding stays, and that the stdio server never gets the key.
func TestE2ELLMFindings(t *testing.T) {
	t.Parallel()
	const (
		server      = "srv-e2e-llm-name-2Hd9"
		argsCanary  = "e2e-llm-args-canary-8Kp2"
		envKeyInCfg = "API_KEY"
	)
	provider := e2eNetStart(t, e2eLLMAnthropic)

	home, work := t.TempDir(), t.TempDir()
	requirePrivateChain(t, home)
	envDir := t.TempDir()
	envFile := filepath.Join(envDir, "env-"+argsCanary+".txt")
	fixture := inspecttest.Fixture(t, "benign")
	// The env value is a plaintext secret, so the config rules report
	// MOAT-T4-002 (high), a rule finding.
	writeServers(t, home, ".claude.json", map[string]any{
		server: map[string]any{
			"command": fixture,
			"args":    []string{"-envfile", envFile},
			"env":     map[string]string{envKeyInCfg: discovertest.CanaryEnv},
		},
	})
	forbidden := []string{server, argsCanary, envKeyInCfg, discovertest.CanaryEnv, fixture, home, envDir, "-envfile"}
	env := []string{llm.KeyEnv + "=" + e2eLLMKey}
	llmArgs := []string{"scan", "--llm", "--llm-base-url", provider.srv.URL}
	warning := e2eLLMWarning(t, provider.srv.URL)

	// Step 1: the terminal report. --ignore MOAT-T4-002 leaves the LLM
	// finding as the only high finding, so it alone gives exit code 1.
	stdout, stderr, code := runBinEnv(t, home, work, env, append(slices.Clone(llmArgs), "--ignore", "MOAT-T4-002")...)

	if code != exitFindings {
		t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFindings, stdout, stderr)
	}
	e2eNetAssertNoKeyOutput(t, stdout, stderr)
	// The warning comes first, before any request.
	if lines := nonEmptyLines(stderr); len(lines) == 0 || lines[0] != warning {
		t.Errorf("first stderr line is not the warning %q\nstderr:\n%s", warning, stderr)
	}
	assertContainsAll(t, "stderr", stderr, []string{scanPrefix + "pinned 2 tools for " + server})
	assertContainsAll(t, "stdout", stdout, []string{
		"\n  " + llm.RuleID + "  " + llm.Title + " [LLM]\n",
		"\n    Source: LLM classification (advisory)\n",
		"\n    Tool: " + e2eLLMRiskyTool + " (hidden-instructions)\n",
	})
	if n := strings.Count(stdout, llm.RuleID); n != 1 {
		t.Errorf("stdout names %s %d times, want once (for %s only)\nstdout:\n%s", llm.RuleID, n, e2eLLMRiskyTool, stdout)
	}
	assertContainsNone(t, "stdout", stdout, []string{llm.RuleIDInvalid})
	_, reqs := provider.settle(t)
	if got := e2eLLMAssertRequests(t, reqs, forbidden); !slices.Equal(got, []string{"add", "echo"}) {
		t.Errorf("tools sent = %v, want [add echo]", got)
	}

	// The stdio server got its configured env, but not the key of mcpmoat.
	dump, err := os.ReadFile(envFile) //nolint:gosec // G304: the path is below a t.TempDir() directory
	if err != nil {
		t.Fatalf("the benign server wrote no env dump: %v", err)
	}
	envLines := strings.Split(string(dump), "\n")
	if !slices.Contains(envLines, envKeyInCfg+"="+discovertest.CanaryEnv) {
		t.Errorf("env dump has no line %s=<canary>, so it is not the env of the server:\n%s", envKeyInCfg, dump)
	}
	if strings.Contains(string(dump), llm.KeyEnv) || strings.Contains(string(dump), e2eLLMKey) {
		t.Errorf("the stdio server got %s in its environment", llm.KeyEnv)
	}

	// Step 2: the JSON report holds both findings, each with its source.
	stdout, stderr, code = runBinEnv(t, home, work, env, append(slices.Clone(llmArgs), "--json")...)

	if code != exitFindings {
		t.Errorf("--json: exit code = %d, want %d\nstderr:\n%s", code, exitFindings, stderr)
	}
	e2eNetAssertNoKeyOutput(t, stdout, stderr)
	if lines := nonEmptyLines(stderr); len(lines) == 0 || lines[0] != warning {
		t.Errorf("--json: first stderr line is not the warning %q\nstderr:\n%s", warning, stderr)
	}
	doc := decodeScanJSON(t, stdout)
	if !doc.Complete {
		t.Error("complete = false, want true")
	}
	wantFindings := []report.JSONFinding{
		{RuleID: "MOAT-T4-002", Severity: "high", Server: server, Field: "env", Key: envKeyInCfg, Source: string(report.SourceRule)},
		{RuleID: llm.RuleID, Severity: "high", Server: server, Field: "tool", Key: e2eLLMRiskyTool, Related: "hidden-instructions", Source: string(report.SourceLLM)},
	}
	for _, want := range wantFindings {
		if !slices.Contains(doc.Findings, want) {
			t.Errorf("no finding %+v\nfindings: %+v", want, doc.Findings)
		}
	}
	if len(doc.Findings) != len(wantFindings) {
		t.Errorf("got %d findings, want %d: %+v", len(doc.Findings), len(wantFindings), doc.Findings)
	}
	_, reqs = provider.settle(t)
	if got := e2eLLMAssertRequests(t, reqs, forbidden); !slices.Equal(got, []string{"add", "add", "echo", "echo"}) {
		t.Errorf("tools sent in both runs = %v, want each tool twice", got)
	}
}

// TestE2ELLMProviderFailure checks a provider that answers 503: scan still
// prints the report, marks the JSON report incomplete and exits with 2. The
// error names the status code only, never the key or the response body.
func TestE2ELLMProviderFailure(t *testing.T) {
	t.Parallel()
	const bodyCanary = "e2e-llm-body-canary-5Wv7"
	tests := []struct {
		name string
		args []string
	}{
		{name: "terminal"},
		{name: "json", args: []string{"--json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			provider := e2eNetStart(t, func(w http.ResponseWriter, _ []byte) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, bodyCanary)
			})
			const server = "benign-llm-fail"
			home, work := benignHome(t, server)
			args := append([]string{"scan", "--llm", "--llm-base-url", provider.srv.URL}, tt.args...)

			stdout, stderr, code := runBinEnv(t, home, work, []string{llm.KeyEnv + "=" + e2eLLMKey}, args...)

			if code != exitError {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitError, stdout, stderr)
			}
			e2eNetAssertNoKeyOutput(t, stdout, stderr)
			assertContainsAll(t, "stderr", stderr, []string{
				e2eLLMWarning(t, provider.srv.URL),
				scanPrefix + "the LLM provider failed (HTTP 503",
			})
			assertContainsNone(t, "stdout", stdout, []string{bodyCanary, pinEnvCanary})
			assertContainsNone(t, "stderr", stderr, []string{bodyCanary, pinEnvCanary})
			if tt.args == nil {
				if got := column(tableRows(t, stdout), 0); !slices.Equal(got, []string{server}) {
					t.Errorf("server names = %v, want [%s]\nstdout:\n%s", got, server, stdout)
				}
			} else {
				doc := decodeScanJSON(t, stdout)
				if doc.Complete {
					t.Error("complete = true, want false")
				}
				if len(doc.Servers) != 1 || doc.Servers[0].Name != server {
					t.Errorf("servers = %+v, want only %s", doc.Servers, server)
				}
				for _, f := range doc.Findings {
					if f.Source == string(report.SourceLLM) {
						t.Errorf("LLM finding %+v after a failed request", f)
					}
				}
			}
			_, reqs := provider.settle(t)
			if len(reqs) == 0 {
				t.Error("the provider got no request")
			}
			e2eLLMAssertRequests(t, reqs, []string{server, pinEnvCanary})
		})
	}
}
