package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// This file tests "mcpmoat scan --llm" (FR-17) in process. The tests inject
// a fake classifier through cli.newClassifier, so they send no request. The
// tests that need the real client (llm.New) are in scan_llm_client_test.go:
// they send their requests to a fake Anthropic API on a loopback httptest
// server. network_test.go holds the no-network proof (NFR-01).

// llmTestKey is the fake API key of the tests, the E2E tests of
// e2e_network_test.go too. It is visible ASCII, so llm.ValidateKey accepts
// it. It holds no word, so no part of it shows in an output by chance. It
// must never show on stdout or stderr.
const llmTestKey = "sk-Kq7vX2pLw9TzR4mNb8HcYf3J"

// The markers that a tool description holds to choose the answer of the fake
// classifier and of the fake LLM server (see llmAnswerFor). A description
// without a marker gets risk none.
const (
	llmMarkHigh    = "llm:high"
	llmMarkMedium  = "llm:medium"
	llmMarkLow     = "llm:low"
	llmMarkInvalid = "llm:invalid"
	llmMark503     = "llm:503"
)

// The limits of the LLM step that FR-17 sets. The tests use their own copy,
// so a change of maxLLMTools or llmWorkers in scan_llm.go fails them.
const (
	llmWantCap     = 500 // tools in one scan
	llmWantWorkers = 4   // requests at the same time
)

// The fixed texts of an LLM finding in the terminal report.
const (
	llmHead001   = "MOAT-LLM-001  " + llm.Title + " [LLM]"
	llmHead002   = "MOAT-LLM-002  " + llm.InvalidTitle + " [LLM]"
	llmSourceTxt = "LLM classification (advisory)"
)

// llmAnswerFor returns the answer for in from the marker in its description:
// a verdict, an error that wraps llm.ErrInvalidOutput, or an
// *llm.StatusError with code 503 (which wraps llm.ErrProvider).
func llmAnswerFor(in llm.Input) (llm.Verdict, error) {
	switch d := in.Description; {
	case strings.Contains(d, llmMark503):
		return llm.Verdict{}, &llm.StatusError{Code: http.StatusServiceUnavailable}
	case strings.Contains(d, llmMarkInvalid):
		return llm.Verdict{}, fmt.Errorf("%w: test", llm.ErrInvalidOutput)
	case strings.Contains(d, llmMarkHigh):
		return llm.Verdict{Risk: llm.RiskHigh, Category: llm.CategoryCredentialAccess}, nil
	case strings.Contains(d, llmMarkMedium):
		return llm.Verdict{Risk: llm.RiskMedium, Category: llm.CategoryHiddenInstructions}, nil
	case strings.Contains(d, llmMarkLow):
		return llm.Verdict{Risk: llm.RiskLow, Category: llm.CategoryOther}, nil
	default:
		return llm.Verdict{Risk: llm.RiskNone, Category: llm.CategoryOther}, nil
	}
}

// llmFake is a fake toolClassifier. It records each input and counts the
// calls that run at the same time. It is safe for concurrent use.
type llmFake struct {
	// answer gives the answer for one input. Nil means llmAnswerFor.
	answer func(llm.Input) (llm.Verdict, error)
	// before, when not nil, runs first in each call, with the context of
	// the call.
	before func(ctx context.Context)
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
	for {
		m := f.maxInFlight.Load()
		if n <= m || f.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}
	f.mu.Lock()
	f.inputs = append(f.inputs, in)
	f.mu.Unlock()

	if f.before != nil {
		f.before(ctx)
	}
	if f.shuffle {
		for range rand.IntN(200) { //nolint:gosec // G404: test order noise, not security
			runtime.Gosched()
		}
	}
	if err := ctx.Err(); err != nil {
		return llm.Verdict{}, fmt.Errorf("test: stopped: %w", err)
	}
	if f.answer != nil {
		return f.answer(in)
	}
	return llmAnswerFor(in)
}

// received returns the inputs so far, sorted by tool name.
func (f *llmFake) received() []llm.Input {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.inputs)
	slices.SortFunc(out, func(a, b llm.Input) int { return strings.Compare(a.ToolName, b.ToolName) })
	return out
}

// llmFactory is the cli.newClassifier of a test. It counts its calls and keeps
// the last config. With a nil cl, every call fails the test: the scan must
// not build a client.
type llmFactory struct {
	t     *testing.T
	cl    toolClassifier
	calls atomic.Int32

	mu  sync.Mutex
	cfg llm.Config
}

// newClassifier has the type of cli.newClassifier.
func (f *llmFactory) newClassifier(cfg llm.Config) (toolClassifier, error) {
	f.calls.Add(1)
	if f.cl == nil {
		f.t.Errorf("cli.newClassifier was called, want no LLM client")
		return nil, errors.New("test: no LLM client")
	}
	f.mu.Lock()
	f.cfg = cfg
	f.mu.Unlock()
	return f.cl, nil
}

// config returns the config of the last call.
func (f *llmFactory) config() llm.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}

// llmCLI builds a cli for the world e with the inspector insp and the factory
// f. Its environment holds the API key llmTestKey.
func llmCLI(e *pinEnv, insp inspect.Inspector, f *llmFactory) (*cli, *bytes.Buffer, *bytes.Buffer) {
	e.t.Helper()
	c, stdout, stderr := e.cli(insp)
	c.getenv = fakeGetenv(map[string]string{"XDG_CONFIG_HOME": e.xdg, "HOME": e.home, llm.KeyEnv: llmTestKey})
	c.newClassifier = f.newClassifier
	return c, stdout, stderr
}

// llmRun runs "mcpmoat scan --config <file> args..." on c and checks the
// rules that hold for every run: the key never shows and no raw escape byte
// shows.
func llmRun(t *testing.T, e *pinEnv, c *cli, stdout, stderr *bytes.Buffer, args ...string) pinRunResult {
	t.Helper()
	code := c.dispatch(append([]string{"scan", "--config", e.config}, args...))
	r := pinRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
	llmAssertNoKey(t, llmTestKey, r.stdout, r.stderr)
	assertNoEscape(t, r.stdout, r.stderr)
	return r
}

// llmScan runs one scan of e with a fake classifier cl (nil: no client may be
// built). The inspector gives each server its tools.
func llmScan(t *testing.T, e *pinEnv, tools map[string][]inspect.Tool, cl toolClassifier, args ...string) pinRunResult {
	t.Helper()
	f := &llmFactory{t: t, cl: cl}
	c, stdout, stderr := llmCLI(e, fakeServers(tools), f)
	return llmRun(t, e, c, stdout, stderr, args...)
}

// llmEnv returns a pinEnv whose config has one stdio server for each name in
// tools.
func llmEnv(t *testing.T, tools map[string][]inspect.Tool) *pinEnv {
	t.Helper()
	servers := make(map[string]any, len(tools))
	for name := range tools {
		servers[name] = map[string]any{"command": "npx", "args": []string{"@acme/fixture-clean@2.0.0"}}
	}
	return newPinEnv(t, servers)
}

// llmAssertNoKey fails the test when key, or a part of it of secretPartLen bytes
// or more, shows in one of the outputs.
func llmAssertNoKey(t *testing.T, key string, outputs ...string) {
	t.Helper()
	for _, out := range outputs {
		if part, ok := secretPartLeak(key, out); ok {
			t.Errorf("output holds a part of the API key (%q)\noutput:\n%s", part, out)
		}
	}
}

// llmWarning returns the exact warning line that scan --llm prints for the
// provider and host.
func llmWarning(provider, host string) string {
	return scanWarnPrefix + "--llm sends the name and description of every tool to the LLM provider " +
		provider + " at " + host + ". This data leaves your machine."
}

// llmSplitFindings returns the LLM findings and the rule findings of found
// (from parseFindings), each in the printed order.
func llmSplitFindings(found []scanFinding) (llmRows, ruleRows []scanFinding) {
	for _, f := range found {
		if f.LLM {
			llmRows = append(llmRows, f)
		} else {
			ruleRows = append(ruleRows, f)
		}
	}
	return llmRows, ruleRows
}

// llmFindingText returns all the parsed parts of f as one string, in Go
// syntax, for comparisons. Two findings with the same text have the same
// first line and the same detail lines in the same order.
func llmFindingText(f scanFinding) string { return fmt.Sprintf("%#v", f) }

// llmHit is the part of an LLM finding that the tests compare: rule, severity,
// server name and tool.
type llmHit struct {
	rule, severity, server, tool string
}

// llmRowsOf returns the rule, the severity, the server name and the tool of
// each LLM finding of found (from parseFindings), in order. It also checks the
// fixed parts of each LLM finding: the title (parseFindings checks the [LLM]
// marker), the Source line right after the Server line, the risk and the fix
// texts.
func llmRowsOf(t *testing.T, found []scanFinding) []llmHit {
	t.Helper()
	var rows []llmHit
	for _, f := range found {
		if !f.LLM {
			continue
		}
		switch f.RuleID {
		case llm.RuleID:
			if f.Title != llm.Title {
				t.Errorf("%s title = %q, want %q", f.RuleID, f.Title, llm.Title)
			}
			if f.Fix != llm.Remediation {
				t.Errorf("%s Fix = %q, want %q", f.RuleID, f.Fix, llm.Remediation)
			}
		case llm.RuleIDInvalid:
			if f.Title != llm.InvalidTitle {
				t.Errorf("%s title = %q, want %q", f.RuleID, f.Title, llm.InvalidTitle)
			}
			if f.Risk != llm.InvalidText || f.Fix != llm.InvalidRemediation {
				t.Errorf("%s Risk, Fix = %q, %q; want the fixed texts of package llm", f.RuleID, f.Risk, f.Fix)
			}
			if f.Severity != "medium" {
				t.Errorf("%s is in group %q, want medium", f.RuleID, f.Severity)
			}
		default:
			t.Errorf("finding %s %q has the [LLM] marker but is not an LLM rule", f.RuleID, f.Title)
		}
		// The Source line comes right after the Server line.
		if len(f.Details) < 2 || !strings.HasPrefix(f.Details[0], "Server: ") || f.Details[1] != "Source: "+llmSourceTxt {
			t.Errorf("LLM finding %s details = %q, want the Server line and then \"Source: %s\"", f.RuleID, f.Details, llmSourceTxt)
		}
		tool, _, _ := strings.Cut(f.Tool, " ")
		rows = append(rows, llmHit{f.RuleID, f.Severity, f.Name, tool})
	}
	return rows
}

// llmJSONRows returns the LLM findings of a JSON document, in order, and
// checks that every finding has the right source: "llm" for an LLM rule and
// "rule" for every other rule.
func llmJSONRows(t *testing.T, doc report.ScanReport) []llmHit {
	t.Helper()
	var rows []llmHit
	for _, f := range doc.Findings {
		isLLM := strings.HasPrefix(f.RuleID, "MOAT-LLM-")
		want := report.SourceRule
		if isLLM {
			want = report.SourceLLM
		}
		if f.Source != want {
			t.Errorf("finding %s of %s has source %q, want %q", f.RuleID, f.Server, f.Source, want)
		}
		if isLLM {
			if f.Field != "tool" {
				t.Errorf("finding %s has field %q, want \"tool\"", f.RuleID, f.Field)
			}
			rows = append(rows, llmHit{f.RuleID, f.Severity, f.Server, f.Key})
		}
	}
	return rows
}

// llmGuardWorld is a world whose hooks count every use, for the usage error
// tests: a scan that stops at its flags must not read a config, inspect a
// server or build a client.
type llmGuardWorld struct {
	c              *cli
	stdout, stderr *bytes.Buffer
	insp           *inspecttest.Fake
	factory        *llmFactory
	dirCalls       atomic.Int32
}

// newLLMGuardWorld builds a guard world. Its home holds a config with one
// server, so a scan that went on would inspect it. env is the environment of
// the cli.
func newLLMGuardWorld(t *testing.T, env map[string]string) *llmGuardWorld {
	t.Helper()
	home := t.TempDir()
	writeServers(t, home, ".claude.json", oneServer("srv"))
	w := &llmGuardWorld{
		insp:    fakeServers(map[string][]inspect.Tool{"srv": {mkTool("t1", llmMarkHigh)}}),
		factory: &llmFactory{t: t, cl: &llmFake{}},
	}
	w.c, w.stdout, w.stderr = dirsCLI(t, home, t.TempDir())
	w.c.homeDir = func() (string, error) { w.dirCalls.Add(1); return home, nil }
	w.c.getwd = func() (string, error) { w.dirCalls.Add(1); return t.TempDir(), nil }
	w.c.getenv = fakeGetenv(env)
	w.c.inspector = w.insp
	w.c.newClassifier = w.factory.newClassifier
	return w
}

// llmCountingServer starts a loopback server that counts its connections. A
// test passes its URL as --llm-base-url to prove that no request is made.
func llmCountingServer(t *testing.T) (url string, conns *atomic.Int32) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	conns = countNewConns(srv)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL, conns
}

// TestScanLLMUsageErrors checks every usage error of the LLM flags (FR-17,
// FR-16): exit code 2, empty stdout, one error line and the usage hint on
// stderr, and no warning. The flags are checked before anything else, so no
// config is read, no server is inspected, no client is built and the server
// at --llm-base-url gets no connection. A message about the key names
// MCPMOAT_LLM_API_KEY and never holds the key.
func TestScanLLMUsageErrors(t *testing.T) {
	t.Parallel()

	const keyCanary = "sk-badkey-canary-Lm3Pq9Xv"
	// baseURLCanary is a base URL with a password. No output may hold the
	// password.
	const passCanary = "CANARYPASS"
	const baseURLCanary = "https://user:" + passCanary + "@host.example/v1"
	validKey := map[string]string{llm.KeyEnv: llmTestKey}
	tests := []struct {
		name string
		args []string // "$SRV" is replaced with the URL of the counting server
		env  map[string]string
		want string // the error line after "mcpmoat scan: "
		// keyName is true when the message must name MCPMOAT_LLM_API_KEY.
		keyName bool
	}{
		{name: "provider without --llm", args: []string{"--llm-provider", "anthropic"}, env: validKey,
			want: "--llm-provider needs --llm"},
		{name: "model without --llm", args: []string{"--llm-model", "m1"}, env: validKey,
			want: "--llm-model needs --llm"},
		{name: "base URL without --llm", args: []string{"--llm-base-url", "$SRV"}, env: validKey,
			want: "--llm-base-url needs --llm"},
		{name: "--llm=false with a model", args: []string{"--llm=false", "--llm-model", "m1"}, env: validKey,
			want: "--llm-model needs --llm"},
		{name: "with --no-connect", args: []string{"--llm", "--no-connect", "--llm-base-url", "$SRV"}, env: validKey,
			want: "--llm cannot be used with --no-connect: the LLM needs a connection to each server to get its tools"},
		{name: "unknown provider", args: []string{"--llm", "--llm-provider", "bogus", "--llm-base-url", "$SRV"}, env: validKey,
			want: `--llm-provider: unknown LLM provider: use "anthropic" or "openai"`},
		{name: "provider in upper case", args: []string{"--llm", "--llm-provider", "OpenAI", "--llm-model", "m1"}, env: validKey,
			want: `--llm-provider: unknown LLM provider: use "anthropic" or "openai"`},
		{name: "openai without a model", args: []string{"--llm", "--llm-provider", "openai", "--llm-base-url", "$SRV"}, env: validKey,
			want: "--llm-provider openai needs --llm-model"},
		{name: "http base URL on a public host", args: []string{"--llm", "--llm-base-url", "http://llm.example.invalid"}, env: validKey,
			want: "--llm-base-url: invalid LLM base URL: http is allowed only for a loopback host, use https"},
		{name: "http base URL on example.com", args: []string{"--llm", "--llm-base-url", "http://example.com"}, env: validKey,
			want: "--llm-base-url: invalid LLM base URL: http is allowed only for a loopback host, use https"},
		// A name that starts like a loopback address is not a loopback host.
		{name: "http base URL on a name that starts with 127.0.0.1", args: []string{"--llm", "--llm-base-url", "http://127.0.0.1.example.com:8080/v1"}, env: validKey,
			want: "--llm-base-url: invalid LLM base URL: http is allowed only for a loopback host, use https"},
		{name: "base URL with user info", args: []string{"--llm", "--llm-base-url", "https://u:" + discovertest.CanaryURL + "@llm.example.invalid"}, env: validKey,
			want: "--llm-base-url: invalid LLM base URL: user info is not allowed"},
		{name: "base URL with a query", args: []string{"--llm", "--llm-base-url", "https://llm.example.invalid/?k=" + discovertest.CanaryURL}, env: validKey,
			want: "--llm-base-url: invalid LLM base URL: a query or fragment is not allowed"},
		{name: "base URL with another scheme", args: []string{"--llm", "--llm-base-url", "ftp://llm.example.invalid"}, env: validKey,
			want: "--llm-base-url: invalid LLM base URL: the scheme must be https"},
		{name: "base URL without a host", args: []string{"--llm", "--llm-base-url", "https:///v1"}, env: validKey,
			want: "--llm-base-url: invalid LLM base URL: the URL must have a host"},
		{name: "empty base URL", args: []string{"--llm", "--llm-base-url", ""}, env: validKey,
			want: "--llm-base-url needs a URL"},
		{name: "base URL that looks like a flag", args: []string{"--llm-base-url", "--llm"}, env: validKey,
			want: "--llm-base-url needs a URL"},
		{name: "base URL given twice, canary first", args: []string{"--llm", "--llm-base-url", baseURLCanary, "--llm-base-url", "$SRV"}, env: validKey,
			want: "--llm-base-url given more than once"},
		{name: "base URL given twice, canary second", args: []string{"--llm", "--llm-base-url", "$SRV", "--llm-base-url", baseURLCanary}, env: validKey,
			want: "--llm-base-url given more than once"},
		{name: "model given twice", args: []string{"--llm", "--llm-model", "a", "--llm-model", "b"}, env: validKey,
			want: `invalid value "b" for flag -llm-model: --llm-model given more than once`},
		{name: "model with a space", args: []string{"--llm", "--llm-model", "bad model", "--llm-base-url", "$SRV"}, env: validKey,
			want: "--llm-model: invalid LLM model name: only visible ASCII characters are allowed"},
		{name: "no key", args: []string{"--llm", "--llm-base-url", "$SRV"}, env: nil,
			want: "--llm: MCPMOAT_LLM_API_KEY is not set", keyName: true},
		{name: "empty key", args: []string{"--llm", "--llm-base-url", "$SRV"}, env: map[string]string{llm.KeyEnv: ""},
			want: "--llm: MCPMOAT_LLM_API_KEY is not set", keyName: true},
		{name: "key with a space", args: []string{"--llm", "--llm-base-url", "$SRV"}, env: map[string]string{llm.KeyEnv: keyCanary + " x"},
			want: "--llm: invalid MCPMOAT_LLM_API_KEY: only visible ASCII characters are allowed (no spaces, tabs or line breaks)", keyName: true},
		{name: "key with a line break", args: []string{"--llm", "--llm-base-url", "$SRV"}, env: map[string]string{llm.KeyEnv: keyCanary + "\r\nX-Injected: 1"},
			want: "--llm: invalid MCPMOAT_LLM_API_KEY: only visible ASCII characters are allowed (no spaces, tabs or line breaks)", keyName: true},
		{name: "key with an escape", args: []string{"--llm", "--llm-base-url", "$SRV"}, env: map[string]string{llm.KeyEnv: keyCanary + "\x1b[31m"},
			want: "--llm: invalid MCPMOAT_LLM_API_KEY: only visible ASCII characters are allowed (no spaces, tabs or line breaks)", keyName: true},
		{name: "key too long", args: []string{"--llm", "--llm-base-url", "$SRV"}, env: map[string]string{llm.KeyEnv: keyCanary + strings.Repeat("k", llm.MaxKeyBytes)},
			want: "--llm: invalid MCPMOAT_LLM_API_KEY: longer than 4096 bytes", keyName: true},
		{name: "openai with a bad key", args: []string{"--llm", "--llm-provider", "openai", "--llm-model", "m1", "--llm-base-url", "$SRV"}, env: map[string]string{llm.KeyEnv: keyCanary + "\t"},
			want: "--llm: invalid MCPMOAT_LLM_API_KEY: only visible ASCII characters are allowed (no spaces, tabs or line breaks)", keyName: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srvURL, conns := llmCountingServer(t)
			w := newLLMGuardWorld(t, tt.env)

			code := w.c.dispatch(append([]string{"scan"}, replaceToken(tt.args, "$SRV", srvURL)...))

			stdout, stderr := w.stdout.String(), w.stderr.String()
			if code != exitError {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitError, stderr)
			}
			assertEmptyStdout(t, stdout)
			assertStderrLines(t, stderr, []lineWant{exactLine(scanPrefix + tt.want), exactLine(usageHint)})
			if tt.keyName && !strings.Contains(stderr, llm.KeyEnv) {
				t.Errorf("stderr does not name %s:\n%s", llm.KeyEnv, stderr)
			}
			for _, secret := range []string{keyCanary, llmTestKey, discovertest.CanaryURL, passCanary} {
				if strings.Contains(stderr, secret) {
					t.Errorf("stderr holds the secret %q:\n%s", secret, stderr)
				}
				if strings.Contains(stdout, secret) {
					t.Errorf("stdout holds the secret %q:\n%s", secret, stdout)
				}
			}
			if strings.Contains(stderr, "leaves your machine") {
				t.Errorf("stderr holds the --llm warning, want only the usage error:\n%s", stderr)
			}
			assertTerminalSafe(t, stderr)
			if n := w.factory.calls.Load(); n != 0 {
				t.Errorf("cli.newClassifier was called %d times, want 0", n)
			}
			if calls := w.insp.Calls(); len(calls) != 0 {
				t.Errorf("the inspector was called for %v, want no call", calls)
			}
			if n := w.dirCalls.Load(); n != 0 {
				t.Errorf("homeDir or getwd was called %d times, want 0: scan read the configs", n)
			}
			if n := conns.Load(); n != 0 {
				t.Errorf("the --llm-base-url server got %d connections, want 0", n)
			}
		})
	}
}

// TestScanBaseURLHiddenInArgErrors checks that a --llm-base-url value never
// shows in the error of another flag, of the flag package or of the
// unexpected-argument check (FR-17, FR-16). The value can hold a
// user:password. Every form gives exit code 2 and empty stdout, the error
// line keeps its other text and shows hiddenArgText in place of the value,
// and no config is read.
func TestScanBaseURLHiddenInArgErrors(t *testing.T) {
	t.Parallel()

	const passCanary = "CANARYPASS7"
	const canaryURL = "https://user:" + passCanary + "@h.example"
	// quoteURL has a quote and a backslash, which the flag package escapes
	// with %q in `invalid value "..."`.
	const quoteURL = `https://user:` + passCanary + `"q\x@h.example`
	tests := []struct {
		name string
		args []string
		want string // the error line after "mcpmoat scan: "
	}{
		{name: "--timeout takes --llm-base-url=URL", args: []string{"--timeout", "--llm-base-url=" + canaryURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -timeout: parse error`},
		{name: "-timeout takes -llm-base-url=URL", args: []string{"-timeout", "-llm-base-url=" + canaryURL},
			want: `invalid value "-llm-base-url=(hidden)" for flag -timeout: parse error`},
		{name: "--timeout takes --llm-base-url URL", args: []string{"--timeout", "--llm-base-url", canaryURL},
			want: `invalid value "--llm-base-url" for flag -timeout: parse error`},
		{name: "--timeout takes -llm-base-url URL", args: []string{"--timeout", "-llm-base-url", canaryURL},
			want: `invalid value "-llm-base-url" for flag -timeout: parse error`},
		{name: "--timeout takes a value with a quote", args: []string{"--timeout", "--llm-base-url=" + quoteURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -timeout: parse error`},
		{name: "--concurrency takes --llm-base-url=URL", args: []string{"--concurrency", "--llm-base-url=" + canaryURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -concurrency: parse error`},
		{name: "--concurrency takes --llm-base-url URL", args: []string{"--concurrency", "--llm-base-url", canaryURL},
			want: `invalid value "--llm-base-url" for flag -concurrency: parse error`},
		{name: "--ignore takes --llm-base-url=URL", args: []string{"--ignore", "--llm-base-url=" + canaryURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -ignore: --ignore needs a rule ID`},
		{name: "-ignore takes -llm-base-url URL", args: []string{"-ignore", "-llm-base-url", canaryURL},
			want: `invalid value "-llm-base-url" for flag -ignore: --ignore needs a rule ID`},
		{name: "--fail-on takes --llm-base-url=URL", args: []string{"--fail-on", "--llm-base-url=" + canaryURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -fail-on: --fail-on needs low, medium, high or critical`},
		{name: "--fail-on takes --llm-base-url URL", args: []string{"--fail-on", "--llm-base-url", canaryURL},
			want: `invalid value "--llm-base-url" for flag -fail-on: --fail-on needs low, medium, high or critical`},
		{name: "--config takes --llm-base-url=URL", args: []string{"--config", "--llm-base-url=" + canaryURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -config: --config needs a file name`},
		{name: "--config takes --llm-base-url URL", args: []string{"--config", "--llm-base-url", canaryURL},
			want: `invalid value "--llm-base-url" for flag -config: --config needs a file name`},
		{name: "--llm-provider takes --llm-base-url=URL", args: []string{"--llm", "--llm-provider", "--llm-base-url=" + canaryURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -llm-provider: --llm-provider needs a provider name`},
		{name: "--llm-provider takes --llm-base-url URL", args: []string{"--llm", "--llm-provider", "--llm-base-url", canaryURL},
			want: `invalid value "--llm-base-url" for flag -llm-provider: --llm-provider needs a provider name`},
		{name: "--llm-model takes -llm-base-url=URL", args: []string{"--llm", "--llm-model", "-llm-base-url=" + canaryURL},
			want: `invalid value "-llm-base-url=(hidden)" for flag -llm-model: --llm-model needs a model name`},
		{name: "--llm-model takes --llm-base-url URL", args: []string{"--llm", "--llm-model", "--llm-base-url", canaryURL},
			want: `invalid value "--llm-base-url" for flag -llm-model: --llm-model needs a model name`},
		// The forms with "=": the value of another flag holds the base URL
		// flag, so the flag package quotes it whole in the error.
		{name: "--timeout=--llm-base-url=URL", args: []string{"--timeout=--llm-base-url=" + canaryURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -timeout: parse error`},
		{name: "-timeout=-llm-base-url=URL", args: []string{"-timeout=-llm-base-url=" + canaryURL},
			want: `invalid value "-llm-base-url=(hidden)" for flag -timeout: parse error`},
		{name: "--timeout= with a value with a quote", args: []string{"--timeout=--llm-base-url=" + quoteURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -timeout: parse error`},
		{name: "--timeout= with text before the flag name", args: []string{"--timeout=x--llm-base-url=" + canaryURL},
			want: `invalid value "x--llm-base-url=(hidden)" for flag -timeout: parse error`},
		{name: "--timeout= with the flag name twice", args: []string{"--timeout=--llm-base-url=a-llm-base-url=" + canaryURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -timeout: parse error`},
		{name: "--concurrency=---llm-base-url=URL", args: []string{"--concurrency=---llm-base-url=" + canaryURL},
			want: `invalid value "---llm-base-url=(hidden)" for flag -concurrency: parse error`},
		{name: "--ignore=--llm-base-url=URL", args: []string{"--ignore=--llm-base-url=" + canaryURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -ignore: --ignore needs a rule ID`},
		{name: "--fail-on=-llm-base-url=URL", args: []string{"--fail-on=-llm-base-url=" + canaryURL},
			want: `invalid value "-llm-base-url=(hidden)" for flag -fail-on: --fail-on needs low, medium, high or critical`},
		{name: "--config=--llm-base-url=URL", args: []string{"--config=--llm-base-url=" + canaryURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -config: --config needs a file name`},
		{name: "--llm=--llm-base-url=URL", args: []string{"--llm=--llm-base-url=" + canaryURL},
			want: `invalid boolean value "--llm-base-url=(hidden)" for -llm: parse error`},
		{name: "--llm-provider=--llm-base-url=URL", args: []string{"--llm", "--llm-provider=--llm-base-url=" + canaryURL},
			want: `invalid value "--llm-base-url=(hidden)" for flag -llm-provider: --llm-provider needs a provider name`},
		{name: "--timeout=--llm-base-url URL", args: []string{"--timeout=--llm-base-url", canaryURL},
			want: `invalid value "--llm-base-url" for flag -timeout: parse error`},
		{name: "flag not defined before the URL", args: []string{"--bogus", "--llm-base-url=" + canaryURL},
			want: "flag provided but not defined: -bogus"},
		{name: "flag not defined with the URL", args: []string{"--bogus=--llm-base-url=" + canaryURL},
			want: "flag provided but not defined: -bogus"},
		{name: "three dashes", args: []string{"---llm-base-url=" + canaryURL},
			want: "bad flag syntax: ---llm-base-url=(hidden)"},
		{name: "positional --llm-base-url=URL", args: []string{"extra", "--llm-base-url=" + canaryURL},
			want: `unexpected arguments ["extra" "--llm-base-url=(hidden)"]`},
		{name: "positional -llm-base-url URL", args: []string{"extra", "-llm-base-url", canaryURL},
			want: `unexpected arguments ["extra" "-llm-base-url" "(hidden)"]`},
		{name: "positional after --", args: []string{"--", "--llm-base-url=" + canaryURL},
			want: `unexpected arguments ["--llm-base-url=(hidden)"]`},
		{name: "positional after the flag", args: []string{"--llm-base-url", canaryURL, "extra"},
			want: `unexpected arguments ["extra"]`},
		{name: "positional --x=--llm-base-url=URL", args: []string{"--", "--x=--llm-base-url=" + canaryURL},
			want: `unexpected arguments ["--x=--llm-base-url=(hidden)"]`},
		{name: "positional --x=--llm-base-url URL", args: []string{"--", "--x=--llm-base-url", canaryURL},
			want: `unexpected arguments ["--x=--llm-base-url" "(hidden)"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := newLLMGuardWorld(t, map[string]string{llm.KeyEnv: llmTestKey})

			code := w.c.dispatch(append([]string{"scan"}, tt.args...))

			stdout, stderr := w.stdout.String(), w.stderr.String()
			if code != exitError {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, exitError, stderr)
			}
			assertEmptyStdout(t, stdout)
			if strings.Contains(stdout+stderr, passCanary) {
				t.Errorf("the output holds the password %q\nstdout:\n%s\nstderr:\n%s", passCanary, stdout, stderr)
			}
			assertStderrLines(t, stderr, []lineWant{exactLine(scanPrefix + tt.want), exactLine(usageHint)})
			assertTerminalSafe(t, stderr)
			if n := w.dirCalls.Load(); n != 0 {
				t.Errorf("homeDir or getwd was called %d times, want 0: scan read the configs", n)
			}
		})
	}
}

// TestArgHider checks newArgHider on its own: which arguments give a value,
// that the longest value wins, and that the zero argHider changes nothing.
func TestArgHider(t *testing.T) {
	t.Parallel()

	const passCanary = "CANARYPASS7"
	const canaryURL = "https://user:" + passCanary + "@h.example"
	tests := []struct {
		name string
		args []string
		in   string
		want string
	}{
		{name: "no value", args: []string{"--timeout", "5s"}, in: "--timeout 5s", want: "--timeout 5s"},
		{name: "empty inline value", args: []string{"--llm-base-url="}, in: "x --llm-base-url= y", want: "x --llm-base-url= y"},
		{name: "bare flag at the end", args: []string{"--llm-base-url"}, in: "--llm-base-url", want: "--llm-base-url"},
		{name: "inline value", args: []string{"--llm-base-url=SECRET"}, in: "a SECRET b", want: "a (hidden) b"},
		{name: "next argument", args: []string{"-llm-base-url", "SECRET"}, in: "a SECRET b", want: "a (hidden) b"},
		{name: "longest first", args: []string{"--llm-base-url=AB", "--llm-base-url=ABCD"}, in: "ABCD AB", want: "(hidden) (hidden)"},
		{name: "quoted form", args: []string{`--llm-base-url=a"b`}, in: `"a\"b" a"b`, want: `"(hidden)" (hidden)`},
		{name: "other flag name", args: []string{"--llm-base-urlx=SECRET"}, in: "SECRET", want: "SECRET"},
		{name: "not a flag", args: []string{"llm-base-url=SECRET"}, in: "SECRET", want: "SECRET"},
		// The flag name inside the value of another flag.
		{name: "value of another flag", args: []string{"--timeout=--llm-base-url=" + canaryURL},
			in: `"--llm-base-url=` + canaryURL + `"`, want: `"--llm-base-url=(hidden)"`},
		{name: "value of a bool flag", args: []string{"--llm=-llm-base-url=" + canaryURL},
			in: `"-llm-base-url=` + canaryURL + `"`, want: `"-llm-base-url=(hidden)"`},
		{name: "text before the flag name", args: []string{"--ignore=x---llm-base-url=" + canaryURL},
			in: `"x---llm-base-url=` + canaryURL + `"`, want: `"x---llm-base-url=(hidden)"`},
		{name: "flag name twice", args: []string{"--a=--llm-base-url=b-llm-base-url=" + canaryURL},
			in: canaryURL + " b-llm-base-url=" + canaryURL, want: "(hidden) (hidden)"},
		{name: "flag name at the end of a value", args: []string{"--timeout=--llm-base-url", canaryURL},
			in: "a " + canaryURL, want: "a (hidden)"},
		{name: "positional with the flag name", args: []string{"extra-llm-base-url=" + canaryURL},
			in: canaryURL, want: "(hidden)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := newArgHider(tt.args, flagLLMBaseURL).hide(tt.in)
			if strings.Contains(got, passCanary) {
				t.Errorf("hide(%q) = %q, which holds the password %q", tt.in, got, passCanary)
			}
			if got != tt.want {
				t.Errorf("hide(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
	if got := (argHider{}).hide("SECRET"); got != "SECRET" {
		t.Errorf("zero argHider hide() = %q, want the text as it is", got)
	}
}

// TestScanLLMConfig checks how the LLM flags and the key reach the client
// config (FR-17): the defaults of each provider, the key from
// MCPMOAT_LLM_API_KEY only, no dial hook in production, and the host that the
// warning names. The fake classifier sends no request.
func TestScanLLMConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		want     llm.Config // APIKey and Dial are checked apart
		wantHost string
	}{
		{
			name:     "defaults",
			want:     llm.Config{Provider: llm.ProviderAnthropic, Model: llm.DefaultAnthropicModel, BaseURL: llm.DefaultAnthropicBaseURL},
			wantHost: "api.anthropic.com",
		},
		{
			name:     "anthropic with a model",
			args:     []string{"--llm-provider", "anthropic", "--llm-model", "claude-test-1"},
			want:     llm.Config{Provider: llm.ProviderAnthropic, Model: "claude-test-1", BaseURL: llm.DefaultAnthropicBaseURL},
			wantHost: "api.anthropic.com",
		},
		{
			name:     "openai",
			args:     []string{"--llm-provider", "openai", "--llm-model", "gpt-test"},
			want:     llm.Config{Provider: llm.ProviderOpenAI, Model: "gpt-test", BaseURL: llm.DefaultOpenAIBaseURL},
			wantHost: "api.openai.com",
		},
		{
			name:     "loopback base URL with a final slash",
			args:     []string{"--llm-provider", "openai", "--llm-model", "llama3:8b", "--llm-base-url", "http://127.0.0.1:11434/v1/"},
			want:     llm.Config{Provider: llm.ProviderOpenAI, Model: "llama3:8b", BaseURL: "http://127.0.0.1:11434/v1"},
			wantHost: "127.0.0.1:11434",
		},
		{
			name:     "https base URL",
			args:     []string{"--llm-base-url", "https://llm.example.invalid:8443/api"},
			want:     llm.Config{Provider: llm.ProviderAnthropic, Model: llm.DefaultAnthropicModel, BaseURL: "https://llm.example.invalid:8443/api"},
			wantHost: "llm.example.invalid:8443",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tools := map[string][]inspect.Tool{"srv": {mkTool("t1", "Add.")}}
			e := llmEnv(t, tools)
			f := &llmFactory{t: t, cl: &llmFake{}}
			c, stdout, stderr := llmCLI(e, fakeServers(tools), f)

			r := llmRun(t, e, c, stdout, stderr, append([]string{"--llm"}, tt.args...)...)

			if r.code != exitOK {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitOK, r.stderr)
			}
			if n := f.calls.Load(); n != 1 {
				t.Fatalf("newClassifier calls = %d, want 1", n)
			}
			got := f.config()
			if got.Provider != tt.want.Provider || got.Model != tt.want.Model || got.BaseURL != tt.want.BaseURL {
				t.Errorf("config = %s %q %q, want %s %q %q", got.Provider, got.Model, got.BaseURL, tt.want.Provider, tt.want.Model, tt.want.BaseURL)
			}
			if got.APIKey.Reveal() != llmTestKey {
				t.Errorf("the config does not hold the key from %s", llm.KeyEnv)
			}
			if got.Dial != nil {
				t.Errorf("config Dial is set, want nil (the default dialer)")
			}
			// The config prints as a mask, so a log of it holds no key.
			llmAssertNoKey(t, llmTestKey, fmt.Sprintf("%v %+v", got, got))
			assertStderrLines(t, r.stderr, []lineWant{
				exactLine(llmWarning(string(tt.want.Provider), tt.wantHost)),
				exactLine(newPinsNoticeLine("scan", e.pinsPath())),
				prefixLine(scanPrefix + "pinned "),
			})
		})
	}
}

// TestScanLLMWithoutFlag checks that a scan without --llm never builds a
// client (NFR-01), also when the key is set, and that the report has no LLM
// row and no LLM warning.
func TestScanLLMWithoutFlag(t *testing.T) {
	t.Parallel()

	tools := map[string][]inspect.Tool{"alpha": {mkTool("t1", llmMarkHigh)}}
	for _, args := range [][]string{nil, {"--json"}, {"--no-connect"}} {
		t.Run(strings.Join(append([]string{"scan"}, args...), " "), func(t *testing.T) {
			t.Parallel()
			e := llmEnv(t, tools)
			r := llmScan(t, e, tools, nil, args...)
			if r.code != exitOK {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitOK, r.stderr)
			}
			assertContainsNone(t, "stdout", r.stdout, []string{"MOAT-LLM", "[LLM]", `"llm"`})
			// A scan that connects creates pins.json and prints the new pins
			// file notice. Its temp path holds the test name, which holds
			// "LLM", so check the rest of stderr. --no-connect writes no pins.
			rest := r.stderr
			if !slices.Contains(args, "--no-connect") {
				rest = withoutPinsFileNotice(t, r.stderr, "scan", e.pinsPath())
			}
			assertContainsNone(t, "stderr", rest, []string{"LLM", "--llm"})
		})
	}
}

// llmNoToolLine is the stderr line of a scan --llm with no tool to classify.
const llmNoToolLine = scanPrefix + "--llm had no tool to classify\n"

// TestScanLLMNoTool checks the notice of a scan --llm that sends no tool: no
// server in the config, a server that failed, or a server with no tools.
// The notice shows once on stderr, the classifier gets no call, and the exit
// code and the JSON report are the same as without --llm. A scan with a tool
// to classify, and a scan without --llm, print no notice. When the pin step
// failed (pins.json cannot be read, or inspect.Run refused its input), the
// error on stderr is the cause, so the notice does not show either.
func TestScanLLMNoTool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		servers map[string]any
		insp    func() inspect.Inspector
		// corruptPins writes a pins.json that cannot be read.
		corruptPins bool
		calls       int32 // the calls of the classifier with --llm
		notice      bool
	}{
		{
			name:    "no server",
			servers: map[string]any{},
			insp:    func() inspect.Inspector { return fakeServers(nil) },
			notice:  true,
		},
		{
			name:    "server failed",
			servers: oneServer("srv"),
			insp:    func() inspect.Inspector { return failingFake("srv") },
			notice:  true,
		},
		{
			name:    "server with no tools",
			servers: oneServer("srv"),
			insp:    func() inspect.Inspector { return fakeServers(map[string][]inspect.Tool{"srv": nil}) },
			notice:  true,
		},
		{
			name:    "server with a tool",
			servers: oneServer("srv"),
			insp:    func() inspect.Inspector { return fakeServers(map[string][]inspect.Tool{"srv": {mkTool("t1", "Add.")}}) },
			calls:   1,
		},
		{
			name:        "pins unreadable",
			servers:     oneServer("srv"),
			insp:        func() inspect.Inspector { return fakeServers(map[string][]inspect.Tool{"srv": {mkTool("t1", "Add.")}}) },
			corruptPins: true,
		},
		{
			// A nil inspector makes inspect.Run refuse its input.
			name:    "inspect.Run failed",
			servers: oneServer("srv"),
			insp:    func() inspect.Inspector { return nil },
		},
	}
	for _, tt := range tests {
		for _, jsonOut := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%v", tt.name, jsonOut), func(t *testing.T) {
				t.Parallel()
				var extra []string
				if jsonOut {
					extra = []string{"--json"}
				}
				// The same world without --llm gives the exit code and the
				// report to compare with.
				base := newPinEnv(t, tt.servers)
				if tt.corruptPins {
					writeTestFile(t, filepath.Join(base.xdg, "mcpmoat"), "pins.json", "{this is not json")
				}
				bc, bout, berr := llmCLI(base, tt.insp(), &llmFactory{t: t})
				want := llmRun(t, base, bc, bout, berr, extra...)
				if strings.Contains(want.stderr, "--llm") {
					t.Errorf("stderr without --llm names --llm:\n%s", want.stderr)
				}

				e := newPinEnv(t, tt.servers)
				if tt.corruptPins {
					writeTestFile(t, filepath.Join(e.xdg, "mcpmoat"), "pins.json", "{this is not json")
				}
				fake := &llmFake{}
				c, stdout, stderr := llmCLI(e, tt.insp(), &llmFactory{t: t, cl: fake})
				r := llmRun(t, e, c, stdout, stderr, append([]string{"--llm"}, extra...)...)

				if r.code != want.code {
					t.Errorf("exit code = %d, want %d as without --llm\nstderr:\n%s", r.code, want.code, r.stderr)
				}
				if n := fake.calls.Load(); n != tt.calls {
					t.Errorf("classifier calls = %d, want %d", n, tt.calls)
				}
				wantCount := 0
				if tt.notice {
					wantCount = 1
				}
				if n := strings.Count(r.stderr, llmNoToolLine); n != wantCount {
					t.Errorf("stderr holds %q %d times, want %d\nstderr:\n%s", llmNoToolLine, n, wantCount, r.stderr)
				}
				if jsonOut {
					got, base := decodeScanJSON(t, r.stdout), decodeScanJSON(t, want.stdout)
					if got.Complete != base.Complete {
						t.Errorf("complete = %v, want %v as without --llm", got.Complete, base.Complete)
					}
					if len(llmJSONRows(t, got)) != 0 {
						t.Errorf("JSON has LLM findings, want none:\n%s", r.stdout)
					}
				}
			})
		}
	}
}

// TestScanLLMMarking checks how the report marks an LLM finding (FR-17): in
// the terminal, the title ends with [LLM] and a Source line follows the
// Server line; in the JSON document, the source is "llm" and the document
// follows schema version 2. A rule finding keeps no marker and the source
// "rule". The summary counts include the LLM findings.
func TestScanLLMMarking(t *testing.T) {
	t.Parallel()

	tools := map[string][]inspect.Tool{
		"alpha": {mkTool("t1", "Read files. "+llmMarkHigh), mkTool("t2", "Odd. "+llmMarkInvalid), mkTool("t3", "Add.")},
		"beta":  {mkTool("t4", "Notes. "+llmMarkMedium), mkTool("t5", "Log. "+llmMarkLow)},
	}
	servers := map[string]any{
		// MOAT-T4-003 (medium): a rule finding next to the LLM findings.
		"alpha": failOnMediumServer,
		"beta":  failOnCleanServer,
	}
	wantLLM := []llmHit{
		{llm.RuleID, "high", "alpha", "t1"},
		{llm.RuleIDInvalid, "medium", "alpha", "t2"},
		{llm.RuleID, "medium", "beta", "t4"},
		{llm.RuleID, "low", "beta", "t5"},
	}

	t.Run("terminal", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, servers)
		r := llmScan(t, e, tools, &llmFake{}, "--llm")
		if r.code != exitFindings {
			t.Errorf("exit code = %d, want %d (a high LLM finding)\nstderr:\n%s", r.code, exitFindings, r.stderr)
		}
		found := parseFindings(t, r.stdout)
		llmRows, ruleRows := llmSplitFindings(found)
		got := llmRowsOf(t, llmRows)
		// The terminal groups the findings by severity; inside a group they
		// keep the order of the servers, then of the tools.
		want := []llmHit{wantLLM[0], wantLLM[1], wantLLM[2], wantLLM[3]}
		if !slices.Equal(got, want) {
			t.Fatalf("LLM findings = %+v, want %+v\nstdout:\n%s", got, want, r.stdout)
		}
		// The risk text is the fixed text of the category, never model text.
		if f := llmRows[0]; f.Risk != llm.CategoryCredentialAccess.Text() || f.Tool != "t1 (credential-access)" {
			t.Errorf("t1 Risk, Tool = %q, %q; want %q, %q", f.Risk, f.Tool, llm.CategoryCredentialAccess.Text(), "t1 (credential-access)")
		}
		if f := llmRows[1]; f.Tool != "t2" {
			t.Errorf("t2 Tool = %q, want \"t2\" (no category for an invalid answer)", f.Tool)
		}
		if len(ruleRows) != 1 || ruleRows[0].RuleID != "MOAT-T4-003" {
			t.Fatalf("rule findings = %+v, want one MOAT-T4-003\nstdout:\n%s", ruleRows, r.stdout)
		}
		if f := ruleRows[0]; f.Source != "" || slices.ContainsFunc(f.Details, func(d string) bool { return strings.HasPrefix(d, "Source:") }) {
			t.Errorf("rule finding has the lines %q, want no Source line", f.Details)
		}
		// Raw checks on the text: the exact first lines and Source lines.
		if n := strings.Count(r.stdout, "[LLM]"); n != len(wantLLM) {
			t.Errorf("stdout holds [LLM] %d times, want %d", n, len(wantLLM))
		}
		if n := strings.Count(r.stdout, "\n  "+llmHead001+"\n"); n != 3 {
			t.Errorf("stdout holds the line %q %d times, want 3", llmHead001, n)
		}
		if n := strings.Count(r.stdout, "\n  "+llmHead002+"\n"); n != 1 {
			t.Errorf("stdout holds the line %q %d times, want 1", llmHead002, n)
		}
		if n := strings.Count(r.stdout, "    Source: "+llmSourceTxt+"\n"); n != len(wantLLM) {
			t.Errorf("stdout holds the Source line %d times, want %d", n, len(wantLLM))
		}
		// The summary counts the rule and the LLM findings of each server.
		perServer := map[string]int{}
		for _, f := range found {
			perServer[f.Name]++
		}
		for _, row := range summaryRows(t, r.stdout) {
			if row.Findings != perServer[row.Name] {
				t.Errorf("summary of %s counts %d findings, the FINDINGS block has %d", row.Name, row.Findings, perServer[row.Name])
			}
		}
	})

	t.Run("json", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, servers)
		r := llmScan(t, e, tools, &llmFake{}, "--llm", "--json")
		if r.code != exitFindings {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
		}
		doc := decodeScanJSON(t, r.stdout)
		if doc.SchemaVersion != 2 {
			t.Errorf("schema_version = %d, want 2", doc.SchemaVersion)
		}
		if !doc.Complete {
			t.Errorf("complete = false, want true")
		}
		if got := llmJSONRows(t, doc); !slices.Equal(got, wantLLM) {
			t.Errorf("LLM findings = %+v, want %+v\nstdout:\n%s", got, wantLLM, r.stdout)
		}
		ruleCount := 0
		for _, f := range doc.Findings {
			switch f.RuleID {
			case llm.RuleID:
				// The category is the related text of a MOAT-LLM-001 row.
				if f.Key == "t1" && f.Related != string(llm.CategoryCredentialAccess) {
					t.Errorf("t1 related = %q, want %q", f.Related, llm.CategoryCredentialAccess)
				}
			case llm.RuleIDInvalid:
				if f.Related != "" {
					t.Errorf("MOAT-LLM-002 related = %q, want empty", f.Related)
				}
			default:
				ruleCount++
			}
		}
		if ruleCount != 1 {
			t.Errorf("JSON has %d rule findings, want 1 (MOAT-T4-003)", ruleCount)
		}
		// Raw check on the text too: the decoder ignores the case of a key.
		if n := strings.Count(r.stdout, `"source": "llm"`); n != len(wantLLM) {
			t.Errorf("stdout holds %q %d times, want %d", `"source": "llm"`, n, len(wantLLM))
		}
		if n := strings.Count(r.stdout, `"source": "rule"`); n != 1 {
			t.Errorf("stdout holds %q %d times, want 1", `"source": "rule"`, n)
		}
	})
}

// TestScanLLMFailOn checks that an LLM finding counts for --fail-on with the
// severity of the verdict (FR-16, FR-17). MOAT-LLM-002 is medium. Risk none
// gives no finding. The server has no rule finding.
func TestScanLLMFailOn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mark string
		// want is the exit code for --fail-on low, medium, high (the
		// default) and critical.
		want perLevel[int]
		rule string // the rule of the one LLM finding; "" for none
	}{
		{mark: llmMarkHigh, want: perLevel[int]{exitFindings, exitFindings, exitFindings, exitOK}, rule: llm.RuleID},
		{mark: llmMarkMedium, want: perLevel[int]{exitFindings, exitFindings, exitOK, exitOK}, rule: llm.RuleID},
		{mark: llmMarkLow, want: perLevel[int]{exitFindings, exitOK, exitOK, exitOK}, rule: llm.RuleID},
		{mark: llmMarkInvalid, want: perLevel[int]{exitFindings, exitFindings, exitOK, exitOK}, rule: llm.RuleIDInvalid},
		{mark: "risk none", want: perLevel[int]{exitOK, exitOK, exitOK, exitOK}},
	}
	for _, tt := range tests {
		tools := map[string][]inspect.Tool{"srv": {mkTool("t1", "Text. "+tt.mark)}}
		// run scans with args after --llm and checks the exit code and the
		// one LLM finding.
		run := func(t *testing.T, wantCode int, args ...string) {
			t.Helper()
			r := llmScan(t, llmEnv(t, tools), tools, &llmFake{}, append([]string{"--llm"}, args...)...)
			if r.code != wantCode {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, wantCode, r.stdout, r.stderr)
			}
			rows := llmRowsOf(t, parseFindings(t, r.stdout))
			switch {
			case tt.rule == "" && len(rows) != 0:
				t.Errorf("LLM findings = %+v, want none", rows)
			case tt.rule != "" && (len(rows) != 1 || rows[0].rule != tt.rule):
				t.Errorf("LLM findings = %+v, want one %s", rows, tt.rule)
			}
		}
		t.Run(tt.mark+"/default", func(t *testing.T) {
			t.Parallel()
			run(t, tt.want.high)
		})
		for _, level := range failOnLevels {
			t.Run(tt.mark+"/"+string(level), func(t *testing.T) {
				t.Parallel()
				run(t, tt.want.at(t, level), "--fail-on", string(level))
			})
		}
	}
}

// TestScanLLMTruncatedFloor checks that a verdict for a cut tool text
// (llm.Verdict.Truncated) is never below medium. With risk none or low, the
// tool gets one MOAT-LLM-001 row with severity medium, the fixed text
// llm.TruncatedText and the category "other", whatever category the model
// gave. With risk medium or high, the row of the model stays as it is. Without
// a cut, risk none still gives no row.
func TestScanLLMTruncatedFloor(t *testing.T) {
	t.Parallel()

	long := "Reads a file. " + strings.Repeat("a", 20<<10) // over llm.MaxDescriptionBytes
	tests := []struct {
		name     string
		desc     string
		risk     llm.Risk
		category llm.Category
		// severity, related and risk are the parts of the one LLM row; an
		// empty severity means no row.
		severity, related, riskText string
	}{
		{name: "none cut", desc: long, risk: llm.RiskNone, category: llm.CategoryCredentialAccess,
			severity: "medium", related: string(llm.CategoryOther), riskText: llm.TruncatedText},
		{name: "low cut", desc: long, risk: llm.RiskLow, category: llm.CategoryDataExfiltration,
			severity: "medium", related: string(llm.CategoryOther), riskText: llm.TruncatedText},
		{name: "medium cut", desc: long, risk: llm.RiskMedium, category: llm.CategoryToolShadowing,
			severity: "medium", related: string(llm.CategoryToolShadowing), riskText: llm.CategoryToolShadowing.Text()},
		{name: "high cut", desc: long, risk: llm.RiskHigh, category: llm.CategoryCredentialAccess,
			severity: "high", related: string(llm.CategoryCredentialAccess), riskText: llm.CategoryCredentialAccess.Text()},
		{name: "none not cut", desc: "Reads a file.", risk: llm.RiskNone, category: llm.CategoryOther},
		{name: "low not cut", desc: "Reads a file.", risk: llm.RiskLow, category: llm.CategoryDataExfiltration,
			severity: "low", related: string(llm.CategoryDataExfiltration), riskText: llm.CategoryDataExfiltration.Text()},
	}
	for _, tt := range tests {
		tools := map[string][]inspect.Tool{"srv": {mkTool("t1", tt.desc)}}
		// The fake sets Truncated as the real client does: when the
		// description is over llm.MaxDescriptionBytes.
		fake := func() *llmFake {
			return &llmFake{answer: func(in llm.Input) (llm.Verdict, error) {
				return llm.Verdict{Risk: tt.risk, Category: tt.category, Truncated: len(in.Description) > llm.MaxDescriptionBytes}, nil
			}}
		}
		var want []llmHit
		if tt.severity != "" {
			want = []llmHit{{llm.RuleID, tt.severity, "srv", "t1"}}
		}

		t.Run(tt.name+"/terminal", func(t *testing.T) {
			t.Parallel()
			r := llmScan(t, llmEnv(t, tools), tools, fake(), "--llm")
			llmRows, _ := llmSplitFindings(parseFindings(t, r.stdout))
			if got := llmRowsOf(t, llmRows); !slices.Equal(got, want) {
				t.Fatalf("LLM findings = %+v, want %+v\nstdout:\n%s\nstderr:\n%s", got, want, r.stdout, r.stderr)
			}
			if len(want) == 0 {
				return
			}
			f := llmRows[0]
			if f.Risk != tt.riskText {
				t.Errorf("Risk = %q, want %q", f.Risk, tt.riskText)
			}
			if wantTool := "t1 (" + tt.related + ")"; f.Tool != wantTool {
				t.Errorf("Tool = %q, want %q", f.Tool, wantTool)
			}
		})

		t.Run(tt.name+"/json", func(t *testing.T) {
			t.Parallel()
			r := llmScan(t, llmEnv(t, tools), tools, fake(), "--llm", "--json")
			doc := decodeScanJSON(t, r.stdout)
			if got := llmJSONRows(t, doc); !slices.Equal(got, want) {
				t.Fatalf("LLM findings = %+v, want %+v\nstdout:\n%s\nstderr:\n%s", got, want, r.stdout, r.stderr)
			}
			for _, f := range doc.Findings {
				if f.RuleID == llm.RuleID && f.Related != tt.related {
					t.Errorf("related = %q, want %q", f.Related, tt.related)
				}
			}
		})
	}
}

// TestScanLLMTruncatedUnusable checks the floor for a cut tool text when the
// model gives no usable answer (llm.ErrInvalidOutput): the tool gets the same
// MOAT-LLM-001 medium row as a cut verdict with risk none, and no MOAT-LLM-002
// row. So --ignore MOAT-LLM-002 does not hide the cut tool. Without a cut, an
// unusable answer still gives MOAT-LLM-002.
func TestScanLLMTruncatedUnusable(t *testing.T) {
	t.Parallel()

	long := "Reads a file. " + strings.Repeat("a", 20<<10) // over llm.MaxDescriptionBytes
	floor := []llmHit{{llm.RuleID, "medium", "srv", "t1"}}
	tests := []struct {
		name       string
		desc       string
		args       []string
		want       []llmHit
		wantStderr string // a line that stderr must hold; "" for none
	}{
		{name: "cut", desc: long, want: floor},
		{name: "cut with --ignore MOAT-LLM-002", desc: long, args: []string{"--ignore", llm.RuleIDInvalid}, want: floor},
		{name: "cut with --ignore MOAT-LLM-001", desc: long, args: []string{"--ignore", llm.RuleID},
			wantStderr: "mcpmoat scan: 1 finding ignored: MOAT-LLM-001 (1)\n"},
		{name: "not cut", desc: "Reads a file.", want: []llmHit{{llm.RuleIDInvalid, "medium", "srv", "t1"}}},
	}
	for _, tt := range tests {
		tools := map[string][]inspect.Tool{"srv": {mkTool("t1", tt.desc)}}
		// The fake answers as the real client does for an unusable answer:
		// only Truncated, set when the description is over
		// llm.MaxDescriptionBytes, with an error that wraps
		// llm.ErrInvalidOutput.
		fake := func() *llmFake {
			return &llmFake{answer: func(in llm.Input) (llm.Verdict, error) {
				return llm.Verdict{Truncated: len(in.Description) > llm.MaxDescriptionBytes}, fmt.Errorf("%w: test", llm.ErrInvalidOutput)
			}}
		}
		for _, jsonOut := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%v", tt.name, jsonOut), func(t *testing.T) {
				t.Parallel()
				args := append([]string{"--llm"}, tt.args...)
				if jsonOut {
					args = append(args, "--json")
				}
				r := llmScan(t, llmEnv(t, tools), tools, fake(), args...)
				// A medium row is below the default --fail-on high.
				if r.code != exitOK {
					t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitOK, r.stderr)
				}
				if jsonOut {
					doc := decodeScanJSON(t, r.stdout)
					if !doc.Complete {
						t.Errorf("complete = false, want true")
					}
					if got := llmJSONRows(t, doc); !slices.Equal(got, tt.want) {
						t.Errorf("LLM findings = %+v, want %+v\nstdout:\n%s", got, tt.want, r.stdout)
					}
					for _, f := range doc.Findings {
						if f.RuleID == llm.RuleID && f.Related != string(llm.CategoryOther) {
							t.Errorf("related = %q, want %q", f.Related, llm.CategoryOther)
						}
					}
				} else {
					llmRows, _ := llmSplitFindings(parseFindings(t, r.stdout))
					if got := llmRowsOf(t, llmRows); !slices.Equal(got, tt.want) {
						t.Fatalf("LLM findings = %+v, want %+v\nstdout:\n%s", got, tt.want, r.stdout)
					}
					if len(llmRows) == 1 && llmRows[0].RuleID == llm.RuleID {
						if f := llmRows[0]; f.Risk != llm.TruncatedText || f.Tool != "t1 ("+string(llm.CategoryOther)+")" {
							t.Errorf("Risk, Tool = %q, %q; want %q, %q", f.Risk, f.Tool, llm.TruncatedText, "t1 (other)")
						}
					}
				}
				if tt.wantStderr != "" {
					assertContainsAll(t, "stderr", r.stderr, []string{tt.wantStderr})
				} else if strings.Contains(r.stderr, "ignored") {
					t.Errorf("stderr counts ignored findings, want none:\n%s", r.stderr)
				}
			})
		}
	}
}

// llmFileWarning returns the stderr line that scan prints when a
// .mcpmoat-ignore entry matches a finding of the LLM rule id but is not
// applied. It is the line of the pin rules (see ignoreFileWarning).
func llmFileWarning(id string) string {
	return "mcpmoat scan: warning: .mcpmoat-ignore cannot ignore " + id + "; use --ignore on the command line\n"
}

// TestScanLLMIgnore checks that only --ignore drops LLM findings (FR-10,
// FR-17), and that scan counts the dropped findings on stderr. A
// .mcpmoat-ignore file can come from a cloned repository, so it cannot ignore
// the LLM rules, as for the pin rules: the findings stay in the report, the
// exit code follows --fail-on, and scan warns once for each rule that a file
// entry matches.
func TestScanLLMIgnore(t *testing.T) {
	t.Parallel()

	tools := map[string][]inspect.Tool{
		"alpha": {mkTool("t1", llmMarkHigh), mkTool("t2", llmMarkInvalid)},
		"beta":  {mkTool("t3", llmMarkMedium)},
	}
	allRows := []llmHit{{llm.RuleID, "high", "alpha", "t1"}, {llm.RuleIDInvalid, "medium", "alpha", "t2"}, {llm.RuleID, "medium", "beta", "t3"}}
	tests := []struct {
		name       string
		args       []string
		ignoreFile string // the content of .mcpmoat-ignore; "" for no file
		want       []llmHit
		wantCode   int
		wantStderr []string
		// warned lists the rule IDs that get the warning that the file
		// cannot ignore them. Each must show once, and no other one.
		warned []string
	}{
		{
			name:     "no ignore",
			want:     allRows,
			wantCode: exitFindings,
		},
		{
			name:       "--ignore MOAT-LLM-001",
			args:       []string{"--ignore", llm.RuleID},
			want:       []llmHit{{llm.RuleIDInvalid, "medium", "alpha", "t2"}},
			wantCode:   exitOK,
			wantStderr: []string{"mcpmoat scan: 2 findings ignored: MOAT-LLM-001 (2)\n"},
		},
		{
			name:       "--ignore both LLM rules",
			args:       []string{"--ignore", llm.RuleID, "--ignore", llm.RuleIDInvalid},
			wantCode:   exitOK,
			wantStderr: []string{"mcpmoat scan: 3 findings ignored: MOAT-LLM-001 (2), MOAT-LLM-002 (1)\n"},
		},
		{
			name:       "ignore file with rule entries",
			ignoreFile: "MOAT-LLM-001\nMOAT-LLM-002\n",
			want:       allRows,
			wantCode:   exitFindings,
			wantStderr: []string{"mcpmoat scan: using 2 entries from .mcpmoat-ignore\n"},
			warned:     []string{llm.RuleID, llm.RuleIDInvalid},
		},
		{
			name:       "ignore file with a tool and a server entry",
			ignoreFile: "MOAT-LLM-001 alpha/t1\nMOAT-LLM-002 alpha # model refusals\n",
			want:       allRows,
			wantCode:   exitFindings,
			wantStderr: []string{"mcpmoat scan: using 2 entries from .mcpmoat-ignore\n"},
			warned:     []string{llm.RuleID, llm.RuleIDInvalid},
		},
		{
			// The file does not change the exit code: it follows --fail-on
			// with all the LLM findings.
			name:       "ignore file with --fail-on critical",
			args:       []string{"--fail-on", "critical"},
			ignoreFile: "MOAT-LLM-001\n",
			want:       allRows,
			wantCode:   exitOK,
			warned:     []string{llm.RuleID},
		},
		{
			// --ignore drops the rows, so the file entry matches no kept
			// row and gives no warning.
			name:       "ignore file and --ignore for one rule",
			args:       []string{"--ignore", llm.RuleID},
			ignoreFile: "MOAT-LLM-001\n",
			want:       []llmHit{{llm.RuleIDInvalid, "medium", "alpha", "t2"}},
			wantCode:   exitOK,
			wantStderr: []string{"mcpmoat scan: 2 findings ignored: MOAT-LLM-001 (2)\n"},
		},
		{
			name:       "ignore file entry for another tool",
			ignoreFile: "MOAT-LLM-001 beta/other\nMOAT-LLM-002 beta\n",
			want:       allRows,
			wantCode:   exitFindings,
			wantStderr: []string{"mcpmoat scan: using 2 entries from .mcpmoat-ignore\n"},
		},
	}
	for _, tt := range tests {
		for _, jsonOut := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%v", tt.name, jsonOut), func(t *testing.T) {
				t.Parallel()
				e := llmEnv(t, tools)
				if tt.ignoreFile != "" {
					writeTestFile(t, e.work, ".mcpmoat-ignore", tt.ignoreFile)
				}
				args := append([]string{"--llm"}, tt.args...)
				if jsonOut {
					args = append(args, "--json")
				}
				r := llmScan(t, e, tools, &llmFake{}, args...)
				if r.code != tt.wantCode {
					t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, tt.wantCode, r.stderr)
				}
				var got []llmHit
				if jsonOut {
					got = llmJSONRows(t, decodeScanJSON(t, r.stdout))
				} else {
					got = llmRowsOf(t, parseFindings(t, r.stdout))
					slices.SortStableFunc(got, func(a, b llmHit) int { return strings.Compare(a.server+a.tool, b.server+b.tool) })
				}
				if !slices.Equal(got, tt.want) {
					t.Errorf("LLM findings = %+v, want %+v\nstdout:\n%s", got, tt.want, r.stdout)
				}
				assertContainsAll(t, "stderr", r.stderr, tt.wantStderr)
				if len(tt.wantStderr) == 0 && strings.Contains(r.stderr, "ignored") {
					t.Errorf("stderr counts ignored findings, want none:\n%s", r.stderr)
				}
				for _, id := range tt.warned {
					if n := strings.Count(r.stderr, llmFileWarning(id)); n != 1 {
						t.Errorf("the warning for %s shows %d times, want 1\nstderr:\n%s", id, n, r.stderr)
					}
				}
				if n := strings.Count(r.stderr, "cannot ignore"); n != len(tt.warned) {
					t.Errorf("stderr has %d \"cannot ignore\" warnings, want %d\nstderr:\n%s", n, len(tt.warned), r.stderr)
				}
			})
		}
	}

	// The pin rules and the LLM rules share the exception: .mcpmoat-ignore
	// drops neither a MOAT-T2 finding nor an LLM finding, and scan warns once
	// for each rule.
	t.Run("ignore file and a pin finding", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, oneServer("srv"))
		firstScan(t, e, mkTool("t1", "Add."))
		writeTestFile(t, e.work, ".mcpmoat-ignore", "MOAT-T2-001\nMOAT-LLM-001\n")
		changed := map[string][]inspect.Tool{"srv": {mkTool("t1", "Add. "+llmMarkHigh)}}

		r := llmScan(t, e, changed, &llmFake{}, "--llm")

		if r.code != exitFindings {
			t.Errorf("exit code = %d, want %d (MOAT-T2-001 stays)\nstderr:\n%s", r.code, exitFindings, r.stderr)
		}
		llmRows, ruleRows := llmSplitFindings(parseFindings(t, r.stdout))
		if got, want := llmRowsOf(t, llmRows), []llmHit{{llm.RuleID, "high", "srv", "t1"}}; !slices.Equal(got, want) {
			t.Errorf("LLM findings = %+v, want %+v", got, want)
		}
		if len(ruleRows) != 1 || ruleRows[0].RuleID != "MOAT-T2-001" {
			t.Errorf("rule findings = %+v, want one MOAT-T2-001", ruleRows)
		}
		assertContainsAll(t, "stderr", r.stderr, []string{ignoreFileWarning, llmFileWarning(llm.RuleID)})
		if strings.Contains(r.stderr, "ignored") {
			t.Errorf("stderr counts ignored findings, want none:\n%s", r.stderr)
		}
	})

	// A file entry for a config rule still drops its finding. Only the LLM
	// entry of the same file gets the warning.
	t.Run("ignore file and a config rule", func(t *testing.T) {
		t.Parallel()
		e := newPinEnv(t, map[string]any{"alpha": failOnHighServer}) // MOAT-T4-001 (high)
		writeTestFile(t, e.work, ".mcpmoat-ignore", "MOAT-T4-001 alpha\nMOAT-LLM-001 alpha\n")
		alphaTools := map[string][]inspect.Tool{"alpha": {mkTool("t1", llmMarkMedium)}}

		r := llmScan(t, e, alphaTools, &llmFake{}, "--llm", "--json")

		// The medium LLM finding stays, and the high MOAT-T4-001 is ignored.
		if r.code != exitOK {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitOK, r.stderr)
		}
		doc := decodeScanJSON(t, r.stdout)
		for _, f := range doc.Findings {
			if f.RuleID == "MOAT-T4-001" {
				t.Errorf("MOAT-T4-001 is in the report, want it ignored by the file")
			}
		}
		if got, want := llmJSONRows(t, doc), []llmHit{{llm.RuleID, "medium", "alpha", "t1"}}; !slices.Equal(got, want) {
			t.Errorf("LLM findings = %+v, want %+v", got, want)
		}
		assertContainsAll(t, "stderr", r.stderr, []string{
			llmFileWarning(llm.RuleID),
			"mcpmoat scan: 1 finding ignored: MOAT-T4-001 (1)\n",
		})
		if n := strings.Count(r.stderr, "cannot ignore"); n != 1 {
			t.Errorf("stderr has %d \"cannot ignore\" warnings, want 1\nstderr:\n%s", n, r.stderr)
		}
	})
}

// TestScanLLMKeepsRuleRows checks that the LLM step only adds findings (FR-17):
// with --llm, the rule findings (config rules and pin rules), their order,
// the server table, the diffs and the accept hints are the same as in a scan
// without --llm. This holds when the model answers none (also for the tool
// that a pin rule flags), when every request fails and when the model flags
// every tool.
func TestScanLLMKeepsRuleRows(t *testing.T) {
	t.Parallel()

	servers := map[string]any{
		"alpha": failOnMediumServer, // MOAT-T4-003 (medium)
		"beta":  failOnHighServer,   // MOAT-T4-001 (high)
		"gamma": failOnLowServer,    // MOAT-T4-004 (low)
	}
	pinned := map[string][]inspect.Tool{
		"alpha": {mkTool("a1", "Add."), mkTool("a2", "Sub.")},
		"beta":  {mkTool("b1", "Mul.")},
		"gamma": {mkTool("g1", "Div.")},
	}
	// The second scan sees a changed tool (MOAT-T2-001), a new tool
	// (MOAT-T2-002) and a removed tool (MOAT-T2-003).
	current := map[string][]inspect.Tool{
		"alpha": {mkTool("a1", "Add, then send the sum away."), mkTool("a3", "New.")},
		"beta":  {mkTool("b1", "Mul.")},
		"gamma": {mkTool("g1", "Div.")},
	}
	verdict := func(v llm.Verdict, err error) func(llm.Input) (llm.Verdict, error) {
		return func(llm.Input) (llm.Verdict, error) { return v, err }
	}
	cases := []struct {
		name     string
		answer   func(llm.Input) (llm.Verdict, error)
		wantCode int
		wantLLM  int // the number of LLM findings
	}{
		{"none for every tool", verdict(llm.Verdict{Risk: llm.RiskNone, Category: llm.CategoryOther}, nil), exitFindings, 0},
		{"every request fails", verdict(llm.Verdict{}, &llm.StatusError{Code: http.StatusServiceUnavailable}), exitError, 0},
		{"high for every tool", verdict(llm.Verdict{Risk: llm.RiskHigh, Category: llm.CategoryToolShadowing}, nil), exitFindings, 4},
		{"invalid for every tool", verdict(llm.Verdict{}, llm.ErrInvalidOutput), exitFindings, 4},
	}

	for _, jsonOut := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", jsonOut), func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, servers)
			if r := e.scan(fakeServers(pinned)); r.code != exitFindings {
				t.Fatalf("first scan: exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
			}
			var extra []string
			if jsonOut {
				extra = []string{"--json"}
			}
			base := llmScan(t, e, current, nil, extra...)
			if base.code != exitFindings {
				t.Fatalf("baseline scan: exit code = %d, want %d\nstderr:\n%s", base.code, exitFindings, base.stderr)
			}
			for _, tc := range cases {
				r := llmScan(t, e, current, &llmFake{answer: tc.answer}, append([]string{"--llm"}, extra...)...)
				if r.code != tc.wantCode {
					t.Errorf("%s: exit code = %d, want %d\nstderr:\n%s", tc.name, r.code, tc.wantCode, r.stderr)
				}
				if jsonOut {
					llmAssertSameRuleJSON(t, tc.name, base.stdout, r.stdout, tc.wantLLM)
				} else {
					llmAssertSameRuleTerminal(t, tc.name, base.stdout, r.stdout, tc.wantLLM)
				}
			}
		})
	}
}

// llmAssertSameRuleTerminal checks that the terminal report got has the same
// server table, the same rule findings in the same order, and the same diffs
// and hints as base, and wantLLM LLM findings.
func llmAssertSameRuleTerminal(t *testing.T, name, base, got string, wantLLM int) {
	t.Helper()
	b, g := splitScanSections(base), splitScanSections(got)
	if b.Table != g.Table {
		t.Errorf("%s: the server table changed\nbase:\n%s\ngot:\n%s", name, b.Table, g.Table)
	}
	if b.Rest != g.Rest {
		t.Errorf("%s: the diffs or the accept hints changed\nbase:\n%s\ngot:\n%s", name, b.Rest, g.Rest)
	}
	_, baseRules := llmSplitFindings(parseFindings(t, base))
	gotLLM, gotRules := llmSplitFindings(parseFindings(t, got))
	if len(baseRules) == 0 {
		t.Fatalf("%s: the baseline has no rule finding", name)
	}
	bt, gt := make([]string, len(baseRules)), make([]string, len(gotRules))
	for i, r := range baseRules {
		bt[i] = llmFindingText(r)
	}
	for i, r := range gotRules {
		gt[i] = llmFindingText(r)
	}
	if !slices.Equal(bt, gt) {
		t.Errorf("%s: the rule findings changed\nbase: %q\ngot:  %q", name, bt, gt)
	}
	if len(gotLLM) != wantLLM {
		t.Errorf("%s: %d LLM findings, want %d", name, len(gotLLM), wantLLM)
	}
	// The summary keeps the status and the tools of each server. Its count
	// grows only by the LLM findings of the server.
	llmPer := map[string]int{}
	for _, r := range gotLLM {
		llmPer[r.Name]++
	}
	bs, gs := summaryRows(t, base), summaryRows(t, got)
	if len(bs) != len(gs) {
		t.Fatalf("%s: the summary has %d rows, want %d", name, len(gs), len(bs))
	}
	for i := range bs {
		want := bs[i]
		want.Findings += llmPer[want.Name]
		if !slices.Equal(want.Warnings, gs[i].Warnings) || want.Server != gs[i].Server || want.Status != gs[i].Status ||
			want.Tools != gs[i].Tools || want.Reason != gs[i].Reason || want.Findings != gs[i].Findings {
			t.Errorf("%s: summary row = %+v, want %+v", name, gs[i], want)
		}
	}
}

// llmAssertSameRuleJSON checks that the JSON report got has the same servers,
// the same rule findings in the same order, and the same diffs as base, and
// wantLLM LLM findings.
func llmAssertSameRuleJSON(t *testing.T, name, base, got string, wantLLM int) {
	t.Helper()
	bd, gd := decodeScanJSON(t, base), decodeScanJSON(t, got)
	var gotRules []report.JSONFinding
	nLLM := 0
	for _, f := range gd.Findings {
		if f.Source == report.SourceLLM {
			nLLM++
			continue
		}
		gotRules = append(gotRules, f)
	}
	if len(bd.Findings) == 0 {
		t.Fatalf("%s: the baseline has no finding", name)
	}
	if !slices.Equal(bd.Findings, gotRules) {
		t.Errorf("%s: the rule findings changed\nbase: %+v\ngot:  %+v", name, bd.Findings, gotRules)
	}
	if nLLM != wantLLM {
		t.Errorf("%s: %d LLM findings, want %d", name, nLLM, wantLLM)
	}
	bj, _ := json.Marshal(bd.Servers)
	gj, _ := json.Marshal(gd.Servers)
	if !bytes.Equal(bj, gj) {
		t.Errorf("%s: the servers changed\nbase: %s\ngot:  %s", name, bj, gj)
	}
	bj, _ = json.Marshal(bd.Diffs)
	gj, _ = json.Marshal(gd.Diffs)
	if !bytes.Equal(bj, gj) {
		t.Errorf("%s: the diffs changed\nbase: %s\ngot:  %s", name, bj, gj)
	}
}

// llmNotClassified matches the stderr line of an LLM step that a provider
// failure stopped, and captures the reason and the count.
var llmNotClassified = regexp.MustCompile(`(?m)^mcpmoat scan: the LLM provider failed \(([^)]*)\); (\d+) (?:tool was|tools were) not classified$`)

// llmInternalFailed matches the stderr line of an LLM step that an internal
// error stopped, and captures the count.
var llmInternalFailed = regexp.MustCompile(`(?m)^mcpmoat scan: the LLM step failed \(internal error\); (\d+) (?:tool was|tools were) not classified$`)

// TestScanLLMProviderFailure checks a failed request (FR-17, FR-16): the
// report still prints, the JSON complete field is false, the exit code is 2
// and stderr gives the HTTP status and the number of tools that were not
// classified. The key never shows.
func TestScanLLMProviderFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		tools     []inspect.Tool
		wantCount string // "" means any count of 1 or more
	}{
		{
			name:      "every request fails",
			tools:     []inspect.Tool{mkTool("t1", llmMark503), mkTool("t2", llmMark503), mkTool("t3", llmMark503)},
			wantCount: "3",
		},
		{
			name:  "one request fails",
			tools: []inspect.Tool{mkTool("t1", llmMarkHigh), mkTool("t2", llmMark503), mkTool("t3", "Add."), mkTool("t4", "Sub.")},
		},
	}
	for _, tt := range tests {
		for _, jsonOut := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%v", tt.name, jsonOut), func(t *testing.T) {
				t.Parallel()
				tools := map[string][]inspect.Tool{"srv": tt.tools}
				e := llmEnv(t, tools)
				args := []string{"--llm"}
				if jsonOut {
					args = append(args, "--json")
				}

				r := llmScan(t, e, tools, &llmFake{}, args...)

				if r.code != exitError {
					t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitError, r.stderr)
				}
				m := llmNotClassified.FindAllStringSubmatch(r.stderr, -1)
				if len(m) != 1 {
					t.Fatalf("stderr has %d LLM failure lines, want 1:\n%s", len(m), r.stderr)
				}
				if m[0][1] != "HTTP 503" {
					t.Errorf("failure reason = %q, want \"HTTP 503\"", m[0][1])
				}
				if tt.wantCount != "" && m[0][2] != tt.wantCount {
					t.Errorf("not classified count = %s, want %s", m[0][2], tt.wantCount)
				}
				if m[0][2] == "0" {
					t.Errorf("not classified count = 0, want at least 1")
				}
				if jsonOut {
					doc := decodeScanJSON(t, r.stdout)
					if doc.Complete {
						t.Errorf("complete = true, want false")
					}
					if len(doc.Servers) != 1 {
						t.Errorf("JSON has %d servers, want 1: the report must still print", len(doc.Servers))
					}
				} else if !strings.Contains(r.stdout, summaryHeading) {
					t.Errorf("stdout has no SUMMARY block: the report must still print\nstdout:\n%s", r.stdout)
				}
				// The first-run pins are still saved: the pin step worked.
				if _, ok := e.readPins().tools("srv"); !ok {
					t.Errorf("pins.json has no entry for srv, want the first-run pins")
				}
			})
		}
	}
}

// TestScanLLMToolCap checks the cap of llmWantCap tools in one scan: the
// first 500 tools are classified and the rest are not, the exit code is 2
// and stderr gives the count. Exactly 500 tools is not over the cap.
func TestScanLLMToolCap(t *testing.T) {
	t.Parallel()

	for _, n := range []int{llmWantCap, llmWantCap + 3} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			many := make([]inspect.Tool, n)
			for i := range many {
				many[i] = mkTool(fmt.Sprintf("tool%03d", i), "Plain.")
			}
			tools := map[string][]inspect.Tool{"big": many}
			fake := &llmFake{}

			r := llmScan(t, llmEnv(t, tools), tools, fake, "--llm", "--json")

			if got := fake.calls.Load(); got != llmWantCap {
				t.Errorf("Classify calls = %d, want %d", got, llmWantCap)
			}
			got := fake.received()
			for i, in := range got {
				if want := fmt.Sprintf("tool%03d", i); in.ToolName != want {
					t.Errorf("classified tool %d = %q, want %q (the first %d tools)", i, in.ToolName, want, llmWantCap)
					break
				}
			}
			doc := decodeScanJSON(t, r.stdout)
			capLine := "mcpmoat scan: --llm classifies at most 500 tools in one scan; 3 tools were not classified\n"
			if n == llmWantCap {
				if r.code != exitOK || !doc.Complete || strings.Contains(r.stderr, "not classified") {
					t.Errorf("exit code = %d, complete = %v; want 0 and true\nstderr:\n%s", r.code, doc.Complete, r.stderr)
				}
				return
			}
			if r.code != exitError || doc.Complete {
				t.Errorf("exit code = %d, complete = %v; want 2 and false", r.code, doc.Complete)
			}
			assertContainsAll(t, "stderr", r.stderr, []string{capLine})
			if llmNotClassified.MatchString(r.stderr) || llmInternalFailed.MatchString(r.stderr) {
				t.Errorf("stderr reports a failure of the LLM step, want only the cap line:\n%s", r.stderr)
			}
		})
	}
}

// TestScanLLMConcurrency checks that at most llmWantWorkers requests run at the
// same time, that the scan does use them all, and that the findings keep the
// order of the servers and the tools whatever order the requests end in.
func TestScanLLMConcurrency(t *testing.T) {
	t.Parallel()

	tools := map[string][]inspect.Tool{
		"alpha": {mkTool("a1", llmMarkLow), mkTool("a2", "x"), mkTool("a3", llmMarkHigh), mkTool("a4", llmMarkInvalid), mkTool("a5", llmMarkMedium)},
		"beta":  {mkTool("b1", llmMarkMedium), mkTool("b2", llmMarkHigh), mkTool("b3", "x")},
		"gamma": {mkTool("c1", llmMarkInvalid), mkTool("c2", llmMarkLow), mkTool("c3", llmMarkHigh), mkTool("c4", "x")},
	}
	want := []llmHit{
		{llm.RuleID, "low", "alpha", "a1"},
		{llm.RuleID, "high", "alpha", "a3"},
		{llm.RuleIDInvalid, "medium", "alpha", "a4"},
		{llm.RuleID, "medium", "alpha", "a5"},
		{llm.RuleID, "medium", "beta", "b1"},
		{llm.RuleID, "high", "beta", "b2"},
		{llm.RuleIDInvalid, "medium", "gamma", "c1"},
		{llm.RuleID, "low", "gamma", "c2"},
		{llm.RuleID, "high", "gamma", "c3"},
	}

	t.Run("at most four at once", func(t *testing.T) {
		t.Parallel()
		// The first calls wait until llmWantWorkers calls run, so the test sees
		// that the scan uses them all. Then every call yields the processor
		// many times, so a fifth call would overlap. The guard timer is not
		// for synchronisation: it only stops a hang when the scan runs fewer
		// calls at once. It then releases every call, and the test fails.
		full := make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(full) }) }
		var timedOut atomic.Bool
		guard := time.AfterFunc(10*time.Second, func() { timedOut.Store(true); release() })
		defer guard.Stop()
		fake := &llmFake{}
		fake.before = func(ctx context.Context) {
			if fake.inFlight.Load() >= llmWantWorkers {
				release()
			}
			select {
			case <-full:
			case <-ctx.Done():
			}
			for range 500 {
				runtime.Gosched()
			}
		}
		r := llmScan(t, llmEnv(t, tools), tools, fake, "--llm", "--json")
		if timedOut.Load() {
			t.Errorf("the scan never ran %d calls at the same time", llmWantWorkers)
		}
		if r.code != exitFindings {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
		}
		if got := fake.maxInFlight.Load(); got != llmWantWorkers {
			t.Errorf("at most %d calls ran at the same time, want %d", got, llmWantWorkers)
		}
		if got := fake.calls.Load(); got != 12 {
			t.Errorf("Classify calls = %d, want 12", got)
		}
	})

	t.Run("stable order", func(t *testing.T) {
		t.Parallel()
		for i := range 20 {
			r := llmScan(t, llmEnv(t, tools), tools, &llmFake{shuffle: true}, "--llm", "--json")
			if got := llmJSONRows(t, decodeScanJSON(t, r.stdout)); !slices.Equal(got, want) {
				t.Fatalf("run %d: LLM findings = %+v, want %+v", i, got, want)
			}
		}
	})
}

// TestScanLLMInterrupted checks a signal during the LLM step: scan prints
// interruptedText, exits with 2, prints no report and saves no pins (the first
// run would have pinned the server).
func TestScanLLMInterrupted(t *testing.T) {
	t.Parallel()

	for _, jsonOut := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", jsonOut), func(t *testing.T) {
			t.Parallel()
			tools := map[string][]inspect.Tool{"srv": {mkTool("t1", llmMarkHigh), mkTool("t2", "Add.")}}
			e := llmEnv(t, tools)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fake := &llmFake{before: func(callCtx context.Context) {
				cancel()
				<-callCtx.Done()
			}}
			f := &llmFactory{t: t, cl: fake}
			c, stdout, stderr := llmCLI(e, fakeServers(tools), f)
			c.ctx = ctx
			args := []string{"--llm"}
			if jsonOut {
				args = append(args, "--json")
			}

			r := llmRun(t, e, c, stdout, stderr, args...)

			if r.code != exitError {
				t.Errorf("exit code = %d, want %d", r.code, exitError)
			}
			assertEmptyStdout(t, r.stdout)
			assertContainsAll(t, "stderr", r.stderr, []string{scanPrefix + interruptedText + "\n"})
			if llmNotClassified.MatchString(r.stderr) || llmInternalFailed.MatchString(r.stderr) {
				t.Errorf("stderr reports a failure of the LLM step for a signal:\n%s", r.stderr)
			}
			e.assertNoPinsFile(t, "a signal during the LLM step")
		})
	}
}

// TestScanLLMSendsOnlyNameAndDescription checks what reaches the classifier
// (FR-17): the name and the description of each tool, and nothing else. The
// config holds canaries in its env, args, headers and URL, and the tools hold
// canaries in their title, schemas, annotations and _meta.
func TestScanLLMSendsOnlyNameAndDescription(t *testing.T) {
	t.Parallel()

	const toolCanary = "mcpmoat-tool-canary-Hx5Wq2"
	tool := func(name, desc string) inspect.Tool {
		tl := mkTool(name, desc)
		tl.Title = toolCanary + "-title"
		tl.InputSchema = json.RawMessage(`{"type":"object","description":"` + toolCanary + `-in"}`)
		tl.OutputSchema = json.RawMessage(`{"type":"object","description":"` + toolCanary + `-out"}`)
		tl.Meta = json.RawMessage(`{"k":"` + toolCanary + `-meta"}`)
		tl.Annotations = &inspect.ToolAnnotations{Title: toolCanary + "-ann"}
		return tl
	}
	tools := map[string][]inspect.Tool{
		"local":  {tool("t1", "Add two numbers."), tool("t2", "Echo the text.")},
		"remote": {tool("t3", "Read a note. "+llmMarkLow)},
	}
	servers := map[string]any{
		"local": map[string]any{
			"command": "npx",
			"args":    []string{"@acme/fixture-clean@2.0.0", "--token", discovertest.CanaryArgs},
			"env":     map[string]string{"FIXTURE_MODE": discovertest.CanaryEnv},
		},
		"remote": map[string]any{
			"type":    "http",
			"url":     "https://mcp.example.invalid/mcp?k=" + discovertest.CanaryURL,
			"headers": map[string]string{"X-Fixture": discovertest.CanaryHeader},
		},
	}
	canaries := append(discovertest.Canaries(), toolCanary, llmTestKey)

	fake := &llmFake{}
	r := llmScan(t, newPinEnv(t, servers), tools, fake, "--llm")

	want := []llm.Input{
		{ToolName: "t1", Description: "Add two numbers."},
		{ToolName: "t2", Description: "Echo the text."},
		{ToolName: "t3", Description: "Read a note. " + llmMarkLow},
	}
	got := fake.received()
	if !slices.Equal(got, want) {
		t.Errorf("classifier inputs = %+v, want %+v", got, want)
	}
	dump := fmt.Sprintf("%#v", got)
	for _, c := range canaries {
		if strings.Contains(dump, c) {
			t.Errorf("the classifier got the canary %q: %s", c, dump)
		}
	}
	assertNoLeakBoth(t, r.stdout, r.stderr)
}

// TestLLMRuleIDsValid checks that the IDs of the LLM findings follow the rule
// ID syntax of internal/rules, so --ignore and .mcpmoat-ignore accept them
// (FR-10, FR-17). Package llm must not import internal/rules, so the check
// sits here, where both packages are imported.
func TestLLMRuleIDsValid(t *testing.T) {
	t.Parallel()

	for _, id := range []string{llm.RuleID, llm.RuleIDInvalid} {
		if !rules.ValidRuleID(id) {
			t.Errorf("rules.ValidRuleID(%q) = false, want true", id)
		}
	}
}

// TestLLMRiskSeveritiesValid checks that each risk with a finding gives a
// severity that internal/rules knows, so the report and --fail-on handle an
// LLM finding like any other. Package llm must not import internal/rules, so
// the check sits here, next to TestLLMRuleIDsValid.
func TestLLMRiskSeveritiesValid(t *testing.T) {
	t.Parallel()

	for _, risk := range []llm.Risk{llm.RiskLow, llm.RiskMedium, llm.RiskHigh} {
		t.Run(string(risk), func(t *testing.T) {
			t.Parallel()
			severity, ok := risk.Severity()
			if !ok {
				t.Fatalf("%q.Severity() ok = false, want true", risk)
			}
			if !rules.Severity(severity).Valid() {
				t.Errorf("%q.Severity() = %q, which is not a valid rules.Severity", risk, severity)
			}
			if rules.Severity(severity) == rules.SeverityCritical {
				t.Errorf("%q.Severity() = %q, want a severity below critical", risk, severity)
			}
		})
	}
}

// failClassifier is a toolClassifier that fails the test when it is called.
type failClassifier struct{ t *testing.T }

// Classify implements toolClassifier.
func (f failClassifier) Classify(context.Context, llm.Input) (llm.Verdict, error) {
	f.t.Error("Classify was called, want no call")
	return llm.Verdict{}, errors.New("unexpected call")
}

// TestClassifyToolsContext checks classifyTools with a context that ended. With
// no tool to classify, the step did nothing: it returns an empty result and no
// error, so a signal after the inspection does not drop the report only with
// --llm. With a tool, it returns the context error.
func TestClassifyToolsContext(t *testing.T) {
	t.Parallel()

	srv := discover.Server{Name: "srv", Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name     string
		ctx      context.Context
		outcomes []inspect.Outcome
		wantErr  error
	}{
		{"no outcomes, ended", canceled, nil, nil},
		{"failed server, ended", canceled, []inspect.Outcome{{Server: srv, Status: inspect.StatusFailed, Err: errors.New("boom")}}, nil},
		{"server without tools, ended", canceled, []inspect.Outcome{{Server: srv, Status: inspect.StatusOK}}, nil},
		{"no outcomes, alive", t.Context(), nil, nil},
		{"one tool, ended", canceled, []inspect.Outcome{{Server: srv, Status: inspect.StatusOK, Result: inspect.Result{Tools: []inspect.Tool{mkTool("t1", "Add.")}}}}, context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var cl toolClassifier = failClassifier{t}
			if tt.wantErr != nil {
				cl = &llmFake{}
			}
			res, err := classifyTools(tt.ctx, tt.outcomes, cl, &scanIgnores{})
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("classifyTools() error = %v, want %v", err, tt.wantErr)
			}
			if len(res.rows) != 0 || res.ignored != nil || res.counts != nil || res.failure != nil || res.skipped != 0 || res.overCap != 0 {
				t.Errorf("classifyTools() result = %+v, want empty", res)
			}
		})
	}
}
