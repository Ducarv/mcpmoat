package main

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// This file tests the limits of the LLM step of scan (FR-17, issue #184): the
// fair share of the cap of llmWantCap tools between the servers (fairShare
// and planLLMJobs), and the notice that scan prints on stderr before the
// first request (llmPlan.sendingNotice). The scan-level tests use the real
// client (llm.New) and the fake Anthropic API of scan_llm_client_test.go on a
// loopback server.

// llmSendingLine returns the exact stderr line, without the newline, of the
// notice for a scan that sends tools tools with about kib KiB of text. The
// test builds the text itself, so a change of the notice fails the tests.
func llmSendingLine(tools, kib int) string {
	noun := "tools"
	if tools == 1 {
		noun = "tool"
	}
	return fmt.Sprintf("%ssending %d %s (about %d KiB of text) to the LLM provider", scanPrefix, tools, noun, kib)
}

// llmCapLine returns the exact stderr line, without the newline, for a scan
// in which notSent tools were over the cap (2 or more).
func llmCapLine(notSent int) string {
	return fmt.Sprintf("%s--llm classifies at most %d tools in one scan; %d tools were not classified", scanPrefix, llmWantCap, notSent)
}

// fairShareRef is the reference of fairShare for the tests: a round robin. In
// each round, every server that still has a tool gets one more, in the order
// of counts, until the budget is used up. So the servers that are cut get
// equal shares, and the first ones in the order of counts get the remainder.
// It is slow but plainly right.
func fairShareRef(counts []int, budget int) []int {
	shares := make([]int, len(counts))
	left := max(budget, 0)
	for left > 0 {
		gave := false
		for i, c := range counts {
			if left == 0 {
				break
			}
			if shares[i] < max(c, 0) {
				shares[i]++
				left--
				gave = true
			}
		}
		if !gave {
			break // every server has all its tools
		}
	}
	return shares
}

// assertFairShare checks the rules that every result of fairShare must
// follow, apart from the exact values:
//   - one share for each count, and 0 <= share <= count (a count below 0
//     counts as 0);
//   - the sum is the smaller of the budget and the sum of the counts, so it
//     never exceeds the budget and no tool is left out while budget is left;
//   - max-min fairness: while a server is cut (share < count), no other
//     server has more than its share + 1;
//   - the remainder goes to the first servers: of two cut servers, the one
//     that comes first never has less.
func assertFairShare(t *testing.T, counts []int, budget int, got []int) {
	t.Helper()
	if len(got) != len(counts) {
		t.Fatalf("fairShare(%v, %d) = %v: %d shares, want %d", counts, budget, got, len(got), len(counts))
	}
	sum, total := 0, 0
	for i, s := range got {
		c := max(counts[i], 0)
		if s < 0 || s > c {
			t.Errorf("fairShare(%v, %d) = %v: share %d of server %d is outside [0, %d]", counts, budget, got, s, i, c)
		}
		sum += s
		total += c
	}
	if want := min(max(budget, 0), total); sum != want {
		t.Errorf("fairShare(%v, %d) = %v: sum %d, want %d (the smaller of the budget and the tools)", counts, budget, got, sum, want)
	}
	for i, si := range got {
		if si >= max(counts[i], 0) {
			continue // server i has all its tools
		}
		for j, sj := range got {
			if sj > si+1 {
				t.Errorf("fairShare(%v, %d) = %v: server %d is cut at %d but server %d has %d", counts, budget, got, i, si, j, sj)
			}
			if j > i && sj < max(counts[j], 0) && sj > si {
				t.Errorf("fairShare(%v, %d) = %v: cut server %d has more (%d) than the cut server %d before it (%d)", counts, budget, got, j, sj, i, si)
			}
		}
	}
}

// TestFairShare checks the max-min fair share of the cap between the servers
// (fairShare): the exact shares of fixed cases, and then the rules of
// assertFairShare and the round-robin reference on random cases.
func TestFairShare(t *testing.T) {
	t.Parallel()

	// One server with many tools and 20 servers with one tool each.
	ones := slices.Repeat([]int{1}, 20)
	bigFirst := append([]int{100000}, ones...)
	bigLast := append(slices.Clone(ones), 100000)
	bigFirstWant := append([]int{480}, ones...)
	bigLastWant := append(slices.Clone(ones), 480)

	tests := []struct {
		name   string
		counts []int
		budget int
		want   []int
	}{
		{name: "nil", counts: nil, budget: 500, want: []int{}},
		{name: "empty", counts: []int{}, budget: 500, want: []int{}},
		{name: "budget 0", counts: []int{3, 5}, budget: 0, want: []int{0, 0}},
		{name: "negative budget", counts: []int{3, 5}, budget: -10, want: []int{0, 0}},
		{name: "negative counts count as 0", counts: []int{-5, 10, 0}, budget: 4, want: []int{0, 4, 0}},
		{name: "negative count, all under budget", counts: []int{-1, 2}, budget: 10, want: []int{0, 2}},
		{name: "all under budget", counts: []int{3, 1, 7}, budget: 500, want: []int{3, 1, 7}},
		{name: "one server under budget", counts: []int{42}, budget: 500, want: []int{42}},
		{name: "one server over budget", counts: []int{503}, budget: 500, want: []int{500}},
		{name: "exactly budget", counts: []int{200, 300}, budget: 500, want: []int{200, 300}},
		{name: "exactly budget, one server", counts: []int{500}, budget: 500, want: []int{500}},
		{name: "equal split with remainder", counts: []int{1000, 1000, 1000}, budget: 500, want: []int{167, 167, 166}},
		{name: "equal split, no remainder", counts: []int{1000, 1000}, budget: 500, want: []int{250, 250}},
		{name: "small server first", counts: []int{3, 1000, 1000}, budget: 500, want: []int{3, 249, 248}},
		{name: "small server in the middle", counts: []int{1000, 3, 1000}, budget: 500, want: []int{249, 3, 248}},
		{name: "small server last", counts: []int{1000, 1000, 3}, budget: 500, want: []int{249, 248, 3}},
		// The scan case: a big first server cannot take the whole cap.
		{name: "600 then 10", counts: []int{600, 10}, budget: 500, want: []int{490, 10}},
		{name: "10 then 600", counts: []int{10, 600}, budget: 500, want: []int{10, 490}},
		{name: "one huge server first, many tiny", counts: bigFirst, budget: 500, want: bigFirstWant},
		{name: "one huge server last, many tiny", counts: bigLast, budget: 500, want: bigLastWant},
		// The water-filling depends on the counts only; the remainder goes
		// to the first cut server in the order of counts, not to the larger
		// or the smaller one.
		{name: "remainder to the first cut server, larger first", counts: []int{900, 300, 10}, budget: 501, want: []int{246, 245, 10}},
		{name: "remainder to the first cut server, smaller first", counts: []int{10, 300, 900}, budget: 501, want: []int{10, 246, 245}},
		{name: "remainder fills a server that has one tool more", counts: []int{246, 900, 10}, budget: 501, want: []int{246, 245, 10}},
		// A server with fewer tools than its part leaves the rest to the
		// others, also in the later steps of the water-filling: 50 <= 500/4,
		// then 100 <= 450/3, then 160 <= 350/2, and the last server gets
		// the 190 that are left.
		{name: "three levels of water-filling", counts: []int{50, 1000, 100, 160}, budget: 500, want: []int{50, 190, 100, 160}},
		{name: "budget smaller than the number of servers", counts: []int{5, 5, 5, 5, 5}, budget: 2, want: []int{1, 1, 0, 0, 0}},
		{name: "budget 1, first server empty", counts: []int{0, 5, 5}, budget: 1, want: []int{0, 1, 0}},
		{name: "equal counts keep the order of counts", counts: []int{7, 7, 7}, budget: 20, want: []int{7, 7, 6}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := slices.Clone(tt.counts)
			got := fairShare(tt.counts, tt.budget)
			if !slices.Equal(got, tt.want) || got == nil {
				t.Errorf("fairShare(%v, %d) = %#v, want %#v", tt.counts, tt.budget, got, tt.want)
			}
			if !slices.Equal(tt.counts, in) {
				t.Errorf("fairShare changed its input: %v, want %v", tt.counts, in)
			}
			assertFairShare(t, tt.counts, tt.budget, got)
			if ref := fairShareRef(tt.counts, tt.budget); !slices.Equal(got, ref) {
				t.Errorf("fairShare(%v, %d) = %v, round robin gives %v", tt.counts, tt.budget, got, ref)
			}
		})
	}

	t.Run("random", func(t *testing.T) {
		t.Parallel()
		rng := rand.New(rand.NewPCG(184, 2026)) //nolint:gosec // G404: fixed seed for a reproducible test, not for security
		for i := range 3000 {
			n := rng.IntN(9)
			counts := make([]int, n)
			for j := range counts {
				switch rng.IntN(4) {
				case 0:
					counts[j] = rng.IntN(5) - 2 // small, sometimes below 0
				case 1:
					counts[j] = 100 // equal counts test the stable order
				default:
					counts[j] = rng.IntN(1200)
				}
			}
			budget := rng.IntN(900) - 5
			got := fairShare(counts, budget)
			assertFairShare(t, counts, budget, got)
			if ref := fairShareRef(counts, budget); !slices.Equal(got, ref) {
				t.Fatalf("case %d: fairShare(%v, %d) = %v, round robin gives %v", i, counts, budget, got, ref)
			}
		}
	})
}

// llmTestOutcome returns the outcome of an inspected server at index with
// name and n tools named <prefix>000, <prefix>001 and so on. Each tool has
// the description "Plain.".
func llmTestOutcome(index int, name, prefix string, n int) inspect.Outcome {
	tools := make([]inspect.Tool, n)
	for i := range tools {
		tools[i] = mkTool(fmt.Sprintf("%s%03d", prefix, i), "Plain.")
	}
	return inspect.Outcome{
		Index:  index,
		Server: discover.Server{Name: name, Client: discover.ClientClaudeCode, Source: "/cfg/mcp.json"},
		Status: inspect.StatusOK,
		Result: inspect.Result{ServerName: name, Tools: tools},
	}
}

// llmToolNames returns the names <prefix>000 to <prefix><n-1>, in order.
func llmToolNames(prefix string, n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("%s%03d", prefix, i)
	}
	return names
}

// TestPlanLLMJobs checks the plan of the LLM step (planLLMJobs): each server
// keeps its first tools up to its fair share of the cap, the jobs keep the
// order of the servers (Outcome.Index, not the order of the outcomes) and
// then of the tools, a server that was not inspected or has no tool takes no
// share, and overCap is the tools that are not sent.
func TestPlanLLMJobs(t *testing.T) {
	t.Parallel()

	failed := func(index int, name string) inspect.Outcome {
		o := llmTestOutcome(index, name, "x", 0)
		o.Status = inspect.StatusFailed
		o.Result = inspect.Result{}
		o.Err = errors.New("boom")
		return o
	}
	// timedOut has tools in its Result. Result is valid only with
	// StatusOK, so the plan must not use them.
	timedOut := func(index int, name string) inspect.Outcome {
		o := llmTestOutcome(index, name, "y", 50)
		o.Status = inspect.StatusTimeout
		o.Err = errors.New("timeout")
		return o
	}

	tests := []struct {
		name     string
		outcomes []inspect.Outcome
		// want is "server/tool" for each job, in order.
		want    []string
		tools   int
		overCap int
	}{
		{
			name:     "no outcomes",
			outcomes: nil,
			tools:    0,
		},
		{
			name:     "two small servers",
			outcomes: []inspect.Outcome{llmTestOutcome(0, "alpha", "a", 3), llmTestOutcome(1, "beta", "b", 2)},
			want:     append(llmJobKeys("alpha", llmToolNames("a", 3)), llmJobKeys("beta", llmToolNames("b", 2))...),
			tools:    5,
		},
		{
			// The outcomes come in the reverse order: the plan sorts them
			// by Index.
			name:     "600 then 10",
			outcomes: []inspect.Outcome{llmTestOutcome(1, "beta", "b", 10), llmTestOutcome(0, "alpha", "a", 600)},
			want:     append(llmJobKeys("alpha", llmToolNames("a", 490)), llmJobKeys("beta", llmToolNames("b", 10))...),
			tools:    610,
			overCap:  110,
		},
		{
			name:     "10 then 600",
			outcomes: []inspect.Outcome{llmTestOutcome(0, "alpha", "a", 10), llmTestOutcome(1, "beta", "b", 600)},
			want:     append(llmJobKeys("alpha", llmToolNames("a", 10)), llmJobKeys("beta", llmToolNames("b", 490))...),
			tools:    610,
			overCap:  110,
		},
		{
			// fairShare({700, 5, 300}, 500) = {248, 5, 247}.
			name:     "three servers",
			outcomes: []inspect.Outcome{llmTestOutcome(2, "gamma", "c", 300), llmTestOutcome(0, "alpha", "a", 700), llmTestOutcome(1, "beta", "b", 5)},
			want: slices.Concat(
				llmJobKeys("alpha", llmToolNames("a", 248)),
				llmJobKeys("beta", llmToolNames("b", 5)),
				llmJobKeys("gamma", llmToolNames("c", 247))),
			tools:   1005,
			overCap: 505,
		},
		{
			name:     "one server over the cap",
			outcomes: []inspect.Outcome{llmTestOutcome(0, "alpha", "a", 503)},
			want:     llmJobKeys("alpha", llmToolNames("a", 500)),
			tools:    503,
			overCap:  3,
		},
		{
			// A server with zero tools takes no share: the other server
			// gets the whole cap.
			name:     "a server with zero tools",
			outcomes: []inspect.Outcome{llmTestOutcome(0, "alpha", "a", 0), llmTestOutcome(1, "beta", "b", 600)},
			want:     llmJobKeys("beta", llmToolNames("b", 500)),
			tools:    600,
			overCap:  100,
		},
		{
			name:     "a server that failed",
			outcomes: []inspect.Outcome{failed(0, "alpha"), llmTestOutcome(1, "beta", "b", 600)},
			want:     llmJobKeys("beta", llmToolNames("b", 500)),
			tools:    600,
			overCap:  100,
		},
		{
			name:     "a server that timed out, with stale tools",
			outcomes: []inspect.Outcome{timedOut(0, "alpha"), llmTestOutcome(1, "beta", "b", 3)},
			want:     llmJobKeys("beta", llmToolNames("b", 3)),
			tools:    3,
		},
		{
			name:     "only failed and empty servers",
			outcomes: []inspect.Outcome{failed(0, "alpha"), llmTestOutcome(1, "beta", "b", 0)},
			tools:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plan := planLLMJobs(tt.outcomes)
			got := make([]string, 0, len(plan.jobs))
			for _, job := range plan.jobs {
				got = append(got, job.ref.Name+"/"+job.in.ToolName)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("plan jobs (%d) = %v\nwant (%d) %v", len(got), llmShortList(got), len(tt.want), llmShortList(tt.want))
			}
			if plan.tools != tt.tools || plan.overCap != tt.overCap {
				t.Errorf("plan tools, overCap = %d, %d; want %d, %d", plan.tools, plan.overCap, tt.tools, tt.overCap)
			}
			if plan.overCap != plan.tools-len(plan.jobs) {
				t.Errorf("overCap = %d, want tools - jobs = %d", plan.overCap, plan.tools-len(plan.jobs))
			}
			if len(plan.jobs) > llmWantCap {
				t.Errorf("plan has %d jobs, want at most %d", len(plan.jobs), llmWantCap)
			}
			// Each job carries the index and the description of its server
			// and tool.
			byName := make(map[string]inspect.Outcome, len(tt.outcomes))
			for _, o := range tt.outcomes {
				byName[o.Server.Name] = o
			}
			for _, job := range plan.jobs {
				o := byName[job.ref.Name]
				if job.index != o.Index || job.in.Description != "Plain." {
					t.Errorf("job %s/%s has index %d and description %q, want %d and %q", job.ref.Name, job.in.ToolName, job.index, job.in.Description, o.Index, "Plain.")
				}
			}
		})
	}
}

// llmJobKeys returns "server/tool" for each tool name.
func llmJobKeys(server string, tools []string) []string {
	keys := make([]string, len(tools))
	for i, name := range tools {
		keys[i] = server + "/" + name
	}
	return keys
}

// llmShortList returns the first and the last items of a long list, so a
// failure message stays short.
func llmShortList(items []string) string {
	if len(items) <= 6 {
		return fmt.Sprint(items)
	}
	return fmt.Sprintf("%v ... %v", items[:3], items[len(items)-3:])
}

// llmNoticeShape is the shape of the notice: numbers only between fixed
// words.
var llmNoticeShape = regexp.MustCompile(`^sending \d+ tools? \(about \d+ KiB of text\) to the LLM provider$`)

// TestSendingNotice checks the text of the notice (llmPlan.sendingNotice):
// one tool or more, the KiB rounded up, the cuts of package llm on the name
// and the description, and that it holds numbers only, never tool text or a
// server name.
func TestSendingNotice(t *testing.T) {
	t.Parallel()

	job := func(name, desc string) llmJob {
		return llmJob{ref: report.ServerRef{Name: "srv"}, in: llm.Input{ToolName: name, Description: desc}}
	}
	// sized returns a job with a name of 1 byte and a description of n-1
	// bytes: n bytes in all.
	sized := func(n int) llmJob { return job("t", strings.Repeat("d", n-1)) }

	tests := []struct {
		name string
		jobs []llmJob
		want string
	}{
		{"no job", nil, "sending 0 tools (about 0 KiB of text) to the LLM provider"},
		{"one job of 0 bytes", []llmJob{job("", "")}, "sending 1 tool (about 0 KiB of text) to the LLM provider"},
		{"one byte", []llmJob{job("t", "")}, "sending 1 tool (about 1 KiB of text) to the LLM provider"},
		{"1023 bytes", []llmJob{sized(1023)}, "sending 1 tool (about 1 KiB of text) to the LLM provider"},
		{"1024 bytes", []llmJob{sized(1024)}, "sending 1 tool (about 1 KiB of text) to the LLM provider"},
		{"1025 bytes", []llmJob{sized(1025)}, "sending 1 tool (about 2 KiB of text) to the LLM provider"},
		{"2049 bytes", []llmJob{sized(2049)}, "sending 1 tool (about 3 KiB of text) to the LLM provider"},
		{"two tools", []llmJob{job("t1", "Add."), job("t2", "Sub.")}, "sending 2 tools (about 1 KiB of text) to the LLM provider"},
		// The sizes add up over the jobs: 3 x (2 + 400) = 1206 bytes.
		{"sum over the jobs", []llmJob{job("t1", strings.Repeat("d", 400)), job("t2", strings.Repeat("d", 400)), job("t3", strings.Repeat("d", 400))},
			"sending 3 tools (about 2 KiB of text) to the LLM provider"},
		// A name over the cut counts as llm.MaxToolNameBytes: 512 + 512 =
		// 1024 bytes, 1 KiB. Without the cut it would be 2 KiB.
		{"name cut", []llmJob{job(strings.Repeat("n", llm.MaxToolNameBytes+88), strings.Repeat("d", 1024-llm.MaxToolNameBytes))},
			"sending 1 tool (about 1 KiB of text) to the LLM provider"},
		// A 1 MiB description counts as llm.MaxDescriptionBytes (16 KiB):
		// 16384 + 1 bytes is 17 KiB. Without the cut it would be 1025 KiB.
		{"description cut", []llmJob{job("t", strings.Repeat("d", 1<<20))},
			"sending 1 tool (about 17 KiB of text) to the LLM provider"},
		{"description at the cut", []llmJob{job("", strings.Repeat("d", llm.MaxDescriptionBytes))},
			"sending 1 tool (about 16 KiB of text) to the LLM provider"},
		{"both cut", []llmJob{job(strings.Repeat("n", 1<<20), strings.Repeat("d", 1<<20))},
			fmt.Sprintf("sending 1 tool (about %d KiB of text) to the LLM provider", (llm.MaxToolNameBytes+llm.MaxDescriptionBytes+1023)/1024)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := llmPlan{jobs: tt.jobs}.sendingNotice()
			if got != tt.want {
				t.Errorf("sendingNotice() = %q, want %q", got, tt.want)
			}
			if !llmNoticeShape.MatchString(got) {
				t.Errorf("sendingNotice() = %q, want only numbers between the fixed words", got)
			}
		})
	}

	t.Run("numbers only", func(t *testing.T) {
		t.Parallel()
		const (
			nameCanary   = "mcpmoat-notice-name-Vq7Lp2"
			descCanary   = "mcpmoat-notice-desc-Rk4Zx9"
			serverCanary = "mcpmoat-notice-server-Hm3Ty6"
			hiddenCanary = "mcpmoat-notice-hidden-Wn8Jc5" // a secret value of the server
		)
		plan := llmPlan{
			jobs: []llmJob{{
				index: 7,
				ref:   report.ServerRef{Name: serverCanary, ProjectPath: "/p/" + serverCanary},
				in: llm.Input{
					ToolName:    nameCanary,
					Description: descCanary + "\x1b[31m\u202e",
					Secrets:     []discover.Secret{discover.NewSecret(hiddenCanary)},
				},
			}},
			tools:   900,
			overCap: 899,
		}
		got := plan.sendingNotice()
		if !llmNoticeShape.MatchString(got) {
			t.Errorf("sendingNotice() = %q, want only numbers between the fixed words", got)
		}
		assertContainsNone(t, "notice", got, []string{nameCanary, descCanary, serverCanary, hiddenCanary, "\x1b", "\u202e"})
		// The notice counts the jobs, not the tools over the cap.
		if want := "sending 1 tool "; !strings.HasPrefix(got, want) {
			t.Errorf("sendingNotice() = %q, want it to start with %q", got, want)
		}
	})
}

// llmLimitsRun is the outcome of one scan of llmLimitsScan.
type llmLimitsRun struct {
	code           int
	stdout, stderr string
	// host is the host and port of the fake API, as the setup warning
	// names it.
	host string
	// events are the writes to stdout and stderr, in order.
	events []llmEvent
	// sent is the tool names that the fake API got, in the order in which
	// the requests arrived.
	sent []string
	// early counts the requests that arrived while stderr did not yet hold
	// the notice.
	early int32
	// pinsPath is the pins.json that the scan created.
	pinsPath string
}

// withPinsNotice returns the exact stderr lines for lines, which hold the
// text after scanPrefix, with the notice of the new pins file before the
// first pin line. The pin step saves the new pins after the LLM step, so the
// notice comes after the lines of the LLM step.
func withPinsNotice(pinsPath string, lines []string) []lineWant {
	var want []lineWant
	noticed := false
	for _, line := range lines {
		if !noticed && strings.HasPrefix(line, "pinned ") {
			want = append(want, exactLine(newPinsNoticeLine("scan", pinsPath)))
			noticed = true
		}
		want = append(want, exactLine(scanPrefix+line))
	}
	return want
}

// llmLimitsScan runs "mcpmoat scan --config <file> --llm --llm-base-url
// <api> args..." in process with the real client (newLLMClassifier) against
// a new fake API. The config has one server for each key of tools, and insp
// answers the inspection. notice is the notice line that each request must
// find on stderr when it arrives ("" when no request is expected). It checks
// that the key and no raw escape byte shows.
func llmLimitsScan(t *testing.T, tools map[string][]inspect.Tool, insp inspect.Inspector, notice string, args ...string) llmLimitsRun {
	t.Helper()
	api := newFakeProvider(t, llm.ProviderAnthropic)
	log := &llmSyncLog{}
	var early atomic.Int32
	api.onRequest = func() {
		if notice == "" || !strings.Contains(log.stderr(), notice+"\n") {
			early.Add(1)
		}
	}

	e := llmEnv(t, tools)
	c, _, _ := e.cli(insp)
	c.stdout = llmLogWriter{log: log, stdout: true}
	c.stderr = llmLogWriter{log: log}
	c.getenv = fakeGetenv(map[string]string{"XDG_CONFIG_HOME": e.xdg, "HOME": e.home, llm.KeyEnv: llmTestKey})
	c.newClassifier = newLLMClassifier

	code := c.dispatch(append([]string{"scan", "--config", e.config, "--llm", "--llm-base-url", api.srv.URL}, args...))

	r := llmLimitsRun{code: code, host: api.host, early: early.Load(), pinsPath: e.pinsPath()}
	r.stdout, r.stderr, r.events = log.snapshot()
	llmAssertNoKey(t, llmTestKey, r.stdout, r.stderr)
	assertNoEscape(t, r.stdout, r.stderr)
	for i, req := range api.snapshot() {
		if req.err != nil {
			t.Fatalf("request %d: %v\nbody: %s", i, req.err, req.body)
		}
		r.sent = append(r.sent, req.payload.ToolName)
	}
	if n := int(api.requests.Load()); n != len(r.sent) {
		t.Errorf("the API counted %d requests but recorded %d bodies", n, len(r.sent))
	}
	return r
}

// llmManyTools returns n tools named <prefix>000, <prefix>001 and so on, with
// the description desc.
func llmManyTools(prefix string, n int, desc string) []inspect.Tool {
	tools := make([]inspect.Tool, n)
	for i := range tools {
		tools[i] = mkTool(fmt.Sprintf("%s%03d", prefix, i), desc)
	}
	return tools
}

// TestScanLLMFairCap checks the fair share of the cap in a whole scan with the
// real client: when one server lists 600 tools and another 10, the provider
// gets exactly 500 requests, all 10 tools of the small server are among them
// (with their findings in the report), and the big server sends its first
// 490. The scan exits with 2 and complete false, the cap line says that 110
// tools were not classified, and the notice before the first request says
// that 500 tools are sent. One server with 503 tools still sends its first
// 500. In --json and in the terminal report.
func TestScanLLMFairCap(t *testing.T) {
	t.Parallel()

	// The small server's tools are rated high, so its findings show that
	// they were classified. The big server's tools are rated none.
	const highDesc = "Read keys. " + llmMarkHigh // 19 bytes
	tests := []struct {
		name  string
		tools map[string][]inspect.Tool
		// wantSent is the tool names that the API must get, in any order.
		wantSent []string
		// wantRows is the LLM findings, in order.
		wantRows []llmHit
		notSent  int
		kib      int
		// pinned is the pin lines, in the order of the servers.
		pinned []string
	}{
		{
			// alpha comes first in the scan. 490 x (4 + 6) + 10 x (4 +
			// 19) = 5130 bytes: 5.01 KiB, shown as 6 KiB.
			name: "big server first",
			tools: map[string][]inspect.Tool{
				"alpha": llmManyTools("a", 600, "Plain."),
				"beta":  llmManyTools("b", 10, highDesc),
			},
			wantSent: append(llmToolNames("a", 490), llmToolNames("b", 10)...),
			wantRows: llmHighRows("beta", llmToolNames("b", 10)),
			notSent:  110,
			kib:      6,
			pinned:   []string{"pinned 600 tools for alpha", "pinned 10 tools for beta"},
		},
		{
			name: "big server last",
			tools: map[string][]inspect.Tool{
				"alpha": llmManyTools("a", 10, highDesc),
				"beta":  llmManyTools("b", 600, "Plain."),
			},
			wantSent: append(llmToolNames("a", 10), llmToolNames("b", 490)...),
			wantRows: llmHighRows("alpha", llmToolNames("a", 10)),
			notSent:  110,
			kib:      6,
			pinned:   []string{"pinned 10 tools for alpha", "pinned 600 tools for beta"},
		},
		{
			// One server takes the whole cap. 500 x (4 + 6) = 5000 bytes:
			// 4.9 KiB, shown as 5 KiB.
			name:     "one server with 503 tools",
			tools:    map[string][]inspect.Tool{"alpha": llmManyTools("a", 503, "Plain.")},
			wantSent: llmToolNames("a", 500),
			notSent:  3,
			kib:      5,
			pinned:   []string{"pinned 503 tools for alpha"},
		},
	}
	for _, tt := range tests {
		for _, jsonOut := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%v", tt.name, jsonOut), func(t *testing.T) {
				t.Parallel()
				var args []string
				if jsonOut {
					args = []string{"--json"}
				}
				notice := llmSendingLine(llmWantCap, tt.kib)

				r := llmLimitsScan(t, tt.tools, fakeServers(tt.tools), notice, args...)

				if r.code != exitError {
					t.Errorf("exit code = %d, want %d (tools over the cap)\nstderr:\n%s", r.code, exitError, r.stderr)
				}
				if len(r.sent) != llmWantCap {
					t.Errorf("the API got %d requests, want %d", len(r.sent), llmWantCap)
				}
				sent := slices.Sorted(slices.Values(r.sent))
				if want := slices.Sorted(slices.Values(tt.wantSent)); !slices.Equal(sent, want) {
					t.Errorf("tools sent = %s\nwant %s", llmShortList(sent), llmShortList(want))
				}
				if r.early != 0 {
					t.Errorf("%d requests arrived before the notice was on stderr", r.early)
				}
				// The setup warning, the notice before the requests, the cap
				// line after the requests, and the pin lines. No failure line.
				// The cap line names all the tools over the shares, in one
				// line also when two servers are cut.
				want := []lineWant{exactLine(llmWarning("anthropic", r.host)), exactLine(notice), exactLine(llmCapLine(tt.notSent))}
				want = append(want, withPinsNotice(r.pinsPath, tt.pinned)...)
				assertStderrLines(t, r.stderr, want)
				if llmNotClassified.MatchString(r.stderr) || llmInternalFailed.MatchString(r.stderr) {
					t.Errorf("stderr reports a failure of the LLM step, want only the cap line:\n%s", r.stderr)
				}
				assertContainsNone(t, "stdout", r.stdout, []string{"sending ", "not classified"})

				rows := llmJSONOrTerminalRows(t, r.stdout, jsonOut)
				if !slices.Equal(rows, tt.wantRows) {
					t.Errorf("LLM findings = %+v, want %+v", rows, tt.wantRows)
				}
				if jsonOut {
					doc := decodeScanJSON(t, r.stdout)
					if doc.Complete {
						t.Errorf("complete = true, want false (tools over the cap)")
					}
					if len(doc.Servers) != len(tt.tools) {
						t.Errorf("JSON has %d servers, want %d: the report must still print", len(doc.Servers), len(tt.tools))
					}
				} else if !strings.Contains(r.stdout, summaryHeading) {
					t.Errorf("stdout has no SUMMARY block: the report must still print\nstdout:\n%s", r.stdout)
				}
			})
		}
	}
}

// llmHighRows returns one high MOAT-LLM-001 finding of server for each tool.
func llmHighRows(server string, tools []string) []llmHit {
	rows := make([]llmHit, len(tools))
	for i, name := range tools {
		rows[i] = llmHit{llm.RuleID, "high", server, name}
	}
	return rows
}

// TestScanLLMSendingNotice checks the notice in a whole scan with the real
// client when no server is over the cap: it is printed once, after the setup
// warning and before the first request, with the number of tools sent and
// their size, also with --json (on stderr; stdout stays pure JSON). It counts
// only the tools of the servers that were inspected. With no tool to send
// (a server with no tools, or a server that failed), no request is made and
// there is no notice, only the llmNoToolLine line.
func TestScanLLMSendingNotice(t *testing.T) {
	t.Parallel()

	failing := func(tools map[string][]inspect.Tool, bad string) inspect.Inspector {
		f := fakeServers(tools)
		f.Errors = map[string]error{bad: errors.New("boom")}
		return f
	}

	tests := []struct {
		name  string
		tools map[string][]inspect.Tool
		// insp answers the inspection; nil means fakeServers(tools).
		insp     func(tools map[string][]inspect.Tool) inspect.Inspector
		wantSent []string
		wantCode int
		wantRows []llmHit
		// notice is the notice line; "" means none.
		notice string
		// wantLines is the stderr lines after the setup warning, without
		// the prefix "mcpmoat scan: ".
		wantLines []string
		// failed is true when the server alpha fails. With --json, stderr
		// then holds its warning right after the setup warning; the terminal
		// report shows the failure on stdout instead.
		failed bool
	}{
		{
			// 3 + 2 tools of 2 + 6 or 2 + 19 bytes: far below 1 KiB.
			name: "two small servers",
			tools: map[string][]inspect.Tool{
				"alpha": {mkTool("a1", "Plain."), mkTool("a2", "Read keys. "+llmMarkHigh), mkTool("a3", "Plain.")},
				"beta":  {mkTool("b1", "Plain."), mkTool("b2", "Plain.")},
			},
			wantSent:  []string{"a1", "a2", "a3", "b1", "b2"},
			wantCode:  exitFindings,
			wantRows:  []llmHit{{llm.RuleID, "high", "alpha", "a2"}},
			notice:    llmSendingLine(5, 1),
			wantLines: []string{"sending 5 tools (about 1 KiB of text) to the LLM provider", "pinned 3 tools for alpha", "pinned 2 tools for beta"},
		},
		{
			// One tool of 2 + 2000 bytes: 1.96 KiB, shown as 2 KiB.
			name:      "one tool",
			tools:     map[string][]inspect.Tool{"alpha": {mkTool("a1", strings.Repeat("p", 2000))}},
			wantSent:  []string{"a1"},
			wantCode:  exitOK,
			notice:    llmSendingLine(1, 2),
			wantLines: []string{"sending 1 tool (about 2 KiB of text) to the LLM provider", "pinned 1 tool for alpha"},
		},
		{
			// The failed server sends nothing and is not counted.
			name: "a server failed, the other has tools",
			tools: map[string][]inspect.Tool{
				"alpha": nil,
				"beta":  {mkTool("b1", "Plain."), mkTool("b2", "Plain.")},
			},
			insp:      func(tools map[string][]inspect.Tool) inspect.Inspector { return failing(tools, "alpha") },
			wantSent:  []string{"b1", "b2"},
			wantCode:  exitOK,
			notice:    llmSendingLine(2, 1),
			wantLines: []string{"sending 2 tools (about 1 KiB of text) to the LLM provider", "pinned 2 tools for beta"},
			failed:    true,
		},
		{
			name:      "a server with no tools",
			tools:     map[string][]inspect.Tool{"alpha": nil},
			wantCode:  exitOK,
			wantLines: []string{"--llm had no tool to classify", "pinned 0 tools for alpha"},
		},
		{
			name:      "the only server failed",
			tools:     map[string][]inspect.Tool{"alpha": nil},
			insp:      func(tools map[string][]inspect.Tool) inspect.Inspector { return failing(tools, "alpha") },
			wantCode:  exitOK,
			wantLines: []string{"--llm had no tool to classify"},
			failed:    true,
		},
	}
	for _, tt := range tests {
		for _, jsonOut := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%v", tt.name, jsonOut), func(t *testing.T) {
				t.Parallel()
				var args []string
				if jsonOut {
					args = []string{"--json"}
				}
				insp := inspect.Inspector(fakeServers(tt.tools))
				if tt.insp != nil {
					insp = tt.insp(tt.tools)
				}

				r := llmLimitsScan(t, tt.tools, insp, tt.notice, args...)

				if r.code != tt.wantCode {
					t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, tt.wantCode, r.stderr)
				}
				if sent := slices.Sorted(slices.Values(r.sent)); !slices.Equal(sent, tt.wantSent) {
					t.Errorf("tools sent = %v, want %v", sent, tt.wantSent)
				}
				if r.early != 0 {
					t.Errorf("%d requests arrived before the notice was on stderr", r.early)
				}
				lines := nonEmptyLines(r.stderr)
				if len(lines) == 0 || lines[0] != llmWarning("anthropic", r.host) {
					t.Fatalf("first stderr line = %q, want the setup warning\nstderr:\n%s", lines[:min(len(lines), 1)], r.stderr)
				}
				noticeLines := 0
				for _, line := range lines {
					if strings.HasPrefix(line, scanPrefix+"sending ") {
						noticeLines++
					}
				}
				if tt.notice == "" {
					if noticeLines != 0 {
						t.Errorf("stderr has %d notice lines, want none: no tool is sent\nstderr:\n%s", noticeLines, r.stderr)
					}
					if n := strings.Count(r.stderr, llmNoToolLine); n != 1 {
						t.Errorf("stderr holds %q %d times, want 1\nstderr:\n%s", llmNoToolLine, n, r.stderr)
					}
				} else {
					if noticeLines != 1 {
						t.Errorf("stderr has %d notice lines, want 1\nstderr:\n%s", noticeLines, r.stderr)
					}
					if strings.Contains(r.stderr, llmNoToolLine) {
						t.Errorf("stderr holds %q, but tools were sent", llmNoToolLine)
					}
				}
				// The exact lines, in order: the setup warning, the warnings
				// of the inspection, the notice before the requests (or the
				// line for no tool), then the notice of the new pins file and
				// the pin lines.
				want := []lineWant{exactLine(llmWarning("anthropic", r.host))}
				if tt.failed && jsonOut {
					want = append(want, exactLine(scanWarnPrefix+"server alpha: failed: inspect: boom"))
				}
				want = append(want, withPinsNotice(r.pinsPath, tt.wantLines)...)
				assertStderrLines(t, r.stderr, want)
				assertContainsNone(t, "stdout", r.stdout, []string{"sending ", "KiB"})
				// No stdout write comes before the notice.
				if tt.notice != "" {
					for _, ev := range r.events {
						if strings.Contains(ev.text, tt.notice) {
							break
						}
						if ev.stdout {
							t.Errorf("stdout was written before the notice: %q", ev.text)
							break
						}
					}
				}
				if rows := llmJSONOrTerminalRows(t, r.stdout, jsonOut); !slices.Equal(rows, tt.wantRows) {
					t.Errorf("LLM findings = %+v, want %+v", rows, tt.wantRows)
				}
				if jsonOut {
					if doc := decodeScanJSON(t, r.stdout); !doc.Complete {
						t.Errorf("complete = false, want true (no tool over the cap, no failure)")
					}
				}
			})
		}
	}
}
