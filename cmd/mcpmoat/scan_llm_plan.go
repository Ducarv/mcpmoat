package main

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// This file holds the plan of the LLM step of scan (--llm, FR-17): the
// jobs to send, and the fair share of the maxLLMTools cap for each server.

// maxLLMTools is the largest number of tools that one scan sends to the
// provider. It bounds the cost of a scan, and llmStepTimeout bounds its
// time. The client of package llm sends at most 3 requests for one tool
// (the first request and 2 retries), so one scan sends at most 1500
// requests. The servers share the cap fairly (see fairShare), so one
// server with many tools cannot use it all and leave the other servers
// without a rating.
const maxLLMTools = 500

// llmJob is one tool to classify.
type llmJob struct {
	// index is the index of the server in the servers of the scan
	// (inspect.Outcome.Index).
	index int
	// ref is the server of the finding row. ref.Name is the server name
	// from the config file. It is untrusted.
	ref report.ServerRef
	// in is what the classifier gets: the tool name and description, and the
	// secret values of the server (inspect.Result.Secrets). The classifier
	// sends only the name and the description, after it replaces each secret
	// value in them with discover.Mask (FR-17). The jobs of one server share
	// one Secrets slice: it is read only.
	in llm.Input
}

// llmPlan is the work of the LLM step, before the first request.
type llmPlan struct {
	// jobs are the tools to send, in the order of the servers
	// (inspect.Outcome.Index), then of the tools. Each server has at most its
	// share of maxLLMTools (see fairShare).
	jobs []llmJob
	// tools is the number of tools of the inspected servers, also the ones
	// over the shares.
	tools int
	// overCap is tools minus len(jobs): the tools over the shares, for all
	// the servers together. They are not sent.
	overCap int
}

// planLLMJobs returns the plan of the LLM step for the inspected servers in
// outcomes (see llmServerJobs). It splits maxLLMTools between the servers
// with fairShare, and keeps the first tools of each server up to its share,
// in the order that the server lists them. So a server with many tools
// cannot take the whole cap: a hostile server that lists thousands of tools
// still leaves a share to each other server.
func planLLMJobs(outcomes []inspect.Outcome) llmPlan {
	servers := llmServerJobs(outcomes)
	counts := make([]int, len(servers))
	for i, jobs := range servers {
		counts[i] = len(jobs)
	}
	shares := fairShare(counts, maxLLMTools)

	var plan llmPlan
	for i, jobs := range servers {
		plan.tools += len(jobs)
		plan.jobs = append(plan.jobs, jobs[:shares[i]]...)
	}
	plan.overCap = plan.tools - len(plan.jobs)
	return plan
}

// sendingNotice returns the text of the notice that llmStep prints on stderr
// before the first request: the number of jobs, and the size of the tool
// text that they send, in KiB rounded up. It holds numbers only: no tool
// text, no server name and nothing from the provider.
//
// The size is the sum of the bytes of each tool name and description after
// the cuts of package llm (llm.MaxToolNameBytes and llm.MaxDescriptionBytes).
// It is approximate ("about"): the masks of the secret values, the JSON
// escapes and the prompt change the real size of a request a little.
func (p llmPlan) sendingNotice() string {
	size := 0
	for _, job := range p.jobs {
		// min is a built-in function since Go 1.21.
		size += min(len(job.in.ToolName), llm.MaxToolNameBytes)
		size += min(len(job.in.Description), llm.MaxDescriptionBytes)
	}
	// Integer division rounds down. Adding 1023 first makes it round up, so
	// 1 byte shows as 1 KiB and not as 0 KiB.
	kib := (size + 1023) / 1024
	n := len(p.jobs)
	return fmt.Sprintf("sending %d %s (about %d KiB of text) to the LLM provider", n, plural(n, "tool", "tools"), kib)
}

// fairShare splits budget between servers that have counts[i] tools each,
// with a max-min fair share, and returns the share of each server, in the
// order of counts. A server never gets more than its count. A server with
// fewer tools than an equal part keeps all of them, and the part that it does
// not use goes to the other servers. The sum of the shares is the smaller of
// budget and the sum of counts.
//
// When the parts cannot be equal, the remainder goes to the servers that come
// first in counts, one tool each, so the result is always the same for the
// same input. For example, counts {3, 1000, 1000} with budget 500 give
// {3, 249, 248}. A count or a budget below 0 counts as 0.
func fairShare(counts []int, budget int) []int {
	shares := make([]int, len(counts))
	// order holds the indexes of counts, the smallest count first. The sort
	// is stable: servers with the same count keep the order of counts.
	order := make([]int, len(counts))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		return cmp.Compare(max(counts[a], 0), max(counts[b], 0))
	})

	// This is "water-filling". Go from the smallest server to the largest.
	// While a server has no more tools than an equal part of what is left,
	// it gets all its tools. The first server with more tools than that part
	// stops the loop: all the servers after it are at least as large, so they
	// all get an equal part of what is left.
	left := max(budget, 0)
	for k, i := range order {
		n := len(order) - k // the servers that have no share yet
		count := max(counts[i], 0)
		if count <= left/n {
			shares[i] = count
			left -= count
			continue
		}
		// Each of the n servers gets left/n tools, and the first left%n of
		// them in the order of counts get one tool more. Each one has more
		// than left/n tools, so it has the tool for the extra one.
		rest := slices.Sorted(slices.Values(order[k:]))
		for j, idx := range rest {
			shares[idx] = left / n
			if j < left%n {
				shares[idx]++
			}
		}
		break
	}
	return shares
}

// llmServerJobs returns, for each inspected server with at least one tool,
// one job for each of its tools, in the order of the tools. The servers are
// in their order in the scan (inspect.Outcome.Index). inspect.Run sorts the
// outcomes, so their order is not the order of the servers.
//
// Every job of a server gets the secret values of that server
// (inspect.Result.Secrets) in llm.Input.Secrets, so that llm removes them
// from the tool text before the request (FR-17). A server that got a token
// can put it in a tool name or description. The jobs share the slice of the
// outcome and never change it.
func llmServerJobs(outcomes []inspect.Outcome) [][]llmJob {
	sorted := slices.SortedStableFunc(slices.Values(outcomes), func(a, b inspect.Outcome) int {
		return cmp.Compare(a.Index, b.Index)
	})
	var servers [][]llmJob
	for _, o := range sorted {
		if o.Status != inspect.StatusOK || len(o.Result.Tools) == 0 {
			continue
		}
		ref := report.NewServerRef(o.Server)
		jobs := make([]llmJob, 0, len(o.Result.Tools))
		for _, t := range o.Result.Tools {
			jobs = append(jobs, llmJob{
				index: o.Index,
				ref:   ref,
				in: llm.Input{
					ToolName:    t.Name,
					Description: t.Description,
					Secrets:     o.Result.Secrets,
				},
			})
		}
		servers = append(servers, jobs)
	}
	return servers
}
