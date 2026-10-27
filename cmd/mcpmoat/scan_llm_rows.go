package main

import (
	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// This file holds the finding rows of the LLM step of scan (--llm, FR-17):
// it turns the answer for one tool into a report row with fixed texts.

// noToolNameKey is the Key of an LLM finding row or a tool rule row (see
// toolKey) for a tool with an empty name. A hostile server can list such a
// tool. The report writers treat a row with an empty Key as a row about the
// whole server, so the row gets this fixed text instead. The request to the
// provider still has the real (empty) name.
const noToolNameKey = "(no name)"

// llmRow returns the finding row that the answer a of job gives, and true. It
// returns false when a gives no row: a verdict with risk none (and no cut
// text), or a job without an answer (see answerKind.answered).
//
// A verdict whose risk or category is not valid counts as an answer that
// cannot be used, so it fails closed. parseVerdict never returns one, but a
// classifier in a test can. A cut tool text (llm.Verdict.Truncated) gets the
// floor row (see truncatedRow) when the model rated it none or low, or gave
// no usable answer, or the provider refused it. So a cut tool always gets an
// llm.RuleID row of at least medium, and never an llm.RuleIDInvalid row.
//
// The Key is toolKey(job.in.ToolName), as in a tool rule row: the name cut to
// maxToolKeyRunes runes, or noToolNameKey for an empty name. All the rows
// below start from this row, so they all get the same Key. The ignore lookup
// in classifyPlan uses the real tool name, not the Key.
func llmRow(job llmJob, a llmAnswer) (report.FindingRow, bool) {
	row := report.FindingRow{
		ServerRef: job.ref,
		Source:    report.SourceLLM,
		Field:     rules.FieldTool,
		Key:       toolKey(job.in.ToolName),
	}
	switch a.kind {
	case answerVerdict:
		v := a.verdict
		if !v.Risk.Valid() || !v.Category.Valid() {
			return unusableRow(row, v.Truncated), true
		}
		if v.Truncated && belowMedium(v.Risk) {
			return truncatedRow(row), true
		}
		severity, hasRisk := llmSeverity(v.Risk)
		if !hasRisk {
			return report.FindingRow{}, false // risk none
		}
		row = llmRuleRow(row)
		row.Severity = string(severity)
		row.Risk = v.Category.Text()
		row.Related = string(v.Category)
		return row, true
	case answerUnusable:
		return unusableRow(row, a.verdict.Truncated), true
	case answerRejected:
		return rejectedRow(row, a.verdict.Truncated), true
	default:
		// answerNotRun, answerStopped, answerProviderFailed,
		// answerInternalFailed and answerDeadline: the tool got no answer.
		return report.FindingRow{}, false
	}
}

// llmSeverity returns the severity of a finding for the LLM risk r, and true.
// It is the one place that maps an llm.Risk to a rules.Severity: low, medium
// and high map to the severity with the same name. The cap is high, never
// critical: the model alone can never give the highest severity. For
// llm.RiskNone and for a risk that is not valid, it returns false and there
// is no finding.
func llmSeverity(r llm.Risk) (rules.Severity, bool) {
	switch r {
	case llm.RiskLow:
		return rules.SeverityLow, true
	case llm.RiskMedium:
		return rules.SeverityMedium, true
	case llm.RiskHigh:
		return rules.SeverityHigh, true
	default:
		return "", false
	}
}

// belowMedium reports whether the valid risk r of a verdict for a cut tool
// text asks for the floor row: r is none or low.
func belowMedium(r llm.Risk) bool {
	return r == llm.RiskNone || r == llm.RiskLow
}

// llmRuleRow fills the fixed texts of an llm.RuleID row into row: the rule
// ID, the title and the remediation.
func llmRuleRow(row report.FindingRow) report.FindingRow {
	row.RuleID = llm.RuleID
	row.Title = llm.Title
	row.Remediation = llm.Remediation
	return row
}

// unusableRow fills row for an answer that cannot be used: the floor row
// (see truncatedRow) when the tool text was cut, else an llm.RuleIDInvalid
// row with severity medium and the fixed texts of package llm.
func unusableRow(row report.FindingRow, truncated bool) report.FindingRow {
	return invalidRow(row, truncated, llm.InvalidText)
}

// rejectedRow fills row for a tool that the provider refused
// (answerRejected): the same row as unusableRow, but with the risk text
// llm.RejectedText. A cut tool gets the floor row (see truncatedRow).
func rejectedRow(row report.FindingRow, truncated bool) report.FindingRow {
	return invalidRow(row, truncated, llm.RejectedText)
}

// invalidRow fills row for a tool without a usable rating: the floor row
// (see truncatedRow) when the tool text was cut, else an llm.RuleIDInvalid
// row with severity medium, the fixed risk text risk and the other fixed
// texts of package llm. risk is one of the fixed texts of package llm.
func invalidRow(row report.FindingRow, truncated bool, risk string) report.FindingRow {
	if truncated {
		return truncatedRow(row)
	}
	row.RuleID = llm.RuleIDInvalid
	row.Title = llm.InvalidTitle
	row.Severity = string(rules.SeverityMedium)
	row.Risk = risk
	row.Remediation = llm.InvalidRemediation
	return row
}

// truncatedRow fills row, an LLM row of a tool whose text was cut, as the
// floor row: llm.RuleID, severity medium, the fixed text llm.TruncatedText
// and the category other, whatever the model answered. The part after the
// cut was not rated, and a prompt injection before the cut can ask for a low
// rating or make the model refuse.
func truncatedRow(row report.FindingRow) report.FindingRow {
	row = llmRuleRow(row)
	row.Severity = string(rules.SeverityMedium)
	row.Risk = llm.TruncatedText
	row.Related = string(llm.CategoryOther)
	return row
}

// addLLMCounts adds the LLM row counts of each server to counts, the
// finding counts by server index that serverStatuses gets. An index outside
// counts cannot happen; it is skipped rather than panic.
func addLLMCounts(counts []int, llmCounts map[int]int) {
	for i, n := range llmCounts {
		if i >= 0 && i < len(counts) {
			counts[i] += n
		}
	}
}
