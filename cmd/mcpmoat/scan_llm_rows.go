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
// returns false when a gives no row: a verdict with risk none (and no cut or
// redacted text), or a job without an answer (see answerKind.answered).
//
// A verdict whose risk or category is not valid counts as an answer that
// cannot be used, so it fails closed. parseVerdict never returns one, but a
// classifier in a test can. A tool text that was not rated in full (see
// unrated) gets the floor row (see floorRow) when the model rated it none or
// low, or gave no usable answer, or the provider refused it. So such a tool
// always gets an llm.RuleID row of at least medium, and never an
// llm.RuleIDInvalid row.
//
// The Key is maskedToolKey of the name with job.redactor, as in a tool rule
// row: each secret value of the server (all of inspect.Result.Secrets) shows
// as discover.Mask, and then the name is cut to maxToolKeyRunes runes, or is
// noToolNameKey for an empty name. The mask comes before the cut, so a cut
// never leaves a part of a secret. All the rows below start from this row, so
// they all get the same Key.
// The ignore lookup in classifyPlan uses the real tool name, not the Key.
func llmRow(job llmJob, a llmAnswer) (report.FindingRow, bool) {
	row := report.FindingRow{
		ServerRef: job.ref,
		Source:    report.SourceLLM,
		Field:     rules.FieldTool,
		Key:       maskedToolKey(job.redactor, job.in.ToolName),
	}
	switch a.kind {
	case answerVerdict:
		v := a.verdict
		if !v.Risk.Valid() || !v.Category.Valid() {
			return unusableRow(row, v), true
		}
		if unrated(v) && belowMedium(v.Risk) {
			return floorRow(row, v), true
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
		return unusableRow(row, a.verdict), true
	case answerRejected:
		return rejectedRow(row, a.verdict), true
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

// unrated reports whether part of the tool text of v was not rated by the
// model: the text was cut (llm.Verdict.Truncated), or mcpmoat removed a
// configured value from it (llm.Verdict.Redacted). A hostile server or config
// can choose what is cut or removed, so the rating of such a tool is not
// trusted below medium.
func unrated(v llm.Verdict) bool {
	return v.Truncated || v.Redacted
}

// belowMedium reports whether the valid risk r of a verdict for an unrated
// tool text asks for the floor row: r is none or low.
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
// (see floorRow) when the tool text was not rated in full (see unrated), else
// an llm.RuleIDInvalid row with severity medium and the fixed texts of package
// llm.
func unusableRow(row report.FindingRow, v llm.Verdict) report.FindingRow {
	return invalidRow(row, v, llm.InvalidText)
}

// rejectedRow fills row for a tool that the provider refused
// (answerRejected): the same row as unusableRow, but with the risk text
// llm.RejectedText. An unrated tool gets the floor row (see floorRow).
func rejectedRow(row report.FindingRow, v llm.Verdict) report.FindingRow {
	return invalidRow(row, v, llm.RejectedText)
}

// invalidRow fills row for a tool without a usable rating: the floor row
// (see floorRow) when the tool text was not rated in full (see unrated), else
// an llm.RuleIDInvalid row with severity medium, the fixed risk text risk and
// the other fixed texts of package llm. risk is one of the fixed texts of
// package llm.
func invalidRow(row report.FindingRow, v llm.Verdict, risk string) report.FindingRow {
	if unrated(v) {
		return floorRow(row, v)
	}
	row.RuleID = llm.RuleIDInvalid
	row.Title = llm.InvalidTitle
	row.Severity = string(rules.SeverityMedium)
	row.Risk = risk
	row.Remediation = llm.InvalidRemediation
	return row
}

// floorRow fills row, an LLM row of a tool whose text was not rated in full
// (see unrated), as the floor row: llm.RuleID, severity medium and the
// category other, whatever the model answered. The risk text is
// llm.TruncatedText for a cut text, and llm.RedactedText when only a
// configured value was removed. A cut text wins when both are true: the cut
// is the larger gap, and one row has one text.
//
// The part after a cut was not rated, and so was the removed text. A prompt
// injection before the cut can ask for a low rating or make the model refuse,
// and a hostile config can choose which text it removes.
func floorRow(row report.FindingRow, v llm.Verdict) report.FindingRow {
	row = llmRuleRow(row)
	row.Severity = string(rules.SeverityMedium)
	row.Risk = llm.RedactedText
	if v.Truncated {
		row.Risk = llm.TruncatedText
	}
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
