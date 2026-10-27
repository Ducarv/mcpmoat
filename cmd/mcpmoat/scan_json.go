package main

import (
	"maps"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/pins"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// programName is the name that the JSON report gives in its "tool" object.
const programName = "mcpmoat"

// scanJSONInput holds everything that buildScanReport needs to build the report
// of scan --json. It holds the same data as the terminal report, in the same
// order.
type scanJSONInput struct {
	// version is the version that "mcpmoat version" prints.
	version string
	// mode is report.ModeConnect when scan runs without --no-connect, and
	// report.ModeNoConnect otherwise.
	mode report.Mode
	// complete is the value of report.ScanReport.Complete.
	complete bool
	// res gives the scanned servers, in the order of the server table, and the
	// config problems that discover found.
	res discover.Result
	// rows are the findings, in the order of the findings table.
	rows []report.FindingRow
	// pr gives the diffs, the accept hints and the inspection status of each
	// server. It is the zero pinReport when scan did not connect, and then every
	// server has the status report.InspectionNotRun.
	pr pinReport
	// ignored holds, for each rule ID, the number of findings that the ignore
	// list dropped. It is the same map that printIgnored writes on stderr. Its
	// keys are rule IDs from findings, never text from the ignore file.
	ignored map[string]int
	// fileEntries is the number of entries that scan read from
	// .mcpmoat-ignore (see scanIgnores.fileEntries).
	fileEntries int
	// configPath is the --config value of the scan, or empty.
	configPath string
	// configProblem is true when a config file has a problem. The accept
	// command of a server depends on it (see acceptAdvice).
	configProblem bool
}

// writeScanJSON writes the report of reportScan as one JSON document on stdout
// (FR-15). Only the document goes to stdout: no table, no "No MCP servers
// found." line and no "To accept" lines. stderr is the same as without --json.
// The input is the one of buildScanReport.
func (c *cli) writeScanJSON(in scanJSONInput) error {
	return report.WriteJSON(c.stdout, buildScanReport(in))
}

// buildScanReport builds the report that scan --json writes on stdout (see
// scanJSONInput for the fields of in):
//   - Ignored holds a copy of in.ignored, and Total is the sum of its counts:
//     the number in the "N findings ignored" line on stderr (see printIgnored);
//   - a server that has an accept hint gets the digest of the hint, and the
//     command only when the terminal hint shows a command (see acceptOf).
//
// The report types hold plain text only. They have no field for env or header
// values, and no field for the text of an inspection error or of a warning.
func buildScanReport(in scanJSONInput) report.ScanReport {
	r := report.ScanReport{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.ToolInfo{Name: programName, Version: in.version},
		Mode:          in.mode,
		Complete:      in.complete,
		Ignored:       jsonIgnored(in.ignored, in.fileEntries),
	}
	hints := hintsByID(in.pr.hints)
	for _, s := range in.res.Servers {
		js := report.NewJSONServer(s, in.pr.inspectionOf(s))
		js.Accept = acceptOf(s, hints, in.configPath, in.configProblem)
		r.Servers = append(r.Servers, js)
	}
	for _, row := range in.rows {
		r.Findings = append(r.Findings, report.NewJSONFinding(row))
	}
	for _, d := range in.pr.diffs {
		r.Diffs = append(r.Diffs, report.NewJSONDiff(d))
	}
	for _, e := range in.res.Errors {
		r.Errors = append(r.Errors, report.NewJSONFileError(e))
	}
	return r
}

// jsonIgnored builds the Ignored part of the report. Rules is a copy of
// ignored, so the report never shares the map of the caller. Total is the sum
// of the counts, as in printIgnored. A nil or empty map gives empty Rules.
func jsonIgnored(ignored map[string]int, fileEntries int) report.JSONIgnored {
	total := 0
	for _, n := range ignored {
		total += n
	}
	return report.JSONIgnored{
		Total:       total,
		Rules:       maps.Clone(ignored),
		FileEntries: fileEntries,
	}
}

// acceptOf returns the accept hint of the server s for the JSON report, or nil
// when s has no hint (a first run, a server that cannot be pinned, unchanged
// tools, or no pin finding kept). It finds the hint by identity, like the
// terminal does: serverIdentity(s) must be a key of hints (see hintsByID).
// Digest is the string that the terminal hint prints. Command is set only when
// acceptAdvice says that the terminal text is a command, never for the prose
// steps.
func acceptOf(s discover.Server, hints map[pins.Identity]acceptHint, configPath string, configProblem bool) *report.JSONAccept {
	h, ok := hints[serverIdentity(s)]
	if !ok {
		return nil
	}
	a := &report.JSONAccept{Digest: h.digest}
	if text, isCommand := acceptAdvice(h, configPath, configProblem); isCommand {
		a.Command = text
	}
	return a
}

// hintsByID returns the hints by identity, so that buildScanReport finds the
// hint of each server without a scan of the whole list (a config can hold
// 10,000 servers). When two hints have the same identity, the first one counts.
func hintsByID(hints []acceptHint) map[pins.Identity]acceptHint {
	byID := make(map[pins.Identity]acceptHint, len(hints))
	for _, h := range hints {
		if _, dup := byID[h.id]; !dup {
			byID[h.id] = h
		}
	}
	return byID
}
