package main

import (
	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/report"
)

// programName is the name that the JSON report gives in its "tool" object.
const programName = "mcpmoat"

// writeScanJSON writes the report of reportScan as one JSON document on stdout
// (FR-15). Only the document goes to stdout: no table, no "No MCP servers
// found." line and no "To accept" lines. stderr is the same as without --json.
// connect is true when scan connected to the servers. complete is false when
// the report can miss results (see report.ScanReport.Complete).
func (c *cli) writeScanJSON(res discover.Result, rows []report.FindingRow, pr pinReport, connect, complete bool) error {
	mode := report.ModeNoConnect
	if connect {
		mode = report.ModeConnect
	}
	return report.WriteJSON(c.stdout, buildScanReport(c.build.version, mode, complete, res.Servers, rows, pr, res.Errors))
}

// buildScanReport builds the report that scan --json writes on stdout. It holds
// the same data as the terminal report, in the same order:
//   - version is the version that "mcpmoat version" prints;
//   - mode is report.ModeConnect when scan runs without --no-connect, and
//     report.ModeNoConnect otherwise;
//   - complete is the value of report.ScanReport.Complete;
//   - servers are the scanned servers, in the order of the server table;
//   - rows are the findings, in the order of the findings table;
//   - pr gives the diffs and the inspection status of each server. It is the
//     zero pinReport when scan did not connect, and then every server has the
//     status report.InspectionNotRun;
//   - fileErrors are the config problems that discover found.
//
// The report types hold plain text only. They have no field for env or header
// values, and no field for the text of an inspection error or of a warning.
func buildScanReport(version string, mode report.Mode, complete bool, servers []discover.Server, rows []report.FindingRow, pr pinReport, fileErrors []*discover.FileError) report.ScanReport {
	r := report.ScanReport{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.ToolInfo{Name: programName, Version: version},
		Mode:          mode,
		Complete:      complete,
	}
	for _, s := range servers {
		r.Servers = append(r.Servers, report.NewJSONServer(s, pr.inspectionOf(s)))
	}
	for _, row := range rows {
		r.Findings = append(r.Findings, report.NewJSONFinding(row))
	}
	for _, d := range pr.diffs {
		r.Diffs = append(r.Diffs, report.NewJSONDiff(d))
	}
	for _, e := range fileErrors {
		r.Errors = append(r.Errors, report.NewJSONFileError(e))
	}
	return r
}
