// Package report renders scan results as terminal text or as versioned JSON.
//
// The terminal report has these parts, in this order: the server table
// (WriteServers), the per-server summary (WriteSummary), the findings in groups
// by severity (WriteFindings) and the tool diffs (WriteDiffs). A Style turns
// colour on or off.
// With colour off, the output is plain text that carries all the meaning in
// words. Every text from a config file or a server is escaped with
// internal/termsafe before it is written, so the only escape sequences in the
// output are the colour codes of this package.
//
// See docs/PRD.md, FR-14 and FR-15.
package report
