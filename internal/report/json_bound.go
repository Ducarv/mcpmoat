package report

import (
	"slices"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// The JSON report keeps text in full, and a hostile project .mcp.json can make
// a name of many MiB that the report then repeats in every row. boundReport
// cuts the untrusted text fields to the lengths below, so the output stays
// small. The cut text ends with termsafe.CutMarker.

// jsonMaxNameRunes is the most runes that boundReport keeps from a name-like
// field: a server name, a tool name, a finding key or a related name. A cut
// value has this many runes and then termsafe.CutMarker (3 runes), so the
// longest output is 515 runes. The JSON schema uses 515 as maxLength.
const jsonMaxNameRunes = 512

// jsonMaxPathRunes is the most runes that boundReport keeps from a path-like
// field: a source file, a project path or a path in a config problem. A cut
// value has this many runes and then termsafe.CutMarker (3 runes), so the
// longest output is 4099 runes. The JSON schema uses 4099 as maxLength.
const jsonMaxPathRunes = 4096

// boundReport returns a copy of r in which the untrusted text fields are cut,
// and tells whether it cut anything. A field with no more runes than its cap is
// not changed, and has no marker.
//
// Cut to jsonMaxNameRunes (and then the marker):
//   - JSONServer.Name
//   - JSONFinding.Server, JSONFinding.Key and JSONFinding.Related
//   - JSONDiff.Server and JSONDiff.Tool
//   - JSONFileError.Server
//
// Cut to jsonMaxPathRunes (and then the marker):
//   - JSONServer.Source and JSONServer.ProjectPath
//   - JSONFileError.Path and JSONFileError.ProjectPath
//
// Never cut: JSONDiff.Diff (it has its own bound, see JSONDiff.Truncated),
// JSONServer.Argv and JSONServer.URL (a cut command line or URL would mislead),
// JSONServer.Accept (a cut digest or command would not work), the rule ID, the
// severity, the finding field and source, and every enum or fixed field
// (client, scope, state, transport, inspection status, kind, reason, mode,
// version).
//
// boundReport never changes the data of the caller. The slices of r are shared
// with the caller, so it copies each slice it needs to change before it writes
// to it. A cut of an invalid UTF-8 byte follows termsafe.Cut: the byte counts
// as one rune, and the JSON encoder writes it as U+FFFD later.
func boundReport(r ScanReport) (ScanReport, bool) {
	cut := false

	// A ScanReport is passed by value, but a slice value is only a pointer,
	// a length and a capacity. The copy r.Servers still points to the array of
	// the caller. slices.Clone makes a new array, so a write to an element
	// does not reach the caller.
	r.Servers = slices.Clone(r.Servers)
	for i := range r.Servers {
		// &r.Servers[i] is a pointer to the element in the new array, so the
		// helper can write the cut text back to it.
		s := &r.Servers[i]
		cut = cutField(&s.Name, jsonMaxNameRunes) || cut
		cut = cutField(&s.ProjectPath, jsonMaxPathRunes) || cut
		cut = cutField(&s.Source, jsonMaxPathRunes) || cut
	}

	r.Findings = slices.Clone(r.Findings)
	for i := range r.Findings {
		f := &r.Findings[i]
		cut = cutField(&f.Server, jsonMaxNameRunes) || cut
		cut = cutField(&f.Key, jsonMaxNameRunes) || cut
		cut = cutField(&f.Related, jsonMaxNameRunes) || cut
	}

	r.Diffs = slices.Clone(r.Diffs)
	for i := range r.Diffs {
		d := &r.Diffs[i]
		cut = cutField(&d.Server, jsonMaxNameRunes) || cut
		cut = cutField(&d.Tool, jsonMaxNameRunes) || cut
	}

	r.Errors = slices.Clone(r.Errors)
	for i := range r.Errors {
		e := &r.Errors[i]
		cut = cutField(&e.Path, jsonMaxPathRunes) || cut
		cut = cutField(&e.ProjectPath, jsonMaxPathRunes) || cut
		cut = cutField(&e.Server, jsonMaxNameRunes) || cut
	}

	return r, cut
}

// cutField cuts *s to limit runes and adds termsafe.CutMarker when *s had more
// than limit runes. It returns true in that case. Otherwise it changes nothing
// and returns false.
func cutField(s *string, limit int) bool {
	short, wasCut := termsafe.Cut(*s, limit)
	if !wasCut {
		return false
	}
	*s = short + termsafe.CutMarker
	return true
}
