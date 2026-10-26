package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// SchemaVersion is the version of the JSON report format (FR-15). Bump it,
// and add docs/schema/scan-output.v<N>.json, when a field is added, renamed or
// removed, or changes type or meaning. An added field needs a bump too: every
// object in the schema sets additionalProperties to false.
//
// Version 2 adds JSONFinding.Source.
const SchemaVersion = 2

// Mode tells if a scan connected to the servers. It is the type of
// ScanReport.Mode.
type Mode string

// The values of ScanReport.Mode.
const (
	// ModeNoConnect is a scan that only reads configs (--no-connect).
	ModeNoConnect Mode = "no-connect"
	// ModeConnect is a scan that also connects to the servers.
	ModeConnect Mode = "connect"
)

// InspectionStatus tells what happened when mcpmoat inspected one server. It
// is the type of JSONInspection.Status.
type InspectionStatus string

// The values of JSONInspection.Status.
const (
	// InspectionNotRun means that mcpmoat did not connect to the server.
	InspectionNotRun InspectionStatus = "not_run"
	// InspectionOK means that mcpmoat connected and listed the tools.
	InspectionOK InspectionStatus = "ok"
	// InspectionTimeout means that the server did not answer in time.
	InspectionTimeout InspectionStatus = "timeout"
	// InspectionFailed means that the connection or the tool list failed.
	InspectionFailed InspectionStatus = "failed"
	// InspectionRefused means that mcpmoat chose not to connect, for example
	// to a disabled or untrusted server.
	InspectionRefused InspectionStatus = "refused"
)

// ScanReport is the JSON report of one scan. It holds plain strings, bools and
// ints only, never a discover type, so no secret can reach the output by
// accident.
type ScanReport struct {
	SchemaVersion int      `json:"schema_version"`
	Tool          ToolInfo `json:"tool"`
	Mode          Mode     `json:"mode"`
	// Complete is false when the report can miss results, and scan then
	// exits with 2: a config file has a problem (see Errors), or the
	// inspection or the pin step failed as a whole (pins.json cannot be read,
	// for example), or the LLM step did not classify every tool: a provider
	// failure, an internal error of the LLM step, or more tools than the
	// --llm cap. The reason is on stderr only.
	Complete bool            `json:"complete"`
	Servers  []JSONServer    `json:"servers"`
	Findings []JSONFinding   `json:"findings"`
	Diffs    []JSONDiff      `json:"diffs"`
	Errors   []JSONFileError `json:"errors"`
}

// ToolInfo names the program that made the report.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// JSONServer is one server in the JSON report. Argv is set for stdio servers
// and URL for http and sse servers. Both are redacted. There is no env, no
// header and no working directory.
type JSONServer struct {
	Name        string         `json:"name"`
	Client      string         `json:"client"`
	Scope       string         `json:"scope"`
	ProjectPath string         `json:"project_path"`
	Untrusted   bool           `json:"untrusted"`
	State       string         `json:"state"`
	Transport   string         `json:"transport"`
	Source      string         `json:"source"`
	Argv        []string       `json:"argv,omitempty"`
	URL         string         `json:"url,omitempty"`
	Inspection  JSONInspection `json:"inspection"`
}

// JSONInspection tells what happened when mcpmoat inspected a server.
type JSONInspection struct {
	// Status is one of the InspectionStatus constants.
	Status InspectionStatus `json:"status"`
}

// JSONFinding is one finding in the JSON report. An empty string means that
// the field does not apply, except for Source, which is never empty.
type JSONFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Server   string `json:"server"`
	Field    string `json:"field"`
	Key      string `json:"key"`
	Related  string `json:"related"`
	// Source is "rule" for a finding from a rule, and "llm" for an advisory
	// finding from the LLM classification (see SourceRule and SourceLLM).
	Source Source `json:"source"`
}

// JSONDiff is the diff of one tool in the JSON report.
type JSONDiff struct {
	Server string `json:"server"`
	Tool   string `json:"tool"`
	Kind   string `json:"kind"`
	Diff   string `json:"diff"`
	// Truncated is true when the stored diff was cut, so Diff is not the
	// whole diff.
	Truncated bool `json:"diff_truncated"`
	// IsNote is true when Diff is a fixed note of mcpmoat, not a unified diff:
	// the diff could not be made, or the change does not show in the rendered
	// text.
	IsNote bool `json:"diff_is_note"`
}

// JSONFileError is one config problem in the JSON report. Reason is fixed
// text. The text of the underlying error is never included.
type JSONFileError struct {
	Path        string `json:"path"`
	ProjectPath string `json:"project_path"`
	Server      string `json:"server"`
	Line        int    `json:"line"`
	Col         int    `json:"col"`
	Reason      string `json:"reason"`
	Untrusted   bool   `json:"untrusted"`
}

// NewJSONServer converts s to its JSON form. status is one of the
// InspectionStatus constants. The command line and the URL are redacted like
// in WriteServers. The text is not quoted: JSON escaping does that job (see
// WriteJSON).
func NewJSONServer(s discover.Server, status InspectionStatus) JSONServer {
	js := JSONServer{
		Name:        s.Name,
		Client:      string(s.Client),
		Scope:       string(s.Scope),
		ProjectPath: s.ProjectPath,
		Untrusted:   s.Untrusted,
		State:       s.State.String(),
		Transport:   string(s.Transport),
		Source:      s.Source,
		Inspection:  JSONInspection{Status: status},
	}
	// Same rule as commandCell: remote servers show the URL, all others
	// (stdio and any unknown transport) show the command line.
	if s.Transport.IsRemote() {
		js.URL = s.URL.String()
	} else {
		js.Argv = redactedArgv(s.Command, s.Args)
	}
	return js
}

// NewJSONFinding converts a finding row to its JSON form. Any r.Source other
// than "llm" (an empty or an unknown value) becomes "rule", as in the terminal
// report. The JSON form has only the server name: the client, the scope, the
// title and the rule texts of the terminal report are not in it (a new field
// bumps the version).
func NewJSONFinding(r FindingRow) JSONFinding {
	return JSONFinding{
		RuleID:   r.RuleID,
		Severity: r.Severity,
		Server:   r.Name,
		Field:    r.Field,
		Key:      r.Key,
		Related:  r.Related,
		Source:   r.Source.normalize(),
	}
}

// NewJSONDiff converts a tool diff to its JSON form.
func NewJSONDiff(d ToolDiff) JSONDiff {
	return JSONDiff{
		Server:    d.Server,
		Tool:      d.Tool,
		Kind:      d.Kind.String(),
		Diff:      d.Diff,
		Truncated: d.Truncated,
		IsNote:    d.IsNote,
	}
}

// NewJSONFileError converts a config problem to its JSON form. It copies
// Reason, which is fixed text, and never the text of e.Err.
func NewJSONFileError(e *discover.FileError) JSONFileError {
	return JSONFileError{
		Path:        e.Path,
		ProjectPath: e.ProjectPath,
		Server:      e.Server,
		Line:        e.Line,
		Col:         e.Col,
		Reason:      e.Reason,
		Untrusted:   e.Untrusted,
	}
}

// WriteJSON writes r to w as indented JSON that ends with a newline. Empty
// lists show as [] and never as null.
//
// The output never holds env or header values: ScanReport has no field for
// them, and commands and URLs are redacted when the JSON types are built.
//
// Names, paths and diffs come from untrusted servers. Valid UTF-8 text stays
// lossless (encoding/json writes invalid bytes as U+FFFD), but every non-ASCII
// character that is not printable or not visible is written as a \uXXXX
// escape, in addition to the escapes of encoding/json for control characters.
// So a terminal that shows the output does not run control sequences or bidi
// tricks.
//
// WriteJSON writes once, after it has built the whole output, and wraps the
// error of the encoder or of the write. Callers must check it: a failed write
// has to become exit code 2 in cmd/mcpmoat.
func WriteJSON(w io.Writer, r ScanReport) error {
	// A nil slice would show as null. Use empty slices, so consumers can
	// always loop over the lists.
	if r.Servers == nil {
		r.Servers = []JSONServer{}
	}
	if r.Findings == nil {
		r.Findings = []JSONFinding{}
	}
	if r.Diffs == nil {
		r.Diffs = []JSONDiff{}
	}
	if r.Errors == nil {
		r.Errors = []JSONFileError{}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode scan report: %w", err)
	}

	if _, err := w.Write(escapeUnsafeRunes(buf.Bytes())); err != nil {
		return fmt.Errorf("write scan report: %w", err)
	}
	return nil
}

// escapeUnsafeRunes returns b with DEL (0x7f) and every non-ASCII rune that is
// not printable or not visible replaced by a \uXXXX escape (a surrogate pair
// above U+FFFF). encoding/json escapes the other ASCII control characters.
// This is safe on the whole output because JSON allows non-ASCII bytes only
// inside strings, and a \u escape means the same there as the rune itself.
func escapeUnsafeRunes(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		// encoding/json escapes the ASCII controls but not DEL. The bound
		// keeps the newlines and spaces of the indented output.
		if (r == 0x7f || r >= utf8.RuneSelf) && termsafe.NeedsEscape(r) {
			if utf16.RuneLen(r) == 2 {
				// Above U+FFFF JSON needs a surrogate pair.
				r1, r2 := utf16.EncodeRune(r)
				out = fmt.Appendf(out, `\u%04x\u%04x`, r1, r2)
			} else {
				out = fmt.Appendf(out, `\u%04x`, r)
			}
		} else {
			out = append(out, b[:size]...)
		}
		b = b[size:]
	}
	return out
}
