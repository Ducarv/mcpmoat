package report

import (
	"bufio"
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
//
// Version 3 adds ScanReport.Ignored, ScanReport.FieldsTruncated and
// JSONServer.Accept.
//
// Version 4 adds JSONFinding.ServerIndex and JSONDiff.ServerIndex
// (server_index).
//
// Version 5 adds JSONAccept.Reason (reason).
const SchemaVersion = 5

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
	// Complete is true when the report holds every result of the scan steps:
	// the configs were read, the servers were inspected, the rules ran, and
	// the LLM step (with --llm) classified every tool. It is false when the
	// report can miss results, and scan then exits with 2: a config file has
	// a problem (see Errors), or the inspection or the pin step failed as a
	// whole (pins.json cannot be read, for example), or the LLM step did not
	// classify every tool: a provider failure, an internal error of the LLM
	// step, or more tools than the --llm cap. The reason is on stderr only.
	//
	// Complete does not cover the save of new pins. scan saves them after it
	// writes the report, so that the user sees the report first. A failed
	// save gives exit code 2 with Complete true. A consumer must read the
	// exit code too.
	Complete bool `json:"complete"`
	// FieldsTruncated is true when WriteJSON cut at least one long text field
	// (a name or a path) of the report, so that value is not the whole text.
	// The cut text ends with termsafe.CutMarker. A caller can set it to true
	// too, and WriteJSON never sets it back to false.
	FieldsTruncated bool            `json:"fields_truncated"`
	Servers         []JSONServer    `json:"servers"`
	Findings        []JSONFinding   `json:"findings"`
	Diffs           []JSONDiff      `json:"diffs"`
	Errors          []JSONFileError `json:"errors"`
	// Ignored tells how many findings an ignore entry dropped. It is always
	// present, with zero counts when nothing was ignored.
	Ignored JSONIgnored `json:"ignored"`
}

// JSONIgnored counts the findings that an ignore entry dropped from the report:
// an entry of .mcpmoat-ignore or an --ignore flag. Rules maps a rule ID to the
// number of findings dropped for that rule. Its keys are rule IDs only, never
// text from the ignore file. Total is the sum of Rules: it is the number in the
// "N findings ignored" line on stderr. FileEntries is the number of entries
// read from .mcpmoat-ignore (the N in the stderr line "using N entries").
type JSONIgnored struct {
	Total       int            `json:"total"`
	Rules       map[string]int `json:"rules"`
	FileEntries int            `json:"file_entries"`
}

// The values of JSONAccept.Reason. Each one is the first cause that stops the
// terminal hint from showing a command. The set is fixed: the schema lists the
// same words, and a test checks that the two agree.
const (
	// AcceptReasonReview means that the user did not see every change: a diff
	// was cut, --ignore hid a change, or a diff is only a fixed note. Review
	// the tools first.
	AcceptReasonReview = "review_first"
	// AcceptReasonPinsFull means that pins.json has no room for the tools, so
	// "pin --accept" would fail.
	AcceptReasonPinsFull = "pins_full"
	// AcceptReasonProjectShareFull means that the project share of pins.json
	// has no room for the tools, so "pin --accept" would fail.
	AcceptReasonProjectShareFull = "project_share_full"
	// AcceptReasonConfigProblem means that a config file has a problem, so
	// "pin" refuses to run until the file is fixed.
	AcceptReasonConfigProblem = "config_problem"
	// AcceptReasonAmbiguousName means that the server name does not select
	// this server alone, so "pin" needs --config.
	AcceptReasonAmbiguousName = "ambiguous_name"
	// AcceptReasonNotShellSafe means that the server name, the project path or
	// the --config path is not a bare shell word, so mcpmoat prints no command
	// that a shell could misread.
	AcceptReasonNotShellSafe = "not_shell_safe"
)

// AcceptReasons lists the values of JSONAccept.Reason.
func AcceptReasons() []string {
	return []string{
		AcceptReasonReview,
		AcceptReasonPinsFull,
		AcceptReasonProjectShareFull,
		AcceptReasonConfigProblem,
		AcceptReasonAmbiguousName,
		AcceptReasonNotShellSafe,
	}
}

// JSONAccept is the hint that tells how to accept the changes of a server. The
// terminal report shows the same hint. Digest is the pin digest that the
// terminal hint shows. Command is set only when the terminal hint shows a
// command, never when it shows prose steps. Reason is set only when Command is
// empty: it is one of the AcceptReason* words, the first cause that stops the
// command. WriteJSON never cuts Digest, Command or Reason.
type JSONAccept struct {
	Digest  string `json:"digest"`
	Command string `json:"command,omitempty"`
	Reason  string `json:"reason,omitempty"`
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
	// Accept is set only for a server that has changes to accept. It is left
	// out when there is nothing to accept.
	Accept *JSONAccept `json:"accept,omitempty"`
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
	// ServerIndex is the position of the server in ScanReport.Servers. A long
	// Server name is cut, so two names can be the same after the cut. The
	// index still tells the servers apart.
	ServerIndex int    `json:"server_index"`
	Field       string `json:"field"`
	Key         string `json:"key"`
	Related     string `json:"related"`
	// Source is "rule" for a finding from a rule, and "llm" for an advisory
	// finding from the LLM classification (see SourceRule and SourceLLM).
	Source Source `json:"source"`
}

// JSONDiff is the diff of one tool in the JSON report.
type JSONDiff struct {
	Server string `json:"server"`
	// ServerIndex is the position of the server in ScanReport.Servers (see
	// JSONFinding.ServerIndex).
	ServerIndex int    `json:"server_index"`
	Tool        string `json:"tool"`
	Kind        string `json:"kind"`
	Diff        string `json:"diff"`
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
// report. The JSON form has the server name and the server index
// (r.Index): the client, the scope, the title and the rule texts of the
// terminal report are not in it (a new field bumps the version).
func NewJSONFinding(r FindingRow) JSONFinding {
	return JSONFinding{
		RuleID:      r.RuleID,
		Severity:    r.Severity,
		Server:      r.Name,
		ServerIndex: r.Index,
		Field:       r.Field,
		Key:         r.Key,
		Related:     r.Related,
		Source:      r.Source.normalize(),
	}
}

// NewJSONDiff converts a tool diff to its JSON form. It copies d.ServerIndex
// to server_index.
func NewJSONDiff(d ToolDiff) JSONDiff {
	return JSONDiff{
		Server:      d.Server,
		ServerIndex: d.ServerIndex,
		Tool:        d.Tool,
		Kind:        d.Kind.String(),
		Diff:        d.Diff,
		Truncated:   d.Truncated,
		IsNote:      d.IsNote,
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
// lists show as [] and never as null, and Ignored.Rules shows as {} and never
// as null.
//
// Long names and paths are cut (see boundReport). When WriteJSON cuts at least
// one field, it sets FieldsTruncated to true in the output. It does not change
// the report of the caller.
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
// WriteJSON streams the document: it encodes and escapes one list element at a
// time, so its memory follows the largest element and not the whole output.
// The bytes are the same as when the whole document is encoded in one call
// with json.Encoder and SetIndent. If a write fails, w may already hold the
// first part of the document. WriteJSON wraps the error of the encoder or of
// the write. Callers must check it: a failed write has to become exit code 2
// in cmd/mcpmoat.
//
// WriteJSON writes Complete as the caller set it. Complete does not cover the
// pin save of scan (see ScanReport.Complete).
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

	// Same for the map: a nil map would show as null. r is a copy, but the
	// map of Ignored.Rules is shared with the caller, so WriteJSON only
	// replaces a nil map. It never writes to a map of the caller.
	if r.Ignored.Rules == nil {
		r.Ignored.Rules = map[string]int{}
	}

	// Cut the long untrusted text fields. boundReport returns a copy, so the
	// slices of the caller stay as they are.
	bounded, truncated := boundReport(r)
	bounded.FieldsTruncated = truncated || r.FieldsTruncated
	r = bounded

	// The object is written by hand, key by key, in the field order of
	// ScanReport. A new field of ScanReport needs a line here:
	// TestWriteJSONMatchesReference and the schema guard test catch a
	// forgotten one. Each value is encoded on its own with the indent prefix that
	// it has inside the whole document, so the bytes are the same as one
	// Encode call for the whole struct.
	s := newJSONStream(w)
	s.raw("{\n")
	s.field("schema_version", r.SchemaVersion)
	s.field("tool", r.Tool)
	s.field("mode", r.Mode)
	s.field("complete", r.Complete)
	s.field("fields_truncated", r.FieldsTruncated)
	streamList(s, "servers", r.Servers)
	streamList(s, "findings", r.Findings)
	streamList(s, "diffs", r.Diffs)
	streamList(s, "errors", r.Errors)
	s.field("ignored", r.Ignored)
	s.raw("\n}\n")
	return s.finish()
}

// The indent of the report: two spaces for each level. A key of the top-level
// object is at level 1 and a list element is at level 2.
const (
	jsonIndent      = "  "
	jsonFieldPrefix = jsonIndent
	jsonItemPrefix  = jsonIndent + jsonIndent
)

// jsonStream writes the JSON report in pieces to a buffered writer.
//
// It keeps the first error in err and does nothing after that. The caller
// writes many pieces in a row and checks the error once, in finish. This is the
// "errors are values" idiom from the Go blog, and it saves an "if err != nil"
// after each piece.
type jsonStream struct {
	bw *bufio.Writer
	// buf and enc are reused for each value. buf grows to the size of the
	// largest value, and that is the peak memory of WriteJSON.
	buf bytes.Buffer
	enc *json.Encoder
	// fields counts the keys written to the top-level object, to place commas.
	fields int
	err    error
}

func newJSONStream(w io.Writer) *jsonStream {
	s := &jsonStream{bw: bufio.NewWriter(w)}
	s.enc = json.NewEncoder(&s.buf)
	s.enc.SetEscapeHTML(false)
	return s
}

// raw writes fixed text: braces, commas, newlines and key names.
func (s *jsonStream) raw(text string) {
	if s.err != nil {
		return
	}
	if _, err := s.bw.WriteString(text); err != nil {
		s.err = fmt.Errorf("write scan report: %w", err)
	}
}

// value encodes v as indented JSON and writes it without a trailing newline.
// prefix is written before each line of the value except the first, so a nested
// value lines up as it does in the whole document. The caller has already
// written the indent of the first line.
func (s *jsonStream) value(v any, prefix string) {
	if s.err != nil {
		return
	}
	s.buf.Reset()
	s.enc.SetIndent(prefix, jsonIndent)
	if err := s.enc.Encode(v); err != nil {
		s.err = fmt.Errorf("encode scan report: %w", err)
		return
	}
	// Encode ends the value with a newline. Remove it: the caller places the
	// separators. escapeUnsafeRunes is safe on one complete value, as it is on
	// the whole document, because it only changes runes inside strings.
	text := bytes.TrimSuffix(s.buf.Bytes(), []byte("\n"))
	if _, err := s.bw.Write(escapeUnsafeRunes(text)); err != nil {
		s.err = fmt.Errorf("write scan report: %w", err)
	}
}

// key starts a field of the top-level object: the comma after the previous
// field, then the indent and the name.
func (s *jsonStream) key(name string) {
	if s.fields > 0 {
		s.raw(",\n")
	}
	s.fields++
	s.raw(jsonFieldPrefix + `"` + name + `": `)
}

// field writes the key and then v, which is a scalar or a small object.
func (s *jsonStream) field(name string, v any) {
	s.key(name)
	s.value(v, jsonFieldPrefix)
}

// finish flushes the buffer and returns the first error.
func (s *jsonStream) finish() error {
	if s.err != nil {
		return s.err
	}
	if err := s.bw.Flush(); err != nil {
		return fmt.Errorf("write scan report: %w", err)
	}
	return nil
}

// streamList writes a list field with one element at a time. An empty list is
// [] on one line, as json.Encoder writes it. A method cannot have its own type
// parameter in Go, so this is a function and not a method of jsonStream.
func streamList[T any](s *jsonStream, name string, items []T) {
	s.key(name)
	if len(items) == 0 {
		s.raw("[]")
		return
	}
	s.raw("[\n")
	for i, item := range items {
		if i > 0 {
			s.raw(",\n")
		}
		s.raw(jsonItemPrefix)
		s.value(item, jsonItemPrefix)
	}
	s.raw("\n" + jsonFieldPrefix + "]")
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
