package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// Reason is the type of the fixed reason texts of a LoadError. A Reason is
// always one of the constants below. Helpers that pick a reason return a
// Reason, not a string. Then a helper cannot return text that is not a
// constant, for example the text of a YAML library error, without an explicit
// conversion that a reviewer can see.
type Reason string

// Fixed reasons for a LoadError. They are plain text and never contain a value
// from a rule file. (The File, Field and Err of a LoadError can: see LoadError.)
const (
	// ReasonUnreadable is for a rule file that cannot be opened or read.
	ReasonUnreadable Reason = "cannot read file"
	// ReasonNotRegular is for a rule path that is not a regular file.
	ReasonNotRegular Reason = "not a regular file"
	// ReasonTooLarge is for a rule file above the size cap.
	ReasonTooLarge Reason = "file is too large"
	// ReasonEmptyFile is for a rule file with no content.
	ReasonEmptyFile Reason = "file is empty"
	// ReasonInvalidYAML is for a rule file that is not valid YAML.
	ReasonInvalidYAML Reason = "invalid YAML"
	// ReasonMultipleDocuments is for a rule file with more than one YAML document.
	ReasonMultipleDocuments Reason = "more than one YAML document"
	// ReasonUnknownField is for a field that the rule format does not define.
	ReasonUnknownField Reason = "unknown field"
	// ReasonDuplicateField is for a field that appears twice in one mapping.
	ReasonDuplicateField Reason = "duplicate field"
	// ReasonMissingField is for a required field that is absent or empty.
	ReasonMissingField Reason = "missing required field"
	// ReasonInvalidValue is for a value with a bad enum, type or format.
	ReasonInvalidValue Reason = "invalid value"
	// ReasonValueTooLong is for a value above its length cap.
	ReasonValueTooLong Reason = "value is too long"
	// ReasonTooManyItems is for a list with more items than the cap allows.
	ReasonTooManyItems Reason = "too many items"
	// ReasonDuplicateID is for a rule ID that two rules share.
	ReasonDuplicateID Reason = "duplicate rule ID"
	// ReasonBuiltinIDClash is for an external rule whose ID is the ID of a
	// built-in rule.
	ReasonBuiltinIDClash Reason = "rule ID clashes with a built-in rule"
	// ReasonDirUnreadable is for a rules directory that cannot be read.
	ReasonDirUnreadable Reason = "cannot read directory"
	// ReasonTooManyFiles is for a rules directory with more files than the cap
	// allows.
	ReasonTooManyFiles Reason = "too many files"
	// ReasonTooManyRules is for a rule set with more rules than the cap allows.
	ReasonTooManyRules Reason = "too many rules"
	// ReasonTooManyErrors is for the last error of a file or a directory that
	// has more errors than the loader reports. Its Err says how many were left
	// out.
	ReasonTooManyErrors Reason = "too many errors"
)

// maxDisplayRunes is the largest number of runes of a field name or a wrapped
// error text that a LoadError message shows. A rule file can hold a name of
// many KiB, and one such error must not fill the terminal.
const maxDisplayRunes = 200

// LoadError describes a problem with one rule file or with one field in it.
// Its message holds the file path, an optional position, an optional field
// name and a fixed reason. A rule file is untrusted (a cloned repository can
// ship it), so Error escapes every untrusted part.
//
// The fields File, Field and Err can hold raw untrusted text: a file name, a
// field name from the rule file, or the text of a YAML syntax error (which can
// repeat text of the file). Print a LoadError with its Error method, which
// quotes and cuts this text. Never print these fields raw, for example with
// fmt.Println(e.Field) or a log call: they can hold terminal escape sequences.
type LoadError struct {
	// File is the rule file path, or the rules directory for a directory error.
	// It is untrusted text.
	File string
	// Line is the 1-based line of the problem, or 0 if unknown.
	Line int
	// Col is the 1-based column of the problem, or 0 if unknown. It is shown
	// only when Line is set.
	Col int
	// Field is the name of the field with the problem. It is empty for a
	// problem with the whole file. It can be untrusted text (an unknown key).
	Field string
	// Reason is fixed text, one of the Reason constants.
	Reason Reason
	// Err is the underlying error, for example an OS error or the syntax error
	// of the YAML library. It is nil when the reason says it all. Its text can
	// be untrusted. A decode error of a field value never shows library text;
	// Parse replaces it with a fixed error.
	Err error
}

var _ error = (*LoadError)(nil) // compile-time check that *LoadError is an error

// Error returns the message in the form
// "<file>[:<line>[:<col>]]: [field <field>: ]<reason>[: <Err>]".
// File, Field and the text of Err are untrusted. termsafe.Quote quotes the
// file when it holds characters that are not visible. The file is never cut:
// the user needs it in full to find the file. termsafe.QuoteCut quotes the
// field and the text of Err, and cuts them to 200 runes first. The message
// never holds a raw control or escape byte.
func (e *LoadError) Error() string {
	if e == nil {
		return "<nil>" // a nil *LoadError in an error value must not panic
	}
	var b strings.Builder
	b.WriteString(termsafe.Quote(e.File))
	if e.Line > 0 {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(e.Line))
		if e.Col > 0 {
			b.WriteByte(':')
			b.WriteString(strconv.Itoa(e.Col))
		}
	}
	b.WriteString(": ")
	if e.Field != "" {
		b.WriteString("field ")
		b.WriteString(displayText(e.Field))
		b.WriteString(": ")
	}
	b.WriteString(string(e.Reason))
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(displayText(errText(e.Err)))
	}
	return b.String()
}

// Unwrap returns the underlying error (Err), so errors.Is and errors.As work.
func (e *LoadError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// newLoadError returns a LoadError for the rule file at file with the fixed
// reason r. Every LoadError of the package is built here, so its Reason is
// always a fixed reason.
//
// Set the other fields with the methods at, inField and wrap, which chain:
//
//	newLoadError(path, ReasonUnknownField).at(3, 5).inField(name)
func newLoadError(file string, r Reason) *LoadError {
	return &LoadError{File: file, Reason: r}
}

// at sets Line and Col and returns e. It changes e: call it only on a
// LoadError that newLoadError just returned.
func (e *LoadError) at(line, col int) *LoadError {
	e.Line, e.Col = line, col
	return e
}

// inField sets Field to name and returns e. It changes e: call it only on a
// LoadError that newLoadError just returned.
func (e *LoadError) inField(name string) *LoadError {
	e.Field = name
	return e
}

// wrap sets Err to err and returns e. It changes e: call it only on a
// LoadError that newLoadError just returned.
func (e *LoadError) wrap(err error) *LoadError {
	e.Err = err
	return e
}

// errText returns the text of err for use in a LoadError message. An
// *fs.PathError prints as "op path: errno", and the path is untrusted text.
// The path is already in LoadError.File, so for a PathError we keep only the
// operation and the OS error.
func errText(err error) string {
	if pe, ok := errors.AsType[*fs.PathError](err); ok && pe.Err != nil {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}

// moreErrors returns the text of the last error of a list that was cut at its
// cap: n errors were counted but not built. It holds only an int, no untrusted
// text.
func moreErrors(n int) error {
	return fmt.Errorf("%d more errors not shown", n)
}

// displayText returns an untrusted name or error text for a LoadError message:
// termsafe.QuoteCut with the cap maxDisplayRunes. A longer text is cut, quoted
// when needed, and ends with termsafe.CutMarker.
func displayText(s string) string {
	return termsafe.QuoteCut(s, maxDisplayRunes)
}
