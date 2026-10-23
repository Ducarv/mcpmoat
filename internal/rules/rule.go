package rules

import (
	"errors"

	"go.yaml.in/yaml/v3"
)

// Severity is how serious a finding from a rule is.
type Severity string

// The allowed severities, from least to most serious.
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Valid reports whether s is one of the known severities.
func (s Severity) Valid() bool {
	return s.Rank() > 0
}

// Rank returns a number for ordering severities: low is 1 and critical is 4.
// An unknown severity returns 0. The --fail-on flag (FR-16) will compare these numbers.
func (s Severity) Rank() int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// Target is the part of an MCP server that a rule inspects.
type Target string

// The allowed rule targets.
const (
	TargetDescription Target = "description"
	TargetSchema      Target = "schema"
	TargetConfig      Target = "config"
)

// Valid reports whether t is one of the known targets.
func (t Target) Valid() bool {
	switch t {
	case TargetDescription, TargetSchema, TargetConfig:
		return true
	default:
		return false
	}
}

// Match holds the match keys of a rule. It is data only: matchers and
// heuristics read these fields elsewhere.
type Match struct {
	// AnyRegex matches when at least one pattern matches.
	AnyRegex []string `yaml:"any_regex"`
	// AllRegex matches when every pattern matches.
	AllRegex []string `yaml:"all_regex"`
	// Keywords are plain words to look for.
	Keywords []string `yaml:"keywords"`
	// Heuristic is the name of a native heuristic.
	Heuristic string `yaml:"heuristic"`
	// Params are options for the heuristic.
	Params map[string]any `yaml:"params"`
}

// Empty reports whether none of the five match keys is set.
func (m Match) Empty() bool {
	return len(m.AnyRegex) == 0 &&
		len(m.AllRegex) == 0 &&
		len(m.Keywords) == 0 &&
		m.Heuristic == "" &&
		len(m.Params) == 0
}

// Case is one test input for a rule, from should_match or should_not_match.
// In YAML it is either a plain string or a mapping with the keys text
// (required) and note (optional).
type Case struct {
	// Text is the input the rule is tested against.
	Text string
	// Note explains why the case exists.
	Note string
}

// Fixed error messages. They never contain the untrusted input.
var (
	errCaseShape  = errors.New("case must be a string or a mapping with text and note")
	errCaseKey    = errors.New("case has an unknown, repeated or invalid key")
	errCaseText   = errors.New("case needs a text value")
	errCaseScalar = errors.New("case values must be strings")
)

// caseErrors are the fixed errors of Case.UnmarshalYAML. When a field fails
// with one of them, the parser shows it so the user sees what is wrong.
func caseErrors() []error {
	return []error{errCaseShape, errCaseKey, errCaseText, errCaseScalar}
}

// UnmarshalYAML decodes a Case from a plain string or from a mapping with
// only the keys text and note. yaml.v3 calls this method by itself when it
// decodes a Case.
func (c *Case) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if isNull(value) {
			// yaml.v3 skips null sequence items and never calls this method for
			// them; Parse reports them itself (nullItemErrors). This branch
			// protects direct use of the type.
			return errCaseShape
		}
		var text string
		if err := value.Decode(&text); err != nil {
			return errCaseScalar
		}
		*c = Case{Text: text}
		return nil
	case yaml.MappingNode:
		return c.decodeMapping(value)
	default:
		return errCaseShape
	}
}

// decodeMapping reads the text and note keys of a mapping node.
func (c *Case) decodeMapping(value *yaml.Node) error {
	var out Case
	seenText, seenNote := false, false
	// A mapping node keeps its content as a flat list: key, value, key, value...
	for i := 0; i+1 < len(value.Content); i += 2 {
		key, val := value.Content[i], value.Content[i+1]
		if key.Kind != yaml.ScalarNode || val.Kind != yaml.ScalarNode || isNull(val) {
			return errCaseScalar
		}
		var text string
		if err := val.Decode(&text); err != nil {
			return errCaseScalar
		}
		switch {
		case key.Value == "text" && !seenText:
			out.Text, seenText = text, true
		case key.Value == "note" && !seenNote:
			out.Note, seenNote = text, true
		default:
			return errCaseKey
		}
	}
	if !seenText {
		return errCaseText
	}
	*c = out
	return nil
}

// Rule is one detection rule, as written in a YAML rule file.
//
// A rule file can come from an untrusted folder. Validate checks the size and
// the shape of the text fields, not their characters, so Title, Risk,
// Remediation, References, Match.Heuristic and the text and note of a Case can
// hold control or escape bytes. Print them only through termsafe, never
// directly.
type Rule struct {
	// ID is the unique rule identifier.
	ID string `yaml:"id"`
	// Title is a short name for the rule.
	Title string `yaml:"title"`
	// Severity is how serious a finding is.
	Severity Severity `yaml:"severity"`
	// Target is the part of the server the rule inspects.
	Target Target `yaml:"target"`
	// Match says what the rule looks for.
	Match Match `yaml:"match"`
	// Risk is a one-sentence description of the risk (NFR-07). Optional here;
	// the built-in rule checks require it.
	Risk string `yaml:"risk"`
	// Remediation says what the user should do (NFR-07). Optional here;
	// the built-in rule checks require it.
	Remediation string `yaml:"remediation"`
	// References are links or names of related sources.
	References []string `yaml:"references"`
	// ShouldMatch are inputs the rule must match (NFR-05).
	ShouldMatch []Case `yaml:"should_match"`
	// ShouldNotMatch are inputs the rule must not match (NFR-05).
	ShouldNotMatch []Case `yaml:"should_not_match"`
	// Source is the file name the rule came from. The loader sets it for
	// use in messages. It is not read from YAML. It is a raw display path and
	// can hold control or escape bytes: print it only through LoadError.Error
	// or termsafe, never directly.
	Source string `yaml:"-"`
}

// matchKeys returns the allowed keys of the match mapping. It returns a new
// slice on each call, so callers cannot change shared state.
func matchKeys() []string {
	return []string{"any_regex", "all_regex", "keywords", "heuristic", "params"}
}

// ruleKeys returns the allowed top-level YAML keys of a rule file. It returns
// a new slice on each call, so callers cannot change shared state.
func ruleKeys() []string {
	return []string{
		"id",
		"title",
		"severity",
		"target",
		"match",
		"risk",
		"remediation",
		"references",
		"should_match",
		"should_not_match",
	}
}
