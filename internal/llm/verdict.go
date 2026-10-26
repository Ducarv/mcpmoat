package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Rule IDs of LLM findings. Both pass rules.ValidRuleID, so a user can put
// them in .mcpmoat-ignore.
const (
	// RuleID is the rule ID of a finding for a verdict with a risk above
	// RiskNone.
	RuleID = "MOAT-LLM-001"
	// RuleIDInvalid is the rule ID of a finding for a tool whose model
	// output was invalid or a refusal (an error that wraps
	// ErrInvalidOutput).
	RuleIDInvalid = "MOAT-LLM-002"
)

// ErrInvalidOutput means that the model output is not one valid verdict. The
// errors of parseVerdict wrap it. Their text is fixed and never holds model
// output.
var ErrInvalidOutput = errors.New("invalid LLM output")

// Risk is the risk level of a verdict.
type Risk string

// The risk levels. There is no critical level: the model alone can never
// give the highest severity.
const (
	// RiskNone means that the model saw no risk. It does not mean that the
	// tool is safe.
	RiskNone Risk = "none"
	// RiskLow is a low risk.
	RiskLow Risk = "low"
	// RiskMedium is a medium risk.
	RiskMedium Risk = "medium"
	// RiskHigh is a high risk.
	RiskHigh Risk = "high"
)

// risks lists every valid Risk, from low to high. The verdict schema uses the
// same values.
var risks = []Risk{RiskNone, RiskLow, RiskMedium, RiskHigh}

// Valid reports whether r is one of the risk levels.
func (r Risk) Valid() bool {
	switch r {
	case RiskNone, RiskLow, RiskMedium, RiskHigh:
		return true
	default:
		return false
	}
}

// Severity returns the severity of a finding for r: "low", "medium" or
// "high". These are the names of rules.Severity and of the report. The cap is
// "high", never "critical". For RiskNone and for an invalid Risk, ok is false
// and there is no finding.
func (r Risk) Severity() (severity string, ok bool) {
	switch r {
	case RiskLow:
		return "low", true
	case RiskMedium:
		return "medium", true
	case RiskHigh:
		return "high", true
	default:
		return "", false
	}
}

// Category is the kind of risk that a verdict names.
type Category string

// The categories.
const (
	// CategoryHiddenInstructions is text that gives the AI agent orders the
	// user does not see.
	CategoryHiddenInstructions Category = "hidden-instructions"
	// CategoryDataExfiltration is text that makes the agent send data out.
	CategoryDataExfiltration Category = "data-exfiltration"
	// CategoryConcealFromUser is text that makes the agent hide actions
	// from the user.
	CategoryConcealFromUser Category = "conceal-from-user"
	// CategoryToolShadowing is text that changes how the agent uses other
	// tools.
	CategoryToolShadowing Category = "tool-shadowing"
	// CategoryKeyAccess is text that makes the agent read secrets,
	// keys or private files.
	CategoryKeyAccess Category = "credential-access"
	// CategoryOther is any other risk.
	CategoryOther Category = "other"
)

// categories lists every valid Category. The verdict schema uses the same
// values.
var categories = []Category{
	CategoryHiddenInstructions,
	CategoryDataExfiltration,
	CategoryConcealFromUser,
	CategoryToolShadowing,
	CategoryKeyAccess,
	CategoryOther,
}

// categoryText holds the fixed risk text of each category. Every category in
// categories has a non-empty entry.
var categoryText = map[Category]string{
	CategoryHiddenInstructions: "An LLM classifier rated this tool description as likely to hold hidden instructions for the AI agent.",
	CategoryDataExfiltration:   "An LLM classifier rated this tool description as likely to make the AI agent send data to an outside party.",
	CategoryConcealFromUser:    "An LLM classifier rated this tool description as likely to make the AI agent hide its actions from the user.",
	CategoryToolShadowing:      "An LLM classifier rated this tool description as likely to change how the AI agent uses other tools.",
	CategoryKeyAccess:          "An LLM classifier rated this tool description as likely to make the AI agent read secrets, keys or private files.",
	CategoryOther:              "An LLM classifier rated this tool description as likely to manipulate the AI agent.",
}

// Valid reports whether c is one of the categories.
func (c Category) Valid() bool {
	_, ok := categoryText[c]
	return ok
}

// Text returns the fixed risk text of c for a finding. It never holds model
// output. An invalid Category gives the text of CategoryOther.
func (c Category) Text() string {
	if text, ok := categoryText[c]; ok {
		return text
	}
	return categoryText[CategoryOther]
}

// Title is the fixed title of a RuleID finding.
const Title = "Language model rates this tool as risky"

// InvalidTitle is the fixed title of a RuleIDInvalid finding.
const InvalidTitle = "Language model answer could not be used"

// Remediation is the fixed remediation text of a RuleID finding.
const Remediation = "Read the full tool description and check it by hand. " +
	"This rating comes from a language model: it is advisory and can be wrong. " +
	"Remove or pin the server if the description tells the agent to do more than the tool needs."

// InvalidText is the fixed risk text of a RuleIDInvalid finding.
const InvalidText = "The LLM classifier gave no valid rating for this tool description. " +
	"The model refused, or its output did not match the verdict schema. " +
	"A description written to confuse the classifier can cause this."

// InvalidRemediation is the fixed remediation text of a RuleIDInvalid
// finding.
const InvalidRemediation = "Read the full tool description and check it by hand."

// Verdict is the rating of one tool description by the model. Only
// parseVerdict makes a Verdict from model output, so both fields are always
// valid. With RiskNone, the category has no meaning.
type Verdict struct {
	// Risk is the risk level.
	Risk Risk
	// Category is the kind of risk.
	Category Category
}

// Field names of the verdict JSON object. The verdict schema uses the same
// names.
const (
	fieldRisk     = "risk"
	fieldCategory = "category"
)

// parseVerdict reads the model output data as one verdict. The rules are
// strict, because the output is untrusted:
//
//   - data has at most MaxVerdictBytes bytes;
//   - data is exactly one JSON object, with optional white space around it,
//     and nothing after it;
//   - the object has exactly the keys "risk" and "category", each one time,
//     with the exact case, and both values are JSON strings;
//   - risk is one of the Risk values ("critical" is refused) and category
//     is one of the Category values.
//
// The object is read token by token with a json.Decoder, and not decoded into
// a struct, because json.Unmarshal matches keys without regard to case and
// keeps the last of two duplicate keys. Both would let odd output pass.
//
// Every error wraps ErrInvalidOutput and has fixed text. No byte of data
// reaches the error.
func parseVerdict(data []byte) (Verdict, error) {
	if len(data) > MaxVerdictBytes {
		return Verdict{}, invalidOutput(fmt.Sprintf("longer than %d bytes", MaxVerdictBytes))
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := expectDelim(dec, '{'); err != nil {
		return Verdict{}, err
	}
	var (
		v                      Verdict
		seenRisk, seenCategory bool
	)
	for dec.More() {
		key, err := stringToken(dec)
		if err != nil {
			return Verdict{}, err
		}
		value, err := stringToken(dec)
		if err != nil {
			return Verdict{}, err
		}
		switch key {
		case fieldRisk:
			if seenRisk {
				return Verdict{}, invalidOutput("duplicate key")
			}
			seenRisk = true
			v.Risk = Risk(value)
		case fieldCategory:
			if seenCategory {
				return Verdict{}, invalidOutput("duplicate key")
			}
			seenCategory = true
			v.Category = Category(value)
		default:
			return Verdict{}, invalidOutput("unknown key")
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return Verdict{}, err
	}
	// Only white space can follow the object. Token returns io.EOF at the
	// end of the input, and an error or a token for anything else.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Verdict{}, invalidOutput("data after the JSON object")
	}
	if !seenRisk || !seenCategory {
		return Verdict{}, invalidOutput("missing key")
	}
	if !v.Risk.Valid() {
		return Verdict{}, invalidOutput("risk is not none, low, medium or high")
	}
	if !v.Category.Valid() {
		return Verdict{}, invalidOutput("unknown category")
	}
	return v, nil
}

// expectDelim reads the next token of dec and checks that it is the
// delimiter want ('{' or '}').
func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		// The decoder error can quote a byte of the output, so it is not
		// wrapped.
		return invalidOutput("not a valid JSON object")
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return invalidOutput("not a JSON object")
	}
	return nil
}

// stringToken reads the next token of dec and checks that it is a JSON
// string.
func stringToken(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", invalidOutput("not a valid JSON object")
	}
	s, ok := tok.(string)
	if !ok {
		return "", invalidOutput("a key or value is not a JSON string")
	}
	return s, nil
}

// invalidOutput returns an error that wraps ErrInvalidOutput with a fixed
// reason. reason must never hold model output.
func invalidOutput(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidOutput, reason)
}
