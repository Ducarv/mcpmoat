package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Rule IDs of LLM findings. Both pass rules.ValidRuleID, so a user can give
// them to scan --ignore. A .mcpmoat-ignore file cannot ignore them: it can
// come from a cloned repository (FR-10).
const (
	// RuleID is the rule ID of a finding for a verdict with a risk above
	// RiskNone.
	RuleID = "MOAT-LLM-001"
	// RuleIDInvalid is the rule ID of a finding for a tool whose model
	// output was invalid or a refusal (an error that wraps
	// ErrInvalidOutput), or that the provider refused (an error that wraps
	// ErrRejected, see RejectedText).
	RuleIDInvalid = "MOAT-LLM-002"
)

// ErrInvalidOutput means that the model output is not one valid verdict. The
// errors of parseVerdict wrap it. Their text is fixed and never holds model
// output.
var ErrInvalidOutput = errors.New("invalid LLM output")

// Risk is the risk level of a verdict.
type Risk string

// The risk levels. There is no critical level: the model alone can never
// give the highest severity. The mapping from a risk level to the severity
// of a finding lives in cmd/mcpmoat (llmSeverity).
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

// Valid reports whether r is one of the risk levels. A test keeps the risk
// enum of the verdict schema in sync with these values.
func (r Risk) Valid() bool {
	switch r {
	case RiskNone, RiskLow, RiskMedium, RiskHigh:
		return true
	default:
		return false
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
	// CategoryCredentialAccess is text that makes the agent read secrets,
	// keys or private files.
	CategoryCredentialAccess Category = "credential-access" //nolint:gosec // G101: a category name, not a credential
	// CategoryOther is any other risk.
	CategoryOther Category = "other"
)

// categoryText holds the fixed risk text of each category. A test checks that
// every valid Category has an entry.
var categoryText = map[Category]string{ //nolint:gosec // G101: risk texts keyed by category, not credentials
	CategoryHiddenInstructions: "An LLM classifier rated this tool description as likely to hold hidden instructions for the AI agent.",
	CategoryDataExfiltration:   "An LLM classifier rated this tool description as likely to make the AI agent send data to an outside party.",
	CategoryConcealFromUser:    "An LLM classifier rated this tool description as likely to make the AI agent hide its actions from the user.",
	CategoryToolShadowing:      "An LLM classifier rated this tool description as likely to change how the AI agent uses other tools.",
	CategoryCredentialAccess:   "An LLM classifier rated this tool description as likely to make the AI agent read secrets, keys or private files.",
	CategoryOther:              "An LLM classifier rated this tool description as likely to manipulate the AI agent.",
}

// Valid reports whether c is one of the categories. A test keeps the
// category enum of the verdict schema in sync with these values.
func (c Category) Valid() bool {
	switch c {
	case CategoryHiddenInstructions, CategoryDataExfiltration, CategoryConcealFromUser,
		CategoryToolShadowing, CategoryCredentialAccess, CategoryOther:
		return true
	default:
		return false
	}
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

// RejectedText is the fixed risk text of a RuleIDInvalid finding for a tool
// that the provider refused (an error that wraps ErrRejected). It holds no
// status code, no response body and no key.
const RejectedText = "The LLM provider refused this tool description (HTTP 4xx), " +
	"so the tool was not classified. " +
	"A safety filter or a size limit of the provider can cause this."

// InvalidRemediation is the fixed remediation text of a RuleIDInvalid
// finding.
const InvalidRemediation = "Read the full tool description and check it by hand."

// TruncatedText is the fixed risk text of a RuleID finding for a tool whose
// name or description was cut (see Verdict.Truncated) and that the model
// rated none or low, or gave no usable rating (ErrInvalidOutput). The caller
// rates such a tool medium, whatever the model answered: text after the cut
// can hold the attack, and a prompt injection in the part before the cut can
// ask the model for a low rating or make it refuse.
const TruncatedText = "The tool description is too long to classify in full. " +
	"The part after the cut was not rated and can hold hidden instructions for the AI agent."

// RedactedText is the fixed risk text of a RuleID finding for a tool whose
// text had a configured value removed (see Verdict.Redacted), and that the
// model rated none or low, or gave no usable rating (ErrInvalidOutput). The
// caller rates such a tool medium whatever the model answered, because a
// hostile config can choose which text to remove.
const RedactedText = "A value from your config, such as an env or header value, was removed from the tool text before it was sent to the model. " +
	"The removed text was not rated and can hold hidden instructions for the AI agent."

// Verdict is the rating of one tool description by the model. Only
// parseVerdict makes a Verdict from model output, so Risk and Category are
// always valid. With RiskNone, the category has no meaning.
type Verdict struct {
	// Risk is the risk level.
	Risk Risk
	// Category is the kind of risk.
	Category Category
	// Truncated is true when the tool name or description was cut before it
	// was sent (see MaxToolNameBytes, MaxDescriptionBytes and
	// MaxToolMessageBytes). Classify sets it, also with an error after the
	// tool message was built. It never comes from the model output:
	// parseVerdict never sets it.
	Truncated bool
	// Redacted is true when toolMessage replaced one or more configured
	// secret values in the tool name or description with discover.Mask,
	// before the request. It is the same flag as the "redacted" field of
	// the message (see toolMessage). Classify sets it, also with an error
	// after the message was built. It never comes from the model output:
	// parseVerdict never sets it. The removed text was not rated, so the
	// caller rates such a tool medium (see RedactedText).
	Redacted bool
}

// Field names of the verdict JSON object. A test keeps the keys of the
// verdict schema in sync with these names.
const (
	fieldRisk     = "risk"
	fieldCategory = "category"
)

// parseVerdict reads the model output data as one verdict. The rules are
// strict, because the output is untrusted:
//
//   - data has at most maxVerdictBytes bytes;
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
	if len(data) > maxVerdictBytes {
		return Verdict{}, invalidOutput(fmt.Sprintf("longer than %d bytes", maxVerdictBytes))
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
