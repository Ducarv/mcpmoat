package llm

import (
	"errors"
	"strings"
	"testing"
	"unicode"
)

// risks lists every valid Risk, from low to high. TestVerdictSchema checks
// that the risk enum of the verdict schema holds the same values, in the
// same order.
var risks = []Risk{RiskNone, RiskLow, RiskMedium, RiskHigh}

// categories lists every valid Category. TestVerdictSchema checks that the
// category enum of the verdict schema holds the same values, in the same
// order.
var categories = []Category{
	CategoryHiddenInstructions,
	CategoryDataExfiltration,
	CategoryConcealFromUser,
	CategoryToolShadowing,
	CategoryCredentialAccess,
	CategoryOther,
}

func TestParseVerdictValid(t *testing.T) {
	t.Parallel()

	for _, r := range risks {
		for _, c := range categories {
			t.Run(string(r)+"/"+string(c), func(t *testing.T) {
				t.Parallel()
				input := `{"risk":"` + string(r) + `","category":"` + string(c) + `"}`
				got, err := parseVerdict([]byte(input))
				if err != nil {
					t.Fatalf("parseVerdict(%s) error = %v", input, err)
				}
				if got != (Verdict{Risk: r, Category: c}) {
					t.Errorf("parseVerdict(%s) = %+v", input, got)
				}
			})
		}
	}

	tests := []struct {
		name  string
		input string
		want  Verdict
	}{
		{name: "keys in other order", input: `{"category":"tool-shadowing","risk":"none"}`, want: Verdict{Risk: RiskNone, Category: CategoryToolShadowing}},
		{name: "white space around", input: " \n\t{ \"risk\" : \"high\" ,\r\n \"category\" : \"other\" }\n ", want: Verdict{Risk: RiskHigh, Category: CategoryOther}},
		{name: "escaped key", input: `{"\u0072isk":"low","category":"other"}`, want: Verdict{Risk: RiskLow, Category: CategoryOther}},
		{name: "padded to max length", input: `{"risk":"low","category":"other"}` + strings.Repeat(" ", maxVerdictBytes-len(`{"risk":"low","category":"other"}`)), want: Verdict{Risk: RiskLow, Category: CategoryOther}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseVerdict([]byte(tt.input))
			if err != nil || got != tt.want {
				t.Errorf("parseVerdict(%q) = %+v, %v; want %+v, nil", tt.input, got, err, tt.want)
			}
		})
	}
}

func TestParseVerdictInvalid(t *testing.T) {
	t.Parallel()

	valid := `{"risk":"high","category":"other"}`
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "white space only", input: "  \n"},
		{name: "null", input: "null"},
		{name: "array", input: `["` + canary + `"]`},
		{name: "string", input: `"` + canary + `"`},
		{name: "plain text refusal", input: "I cannot help with " + canary},
		{name: "empty object", input: "{}"},
		{name: "missing category", input: `{"risk":"high"}`},
		{name: "missing risk", input: `{"category":"other"}`},
		{name: "unknown field", input: `{"risk":"high","category":"other","` + canary + `":"x"}`},
		{name: "unknown field first", input: `{"reason":"` + canary + `","risk":"high","category":"other"}`},
		// Truncated comes only from Classify, never from the model.
		{name: "truncated key", input: `{"risk":"high","category":"other","truncated":"true"}`},
		{name: "truncated bool", input: `{"risk":"none","category":"other","truncated":false}`},
		{name: "duplicate risk", input: `{"risk":"high","risk":"none","category":"other"}`},
		{name: "duplicate category", input: `{"risk":"high","category":"other","category":"other"}`},
		{name: "wrong-case key", input: `{"RISK":"high","category":"other"}`},
		{name: "title-case key", input: `{"risk":"high","Category":"other"}`},
		{name: "number value", input: `{"risk":1,"category":"other"}`},
		{name: "null value", input: `{"risk":null,"category":"other"}`},
		{name: "bool value", input: `{"risk":"high","category":true}`},
		{name: "object value", input: `{"risk":{"` + canary + `":"high"},"category":"other"}`},
		{name: "array value", input: `{"risk":["high"],"category":"other"}`},
		{name: "critical", input: `{"risk":"critical","category":"other"}`},
		{name: "upper-case risk", input: `{"risk":"HIGH","category":"other"}`},
		{name: "risk with space", input: `{"risk":"high ","category":"other"}`},
		{name: "unknown risk", input: `{"risk":"` + canary + `","category":"other"}`},
		{name: "unknown category", input: `{"risk":"high","category":"` + canary + `"}`},
		{name: "empty category", input: `{"risk":"high","category":""}`},
		{name: "trailing text", input: valid + " " + canary},
		{name: "trailing comma", input: `{"risk":"high","category":"other",}`},
		{name: "two objects", input: valid + valid},
		{name: "two objects with newline", input: valid + "\n" + valid},
		{name: "unclosed object", input: `{"risk":"high","category":"other"`},
		{name: "leading text", input: canary + valid},
		{name: "markdown fence", input: "```json\n" + valid + "\n```"},
		{name: "over max length", input: valid + strings.Repeat(" ", maxVerdictBytes-len(valid)) + " "},
		{name: "huge", input: `{"risk":"high","category":"` + strings.Repeat(canary, 1000) + `"}`},
		{name: "invalid UTF-8 in value", input: `{"risk":"high` + "\xff" + `","category":"other"}`},
		{name: "invalid UTF-8 outside value", input: "\xff" + valid},
		{name: "invalid UTF-8 key", input: `{"risk":"high","` + canary + "\xfe" + `":"other"}`},
		{name: "NUL byte", input: valid + "\x00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseVerdict([]byte(tt.input))
			if !errors.Is(err, ErrInvalidOutput) {
				t.Fatalf("parseVerdict(%q) = %+v, %v; want ErrInvalidOutput", tt.input, got, err)
			}
			if got != (Verdict{}) {
				t.Errorf("parseVerdict(%q) = %+v, want zero Verdict on error", tt.input, got)
			}
			// Model output is untrusted: no byte of it may reach the error.
			if msg := err.Error(); strings.Contains(msg, canary) || containsAnyByte(msg, "\xff\xfe\x00{}\"") {
				t.Errorf("parseVerdict(%q) error %q holds model output", tt.input, msg)
			}
		})
	}
}

func FuzzParseVerdict(f *testing.F) {
	seeds := []string{
		`{"risk":"high","category":"other"}`,
		`{"category":"tool-shadowing","risk":"none"}`,
		` {"risk":"low","category":"credential-access"} `,
		`{"risk":"critical","category":"other"}`,
		`{"RISK":"high","category":"other"}`,
		`{"risk":"high","risk":"none","category":"other"}`,
		`{"risk":"high","category":"other"}{}`,
		`{"risk":1,"category":"other"}`,
		`{"risk":"high","category":"other","x":{"y":[1,2]}}`,
		`{"\u0072isk":"low","category":"other"}`,
		`{"risk":"none","category":"other","truncated":true}`,
		"",
		"null",
		"[",
		"\xff{",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := parseVerdict(data)
		if err != nil {
			if !errors.Is(err, ErrInvalidOutput) {
				t.Fatalf("parseVerdict error %v does not wrap ErrInvalidOutput", err)
			}
			if v != (Verdict{}) {
				t.Fatalf("parseVerdict = %+v with error, want zero Verdict", v)
			}
			return
		}
		if !v.Risk.Valid() || !v.Category.Valid() {
			t.Fatalf("parseVerdict(%q) = %+v, nil; want valid enums", data, v)
		}
		if v.Truncated {
			t.Fatalf("parseVerdict(%q) set Truncated, want it set only by Classify", data)
		}
		if len(data) > maxVerdictBytes {
			t.Fatalf("parseVerdict accepted %d bytes, max %d", len(data), maxVerdictBytes)
		}
	})
}

func TestRiskAndCategoryValid(t *testing.T) {
	t.Parallel()

	for _, r := range risks {
		if !r.Valid() {
			t.Errorf("%q.Valid() = false", r)
		}
	}
	for _, r := range []Risk{"", "critical", "High", "none "} {
		if r.Valid() {
			t.Errorf("%q.Valid() = true", r)
		}
	}
	for _, c := range categories {
		if !c.Valid() {
			t.Errorf("%q.Valid() = false", c)
		}
	}
	for _, c := range []Category{"", "Other", "unknown"} {
		if c.Valid() {
			t.Errorf("%q.Valid() = true", c)
		}
	}
	if len(categoryText) != len(categories) {
		t.Errorf("categoryText has %d entries, categories has %d", len(categoryText), len(categories))
	}
	for _, c := range categories {
		if categoryText[c] == "" {
			t.Errorf("categoryText has no entry for %q", c)
		}
	}
	for c := range categoryText {
		if !c.Valid() {
			t.Errorf("categoryText has an entry for %q, which is not valid", c)
		}
	}
}

func TestFixedTexts(t *testing.T) {
	t.Parallel()

	texts := map[string]string{
		"Title":              Title,
		"InvalidTitle":       InvalidTitle,
		"Remediation":        Remediation,
		"InvalidText":        InvalidText,
		"RejectedText":       RejectedText,
		"TruncatedText":      TruncatedText,
		"InvalidRemediation": InvalidRemediation,
	}
	for _, c := range categories {
		texts["Text "+string(c)] = c.Text()
	}
	// No two fixed texts are the same, so a reader can tell the findings
	// apart (for example RejectedText and InvalidText).
	seen := map[string]string{}
	for name, text := range texts {
		if prev, dup := seen[text]; dup {
			t.Errorf("%s is the same as %s", name, prev)
		}
		seen[text] = name
	}
	for name, text := range texts {
		if strings.TrimSpace(text) == "" {
			t.Errorf("%s is empty", name)
		}
		for _, r := range text {
			if r != ' ' && !unicode.IsPrint(r) {
				t.Errorf("%s holds the non-printable rune %U", name, r)
			}
		}
	}

	// An invalid category falls back to the fixed text of CategoryOther and
	// never echoes the category.
	if got := Category(canary).Text(); got != CategoryOther.Text() {
		t.Errorf("Category(unknown).Text() = %q, want the CategoryOther text", got)
	}
}

// TestRejectedText checks that RejectedText is fixed, plain ASCII text with
// no value from the server: no status code (only the class "4xx") and no
// URL. TestFixedTexts checks that it differs from the other texts.
func TestRejectedText(t *testing.T) {
	t.Parallel()
	for i := range len(RejectedText) {
		if b := RejectedText[i]; b < ' ' || b > '~' {
			t.Errorf("RejectedText holds the byte %#x at %d, want printable ASCII", b, i)
		}
	}
	if rest := strings.ReplaceAll(RejectedText, "4xx", ""); containsAnyByte(rest, "0123456789") {
		t.Errorf("RejectedText = %q, holds a digit outside %q", RejectedText, "4xx")
	}
	if strings.Contains(RejectedText, "://") {
		t.Errorf("RejectedText = %q, holds a URL", RejectedText)
	}
}

func TestRuleIDs(t *testing.T) {
	t.Parallel()

	// TestLLMRuleIDsValid in cmd/mcpmoat checks both IDs with
	// rules.ValidRuleID. This package must not import internal/rules, so this
	// test checks only the simple shape.
	if RuleID == RuleIDInvalid {
		t.Errorf("RuleID and RuleIDInvalid are both %q", RuleID)
	}
	for _, id := range []string{RuleID, RuleIDInvalid} {
		if id == "" || !strings.HasPrefix(id, "MOAT-LLM-") {
			t.Errorf("rule ID %q does not start with %q", id, "MOAT-LLM-")
		}
	}
}

// containsAnyByte reports whether s holds any byte of chars. It compares
// bytes, not runes: strings.ContainsAny decodes chars as UTF-8, so it reads a
// byte such as 0xff as U+FFFD and never finds the byte itself.
func containsAnyByte(s, chars string) bool {
	for i := range len(chars) {
		if strings.IndexByte(s, chars[i]) >= 0 {
			return true
		}
	}
	return false
}
