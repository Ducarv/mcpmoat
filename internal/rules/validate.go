package rules

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Size caps for the fields of a rule. A rule file is untrusted input, so each
// field has a limit. Caps on text are in runes where a person reads the text
// (title, risk, remediation, note) and in bytes everywhere else.
const (
	maxTitleRunes       = 200      // longest title, in runes
	maxRiskRunes        = 500      // longest risk text, in runes
	maxRemediationRunes = 1000     // longest remediation text, in runes
	maxPatternBytes     = 4096     // longest single regex or keyword, in bytes
	maxPatternItems     = 100      // most items in any_regex, all_regex or keywords
	maxHeuristicBytes   = 64       // longest heuristic name, in bytes
	maxReferences       = 20       // most items in references
	maxReferenceBytes   = 2048     // longest single reference, in bytes
	maxCases            = 100      // most cases in should_match or should_not_match
	maxCaseTextBytes    = 64 << 10 // longest case text, in bytes
	maxCaseNoteRunes    = 500      // longest case note, in runes
)

// idPattern is the allowed form of a rule ID. No whitespace and no '/', because
// a line in .mcpmoat-ignore reads "RULE-ID [server[/tool]]". It is built once
// and never changed (read-only). Go's regexp package uses RE2, so a match
// takes time linear in the input.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Fixed explanatory texts for LoadError.Err. They never hold input from a rule
// file.
var (
	errIDForm            = errors.New("must start with a letter or digit, use only letters, digits, '.', '_' and '-', and have at most 64 characters")
	errSeverityEnum      = errors.New("allowed values: low, medium, high, critical")
	errTargetEnum        = errors.New("allowed values: description, schema, config")
	errBlank             = errors.New("must not be empty or only white space")
	errNotUTF8           = errors.New("must be valid UTF-8 text")
	errReferenceURL      = errors.New("must be an http or https URL with ASCII characters only (percent-encode other characters)")
	errParamsNoHeuristic = errors.New("params needs a heuristic")
)

// Validate checks the rule and returns every problem it finds, in the order of
// the fields of Rule. It returns nil when the rule is valid. Each error has
// File set to r.Source and Field set to the YAML path of the bad value, for
// example "severity", "match.any_regex[2]" or "should_match[1].text". Line and
// Col stay zero: the parser fills them from the YAML node.
//
// Validate does not compile regexes and does not check the heuristic name or
// the shape of Match.Params. Other code does that. It does require a heuristic
// when Match.Params is set, and at least one match key other than Params.
func (r Rule) Validate() []*LoadError {
	c := &checker{file: r.Source}

	c.validateID(r.ID)
	c.validateTitle(r.Title)
	c.validateSeverity(r.Severity)
	c.validateTarget(r.Target)
	c.validateMatch(r.Match)

	c.checkRunes("risk", r.Risk, maxRiskRunes)
	c.checkRunes("remediation", r.Remediation, maxRemediationRunes)
	c.validateReferences(r.References)
	c.validateCases("should_match", r.ShouldMatch)
	c.validateCases("should_not_match", r.ShouldNotMatch)

	return c.errs
}

// checker collects the problems found in one rule.
type checker struct {
	file string
	errs []*LoadError
}

// add records one problem. detail may be nil when the reason says it all.
func (c *checker) add(field string, reason Reason, detail error) {
	c.errs = append(c.errs, newLoadError(c.file, reason).inField(field).wrap(detail))
}

// checkNonBlankBytes checks that s is at most limit bytes (like checkBytes) and
// that it is not blank. It reports a problem at field and returns false, or
// returns true when s is fine.
func (c *checker) checkNonBlankBytes(field, s string, limit int) bool {
	if !c.checkBytes(field, s, limit) {
		return false
	}
	if isBlank(s) {
		c.add(field, ReasonInvalidValue, errBlank)
		return false
	}
	return true
}

// indexField returns the YAML path of item i in the list at field, for example
// "references[0]".
func indexField(field string, i int) string {
	return field + "[" + strconv.Itoa(i) + "]"
}

// isBlank reports whether s is empty or holds only white space.
func isBlank(s string) bool {
	return strings.TrimSpace(s) == ""
}

func (c *checker) validateID(id string) {
	switch {
	case isBlank(id):
		c.add("id", ReasonMissingField, nil)
	case !idPattern.MatchString(id):
		c.add("id", ReasonInvalidValue, errIDForm)
	}
}

func (c *checker) validateTitle(title string) {
	if isBlank(title) {
		c.add("title", ReasonMissingField, nil)
		return
	}
	c.checkRunes("title", title, maxTitleRunes)
}

func (c *checker) validateSeverity(s Severity) {
	switch {
	case s == "":
		c.add("severity", ReasonMissingField, nil)
	case !s.Valid():
		c.add("severity", ReasonInvalidValue, errSeverityEnum)
	}
}

func (c *checker) validateTarget(t Target) {
	switch {
	case t == "":
		c.add("target", ReasonMissingField, nil)
	case !t.Valid():
		c.add("target", ReasonInvalidValue, errTargetEnum)
	}
}

func (c *checker) validateMatch(m Match) {
	if m.Empty() {
		c.add("match", ReasonMissingField, nil)
		return
	}
	c.checkList("match.any_regex", m.AnyRegex, maxPatternItems, maxPatternBytes, nil)
	c.checkList("match.all_regex", m.AllRegex, maxPatternItems, maxPatternBytes, nil)
	c.checkList("match.keywords", m.Keywords, maxPatternItems, maxPatternBytes, nil)
	// A blank heuristic is an error, not a match key: it gets its own error
	// (so "match" is not also reported missing) and it never counts as a real
	// heuristic for the params check below.
	if m.Heuristic != "" {
		c.checkNonBlankBytes("match.heuristic", m.Heuristic, maxHeuristicBytes)
	}
	// Params are options for a heuristic. Without a real heuristic the rule can
	// never use them, so a rule with only params (or params next to a regex
	// or a blank heuristic) is a mistake. The shape of Params is not checked here.
	if len(m.Params) > 0 && isBlank(m.Heuristic) {
		c.add("match.params", ReasonInvalidValue, errParamsNoHeuristic)
	}
}

func (c *checker) validateReferences(refs []string) {
	// The URLs are only parsed, never fetched (NFR-01).
	c.checkList("references", refs, maxReferences, maxReferenceBytes, c.checkReferenceURL)
}

// checkReferenceURL reports a reference that is not an http or https URL with
// a host, no user info and only printable ASCII characters. It parses the text
// but never fetches it (NFR-01).
//
// The ASCII rule is checked first. url.Parse accepts bidi controls, C1
// controls, zero-width characters, fillers and other invisible or look-alike
// text, in the path and in the host. A reference with such text is not safe to
// print raw and can look like another host. Non-ASCII text in a URL must be
// percent-encoded (path, query) or written in punycode (host).
//
// The error of url.Parse holds the input, so it is not wrapped.
func (c *checker) checkReferenceURL(field, ref string) {
	if !isPrintableASCII(ref) {
		c.add(field, ReasonInvalidValue, errReferenceURL)
		return
	}
	u, err := url.Parse(ref)
	if err != nil {
		c.add(field, ReasonInvalidValue, errReferenceURL)
		return
	}
	// url.Parse already lowercases the scheme.
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		c.add(field, ReasonInvalidValue, errReferenceURL)
	}
}

// isPrintableASCII reports whether every byte of s is in 0x21..0x7E. That
// excludes space, control bytes, DEL and every non-ASCII byte. It works on
// bytes, not runes, so invalid UTF-8 fails too.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

func (c *checker) validateCases(field string, cases []Case) {
	if len(cases) > maxCases {
		c.add(field, ReasonTooManyItems, nil)
		cases = cases[:maxCases] // check only the first maxCases, to bound the work
	}
	for i, tc := range cases {
		item := indexField(field, i)
		c.checkNonBlankBytes(item+".text", tc.Text, maxCaseTextBytes)
		c.checkRunes(item+".note", tc.Note, maxCaseNoteRunes)
	}
}

// checkList checks a list of strings: the item count, then for each item the
// size, the UTF-8 form and that it is not blank. If extra is not nil, it runs
// on each item that passed these checks.
func (c *checker) checkList(field string, items []string, maxItems, maxBytes int, extra func(field, s string)) {
	if len(items) > maxItems {
		c.add(field, ReasonTooManyItems, nil)
		items = items[:maxItems] // check only the first maxItems, to bound the work
	}
	for i, s := range items {
		item := indexField(field, i)
		if !c.checkNonBlankBytes(item, s, maxBytes) {
			continue
		}
		if extra != nil {
			extra(item, s)
		}
	}
}

// checkRunes checks that s is valid UTF-8 and has at most limit runes. It
// returns true when s passes. An empty s passes.
func (c *checker) checkRunes(field, s string, limit int) bool {
	return c.checkString(field, s, utf8.RuneCountInString(s), limit)
}

// checkBytes checks that s is valid UTF-8 and has at most limit bytes. It
// returns true when s passes. An empty s passes.
func (c *checker) checkBytes(field, s string, limit int) bool {
	return c.checkString(field, s, len(s), limit)
}

// checkString records at most one problem for s: too long (size is above
// limit) or not valid UTF-8. It returns true when there is no problem.
func (c *checker) checkString(field, s string, size, limit int) bool {
	if size > limit {
		c.add(field, ReasonValueTooLong, nil)
		return false
	}
	if !utf8.ValidString(s) {
		c.add(field, ReasonInvalidValue, errNotUTF8)
		return false
	}
	return true
}
