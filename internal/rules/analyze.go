package rules

import (
	"context"
	"fmt"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// Analyzer applies the description and schema rules of a Set to MCP tools.
// Make one with NewAnalyzer. It compiles each rule once, so a scan does not
// compile the rules again for each tool.
//
// An Analyzer is read-only after NewAnalyzer returns, so it is safe for
// concurrent use. It keeps nothing from one CheckTool call to the next, so
// the memory for the text of a tool is freed when the call returns.
type Analyzer struct {
	description []analyzerRule // the description rules, in rule ID order
	schema      []analyzerRule // the schema rules, in rule ID order
	// maxSeverity is the highest severity of the rules in description and
	// schema, or "" when there is no rule (see MaxSeverity).
	maxSeverity Severity
}

// analyzerRule is one rule of an Analyzer with its compiled match block.
type analyzerRule struct {
	id string
	m  *Matcher
}

// TextFinding is one rule hit on one tool text. It holds no tool text and no
// pattern text, so it is safe to keep and to print.
type TextFinding struct {
	// RuleID is the ID of the rule that matched.
	RuleID string
	// Target is the text that the rule read: TargetDescription or
	// TargetSchema.
	Target Target
}

// NewAnalyzer compiles the match block of each rule of set once, and keeps
// the compiled description and schema rules.
//
// It compiles the config rules too, but it does not keep them: scan checks
// them natively. So a match block that does not compile is an error for every
// rule, whatever its target, as the docs of the exit codes say. The same is
// true for a rule whose target Validate would refuse, which only a Set built
// by hand can hold.
//
// A rule whose match block does not compile gives a *LoadError with the same
// text and fields as the loader gives with a compiler (see loadFile). After
// maxSetErrors errors, NewAnalyzer stops to compile and adds one last error
// with ReasonTooManyErrors that says how many rules it did not check.
//
// When there is an error, NewAnalyzer returns a nil Analyzer and the errors,
// and the caller must stop (scan exits with code 2). A nil or empty set gives
// an empty Analyzer and no error.
func NewAnalyzer(set *Set) (*Analyzer, []*LoadError) {
	a := &Analyzer{}
	if set == nil {
		return a, nil
	}
	var errs []*LoadError
	for i, r := range set.rules {
		if len(errs) >= maxSetErrors {
			// NewAnalyzer compiles every rule, so the rules from i on are the
			// rules that it did not check. Only ints in the text: no
			// untrusted text.
			stop := fmt.Errorf("stopped after %d errors; %d rules not checked", maxSetErrors, len(set.rules)-i)
			errs = append(errs, newLoadError(setLabel, ReasonTooManyErrors).wrap(stop))
			break
		}
		m, err := r.Match.CompileFor(r.Target)
		if err != nil {
			errs = append(errs, newLoadError(r.Source, ReasonInvalidValue).inField("match").wrap(err))
			continue
		}
		ar := analyzerRule{id: r.ID, m: m}
		switch r.Target {
		case TargetDescription:
			a.description = append(a.description, ar)
		case TargetSchema:
			a.schema = append(a.schema, ar)
		default:
			// A config rule, or a target that Validate would refuse: the
			// match block compiles, but CheckTool does not run it.
			continue
		}
		a.maxSeverity = higherSeverity(a.maxSeverity, r.Severity)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return a, nil
}

// MaxSeverity returns the highest severity of the description and schema
// rules of a: the most serious finding that CheckTool can give. A rule
// severity that is not valid counts as SeverityCritical, so the result fails
// closed. Validate refuses such a rule, so this does not occur with a loaded
// set.
//
// A nil Analyzer, or one with no description or schema rule, returns the
// empty Severity (its Rank is 0).
//
// scan uses it for the severity of the rule analysis budget finding
// (RuleAnalysisBudget): the rules that did not run could have given a finding
// of this severity.
func (a *Analyzer) MaxSeverity() Severity {
	if a == nil {
		return ""
	}
	return a.maxSeverity
}

// CheckTool runs every description rule on t.Description and every schema
// rule on the input schema of t, string(t.InputSchema). A rule with at least
// one hit gives one TextFinding. The findings of the description rules come
// first, then the findings of the schema rules, each in rule ID order.
//
// The rules of one target share one preparedText, so the match forms of a
// text are built once for all its rules. CheckTool builds it only when the
// target has at least one rule. An empty text is matched like any other
// text, so the result is always the result of Matcher.Match on the same text.
//
// CheckTool checks ctx before each rule, and the matchers check it while
// they run (see Matcher.matchCtx). When ctx ends, CheckTool returns the
// findings found so far and an error that wraps ctx.Err(). A rule that ctx
// stopped in the middle still gives a finding when it had a hit before the
// stop: every hit that a matcher returns is a real match. The error names a
// rule ID, never tool text or pattern text.
//
// A nil or empty Analyzer returns nil and no error.
func (a *Analyzer) CheckTool(ctx context.Context, t inspect.Tool) ([]TextFinding, error) {
	if a == nil {
		return nil, nil
	}
	out, err := checkTarget(ctx, a.description, TargetDescription, t.Description, nil)
	if err != nil {
		return out, err
	}
	return checkTarget(ctx, a.schema, TargetSchema, string(t.InputSchema), out)
}

// checkTarget runs rs, the rules of target, on text and appends a
// TextFinding to out for each rule with a hit. It returns out, and on the
// first error it stops and returns out with the error. The preparedText of
// text lives only for this call, so the forms of the description are freed
// before the schema rules run.
func checkTarget(ctx context.Context, rs []analyzerRule, target Target, text string, out []TextFinding) ([]TextFinding, error) {
	if len(rs) == 0 {
		return out, nil
	}
	// prepareText cannot stop in the middle (issue #146), so check ctx
	// before it. A target that starts after ctx ended then costs nothing.
	// The error names the first rule, like the check in the loop does.
	if err := ctx.Err(); err != nil {
		return out, fmt.Errorf("check rule %q: %w", rs[0].id, err)
	}
	p := prepareText(text)
	for _, r := range rs {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("check rule %q: %w", r.id, err)
		}
		hits, err := r.m.matchCtx(ctx, p)
		if len(hits) > 0 {
			out = append(out, TextFinding{RuleID: r.id, Target: target})
		}
		if err != nil {
			// The matcher error names a kind and an index, never input text.
			return out, fmt.Errorf("check rule %q: %w", r.id, err)
		}
	}
	return out, nil
}
