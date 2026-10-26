package main

import (
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// loadedRules is what loadRules gives to scan.
type loadedRules struct {
	// set holds the built-in rules and the rules from --rules. Scan reads the
	// severity and the texts of a finding from it (see findingRule).
	set *rules.Set
	// analyzer applies the description and schema rules of set to the tools
	// (see toolRulesStep). Each rule in it is compiled once.
	analyzer *rules.Analyzer
	// external tells which targets the rules from --rules use. It is the zero
	// value without --rules.
	external externalTargets
}

// loadRules loads the built-in rules and, when dir is not empty, the extra
// rules in dir. Then it compiles the description and schema rules of the
// joined set once (rules.NewAnalyzer). It returns the result and true, or a
// zero loadedRules and false after it printed every problem on stderr. Scan
// then exits with code 2 (FR-07, FR-16), also with --no-connect: a rule whose
// regex does not compile is an invalid rule.
//
// The rules are loaded without rules.WithCompiler on purpose: NewAnalyzer
// compiles them, so each rule is compiled only once.
//
// Every line has the prefix "mcpmoat scan: " and holds only
// rules.LoadError.Error(), which already escapes the file name and the
// reason. The rule files can come from an untrusted repository, so this
// function never prints rule text itself, and it prints nothing on stdout.
func (c *cli) loadRules(dir string) (loadedRules, bool) {
	builtin, errs := rules.Builtin()
	if len(errs) > 0 {
		// The built-in rules are part of the binary, so an error here is a
		// bug in mcpmoat and not a mistake of the user.
		fprintf(c.stderr, "mcpmoat scan: internal error: built-in rules are invalid\n")
		c.printRuleErrors(errs)
		return loadedRules{}, false
	}

	var external []rules.Rule
	if dir != "" {
		external, errs = rules.LoadDir(dir)
		if len(errs) > 0 {
			// LoadDir returns no rules when any file failed, so NewSet does
			// not run. A duplicate ID, or a clash with a built-in rule, shows
			// up only after the user fixes the file errors. Both cases fail
			// closed with exit 2.
			c.printRuleErrors(errs)
			return loadedRules{}, false
		}
	}

	// NewSet finds the ID clashes and the duplicate IDs.
	set, errs := rules.NewSet(builtin, external)
	if len(errs) > 0 {
		c.printRuleErrors(errs)
		return loadedRules{}, false
	}

	// NewAnalyzer compiles the match block of each description and schema
	// rule. A bad regex in a rule from --rules shows up here.
	analyzer, errs := rules.NewAnalyzer(set)
	if len(errs) > 0 {
		c.printRuleErrors(errs)
		return loadedRules{}, false
	}
	return loadedRules{set: set, analyzer: analyzer, external: targetsOf(external)}, true
}

// printRuleErrors writes one line per rule problem on stderr.
func (c *cli) printRuleErrors(errs []*rules.LoadError) {
	for _, e := range errs {
		fprintf(c.stderr, "mcpmoat scan: %s\n", e.Error())
	}
}

// externalTargets tells which targets the rules from --rules use. Scan
// applies a description or schema rule to the tools of each server, but it
// does not apply a config rule: it runs only its built-in config checks. The
// notices tell the user about the rules that scan does not apply (see
// notices).
type externalTargets struct {
	// config is true when at least one rule has the target config.
	config bool
	// tool is true when at least one rule has the target description or
	// schema.
	tool bool
}

// targetsOf returns the targets that the rules rs use. rs must be the rules
// from --rules only, not the built-in rules.
func targetsOf(rs []rules.Rule) externalTargets {
	var t externalTargets
	for _, r := range rs {
		switch r.Target {
		case rules.TargetConfig:
			t.config = true
		case rules.TargetDescription, rules.TargetSchema:
			t.tool = true
		}
	}
	return t
}

// The notices about the rules from --rules that scan does not apply. They are
// fixed text: they hold no path, no rule ID, no rule text and no pattern.
const (
	// configRulesNotice is printed when a rule from --rules has the target
	// config.
	configRulesNotice = "mcpmoat scan: rules from --rules with target config are not applied; " +
		"scan applies only the built-in config checks"
	// toolRulesNoConnectNotice is printed with --no-connect when a rule from
	// --rules has the target description or schema.
	toolRulesNoConnectNotice = "mcpmoat scan: rules from --rules with target description or schema are not applied with --no-connect; " +
		"these rules need a connection to each server to get its tools"
)

// notices returns the lines that scan prints on stderr about the rules from
// --rules that it does not apply, in a fixed order: configRulesNotice when a
// rule has the target config, then toolRulesNoConnectNotice with --no-connect
// (noConnect) when a rule has the target description or schema. It returns
// nil when scan applies every rule from --rules, or when there is none.
func (t externalTargets) notices(noConnect bool) []string {
	var out []string
	if t.config {
		out = append(out, configRulesNotice)
	}
	if t.tool && noConnect {
		out = append(out, toolRulesNoConnectNotice)
	}
	return out
}
