package main

import (
	"github.com/Ducarv/mcpmoat/internal/rules"
)

// loadRules loads the built-in rules and, when dir is not empty, the extra
// rules in dir. It returns the joined set and true, or nil and false after it
// printed every problem on stderr.
//
// The rules are loaded and checked here, but scan does not apply them yet.
// Every line has the prefix "mcpmoat scan: " and holds only
// rules.LoadError.Error(), which already escapes the file name and the
// reason. The rule files can come from an untrusted repository, so this
// function never prints rule text itself, and it prints nothing on stdout.
func (c *cli) loadRules(dir string) (*rules.Set, bool) {
	builtin, errs := rules.Builtin()
	if len(errs) > 0 {
		// The built-in rules are part of the binary, so an error here is a
		// bug in mcpmoat and not a mistake of the user.
		fprintf(c.stderr, "mcpmoat scan: internal error: built-in rules are invalid\n")
		c.printRuleErrors(errs)
		return nil, false
	}

	var external []rules.Rule
	if dir != "" {
		// The rules are loaded without a regex compiler on purpose, until
		// issue #35 provides one. Then pass rules.WithCompiler(...) here, so
		// a bad regex makes scan exit 2.
		external, errs = rules.LoadDir(dir)
		if len(errs) > 0 {
			// LoadDir returns no rules when any file failed, so there is
			// nothing left to join. NewSet does not run in this case. This is
			// a deliberate choice: a duplicate ID, or a clash with a built-in
			// rule, shows up only after the user fixes the file errors. It
			// fails closed: scan exits 2 in both cases. printRuleErrors prints
			// every error it gets. The caps on the number of errors belong in
			// the loader (LoadDir and NewSet).
			c.printRuleErrors(errs)
			return nil, false
		}
	}

	// NewSet finds the ID clashes and the duplicate IDs.
	set, errs := rules.NewSet(builtin, external)
	if len(errs) > 0 {
		c.printRuleErrors(errs)
		return nil, false
	}
	return set, true
}

// printRuleErrors writes one line per rule problem on stderr.
func (c *cli) printRuleErrors(errs []*rules.LoadError) {
	for _, e := range errs {
		fprintf(c.stderr, "mcpmoat scan: %s\n", e.Error())
	}
}
