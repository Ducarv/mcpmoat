package main

import (
	"strings"
)

// This file holds the command handlers. Each one has the signature of
// command.run: it gets the resolved global options and its own arguments, and
// returns the exit code.

// runVersion implements "mcpmoat version".
func (c *cli) runVersion(_ options, args []string) int {
	if c.rejectArgs("version", newArgHider(args, flagLLMBaseURL), args) {
		return exitError
	}
	fprintf(c.stdout, "%s\n", c.build)
	return exitOK
}

// runHelp implements "mcpmoat help".
func (c *cli) runHelp(_ options, args []string) int {
	if c.rejectArgs("help", newArgHider(args, flagLLMBaseURL), args) {
		return exitError
	}
	c.usage(c.stdout)
	return exitOK
}

// rejectArgs is for the arguments that a command does not take. If args is
// not empty, it prints an error to stderr and returns true. The arguments come
// from the user, so each one goes through quoteArg to stop terminal escape
// injection. Before that, h.errorText hides it: h is the argHider of the full
// argument list of the command (newArgHider(args, flagLLMBaseURL)), so a
// --llm-base-url value does not show, also one without a scheme such as
// "user:pass@host", and neither does the user info of any URL, as in a stray
// "https://user:pass@host" (see argscrub.go). Every command uses this one
// rule.
func (c *cli) rejectArgs(name string, h argHider, args []string) bool {
	if len(args) == 0 {
		return false
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = quoteArg(h.errorText(a))
	}
	c.usageError(name, "unexpected arguments [%s]", strings.Join(quoted, " "))
	return true
}

// usageError prints "mcpmoat <name>: <message>" and the usage hint to stderr,
// and returns exitError. The message is fmt.Sprintf(format, a...). The caller
// must escape untrusted text in a before the call (see quoteArg and
// termsafe.Quote).
func (c *cli) usageError(name, format string, a ...any) int {
	c.cmdPrintf(name, format, a...)
	fprintf(c.stderr, "Run \"mcpmoat help\" for usage.\n")
	return exitError
}
