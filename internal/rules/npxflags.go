package rules

import "strings"

// walkNPXFlags reads the npx flags in args for MOAT-T4-004. args are the
// arguments after the npx command (see unwrapCmd). It returns two results:
//   - yes is true when an argument before the command may set the yes option
//     to on or to null (see isYesFlag).
//   - runs is true when npx may have something to install or run: an argument
//     that is not a flag, a -p, --package, -c or --call flag, or a flag with
//     an "=" value (npx moves the value of a shorthand such as -y=<v> to its
//     own argument).
//
// The walk does not copy how npx and nopt decide which flag takes a value.
// npm has many value flags, aliases, shorthands and removed options, and each
// one that a copy gets wrong hides a yes flag. The walk fails closed instead:
//   - Every argument that starts with "-" is checked as a yes flag, even one
//     that npm may read as the value of the flag before it.
//   - An argument that does not start with "-", or "--", may be the value of
//     the argument before it when that argument is a flag with no "=". The
//     walk then goes on.
//   - The walk stops at the first "--" or argument that does not start with
//     "-" and that is not such a value. That argument starts the command. The
//     arguments after it belong to the server.
//
// So "npx pkg -y" and "npx -p pkg bin -y" give no yes: the -y belongs to the
// server. The cost is a false finding in some configs, for example
// "npx --registry -y pkg" (-y is the registry value), "npx --quiet pkg -y" or
// "npx --no-install pkg -y" (pkg is the command, so -y belongs to the server).
// An off flag, such as --no-yes, never clears an earlier yes flag.
//
// This differs on purpose from scanArgs, which gives up when in doubt
// (no MOAT-T4-003 finding).
func walkNPXFlags(args []string) (yes, runs bool) {
	maybeValue := false // the argument before is a flag that may take this one as its value
	for i, arg := range args {
		isFlag := strings.HasPrefix(arg, "-") && arg != "--"
		if !isFlag && !maybeValue {
			if arg == "--" {
				return yes, runs || i+1 < len(args)
			}
			return yes, true // the command: npx runs it
		}
		if !isFlag {
			runs = runs || arg != "--" // a value; it may be the package of -p
			maybeValue = false
			continue
		}
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		yes = yes || isYesFlag(arg, next)
		runs = runs || isRunFlag(arg)
		maybeValue = !strings.Contains(arg, "=")
	}
	return yes, runs
}

// isRunFlag reports whether a flag names something for npx to run: -p,
// --package, -c or --call, or any flag with an "=" value.
func isRunFlag(arg string) bool {
	name, _, hasValue := strings.Cut(arg, "=")
	switch strings.TrimLeft(name, "-") {
	case "p", "package", "c", "call":
		return true
	default:
		return hasValue
	}
}

// isYesFlag reports whether one npx argument may set the yes option to on, or
// to null. null is the default, and it also overrides the npm_config_yes=false
// of the scan, so it counts as on. next is the argument after arg, or "". The
// rules follow npx-cli.js and nopt (npm 11) and fail closed:
//   - A short flag, or a cluster of them, is on when it holds a "y" (-y) or an
//     "n" (npm's shorthand for --no-yes, which a later "false" or "null" turns
//     on), such as "-y", "-qy" or "-n".
//   - For a long flag, "--no" and "--n" are the shorthand of "--no-yes". nopt
//     then strips every leading "no-", in any letter case, and each one flips
//     the result. The rest must be a prefix of "yes", such as "yes" or "ye", or
//     the flag is not a yes flag. "--y" is the -y shorthand, so it is on.
//   - "--yes" or "--ye" with no "=" is on. npx puts "--" before the next word,
//     so that word is not a value. (npm reads "--ye false" as off, so this is
//     a false finding at worst.)
//   - Otherwise the value is the text after "=", or the next argument: npx
//     skips the word after a flag it does not know, such as --no-yes, so nopt
//     reads that word. "true" and "false" set the option before the flips.
//     "null" sets null. Any other value, such as "0" or " false", leaves the
//     option on before the flips.
func isYesFlag(arg, next string) bool {
	name, value, hasValue := strings.Cut(arg, "=")
	if !strings.HasPrefix(name, "--") {
		return strings.ContainsAny(strings.TrimPrefix(name, "-"), "yn")
	}
	key := strings.ToLower(strings.TrimLeft(name, "-"))
	if key == "no" || key == "n" {
		key = "no-yes"
	}
	flips := 0
	for strings.HasPrefix(key, "no-") {
		key = key[len("no-"):]
		flips++
	}
	if key == "" || !strings.HasPrefix("yes", key) {
		return false
	}
	if flips == 0 && (key == "y" || !hasValue) {
		return true
	}
	if !hasValue {
		value = next
	}
	switch value {
	case "null":
		return true
	case "false":
		return flips%2 == 1
	default: // "true" or any other value
		return flips%2 == 0
	}
}
