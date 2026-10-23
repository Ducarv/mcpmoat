package rules

import "strings"

// npmShortFlags are the one-letter shorthands of npm 11 (the @npmcli/config
// definitions). nopt expands a flag made only of these letters as a group of
// short flags, with one dash or more: "--qy" is "--loglevel warn --yes".
const npmShortFlags = "dqsnacfgLlmpCSBDEOP?Hhvwy"

// walkNPXFlags reads the npx flags in args for MOAT-T4-004. args are the
// arguments after the npx command (see unwrapCmd). It returns two results:
//   - yes is true when an argument before the command may set the yes option
//     to on or to null (see isYesFlag).
//   - runs is true when npx may have something to install or run. It is false
//     only when every argument is a yes flag with no "=" or "--": any other
//     flag may name a package, or expand to a word that becomes the command
//     (npx expands -q to "--loglevel warn"), and npx moves the value of a
//     shorthand such as -y=<v> to its own argument.
//
// The walk does not copy how npx and nopt decide which flag takes a value.
// npm has many value flags, aliases, shorthands and removed options, and each
// one that a copy gets wrong hides a yes flag. The walk fails closed instead:
//   - Every argument that starts with "-" is checked as a yes flag, even one
//     that npm may read as the value of the flag before it. When the flag
//     before has no "=", npx may skip this flag as that flag's value, and then
//     the word after it is not its value. So it is checked with and without
//     that word.
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
		switch {
		case arg == "--" && !maybeValue:
			return yes, runs || i+1 < len(args) // the command follows
		case !isFlag && !maybeValue:
			return yes, true // the command: npx runs it
		case !isFlag:
			// A value of the flag before. It may be the package of -p. A "--"
			// may also end the flags, and then the next argument is the command.
			runs = runs || arg != "--" || i+1 < len(args)
			maybeValue = false
			continue
		}
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		isYes := isYesFlag(arg, next) || (maybeValue && isYesFlag(arg, ""))
		yes = yes || isYes
		runs = runs || !isYes || strings.Contains(arg, "=")
		maybeValue = !strings.Contains(arg, "=")
	}
	return yes, runs
}

// isYesFlag reports whether one npx argument may set the yes option to on, or
// to null. null is the default, and it also overrides the npm_config_yes=false
// of the scan, so it counts as on. next is the argument after arg, or "". The
// rules follow npx-cli.js and nopt (npm 11) and fail closed:
//   - A short flag, or a group of them, is on when it holds a "y" (-y) or an
//     "n" (npm's shorthand for --no-yes, which a later "false" or "null" turns
//     on), such as "-y", "-qy" or "-n".
//   - A long flag made only of npm's one-letter shorthands (npmShortFlags) is
//     such a group too, so "--qy" and "--ny" are on.
//   - For other long flags, "--no" is the shorthand of "--no-yes". nopt then
//     strips every leading "no-", in any letter case, and each one flips the
//     result. The rest must be a prefix of "yes", such as "yes" or "ye", or
//     the flag is not a yes flag.
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
	key := strings.TrimLeft(name, "-")
	if isShortGroup(key) {
		return strings.ContainsAny(key, "yn")
	}
	key = strings.ToLower(key)
	if key == "no" {
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
	if flips == 0 && !hasValue {
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

// isShortGroup reports whether key, a flag without its dashes, is made only
// of npm's one-letter shorthands (see npmShortFlags).
func isShortGroup(key string) bool {
	return key != "" && !strings.ContainsFunc(key, func(r rune) bool {
		return !strings.ContainsRune(npmShortFlags, r)
	})
}
