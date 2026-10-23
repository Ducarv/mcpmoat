package rules

import (
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Runner names a package runner that fetches and runs a package or image.
type Runner string

// The package runners that ExtractPackage understands.
const (
	// RunnerNPX is npx, the npm package runner.
	RunnerNPX Runner = "npx"
	// RunnerBunx is bunx, the Bun package runner.
	RunnerBunx Runner = "bunx"
	// RunnerUVX is uvx, the uv tool runner for Python packages.
	RunnerUVX Runner = "uvx"
	// RunnerPipx is "pipx run", the pipx tool runner for Python packages.
	RunnerPipx Runner = "pipx"
	// RunnerDocker is "docker run", which pulls and runs an image.
	RunnerDocker Runner = "docker"
)

// maxSpecLen caps the length of a package spec. The spec is untrusted
// config text, and no real package name or version is this long.
const maxSpecLen = 512

// maxPackageNameLen caps the length of a package or image name for every
// registry. npm allows 214 bytes, which is also more than a PyPI name or an
// image path needs.
const maxPackageNameLen = 214

// maxPortDigits is the most digits a registry port can have (65535).
const maxPortDigits = 5

// PackageSpec is the package that a stdio server's package runner fetches.
type PackageSpec struct {
	// Runner is the package runner that fetches the package.
	Runner Runner
	// Name is the package name, or for docker the image without tag and
	// digest (the registry and path are kept).
	Name string
	// Version is the version, range or tag as written. It is empty when
	// none is given. For docker it is the tag, or the digest "sha256:...".
	Version string
}

// Unpinned reports whether the spec has no version, the version "latest"
// (case-insensitive), for npx and bunx the "any version" range "*" or "x",
// or a lone exclusion such as "!=1.0" (every version but one). A docker
// digest counts as pinned. Known limit: other dist-tags, such as "next" or
// "beta", and open ranges such as ">=1" also move, but they count as pinned.
func (p PackageSpec) Unpinned() bool {
	if p.Version == "" || strings.EqualFold(p.Version, "latest") {
		return true
	}
	if strings.HasPrefix(p.Version, "!=") && !strings.Contains(p.Version, ",") {
		return true
	}
	return p.Runner.isNPM() && (p.Version == "*" || strings.EqualFold(p.Version, "x"))
}

// isNPM reports whether r fetches from the npm registry.
func (r Runner) isNPM() bool {
	return r == RunnerNPX || r == RunnerBunx
}

// nameSeparators matches a run of "-", "_", "." and "/". PyPI treats a run of
// the first three as one "-" (PEP 503); a PyPI name never holds "/". The
// typosquat check reads server names the same way, so "mcp-fetch" and the
// image "mcp/fetch" compare as one name.
var nameSeparators = regexp.MustCompile(`[-_./]+`)

// nameForm writes every run of "-", "_", "." and "/" as "-".
func nameForm(name string) string {
	return nameSeparators.ReplaceAllString(name, "-")
}

// registryName returns the package name of spec in the form that the
// registry resolves and that the popular list uses: lower case; for PyPI,
// every run of "-", "_" and "." written as "-" (PEP 503), so
// "mcp_server_fetch" is "mcp-server-fetch"; for docker, without a Docker Hub
// registry prefix or "library/", so "docker.io/mcp/fetch" is "mcp/fetch".
func registryName(spec PackageSpec) string {
	name := strings.ToLower(spec.Name)
	switch spec.Runner {
	case RunnerUVX, RunnerPipx:
		return nameForm(name)
	case RunnerDocker:
		for _, prefix := range []string{"docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
			if rest, found := strings.CutPrefix(name, prefix); found {
				name = rest
				break
			}
		}
		return strings.TrimPrefix(name, "library/")
	default:
		return name
	}
}

// ExtractPackage returns the package that command and args would fetch and
// run. It returns false when the runner is unknown, no package is found, the
// spec is a local path or a URL, or the parse is doubtful. A false result
// means "no finding": the function prefers false over a guess.
//
// The name must also fit the name rules of the registry (see validName). When
// an unknown flag takes a value, the scan can pick that value as the package.
// Text that is not a valid package name gives false, but a token that is also
// a valid name (for example a lower-case "ghp_..." value) is returned. The
// callers must not print the name unless discover.RedactArgs shows it.
//
// A Windows "cmd /c <runner> ..." wrapper is read through. A second
// "-p"/"--package" (or "--from") makes the parse doubtful, because npx then
// installs several packages and the one that runs is not known.
//
// Known limits: pnpm dlx, npm exec, yarn dlx, uv tool run and podman are not
// covered. Version ranges such as ^1 or >=1 count as pinned.
//
// The parse treats a flag that is not in the flag tables below as a boolean.
// The tables list the documented value-taking flags of each runner. npm
// accepts any "--<config> <value>" pair, so an unknown npm config flag that
// takes a value can still steer the parse to the wrong word. If that word is a
// valid package name, it is returned.
func ExtractPackage(command string, args []string) (PackageSpec, bool) {
	spec, _, ok := packageAt(command, args)
	return spec, ok
}

// packageAt is ExtractPackage that also returns the index in args of the
// argument that holds the spec.
func packageAt(command string, args []string) (PackageSpec, int, bool) {
	spec, at, ok := parseRunnerArgs(command, args)
	if !ok || !validName(spec.Runner, spec.Name) {
		return PackageSpec{}, 0, false
	}
	return spec, at, true
}

// parseRunnerArgs does the parse for packageAt. It does not run validName,
// so only packageAt may call it.
func parseRunnerArgs(command string, args []string) (PackageSpec, int, bool) {
	command, runArgs, skip := runnerArgs(command, args)
	spec, at, ok := parseUnwrapped(command, runArgs)
	return spec, skip + at, ok
}

// parseUnwrapped is parseRunnerArgs for a command that is not a cmd /c
// wrapper.
func parseUnwrapped(command string, args []string) (PackageSpec, int, bool) {
	switch r := runnerOf(command); r {
	case RunnerNPX:
		return extractNPM(r, npmFlags, args)
	case RunnerBunx:
		return extractNPM(r, bunxFlags, args)
	case RunnerUVX:
		return extractPython(r, uvxFlags, args)
	case RunnerPipx:
		// Global flags such as "--verbose" may come before "run".
		sub, at, ok := scanArgs(args, flagTable{})
		if !ok || sub != "run" {
			return PackageSpec{}, 0, false
		}
		spec, specAt, ok := extractPython(r, pipxFlags, args[at+1:])
		return spec, at + 1 + specAt, ok
	case RunnerDocker:
		return extractDocker(args)
	default:
		return PackageSpec{}, 0, false
	}
}

// cmdWrapped reports whether command and args are "cmd [/s /d /q] /c
// <command> ...", the usual way to start npx or uvx from a Windows client
// config. It returns the index in args of the wrapped command.
func cmdWrapped(command string, args []string) (int, bool) {
	if commandBase(command) != "cmd" {
		return 0, false
	}
	for i, arg := range args {
		switch {
		case strings.EqualFold(arg, "/c"):
			return i + 1, i+1 < len(args)
		case len(arg) == 2 && arg[0] == '/':
			continue // another switch, such as /s or /q
		default:
			return 0, false
		}
	}
	return 0, false
}

// commandBase returns the base name of command in lower case, without a
// Windows ".exe" or ".cmd" suffix.
func commandBase(command string) string {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	return strings.TrimSuffix(base, ".cmd")
}

// validName reports whether name is a valid package name for the registry of
// runner r. It checks the character rules only. It does not reject a name
// because a part looks like a token prefix ("xox", "eyj", "sk-"): an attacker
// can publish a package such as "@xoxo/server-filesystem", and a refused name
// would hide it from the typosquat and unpinned checks. A name is never copied
// into a Finding message, and the callers gate any use of it with
// discover.RedactArgs, so a misparsed secret does not leak.
func validName(r Runner, name string) bool {
	switch r {
	case RunnerNPX, RunnerBunx:
		return validNPMName(name)
	case RunnerUVX, RunnerPipx:
		return validPyPIName(name)
	case RunnerDocker:
		return validImageName(name)
	default:
		return false
	}
}

// validNPMName reports whether name is "name" or "@scope/name" with scope and
// name made of lower-case letters, digits and "._~-". Neither part is empty or
// starts with "." or "_". npm names are lower case, so upper case is refused.
func validNPMName(name string) bool {
	if len(name) > maxPackageNameLen {
		return false
	}
	if rest, scoped := strings.CutPrefix(name, "@"); scoped {
		scope, pkg, found := strings.Cut(rest, "/")
		return found && validNPMPart(scope) && validNPMPart(pkg)
	}
	return validNPMPart(name)
}

// validNPMPart checks one part of an npm package name (see validNPMName).
func validNPMPart(part string) bool {
	if part == "" || strings.HasPrefix(part, ".") || strings.HasPrefix(part, "_") {
		return false
	}
	return !strings.ContainsFunc(part, func(r rune) bool {
		return !isLowerAlnum(r) && !strings.ContainsRune("._~-", r)
	})
}

// validPyPIName reports whether name uses only ASCII letters, digits and
// "._-", and starts and ends with a letter or digit.
func validPyPIName(name string) bool {
	if name == "" || len(name) > maxPackageNameLen {
		return false
	}
	isAlnum := func(r rune) bool { return isLowerAlnum(r) || (r >= 'A' && r <= 'Z') }
	if first, last := rune(name[0]), rune(name[len(name)-1]); !isAlnum(first) || !isAlnum(last) {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool {
		return !isAlnum(r) && !strings.ContainsRune("._-", r)
	})
}

// validImageName reports whether name is a docker image path: components
// separated by "/". Each component is lower case, uses letters, digits and
// "._-", and starts and ends with a letter or digit. Only the first component
// of a multi-component name can be a registry host, with a port: "host:5000".
func validImageName(name string) bool {
	if name == "" || len(name) > maxPackageNameLen {
		return false
	}
	if isDigitsAndDots(name) {
		return false // an IP address or a number is never an image
	}
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if i == 0 && len(parts) > 1 {
			if host, port, found := strings.Cut(part, ":"); found {
				if !isPortNumber(port) {
					return false
				}
				part = host
			}
			// A registry host is a DNS name, and DNS names ignore case.
			part = strings.ToLower(part)
		}
		if !validImagePart(part) {
			return false
		}
	}
	return true
}

// validImagePart checks one component of a docker image name.
func validImagePart(part string) bool {
	if part == "" {
		return false
	}
	isEnd := func(b byte) bool { return isLowerAlnum(rune(b)) }
	if !isEnd(part[0]) || !isEnd(part[len(part)-1]) {
		return false
	}
	return !strings.ContainsFunc(part, func(r rune) bool {
		return !isLowerAlnum(r) && !strings.ContainsRune("._-", r)
	})
}

// isPortNumber reports whether s is a port: 1 to maxPortDigits ASCII digits.
func isPortNumber(s string) bool {
	if s == "" || len(s) > maxPortDigits {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return r < '0' || r > '9' })
}

// isDigitsAndDots reports whether s has only ASCII digits and dots, such as
// "10.0.0.1" or "42".
func isDigitsAndDots(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
}

// isLowerAlnum reports whether r is an ASCII lower-case letter or digit.
func isLowerAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

// runnerOf maps a command to a runner by its base name (see commandBase).
// It returns "" for an unknown command.
func runnerOf(command string) Runner {
	switch r := Runner(commandBase(command)); r {
	case RunnerNPX, RunnerBunx, RunnerUVX, RunnerPipx, RunnerDocker:
		return r
	default:
		return ""
	}
}

// flagTable tells scanArgs, secondOverride and walkNPXFlags how to read the
// flags of one runner.
type flagTable struct {
	valued       map[string]bool // flags that consume the next argument
	override     map[string]bool // flags whose value is the spec itself
	stop         map[string]bool // flags that make the parse doubtful
	stringValued map[string]bool // valued flags that take no next argument that looks like a flag (walkNPXFlags only)
}

// flagSet builds a lookup table from a list of flag names.
func flagSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// scanArgs walks args and returns the spec: the value of an override flag, or
// else the first argument that is not a flag. It also returns the index of
// the argument that holds the spec. It returns false if there is no spec, if
// a stop flag comes first, or if a second override flag follows the first
// one (see secondOverride, which walks the flags in the same way).
func scanArgs(args []string, flags flagTable) (spec string, at int, ok bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				return args[i+1], i + 1, true
			}
			return "", 0, false
		}
		if arg == "-" {
			return "", 0, false
		}
		if !strings.HasPrefix(arg, "-") {
			return arg, i, true
		}
		flag, value, hasValue := strings.Cut(arg, "=")
		switch {
		case flags.stop[flag]:
			return "", 0, false
		case flags.override[flag]:
			at := i
			if !hasValue {
				if i+1 >= len(args) {
					return "", 0, false
				}
				at, value = i+1, args[i+1]
			}
			if value == "" || secondOverride(args[at+1:], flags) {
				return "", 0, false
			}
			return value, at, true
		case flags.valued[flag] && !hasValue:
			i++ // skip the flag value
		}
	}
	return "", 0, false
}

// secondOverride reports whether the runner flags in args, up to the first
// argument that is not a flag (the command that the runner runs), hold
// another override flag. Arguments after that command belong to the server.
// It walks the flags as scanArgs does; keep the two loops in step.
// walkNPXFlags reads npx flags in a different way on purpose: scanArgs gives
// up when in doubt (no MOAT-T4-003 finding), and walkNPXFlags fails closed
// (a MOAT-T4-004 finding).
func secondOverride(args []string, flags flagTable) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			return false
		}
		flag, _, hasValue := strings.Cut(arg, "=")
		switch {
		case flags.override[flag]:
			return true
		case flags.valued[flag] && !hasValue:
			i++ // skip the flag value
		}
	}
	return false
}

// npmFlags are the flags of npx. They follow npm exec and the npm config
// flags that npx accepts.
var npmFlags = flagTable{
	valued: flagSet(
		"--loglevel", "-w", "--workspace", "--shell", "--script-shell",
		"--userconfig", "--globalconfig", "--registry", "--cache", "--prefix", "-C",
		"--node-options", "--otp", "--tag", "--before", "--ca", "--cafile",
		"--proxy", "--https-proxy", "--noproxy", "--include", "--omit",
		"--install-strategy", "--fetch-retries", "--fetch-timeout",
		"--fetch-retry-mintimeout", "--fetch-retry-maxtimeout", "--maxsockets",
		"--logs-dir", "--logs-max", "--audit-level", "--init-module",
		"--min-release-age",
	),
	override: flagSet("-p", "--package"),
	stop:     flagSet("-c", "--call"),
	// npx rewrites --shell to --script-shell, which takes any next argument,
	// so --shell is not listed here.
	stringValued: flagSet("--tag", "--min-release-age"),
}

// runnerArgs reads through Windows "cmd /c" wrappers (see cmdWrapped). It
// returns the wrapped command, the arguments that follow it, and the number
// of arguments it skipped. A single-string wrapper such as
// "cmd /c \"npx -y pkg\"" is not read through.
func runnerArgs(command string, args []string) (string, []string, int) {
	skip := 0
	for {
		i, ok := cmdWrapped(command, args)
		if !ok {
			return command, args, skip
		}
		command, args = args[i], args[i+1:]
		skip += i + 1
	}
}

// walkNPXFlags reads the npx flags in args the way npx 11 reads them
// (npx-cli.js, then nopt), up to the command. args are the arguments after the
// npx command (see runnerArgs). It returns two results:
//   - yes is true when a yes flag (see isYesFlag) comes before the command.
//   - runs is true when npx has something to install or run: a positional
//     argument (the command), a -p or --package value, or a -c or --call value.
//
// The walk follows these rules:
//   - A short yes flag takes no value from the next argument. npx puts "--"
//     before the next word that is not a flag, so "-y false pkg" runs the
//     command "false" with yes on. npx also moves the value of "-y=<v>" and
//     "--y=<v>" to its own argument, so <v> is the command.
//   - A flag of npmFlags.valued takes the next argument, even one that starts
//     with "-". npm reads "--registry -y" as a registry value. A flag of
//     npmFlags.stringValued, and -c or --call, takes the next argument unless
//     it looks like a flag (see looksLikeFlag): "--tag -y" leaves -y as a yes
//     flag, and "--tag -" takes "-" as the tag.
//   - -p and --package take the next argument, even one that starts with "-".
//     That argument is something to run.
//   - An unknown flag takes the next argument when that argument does not start
//     with "-". The walk then goes on past that word. The word counts as
//     something to run, because it may be the package. So npx --quiet pkg -y
//     reads -y as a yes flag, although npm reads -y as an argument of the
//     command. This is a deliberate fail-closed trade-off: an unknown flag that
//     takes a value, as in npx --unknown value -y pkg, is not missed.
//   - The walk stops at "--", at "-" and at the first argument that is neither
//     a flag nor a value. That argument is the command. The arguments after it
//     belong to the server.
//
// An off flag, such as --no-yes or --yes=false, does not clear an earlier yes
// flag. npm takes the last one, but this check must not miss a yes flag, so
// it fails closed: the worst case is a false finding.
func walkNPXFlags(args []string) (yes, runs bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			return yes, runs || i+1 < len(args)
		case arg == "-" || !strings.HasPrefix(arg, "-"):
			return yes, true // the command: npx runs it
		}
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		name, _, hasValue := strings.Cut(arg, "=")
		switch {
		case isYesFlag(arg, next):
			yes = true
			if hasValue && strings.TrimLeft(name, "-") == "y" {
				return yes, true // npx runs the value of -y=<v> as the command
			}
		case hasValue:
			// The value is in the same argument.
			runs = runs || npmFlags.override[name] || npmFlags.stop[name]
		case npmFlags.override[name]:
			runs = runs || i+1 < len(args)
			i++ // the next argument is the value, even one that starts with "-"
		case npmFlags.stop[name]:
			runs = true
			if i+1 < len(args) && !looksLikeFlag(next) {
				i++ // the next argument is the value
			}
		case npmFlags.valued[name]:
			if i+1 < len(args) && (!npmFlags.stringValued[name] || !looksLikeFlag(next)) {
				i++ // the next argument is the value
			}
		default:
			// An unknown flag may take the next word as its value.
			if i+1 < len(args) && !strings.HasPrefix(next, "-") {
				i++
				runs = true
			}
		}
	}
	return yes, runs
}

// looksLikeFlag reports whether nopt reads a as a flag and not as the value of
// a String option before it. nopt checks a against ^-{1,2}[^-], so "-" and
// "---x" are values.
func looksLikeFlag(a string) bool {
	return len(a) >= 2 && a[0] == '-' && (a[1] != '-' || (len(a) >= 3 && a[2] != '-'))
}

// isYesFlag reports whether one npx argument sets the yes option to on, or to
// null. null is the default, and it also overrides the npm_config_yes=false
// of the scan, so it counts as on. next is the argument after arg, or "". The
// rules follow npx-cli.js and nopt (npm 11):
//   - A short flag with a y, such as "-y" or the cluster "-qy", is on.
//   - For a long flag, nopt strips every leading "no-", in any letter case,
//     and each one flips the result. The rest must be a prefix of "yes", such
//     as "yes" or "ye", or it is not a yes flag. "--y" is the -y shorthand,
//     so it is on whatever follows.
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
		return strings.HasPrefix(name, "-") && strings.Contains(name, "y")
	}
	key := strings.ToLower(strings.TrimLeft(name, "-"))
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

// bunxFlags are the flags of bunx. "--bun" and similar boolean flags are not
// listed.
var bunxFlags = flagTable{
	valued: flagSet(
		"--cwd", "--registry", "--install", "--tsconfig-override", "--env-file",
		"-r", "--preload", "--port", "--define", "-d", "--loader", "-l",
		"--elide-lines", "--user-agent", "-c", "--config",
	),
	override: flagSet("-p", "--package"),
}

// extractNPM reads the package from npx or bunx arguments, with the flag
// table of that runner. It also returns the index of the spec argument.
func extractNPM(r Runner, flags flagTable, args []string) (PackageSpec, int, bool) {
	spec, at, ok := scanArgs(args, flags)
	if !ok {
		return PackageSpec{}, 0, false
	}
	name, version, ok := parseNPMSpec(spec)
	if !ok {
		return PackageSpec{}, 0, false
	}
	return PackageSpec{Runner: r, Name: name, Version: version}, at, true
}

// parseNPMSpec splits "@scope/name@version", "@scope/name", "name@version"
// or "name". The version starts after the last "@" that is not at index 0.
func parseNPMSpec(spec string) (name, version string, ok bool) {
	if !plainSpec(spec) {
		return "", "", false
	}
	name = spec
	if i := strings.LastIndex(spec, "@"); i > 0 {
		name, version = spec[:i], spec[i+1:]
		if version == "" || strings.ContainsAny(version, ":/") {
			return "", "", false // empty, URL, alias or git ref
		}
	}
	if name == "" || strings.Contains(name, ":") {
		return "", "", false // npm:, github: and similar prefixes
	}
	if strings.HasPrefix(name, "@") {
		scope, pkg, found := strings.Cut(name[1:], "/")
		if !found || scope == "" || pkg == "" || strings.Contains(pkg, "/") {
			return "", "", false
		}
	} else if strings.Contains(name, "/") {
		return "", "", false // GitHub shorthand "user/repo"
	}
	if strings.HasSuffix(name, ".tgz") || strings.HasSuffix(name, ".tar.gz") {
		return "", "", false // local archive
	}
	return name, version, true
}

// uvxFlags are the value-taking flags of uvx (uv tool run). Boolean flags such
// as "--isolated" or "--compile-bytecode" are not listed.
var uvxFlags = flagTable{
	valued: flagSet(
		"--with", "-w", "--with-editable", "--with-requirements",
		"--python", "-p", "--python-preference", "--python-platform",
		"--index", "--default-index", "--index-url", "-i", "--extra-index-url",
		"--find-links", "-f", "--index-strategy", "--keyring-provider",
		"--constraint", "--constraints", "-c", "--override", "--overrides",
		"--build-constraint", "--build-constraints", "--env-file",
		"--directory", "--project", "--config-file", "--cache-dir", "--color",
		"--resolution", "--prerelease", "--fork-strategy", "--exclude-newer",
		"--exclude-newer-package", "--link-mode", "--torch-backend",
		"--config-setting", "-C", "--config-settings-package",
		"--refresh-package", "--reinstall-package", "--upgrade-package", "-P",
		"--no-binary-package", "--no-build-package",
		"--no-build-isolation-package", "--allow-insecure-host",
	),
	override: flagSet("--from"),
}

// pipxFlags are the flags of "pipx run". "--editable", "--path" and
// "--fetch-missing-python" are booleans and are not listed.
var pipxFlags = flagTable{
	valued:   flagSet("--python", "--pip-args", "--index-url", "-i"),
	override: flagSet("--spec"),
}

// extractPython reads the package from uvx arguments, or from the arguments
// after "pipx run", with the flag table of that runner. Only uvx accepts the
// "name@version" form. It also returns the index of the spec argument.
func extractPython(r Runner, flags flagTable, args []string) (PackageSpec, int, bool) {
	spec, at, ok := scanArgs(args, flags)
	if !ok || strings.HasSuffix(spec, ".py") {
		return PackageSpec{}, 0, false // a script, not a package
	}
	name, version, ok := parsePythonSpec(spec, r == RunnerUVX)
	if !ok {
		return PackageSpec{}, 0, false
	}
	return PackageSpec{Runner: r, Name: name, Version: version}, at, true
}

// parsePythonSpec splits "name", "name@version" (if allowAt), "name==version"
// and range forms such as "name>=1". It drops extras such as "name[extra]".
// A range is returned whole as the version.
func parsePythonSpec(spec string, allowAt bool) (name, version string, ok bool) {
	if !plainSpec(spec) || strings.Contains(spec, ";") {
		return "", "", false
	}
	name, rest := spec, ""
	if i := strings.IndexAny(spec, "@=<>~!"); i >= 0 {
		name, rest = spec[:i], spec[i:]
	}
	if j := strings.Index(name, "["); j >= 0 {
		if !strings.HasSuffix(name, "]") {
			return "", "", false
		}
		name = name[:j]
	}
	if name == "" || strings.ContainsAny(name, "/:[]()") {
		return "", "", false
	}
	switch {
	case rest == "":
		return name, "", true
	case strings.Trim(rest, "@=<>~!") == "":
		return "", "", false // operator without a version
	case strings.HasPrefix(rest, "@"):
		if !allowAt {
			return "", "", false
		}
		version = rest[1:]
	case strings.HasPrefix(rest, "=="):
		version = strings.TrimLeft(rest, "=")
	case strings.HasPrefix(rest, ">"), strings.HasPrefix(rest, "<"),
		strings.HasPrefix(rest, "~="), strings.HasPrefix(rest, "!="):
		version = rest
	default:
		return "", "", false
	}
	if strings.ContainsAny(version, ":/@") {
		return "", "", false
	}
	return name, version, true
}

var (
	// dockerGlobalFlags lists the value-taking global flags that come
	// before the docker subcommand.
	dockerGlobalFlags = flagTable{
		valued: flagSet("--config", "-c", "--context", "-H", "--host", "-l", "--log-level",
			"--tlscacert", "--tlscert", "--tlskey"),
	}
	// dockerRunFlags lists the value-taking flags of "docker run". Boolean
	// flags such as "-i", "-t", "--rm" and "--privileged" are not listed.
	dockerRunFlags = flagTable{
		valued: flagSet(
			// Environment, mounts and files.
			"-e", "--env", "--env-file", "-v", "--volume", "--volumes-from",
			"--volume-driver", "--mount", "--tmpfs", "--storage-opt", "--cidfile",
			"--label-file", "--device", "--device-cgroup-rule", "--gpus",
			// Naming, process and user.
			"--name", "-w", "--workdir", "-u", "--user", "--group-add",
			"--entrypoint", "-l", "--label", "--annotation", "--platform", "--umask",
			"--pull", "--runtime", "--isolation", "-a", "--attach",
			"--detach-keys", "--stop-signal", "--stop-timeout",
			// Network.
			"-p", "--publish", "--expose", "--network", "--net",
			"--network-alias", "--add-host", "--hostname", "-h", "--domainname",
			"--ip", "--ip6", "--link", "--link-local-ip", "--mac-address",
			"--dns", "--dns-search", "--dns-option",
			// Namespaces, security and cgroups.
			"--pid", "--ipc", "--uts", "--userns", "--cgroupns", "--cgroup-parent",
			"--cap-add", "--cap-drop", "--security-opt", "--sysctl", "--ulimit",
			// Resources.
			"--cpus", "-c", "--cpu-count", "--cpu-percent", "--cpu-shares", "--cpu-period", "--cpu-quota",
			"--cpu-rt-period", "--cpu-rt-runtime", "--cpuset-cpus", "--cpuset-mems",
			"-m", "--memory", "--memory-swap", "--memory-reservation",
			"--memory-swappiness", "--kernel-memory", "--shm-size",
			"--oom-score-adj", "--pids-limit", "--blkio-weight",
			"--blkio-weight-device", "--device-read-bps", "--device-read-iops",
			"--device-write-bps", "--device-write-iops", "--io-maxbandwidth",
			"--io-maxiops",
			// Restart, logging and health.
			"--restart", "--log-driver", "--log-opt", "--health-cmd",
			"--health-interval", "--health-retries", "--health-timeout",
			"--health-start-period", "--health-start-interval",
		),
	}
)

// extractDocker reads the image from "docker run" (or "docker container run")
// arguments. It also returns the index of the image argument.
func extractDocker(args []string) (PackageSpec, int, bool) {
	sub, at, ok := scanArgs(args, dockerGlobalFlags)
	if !ok {
		return PackageSpec{}, 0, false
	}
	base := at + 1 // index in args of rest[0]
	rest := args[base:]
	if sub == "container" {
		sub, at, ok = scanArgs(rest, flagTable{})
		if !ok {
			return PackageSpec{}, 0, false
		}
		base += at + 1
		rest = rest[at+1:]
	}
	if sub != "run" {
		return PackageSpec{}, 0, false
	}
	image, at, ok := scanArgs(rest, dockerRunFlags)
	if !ok {
		return PackageSpec{}, 0, false
	}
	name, version, ok := parseImage(image)
	if !ok {
		return PackageSpec{}, 0, false
	}
	return PackageSpec{Runner: RunnerDocker, Name: name, Version: version}, base + at, true
}

// parseImage splits an image reference into name and version. A digest wins
// over a tag. A ":" only starts a tag after the last "/", so a registry port
// as in "localhost:5000/img" is not a tag.
func parseImage(image string) (name, version string, ok bool) {
	if !plainSpec(image) {
		return "", "", false
	}
	name, digest, hasDigest := strings.Cut(image, "@")
	if hasDigest {
		algo, hex, found := strings.Cut(digest, ":")
		if (algo != "sha256" && algo != "sha512") || !found || hex == "" || strings.Contains(hex, "@") {
			return "", "", false
		}
	}
	tag := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, tag = name[:i], name[i+1:]
		if tag == "" {
			return "", "", false
		}
	}
	if name == "" {
		return "", "", false
	}
	if hasDigest {
		return name, digest, true
	}
	return name, tag, true
}

// hasPrefixFold reports whether s starts with prefix, in any case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// plainSpec reports whether spec is a usable registry reference: it is not
// empty or too long, has no space or control character, and is not a local
// path, a file or a URL.
func plainSpec(spec string) bool {
	if spec == "" || len(spec) > maxSpecLen {
		return false
	}
	if strings.ContainsFunc(spec, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return false
	}
	if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "~") ||
		strings.Contains(spec, "\\") {
		return false
	}
	for _, prefix := range []string{"file:", "git+", "http:", "https:"} {
		if hasPrefixFold(spec, prefix) {
			return false
		}
	}
	return true
}
