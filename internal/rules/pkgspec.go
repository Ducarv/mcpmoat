package rules

import (
	"path/filepath"
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
// (case-insensitive), or for npx and bunx the "any version" range "*" or "x".
// A docker digest counts as pinned. Known limit: other dist-tags, such as
// "next" or "beta", also move, but they count as pinned.
func (p PackageSpec) Unpinned() bool {
	if p.Version == "" || strings.EqualFold(p.Version, "latest") {
		return true
	}
	npm := p.Runner == RunnerNPX || p.Runner == RunnerBunx
	return npm && (p.Version == "*" || strings.EqualFold(p.Version, "x"))
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
// Known limits: pnpm dlx, npm exec, yarn dlx, uv tool run and podman are not
// covered. Version ranges such as ^1 or >=1 count as pinned.
//
// The parse treats a flag that is not in the flag tables below as a boolean.
// The tables list the documented value-taking flags of each runner. npm
// accepts any "--<config> <value>" pair, so an unknown npm config flag that
// takes a value can still steer the parse to the wrong word. If that word is a
// valid package name, it is returned.
func ExtractPackage(command string, args []string) (PackageSpec, bool) {
	spec, ok := extractPackage(command, args)
	if !ok || !validName(spec.Runner, spec.Name) {
		return PackageSpec{}, false
	}
	return spec, true
}

// extractPackage does the parse for ExtractPackage, before the name check.
func extractPackage(command string, args []string) (PackageSpec, bool) {
	switch r := runnerOf(command); r {
	case RunnerNPX:
		return extractNPM(r, npmRules, args)
	case RunnerBunx:
		return extractNPM(r, bunxRules, args)
	case RunnerUVX:
		return extractPython(r, uvxRules, args)
	case RunnerPipx:
		if len(args) == 0 || args[0] != "run" {
			return PackageSpec{}, false
		}
		return extractPython(r, pipxRules, args[1:])
	case RunnerDocker:
		return extractDocker(args)
	default:
		return PackageSpec{}, false
	}
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
	if isNumeric(name) {
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

// isNumeric reports whether s has only ASCII digits and dots, such as
// "10.0.0.1" or "42".
func isNumeric(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
}

// isLowerAlnum reports whether r is an ASCII lower-case letter or digit.
func isLowerAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

// runnerOf maps a command to a runner by its base name. It ignores case and
// a Windows ".exe" or ".cmd" suffix. It returns "" for an unknown command.
func runnerOf(command string) Runner {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimSuffix(base, ".cmd")
	switch r := Runner(base); r {
	case RunnerNPX, RunnerBunx, RunnerUVX, RunnerPipx, RunnerDocker:
		return r
	default:
		return ""
	}
}

// scanRules tells scanArgs how to read the flags of one runner.
type scanRules struct {
	valued   map[string]bool // flags that consume the next argument
	override map[string]bool // flags whose value is the spec itself
	stop     map[string]bool // flags that make the parse doubtful
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
// the first argument after the spec. It returns false if there is no spec,
// or if a stop flag comes first.
func scanArgs(args []string, flags scanRules) (spec string, next int, ok bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				return args[i+1], i + 2, true
			}
			return "", 0, false
		}
		if arg == "-" {
			return "", 0, false
		}
		if !strings.HasPrefix(arg, "-") {
			return arg, i + 1, true
		}
		flag, value, hasValue := strings.Cut(arg, "=")
		switch {
		case flags.stop[flag]:
			return "", 0, false
		case flags.override[flag]:
			if hasValue {
				return value, i + 1, value != ""
			}
			if i+1 < len(args) {
				return args[i+1], i + 2, true
			}
			return "", 0, false
		case flags.valued[flag] && !hasValue:
			i++ // skip the flag value
		}
	}
	return "", 0, false
}

// npmRules are the flags of npx. They follow npm exec and the npm config
// flags that npx accepts.
var npmRules = scanRules{
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
}

// bunxRules are the flags of bunx. "--bun" and similar boolean flags are not
// listed.
var bunxRules = scanRules{
	valued: flagSet(
		"--cwd", "--registry", "--install", "--tsconfig-override", "--env-file",
		"-r", "--preload", "--port", "--define", "-d", "--loader", "-l",
		"--elide-lines", "--user-agent",
	),
	override: flagSet("-p", "--package"),
	stop:     flagSet("-c", "--config"),
}

// extractNPM reads the package from npx or bunx arguments, with the flag
// rules of that runner.
func extractNPM(r Runner, flags scanRules, args []string) (PackageSpec, bool) {
	spec, _, ok := scanArgs(args, flags)
	if !ok {
		return PackageSpec{}, false
	}
	name, version, ok := parseNPMSpec(spec)
	if !ok {
		return PackageSpec{}, false
	}
	return PackageSpec{Runner: r, Name: name, Version: version}, true
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

// uvxRules are the value-taking flags of uvx (uv tool run). Boolean flags such
// as "--isolated" or "--compile-bytecode" are not listed.
var uvxRules = scanRules{
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

// pipxRules are the flags of "pipx run". "--editable", "--path" and
// "--fetch-missing-python" are booleans and are not listed.
var pipxRules = scanRules{
	valued:   flagSet("--python", "--pip-args", "--index-url", "-i"),
	override: flagSet("--spec"),
}

// extractPython reads the package from uvx arguments, or from the arguments
// after "pipx run", with the flag rules of that runner. Only uvx accepts the
// "name@version" form.
func extractPython(r Runner, flags scanRules, args []string) (PackageSpec, bool) {
	spec, _, ok := scanArgs(args, flags)
	if !ok || strings.HasSuffix(spec, ".py") {
		return PackageSpec{}, false // a script, not a package
	}
	name, version, ok := parsePythonSpec(spec, r == RunnerUVX)
	if !ok {
		return PackageSpec{}, false
	}
	return PackageSpec{Runner: r, Name: name, Version: version}, true
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
	dockerGlobalRules = scanRules{
		valued: flagSet("--config", "-c", "--context", "-H", "--host", "-l", "--log-level",
			"--tlscacert", "--tlscert", "--tlskey"),
	}
	// dockerRunRules lists the value-taking flags of "docker run". Boolean
	// flags such as "-i", "-t", "--rm" and "--privileged" are not listed.
	dockerRunRules = scanRules{
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
// arguments.
func extractDocker(args []string) (PackageSpec, bool) {
	sub, next, ok := scanArgs(args, dockerGlobalRules)
	if !ok {
		return PackageSpec{}, false
	}
	rest := args[next:]
	if sub == "container" {
		sub, next, ok = scanArgs(rest, scanRules{})
		if !ok {
			return PackageSpec{}, false
		}
		rest = rest[next:]
	}
	if sub != "run" {
		return PackageSpec{}, false
	}
	image, _, ok := scanArgs(rest, dockerRunRules)
	if !ok {
		return PackageSpec{}, false
	}
	name, version, ok := parseImage(image)
	if !ok {
		return PackageSpec{}, false
	}
	return PackageSpec{Runner: RunnerDocker, Name: name, Version: version}, true
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
	lower := strings.ToLower(spec)
	for _, prefix := range []string{"file:", "git+", "http:", "https:"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}
