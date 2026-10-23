package inspect

import (
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// errInvalidEnvName reports that a server config declares an environment
// variable name that a child process cannot get: an empty name, or a name
// that contains "=" or a NUL byte. The text is fixed on purpose. A bad name
// such as "TOKEN=abc" can hold a secret, so the error never includes it.
var errInvalidEnvName = errors.New("inspect: invalid environment variable name in server config")

// errInvalidEnvValue reports that a server config declares an environment
// variable value that contains a NUL byte. The operating system cannot pass
// such a value to a child process. The error never includes the name or the
// value.
var errInvalidEnvValue = errors.New("inspect: invalid environment variable value in server config")

// isBaseEnv reports whether the parent environment variable name is on the
// allowlist that a stdio server child gets from the mcpmoat process.
//
// The list is the union of the default lists of the official MCP SDKs
// (getDefaultEnvironment) and of Codex, plus LC_CTYPE. Other variables are excluded on
// purpose, for example SSH_AUTH_SOCK, proxy variables, AWS_*, *_TOKEN,
// LD_* and DYLD_* (loader injection) and NODE_OPTIONS (code injection into
// node). A user who needs one of them declares it in the env of the server
// config.
//
// A switch with constant cases needs no package-level variable, so the list
// cannot change at run time. Names are case-sensitive, as on Unix.
func isBaseEnv(name string) bool {
	switch name {
	case
		"HOME",                    // runtimes find caches and config, such as ~/.npm and ~/.cache/uv
		"LANG",                    // text encoding of stdio for Python and Node
		"LC_ALL",                  // text encoding of stdio for Python and Node
		"LC_CTYPE",                // text encoding of stdio for Python and Node
		"LOGNAME",                 // user identity that some tools read; not secret
		"PATH",                    // the child finds its own tools, for example npx starts node
		"SHELL",                   // npm and some tools read it; in the MCP SDK default list
		"TERM",                    // in the MCP SDK and Codex default lists; low risk
		"TMPDIR",                  // per-user temp dir on macOS; without it tools use the shared /tmp
		"TZ",                      // time zone; in the Codex default list
		"USER",                    // user identity that some tools read; not secret
		"__CF_USER_TEXT_ENCODING": // macOS CoreFoundation text encoding; in the Codex list; absent on Linux
		return true
	}
	return false
}

// buildEnv returns the environment for a stdio server child process. The
// result has the parent entries whose names pass isBaseEnv, plus all the
// entries that the server config declares. A declared entry overrides a
// parent entry with the same name.
//
// Key invariant: on success the result is never nil, also when it has no
// entries. exec.Cmd treats a nil Env as "inherit the whole parent
// environment", which would undo the scrub (NFR-04). An empty non-nil slice
// gives the child an empty environment.
//
// parent has the form of os.Environ: "name=value" entries. Entries with no
// "=" are skipped. Entries whose value contains a NUL byte are skipped too:
// os.Environ cannot return them, and the operating system cannot pass them to
// a child. If a name occurs more than once in parent, the first entry wins,
// the same as os.Getenv on Unix.
//
// Declared values are passed as buildEnv gets them. buildEnv does not expand
// placeholders: SDKInspector.Inspect expands the server with discover.Expand
// before it gets here. A zero discover.Secret (for example from a JSON null
// in the config) gives the child the name with an empty value.
//
// buildEnv returns errInvalidEnvName for a declared name that is empty or
// contains "=" or a NUL byte, and errInvalidEnvValue for a declared value
// that contains a NUL byte. It checks the declared names in sorted order, so
// the first error is always the same for the same config.
//
// The result is sorted by name. It holds secret values from
// discover.Secret.Reveal: use it only as exec.Cmd.Env. Never pass it to fmt,
// a logger, an error or an encoder.
func buildEnv(parent []string, declared discover.SecretMap) ([]string, error) {
	values := make(map[string]string, len(declared))
	for _, entry := range parent {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !isBaseEnv(name) || hasNUL(value) {
			continue
		}
		if _, seen := values[name]; seen {
			continue // the first entry wins
		}
		values[name] = value
	}

	for _, name := range declared.Keys() {
		if name == "" || strings.ContainsAny(name, "=\x00") {
			return nil, errInvalidEnvName
		}
		value := declared[name].Reveal()
		if hasNUL(value) {
			return nil, errInvalidEnvValue
		}
		values[name] = value
	}

	// make gives a non-nil slice even when values is empty. See the key
	// invariant in the doc comment.
	env := make([]string, 0, len(values))
	for _, name := range slices.Sorted(maps.Keys(values)) {
		env = append(env, name+"="+values[name])
	}
	return env, nil
}

// npmYesName is the npm config variable that answers the install prompt of
// npm exec and npx.
const npmYesName = "npm_config_yes"

// noAutoInstallEnv returns a copy of env with npm_config_yes=false added.
// env is a result of buildEnv. The copy is sorted by name, the same as
// buildEnv sorts, and it is never nil. noAutoInstallEnv does not change env.
//
// The reason is issue #104 (dependency confusion). When stdin is not a
// terminal, npm exec and npx assume --yes. A stdio server child has a pipe
// as stdin, so "npx some-name" installs and runs a package from the registry
// when some-name is not installed. An attacker can publish a package with
// that name. With npm_config_yes=false, npx stops with an error and installs
// nothing.
//
// The configured behaviour wins:
//   - When env already has an entry whose name equals npm_config_yes in any
//     letter case, noAutoInstallEnv adds nothing. npm reads its config
//     variables in any letter case.
//   - An explicit -y or --yes in the configured args overrides the
//     variable, so npx then installs, the same as in the client.
//
// The result holds the same secret values as env: use it only as
// exec.Cmd.Env. Never pass it to fmt, a logger, an error or an encoder.
func noAutoInstallEnv(env []string) []string {
	out := make([]string, 0, len(env)+1)
	out = append(out, env...)
	if !slices.ContainsFunc(env, isNpmYesEntry) {
		out = append(out, npmYesName+"=false")
	}
	slices.SortStableFunc(out, func(a, b string) int {
		return strings.Compare(envName(a), envName(b))
	})
	return out
}

// isNpmYesEntry reports whether the name of the "name=value" entry equals
// npm_config_yes in any ASCII letter case, as npm matches it. It reads only
// the name. strings.EqualFold also folds some non-ASCII letters, such as
// U+017F to "s", but such a letter is more than one byte, so the length check
// rules it out: npm ignores "npm_config_yeſ", so it must not stop the
// npm_config_yes=false entry.
func isNpmYesEntry(entry string) bool {
	name := envName(entry)
	return len(name) == len(npmYesName) && strings.EqualFold(name, npmYesName)
}

// envName returns the name part of a "name=value" entry: the text before the
// first "=", or the whole entry when it has no "=".
func envName(entry string) string {
	name, _, _ := strings.Cut(entry, "=")
	return name
}
