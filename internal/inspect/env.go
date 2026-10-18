package inspect

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// baseEnvKeys are the variables that a stdio server child process gets from
// the environment of mcpmoat. Every other parent variable is dropped.
//
// It is an array, not a slice, so that no code can append to it at run time.
var baseEnvKeys = [...]string{
	// PATH lets launchers such as npx, uvx or docker find their own
	// helpers (for example node). The command itself is not resolved
	// against it here: inspect runs exactly the configured command.
	"PATH",
	// HOME is where many servers and their runtimes read their own config
	// and caches.
	"HOME",
}

// childEnv builds the environment for a stdio server child process, as a
// list of "KEY=VALUE" entries for exec.Cmd.Env.
//
// The result is built from scratch and never inherits the parent
// environment (NFR-04). It holds:
//
//   - the base keys in baseEnvKeys, read with getenv, but only when the
//     parent value is not empty;
//   - every key of env, the env of the server in the client config. A
//     configured key wins over a base key with the same name, so a config
//     PATH replaces the parent PATH.
//
// The entries are sorted by key, with one entry for each key, so the result
// is deterministic.
//
// childEnv returns an error that wraps [ErrInvalidServer] when a configured
// key is empty or contains '=' or a NUL byte, or when a configured value
// contains a NUL byte. The error names the problem and the position of the
// key in sorted order, never the key bytes or the value: keys are untrusted
// text and values are secrets.
//
// The values in the result are secrets. Never log or print them.
//
// This is the minimal base for the stdio transport. Issue #27 (NFR-04) adds
// the full allowlist (USER, LANG, TMPDIR and what the SDK needs), its docs
// and its tests.
func childEnv(getenv func(string) string, env discover.SecretMap) ([]string, error) {
	vars := make(map[string]string, len(baseEnvKeys)+len(env))

	for _, key := range baseEnvKeys {
		if value := getenv(key); value != "" {
			vars[key] = value
		}
	}

	// env.Keys gives the keys in sorted order, so the position in an error
	// is stable from run to run.
	for i, key := range env.Keys() {
		value := env[key].Reveal()
		if err := checkEnvEntry(key, value); err != nil {
			return nil, fmt.Errorf("%w: env key #%d (sorted order): %w", ErrInvalidServer, i+1, err)
		}
		vars[key] = value
	}

	entries := make([]string, 0, len(vars))
	for _, key := range slices.Sorted(maps.Keys(vars)) {
		entries = append(entries, key+"="+vars[key])
	}
	return entries, nil
}

// checkEnvEntry reports why key and value cannot be an environment variable,
// or nil if they can. The error text never contains the key or the value.
func checkEnvEntry(key, value string) error {
	switch {
	case key == "":
		return errors.New("key is empty")
	case strings.ContainsRune(key, '='):
		return errors.New("key contains '='")
	case strings.ContainsRune(key, 0):
		return errors.New("key contains a NUL byte")
	case strings.ContainsRune(value, 0):
		return errors.New("value contains a NUL byte")
	}
	return nil
}
