package rules

import (
	"regexp"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
	builtinrules "github.com/Ducarv/mcpmoat/rules"
)

// The adapters in this file let the built-in config rules run their YAML test
// cases. Each case is one line of text. An adapter turns that line into a
// discover.Server and calls the native check on it. The native checks in
// config.go and typosquat.go take a server, not text, so these adapters are
// the bridge. The scan command does not use them: it calls CheckConfig on the
// real servers from the client config files.

// caseServerName is the server name that the adapters use. The checks copy the
// name into a finding only, so a fixed name does not change a result.
const caseServerName = "case"

// configTextChecks maps the config heuristics that need no setup to their
// adapters. typosquat is not here: newTyposquatText builds it.
var configTextChecks = map[string]func(raw string) []Hit{
	HeuristicInsecureURL:     insecureURLText,
	HeuristicPlaintextSecret: plaintextSecretText,
	HeuristicUnpinnedPackage: unpinnedPackageText,
	HeuristicAutoInstall:     autoInstallText,
}

// isConfigHeuristic reports whether name is a config heuristic: one that reads
// a config entry with an adapter in this file.
func isConfigHeuristic(name string) bool {
	_, ok := configTextChecks[name]
	return ok || name == HeuristicTyposquat
}

// envEntryRe matches the start of an env entry: an env name, then "=".
var envEntryRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// headerEntryRe matches the start of a header entry: a header name, then ":".
var headerEntryRe = regexp.MustCompile(`^[A-Za-z0-9-]+:`)

// insecureURLText runs the MOAT-T4-001 check on one URL.
//
// Grammar: the line is one URL, such as "http://mcp.example.com/sse". White
// space at both ends is trimmed. The URL is read as the URL of a remote
// server. A line that is blank gives a URL that is not http, so no hit.
func insecureURLText(raw string) []Hit {
	s := discover.Server{
		Name:      caseServerName,
		Transport: discover.TransportHTTP,
		URL:       discover.NewURL(strings.TrimSpace(raw)),
	}
	return findingHits(checkInsecureURL(s), HeuristicInsecureURL)
}

// plaintextSecretText runs the MOAT-T4-002 check on one entry.
//
// Grammar: the line is one of these two forms. White space at both ends is
// trimmed first.
//
//   - Env entry "KEY=VALUE". The key starts with a letter or "_" and holds
//     only letters, digits and "_". The value is the rest of the line after
//     the first "=", so it may hold more "=" or ":". The entry is read as an
//     env entry of a stdio server.
//   - Header entry "Name: value". The name holds only letters, digits and
//     "-". The value is the rest of the line after the first ":", with white
//     space trimmed. The entry is read as a header of a remote server.
//
// Any other line gives no hit. The value is never put into a Hit, an error or
// a log.
func plaintextSecretText(raw string) []Hit {
	line := strings.TrimSpace(raw)
	if envEntryRe.MatchString(line) {
		key, value, _ := strings.Cut(line, "=")
		// node is not a package runner, so only the env entry can give a finding.
		s := caseStdioServer(caseServerName, "node", nil)
		s.Env = discover.SecretMap{key: discover.NewSecret(value)}
		return findingHits(checkPlaintextSecrets(s), HeuristicPlaintextSecret)
	}
	if headerEntryRe.MatchString(line) {
		name, value, _ := strings.Cut(line, ":")
		s := discover.Server{
			Name:      caseServerName,
			Transport: discover.TransportHTTP,
			Headers:   discover.SecretMap{name: discover.NewSecret(strings.TrimSpace(value))},
		}
		return findingHits(checkPlaintextSecrets(s), HeuristicPlaintextSecret)
	}
	return nil
}

// unpinnedPackageText runs the MOAT-T4-003 check on one command line.
//
// Grammar: the line is a command line, split at white space (strings.Fields).
// The first field is the command and the other fields are its args. The
// server is stdio. Example: "npx -y @scope/server@latest". A blank line gives
// no hit.
func unpinnedPackageText(raw string) []Hit {
	return commandLineHits(caseServerName, strings.Fields(raw), checkUnpinnedPackage, HeuristicUnpinnedPackage)
}

// autoInstallText runs the MOAT-T4-004 check on one command line.
//
// Grammar: the same as unpinnedPackageText. Example: "npx -y @scope/server".
// A blank line gives no hit.
func autoInstallText(raw string) []Hit {
	return commandLineHits(caseServerName, strings.Fields(raw), checkAutoInstall, HeuristicAutoInstall)
}

// newTyposquatText returns the MOAT-T5-001 check as a text adapter. It parses
// the embedded popular server list once, when it is called. The returned
// function holds no global state.
//
// Grammar: the line is split at white space (strings.Fields). If it has one
// field, it is a bare package name, such as
// "@modelcontextprotocol/server-filesytem". That package is run as "npx <name>".
// If it has more fields, they are a command line, as in unpinnedPackageText.
// A blank line gives no hit.
//
// The server has no name. Only the package is compared, so the name cannot
// make a result.
func newTyposquatText() (func(raw string) []Hit, error) {
	popular, err := builtinPopular()
	if err != nil {
		return nil, err
	}
	check := NewTyposquat(popular)
	return func(raw string) []Hit {
		fields := strings.Fields(raw)
		if len(fields) == 1 {
			fields = []string{"npx", fields[0]}
		}
		return commandLineHits("", fields, check.Check, HeuristicTyposquat)
	}, nil
}

// builtinPopular parses the embedded popular server list.
func builtinPopular() ([]string, error) {
	return ParsePopular(strings.NewReader(builtinrules.PopularServers))
}

// commandLineHits runs check on a stdio server with the given name. The first
// field is the command and the other fields are its args. No fields give no
// hit.
func commandLineHits(name string, fields []string, check func(discover.Server) []Finding, heuristic string) []Hit {
	if len(fields) == 0 {
		return nil
	}
	return findingHits(check(caseStdioServer(name, fields[0], fields[1:])), heuristic)
}

// caseStdioServer returns a stdio server with the given name, command and args.
func caseStdioServer(name, command string, args []string) discover.Server {
	return discover.Server{
		Name:      name,
		Transport: discover.TransportStdio,
		Command:   command,
		Args:      discover.NewArgs(args),
	}
}

// findingHits turns the findings of one native check into text hits. It
// returns nil when there are no findings. Otherwise it returns one Hit with no
// offset and the detail "<heuristic> matched". heuristic is the fixed name of
// the heuristic, so the detail never holds input text or a Finding field.
func findingHits(findings []Finding, heuristic string) []Hit {
	if len(findings) == 0 {
		return nil
	}
	return []Hit{{Offset: NoOffset, Detail: heuristic + " matched"}}
}
