package rules

// Rule IDs of the native checks. Each native check backs one rule. The
// built-in YAML rules use the same IDs, so a finding has one ID whatever code
// produced it.
const (
	// RuleShadowing is the ID of the tool shadowing check (threat T3): a
	// tool description names a tool of another server.
	RuleShadowing = "MOAT-T3-001"

	// RuleInsecureURL is the ID of the insecure URL check (threat T4): a
	// remote server URL that does not use HTTPS.
	RuleInsecureURL = "MOAT-T4-001"

	// RulePlaintextSecret is the ID of the plaintext secret check
	// (threat T4): a secret written in clear text in the client config.
	RulePlaintextSecret = "MOAT-T4-002" //nolint:gosec // G101: rule ID, not a credential

	// RuleUnpinnedPackage is the ID of the unpinned package check
	// (threat T4): a server that runs a package with no fixed version.
	RuleUnpinnedPackage = "MOAT-T4-003"

	// RuleAutoInstall is the ID of the auto install check (threat T4): a stdio
	// server that runs npx with its yes option on (-y, --yes or an
	// npm_config_yes env entry). See checkAutoInstall.
	RuleAutoInstall = "MOAT-T4-004"

	// RuleTyposquat is the ID of the typosquat check (threat T5): a server
	// or package name that is close to a popular name.
	RuleTyposquat = "MOAT-T5-001"
)

// Fixed texts of Finding.Message, one for each rule.
const (
	shadowingMessage       = "tool description names a tool of another server"
	insecureURLMessage     = "remote server uses plain http:// without TLS"
	plaintextSecretMessage = "config holds a plaintext secret; use an environment variable reference" //nolint:gosec // G101: message text, not a credential
	unpinnedPackageMessage = "package runner fetches an unpinned version"
	autoInstallMessage     = "npx runs with its yes option on (-y, --yes or npm_config_yes)"
	typosquatMessage       = "name is close to a popular MCP server"
)

// Values of Finding.Field: the config field that a finding is about.
const (
	// FieldURL is the server URL.
	FieldURL = "url"

	// FieldEnv is the env map of a stdio server.
	FieldEnv = "env"

	// FieldHeaders is the header map of a remote server.
	FieldHeaders = "headers"

	// FieldArgs is the command arguments of a stdio server.
	FieldArgs = "args"

	// FieldName is the server name.
	FieldName = "name"
)

// Finding is one result of a native check. It says which rule fired and where.
//
// A Finding holds untrusted text from client configs and from MCP servers
// (server names, tool names, keys). Callers must escape every field with
// internal/termsafe before they print it to a terminal, and must never execute
// it or put it into a command or a format string. A Finding never holds a
// secret value, a URL or a description text: it names the place of the problem,
// not the content.
type Finding struct {
	// RuleID is the ID of the rule that the native check backs, such as
	// RuleShadowing. The built-in YAML rules use the same IDs.
	RuleID string

	// Server is the name of the server, from discover.Server.Name.
	Server string

	// Tool is the tool name for a T3 finding. It is empty for the other
	// threats.
	Tool string

	// Field is the config field that the finding is about: FieldURL, FieldEnv,
	// FieldHeaders, FieldArgs or FieldName. It is empty when no field applies,
	// as for T3 findings.
	Field string

	// Key is the env or header KEY that the finding is about. It is never the
	// value. It is empty when no key applies.
	Key string

	// Related names the second party of the finding. For T3 it is the shadowed
	// tool, as "<server>/<tool>". For T5 it is the popular name that the
	// server or package name resembles. For MOAT-T4-003 it is the package
	// name, only when the redaction policy (discover.RedactArgs) shows it
	// unmasked; otherwise it is empty. It is empty for the other findings.
	Related string

	// Message is a fixed English text. It is built only from constants in
	// mcpmoat and from the safe fields above, never from a value, a URL or a
	// description.
	Message string
}
