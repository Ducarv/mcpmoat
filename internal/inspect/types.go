package inspect

import "encoding/json"

// This file holds the result types of an inspection. They do not import the
// MCP SDK on purpose: they are the stable contract between inspect and the
// rest of mcpmoat, so an SDK or spec change stays local (NFR-06).
//
// Every string in these types comes from the MCP server, and a malicious
// server controls it. Treat it as untrusted text. Callers must escape it with
// internal/termsafe before they print it to a terminal, and must never
// execute it or put it into a command or a format string. The one exception
// is Warning: its strings come from the client config or from fixed lists in
// mcpmoat, never from the server. Callers must still escape them with
// internal/termsafe.
//
// The types have no methods and no struct tags on purpose: output types live
// in internal/report.

// Tool is one tool that a server lists with tools/list.
type Tool struct {
	// Name is the tool name.
	Name string

	// Title is the human-readable name. It is empty when the server sends
	// none.
	Title string

	// Description tells the model what the tool does. Clients put it in the
	// model prompt, so it is a main place for prompt injection (threat T1).
	Description string

	// InputSchema is the JSON Schema of the tool arguments, as raw JSON.
	// The SDK decodes it, so this is the server's JSON encoded again: key
	// order and spacing can differ, and numbers pass through float64, so an
	// integer above 2^53 can change. It is nil when the server sends none.
	InputSchema json.RawMessage

	// OutputSchema is the JSON Schema of the tool result, with the same
	// encoding as InputSchema. It is nil when the server sends none.
	OutputSchema json.RawMessage

	// Annotations are the behaviour hints of the tool. They are nil when the
	// server sends none. The annotations are part of the pin hash and of the
	// rule input (PRD FR-11), so a server that flips a hint after approval
	// changes the pin.
	Annotations *ToolAnnotations
}

// ToolAnnotations are the hints that a server gives about the behaviour of a
// tool. The server sets them, so they are claims, not facts. A malicious
// server can say that a destructive tool is read-only.
//
// A nil hint means that the server did not send it. The MCP SDK v1.8.0
// decodes readOnlyHint and idempotentHint as plain bool, not as a pointer.
// For these two hints, absent and false look the same, so nil means "absent
// or false". False is the spec default for both. Only true is visible, so a
// change to true is always visible.
type ToolAnnotations struct {
	// Title is the human-readable name of the tool from the annotations. It
	// is empty when the server sends none. It is untrusted server text, like
	// Tool.Description, and can carry prompt injection (threat T1).
	Title string

	// ReadOnlyHint is true when the server says that the tool does not change
	// its environment. It is nil when the hint is absent or false (the spec
	// default), because the SDK does not keep the difference.
	ReadOnlyHint *bool

	// DestructiveHint is true when the server says that the tool can delete
	// or overwrite data. It is nil when the server does not send the hint.
	// The spec default is true.
	DestructiveHint *bool

	// IdempotentHint is true when the server says that a second call with the
	// same arguments has no additional effect. It is nil when the hint is
	// absent or false (the spec default), because the SDK does not keep the
	// difference.
	IdempotentHint *bool

	// OpenWorldHint is true when the server says that the tool can reach
	// external entities, for example the web. It is nil when the server does
	// not send the hint. The spec default is true.
	OpenWorldHint *bool
}

// PromptArgument is one argument of a Prompt.
type PromptArgument struct {
	// Name is the argument name.
	Name string

	// Description explains the argument.
	Description string

	// Required is true when the client must give the argument.
	Required bool
}

// Prompt is one prompt template that a server lists with prompts/list.
type Prompt struct {
	// Name is the prompt name.
	Name string

	// Title is the human-readable name. It is empty when the server sends
	// none.
	Title string

	// Description explains the prompt.
	Description string

	// Arguments are the arguments that the prompt accepts. It is empty when
	// the prompt has none.
	Arguments []PromptArgument
}

// Resource is one resource that a server lists with resources/list.
type Resource struct {
	// URI is the address of the resource. It can be any scheme, so do not
	// open or fetch it.
	URI string

	// Name is the resource name.
	Name string

	// Title is the human-readable name. It is empty when the server sends
	// none.
	Title string

	// Description explains the resource.
	Description string

	// MIMEType is the media type that the server declares for the resource.
	// It is empty when the server declares none.
	MIMEType string
}

// ResourceTemplate is one parameterized resource that a server lists with
// resources/templates/list. All text fields are untrusted server text.
type ResourceTemplate struct {
	// URITemplate is the RFC 6570 URI template of the resource. mcpmoat never
	// expands it and never opens or fetches it.
	URITemplate string

	// Name is the template name.
	Name string

	// Title is the human-readable name. It is empty when the server sends
	// none.
	Title string

	// Description explains the template. Clients can put it in the model
	// prompt, so it is a place for prompt injection (threat T1).
	Description string

	// MIMEType is the media type that the server declares for the resources
	// of the template. It is empty when the server declares none.
	MIMEType string
}

// WarningKind names the kind of a Warning. Its values are stable: reports and
// JSON output can show them, and users can match on them.
type WarningKind string

// WarnCleartextSecrets is the kind of a Warning about secrets that the config
// makes mcpmoat send over plain http:// to a host that is not loopback. On a
// failed inspection, the secrets may not have gone out (see
// ConnectError.Warnings). The value
// "cleartext-secrets" is stable and does not change between versions.
const WarnCleartextSecrets WarningKind = "cleartext-secrets"

// WarnUndeclaredCapability is the kind of a Warning about lists that the
// server did not declare in its capabilities but still answered with at least
// one item. A server that hides a capability from its declaration can show
// different lists to different clients, so the user should look at it (issue
// #97). Warning.Capabilities names the lists. The value
// "undeclared-capability" is stable and does not change between versions.
const WarnUndeclaredCapability WarningKind = "undeclared-capability"

// WarnDNSPinUnavailable is the kind of a Warning that mcpmoat could not pin
// the DNS answer for the server host, because the connection goes through a
// proxy from the environment (HTTP_PROXY, HTTPS_PROXY). The proxy resolves the
// host, so the address checks of the pinned dialer do not apply to it (issue
// #106). The warning holds no URL: the proxy setting can hold a user name and
// a password. The value "dns-pin-unavailable" is stable and does not change
// between versions.
const WarnDNSPinUnavailable WarningKind = "dns-pin-unavailable"

// Warning is a problem with the way mcpmoat connects to a server, or a sign
// that the server behaves in an unusual way. It is not a rule finding. A
// Warning holds keys and fixed names only, never secret values, never URLs
// and never server text.
//
// Only the fields that belong to Kind are set. The other fields are zero.
type Warning struct {
	// Kind tells what the warning is about.
	Kind WarningKind

	// HeaderKeys are the header keys from the client config that mcpmoat
	// sends, as written in the config. Each key is in the list one time. The
	// list never holds header values. The keys are config text, so callers
	// must escape them with internal/termsafe before they print them.
	HeaderKeys []string

	// URLUserInfo is true when mcpmoat sends the user info of the server URL
	// as a Basic Authorization header: the URL has user info and the config
	// sets no non-empty Authorization header. It is false when a config
	// Authorization header replaces the user info, because the user info
	// then does not go out.
	URLUserInfo bool

	// URLSecrets is true when the query or the path of the server URL holds
	// parts that mcpmoat treats as secrets: the parts that the redacted URL
	// masks (discover.SecretQueryParts and discover.SecretPathSegments). The
	// Warning never holds these parts, their names or their values.
	URLSecrets bool

	// Capabilities are the lists that a WarnUndeclaredCapability warning is
	// about, in this order: "tools", "prompts", "resources" and
	// "resource-templates". It holds only these fixed names, never server
	// text. Each name is in the list one time.
	Capabilities []string
}

// Result is everything that inspect reads from one MCP server.
//
// A list is nil when the server did not declare the capability and refused
// the list request. It is empty but not nil when the server answered with an
// empty list. In both cases the server offers no such item. A report can use
// the difference: a server that hides a list only from some clients can look
// like a server without the capability.
//
// mcpmoat sends every list request, also for a capability that the server did
// not declare. When such a list has at least one item, Warnings holds a
// WarnUndeclaredCapability warning that names the list. An undeclared list
// that the server answers empty gets no warning: some servers, the SDK server
// for example, answer every list request.
type Result struct {
	// ServerName is the server name from the initialize result.
	ServerName string

	// ServerVersion is the server version from the initialize result.
	ServerVersion string

	// ProtocolVersion is the MCP protocol version that client and server
	// agreed on.
	ProtocolVersion string

	// Instructions is the server instructions text from the initialize
	// result. Clients may put it in the model prompt, so it is a place for
	// prompt injection (threat T1). It is empty when the server sends none.
	Instructions string

	// Tools are the tools that the server lists.
	Tools []Tool

	// Prompts are the prompts that the server lists.
	Prompts []Prompt

	// Resources are the resources that the server lists.
	Resources []Resource

	// ResourceTemplates are the resource templates that the server lists.
	// They follow the same nil-or-empty rule as the other lists, with one
	// addition: a server that declares the resources capability but answers
	// "method not found" for resources/templates/list gives an empty list,
	// not nil.
	ResourceTemplates []ResourceTemplate

	// Warnings are the problems with the connection to the server and the
	// unusual server behaviour that mcpmoat saw, for example secrets sent over
	// plain http://, a proxy that keeps mcpmoat from pinning the DNS answer,
	// or items in a list that the server did not declare. It is nil when there
	// are none.
	Warnings []Warning
}
