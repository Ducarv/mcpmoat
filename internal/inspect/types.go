package inspect

import "encoding/json"

// This file holds the result types of an inspection. They do not import the
// MCP SDK on purpose: they are the stable contract between inspect and the
// rest of mcpmoat, so an SDK or spec change stays local (NFR-06).
//
// Every string in these types comes from the MCP server, and a malicious
// server controls it. Treat it as untrusted text. Callers must escape it with
// internal/termsafe before they print it to a terminal, and must never
// execute it or put it into a command or a format string.
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
	// The SDK decodes it, so this is the server's JSON encoded again. It is
	// nil when the server sends none.
	InputSchema json.RawMessage

	// OutputSchema is the JSON Schema of the tool result, with the same
	// encoding as InputSchema. It is nil when the server sends none.
	OutputSchema json.RawMessage
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

// Result is everything that inspect reads from one MCP server.
//
// A server that does not offer a capability gives an empty list for it. The
// list is nil when the server did not declare the capability and refused the
// list request, and empty but not nil when the server answered with an empty
// list. A report can use the difference: a server that hides a list only from
// some clients can look like a server without the capability.
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
}
