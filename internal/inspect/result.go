package inspect

import "encoding/json"

// Result is what one MCP server reports about itself: its identity from the
// initialize handshake and the tools, prompts and resources it lists.
//
// Result does not use types from the MCP SDK, so that rules, pins and report
// do not depend on the SDK (NFR-06).
//
// Every string in Result and in the types it holds is untrusted text that the
// server sent. Callers must print it through package internal/termsafe and
// must never execute or interpolate it. Each slice keeps the order in which
// the server sent the items.
type Result struct {
	// ProtocolVersion is the MCP protocol version that the client and the
	// server agreed on in the handshake, for example "2025-06-18".
	ProtocolVersion string

	// ServerName is the name that the server gives in its handshake
	// (serverInfo.name).
	ServerName string

	// ServerVersion is the version that the server gives in its handshake
	// (serverInfo.version).
	ServerVersion string

	// Instructions is the optional text that the server sends in its
	// handshake for the AI model. A model reads it, so it can hold a prompt
	// injection.
	Instructions string

	// Tools are the tools that the server lists. Tools is nil when the
	// server does not advertise the tools capability, and empty but not nil
	// when it advertises the capability and lists no tools.
	Tools []Tool

	// Prompts are the prompts that the server lists. Nil and empty differ
	// as for Tools.
	Prompts []Prompt

	// Resources are the resources that the server lists. Nil and empty
	// differ as for Tools.
	Resources []Resource
}

// Tool is one tool that a server lists.
//
// All fields are untrusted text from the server. See [Result].
type Tool struct {
	// Name is the tool name that the model uses to call the tool.
	Name string

	// Title is the optional display name of the tool.
	Title string

	// Description is the text that the model reads to decide when to call
	// the tool.
	Description string

	// InputSchema is the JSON Schema of the tool arguments, as raw JSON.
	// Rules and pins read and hash it without SDK types.
	InputSchema json.RawMessage

	// OutputSchema is the JSON Schema of the tool result, as raw JSON. It is
	// nil when the server sends no output schema.
	OutputSchema json.RawMessage
}

// Prompt is one prompt template that a server lists.
//
// All fields are untrusted text from the server. See [Result].
type Prompt struct {
	// Name is the prompt name.
	Name string

	// Title is the optional display name of the prompt.
	Title string

	// Description is the optional text that tells what the prompt does.
	Description string

	// Arguments are the arguments that the prompt accepts.
	Arguments []PromptArgument
}

// PromptArgument is one argument of a [Prompt].
//
// All string fields are untrusted text from the server. See [Result].
type PromptArgument struct {
	// Name is the argument name.
	Name string

	// Title is the optional display name of the argument.
	Title string

	// Description is the optional text that tells what the argument is.
	Description string

	// Required is true when the prompt cannot be used without the argument.
	Required bool
}

// Resource is one resource that a server lists.
//
// All fields are untrusted text from the server. See [Result].
type Resource struct {
	// URI is the identifier of the resource, as the server sent it. mcpmoat
	// does not read or fetch it.
	URI string

	// Name is the resource name.
	Name string

	// Title is the optional display name of the resource.
	Title string

	// Description is the optional text that tells what the resource is.
	Description string

	// MIMEType is the optional media type of the resource, for example
	// "text/plain".
	MIMEType string
}
