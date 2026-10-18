package inspecttest

import (
	"encoding/json"

	"github.com/Ducarv/mcpmoat/internal/inspect"
)

// BenignProtocolVersion is the protocol version that the stdio inspector
// negotiates with the benign fixture server.
//
// Both sides use the MCP SDK v1.8.0, so they agree on its latest version,
// latestProtocolVersion in mcp/shared.go of the SDK. The client gets it from
// the server/discover request (SEP-2575), because the stdio transport serves
// all versions. Update this value when the SDK version in go.mod changes.
const BenignProtocolVersion = "2026-07-28"

// BenignResult returns the [inspect.Result] that the stdio inspector produces
// for the benign fixture server (testdata/servers/benign) in mode ok.
//
// Tests use it as the negative baseline: no rule or heuristic must report a
// finding on it (NFR-05). Tests of rules and pins also give it to a [Fake]
// (M4, M5), so they do not have to start the server.
//
// Each call returns a new value, so a caller can change it without an effect
// on other tests. Keep it in sync with testdata/servers/benign/main.go.
//
// The SDK lists features sorted by name, so the tools come in the order
// "add", "echo". The input schemas are the bytes that the inspector makes
// when it encodes the decoded schema again: sorted keys and no spaces. The
// server sends no output schemas, no titles and no instructions.
func BenignResult() inspect.Result {
	return inspect.Result{
		ProtocolVersion: BenignProtocolVersion,
		ServerName:      "benign",
		ServerVersion:   "1.0.0",
		Instructions:    "",
		Tools: []inspect.Tool{
			{
				Name:        "add",
				Description: "Add two numbers and return the sum.",
				InputSchema: json.RawMessage(`{"properties":{"a":{"description":"First number.","type":"number"},"b":{"description":"Second number.","type":"number"}},"required":["a","b"],"type":"object"}`),
			},
			{
				Name:        "echo",
				Description: "Return the input text unchanged.",
				InputSchema: json.RawMessage(`{"properties":{"text":{"description":"Text to return.","type":"string"}},"required":["text"],"type":"object"}`),
			},
		},
		Prompts: []inspect.Prompt{
			{
				Name:        "greeting",
				Description: "Write a short, friendly greeting.",
				Arguments: []inspect.PromptArgument{
					{
						Name:        "name",
						Description: "Name of the person to greet.",
						Required:    true,
					},
				},
			},
		},
		Resources: []inspect.Resource{
			{
				URI:         "mcpmoat://benign/readme",
				Name:        "readme",
				Description: "Short text about this test server.",
				MIMEType:    "text/plain",
			},
		},
	}
}
