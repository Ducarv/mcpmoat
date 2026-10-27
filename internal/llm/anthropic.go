package llm

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Settings of the Anthropic Messages API.
const (
	// anthropicPath is the path of the Messages API.
	anthropicPath = "/v1/messages"
	// anthropicVersion is the value of the anthropic-version header.
	anthropicVersion = "2023-06-01"
	// anthropicMaxTokens caps the model output. A verdict needs about 30
	// tokens.
	anthropicMaxTokens = 200
	// anthropicToolName is the name of the one tool that the model must
	// call. Its input is the verdict.
	anthropicToolName = "classify"
	// anthropicToolDescription is the fixed description of that tool.
	anthropicToolDescription = "Record the risk rating of the tool description in the user message."
)

// anthropicAPI implements api for the Anthropic Messages API. The request
// forces the model to call the tool anthropicToolName, whose input schema is
// the verdict schema, so the tool input is the verdict.
type anthropicAPI struct{}

// anthropicRequest is the request body.
type anthropicRequest struct {
	Model     string `json:"model"`
	MaxTokens int    `json:"max_tokens"`
	// Temperature has no omitempty: 0 must be sent.
	Temperature float64         `json:"temperature"`
	System      string          `json:"system"`
	Messages    []chatMessage   `json:"messages"`
	Tools       []anthropicTool `json:"tools"`
	ToolChoice  anthropicChoice `json:"tool_choice"`
}

// anthropicTool is one tool of the request.
type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// anthropicChoice is the tool_choice of the request. Type "tool" forces the
// tool Name.
type anthropicChoice struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// anthropicMessageType is the "type" of a Messages API response.
const anthropicMessageType = "message"

// anthropicResponse is the part of the response body that the client reads.
// Other fields are ignored. Type and Content are pointers, so the client can
// tell a missing or null field (nil) from an empty string or array.
type anthropicResponse struct {
	Type       *string                  `json:"type"`
	StopReason string                   `json:"stop_reason"`
	Content    *[]anthropicContentBlock `json:"content"`
}

// anthropicContentBlock is one content block of the response.
type anthropicContentBlock struct {
	Type  string          `json:"type"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// path returns the path of the Messages API.
func (anthropicAPI) path() string { return anthropicPath }

// requestBody returns the Messages API request for model and message.
func (anthropicAPI) requestBody(model, message string) any {
	return anthropicRequest{
		Model:       model,
		MaxTokens:   anthropicMaxTokens,
		Temperature: 0,
		System:      SystemPrompt,
		Messages:    []chatMessage{{Role: "user", Content: message}},
		Tools: []anthropicTool{{
			Name:        anthropicToolName,
			Description: anthropicToolDescription,
			InputSchema: verdictSchema(),
		}},
		ToolChoice: anthropicChoice{Type: "tool", Name: anthropicToolName},
	}
}

// setAuth sets the x-api-key and anthropic-version headers.
func (anthropicAPI) setAuth(h http.Header, key discover.Secret) {
	h.Set("x-api-key", key.Reveal())
	h.Set("anthropic-version", anthropicVersion)
}

// parseResponse reads a Messages API response. The verdict is the input of
// the one tool_use block named anthropicToolName.
//
// A body that is not the API envelope gives errBadResponse: a body that is
// not a JSON object, a top-level "error" that is not null, a "type" that is
// present and not "message", or a "content" that is missing or null. An
// envelope whose message is not usable gives ErrInvalidOutput: a refusal, an
// output cut at max_tokens, or no such block or more than one (an empty
// "content" array has none). parseVerdict checks the tool input.
func (anthropicAPI) parseResponse(body []byte) (Verdict, error) {
	var resp anthropicResponse
	if err := decodeEnvelope(body, &resp); err != nil {
		return Verdict{}, err
	}
	if resp.Type != nil && *resp.Type != anthropicMessageType {
		return Verdict{}, errBadResponse
	}
	if resp.Content == nil {
		return Verdict{}, errBadResponse
	}
	switch resp.StopReason {
	case "refusal":
		return Verdict{}, invalidOutput("the model refused")
	case "max_tokens":
		return Verdict{}, invalidOutput("the output was cut at the token limit")
	}
	var (
		input json.RawMessage
		found int
	)
	for _, block := range *resp.Content {
		if block.Type == "tool_use" && block.Name == anthropicToolName {
			input = block.Input
			found++
		}
	}
	switch found {
	case 0:
		return Verdict{}, invalidOutput(fmt.Sprintf("no %s tool call", anthropicToolName))
	case 1:
		return parseVerdict(input)
	default:
		return Verdict{}, invalidOutput(fmt.Sprintf("more than one %s tool call", anthropicToolName))
	}
}
