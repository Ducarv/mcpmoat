package llm

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// openAIPath is the path of the Chat Completions API. The default base URL
// already holds "/v1".
const openAIPath = "/chat/completions"

// openAIAPI implements api for the OpenAI Chat Completions API, or a server
// that speaks it. The request asks for structured output with the verdict
// schema in strict mode, so the message content is the verdict.
type openAIAPI struct{}

// openAIRequest is the request body. It has no temperature: OpenAI reasoning
// models (the o-series and the gpt-5 family) accept only the default value
// and answer HTTP 400 to any other. The strict json_schema response format
// keeps the output in the verdict format.
type openAIRequest struct {
	Model          string               `json:"model"`
	Messages       []chatMessage        `json:"messages"`
	ResponseFormat openAIResponseFormat `json:"response_format"`
}

// openAIResponseFormat is the response_format of the request.
type openAIResponseFormat struct {
	Type       string           `json:"type"`
	JSONSchema openAIJSONSchema `json:"json_schema"`
}

// openAIJSONSchema is the json_schema of the response format.
type openAIJSONSchema struct {
	Name   string          `json:"name"`
	Strict bool            `json:"strict"`
	Schema json.RawMessage `json:"schema"`
}

// openAIResponse is the part of the response body that the client reads.
// Other fields are ignored. Choices is a pointer, so the client can tell a
// missing or null "choices" (nil) from an empty array.
type openAIResponse struct {
	Choices *[]openAIChoice `json:"choices"`
}

// openAIChoice is one choice of the response.
type openAIChoice struct {
	FinishReason string `json:"finish_reason"`
	Message      struct {
		// Content and Refusal are raw, so the client can tell a string
		// from null or another JSON type.
		Content json.RawMessage `json:"content"`
		Refusal json.RawMessage `json:"refusal"`
	} `json:"message"`
}

// path returns the path of the Chat Completions API.
func (openAIAPI) path() string { return openAIPath }

// requestBody returns the Chat Completions request for model and message.
func (openAIAPI) requestBody(model, message string) any {
	return openAIRequest{
		Model: model,
		Messages: []chatMessage{
			{Role: "system", Content: SystemPrompt},
			{Role: "user", Content: message},
		},
		ResponseFormat: openAIResponseFormat{
			Type: "json_schema",
			JSONSchema: openAIJSONSchema{
				Name:   VerdictSchemaName,
				Strict: true,
				Schema: VerdictSchema(),
			},
		},
	}
}

// setAuth sets the Authorization header.
func (openAIAPI) setAuth(h http.Header, key discover.Secret) {
	h.Set("Authorization", "Bearer "+key.Reveal())
}

// parseResponse reads a Chat Completions response. The verdict is the
// content string of the message of the one choice.
//
// A body that is not the API envelope gives ErrBadResponse: a body that is
// not a JSON object, a top-level "error" that is not null, or a "choices"
// that is missing or null. An envelope whose message is not usable gives
// ErrInvalidOutput: an empty "choices" array or more than one choice, a
// refusal, an output cut at the token limit or by a content filter, or a
// content that is empty or not a JSON string. parseVerdict checks the
// content.
func (openAIAPI) parseResponse(body []byte) (Verdict, error) {
	var resp openAIResponse
	if err := decodeEnvelope(body, &resp); err != nil {
		return Verdict{}, err
	}
	if resp.Choices == nil {
		return Verdict{}, ErrBadResponse
	}
	choices := *resp.Choices
	switch len(choices) {
	case 0:
		return Verdict{}, invalidOutput("no choices")
	case 1:
	default:
		return Verdict{}, invalidOutput("more than one choice")
	}
	choice := choices[0]
	if !jsonAbsent(choice.Message.Refusal) {
		return Verdict{}, invalidOutput("the model refused")
	}
	switch choice.FinishReason {
	case "length":
		return Verdict{}, invalidOutput("the output was cut at the token limit")
	case "content_filter":
		return Verdict{}, invalidOutput("the output was blocked by a content filter")
	}
	var content string
	if err := json.Unmarshal(choice.Message.Content, &content); err != nil {
		// null, a number, an array of parts or no content at all.
		return Verdict{}, invalidOutput("the message content is not a string")
	}
	if content == "" {
		return Verdict{}, invalidOutput("the message content is empty")
	}
	return parseVerdict([]byte(content))
}

// jsonAbsent reports whether raw is a missing field, JSON null or an empty
// JSON string.
func jsonAbsent(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) == 0 || string(raw) == "null" || string(raw) == `""`
}
