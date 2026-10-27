package llm

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"testing"
)

// openAIReply returns a Chat Completions response whose message content is
// the verdict risk and category.
func openAIReply(risk Risk, category Category) string {
	return openAIContentReply(fmt.Sprintf(`{"risk":%q,"category":%q}`, risk, category))
}

// openAIContentReply returns a Chat Completions response with content as the
// message content string.
func openAIContentReply(content string) string {
	quoted, _ := json.Marshal(content) // a string always encodes
	return `{"id":"chatcmpl-1","object":"chat.completion","model":"m","choices":[{"index":0,"finish_reason":"stop",` +
		`"message":{"role":"assistant","content":` + string(quoted) + `,"refusal":null}}],"usage":{}}`
}

// openAIChoiceReply returns a Chat Completions response with one choice
// whose finish reason and message are given as raw JSON.
func openAIChoiceReply(finish, message string) string {
	return `{"choices":[{"index":0,"finish_reason":` + finish + `,"message":` + message + `}]}`
}

func TestOpenAIRequestShape(t *testing.T) {
	t.Parallel()
	srv := startServer(t, reply(http.StatusOK, openAIReply(RiskNone, CategoryOther)))
	c := newTestClient(t, ProviderOpenAI, srv.URL+"/v1/")

	v, err := c.Classify(t.Context(), shapeInput)
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if want := (Verdict{Risk: RiskNone, Category: CategoryOther}); v != want {
		t.Errorf("Classify() = %+v, want %+v", v, want)
	}
	req := srv.lastRequest()

	if req.Method != http.MethodPost || req.RequestURI != "/v1/chat/completions" {
		t.Errorf("request = %s %s, want POST /v1/chat/completions", req.Method, req.RequestURI)
	}
	for name, want := range map[string]string{
		"Authorization":     "Bearer " + llmTestKey,
		"Content-Type":      "application/json",
		"Accept":            "application/json",
		"X-Api-Key":         "",
		"Anthropic-Version": "",
		"Accept-Encoding":   "", // DisableCompression
	} {
		if got := req.Header.Get(name); got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}

	checkRawBody(t, req.Body)
	// No temperature: OpenAI reasoning models refuse any value but the
	// default (HTTP 400).
	body := decodeKeys(t, "body", req.Body, "model", "messages", "response_format")
	if got := decodeAs[string](t, "model", body["model"]); got != llmTestModel {
		t.Errorf("model = %q, want %q", got, llmTestModel)
	}

	wantMessage, _, err := toolMessage(shapeInput)
	if err != nil {
		t.Fatalf("toolMessage() error = %v", err)
	}
	messages := decodeAs[[]map[string]string](t, "messages", body["messages"])
	want := []map[string]string{
		{"role": "system", "content": SystemPrompt},
		{"role": "user", "content": wantMessage},
	}
	if !slices.EqualFunc(messages, want, maps.Equal) {
		t.Errorf("messages = %q, want %q", messages, want)
	}

	format := decodeKeys(t, "response_format", body["response_format"], "type", "json_schema")
	if got := decodeAs[string](t, "response_format type", format["type"]); got != "json_schema" {
		t.Errorf("response_format type = %q, want json_schema", got)
	}
	schema := decodeKeys(t, "json_schema", format["json_schema"], "name", "strict", "schema")
	if got := decodeAs[string](t, "json_schema name", schema["name"]); got != verdictSchemaName {
		t.Errorf("json_schema name = %q, want %q", got, verdictSchemaName)
	}
	if got := string(schema["strict"]); got != "true" {
		t.Errorf("json_schema strict = %s, want true", got)
	}
	if got, want := compactJSON(t, schema["schema"]), compactJSON(t, verdictSchema()); got != want {
		t.Errorf("json_schema schema = %s, want %s", got, want)
	}
}

// TestNewOpenAIAPIMaxCompletionTokens checks that only the exact default
// OpenAI base URL gets the output-token cap.
func TestNewOpenAIAPIMaxCompletionTokens(t *testing.T) {
	t.Parallel()
	tests := []struct {
		baseURL string
		want    int
	}{
		{baseURL: defaultOpenAIBaseURL, want: 2048},
		{baseURL: "https://api.openai.com/v1/", want: 0}, // Resolve trims the slash first
		{baseURL: "https://API.openai.com/v1", want: 0},
		{baseURL: "https://api.openai.com", want: 0},
		{baseURL: "https://api.openai.com/v2", want: 0},
		{baseURL: "https://api.openai.com:443/v1", want: 0},
		{baseURL: "http://api.openai.com/v1", want: 0},
		{baseURL: "https://api.openai.com.example.com/v1", want: 0},
		{baseURL: "https://openai.example.com/v1", want: 0},
		{baseURL: "http://127.0.0.1:8080/v1", want: 0},
		{baseURL: "", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.baseURL, func(t *testing.T) {
			t.Parallel()
			if got := newOpenAIAPI(tt.baseURL).maxCompletionTokens; got != tt.want {
				t.Errorf("newOpenAIAPI(%q).maxCompletionTokens = %d, want %d", tt.baseURL, got, tt.want)
			}
		})
	}
}

// TestOpenAIRequestTokenField checks the encoded request of a client from
// New. The default base URL cannot be reached in a unit test, so the test
// encodes the request body of the client as send does. Only the default URL
// has max_completion_tokens; no request ever has max_tokens.
func TestOpenAIRequestTokenField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		baseURL string
		wantCap bool
	}{
		{name: "default", baseURL: "", wantCap: true},
		{name: "default written out", baseURL: defaultOpenAIBaseURL, wantCap: true},
		{name: "default with a slash", baseURL: defaultOpenAIBaseURL + "/", wantCap: true},
		{name: "custom host", baseURL: "https://openai.example.com/v1", wantCap: false},
		{name: "loopback", baseURL: "http://127.0.0.1:8080/v1", wantCap: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(Config{Provider: ProviderOpenAI, Model: llmTestModel, BaseURL: tt.baseURL, APIKey: testSecret()})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			t.Cleanup(c.CloseIdleConnections)
			body, err := encodeJSON(c.api.requestBody(c.model, "m"))
			if err != nil {
				t.Fatalf("encodeJSON() error = %v", err)
			}
			keys := []string{"model", "messages", "response_format"}
			if tt.wantCap {
				keys = append(keys, "max_completion_tokens")
			}
			got := decodeKeys(t, "body", body, keys...)
			if tt.wantCap {
				if v := string(got["max_completion_tokens"]); v != "2048" {
					t.Errorf("max_completion_tokens = %s, want 2048", v)
				}
			}
		})
	}
}

func TestOpenAIParseResponseValid(t *testing.T) {
	t.Parallel()
	for _, risk := range risks {
		for _, category := range categories {
			t.Run(string(risk)+"/"+string(category), func(t *testing.T) {
				t.Parallel()
				v, err := openAIAPI{}.parseResponse([]byte(openAIReply(risk, category)))
				if err != nil {
					t.Fatalf("parseResponse() error = %v", err)
				}
				if want := (Verdict{Risk: risk, Category: category}); v != want {
					t.Errorf("parseResponse() = %+v, want %+v", v, want)
				}
			})
		}
	}

	verdict := `"{\"risk\":\"low\",\"category\":\"other\"}"`
	shapes := []struct {
		name string
		body string
	}{
		{name: "empty refusal", body: openAIChoiceReply(`"stop"`, `{"content":`+verdict+`,"refusal":""}`)},
		{name: "no refusal field", body: openAIChoiceReply(`"stop"`, `{"content":`+verdict+`}`)},
		{name: "null finish reason", body: openAIChoiceReply(`null`, `{"content":`+verdict+`}`)},
		{name: "no finish reason", body: `{"choices":[{"message":{"content":` + verdict + `}}]}`},
		{name: "white space in the content", body: openAIContentReply("\n {\"risk\" : \"low\", \"category\":\"other\"}\n")},
		{name: "unknown fields", body: `{"x":{},"choices":[{"logprobs":null,"message":{"tool_calls":[],"content":` + verdict + `}}]}`},
		{name: "null error", body: `{"error":null,"choices":[{"message":{"content":` + verdict + `}}]}`},
	}
	for _, tt := range shapes {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v, err := openAIAPI{}.parseResponse([]byte(tt.body))
			if err != nil {
				t.Fatalf("parseResponse() error = %v", err)
			}
			if want := (Verdict{Risk: RiskLow, Category: CategoryOther}); v != want {
				t.Errorf("parseResponse() = %+v, want %+v", v, want)
			}
		})
	}
}

func TestOpenAIParseResponseInvalid(t *testing.T) {
	t.Parallel()
	verdict := `"{\"risk\":\"none\",\"category\":\"other\"}"`
	choice := `{"finish_reason":"stop","message":{"content":` + verdict + `}}`
	tests := []struct {
		name    string
		body    string
		wantBad bool
	}{
		// Not the API envelope: errBadResponse.
		{name: "empty body", body: "", wantBad: true},
		{name: "html", body: "<html>" + outputCanary + "</html>", wantBad: true},
		{name: "array", body: `[` + choice + `]`, wantBad: true},
		{name: "truncated", body: `{"choices":[` + choice, wantBad: true},
		{name: "choices not an array", body: `{"choices":{"0":` + choice + `}}`, wantBad: true},
		{name: "message not an object", body: `{"choices":[{"message":"` + outputCanary + `"}]}`, wantBad: true},
		{name: "finish reason not a string", body: `{"choices":[{"finish_reason":1,"message":{"content":` + verdict + `}}]}`, wantBad: true},
		{name: "null", body: `null`, wantBad: true},
		{name: "null with whitespace", body: " \t\r\nnull\n ", wantBad: true},
		{name: "empty array", body: `[]`, wantBad: true},
		{name: "string", body: `"x"`, wantBad: true},
		{name: "number", body: `1`, wantBad: true},
		{name: "whitespace only", body: " \n", wantBad: true},
		// A JSON object, but no envelope: FR-17 keeps MOAT-LLM-002 for a model
		// answer, so these must not look like one.
		{name: "empty object", body: `{}`, wantBad: true},
		{name: "null choices", body: `{"choices":null}`, wantBad: true},
		{name: "other keys only", body: `{"id":"x","object":"chat.completion"}`, wantBad: true},
		{name: "error object", body: `{"error":{"message":"` + outputCanary + `","type":"server_error"}}`, wantBad: true},
		{name: "error string", body: `{"error":"` + outputCanary + `"}`, wantBad: true},
		{name: "error with choices", body: `{"error":{"message":"x"},"choices":[` + choice + `]}`, wantBad: true},
		{name: "error with empty choices", body: `{"error":{},"choices":[]}`, wantBad: true},

		// The API answered, but the output is no verdict: ErrInvalidOutput.
		{name: "no choices", body: `{"choices":[]}`},
		{name: "two choices", body: `{"choices":[` + choice + `,` + choice + `]}`},
		{name: "refusal", body: openAIChoiceReply(`"stop"`, `{"content":null,"refusal":"`+outputCanary+`"}`)},
		{name: "refusal with content", body: openAIChoiceReply(`"stop"`, `{"content":`+verdict+`,"refusal":"no"}`)},
		{name: "refusal not a string", body: openAIChoiceReply(`"stop"`, `{"content":`+verdict+`,"refusal":{}}`)},
		{name: "cut at the token limit", body: openAIChoiceReply(`"length"`, `{"content":`+verdict+`}`)},
		{name: "content filter", body: openAIChoiceReply(`"content_filter"`, `{"content":`+verdict+`}`)},
		{name: "null content", body: openAIChoiceReply(`"stop"`, `{"content":null}`)},
		{name: "no content", body: openAIChoiceReply(`"stop"`, `{"role":"assistant"}`)},
		{name: "array content", body: openAIChoiceReply(`"stop"`, `{"content":[{"type":"text","text":`+verdict+`}]}`)},
		{name: "object content", body: openAIChoiceReply(`"stop"`, `{"content":{"risk":"none","category":"other"}}`)},
		{name: "number content", body: openAIChoiceReply(`"stop"`, `{"content":1}`)},
		{name: "empty content", body: openAIChoiceReply(`"stop"`, `{"content":""}`)},
		{name: "prose content", body: openAIContentReply("The risk is none. " + outputCanary)},
		{name: "text after the verdict", body: openAIContentReply(`{"risk":"none","category":"other"} ` + outputCanary)},
		{name: "critical risk", body: openAIContentReply(`{"risk":"critical","category":"other"}`)},
		{name: "unknown category", body: openAIContentReply(`{"risk":"low","category":"` + outputCanary + `"}`)},
		{name: "extra key", body: openAIContentReply(`{"risk":"low","category":"other","why":"` + outputCanary + `"}`)},
		{name: "duplicate key", body: openAIContentReply(`{"risk":"high","category":"other","risk":"none"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v, err := openAIAPI{}.parseResponse([]byte(tt.body))
			checkParseError(t, v, err, tt.wantBad)
		})
	}
}

// TestOpenAIClassifyOutputErrors checks the same mapping through a real
// request, and that the error text holds no output or URL.
func TestOpenAIClassifyOutputErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		wantBad bool
	}{
		{name: "html", body: "<html>" + outputCanary + "</html>", wantBad: true},
		{name: "error with HTTP 200", body: `{"error":{"message":"` + outputCanary + `"}}`, wantBad: true},
		{name: "refusal", body: openAIChoiceReply(`"stop"`, `{"content":null,"refusal":"`+outputCanary+`"}`)},
		{name: "bad verdict", body: openAIContentReply(`{"risk":"low","category":"` + outputCanary + `"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, reply(http.StatusOK, tt.body))
			c := newTestClient(t, ProviderOpenAI, srv.URL)
			v, err := c.Classify(t.Context(), Input{ToolName: "t", Description: "d"})
			checkParseError(t, v, err, tt.wantBad)
			assertNoLeak(t, err, srv.URL)
		})
	}
}

// FuzzOpenAIParseResponse checks that any body gives a valid verdict or one
// of the two documented error classes, and never panics.
func FuzzOpenAIParseResponse(f *testing.F) {
	f.Add([]byte(openAIReply(RiskMedium, CategoryCredentialAccess)))
	f.Add([]byte(`{"choices":[{"message":{"content":null,"refusal":"no"}}]}`))
	f.Add([]byte(`{"choices":[{"finish_reason":"length","message":{"content":"{"}}]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`<html>`))
	f.Fuzz(func(t *testing.T, body []byte) {
		v, err := openAIAPI{}.parseResponse(body)
		checkFuzzResult(t, v, err)
	})
}
