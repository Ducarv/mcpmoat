package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// canary is a distinctive text in untrusted or secret test input. No error
// and no printed value may contain it.
const canary = "ZQXCANARYQXZ"

func TestParseProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    Provider
		wantErr bool
	}{
		{name: "anthropic", input: "anthropic", want: ProviderAnthropic},
		{name: "openai", input: "openai", want: ProviderOpenAI},
		{name: "empty", input: "", wantErr: true},
		{name: "upper case", input: "Anthropic", wantErr: true},
		{name: "all upper case", input: "OPENAI", wantErr: true},
		{name: "space around", input: " openai", wantErr: true},
		{name: "unknown", input: canary, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseProvider(tt.input)
			if tt.wantErr {
				if !errors.Is(err, ErrUnknownProvider) {
					t.Fatalf("ParseProvider(%q) error = %v, want ErrUnknownProvider", tt.input, err)
				}
				if got != "" {
					t.Errorf("ParseProvider(%q) = %q, want empty on error", tt.input, got)
				}
				if tt.input != "" && strings.Contains(err.Error(), tt.input) {
					t.Errorf("ParseProvider(%q) error %q holds the input", tt.input, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ParseProvider(%q) = %q, %v; want %q, nil", tt.input, got, err, tt.want)
			}
			if !got.Valid() {
				t.Errorf("%q.Valid() = false, want true", got)
			}
		})
	}
}

func TestProviderDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		provider  Provider
		wantURL   string
		wantModel string
	}{
		{provider: ProviderAnthropic, wantURL: DefaultAnthropicBaseURL, wantModel: DefaultAnthropicModel},
		{provider: ProviderOpenAI, wantURL: DefaultOpenAIBaseURL, wantModel: ""}, // no default model
		{provider: "", wantURL: "", wantModel: ""},
		{provider: "other", wantURL: "", wantModel: ""},
	}
	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			t.Parallel()
			if got := tt.provider.DefaultBaseURL(); got != tt.wantURL {
				t.Errorf("%q.DefaultBaseURL() = %q, want %q", tt.provider, got, tt.wantURL)
			}
			if got := tt.provider.DefaultModel(); got != tt.wantModel {
				t.Errorf("%q.DefaultModel() = %q, want %q", tt.provider, got, tt.wantModel)
			}
		})
	}

	// The default base URLs must pass the base URL check themselves.
	for _, u := range []string{DefaultAnthropicBaseURL, DefaultOpenAIBaseURL} {
		if err := ValidateBaseURL(u); err != nil {
			t.Errorf("ValidateBaseURL(%q) = %v, want nil", u, err)
		}
	}
}

func TestConfigResolve(t *testing.T) {
	t.Parallel()

	key := discover.NewSecret("sk-test-key")
	tests := []struct {
		name      string
		cfg       Config
		wantModel string
		wantURL   string
		wantErr   error
	}{
		{
			name:      "anthropic defaults",
			cfg:       Config{Provider: ProviderAnthropic, APIKey: key},
			wantModel: DefaultAnthropicModel,
			wantURL:   DefaultAnthropicBaseURL,
		},
		{
			name:      "openai with model gets default URL",
			cfg:       Config{Provider: ProviderOpenAI, Model: "gpt-4o-mini", APIKey: key},
			wantModel: "gpt-4o-mini",
			wantURL:   DefaultOpenAIBaseURL,
		},
		{
			name:      "trailing slash trimmed",
			cfg:       Config{Provider: ProviderAnthropic, BaseURL: "https://llm.example.com/", APIKey: key},
			wantModel: DefaultAnthropicModel,
			wantURL:   "https://llm.example.com",
		},
		{
			name:      "local model server kept",
			cfg:       Config{Provider: ProviderOpenAI, Model: "llama3:8b", BaseURL: "http://localhost:11434/v1/", APIKey: key},
			wantModel: "llama3:8b",
			wantURL:   "http://localhost:11434/v1",
		},
		{
			name:      "all trailing slashes trimmed",
			cfg:       Config{Provider: ProviderOpenAI, Model: "gpt-4o-mini", BaseURL: "https://h/v1//", APIKey: key},
			wantModel: "gpt-4o-mini",
			wantURL:   "https://h/v1",
		},
		{
			name:      "many slashes after the host",
			cfg:       Config{Provider: ProviderAnthropic, BaseURL: "https://llm.example.com///", APIKey: key},
			wantModel: DefaultAnthropicModel,
			wantURL:   "https://llm.example.com",
		},
		{
			name:    "openai without model",
			cfg:     Config{Provider: ProviderOpenAI, APIKey: key},
			wantErr: ErrInvalidModel,
		},
		{
			name:    "model with space",
			cfg:     Config{Provider: ProviderAnthropic, Model: "a b", APIKey: key},
			wantErr: ErrInvalidModel,
		},
		{
			name:    "model too long",
			cfg:     Config{Provider: ProviderAnthropic, Model: strings.Repeat("m", MaxModelBytes+1), APIKey: key},
			wantErr: ErrInvalidModel,
		},
		{
			name:    "empty provider",
			cfg:     Config{APIKey: key},
			wantErr: ErrUnknownProvider,
		},
		{
			name:    "unknown provider",
			cfg:     Config{Provider: "Anthropic", APIKey: key},
			wantErr: ErrUnknownProvider,
		},
		{
			name:    "http to a remote host",
			cfg:     Config{Provider: ProviderAnthropic, BaseURL: "http://llm.example.com", APIKey: key},
			wantErr: ErrInvalidBaseURL,
		},
		{
			name:    "base URL only a slash",
			cfg:     Config{Provider: ProviderAnthropic, BaseURL: "/", APIKey: key},
			wantErr: ErrInvalidBaseURL,
		},
		{
			name:    "base URL only slashes",
			cfg:     Config{Provider: ProviderAnthropic, BaseURL: "///", APIKey: key},
			wantErr: ErrInvalidBaseURL,
		},
		{
			// After the trim this is "https:", which has no host.
			name:    "empty host with slashes",
			cfg:     Config{Provider: ProviderAnthropic, BaseURL: "https:///", APIKey: key},
			wantErr: ErrInvalidBaseURL,
		},
		{
			name:    "no host with many slashes",
			cfg:     Config{Provider: ProviderOpenAI, Model: "m", BaseURL: "https://////", APIKey: key},
			wantErr: ErrInvalidBaseURL,
		},
		{
			name:    "missing key",
			cfg:     Config{Provider: ProviderAnthropic},
			wantErr: ErrMissingKey,
		},
		{
			name:    "bad key",
			cfg:     Config{Provider: ProviderAnthropic, APIKey: discover.NewSecret("sk\nx")},
			wantErr: ErrInvalidKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.cfg.Resolve()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Resolve() error = %v, want %v", err, tt.wantErr)
				}
				if got.Provider != "" || got.BaseURL != "" || got.Model != "" {
					t.Errorf("Resolve() = %+v, want zero Config on error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve() error = %v, want nil", err)
			}
			if got.Model != tt.wantModel || got.BaseURL != tt.wantURL {
				t.Errorf("Resolve() model, URL = %q, %q; want %q, %q", got.Model, got.BaseURL, tt.wantModel, tt.wantURL)
			}
			if got.APIKey.Reveal() != tt.cfg.APIKey.Reveal() {
				t.Error("Resolve() changed the API key")
			}
			if err := got.Validate(); err != nil {
				t.Errorf("Validate() of a resolved Config = %v, want nil", err)
			}
		})
	}
}

func TestConfigValidateNeedsDefaults(t *testing.T) {
	t.Parallel()

	// Validate does not fill in defaults, so an empty model or base URL fails.
	cfg := Config{Provider: ProviderAnthropic, APIKey: discover.NewSecret("k")}
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidModel) {
		t.Errorf("Validate() with empty model = %v, want ErrInvalidModel", err)
	}
	cfg.Model = DefaultAnthropicModel
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidBaseURL) {
		t.Errorf("Validate() with empty base URL = %v, want ErrInvalidBaseURL", err)
	}
}

func TestValidateBaseURL(t *testing.T) {
	t.Parallel()

	// exact2048 is a valid https URL of exactly MaxBaseURLBytes bytes.
	exact2048 := "https://h/" + strings.Repeat("a", MaxBaseURLBytes-len("https://h/"))

	tests := []struct {
		name string
		raw  string
		ok   bool
	}{
		{name: "https", raw: "https://api.example.com", ok: true},
		{name: "https with path", raw: "https://api.example.com/v1", ok: true},
		{name: "https with port", raw: "https://api.example.com:8443/v1", ok: true},
		{name: "upper-case scheme", raw: "HTTPS://api.example.com", ok: true},
		{name: "http 127.0.0.1 with port", raw: "http://127.0.0.1:8080", ok: true},
		{name: "http 127.0.0.2", raw: "http://127.0.0.2/v1", ok: true},
		{name: "http localhost", raw: "http://localhost", ok: true},
		{name: "http localhost with port", raw: "http://localhost:11434/v1", ok: true},
		{name: "http ipv6 loopback with port", raw: "http://[::1]:8080", ok: true},
		{name: "http ipv6 loopback with zone", raw: "http://[::1%25lo0]:8080", ok: true},
		{name: "exactly max length", raw: exact2048, ok: true},

		{name: "empty", raw: ""},
		{name: "http remote", raw: "http://example.com/" + canary},
		{name: "http private address", raw: "http://10.0.0.1/" + canary},
		{name: "http localhost suffix", raw: "http://localhost.example.com/" + canary},
		// Only "localhost" in lower case, without a final dot, is loopback.
		{name: "http upper-case localhost", raw: "http://LOCALHOST:11434"},
		{name: "http localhost with final dot", raw: "http://localhost.:11434"},
		{name: "other scheme", raw: "ftp://api.example.com/" + canary},
		{name: "ws on loopback", raw: "ws://localhost/" + canary},
		{name: "file", raw: "file:///etc/" + canary},
		{name: "userinfo with password", raw: "https://user:" + canary + "@api.example.com"},
		{name: "userinfo user only", raw: "https://" + canary + "@api.example.com"},
		{name: "userinfo on loopback", raw: "http://user:" + canary + "@localhost"},
		{name: "query", raw: "https://api.example.com/v1?key=" + canary},
		{name: "empty query", raw: "https://api.example.com/" + canary + "?"},
		{name: "fragment", raw: "https://api.example.com/v1#" + canary},
		{name: "empty fragment", raw: "https://api.example.com/" + canary + "#"},
		{name: "opaque", raw: "https:" + canary + ".example.com"},
		{name: "mailto", raw: "mailto:" + canary + "@example.com"},
		{name: "no host", raw: "https://"},
		{name: "scheme only", raw: "https:"},
		{name: "empty host with path", raw: "https:///" + canary},
		{name: "port only", raw: "https://:443/" + canary},
		{name: "relative path", raw: "/v1/" + canary},
		{name: "no scheme", raw: canary + ".example.com"},
		{name: "parse error bad escape", raw: "https://api.example.com/%zz" + canary},
		{name: "parse error bracket", raw: "https://[::1/" + canary},
		{name: "parse error control char", raw: "https://api.example.com/" + canary + "\n"},
		{name: "too long", raw: exact2048 + canary},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateBaseURL(tt.raw)
			if tt.ok {
				if err != nil {
					t.Fatalf("ValidateBaseURL(%q) = %v, want nil", tt.raw, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidBaseURL) {
				t.Fatalf("ValidateBaseURL(%q) = %v, want ErrInvalidBaseURL", tt.raw, err)
			}
			// The URL can hold credentials, so the error never quotes it.
			if strings.Contains(err.Error(), canary) || (tt.raw != "" && strings.Contains(err.Error(), tt.raw)) {
				t.Errorf("ValidateBaseURL error %q holds the URL", err)
			}
			// The url.Parse error quotes the URL, so it must not be wrapped.
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				t.Errorf("ValidateBaseURL error %v wraps a *url.Error", err)
			}
		})
	}
}

func TestValidateKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     string
		wantErr error
	}{
		{name: "normal", key: "sk-ant-api03-abc_DEF.123~xyz"},
		{name: "all visible ASCII", key: "!\"#$%&'()*+,-./0123456789:;<=>?@AZ[\\]^_`az{|}~"},
		{name: "exactly max length", key: strings.Repeat("k", MaxKeyBytes)},
		{name: "empty", key: "", wantErr: ErrMissingKey},
		{name: "space", key: canary + " x", wantErr: ErrInvalidKey},
		{name: "leading space", key: " " + canary, wantErr: ErrInvalidKey},
		{name: "tab", key: canary + "\tx", wantErr: ErrInvalidKey},
		{name: "CR", key: canary + "\r", wantErr: ErrInvalidKey},
		{name: "LF", key: canary + "\n", wantErr: ErrInvalidKey},
		{name: "CRLF header injection", key: canary + "\r\nX-Evil: 1", wantErr: ErrInvalidKey},
		{name: "DEL", key: canary + "\x7f", wantErr: ErrInvalidKey},
		{name: "NUL", key: canary + "\x00", wantErr: ErrInvalidKey},
		{name: "non-ASCII", key: canary + "é", wantErr: ErrInvalidKey},
		{name: "invalid UTF-8", key: canary + "\xff", wantErr: ErrInvalidKey},
		{name: "too long", key: canary + strings.Repeat("k", MaxKeyBytes), wantErr: ErrInvalidKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateKey(tt.key)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateKey() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateKey() = %v, want %v", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), KeyEnv) {
				t.Errorf("ValidateKey() error %q does not name %s", err, KeyEnv)
			}
			if strings.Contains(err.Error(), canary) {
				t.Errorf("ValidateKey() error %q holds the key", err)
			}
		})
	}
}

func TestConfigMasksAPIKey(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Provider: ProviderAnthropic,
		Model:    DefaultAnthropicModel,
		BaseURL:  DefaultAnthropicBaseURL,
		APIKey:   discover.NewSecret(canary),
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		for _, value := range []any{cfg, &cfg} {
			out := fmt.Sprintf(verb, value)
			if strings.Contains(out, canary) {
				t.Errorf("Sprintf(%q, %T) = %q, holds the key", verb, value, out)
			}
			if !strings.Contains(out, discover.Mask) {
				t.Errorf("Sprintf(%q, %T) = %q, want the mask %q", verb, value, out, discover.Mask)
			}
		}
	}

	// encoding/json refuses Config as a whole, because the Dial field has a
	// func type (even when it is nil). The error must not hold the key.
	// marshalAny hides the static type from staticcheck (SA1026), which
	// flags this call because it knows that it fails: that failure is what
	// the test checks.
	out, err := marshalAny(cfg)
	var typeErr *json.UnsupportedTypeError
	if !errors.As(err, &typeErr) {
		t.Errorf("json.Marshal(Config) = %s, %v; want an UnsupportedTypeError", out, err)
	}
	if strings.Contains(string(out), canary) || (err != nil && strings.Contains(err.Error(), canary)) {
		t.Errorf("json.Marshal(Config) leaks the key: %s, %v", out, err)
	}

	// The key field alone, and a struct that holds it, encode as the mask.
	out, err = json.Marshal(struct {
		Provider Provider
		APIKey   discover.Secret
	}{cfg.Provider, cfg.APIKey})
	if err != nil {
		t.Fatalf("json.Marshal(key struct) error = %v", err)
	}
	if want := `{"Provider":"anthropic","APIKey":"` + discover.Mask + `"}`; string(out) != want {
		t.Errorf("json.Marshal(key struct) = %s, want %s", out, want)
	}
}

// marshalAny is json.Marshal with an argument of type any. A test uses it to
// check that json.Marshal fails on a type that staticcheck knows it cannot
// encode.
func marshalAny(v any) ([]byte, error) {
	return json.Marshal(v)
}
