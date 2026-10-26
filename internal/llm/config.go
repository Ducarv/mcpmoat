package llm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// Provider names an LLM API that the client can call.
type Provider string

// The supported providers.
const (
	// ProviderAnthropic is the Anthropic Messages API.
	ProviderAnthropic Provider = "anthropic"
	// ProviderOpenAI is the OpenAI Chat Completions API, or a server that
	// speaks the same API.
	ProviderOpenAI Provider = "openai"
)

// KeyEnv is the environment variable that holds the API key. It is the only
// place the key comes from (FR-17).
const KeyEnv = "MCPMOAT_LLM_API_KEY"

// Default base URLs. The client of each provider adds the API path to the
// base URL.
const (
	// DefaultAnthropicBaseURL is the base URL of the Anthropic API.
	DefaultAnthropicBaseURL = "https://api.anthropic.com"
	// DefaultOpenAIBaseURL is the base URL of the OpenAI API. It includes
	// the "/v1" path.
	DefaultOpenAIBaseURL = "https://api.openai.com/v1"
)

// DefaultAnthropicModel is the model that the Anthropic provider uses when
// Config.Model is empty. The OpenAI provider has no default model.
//
// Check this model ID against the Anthropic model list before each release.
const DefaultAnthropicModel = "claude-haiku-5-5"

// Limits on config values.
const (
	// MaxKeyBytes is the longest API key that ValidKey accepts.
	MaxKeyBytes = 4096
	// MaxModelBytes is the longest model name that Config.Validate accepts.
	MaxModelBytes = 256
	// MaxBaseURLBytes is the longest base URL that ValidateBaseURL accepts.
	MaxBaseURLBytes = 2048
)

// Errors of the config checks. Each error that this file returns wraps one
// of them. The error text is fixed: it never holds the key, and it never
// holds the base URL or the model name.
var (
	// ErrUnknownProvider means that the provider name is not supported.
	ErrUnknownProvider = errors.New("unknown LLM provider")
	// ErrMissingKey means that the API key is empty. Its text names KeyEnv.
	ErrMissingKey = errors.New(KeyEnv + " is not set")
	// ErrInvalidKey means that the API key has a character that cannot go
	// in an HTTP header, or is too long.
	ErrInvalidKey = errors.New("invalid " + KeyEnv)
	// ErrInvalidBaseURL means that the base URL is not allowed.
	ErrInvalidBaseURL = errors.New("invalid LLM base URL")
	// ErrInvalidModel means that the model name is empty, too long or has a
	// character that is not allowed.
	ErrInvalidModel = errors.New("invalid LLM model name")
)

// ParseProvider returns the Provider for name. name must be "anthropic" or
// "openai", in lower case. Another value gives an error that wraps
// ErrUnknownProvider. The error does not hold name.
func ParseProvider(name string) (Provider, error) {
	p := Provider(name)
	if !p.Valid() {
		return "", unknownProviderError()
	}
	return p, nil
}

// Valid reports whether p is a supported provider.
func (p Provider) Valid() bool {
	return p == ProviderAnthropic || p == ProviderOpenAI
}

// unknownProviderError returns the error for a provider that is not
// supported. It wraps ErrUnknownProvider, names the supported providers and
// never holds the name that was given.
func unknownProviderError() error {
	return fmt.Errorf("%w: use %q or %q", ErrUnknownProvider, ProviderAnthropic, ProviderOpenAI)
}

// DefaultBaseURL returns the base URL of p, or "" for an unknown provider.
func (p Provider) DefaultBaseURL() string {
	switch p {
	case ProviderAnthropic:
		return DefaultAnthropicBaseURL
	case ProviderOpenAI:
		return DefaultOpenAIBaseURL
	default:
		return ""
	}
}

// DefaultModel returns the default model of p. It returns "" for
// ProviderOpenAI, which has no default model, and for an unknown provider.
func (p Provider) DefaultModel() string {
	if p == ProviderAnthropic {
		return DefaultAnthropicModel
	}
	return ""
}

// Config holds the settings of an LLM client. New takes a Config and calls
// Resolve, which fills in the defaults and checks every field.
//
// Config is safe to print: APIKey is a discover.Secret and prints as a mask.
type Config struct {
	// Provider is the API to call.
	Provider Provider
	// Model is the model name. Empty means the default of the provider
	// (Provider.DefaultModel). ProviderOpenAI has no default, so the model
	// is required there.
	Model string
	// BaseURL is the base URL of the API. Empty means the default of the
	// provider (Provider.DefaultBaseURL). See ValidateBaseURL for the
	// rules.
	BaseURL string
	// APIKey is the API key from KeyEnv. Call APIKey.Reveal only where the
	// client sets the auth header. See ValidKey for the rules.
	APIKey discover.Secret
	// Dial, when it is not nil, opens every network connection of the
	// client in place of the default dialer. Tests use it to see or block
	// each connection (NFR-01). Nil means the default dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Resolve returns a copy of c with the defaults filled in, and checks it with
// Validate. An empty Model becomes Provider.DefaultModel and an empty BaseURL
// becomes Provider.DefaultBaseURL. Resolve removes a final "/" from BaseURL,
// so the client can add a path that starts with "/". An unknown provider has
// no defaults, and Validate refuses it.
func (c Config) Resolve() (Config, error) {
	if c.Model == "" {
		c.Model = c.Provider.DefaultModel()
	}
	if c.BaseURL == "" {
		c.BaseURL = c.Provider.DefaultBaseURL()
	}
	c.BaseURL = strings.TrimSuffix(c.BaseURL, "/")
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks c as it is. It does not fill in defaults, so an empty Model
// or BaseURL is an error: call Resolve to fill them in first. It checks the
// provider, the model name (see validModel), the base URL (ValidateBaseURL)
// and the key (ValidKey). Dial can be nil.
func (c Config) Validate() error {
	if !c.Provider.Valid() {
		return unknownProviderError()
	}
	if err := validModel(c.Model); err != nil {
		return err
	}
	if err := ValidateBaseURL(c.BaseURL); err != nil {
		return err
	}
	return ValidKey(c.APIKey.Reveal())
}

// validModel checks a model name. The name goes into the JSON request body,
// so the check is only a sanity check: 1 to MaxModelBytes bytes of visible
// ASCII (no space). Real model names such as "gpt-4o-mini",
// "claude-haiku-5-5" or "llama3:8b" pass.
func validModel(model string) error {
	if model == "" {
		return fmt.Errorf("%w: the model name is empty (set it for this provider)", ErrInvalidModel)
	}
	if len(model) > MaxModelBytes {
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidModel, MaxModelBytes)
	}
	if !visibleASCII(model) {
		return fmt.Errorf("%w: only visible ASCII characters are allowed", ErrInvalidModel)
	}
	return nil
}

// ValidateBaseURL checks the base URL of an LLM API. The rules are:
//
//   - at most MaxBaseURLBytes bytes, and url.Parse accepts it;
//   - an absolute URL with a host ("https://host" or "https://host/path");
//   - scheme https, or scheme http only when the host is a loopback host for
//     discover.IsLoopbackHost (a local model server), so the key never
//     crosses a network in clear text;
//   - no userinfo ("user:pass@"), no query ("?") and no fragment ("#").
//
// The error wraps ErrInvalidBaseURL and has fixed text. It never holds raw,
// because raw can hold credentials, and it does not wrap the url.Parse error
// for the same reason.
func ValidateBaseURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("%w: empty", ErrInvalidBaseURL)
	}
	if len(raw) > MaxBaseURLBytes {
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidBaseURL, MaxBaseURLBytes)
	}
	// A '?' or '#' can only start a query or a fragment. Check the raw text,
	// so an empty query ("https://h/?") or fragment ("https://h/#") is
	// refused too.
	if strings.ContainsAny(raw, "?#") {
		return fmt.Errorf("%w: a query or fragment is not allowed", ErrInvalidBaseURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: not a valid URL", ErrInvalidBaseURL)
	}
	if u.User != nil {
		return fmt.Errorf("%w: user info is not allowed", ErrInvalidBaseURL)
	}
	if u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%w: the URL must have a host", ErrInvalidBaseURL)
	}
	// url.Parse gives the scheme in lower case.
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if discover.IsLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%w: http is allowed only for a loopback host, use https", ErrInvalidBaseURL)
	default:
		return fmt.Errorf("%w: the scheme must be https", ErrInvalidBaseURL)
	}
}

// ValidKey checks an API key before the client puts it in an HTTP header.
// An empty key gives an error that wraps ErrMissingKey. A key longer than
// MaxKeyBytes, or with a byte that is not visible ASCII (a control character
// such as CR, LF, tab or DEL, a space, or a non-ASCII byte), gives an error
// that wraps ErrInvalidKey. Real API keys are visible ASCII.
//
// The error text is fixed and never holds the key or a part of it.
func ValidKey(key string) error {
	if key == "" {
		return ErrMissingKey
	}
	if len(key) > MaxKeyBytes {
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidKey, MaxKeyBytes)
	}
	if !visibleASCII(key) {
		return fmt.Errorf("%w: only visible ASCII characters are allowed (no spaces, tabs or line breaks)", ErrInvalidKey)
	}
	return nil
}

// visibleASCII reports whether every byte of s is a visible ASCII character
// (0x21 to 0x7E). It is false for a space, a control character, DEL and any
// non-ASCII byte.
func visibleASCII(s string) bool {
	for i := range len(s) {
		if b := s[i]; b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}
