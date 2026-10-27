package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/llm"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// This file holds the setup of the LLM step of scan (--llm, FR-17): the LLM
// flags, their checks, the warning on stderr and the LLM client.

// noLLMClientText is the text after the prefix of the error line that scan
// prints when it has no LLM client. This is a bug in mcpmoat, not a user
// error. It is fixed text.
const noLLMClientText = "internal error: no LLM client"

// newLLMClassifier is the real value of cli.newClassifier: it wraps llm.New.
// It sends no request.
func newLLMClassifier(cfg llm.Config) (toolClassifier, error) {
	client, err := llm.New(cfg)
	if err != nil {
		// Return a plain nil. A nil *llm.Client in the interface would not
		// compare equal to nil.
		return nil, err
	}
	return client, nil
}

// The names of the LLM flags of scan (FR-17), without the dashes.
const (
	flagLLM         = "llm"
	flagLLMProvider = "llm-provider"
	flagLLMModel    = "llm-model"
	flagLLMBaseURL  = "llm-base-url"
)

// addLLMFlags adds the four LLM flags of scan (FR-17) to fs. They store
// their values in f. --llm is off by default. The other three refuse an
// empty value (see onceStringFlag), so an empty value in f means that the
// flag was not given. checkLLMFlags checks them all.
//
// The base URL can hold a user:password, so the errors of its flag never
// hold the value. addLLMFlags returns that flag: when Parse fails, the
// caller prints its problem in place of the Parse error (see
// secretStringFlag).
func addLLMFlags(fs *flag.FlagSet, f *llmFlags) *secretFlag {
	fs.BoolVar(&f.on, flagLLM, false, "")
	onceStringFlag(fs, flagLLMProvider, "a provider name", &f.provider)
	onceStringFlag(fs, flagLLMModel, "a model name", &f.model)
	return secretStringFlag(fs, flagLLMBaseURL, "a URL", &f.baseURL)
}

// setupLLM checks the LLM flags (see checkLLMFlags) and, with --llm, prints
// the warning on stderr and builds the classifier (see buildClassifier).
// runScan calls it before it reads a config file. The warning comes before
// the client is built and before any request, also with --json (FR-17).
//
// It returns a nil classifier and true without --llm: then it reads no API
// key and builds no client. On a problem it has printed the error and
// returns false, and scan exits with 2.
func (c *cli) setupLLM(f llmFlags, noConnect bool) (toolClassifier, bool) {
	setup, ok := c.checkLLMFlags(f, noConnect)
	if !ok || setup == nil {
		return nil, ok
	}
	c.scanWarnf("%s", setup.warningText())
	return c.buildClassifier(setup.cfg)
}

// buildClassifier gets the classifier for cfg from c.newClassifier. This is
// the only place that calls it, and runScan calls it only with --llm. On an
// error it prints one line on stderr and returns false. The errors of llm.New
// have fixed text; termsafe.Quote still escapes the text, because a test can
// set any factory.
func (c *cli) buildClassifier(cfg llm.Config) (toolClassifier, bool) {
	if c.newClassifier == nil {
		c.cmdPrintf("scan", "%s", noLLMClientText)
		return nil, false
	}
	cl, err := c.newClassifier(cfg)
	if err != nil {
		c.cmdErr("scan", "cannot set up the LLM client", err)
		return nil, false
	}
	if cl == nil {
		c.cmdPrintf("scan", "%s", noLLMClientText)
		return nil, false
	}
	return cl, true
}

// closeClassifier closes the idle connections of cl, when cl has such a
// method (*llm.Client has one). A fake from a test usually has none. cl can
// be nil (no --llm): the type assertion is then false, and it does nothing.
func closeClassifier(cl toolClassifier) {
	if closer, ok := cl.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// llmFlags holds the values of the LLM flags as the user gave them. An empty
// string means that the flag was not given.
type llmFlags struct {
	on       bool   // --llm
	provider string // --llm-provider
	model    string // --llm-model
	baseURL  string // --llm-base-url
}

// strayLLMFlag returns the name of the first LLM flag in f that needs --llm,
// for example "--llm-model", or "" when f has none.
func strayLLMFlag(f llmFlags) string {
	for _, given := range []struct{ name, value string }{
		{"--" + flagLLMProvider, f.provider},
		{"--" + flagLLMModel, f.model},
		{"--" + flagLLMBaseURL, f.baseURL},
	} {
		if given.value != "" {
			return given.name
		}
	}
	return ""
}

// llmSetup is the checked LLM config of one scan.
type llmSetup struct {
	// cfg is the resolved config, with the defaults filled in and the API key
	// from the environment. cfg.APIKey prints as a mask.
	cfg llm.Config
	// host is the host of cfg.BaseURL, with the port if it has one. The
	// warning names it.
	host string
}

// newLLMSetup returns the llmSetup of cfg, a config that Resolve returned.
// Resolve checked cfg.BaseURL with llm.ValidateBaseURL, so the URL parses
// and has a host: the error is only a guard. It is llm.ErrInvalidBaseURL
// and never the url.Parse error, because that text quotes the URL, which
// can hold a secret.
func newLLMSetup(cfg llm.Config) (*llmSetup, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, llm.ErrInvalidBaseURL
	}
	return &llmSetup{cfg: cfg, host: u.Host}, nil
}

// warningText returns the text of the warning that scan prints on stderr
// before it builds the client and before any request (FR-17). The provider
// name is one of the fixed llm.Provider values. The host comes from the user,
// so termsafe.Quote escapes it.
func (s *llmSetup) warningText() string {
	return fmt.Sprintf("--llm sends the name and description of every tool to the LLM provider %s at %s. This data leaves your machine.",
		s.cfg.Provider, termsafe.Quote(s.host))
}

// checkLLMFlags checks the LLM flags and returns the LLM config of the scan.
// It returns nil and true when --llm is not set: then it reads no API key.
// On a problem it prints one usage error on stderr and returns false, and
// scan exits with 2.
//
// The API key comes only from the environment variable llm.KeyEnv, read
// through c.getenv. No message holds the key: the texts come from the llm
// errors, which are fixed and never hold the key, the model name or the URL.
func (c *cli) checkLLMFlags(f llmFlags, noConnect bool) (*llmSetup, bool) {
	if !f.on {
		// An LLM flag without --llm would do nothing. Say so, or the user
		// could think that the scan used the LLM.
		if name := strayLLMFlag(f); name != "" {
			c.usageError("scan", "%s needs --llm", name)
			return nil, false
		}
		return nil, true
	}
	if noConnect {
		c.usageError("scan", "--llm cannot be used with --no-connect: the LLM needs a connection to each server to get its tools")
		return nil, false
	}

	name := f.provider
	if name == "" {
		name = string(llm.ProviderAnthropic)
	}
	provider, err := llm.ParseProvider(name)
	if err != nil {
		c.usageError("scan", "--llm-provider: %v", err)
		return nil, false
	}
	if f.model == "" && provider.DefaultModel() == "" {
		c.usageError("scan", "--llm-provider %s needs --llm-model", provider)
		return nil, false
	}
	if f.baseURL != "" {
		if err := llm.ValidateBaseURL(f.baseURL); err != nil {
			c.usageError("scan", "--llm-base-url: %v", err)
			return nil, false
		}
	}
	key := c.getenv(llm.KeyEnv)
	if err := llm.ValidateKey(key); err != nil {
		// The error text names llm.KeyEnv and never holds the key.
		c.usageError("scan", "--llm: %v", err)
		return nil, false
	}

	cfg, err := llm.Config{
		Provider: provider,
		Model:    f.model,
		BaseURL:  f.baseURL,
		APIKey:   discover.NewSecret(key),
	}.Resolve()
	if err != nil {
		if errors.Is(err, llm.ErrInvalidModel) {
			c.usageError("scan", "--llm-model: %v", err)
		} else {
			c.usageError("scan", "--llm: %v", err)
		}
		return nil, false
	}
	setup, err := newLLMSetup(cfg)
	if err != nil {
		c.usageError("scan", "--llm-base-url: %v", err)
		return nil, false
	}
	return setup, true
}
