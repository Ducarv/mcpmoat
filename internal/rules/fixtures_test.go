package rules_test

// Integration tests: the native checks against the fixtures of issue #57.
// The server fixtures are stdio programs under testdata/servers that make no
// network call. The config fixtures are Cursor files under testdata/configs.

import (
	"cmp"
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/discover/discovertest"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/rules"
)

const (
	fixtureTimeout = 10 * time.Second

	// Synthetic canaries of testdata/configs/dangerous. They must never
	// appear in a Finding.
	canaryHeader = "mcpmoat-canary-header-8Fk2Zs"
	canaryToken  = "ghp_mcpmoatcanaryZk3Qp8Vw2LxN7rTb5HcYd4M" //nolint:gosec // G101: synthetic canary of the test fixture, not a credential
	canaryHost   = "mcp.example.invalid"
)

// inspectFixture builds and runs the stdio fixture server name and returns
// the server with the tools that it lists. The project path is a new
// directory, so no server work directory goes below the user cache.
func inspectFixture(t *testing.T, name string) rules.ServerTools {
	t.Helper()
	srv := discover.Server{
		Name:        name,
		Transport:   discover.TransportStdio,
		Command:     inspecttest.Fixture(t, name),
		Scope:       discover.ScopeProject,
		ProjectPath: t.TempDir(),
	}
	ctx, cancel := context.WithTimeout(t.Context(), fixtureTimeout)
	t.Cleanup(cancel)
	res, err := inspect.New(inspect.SDKOptions{}).Inspect(ctx, srv)
	if err != nil {
		t.Fatalf("Inspect(%s) error = %v, want nil", name, err)
	}
	return rules.ServerTools{Server: srv, Tools: res.Tools}
}

// configServers reads the Cursor config of the fixture testdata/configs/<name>
// from a copy in a new home, and returns its servers in the order that
// ReadCursor gives them.
func configServers(t *testing.T, name string) []discover.Server {
	t.Helper()
	home, _ := discovertest.CopyFixture(t, filepath.Join("..", "..", "testdata", "configs", name))
	res := discover.ReadCursor(t.Context(), filepath.Join(home, ".cursor", "mcp.json"), discover.ScopeGlobal, "")
	if len(res.Errors) != 0 {
		t.Fatalf("ReadCursor() errors = %v, want none", res.Errors)
	}
	return res.Servers
}

// popularTyposquat builds the typosquat check from the built-in list.
func popularTyposquat(t *testing.T) *rules.Typosquat {
	t.Helper()
	return rules.NewTyposquat(rules.LoadPopular(t))
}

// findingKey is the comparable form of a Finding for the config tests.
type findingKey struct{ Server, RuleID, Field, Key, Related string }

// compareFindingKeys orders findingKey values by their fields.
func compareFindingKeys(a, b findingKey) int {
	return cmp.Or(
		cmp.Compare(a.Server, b.Server),
		cmp.Compare(a.RuleID, b.RuleID),
		cmp.Compare(a.Field, b.Field),
		cmp.Compare(a.Key, b.Key),
		cmp.Compare(a.Related, b.Related),
	)
}

// assertFindings compares findings with want, ignoring order.
func assertFindings(t *testing.T, what string, findings []rules.Finding, want []findingKey) {
	t.Helper()
	var have []findingKey
	for _, f := range findings {
		have = append(have, findingKey{f.Server, f.RuleID, f.Field, f.Key, f.Related})
	}
	want = slices.Clone(want)
	slices.SortFunc(have, compareFindingKeys)
	slices.SortFunc(want, compareFindingKeys)
	if !slices.Equal(have, want) {
		t.Errorf("%s findings =\n%+v\nwant\n%+v", what, have, want)
	}
}

func TestFixtureShadowing(t *testing.T) {
	t.Parallel()

	all := []rules.ServerTools{inspectFixture(t, "shadowing"), inspectFixture(t, "mailer")}
	want := []rules.Finding{{
		RuleID:  rules.RuleShadowing,
		Server:  "shadowing",
		Tool:    "add_numbers",
		Related: "mailer/send_email",
	}}

	findings := rules.CheckShadowing(all)
	if len(findings) != len(want) {
		t.Fatalf("CheckShadowing() = %+v, want exactly one finding %+v", findings, want)
	}
	// Message is fixed text; check that it is set, then compare the other
	// fields.
	if findings[0].Message == "" {
		t.Error("Finding.Message is empty, want a fixed text")
	}
	findings[0].Message = ""
	if !reflect.DeepEqual(findings, want) {
		t.Errorf("CheckShadowing() = %+v, want %+v", findings, want)
	}
}

func TestFixtureBenign(t *testing.T) {
	t.Parallel()

	benign := inspectFixture(t, "benign")
	mailer := inspectFixture(t, "mailer")

	t.Run("shadowing", func(t *testing.T) {
		t.Parallel()
		if f := rules.CheckShadowing([]rules.ServerTools{benign, mailer}); len(f) != 0 {
			t.Errorf("CheckShadowing(benign, mailer) = %+v, want none", f)
		}
	})
	t.Run("config", func(t *testing.T) {
		t.Parallel()
		if f := rules.CheckConfig(benign.Server); len(f) != 0 {
			t.Errorf("CheckConfig(benign) = %+v, want none", f)
		}
	})
	t.Run("typosquat", func(t *testing.T) {
		t.Parallel()
		if f := popularTyposquat(t).Check(benign.Server); len(f) != 0 {
			t.Errorf("Typosquat.Check(benign) = %+v, want none", f)
		}
	})
	t.Run("canned result", func(t *testing.T) {
		t.Parallel()
		canned := rules.ServerTools{
			Server: discover.Server{Name: "benign", Transport: discover.TransportStdio},
			Tools:  inspecttest.BenignResult().Tools,
		}
		if f := rules.CheckShadowing([]rules.ServerTools{canned, mailer}); len(f) != 0 {
			t.Errorf("CheckShadowing(canned benign, mailer) = %+v, want none", f)
		}
	})
}

// TestFixturePoisoned is a T1 smoke test: it checks that the fixture serves
// its payloads. It asserts no rule ID, because the T1 rules wait for issue
// #36 and issues #42 to #50.
func TestFixturePoisoned(t *testing.T) {
	t.Parallel()

	st := inspectFixture(t, "poisoned")

	var names []string
	byName := make(map[string]inspect.Tool)
	for _, tool := range st.Tools {
		names = append(names, tool.Name)
		byName[tool.Name] = tool
	}
	slices.Sort(names)
	wantNames := []string{"currency_convert", "daily_quote", "unit_convert", "weather_lookup"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("tool names = %q, want %q", names, wantNames)
	}

	if d := byName["daily_quote"].Description; !strings.Contains(d, "<IMPORTANT>") {
		t.Errorf("daily_quote description has no <IMPORTANT> marker")
	}
	d := byName["currency_convert"].Description
	for _, r := range []rune{0x200B, 0x202E, 0xE0041} {
		if !strings.ContainsRune(d, r) {
			t.Errorf("currency_convert description has no U+%04X", r)
		}
	}
	if d := byName["unit_convert"].Description; !strings.Contains(d, "SWdub3JlIHByZXZpb3Vz") {
		t.Errorf("unit_convert description has no base64 blob prefix")
	}
	if s := string(byName["weather_lookup"].InputSchema); !strings.Contains(s, "sidenote") {
		t.Errorf("weather_lookup InputSchema has no sidenote parameter")
	}

	if f := rules.CheckShadowing([]rules.ServerTools{st}); len(f) != 0 {
		t.Errorf("CheckShadowing(poisoned) = %+v, want none", f)
	}
}

func TestFixtureDangerousConfig(t *testing.T) {
	t.Parallel()

	servers := configServers(t, "dangerous")
	if len(servers) != 5 {
		t.Fatalf("ReadCursor() returned %d servers, want 5", len(servers))
	}
	ts := popularTyposquat(t)

	// Guard against a vacuous leak check: the canaries must be in the config.
	for _, s := range servers {
		if s.Name == "env-secret" && s.Env["GITHUB_TOKEN"].Reveal() != canaryToken {
			t.Fatal("fixture env-secret no longer holds the canary token; update the test")
		}
	}

	var all []rules.Finding
	for _, s := range servers {
		all = append(all, rules.CheckConfig(s)...)
		if f := ts.Check(s); len(f) != 0 {
			t.Errorf("Typosquat.Check(%s) = %+v, want none", s.Name, f)
		}
	}

	assertFindings(t, "CheckConfig", all, []findingKey{
		{"remote-plain", rules.RuleInsecureURL, rules.FieldURL, "", ""},
		{"remote-plain", rules.RulePlaintextSecret, rules.FieldHeaders, "X-Api-Key", ""},
		{"env-secret", rules.RulePlaintextSecret, rules.FieldEnv, "GITHUB_TOKEN", ""},
		{"env-secret", rules.RuleAutoInstall, rules.FieldArgs, "", ""},
		{"latest-pkg", rules.RuleUnpinnedPackage, rules.FieldArgs, "", "@example-corp/files-mcp"},
		{"latest-pkg", rules.RuleAutoInstall, rules.FieldArgs, "", ""},
		{"docker-untagged", rules.RuleUnpinnedPackage, rules.FieldArgs, "", "registry.invalid/example/mcp-server"},
	})

	// A finding names the place of a problem and never the content.
	for _, f := range all {
		rules.AssertFindingNoLeak(t, f, canaryHeader, canaryToken, canaryHost)
	}
}

func TestFixtureTyposquatConfig(t *testing.T) {
	t.Parallel()

	servers := configServers(t, "typosquat")
	if len(servers) != 3 {
		t.Fatalf("ReadCursor() returned %d servers, want 3", len(servers))
	}
	ts := popularTyposquat(t)

	var squat, config []rules.Finding
	for _, s := range servers {
		squat = append(squat, ts.Check(s)...)
		config = append(config, rules.CheckConfig(s)...)
	}

	assertFindings(t, "Typosquat.Check", squat, []findingKey{
		{"filesystem", rules.RuleTyposquat, rules.FieldArgs, "", "@modelcontextprotocol/server-filesystem"},
		{"mcp-server-fecth", rules.RuleTyposquat, rules.FieldName, "", "mcp-server-fetch"},
	})
	assertFindings(t, "CheckConfig", config, []findingKey{
		{"filesystem", rules.RuleAutoInstall, rules.FieldArgs, "", ""},
		{"memory", rules.RuleAutoInstall, rules.FieldArgs, "", ""},
	})
}

// compiledRule is a built-in rule with its match block compiled. It keeps the
// target, so a text is only checked against the rules of its own target.
type compiledRule struct {
	id     string
	target rules.Target
	m      *rules.Matcher
}

// compileBuiltin loads the built-in rules and compiles their match blocks with
// Match.Compile, the Compiler of the built-in case tests.
func compileBuiltin(t *testing.T) []compiledRule {
	t.Helper()
	rs, errs := rules.Builtin()
	if len(errs) != 0 {
		t.Fatalf("Builtin() errors = %v, want none", errs)
	}
	out := make([]compiledRule, 0, len(rs))
	for _, r := range rs {
		m, err := r.Match.Compile()
		if err != nil {
			t.Fatalf("%s: Match.Compile() error = %v, want nil", r.ID, err)
		}
		out = append(out, compiledRule{id: r.ID, target: r.Target, m: m})
	}
	return out
}

// builtinHits returns the sorted IDs of the rules with the target that match
// text.
func builtinHits(rs []compiledRule, target rules.Target, text string) []string {
	var ids []string
	for _, r := range rs {
		if r.target == target && len(r.m.Match(text)) > 0 {
			ids = append(ids, r.id)
		}
	}
	slices.Sort(ids)
	return ids
}

// TestFixtureBuiltinDescriptionRules runs the built-in description and schema
// rules over the benign fixture (no hit) and the shadowing fixture (T3 hit).
func TestFixtureBuiltinDescriptionRules(t *testing.T) {
	t.Parallel()

	rs := compileBuiltin(t)
	if len(rs) == 0 {
		t.Fatal("Builtin() returned no rules, want at least 1")
	}

	t.Run("benign", func(t *testing.T) {
		t.Parallel()
		// The canned result holds the tools of testdata/servers/benign.
		for _, tool := range inspecttest.BenignResult().Tools {
			if got := builtinHits(rs, rules.TargetDescription, tool.Description); len(got) != 0 {
				t.Errorf("description of %s: hits = %q, want none", tool.Name, got)
			}
			if got := builtinHits(rs, rules.TargetSchema, string(tool.InputSchema)); len(got) != 0 {
				t.Errorf("schema of %s: hits = %q, want none", tool.Name, got)
			}
		}
	})

	t.Run("shadowing", func(t *testing.T) {
		t.Parallel()
		st := inspectFixture(t, "shadowing")
		// Wanted description hits per tool. A tool not listed wants none.
		wantDescription := map[string][]string{
			"add_numbers": {"MOAT-T1-003", "MOAT-T3-001"},
		}
		if !slices.ContainsFunc(st.Tools, func(tool inspect.Tool) bool { return tool.Name == "add_numbers" }) {
			t.Error("shadowing fixture has no add_numbers tool")
		}
		for _, tool := range st.Tools {
			if got, want := builtinHits(rs, rules.TargetDescription, tool.Description), wantDescription[tool.Name]; !slices.Equal(got, want) {
				t.Errorf("description of %s: hits = %q, want %q", tool.Name, got, want)
			}
			if got := builtinHits(rs, rules.TargetSchema, string(tool.InputSchema)); len(got) != 0 {
				t.Errorf("schema of %s: hits = %q, want none", tool.Name, got)
			}
		}
	})
}
