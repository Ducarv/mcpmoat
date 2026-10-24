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

	canaryArgSecret = "Zq8Lm3Vx0Rt5Ws2Hy7Nb4Kd1" //nolint:gosec // G101: synthetic canary of the test fixture, not a credential
	canaryURLSecret = "Jt6Pc9Gh2Fw8Ye4Ua1Xs7Mq3" //nolint:gosec // G101: synthetic canary of the test fixture, not a credential
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

// TestFixturePoisoned checks that the fixture serves its payloads. The rule
// hits on these tools are asserted in TestFixtureBuiltinT1.
func TestFixturePoisoned(t *testing.T) {
	t.Parallel()

	st := inspectFixture(t, "poisoned")

	byName := make(map[string]inspect.Tool)
	for _, tool := range st.Tools {
		byName[tool.Name] = tool
	}
	for _, name := range []string{"currency_convert", "daily_quote", "padded_notes", "unit_convert", "weather_lookup"} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("poisoned fixture has no tool %q", name)
		}
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
	// padded_notes hides its payload past the window that the regex and
	// keyword matchers read. No other check above reads padded_notes, so no
	// check needs the payload inside the window.
	d = byName["padded_notes"].Description
	if len(d) <= rules.MaxMatchInputBytes {
		t.Errorf("padded_notes description is %d bytes, want more than MaxMatchInputBytes (%d)", len(d), rules.MaxMatchInputBytes)
	}
	if at := strings.Index(d, "<IMPORTANT>"); at < rules.MaxMatchInputBytes {
		t.Errorf("padded_notes first <IMPORTANT> is at byte %d, want at or past MaxMatchInputBytes (%d)", at, rules.MaxMatchInputBytes)
	}

	if f := rules.CheckShadowing([]rules.ServerTools{st}); len(f) != 0 {
		t.Errorf("CheckShadowing(poisoned) = %+v, want none", f)
	}
}

// The ID prefixes of the T1 (tool poisoning) and T3 (shadowing) rules. Each
// fixture test asserts only the IDs of one threat, so a rule of another threat
// does not break it.
const (
	t1Prefix = "MOAT-T1-"
	t3Prefix = "MOAT-T3-"
)

// compiledRule is a built-in rule with its compiled match block.
type compiledRule struct {
	id     string
	target rules.Target
	m      *rules.Matcher
}

// prefixRules returns the built-in rules whose ID starts with prefix and that
// run on a description or a schema, with their match blocks compiled. Config
// rules need a server config, so they are skipped.
func prefixRules(t *testing.T, prefix string) []compiledRule {
	t.Helper()
	c := rules.BuiltinCompiler()
	// WithCompiler makes a load error name the file, the line and the column.
	// The loader discards the Matchers (see WithCompiler), so compile again.
	rs := rules.MustBuiltin(t, rules.WithCompiler(c))
	var out []compiledRule
	for _, r := range rs {
		if r.Target == rules.TargetConfig || !strings.HasPrefix(r.ID, prefix) {
			continue
		}
		m, err := c(r.Match, r.Target)
		if err != nil {
			t.Fatalf("%s: compile: %v", r.ID, err)
		}
		out = append(out, compiledRule{id: r.ID, target: r.Target, m: m})
	}
	return out
}

// ruleHits returns the sorted IDs of the rules in rs with the given target
// that match text. It prepares text once and shares it between the rules, so
// one set of match forms is built for each target text (not for a schema
// target, whose strings get their own forms, see matchPrepared).
func ruleHits(rs []compiledRule, target rules.Target, text string) []string {
	p := rules.PrepareText(text)
	var ids []string
	for _, cr := range rs {
		if cr.target == target && len(rules.MatchPrepared(cr.m, p)) > 0 {
			ids = append(ids, cr.id)
		}
	}
	slices.Sort(ids)
	return ids
}

// targetText returns the text that a rule with target sees in tool: the
// description, or the input schema as raw JSON.
func targetText(tool inspect.Tool, target rules.Target) string {
	if target == rules.TargetSchema {
		return string(tool.InputSchema)
	}
	return tool.Description
}

// toolTarget is a tool and one of its targets, the key of an expected result.
type toolTarget struct {
	tool   string
	target rules.Target
}

// TestBuiltinT1IDs checks the loaded T1 rule IDs. TestFixtureBuiltinT1 does
// not check a rule that no fixture triggers, so the two tests together fail
// when a T1 rule is missing or new.
func TestBuiltinT1IDs(t *testing.T) {
	t.Parallel()

	var ids []string
	for _, cr := range prefixRules(t, t1Prefix) {
		ids = append(ids, cr.id)
	}
	slices.Sort(ids)
	wantIDs := []string{
		"MOAT-T1-001", "MOAT-T1-002", "MOAT-T1-003", "MOAT-T1-004", "MOAT-T1-005",
		"MOAT-T1-006", "MOAT-T1-007", "MOAT-T1-008", "MOAT-T1-009", "MOAT-T1-010",
		"MOAT-T1-011", "MOAT-T1-012", "MOAT-T1-013", "MOAT-T1-014", "MOAT-T1-015",
		"MOAT-T1-016", "MOAT-T1-017", "MOAT-T1-018", "MOAT-T1-019", "MOAT-T1-020",
		"MOAT-T1-021", "MOAT-T1-022",
	}
	if !slices.Equal(ids, wantIDs) {
		t.Errorf("loaded T1 rule IDs = %q, want %q", ids, wantIDs)
	}
}

// TestFixtureBuiltinT1 runs the built-in T1 rules on every tool of the fixture
// servers, once for the description and once for the schema. It does not check
// prompts or resources. A rule has one target, so the two are checked apart.
// Each tool and target must match the rule IDs listed for it, and no others;
// a pair that is not listed must match none. The test also checks the tool
// names of each server, so a missing or new tool fails the test.
func TestFixtureBuiltinT1(t *testing.T) {
	t.Parallel()

	rs := prefixRules(t, t1Prefix)
	if len(rs) == 0 {
		t.Fatal("no built-in T1 rules loaded; the checks would pass with no rule")
	}

	fixtures := []struct {
		name  string
		tools []string                // every tool the server lists, sorted
		want  map[toolTarget][]string // sorted; a pair not in the map matches none
	}{
		{"benign", []string{"add", "echo"}, nil},
		{"mailer", []string{"send_email"}, nil},
		{"poisoned", []string{"currency_convert", "daily_quote", "padded_notes", "unit_convert", "weather_lookup"}, map[toolTarget][]string{
			{"daily_quote", rules.TargetDescription}:      {"MOAT-T1-002", "MOAT-T1-003", "MOAT-T1-004", "MOAT-T1-005"},
			{"weather_lookup", rules.TargetSchema}:        {"MOAT-T1-009", "MOAT-T1-012"},
			{"currency_convert", rules.TargetDescription}: {"MOAT-T1-006", "MOAT-T1-019"},
			{"unit_convert", rules.TargetDescription}:     {"MOAT-T1-008", "MOAT-T1-020"},
			// The payload is past the regex window, so only the heuristics
			// that read the full text match.
			{"padded_notes", rules.TargetDescription}: {"MOAT-T1-007", "MOAT-T1-017"},
		}},
		{"shadowing", []string{"add_numbers"}, map[toolTarget][]string{
			{"add_numbers", rules.TargetDescription}: {"MOAT-T1-003", "MOAT-T1-005"},
		}},
	}
	for _, fx := range fixtures {
		st := inspectFixture(t, fx.name)
		var names []string
		for _, tool := range st.Tools {
			names = append(names, tool.Name)
		}
		slices.Sort(names)
		if !slices.Equal(names, fx.tools) {
			t.Errorf("%s tool names = %q, want %q", fx.name, names, fx.tools)
		}
		// A key that names no served tool would never be checked.
		for key := range fx.want {
			if !slices.Contains(names, key.tool) {
				t.Errorf("%s expects results for tool %q, which the server does not list", fx.name, key.tool)
			}
		}

		for _, tool := range st.Tools {
			for _, target := range []rules.Target{rules.TargetDescription, rules.TargetSchema} {
				t.Run(fx.name+"/"+tool.Name+"/"+string(target), func(t *testing.T) {
					t.Parallel()
					got := ruleHits(rs, target, targetText(tool, target))
					want := fx.want[toolTarget{tool.Name, target}]
					if !slices.Equal(got, want) {
						t.Errorf("T1 hits = %q, want %q", got, want)
					}
				})
			}
		}
	}
}

func TestFixtureDangerousConfig(t *testing.T) {
	t.Parallel()

	servers := configServers(t, "dangerous")
	if len(servers) != 9 {
		t.Fatalf("ReadCursor() returned %d servers, want 9", len(servers))
	}
	ts := popularTyposquat(t)

	// Guard against a vacuous leak check: the canaries must be in the config.
	for _, s := range servers {
		switch s.Name {
		case "env-secret":
			if s.Env["GITHUB_TOKEN"].Reveal() != canaryToken {
				t.Fatal("fixture env-secret no longer holds the canary token; update the test")
			}
		case "docker-arg-secret":
			if !slices.Contains(s.Args.Values(), "SOME_API_TOKEN="+canaryArgSecret) {
				t.Fatal("fixture docker-arg-secret no longer holds the canary arg secret; update the test")
			}
		case "remote-url-secret":
			if !strings.Contains(s.URL.Reveal(), canaryURLSecret) {
				t.Fatal("fixture remote-url-secret no longer holds the canary URL secret; update the test")
			}
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
		{"docker-arg-secret", rules.RulePlaintextSecret, rules.FieldArgs, "", ""},
		{"remote-url-secret", rules.RulePlaintextSecret, rules.FieldURL, "", ""},
		{"npx-git-unpinned", rules.RuleUnpinnedPackage, rules.FieldArgs, "", ""},
		{"npx-git-unpinned", rules.RuleAutoInstall, rules.FieldArgs, "", ""},
		{"npx-git-pinned", rules.RuleAutoInstall, rules.FieldArgs, "", ""},
	})

	// A finding names the place of a problem and never the content.
	for _, f := range all {
		rules.AssertFindingNoLeak(t, f, canaryHeader, canaryToken, canaryHost, canaryArgSecret, canaryURLSecret)
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

// TestFixtureBuiltinT3 runs the built-in T3 rules on every tool of the fixture
// servers, once for the description and once for the schema. Only the
// description of add_numbers in the shadowing fixture may match.
func TestFixtureBuiltinT3(t *testing.T) {
	t.Parallel()

	rs := prefixRules(t, t3Prefix)
	if len(rs) == 0 {
		t.Fatal("no built-in T3 rules loaded; the checks would pass with no rule")
	}
	want := map[string]map[toolTarget][]string{ // sorted; a pair not listed matches none
		"shadowing": {{"add_numbers", rules.TargetDescription}: {rules.RuleShadowing}},
	}
	for _, name := range []string{"benign", "mailer", "poisoned", "shadowing"} {
		st := inspectFixture(t, name)
		for key := range want[name] {
			if !slices.ContainsFunc(st.Tools, func(tool inspect.Tool) bool { return tool.Name == key.tool }) {
				t.Errorf("%s expects results for tool %q, which the server does not list", name, key.tool)
			}
		}
		for _, tool := range st.Tools {
			for _, target := range []rules.Target{rules.TargetDescription, rules.TargetSchema} {
				got := ruleHits(rs, target, targetText(tool, target))
				if w := want[name][toolTarget{tool.Name, target}]; !slices.Equal(got, w) {
					t.Errorf("%s/%s/%s: T3 hits = %q, want %q", name, tool.Name, target, got, w)
				}
			}
		}
	}
}
