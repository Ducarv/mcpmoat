package rules_test

// Integration tests: the native checks against the fixtures of issue #57.
// The server fixtures are stdio programs under testdata/servers that make no
// network call. The config fixtures are Cursor files under testdata/configs.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	canaryHost   = "mcp.example.com"
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
// from a copy in a new home, and returns its servers in file order of Name.
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
	data, err := os.ReadFile(filepath.Join("..", "..", "rules", "data", "popular-servers.txt"))
	if err != nil {
		t.Fatalf("read popular list: %v", err)
	}
	names, err := rules.ParsePopular(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParsePopular() error = %v", err)
	}
	return rules.NewTyposquat(names)
}

// got is the comparable form of a Finding for the config tests.
type got struct{ Server, RuleID, Field, Key, Related string }

// compareGot orders got values by their fields.
func compareGot(a, b got) int {
	return strings.Compare(fmt.Sprintf("%v", a), fmt.Sprintf("%v", b))
}

// assertFindings compares findings with want, ignoring order.
func assertFindings(t *testing.T, what string, findings []rules.Finding, want []got) {
	t.Helper()
	var have []got
	for _, f := range findings {
		have = append(have, got{f.Server, f.RuleID, f.Field, f.Key, f.Related})
	}
	slices.SortFunc(have, compareGot)
	slices.SortFunc(want, compareGot)
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
	// Message is fixed text; compare the other fields.
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

	assertFindings(t, "CheckConfig", all, []got{
		{"remote-plain", rules.RuleInsecureURL, "url", "", ""},
		{"remote-plain", rules.RulePlaintextSecret, "headers", "X-Api-Key", ""},
		{"env-secret", rules.RulePlaintextSecret, "env", "GITHUB_TOKEN", ""},
		{"latest-pkg", rules.RuleUnpinnedPackage, "args", "", "@example-corp/files-mcp"},
		{"docker-untagged", rules.RuleUnpinnedPackage, "args", "", "example/mcp-server"},
	})

	// A finding names the place of a problem and never the content.
	for _, f := range all {
		for verb, out := range map[string]string{
			"%+v": fmt.Sprintf("%+v", f),
			"%#v": fmt.Sprintf("%#v", f),
		} {
			discovertest.AssertNoLeak(t, verb+" of "+f.Server+"/"+f.RuleID, out, canaryHeader, canaryToken, canaryHost)
		}
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error = %v", f.RuleID, err)
		}
		discovertest.AssertNoLeak(t, "JSON of "+f.Server+"/"+f.RuleID, string(b), canaryHeader, canaryToken, canaryHost)
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

	assertFindings(t, "Typosquat.Check", squat, []got{
		{"filesystem", rules.RuleTyposquat, "args", "", "@modelcontextprotocol/server-filesystem"},
		{"mcp-server-fecth", rules.RuleTyposquat, "name", "", "mcp-server-fetch"},
	})
	assertFindings(t, "CheckConfig", config, nil)
}
