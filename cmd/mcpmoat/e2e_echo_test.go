package main

// End-to-end tests of the mask of configured values that a hostile server
// echoes back (issues #228, #234 and #180). They run the real binary with the
// echo fixture in its two modes (see testdata/servers/echo/README.md):
//
//   - echo-env offers one tool, fetch_<value>, with the value also in its
//     description and in the description of a schema property;
//   - fail-echo answers initialize with the error "cannot start: bad token
//     <value>" and exits.
//
// The values come from the "env" of the server config, so the real inspector
// puts them in Result.Secrets. All values are fake.

import (
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
)

// e2eKeywordRule is an extra rule for --rules that flags the word "token" in a
// tool description, so that the echo-env tool gets a tool rule row.
const e2eKeywordRule = `id: MOAT-X-900
title: Tool description mentions a token
severity: low
target: description
match:
  keywords:
    - token
risk: The tool may ask for a credential.
remediation: Check what the tool does with the token.
should_match:
  - Fetch data with the token abc.
should_not_match:
  - Lists the files in a folder.
`

// e2eShortPin is the fake env value of TestE2EScanShortValueInFailure. It has
// fewer than 8 bytes, so the report masks it only as a whole word.
const e2eShortPin = "123456"

// TestE2EScanEchoedSecret runs the pin journey with a server that echoes a
// configured env value in its tool name, description and schema. The config
// holds two values, the fake tokens echoToken and echoToken2
// (scan_echo_secret_test.go). Each one has 8 bytes or more
// (discover.MinSecretBytes), so the report masks it wherever it stands. The
// server echoes the first one, then the config switches it to the second
// one, so its only tool gets a new name: scan reports a new tool and a
// removed tool, with a diff. An extra rule (--rules) also flags the
// description of the tool in each scan, so the run has a tool rule row too.
// No run prints a value: the rows, the diffs and the --json keys show
// discover.Mask. pins.json keeps the real tool names, because the pins and
// their hashes use the raw text.
func TestE2EScanEchoedSecret(t *testing.T) {
	t.Parallel()
	const server = "echo"
	tokens := []string{echoToken, echoToken2}
	maskedName := "fetch_" + discover.Mask

	home, work := t.TempDir(), t.TempDir()
	requirePrivateChain(t, home)
	// The extra rule flags the word "token" in each tool description.
	rulesDir := t.TempDir()
	writeTestFile(t, rulesDir, "MOAT-X-900.yaml", e2eKeywordRule)
	// writeConfig writes the global config. The server echoes the env
	// variable echoVar. Both values stay in the env, so both are secrets of
	// the server in every run, also the one that only pins.json still holds.
	writeConfig := func(echoVar string) {
		writeServers(t, home, ".claude.json", map[string]any{
			server: map[string]any{
				"command": inspecttest.Fixture(t, "echo"),
				"args":    []string{"-mode", "echo-env", "-echovar", echoVar},
				"env":     map[string]string{"MCPMOAT_FAKE_TOKEN": echoToken, "MCPMOAT_FAKE_TOKEN2": echoToken2},
			},
		})
	}
	// assertNoToken checks that no stream of a run holds a token.
	assertNoToken := func(t *testing.T, stdout, stderr string) {
		t.Helper()
		assertContainsNone(t, "stdout", stdout, tokens)
		assertContainsNone(t, "stderr", stderr, tokens)
	}
	// baseRows are the rows of every scan. The config rows of the two literal
	// env values are about the env keys, so they show no value, and they make
	// the exit code 1. The extra rule row shows the masked tool name.
	baseRows := []string{
		"MOAT-T4-002 high env MCPMOAT_FAKE_TOKEN",
		"MOAT-T4-002 high env MCPMOAT_FAKE_TOKEN2",
		"MOAT-X-900 low tool " + maskedName,
	}
	// pinRows are the rows of the second scan: the tool with the second token
	// is new, and the pinned tool with the first token is gone. Both names are
	// masked, so both rows show the same Key.
	pinRows := []string{"MOAT-T2-002 high tool " + maskedName, "MOAT-T2-003 low tool " + maskedName}

	// textRows returns the sorted findings of a text stdout as "RULE severity
	// field key". A tool row has a "Tool:" line, a config row a "Where:" line.
	// A rule row adds the field it matched to the tool name, as in
	// "fetch_******** (description)"; the --json key has no such suffix.
	textRows := func(t *testing.T, stdout string) []string {
		t.Helper()
		body, _ := cutAcceptHints(stdout)
		var got []string
		for _, f := range parseFindings(t, body) {
			if f.Tool != "" {
				got = append(got, f.RuleID+" "+f.Severity+" tool "+strings.TrimSuffix(f.Tool, " (description)"))
			} else {
				got = append(got, f.RuleID+" "+f.Severity+" "+f.Where)
			}
		}
		slices.Sort(got)
		return got
	}
	// jsonRows returns the sorted findings of a --json stdout in the same form.
	jsonRows := func(t *testing.T, stdout string) []string {
		t.Helper()
		var got []string
		// decodeScanJSON fails the test when stdout is not a valid report.
		for _, f := range decodeScanJSON(t, stdout).Findings {
			got = append(got, f.RuleID+" "+f.Severity+" "+f.Field+" "+f.Key)
		}
		slices.Sort(got)
		return got
	}
	// assertPinnedName checks that pins.json has the raw tool name with
	// token, and no name with the other token.
	assertPinnedName := func(t *testing.T, token, other string) {
		t.Helper()
		data := string(readFileBytes(t, pinsPath(home)))
		if !strings.Contains(data, `"fetch_`+token+`"`) || strings.Contains(data, "fetch_"+other) {
			t.Errorf("pins.json does not pin only the raw name fetch_%s:\n%s", token, data)
		}
	}

	// Step 1: the first scan pins the tool with the first token. The pin is
	// not a finding, so only the config rows are on stdout.
	writeConfig("MCPMOAT_FAKE_TOKEN")
	stdout, stderr, code := runBin(t, home, work, "scan", "--rules", rulesDir)
	wantErr := e2eNewPinsFileNotice("scan", home) + "\nmcpmoat scan: pinned 1 tool for " + server + "\n"
	assertScanResult(t, code, stdout, stderr, scanWant{code: exitFindings, stderr: []string{wantErr}})
	assertServerNames(t, stdout, server)
	if got := textRows(t, stdout); !slices.Equal(got, baseRows) {
		t.Errorf("step 1 findings = %q, want %q\nstdout:\n%s", got, baseRows, stdout)
	}
	assertNoToken(t, stdout, stderr)
	assertPinnedName(t, echoToken, echoToken2)

	// Step 1b: --json of the same state. The pin is saved already, so stderr
	// is empty.
	stdout, stderr, code = runBin(t, home, work, "scan", "--rules", rulesDir, "--json")
	if code != exitFindings || stderr != "" {
		t.Errorf("step 1 --json: exit code %d, stderr %q, want exit code %d and no stderr", code, stderr, exitFindings)
	}
	if got := jsonRows(t, stdout); !slices.Equal(got, baseRows) {
		t.Errorf("step 1 --json findings = %q, want %q", got, baseRows)
	}
	assertNoToken(t, stdout, stderr)

	// Step 2: the server now echoes the second token, so its tool has a new
	// name. The text report has the two pin rows and the diff of the new
	// tool, all masked.
	writeConfig("MCPMOAT_FAKE_TOKEN2")
	stdout, stderr, code = runBin(t, home, work, "scan", "--rules", rulesDir)
	assertScanResult(t, code, stdout, stderr, scanWant{code: exitFindings})
	// slices.Clone keeps append from writing into the array of baseRows.
	wantRows := slices.Sorted(slices.Values(append(slices.Clone(baseRows), pinRows...)))
	if got := textRows(t, stdout); !slices.Equal(got, wantRows) {
		t.Errorf("step 2 findings = %q, want %q\nstdout:\n%s", got, wantRows, stdout)
	}
	body, _ := cutAcceptHints(stdout)
	assertDiffsOf(t, splitScanSections(body).Rest, server, []string{"+" + maskedName})
	assertContainsAll(t, "stdout", stdout, []string{
		"\n+name: " + maskedName + "\n",
		"\n+description: Fetch data with the token " + discover.Mask + ".\n",
		`"description": "Text to send with the token ` + discover.Mask + `.",`,
	})
	assertNoToken(t, stdout, stderr)
	digest := hintDigest(t, stdout, server)

	// Step 2b: --json has the same rows, and the one diff names the masked tool.
	stdout, stderr, code = runBin(t, home, work, "scan", "--rules", rulesDir, "--json")
	if code != exitFindings || stderr != "" {
		t.Errorf("step 2 --json: exit code %d, stderr %q, want exit code %d and no stderr", code, stderr, exitFindings)
	}
	if got := jsonRows(t, stdout); !slices.Equal(got, wantRows) {
		t.Errorf("step 2 --json findings = %q, want %q", got, wantRows)
	}
	diffs := decodeScanJSON(t, stdout).Diffs
	if len(diffs) != 1 || diffs[0].Server != server || diffs[0].Tool != maskedName || diffs[0].Kind != "new" ||
		!strings.Contains(diffs[0].Diff, "\n+name: "+maskedName+"\n") {
		t.Errorf("step 2 --json diffs = %+v, want one new diff of %s", diffs, maskedName)
	}
	assertNoToken(t, stdout, stderr)

	// Step 3: pin --accept with the digest of the scan prints the masked diff
	// again and saves the real name of the new tool.
	stdout, stderr, code = runBin(t, home, work, "pin", "--accept", server, "--expect", digest)
	diffText, accepted := strings.CutSuffix(stdout, "accepted "+server+": 1 new, 0 changed, 1 removed\n")
	if code != exitOK || !accepted || stderr != "" {
		t.Errorf("pin --accept: exit code %d, stdout %q, stderr %q, want exit code %d, the accepted line and no stderr", code, stdout, stderr, exitOK)
	}
	assertDiffsOf(t, diffText, server, []string{"+" + maskedName})
	assertNoToken(t, stdout, stderr)
	assertPinnedName(t, echoToken2, echoToken)

	// Step 4: the new name is pinned, so the pin rows are gone.
	stdout, stderr, code = runBin(t, home, work, "scan", "--rules", rulesDir)
	assertScanResult(t, code, stdout, stderr, scanWant{code: exitFindings, noStdout: []string{"MOAT-T2"}})
	if got := textRows(t, stdout); !slices.Equal(got, baseRows) {
		t.Errorf("step 4 findings = %q, want %q\nstdout:\n%s", got, baseRows, stdout)
	}
	assertNoToken(t, stdout, stderr)
}

// TestE2EScanShortValueInFailure checks a server that echoes a short env value
// (6 bytes) in the error of its initialize reply. The value is shorter than
// discover.MinSecretBytes, so mcpmoat masks it only as a whole word: the
// reason "bad token 123456" becomes "bad token ********" in the SUMMARY of
// scan, in the stderr warning of scan --json and in the stderr error of pin.
//
// The checks look for the phrase "bad token 123456", not for the bare value:
// six digits can also be part of a fixed text, such as a path or an ID.
func TestE2EScanShortValueInFailure(t *testing.T) {
	t.Parallel()
	const server = "fail"
	const reason = `inspect: fail: calling "initialize": cannot start: bad token ` + discover.Mask
	leak := []string{"bad token " + e2eShortPin}

	home, work := t.TempDir(), t.TempDir()
	requirePrivateChain(t, home)
	writeServers(t, home, ".claude.json", map[string]any{
		server: map[string]any{
			"command": inspecttest.Fixture(t, "echo"),
			"args":    []string{"-mode", "fail-echo", "-echovar", "MCPMOAT_FAKE_PIN"},
			"env":     map[string]string{"MCPMOAT_FAKE_PIN": e2eShortPin},
		},
	})

	// The subtests share one home, so they run one after the other.
	t.Run("scan", func(t *testing.T) {
		stdout, stderr, code := runBin(t, home, work, "scan")
		assertScanResult(t, code, stdout, stderr, scanWant{code: exitOK})
		want := "  " + server + " (claude-code, global): failed, 0 findings (" + reason + ")"
		if summary := splitScanSections(stdout).Summary; !strings.Contains(summary, want) {
			t.Errorf("SUMMARY has no line %q\nstdout:\n%s", want, stdout)
		}
		assertContainsNone(t, "stdout", stdout, leak)
		assertContainsNone(t, "stderr", stderr, leak)
	})

	t.Run("scan --json", func(t *testing.T) {
		stdout, stderr, code := runBin(t, home, work, "scan", "--json")
		want := "mcpmoat scan: warning: server " + server + ": failed: " + reason + "\n"
		if code != exitOK || stderr != want {
			t.Errorf("exit code %d, stderr %q, want exit code %d and stderr %q", code, stderr, exitOK, want)
		}
		// decodeScanJSON fails the test when stdout is not a valid report.
		decodeScanJSON(t, stdout)
		assertContainsNone(t, "stdout", stdout, leak)
	})

	t.Run("pin", func(t *testing.T) {
		stdout, stderr, code := runBin(t, home, work, "pin", "--accept", server)
		want := "mcpmoat pin: server " + server + ": failed: " + reason + "\n"
		if code != exitError || stdout != "" || stderr != want {
			t.Errorf("exit code %d, stdout %q, stderr %q, want exit code %d, no stdout and stderr %q", code, stdout, stderr, exitError, want)
		}
		assertNoPinsFile(t, home)
	})
}
