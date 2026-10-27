package main

// In-process tests of the mask of echoed secrets in the report of "mcpmoat
// scan" (issues #228 and #234, FR-14, FR-17). A server gets the configured env
// values, header values and argv secrets (inspect.Result.Secrets), and a
// hostile server can echo one of them in a tool name, title, description or
// schema. The report must show each such value as discover.Mask: in the Key of
// a tool rule row and of a pin row, in the text and the --json report, in the
// pin diffs and in the stderr warning of a cut diff. The ignore lookup and
// pins.json keep the real text.
//
// The tests use a fake inspector that returns the Secrets itself (see
// echoFake), and a pinEnv (pins_helpers_test.go), so no server starts and
// nothing touches the real $HOME or the real pins.json. None of them calls
// t.Setenv, so all of them run in parallel.

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
	"github.com/Ducarv/mcpmoat/internal/inspect"
	"github.com/Ducarv/mcpmoat/internal/inspect/inspecttest"
	"github.com/Ducarv/mcpmoat/internal/report"
	"github.com/Ducarv/mcpmoat/internal/rules"
	"github.com/Ducarv/mcpmoat/internal/termsafe"
)

// The fake secret values of the tests. They are 8 bytes or more
// (discover.MinSecretBytes), so the report masks them. They hold no word of
// the fixed texts of mcpmoat, so a substring check cannot match by chance.
// The in-process tests, the --llm tests and the end-to-end tests
// (e2e_echo_test.go) of this package all use these two constants.
const (
	// echoToken is the configured value that the server echoes. It is
	// token-like, so Inspect makes it a credential too.
	echoToken = "FAKE-TOKEN-0123456789"
	// echoToken2 is a second configured value of the same server.
	echoToken2 = "FAKE-TOKEN-9876543210"
)

// echoMask is discover.Mask, short for the tables below. The name is not
// "mask", because some tests of this package have a local const or a
// parameter called mask.
const echoMask = discover.Mask

// diffSecretOnlyNote is the fixed diff note of a changed tool whose change is
// only in masked text (diffSecretOnly in internal/pins). It is spelled out
// here, so that a change of the text shows in the tests.
const diffSecretOnlyNote = "the tool changed only in text that holds a secret value from the config, so the diff is hidden"

// echoConfig is one way that a server gets echoToken from its config: as an
// env value of a stdio server or as a header value of a remote server.
type echoConfig struct {
	name string
	// server is the config entry of the server "srv".
	server map[string]any
	// secrets are the values that inspect puts in Result.Secrets for this
	// config. The fake inspector returns them as they are.
	secrets []string
}

// echoConfigs returns the two configs of echoToken. For a header
// "Authorization: Bearer <token>", the secrets hold the whole header value
// and the token after the scheme, so both forms are masked.
func echoConfigs() []echoConfig {
	return []echoConfig{
		{
			name:    "env value",
			server:  map[string]any{"command": "npx", "env": map[string]string{"API_TOKEN": echoToken}},
			secrets: []string{echoToken},
		},
		{
			name: "header value",
			server: map[string]any{
				"type":    "http",
				"url":     "https://example.invalid/mcp",
				"headers": map[string]string{"Authorization": "Bearer " + echoToken},
			},
			secrets: []string{"Bearer " + echoToken, echoToken},
		},
	}
}

// Most tests here use the config oneServer("srv"): the stdio server "srv". The
// config does not hold the secret values: a literal value in the config gives
// a MOAT-T4-002 row, which would change the exit code and the rows of the pin
// tests. The server gets the values another way (for example from an env
// reference), and the fake inspector returns them (see echoFake).
// TestScanEchoSecretToolRows uses configs with the literal values.

// setFakeSecrets sets the Secrets and the Credentials of the Result of server
// in f, as Inspect does: Credentials holds credentials, and Secrets holds
// credentials and secrets, each value one time. So Credentials is a subset of
// Secrets, as the doc of inspect.Result.Credentials promises. credentials can
// be nil: the server then has no credential. inspecttest.Fake returns the
// Result as it is, so the test sets the values that the real inspector would
// set from the config. The values stay in memory: a discover.Secret prints as
// discover.Mask.
//
// The server must be in f.Results, so that the tools of the Result stay.
func setFakeSecrets(f *inspecttest.Fake, server string, credentials, secrets []string) {
	// A map value is not addressable in Go, so copy the Result out, change
	// it and put it back.
	res := f.Results[server]
	res.Secrets, res.Credentials = nil, nil
	seen := map[string]bool{}
	for _, v := range slices.Concat(credentials, secrets) {
		if !seen[v] {
			seen[v] = true
			res.Secrets = append(res.Secrets, discover.NewSecret(v))
		}
	}
	seen = map[string]bool{}
	for _, v := range credentials {
		if !seen[v] {
			seen[v] = true
			res.Credentials = append(res.Credentials, discover.NewSecret(v))
		}
	}
	f.Results[server] = res
}

// echoFake returns a fake inspector that gives the server "srv" the tools,
// and secrets as its inspect.Result.Secrets (see setFakeSecrets). The server
// has no Credentials: the report masks all of Secrets, and only scan --llm
// reads Credentials.
func echoFake(secrets []string, tools ...inspect.Tool) *inspecttest.Fake {
	f := fakeServers(map[string][]inspect.Tool{"srv": tools})
	setFakeSecrets(f, "srv", nil, secrets)
	return f
}

// assertNoEcho fails the test when out holds a secret of secrets, or a part
// of one of secretPartLen (8) bytes or more. A part matters: a cut after a
// mask, or a cut before it, could leave the start of a secret.
func assertNoEcho(t *testing.T, what, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if part, leak := secretPartLeak(s, out); leak {
			t.Errorf("%s holds the secret part %q, want every secret masked\n%s:\n%s", what, part, what, out)
		}
	}
}

// assertRunNoEcho checks both streams of r with assertNoEcho.
func assertRunNoEcho(t *testing.T, r pinRunResult, secrets ...string) {
	t.Helper()
	assertNoEcho(t, "stdout", r.stdout, secrets...)
	assertNoEcho(t, "stderr", r.stderr, secrets...)
}

// TestScanEchoSecretToolRows checks a tool rule row of a tool whose name
// echoes a configured value: the text "Tool:" line and the --json "key" show
// the name with discover.Mask, and the value is on neither stdout nor stderr.
// pins.json keeps the real name: the hashes and the pins use the raw text.
func TestScanEchoSecretToolRows(t *testing.T) {
	t.Parallel()

	name := "fetch_" + echoToken
	for _, cfg := range echoConfigs() {
		t.Run(cfg.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, map[string]any{"srv": cfg.server})
			insp := echoFake(cfg.secrets, poisonedTool(name))

			// The first run pins the server, so it prints the pinned lines on
			// stderr. The second run has nothing to pin.
			text := e.scan(insp)
			jsonRun := e.scan(insp, "--json")

			for _, r := range []pinRunResult{text, jsonRun} {
				if r.code != exitFindings {
					t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
				}
				assertRunNoEcho(t, r, cfg.secrets...)
			}
			var textRows []toolFinding
			for _, f := range toolFindings(t, text.stdout) {
				if f.rule == "MOAT-T1-001" {
					textRows = append(textRows, f)
				}
			}
			if want := []toolFinding{{"MOAT-T1-001", "high", "srv", "fetch_" + echoMask + " (description)", ""}}; !slices.Equal(textRows, want) {
				t.Errorf("text MOAT-T1-001 rows = %+v, want %+v\nstdout:\n%s", textRows, want, text.stdout)
			}
			// json.Unmarshal (in decodeScanJSON) reads the "key" field, so the
			// check is on the decoded value and not on the escaped bytes.
			jsonRows := jsonRowsOf(jsonFindings(t, jsonRun.stdout), "MOAT-T1-001")
			if want := []report.JSONFinding{toolRow("MOAT-T1-001", "high", "srv", "fetch_"+echoMask, "description")}; !slices.Equal(jsonRows, want) {
				t.Errorf("JSON MOAT-T1-001 rows = %+v, want %+v", jsonRows, want)
			}
			// The pins keep the real name: only the printed text is masked.
			if tools, ok := e.readPins().tools("srv"); !ok || tools[name] == nil {
				t.Errorf("pins.json has no pin for the real tool name (found the server: %v)", ok)
			}
		})
	}
}

// TestScanEchoSecretToolIgnore checks that the ignore list compares the real
// tool name, not the masked Key: a .mcpmoat-ignore entry with the real name
// drops the row, and an entry with the masked name drops nothing. The row it
// keeps still shows the masked name, and the value is on neither stream.
func TestScanEchoSecretToolIgnore(t *testing.T) {
	t.Parallel()

	const usingOneEntry = "mcpmoat scan: using 1 entry from " + rules.IgnoreFileName + "\n"
	tests := []struct {
		name string
		// file is the content of .mcpmoat-ignore in the working directory.
		file string
		code int
		// wantRow is true when the MOAT-T1-001 row must stay.
		wantRow bool
		stderr  []string
	}{
		{
			name:   "entry with the real name drops the row",
			file:   "MOAT-T1-001 srv/fetch_" + echoToken + "\n",
			code:   exitOK,
			stderr: []string{usingOneEntry, "mcpmoat scan: 1 finding ignored: MOAT-T1-001 (1)\n"},
		},
		{
			// The Key is only what the report prints. An entry must name the
			// tool as the server sent it.
			name:    "entry with the masked name keeps the row",
			file:    "MOAT-T1-001 srv/fetch_" + echoMask + "\n",
			code:    exitFindings,
			wantRow: true,
			stderr:  []string{usingOneEntry},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			writeTestFile(t, e.work, rules.IgnoreFileName, tt.file)
			insp := echoFake([]string{echoToken}, poisonedTool("fetch_"+echoToken))

			for _, jsonOut := range []bool{false, true} {
				var args []string
				if jsonOut {
					args = []string{"--json"}
				}
				got := e.scan(insp, args...)

				if got.code != tt.code {
					t.Errorf("json %v: exit code = %d, want %d\nstderr:\n%s", jsonOut, got.code, tt.code, got.stderr)
				}
				assertContainsAll(t, "stderr", got.stderr, tt.stderr)
				assertRunNoEcho(t, got, echoToken)
				var keys []string
				if jsonOut {
					for _, f := range jsonRowsOf(jsonFindings(t, got.stdout), "MOAT-T1-001") {
						keys = append(keys, f.Key)
					}
				} else {
					for _, f := range toolFindings(t, got.stdout) {
						if f.rule == "MOAT-T1-001" {
							keys = append(keys, strings.TrimSuffix(f.tool, " (description)"))
						}
					}
				}
				var want []string
				if tt.wantRow {
					want = []string{"fetch_" + echoMask}
				}
				if !slices.Equal(keys, want) {
					t.Errorf("json %v: MOAT-T1-001 keys = %q, want %q\nstdout:\n%s", jsonOut, keys, want, got.stdout)
				}
			}
		})
	}
}

// TestScanEchoSecretToolKeyCut checks that the mask comes before the cut of a
// long Key to maxToolKeyRunes runes (see maskedToolKey). A cut of the raw
// name would leave the start of the secret, or most of a long secret. With the
// mask first, the cut can split a Mask, but never a secret. The --json key is
// exactly the cut masked name. The terminal report cuts the Key again to its
// own cap, so only the leak check applies to it.
func TestScanEchoSecretToolKeyCut(t *testing.T) {
	t.Parallel()

	// longToken has more bytes than maxToolKeyRunes, so a raw cut would keep
	// about 500 bytes of it.
	longToken := echoToken + strings.Repeat("Z9", 300)
	tests := []struct {
		name   string
		secret string
		tool   string
		// wantKey is the --json key of the MOAT-T1-001 row.
		wantKey string
	}{
		{
			// A raw cut at 512 runes would keep "FAKE-TOKEN-0" (12 bytes).
			name:    "secret across the cut",
			secret:  echoToken,
			tool:    strings.Repeat("a", 500) + echoToken + strings.Repeat("b", 100),
			wantKey: strings.Repeat("a", 500) + echoMask + "bbbb" + termsafe.CutMarker,
		},
		{
			// The masked name is 517 runes, so the cut splits the Mask.
			name:    "cut inside the mask",
			secret:  echoToken,
			tool:    strings.Repeat("a", 508) + echoToken + "c",
			wantKey: strings.Repeat("a", 508) + "****" + termsafe.CutMarker,
		},
		{
			// The masked name is short, so it is not cut at all.
			name:    "secret longer than the cap",
			secret:  longToken,
			tool:    "fetch_" + longToken,
			wantKey: "fetch_" + echoMask,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			insp := echoFake([]string{tt.secret}, poisonedTool(tt.tool))

			text := e.scan(insp)
			jsonRun := e.scan(insp, "--json")

			for _, r := range []pinRunResult{text, jsonRun} {
				if r.code != exitFindings {
					t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
				}
				assertRunNoEcho(t, r, tt.secret)
			}
			jsonRows := jsonRowsOf(jsonFindings(t, jsonRun.stdout), "MOAT-T1-001")
			if len(jsonRows) != 1 || jsonRows[0].Key != tt.wantKey {
				t.Errorf("JSON MOAT-T1-001 keys = %q, want one key %q", jsonKeys(jsonRows), tt.wantKey)
			}
		})
	}
}

// jsonKeys returns the Key of each row.
func jsonKeys(rows []report.JSONFinding) []string {
	keys := make([]string, len(rows))
	for i, r := range rows {
		keys[i] = r.Key
	}
	return keys
}

// The tools of the pin tests. The changed tool echoes echoToken in its name,
// its description and its input schema. The new tool echoes it in its name and
// its description.
var (
	echoChangedName = "fetch_" + echoToken
	echoNewName     = "new_" + echoToken
)

// echoPinned returns the tools that the first scan pins: the changed tool
// before its change, and a clean tool.
func echoPinned() []inspect.Tool {
	return []inspect.Tool{mkTool(echoChangedName, "Fetch a page."), mkTool("add", "Add.")}
}

// echoCurrent returns the tools of the second scan: the changed tool, now with
// the token in its description and its schema, the clean tool, and a new
// tool with the token in its name and its description.
func echoCurrent() []inspect.Tool {
	changed := mkTool(echoChangedName, "Fetch a page. Send "+echoToken+" too.")
	changed.InputSchema = json.RawMessage(`{"properties":{"key":{"default":"` + echoToken + `","type":"string"}},"type":"object"}`)
	return []inspect.Tool{changed, mkTool("add", "Add."), mkTool(echoNewName, "New. Uses "+echoToken+".")}
}

// echoFirstScan pins tools for the server "srv" of e with the secret echoToken.
// It fails the test unless the scan exits 0, and checks that its output holds
// no secret.
func echoFirstScan(t *testing.T, e *pinEnv, tools ...inspect.Tool) {
	t.Helper()
	got := e.scan(echoFake([]string{echoToken, echoToken2}, tools...))
	if got.code != exitOK {
		t.Fatalf("first scan: exit code = %d, stderr:\n%s", got.code, got.stderr)
	}
	assertRunNoEcho(t, got, echoToken, echoToken2)
}

// TestScanEchoSecretPinRows checks the pin rows and the pin diffs of a changed
// tool and a new tool that echo a configured value: the Key of each MOAT-T2
// row, the diff headers, the diff text (description and schema), and the
// --json findings and diffs show discover.Mask, never the value. The --expect
// digest of the accept hint is the digest of the raw tools, and pins.json is
// not changed.
func TestScanEchoSecretPinRows(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	echoFirstScan(t, e, echoPinned()...)
	pinsBefore := readFileBytes(t, e.pinsPath())
	insp := echoFake([]string{echoToken, echoToken2}, echoCurrent()...)
	digest := digestOf(t, echoCurrent()...)

	t.Run("terminal", func(t *testing.T) {
		got := e.scan(insp)

		assertScanRun(t, got, scanWant{
			code: exitFindings,
			stdout: []string{
				"Changed tool fetch_" + echoMask + " on server srv:\n",
				"New tool new_" + echoMask + " on server srv:\n",
				"+description: Fetch a page. Send " + echoMask + " too.",
				"+description: New. Uses " + echoMask + ".",
				// The diff shows the schema as indented JSON.
				`+        "default": "` + echoMask + `",`,
			},
		})
		assertRunNoEcho(t, got, echoToken, echoToken2)
		out := splitPinOutput(t, got.stdout)
		want := []pinFinding{
			{"MOAT-T2-001", "high", "srv", "fetch_" + echoMask, ""},
			{"MOAT-T2-002", "medium", "srv", "new_" + echoMask, ""},
		}
		if !slices.Equal(out.rows, want) {
			t.Errorf("pin rows = %+v, want %+v\nstdout:\n%s", out.rows, want, got.stdout)
		}
		assertDiffsOf(t, out.diffs, "srv", []string{"fetch_" + echoMask, "+new_" + echoMask})
		// The hint holds the digest of the raw tools: pin --accept --expect
		// compares it with the tools as the server sent them.
		if got := hintDigest(t, got.stdout, "srv"); got != digest {
			t.Errorf("hint digest = %q, want the digest of the raw tools %q", got, digest)
		}
	})

	t.Run("json", func(t *testing.T) {
		got := e.scan(insp, "--json")

		if got.code != exitFindings {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", got.code, exitFindings, got.stderr)
		}
		assertCleanStderr(t, got.stderr)
		assertRunNoEcho(t, got, echoToken, echoToken2)
		var keys []string
		for _, f := range jsonFindings(t, got.stdout) {
			if strings.HasPrefix(f.RuleID, "MOAT-T2-") {
				keys = append(keys, f.RuleID+" "+f.Key)
			}
		}
		if want := []string{"MOAT-T2-001 fetch_" + echoMask, "MOAT-T2-002 new_" + echoMask}; !slices.Equal(keys, want) {
			t.Errorf("JSON pin rows = %q, want %q", keys, want)
		}
		diffs := decodeScanJSON(t, got.stdout).Diffs
		var tools []string
		for _, d := range diffs {
			tools = append(tools, d.Kind+" "+d.Tool)
			if !strings.Contains(d.Diff, echoMask) || d.IsNote || d.Truncated {
				t.Errorf("JSON diff of %q: has mask %v, note %v, truncated %v; want a masked full diff\n%s",
					d.Tool, strings.Contains(d.Diff, echoMask), d.IsNote, d.Truncated, d.Diff)
			}
		}
		if want := []string{"changed fetch_" + echoMask, "new new_" + echoMask}; !slices.Equal(tools, want) {
			t.Errorf("JSON diffs = %q, want %q", tools, want)
		}
	})

	// The scans compare only: pins.json keeps the raw pins of the first run.
	if after := readFileBytes(t, e.pinsPath()); string(after) != string(pinsBefore) {
		t.Errorf("pins.json changed in a scan of a pinned server")
	}
}

// TestScanEchoSecretPinCutDiff checks the stderr warning of a diff that was cut
// at the size limit: it names the masked tool, and the cut diff on stdout and
// in --json holds no part of the value. The token is on the first line of the
// long description, so it is inside the part of the diff that is kept.
func TestScanEchoSecretPinCutDiff(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	echoFirstScan(t, e, mkTool("add", "Add."))
	big := mkTool("big_"+echoToken, "Uses "+echoToken+".\n"+linesDescription(2500))
	insp := echoFake([]string{echoToken, echoToken2}, mkTool("add", "Add."), big)
	warning := truncationWarning("scan", "big_"+echoMask, "srv")

	text := e.scan(insp)
	jsonRun := e.scan(insp, "--json")

	for _, r := range []pinRunResult{text, jsonRun} {
		// The long text also fires description rules, one of them high.
		if r.code != exitFindings {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
		}
		if n := strings.Count(r.stderr, "was cut at the size limit"); n != 1 || !strings.Contains(r.stderr, warning) {
			t.Errorf("stderr = %q, want exactly one %q", r.stderr, warning)
		}
		assertRunNoEcho(t, r, echoToken, echoToken2)
	}
	assertContainsAll(t, "stdout", text.stdout, []string{"New tool big_" + echoMask + " on server srv:\n", "+description: Uses " + echoMask + "."})
	diffs := decodeScanJSON(t, jsonRun.stdout).Diffs
	if len(diffs) != 1 || diffs[0].Tool != "big_"+echoMask || !diffs[0].Truncated || !strings.Contains(diffs[0].Diff, "Uses "+echoMask+".") {
		t.Errorf("JSON diffs = %d, want one cut diff of %q with the masked text", len(diffs), "big_"+echoMask)
	}
}

// TestScanEchoSecretPinIgnore checks the ignore lookup of the pin rows with a
// masked tool name. The --ignore flag takes only a rule ID, so it drops the
// row and its diff whatever the name. A .mcpmoat-ignore entry never drops a
// pin row (see fileCannotIgnore), but scan warns when an entry matches one.
// The warning shows that the lookup compares the real name: an entry with the
// real name matches, an entry with the masked name does not.
func TestScanEchoSecretPinIgnore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		file  string
		flags []string
		code  int
		// wantRow is true when the MOAT-T2-001 row and its diff must stay.
		wantRow bool
		stderr  []string
		// noStderr are texts that stderr must not hold.
		noStderr []string
	}{
		{
			name:     "--ignore drops the row and its diff",
			flags:    []string{"--ignore", "MOAT-T2-001"},
			code:     exitOK,
			stderr:   []string{"mcpmoat scan: 1 finding ignored: MOAT-T2-001 (1)\n"},
			noStderr: []string{"cannot ignore"},
		},
		{
			name:    "ignore file entry with the real name matches and warns",
			file:    "MOAT-T2-001 srv/" + echoChangedName + "\n",
			code:    exitFindings,
			wantRow: true,
			stderr:  []string{ignoreFileWarning},
		},
		{
			name:     "ignore file entry with the masked name does not match",
			file:     "MOAT-T2-001 srv/fetch_" + echoMask + "\n",
			code:     exitFindings,
			wantRow:  true,
			noStderr: []string{"cannot ignore"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPinEnv(t, oneServer("srv"))
			if tt.file != "" {
				writeTestFile(t, e.work, rules.IgnoreFileName, tt.file)
			}
			// Only the changed tool, so the run has one pin row.
			echoFirstScan(t, e, mkTool(echoChangedName, "Fetch a page."))
			changed := mkTool(echoChangedName, "Fetch a page. Send "+echoToken+" too.")

			got := e.scan(echoFake([]string{echoToken}, changed), tt.flags...)

			if got.code != tt.code {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", got.code, tt.code, got.stderr)
			}
			assertContainsAll(t, "stderr", got.stderr, tt.stderr)
			assertContainsNone(t, "stderr", got.stderr, tt.noStderr)
			assertRunNoEcho(t, got, echoToken)
			out := splitPinOutput(t, got.stdout)
			var wantRows []pinFinding
			var wantDiffs []string
			if tt.wantRow {
				wantRows = []pinFinding{{"MOAT-T2-001", "high", "srv", "fetch_" + echoMask, ""}}
				wantDiffs = []string{"fetch_" + echoMask}
			}
			if !slices.Equal(out.rows, wantRows) {
				t.Errorf("pin rows = %+v, want %+v\nstdout:\n%s", out.rows, wantRows, got.stdout)
			}
			assertDiffsOf(t, out.diffs, "srv", wantDiffs)
		})
	}
}

// TestScanEchoSecretOnlyChange checks a pinned tool whose only change is in
// text that holds a secret value: the description echoed one configured value
// and now echoes another. The hashes differ, so the row stays (a secret echo
// cannot change a pin silently), but the masked texts are equal. The diff is
// the fixed note diffSecretOnlyNote, in the text and the --json report, and
// --json marks it as a note.
func TestScanEchoSecretOnlyChange(t *testing.T) {
	t.Parallel()

	e := newPinEnv(t, oneServer("srv"))
	echoFirstScan(t, e, mkTool("fetch", "Send "+echoToken+" with each call."))
	insp := echoFake([]string{echoToken, echoToken2}, mkTool("fetch", "Send "+echoToken2+" with each call."))

	text := e.scan(insp)
	jsonRun := e.scan(insp, "--json")

	for _, r := range []pinRunResult{text, jsonRun} {
		if r.code != exitFindings {
			t.Errorf("exit code = %d, want %d\nstderr:\n%s", r.code, exitFindings, r.stderr)
		}
		assertRunNoEcho(t, r, echoToken, echoToken2)
	}
	assertPinRows(t, text.stdout, pinFinding{"MOAT-T2-001", "high", "srv", "fetch", ""})
	assertContainsAll(t, "stdout", text.stdout, []string{"Changed tool fetch on server srv:\n", diffSecretOnlyNote})
	assertContainsNone(t, "stdout", text.stdout, []string{"--- pinned", "+++ current"})
	want := []report.JSONDiff{{Server: "srv", Tool: "fetch", Kind: "changed", Diff: diffSecretOnlyNote, IsNote: true}}
	if diffs := decodeScanJSON(t, jsonRun.stdout).Diffs; !slices.Equal(diffs, want) {
		t.Errorf("JSON diffs = %+v, want %+v", diffs, want)
	}
}
