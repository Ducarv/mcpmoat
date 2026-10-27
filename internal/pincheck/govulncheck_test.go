package main

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// gvTestRunLine is the call line, as the three good workflows write it.
const gvTestRunLine = `        run: go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...`

// gvTestReleaseStep is the govulncheck step of the good release.yml.
const gvTestReleaseStep = `      - name: Vulnerability check
        env:
          GOVULNCHECK_VERSION: v1.9.0
` + gvTestRunLine

// goodGovulncheckSet returns the sources of the three listed workflows, in the
// shape of the real files in .github/workflows. They give zero messages. The
// line numbers in the comments are the ones the tests assert on.
func goodGovulncheckSet() map[string]string {
	return map[string]string{
		gvCIPath: `name: CI
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Vulnerability check
        env:
          # A comment that names govulncheck is not a node.
          GOVULNCHECK_VERSION: v1.9.0
` + gvTestRunLine + "\n", // pin on line 14, run on line 15
		gvReleasePath: `name: Release
on:
  push:
    tags: ['v*']
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
` + gvTestReleaseStep + "\n", // step name on line 9, pin on line 11
		gvWeeklyPath: `name: govulncheck
on:
  schedule:
    - cron: '17 6 * * 1'
  workflow_dispatch:
permissions: {}
jobs:
  govulncheck:
    runs-on: ubuntu-latest
    steps:
      - name: Check for known vulnerabilities
        env:
          GOVULNCHECK_VERSION: v1.9.0
` + gvTestRunLine + `
  notify-failure:
    needs: govulncheck
    if: failure() || needs.govulncheck.result == 'cancelled'
    runs-on: ubuntu-latest
    steps:
      - name: Open or update the failure issue
        run: |
          set -euo pipefail
          gh issue list --label security
`, // pin on line 13, needs on line 16
	}
}

// gvEdit changes one source of the good set. With remove, the file is gone.
// With an empty old, the file gets the text new. Else the one place of old is
// replaced with new.
type gvEdit struct {
	path, old, new string
	remove         bool
}

// mustParseGV parses src as the workflow path, and stops the test on error.
func mustParseGV(t *testing.T, path, src string) *workflow {
	t.Helper()
	w, err := parseWorkflow(path, []byte(src))
	if err != nil {
		t.Fatalf("parseWorkflow(%s) error = %v", path, err)
	}
	return w
}

// gvBuild applies edits to the good set and parses the result.
func gvBuild(t *testing.T, edits []gvEdit) map[string]*workflow {
	t.Helper()
	srcs := goodGovulncheckSet()
	for _, e := range edits {
		switch {
		case e.remove:
			delete(srcs, e.path)
		case e.old == "":
			srcs[e.path] = e.new
		default:
			// Fail on a stale edit, so that a case cannot pass because it
			// changed nothing.
			if n := strings.Count(srcs[e.path], e.old); n != 1 {
				t.Fatalf("edit of %s: old text found %d times, want 1: %q", e.path, n, e.old)
			}
			srcs[e.path] = strings.Replace(srcs[e.path], e.old, e.new, 1)
		}
	}
	wfs := make(map[string]*workflow)
	for p, src := range srcs {
		wfs[p] = mustParseGV(t, p, src)
	}
	return wfs
}

// gvHas reports whether some message contains frag.
func gvHas(msgs []string, frag string) bool {
	for _, m := range msgs {
		if strings.Contains(m, frag) {
			return true
		}
	}
	return false
}

func TestGovulncheckRules(t *testing.T) {
	t.Parallel()

	// A step of another job, inserted in the jobs mapping of release.yml.
	extraJob := func(job string) []gvEdit {
		return []gvEdit{{path: gvReleasePath, old: "jobs:\n  test:", new: "jobs:\n" + job + "\n  test:"}}
	}
	// A step inserted before the govulncheck step of path.
	extraStep := func(path, step string) []gvEdit {
		return []gvEdit{{path: path, old: gvTestRunLine, new: gvTestRunLine + "\n" + step}}
	}
	// The call line of release.yml replaced with run.
	releaseRun := func(run string) []gvEdit {
		return []gvEdit{{path: gvReleasePath, old: gvTestRunLine, new: run}}
	}
	const noCall = `no step has the run value ` + gvCall
	const notAllowed = `names govulncheck, but it is not the GOVULNCHECK_VERSION pin, the call or an allowed name`
	const coe = `continue-on-error is not allowed in this file`
	const others = `the workflow names govulncheck. Only ci.yml, release.yml and govulncheck.yml may`

	tests := []struct {
		name    string
		edits   []gvEdit
		want    []string // each must be in some message; empty means zero messages
		notWant []string // none may be in any message
		n       int      // when > 0, the exact number of messages
	}{
		{name: "good set gives no message"},

		// (0) A listed workflow is missing.
		{
			name:  "ci.yml missing",
			edits: []gvEdit{{path: gvCIPath, remove: true}},
			want:  []string{".github/workflows/ci.yml: the govulncheck check needs this workflow, but it is missing or did not parse"},
			n:     1,
		},
		{
			name:  "release.yml missing",
			edits: []gvEdit{{path: gvReleasePath, remove: true}},
			want:  []string{".github/workflows/release.yml: the govulncheck check needs this workflow"},
			n:     1,
		},
		{
			name:  "govulncheck.yml missing",
			edits: []gvEdit{{path: gvWeeklyPath, remove: true}},
			want:  []string{".github/workflows/govulncheck.yml: the govulncheck check needs this workflow"},
			n:     1,
		},
		{
			name: "missing listed workflow does not skip the other workflows",
			edits: []gvEdit{
				{path: gvCIPath, remove: true},
				{path: ".github/workflows/other.yml", new: "name: govulncheck\non: push\njobs: {}\n"},
			},
			want: []string{"ci.yml: the govulncheck check needs", ".github/workflows/other.yml:1: " + others},
			n:    2,
		},

		// (1) Pins.
		{
			name:  "ci.yml has no pin",
			edits: []gvEdit{{path: gvCIPath, old: "          GOVULNCHECK_VERSION: v1.9.0\n", new: ""}},
			want:  []string{".github/workflows/ci.yml: the file must pin one version of govulncheck in GOVULNCHECK_VERSION (a full version such as v1.2.3), found: none"},
		},
		{
			name:  "ci.yml pins two versions",
			edits: []gvEdit{{path: gvCIPath, old: "permissions:\n", new: "env:\n  GOVULNCHECK_VERSION: v1.10.0\npermissions:\n"}},
			want:  []string{"ci.yml: the file must pin one version of govulncheck in GOVULNCHECK_VERSION (a full version such as v1.2.3), found: v1.10.0, v1.9.0"},
			// No reference pin, so the pins of the other files are not compared.
			notWant: []string{"differs"},
		},
		{
			name:  "ci.yml pins one version twice",
			edits: []gvEdit{{path: gvCIPath, old: "permissions:\n", new: "env:\n  GOVULNCHECK_VERSION: v1.9.0\npermissions:\n"}},
		},
		{
			name:  "ci.yml short version is not a pin",
			edits: []gvEdit{{path: gvCIPath, old: "GOVULNCHECK_VERSION: v1.9.0", new: "GOVULNCHECK_VERSION: v1.9"}},
			want: []string{
				"ci.yml: the file must pin one version of govulncheck in GOVULNCHECK_VERSION (a full version such as v1.2.3), found: none",
				`.github/workflows/ci.yml:14: "GOVULNCHECK_VERSION" ` + notAllowed,
			},
		},
		{
			name: "pre-release version is a full version",
			edits: []gvEdit{
				{path: gvCIPath, old: "v1.9.0", new: "v1.9.0-rc.1+build.5"},
				{path: gvReleasePath, old: "v1.9.0", new: "v1.9.0-rc.1+build.5"},
				{path: gvWeeklyPath, old: "v1.9.0", new: "v1.9.0-rc.1+build.5"},
			},
		},
		{
			name:  "release.yml has no pin",
			edits: []gvEdit{{path: gvReleasePath, old: "          GOVULNCHECK_VERSION: v1.9.0\n", new: "          OTHER: x\n"}},
			want:  []string{".github/workflows/release.yml: the file has no GOVULNCHECK_VERSION pin (a full version such as v1.2.3)"},
			n:     1,
		},
		{
			name:  "govulncheck.yml has no pin",
			edits: []gvEdit{{path: gvWeeklyPath, old: "          GOVULNCHECK_VERSION: v1.9.0\n", new: "          OTHER: x\n"}},
			want:  []string{".github/workflows/govulncheck.yml: the file has no GOVULNCHECK_VERSION pin"},
			n:     1,
		},
		{
			name:  "release.yml version with a trailing newline is not a pin",
			edits: []gvEdit{{path: gvReleasePath, old: "GOVULNCHECK_VERSION: v1.9.0", new: "GOVULNCHECK_VERSION: |\n            v1.9.0"}},
			want:  []string{"release.yml: the file has no GOVULNCHECK_VERSION pin", `release.yml:11: "GOVULNCHECK_VERSION" ` + notAllowed},
		},
		{
			// The ^ anchor of gvVersionRe: text before the v is not a pin.
			name:    "release.yml version with text before the v is not a pin",
			edits:   []gvEdit{{path: gvReleasePath, old: "GOVULNCHECK_VERSION: v1.9.0", new: "GOVULNCHECK_VERSION: xv1.9.0"}},
			want:    []string{".github/workflows/release.yml: the file has no GOVULNCHECK_VERSION pin (a full version such as v1.2.3)", `release.yml:11: "GOVULNCHECK_VERSION" ` + notAllowed},
			notWant: []string{"differs"},
			n:       2,
		},
		{
			name:  "release.yml pin differs from ci.yml",
			edits: []gvEdit{{path: gvReleasePath, old: "v1.9.0", new: "v1.8.0"}},
			want:  []string{".github/workflows/release.yml:11: the govulncheck pin v1.8.0 differs from v1.9.0, the pin in ci.yml"},
			n:     1,
		},
		{
			name:  "long pin version is cut in the message",
			edits: []gvEdit{{path: gvReleasePath, old: "v1.9.0", new: "v1.9.0-" + strings.Repeat("a", 100<<10)}},
			want:  []string{".github/workflows/release.yml:11: the govulncheck pin v1.9.0-" + strings.Repeat("a", 80-len("v1.9.0-")) + "... differs from v1.9.0, the pin in ci.yml"},
			n:     1,
		},
		{
			name:  "govulncheck.yml pin differs from ci.yml",
			edits: []gvEdit{{path: gvWeeklyPath, old: "v1.9.0", new: "v1.9.1"}},
			want:  []string{".github/workflows/govulncheck.yml:13: the govulncheck pin v1.9.1 differs from v1.9.0"},
			n:     1,
		},
		{
			name: "quoted pins are accepted",
			edits: []gvEdit{
				{path: gvCIPath, old: "GOVULNCHECK_VERSION: v1.9.0", new: `GOVULNCHECK_VERSION: 'v1.9.0'`},
				{path: gvReleasePath, old: "GOVULNCHECK_VERSION: v1.9.0", new: `"GOVULNCHECK_VERSION": "v1.9.0"`},
			},
		},
		{
			name: "pin in the top-level env is accepted",
			edits: []gvEdit{
				{path: gvReleasePath, old: "          GOVULNCHECK_VERSION: v1.9.0\n", new: "          OTHER: x\n"},
				{path: gvReleasePath, old: "jobs:\n", new: "env:\n  GOVULNCHECK_VERSION: v1.9.0\njobs:\n"},
			},
		},

		// (2) The call: accepted forms.
		{
			name: "call with run as the first key",
			edits: []gvEdit{{path: gvReleasePath, old: gvTestReleaseStep, new: `      - run: go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...
        name: Vulnerability check
        env:
          GOVULNCHECK_VERSION: v1.9.0`}},
		},
		{
			name:  "call single quoted",
			edits: releaseRun(`        run: 'go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...'`),
		},
		{
			name:  "call double quoted with escapes",
			edits: releaseRun(`        run: "go run \"golang.org/x/vuln/cmd/\x67ovulncheck@$GOVULNCHECK_VERSION\" ./..."`),
		},
		{
			name:  "call in a strip block",
			edits: releaseRun("        run: |-\n          " + gvCall),
		},
		{
			name: "call in a flow step",
			edits: []gvEdit{{path: gvReleasePath, old: gvTestReleaseStep,
				new: `      - {name: Vulnerability check, env: {GOVULNCHECK_VERSION: v1.9.0}, run: 'go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...'}`}},
		},
		{
			name:  "call with a trailing comment",
			edits: releaseRun(gvTestRunLine + " # x"),
		},

		// (2) The call: rejected forms.
		{
			name:  "call missing in release.yml",
			edits: releaseRun("        run: go test ./..."),
			want:  []string{".github/workflows/release.yml: " + noCall},
			n:     1,
		},
		{
			name:  "call missing in ci.yml",
			edits: []gvEdit{{path: gvCIPath, old: gvTestRunLine, new: "        run: go test ./..."}},
			want:  []string{".github/workflows/ci.yml: " + noCall},
			n:     1,
		},
		{
			name:  "call missing in govulncheck.yml",
			edits: []gvEdit{{path: gvWeeklyPath, old: gvTestRunLine, new: "        run: go test ./..."}},
			want:  []string{".github/workflows/govulncheck.yml: " + noCall},
			n:     1,
		},
		{
			name:  "call in a clip block has a trailing newline",
			edits: releaseRun("        run: |\n          " + gvCall),
			want:  []string{"release.yml: " + noCall, `release.yml:12: "go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\" ./...\n" ` + notAllowed},
		},
		{
			name:  "call with or true",
			edits: releaseRun(gvTestRunLine + " || true"),
			want:  []string{"release.yml: " + noCall, fmt.Sprintf("release.yml:12: %q ", gvCall+" || true") + notAllowed},
		},
		{
			name:  "call with a shell line continuation",
			edits: releaseRun("        run: |-\n          go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\" \\\n            ./..."),
			want:  []string{"release.yml: " + noCall, "release.yml:12: "},
		},
		{
			name:  "call in a folded block has a trailing newline",
			edits: releaseRun("        run: >\n          go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\"\n          ./..."),
			want:  []string{"release.yml: " + noCall, "release.yml:12: "},
		},
		{
			name:  "call with another version variable",
			edits: releaseRun(`        run: go run "golang.org/x/vuln/cmd/govulncheck@$OTHER_VERSION" ./...`),
			want:  []string{"release.yml: " + noCall},
		},
		{
			name:  "call as a sequence is not a call",
			edits: releaseRun(`        run: ['go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...']`),
			want:  []string{"release.yml: " + noCall, "release.yml:12: "},
		},

		// (2) The call: structure errors.
		{
			name:  "no jobs mapping",
			edits: []gvEdit{{path: gvReleasePath, new: "name: Release\non: push\nenv:\n  GOVULNCHECK_VERSION: v1.9.0\n"}},
			want:  []string{".github/workflows/release.yml:1: the workflow has no jobs mapping", "release.yml: " + noCall},
		},
		{
			name:  "jobs is not a mapping",
			edits: []gvEdit{{path: gvReleasePath, new: "name: Release\non: push\nenv:\n  GOVULNCHECK_VERSION: v1.9.0\njobs: []\n"}},
			want:  []string{`.github/workflows/release.yml:5: the value of "jobs" must be a mapping, found a sequence`, "release.yml: " + noCall},
		},
		{
			name:    "a job that is not a mapping does not hide the call",
			edits:   extraJob("  broken: []"),
			want:    []string{`.github/workflows/release.yml:6: the job "broken" must be a mapping, found a sequence`},
			notWant: []string{noCall},
			n:       1,
		},
		{
			name:    "steps not a sequence",
			edits:   extraJob("  other:\n    steps: x"),
			want:    []string{`.github/workflows/release.yml:7: the value of "steps" must be a sequence, found a scalar`},
			notWant: []string{noCall},
			n:       1,
		},
		{
			name:    "step not a mapping",
			edits:   extraJob("  other:\n    steps:\n      - x"),
			want:    []string{`.github/workflows/release.yml:8: a step of the job "other" must be a mapping, found a scalar`},
			notWant: []string{noCall},
			n:       1,
		},
		{
			name:  "steps not a sequence in the only job hides the call",
			edits: []gvEdit{{path: gvReleasePath, new: "name: Release\non: push\njobs:\n  test:\n    env:\n      GOVULNCHECK_VERSION: v1.9.0\n    steps: {}\n"}},
			want:  []string{`release.yml:7: the value of "steps" must be a sequence, found a mapping`, "release.yml: " + noCall},
		},

		// (3) Names.
		{
			name:  "step name names govulncheck",
			edits: []gvEdit{{path: gvReleasePath, old: "- name: Vulnerability check", new: "- name: Run govulncheck"}},
			want:  []string{`.github/workflows/release.yml:9: "Run govulncheck" ` + notAllowed},
			n:     1,
		},
		{
			name:  "name in another case",
			edits: []gvEdit{{path: gvCIPath, old: "- name: Vulnerability check", new: "- name: GoVulnCheck"}},
			want:  []string{`.github/workflows/ci.yml:11: "GoVulnCheck" ` + notAllowed},
			n:     1,
		},
		{
			name:  "run line names govulncheck",
			edits: extraStep(gvReleasePath, "      - run: govulncheck ./..."),
			want:  []string{`.github/workflows/release.yml:13: "govulncheck ./..." ` + notAllowed},
			n:     1,
		},
		{
			name:  "uses names govulncheck",
			edits: extraStep(gvCIPath, "      - uses: golang/govulncheck-action@v1"),
			want:  []string{`.github/workflows/ci.yml:16: "golang/govulncheck-action@v1" ` + notAllowed},
			n:     1,
		},
		{
			name:  "escaped name",
			edits: extraStep(gvReleasePath, `      - name: "\x67ovulncheck"`),
			want:  []string{`release.yml:13: "govulncheck" ` + notAllowed},
			n:     1,
		},
		{
			name:  "key names govulncheck",
			edits: extraStep(gvReleasePath, "      - run: echo\n        env:\n          GOVULNCHECK_PATH: x"),
			want:  []string{`release.yml:15: "GOVULNCHECK_PATH" ` + notAllowed},
			n:     1,
		},
		{
			name:  "pin key in another case is not a pin",
			edits: []gvEdit{{path: gvReleasePath, old: "GOVULNCHECK_VERSION: v1.9.0", new: "govulncheck_version: v1.9.0"}},
			want:  []string{"release.yml: the file has no GOVULNCHECK_VERSION pin", `release.yml:11: "govulncheck_version" ` + notAllowed},
		},
		{
			name:  "long name is cut in the message",
			edits: extraStep(gvReleasePath, "      - name: govulncheck "+strings.Repeat("x", 100)),
			want:  []string{`release.yml:13: "govulncheck ` + strings.Repeat("x", 80-len("govulncheck ")) + `"... ` + notAllowed},
			n:     1,
		},

		// (3) The allow-list of govulncheck.yml, accepted only exactly.
		{
			name:  "top-level name in another case",
			edits: []gvEdit{{path: gvWeeklyPath, old: "name: govulncheck\non:", new: "name: Govulncheck\non:"}},
			want:  []string{`.github/workflows/govulncheck.yml:1: "Govulncheck" ` + notAllowed},
			n:     1,
		},
		{
			name:  "top-level name with another value",
			edits: []gvEdit{{path: gvWeeklyPath, old: "name: govulncheck\non:", new: "name: govulncheck weekly\non:"}},
			want:  []string{`govulncheck.yml:1: "govulncheck weekly" ` + notAllowed},
			n:     1,
		},
		{
			name:  "top-level name in another file",
			edits: []gvEdit{{path: gvReleasePath, old: "name: Release", new: "name: govulncheck"}},
			want:  []string{`.github/workflows/release.yml:1: "govulncheck" ` + notAllowed},
			n:     1,
		},
		{
			name:  "name govulncheck as a step name",
			edits: []gvEdit{{path: gvWeeklyPath, old: "- name: Check for known vulnerabilities", new: "- name: govulncheck"}},
			want:  []string{`govulncheck.yml:11: "govulncheck" ` + notAllowed},
			n:     1,
		},
		{
			name: "job ID in another case",
			edits: []gvEdit{
				{path: gvWeeklyPath, old: "  govulncheck:\n", new: "  Govulncheck:\n"},
				{path: gvWeeklyPath, old: "needs: govulncheck", new: "needs: notify"},
				{path: gvWeeklyPath, old: "needs.govulncheck.result", new: "needs.notify.result"},
			},
			want: []string{`govulncheck.yml:8: "Govulncheck" ` + notAllowed},
			n:    1,
		},
		{
			name:  "job ID govulncheck in ci.yml",
			edits: []gvEdit{{path: gvCIPath, old: "  test:\n", new: "  govulncheck:\n"}},
			want:  []string{`.github/workflows/ci.yml:7: "govulncheck" ` + notAllowed},
			n:     1,
		},
		{
			name:  "job ID govulncheck as a key outside jobs",
			edits: []gvEdit{{path: gvWeeklyPath, old: "permissions: {}\n", new: "permissions: {}\nenv:\n  govulncheck: x\n"}},
			want:  []string{`govulncheck.yml:8: "govulncheck" ` + notAllowed},
			n:     1,
		},
		{
			name:  "needs as a list",
			edits: []gvEdit{{path: gvWeeklyPath, old: "needs: govulncheck", new: "needs: [govulncheck]"}},
			want:  []string{`govulncheck.yml:16: "govulncheck" ` + notAllowed},
			n:     1,
		},
		{
			name:  "needs with another value",
			edits: []gvEdit{{path: gvWeeklyPath, old: "needs: govulncheck", new: "needs: Govulncheck"}},
			want:  []string{`govulncheck.yml:16: "Govulncheck" ` + notAllowed},
			n:     1,
		},
		{
			name:  "needs key in another case",
			edits: []gvEdit{{path: gvWeeklyPath, old: "needs: govulncheck", new: "Needs: govulncheck"}},
			want:  []string{`govulncheck.yml:16: "govulncheck" ` + notAllowed},
			n:     1,
		},
		{
			name:  "needs govulncheck in another file",
			edits: []gvEdit{{path: gvReleasePath, old: "    runs-on: ubuntu-latest\n", new: "    runs-on: ubuntu-latest\n    needs: govulncheck\n"}},
			want:  []string{`release.yml:8: "govulncheck" ` + notAllowed},
			n:     1,
		},
		{
			name:  "failure if with another value",
			edits: []gvEdit{{path: gvWeeklyPath, old: "== 'cancelled'", new: "== 'cancelled' || always()"}},
			want:  []string{`govulncheck.yml:17: "failure() || needs.govulncheck.result == 'cancelled' || always()" ` + notAllowed},
			n:     1,
		},
		{
			name:  "failure if in another file",
			edits: []gvEdit{{path: gvReleasePath, old: "    runs-on: ubuntu-latest\n", new: "    runs-on: ubuntu-latest\n    if: " + gvFailureIf + "\n"}},
			want:  []string{`release.yml:8: "` + gvFailureIf + `" ` + notAllowed},
			n:     1,
		},
		{
			name:  "failure if key in another case",
			edits: []gvEdit{{path: gvWeeklyPath, old: "    if: failure()", new: "    IF: failure()"}},
			want:  []string{`govulncheck.yml:17: "` + gvFailureIf + `" ` + notAllowed},
			n:     1,
		},

		// (4) continue-on-error.
		{
			name:  "continue-on-error in ci.yml",
			edits: extraStep(gvCIPath, "        continue-on-error: true"),
			want:  []string{".github/workflows/ci.yml:16: " + coe},
			n:     1,
		},
		{
			name:  "continue-on-error in release.yml",
			edits: extraStep(gvReleasePath, "        continue-on-error: false"),
			want:  []string{".github/workflows/release.yml:13: " + coe},
			n:     1,
		},
		{
			name:  "continue-on-error in govulncheck.yml at job level",
			edits: []gvEdit{{path: gvWeeklyPath, old: "    needs: govulncheck\n", new: "    needs: govulncheck\n    continue-on-error: true\n"}},
			want:  []string{".github/workflows/govulncheck.yml:17: " + coe},
			n:     1,
		},
		{
			name:  "continue-on-error in another case",
			edits: extraStep(gvReleasePath, "        Continue-On-Error: true"),
			want:  []string{"release.yml:13: " + coe},
			n:     1,
		},
		{
			name:  "continue-on-error quoted with spaces",
			edits: extraStep(gvReleasePath, `        " continue-on-error ": true`),
			want:  []string{"release.yml:13: " + coe},
			n:     1,
		},
		{
			name:  "continue-on-error in a flow step",
			edits: extraStep(gvWeeklyPath, "      - {run: echo hi, CONTINUE-ON-ERROR: true}"),
			want:  []string{"govulncheck.yml:15: " + coe},
			n:     1,
		},
		{
			name:  "continue-on-error as run text is fine",
			edits: extraStep(gvReleasePath, "      - run: 'echo continue-on-error: true'\n      - run: |\n          continue-on-error: true"),
		},

		// (5) Another workflow names govulncheck.
		{
			name:  "other.yml names govulncheck",
			edits: []gvEdit{{path: ".github/workflows/other.yml", new: "name: Other\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: govulncheck ./...\n      - run: govulncheck -h\n"}},
			want:  []string{".github/workflows/other.yml:7: " + others},
			n:     1, // one message per file
		},
		{
			name:  "govulncheck.yaml is not govulncheck.yml",
			edits: []gvEdit{{path: ".github/workflows/govulncheck.yaml", new: "name: govulncheck\non: push\njobs: {}\n"}},
			want:  []string{".github/workflows/govulncheck.yaml:1: " + others},
			n:     1,
		},
		{
			name:  "other workflow names govulncheck in a key",
			edits: []gvEdit{{path: ".github/workflows/other.yml", new: "name: Other\non: push\nenv:\n  GOVULNCHECK_VERSION: v1.9.0\njobs: {}\n"}},
			want:  []string{".github/workflows/other.yml:4: " + others},
			n:     1,
		},

		// (6) An unknown workflow that does not name govulncheck.
		{
			name:  "unknown workflow without the name is fine",
			edits: []gvEdit{{path: ".github/workflows/lint.yml", new: "name: Lint\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: golangci-lint run\n"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := checkGovulncheck(nil, gvBuild(t, tt.edits))
			if len(tt.want) == 0 && len(got) != 0 {
				t.Fatalf("checkGovulncheck() = %q, want no message", got)
			}
			for _, frag := range tt.want {
				if !gvHas(got, frag) {
					t.Errorf("checkGovulncheck() = %q, want a message with %q", got, frag)
				}
			}
			for _, frag := range tt.notWant {
				if gvHas(got, frag) {
					t.Errorf("checkGovulncheck() = %q, want no message with %q", got, frag)
				}
			}
			if tt.n > 0 && len(got) != tt.n {
				t.Errorf("checkGovulncheck() gave %d messages, want %d: %q", len(got), tt.n, got)
			}
		})
	}
}

func TestGovulncheckRealWorkflows(t *testing.T) {
	t.Parallel()
	wfs, problems := loadWorkflows(os.DirFS("../.."))
	if len(problems) != 0 {
		t.Fatalf("loadWorkflows() problems = %q", problems)
	}
	for _, p := range gvListedPaths() {
		if wfs[p] == nil {
			t.Fatalf("loadWorkflows() has no %s", p)
		}
	}
	if got := checkGovulncheck(nil, wfs); len(got) != 0 {
		t.Errorf("checkGovulncheck(real workflows) = %q, want no message", got)
	}
}

func TestGovulncheckStableOrder(t *testing.T) {
	t.Parallel()
	edits := []gvEdit{
		{path: gvReleasePath, old: "v1.9.0", new: "v1.8.0"},
		{path: gvCIPath, old: "- name: Vulnerability check", new: "- name: govulncheck"},
	}
	// Many other workflows, so that a random map order shows.
	var wantOthers []string
	for i := range 20 {
		p := fmt.Sprintf(".github/workflows/w%02d.yml", i)
		edits = append(edits, gvEdit{path: p, new: "name: govulncheck\non: push\njobs: {}\n"})
		wantOthers = append(wantOthers, p)
	}
	sort.Strings(wantOthers)

	first := checkGovulncheck(nil, gvBuild(t, edits))
	for range 5 {
		if got := checkGovulncheck(nil, gvBuild(t, edits)); !reflect.DeepEqual(got, first) {
			t.Fatalf("checkGovulncheck() order changed:\n%q\n%q", first, got)
		}
	}
	var gotOthers []string
	for _, m := range first {
		if p, _, ok := strings.Cut(m, ":1: the workflow names govulncheck"); ok {
			gotOthers = append(gotOthers, p)
		}
	}
	if !reflect.DeepEqual(gotOthers, wantOthers) {
		t.Errorf("other workflow messages in order %q, want %q", gotOthers, wantOthers)
	}
}

func TestGovulncheckNilInputs(t *testing.T) {
	t.Parallel()
	missing := func(p string) string {
		return p + ": the govulncheck check needs this workflow, but it is missing or did not parse"
	}
	tests := []struct {
		name string
		edit func(wfs map[string]*workflow) map[string]*workflow
		want []string
	}{
		{
			name: "nil map",
			edit: func(map[string]*workflow) map[string]*workflow { return nil },
			want: []string{missing(gvCIPath), missing(gvReleasePath), missing(gvWeeklyPath)},
		},
		{
			name: "nil listed workflow",
			edit: func(wfs map[string]*workflow) map[string]*workflow { wfs[gvCIPath] = nil; return wfs },
			want: []string{missing(gvCIPath)},
		},
		{
			name: "listed workflow with nil top",
			edit: func(wfs map[string]*workflow) map[string]*workflow {
				wfs[gvWeeklyPath] = &workflow{file: gvWeeklyPath}
				return wfs
			},
			want: []string{missing(gvWeeklyPath)},
		},
		{
			name: "nil and empty other workflows",
			edit: func(wfs map[string]*workflow) map[string]*workflow {
				wfs[".github/workflows/a.yml"] = nil
				wfs[".github/workflows/b.yml"] = &workflow{file: ".github/workflows/b.yml"}
				return wfs
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := checkGovulncheck(nil, tt.edit(gvBuild(t, nil)))
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checkGovulncheck() = %q, want %q", got, tt.want)
			}
		})
	}
}
