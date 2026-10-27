package main

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
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
		ciPath: `name: CI
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
		releasePath: `name: Release
on:
  push:
    tags: ['v*']
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
` + gvTestReleaseStep + "\n", // step name on line 9, pin on line 11
		weeklyPath: `name: govulncheck
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

// gvBuild applies mutate to the good set and parses the result. mutate is a
// grMutation, the same scheme as the GoReleaser tests; nil changes nothing.
func gvBuild(t *testing.T, mutate grMutation) map[string]*workflow {
	t.Helper()
	fsys := make(fstest.MapFS)
	for p, src := range goodGovulncheckSet() {
		fsys[p] = &fstest.MapFile{Data: []byte(src)}
	}
	if mutate != nil {
		mutate(t, fsys)
	}
	return grWorkflows(t, fsys)
}

// hasFrag returns a function that reports whether a message contains frag,
// for slices.ContainsFunc.
func hasFrag(frag string) func(string) bool {
	return func(m string) bool { return strings.Contains(m, frag) }
}

func TestGovulncheckRules(t *testing.T) {
	t.Parallel()

	// A step of another job, inserted in the jobs mapping of release.yml.
	extraJob := func(job string) grMutation {
		return grReplace(releasePath, "jobs:\n  test:", "jobs:\n"+job+"\n  test:")
	}
	// A step inserted before the govulncheck step of path.
	extraStep := func(path, step string) grMutation {
		return grReplace(path, gvTestRunLine, gvTestRunLine+"\n"+step)
	}
	// The call line of release.yml replaced with run.
	releaseRun := func(run string) grMutation {
		return grReplace(releasePath, gvTestRunLine, run)
	}
	const noCall = `no step has the run value ` + gvCall
	const notAllowed = `names govulncheck, but it is not the GOVULNCHECK_VERSION pin, the call or an allowed name`
	const coe = `continue-on-error is not allowed in this file`
	const others = `the workflow names govulncheck. Only ci.yml, release.yml and govulncheck.yml may`

	tests := []struct {
		name    string
		mutate  grMutation
		want    []string // each must be in some message; empty means zero messages
		notWant []string // none may be in any message
		n       int      // when > 0, the exact number of messages
	}{
		{name: "good set gives no message"},

		// (0) A listed workflow is missing. The listed rules do not run and
		// give no message: check reports the missing file once.
		{
			name:   "ci.yml missing",
			mutate: grDelete(ciPath),
		},
		{
			name:   "release.yml missing",
			mutate: grDelete(releasePath),
		},
		{
			name: "govulncheck.yml missing, so the listed rules do not run",
			mutate: grAll(
				grDelete(weeklyPath),
				grReplace(releasePath, "v1.9.0", "v1.8.0"),
			),
		},
		{
			name: "missing listed workflow does not skip the other workflows",
			mutate: grAll(
				grDelete(ciPath),
				grSet(".github/workflows/other.yml", &fstest.MapFile{Data: []byte("name: govulncheck\non: push\njobs: {}\n")}),
			),
			want: []string{".github/workflows/other.yml:1: " + others},
			n:    1,
		},

		// (1) Pins.
		{
			name:   "ci.yml has no pin",
			mutate: grReplace(ciPath, "          GOVULNCHECK_VERSION: v1.9.0\n", ""),
			want:   []string{".github/workflows/ci.yml: the file must pin one version of govulncheck in GOVULNCHECK_VERSION (a full version such as v1.2.3), found: none"},
		},
		{
			name:   "ci.yml pins two versions",
			mutate: grReplace(ciPath, "permissions:\n", "env:\n  GOVULNCHECK_VERSION: v1.10.0\npermissions:\n"),
			want:   []string{"ci.yml: the file must pin one version of govulncheck in GOVULNCHECK_VERSION (a full version such as v1.2.3), found: v1.10.0, v1.9.0"},
			// No reference pin, so the pins of the other files are not compared.
			notWant: []string{"differs"},
		},
		{
			name:   "ci.yml pins one version twice",
			mutate: grReplace(ciPath, "permissions:\n", "env:\n  GOVULNCHECK_VERSION: v1.9.0\npermissions:\n"),
		},
		{
			name:   "ci.yml short version is not a pin",
			mutate: grReplace(ciPath, "GOVULNCHECK_VERSION: v1.9.0", "GOVULNCHECK_VERSION: v1.9"),
			want: []string{
				"ci.yml: the file must pin one version of govulncheck in GOVULNCHECK_VERSION (a full version such as v1.2.3), found: none",
				`.github/workflows/ci.yml:14: "GOVULNCHECK_VERSION" ` + notAllowed,
			},
		},
		{
			name: "pre-release version is a full version",
			mutate: grAll(
				grReplace(ciPath, "v1.9.0", "v1.9.0-rc.1+build.5"),
				grReplace(releasePath, "v1.9.0", "v1.9.0-rc.1+build.5"),
				grReplace(weeklyPath, "v1.9.0", "v1.9.0-rc.1+build.5"),
			),
		},
		{
			name:   "release.yml has no pin",
			mutate: grReplace(releasePath, "          GOVULNCHECK_VERSION: v1.9.0\n", "          OTHER: x\n"),
			want:   []string{".github/workflows/release.yml: the file has no GOVULNCHECK_VERSION pin (a full version such as v1.2.3)"},
			n:      1,
		},
		{
			name:   "govulncheck.yml has no pin",
			mutate: grReplace(weeklyPath, "          GOVULNCHECK_VERSION: v1.9.0\n", "          OTHER: x\n"),
			want:   []string{".github/workflows/govulncheck.yml: the file has no GOVULNCHECK_VERSION pin"},
			n:      1,
		},
		{
			name:   "release.yml version with a trailing newline is not a pin",
			mutate: grReplace(releasePath, "GOVULNCHECK_VERSION: v1.9.0", "GOVULNCHECK_VERSION: |\n            v1.9.0"),
			want:   []string{"release.yml: the file has no GOVULNCHECK_VERSION pin", `release.yml:11: "GOVULNCHECK_VERSION" ` + notAllowed},
		},
		{
			// The ^ anchor of fullVersion: text before the v is not a pin.
			name:    "release.yml version with text before the v is not a pin",
			mutate:  grReplace(releasePath, "GOVULNCHECK_VERSION: v1.9.0", "GOVULNCHECK_VERSION: xv1.9.0"),
			want:    []string{".github/workflows/release.yml: the file has no GOVULNCHECK_VERSION pin (a full version such as v1.2.3)", `release.yml:11: "GOVULNCHECK_VERSION" ` + notAllowed},
			notWant: []string{"differs"},
			n:       2,
		},
		{
			name:   "release.yml pin differs from ci.yml",
			mutate: grReplace(releasePath, "v1.9.0", "v1.8.0"),
			want:   []string{`.github/workflows/release.yml:11: the govulncheck pin "v1.8.0" differs from "v1.9.0", the pin in ci.yml`},
			n:      1,
		},
		{
			name:   "long pin version is cut in the message",
			mutate: grReplace(releasePath, "v1.9.0", "v1.9.0-"+strings.Repeat("a", 100<<10)),
			want:   []string{`.github/workflows/release.yml:11: the govulncheck pin "v1.9.0-` + strings.Repeat("a", 80-len("v1.9.0-")) + `"... differs from "v1.9.0", the pin in ci.yml`},
			n:      1,
		},
		{
			name:   "govulncheck.yml pin differs from ci.yml",
			mutate: grReplace(weeklyPath, "v1.9.0", "v1.9.1"),
			want:   []string{`.github/workflows/govulncheck.yml:13: the govulncheck pin "v1.9.1" differs from "v1.9.0"`},
			n:      1,
		},
		{
			name: "quoted pins are accepted",
			mutate: grAll(
				grReplace(ciPath, "GOVULNCHECK_VERSION: v1.9.0", `GOVULNCHECK_VERSION: 'v1.9.0'`),
				grReplace(releasePath, "GOVULNCHECK_VERSION: v1.9.0", `"GOVULNCHECK_VERSION": "v1.9.0"`),
			),
		},
		{
			name: "pin in the top-level env is accepted",
			mutate: grAll(
				grReplace(releasePath, "          GOVULNCHECK_VERSION: v1.9.0\n", "          OTHER: x\n"),
				grReplace(releasePath, "jobs:\n", "env:\n  GOVULNCHECK_VERSION: v1.9.0\njobs:\n"),
			),
		},

		// (2) The call: accepted forms.
		{
			name: "call with run as the first key",
			mutate: grReplace(releasePath, gvTestReleaseStep, `      - run: go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...
        name: Vulnerability check
        env:
          GOVULNCHECK_VERSION: v1.9.0`),
		},
		{
			name:   "call single quoted",
			mutate: releaseRun(`        run: 'go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...'`),
		},
		{
			name:   "call double quoted with escapes",
			mutate: releaseRun(`        run: "go run \"golang.org/x/vuln/cmd/\x67ovulncheck@$GOVULNCHECK_VERSION\" ./..."`),
		},
		{
			name:   "call in a strip block",
			mutate: releaseRun("        run: |-\n          " + gvCall),
		},
		{
			name:   "call in a flow step",
			mutate: grReplace(releasePath, gvTestReleaseStep, `      - {name: Vulnerability check, env: {GOVULNCHECK_VERSION: v1.9.0}, run: 'go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...'}`),
		},
		{
			name:   "call with a trailing comment",
			mutate: releaseRun(gvTestRunLine + " # x"),
		},

		// (2) The call: rejected forms.
		{
			name:   "call missing in release.yml",
			mutate: releaseRun("        run: go test ./..."),
			want:   []string{".github/workflows/release.yml: " + noCall},
			n:      1,
		},
		{
			name:   "call missing in ci.yml",
			mutate: grReplace(ciPath, gvTestRunLine, "        run: go test ./..."),
			want:   []string{".github/workflows/ci.yml: " + noCall},
			n:      1,
		},
		{
			name:   "call missing in govulncheck.yml",
			mutate: grReplace(weeklyPath, gvTestRunLine, "        run: go test ./..."),
			want:   []string{".github/workflows/govulncheck.yml: " + noCall},
			n:      1,
		},
		{
			name:   "call in a clip block has a trailing newline",
			mutate: releaseRun("        run: |\n          " + gvCall),
			want:   []string{"release.yml: " + noCall, `release.yml:12: "go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\" ./...\n" ` + notAllowed},
		},
		{
			name:   "call with or true",
			mutate: releaseRun(gvTestRunLine + " || true"),
			want:   []string{"release.yml: " + noCall, fmt.Sprintf("release.yml:12: %q ", gvCall+" || true") + notAllowed},
		},
		{
			name:   "call with a shell line continuation",
			mutate: releaseRun("        run: |-\n          go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\" \\\n            ./..."),
			want:   []string{"release.yml: " + noCall, "release.yml:12: "},
		},
		{
			name:   "call in a folded block has a trailing newline",
			mutate: releaseRun("        run: >\n          go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\"\n          ./..."),
			want:   []string{"release.yml: " + noCall, "release.yml:12: "},
		},
		{
			name:   "call with another version variable",
			mutate: releaseRun(`        run: go run "golang.org/x/vuln/cmd/govulncheck@$OTHER_VERSION" ./...`),
			want:   []string{"release.yml: " + noCall},
		},
		{
			name:   "call as a sequence is not a call",
			mutate: releaseRun(`        run: ['go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...']`),
			want:   []string{"release.yml: " + noCall, "release.yml:12: "},
		},

		// (2) The call: structure errors.
		{
			name:   "no jobs mapping",
			mutate: grSet(releasePath, &fstest.MapFile{Data: []byte("name: Release\non: push\nenv:\n  GOVULNCHECK_VERSION: v1.9.0\n")}),
			want:   []string{".github/workflows/release.yml:1: the workflow has no jobs mapping", "release.yml: " + noCall},
		},
		{
			name:   "jobs is not a mapping",
			mutate: grSet(releasePath, &fstest.MapFile{Data: []byte("name: Release\non: push\nenv:\n  GOVULNCHECK_VERSION: v1.9.0\njobs: []\n")}),
			want:   []string{`.github/workflows/release.yml:5: the value of "jobs" must be a mapping, found a sequence`, "release.yml: " + noCall},
		},
		{
			name:    "a job that is not a mapping does not hide the call",
			mutate:  extraJob("  broken: []"),
			want:    []string{`.github/workflows/release.yml:6: the job "broken" must be a mapping, found a sequence`},
			notWant: []string{noCall},
			n:       1,
		},
		{
			name:    "steps not a sequence",
			mutate:  extraJob("  other:\n    steps: x"),
			want:    []string{`.github/workflows/release.yml:7: the value of "steps" must be a sequence, found a scalar`},
			notWant: []string{noCall},
			n:       1,
		},
		{
			name:    "step not a mapping",
			mutate:  extraJob("  other:\n    steps:\n      - x"),
			want:    []string{`.github/workflows/release.yml:8: a step of the job "other" must be a mapping, found a scalar`},
			notWant: []string{noCall},
			n:       1,
		},
		{
			name:   "steps not a sequence in the only job hides the call",
			mutate: grSet(releasePath, &fstest.MapFile{Data: []byte("name: Release\non: push\njobs:\n  test:\n    env:\n      GOVULNCHECK_VERSION: v1.9.0\n    steps: {}\n")}),
			want:   []string{`release.yml:7: the value of "steps" must be a sequence, found a mapping`, "release.yml: " + noCall},
		},

		// (3) Names.
		{
			name:   "step name names govulncheck",
			mutate: grReplace(releasePath, "- name: Vulnerability check", "- name: Run govulncheck"),
			want:   []string{`.github/workflows/release.yml:9: "Run govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "name in another case",
			mutate: grReplace(ciPath, "- name: Vulnerability check", "- name: GoVulnCheck"),
			want:   []string{`.github/workflows/ci.yml:11: "GoVulnCheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "run line names govulncheck",
			mutate: extraStep(releasePath, "      - run: govulncheck ./..."),
			want:   []string{`.github/workflows/release.yml:13: "govulncheck ./..." ` + notAllowed},
			n:      1,
		},
		{
			name:   "uses names govulncheck",
			mutate: extraStep(ciPath, "      - uses: golang/govulncheck-action@v1"),
			want:   []string{`.github/workflows/ci.yml:16: "golang/govulncheck-action@v1" ` + notAllowed},
			n:      1,
		},
		{
			name:   "escaped name",
			mutate: extraStep(releasePath, `      - name: "\x67ovulncheck"`),
			want:   []string{`release.yml:13: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "key names govulncheck",
			mutate: extraStep(releasePath, "      - run: echo\n        env:\n          GOVULNCHECK_PATH: x"),
			want:   []string{`release.yml:15: "GOVULNCHECK_PATH" ` + notAllowed},
			n:      1,
		},
		{
			name:   "pin key in another case is not a pin",
			mutate: grReplace(releasePath, "GOVULNCHECK_VERSION: v1.9.0", "govulncheck_version: v1.9.0"),
			want:   []string{"release.yml: the file has no GOVULNCHECK_VERSION pin", `release.yml:11: "govulncheck_version" ` + notAllowed},
		},
		{
			name:   "long name is cut in the message",
			mutate: extraStep(releasePath, "      - name: govulncheck "+strings.Repeat("x", 100)),
			want:   []string{`release.yml:13: "govulncheck ` + strings.Repeat("x", 80-len("govulncheck ")) + `"... ` + notAllowed},
			n:      1,
		},

		// (3) The allow-list of govulncheck.yml, accepted only exactly.
		{
			name:   "top-level name in another case",
			mutate: grReplace(weeklyPath, "name: govulncheck\non:", "name: Govulncheck\non:"),
			want:   []string{`.github/workflows/govulncheck.yml:1: "Govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "top-level name with another value",
			mutate: grReplace(weeklyPath, "name: govulncheck\non:", "name: govulncheck weekly\non:"),
			want:   []string{`govulncheck.yml:1: "govulncheck weekly" ` + notAllowed},
			n:      1,
		},
		{
			name:   "top-level name in another file",
			mutate: grReplace(releasePath, "name: Release", "name: govulncheck"),
			want:   []string{`.github/workflows/release.yml:1: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "name govulncheck as a step name",
			mutate: grReplace(weeklyPath, "- name: Check for known vulnerabilities", "- name: govulncheck"),
			want:   []string{`govulncheck.yml:11: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name: "job ID in another case",
			mutate: grAll(
				grReplace(weeklyPath, "  govulncheck:\n", "  Govulncheck:\n"),
				grReplace(weeklyPath, "needs: govulncheck", "needs: notify"),
				grReplace(weeklyPath, "needs.govulncheck.result", "needs.notify.result"),
			),
			want: []string{`govulncheck.yml:8: "Govulncheck" ` + notAllowed},
			n:    1,
		},
		{
			name:   "job ID govulncheck in ci.yml",
			mutate: grReplace(ciPath, "  test:\n", "  govulncheck:\n"),
			want:   []string{`.github/workflows/ci.yml:7: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "job ID govulncheck as a key outside jobs",
			mutate: grReplace(weeklyPath, "permissions: {}\n", "permissions: {}\nenv:\n  govulncheck: x\n"),
			want:   []string{`govulncheck.yml:8: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "needs as a list",
			mutate: grReplace(weeklyPath, "needs: govulncheck", "needs: [govulncheck]"),
			want:   []string{`govulncheck.yml:16: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "needs with another value",
			mutate: grReplace(weeklyPath, "needs: govulncheck", "needs: Govulncheck"),
			want:   []string{`govulncheck.yml:16: "Govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "needs key in another case",
			mutate: grReplace(weeklyPath, "needs: govulncheck", "Needs: govulncheck"),
			want:   []string{`govulncheck.yml:16: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "needs govulncheck in another file",
			mutate: grReplace(releasePath, "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    needs: govulncheck\n"),
			want:   []string{`release.yml:8: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "failure if with another value",
			mutate: grReplace(weeklyPath, "== 'cancelled'", "== 'cancelled' || always()"),
			want:   []string{`govulncheck.yml:17: "failure() || needs.govulncheck.result == 'cancelled' || always()" ` + notAllowed},
			n:      1,
		},
		{
			name:   "failure if in another file",
			mutate: grReplace(releasePath, "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    if: "+gvFailureIf+"\n"),
			want:   []string{`release.yml:8: "` + gvFailureIf + `" ` + notAllowed},
			n:      1,
		},
		{
			name:   "failure if key in another case",
			mutate: grReplace(weeklyPath, "    if: failure()", "    IF: failure()"),
			want:   []string{`govulncheck.yml:17: "` + gvFailureIf + `" ` + notAllowed},
			n:      1,
		},

		// (4) continue-on-error.
		{
			name:   "continue-on-error in ci.yml",
			mutate: extraStep(ciPath, "        continue-on-error: true"),
			want:   []string{".github/workflows/ci.yml:16: " + coe},
			n:      1,
		},
		{
			name:   "continue-on-error in release.yml",
			mutate: extraStep(releasePath, "        continue-on-error: false"),
			want:   []string{".github/workflows/release.yml:13: " + coe},
			n:      1,
		},
		{
			name:   "continue-on-error in govulncheck.yml at job level",
			mutate: grReplace(weeklyPath, "    needs: govulncheck\n", "    needs: govulncheck\n    continue-on-error: true\n"),
			want:   []string{".github/workflows/govulncheck.yml:17: " + coe},
			n:      1,
		},
		{
			name:   "continue-on-error in another case",
			mutate: extraStep(releasePath, "        Continue-On-Error: true"),
			want:   []string{"release.yml:13: " + coe},
			n:      1,
		},
		{
			name:   "continue-on-error quoted with spaces",
			mutate: extraStep(releasePath, `        " continue-on-error ": true`),
			want:   []string{"release.yml:13: " + coe},
			n:      1,
		},
		{
			name:   "continue-on-error in a flow step",
			mutate: extraStep(weeklyPath, "      - {run: echo hi, CONTINUE-ON-ERROR: true}"),
			want:   []string{"govulncheck.yml:15: " + coe},
			n:      1,
		},
		{
			name:   "continue-on-error as run text is fine",
			mutate: extraStep(releasePath, "      - run: 'echo continue-on-error: true'\n      - run: |\n          continue-on-error: true"),
		},

		// (5) Another workflow names govulncheck.
		{
			name:   "other.yml names govulncheck",
			mutate: grSet(".github/workflows/other.yml", &fstest.MapFile{Data: []byte("name: Other\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: govulncheck ./...\n      - run: govulncheck -h\n")}),
			want:   []string{".github/workflows/other.yml:7: " + others},
			n:      1, // one message per file
		},
		{
			name:   "govulncheck.yaml is not govulncheck.yml",
			mutate: grSet(".github/workflows/govulncheck.yaml", &fstest.MapFile{Data: []byte("name: govulncheck\non: push\njobs: {}\n")}),
			want:   []string{".github/workflows/govulncheck.yaml:1: " + others},
			n:      1,
		},
		{
			name:   "other workflow names govulncheck in a key",
			mutate: grSet(".github/workflows/other.yml", &fstest.MapFile{Data: []byte("name: Other\non: push\nenv:\n  GOVULNCHECK_VERSION: v1.9.0\njobs: {}\n")}),
			want:   []string{".github/workflows/other.yml:4: " + others},
			n:      1,
		},

		// (6) An unknown workflow that does not name govulncheck.
		{
			name:   "unknown workflow without the name is fine",
			mutate: grSet(".github/workflows/lint.yml", &fstest.MapFile{Data: []byte("name: Lint\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: golangci-lint run\n")}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := checkGovulncheck(gvBuild(t, tt.mutate))
			if len(tt.want) == 0 && len(got) != 0 {
				t.Fatalf("checkGovulncheck() = %q, want no message", got)
			}
			for _, frag := range tt.want {
				if !slices.ContainsFunc(got, hasFrag(frag)) {
					t.Errorf("checkGovulncheck() = %q, want a message with %q", got, frag)
				}
			}
			for _, frag := range tt.notWant {
				if slices.ContainsFunc(got, hasFrag(frag)) {
					t.Errorf("checkGovulncheck() = %q, want no message with %q", got, frag)
				}
			}
			if tt.n > 0 && len(got) != tt.n {
				t.Errorf("checkGovulncheck() gave %d messages, want %d: %q", len(got), tt.n, got)
			}
		})
	}
}

func TestGovulncheckStableOrder(t *testing.T) {
	t.Parallel()
	mutations := []grMutation{
		grReplace(releasePath, "v1.9.0", "v1.8.0"),
		grReplace(ciPath, "- name: Vulnerability check", "- name: govulncheck"),
	}
	// Many other workflows, so that a random map order shows.
	var wantOthers []string
	for i := range 20 {
		p := fmt.Sprintf(".github/workflows/w%02d.yml", i)
		mutations = append(mutations, grSet(p, &fstest.MapFile{Data: []byte("name: govulncheck\non: push\njobs: {}\n")}))
		wantOthers = append(wantOthers, p)
	}
	slices.Sort(wantOthers)
	mutate := grAll(mutations...)

	first := checkGovulncheck(gvBuild(t, mutate))
	for range 5 {
		if got := checkGovulncheck(gvBuild(t, mutate)); !reflect.DeepEqual(got, first) {
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

// TestGovulncheckNilMap checks that a nil map gives no message and does not
// panic. Reading a key of a nil map is allowed in Go and gives nil.
func TestGovulncheckNilMap(t *testing.T) {
	t.Parallel()
	if got := checkGovulncheck(nil); len(got) != 0 {
		t.Errorf("checkGovulncheck(nil) = %q, want no message", got)
	}
}
