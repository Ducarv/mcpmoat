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
// mutation from helpers_test.go; nil changes nothing.
func gvBuild(t *testing.T, mutate mutation) map[string]*workflow {
	t.Helper()
	fsys := make(fstest.MapFS)
	for p, src := range goodGovulncheckSet() {
		fsys[p] = &fstest.MapFile{Data: []byte(src)}
	}
	if mutate != nil {
		mutate(t, fsys)
	}
	return parseWorkflows(t, fsys)
}

// hasFrag returns a function that reports whether a message contains frag,
// for slices.ContainsFunc.
func hasFrag(frag string) func(string) bool {
	return func(m string) bool { return strings.Contains(m, frag) }
}

func TestGovulncheckRules(t *testing.T) {
	t.Parallel()

	// A step of another job, inserted in the jobs mapping of release.yml.
	extraJob := func(job string) mutation {
		return replaceOnce(releasePath, "jobs:\n  test:", "jobs:\n"+job+"\n  test:")
	}
	// A step inserted after the call line of the govulncheck step of path.
	extraStep := func(path, step string) mutation {
		return replaceOnce(path, gvTestRunLine, gvTestRunLine+"\n"+step)
	}
	// The call line of release.yml replaced with run.
	releaseRun := func(run string) mutation {
		return replaceOnce(releasePath, gvTestRunLine, run)
	}
	const noCall = `no step has the run value ` + gvCall
	const notAllowed = `names govulncheck, but it is not the GOVULNCHECK_VERSION pin, the call or an allowed name`
	const coe = `continue-on-error is not allowed in this file`
	const others = `the workflow names govulncheck. Only ci.yml, release.yml and govulncheck.yml may`
	// jobCall is the message when the job govulncheck of govulncheck.yml, which
	// notify-failure waits for, does not run the call. Its key is on line 8.
	const jobCall = `.github/workflows/govulncheck.yml:8: the job "govulncheck" must run the govulncheck call: notify-failure waits for it`
	// jobMissing is the message when govulncheck.yml has no job govulncheck.
	const jobMissing = `.github/workflows/govulncheck.yml: the job "govulncheck" is missing: notify-failure waits for it`
	// jobIf is the message for a job-level if: key of the job job, which runs
	// the call, in the file p at the line line.
	jobIf := func(p string, line int, job string) string {
		return fmt.Sprintf(`%s:%d: the job %q runs govulncheck, so it must not have a job-level if: a skipped job would hide a vulnerability`, p, line, job)
	}
	// jobNeeds is the message for a job-level needs: key of the job job, which
	// runs the call, in the file p at the line line.
	jobNeeds := func(p string, line int, job string) string {
		return fmt.Sprintf(`%s:%d: the job %q runs govulncheck, so it must not have a job-level needs: a skipped job it waits for would skip the scan too`, p, line, job)
	}

	tests := []struct {
		name    string
		mutate  mutation
		want    []string // each must be in some message; empty means zero messages
		notWant []string // none may be in any message
		n       int      // when > 0, the exact number of messages
	}{
		{name: "good set gives no message"},

		// (0) A listed workflow is missing. The listed rules do not run and
		// give no message: check reports the missing file once.
		{
			name:   "ci.yml missing",
			mutate: deleteFile(ciPath),
		},
		{
			name:   "release.yml missing",
			mutate: deleteFile(releasePath),
		},
		{
			name: "govulncheck.yml missing, so the listed rules do not run",
			mutate: applyAll(
				deleteFile(weeklyPath),
				replaceOnce(releasePath, "v1.9.0", "v1.8.0"),
			),
		},
		{
			name: "missing listed workflow does not skip the other workflows",
			mutate: applyAll(
				deleteFile(ciPath),
				setFile(".github/workflows/other.yml", &fstest.MapFile{Data: []byte("name: govulncheck\non: push\njobs: {}\n")}),
			),
			want: []string{".github/workflows/other.yml:1: " + others},
			n:    1,
		},

		// (1) Pins.
		{
			name:   "ci.yml has no pin",
			mutate: replaceOnce(ciPath, "          GOVULNCHECK_VERSION: v1.9.0\n", ""),
			want:   []string{".github/workflows/ci.yml: the file must pin one version of govulncheck in GOVULNCHECK_VERSION (a full version such as v1.2.3), found: none"},
		},
		{
			name:   "ci.yml pins two versions",
			mutate: replaceOnce(ciPath, "permissions:\n", "env:\n  GOVULNCHECK_VERSION: v1.10.0\npermissions:\n"),
			want:   []string{"ci.yml: the file must pin one version of govulncheck in GOVULNCHECK_VERSION (a full version such as v1.2.3), found: v1.10.0, v1.9.0"},
			// No reference pin, so the pins of the other files are not compared.
			notWant: []string{"differs"},
		},
		{
			name:   "ci.yml pins one version twice",
			mutate: replaceOnce(ciPath, "permissions:\n", "env:\n  GOVULNCHECK_VERSION: v1.9.0\npermissions:\n"),
		},
		{
			name:   "ci.yml short version is not a pin",
			mutate: replaceOnce(ciPath, "GOVULNCHECK_VERSION: v1.9.0", "GOVULNCHECK_VERSION: v1.9"),
			want: []string{
				"ci.yml: the file must pin one version of govulncheck in GOVULNCHECK_VERSION (a full version such as v1.2.3), found: none",
				`.github/workflows/ci.yml:14: "GOVULNCHECK_VERSION" ` + notAllowed,
			},
		},
		{
			name: "pre-release version is a full version",
			mutate: applyAll(
				replaceOnce(ciPath, "v1.9.0", "v1.9.0-rc.1+build.5"),
				replaceOnce(releasePath, "v1.9.0", "v1.9.0-rc.1+build.5"),
				replaceOnce(weeklyPath, "v1.9.0", "v1.9.0-rc.1+build.5"),
			),
		},
		{
			name:   "release.yml has no pin",
			mutate: replaceOnce(releasePath, "          GOVULNCHECK_VERSION: v1.9.0\n", "          OTHER: x\n"),
			want:   []string{".github/workflows/release.yml: the file has no GOVULNCHECK_VERSION pin (a full version such as v1.2.3)"},
			n:      1,
		},
		{
			name:   "govulncheck.yml has no pin",
			mutate: replaceOnce(weeklyPath, "          GOVULNCHECK_VERSION: v1.9.0\n", "          OTHER: x\n"),
			want:   []string{".github/workflows/govulncheck.yml: the file has no GOVULNCHECK_VERSION pin"},
			n:      1,
		},
		{
			name:   "release.yml version with a trailing newline is not a pin",
			mutate: replaceOnce(releasePath, "GOVULNCHECK_VERSION: v1.9.0", "GOVULNCHECK_VERSION: |\n            v1.9.0"),
			want:   []string{"release.yml: the file has no GOVULNCHECK_VERSION pin", `release.yml:11: "GOVULNCHECK_VERSION" ` + notAllowed},
		},
		{
			// The ^ anchor of fullVersion: text before the v is not a pin.
			name:    "release.yml version with text before the v is not a pin",
			mutate:  replaceOnce(releasePath, "GOVULNCHECK_VERSION: v1.9.0", "GOVULNCHECK_VERSION: xv1.9.0"),
			want:    []string{".github/workflows/release.yml: the file has no GOVULNCHECK_VERSION pin (a full version such as v1.2.3)", `release.yml:11: "GOVULNCHECK_VERSION" ` + notAllowed},
			notWant: []string{"differs"},
			n:       2,
		},
		{
			name:   "release.yml pin differs from ci.yml",
			mutate: replaceOnce(releasePath, "v1.9.0", "v1.8.0"),
			want:   []string{`.github/workflows/release.yml:11: the govulncheck pin "v1.8.0" differs from "v1.9.0", the pin in ci.yml`},
			n:      1,
		},
		{
			name:   "long pin version is cut in the message",
			mutate: replaceOnce(releasePath, "v1.9.0", "v1.9.0-"+strings.Repeat("a", 100<<10)),
			want:   []string{`.github/workflows/release.yml:11: the govulncheck pin "v1.9.0-` + strings.Repeat("a", 80-len("v1.9.0-")) + `"... differs from "v1.9.0", the pin in ci.yml`},
			n:      1,
		},
		{
			name:   "govulncheck.yml pin differs from ci.yml",
			mutate: replaceOnce(weeklyPath, "v1.9.0", "v1.9.1"),
			want:   []string{`.github/workflows/govulncheck.yml:13: the govulncheck pin "v1.9.1" differs from "v1.9.0"`},
			n:      1,
		},
		{
			name: "quoted pins are accepted",
			mutate: applyAll(
				replaceOnce(ciPath, "GOVULNCHECK_VERSION: v1.9.0", `GOVULNCHECK_VERSION: 'v1.9.0'`),
				replaceOnce(releasePath, "GOVULNCHECK_VERSION: v1.9.0", `"GOVULNCHECK_VERSION": "v1.9.0"`),
			),
		},
		{
			name: "pin in the top-level env is accepted",
			mutate: applyAll(
				replaceOnce(releasePath, "          GOVULNCHECK_VERSION: v1.9.0\n", "          OTHER: x\n"),
				replaceOnce(releasePath, "jobs:\n", "env:\n  GOVULNCHECK_VERSION: v1.9.0\njobs:\n"),
			),
		},

		// (2) The call: accepted forms.
		{
			name: "call with run as the first key",
			mutate: replaceOnce(releasePath, gvTestReleaseStep, `      - run: go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...
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
			mutate: replaceOnce(releasePath, gvTestReleaseStep, `      - {name: Vulnerability check, env: {GOVULNCHECK_VERSION: v1.9.0}, run: 'go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...'}`),
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
			mutate: replaceOnce(ciPath, gvTestRunLine, "        run: go test ./..."),
			want:   []string{".github/workflows/ci.yml: " + noCall},
			n:      1,
		},
		{
			name:   "call missing in govulncheck.yml",
			mutate: replaceOnce(weeklyPath, gvTestRunLine, "        run: go test ./..."),
			want:   []string{".github/workflows/govulncheck.yml: " + noCall, jobCall},
			n:      2,
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

		// (2) The keys steps and run are read with their exact case, as GitHub
		// reads them. A call under the key Run is not a call, and a job under
		// the key Steps has no steps. The name rule still reports the text.
		{
			name:   "run key with another case in ci.yml",
			mutate: replaceOnce(ciPath, gvTestRunLine, `        Run: go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...`),
			want:   []string{".github/workflows/ci.yml: " + noCall, `.github/workflows/ci.yml:15: "go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\" ./..." ` + notAllowed},
			n:      2,
		},
		{
			name:   "run key with another case in release.yml",
			mutate: releaseRun(`        Run: go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...`),
			want:   []string{".github/workflows/release.yml: " + noCall, `.github/workflows/release.yml:12: "go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\" ./..." ` + notAllowed},
			n:      2,
		},
		{
			name:   "run key with another case in govulncheck.yml",
			mutate: replaceOnce(weeklyPath, gvTestRunLine, `        Run: go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...`),
			want:   []string{".github/workflows/govulncheck.yml: " + noCall, `.github/workflows/govulncheck.yml:14: "go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\" ./..." ` + notAllowed, jobCall},
			n:      3,
		},
		{
			name:   "steps key with another case in ci.yml",
			mutate: replaceOnce(ciPath, "    steps:\n", "    Steps:\n"),
			want:   []string{".github/workflows/ci.yml: " + noCall, `.github/workflows/ci.yml:15: "go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\" ./..." ` + notAllowed},
			n:      2,
		},
		{
			name:   "steps key with another case in release.yml",
			mutate: replaceOnce(releasePath, "    steps:\n", "    Steps:\n"),
			want:   []string{".github/workflows/release.yml: " + noCall, `.github/workflows/release.yml:12: "go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\" ./..." ` + notAllowed},
			n:      2,
		},
		{
			name:   "steps key with another case in govulncheck.yml",
			mutate: replaceOnce(weeklyPath, "  govulncheck:\n    runs-on: ubuntu-latest\n    steps:\n", "  govulncheck:\n    runs-on: ubuntu-latest\n    Steps:\n"),
			want:   []string{".github/workflows/govulncheck.yml: " + noCall, `.github/workflows/govulncheck.yml:14: "go run \"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION\" ./..." ` + notAllowed, jobCall},
			n:      3,
		},
		{
			// A job under the key Steps has no steps, so its scalar is not read as
			// steps and gives no message. The job runs no call, so no rule reads it.
			name:   "Steps key with a scalar is not read as steps",
			mutate: extraJob("  other:\n    Steps: x"),
		},

		// (2) The call: structure errors.
		{
			name:   "no jobs mapping",
			mutate: setFile(releasePath, &fstest.MapFile{Data: []byte("name: Release\non: push\nenv:\n  GOVULNCHECK_VERSION: v1.9.0\n")}),
			want:   []string{".github/workflows/release.yml:1: the workflow has no jobs mapping", "release.yml: " + noCall},
		},
		{
			name:   "jobs is not a mapping",
			mutate: setFile(releasePath, &fstest.MapFile{Data: []byte("name: Release\non: push\nenv:\n  GOVULNCHECK_VERSION: v1.9.0\njobs: []\n")}),
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
			mutate: setFile(releasePath, &fstest.MapFile{Data: []byte("name: Release\non: push\njobs:\n  test:\n    env:\n      GOVULNCHECK_VERSION: v1.9.0\n    steps: {}\n")}),
			want:   []string{`release.yml:7: the value of "steps" must be a sequence, found a mapping`, "release.yml: " + noCall},
		},

		// (3) Names.
		{
			name:   "step name names govulncheck",
			mutate: replaceOnce(releasePath, "- name: Vulnerability check", "- name: Run govulncheck"),
			want:   []string{`.github/workflows/release.yml:9: "Run govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "name in another case",
			mutate: replaceOnce(ciPath, "- name: Vulnerability check", "- name: GoVulnCheck"),
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
			mutate: replaceOnce(releasePath, "GOVULNCHECK_VERSION: v1.9.0", "govulncheck_version: v1.9.0"),
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
			mutate: replaceOnce(weeklyPath, "name: govulncheck\non:", "name: Govulncheck\non:"),
			want:   []string{`.github/workflows/govulncheck.yml:1: "Govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "top-level name with another value",
			mutate: replaceOnce(weeklyPath, "name: govulncheck\non:", "name: govulncheck weekly\non:"),
			want:   []string{`govulncheck.yml:1: "govulncheck weekly" ` + notAllowed},
			n:      1,
		},
		{
			name:   "top-level name in another file",
			mutate: replaceOnce(releasePath, "name: Release", "name: govulncheck"),
			want:   []string{`.github/workflows/release.yml:1: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "name govulncheck as a step name",
			mutate: replaceOnce(weeklyPath, "- name: Check for known vulnerabilities", "- name: govulncheck"),
			want:   []string{`govulncheck.yml:11: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name: "job ID in another case",
			mutate: applyAll(
				replaceOnce(weeklyPath, "  govulncheck:\n", "  Govulncheck:\n"),
				replaceOnce(weeklyPath, "needs: govulncheck", "needs: notify"),
				replaceOnce(weeklyPath, "needs.govulncheck.result", "needs.notify.result"),
			),
			want: []string{`govulncheck.yml:8: "Govulncheck" ` + notAllowed, jobMissing},
			n:    2,
		},
		{
			// notify-failure waits for the job govulncheck. The job that runs the
			// call is scan, and the job govulncheck runs nothing: the rule reports it.
			name: "call moved to job scan, job govulncheck runs nothing",
			mutate: applyAll(
				replaceOnce(weeklyPath, "  govulncheck:\n    runs-on: ubuntu-latest\n", "  scan:\n    runs-on: ubuntu-latest\n"),
				replaceOnce(weeklyPath, "  notify-failure:\n", "  govulncheck:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo nothing\n  notify-failure:\n"),
			),
			want: []string{`.github/workflows/govulncheck.yml:15: the job "govulncheck" must run the govulncheck call: notify-failure waits for it`},
			n:    1,
		},
		{
			// The positive twin of the case above: the job govulncheck runs the
			// call after another step, so the rule passes.
			name:   "job govulncheck runs the call after another step",
			mutate: replaceOnce(weeklyPath, "      - name: Check for known vulnerabilities\n", "      - run: echo start\n      - name: Check for known vulnerabilities\n"),
		},
		{
			name:   "no job named govulncheck in govulncheck.yml",
			mutate: replaceOnce(weeklyPath, "  govulncheck:\n    runs-on: ubuntu-latest\n", "  scan:\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobMissing},
			n:      1,
		},
		{
			// The rule is for govulncheck.yml only. A job scan that runs the call
			// is fine in ci.yml and release.yml, which have no job govulncheck.
			name: "job scan runs the call in ci.yml and release.yml, no job govulncheck",
			mutate: applyAll(
				replaceOnce(ciPath, "  test:\n", "  scan:\n"),
				replaceOnce(releasePath, "  test:\n", "  scan:\n"),
			),
		},
		{
			name:   "job ID govulncheck in ci.yml",
			mutate: replaceOnce(ciPath, "  test:\n", "  govulncheck:\n"),
			want:   []string{`.github/workflows/ci.yml:7: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "job ID govulncheck as a key outside jobs",
			mutate: replaceOnce(weeklyPath, "permissions: {}\n", "permissions: {}\nenv:\n  govulncheck: x\n"),
			want:   []string{`govulncheck.yml:8: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "needs as a list",
			mutate: replaceOnce(weeklyPath, "needs: govulncheck", "needs: [govulncheck]"),
			want:   []string{`govulncheck.yml:16: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "needs with another value",
			mutate: replaceOnce(weeklyPath, "needs: govulncheck", "needs: Govulncheck"),
			want:   []string{`govulncheck.yml:16: "Govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			name:   "needs key in another case",
			mutate: replaceOnce(weeklyPath, "needs: govulncheck", "Needs: govulncheck"),
			want:   []string{`govulncheck.yml:16: "govulncheck" ` + notAllowed},
			n:      1,
		},
		{
			// The job test of release.yml runs the call, so its needs: is also a
			// problem (see section 4c). That gives two messages.
			name:   "needs govulncheck in another file",
			mutate: replaceOnce(releasePath, "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    needs: govulncheck\n"),
			want:   []string{`release.yml:8: "govulncheck" ` + notAllowed, jobNeeds(releasePath, 8, "test")},
			n:      2,
		},
		{
			name:   "failure if with another value",
			mutate: replaceOnce(weeklyPath, "== 'cancelled'", "== 'cancelled' || always()"),
			want:   []string{`govulncheck.yml:17: "failure() || needs.govulncheck.result == 'cancelled' || always()" ` + notAllowed},
			n:      1,
		},
		{
			// The job of release.yml runs the call, so the job-level if: is also
			// a problem (see section 4b). That gives two messages.
			name:   "failure if in another file",
			mutate: replaceOnce(releasePath, "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    if: "+gvFailureIf+"\n"),
			want:   []string{`release.yml:8: "` + gvFailureIf + `" ` + notAllowed, jobIf(releasePath, 8, "test")},
			n:      2,
		},
		{
			name:   "failure if key in another case",
			mutate: replaceOnce(weeklyPath, "    if: failure()", "    IF: failure()"),
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
			mutate: replaceOnce(weeklyPath, "    needs: govulncheck\n", "    needs: govulncheck\n    continue-on-error: true\n"),
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

		// (4b) A job-level if: on a job that runs the call. GitHub skips a job
		// whose if is false, so the scan would not run. Each file has the rule.
		// Each problem has a twin that is fine: the if of a job without the
		// call, or the if of a step.
		{
			name:   "job if false on the call job of ci.yml",
			mutate: replaceOnce(ciPath, "  test:\n    runs-on: ubuntu-latest\n", "  test:\n    if: false\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobIf(ciPath, 8, "test")},
			n:      1,
		},
		{
			name:   "job if false on the call job of release.yml",
			mutate: replaceOnce(releasePath, "    runs-on: ubuntu-latest\n", "    if: false\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobIf(releasePath, 7, "test")},
			n:      1,
		},
		{
			name:   "job if false on the call job of govulncheck.yml",
			mutate: replaceOnce(weeklyPath, "  govulncheck:\n    runs-on: ubuntu-latest\n", "  govulncheck:\n    if: false\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobIf(weeklyPath, 9, "govulncheck")},
			n:      1,
		},
		{
			// The if key comes after the steps. A rule that read only the first
			// key of the job would miss it.
			name:   "job if false after the steps of the call job",
			mutate: replaceOnce(releasePath, gvTestRunLine+"\n", gvTestRunLine+"\n    if: false\n"),
			want:   []string{jobIf(releasePath, 13, "test")},
			n:      1,
		},
		{
			name:   "job if with runner.os on the call job",
			mutate: replaceOnce(releasePath, "    runs-on: ubuntu-latest\n", "    if: runner.os == 'Linux'\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobIf(releasePath, 7, "test")},
			n:      1,
		},
		{
			name:   "job if with the key IF in upper case on the call job",
			mutate: replaceOnce(ciPath, "  test:\n    runs-on: ubuntu-latest\n", "  test:\n    IF : false\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobIf(ciPath, 8, "test")},
			n:      1,
		},
		{
			name:   "job if with a padded key on the call job",
			mutate: replaceOnce(releasePath, "    runs-on: ubuntu-latest\n", "    \" if \": false\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobIf(releasePath, 7, "test")},
			n:      1,
		},
		{
			name:   "job if on a job without the call is fine",
			mutate: extraJob("  other:\n    if: false\n    steps:\n      - run: echo hi"),
		},
		{
			name:   "step if on the call step is fine",
			mutate: replaceOnce(releasePath, "      - name: Vulnerability check\n", "      - name: Vulnerability check\n        if: runner.os == 'Linux'\n"),
		},
		{
			name:   "step if with the key IF in upper case is fine",
			mutate: replaceOnce(ciPath, "      - name: Vulnerability check\n", "      - name: Vulnerability check\n        IF : false\n"),
		},
		{
			name:   "step if with a padded key is fine",
			mutate: replaceOnce(releasePath, "      - name: Vulnerability check\n", "      - name: Vulnerability check\n        \" if \": false\n"),
		},
		{
			// needs and the failure if: are names of the failure job. On the
			// call job they are not allowed, so the name rule reports them. The
			// job-level if: and needs: are also problems (sections 4b and 4c).
			name: "needs and failure if on the call job of govulncheck.yml",
			mutate: replaceOnce(weeklyPath, "  govulncheck:\n    runs-on: ubuntu-latest\n",
				"  govulncheck:\n    needs: govulncheck\n    if: "+gvFailureIf+"\n    runs-on: ubuntu-latest\n"),
			want: []string{
				`govulncheck.yml:9: "govulncheck" ` + notAllowed,
				`govulncheck.yml:10: "` + gvFailureIf + `" ` + notAllowed,
				jobIf(weeklyPath, 10, "govulncheck"),
				jobNeeds(weeklyPath, 9, "govulncheck"),
			},
			n: 4,
		},
		{
			// The same two names on a job that runs no call are allowed.
			name: "needs and failure if on a job without the call is fine",
			mutate: replaceOnce(weeklyPath, "  notify-failure:\n",
				"  other:\n    needs: govulncheck\n    if: "+gvFailureIf+"\n    steps:\n      - run: echo hi\n  notify-failure:\n"),
		},

		// (4c) A job-level needs: on a job that runs the call. GitHub skips a
		// job that waits for a skipped job, so the scan would not run. Each
		// problem has a twin that is fine: the needs: of a job without the
		// call, or the needs: of a step.
		{
			name:   "needs gate on the call job of ci.yml",
			mutate: replaceOnce(ciPath, "  test:\n    runs-on: ubuntu-latest\n", "  test:\n    needs: gate\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobNeeds(ciPath, 8, "test")},
			n:      1,
		},
		{
			name:   "needs gate on the call job of release.yml",
			mutate: replaceOnce(releasePath, "    runs-on: ubuntu-latest\n", "    needs: gate\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobNeeds(releasePath, 7, "test")},
			n:      1,
		},
		{
			name:   "needs gate on the call job of govulncheck.yml",
			mutate: replaceOnce(weeklyPath, "  govulncheck:\n    runs-on: ubuntu-latest\n", "  govulncheck:\n    needs: gate\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobNeeds(weeklyPath, 9, "govulncheck")},
			n:      1,
		},
		{
			name:   "needs gate in a list on the call job of ci.yml",
			mutate: replaceOnce(ciPath, "  test:\n    runs-on: ubuntu-latest\n", "  test:\n    needs: [gate]\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobNeeds(ciPath, 8, "test")},
			n:      1,
		},
		{
			name:   "needs gate in a list on the call job of release.yml",
			mutate: replaceOnce(releasePath, "    runs-on: ubuntu-latest\n", "    needs: [gate]\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobNeeds(releasePath, 7, "test")},
			n:      1,
		},
		{
			name:   "needs gate in a list on the call job of govulncheck.yml",
			mutate: replaceOnce(weeklyPath, "  govulncheck:\n    runs-on: ubuntu-latest\n", "  govulncheck:\n    needs: [gate]\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobNeeds(weeklyPath, 9, "govulncheck")},
			n:      1,
		},
		{
			name:   "needs with an empty value on the call job of ci.yml",
			mutate: replaceOnce(ciPath, "  test:\n    runs-on: ubuntu-latest\n", "  test:\n    needs:\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobNeeds(ciPath, 8, "test")},
			n:      1,
		},
		{
			name:   "NEEDS key in upper case on the call job of ci.yml",
			mutate: replaceOnce(ciPath, "  test:\n    runs-on: ubuntu-latest\n", "  test:\n    NEEDS: gate\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobNeeds(ciPath, 8, "test")},
			n:      1,
		},
		{
			name:   "padded needs key on the call job of release.yml",
			mutate: replaceOnce(releasePath, "    runs-on: ubuntu-latest\n", "    \" needs \": gate\n    runs-on: ubuntu-latest\n"),
			want:   []string{jobNeeds(releasePath, 7, "test")},
			n:      1,
		},
		{
			// The needs key comes after the steps. A rule that read only the
			// first key of the job would miss it.
			name:   "needs gate after the steps of the call job of release.yml",
			mutate: replaceOnce(releasePath, gvTestRunLine+"\n", gvTestRunLine+"\n    needs: gate\n"),
			want:   []string{jobNeeds(releasePath, 13, "test")},
			n:      1,
		},
		{
			name:   "needs gate on a job without the call is fine",
			mutate: extraJob("  other:\n    needs: gate\n    steps:\n      - run: echo hi"),
		},
		{
			name:   "needs gate on a job without the call in ci.yml is fine",
			mutate: replaceOnce(ciPath, "  test:\n", "  lint:\n    needs: test\n    steps:\n      - run: echo hi\n  test:\n"),
		},
		{
			name:   "needs gate on the call step is not read",
			mutate: replaceOnce(releasePath, "      - name: Vulnerability check\n", "      - name: Vulnerability check\n        needs: gate\n"),
		},
		{
			name:   "NEEDS key on the call step is not read",
			mutate: replaceOnce(ciPath, "      - name: Vulnerability check\n", "      - name: Vulnerability check\n        NEEDS: gate\n"),
		},

		// (5) Another workflow names govulncheck.
		{
			name:   "other.yml names govulncheck",
			mutate: setFile(".github/workflows/other.yml", &fstest.MapFile{Data: []byte("name: Other\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: govulncheck ./...\n      - run: govulncheck -h\n")}),
			want:   []string{".github/workflows/other.yml:7: " + others},
			n:      1, // one message per file
		},
		{
			name:   "govulncheck.yaml is not govulncheck.yml",
			mutate: setFile(".github/workflows/govulncheck.yaml", &fstest.MapFile{Data: []byte("name: govulncheck\non: push\njobs: {}\n")}),
			want:   []string{".github/workflows/govulncheck.yaml:1: " + others},
			n:      1,
		},
		{
			name:   "other workflow names govulncheck in a key",
			mutate: setFile(".github/workflows/other.yml", &fstest.MapFile{Data: []byte("name: Other\non: push\nenv:\n  GOVULNCHECK_VERSION: v1.9.0\njobs: {}\n")}),
			want:   []string{".github/workflows/other.yml:4: " + others},
			n:      1,
		},

		// (6) An unknown workflow that does not name govulncheck.
		{
			name:   "unknown workflow without the name is fine",
			mutate: setFile(".github/workflows/lint.yml", &fstest.MapFile{Data: []byte("name: Lint\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: golangci-lint run\n")}),
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
	mutations := []mutation{
		replaceOnce(releasePath, "v1.9.0", "v1.8.0"),
		replaceOnce(ciPath, "- name: Vulnerability check", "- name: govulncheck"),
	}
	// Many other workflows, so that a random map order shows.
	var wantOthers []string
	for i := range 20 {
		p := fmt.Sprintf(".github/workflows/w%02d.yml", i)
		mutations = append(mutations, setFile(p, &fstest.MapFile{Data: []byte("name: govulncheck\non: push\njobs: {}\n")}))
		wantOthers = append(wantOthers, p)
	}
	slices.Sort(wantOthers)
	mutate := applyAll(mutations...)

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

// TestGvListedNames checks the list of the listed workflows that the messages
// name. A change to gvListedPaths must show in every message that names them.
func TestGvListedNames(t *testing.T) {
	t.Parallel()
	const want = "ci.yml, release.yml and govulncheck.yml"
	if got := gvListedNames(); got != want {
		t.Errorf("gvListedNames() = %q, want %q", got, want)
	}
	other := map[string]*workflow{
		".github/workflows/other.yml": mustParse(t, ".github/workflows/other.yml", "name: govulncheck\non: push\njobs: {}\n"),
	}
	got := gvCheckOthers(other)
	if len(got) != 1 || !strings.Contains(got[0], "Only "+want+" may") {
		t.Errorf("gvCheckOthers() = %q, want one message with %q", got, "Only "+want+" may")
	}
}

// TestExactValue checks that exactValue matches a key only with its exact
// text. GitHub reads steps and run with their exact case, so a key with another
// case, or with spaces around it, is not a match.
func TestExactValue(t *testing.T) {
	t.Parallel()
	// The parser rejects two keys that differ only in case, so each source
	// holds one spelling of run. The key " run " has spaces around it.
	tests := []struct {
		name string
		src  string
		key  string
		want string // the value text; "" when exactValue must return nil
	}{
		{name: "exact key", src: "run: echo\n", key: "run", want: "echo"},
		{name: "other case of the key", src: "Run: x\n", key: "run", want: ""},
		{name: "other case, found by its own spelling", src: "Run: x\n", key: "Run", want: "x"},
		{name: "upper case of the key", src: "run: echo\n", key: "RUN", want: ""},
		{name: "key with spaces around it", src: "\" run \": y\n", key: "run", want: ""},
		{name: "key with spaces, exact", src: "\" run \": y\n", key: " run ", want: "y"},
		{name: "missing key", src: "steps: []\n", key: "run", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := mustParse(t, ciPath, tt.src)
			got := exactValue(w.top, tt.key)
			if tt.want == "" {
				if got != nil {
					t.Errorf("exactValue(%q) = %q, want nil", tt.key, got.Value)
				}
				return
			}
			if got == nil || got.Value != tt.want {
				t.Errorf("exactValue(%q) = %v, want the value %q", tt.key, got, tt.want)
			}
		})
	}
	t.Run("scalar has no keys", func(t *testing.T) {
		t.Parallel()
		// The first Content node of the top mapping is the key "run", a scalar.
		w := mustParse(t, ciPath, "run: echo\n")
		if got := exactValue(w.top.Content[0], "run"); got != nil {
			t.Errorf("exactValue(scalar) = %v, want nil", got)
		}
	})
}

// TestExactPair checks that exactPair returns the key node and the value node
// of a key with exactly the text name, and two nil nodes otherwise.
func TestExactPair(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		src     string
		key     string
		wantKey string // the key text; "" when exactPair must return nil nodes
		wantVal string // the value text
	}{
		{name: "exact key", src: "run: echo\n", key: "run", wantKey: "run", wantVal: "echo"},
		{name: "other case is not found", src: "Run: x\n", key: "run"},
		{name: "missing key", src: "steps: []\n", key: "run"},
		{name: "key with spaces is not found by its name", src: "\" run \": y\n", key: "run"},
		{name: "key with spaces, exact", src: "\" run \": y\n", key: " run ", wantKey: " run ", wantVal: "y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := mustParse(t, ciPath, tt.src)
			k, v := exactPair(w.top, tt.key)
			if tt.wantKey == "" {
				if k != nil || v != nil {
					t.Errorf("exactPair(%q) = %v, %v, want two nil nodes", tt.key, k, v)
				}
				return
			}
			if k == nil || k.Value != tt.wantKey || v == nil || v.Value != tt.wantVal {
				t.Errorf("exactPair(%q) = %v, %v, want the key %q and the value %q", tt.key, k, v, tt.wantKey, tt.wantVal)
			}
		})
	}
	t.Run("scalar has no pairs", func(t *testing.T) {
		t.Parallel()
		// The first Content node of the top mapping is the key "run", a scalar. A
		// scalar has no pairs, so there is no key to find.
		w := mustParse(t, ciPath, "run: echo\n")
		if k, v := exactPair(w.top.Content[0], "run"); k != nil || v != nil {
			t.Errorf("exactPair(scalar) = %v, %v, want two nil nodes", k, v)
		}
	})
}
