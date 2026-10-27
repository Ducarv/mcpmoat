package main

import (
	"io/fs"
	"maps"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// The files of grGoodRepo. Each negative case changes one thing in them. The
// line numbers in the cases refer to these texts: in both workflows the pin is
// on line 7, the step on line 9, the uses value on line 10, the with mapping
// on line 11 and the version input on line 13.
const (
	grGoodCI = `name: ci
on: push
jobs:
  release-check:
    runs-on: ubuntu-latest
    env:
      GORELEASER_VERSION: v2.19.0
    steps:
      - name: Check
        uses: goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de
        with:
          distribution: goreleaser
          version: ${{ env.GORELEASER_VERSION }}
  test:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
`
	grGoodRelease = `name: release
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    env:
      GORELEASER_VERSION: v2.19.0
    steps:
      - name: Run GoReleaser
        uses: goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de
        with:
          distribution: goreleaser
          version: ${{ env.GORELEASER_VERSION }}
`
	grGoodDoc = "# Contributing\n\nRun `go run github.com/goreleaser/goreleaser/v2@v2.19.0 check`.\n"

	grPinLine = "GORELEASER_VERSION: v2.19.0"
	grJobEnv  = "    env:\n      GORELEASER_VERSION: v2.19.0\n"
	grTestJob = "  test:\n    runs-on: ubuntu-latest\n"
	grDocPin  = "goreleaser/v2@v2.19.0"
)

// grGoodRepo returns a repository that gives zero messages.
func grGoodRepo() fstest.MapFS {
	return fstest.MapFS{
		grCIPath:      {Data: []byte(grGoodCI)},
		grReleasePath: {Data: []byte(grGoodRelease)},
		grDocPath:     {Data: []byte(grGoodDoc)},
	}
}

// grParse parses src as the workflow file p and fails the test on an error.
func grParse(t *testing.T, p, src string) *workflow {
	t.Helper()
	w, err := parseWorkflow(p, []byte(src))
	if err != nil {
		t.Fatalf("parseWorkflow(%q) error = %v, want nil", p, err)
	}
	return w
}

// grWorkflows parses every .yml file directly in .github/workflows of fsys.
func grWorkflows(t *testing.T, fsys fstest.MapFS) map[string]*workflow {
	t.Helper()
	wfs := make(map[string]*workflow)
	for p, f := range fsys {
		if path.Dir(p) == workflowDir && isWorkflowName(p) {
			wfs[p] = grParse(t, p, string(f.Data))
		}
	}
	return wfs
}

// grMutation changes the repository of one case.
type grMutation func(t *testing.T, fsys fstest.MapFS)

// grReplace replaces old with repl in the file p. old must occur exactly once,
// so that the case changes exactly the place it names.
func grReplace(p, old, repl string) grMutation {
	return func(t *testing.T, fsys fstest.MapFS) {
		t.Helper()
		data := string(fsys[p].Data)
		if n := strings.Count(data, old); n != 1 {
			t.Fatalf("%s has %d copies of %q, want 1", p, n, old)
		}
		fsys[p] = &fstest.MapFile{Data: []byte(strings.Replace(data, old, repl, 1))}
	}
}

// grSet adds the file p, or replaces it.
func grSet(p string, f *fstest.MapFile) grMutation {
	return func(_ *testing.T, fsys fstest.MapFS) { fsys[p] = f }
}

// grDelete removes the file p.
func grDelete(p string) grMutation {
	return func(_ *testing.T, fsys fstest.MapFS) { delete(fsys, p) }
}

// grAll applies the mutations in order. Use it for one change that touches
// two places, such as a move.
func grAll(ms ...grMutation) grMutation {
	return func(t *testing.T, fsys fstest.MapFS) {
		t.Helper()
		for _, m := range ms {
			m(t, fsys)
		}
	}
}

// grMsg is one expected message: it starts with prefix and contains text.
type grMsg struct {
	prefix string
	text   string
}

// grCase is one repository: grGoodRepo with the mutation applied. An empty
// want means zero messages.
type grCase struct {
	name   string
	mutate grMutation
	want   []grMsg
}

// grRunCases runs each case through checkGoreleaser.
func grRunCases(t *testing.T, cases []grCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fsys := grGoodRepo()
			if tc.mutate != nil {
				tc.mutate(t, fsys)
			}
			got := checkGoreleaser(fsys, grWorkflows(t, fsys))
			grCheckMsgs(t, got, tc.want)
		})
	}
}

// grCheckMsgs fails the test unless every want has a message, or, when want
// is empty, unless got is empty.
func grCheckMsgs(t *testing.T, got []string, want []grMsg) {
	t.Helper()
	if len(want) == 0 && len(got) != 0 {
		t.Fatalf("checkGoreleaser() = %q, want no messages", got)
	}
	for _, w := range want {
		found := slices.ContainsFunc(got, func(m string) bool {
			return strings.HasPrefix(m, w.prefix) && strings.Contains(m, w.text)
		})
		if !found {
			t.Errorf("checkGoreleaser() = %q, want a message that starts with %q and contains %q", got, w.prefix, w.text)
		}
	}
}

const (
	grMsgOnePin   = "ci.yml must pin one full version of GoReleaser"
	grMsgNotFull  = "is not a full version (vMAJOR.MINOR.PATCH)"
	grMsgMention  = "mentions GORELEASER_VERSION in a form this check does not allow"
	grMsgNames    = "names goreleaser/goreleaser-action, but it is not the uses value"
	grMsgNoJobPin = "but its env does not define GORELEASER_VERSION"
	grMsgDiffers  = "(the pin in ci.yml)"
	ciLine        = ".github/workflows/ci.yml:"
	relLine       = ".github/workflows/release.yml:"
)

func TestGoreleaserGoodRepo(t *testing.T) {
	t.Parallel()
	grRunCases(t, []grCase{{name: "good repo"}})
}

// TestGoreleaserCIPin covers rule 1 (ci.yml pins one full version) and the
// compare of the other pins against it.
func TestGoreleaserCIPin(t *testing.T) {
	t.Parallel()
	grRunCases(t, []grCase{
		// Positive controls.
		{
			name:   "same pin repeated in two ci jobs",
			mutate: grReplace(grCIPath, grTestJob, grTestJob+grJobEnv),
		},
		{
			name:   "quoted pin",
			mutate: grReplace(grCIPath, grPinLine, `GORELEASER_VERSION: "v2.19.0"`),
		},
		{
			name:   "flow job env",
			mutate: grReplace(grCIPath, grJobEnv, "    env: {GORELEASER_VERSION: v2.19.0}\n"),
		},
		{
			name: "rc pin everywhere",
			mutate: grAll(
				grReplace(grCIPath, grPinLine, "GORELEASER_VERSION: v2.19.0-rc.1"),
				grReplace(grReleasePath, grPinLine, "GORELEASER_VERSION: v2.19.0-rc.1"),
				grReplace(grDocPath, grDocPin, "goreleaser/v2@v2.19.0-rc.1"),
			),
		},
		// Negative cases.
		{
			name:   "no pin",
			mutate: grReplace(grCIPath, grJobEnv, ""),
			want:   []grMsg{{".github/workflows/ci.yml: ", grMsgOnePin + " (GORELEASER_VERSION in the env of a job). Found: none"}},
		},
		{
			name:   "two different pins",
			mutate: grReplace(grCIPath, grTestJob, grTestJob+strings.Replace(grJobEnv, "v2.19.0", "v2.20.0", 1)),
			want:   []grMsg{{".github/workflows/ci.yml: ", "Found: v2.19.0, v2.20.0"}},
		},
		{
			name:   "short version",
			mutate: grReplace(grCIPath, grPinLine, "GORELEASER_VERSION: v2.19"),
			want: []grMsg{
				{ciLine + "7: ", `the GORELEASER_VERSION pin "v2.19" ` + grMsgNotFull},
				{ciLine, "Found: none"},
			},
		},
		{
			name:   "quoted short version",
			mutate: grReplace(grCIPath, grPinLine, `GORELEASER_VERSION: 'v2.19'`),
			want:   []grMsg{{ciLine + "7: ", grMsgNotFull}},
		},
		{
			name:   "no v prefix",
			mutate: grReplace(grCIPath, grPinLine, "GORELEASER_VERSION: 2.19.0"),
			want:   []grMsg{{ciLine + "7: ", grMsgNotFull}},
		},
		{
			// The ^ anchor of grFullVersion: text before the v fails.
			name:   "text before the v",
			mutate: grReplace(grCIPath, grPinLine, "GORELEASER_VERSION: xv2.19.0"),
			want: []grMsg{
				{ciLine + "7: ", `the GORELEASER_VERSION pin "xv2.19.0" ` + grMsgNotFull},
				{ciLine, "Found: none"},
			},
		},
		{
			name:   "latest",
			mutate: grReplace(grCIPath, grPinLine, "GORELEASER_VERSION: latest"),
			want:   []grMsg{{ciLine + "7: ", grMsgNotFull}},
		},
		{
			name:   "empty quoted string",
			mutate: grReplace(grCIPath, grPinLine, `GORELEASER_VERSION: ""`),
			want:   []grMsg{{ciLine + "7: ", `pin "" ` + grMsgNotFull}},
		},
		{
			name:   "empty value",
			mutate: grReplace(grCIPath, grPinLine, "GORELEASER_VERSION:"),
			want:   []grMsg{{ciLine + "7: ", "must be a full version (vMAJOR.MINOR.PATCH), found an empty value"}},
		},
		{
			name:   "null",
			mutate: grReplace(grCIPath, grPinLine, "GORELEASER_VERSION: null"),
			want:   []grMsg{{ciLine + "7: ", "found an empty value"}},
		},
		{
			name:   "mapping",
			mutate: grReplace(grCIPath, grPinLine, "GORELEASER_VERSION: {v: v2.19.0}"),
			want:   []grMsg{{ciLine + "7: ", "found a mapping"}},
		},
		{
			name:   "rc only in ci",
			mutate: grReplace(grCIPath, grPinLine, "GORELEASER_VERSION: v2.19.0-rc.1"),
			want:   []grMsg{{relLine + "7: ", `GORELEASER_VERSION is "v2.19.0", expected "v2.19.0-rc.1" ` + grMsgDiffers}},
		},
		// The other workflows against the pin of ci.yml.
		{
			name:   "release pin differs",
			mutate: grReplace(grReleasePath, grPinLine, "GORELEASER_VERSION: v2.18.0"),
			want:   []grMsg{{relLine + "7: ", `GORELEASER_VERSION is "v2.18.0", expected "v2.19.0" ` + grMsgDiffers}},
		},
		{
			name:   "release pin is short",
			mutate: grReplace(grReleasePath, grPinLine, "GORELEASER_VERSION: v2.19"),
			want: []grMsg{
				{relLine + "7: ", grMsgNotFull},
				{".github/workflows/release.yml: ", `the workflow has no full GORELEASER_VERSION pin in the env of a job, expected "v2.19.0"`},
			},
		},
		{
			name:   "release pin missing",
			mutate: grReplace(grReleasePath, grJobEnv, ""),
			want:   []grMsg{{".github/workflows/release.yml: ", "the workflow has no full GORELEASER_VERSION pin"}},
		},
		{
			name:   "other workflow pin differs",
			mutate: grSet(".github/workflows/other.yml", &fstest.MapFile{Data: []byte(strings.Replace(grGoodRelease, "v2.19.0", "v2.18.0", 1))}),
			want:   []grMsg{{".github/workflows/other.yml:7: ", `expected "v2.19.0"`}},
		},
	})
}

// TestGoreleaserMention covers rule 2: every other text with goreleaser_version,
// in any case, fails.
func TestGoreleaserMention(t *testing.T) {
	t.Parallel()
	grRunCases(t, []grCase{
		{
			name:   "comment is not a node",
			mutate: grReplace(grCIPath, grPinLine, grPinLine+" # goreleaser_version, GORELEASER_VERSION: v1.0.0"),
		},
		{
			name:   "workflow-level env",
			mutate: grReplace(grCIPath, "jobs:\n", "env:\n  GORELEASER_VERSION: v2.19.0\njobs:\n"),
			want:   []grMsg{{ciLine + "4: ", `the text "GORELEASER_VERSION" ` + grMsgMention}},
		},
		{
			name: "step env",
			mutate: grReplace(grCIPath, "      - run: go test ./...\n",
				"      - run: go test ./...\n        env:\n          GORELEASER_VERSION: v2.19.0\n"),
			want: []grMsg{{ciLine + "19: ", `"GORELEASER_VERSION" ` + grMsgMention}},
		},
		{
			name:   "job outputs",
			mutate: grReplace(grCIPath, grTestJob, grTestJob+"    outputs:\n      v: ${{ env.GORELEASER_VERSION }}\n"),
			want:   []grMsg{{ciLine + "17: ", `"${{ env.GORELEASER_VERSION }}" ` + grMsgMention}},
		},
		{
			name: "run line writes GITHUB_ENV",
			mutate: grReplace(grCIPath, "      - run: go test ./...\n",
				"      - run: echo \"GORELEASER_VERSION=v2.0.0\" >> \"$GITHUB_ENV\"\n"),
			want: []grMsg{{ciLine + "17: ", grMsgMention}},
		},
		{
			name:   "X_ prefix in job env",
			mutate: grReplace(grCIPath, grPinLine, grPinLine+"\n      X_GORELEASER_VERSION: v2.19.0"),
			want:   []grMsg{{ciLine + "8: ", `"X_GORELEASER_VERSION" ` + grMsgMention}},
		},
		{
			name:   "lower case key is not a pin",
			mutate: grReplace(grCIPath, grPinLine, "goreleaser_version: v2.19.0"),
			want: []grMsg{
				{ciLine + "7: ", `"goreleaser_version" ` + grMsgMention},
				{ciLine, "Found: none"},
			},
		},
		{
			name:   "mixed case in a step name",
			mutate: grReplace(grCIPath, "      - run: go test ./...\n", "      - name: print GoReleaser_Version\n        run: go test ./...\n"),
			want:   []grMsg{{ciLine + "17: ", grMsgMention}},
		},
		{
			name: "version input on another action",
			mutate: grReplace(grCIPath, "      - run: go test ./...\n",
				"      - uses: actions/setup-go@v5\n        with:\n          version: ${{ env.GORELEASER_VERSION }}\n"),
			want: []grMsg{{ciLine + "19: ", grMsgMention}},
		},
	})
}

// TestGoreleaserActionText covers rule 4: every scalar that names
// goreleaser-action and is not the uses value of a step fails.
func TestGoreleaserActionText(t *testing.T) {
	t.Parallel()
	const runStep = "      - run: go test ./...\n"
	grRunCases(t, []grCase{
		{
			name:   "comment is not a node",
			mutate: grReplace(grCIPath, runStep, "      # goreleaser/goreleaser-action@v1\n"+runStep),
		},
		{
			name:   "run line",
			mutate: grReplace(grCIPath, runStep, "      - run: echo goreleaser/goreleaser-action\n"),
			want:   []grMsg{{ciLine + "17: ", `the text "echo goreleaser/goreleaser-action" ` + grMsgNames}},
		},
		{
			name:   "docker uses",
			mutate: grReplace(grCIPath, runStep, "      - uses: docker://goreleaser/goreleaser-action:v2\n"),
			want:   []grMsg{{ciLine + "17: ", grMsgNames}},
		},
		{
			name:   "local path uses",
			mutate: grReplace(grCIPath, runStep, "      - uses: ./goreleaser/goreleaser-action\n"),
			want:   []grMsg{{ciLine + "17: ", grMsgNames}},
		},
		{
			name:   "sub-path uses",
			mutate: grReplace(grCIPath, runStep, "      - uses: goreleaser/goreleaser-action/sub@v7\n"),
			want:   []grMsg{{ciLine + "17: ", grMsgNames}},
		},
		{
			name:   "upper case in a step name",
			mutate: grReplace(grCIPath, runStep, "      - name: GoReleaser/GoReleaser-Action\n        run: go test ./...\n"),
			want:   []grMsg{{ciLine + "17: ", grMsgNames}},
		},
		{
			// The good repo is the positive control: the same uses value as a
			// scalar passes.
			name:   "uses value is a sequence",
			mutate: grReplace(grCIPath, "uses: goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de", "uses: [goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de]"),
			want:   []grMsg{{ciLine + "10: ", `the value of "uses" must be a scalar, found a sequence`}},
		},
		{
			name:   "job-level uses of a reusable workflow",
			mutate: grReplace(grCIPath, grTestJob+"    steps:\n      - run: go test ./...\n", "  test:\n    uses: goreleaser/goreleaser-action/.github/workflows/x.yml@v7\n"),
			want:   []grMsg{{ciLine + "15: ", grMsgNames}},
		},
	})
}

// TestGoreleaserJobEnv covers rule 5: a job with a goreleaser-action step needs
// the pin in its own env.
func TestGoreleaserJobEnv(t *testing.T) {
	t.Parallel()
	grRunCases(t, []grCase{
		{
			name: "pin in another job",
			mutate: grAll(
				grReplace(grCIPath, grJobEnv, ""),
				grReplace(grCIPath, grTestJob, grTestJob+grJobEnv),
			),
			want: []grMsg{{ciLine + "4: ", `the job "release-check" has a goreleaser-action step, ` + grMsgNoJobPin}},
		},
		{
			name: "workflow-level env does not count",
			mutate: grAll(
				grReplace(grReleasePath, grJobEnv, ""),
				grReplace(grReleasePath, "jobs:\n", "env:\n  GORELEASER_VERSION: v2.19.0\njobs:\n"),
			),
			want: []grMsg{{relLine + "6: ", `the job "release" has a goreleaser-action step, ` + grMsgNoJobPin}},
		},
		{
			name:   "job env is an expression",
			mutate: grReplace(grReleasePath, grJobEnv, "    env: ${{ fromJSON(vars.RELEASE_ENV) }}\n"),
			want: []grMsg{
				{relLine + "6: ", `the value of "env" must be a mapping, found a scalar`},
				{relLine + "4: ", grMsgNoJobPin},
			},
		},
		{
			name:   "job env is empty",
			mutate: grReplace(grReleasePath, grJobEnv, "    env:\n"),
			want: []grMsg{
				{relLine + "6: ", `the value of "env" must be a mapping, found an empty value`},
				{relLine + "4: ", grMsgNoJobPin},
			},
		},
		{
			name:   "unlisted workflow with a good job",
			mutate: grSet(".github/workflows/other.yml", &fstest.MapFile{Data: []byte("on: push\njobs: {a: {runs-on: x}}\n")}),
		},
		{
			// Only grScanWorkflow reads the jobs of an unlisted workflow, so
			// this is the only message for the bad job.
			name:   "unlisted workflow with a job that is not a mapping",
			mutate: grSet(".github/workflows/other.yml", &fstest.MapFile{Data: []byte("on: push\njobs: {a: x}\n")}),
			want:   []grMsg{{".github/workflows/other.yml:2: ", `the job "a" must be a mapping, found a scalar`}},
		},
		{
			name:   "steps not a sequence",
			mutate: grReplace(grCIPath, "    steps:\n      - run: go test ./...\n", "    steps: go test\n"),
			want:   []grMsg{{ciLine + "16: ", `the value of "steps" must be a sequence`}},
		},
	})
}

// TestGoreleaserDoc covers rule 6: every goreleaser(/vN)?@<text> in
// CONTRIBUTING.md equals the pin of ci.yml.
func TestGoreleaserDoc(t *testing.T) {
	t.Parallel()
	const docLine = "CONTRIBUTING.md:3: "
	grRunCases(t, []grCase{
		{
			name:   "second mention without major path",
			mutate: grReplace(grDocPath, "check`.\n", "check`.\n\n`goreleaser@v2.19.0`\n"),
		},
		{
			name:   "latest",
			mutate: grReplace(grDocPath, grDocPin, "goreleaser/v2@latest"),
			want:   []grMsg{{docLine, `the GoReleaser version "latest" differs from the pin "v2.19.0" in ci.yml`}},
		},
		{
			name:   "short version",
			mutate: grReplace(grDocPath, grDocPin, "goreleaser/v2@v2.19"),
			want:   []grMsg{{docLine, `"v2.19" differs`}},
		},
		{
			name:   "second mention differs",
			mutate: grReplace(grDocPath, "check`.\n", "check`.\n\n`goreleaser@v2.18.0`\n"),
			want:   []grMsg{{"CONTRIBUTING.md:5: ", `"v2.18.0" differs`}},
		},
		{
			name:   "no version",
			mutate: grReplace(grDocPath, grDocPin, "goreleaser/v2"),
			want:   []grMsg{{"CONTRIBUTING.md: ", `names no GoReleaser version (goreleaser/vN@<version>), expected "v2.19.0"`}},
		},
		{
			name:   "missing file",
			mutate: grDelete(grDocPath),
			want:   []grMsg{{"CONTRIBUTING.md: ", "open: "}},
		},
		{
			name:   "file over the limit",
			mutate: grReplace(grDocPath, "check`.\n", "check`.\n"+strings.Repeat("x", grMaxFileBytes)),
			want:   []grMsg{{"CONTRIBUTING.md: ", "the file has more than 1048576 bytes"}},
		},
		{
			name:   "overlong version text",
			mutate: grReplace(grDocPath, grDocPin, grDocPin+strings.Repeat("x", 300)),
			want:   []grMsg{{docLine, `"... differs from the pin "v2.19.0"`}},
		},
	})
}

// TestGoreleaserDocOverlongCapped checks that a message shows at most
// maxShown bytes of a long version text.
func TestGoreleaserDocOverlongCapped(t *testing.T) {
	t.Parallel()
	fsys := grGoodRepo()
	grReplace(grDocPath, grDocPin, grDocPin+strings.Repeat("x", 300))(t, fsys)
	got := checkGoreleaser(fsys, grWorkflows(t, fsys))
	if len(got) != 1 {
		t.Fatalf("checkGoreleaser() = %q, want 1 message", got)
	}
	if n := strings.Count(got[0], "x"); n > maxShown {
		t.Errorf("message shows %d bytes of the version, want at most %d: %q", n, maxShown, got[0])
	}
}

// TestGoreleaserLocalActions covers rule 7: the files under .github/actions.
func TestGoreleaserLocalActions(t *testing.T) {
	t.Parallel()
	const action = ".github/actions/build/action.yml"
	symlink := func(target string) *fstest.MapFile {
		return &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(target)}
	}
	grRunCases(t, []grCase{
		{
			name:   "action that does not name goreleaser-action",
			mutate: grSet(action, &fstest.MapFile{Data: []byte("runs:\n  using: composite\n")}),
		},
		{
			name:   "action names goreleaser-action",
			mutate: grSet(action, &fstest.MapFile{Data: []byte("runs:\n  steps:\n    - uses: GoReleaser/goreleaser-action@v7\n")}),
			want:   []grMsg{{action + ": ", "names goreleaser/goreleaser-action. This check does not read .github/actions."}},
		},
		{
			name:   "Actions directory in another case",
			mutate: grSet(".github/Actions/build/action.yml", &fstest.MapFile{Data: []byte("uses: goreleaser/goreleaser-action@v7\n")}),
			want:   []grMsg{{".github/Actions/build/action.yml: ", "names goreleaser/goreleaser-action."}},
		},
		{
			name:   "symlink file",
			mutate: grSet(".github/actions/link.yml", symlink("../../release.yml")),
			want:   []grMsg{{".github/actions/link.yml: ", "is a symlink"}},
		},
		{
			name:   "symlink directory below actions",
			mutate: grSet(".github/actions/shared", symlink("../../shared")),
			want:   []grMsg{{".github/actions/shared: ", "is a symlink"}},
		},
		{
			name:   "actions directory is a symlink",
			mutate: grSet(".github/actions", symlink("../actions")),
			want:   []grMsg{{".github/actions: ", "is a symlink"}},
		},
		{
			name:   "named pipe",
			mutate: grSet(".github/actions/fifo", &fstest.MapFile{Mode: fs.ModeNamedPipe}),
			want:   []grMsg{{".github/actions/fifo: ", "is not a regular file"}},
		},
		{
			name:   "file over the limit",
			mutate: grSet(action, &fstest.MapFile{Data: make([]byte, grMaxFileBytes+1)}),
			want:   []grMsg{{action + ": ", "the file has more than 1048576 bytes"}},
		},
	})
}

// TestGoreleaserMissingWorkflow covers a missing ci.yml or release.yml.
func TestGoreleaserMissingWorkflow(t *testing.T) {
	t.Parallel()
	grRunCases(t, []grCase{
		{
			name:   "missing ci.yml",
			mutate: grDelete(grCIPath),
			want:   []grMsg{{".github/workflows/ci.yml: ", "the workflow is missing or did not parse"}},
		},
		{
			name:   "missing release.yml",
			mutate: grDelete(grReleasePath),
			want:   []grMsg{{".github/workflows/release.yml: ", "the workflow is missing or did not parse"}},
		},
	})
}

// TestGoreleaserNilInputs checks that a nil map, a nil workflow and a workflow
// with no top node give messages and do not panic.
func TestGoreleaserNilInputs(t *testing.T) {
	t.Parallel()
	missing := func(p string) grMsg { return grMsg{p + ": ", "the workflow is missing or did not parse"} }
	tests := []struct {
		name string
		wfs  func(t *testing.T) map[string]*workflow
		want []grMsg
	}{
		{
			name: "nil map",
			wfs:  func(*testing.T) map[string]*workflow { return nil },
			want: []grMsg{missing(grCIPath), missing(grReleasePath)},
		},
		{
			name: "nil ci workflow",
			wfs: func(t *testing.T) map[string]*workflow {
				return map[string]*workflow{grCIPath: nil, grReleasePath: grParse(t, grReleasePath, grGoodRelease)}
			},
			want: []grMsg{missing(grCIPath), {grCIPath + ": ", "the workflow was not parsed"}},
		},
		{
			name: "release workflow with no top node",
			wfs: func(t *testing.T) map[string]*workflow {
				return map[string]*workflow{grCIPath: grParse(t, grCIPath, grGoodCI), grReleasePath: {file: grReleasePath}}
			},
			want: []grMsg{{grReleasePath + ": ", "the workflow was not parsed"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			grCheckMsgs(t, checkGoreleaser(grGoodRepo(), tt.wfs(t)), tt.want)
		})
	}
}

// TestGoreleaserStableOrder checks that the messages come in the same order on
// every run, although a Go map has no order.
func TestGoreleaserStableOrder(t *testing.T) {
	t.Parallel()
	fsys := grGoodRepo()
	grAll(
		grReplace(grReleasePath, grPinLine, "GORELEASER_VERSION: v2.18.0"),
		grSet(".github/workflows/a.yml", &fstest.MapFile{Data: []byte(strings.Replace(grGoodRelease, "v2.19.0", "v2.17.0", 1))}),
		grSet(".github/workflows/z.yml", &fstest.MapFile{Data: []byte(strings.Replace(grGoodRelease, "v2.19.0", "v2.16.0", 1))}),
		grReplace(grDocPath, grDocPin, "goreleaser/v2@latest"),
		grSet(".github/actions/a.yml", &fstest.MapFile{Data: []byte("goreleaser/goreleaser-action")}),
		grSet(".github/actions/b.yml", &fstest.MapFile{Data: []byte("goreleaser/goreleaser-action")}),
	)(t, fsys)
	first := checkGoreleaser(fsys, grWorkflows(t, fsys))
	if len(first) < 6 {
		t.Fatalf("checkGoreleaser() = %q, want at least 6 messages", first)
	}
	for range 20 {
		if got := checkGoreleaser(fsys, grWorkflows(t, fsys)); !reflect.DeepEqual(got, first) {
			t.Fatalf("checkGoreleaser() order changed:\n got %q\nwant %q", got, first)
		}
	}
}

// TestGoreleaserRealRepo checks that the files of this repository pass.
func TestGoreleaserRealRepo(t *testing.T) {
	t.Parallel()
	fsys := os.DirFS("../..")
	wfs := make(map[string]*workflow)
	for _, pattern := range []string{".github/workflows/*.yml", ".github/workflows/*.yaml"} {
		names, err := fs.Glob(fsys, pattern)
		if err != nil {
			t.Fatalf("fs.Glob(%q) error = %v", pattern, err)
		}
		for _, p := range names {
			data, err := fs.ReadFile(fsys, p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			wfs[p] = grParse(t, p, string(data))
		}
	}
	if wfs[grCIPath] == nil || wfs[grReleasePath] == nil {
		t.Fatalf("workflows found = %q, want ci.yml and release.yml", slices.Sorted(maps.Keys(wfs)))
	}
	if got := checkGoreleaser(fsys, wfs); len(got) != 0 {
		t.Errorf("checkGoreleaser(repository) = %q, want no messages", got)
	}
}
