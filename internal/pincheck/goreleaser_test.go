package main

import (
	"io/fs"
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
		ciPath:      {Data: []byte(grGoodCI)},
		releasePath: {Data: []byte(grGoodRelease)},
		docPath:     {Data: []byte(grGoodDoc)},
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
	mutate mutation
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
			got := checkGoreleaser(fsys, parseWorkflows(t, fsys))
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
			mutate: replaceOnce(ciPath, grTestJob, grTestJob+grJobEnv),
		},
		{
			name:   "quoted pin",
			mutate: replaceOnce(ciPath, grPinLine, `GORELEASER_VERSION: "v2.19.0"`),
		},
		{
			name:   "flow job env",
			mutate: replaceOnce(ciPath, grJobEnv, "    env: {GORELEASER_VERSION: v2.19.0}\n"),
		},
		{
			name: "rc pin everywhere",
			mutate: applyAll(
				replaceOnce(ciPath, grPinLine, "GORELEASER_VERSION: v2.19.0-rc.1"),
				replaceOnce(releasePath, grPinLine, "GORELEASER_VERSION: v2.19.0-rc.1"),
				replaceOnce(docPath, grDocPin, "goreleaser/v2@v2.19.0-rc.1"),
			),
		},
		// Negative cases.
		{
			name:   "no pin",
			mutate: replaceOnce(ciPath, grJobEnv, ""),
			want:   []grMsg{{".github/workflows/ci.yml: ", grMsgOnePin + " (GORELEASER_VERSION in the env of a job). Found: none"}},
		},
		{
			name:   "two different pins",
			mutate: replaceOnce(ciPath, grTestJob, grTestJob+strings.Replace(grJobEnv, "v2.19.0", "v2.20.0", 1)),
			want:   []grMsg{{".github/workflows/ci.yml: ", "Found: v2.19.0, v2.20.0"}},
		},
		{
			name:   "short version",
			mutate: replaceOnce(ciPath, grPinLine, "GORELEASER_VERSION: v2.19"),
			want: []grMsg{
				{ciLine + "7: ", `the GORELEASER_VERSION pin "v2.19" ` + grMsgNotFull},
				{ciLine, "Found: none"},
			},
		},
		{
			name:   "quoted short version",
			mutate: replaceOnce(ciPath, grPinLine, `GORELEASER_VERSION: 'v2.19'`),
			want:   []grMsg{{ciLine + "7: ", grMsgNotFull}},
		},
		{
			name:   "no v prefix",
			mutate: replaceOnce(ciPath, grPinLine, "GORELEASER_VERSION: 2.19.0"),
			want:   []grMsg{{ciLine + "7: ", grMsgNotFull}},
		},
		{
			// The ^ anchor of fullVersion: text before the v fails.
			name:   "text before the v",
			mutate: replaceOnce(ciPath, grPinLine, "GORELEASER_VERSION: xv2.19.0"),
			want: []grMsg{
				{ciLine + "7: ", `the GORELEASER_VERSION pin "xv2.19.0" ` + grMsgNotFull},
				{ciLine, "Found: none"},
			},
		},
		{
			name:   "latest",
			mutate: replaceOnce(ciPath, grPinLine, "GORELEASER_VERSION: latest"),
			want:   []grMsg{{ciLine + "7: ", grMsgNotFull}},
		},
		{
			name:   "empty quoted string",
			mutate: replaceOnce(ciPath, grPinLine, `GORELEASER_VERSION: ""`),
			want:   []grMsg{{ciLine + "7: ", `pin "" ` + grMsgNotFull}},
		},
		{
			name:   "empty value",
			mutate: replaceOnce(ciPath, grPinLine, "GORELEASER_VERSION:"),
			want:   []grMsg{{ciLine + "7: ", "must be a full version (vMAJOR.MINOR.PATCH), found an empty value"}},
		},
		{
			name:   "null",
			mutate: replaceOnce(ciPath, grPinLine, "GORELEASER_VERSION: null"),
			want:   []grMsg{{ciLine + "7: ", "found an empty value"}},
		},
		{
			name:   "mapping",
			mutate: replaceOnce(ciPath, grPinLine, "GORELEASER_VERSION: {v: v2.19.0}"),
			want:   []grMsg{{ciLine + "7: ", "found a mapping"}},
		},
		{
			name:   "rc only in ci",
			mutate: replaceOnce(ciPath, grPinLine, "GORELEASER_VERSION: v2.19.0-rc.1"),
			want:   []grMsg{{relLine + "7: ", `GORELEASER_VERSION is "v2.19.0", expected "v2.19.0-rc.1" ` + grMsgDiffers}},
		},
		// The other workflows against the pin of ci.yml.
		{
			name:   "release pin differs",
			mutate: replaceOnce(releasePath, grPinLine, "GORELEASER_VERSION: v2.18.0"),
			want:   []grMsg{{relLine + "7: ", `GORELEASER_VERSION is "v2.18.0", expected "v2.19.0" ` + grMsgDiffers}},
		},
		{
			name:   "release pin is short",
			mutate: replaceOnce(releasePath, grPinLine, "GORELEASER_VERSION: v2.19"),
			want: []grMsg{
				{relLine + "7: ", grMsgNotFull},
				{".github/workflows/release.yml: ", `the workflow has no full GORELEASER_VERSION pin in the env of a job, expected "v2.19.0"`},
			},
		},
		{
			name:   "release pin missing",
			mutate: replaceOnce(releasePath, grJobEnv, ""),
			want:   []grMsg{{".github/workflows/release.yml: ", "the workflow has no full GORELEASER_VERSION pin"}},
		},
		{
			name:   "other workflow pin differs",
			mutate: setFile(".github/workflows/other.yml", &fstest.MapFile{Data: []byte(strings.Replace(grGoodRelease, "v2.19.0", "v2.18.0", 1))}),
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
			mutate: replaceOnce(ciPath, grPinLine, grPinLine+" # goreleaser_version, GORELEASER_VERSION: v1.0.0"),
		},
		{
			name:   "workflow-level env",
			mutate: replaceOnce(ciPath, "jobs:\n", "env:\n  GORELEASER_VERSION: v2.19.0\njobs:\n"),
			want:   []grMsg{{ciLine + "4: ", `the text "GORELEASER_VERSION" ` + grMsgMention}},
		},
		{
			name: "step env",
			mutate: replaceOnce(ciPath, "      - run: go test ./...\n",
				"      - run: go test ./...\n        env:\n          GORELEASER_VERSION: v2.19.0\n"),
			want: []grMsg{{ciLine + "19: ", `"GORELEASER_VERSION" ` + grMsgMention}},
		},
		{
			name:   "job outputs",
			mutate: replaceOnce(ciPath, grTestJob, grTestJob+"    outputs:\n      v: ${{ env.GORELEASER_VERSION }}\n"),
			want:   []grMsg{{ciLine + "17: ", `"${{ env.GORELEASER_VERSION }}" ` + grMsgMention}},
		},
		{
			name: "run line writes GITHUB_ENV",
			mutate: replaceOnce(ciPath, "      - run: go test ./...\n",
				"      - run: echo \"GORELEASER_VERSION=v2.0.0\" >> \"$GITHUB_ENV\"\n"),
			want: []grMsg{{ciLine + "17: ", grMsgMention}},
		},
		{
			name:   "X_ prefix in job env",
			mutate: replaceOnce(ciPath, grPinLine, grPinLine+"\n      X_GORELEASER_VERSION: v2.19.0"),
			want:   []grMsg{{ciLine + "8: ", `"X_GORELEASER_VERSION" ` + grMsgMention}},
		},
		{
			name:   "lower case key is not a pin",
			mutate: replaceOnce(ciPath, grPinLine, "goreleaser_version: v2.19.0"),
			want: []grMsg{
				{ciLine + "7: ", `"goreleaser_version" ` + grMsgMention},
				{ciLine, "Found: none"},
			},
		},
		{
			name:   "mixed case in a step name",
			mutate: replaceOnce(ciPath, "      - run: go test ./...\n", "      - name: print GoReleaser_Version\n        run: go test ./...\n"),
			want:   []grMsg{{ciLine + "17: ", grMsgMention}},
		},
		{
			name: "version input on another action",
			mutate: replaceOnce(ciPath, "      - run: go test ./...\n",
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
			mutate: replaceOnce(ciPath, runStep, "      # goreleaser/goreleaser-action@v1\n"+runStep),
		},
		{
			name:   "run line",
			mutate: replaceOnce(ciPath, runStep, "      - run: echo goreleaser/goreleaser-action\n"),
			want:   []grMsg{{ciLine + "17: ", `the text "echo goreleaser/goreleaser-action" ` + grMsgNames}},
		},
		{
			name:   "docker uses",
			mutate: replaceOnce(ciPath, runStep, "      - uses: docker://goreleaser/goreleaser-action:v2\n"),
			want:   []grMsg{{ciLine + "17: ", grMsgNames}},
		},
		{
			name:   "local path uses",
			mutate: replaceOnce(ciPath, runStep, "      - uses: ./goreleaser/goreleaser-action\n"),
			want:   []grMsg{{ciLine + "17: ", grMsgNames}},
		},
		{
			name:   "sub-path uses",
			mutate: replaceOnce(ciPath, runStep, "      - uses: goreleaser/goreleaser-action/sub@v7\n"),
			want:   []grMsg{{ciLine + "17: ", grMsgNames}},
		},
		{
			name:   "upper case in a step name",
			mutate: replaceOnce(ciPath, runStep, "      - name: GoReleaser/GoReleaser-Action\n        run: go test ./...\n"),
			want:   []grMsg{{ciLine + "17: ", grMsgNames}},
		},
		{
			// The good repo is the positive control: the same uses value as a
			// scalar passes.
			name:   "uses value is a sequence",
			mutate: replaceOnce(ciPath, "uses: goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de", "uses: [goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de]"),
			want:   []grMsg{{ciLine + "10: ", `the value of "uses" must be a scalar, found a sequence`}},
		},
		{
			name:   "job-level uses of a reusable workflow",
			mutate: replaceOnce(ciPath, grTestJob+"    steps:\n      - run: go test ./...\n", "  test:\n    uses: goreleaser/goreleaser-action/.github/workflows/x.yml@v7\n"),
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
			mutate: applyAll(
				replaceOnce(ciPath, grJobEnv, ""),
				replaceOnce(ciPath, grTestJob, grTestJob+grJobEnv),
			),
			want: []grMsg{{ciLine + "4: ", `the job "release-check" has a goreleaser-action step, ` + grMsgNoJobPin}},
		},
		{
			name: "workflow-level env does not count",
			mutate: applyAll(
				replaceOnce(releasePath, grJobEnv, ""),
				replaceOnce(releasePath, "jobs:\n", "env:\n  GORELEASER_VERSION: v2.19.0\njobs:\n"),
			),
			want: []grMsg{{relLine + "6: ", `the job "release" has a goreleaser-action step, ` + grMsgNoJobPin}},
		},
		{
			name:   "job env is an expression",
			mutate: replaceOnce(releasePath, grJobEnv, "    env: ${{ fromJSON(vars.RELEASE_ENV) }}\n"),
			want: []grMsg{
				{relLine + "6: ", `the value of "env" must be a mapping, found a scalar`},
				{relLine + "4: ", grMsgNoJobPin},
			},
		},
		{
			name:   "job env is empty",
			mutate: replaceOnce(releasePath, grJobEnv, "    env:\n"),
			want: []grMsg{
				{relLine + "6: ", `the value of "env" must be a mapping, found an empty value`},
				{relLine + "4: ", grMsgNoJobPin},
			},
		},
		{
			name:   "unlisted workflow with a good job",
			mutate: setFile(".github/workflows/other.yml", &fstest.MapFile{Data: []byte("on: push\njobs: {a: {runs-on: x}}\n")}),
		},
		{
			// Only grScanWorkflow reads the jobs of an unlisted workflow, so
			// this is the only message for the bad job.
			name:   "unlisted workflow with a job that is not a mapping",
			mutate: setFile(".github/workflows/other.yml", &fstest.MapFile{Data: []byte("on: push\njobs: {a: x}\n")}),
			want:   []grMsg{{".github/workflows/other.yml:2: ", `the job "a" must be a mapping, found a scalar`}},
		},
		{
			name:   "steps not a sequence",
			mutate: replaceOnce(ciPath, "    steps:\n      - run: go test ./...\n", "    steps: go test\n"),
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
			mutate: replaceOnce(docPath, "check`.\n", "check`.\n\n`goreleaser@v2.19.0`\n"),
		},
		{
			name:   "latest",
			mutate: replaceOnce(docPath, grDocPin, "goreleaser/v2@latest"),
			want:   []grMsg{{docLine, `the GoReleaser version "latest" differs from the pin "v2.19.0" in ci.yml`}},
		},
		{
			name:   "short version",
			mutate: replaceOnce(docPath, grDocPin, "goreleaser/v2@v2.19"),
			want:   []grMsg{{docLine, `"v2.19" differs`}},
		},
		{
			name:   "second mention differs",
			mutate: replaceOnce(docPath, "check`.\n", "check`.\n\n`goreleaser@v2.18.0`\n"),
			want:   []grMsg{{"CONTRIBUTING.md:5: ", `"v2.18.0" differs`}},
		},
		{
			name:   "no version",
			mutate: replaceOnce(docPath, grDocPin, "goreleaser/v2"),
			want:   []grMsg{{"CONTRIBUTING.md: ", `names no GoReleaser version (goreleaser/vN@<version>), expected "v2.19.0"`}},
		},
		{
			// checkRequired reports a missing CONTRIBUTING.md.
			name:   "missing file",
			mutate: deleteFile(docPath),
		},
		{
			// checkRequired reports a CONTRIBUTING.md that is not a regular
			// file, so the rule gives no second message.
			name:   "directory",
			mutate: applyAll(deleteFile(docPath), setFile(docPath+"/inner", &fstest.MapFile{Data: []byte("x")})),
		},
		{
			name:   "named pipe",
			mutate: setFile(docPath, &fstest.MapFile{Mode: fs.ModeNamedPipe}),
		},
		{
			name:   "file over the limit",
			mutate: replaceOnce(docPath, "check`.\n", "check`.\n"+strings.Repeat("x", maxFileBytes)),
			want:   []grMsg{{"CONTRIBUTING.md: ", "the file has more than 1048576 bytes"}},
		},
		{
			name:   "overlong version text",
			mutate: replaceOnce(docPath, grDocPin, grDocPin+strings.Repeat("x", 300)),
			want:   []grMsg{{docLine, `"... differs from the pin "v2.19.0"`}},
		},
	})
}

// TestGoreleaserDocOverlongCapped checks that a message shows at most
// maxShown bytes of a long version text.
func TestGoreleaserDocOverlongCapped(t *testing.T) {
	t.Parallel()
	fsys := grGoodRepo()
	replaceOnce(docPath, grDocPin, grDocPin+strings.Repeat("x", 300))(t, fsys)
	got := checkGoreleaser(fsys, parseWorkflows(t, fsys))
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
			mutate: setFile(action, &fstest.MapFile{Data: []byte("runs:\n  using: composite\n")}),
		},
		{
			name:   "action names goreleaser-action",
			mutate: setFile(action, &fstest.MapFile{Data: []byte("runs:\n  steps:\n    - uses: GoReleaser/goreleaser-action@v7\n")}),
			want:   []grMsg{{action + ": ", "names goreleaser/goreleaser-action or GORELEASER_VERSION. This check does not read .github/actions."}},
		},
		{
			name:   "composite action writes GORELEASER_VERSION to GITHUB_ENV",
			mutate: setFile(action, &fstest.MapFile{Data: []byte("runs:\n  using: composite\n  steps:\n    - run: echo \"GORELEASER_VERSION=v1.0.0\" >> \"$GITHUB_ENV\"\n")}),
			want:   []grMsg{{action + ": ", "names goreleaser/goreleaser-action or GORELEASER_VERSION."}},
		},
		{
			name:   "Actions directory in another case",
			mutate: setFile(".github/Actions/build/action.yml", &fstest.MapFile{Data: []byte("uses: goreleaser/goreleaser-action@v7\n")}),
			want:   []grMsg{{".github/Actions/build/action.yml: ", "names goreleaser/goreleaser-action or GORELEASER_VERSION."}},
		},
		{
			name:   "symlink file",
			mutate: setFile(".github/actions/link.yml", symlink("../../release.yml")),
			want:   []grMsg{{".github/actions/link.yml: ", "is a symlink"}},
		},
		{
			name:   "symlink directory below actions",
			mutate: setFile(".github/actions/shared", symlink("../../shared")),
			want:   []grMsg{{".github/actions/shared: ", "is a symlink"}},
		},
		{
			name:   "actions directory is a symlink",
			mutate: setFile(".github/actions", symlink("../actions")),
			want:   []grMsg{{".github/actions: ", "is a symlink"}},
		},
		{
			name:   "named pipe",
			mutate: setFile(".github/actions/fifo", &fstest.MapFile{Mode: fs.ModeNamedPipe}),
			want:   []grMsg{{".github/actions/fifo: ", "is not a regular file"}},
		},
		{
			name:   "file over the limit",
			mutate: setFile(action, &fstest.MapFile{Data: make([]byte, maxFileBytes+1)}),
			want:   []grMsg{{action + ": ", "the file has more than 1048576 bytes"}},
		},
	})
}

// TestGoreleaserActionYAML covers the decoded check of a YAML file under
// .github/actions. A YAML escape such as \x2d hides the name from the raw bytes,
// but the decoded scalars show it. Each case has one file, so the messages are
// exact. The negative cases are the same escape in a file that is not YAML, a
// file that names another action, and a file that does not name the action.
func TestGoreleaserActionYAML(t *testing.T) {
	t.Parallel()
	const (
		action = ".github/actions/build/action.yml"
		// actionMsg is the message of action when it names the action.
		actionMsg = action + ": names goreleaser/goreleaser-action or GORELEASER_VERSION. This check does not read .github/actions. Extend the check before you add such a file"
	)
	tests := []struct {
		name string
		path string
		data string
		want []string // the exact messages, in order; nil means none
	}{
		{
			name: "escaped hyphen in action.yml",
			path: action,
			data: `runs:
  steps:
    - uses: "goreleaser/goreleaser\x2daction@v6"
`,
			want: []string{actionMsg},
		},
		{
			name: "escaped hyphen in action.yml, another action",
			path: action,
			data: `runs:
  steps:
    - uses: "goreleaser/goreleaser\x2dtool@v1"
`,
		},
		{
			name: "escaped hyphen in action.yaml",
			path: ".github/actions/build/action.yaml",
			data: `uses: "goreleaser/goreleaser\x2daction@v6"
`,
			want: []string{".github/actions/build/action.yaml: names goreleaser/goreleaser-action or GORELEASER_VERSION. This check does not read .github/actions. Extend the check before you add such a file"},
		},
		{
			name: "escaped hyphen in action.YML with an upper case extension",
			path: ".github/actions/build/action.YML",
			data: `uses: "goreleaser/goreleaser\x2daction@v6"
`,
			want: []string{".github/actions/build/action.YML: names goreleaser/goreleaser-action or GORELEASER_VERSION. This check does not read .github/actions. Extend the check before you add such a file"},
		},
		{
			// A backslash at the end of a line in a double-quoted scalar escapes the
			// line break, so the two lines join into the name.
			name: "name folded over two lines in a double-quoted scalar",
			path: action,
			data: `runs:
  steps:
    - uses: "goreleaser/goreleaser-\
      action@v6"
`,
			want: []string{actionMsg},
		},
		{
			name: "plain name in action.yml gives one message",
			path: action,
			data: `runs:
  steps:
    - uses: goreleaser/goreleaser-action@v6
`,
			want: []string{actionMsg},
		},
		{
			name: "action.yml that does not name the action",
			path: action,
			data: `runs:
  using: composite
`,
		},
		{
			// The escape is text in a file that is not YAML: only the raw check runs.
			name: "escaped name in a text file",
			path: ".github/actions/build/notes.txt",
			data: `uses: "goreleaser/goreleaser\x2daction@v6"
`,
		},
		{
			name: "plain name in a shell file gives one message",
			path: ".github/actions/build/run.sh",
			data: "uses: goreleaser/goreleaser-action@v6\n",
			want: []string{".github/actions/build/run.sh: names goreleaser/goreleaser-action or GORELEASER_VERSION. This check does not read .github/actions. Extend the check before you add such a file"},
		},
		{
			name: "GORELEASER_VERSION written to GITHUB_ENV in action.yml",
			path: action,
			data: `runs:
  using: composite
  steps:
    - run: echo "GORELEASER_VERSION=v1.0.0" >> "$GITHUB_ENV"
`,
			want: []string{actionMsg},
		},
		{
			name: "lower case goreleaser_version in action.yml",
			path: action,
			data: `runs:
  using: composite
  steps:
    - run: echo "goreleaser_version=v1.0.0" >> "$GITHUB_ENV"
`,
			want: []string{actionMsg},
		},
		{
			// The escape \x5f is _ in the decoded text. The raw bytes do not hold the name.
			name: "escaped underscore in a double-quoted run of action.yml",
			path: action,
			data: `runs:
  steps:
    - run: "echo \"GORELEASER\x5fVERSION=v1.0.0\" >> \"$GITHUB_ENV\""
`,
			want: []string{actionMsg},
		},
		{
			name: "GORELEASER_VERSION written to GITHUB_ENV in a shell file",
			path: ".github/actions/build/write.sh",
			data: "echo \"GORELEASER_VERSION=v1.0.0\" >> \"$GITHUB_ENV\"\n",
			want: []string{".github/actions/build/write.sh: names goreleaser/goreleaser-action or GORELEASER_VERSION. This check does not read .github/actions. Extend the check before you add such a file"},
		},
		{
			// The escape is text in a file that is not YAML: only the raw check runs.
			name: "escaped GORELEASER_VERSION in a text file",
			path: ".github/actions/build/notes-version.txt",
			data: `"GORELEASER\x5fVERSION=v1.0.0"
`,
		},
		{
			name: "action.yml that writes another variable to GITHUB_ENV",
			path: action,
			data: `runs:
  steps:
    - run: echo "FOO=v1" >> "$GITHUB_ENV"
`,
		},
		{
			name: "unparsable action.yml fails closed",
			path: action,
			data: "steps: [unclosed\n",
			want: []string{action + ": parse YAML: yaml: line 1: did not find expected ',' or ']'"},
		},
		{
			name: "anchor in action.yml fails closed",
			path: action,
			data: `runs:
  x: &a y
`,
			want: []string{action + ":2: an anchor (&a) is not allowed"},
		},
		{
			name: "two documents in action.yml fail closed",
			path: action,
			data: `name: a
---
name: b
`,
			want: []string{action + ":2: the file has more than one YAML document"},
		},
		{
			name: "empty action.yml fails closed",
			path: action,
			data: "",
			want: []string{action + ": the file has no YAML document"},
		},
		{
			name: "file over the limit",
			path: action,
			data: strings.Repeat("x", maxFileBytes+1),
			want: []string{action + ": the file has more than 1048576 bytes, so the check does not read it"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fsys := fstest.MapFS{tt.path: {Data: []byte(tt.data)}}
			if got := grWalkActions(fsys, grActionsPath); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("grWalkActions() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGoreleaserMissingWorkflow covers a missing ci.yml or release.yml. The
// rules that need the workflow do not run and give no message: check reports
// the missing file once. Each case also changes a pin, so a rule that still
// ran on the missing workflow would give a message.
func TestGoreleaserMissingWorkflow(t *testing.T) {
	t.Parallel()
	grRunCases(t, []grCase{
		{
			// No pin to compare: release.yml and CONTRIBUTING.md are not checked.
			name: "missing ci.yml",
			mutate: applyAll(
				deleteFile(ciPath),
				replaceOnce(releasePath, grPinLine, "GORELEASER_VERSION: v2.18.0"),
				replaceOnce(docPath, grDocPin, "goreleaser/v2@latest"),
			),
		},
		{
			name:   "missing release.yml",
			mutate: deleteFile(releasePath),
		},
	})
}

// TestGoreleaserExactKeys covers the keys that GitHub reads case-sensitively:
// jobs, the job env and the step with. A key in another case does not satisfy
// the rule, so each case gives the whole list of messages, and the count is
// checked too.
func TestGoreleaserExactKeys(t *testing.T) {
	t.Parallel()
	const (
		relPin  = `the workflow has no full GORELEASER_VERSION pin in the env of a job, expected "v2.19.0" (the pin in ci.yml)`
		relEnv  = `the job "release" has a goreleaser-action step, ` + grMsgNoJobPin
		relWith = `the goreleaser-action step "Run GoReleaser" has no with mapping, so it has no version input`
		ciWith  = `the goreleaser-action step "Check" has no with mapping, so it has no version input`
		noJobs  = "the workflow has no jobs mapping"
	)
	tests := []struct {
		name   string
		mutate mutation
		want   []grMsg // the whole list; its length is the exact count
	}{
		{name: "good repo gives no message"},
		{
			name:   "ci.yml with Jobs: key",
			mutate: replaceOnce(ciPath, "jobs:\n", "Jobs:\n"),
			want: []grMsg{
				{ciLine + "1: ", noJobs},
				{ciLine, grMsgOnePin + " (GORELEASER_VERSION in the env of a job). Found: none"},
				{ciLine + "7: ", grMsgMention},
				{ciLine + "10: ", grMsgNames},
				{ciLine + "13: ", grMsgMention},
			},
		},
		{
			name:   "release.yml with Jobs: key",
			mutate: replaceOnce(releasePath, "jobs:\n", "Jobs:\n"),
			want: []grMsg{
				{relLine + "1: ", noJobs},
				{relLine + "7: ", grMsgMention},
				{relLine + "10: ", grMsgNames},
				{relLine + "13: ", grMsgMention},
				{".github/workflows/release.yml: ", relPin},
			},
		},
		{
			name:   "release.yml with ENV: key in the release job",
			mutate: replaceOnce(releasePath, "    env:\n", "    ENV:\n"),
			want: []grMsg{
				{relLine + "4: ", relEnv},
				{relLine + "7: ", grMsgMention},
				{".github/workflows/release.yml: ", relPin},
			},
		},
		{
			name:   "release.yml with With: key on the goreleaser-action step",
			mutate: replaceOnce(releasePath, "        with:\n", "        With:\n"),
			want: []grMsg{
				{relLine + "9: ", relWith},
				{relLine + "13: ", grMsgMention},
			},
		},
		{
			name:   "ci.yml with With: key on the goreleaser-action step",
			mutate: replaceOnce(ciPath, "        with:\n", "        With:\n"),
			want: []grMsg{
				{ciLine + "9: ", ciWith},
				{ciLine + "13: ", grMsgMention},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fsys := grGoodRepo()
			if tc.mutate != nil {
				tc.mutate(t, fsys)
			}
			got := checkGoreleaser(fsys, parseWorkflows(t, fsys))
			grCheckMsgs(t, got, tc.want)
			if len(got) != len(tc.want) {
				t.Errorf("checkGoreleaser() gave %d messages, want %d: %q", len(got), len(tc.want), got)
			}
		})
	}
}

// TestGoreleaserNilMap checks that a nil map gives no message and does not
// panic. Reading a key of a nil map is allowed in Go and gives nil.
func TestGoreleaserNilMap(t *testing.T) {
	t.Parallel()
	if got := checkGoreleaser(grGoodRepo(), nil); len(got) != 0 {
		t.Errorf("checkGoreleaser(nil map) = %q, want no message", got)
	}
}

// TestGoreleaserStableOrder checks that the messages come in the same order on
// every run, although a Go map has no order.
func TestGoreleaserStableOrder(t *testing.T) {
	t.Parallel()
	fsys := grGoodRepo()
	applyAll(
		replaceOnce(releasePath, grPinLine, "GORELEASER_VERSION: v2.18.0"),
		setFile(".github/workflows/a.yml", &fstest.MapFile{Data: []byte(strings.Replace(grGoodRelease, "v2.19.0", "v2.17.0", 1))}),
		setFile(".github/workflows/z.yml", &fstest.MapFile{Data: []byte(strings.Replace(grGoodRelease, "v2.19.0", "v2.16.0", 1))}),
		replaceOnce(docPath, grDocPin, "goreleaser/v2@latest"),
		setFile(".github/actions/a.yml", &fstest.MapFile{Data: []byte("goreleaser/goreleaser-action")}),
		setFile(".github/actions/b.yml", &fstest.MapFile{Data: []byte("goreleaser/goreleaser-action")}),
	)(t, fsys)
	first := checkGoreleaser(fsys, parseWorkflows(t, fsys))
	if len(first) < 6 {
		t.Fatalf("checkGoreleaser() = %q, want at least 6 messages", first)
	}
	for range 20 {
		if got := checkGoreleaser(fsys, parseWorkflows(t, fsys)); !reflect.DeepEqual(got, first) {
			t.Fatalf("checkGoreleaser() order changed:\n got %q\nwant %q", got, first)
		}
	}
}

// TestSymlinkUnder checks the exact text of the symlink and pipe problems of
// .github/actions. grCheckActions and grWalkActions build them with symlinkUnder
// and with the text of the pipe case, so these texts must not change.
func TestSymlinkUnder(t *testing.T) {
	t.Parallel()
	const dir = ".github/actions"
	if got, want := symlinkUnder(dir+"/link.yml", grActionsPath), dir+"/link.yml: is a symlink. This check does not follow symlinks under "+dir; got != want {
		t.Errorf("symlinkUnder() = %q, want %q", got, want)
	}
	tests := []struct {
		name string
		fsys fstest.MapFS
		want []string
	}{
		{
			name: "symlink file below actions",
			fsys: fstest.MapFS{dir + "/link.yml": {Data: []byte("../../release.yml"), Mode: fs.ModeSymlink | 0o777}},
			want: []string{dir + "/link.yml: is a symlink. This check does not follow symlinks under " + dir},
		},
		{
			name: "actions directory is a symlink",
			fsys: fstest.MapFS{dir: {Data: []byte("../actions"), Mode: fs.ModeSymlink | 0o777}},
			want: []string{dir + ": is a symlink. This check does not follow symlinks under " + dir},
		},
		{
			name: "named pipe below actions",
			fsys: fstest.MapFS{dir + "/fifo": {Mode: fs.ModeNamedPipe}},
			want: []string{dir + "/fifo: is not a regular file. This check reads only regular files under " + dir},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := grCheckActions(tt.fsys); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("grCheckActions() = %q, want %q", got, tt.want)
			}
		})
	}
}
