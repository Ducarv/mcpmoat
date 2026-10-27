#!/usr/bin/env bash
# Tests check-tool-pins.sh on changed copies of the files that it reads. The
# ci-scripts job in ci.yml runs it. You can also run it on your machine,
# from any directory: see CONTRIBUTING.md, Checks. It needs bash and the
# standard tools that check-tool-pins.sh needs, and also cp, mv, mkdir, head,
# basename, cmp, mktemp and ln.
# shellcheck disable=SC2016 # the sed expressions and the call hold a literal $
set -euo pipefail

src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

wf=.github/workflows
# workflows is the list of check-tool-pins.sh.
workflows=(ci release govulncheck)
failed=0
total=0

# current_pin prints the version that ci.yml pins for NAME ($1). The cases read
# it, so that a version bump does not break them.
current_pin() {
  sed -nE "s/^ *$1: *\"?(v[^\" ]+).*/\\1/p" "$src/$wf/ci.yml" | head -n 1
}
vuln_ver=$(current_pin GOVULNCHECK_VERSION)

# sub edits a file of the copy with a sed expression. It works with GNU and
# BSD sed. It fails when sed fails or when the expression changes nothing, so
# that a broken expression cannot let a case pass without a change.
sub() {
  sed -E "$2" "$1" >"$1.new" || return 1
  if cmp -s "$1" "$1.new"; then
    echo "sub: '$2' changes nothing in $1" >&2
    return 1
  fi
  mv "$1.new" "$1"
}

# after_call adds a line right after the call line of a file of the copy.
after_call() {
  awk -v add="$2" '{ print } /run: go run "golang/ { print add }' "$1" >"$1.new" && mv "$1.new" "$1"
}

# append adds a line to a file of the copy.
append() {
  printf '%s\n' "$2" >>"$1"
}

# check_case copies the files that the script reads, changes the copy with the
# command after the message, and runs the script. The case passes when the
# exit code is the wanted one. A case that wants exit 1 also needs the message
# to contain the text of $3, so that it fails for the reason in its name.
check_case() {
  local name=$1 want=$2 msg=$3 got=0 out
  shift 3
  total=$((total + 1))
  rm -rf "${tmp:?}/w"
  mkdir -p "$tmp/w/.github"
  cp -R "$src/.github/scripts" "$src/$wf" "$tmp/w/.github/"
  cp "$src/CONTRIBUTING.md" "$tmp/w/"
  if ! (cd "$tmp/w" && "$@"); then
    echo "FAIL: $name: the change to the copy failed" >&2
    failed=$((failed + 1))
    return
  fi
  out=$("$tmp/w/.github/scripts/check-tool-pins.sh" 2>&1) || got=$?
  if [ "$got" != "$want" ]; then
    echo "FAIL: $name: exit $got, want $want: $out" >&2
    failed=$((failed + 1))
  elif [ "$want" = 1 ] && [[ $out != *"$msg"* ]]; then
    echo "FAIL: $name: the message lacks '$msg': $out" >&2
    failed=$((failed + 1))
  fi
}

# call is the call line of govulncheck in the workflows.
call='        run: go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...'

# append_step adds a step to a file. The step pins version $2 and has the call.
append_step() {
  printf '      - env:\n          GOVULNCHECK_VERSION: %s\n%s\n' "$2" "$call" >>"$1"
}

# decoy_pin makes the real pin invalid and adds a second step with a valid
# pin, so that one good pin cannot hide a bad one.
decoy_pin() {
  sub "$wf/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: latest/' &&
    append_step "$wf/govulncheck.yml" "$vuln_ver"
}

# same_extra_pin_everywhere adds the same second pin to all three workflows.
same_extra_pin_everywhere() {
  local f
  for f in "${workflows[@]}"; do
    append_step "$wf/$f.yml" v0.0.1 || return 1
  done
}

# float_govulncheck and float_goreleaser cut the patch number of a pin in every
# file that holds it. Go reads a short version as a query for the newest match.
float_govulncheck() {
  local f
  for f in "${workflows[@]}"; do
    sub "$wf/$f.yml" 's/(GOVULNCHECK_VERSION: v[0-9]+\.[0-9]+)\.[0-9]+/\1/' || return 1
  done
}

float_goreleaser() {
  sub "$wf/ci.yml" 's/(GORELEASER_VERSION: v[0-9]+\.[0-9]+)\.[0-9]+/\1/' &&
    sub "$wf/release.yml" 's/(GORELEASER_VERSION: v[0-9]+\.[0-9]+)\.[0-9]+/\1/' &&
    sub CONTRIBUTING.md 's|(goreleaser/v[0-9]+@v[0-9]+\.[0-9]+)\.[0-9]+|\1|g'
}

# fourth_workflow adds a workflow that is not in the list of the script. It
# runs govulncheck with a version of its own. $1 is the file name. $2 is the
# number of padding lines: a large file has more output than a pipe holds.
fourth_workflow() {
  {
    printf 'name: extra\njobs:\n  x:\n    steps:\n      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...\n' &&
      awk -v n="$2" 'BEGIN { for (i = 0; i < n; i++) print "      - run: echo padding padding padding padding" }'
  } >"$wf/$1"
}

# gr_ver is the GoReleaser pin of ci.yml. The new workflows define it, as the
# check requires for a file with a goreleaser-action step.
gr_ver=$(current_pin GORELEASER_VERSION)

# step_workflow writes a workflow, with the file name $1, that defines the pin
# of GoReleaser and has the steps text $2 (several lines, in the steps list).
step_workflow() {
  printf 'name: extra\njobs:\n  x:\n    env:\n      GORELEASER_VERSION: %s\n    steps:\n%s\n' "$gr_ver" "$2" >"$wf/$1"
}

# goreleaser_workflow writes a workflow, with the file name $1, that has one
# goreleaser-action step. The step starts on its "- uses:" line. $2 is the
# version line of the step. When $2 is empty, the step has no version line.
goreleaser_workflow() {
  local ver=''
  if [ -n "$2" ]; then ver=$'\n'"          $2"; fi
  step_workflow "$1" "      - uses: goreleaser/goreleaser-action@x
        with:
          distribution: goreleaser$ver
          args: check"
}

# add_define_to adds a GORELEASER_VERSION line to a file of the copy.
add_define_to() {
  append "$wf/$1" "      GORELEASER_VERSION: $2"
}

# write_workflow_without_pin writes a workflow, with the file name $1, that has a
# good goreleaser-action step but does not define GORELEASER_VERSION.
write_workflow_without_pin() {
  printf 'name: extra\njobs:\n  x:\n    steps:\n      - uses: goreleaser/goreleaser-action@x\n        with:\n          version: ${{ env.GORELEASER_VERSION }}\n' >"$wf/$1"
}

# wf_with_pin writes extra.yml with a good step and the pin value $1.
wf_with_pin() {
  write_workflow_without_pin extra.yml &&
    printf '    env:\n      GORELEASER_VERSION: %s\n' "$1" >>"$wf/extra.yml"
}

# step_workflow_pin writes a workflow, with the file name $1, with the pin value
# $2 and no goreleaser step.
step_workflow_pin() {
  printf 'name: extra\njobs:\n  x:\n    env:\n      GORELEASER_VERSION: %s\n    steps:\n      - run: echo hi\n' "$2" >"$wf/$1"
}

# rc_goreleaser and quoted_goreleaser change the pin of GoReleaser in every file
# that holds it. The form is still a full version, so the files must pass.
rc_goreleaser() {
  sub "$wf/ci.yml" 's/(GORELEASER_VERSION: v[0-9]+\.[0-9]+\.[0-9]+)/\1-rc.1/' &&
    sub "$wf/release.yml" 's/(GORELEASER_VERSION: v[0-9]+\.[0-9]+\.[0-9]+)/\1-rc.1/' &&
    sub CONTRIBUTING.md 's|(goreleaser/v[0-9]+@v[0-9]+\.[0-9]+\.[0-9]+)|\1-rc.1|g'
}

quoted_goreleaser() {
  sub "$wf/ci.yml" 's/(GORELEASER_VERSION: )(v[0-9.]+)/\1"\2" # note/' &&
    sub "$wf/release.yml" 's/(GORELEASER_VERSION: )(v[0-9.]+)/\1"\2" # note/'
}

# job_workflow writes a workflow, with the file name $1, with one job. The job
# defines the pin, then the extra env text $2 (may be empty), then the steps
# text $3. This puts a line next to the pin, where a bypass would go.
job_workflow() {
  printf 'name: extra\njobs:\n  x:\n    env:\n      GORELEASER_VERSION: %s\n%s\n    steps:\n%s\n' "$gr_ver" "$2" "$3" >"$wf/$1"
}

# two_jobs_workflow writes a workflow, with the file name $1, with a job "a" that
# has a step without goreleaser and a job "b" that has the good goreleaser-action
# step. The text $2 is the env of job "a" and the text $3 is the env of job "b".
two_jobs_workflow() {
  printf 'name: extra\njobs:\n  a:\n%s\n    steps:\n      - run: echo hi\n  b:\n%s\n    steps:\n      - uses: goreleaser/goreleaser-action@x\n        with:\n          version: ${{ env.GORELEASER_VERSION }}\n' "$2" "$3" >"$wf/$1"
}

# actions_file writes the composite action .github/actions/x/action.yml with the
# text $1.
actions_file() {
  mkdir -p .github/actions/x && printf '%s\n' "$1" >.github/actions/x/action.yml
}

# step_workflow_top writes a workflow, with the file name $1, with the pin in the
# env of the workflow and a good step in a job that has no env.
step_workflow_top() {
  printf 'name: extra\nenv:\n  GORELEASER_VERSION: %s\njobs:\n  x:\n    steps:\n      - uses: goreleaser/goreleaser-action@x\n        with:\n          version: ${{ env.GORELEASER_VERSION }}\n' "$gr_ver" >"$wf/$1"
}

# wf_pin_indent writes a workflow, with the file name $1, with the pin at the
# indent of a job key, not in the env.
wf_pin_indent() {
  printf 'name: extra\njobs:\n  x:\n    GORELEASER_VERSION: %s\n    steps:\n      - uses: goreleaser/goreleaser-action@x\n        with:\n          version: ${{ env.GORELEASER_VERSION }}\n' "$gr_ver" >"$wf/$1"
}

# wf_pin_other_key writes a workflow, with the file name $1, with the pin at the
# right indent but under another job key than env, and no env in the job.
wf_pin_other_key() {
  printf 'name: extra\njobs:\n  x:\n    outputs:\n      GORELEASER_VERSION: %s\n    steps:\n      - uses: goreleaser/goreleaser-action@x\n        with:\n          version: ${{ env.GORELEASER_VERSION }}\n' "$gr_ver" >"$wf/$1"
}

# anchor_poc turns the GoReleaser check step of ci.yml into an anchor with the
# name $1 (default gr) and adds a job that uses the alias. The alias line names
# nothing, and the new job has no pin of its own.
anchor_poc() {
  awk -v n="${1:-gr}" '/- name: Check the GoReleaser config/ { print "      - &" n; sub(/- name:/, "  name:") } { print }' "$wf/ci.yml" >"$wf/ci.yml.new" &&
    mv "$wf/ci.yml.new" "$wf/ci.yml" &&
    printf '  alias-job:\n    runs-on: ubuntu-latest\n    steps:\n      - *%s\n' "${1:-gr}" >>"$wf/ci.yml"
}

# symlinked_action puts a composite action that names goreleaser-action outside
# .github/actions and links to it from inside.
symlinked_action() {
  mkdir -p elsewhere .github/actions &&
    printf '    - uses: goreleaser/goreleaser-action@x\n' >elsewhere/action.yml &&
    ln -s ../../elsewhere .github/actions/y
}

# The real files must pass.
check_case "real files" 0 "" true

# The pin of govulncheck.
check_case "govulncheck: different pin" 1 "The govulncheck pin of" sub "$wf/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: v0.0.1/'
check_case "govulncheck: no pin in ci.yml" 1 "ci.yml must pin one version of govulncheck" sub "$wf/ci.yml" '/^ *GOVULNCHECK_VERSION: v/d'
check_case "govulncheck: pin value latest" 1 "has no GOVULNCHECK_VERSION pin" sub "$wf/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: latest/'
check_case "govulncheck: pin value from vars" 1 "has no GOVULNCHECK_VERSION pin" sub "$wf/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: ${{ vars.X }}/'
check_case "govulncheck: pin value latest and a decoy pin" 1 "is not the pin, the call line or a name" decoy_pin
check_case "govulncheck: short version in all files" 1 "ci.yml must pin one version of govulncheck" float_govulncheck
check_case "govulncheck: two equal pins in a file" 0 "" append_step "$wf/release.yml" "$vuln_ver"
check_case "govulncheck: two different pins in a file" 1 "The govulncheck pin of" append_step "$wf/release.yml" v0.0.1
check_case "govulncheck: two pins in ci.yml" 1 "ci.yml must pin one version of govulncheck" append_step "$wf/ci.yml" v0.0.1
check_case "govulncheck: same extra pin in all files" 1 "ci.yml must pin one version of govulncheck" same_extra_pin_everywhere

# The call of govulncheck.
check_case "call: hard-coded version" 1 "release.yml has no call line" sub "$wf/release.yml" 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@v0.0.1/'
check_case "call: @latest" 1 "govulncheck.yml has no call line" sub "$wf/govulncheck.yml" 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@latest/'
check_case "call: braces form" 1 "govulncheck.yml has no call line" sub "$wf/govulncheck.yml" 's/\$GOVULNCHECK_VERSION"/${GOVULNCHECK_VERSION}"/'
check_case "call: variable name with a suffix" 1 "govulncheck.yml has no call line" sub "$wf/govulncheck.yml" 's/\$GOVULNCHECK_VERSION"/$GOVULNCHECK_VERSION_X"/'
check_case "call: quote before @latest" 1 "govulncheck.yml has no call line" sub "$wf/govulncheck.yml" 's|run: go run .*|run: go run "golang.org/x/vuln/cmd/govulncheck"@latest ./...|'
check_case "call: variable set in the run line" 1 "govulncheck.yml has no call line" sub "$wf/govulncheck.yml" 's|run: go run|run: GOVULNCHECK_VERSION=latest; go run|'
check_case "call: go install @latest and the call" 1 "release.yml has no call line" sub "$wf/release.yml" 's|run: go run|run: go install golang.org/x/vuln/cmd/govulncheck@latest \&\& go run|'
check_case "call: inline comment after the call" 1 "release.yml has no call line" sub "$wf/release.yml" 's@^(.*run: go run .*)$@\1 # x@'
check_case "call: || true after the call" 1 "release.yml has no call line" sub "$wf/release.yml" 's@^(.*run: go run .*)$@\1 || true@'
check_case "continuation line after the call" 1 "govulncheck.yml: line uses a YAML form this check cannot read" after_call "$wf/govulncheck.yml" '          || true'
check_case "continuation line after the call in release.yml" 1 "release.yml: line uses a YAML form this check cannot read" after_call "$wf/release.yml" '          || true'
check_case "continue-on-error in a step" 1 "uses continue-on-error" append "$wf/govulncheck.yml" '        continue-on-error: true'
check_case "continue-on-error as the first key of a step" 1 "uses continue-on-error" append "$wf/govulncheck.yml" '      - continue-on-error: true'
check_case "govulncheck-action step" 1 "is not the pin, the call line or a name" append "$wf/govulncheck.yml" '      - uses: golang/govulncheck-action@v1'
check_case "bare govulncheck: line after the call" 1 "govulncheck.yml: line uses a YAML form this check cannot read" after_call "$wf/govulncheck.yml" '          govulncheck:'
check_case "job ID govulncheck in ci.yml" 1 "is not the pin, the call line or a name" append "$wf/ci.yml" '  govulncheck:'
check_case "call: no call in release.yml" 1 "release.yml has no call line" sub "$wf/release.yml" '/govulncheck@/d'
check_case "comment names govulncheck@v1.2.3" 0 "" append "$wf/release.yml" '# see govulncheck@v1.2.3'

# A workflow outside the list.
check_case "fourth workflow with a space in its name" 1 "mentions govulncheck" fourth_workflow "ci release.yml" 0
check_case "fourth workflow runs govulncheck" 1 "mentions govulncheck" fourth_workflow extra.yml 0
check_case "fourth workflow with the .yaml extension" 1 "mentions govulncheck" fourth_workflow extra.yaml 0
check_case "large fourth workflow runs govulncheck" 1 "mentions govulncheck" fourth_workflow extra.yml 4000

# Missing files.
check_case "ci.yml missing" 1 "ci.yml is missing" rm "$wf/ci.yml"
check_case "release.yml missing" 1 "release.yml is missing" rm "$wf/release.yml"
check_case "govulncheck.yml missing" 1 "govulncheck.yml is missing" rm "$wf/govulncheck.yml"
check_case "CONTRIBUTING.md missing" 1 "CONTRIBUTING.md is missing" rm CONTRIBUTING.md

# The pin of GoReleaser.
check_case "GoReleaser: different pin in release.yml" 1 "The GoReleaser pins differ" sub "$wf/release.yml" 's/GORELEASER_VERSION: v[0-9.]+/GORELEASER_VERSION: v0.0.1/'
check_case "GoReleaser: different pin in CONTRIBUTING.md" 1 "The GoReleaser pins differ" sub CONTRIBUTING.md 's|(goreleaser/v[0-9]+)@v[0-9.]+|\1@v0.0.1|g'
check_case "GoReleaser: different pin in one command only" 1 "The GoReleaser pins differ" sub CONTRIBUTING.md '/ check /s|(goreleaser/v[0-9]+)@v[0-9.]+|\1@v0.0.1|'
check_case "GoReleaser: pin value latest in release.yml" 1 "not a full version" append "$wf/release.yml" '      GORELEASER_VERSION: latest'
check_case "GoReleaser: short pin value in ci.yml" 1 "not a full version" append "$wf/ci.yml" "      GORELEASER_VERSION: ${gr_ver%.*}"
check_case "GoReleaser: @latest in one CONTRIBUTING.md command" 1 "The GoReleaser pins differ" sub CONTRIBUTING.md '/ check /s|(goreleaser/v[0-9]+)@v[0-9.]+|\1@latest|'
check_case "GoReleaser: short version in one CONTRIBUTING.md command" 1 "The GoReleaser pins differ" sub CONTRIBUTING.md '/ check /s|(goreleaser/v[0-9]+@v[0-9]+\.[0-9]+)\.[0-9]+|\1|'
check_case "GoReleaser: two pins in ci.yml" 1 "ci.yml must pin one version of GoReleaser" append "$wf/ci.yml" '      GORELEASER_VERSION: v0.0.1'
check_case "GoReleaser: no pin in ci.yml" 1 "ci.yml must pin one version of GoReleaser" sub "$wf/ci.yml" '/GORELEASER_VERSION: v/d'
check_case "GoReleaser: no pin in release.yml" 1 "The GoReleaser pins differ" sub "$wf/release.yml" '/GORELEASER_VERSION: v/d'
check_case "GoReleaser: no version in CONTRIBUTING.md" 1 "The GoReleaser pins differ" sub CONTRIBUTING.md '/goreleaser\/v2@/d'
check_case "GoReleaser: short version in all files" 1 "ci.yml must pin one version of GoReleaser" float_goreleaser

# The version input of each goreleaser-action step. The real steps are in
# ci.yml (two) and release.yml (one). The ranges select the step of a case.
ga_check="/Check the GoReleaser config/,/args: check/"
ga_release="/Run GoReleaser/,/args: release/"
check_case "goreleaser-action: hard-coded version" 1 "ci.yml: the step \"- name: Check the GoReleaser config\" has a version input that is not" sub "$wf/ci.yml" "$ga_check"'s/version: .*/version: v2.0.0/'
check_case "goreleaser-action: version latest" 1 "release.yml: the step \"- name: Run GoReleaser\" has a version input that is not" sub "$wf/release.yml" "$ga_release"'s/version: .*/version: latest/'
check_case "goreleaser-action: other variable" 1 "has a version input that is not" sub "$wf/release.yml" "$ga_release"'s/GORELEASER_VERSION/OTHER_VERSION/'
check_case "goreleaser-action: text after the variable" 1 "has a version input that is not" sub "$wf/release.yml" "$ga_release"'s/(version: .*)$/\1-x/'
check_case "goreleaser-action: no version input" 1 "release.yml: the step \"- name: Run GoReleaser\" has no version input" sub "$wf/release.yml" "$ga_release"'{/version:/d;}'
check_case "goreleaser-action: no version input, next step has one" 1 "ci.yml: the step \"- name: Check the GoReleaser config\" has no version input" sub "$wf/ci.yml" "$ga_check"'{/version:/d;}'
check_case "goreleaser-action: new workflow without a version" 1 "extra.yml: the step \"- uses: goreleaser/goreleaser-action@x\" has no version input" goreleaser_workflow extra.yml ""
check_case "goreleaser-action: new .yaml workflow with latest" 1 "extra.yaml: the step" goreleaser_workflow extra.yaml "version: latest"
check_case "goreleaser-action: new workflow, quoted pin and trailing spaces" 0 "" goreleaser_workflow extra.yml 'version: "${{ env.GORELEASER_VERSION }}"   '
check_case "goreleaser-action: new workflow, comment after the pin" 0 "" goreleaser_workflow extra.yml 'version: ${{ env.GORELEASER_VERSION }} # pinned'
check_case "goreleaser-action: new workflow, plain pin" 0 "" goreleaser_workflow extra.yml 'version: ${{ env.GORELEASER_VERSION }}'

# The bypass classes of the step check. ok_ver is the allowed version line.
ok_ver='version: ${{ env.GORELEASER_VERSION }}'
w_with="        with:
          distribution: goreleaser
          $ok_ver"
w_latest="        with:
          version: latest"
# (a) A quoted uses value.
check_case "goreleaser-action: quoted uses, version latest" 1 "extra.yml: the step" step_workflow extra.yml "      - uses: \"goreleaser/goreleaser-action@x\"
$w_latest"
check_case "goreleaser-action: single-quoted uses, version latest" 1 "extra.yml: the step" step_workflow extra.yml "      - uses: 'goreleaser/goreleaser-action@x'
$w_latest"
check_case "goreleaser-action: quoted uses, no version" 1 "has no version input" step_workflow extra.yml "      - uses: \"goreleaser/goreleaser-action@x\""
check_case "goreleaser-action: quoted uses, good version" 0 "" step_workflow extra.yml "      - uses: \"goreleaser/goreleaser-action@x\"
$w_with"
check_case "goreleaser-action: single-quoted uses, good version" 0 "" step_workflow extra.yml "      - uses: 'goreleaser/goreleaser-action@x' # note
$w_with"
# (b) Owner and repo names ignore case.
check_case "goreleaser-action: other case, version latest" 1 "extra.yml: the step" step_workflow extra.yml "      - uses: GoReleaser/goreleaser-action@x
$w_latest"
check_case "goreleaser-action: other case, good version" 0 "" step_workflow extra.yml "      - uses: GoReleaser/GoReleaser-Action@x
$w_with"
# (c) Flow style, and (g) other styles that the check cannot read.
check_case "goreleaser-action: flow style" 1 "a line names goreleaser-action in a style this check cannot read" step_workflow extra.yml "      - {uses: goreleaser/goreleaser-action@x, with: {version: latest}}"
check_case "goreleaser-action: flow style, good version" 1 "a style this check cannot read" step_workflow extra.yml "      - {uses: goreleaser/goreleaser-action@x, with: {version: \${{ env.GORELEASER_VERSION }}}}"
check_case "goreleaser-action: anchor before the action" 1 "line uses a YAML form this check cannot read" step_workflow extra.yml "      - uses: &a goreleaser/goreleaser-action@x
$w_with"
check_case "goreleaser-action: uses value on the next line" 1 "a style this check cannot read" step_workflow extra.yml "      - uses:
          goreleaser/goreleaser-action@x
$w_with"
check_case "goreleaser-action: action path in a name line" 1 "a style this check cannot read" step_workflow extra.yml "      - name: goreleaser/goreleaser-action
        run: echo hi"
check_case "goreleaser-action: action word without the path in a name line" 0 "" step_workflow extra.yml "      - name: Run goreleaser-action
        uses: goreleaser/goreleaser-action@x
$w_with"
check_case "goreleaser-action: local action" 0 "" step_workflow extra.yml "      - uses: ./some/local@x"
# (d) More than one space after the dash.
check_case "goreleaser-action: extra spaces after the dash, version latest" 1 "extra.yml: the step" step_workflow extra.yml "      -   uses: goreleaser/goreleaser-action@x
          with:
            version: latest"
check_case "goreleaser-action: extra spaces after the dash, no version" 1 "has no version input" step_workflow extra.yml "      -   uses: goreleaser/goreleaser-action@x"
check_case "goreleaser-action: extra spaces after the dash, good version" 0 "" step_workflow extra.yml "      -   uses: goreleaser/goreleaser-action@x
          with:
            $ok_ver"
check_case "goreleaser-action: with on the first line, good version" 0 "" step_workflow extra.yml "      - with:
          $ok_ver
        uses: goreleaser/goreleaser-action@x"
# (e) A version key outside the with: block does not count.
check_case "goreleaser-action: version under env" 1 "has no version input" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          distribution: goreleaser
        env:
          $ok_ver"
check_case "goreleaser-action: version at the step level" 1 "has no version input" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          distribution: goreleaser
        $ok_ver"
check_case "goreleaser-action: version in a nested mapping of with" 1 "has no version input" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          extra:
            $ok_ver"
check_case "goreleaser-action: good version in env, latest in with" 1 "has a version input that is not" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          version: latest
        env:
          $ok_ver"
check_case "goreleaser-action: version after env, back in with" 0 "" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          distribution: goreleaser
          $ok_ver
          args: check
        env:
          X: y"
# (f) GORELEASER_VERSION must be a full pin that equals ci.yml, in every file.
check_case "GoReleaser: new workflow, no definition" 1 "extra.yml has a goreleaser-action step but does not define GORELEASER_VERSION" write_workflow_without_pin extra.yml
check_case "GoReleaser: new workflow, pin value latest" 1 "extra.yml has a GORELEASER_VERSION line that is not a full version" wf_with_pin latest
check_case "GoReleaser: new workflow, other full pin" 1 "extra.yml has GORELEASER_VERSION v0.0.1, expected" wf_with_pin v0.0.1
check_case "GoReleaser: new workflow, same pin" 0 "" wf_with_pin "$gr_ver"
check_case "GoReleaser: other pin in govulncheck.yml" 1 "govulncheck.yml has GORELEASER_VERSION v0.0.1, expected" add_define_to govulncheck.yml v0.0.1
check_case "GoReleaser: latest in govulncheck.yml" 1 "govulncheck.yml has a GORELEASER_VERSION line that is not a full version" add_define_to govulncheck.yml latest
check_case "GoReleaser: pin in a new .yaml workflow without a step" 1 "extra.yaml has GORELEASER_VERSION v0.0.1, expected" step_workflow_pin extra.yaml v0.0.1

# Ways to change the version at run time. The step reads the pin, but another
# line could change what env.GORELEASER_VERSION holds. Each form must fail.
w_step="      - uses: goreleaser/goreleaser-action@x
        with:
          $ok_ver"
mention="mentions GORELEASER_VERSION in a form this check does not allow"
check_case "override: job env, same pin" 0 "" job_workflow extra.yml "" "$w_step"
check_case "override: space before the colon" 1 "$mention" job_workflow extra.yml "      GORELEASER_VERSION : latest" "$w_step"
check_case "override: quoted key" 1 "$mention" job_workflow extra.yml '      "GORELEASER_VERSION": latest' "$w_step"
check_case "override: single-quoted key" 1 "$mention" job_workflow extra.yml "      'GORELEASER_VERSION': latest" "$w_step"
check_case "override: lower case key" 1 "$mention" job_workflow extra.yml "      goreleaser_version: latest" "$w_step"
check_case "override: mixed case key" 1 "$mention" job_workflow extra.yml "      Goreleaser_Version: latest" "$w_step"
check_case "override: mixed case key with the same version" 1 "$mention" job_workflow extra.yml "      Goreleaser_Version: $gr_ver" "$w_step"
check_case "override: flow style env" 1 "$mention" job_workflow extra.yml "    env: {GORELEASER_VERSION: latest}" "$w_step"
check_case "override: run step writes GITHUB_ENV" 1 "$mention" job_workflow extra.yml "" "$w_step
      - run: echo GORELEASER_VERSION=latest >> \"\$GITHUB_ENV\""
check_case "override: run block writes GITHUB_ENV" 1 "$mention" job_workflow extra.yml "" "      - run: |
          echo \"GORELEASER_VERSION=latest\" >> \"\$GITHUB_ENV\"
$w_step"
check_case "override: run step reads the variable" 1 "$mention" job_workflow extra.yml "" "$w_step
      - run: echo \"\${{ env.GORELEASER_VERSION }}\""
check_case "override: step env, same pin" 1 "$mention" job_workflow extra.yml "" "$w_step
        env:
          GORELEASER_VERSION: $gr_ver"
check_case "override: step env, latest" 1 "not a full version" job_workflow extra.yml "" "$w_step
        env:
          GORELEASER_VERSION: latest"
check_case "override: step env, lower case latest" 1 "$mention" job_workflow extra.yml "" "$w_step
        env:
          goreleaser_version: latest"
check_case "override: other variable name that holds the name" 1 "$mention" job_workflow extra.yml "      X_GORELEASER_VERSION: latest" "$w_step"
check_case "override: the line shows in the message" 1 "the line \"goreleaser_version: latest\" mentions" job_workflow extra.yml "      goreleaser_version: latest" "$w_step"
check_case "override: a comment may name it" 0 "" job_workflow extra.yml "      # goreleaser_version: latest" "$w_step"
check_case "override: the file is named" 1 "extra.yaml: the line" job_workflow extra.yaml "      goreleaser_version: latest" "$w_step"
check_case "override: in govulncheck.yml" 1 "govulncheck.yml: the line" append "$wf/govulncheck.yml" '      - run: echo GORELEASER_VERSION=latest >> "$GITHUB_ENV"'
check_case "override: second pin from vars in the job env" 1 "not a full version" job_workflow extra.yml "      GORELEASER_VERSION: \${{ vars.X }}" "$w_step"

# The scope of the pin: a job needs the pin in its own env.
check_case "scope: pin in job a, step in job b" 1 "the job \"b\" has a goreleaser-action step but its env: does not define GORELEASER_VERSION" two_jobs_workflow extra.yml "    env:
      GORELEASER_VERSION: $gr_ver" ""
check_case "scope: pin in both jobs" 0 "" two_jobs_workflow extra.yml "    env:
      GORELEASER_VERSION: $gr_ver" "    env:
      GORELEASER_VERSION: $gr_ver"
check_case "scope: pin in job b only" 0 "" two_jobs_workflow extra.yml "" "    env:
      GORELEASER_VERSION: $gr_ver"
check_case "scope: pin at the workflow level only" 1 "does not define GORELEASER_VERSION" step_workflow_top extra.yml
check_case "scope: pin at the wrong indent in the job" 1 "$mention" wf_pin_indent extra.yml
check_case "scope: pin under another job key" 1 "$mention" wf_pin_other_key extra.yml

# The composite actions are not read, so a file that names the action fails.
check_case "actions: composite action with goreleaser-action" 1 "action.yml names goreleaser/goreleaser-action" actions_file "runs:
  using: composite
  steps:
    - uses: goreleaser/goreleaser-action@x"
check_case "actions: other case" 1 "names goreleaser/goreleaser-action" actions_file "    - uses: GoReleaser/GoReleaser-Action@x"
check_case "actions: other action" 0 "" actions_file "    - uses: actions/checkout@x"
check_case "actions: symlinked directory" 1 "names goreleaser/goreleaser-action" symlinked_action

# A # starts a comment only after a space.
check_case "comment: no space after the version input" 1 "has a version input that is not" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          $ok_ver#x"
check_case "comment: no space after the quoted version input" 1 "has a version input that is not" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          version: \"\${{ env.GORELEASER_VERSION }}\"#x"
check_case "comment: no space after the pin" 1 "not a full version" append "$wf/release.yml" "      GORELEASER_VERSION: $gr_ver#x"
check_case "comment: no space after the quoted pin" 1 "not a full version" append "$wf/release.yml" "      GORELEASER_VERSION: \"$gr_ver\"#x"
check_case "comment: key quoted in the version input" 0 "" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          \"version\": \"\${{ env.GORELEASER_VERSION }}\"  # pinned"

# YAML anchors, aliases and merge keys are not allowed. An alias line names
# nothing, so the checks above could not see the step that it repeats.
refs="line uses a YAML form this check cannot read"
check_case "yaml: anchor on the pinned step and an alias in a second job" 1 "ci.yml: $refs: \"- &gr\"" anchor_poc
check_case "yaml: anchor on a key" 1 "extra.yml: $refs: \"name: &a v\"" step_workflow extra.yml "      - run: echo hi
        name: &a v"
check_case "yaml: anchor on a list item" 1 "$refs" step_workflow extra.yml "      - &a
        run: echo hi"
check_case "yaml: alias as a list item" 1 "$refs" step_workflow extra.yml "      - *gr"
check_case "yaml: alias as a value" 1 "$refs" step_workflow extra.yml "      - run: echo hi
        env: *e"
check_case "yaml: alias with a comment" 1 "$refs" step_workflow extra.yml "      - *gr # note"
check_case "yaml: alias in a flow list" 1 "$refs" step_workflow extra.yml "      - run: echo hi
        needs: [a, *b]"
check_case "yaml: merge key with an alias" 1 "$refs" step_workflow extra.yml "      - run: echo hi
        <<: *x"
check_case "yaml: merge key with a map" 1 "$refs" step_workflow extra.yml "      - run: echo hi
        <<: {a: b}"
check_case "yaml: alias after a block scalar" 1 "$refs" step_workflow extra.yml "      - run: |
          echo hi
      - *gr"
check_case "yaml: dotted anchor name and an alias in a second job" 1 "ci.yml: $refs: \"- &gr.step\"" anchor_poc gr.step
check_case "yaml: anchor on its own line" 1 "$refs: \"&l\"" step_workflow extra.yml "      &l
      - run: echo hi"
check_case "yaml: alias on its own line" 1 "$refs: \"*l\"" step_workflow extra.yml "      - run: echo hi
      *l"
check_case "yaml: key alias with a space before the colon" 1 "$refs" step_workflow extra.yml "      - run: echo hi
        *k : v"
check_case "yaml: merge key with a space before the colon" 1 "$refs" step_workflow extra.yml "      - run: echo hi
        << : *x"
check_case "yaml: uses value with a hex escape" 1 "$refs" step_workflow extra.yml "      - uses: \"goreleaser/goreleaser-actio\\x6e@x\"
        with:
          version: latest"
check_case "yaml: uses value with an escaped line break" 1 "$refs" step_workflow extra.yml "      - uses: \"goreleaser/goreleaser-\\
          action@y\"
        with:
          version: latest"
check_case "yaml: quoted uses key with an escape" 1 "$refs" step_workflow extra.yml "      - \"us\\x65s\": goreleaser/goreleaser-action@x"
check_case "yaml: double-quoted uses value, no escape" 0 "" step_workflow extra.yml "      - uses: \"actions/checkout@x\" # note"
check_case "yaml: alias in govulncheck.yml" 1 "govulncheck.yml: $refs" append "$wf/govulncheck.yml" '      - *gr'
check_case "yaml: alias in a .yaml workflow" 1 "extra.yaml: $refs" step_workflow extra.yaml "      - *gr"
check_case "yaml: the line shows in the message" 1 "\"env: &e {a: b}\"" step_workflow extra.yml "      - run: echo hi
        env: &e {a: b}"
check_case "yaml: a comment may hold an alias" 0 "" step_workflow extra.yml "      # - *gr
      - run: echo hi # key: &a"
check_case "yaml: quoted & and * in values" 0 "" step_workflow extra.yml "      - name: \"x: &a *b\"
        run: echo 'k: *b' ; echo \"k: &a\""
check_case "yaml: grep with a glob" 0 "" step_workflow extra.yml "      - run: grep -r '*.sh' ."
check_case "yaml: && in a run line" 0 "" step_workflow extra.yml "      - run: a && b"
check_case "yaml: branches with a quoted star" 0 "" step_workflow extra.yml "        branches: ['*']"
check_case "yaml: paths with a quoted glob" 0 "" step_workflow extra.yml "        paths: ['**/*.md']"
check_case "yaml: expression" 0 "" step_workflow extra.yml "      - run: echo \${{ matrix.os }} \${{ a && b }}
        if: \${{ matrix.os == 'x' }}"
check_case "yaml: quoted star as a list item" 0 "" step_workflow extra.yml "        branches:
          - '*'
          - \"**\""
check_case "yaml: block scalar with & and *" 0 "" step_workflow extra.yml "      - run: |
          cmd &
          echo *
          *foo
          k: *bar
          - *baz
          <<: *x

          wait
      - run: echo hi"
check_case "yaml: folded block scalar with a star" 0 "" step_workflow extra.yml "      - run: >-
          echo
          *foo"
check_case "yaml: list item block scalar with a star" 0 "" step_workflow extra.yml "      - |
        *foo"

# Forms that hide the action or the pin from a reader of single lines: a flow
# mapping with an escape, a tag, a tab, a quote that goes on in the next line.
tab=$'\t'
check_case "yaml: flow mapping with an escape in uses" 1 "$refs" step_workflow extra.yml "      - {uses: \"goreleaser/goreleaser-actio\\x6e@x\", with: {version: latest}}"
check_case "yaml: tag before an escaped uses value" 1 "$refs" step_workflow extra.yml "      - uses: !!str \"goreleaser/goreleaser-actio\\x6e@x\"
        with:
          version: latest"
check_case "yaml: tab after the colon of uses" 1 "$refs" step_workflow extra.yml "      - uses:${tab}\"goreleaser/goreleaser-actio\\x6e@x\"
        with:
          version: latest"
check_case "yaml: tab before an anchor" 1 "$refs" step_workflow extra.yml "      - run: echo hi
        name:${tab}&s v"
check_case "yaml: tag before an anchor" 1 "$refs" step_workflow extra.yml "      - !!map &gr
        run: echo hi"
check_case "yaml: escaped quote moves the pairing in a flow list" 1 "$refs" step_workflow extra.yml "      - run: echo hi
        needs: [{name: \"a\\\"\", run: x}, *gr, {name: \"b\"}]"
check_case "yaml: double quote that goes on in the next line" 1 "$refs" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          args: \"release
          version: \${{ env.GORELEASER_VERSION }}
          \""
check_case "yaml: single quote that goes on in the next line" 1 "$refs" step_workflow extra.yml "      - run: echo hi
        env:
          OTHER: 'a
          GORELEASER_VERSION: $gr_ver
          '"
check_case "yaml: tab in a block scalar is fine" 0 "" step_workflow extra.yml "      - run: |
          a${tab}b"
check_case "yaml: apostrophe in a plain value is fine" 0 "" step_workflow extra.yml "      - run: echo it's fine"
check_case "yaml: apostrophe in a double-quoted value is fine" 0 "" step_workflow extra.yml "      - name: \"it's fine\"
        run: echo hi"
check_case "yaml: closed quotes at the start of a value are fine" 0 "" step_workflow extra.yml "      - name: 'a'
        run: \"echo hi\""

# A dash line with nothing after it, a doubled single quote that does not close
# the text, and a plain value that goes on in a deeper line.
check_case "yaml: dash line with a comment only" 1 "$refs" step_workflow extra.yml "      -   # note
          name: x
          run: echo hi"
check_case "yaml: dash line with trailing spaces only" 1 "$refs" step_workflow extra.yml "      -   
          name: x
          run: echo hi"
check_case "yaml: doubled single quote keeps the text open" 1 "$refs" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          args: 'release''
          version: \${{ env.GORELEASER_VERSION }}
          end'"
check_case "yaml: doubled single quote inside a closed text is fine" 0 "" step_workflow extra.yml "      - name: 'it''s fine'
        run: echo hi"
check_case "yaml: version input goes on in a deeper line" 1 "$refs" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          version: \${{ env.GORELEASER_VERSION }}
            || >=2.0.0"
# pin_goes_on writes a workflow whose pin line is followed by a deeper line.
pin_goes_on() {
  job_workflow extra.yml "" "      - run: echo hi" &&
    awk '{ print } /GORELEASER_VERSION:/ { print "        || >=2.0.0" }' "$wf/extra.yml" >"$wf/extra.yml.new" &&
    mv "$wf/extra.yml.new" "$wf/extra.yml"
}
check_case "yaml: pin line goes on in a deeper line" 1 "$refs" pin_goes_on
check_case "yaml: plain list item goes on in a deeper line" 1 "$refs" step_workflow extra.yml "      - run: echo hi
        needs:
          - a
            b"
check_case "yaml: nested keys and block scalars are fine" 0 "" step_workflow extra.yml "      - name: x
        with:
          a: b
          c:
            - d
            - e: f
              g: h
        run: |
          echo hi
            indented
      - run: echo done"
check_case "yaml: single-quoted backslash after a double-quoted text is fine" 0 "" step_workflow extra.yml "      - run: printf \"%s\" 'a\\\\n'"
check_case "govulncheck: call line at another indent" 1 "has no call line" sub "$wf/govulncheck.yml" 's/^ +(run: go run)/          \\1/'

# GitHub may run a workflow whose name starts with a dot, and a plain * skips it.
check_case "workflow file with a dot name" 1 "the step" step_workflow .hidden.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          version: latest"

# The names that govulncheck.yml may have, with the needs line of its job.
check_case "needs: govulncheck once more" 0 "" append "$wf/govulncheck.yml" '    needs: govulncheck'
check_case "needs: list form" 1 "is not the pin, the call line or a name" append "$wf/govulncheck.yml" '    needs: [govulncheck]'
check_case "needs: other indent" 1 "is not the pin, the call line or a name" append "$wf/govulncheck.yml" '      needs: govulncheck'
check_case "needs: in ci.yml" 1 "ci.yml has a govulncheck line that is not the pin" append "$wf/ci.yml" '    needs: govulncheck'
check_case "if: line of the failure job, other result" 1 "is not the pin, the call line or a name" append "$wf/govulncheck.yml" "    if: failure() || needs.govulncheck.result == 'success'"
check_case "if: line of the failure job in ci.yml" 1 "ci.yml has a govulncheck line that is not the pin" append "$wf/ci.yml" "    if: failure() || needs.govulncheck.result == 'cancelled'"
check_case "step that runs govulncheck" 1 "is not the pin, the call line or a name" append "$wf/govulncheck.yml" '      - run: govulncheck ./...'

# A pin with the form of a pre-release or with quotes is still a full version.
check_case "GoReleaser: rc suffix in all files" 0 "" rc_goreleaser
check_case "GoReleaser: rc suffix in ci.yml only" 1 "The GoReleaser pins differ" sub "$wf/ci.yml" 's/(GORELEASER_VERSION: v[0-9]+\.[0-9]+\.[0-9]+)/\1-rc.1/'
check_case "GoReleaser: quoted pin with a comment in all files" 0 "" quoted_goreleaser

if [ "$failed" -ne 0 ]; then
  echo "check-tool-pins-test: $failed of $total cases failed" >&2
  exit 1
fi
echo "check-tool-pins-test: all $total cases pass"
