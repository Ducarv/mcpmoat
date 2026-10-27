#!/usr/bin/env bash
# Tests the pin check (internal/pincheck, run by check-tool-pins.sh) end to
# end, on changed copies of the files that it reads. The Go tests in
# internal/pincheck cover each guard in detail. These cases keep one probe or
# more per rule class on real workflow text. The ci-scripts job in ci.yml runs
# it. You can also run it on your machine, from any directory: see
# CONTRIBUTING.md, Checks. It needs bash, go and the standard tools cp, mv,
# mkdir, rm, sed, awk, cmp, head, grep, mktemp and ln.
# shellcheck disable=SC2016 # the sed expressions and the YAML hold a literal $
set -euo pipefail

src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT

# Build the checker once. A go run per case would make the test slow.
(cd "$src" && go build -o "$tmp/pincheck" ./internal/pincheck)

wf=.github/workflows
# workflows is the list of the workflows that may run govulncheck.
workflows=(ci release govulncheck)
failed=0
total=0

# current_pin prints the version that ci.yml pins for NAME ($1). The cases read
# it, so that a version bump does not break them.
current_pin() {
  sed -nE "s/^ *$1: *\"?(v[^\" ]+).*/\\1/p" "$src/$wf/ci.yml" | head -n 1
}
vuln_ver=$(current_pin GOVULNCHECK_VERSION)
# gr_ver is the GoReleaser pin of ci.yml. The new workflows define it, as the
# check requires for a job with a goreleaser-action step.
gr_ver=$(current_pin GORELEASER_VERSION)

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

# add_job adds the job text $2 (the job ID line at indent 2 and its body) to the
# workflow file $1 of the copy. jobs is the last top-level key of the three
# real workflows, so the job lands in the jobs mapping.
add_job() {
  append "$1" "$2"
}

# copy_tree makes a fresh copy, in $tmp/w, of the files that the checker reads.
copy_tree() {
  rm -rf "${tmp:?}/w"
  mkdir -p "$tmp/w/.github"
  cp -R "$src/$wf" "$tmp/w/.github/"
  if [ -d "$src/.github/actions" ]; then cp -R "$src/.github/actions" "$tmp/w/.github/"; fi
  cp "$src/CONTRIBUTING.md" "$tmp/w/"
}

# check_case copies the files that the checker reads, changes the copy with the
# command after the message, and runs the checker. The case passes when the
# exit code is the wanted one. A case that wants exit 1 also needs the output
# to contain the text of $3, so that it fails for the reason in its name.
check_case() {
  local name=$1 want=$2 msg=$3 got=0 out
  shift 3
  total=$((total + 1))
  copy_tree
  if ! (cd "$tmp/w" && "$@"); then
    echo "FAIL: $name: the change to the copy failed" >&2
    failed=$((failed + 1))
    return
  fi
  out=$("$tmp/pincheck" -root "$tmp/w" 2>&1) || got=$?
  if [ "$got" != "$want" ]; then
    echo "FAIL: $name: exit $got, want $want: $out" >&2
    failed=$((failed + 1))
  elif [ "$want" = 1 ] && [[ $out != *"$msg"* ]]; then
    echo "FAIL: $name: the message lacks '$msg': $out" >&2
    failed=$((failed + 1))
  fi
}

# stream_case runs the checker on a copy with a wrong govulncheck pin, with
# GITHUB_ACTIONS set to $2. It wants exit 1, every stdout line to start with
# $3 and every stderr line to start with $4. An empty prefix wants an empty
# stream.
stream_case() {
  local name=$1 actions=$2 out_prefix=$3 err_prefix=$4 got=0 stream prefix
  total=$((total + 1))
  copy_tree
  (cd "$tmp/w" && sub "$wf/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: v0.0.1/')
  GITHUB_ACTIONS=$actions "$tmp/pincheck" -root "$tmp/w" >"$tmp/stdout" 2>"$tmp/stderr" || got=$?
  if [ "$got" != 1 ]; then
    echo "FAIL: $name: exit $got, want 1" >&2
    failed=$((failed + 1))
    return
  fi
  for stream in stdout stderr; do
    prefix=$out_prefix
    if [ "$stream" = stderr ]; then prefix=$err_prefix; fi
    if [ -z "$prefix" ]; then
      if [ -s "$tmp/$stream" ]; then
        echo "FAIL: $name: $stream is not empty: $(cat "$tmp/$stream")" >&2
        failed=$((failed + 1))
      fi
    elif [ ! -s "$tmp/$stream" ] || grep -qv "^$prefix" "$tmp/$stream"; then
      echo "FAIL: $name: a $stream line lacks the prefix '$prefix': $(cat "$tmp/$stream")" >&2
      failed=$((failed + 1))
    fi
  done
}

# wrapper_case runs check-tool-pins.sh from the directory / with the arguments
# after $2, and wants the exit code $2. It tests that the wrapper finds the
# repository root and passes its arguments on.
wrapper_case() {
  local name=$1 want=$2 got=0 out
  shift 2
  total=$((total + 1))
  out=$(cd / && "$src/.github/scripts/check-tool-pins.sh" "$@" 2>&1) || got=$?
  if [ "$got" != "$want" ]; then
    echo "FAIL: $name: exit $got, want $want: $out" >&2
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

# write_wf writes a workflow, with the file name $1, whose jobs mapping is the
# text $2. All the new workflows of the cases below come from here.
write_wf() {
  printf 'name: extra\njobs:\n%s\n' "$2" >"$wf/$1"
}

# pin_env is the env of a job with the GoReleaser pin of ci.yml.
pin_env="    env:
      GORELEASER_VERSION: $gr_ver"
# gr_step is the good goreleaser-action step. The cases change it or add to it.
ok_ver='version: ${{ env.GORELEASER_VERSION }}'
gr_step="      - uses: goreleaser/goreleaser-action@x
        with:
          $ok_ver"

# fourth_workflow adds a workflow that is not in the list of the checker. It
# runs govulncheck with a version of its own. $1 is the file name. $2 is the
# number of padding steps.
fourth_workflow() {
  write_wf "$1" "  x:
    steps:
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
$(awk -v n="$2" 'BEGIN { for (i = 0; i < n; i++) print "      - run: echo padding padding padding padding" }')"
}

# step_workflow writes a workflow, with the file name $1, with one job that
# defines the pin of GoReleaser and has the steps text $2.
step_workflow() {
  write_wf "$1" "  x:
$pin_env
    steps:
$2"
}

# goreleaser_workflow writes a workflow, with the file name $1, that has one
# goreleaser-action step with more inputs. $2 is the version line of the step.
# When $2 is empty, the step has no version line.
goreleaser_workflow() {
  local ver=''
  if [ -n "$2" ]; then ver=$'\n'"          $2"; fi
  step_workflow "$1" "      - uses: goreleaser/goreleaser-action@x
        with:
          distribution: goreleaser$ver
          args: check"
}

# write_workflow_without_pin writes a workflow, with the file name $1, that has a
# good goreleaser-action step but does not define GORELEASER_VERSION.
write_workflow_without_pin() {
  write_wf "$1" "  x:
    steps:
$gr_step"
}

# wf_with_pin writes extra.yml with a good step and the pin value $1, in an env
# after the steps.
wf_with_pin() {
  write_workflow_without_pin extra.yml &&
    printf '    env:\n      GORELEASER_VERSION: %s\n' "$1" >>"$wf/extra.yml"
}

# step_workflow_pin writes a workflow, with the file name $1, with the pin value
# $2 and no goreleaser step.
step_workflow_pin() {
  write_wf "$1" "  x:
    env:
      GORELEASER_VERSION: $2
    steps:
      - run: echo hi"
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
  write_wf "$1" "  x:
$pin_env
$2
    steps:
$3"
}

# two_jobs_workflow writes a workflow, with the file name $1, with a job "a" that
# has a step without goreleaser and a job "b" that has the good goreleaser-action
# step. The text $2 is the env of job "a" and the text $3 is the env of job "b".
two_jobs_workflow() {
  write_wf "$1" "  a:
$2
    steps:
      - run: echo hi
  b:
$3
    steps:
$gr_step"
}

# actions_file writes the composite action .github/actions/x/action.yml with the
# text $1.
actions_file() {
  mkdir -p .github/actions/x && printf '%s\n' "$1" >.github/actions/x/action.yml
}

# step_workflow_top writes a workflow, with the file name $1, with the pin in the
# env of the workflow and a good step in a job that has no env.
step_workflow_top() {
  printf 'name: extra\nenv:\n  GORELEASER_VERSION: %s\njobs:\n  x:\n    steps:\n%s\n' "$gr_ver" "$gr_step" >"$wf/$1"
}

# wf_pin_indent writes a workflow, with the file name $1, with the pin at the
# indent of a job key, not in the env.
wf_pin_indent() {
  write_wf "$1" "  x:
    GORELEASER_VERSION: $gr_ver
    steps:
$gr_step"
}

# wf_pin_other_key writes a workflow, with the file name $1, with the pin at the
# right indent but under another job key than env, and no env in the job.
wf_pin_other_key() {
  write_wf "$1" "  x:
    outputs:
      GORELEASER_VERSION: $gr_ver
    steps:
$gr_step"
}

# anchor_and_alias turns the GoReleaser check step of ci.yml into an anchor with the
# name $1 (default gr) and adds a job that uses the alias. The alias line names
# nothing, and the new job has no pin of its own.
anchor_and_alias() {
  awk -v n="${1:-gr}" '/- name: Check the GoReleaser config/ { print "      - &" n; sub(/- name:/, "  name:") } { print }' "$wf/ci.yml" >"$wf/ci.yml.new" &&
    mv "$wf/ci.yml.new" "$wf/ci.yml" &&
    printf '  alias-job:\n    runs-on: ubuntu-latest\n    steps:\n      - *%s\n' "${1:-gr}" >>"$wf/ci.yml"
}

# pin_goes_on writes a workflow whose pin line goes on in a deeper line. YAML
# joins the two lines into one plain value.
pin_goes_on() {
  job_workflow extra.yml "" "      - run: echo hi" &&
    awk '{ print } /GORELEASER_VERSION:/ { print "        || >=2.0.0" }' "$wf/extra.yml" >"$wf/extra.yml.new" &&
    mv "$wf/extra.yml.new" "$wf/extra.yml"
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
vuln_name="names govulncheck, but it is not the GOVULNCHECK_VERSION pin, the call or an allowed name"
no_call="no step has the run value"
check_case "govulncheck: different pin" 1 "the govulncheck pin v0.0.1 differs from $vuln_ver" sub "$wf/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: v0.0.1/'
check_case "govulncheck: no pin in ci.yml" 1 "ci.yml: the file must pin one version of govulncheck" sub "$wf/ci.yml" '/^ *GOVULNCHECK_VERSION: v/d'
check_case "govulncheck: pin value latest" 1 "govulncheck.yml: the file has no GOVULNCHECK_VERSION pin" sub "$wf/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: latest/'
check_case "govulncheck: pin value from vars" 1 "has no GOVULNCHECK_VERSION pin" sub "$wf/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: ${{ vars.X }}/'
check_case "govulncheck: pin value latest and a decoy pin" 1 "$vuln_name" decoy_pin
check_case "govulncheck: short version in all files" 1 "must pin one version of govulncheck" float_govulncheck
check_case "govulncheck: two equal pins in a file" 0 "" append_step "$wf/release.yml" "$vuln_ver"
check_case "govulncheck: two different pins in a file" 1 "the govulncheck pin v0.0.1 differs from" append_step "$wf/release.yml" v0.0.1
check_case "govulncheck: two pins in ci.yml" 1 "must pin one version of govulncheck" append_step "$wf/ci.yml" v0.0.1
check_case "govulncheck: same extra pin in all files" 1 "must pin one version of govulncheck" same_extra_pin_everywhere

# The call of govulncheck.
check_case "call: hard-coded version" 1 "release.yml: $no_call" sub "$wf/release.yml" 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@v0.0.1/'
check_case "call: @latest" 1 "govulncheck.yml: $no_call" sub "$wf/govulncheck.yml" 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@latest/'
check_case "call: braces form" 1 "govulncheck.yml: $no_call" sub "$wf/govulncheck.yml" 's/\$GOVULNCHECK_VERSION"/${GOVULNCHECK_VERSION}"/'
check_case "call: variable name with a suffix" 1 "govulncheck.yml: $no_call" sub "$wf/govulncheck.yml" 's/\$GOVULNCHECK_VERSION"/$GOVULNCHECK_VERSION_X"/'
check_case "call: quote before @latest" 1 "govulncheck.yml: $no_call" sub "$wf/govulncheck.yml" 's|run: go run .*|run: go run "golang.org/x/vuln/cmd/govulncheck"@latest ./...|'
check_case "call: variable set in the run line" 1 "govulncheck.yml: $no_call" sub "$wf/govulncheck.yml" 's|run: go run|run: GOVULNCHECK_VERSION=latest; go run|'
check_case "call: go install @latest and the call" 1 "release.yml: $no_call" sub "$wf/release.yml" 's|run: go run|run: go install golang.org/x/vuln/cmd/govulncheck@latest \&\& go run|'
# YAML drops the comment, so the run value is still the call.
check_case "call: inline comment after the call" 0 "" sub "$wf/release.yml" 's@^(.*run: go run .*)$@\1 # x@'
check_case "call: || true after the call" 1 "release.yml: $no_call" sub "$wf/release.yml" 's@^(.*run: go run .*)$@\1 || true@'
# YAML joins a deeper line to the plain value before it.
check_case "call: || true on a continuation line" 1 "govulncheck.yml: $no_call" after_call "$wf/govulncheck.yml" '          || true'
check_case "call: || true on a continuation line in release.yml" 1 "release.yml: $no_call" after_call "$wf/release.yml" '          || true'
check_case "govulncheck: call line at another indent" 1 "$no_call" sub "$wf/govulncheck.yml" 's/^ +(run: go run)/          \1/'
check_case "continue-on-error in a step" 1 "continue-on-error is not allowed" append "$wf/govulncheck.yml" '        continue-on-error: true'
check_case "continue-on-error with a quoted key" 1 "continue-on-error is not allowed" append "$wf/govulncheck.yml" '        "continue-on-error": true'
check_case "continue-on-error as the first key of a step" 1 "continue-on-error is not allowed" append "$wf/govulncheck.yml" '      - continue-on-error: true'
check_case "continue-on-error in another case" 1 "continue-on-error is not allowed" append "$wf/release.yml" '        Continue-On-Error: true'
check_case "govulncheck-action step" 1 "$vuln_name" append "$wf/govulncheck.yml" '      - uses: golang/govulncheck-action@v1'
# A key on a continuation line of a plain value is not valid YAML.
check_case "invalid YAML fails closed: key after the call" 1 "govulncheck.yml: parse YAML" after_call "$wf/govulncheck.yml" '          govulncheck:'
check_case "job ID govulncheck in ci.yml" 1 "$vuln_name" add_job "$wf/ci.yml" '  govulncheck:
    runs-on: ubuntu-latest'
check_case "call: no call in release.yml" 1 "release.yml: $no_call" sub "$wf/release.yml" '/govulncheck@/d'
check_case "comment names govulncheck@v1.2.3" 0 "" append "$wf/release.yml" '# see govulncheck@v1.2.3'

# A workflow outside the list.
outside="the workflow names govulncheck. Only ci.yml"
check_case "fourth workflow with a space in its name" 1 "ci release.yml:5: $outside" fourth_workflow "ci release.yml" 0
check_case "fourth workflow runs govulncheck" 1 "extra.yml:5: $outside" fourth_workflow extra.yml 0
check_case "fourth workflow with the .yaml extension" 1 "extra.yaml:5: $outside" fourth_workflow extra.yaml 0
check_case "large fourth workflow runs govulncheck" 1 "$outside" fourth_workflow extra.yml 4000

# Missing files.
check_case "ci.yml missing" 1 "ci.yml: the file is missing" rm "$wf/ci.yml"
check_case "release.yml missing" 1 "release.yml: the file is missing" rm "$wf/release.yml"
check_case "govulncheck.yml missing" 1 "govulncheck.yml: the file is missing" rm "$wf/govulncheck.yml"
check_case "CONTRIBUTING.md missing" 1 "CONTRIBUTING.md: the file is missing" rm CONTRIBUTING.md

# The pin of GoReleaser.
gr_differs="differs from the pin \"$gr_ver\" in ci.yml"
gr_one="ci.yml must pin one full version of GoReleaser"
not_full="is not a full version"
check_case "GoReleaser: different pin in release.yml" 1 "GORELEASER_VERSION is \"v0.0.1\", expected \"$gr_ver\"" sub "$wf/release.yml" 's/GORELEASER_VERSION: v[0-9.]+/GORELEASER_VERSION: v0.0.1/'
check_case "GoReleaser: different pin in CONTRIBUTING.md" 1 "the GoReleaser version \"v0.0.1\" $gr_differs" sub CONTRIBUTING.md 's|(goreleaser/v[0-9]+)@v[0-9.]+|\1@v0.0.1|g'
check_case "GoReleaser: different pin in one command only" 1 "\"v0.0.1\" $gr_differs" sub CONTRIBUTING.md '/ check /s|(goreleaser/v[0-9]+)@v[0-9.]+|\1@v0.0.1|'
check_case "GoReleaser: pin value latest in release.yml" 1 "the GORELEASER_VERSION pin \"latest\" $not_full" sub "$wf/release.yml" 's/GORELEASER_VERSION: v[0-9.]+/GORELEASER_VERSION: latest/'
check_case "GoReleaser: short pin value in a new job of ci.yml" 1 "the GORELEASER_VERSION pin \"${gr_ver%.*}\" $not_full" add_job "$wf/ci.yml" "  short:
    env:
      GORELEASER_VERSION: ${gr_ver%.*}"
check_case "GoReleaser: @latest in one CONTRIBUTING.md command" 1 "\"latest\" $gr_differs" sub CONTRIBUTING.md '/ check /s|(goreleaser/v[0-9]+)@v[0-9.]+|\1@latest|'
check_case "GoReleaser: short version in one CONTRIBUTING.md command" 1 "\"${gr_ver%.*}\" $gr_differs" sub CONTRIBUTING.md '/ check /s|(goreleaser/v[0-9]+@v[0-9]+\.[0-9]+)\.[0-9]+|\1|'
check_case "GoReleaser: two pins in ci.yml" 1 "$gr_one" add_job "$wf/ci.yml" '  other:
    env:
      GORELEASER_VERSION: v0.0.1'
check_case "GoReleaser: no pin in ci.yml" 1 "$gr_one" sub "$wf/ci.yml" '/GORELEASER_VERSION: v/d'
check_case "GoReleaser: no pin in release.yml" 1 "release.yml: the workflow has no full GORELEASER_VERSION pin" sub "$wf/release.yml" '/GORELEASER_VERSION: v/d'
check_case "GoReleaser: no version in CONTRIBUTING.md" 1 "CONTRIBUTING.md: names no GoReleaser version" sub CONTRIBUTING.md '/goreleaser\/v2@/d'
check_case "GoReleaser: short version in all files" 1 "$gr_one" float_goreleaser

# The version input of each goreleaser-action step. The real steps are in
# ci.yml (two) and release.yml (one). The ranges select the step of a case.
ga_check="/Check the GoReleaser config/,/args: check/"
ga_release="/Run GoReleaser/,/args: release/"
bad_input='has a version input that is not ${{ env.GORELEASER_VERSION }}'
no_input="has no version input"
check_case "goreleaser-action: hard-coded version" 1 "the goreleaser-action step \"Check the GoReleaser config\" $bad_input" sub "$wf/ci.yml" "$ga_check"'s/version: .*/version: v2.0.0/'
check_case "goreleaser-action: version latest" 1 "the goreleaser-action step \"Run GoReleaser\" $bad_input" sub "$wf/release.yml" "$ga_release"'s/version: .*/version: latest/'
check_case "goreleaser-action: other variable" 1 "$bad_input" sub "$wf/release.yml" "$ga_release"'s/GORELEASER_VERSION/OTHER_VERSION/'
check_case "goreleaser-action: text after the variable" 1 "$bad_input" sub "$wf/release.yml" "$ga_release"'s/(version: .*)$/\1-x/'
check_case "goreleaser-action: no version input" 1 "the goreleaser-action step \"Run GoReleaser\" $no_input" sub "$wf/release.yml" "$ga_release"'{/version:/d;}'
check_case "goreleaser-action: no version input, next step has one" 1 "the goreleaser-action step \"Check the GoReleaser config\" $no_input" sub "$wf/ci.yml" "$ga_check"'{/version:/d;}'
check_case "goreleaser-action: version key in another case" 1 "Write the version input key as version" sub "$wf/release.yml" "$ga_release"'s/version:/Version:/'
check_case "goreleaser-action: new workflow without a version" 1 "extra.yml:9: the goreleaser-action step \"goreleaser/goreleaser-action@x\" $no_input" goreleaser_workflow extra.yml ""
check_case "goreleaser-action: new .yaml workflow with latest" 1 "extra.yaml:10: the goreleaser-action step" goreleaser_workflow extra.yaml "version: latest"
check_case "goreleaser-action: new workflow, quoted pin and trailing spaces" 0 "" goreleaser_workflow extra.yml 'version: "${{ env.GORELEASER_VERSION }}"   '
check_case "goreleaser-action: new workflow, comment after the pin" 0 "" goreleaser_workflow extra.yml "$ok_ver # pinned"
check_case "goreleaser-action: new workflow, plain pin" 0 "" goreleaser_workflow extra.yml "$ok_ver"

# The bypass classes of the step check.
w_with="        with:
          distribution: goreleaser
          $ok_ver"
w_latest="        with:
          version: latest"
# (a) A quoted uses value.
check_case "goreleaser-action: quoted uses, version latest" 1 "$bad_input" step_workflow extra.yml "      - uses: \"goreleaser/goreleaser-action@x\"
$w_latest"
check_case "goreleaser-action: single-quoted uses, version latest" 1 "$bad_input" step_workflow extra.yml "      - uses: 'goreleaser/goreleaser-action@x'
$w_latest"
check_case "goreleaser-action: quoted uses, no version" 1 "$no_input" step_workflow extra.yml "      - uses: \"goreleaser/goreleaser-action@x\""
check_case "goreleaser-action: quoted uses, good version" 0 "" step_workflow extra.yml "      - uses: \"goreleaser/goreleaser-action@x\"
$w_with"
check_case "goreleaser-action: single-quoted uses, good version" 0 "" step_workflow extra.yml "      - uses: 'goreleaser/goreleaser-action@x' # note
$w_with"
# (b) Owner and repo names ignore case.
check_case "goreleaser-action: other case, version latest" 1 "$bad_input" step_workflow extra.yml "      - uses: GoReleaser/goreleaser-action@x
$w_latest"
check_case "goreleaser-action: other case, good version" 0 "" step_workflow extra.yml "      - uses: GoReleaser/GoReleaser-Action@x
$w_with"
# (c) Flow style is read like block style.
check_case "goreleaser-action: flow style" 1 "$bad_input" step_workflow extra.yml "      - {uses: goreleaser/goreleaser-action@x, with: {version: latest}}"
check_case "goreleaser-action: flow style, good version" 0 "" step_workflow extra.yml "      - {uses: goreleaser/goreleaser-action@x, with: {version: \"\${{ env.GORELEASER_VERSION }}\"}}"
check_case "invalid YAML fails closed: flow style, plain expression" 1 "extra.yml: parse YAML" step_workflow extra.yml "      - {uses: goreleaser/goreleaser-action@x, with: {version: \${{ env.GORELEASER_VERSION }}}}"
check_case "goreleaser-action: anchor before the action" 1 "an anchor (&a) is not allowed" step_workflow extra.yml "      - uses: &a goreleaser/goreleaser-action@x
$w_with"
check_case "goreleaser-action: uses value on the next line" 0 "" step_workflow extra.yml "      - uses:
          goreleaser/goreleaser-action@x
$w_with"
check_case "goreleaser-action: uses value on the next line, version latest" 1 "$bad_input" step_workflow extra.yml "      - uses:
          goreleaser/goreleaser-action@x
$w_latest"
check_case "goreleaser-action: action path in a name line" 1 "names goreleaser/goreleaser-action, but it is not the uses value of a step" step_workflow extra.yml "      - name: goreleaser/goreleaser-action
        run: echo hi"
check_case "goreleaser-action: action word without the path in a name line" 0 "" step_workflow extra.yml "      - name: Run goreleaser-action
        uses: goreleaser/goreleaser-action@x
$w_with"
check_case "goreleaser-action: local action" 0 "" step_workflow extra.yml "      - uses: ./some/local@x"
# (d) More than one space after the dash.
check_case "goreleaser-action: extra spaces after the dash, version latest" 1 "$bad_input" step_workflow extra.yml "      -   uses: goreleaser/goreleaser-action@x
          with:
            version: latest"
check_case "goreleaser-action: extra spaces after the dash, no version" 1 "$no_input" step_workflow extra.yml "      -   uses: goreleaser/goreleaser-action@x"
check_case "goreleaser-action: extra spaces after the dash, good version" 0 "" step_workflow extra.yml "      -   uses: goreleaser/goreleaser-action@x
          with:
            $ok_ver"
check_case "goreleaser-action: with on the first line, good version" 0 "" step_workflow extra.yml "      - with:
          $ok_ver
        uses: goreleaser/goreleaser-action@x"
# (e) A version key outside the with: block does not count.
check_case "goreleaser-action: version under env" 1 "$no_input" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          distribution: goreleaser
        env:
          $ok_ver"
check_case "goreleaser-action: version at the step level" 1 "$no_input" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          distribution: goreleaser
        $ok_ver"
check_case "goreleaser-action: version in a nested mapping of with" 1 "$no_input" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          extra:
            $ok_ver"
check_case "goreleaser-action: good version in env, latest in with" 1 "$bad_input" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
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
no_define="has a goreleaser-action step, but its env does not define GORELEASER_VERSION"
check_case "GoReleaser: new workflow, no definition" 1 "extra.yml:3: the job \"x\" $no_define" write_workflow_without_pin extra.yml
check_case "GoReleaser: new workflow, pin value latest" 1 "extra.yml:9: the GORELEASER_VERSION pin \"latest\" $not_full" wf_with_pin latest
check_case "GoReleaser: new workflow, other full pin" 1 "extra.yml:9: GORELEASER_VERSION is \"v0.0.1\", expected \"$gr_ver\"" wf_with_pin v0.0.1
check_case "GoReleaser: new workflow, same pin" 0 "" wf_with_pin "$gr_ver"
check_case "GoReleaser: other pin in govulncheck.yml" 1 "GORELEASER_VERSION is \"v0.0.1\", expected" add_job "$wf/govulncheck.yml" '  other:
    env:
      GORELEASER_VERSION: v0.0.1'
check_case "GoReleaser: latest in govulncheck.yml" 1 "the GORELEASER_VERSION pin \"latest\" $not_full" add_job "$wf/govulncheck.yml" '  other:
    env:
      GORELEASER_VERSION: latest'
check_case "GoReleaser: pin in a new .yaml workflow without a step" 1 "extra.yaml:5: GORELEASER_VERSION is \"v0.0.1\"" step_workflow_pin extra.yaml v0.0.1

# Ways to change the version at run time. The step reads the pin, but another
# entry could change what env.GORELEASER_VERSION holds. Each form must fail.
mention="mentions GORELEASER_VERSION in a form this check does not allow"
dup="is a duplicate (case-insensitive) of the key on line"
check_case "override: job env, same pin" 0 "" job_workflow extra.yml "" "$gr_step"
# A second key next to the pin is a duplicate key, in any case or quote form.
check_case "override: space before the colon" 1 "$dup" job_workflow extra.yml "      GORELEASER_VERSION : latest" "$gr_step"
check_case "override: quoted key" 1 "$dup" job_workflow extra.yml '      "GORELEASER_VERSION": latest' "$gr_step"
check_case "override: single-quoted key" 1 "$dup" job_workflow extra.yml "      'GORELEASER_VERSION': latest" "$gr_step"
check_case "override: escaped key" 1 "$dup" job_workflow extra.yml '      "GORELEASER_VERSIO\x4e": latest' "$gr_step"
check_case "override: lower case key" 1 "the key \"goreleaser_version\" $dup" job_workflow extra.yml "      goreleaser_version: latest" "$gr_step"
check_case "override: mixed case key" 1 "$dup" job_workflow extra.yml "      Goreleaser_Version: latest" "$gr_step"
check_case "override: mixed case key with the same version" 1 "$dup" job_workflow extra.yml "      Goreleaser_Version: $gr_ver" "$gr_step"
check_case "override: flow style env" 1 "the GORELEASER_VERSION pin \"latest\" $not_full" two_jobs_workflow extra.yml "" "    env: {GORELEASER_VERSION: latest}"
check_case "override: flow style env, same pin" 0 "" two_jobs_workflow extra.yml "" "    env: {GORELEASER_VERSION: $gr_ver}"
check_case "override: run step writes GITHUB_ENV" 1 "$mention" job_workflow extra.yml "" "$gr_step
      - run: echo GORELEASER_VERSION=latest >> \"\$GITHUB_ENV\""
check_case "override: run block writes GITHUB_ENV" 1 "$mention" job_workflow extra.yml "" "      - run: |
          echo \"GORELEASER_VERSION=latest\" >> \"\$GITHUB_ENV\"
$gr_step"
check_case "override: run step reads the variable" 1 "$mention" job_workflow extra.yml "" "$gr_step
      - run: echo \"\${{ env.GORELEASER_VERSION }}\""
check_case "override: step env, same pin" 1 "$mention" job_workflow extra.yml "" "$gr_step
        env:
          GORELEASER_VERSION: $gr_ver"
check_case "override: step env, latest" 1 "$mention" job_workflow extra.yml "" "$gr_step
        env:
          GORELEASER_VERSION: latest"
check_case "override: step env, lower case latest" 1 "$mention" job_workflow extra.yml "" "$gr_step
        env:
          goreleaser_version: latest"
check_case "override: other variable name that holds the name" 1 "$mention" job_workflow extra.yml "      X_GORELEASER_VERSION: latest" "$gr_step"
check_case "override: the text shows in the message" 1 "the text \"goreleaser_version\" $mention" job_workflow extra.yml "" "$gr_step
        env:
          goreleaser_version: latest"
check_case "override: a comment may name it" 0 "" job_workflow extra.yml "      # goreleaser_version: latest" "$gr_step"
check_case "override: the file is named" 1 "extra.yaml:12: the text \"goreleaser_version\"" job_workflow extra.yaml "" "$gr_step
        env:
          goreleaser_version: latest"
check_case "override: in govulncheck.yml" 1 "$mention" append "$wf/govulncheck.yml" '      - run: echo GORELEASER_VERSION=latest >> "$GITHUB_ENV"'
check_case "override: pin from vars in the job env" 1 "the GORELEASER_VERSION pin \"\${{ vars.X }}\" $not_full" two_jobs_workflow extra.yml "" '    env:
      GORELEASER_VERSION: ${{ vars.X }}'
check_case "override: empty pin in the job env" 1 "the GORELEASER_VERSION pin must be a full version" two_jobs_workflow extra.yml "" '    env:
      GORELEASER_VERSION:'

# The scope of the pin: a job needs the pin in its own env.
check_case "scope: pin in job a, step in job b" 1 "the job \"b\" $no_define" two_jobs_workflow extra.yml "$pin_env" ""
check_case "scope: pin in both jobs" 0 "" two_jobs_workflow extra.yml "$pin_env" "$pin_env"
check_case "scope: pin in job b only" 0 "" two_jobs_workflow extra.yml "" "$pin_env"
check_case "scope: pin at the workflow level only" 1 "the job \"x\" $no_define" step_workflow_top extra.yml
check_case "scope: pin at the wrong indent in the job" 1 "$mention" wf_pin_indent extra.yml
check_case "scope: pin under another job key" 1 "$mention" wf_pin_other_key extra.yml

# The composite actions are not read, so a file that names the action fails.
in_action="names goreleaser/goreleaser-action. This check does not read .github/actions"
check_case "actions: composite action with goreleaser-action" 1 ".github/actions/x/action.yml: $in_action" actions_file "runs:
  using: composite
  steps:
    - uses: goreleaser/goreleaser-action@x"
check_case "actions: other case" 1 "$in_action" actions_file "    - uses: GoReleaser/GoReleaser-Action@x"
check_case "actions: other action" 0 "" actions_file "    - uses: actions/checkout@x"
check_case "actions: symlinked directory" 1 ".github/actions/y: is a symlink" symlinked_action

# A # starts a comment only after a space.
check_case "comment: no space after the version input" 1 "$bad_input" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          $ok_ver#x"
check_case "comment: no space after the pin" 1 "the GORELEASER_VERSION pin \"$gr_ver#x\" $not_full" sub "$wf/release.yml" 's/(GORELEASER_VERSION: v[0-9.]+)/\1#x/'
check_case "comment: key quoted in the version input" 0 "" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          \"version\": \"\${{ env.GORELEASER_VERSION }}\"  # pinned"
# After a closing quote, the YAML decoder reads #x as a comment. The decoded
# value is the pin, so the step is fine.
check_case "comment: no space after the quoted version input" 0 "" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          version: \"\${{ env.GORELEASER_VERSION }}\"#x"
check_case "comment: no space after the quoted pin" 0 "" sub "$wf/release.yml" 's/(GORELEASER_VERSION: )(v[0-9.]+)/\1"\2"#x/'

# YAML anchors, aliases, merge keys and tags are not allowed. An alias names
# nothing, so the checks could not see the step that it repeats. The decoder
# fails on an alias without its anchor.
unknown_anchor="parse YAML: yaml: unknown anchor"
check_case "yaml: anchor on the pinned step and an alias in a second job" 1 "an anchor (&gr) is not allowed" anchor_and_alias
check_case "yaml: anchor on a key" 1 "extra.yml:8: an anchor (&a) is not allowed" step_workflow extra.yml "      - run: echo hi
        name: &a v"
check_case "yaml: anchor on a list item" 1 "an anchor (&a) is not allowed" step_workflow extra.yml "      - &a
        run: echo hi"
check_case "yaml: alias as a list item" 1 "$unknown_anchor 'gr'" step_workflow extra.yml "      - *gr"
check_case "yaml: alias as a value" 1 "$unknown_anchor 'e'" step_workflow extra.yml "      - run: echo hi
        env: *e"
check_case "yaml: alias with its anchor" 1 "an anchor (&e) is not allowed" step_workflow extra.yml "      - run: echo hi
        env: &e {A: b}
      - run: echo hi
        env: *e"
check_case "yaml: alias with a comment" 1 "$unknown_anchor 'gr'" step_workflow extra.yml "      - *gr # note"
check_case "yaml: alias in a flow list" 1 "$unknown_anchor 'b'" step_workflow extra.yml "      - run: echo hi
        needs: [a, *b]"
check_case "yaml: merge key with an alias" 1 "$unknown_anchor 'x'" step_workflow extra.yml "      - run: echo hi
        <<: *x"
check_case "yaml: merge key with a map" 1 "extra.yml:8: a merge key (<<) is not allowed" step_workflow extra.yml "      - run: echo hi
        <<: {a: b}"
check_case "yaml: alias after a block scalar" 1 "$unknown_anchor 'gr'" step_workflow extra.yml "      - run: |
          echo hi
      - *gr"
check_case "invalid YAML fails closed: dotted anchor name and an alias" 1 "ci.yml: parse YAML" anchor_and_alias gr.step
check_case "yaml: anchor on its own line" 1 "an anchor (&l) is not allowed" step_workflow extra.yml "      &l
      - run: echo hi"
check_case "invalid YAML fails closed: alias on its own line" 1 "extra.yml: parse YAML" step_workflow extra.yml "      - run: echo hi
      *l"
check_case "yaml: the line shows in the message" 1 "extra.yml:8: an anchor (&e) is not allowed" step_workflow extra.yml "      - run: echo hi
        env: &e {a: b}"
check_case "yaml: key alias with a space before the colon" 1 "$unknown_anchor 'k'" step_workflow extra.yml "      - run: echo hi
        *k : v"
check_case "yaml: merge key with a space before the colon" 1 "a merge key (<<) is not allowed" step_workflow extra.yml "      - run: echo hi
        << : {a: b}"
check_case "yaml: alias in govulncheck.yml" 1 "govulncheck.yml: $unknown_anchor" append "$wf/govulncheck.yml" '      - *gr'
check_case "yaml: alias in a .yaml workflow" 1 "extra.yaml: $unknown_anchor" step_workflow extra.yaml "      - *gr"
check_case "yaml: alias after a block scalar in a nested list" 1 "$unknown_anchor 'gr'" step_workflow extra.yml "      - - |
          text
        - *gr"
check_case "yaml: tag before an escaped uses value" 1 "an explicit tag (!!str) is not allowed" step_workflow extra.yml "      - uses: !!str \"goreleaser/goreleaser-actio\\x6e@x\"
        with:
          version: latest"
check_case "yaml: tag before an anchor" 1 "an anchor (&gr) is not allowed" step_workflow extra.yml "      - !!map &gr
        run: echo hi"
check_case "yaml: tag on a value, no other form" 1 "extra.yml:7: an explicit tag (!!str) is not allowed" step_workflow extra.yml "      - name: !!str x
        run: echo hi"
check_case "yaml: local tag on a value" 1 "an explicit tag (!x) is not allowed" step_workflow extra.yml "      - name: !x y
        run: echo hi"
check_case "yaml: a comment may hold an alias" 0 "" step_workflow extra.yml "      # - *gr
      - run: echo hi # key: &a"
check_case "yaml: quoted & and * in values" 0 "" step_workflow extra.yml "      - name: \"x: &a *b\"
        run: echo '*b' ; echo \"&a\""
check_case "yaml: grep with a glob" 0 "" step_workflow extra.yml "      - run: grep -r '*.sh' ."
check_case "yaml: && in a run line" 0 "" step_workflow extra.yml "      - run: a && b"
check_case "yaml: branches with a quoted star" 0 "" step_workflow extra.yml "      - run: echo hi
        branches: ['*']"
check_case "yaml: paths with a quoted glob" 0 "" step_workflow extra.yml "      - run: echo hi
        paths: ['**/*.md']"
check_case "yaml: quoted star as a list item" 0 "" step_workflow extra.yml "      - run: echo hi
        branches:
          - '*'
          - \"**\""
check_case "yaml: expression" 0 "" step_workflow extra.yml "      - run: echo \${{ matrix.os }} \${{ a && b }}
        if: \${{ matrix.os == 'x' }}"
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

# Escapes in double-quoted texts are decoded, so they cannot hide the action.
check_case "yaml: uses value with a hex escape" 1 "the goreleaser-action step \"goreleaser/goreleaser-action@x\" $bad_input" step_workflow extra.yml "      - uses: \"goreleaser/goreleaser-actio\\x6e@x\"
        with:
          version: latest"
check_case "yaml: uses value with an escaped line break" 1 "the goreleaser-action step \"goreleaser/goreleaser-action@y\" $bad_input" step_workflow extra.yml "      - uses: \"goreleaser/goreleaser-\\
          action@y\"
        with:
          version: latest"
check_case "yaml: quoted uses key with an escape" 1 "$no_input" step_workflow extra.yml "      - \"us\\x65s\": goreleaser/goreleaser-action@x"
check_case "yaml: flow mapping with an escape in uses" 1 "$bad_input" step_workflow extra.yml "      - {uses: \"goreleaser/goreleaser-actio\\x6e@x\", with: {version: latest}}"
check_case "yaml: double-quoted uses value, no escape" 0 "" step_workflow extra.yml "      - uses: \"actions/checkout@x\" # note"

# Duplicate keys, a key that is not a scalar and a second document fail.
check_case "yaml: duplicate uses key in a step" 1 "the key \"Uses\" $dup" step_workflow extra.yml "      - uses: actions/checkout@x
        Uses: goreleaser/goreleaser-action@x"
check_case "yaml: duplicate job ID" 1 "$dup" add_job "$wf/release.yml" '  release:
    runs-on: ubuntu-latest'
check_case "yaml: key that is not a scalar" 1 "a mapping key must be a scalar" step_workflow extra.yml "      - run: echo hi
        ? [a, b]
        : c"
check_case "yaml: second document" 1 "the file has more than one YAML document" append "$wf/govulncheck.yml" '---
name: second'

# The structure that the rules walk must have the shape GitHub needs.
check_case "goreleaser-action: nested with: in a block body" 1 "$bad_input" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          args: |
            with:
              version: \${{ env.GORELEASER_VERSION }}
          version: latest"
check_case "yaml: env with an expression on the job" 1 "the value of \"env\" must be a mapping, found a scalar" two_jobs_workflow extra.yml "" '    env: ${{ matrix.env }}'
check_case "pin: pin text inside a block scalar of the job env" 1 "the value of \"env\" must be a mapping, found a scalar" two_jobs_workflow extra.yml "    env:
      OTHER: x" "    env: >-
      GORELEASER_VERSION: $gr_ver"
check_case "yaml: version input goes on in a deeper line" 1 "$bad_input" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          $ok_ver
            || >=2.0.0"
check_case "yaml: pin line goes on in a deeper line" 1 "the GORELEASER_VERSION pin \"$gr_ver || >=2.0.0\" $not_full" pin_goes_on
check_case "yaml: steps as a mapping" 1 "the value of \"steps\" must be a sequence" step_workflow extra.yml "        uses: goreleaser/goreleaser-action@x"

# GitHub may run a workflow whose name starts with a dot, and a plain * skips it.
check_case "workflow file with a dot name" 1 ".hidden.yml:" step_workflow .hidden.yml "      - uses: goreleaser/goreleaser-action@x
$w_latest"
check_case "workflow file named .yml" 1 "workflows/.yml:" step_workflow .yml "      - uses: goreleaser/goreleaser-action@x
$w_latest"
check_case "workflow file named .yaml" 1 "workflows/.yaml:" step_workflow .yaml "      - uses: goreleaser/goreleaser-action@x
$w_latest"
check_case "workflow file with an upper case extension" 1 "extra.YML:" step_workflow extra.YML "      - uses: goreleaser/goreleaser-action@x
$w_latest"

# An env: or with: key must be a plain mapping. Any other form can build the
# name GORELEASER_VERSION or the version input from an expression.
env_expr="\${{ fromJSON(format('{{\"{0}_VERSION\":\"latest\"}}', 'GORELEASER')) }}"
env_not_map="the value of \"env\" must be a mapping"
check_case "yaml: env with an expression on the step" 1 "$env_not_map" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        env: \${{ matrix.env }}
        with:
          $ok_ver"
check_case "yaml: step env as a block scalar" 1 "$env_not_map" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        env: >-
          $env_expr
        with:
          $ok_ver"
check_case "yaml: step env as a block scalar, comment after the indicator" 1 "$env_not_map" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        env: >- # c
          $env_expr
        with:
          $ok_ver"
check_case "yaml: step env as a plain text on the next line" 1 "$env_not_map" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        env:
          $env_expr
        with:
          $ok_ver"
check_case "yaml: step env with a quoted key" 1 "$env_not_map" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        \"env\": $env_expr
        with:
          $ok_ver"
check_case "yaml: step env as an explicit key" 1 "$env_not_map" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        ? env
        : $env_expr
        with:
          $ok_ver"
with_not_map="the value of \"with\" must be a mapping, found a scalar"
check_case "yaml: with as a block scalar" 1 "$with_not_map" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with: >-
          \${{ fromJSON('{\"version\":\"latest\",\"x\":\"
          $ok_ver
          \"}') }}"
check_case "yaml: with as a plain text on the next line" 1 "$with_not_map" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        with:
          \${{ fromJSON('{\"version\":\"latest\"}') }}"
check_case "yaml: env and with as plain mappings are fine" 0 "" step_workflow extra.yml "      - uses: goreleaser/goreleaser-action@x
        env:
          \"QUOTED_KEY\": x
          OTHER: \${{ github.token }}
        with:
          $ok_ver"

# The names that govulncheck.yml may have, with the needs line of its job.
check_case "needs: govulncheck in a new job" 0 "" add_job "$wf/govulncheck.yml" '  other:
    needs: govulncheck
    runs-on: ubuntu-latest'
check_case "needs: a second needs key in the failure job" 1 "the key \"needs\" $dup" append "$wf/govulncheck.yml" '    needs: govulncheck'
check_case "needs: list form" 1 "$vuln_name" add_job "$wf/govulncheck.yml" '  other:
    needs: [govulncheck]
    runs-on: ubuntu-latest'
check_case "needs: key of a step" 1 "$vuln_name" append "$wf/govulncheck.yml" '      - needs: govulncheck
        run: echo hi'
check_case "needs: in ci.yml" 1 "$vuln_name" add_job "$wf/ci.yml" '  other:
    needs: govulncheck
    runs-on: ubuntu-latest'
check_case "if: line of the failure job, other result" 1 "$vuln_name" add_job "$wf/govulncheck.yml" "  other:
    if: failure() || needs.govulncheck.result == 'success'
    runs-on: ubuntu-latest"
check_case "if: line of the failure job in ci.yml" 1 "$vuln_name" add_job "$wf/ci.yml" "  other:
    if: failure() || needs.govulncheck.result == 'cancelled'
    runs-on: ubuntu-latest"
check_case "step that runs govulncheck" 1 "$vuln_name" append "$wf/govulncheck.yml" '      - run: govulncheck ./...'

# A pin with the form of a pre-release or with quotes is still a full version.
check_case "GoReleaser: rc suffix in all files" 0 "" rc_goreleaser
check_case "GoReleaser: rc suffix in ci.yml only" 1 "GORELEASER_VERSION is \"$gr_ver\", expected \"$gr_ver-rc.1\"" sub "$wf/ci.yml" 's/(GORELEASER_VERSION: v[0-9]+\.[0-9]+\.[0-9]+)/\1-rc.1/'
check_case "GoReleaser: quoted pin with a comment in all files" 0 "" quoted_goreleaser

# The output streams: ::error:: lines on stdout in GitHub Actions, else plain
# lines on stderr.
stream_case "output: GITHUB_ACTIONS=true" true '::error::' ''
stream_case "output: GITHUB_ACTIONS empty" '' '' 'check-tool-pins: '

# The wrapper finds the repository root from another directory, and passes its
# arguments to the checker.
wrapper_case "wrapper: real repository from /" 0
copy_tree
(cd "$tmp/w" && sub "$wf/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: v0.0.1/')
wrapper_case "wrapper: -root on a changed copy" 1 -root "$tmp/w"

if [ "$failed" -ne 0 ]; then
  echo "check-tool-pins-test: $failed of $total cases failed" >&2
  exit 1
fi
echo "check-tool-pins-test: all $total cases pass"
