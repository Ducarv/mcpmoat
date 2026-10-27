#!/usr/bin/env bash
# Tests the pin check (internal/pincheck, run by check-tool-pins.sh) end to
# end, on changed copies of the files that it reads. These cases are end to
# end probes: they run the real binary on real workflow files. They overlap
# the table tests in internal/pincheck on purpose. The Go tables own the
# details of the messages, so a case here checks only a fragment of the
# message. The ci-scripts job in ci.yml runs it. You can also run it on your
# machine, from any directory: see CONTRIBUTING.md, Checks. It needs bash, go
# and the standard tools cp, mv, mkdir, rm, sed, awk, cmp, head, grep, mktemp
# and ln.
# shellcheck disable=SC2016 # the sed expressions and the YAML hold a literal $
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=test-harness.sh
. "$(dirname -- "$0")/test-harness.sh"

CDPATH='' cd -- "$(dirname -- "$0")/../.."
src=$PWD
tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT

# Build the checker once. A go run per case would make the test slow.
go build -o "$tmp/pincheck" ./internal/pincheck

wfdir=.github/workflows
# workflows is the list of the workflows that may run govulncheck.
workflows=(ci release govulncheck)

# current_pin prints the version that ci.yml pins for NAME ($1). The cases read
# it, so that a version bump does not break them.
current_pin() {
  sed -nE "s/^ *$1: *\"?(v[^\" ]+).*/\\1/p" "$src/$wfdir/ci.yml" | head -n 1
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

# append adds the text $2 and a line break to the file $1 of the copy. jobs is
# the last top-level key of the three real workflows, so the indent of the
# text picks where it lands: indent 2 adds a job, a deeper indent adds to the
# last job or to its last step.
append() {
  printf '%s\n' "$2" >>"$1"
}

# copy_tree makes a fresh copy, in $tmp/w, of the files that the checker reads.
copy_tree() {
  rm -rf "${tmp:?}/w"
  mkdir -p "$tmp/w/.github"
  cp -R "$src/$wfdir" "$tmp/w/.github/"
  if [ -d "$src/.github/actions" ]; then cp -R "$src/.github/actions" "$tmp/w/.github/"; fi
  cp "$src/CONTRIBUTING.md" "$tmp/w/"
}

# pins_case NAME WANT_CODE WANT_TEXT SETUP [ARGS...]: makes a fresh copy, runs
# SETUP with ARGS in it and runs the checker on the copy. A failed setup stops
# the run and names the case.
pins_case() {
  local name=$1 want_code=$2 want_text=$3
  shift 3
  copy_tree
  run_setup "$name" in_dir "$tmp/w" "$@"
  check_case "$name" "$want_code" "$want_text" "$tmp/pincheck" -root "$tmp/w"
}

# streams_ok ACTIONS OUT_PREFIX ERR_PREFIX: runs the checker on the copy with
# GITHUB_ACTIONS set to ACTIONS. It wants exit 1, every stdout line to start
# with OUT_PREFIX and every stderr line to start with ERR_PREFIX. An empty
# prefix wants an empty stream. It prints the reason when it fails.
streams_ok() {
  local got=0 stream prefix
  GITHUB_ACTIONS=$1 "$tmp/pincheck" -root "$tmp/w" >"$tmp/stdout" 2>"$tmp/stderr" </dev/null || got=$?
  if [ "$got" != 1 ]; then
    echo "streams_ok: exit $got, want 1" >&2
    return 1
  fi
  for stream in stdout stderr; do
    prefix=$2
    if [ "$stream" = stderr ]; then prefix=$3; fi
    if [ -z "$prefix" ]; then
      if [ -s "$tmp/$stream" ]; then
        echo "streams_ok: $stream is not empty: $(cat "$tmp/$stream")" >&2
        return 1
      fi
    elif [ ! -s "$tmp/$stream" ] || grep -qv "^$prefix" "$tmp/$stream"; then
      echo "streams_ok: a $stream line lacks the prefix '$prefix': $(cat "$tmp/$stream")" >&2
      return 1
    fi
  done
}

# from_root runs check-tool-pins.sh from the directory / with the arguments
# ARGS. It tests that the wrapper finds the repository root and passes its
# arguments on.
from_root() {
  cd / && "$src/.github/scripts/check-tool-pins.sh" "$@"
}

# not_tmp_in_output: succeeds when the output of the last check_case does not
# hold the path of the temporary directory $tmp. It runs in a subshell, which
# sees case_out.
not_tmp_in_output() {
  [[ $case_out != *"$tmp"* ]]
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
  sub "$wfdir/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: latest/' &&
    append_step "$wfdir/govulncheck.yml" "$vuln_ver"
}

# same_extra_pin_everywhere adds the same second pin to all three workflows.
same_extra_pin_everywhere() {
  local f
  for f in "${workflows[@]}"; do
    append_step "$wfdir/$f.yml" v0.0.1 || return 1
  done
}

# float_govulncheck and float_goreleaser cut the patch number of a pin in every
# file that holds it. Go reads a short version as a query for the newest match.
float_govulncheck() {
  local f
  for f in "${workflows[@]}"; do
    sub "$wfdir/$f.yml" 's/(GOVULNCHECK_VERSION: v[0-9]+\.[0-9]+)\.[0-9]+/\1/' || return 1
  done
}

float_goreleaser() {
  sub "$wfdir/ci.yml" 's/(GORELEASER_VERSION: v[0-9]+\.[0-9]+)\.[0-9]+/\1/' &&
    sub "$wfdir/release.yml" 's/(GORELEASER_VERSION: v[0-9]+\.[0-9]+)\.[0-9]+/\1/' &&
    sub CONTRIBUTING.md 's|(goreleaser/v[0-9]+@v[0-9]+\.[0-9]+)\.[0-9]+|\1|g'
}

# rc_goreleaser and quoted_goreleaser change the pin of GoReleaser in every file
# that holds it. The form is still a full version, so the files must pass.
rc_goreleaser() {
  sub "$wfdir/ci.yml" 's/(GORELEASER_VERSION: v[0-9]+\.[0-9]+\.[0-9]+)/\1-rc.1/' &&
    sub "$wfdir/release.yml" 's/(GORELEASER_VERSION: v[0-9]+\.[0-9]+\.[0-9]+)/\1-rc.1/' &&
    sub CONTRIBUTING.md 's|(goreleaser/v[0-9]+@v[0-9]+\.[0-9]+\.[0-9]+)|\1-rc.1|g'
}

quoted_goreleaser() {
  sub "$wfdir/ci.yml" 's/(GORELEASER_VERSION: )(v[0-9.]+)/\1"\2" # note/' &&
    sub "$wfdir/release.yml" 's/(GORELEASER_VERSION: )(v[0-9.]+)/\1"\2" # note/'
}

# pin_env is the env of a job with the GoReleaser pin of ci.yml.
pin_env="    env:
      GORELEASER_VERSION: $gr_ver"
# gr_uses is the uses line of a goreleaser-action step, and gr_step is the good
# step. The cases change them or add to them.
ok_ver='version: ${{ env.GORELEASER_VERSION }}'
gr_uses='      - uses: goreleaser/goreleaser-action@x'
gr_step="$gr_uses
        with:
          $ok_ver"

# The wf_* functions write the new workflows of the cases, in the copy. Each
# takes the file name first.

# wf_write FILE JOBS [TOP]: a workflow whose jobs mapping is the text JOBS.
# TOP is more top-level text, before jobs. All the wf_* functions end here.
wf_write() {
  local top=''
  if [ -n "${3-}" ]; then top=$3$'\n'; fi
  printf 'name: extra\n%sjobs:\n%s\n' "$top" "$2" >"$wfdir/$1"
}

# wf_job FILE HEAD STEPS [TOP]: one job "x" with the job text HEAD (no line
# when it is empty), then the steps text STEPS.
wf_job() {
  local head=''
  if [ -n "$2" ]; then head=$2$'\n'; fi
  wf_write "$1" "  x:
${head}    steps:
$3" "${4-}"
}

# wf_steps FILE STEPS: one job that defines the pin of GoReleaser and has the
# steps STEPS.
wf_steps() {
  wf_job "$1" "$pin_env" "$2"
}

# wf_extra_env FILE EXTRA STEPS: as wf_steps, with the env text EXTRA after
# the pin (an empty EXTRA leaves a blank line). This puts a line next to the
# pin, where a bypass would go.
wf_extra_env() {
  wf_job "$1" "$pin_env
$2" "$3"
}

# wf_gr_inputs FILE VERSION_LINE: one goreleaser-action step with more
# inputs. When VERSION_LINE is empty, the step has no version line.
wf_gr_inputs() {
  local ver=''
  if [ -n "$2" ]; then ver=$'\n'"          $2"; fi
  wf_steps "$1" "$gr_uses
        with:
          distribution: goreleaser$ver
          args: check"
}

# wf_no_pin FILE: the good step in a job that does not define
# GORELEASER_VERSION.
wf_no_pin() {
  wf_job "$1" "" "$gr_step"
}

# wf_pin_after FILE VALUE: as wf_no_pin, with the pin VALUE in an env after
# the steps.
wf_pin_after() {
  wf_no_pin "$1" &&
    printf '    env:\n      GORELEASER_VERSION: %s\n' "$2" >>"$wfdir/$1"
}

# wf_pin_no_step FILE VALUE: the pin VALUE in the env of the job, and no
# goreleaser step.
wf_pin_no_step() {
  wf_job "$1" "    env:
      GORELEASER_VERSION: $2" "      - run: echo hi"
}

# wf_pin_top FILE: the pin in the env of the workflow, and the good step in a
# job that has no env.
wf_pin_top() {
  wf_job "$1" "" "$gr_step" "env:
  GORELEASER_VERSION: $gr_ver"
}

# wf_pin_indent FILE: the pin at the indent of a job key, not in the env.
wf_pin_indent() {
  wf_job "$1" "    GORELEASER_VERSION: $gr_ver" "$gr_step"
}

# wf_pin_other_key FILE: the pin at the right indent but under another job
# key than env, and no env in the job.
wf_pin_other_key() {
  wf_job "$1" "    outputs:
      GORELEASER_VERSION: $gr_ver" "$gr_step"
}

# wf_two_jobs FILE ENV_A ENV_B: a job "a" with the env text ENV_A and a step
# without goreleaser, and a job "b" with the env text ENV_B and the good step.
# An empty env text leaves a blank line.
wf_two_jobs() {
  wf_write "$1" "  a:
$2
    steps:
      - run: echo hi
  b:
$3
    steps:
$gr_step"
}

# wf_unlisted FILE PADDING: a workflow that is not one of the three that the
# checker lists. It runs govulncheck with a version of its own, then has
# PADDING padding steps.
wf_unlisted() {
  wf_write "$1" "  x:
    steps:
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
$(awk -v n="$2" 'BEGIN { for (i = 0; i < n; i++) print "      - run: echo padding padding padding padding" }')"
}

# actions_file writes the composite action .github/actions/x/action.yml with the
# text $1.
actions_file() {
  mkdir -p .github/actions/x && printf '%s\n' "$1" >.github/actions/x/action.yml
}

# anchor_and_alias turns the GoReleaser check step of ci.yml into an anchor with the
# name $1 (default gr) and adds a job that uses the alias. The alias line names
# nothing, and the new job has no pin of its own.
anchor_and_alias() {
  awk -v n="${1:-gr}" '/- name: Check the GoReleaser config/ { print "      - &" n; sub(/- name:/, "  name:") } { print }' "$wfdir/ci.yml" >"$wfdir/ci.yml.new" &&
    mv "$wfdir/ci.yml.new" "$wfdir/ci.yml" &&
    printf '  alias-job:\n    runs-on: ubuntu-latest\n    steps:\n      - *%s\n' "${1:-gr}" >>"$wfdir/ci.yml"
}

# pin_goes_on writes a workflow whose pin line goes on in a deeper line. YAML
# joins the two lines into one plain value.
pin_goes_on() {
  wf_extra_env extra.yml "" "      - run: echo hi" &&
    awk '{ print } /GORELEASER_VERSION:/ { print "        || >=2.0.0" }' "$wfdir/extra.yml" >"$wfdir/extra.yml.new" &&
    mv "$wfdir/extra.yml.new" "$wfdir/extra.yml"
}

# symlinked_action puts a composite action that names goreleaser-action outside
# .github/actions and links to it from inside.
symlinked_action() {
  mkdir -p elsewhere .github/actions &&
    printf '    - uses: goreleaser/goreleaser-action@x\n' >elsewhere/action.yml &&
    ln -s ../../elsewhere .github/actions/y
}

# The real files must pass.
pins_case "real files" 0 "" true

# The pin of govulncheck.
vuln_name="names govulncheck, but it is not the GOVULNCHECK_VERSION pin, the call or an allowed name"
no_call="no step has the run value"
pins_case "govulncheck: different pin" 1 "the govulncheck pin \"v0.0.1\" differs from \"$vuln_ver\"" sub "$wfdir/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: v0.0.1/'
pins_case "govulncheck: no pin in ci.yml" 1 "ci.yml: the file must pin one version of govulncheck" sub "$wfdir/ci.yml" '/^ *GOVULNCHECK_VERSION: v/d'
pins_case "govulncheck: pin value latest" 1 "govulncheck.yml: the file has no GOVULNCHECK_VERSION pin" sub "$wfdir/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: latest/'
pins_case "govulncheck: pin value from vars" 1 "has no GOVULNCHECK_VERSION pin" sub "$wfdir/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: ${{ vars.X }}/'
pins_case "govulncheck: pin value latest and a decoy pin" 1 "$vuln_name" decoy_pin
pins_case "govulncheck: short version in all files" 1 "must pin one version of govulncheck" float_govulncheck
# The second pin is in a job of its own: the last job of release.yml has a needs:
# key, and a job with the call may not have one.
pins_case "govulncheck: two equal pins in a file" 0 "" append "$wfdir/release.yml" "  again:
    runs-on: ubuntu-latest
    steps:
      - env:
          GOVULNCHECK_VERSION: $vuln_ver
$call"
pins_case "govulncheck: two different pins in a file" 1 "the govulncheck pin \"v0.0.1\" differs from" append_step "$wfdir/release.yml" v0.0.1
pins_case "govulncheck: two pins in ci.yml" 1 "must pin one version of govulncheck" append_step "$wfdir/ci.yml" v0.0.1
pins_case "govulncheck: same extra pin in all files" 1 "must pin one version of govulncheck" same_extra_pin_everywhere

# The call of govulncheck.
pins_case "call: hard-coded version" 1 "release.yml: $no_call" sub "$wfdir/release.yml" 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@v0.0.1/'
pins_case "call: @latest" 1 "govulncheck.yml: $no_call" sub "$wfdir/govulncheck.yml" 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@latest/'
pins_case "call: braces form" 1 "govulncheck.yml: $no_call" sub "$wfdir/govulncheck.yml" 's/\$GOVULNCHECK_VERSION"/${GOVULNCHECK_VERSION}"/'
pins_case "call: variable name with a suffix" 1 "govulncheck.yml: $no_call" sub "$wfdir/govulncheck.yml" 's/\$GOVULNCHECK_VERSION"/$GOVULNCHECK_VERSION_X"/'
pins_case "call: quote before @latest" 1 "govulncheck.yml: $no_call" sub "$wfdir/govulncheck.yml" 's|run: go run .*|run: go run "golang.org/x/vuln/cmd/govulncheck"@latest ./...|'
pins_case "call: variable set in the run line" 1 "govulncheck.yml: $no_call" sub "$wfdir/govulncheck.yml" 's|run: go run|run: GOVULNCHECK_VERSION=latest; go run|'
pins_case "call: go install @latest and the call" 1 "release.yml: $no_call" sub "$wfdir/release.yml" 's|run: go run|run: go install golang.org/x/vuln/cmd/govulncheck@latest \&\& go run|'
# YAML drops the comment, so the run value is still the call.
pins_case "call: inline comment after the call" 0 "" sub "$wfdir/release.yml" 's@^(.*run: go run .*)$@\1 # x@'
pins_case "call: || true after the call" 1 "release.yml: $no_call" sub "$wfdir/release.yml" 's@^(.*run: go run .*)$@\1 || true@'
# YAML joins a deeper line to the plain value before it.
pins_case "call: || true on a continuation line" 1 "govulncheck.yml: $no_call" after_call "$wfdir/govulncheck.yml" '          || true'
pins_case "call: || true on a continuation line in release.yml" 1 "release.yml: $no_call" after_call "$wfdir/release.yml" '          || true'
pins_case "govulncheck: call line at another indent" 1 "$no_call" sub "$wfdir/govulncheck.yml" 's/^ +(run: go run)/          \1/'
pins_case "continue-on-error in a step" 1 "continue-on-error is not allowed" append "$wfdir/govulncheck.yml" '        continue-on-error: true'
pins_case "continue-on-error with a quoted key" 1 "continue-on-error is not allowed" append "$wfdir/govulncheck.yml" '        "continue-on-error": true'
pins_case "continue-on-error as the first key of a step" 1 "continue-on-error is not allowed" append "$wfdir/govulncheck.yml" '      - continue-on-error: true'
pins_case "continue-on-error in another case" 1 "continue-on-error is not allowed" append "$wfdir/release.yml" '        Continue-On-Error: true'
pins_case "govulncheck-action step" 1 "$vuln_name" append "$wfdir/govulncheck.yml" '      - uses: golang/govulncheck-action@v1'
# A key on a continuation line of a plain value is not valid YAML.
pins_case "invalid YAML fails closed: key after the call" 1 "govulncheck.yml: parse YAML" after_call "$wfdir/govulncheck.yml" '          govulncheck:'
pins_case "job ID govulncheck in ci.yml" 1 "$vuln_name" append "$wfdir/ci.yml" '  govulncheck:
    runs-on: ubuntu-latest'
pins_case "call: no call in release.yml" 1 "release.yml: $no_call" sub "$wfdir/release.yml" '/govulncheck@/d'
pins_case "comment names govulncheck@v1.2.3" 0 "" append "$wfdir/release.yml" '# see govulncheck@v1.2.3'

# A workflow outside the list.
outside="the workflow names govulncheck. Only ci.yml"
pins_case "unlisted workflow with a space in its name" 1 "ci release.yml:5: $outside" wf_unlisted "ci release.yml" 0
pins_case "unlisted workflow runs govulncheck" 1 "extra.yml:5: $outside" wf_unlisted extra.yml 0
pins_case "unlisted workflow with the .yaml extension" 1 "extra.yaml:5: $outside" wf_unlisted extra.yaml 0
pins_case "large unlisted workflow runs govulncheck" 1 "$outside" wf_unlisted extra.yml 4000

# Missing files.
pins_case "ci.yml missing" 1 "ci.yml: the file is missing" rm "$wfdir/ci.yml"
pins_case "release.yml missing" 1 "release.yml: the file is missing" rm "$wfdir/release.yml"
pins_case "govulncheck.yml missing" 1 "govulncheck.yml: the file is missing" rm "$wfdir/govulncheck.yml"
pins_case "CONTRIBUTING.md missing" 1 "CONTRIBUTING.md: the file is missing" rm CONTRIBUTING.md

# The pin of GoReleaser.
gr_differs="differs from the pin \"$gr_ver\" in ci.yml"
gr_one="ci.yml must pin one full version of GoReleaser"
not_full="is not a full version"
pins_case "GoReleaser: different pin in release.yml" 1 "GORELEASER_VERSION is \"v0.0.1\", expected \"$gr_ver\"" sub "$wfdir/release.yml" 's/GORELEASER_VERSION: v[0-9.]+/GORELEASER_VERSION: v0.0.1/'
pins_case "GoReleaser: different pin in CONTRIBUTING.md" 1 "the GoReleaser version \"v0.0.1\" $gr_differs" sub CONTRIBUTING.md 's|(goreleaser/v[0-9]+)@v[0-9.]+|\1@v0.0.1|g'
pins_case "GoReleaser: different pin in one command only" 1 "\"v0.0.1\" $gr_differs" sub CONTRIBUTING.md '/ check /s|(goreleaser/v[0-9]+)@v[0-9.]+|\1@v0.0.1|'
pins_case "GoReleaser: pin value latest in release.yml" 1 "the GORELEASER_VERSION pin \"latest\" $not_full" sub "$wfdir/release.yml" 's/GORELEASER_VERSION: v[0-9.]+/GORELEASER_VERSION: latest/'
pins_case "GoReleaser: short pin value in a new job of ci.yml" 1 "the GORELEASER_VERSION pin \"${gr_ver%.*}\" $not_full" append "$wfdir/ci.yml" "  short:
    env:
      GORELEASER_VERSION: ${gr_ver%.*}"
pins_case "GoReleaser: @latest in one CONTRIBUTING.md command" 1 "\"latest\" $gr_differs" sub CONTRIBUTING.md '/ check /s|(goreleaser/v[0-9]+)@v[0-9.]+|\1@latest|'
pins_case "GoReleaser: short version in one CONTRIBUTING.md command" 1 "\"${gr_ver%.*}\" $gr_differs" sub CONTRIBUTING.md '/ check /s|(goreleaser/v[0-9]+@v[0-9]+\.[0-9]+)\.[0-9]+|\1|'
pins_case "GoReleaser: two pins in ci.yml" 1 "$gr_one" append "$wfdir/ci.yml" '  other:
    env:
      GORELEASER_VERSION: v0.0.1'
pins_case "GoReleaser: no pin in ci.yml" 1 "$gr_one" sub "$wfdir/ci.yml" '/GORELEASER_VERSION: v/d'
pins_case "GoReleaser: no pin in release.yml" 1 "release.yml: the workflow has no full GORELEASER_VERSION pin" sub "$wfdir/release.yml" '/GORELEASER_VERSION: v/d'
pins_case "GoReleaser: no version in CONTRIBUTING.md" 1 "CONTRIBUTING.md: names no GoReleaser version" sub CONTRIBUTING.md '/goreleaser\/v2@/d'
pins_case "GoReleaser: short version in all files" 1 "$gr_one" float_goreleaser

# The version input of each goreleaser-action step. The real steps are in
# ci.yml (two) and release.yml (one). The ranges select the step of a case.
ga_check="/Check the GoReleaser config/,/args: check/"
ga_release="/Run GoReleaser/,/args: release/"
bad_input='has a version input that is not ${{ env.GORELEASER_VERSION }}'
no_input="has no version input"
pins_case "goreleaser-action: hard-coded version" 1 "the goreleaser-action step \"Check the GoReleaser config\" $bad_input" sub "$wfdir/ci.yml" "$ga_check"'s/version: .*/version: v2.0.0/'
pins_case "goreleaser-action: version latest" 1 "the goreleaser-action step \"Run GoReleaser\" $bad_input" sub "$wfdir/release.yml" "$ga_release"'s/version: .*/version: latest/'
pins_case "goreleaser-action: other variable" 1 "$bad_input" sub "$wfdir/release.yml" "$ga_release"'s/GORELEASER_VERSION/OTHER_VERSION/'
pins_case "goreleaser-action: text after the variable" 1 "$bad_input" sub "$wfdir/release.yml" "$ga_release"'s/(version: .*)$/\1-x/'
pins_case "goreleaser-action: no version input" 1 "the goreleaser-action step \"Run GoReleaser\" $no_input" sub "$wfdir/release.yml" "$ga_release"'{/version:/d;}'
pins_case "goreleaser-action: no version input, next step has one" 1 "the goreleaser-action step \"Check the GoReleaser config\" $no_input" sub "$wfdir/ci.yml" "$ga_check"'{/version:/d;}'
pins_case "goreleaser-action: version key in another case" 1 "Write the version input key as version" sub "$wfdir/release.yml" "$ga_release"'s/version:/Version:/'
pins_case "goreleaser-action: new workflow without a version" 1 "extra.yml:9: the goreleaser-action step \"goreleaser/goreleaser-action@x\" $no_input" wf_gr_inputs extra.yml ""
pins_case "goreleaser-action: new .yaml workflow with latest" 1 "extra.yaml:10: the goreleaser-action step" wf_gr_inputs extra.yaml "version: latest"
pins_case "goreleaser-action: new workflow, quoted pin and trailing spaces" 0 "" wf_gr_inputs extra.yml 'version: "${{ env.GORELEASER_VERSION }}"   '
pins_case "goreleaser-action: new workflow, comment after the pin" 0 "" wf_gr_inputs extra.yml "$ok_ver # pinned"
pins_case "goreleaser-action: new workflow, plain pin" 0 "" wf_gr_inputs extra.yml "$ok_ver"

# The bypass classes of the step check.
w_with="        with:
          distribution: goreleaser
          $ok_ver"
w_latest="        with:
          version: latest"
# (a) A quoted uses value.
pins_case "goreleaser-action: quoted uses, version latest" 1 "$bad_input" wf_steps extra.yml "      - uses: \"goreleaser/goreleaser-action@x\"
$w_latest"
pins_case "goreleaser-action: single-quoted uses, version latest" 1 "$bad_input" wf_steps extra.yml "      - uses: 'goreleaser/goreleaser-action@x'
$w_latest"
pins_case "goreleaser-action: quoted uses, no version" 1 "$no_input" wf_steps extra.yml "      - uses: \"goreleaser/goreleaser-action@x\""
pins_case "goreleaser-action: quoted uses, good version" 0 "" wf_steps extra.yml "      - uses: \"goreleaser/goreleaser-action@x\"
$w_with"
pins_case "goreleaser-action: single-quoted uses, good version" 0 "" wf_steps extra.yml "      - uses: 'goreleaser/goreleaser-action@x' # note
$w_with"
# (b) Owner and repo names ignore case.
pins_case "goreleaser-action: other case, version latest" 1 "$bad_input" wf_steps extra.yml "      - uses: GoReleaser/goreleaser-action@x
$w_latest"
pins_case "goreleaser-action: other case, good version" 0 "" wf_steps extra.yml "      - uses: GoReleaser/GoReleaser-Action@x
$w_with"
# (c) Flow style is read like block style.
pins_case "goreleaser-action: flow style" 1 "$bad_input" wf_steps extra.yml "      - {uses: goreleaser/goreleaser-action@x, with: {version: latest}}"
pins_case "goreleaser-action: flow style, good version" 0 "" wf_steps extra.yml "      - {uses: goreleaser/goreleaser-action@x, with: {version: \"\${{ env.GORELEASER_VERSION }}\"}}"
pins_case "invalid YAML fails closed: flow style, plain expression" 1 "extra.yml: parse YAML" wf_steps extra.yml "      - {uses: goreleaser/goreleaser-action@x, with: {version: \${{ env.GORELEASER_VERSION }}}}"
pins_case "goreleaser-action: anchor before the action" 1 "an anchor (&a) is not allowed" wf_steps extra.yml "      - uses: &a goreleaser/goreleaser-action@x
$w_with"
pins_case "goreleaser-action: uses value on the next line" 0 "" wf_steps extra.yml "      - uses:
          goreleaser/goreleaser-action@x
$w_with"
pins_case "goreleaser-action: uses value on the next line, version latest" 1 "$bad_input" wf_steps extra.yml "      - uses:
          goreleaser/goreleaser-action@x
$w_latest"
pins_case "goreleaser-action: action path in a name line" 1 "names goreleaser/goreleaser-action, but it is not the uses value of a step" wf_steps extra.yml "      - name: goreleaser/goreleaser-action
        run: echo hi"
pins_case "goreleaser-action: action word without the path in a name line" 0 "" wf_steps extra.yml "      - name: Run goreleaser-action
        uses: goreleaser/goreleaser-action@x
$w_with"
pins_case "goreleaser-action: local action" 0 "" wf_steps extra.yml "      - uses: ./some/local@x"
# (d) More than one space after the dash.
pins_case "goreleaser-action: extra spaces after the dash, version latest" 1 "$bad_input" wf_steps extra.yml "      -   uses: goreleaser/goreleaser-action@x
          with:
            version: latest"
pins_case "goreleaser-action: extra spaces after the dash, no version" 1 "$no_input" wf_steps extra.yml "      -   uses: goreleaser/goreleaser-action@x"
pins_case "goreleaser-action: extra spaces after the dash, good version" 0 "" wf_steps extra.yml "      -   uses: goreleaser/goreleaser-action@x
          with:
            $ok_ver"
pins_case "goreleaser-action: with on the first line, good version" 0 "" wf_steps extra.yml "      - with:
          $ok_ver
        uses: goreleaser/goreleaser-action@x"
# (e) A version key outside the with: block does not count.
pins_case "goreleaser-action: version under env" 1 "$no_input" wf_steps extra.yml "$gr_uses
        with:
          distribution: goreleaser
        env:
          $ok_ver"
pins_case "goreleaser-action: version at the step level" 1 "$no_input" wf_steps extra.yml "$gr_uses
        with:
          distribution: goreleaser
        $ok_ver"
pins_case "goreleaser-action: version in a nested mapping of with" 1 "$no_input" wf_steps extra.yml "$gr_uses
        with:
          extra:
            $ok_ver"
pins_case "goreleaser-action: good version in env, latest in with" 1 "$bad_input" wf_steps extra.yml "$gr_uses
        with:
          version: latest
        env:
          $ok_ver"
pins_case "goreleaser-action: version after env, back in with" 0 "" wf_steps extra.yml "$gr_uses
        with:
          distribution: goreleaser
          $ok_ver
          args: check
        env:
          X: y"
# (f) GORELEASER_VERSION must be a full pin that equals ci.yml, in every file.
no_define="has a goreleaser-action step, but its env does not define GORELEASER_VERSION"
pins_case "GoReleaser: new workflow, no definition" 1 "extra.yml:3: the job \"x\" $no_define" wf_no_pin extra.yml
pins_case "GoReleaser: new workflow, pin value latest" 1 "extra.yml:9: the GORELEASER_VERSION pin \"latest\" $not_full" wf_pin_after extra.yml latest
pins_case "GoReleaser: new workflow, other full pin" 1 "extra.yml:9: GORELEASER_VERSION is \"v0.0.1\", expected \"$gr_ver\"" wf_pin_after extra.yml v0.0.1
pins_case "GoReleaser: new workflow, same pin" 0 "" wf_pin_after extra.yml "$gr_ver"
pins_case "GoReleaser: other pin in govulncheck.yml" 1 "GORELEASER_VERSION is \"v0.0.1\", expected" append "$wfdir/govulncheck.yml" '  other:
    env:
      GORELEASER_VERSION: v0.0.1'
pins_case "GoReleaser: latest in govulncheck.yml" 1 "the GORELEASER_VERSION pin \"latest\" $not_full" append "$wfdir/govulncheck.yml" '  other:
    env:
      GORELEASER_VERSION: latest'
pins_case "GoReleaser: pin in a new .yaml workflow without a step" 1 "extra.yaml:5: GORELEASER_VERSION is \"v0.0.1\"" wf_pin_no_step extra.yaml v0.0.1

# Ways to change the version at run time. The step reads the pin, but another
# entry could change what env.GORELEASER_VERSION holds. Each form must fail.
mention="mentions GORELEASER_VERSION in a form this check does not allow"
dup="is a duplicate (case-insensitive) of the key on line"
pins_case "override: job env, same pin" 0 "" wf_extra_env extra.yml "" "$gr_step"
# A second key next to the pin is a duplicate key, in any case or quote form.
pins_case "override: space before the colon" 1 "$dup" wf_extra_env extra.yml "      GORELEASER_VERSION : latest" "$gr_step"
pins_case "override: quoted key" 1 "$dup" wf_extra_env extra.yml '      "GORELEASER_VERSION": latest' "$gr_step"
pins_case "override: single-quoted key" 1 "$dup" wf_extra_env extra.yml "      'GORELEASER_VERSION': latest" "$gr_step"
pins_case "override: escaped key" 1 "$dup" wf_extra_env extra.yml '      "GORELEASER_VERSIO\x4e": latest' "$gr_step"
pins_case "override: lower case key" 1 "the key \"goreleaser_version\" $dup" wf_extra_env extra.yml "      goreleaser_version: latest" "$gr_step"
pins_case "override: mixed case key" 1 "$dup" wf_extra_env extra.yml "      Goreleaser_Version: latest" "$gr_step"
pins_case "override: mixed case key with the same version" 1 "$dup" wf_extra_env extra.yml "      Goreleaser_Version: $gr_ver" "$gr_step"
pins_case "override: flow style env" 1 "the GORELEASER_VERSION pin \"latest\" $not_full" wf_two_jobs extra.yml "" "    env: {GORELEASER_VERSION: latest}"
pins_case "override: flow style env, same pin" 0 "" wf_two_jobs extra.yml "" "    env: {GORELEASER_VERSION: $gr_ver}"
pins_case "override: run step writes GITHUB_ENV" 1 "$mention" wf_extra_env extra.yml "" "$gr_step
      - run: echo GORELEASER_VERSION=latest >> \"\$GITHUB_ENV\""
pins_case "override: run block writes GITHUB_ENV" 1 "$mention" wf_extra_env extra.yml "" "      - run: |
          echo \"GORELEASER_VERSION=latest\" >> \"\$GITHUB_ENV\"
$gr_step"
pins_case "override: run step reads the variable" 1 "$mention" wf_extra_env extra.yml "" "$gr_step
      - run: echo \"\${{ env.GORELEASER_VERSION }}\""
pins_case "override: step env, same pin" 1 "$mention" wf_extra_env extra.yml "" "$gr_step
        env:
          GORELEASER_VERSION: $gr_ver"
pins_case "override: step env, latest" 1 "$mention" wf_extra_env extra.yml "" "$gr_step
        env:
          GORELEASER_VERSION: latest"
pins_case "override: step env, lower case latest" 1 "$mention" wf_extra_env extra.yml "" "$gr_step
        env:
          goreleaser_version: latest"
pins_case "override: other variable name that holds the name" 1 "$mention" wf_extra_env extra.yml "      X_GORELEASER_VERSION: latest" "$gr_step"
pins_case "override: the text shows in the message" 1 "the text \"goreleaser_version\" $mention" wf_extra_env extra.yml "" "$gr_step
        env:
          goreleaser_version: latest"
pins_case "override: a comment may name it" 0 "" wf_extra_env extra.yml "      # goreleaser_version: latest" "$gr_step"
pins_case "override: the file is named" 1 "extra.yaml:12: the text \"goreleaser_version\"" wf_extra_env extra.yaml "" "$gr_step
        env:
          goreleaser_version: latest"
pins_case "override: in govulncheck.yml" 1 "$mention" append "$wfdir/govulncheck.yml" '      - run: echo GORELEASER_VERSION=latest >> "$GITHUB_ENV"'
pins_case "override: pin from vars in the job env" 1 "the GORELEASER_VERSION pin \"\${{ vars.X }}\" $not_full" wf_two_jobs extra.yml "" '    env:
      GORELEASER_VERSION: ${{ vars.X }}'
pins_case "override: empty pin in the job env" 1 "the GORELEASER_VERSION pin must be a full version" wf_two_jobs extra.yml "" '    env:
      GORELEASER_VERSION:'

# The scope of the pin: a job needs the pin in its own env.
pins_case "scope: pin in job a, step in job b" 1 "the job \"b\" $no_define" wf_two_jobs extra.yml "$pin_env" ""
pins_case "scope: pin in both jobs" 0 "" wf_two_jobs extra.yml "$pin_env" "$pin_env"
pins_case "scope: pin in job b only" 0 "" wf_two_jobs extra.yml "" "$pin_env"
pins_case "scope: pin at the workflow level only" 1 "the job \"x\" $no_define" wf_pin_top extra.yml
pins_case "scope: pin at the wrong indent in the job" 1 "$mention" wf_pin_indent extra.yml
pins_case "scope: pin under another job key" 1 "$mention" wf_pin_other_key extra.yml

# The composite actions are not read, so a file that names the action fails.
in_action="names goreleaser/goreleaser-action. This check does not read .github/actions"
pins_case "actions: composite action with goreleaser-action" 1 ".github/actions/x/action.yml: $in_action" actions_file "runs:
  using: composite
  steps:
    - uses: goreleaser/goreleaser-action@x"
pins_case "actions: other case" 1 "$in_action" actions_file "    - uses: GoReleaser/GoReleaser-Action@x"
pins_case "actions: other action" 0 "" actions_file "    - uses: actions/checkout@x"
pins_case "actions: symlinked directory" 1 ".github/actions/y: is a symlink" symlinked_action

# A # starts a comment only after a space.
pins_case "comment: no space after the version input" 1 "$bad_input" wf_steps extra.yml "$gr_uses
        with:
          $ok_ver#x"
pins_case "comment: no space after the pin" 1 "the GORELEASER_VERSION pin \"$gr_ver#x\" $not_full" sub "$wfdir/release.yml" 's/(GORELEASER_VERSION: v[0-9.]+)/\1#x/'
pins_case "comment: key quoted in the version input" 0 "" wf_steps extra.yml "$gr_uses
        with:
          \"version\": \"\${{ env.GORELEASER_VERSION }}\"  # pinned"
# After a closing quote, the YAML decoder reads #x as a comment. The decoded
# value is the pin, so the step is fine.
pins_case "comment: no space after the quoted version input" 0 "" wf_steps extra.yml "$gr_uses
        with:
          version: \"\${{ env.GORELEASER_VERSION }}\"#x"
pins_case "comment: no space after the quoted pin" 0 "" sub "$wfdir/release.yml" 's/(GORELEASER_VERSION: )(v[0-9.]+)/\1"\2"#x/'

# YAML anchors, aliases, merge keys and tags are not allowed. An alias names
# nothing, so the checks could not see the step that it repeats. The decoder
# fails on an alias without its anchor.
unknown_anchor="parse YAML: yaml: unknown anchor"
pins_case "yaml: anchor on the pinned step and an alias in a second job" 1 "an anchor (&gr) is not allowed" anchor_and_alias
pins_case "yaml: anchor on a value" 1 "extra.yml:8: an anchor (&a) is not allowed" wf_steps extra.yml "      - run: echo hi
        name: &a v"
pins_case "yaml: anchor on a key" 1 "extra.yml:8: an anchor (&a) is not allowed" wf_steps extra.yml "      - run: echo hi
        &a name: v"
pins_case "yaml: anchor on a list item" 1 "an anchor (&a) is not allowed" wf_steps extra.yml "      - &a
        run: echo hi"
pins_case "yaml: alias as a list item" 1 "$unknown_anchor 'gr'" wf_steps extra.yml "      - *gr"
pins_case "yaml: alias as a value" 1 "$unknown_anchor 'e'" wf_steps extra.yml "      - run: echo hi
        env: *e"
pins_case "yaml: alias with its anchor" 1 "an anchor (&e) is not allowed" wf_steps extra.yml "      - run: echo hi
        env: &e {A: b}
      - run: echo hi
        env: *e"
pins_case "yaml: alias with a comment" 1 "$unknown_anchor 'gr'" wf_steps extra.yml "      - *gr # note"
pins_case "yaml: alias in a flow list" 1 "$unknown_anchor 'b'" wf_steps extra.yml "      - run: echo hi
        needs: [a, *b]"
pins_case "yaml: merge key with an alias" 1 "$unknown_anchor 'x'" wf_steps extra.yml "      - run: echo hi
        <<: *x"
pins_case "yaml: merge key with a map" 1 "extra.yml:8: a merge key (<<) is not allowed" wf_steps extra.yml "      - run: echo hi
        <<: {a: b}"
pins_case "yaml: alias after a block scalar" 1 "$unknown_anchor 'gr'" wf_steps extra.yml "      - run: |
          echo hi
      - *gr"
pins_case "invalid YAML fails closed: dotted anchor name and an alias" 1 "ci.yml: parse YAML" anchor_and_alias gr.step
pins_case "yaml: anchor on its own line" 1 "an anchor (&l) is not allowed" wf_steps extra.yml "      &l
      - run: echo hi"
pins_case "invalid YAML fails closed: alias on its own line" 1 "extra.yml: parse YAML" wf_steps extra.yml "      - run: echo hi
      *l"
pins_case "yaml: the line shows in the message" 1 "extra.yml:8: an anchor (&e) is not allowed" wf_steps extra.yml "      - run: echo hi
        env: &e {a: b}"
pins_case "yaml: key alias with a space before the colon" 1 "$unknown_anchor 'k'" wf_steps extra.yml "      - run: echo hi
        *k : v"
pins_case "yaml: merge key with a space before the colon" 1 "a merge key (<<) is not allowed" wf_steps extra.yml "      - run: echo hi
        << : {a: b}"
pins_case "yaml: alias in govulncheck.yml" 1 "govulncheck.yml: $unknown_anchor" append "$wfdir/govulncheck.yml" '      - *gr'
pins_case "yaml: alias in a .yaml workflow" 1 "extra.yaml: $unknown_anchor" wf_steps extra.yaml "      - *gr"
pins_case "yaml: alias after a block scalar in a nested list" 1 "$unknown_anchor 'gr'" wf_steps extra.yml "      - - |
          text
        - *gr"
pins_case "yaml: tag before an escaped uses value" 1 "an explicit tag (!!str) is not allowed" wf_steps extra.yml "      - uses: !!str \"goreleaser/goreleaser-actio\\x6e@x\"
        with:
          version: latest"
pins_case "yaml: tag before an anchor" 1 "an anchor (&gr) is not allowed" wf_steps extra.yml "      - !!map &gr
        run: echo hi"
pins_case "yaml: tag on a value, no other form" 1 "extra.yml:7: an explicit tag (!!str) is not allowed" wf_steps extra.yml "      - name: !!str x
        run: echo hi"
pins_case "yaml: local tag on a value" 1 "an explicit tag (!x) is not allowed" wf_steps extra.yml "      - name: !x y
        run: echo hi"
pins_case "yaml: a comment may hold an alias" 0 "" wf_steps extra.yml "      # - *gr
      - run: echo hi # key: &a"
pins_case "yaml: quoted & and * in values" 0 "" wf_steps extra.yml "      - name: \"x: &a *b\"
        run: echo '*b' ; echo \"&a\""
pins_case "yaml: grep with a glob" 0 "" wf_steps extra.yml "      - run: grep -r '*.sh' ."
pins_case "yaml: && in a run line" 0 "" wf_steps extra.yml "      - run: a && b"
pins_case "yaml: branches with a quoted star" 0 "" wf_steps extra.yml "      - run: echo hi
        branches: ['*']"
pins_case "yaml: paths with a quoted glob" 0 "" wf_steps extra.yml "      - run: echo hi
        paths: ['**/*.md']"
pins_case "yaml: quoted star as a list item" 0 "" wf_steps extra.yml "      - run: echo hi
        branches:
          - '*'
          - \"**\""
pins_case "yaml: expression" 0 "" wf_steps extra.yml "      - run: echo \${{ matrix.os }} \${{ a && b }}
        if: \${{ matrix.os == 'x' }}"
pins_case "yaml: nested keys and block scalars are fine" 0 "" wf_steps extra.yml "      - name: x
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
pins_case "yaml: uses value with a hex escape" 1 "the goreleaser-action step \"goreleaser/goreleaser-action@x\" $bad_input" wf_steps extra.yml "      - uses: \"goreleaser/goreleaser-actio\\x6e@x\"
        with:
          version: latest"
pins_case "yaml: uses value with an escaped line break" 1 "the goreleaser-action step \"goreleaser/goreleaser-action@y\" $bad_input" wf_steps extra.yml "      - uses: \"goreleaser/goreleaser-\\
          action@y\"
        with:
          version: latest"
pins_case "yaml: quoted uses key with an escape" 1 "$no_input" wf_steps extra.yml "      - \"us\\x65s\": goreleaser/goreleaser-action@x"
pins_case "yaml: flow mapping with an escape in uses" 1 "$bad_input" wf_steps extra.yml "      - {uses: \"goreleaser/goreleaser-actio\\x6e@x\", with: {version: latest}}"
pins_case "yaml: double-quoted uses value, no escape" 0 "" wf_steps extra.yml "      - uses: \"actions/checkout@x\" # note"

# Duplicate keys, a key that is not a scalar and a second document fail.
pins_case "yaml: duplicate uses key in a step" 1 "the key \"Uses\" $dup" wf_steps extra.yml "      - uses: actions/checkout@x
        Uses: goreleaser/goreleaser-action@x"
pins_case "yaml: duplicate job ID" 1 "$dup" append "$wfdir/release.yml" '  release:
    runs-on: ubuntu-latest'
pins_case "yaml: key that is not a scalar" 1 "a mapping key must be a scalar" wf_steps extra.yml "      - run: echo hi
        ? [a, b]
        : c"
pins_case "yaml: second document" 1 "the file has more than one YAML document" append "$wfdir/govulncheck.yml" '---
name: second'

# The structure that the rules walk must have the shape GitHub needs.
pins_case "goreleaser-action: nested with: in a block body" 1 "$bad_input" wf_steps extra.yml "$gr_uses
        with:
          args: |
            with:
              version: \${{ env.GORELEASER_VERSION }}
          version: latest"
pins_case "yaml: env with an expression on the job" 1 "the value of \"env\" must be a mapping, found a scalar" wf_two_jobs extra.yml "" '    env: ${{ matrix.env }}'
pins_case "pin: pin text inside a block scalar of the job env" 1 "the value of \"env\" must be a mapping, found a scalar" wf_two_jobs extra.yml "    env:
      OTHER: x" "    env: >-
      GORELEASER_VERSION: $gr_ver"
pins_case "yaml: version input goes on in a deeper line" 1 "$bad_input" wf_steps extra.yml "$gr_uses
        with:
          $ok_ver
            || >=2.0.0"
pins_case "yaml: pin line goes on in a deeper line" 1 "the GORELEASER_VERSION pin \"$gr_ver || >=2.0.0\" $not_full" pin_goes_on
pins_case "yaml: steps as a mapping" 1 "the value of \"steps\" must be a sequence" wf_steps extra.yml "        uses: goreleaser/goreleaser-action@x"

# GitHub may run a workflow whose name starts with a dot, and a plain * skips it.
pins_case "workflow file with a dot name" 1 ".hidden.yml:" wf_steps .hidden.yml "$gr_uses
$w_latest"
pins_case "workflow file named .yml" 1 "workflows/.yml:" wf_steps .yml "$gr_uses
$w_latest"
pins_case "workflow file named .yaml" 1 "workflows/.yaml:" wf_steps .yaml "$gr_uses
$w_latest"
pins_case "workflow file with an upper case extension" 1 "extra.YML:" wf_steps extra.YML "$gr_uses
$w_latest"

# An env: or with: key must be a plain mapping. Any other form can build the
# name GORELEASER_VERSION or the version input from an expression.
env_expr="\${{ fromJSON(format('{{\"{0}_VERSION\":\"latest\"}}', 'GORELEASER')) }}"
env_not_map="the value of \"env\" must be a mapping"
pins_case "yaml: env with an expression on the step" 1 "$env_not_map" wf_steps extra.yml "$gr_uses
        env: \${{ matrix.env }}
        with:
          $ok_ver"
pins_case "yaml: step env as a block scalar" 1 "$env_not_map" wf_steps extra.yml "$gr_uses
        env: >-
          $env_expr
        with:
          $ok_ver"
pins_case "yaml: step env as a block scalar, comment after the indicator" 1 "$env_not_map" wf_steps extra.yml "$gr_uses
        env: >- # c
          $env_expr
        with:
          $ok_ver"
pins_case "yaml: step env as a plain text on the next line" 1 "$env_not_map" wf_steps extra.yml "$gr_uses
        env:
          $env_expr
        with:
          $ok_ver"
pins_case "yaml: step env with a quoted key" 1 "$env_not_map" wf_steps extra.yml "$gr_uses
        \"env\": $env_expr
        with:
          $ok_ver"
pins_case "yaml: step env as an explicit key" 1 "$env_not_map" wf_steps extra.yml "$gr_uses
        ? env
        : $env_expr
        with:
          $ok_ver"
with_not_map="the value of \"with\" must be a mapping, found a scalar"
pins_case "yaml: with as a block scalar" 1 "$with_not_map" wf_steps extra.yml "$gr_uses
        with: >-
          \${{ fromJSON('{\"version\":\"latest\",\"x\":\"
          $ok_ver
          \"}') }}"
pins_case "yaml: with as a plain text on the next line" 1 "$with_not_map" wf_steps extra.yml "$gr_uses
        with:
          \${{ fromJSON('{\"version\":\"latest\"}') }}"
pins_case "yaml: env and with as plain mappings are fine" 0 "" wf_steps extra.yml "$gr_uses
        env:
          \"QUOTED_KEY\": x
          OTHER: \${{ github.token }}
        with:
          $ok_ver"

# The names that govulncheck.yml may have, with the needs line of its job.
pins_case "needs: govulncheck in a new job" 0 "" append "$wfdir/govulncheck.yml" '  other:
    needs: govulncheck
    runs-on: ubuntu-latest'
pins_case "needs: a second needs key in the failure job" 1 "the key \"needs\" $dup" append "$wfdir/govulncheck.yml" '    needs: govulncheck'
pins_case "needs: list form" 1 "$vuln_name" append "$wfdir/govulncheck.yml" '  other:
    needs: [govulncheck]
    runs-on: ubuntu-latest'
pins_case "needs: key of a step" 1 "$vuln_name" append "$wfdir/govulncheck.yml" '      - needs: govulncheck
        run: echo hi'
pins_case "needs: in ci.yml" 1 "$vuln_name" append "$wfdir/ci.yml" '  other:
    needs: govulncheck
    runs-on: ubuntu-latest'
pins_case "if: line of the failure job, other result" 1 "$vuln_name" append "$wfdir/govulncheck.yml" "  other:
    if: failure() || needs.govulncheck.result == 'success'
    runs-on: ubuntu-latest"
pins_case "if: line of the failure job in ci.yml" 1 "$vuln_name" append "$wfdir/ci.yml" "  other:
    if: failure() || needs.govulncheck.result == 'cancelled'
    runs-on: ubuntu-latest"
pins_case "step that runs govulncheck" 1 "$vuln_name" append "$wfdir/govulncheck.yml" '      - run: govulncheck ./...'

# A job-level if: on the job that runs the call. GitHub skips the job when the
# if is false, so the scan would not run. The step-level if of the real ci.yml
# call step is fine. The real files pass (the first case of this script).
jobif_says='runs govulncheck, so it must not have a job-level if'
pins_case "job if: false on the call job of govulncheck.yml" 1 "the job \"govulncheck\" $jobif_says" sub "$wfdir/govulncheck.yml" 's/^  govulncheck:$/  govulncheck:\n    if: false/'
pins_case "job if: false on the call job of ci.yml" 1 "the job \"test\" $jobif_says" sub "$wfdir/ci.yml" 's/^  test:$/  test:\n    if: false/'
pins_case "job if: false on the call job of release.yml" 1 "the job \"test\" $jobif_says" sub "$wfdir/release.yml" 's/^  test:$/  test:\n    if: false/'
pins_case "job if: false on a job without the call is fine" 0 "" append "$wfdir/ci.yml" '  other:
    if: false
    runs-on: ubuntu-latest'
pins_case "step if on the call step of govulncheck.yml is fine" 0 "" sub "$wfdir/govulncheck.yml" 's/^      - name: Check for known vulnerabilities$/&\n        if: runner.os == "Linux"/'

# A job-level needs: on the job that runs the call. GitHub skips a job that
# waits for a skipped job, so the scan would not run. A needs: on a job without
# the call is fine.
needs_says='runs govulncheck, so it must not have a job-level needs'
pins_case "needs: gate on the call job of govulncheck.yml" 1 "the job \"govulncheck\" $needs_says" sub "$wfdir/govulncheck.yml" 's/^  govulncheck:$/  govulncheck:\n    needs: gate/'
pins_case "needs: [gate] on the call job of govulncheck.yml" 1 "the job \"govulncheck\" $needs_says" sub "$wfdir/govulncheck.yml" 's/^  govulncheck:$/  govulncheck:\n    needs: [gate]/'
pins_case "needs: gate on the call job of ci.yml" 1 "the job \"test\" $needs_says" sub "$wfdir/ci.yml" 's/^  test:$/  test:\n    needs: gate/'
pins_case "needs: gate on the call job of release.yml" 1 "the job \"test\" $needs_says" sub "$wfdir/release.yml" 's/^  test:$/  test:\n    needs: gate/'
pins_case "needs: gate on a job without the call is fine" 0 "" append "$wfdir/ci.yml" '  other:
    needs: gate
    runs-on: ubuntu-latest'

# A pin with the form of a pre-release or with quotes is still a full version.
pins_case "GoReleaser: rc suffix in all files" 0 "" rc_goreleaser
pins_case "GoReleaser: rc suffix in ci.yml only" 1 "GORELEASER_VERSION is \"$gr_ver\", expected \"$gr_ver-rc.1\"" sub "$wfdir/ci.yml" 's/(GORELEASER_VERSION: v[0-9]+\.[0-9]+\.[0-9]+)/\1-rc.1/'
pins_case "GoReleaser: quoted pin with a comment in all files" 0 "" quoted_goreleaser

# The output streams: ::error:: lines on stdout in GitHub Actions, else plain
# lines on stderr. Then the wrapper: it finds the repository root from another
# directory, and passes its arguments to the checker. The stream cases and the
# -root case run on one copy with a wrong govulncheck pin. go run exits 1 for
# every failure of the checker, so the -root cases also want a text.
copy_tree
run_setup "output and wrapper: wrong govulncheck pin" in_dir "$tmp/w" sub "$wfdir/govulncheck.yml" 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: v0.0.1/'
check_cmd "output: ::error:: lines on stdout with GITHUB_ACTIONS=true" streams_ok true '::error::' ''
check_cmd "output: plain lines on stderr with GITHUB_ACTIONS empty" streams_ok '' '' 'check-tool-pins: '
check_case "wrapper: real repository from /" 0 "" from_root
check_case "wrapper: -root on a changed copy" 1 "the govulncheck pin \"v0.0.1\" differs from \"$vuln_ver\"" from_root -root "$tmp/w"
check_case "wrapper: -root on a missing directory" 1 "open the repository root" from_root -root "$tmp/missing"
# The output of that run does not hold the temporary directory path, so the host path does not show.
check_cmd "wrapper: the root error shows no path" not_tmp_in_output

harness_footer check-tool-pins-test
