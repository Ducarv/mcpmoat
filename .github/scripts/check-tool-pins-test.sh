#!/usr/bin/env bash
# Tests check-tool-pins.sh on changed copies of the files that it reads. The
# release-check job in ci.yml runs it. You can also run it on your machine,
# from any directory: see CONTRIBUTING.md, Checks.
# shellcheck disable=SC2016 # the sed expressions and the call hold a literal $
set -euo pipefail

src=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

wf=.github/workflows
failed=0
total=0

# sub edits a file of the copy with a sed expression. It works with GNU and
# BSD sed.
sub() {
  sed -E "$2" "$1" >"$1.new"
  mv "$1.new" "$1"
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
  cp -R "$src/.github/scripts" "$src/.github/workflows" "$tmp/w/.github/"
  cp "$src/CONTRIBUTING.md" "$tmp/w/"
  if ! (cd "$tmp/w" && "$@"); then
    echo "FAIL: $name: the change to the copy failed"
    failed=$((failed + 1))
    return
  fi
  out=$("$tmp/w/.github/scripts/check-tool-pins.sh" 2>&1) || got=$?
  if [ "$got" != "$want" ]; then
    echo "FAIL: $name: exit $got, want $want"
    failed=$((failed + 1))
  elif [ "$want" = 1 ] && [[ $out != *"$msg"* ]]; then
    echo "FAIL: $name: the message lacks '$msg': $out"
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
  sub $wf/govulncheck.yml 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: latest/' &&
    append_step $wf/govulncheck.yml v1.9.0
}

# same_extra_pin_everywhere adds the same second pin to all three workflows.
same_extra_pin_everywhere() {
  local f
  for f in ci release govulncheck; do
    append_step "$wf/$f.yml" v1.0.0
  done
}

# float_govulncheck and float_goreleaser move a pin to a short version in every
# file that holds it. Go reads a short version as a query for the newest match.
float_govulncheck() {
  sub $wf/ci.yml 's/GOVULNCHECK_VERSION: v1\.9\.0/GOVULNCHECK_VERSION: v1.9/' &&
    sub $wf/release.yml 's/GOVULNCHECK_VERSION: v1\.9\.0/GOVULNCHECK_VERSION: v1.9/' &&
    sub $wf/govulncheck.yml 's/GOVULNCHECK_VERSION: v1\.9\.0/GOVULNCHECK_VERSION: v1.9/'
}

float_goreleaser() {
  sub $wf/ci.yml 's/GORELEASER_VERSION: v2\.19\.0/GORELEASER_VERSION: v2.19/' &&
    sub $wf/release.yml 's/GORELEASER_VERSION: v2\.19\.0/GORELEASER_VERSION: v2.19/' &&
    sub CONTRIBUTING.md 's|(goreleaser/v[0-9]+)@v2\.19\.0|\1@v2.19|g'
}

# fourth_workflow adds a workflow that is not in the list of the script. It
# runs govulncheck with a version of its own.
fourth_workflow() {
  printf 'name: extra\njobs:\n  x:\n    steps:\n      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...\n' >$wf/extra.yml
}

# The real files must pass.
check_case "real files" 0 "" true

# The pin of govulncheck.
check_case "different pin" 1 "The govulncheck pin of" sub $wf/govulncheck.yml 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: v0.0.1/'
check_case "no pin in ci.yml" 1 "ci.yml must pin one version of govulncheck" sub $wf/ci.yml '/^ *GOVULNCHECK_VERSION: v/d'
check_case "pin value latest" 1 "has no GOVULNCHECK_VERSION pin" sub $wf/govulncheck.yml 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: latest/'
check_case "pin value from vars" 1 "has no GOVULNCHECK_VERSION pin" sub $wf/govulncheck.yml 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: ${{ vars.X }}/'
check_case "pin value latest and a decoy pin" 1 "is not the pin, the call line or a name" decoy_pin
check_case "short version in all files" 1 "ci.yml must pin one version of govulncheck" float_govulncheck
check_case "two equal pins in a file" 0 "" append_step $wf/release.yml v1.9.0
check_case "two different pins in a file" 1 "The govulncheck pin of" append_step $wf/release.yml v1.8.0
check_case "two pins in ci.yml" 1 "ci.yml must pin one version of govulncheck" append_step $wf/ci.yml v1.8.0
check_case "same extra pin in all files" 1 "ci.yml must pin one version of govulncheck" same_extra_pin_everywhere

# The call of govulncheck.
check_case "hard-coded version" 1 "has no call line" sub $wf/release.yml 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@v1.9.0/'
check_case "@latest" 1 "has no call line" sub $wf/govulncheck.yml 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@latest/'
check_case "braces form" 1 "has no call line" sub $wf/govulncheck.yml 's/\$GOVULNCHECK_VERSION"/${GOVULNCHECK_VERSION}"/'
check_case "variable name with a suffix" 1 "has no call line" sub $wf/govulncheck.yml 's/\$GOVULNCHECK_VERSION"/$GOVULNCHECK_VERSION_X"/'
check_case "quote before @latest" 1 "has no call line" sub $wf/govulncheck.yml 's|run: go run .*|run: go run "golang.org/x/vuln/cmd/govulncheck"@latest ./...|'
check_case "variable set in the run line" 1 "has no call line" sub $wf/govulncheck.yml 's|run: go run|run: GOVULNCHECK_VERSION=latest; go run|'
check_case "go install @latest and the call" 1 "has no call line" sub $wf/release.yml 's|run: go run|run: go install golang.org/x/vuln/cmd/govulncheck@latest \&\& go run|'
check_case "inline comment after the call" 1 "has no call line" sub $wf/release.yml 's@^(.*run: go run .*)$@\1 # x@'
check_case "|| true after the call" 1 "has no call line" sub $wf/release.yml 's@^(.*run: go run .*)$@\1 || true@'
check_case "continuation line after the call" 1 "continues the call line" append $wf/govulncheck.yml '          || true'
check_case "continue-on-error in a step" 1 "uses continue-on-error" append $wf/govulncheck.yml '        continue-on-error: true'
check_case "govulncheck-action step" 1 "is not the pin, the call line or a name" append $wf/govulncheck.yml '      - uses: golang/govulncheck-action@v1'
check_case "bare govulncheck line in a run block" 1 "is not the pin, the call line or a name" append $wf/govulncheck.yml '          govulncheck:'
check_case "no call in release.yml" 1 "has no call line" sub $wf/release.yml '/govulncheck@/d'
check_case "comment names govulncheck@v1.2.3" 0 "" append $wf/release.yml '# see govulncheck@v1.2.3'
check_case "fourth workflow runs govulncheck" 1 "Add it to the workflows list" fourth_workflow

# Missing files.
check_case "ci.yml missing" 1 "ci.yml is missing" rm $wf/ci.yml
check_case "release.yml missing" 1 "release.yml is missing" rm $wf/release.yml
check_case "govulncheck.yml missing" 1 "govulncheck.yml is missing" rm $wf/govulncheck.yml
check_case "CONTRIBUTING.md missing" 1 "CONTRIBUTING.md is missing" rm CONTRIBUTING.md

# The pin of GoReleaser.
check_case "different pin in release.yml" 1 "The GoReleaser pins differ" sub $wf/release.yml 's/GORELEASER_VERSION: v[0-9.]+/GORELEASER_VERSION: v0.0.1/'
check_case "different pin in CONTRIBUTING.md" 1 "The GoReleaser pins differ" sub CONTRIBUTING.md 's|(goreleaser/v[0-9]+)@v[0-9.]+|\1@v0.0.1|g'
check_case "two pins in ci.yml" 1 "ci.yml must pin one version of GoReleaser" append $wf/ci.yml '      GORELEASER_VERSION: v0.0.1'
check_case "no pin in ci.yml" 1 "ci.yml must pin one version of GoReleaser" sub $wf/ci.yml '/GORELEASER_VERSION: v/d'
check_case "no pin in release.yml" 1 "The GoReleaser pins differ" sub $wf/release.yml '/GORELEASER_VERSION: v/d'
check_case "no version in CONTRIBUTING.md" 1 "The GoReleaser pins differ" sub CONTRIBUTING.md '/goreleaser\/v2@/d'
check_case "short version in all files" 1 "ci.yml must pin one version of GoReleaser" float_goreleaser

if [ "$failed" -ne 0 ]; then
  echo "check-tool-pins-test: $failed of $total cases failed" >&2
  exit 1
fi
echo "check-tool-pins-test: all $total cases pass"
