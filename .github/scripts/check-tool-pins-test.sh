#!/usr/bin/env bash
# Tests check-tool-pins.sh on changed copies of the files that it reads. The
# release-check job in ci.yml runs it. You can also run it on your machine,
# from any directory: see CONTRIBUTING.md, Checks.
# shellcheck disable=SC2016 # the sed expressions and the call hold a literal $
set -euo pipefail

src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

wf=.github/workflows
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
  for f in ci release govulncheck; do
    append_step "$wf/$f.yml" v0.0.1
  done
}

# float_govulncheck and float_goreleaser cut the patch number of a pin in every
# file that holds it. Go reads a short version as a query for the newest match.
float_govulncheck() {
  local f
  for f in ci release govulncheck; do
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
    printf 'name: extra\njobs:\n  x:\n    steps:\n      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...\n'
    awk -v n="$2" 'BEGIN { for (i = 0; i < n; i++) print "      - run: echo padding padding padding padding" }'
  } >"$wf/$1"
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
check_case "hard-coded version" 1 "has no call line" sub "$wf/release.yml" 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@v0.0.1/'
check_case "@latest" 1 "has no call line" sub "$wf/govulncheck.yml" 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@latest/'
check_case "braces form" 1 "has no call line" sub "$wf/govulncheck.yml" 's/\$GOVULNCHECK_VERSION"/${GOVULNCHECK_VERSION}"/'
check_case "variable name with a suffix" 1 "has no call line" sub "$wf/govulncheck.yml" 's/\$GOVULNCHECK_VERSION"/$GOVULNCHECK_VERSION_X"/'
check_case "quote before @latest" 1 "has no call line" sub "$wf/govulncheck.yml" 's|run: go run .*|run: go run "golang.org/x/vuln/cmd/govulncheck"@latest ./...|'
check_case "variable set in the run line" 1 "has no call line" sub "$wf/govulncheck.yml" 's|run: go run|run: GOVULNCHECK_VERSION=latest; go run|'
check_case "go install @latest and the call" 1 "has no call line" sub "$wf/release.yml" 's|run: go run|run: go install golang.org/x/vuln/cmd/govulncheck@latest \&\& go run|'
check_case "inline comment after the call" 1 "has no call line" sub "$wf/release.yml" 's@^(.*run: go run .*)$@\1 # x@'
check_case "|| true after the call" 1 "has no call line" sub "$wf/release.yml" 's@^(.*run: go run .*)$@\1 || true@'
check_case "continuation line after the call" 1 "continues the call line" append "$wf/govulncheck.yml" '          || true'
check_case "continue-on-error in a step" 1 "uses continue-on-error" append "$wf/govulncheck.yml" '        continue-on-error: true'
check_case "continue-on-error as the first key of a step" 1 "uses continue-on-error" append "$wf/govulncheck.yml" '      - continue-on-error: true'
check_case "govulncheck-action step" 1 "is not the pin, the call line or a name" append "$wf/govulncheck.yml" '      - uses: golang/govulncheck-action@v1'
check_case "bare govulncheck line in a run block" 1 "is not the pin, the call line or a name" append "$wf/govulncheck.yml" '          govulncheck:'
check_case "job ID govulncheck in ci.yml" 1 "is not the pin, the call line or a name" append "$wf/ci.yml" '  govulncheck:'
check_case "no call in release.yml" 1 "has no call line" sub "$wf/release.yml" '/govulncheck@/d'
check_case "comment names govulncheck@v1.2.3" 0 "" append "$wf/release.yml" '# see govulncheck@v1.2.3'

# A workflow outside the list.
check_case "fourth workflow runs govulncheck" 1 "Add it to the workflows list" fourth_workflow extra.yml 0
check_case "fourth workflow with the .yaml extension" 1 "Add it to the workflows list" fourth_workflow extra.yaml 0
check_case "large fourth workflow runs govulncheck" 1 "Add it to the workflows list" fourth_workflow extra.yml 4000

# Missing files.
check_case "ci.yml missing" 1 "ci.yml is missing" rm "$wf/ci.yml"
check_case "release.yml missing" 1 "release.yml is missing" rm "$wf/release.yml"
check_case "govulncheck.yml missing" 1 "govulncheck.yml is missing" rm "$wf/govulncheck.yml"
check_case "CONTRIBUTING.md missing" 1 "CONTRIBUTING.md is missing" rm CONTRIBUTING.md

# The pin of GoReleaser.
check_case "GoReleaser: different pin in release.yml" 1 "The GoReleaser pins differ" sub "$wf/release.yml" 's/GORELEASER_VERSION: v[0-9.]+/GORELEASER_VERSION: v0.0.1/'
check_case "GoReleaser: different pin in CONTRIBUTING.md" 1 "The GoReleaser pins differ" sub CONTRIBUTING.md 's|(goreleaser/v[0-9]+)@v[0-9.]+|\1@v0.0.1|g'
check_case "GoReleaser: different pin in one command only" 1 "The GoReleaser pins differ" sub CONTRIBUTING.md '/ check /s|(goreleaser/v[0-9]+)@v[0-9.]+|\1@v0.0.1|'
check_case "GoReleaser: two pins in ci.yml" 1 "ci.yml must pin one version of GoReleaser" append "$wf/ci.yml" '      GORELEASER_VERSION: v0.0.1'
check_case "GoReleaser: no pin in ci.yml" 1 "ci.yml must pin one version of GoReleaser" sub "$wf/ci.yml" '/GORELEASER_VERSION: v/d'
check_case "GoReleaser: no pin in release.yml" 1 "The GoReleaser pins differ" sub "$wf/release.yml" '/GORELEASER_VERSION: v/d'
check_case "GoReleaser: no version in CONTRIBUTING.md" 1 "The GoReleaser pins differ" sub CONTRIBUTING.md '/goreleaser\/v2@/d'
check_case "GoReleaser: short version in all files" 1 "ci.yml must pin one version of GoReleaser" float_goreleaser

if [ "$failed" -ne 0 ]; then
  echo "check-tool-pins-test: $failed of $total cases failed" >&2
  exit 1
fi
echo "check-tool-pins-test: all $total cases pass"
