#!/usr/bin/env bash
# Tests check-tool-pins.sh on changed copies of the files that it reads. The
# release-check job in ci.yml runs it. You can also run it on your machine,
# from any directory.
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
# command after the exit code, runs the script and compares its exit code.
check_case() {
  local name=$1 want=$2 got=0
  shift 2
  total=$((total + 1))
  rm -rf "${tmp:?}/w"
  mkdir -p "$tmp/w/.github"
  cp -R "$src/.github/scripts" "$src/.github/workflows" "$tmp/w/.github/"
  cp "$src/CONTRIBUTING.md" "$tmp/w/"
  (cd "$tmp/w" && "$@")
  "$tmp/w/.github/scripts/check-tool-pins.sh" >/dev/null 2>&1 || got=$?
  if [ "$got" != "$want" ]; then
    echo "FAIL: $name: exit $got, want $want"
    failed=$((failed + 1))
  fi
}

call='        run: go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...'
extra_step() {
  printf '      - env:\n          GOVULNCHECK_VERSION: %s\n%s\n' "$1" "$call"
}

decoy_pin() {
  sub $wf/govulncheck.yml 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: latest/'
  extra_step v1.9.0 >>$wf/govulncheck.yml
}

same_extra_pin_everywhere() {
  local f
  for f in ci release govulncheck; do
    extra_step v1.0.0 >>"$wf/$f.yml"
  done
}

# The real files must pass.
check_case "real files" 0 true

# The pin of govulncheck.
check_case "different pin" 1 sub $wf/govulncheck.yml 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: v0.0.1/'
check_case "no pin in ci.yml" 1 sub $wf/ci.yml '/^ *GOVULNCHECK_VERSION: v/d'
check_case "pin value latest" 1 sub $wf/govulncheck.yml 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: latest/'
check_case "pin value from vars" 1 sub $wf/govulncheck.yml 's/GOVULNCHECK_VERSION: v[0-9.]+/GOVULNCHECK_VERSION: ${{ vars.X }}/'
check_case "pin value latest and a decoy pin" 1 decoy_pin
check_case "two equal pins in a file" 0 eval "extra_step v1.9.0 >>$wf/release.yml"
check_case "two different pins in a file" 1 eval "extra_step v1.8.0 >>$wf/release.yml"
check_case "two pins in ci.yml" 1 eval "extra_step v1.8.0 >>$wf/ci.yml"
check_case "same extra pin in all files" 1 same_extra_pin_everywhere

# The call of govulncheck.
check_case "hard-coded version" 1 sub $wf/release.yml 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@v1.9.0/'
check_case "@latest" 1 sub $wf/govulncheck.yml 's/govulncheck@\$GOVULNCHECK_VERSION/govulncheck@latest/'
check_case "braces form" 1 sub $wf/govulncheck.yml 's/\$GOVULNCHECK_VERSION"/${GOVULNCHECK_VERSION}"/'
check_case "variable name with a suffix" 1 sub $wf/govulncheck.yml 's/\$GOVULNCHECK_VERSION"/$GOVULNCHECK_VERSION_X"/'
check_case "quote before @latest" 1 sub $wf/govulncheck.yml 's|run: go run .*|run: go run "golang.org/x/vuln/cmd/govulncheck"@latest ./...|'
check_case "variable set in the run line" 1 sub $wf/govulncheck.yml 's|run: go run|run: GOVULNCHECK_VERSION=latest; go run|'
check_case "go install @latest and the call" 1 sub $wf/release.yml 's|run: go run|run: go install golang.org/x/vuln/cmd/govulncheck@latest \&\& go run|'
check_case "inline comment after the call" 1 sub $wf/release.yml 's@^(.*run: go run .*)$@\1 # x@'
check_case "|| true after the call" 1 sub $wf/release.yml 's@^(.*run: go run .*)$@\1 || true@'
check_case "govulncheck-action step" 1 append $wf/govulncheck.yml '      - uses: golang/govulncheck-action@v1'
check_case "bare govulncheck line in a run block" 1 append $wf/govulncheck.yml '          govulncheck:'
check_case "no call in release.yml" 1 sub $wf/release.yml '/govulncheck@/d'
check_case "comment names govulncheck@v1.2.3" 0 append $wf/release.yml '# see govulncheck@v1.2.3'

# Missing files.
check_case "ci.yml missing" 1 rm $wf/ci.yml
check_case "release.yml missing" 1 rm $wf/release.yml
check_case "govulncheck.yml missing" 1 rm $wf/govulncheck.yml
check_case "CONTRIBUTING.md missing" 1 rm CONTRIBUTING.md

# The pin of GoReleaser.
check_case "different GoReleaser pin in release.yml" 1 sub $wf/release.yml 's/GORELEASER_VERSION: v[0-9.]+/GORELEASER_VERSION: v0.0.1/'
check_case "different GoReleaser pin in CONTRIBUTING.md" 1 sub CONTRIBUTING.md 's|(goreleaser/v[0-9]+)@v[0-9.]+|\1@v0.0.1|g'
check_case "two GoReleaser pins in ci.yml" 1 append $wf/ci.yml '      GORELEASER_VERSION: v0.0.1'

if [ "$failed" -ne 0 ]; then
  echo "check-tool-pins-test: $failed of $total cases failed" >&2
  exit 1
fi
echo "check-tool-pins-test: all $total cases pass"
