#!/usr/bin/env bash
# Tests the notify-failure job of govulncheck.yml with a fake gh. The ci-scripts
# job in ci.yml runs it. Maintainers can also run it on their machine, from any
# directory: see CONTRIBUTING.md, Checks. It needs bash, jq and the standard
# tools (awk, grep, sed, cat, mktemp and so on). It needs no network and no
# token.
#
# The job cannot call a script: it has no checkout, so that it can keep
# `permissions: issues: write` and nothing else. So this test takes the real
# code out of the workflow. The run body is tested by running it: the test
# reads the `run: |` body of the step "Open or update the failure issue" in the
# job notify-failure, and it runs that body. The job and step keys are checked
# by text: needs, if, permissions (only issues: write), env, no checkout, no
# continue-on-error and no step key other than name and run. A change to the
# workflow is a change to the code under test.
#
# The fake gh keeps a call log. It exits 99 on an unknown subcommand, on a
# missing `-R owner/repo`, on a missing token, and on a list call without
# `--label security --state open --limit 200 --json number,title`. A case sets the list that the
# fake prints, runs the body, and wants an exit code, the exact calls and a
# text in the output.
#
# NOTIFY_WORKFLOW (a path) selects another copy of the workflow to test.
set -euo pipefail

CDPATH='' cd -- "$(dirname -- "$0")/../.."
workflow=${NOTIFY_WORKFLOW:-$PWD/.github/workflows/govulncheck.yml}
tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT

S=$tmp/state # the state of the fake gh
title="Weekly vulnerability check failed"
run_url=https://github.com/owner/repo/actions/runs/42
failed=0
total=0

# fail stops the test at once.
fail() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error::$*" >&2
  else
    echo "FAIL: $*" >&2
  fi
  exit 1
}

# record_failure reports a failed case and goes on with the next one.
record_failure() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error::$*" >&2
  else
    echo "FAIL: $*" >&2
  fi
  failed=$((failed + 1))
}

# extract_run prints the body of the run step out of the job notify-failure,
# without the YAML indent. The job ends at the next line with an indent of two
# spaces. The first run block of the step is the only block that it prints:
# the line that ends the block still counts as the start of the next step.
# It exits 3 when there is no run block.
extract_run() {
  awk '
    /^  [A-Za-z0-9_-]+:/ { job = ($1 == "notify-failure:"); step = 0 }
    inrun {
      if ($0 ~ /^ *$/) { print ""; next }
      match($0, /^ */)
      if (RLENGTH >= indent) { print substr($0, indent + 1); next }
      exit
    }
    job && /^ *- name: Open or update the failure issue *$/ { step = 1; next }
    step && /^ *- name:/ { step = 0 }
    step && /^ *run: \|[+-]? *$/ {
      match($0, /^ */)
      indent = RLENGTH + 2
      inrun = 1
      found = 1
    }
    END { exit found ? 0 : 3 }
  ' "$1"
}

# Regression test for the extractor: a later step and a later job with their
# own run blocks must not end up in the output.
cat >"$tmp/two-steps.yml" <<'YAML'
jobs:
  notify-failure:
    steps:
      - name: Open or update the failure issue
        run: |
          echo first
          echo second
      - name: Another step
        run: |
          exit 7
  other:
    steps:
      - run: |
          exit 8
YAML
total=$((total + 1))
got=$(extract_run "$tmp/two-steps.yml" || true)
[ "$got" = "$(printf 'echo first\necho second')" ] ||
  record_failure "the extractor prints more or less than the first run block of the step: $got"

[ -r "$workflow" ] || fail "Cannot read the workflow $workflow."
extract_run "$workflow" >"$tmp/run.sh" ||
  fail "$workflow has no run block in the step 'Open or update the failure issue' of the job notify-failure."
grep -q '[^[:space:]]' "$tmp/run.sh" || fail "The run block of the step 'Open or update the failure issue' is empty."

# The run body is inline shell in the workflow, and `shellcheck
# .github/scripts/*.sh` does not see it.
if command -v shellcheck >/dev/null 2>&1; then
  total=$((total + 1))
  shellcheck -s bash "$tmp/run.sh" || record_failure "shellcheck reports a problem in the run block"
fi

# The fake gh. The quoted delimiter keeps every $ for the fake to expand.
mkdir -p "$tmp/bin" "$tmp/home"
cat >"$tmp/bin/gh" <<'FAKE'
#!/usr/bin/env bash
# Fake gh for notify-failure-test.sh. State is in files in $FAKE_GH_STATE.
set -euo pipefail
S=${FAKE_GH_STATE:?}
die() {
  echo "fake gh: $*" >&2
  exit 99
}
[ "${GH_TOKEN:-}" = fake ] || die "GH_TOKEN is not 'fake'"
args="$*"
echo "$args" >>"$S/calls"
# has dies unless the arguments contain $1 as whole words.
has() { [[ " $args " == *" $1 "* ]] || die "'$1' is missing: $args"; }

case "${1:-} ${2:-}" in
"issue list")
  has "-R owner/repo"
  has "--label security"
  has "--state open"
  has "--limit 200"
  has "--json number,title"
  if [ -e "$S/list_fails" ]; then
    echo "fake gh: the list call failed" >&2
    exit 1
  fi
  cat "$S/list.json"
  ;;
"issue create")
  has "-R owner/repo"
  ;;
"issue comment")
  has "-R owner/repo"
  ;;
*) die "unexpected call: $args" ;;
esac
FAKE
chmod +x "$tmp/bin/gh"

# Ways to set the list that the fake prints.
new_state() {
  rm -rf "${S:?}"
  mkdir -p "$S"
  : >"$S/calls"
}
empty_list() { echo '[]' >"$S/list.json"; }
exact_and_similar() {
  echo '[{"number":7,"title":"Weekly vulnerability check failed again"},{"number":9,"title":"Weekly vulnerability check failed"}]' >"$S/list.json"
}
only_similar() { echo '[{"number":7,"title":"Weekly vulnerability check failed again"}]' >"$S/list.json"; }
two_exact() {
  echo '[{"number":5,"title":"Weekly vulnerability check failed"},{"number":3,"title":"Weekly vulnerability check failed"}]' >"$S/list.json"
}
list_fails() { touch "$S/list_fails"; }
other_case() { echo '[{"number":4,"title":"weekly vulnerability check failed"}]' >"$S/list.json"; }

# check_case runs the body with the list from the setup $3 and checks three
# things: the exit code $2, the calls and the text $5 in the output. $4 is
# "none" (only the list call), "create" or "comment N" (the list call, then
# exactly that call, with the run URL in its arguments).
check_case() {
  local name=$1 want=$2 setup=$3 action=$4 msg=$5 got=0 out calls list_call want_call
  total=$((total + 1))
  new_state
  "$setup"
  out=$(env -i PATH="$tmp/bin:$PATH" HOME="$tmp/home" FAKE_GH_STATE="$S" \
    GH_TOKEN=fake GITHUB_SERVER_URL=https://github.com GITHUB_REPOSITORY=owner/repo \
    GITHUB_RUN_ID=42 bash -e "$tmp/run.sh" 2>&1) || got=$?
  calls=$(cat "$S/calls")
  list_call="issue list -R owner/repo --label security --state open --limit 200 --json number,title"
  case $action in
  none) want_call="" ;;
  create) want_call="issue create -R owner/repo --title $title --label security --body " ;;
  comment*) want_call="issue comment ${action#comment } -R owner/repo --body " ;;
  esac
  if [ "$got" != "$want" ]; then
    record_failure "$name: exit $got, want $want: $out"
  elif [ "${calls%%$'\n'*}" != "$list_call" ]; then
    record_failure "$name: the first call is not the list call: $calls"
  elif [ "$action" = none ] && [ "$calls" != "$list_call" ]; then
    record_failure "$name: want only the list call, got: $calls"
  elif [ "$action" != none ] &&
    { [ "$(wc -l <<<"$calls")" -ne 2 ] || [[ $(tail -n 1 <<<"$calls") != "$want_call"*"$run_url"* ]]; }; then
    record_failure "$name: want the list call and then '$want_call...$run_url', got: $calls"
  elif [[ $out != *"$msg"* ]]; then
    record_failure "$name: the output lacks '$msg': $out"
  fi
}

check_case "no open issue" 0 empty_list create ""
check_case "exact and similar title" 0 exact_and_similar "comment 9" ""
check_case "only a similar title" 0 only_similar create ""
check_case "two issues with the title" 0 two_exact "comment 5" ""
check_case "the list call fails" 1 list_fails none "the list call failed"
check_case "the title is case sensitive" 0 other_case create ""

# The keys of the job. The cases above give the fake its token, so they cannot
# see a missing key. The checks below read the job block as text, without the
# comment lines.
awk '
  /^  [A-Za-z0-9_-]+:/ { job = ($1 == "notify-failure:") }
  /^[^ #]/ { job = 0 }
  job && !/^ *#/
' "$workflow" >"$tmp/job.txt"
[ -s "$tmp/job.txt" ] || fail "$workflow has no job notify-failure."

# job_section prints the lines under the job key $1, for example permissions.
job_section() {
  awk -v k="$1" '
    $0 ~ "^    " k ":" { on = 1; next }
    on && /^      / { print; next }
    { on = 0 }
  ' "$tmp/job.txt"
}

# check_text runs the command after the name and records a failure when it
# fails.
check_text() {
  local name=$1
  shift
  total=$((total + 1))
  "$@" || record_failure "the job notify-failure: $name"
}
# shellcheck disable=SC2016 # the ${{ }} must stay literal
has_job_token() { job_section env | grep -Fqx '      GH_TOKEN: ${{ github.token }}'; }
no_checkout() { ! grep -q 'actions/checkout' "$tmp/job.txt"; }

# The step has only a name and a run key. Any other key, such as if:,
# continue-on-error:, shell:, env: or working-directory:, could change how the
# body runs. The job must not hide a failure of its own.
step_has_only_run() {
  ! awk '
    /^      - name: Open or update the failure issue *$/ { s = 1; next }
    s && /^      - / { s = 0 }
    s && /^        [A-Za-z_-]+:/ && $1 != "run:" { print }
  ' "$tmp/job.txt" | grep -q .
}
# The job has the permission issues: write and no other permission.
only_issues_write() { [ "$(job_section permissions)" = "      issues: write" ]; }
job_has_no_switch() { ! grep -Eq '^    continue-on-error:' "$tmp/job.txt"; }

check_text "lacks 'needs: govulncheck'" grep -Eq '^    needs: govulncheck *$' "$tmp/job.txt"
check_text "lacks the if: line for a failed or cancelled scan" grep -Eq "^    if: failure\(\) \|\| needs\.govulncheck\.result == 'cancelled' *$" "$tmp/job.txt"
check_text "the step has a key other than name and run" step_has_only_run
check_text "the job has a continue-on-error: key" job_has_no_switch
check_text "the permissions are not exactly 'issues: write'" only_issues_write
check_text "has a checkout step" no_checkout
check_text "lacks 'GH_TOKEN: \${{ github.token }}' under the job env" has_job_token

if [ "$failed" -ne 0 ]; then
  echo "notify-failure-test: $failed of $total cases failed" >&2
  exit 1
fi
echo "notify-failure-test: all $total cases pass"
