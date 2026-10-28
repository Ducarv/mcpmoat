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
# `--label security --state open --limit 200 --json number,title`. A case
# sets the list that the fake prints, runs the body, and wants an exit code,
# the exact calls and a text in the output.
#
# NOTIFY_WORKFLOW (a path) selects another copy of the workflow to test.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=test-harness.sh
. "$(dirname -- "$0")/test-harness.sh"
CDPATH='' cd -- "$(dirname -- "$0")/../.."
workflow=${NOTIFY_WORKFLOW:-$PWD/.github/workflows/govulncheck.yml}
tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT

S=$tmp/state # the state of the fake gh
title="Weekly vulnerability check failed"
run_url=https://github.com/owner/repo/actions/runs/42
list_call="issue list -R owner/repo --label security --state open --limit 200 --json number,title"

[ -r "$workflow" ] || fail "Cannot read the workflow $workflow."
extract_run_block "$workflow" "Open or update the failure issue" notify-failure >"$tmp/run.sh" ||
  fail "$workflow has no run block in the step 'Open or update the failure issue' of the job notify-failure."

# The run body is inline shell in the workflow, and `shellcheck
# .github/scripts/*.sh` does not see it.
if command -v shellcheck >/dev/null 2>&1; then
  check_cmd "shellcheck passes on the run block" shellcheck -s bash "$tmp/run.sh"
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
  if [ -e "$S/create_fails" ]; then
    echo "fake gh: the create call failed" >&2
    exit 1
  fi
  ;;
"issue comment")
  has "-R owner/repo"
  if [ -e "$S/comment_fails" ]; then
    echo "fake gh: the comment call failed" >&2
    exit 1
  fi
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
create_fails() { empty_list && touch "$S/create_fails"; }
comment_fails() { exact_and_similar && touch "$S/comment_fails"; }
other_case() { echo '[{"number":4,"title":"weekly vulnerability check failed"}]' >"$S/list.json"; }

# run_body runs the body with the fake gh, in an empty environment.
run_body() {
  env -i PATH="$tmp/bin:$PATH" HOME="$tmp/home" FAKE_GH_STATE="$S" \
    GH_TOKEN=fake GITHUB_SERVER_URL=https://github.com GITHUB_REPOSITORY=owner/repo \
    GITHUB_RUN_ID=42 bash -e "$tmp/run.sh"
}

# calls_are ACTION: checks the call log of the fake. ACTION is "none" (only
# the list call), "create" or "comment N" (the list call, then exactly that
# call, with the run URL in its arguments). It prints what it got on a
# mismatch.
calls_are() {
  local action=$1 calls want_call
  calls=$(cat "$S/calls")
  case $action in
  none) want_call="" ;;
  create) want_call="issue create -R owner/repo --title $title --label security --body " ;;
  comment*) want_call="issue comment ${action#comment } -R owner/repo --body " ;;
  esac
  if [ "${calls%%$'\n'*}" != "$list_call" ]; then
    echo "the first call is not the list call: $calls" >&2
    return 1
  elif [ "$action" = none ] && [ "$calls" != "$list_call" ]; then
    echo "want only the list call, got: $calls" >&2
    return 1
  elif [ "$action" != none ] &&
    { [ "$(wc -l <<<"$calls")" -ne 2 ] || [[ $(tail -n 1 <<<"$calls") != "$want_call"*"$run_url"* ]]; }; then
    echo "want the list call and then '$want_call...$run_url', got: $calls" >&2
    return 1
  fi
}

# notify_case NAME WANT_CODE WANT_TEXT SETUP ACTION: runs the body with the
# list from SETUP, checks the exit code and the text, then checks the calls
# with calls_are ACTION.
notify_case() {
  local name=$1 want_code=$2 want_text=$3 setup=$4 action=$5
  new_state
  run_setup "$name" "$setup"
  check_case "$name" "$want_code" "$want_text" run_body
  check_cmd "$name: the gh calls are '$action'" calls_are "$action"
}

notify_case "no open issue" 0 "" empty_list create
notify_case "exact and similar title" 0 "" exact_and_similar "comment 9"
notify_case "only a similar title" 0 "" only_similar create
notify_case "two issues with the title" 0 "" two_exact "comment 5"
notify_case "the list call fails" 1 "the list call failed" list_fails none
notify_case "the create call fails" 1 "the create call failed" create_fails create
notify_case "the comment call fails" 1 "the comment call failed" comment_fails "comment 9"
notify_case "the title is case sensitive" 0 "" other_case create

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
    s && /^        ["\047]?[A-Za-z_-]+["\047]? *:/ && $1 != "run:" { print }
  ' "$tmp/job.txt" | grep -q .
}
# The job has the permission issues: write and no other permission.
only_issues_write() { [ "$(job_section permissions)" = "      issues: write" ]; }
job_has_no_switch() { ! grep -Eq "^    [\"']?continue-on-error[\"']? *:" "$tmp/job.txt"; }

check_cmd "the job notify-failure has 'needs: govulncheck'" grep -Eq '^    needs: govulncheck *$' "$tmp/job.txt"
check_cmd "the job notify-failure has the if: line for a failed or cancelled scan" grep -Eq "^    if: failure\(\) \|\| needs\.govulncheck\.result == 'cancelled' *$" "$tmp/job.txt"
check_cmd "the step of the job notify-failure has no key other than name and run" step_has_only_run
check_cmd "the job notify-failure has no continue-on-error: key" job_has_no_switch
check_cmd "the job notify-failure has exactly the permission 'issues: write'" only_issues_write
check_cmd "the job notify-failure has no checkout step" no_checkout
check_cmd "the job notify-failure has 'GH_TOKEN: \${{ github.token }}' under the job env" has_job_token

harness_footer notify-failure-test
