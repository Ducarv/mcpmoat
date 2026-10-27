#!/usr/bin/env bash
# Tests test-harness.sh, the helpers that the other test scripts source. The
# ci-scripts job in ci.yml runs it. You can also run it on your machine, from
# any directory: see CONTRIBUTING.md, Checks. It needs bash and the standard
# tools awk, cmp, cat, env and mktemp. It needs no network and no token.
#
# Each check runs the harness under test in a new bash, so that a failure or
# an exit of the harness is a result, not the end of this test. Part 1 tests
# the case runner, the failure output and the footer with plain bash, because
# part 2 uses the case runner. Part 2 tests the run block extractor.
#
# HARNESS_UNDER_TEST is a test hook, not a setting for normal use. Set it to
# an absolute path to test another copy of the harness, for example a copy
# with a bug on purpose, to see that the checks fail. Part 2 runs the
# extractor of the harness under test, with the case runner of the real
# harness.
# shellcheck disable=SC2016 # the scripts in single quotes run in the child
set -euo pipefail

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR source=test-harness.sh
. "$here/test-harness.sh"
under=${HARNESS_UNDER_TEST:-$here/test-harness.sh}
tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT

# Part 1: plain bash.
plain_total=0
plain_failed=0

# expect NAME WANT_CODE WANT_TEXT SCRIPT: runs SCRIPT in a new bash with
# set -euo pipefail, GITHUB_ACTIONS unset and the harness under test sourced.
# It wants the exit code and the fixed text in stdout and stderr.
expect() {
  local name=$1 want=$2 text=$3 script=$4 out code=0
  plain_total=$((plain_total + 1))
  out=$(env -u GITHUB_ACTIONS "$BASH" -c 'set -euo pipefail; . "$1"; eval "$2"' _ "$under" "$script" 2>&1) || code=$?
  if [ "$code" != "$want" ]; then
    echo "FAIL: $name: exit $code, want $want: $out" >&2
    plain_failed=$((plain_failed + 1))
  elif [[ $out != *"$text"* ]]; then
    echo "FAIL: $name: the output lacks '$text': $out" >&2
    plain_failed=$((plain_failed + 1))
  fi
}

expect "record_failure prints FAIL: and counts" 0 $'FAIL: x y\nfailed=1' \
  'record_failure x y; echo "failed=$harness_failed"'
expect "record_failure in GitHub Actions" 0 "::error::x" \
  'GITHUB_ACTIONS=true record_failure x'
# GitHub sets GITHUB_ACTIONS to exactly "true". Another value is not Actions.
expect "record_failure with GITHUB_ACTIONS=1 prints FAIL:" 0 "FAIL: x" \
  'GITHUB_ACTIONS=1 record_failure x'
# A line break in the output of a case must not end the annotation: the next
# line could be a workflow command. The child prints the output with %q only,
# so a raw command never reaches this script.
expect "an annotation stays one line" 0 "one annotation" \
  'err=$(GITHUB_ACTIONS=true check_case demo 1 "" printf "x\n::stop-commands::x\n" 2>&1)
  if [ "$err" = "::error::demo: exit 0, want 1: x%0A::stop-commands::x" ]; then echo "one annotation"; else printf "got %q\n" "$err"; exit 1; fi'
expect "an annotation encodes % and CR" 0 "encoded" \
  'err=$(GITHUB_ACTIONS=true record_failure "a%0Ab$(printf "\r")::x" 2>&1)
  if [ "$err" = "::error::a%250Ab%0D::x" ]; then echo encoded; else printf "got %q\n" "$err"; exit 1; fi'
# A CR shows as the two characters \r.
expect "a FAIL: line indents the later lines of the output" 0 "indented" \
  'err=$(check_case demo 1 "" printf "x\n::stop-commands::x\rt: all 9 cases pass\n" 2>&1)
  want=$(printf "FAIL: demo: exit 0, want 1: x\n  > ::stop-commands::x\\\\rt: all 9 cases pass")
  if [ "$err" = "$want" ]; then echo indented; else printf "got %q\n" "$err"; exit 1; fi'
expect "fail records and exits 1" 1 "FAIL: boom" \
  'fail boom; echo after'
expect "run_setup goes on after a good setup" 0 "after" \
  'run_setup "the case" true; echo after'
expect "run_setup names the case of a failed setup" 1 "FAIL: the case: the setup failed (sh -c echo why; exit 4)" \
  'run_setup "the case" sh -c "echo why; exit 4"; echo after'
expect "run_setup names the inner command of a wrapper" 1 "FAIL: the case: the setup failed (in_dir / false)" \
  'run_setup "the case" in_dir / false'
expect "run_setup keeps a newline in the command on one line" 1 "the setup failed (in_dir / false a ::error::x)" \
  'GITHUB_ACTIONS=true run_setup "the case" in_dir / false $'"'"'a\n::error::x'"'"
expect "in_dir runs the command in the directory" 0 "pwd=/." \
  'out=$(cd "$HOME" && in_dir / pwd); echo "pwd=$out."'
expect "in_dir passes the arguments" 0 "args=a b|c." \
  'out=$(in_dir / printf "%s|" "a b" c); echo "args=${out%|}."'
expect "in_dir fails on a missing directory" 0 "code=1" \
  'in_dir /nonexistent-in-dir-test true 2>/dev/null || echo "code=$?"'
expect "run_setup shows the output of a failed setup" 1 "why" \
  'run_setup "the case" sh -c "echo why; exit 4"'
expect "check_case goes on after a non-zero exit" 0 "t: all 2 cases pass" \
  'check_case c 3 "" sh -c "exit 3"; check_case d 0 "" true; harness_footer t'
expect "check_case catches a wrong exit code" 1 "FAIL: bad code: exit 2, want 0: out" \
  'check_case "bad code" 0 "" sh -c "echo out; exit 2"; harness_footer t'
expect "check_case catches a missing text" 1 "FAIL: no text: the output lacks 'hello': bye" \
  'check_case "no text" 0 hello echo bye; harness_footer t'
expect "check_case reads stderr" 0 "t: all 1 cases pass" \
  'check_case c 0 "on err" sh -c "echo on err >&2"; harness_footer t'
expect "check_case nonzero accepts 1" 0 "t: all 1 cases pass" \
  'check_case c nonzero "" false; harness_footer t'
expect "check_case nonzero rejects 0" 1 "FAIL: z: exit 0, want nonzero" \
  'check_case z nonzero "" true; harness_footer t'
expect "a failed case does not stop the later cases" 1 "t: 1 of 2 cases failed" \
  'check_case a 0 "" false; check_case b 0 "" true; harness_footer t'
expect "check_case cuts a long output" 1 "(3000 more characters)" \
  'check_case big 0 "" sh -c "printf %05000d 0; exit 1"; harness_footer t'
expect "check_output finds a second text of the run" 1 "FAIL: third: the output lacks 'three'" \
  'check_case c 0 one echo one two; check_output second two; check_output third three; harness_footer t'
expect "check_output counts its cases" 1 "t: 1 of 3 cases failed" \
  'check_case c 0 one echo one two; check_output second two; check_output third three; harness_footer t'
expect "check_cmd records the name of a failed check" 1 "FAIL: named check: the check failed" \
  'check_cmd "named check" false; harness_footer t'
expect "check_cmd shows the output of a failed check" 1 "FAIL: named check: the check failed: why" \
  'check_cmd "named check" sh -c "echo why; exit 1"; harness_footer t'
expect "check_cmd passes" 0 "t: all 1 cases pass" \
  'check_cmd "named check" true; harness_footer t'
expect "footer with no case exits 1" 1 "t: no case ran" \
  'harness_footer t; echo after'
expect "footer with one failure exits 1" 1 "t: 1 of 1 cases failed" \
  'check_cmd one false; harness_footer t; echo after'

# Sourcing the harness prints nothing and turns on no shell option.
plain_total=$((plain_total + 1))
out=$("$BASH" -c '. "$1"; echo "options=$-"' _ "$under" 2>&1)
if [[ $out != options=* ]] || [[ ${out#options=} == *[eu]* ]]; then
  echo "FAIL: sourcing the harness prints text or sets an option: $out" >&2
  plain_failed=$((plain_failed + 1))
fi

if [ "$plain_failed" -ne 0 ]; then
  echo "test-harness-test: $plain_failed of $plain_total plain checks failed" >&2
  exit 1
fi

# Part 2: the extractor, with the case runner of the real harness.

# extract FILE STEP [JOB]: runs extract_run_block of the harness under test.
extract() {
  "$BASH" -c '. "$1"; shift; extract_run_block "$@"' _ "$under" "$@"
}

# block_is WANT STEP [JOB]: the extractor prints exactly WANT for the step of
# the fixture, byte for byte.
block_is() {
  local want=$1
  shift
  printf '%s' "$want" >"$tmp/want"
  extract "$tmp/fixture.yml" "$@" >"$tmp/got" || return 1
  cmp -s "$tmp/want" "$tmp/got" || {
    echo "got:" && cat "$tmp/got"
    return 1
  }
}

# Every run block that must not show in an output prints LEAK.
cat >"$tmp/fixture.yml" <<'YAML'
name: fixture
on:
  push:
jobs:
  first:
    steps:
      - name: Build
        run: |
          echo build
      - name: Target
        run: |
          echo "a ${{ github.sha }} 'q'"

            indented line
          echo "end \$x \\ done"   # trailing

      # a comment
      - name: Last
        run: |
              echo last
  second:
    steps:
      - name: Target
        run: |-
          echo second
      - name: No run
        uses: actions/checkout@v4
        with:
          run: |
            echo LEAK nested
      - name: Next
        run: |
          echo LEAK next step
      - run: |
          echo LEAK unnamed
  third:
    steps:
      - run: echo LEAK
      - name: Twice
        uses: actions/checkout@v4
      - name: Twice
        run: |
          echo LEAK twice
YAML
# A line of only tabs and spaces is blank: in a run block, and before a job
# key, where it must not end the jobs mapping.
printf '  tabs:\n    steps:\n      - name: Tab\n        run: |\n          echo one\n\t\n \t \n          echo two\n\t\n  after:\n    steps:\n      - name: Tab\n        run: |\n          echo after tab\n' >>"$tmp/fixture.yml"

target=$'echo "a ${{ github.sha }} \'q\'"\n\n  indented line\necho "end \\$x \\\\ done"   # trailing\n'
check_cmd "extractor: block with blank lines, \${{ }} and quotes, byte for byte" block_is "$target" Target
check_cmd "extractor: the job first gives the same block" block_is "$target" Target first
check_cmd "extractor: the later step is not in the block" block_is $'echo build\n' Build
# The body of Last has a deeper indent than usual. YAML takes the indent of
# its first line.
check_cmd "extractor: the later job is not in the block, any body indent" block_is $'echo last\n' Last
check_cmd "extractor: the job argument picks the second job, run: |-" block_is $'echo second\n' Target second
check_cmd "extractor: a line of tabs and spaces is a blank line of the block" block_is $'echo one\n\n\necho two\n' Tab
check_cmd "extractor: a line of tabs before a job key keeps the job" block_is $'echo after tab\n' Tab after
check_case "extractor: a step with no run block exits 3" 3 "" extract "$tmp/fixture.yml" "No run"
check_case "extractor: the first step with the name has no run block" 3 "" extract "$tmp/fixture.yml" Twice
check_case "extractor: a missing step exits 3" 3 "" extract "$tmp/fixture.yml" Missing
check_case "extractor: the step is not in the job" 3 "" extract "$tmp/fixture.yml" Target third
check_case "extractor: a missing job exits 3" 3 "" extract "$tmp/fixture.yml" Target fourth

harness_total=$((harness_total + plain_total)) # part 1 passed
harness_footer test-harness-test
