# shellcheck shell=bash
# Shared helpers for the test scripts in .github/scripts. Source this file, do
# not run it. It defines functions and sets the counters to zero. It runs
# nothing else and sets no shell options: the test script sets its own.
# test-harness-test.sh tests it.
#
# The pattern. Every case has the arguments NAME WANT_CODE WANT_TEXT, then a
# command. A script with a setup per case wraps check_case in a case function
# of its own, with the same order:
#
#   #!/usr/bin/env bash
#   set -euo pipefail
#   # shellcheck source-path=SCRIPTDIR source=test-harness.sh
#   . "$(dirname -- "$0")/test-harness.sh"
#   src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
#   tmp=$(mktemp -d)
#   trap 'rm -rf "${tmp:?}"' EXIT
#
#   in_copy() { cd "$tmp/w" && "$@"; }  # run_setup runs it in a subshell
#
#   # snapshot_case NAME WANT_CODE WANT_TEXT SETUP [ARGS...]
#   snapshot_case() {
#     local name=$1 want_code=$2 want_text=$3
#     shift 3
#     rm -rf "${tmp:?}/w" && cp -R "$src/dist" "$tmp/w"  # a new dir per case
#     run_setup "$name" in_copy "$@"  # a failure stops and names the case
#     check_case "$name" "$want_code" "$want_text" "$tmp/w/check.sh"
#     # More checks on the same run: case_out has its output.
#     check_output "$name: closing message" "the release is public"
#     check_cmd "$name: the release is a draft" state_is draft
#   }
#
#   extract_run_block "$workflow" "Step name" job-id >"$tmp/run.sh" ||
#     fail "$workflow has no run block in the step 'Step name'."
#   snapshot_case "real snapshot" 0 "" true
#   snapshot_case "extra archive" 1 "expected only" extra_archive
#   check_cmd "the job has no checkout step" no_checkout
#   harness_footer check-snapshot-test  # the last line of the script

harness_total=0  # the number of cases
harness_failed=0 # the number of failures
case_code=0      # the exit code of the last check_case
case_out=''      # the output (stdout and stderr) of the last check_case

# record_failure MSG...: reports a failure and counts it. The run goes on. In
# GitHub Actions it prints an ::error:: annotation, else a FAIL: line. Both go
# to stderr.
record_failure() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error::$*" >&2
  else
    echo "FAIL: $*" >&2
  fi
  harness_failed=$((harness_failed + 1))
}

# fail MSG...: records the failure, then stops the script with exit 1. Use it
# when the later cases cannot run, for example when an input file is missing.
# In a subshell it stops only the subshell.
fail() {
  record_failure "$@"
  exit 1
}

# harness_clip TEXT: prints TEXT, cut to its first 2000 characters, so that a
# failure line stays readable.
harness_clip() {
  if [ "${#1}" -gt 2000 ]; then
    printf '%s... (%d more characters)' "${1:0:2000}" $((${#1} - 2000))
  else
    printf '%s' "$1"
  fi
}

# run_setup NAME CMD [ARGS...]: runs the setup of the case NAME in a subshell,
# so that a cd in the setup does not leak. Its output shows only when it
# fails. A failure stops the script with a message that names the case and
# the whole command, so that a wrapper such as in_copy does not hide the real
# setup. CMD runs where set -e has no effect, so join the commands of a setup
# function with && or end each one with || return 1.
run_setup() {
  local name=$1 out cmd
  shift
  cmd=$*
  # A newline or control character in an argument must not start a new line.
  out=$("$@" 2>&1 </dev/null) || fail "$name: the setup failed ($(harness_clip "${cmd//[[:cntrl:]]/ }")): $(harness_clip "$out")"
}

# check_case NAME WANT_CODE WANT_TEXT CMD [ARGS...]: runs one case. It runs
# CMD with ARGS, with stdin from /dev/null, and keeps stdout and stderr in
# case_out and the exit code in case_code. A non-zero exit does not stop the
# script under set -e. The case fails when the exit code is not WANT_CODE
# ("nonzero" accepts every code but 0), or when the output does not contain
# the fixed text WANT_TEXT. An empty WANT_TEXT checks no text.
check_case() {
  local name=$1 want_code=$2 want_text=$3
  shift 3
  harness_total=$((harness_total + 1))
  case_code=0
  case_out=$("$@" 2>&1 </dev/null) || case_code=$?
  if [ "$want_code" = nonzero ] && [ "$case_code" != 0 ]; then
    want_code=$case_code
  fi
  if [ "$case_code" != "$want_code" ]; then
    record_failure "$name: exit $case_code, want $want_code: $(harness_clip "$case_out")"
  elif [ -n "$want_text" ] && [[ $case_out != *"$want_text"* ]]; then
    record_failure "$name: the output lacks '$want_text': $(harness_clip "$case_out")"
  fi
}

# check_output NAME TEXT: a case on the output of the last check_case. It
# fails when case_out does not contain the fixed text TEXT. Use it to check a
# second message of one run, instead of a second run of the same setup.
check_output() {
  harness_total=$((harness_total + 1))
  [[ $case_out == *"$2"* ]] || record_failure "$1: the output lacks '$2': $(harness_clip "$case_out")"
}

# check_cmd NAME CMD [ARGS...]: a case with no exit code or text to compare.
# It runs CMD in the current shell and records the failure NAME when CMD
# fails. The output of CMD shows. As in run_setup, set -e has no effect in CMD.
check_cmd() {
  local name=$1
  shift
  harness_total=$((harness_total + 1))
  "$@" || record_failure "$name"
}

# harness_footer NAME: the last line of a test script. It prints
# "NAME: all M cases pass", or "NAME: N of M cases failed" on stderr and then
# exits 1.
harness_footer() {
  if [ "$harness_failed" -ne 0 ]; then
    echo "$1: $harness_failed of $harness_total cases failed" >&2
    exit 1
  fi
  echo "$1: all $harness_total cases pass"
}

# extract_run_block FILE STEP [JOB]: prints the body of the `run: |` (or
# `run: |-`) block of the first step with the name STEP, without the YAML
# indent. With JOB, it looks only in the job with that ID. The name must be
# the first key of the step (`- name: STEP`). The run key must be a key of the
# step itself. The block ends at the first line with less indent, and blank
# lines at its end are dropped, as YAML does. Text of later steps and jobs
# never shows. It exits 3 when there is no such step or the step has no block.
extract_run_block() {
  HARNESS_STEP=$2 HARNESS_JOB=${3-} awk '
    BEGIN { step = ENVIRON["HARNESS_STEP"]; job = ENVIRON["HARNESS_JOB"] }
    inrun {
      if ($0 ~ /^ *$/) { blank++; next }
      match($0, /^ */)
      if (indent == 0) {
        if (RLENGTH <= keyindent) exit
        indent = RLENGTH
      }
      if (RLENGTH < indent) exit
      for (; blank > 0; blank--) print ""
      print substr($0, indent + 1)
      next
    }
    /^ *(#.*)?$/ { next }
    { match($0, /^ */); ind = RLENGTH }
    ind == 0 { injobs = ($1 == "jobs:"); injob = 0 }
    ind == 2 && injobs { injob = ($1 == (job ":")) }
    instep && ind <= dash { instep = 0 }
    !instep && /^ *- +name:/ && (job == "" || injob) {
      name = $0
      sub(/^ *- +name: */, "", name)
      sub(/ *$/, "", name)
      if (name == step) {
        instep = 1
        dash = ind
        match($0, /^ *- +/)
        keyindent = RLENGTH
      }
      next
    }
    instep && ind == keyindent && /^ *run: *[|][-+]? *(#.*)?$/ { inrun = 1; found = 1 }
    END { exit found ? 0 : 3 }
  ' "$1"
}
