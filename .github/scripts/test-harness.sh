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
#   CDPATH='' cd -- "$(dirname -- "$0")/../.."  # work in the repository root
#   src=$PWD
#   tmp=$(mktemp -d)
#   trap 'rm -rf "${tmp:?}"' EXIT
#
#   # snapshot_case NAME WANT_CODE WANT_TEXT SETUP [ARGS...]
#   snapshot_case() {
#     local name=$1 want_code=$2 want_text=$3
#     shift 3
#     rm -rf "${tmp:?}/w" && cp -R "$src/dist" "$tmp/w"  # a new dir per case
#     run_setup "$name" in_dir "$tmp/w" "$@"  # a failure stops and names the case
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
# GitHub Actions (GITHUB_ACTIONS is exactly "true", as GitHub sets it and as
# internal/pincheck reads it) it prints an ::error:: annotation, else a FAIL:
# line. Both go to stderr. MSG often holds the output of a case, so a line
# break in it must not start a line that a reader or the runner takes for a
# workflow command, a FAIL: line or a footer. An ASCII control character
# other than tab, LF and CR (0x01 to 0x1f, and DEL 0x7f) shows as \xNN, so
# that an ESC cannot send a terminal escape sequence. A tab stays a tab.
# shortcut: only ASCII controls, not C1, bidi or zero-width characters (bash
# 3.2 cannot match them reliably); move to Go if the harness needs them.
record_failure() {
  # The quotes matter: bash 5.3 doubles a 0x01 or 0x7f in local msg=$*.
  local msg="$*" i hex c
  for i in {1..8} 11 12 {14..31} 127; do
    printf -v hex '%02x' "$i"
    printf -v c '%b' "\\x$hex"
    msg=${msg//"$c"/"\\x$hex"}
  done
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    # Encode MSG as workflow command data: it stays one annotation. The \xNN
    # escapes above hold no %, so the % encoding still covers every %.
    msg=${msg//'%'/%25}
    msg=${msg//$'\r'/%0D}
    msg=${msg//$'\n'/%0A}
    echo "::error::$msg" >&2
  else
    # Show a CR as \r and start each later line with "  > ".
    msg=${msg//$'\r'/'\r'}
    msg=${msg//$'\n'/$'\n'"  > "}
    echo "FAIL: $msg" >&2
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
# the whole command, so that a wrapper such as in_dir does not hide the real
# setup. CMD runs where set -e has no effect, so join the commands of a setup
# function with && or end each one with || return 1.
run_setup() {
  local name=$1 out cmd
  shift
  cmd=$*
  # A newline or control character in an argument must not start a new line.
  out=$("$@" 2>&1 </dev/null) || fail "$name: the setup failed ($(harness_clip "${cmd//[[:cntrl:]]/ }")): $(harness_clip "$out")"
}

# in_dir DIR CMD [ARGS...]: runs CMD with ARGS in the directory DIR. The cd
# changes the current shell, so pass in_dir to run_setup or check_case, which
# run it in a subshell: run_setup "$name" in_dir "$tmp/w" "$@".
in_dir() {
  CDPATH='' cd -- "$1" && shift && "$@"
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
# NAME says what the check wants, for example "the job has no checkout step".
# It runs CMD in a subshell, with stdin from /dev/null, and records the
# failure "NAME: the check failed", with the output of CMD, when CMD fails. As
# in run_setup, set -e has no effect in CMD.
check_cmd() {
  local name=$1 out
  shift
  harness_total=$((harness_total + 1))
  out=$("$@" 2>&1 </dev/null) || record_failure "$name: the check failed${out:+: $(harness_clip "$out")}"
}

# harness_footer NAME: the last line of a test script. It prints
# "NAME: all M cases pass". It prints "NAME: N of M cases failed", or
# "NAME: no case ran" when M is 0, on stderr and then exits 1.
harness_footer() {
  if [ "$harness_failed" -ne 0 ]; then
    echo "$1: $harness_failed of $harness_total cases failed" >&2
    exit 1
  fi
  if [ "$harness_total" -eq 0 ]; then
    echo "$1: no case ran" >&2
    exit 1
  fi
  echo "$1: all $harness_total cases pass"
}

# extract_run_block FILE STEP [JOB]: prints the body of the `run: |` (or
# `run: |-`) block of the first step with the name STEP, without the YAML
# indent. With JOB, it looks only in the job with that ID. The name must be
# the first key of the step (`- name: STEP`). The run key must be a key of the
# step itself. The block ends at the first line with less indent. Blank lines
# at its end are always dropped, and the last line always ends with a newline,
# whatever the chomping indicator (|, |- or |+) says. A line of only spaces and
# tabs counts as blank. Text of later steps and jobs never shows.
#
# It reads lines, not YAML. The body of a block scalar (a key that ends in `|`
# or `>`), such as a heredoc, is text and never starts a step. Other forms that
# hold text (a list item `- |`, a value with an anchor or a tag, a quoted value
# over several lines) are not known to it. A decoy in such a form needs the
# name of the real step, so a second `- name: STEP` line in the same job makes
# it fail closed.
#
# It exits 3 when there is no such step, when the first step with the name has
# no block, when the block has no line, or when the job has another step line
# with the same name.
extract_run_block() {
  HARNESS_STEP=$2 HARNESS_JOB=${3-} awk '
    # skip_block starts to skip the body of a block scalar when the line ends in
    # | or >: the lines of the body are indented more than the key.
    function skip_block() {
      if ($0 ~ /: *[|>][-+0-9]* *(#.*)?$/) {
        match($0, /^ *(- +)*/)
        skipbody = 1
        skipind = RLENGTH # the column of the key
      }
    }
    BEGIN { step = ENVIRON["HARNESS_STEP"]; job = ENVIRON["HARNESS_JOB"] }
    inrun {
      if ($0 ~ /^[[:space:]]*$/) { blank++; next }
      match($0, /^ */)
      if (indent == 0) {
        if (RLENGTH <= keyindent) inrun = 0
        else indent = RLENGTH
      }
      if (inrun && RLENGTH < indent) inrun = 0
      if (inrun) {
        for (; blank > 0; blank--) print ""
        print substr($0, indent + 1)
        printed = 1
        next
      }
      runended = 1 # the run block ended; this line is read as usual
    }
    /^[[:space:]]*(#.*)?$/ { next }
    # The body of a block scalar of another key is text, not YAML: skip its
    # lines, so a heredoc that holds "- name:" cannot look like a step.
    skipbody {
      match($0, /^ */)
      if (RLENGTH > skipind) next
      skipbody = 0
    }
    { match($0, /^ */); ind = RLENGTH }
    ind == 0 { injobs = ($1 == "jobs:"); injob = 0; curjob = "" }
    ind == 2 && injobs { curjob = $1; injob = ($1 == (job ":")) }
    instep && ind <= dash { instep = 0 } # the end of the first step with the name
    !instep && /^ *- +name:/ && (job == "" || injob) {
      name = $0
      sub(/^ *- +name: */, "", name)
      sub(/ *$/, "", name)
      if (name == step && seen && curjob == foundjob) { dup = 1; exit }
      if (name == step && !seen) {
        seen = 1
        foundjob = curjob
        instep = 1
        dash = ind
        match($0, /^ *- +/)
        keyindent = RLENGTH
      }
      skip_block() # a name that is a block scalar has a body that is text too
      next
    }
    instep && !runended && ind == keyindent && /^ *run: *[|][-+]? *(#.*)?$/ { inrun = 1; found = 1 }
    !inrun { skip_block() }
    END { exit (!dup && found && printed) ? 0 : 3 }
  ' "$1"
}
