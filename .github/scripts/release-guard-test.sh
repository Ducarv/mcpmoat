#!/usr/bin/env bash
# Tests the step "Check that the build left the scripts unchanged" of
# release.yml. The tool-pins job in ci.yml runs it. Maintainers can also run it
# on their machine, from any directory: see CONTRIBUTING.md, Checks. It needs
# bash, awk and git. It needs no network and no token.
#
# The step is inline in the workflow, so this test takes the real code out of
# it: it reads the `run: |` body of the step and runs that body. A change to
# the workflow is a change to the code under test.
#
# Each case builds a new git repo in a temp dir. The repo has the publish
# script and one other script in .github/scripts, in one commit, and
# GITHUB_SHA is that commit. The case then changes the tree, runs the body with
# `bash -eo pipefail` (that is what `shell: bash` gives), and wants an exit code
# and a text in the output. Git ignores the host config and the host hooks.
#
# GUARD_WORKFLOW (a path) is a test hook, not a setting for normal use. It
# selects another copy of release.yml, for example a copy with one check
# removed, to see that the cases fail.
set -euo pipefail

CDPATH='' cd -- "$(dirname -- "$0")/../.."
workflow=${GUARD_WORKFLOW:-$PWD/.github/workflows/release.yml}
tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT

# Keep the host git config, home and hooks out of the scratch repos.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GITHUB_SHA
export HOME=$tmp/home GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"

step="Check that the build left the scripts unchanged"
repo=$tmp/repo
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

# Take the body of the first run block of the step and remove the YAML indent.
# The block ends at the first line with a smaller indent. That line is still
# read by the rules below, so a later step is seen. The awk stops after the
# block.
[ -r "$workflow" ] || fail "Cannot read the workflow $workflow."
awk -v step="$step" '
  inrun {
    if ($0 ~ /^ *$/) { print ""; next }
    match($0, /^ */)
    if (RLENGTH >= indent) { print substr($0, indent + 1); next }
    exit
  }
  $0 ~ /^ *- name: / {
    name = $0
    sub(/^ *- name: */, "", name)
    sub(/ *$/, "", name)
    instep = (name == step)
    next
  }
  instep && /^ *run: \|[+-]? *$/ {
    match($0, /^ */)
    indent = RLENGTH + 2
    inrun = 1
    found = 1
  }
  END { exit found ? 0 : 3 }
' "$workflow" >"$tmp/run.sh" ||
  fail "$workflow has no run block in the step '$step'."
grep -q '[^[:space:]]' "$tmp/run.sh" || fail "The run block of the step '$step' is empty."

# new_repo makes a repo with one commit and sets GITHUB_SHA for the case.
new_repo() {
  rm -rf "${repo:?}"
  mkdir -p "$repo/.github/scripts"
  git -C "$repo" init -q
  git -C "$repo" config user.email test@example.com
  git -C "$repo" config user.name test
  git -C "$repo" config commit.gpgsign false
  git -C "$repo" config core.hooksPath /dev/null
  git -C "$repo" config core.fileMode true
  printf '#!/usr/bin/env bash\necho publish\n' >"$repo/.github/scripts/verify-and-publish.sh"
  printf '#!/usr/bin/env bash\necho other\n' >"$repo/.github/scripts/other.sh"
  printf 'readme\n' >"$repo/README.md"
  chmod +x "$repo/.github/scripts/verify-and-publish.sh" "$repo/.github/scripts/other.sh"
  git -C "$repo" add -A
  git -C "$repo" commit -q -m initial
  sha=$(git -C "$repo" rev-parse HEAD)
}

# check_case NAME WANT_CODE WANT_TEXT SETUP [SHA_MODE]
# SETUP is a shell command that runs in the repo before the guard. WANT_TEXT is
# a fixed text that the output must contain, or empty for none. SHA_MODE is
# empty (GITHUB_SHA is the commit), unset or wrong.
check_case() {
  local name=$1 want_code=$2 want_text=$3 setup=$4 sha_mode=${5:-}
  local out code=0
  total=$((total + 1))
  new_repo
  (cd "$repo" && eval "$setup") >/dev/null 2>&1 || {
    record_failure "$name: the setup failed"
    return
  }
  case $sha_mode in
    unset) out=$(cd "$repo" && env -u GITHUB_SHA bash -eo pipefail "$tmp/run.sh" 2>&1) || code=$? ;;
    wrong) out=$(cd "$repo" && GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 bash -eo pipefail "$tmp/run.sh" 2>&1) || code=$? ;;
    *) out=$(cd "$repo" && GITHUB_SHA=$sha bash -eo pipefail "$tmp/run.sh" 2>&1) || code=$? ;;
  esac
  if [ "$want_code" = nonzero ]; then
    if [ "$code" -eq 0 ]; then
      record_failure "$name: want a non-zero exit code, got 0: $out"
      return
    fi
  elif [ "$code" -ne "$want_code" ]; then
    record_failure "$name: want exit code $want_code, got $code: $out"
    return
  fi
  if [ -n "$want_text" ] && ! printf '%s\n' "$out" | grep -qF -- "$want_text"; then
    record_failure "$name: the output lacks '$want_text': $out"
  fi
}

p=.github/scripts/verify-and-publish.sh
o=.github/scripts/other.sh
edit_p="echo '# edit' >>$p"
edit_o="echo '# edit' >>$o"

check_case "clean tree" 0 "" ":"
check_case "publish script edited" 1 "The build changed .github/scripts" "$edit_p"
check_case "publish script edited and staged" 1 "The build changed .github/scripts" "$edit_p; git add $p"
check_case "publish script edited, assume-unchanged" 1 "The build changed $p" "$edit_p; git update-index --assume-unchanged $p"
check_case "publish script edited, skip-worktree" 1 "Stop before the publish" "$edit_p; git update-index --skip-worktree $p"
check_case "other script edited, assume-unchanged" 1 "as hidden" "$edit_o; git update-index --assume-unchanged $o"
check_case "other script edited, skip-worktree" 1 "as hidden" "$edit_o; git update-index --skip-worktree $o"
check_case "new untracked file" 1 "added a file" "echo x >.github/scripts/new.sh"
check_case "new ignored file" 1 "added a file" "echo new.sh >>.git/info/exclude; echo x >.github/scripts/new.sh"
check_case "mode change on the other script" 1 "The build changed .github/scripts" "chmod -x $o"
check_case "file outside .github/scripts edited" 0 "" "echo more >>README.md"
check_case "the build committed a change" 1 "The build changed .github/scripts" "$edit_p; git commit -q -am build"
check_case "GITHUB_SHA unset" nonzero "" ":" unset
check_case "GITHUB_SHA wrong" nonzero "" ":" wrong

if [ "$failed" -ne 0 ]; then
  echo "release-guard-test: $failed of $total cases failed" >&2
  exit 1
fi
echo "release-guard-test: all $total cases pass"
