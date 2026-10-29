#!/usr/bin/env bash
# Tests the step "Check that the build left the scripts unchanged" of
# release.yml. The ci-scripts job in ci.yml runs it. Maintainers can also run it
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
# shellcheck source-path=SCRIPTDIR source=test-harness.sh
. "$(dirname -- "$0")/test-harness.sh"
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

[ -r "$workflow" ] || fail "Cannot read the workflow $workflow."
extract_run_block "$workflow" "$step" release >"$tmp/run.sh" ||
  fail "$workflow has no run block in the step '$step'."

# The run body is inline shell in the workflow, and `shellcheck
# .github/scripts/*.sh` does not see it.
if command -v shellcheck >/dev/null 2>&1; then
  check_cmd "shellcheck passes on the run block" shellcheck -s bash "$tmp/run.sh"
fi

# A step starts at a line with six spaces and a dash. An unnamed step has the
# name "". step_text prints the lines of the guard step, up to the next step.
step_text() {
  awk -v step="$step" '
    /^      - / {
      name = ""
      if ($0 ~ /^      - name: /) {
        name = $0
        sub(/^ *- name: */, "", name)
        sub(/ *$/, "", name)
      }
      on = (name == step)
    }
    on { print }
  ' "$workflow"
}

# next_step_name prints the name of the step after the guard step. It prints an
# empty line when that step has no name.
next_step_name() {
  awk -v step="$step" '
    /^      - / {
      name = ""
      if ($0 ~ /^      - name: /) {
        name = $0
        sub(/^ *- name: */, "", name)
        sub(/ *$/, "", name)
      }
      if (seen) { print name; exit }
      seen = (name == step)
    }
  ' "$workflow"
}

# The body can pass while a step key turns the step off, changes what it
# compares, a different shell runs it, or it runs after the publish. Check
# these keys by text. Each check is a function that must succeed.
only_known_keys() { ! step_text | grep -E "^ {8}[\"']?[A-Za-z_-]+[\"']? *:" | grep -Evq '^ {8}(shell|run):'; }
uses_bash() { step_text | grep -Eq '^ {8}shell: bash *$'; }
runs_before_publish() { [ "$(next_step_name)" = "Verify and publish the release" ]; }
check_cmd "the guard step has no key other than name, shell and run (for example if:, env: or working-directory:)" only_known_keys
check_cmd "the guard step has 'shell: bash'" uses_bash
check_cmd "the step after the guard step is 'Verify and publish the release'" runs_before_publish

# new_repo makes a repo with one commit and sets the global sha for the case.
# guard_case runs it in the current shell, where set -e has no effect, so the
# commands are joined with &&.
new_repo() {
  rm -rf "${repo:?}" &&
    mkdir -p "$repo/.github/scripts" &&
    git -C "$repo" init -q &&
    git -C "$repo" config user.email test@example.com &&
    git -C "$repo" config user.name test &&
    git -C "$repo" config commit.gpgsign false &&
    git -C "$repo" config core.hooksPath /dev/null &&
    git -C "$repo" config core.fileMode true &&
    printf '#!/usr/bin/env bash\necho publish\n' >"$repo/.github/scripts/verify-and-publish.sh" &&
    printf '#!/usr/bin/env bash\necho other\n' >"$repo/.github/scripts/other.sh" &&
    printf 'readme\n' >"$repo/README.md" &&
    chmod +x "$repo/.github/scripts/verify-and-publish.sh" "$repo/.github/scripts/other.sh" &&
    git -C "$repo" add -A &&
    git -C "$repo" commit -q -m initial &&
    sha=$(git -C "$repo" rev-parse HEAD)
}

# run_guard SHA_MODE: runs the run block in the repo. SHA_MODE good sets
# GITHUB_SHA to the commit, unset leaves it out and wrong sets a wrong one.
# check_case runs it in a subshell, so the cd does not leak.
run_guard() {
  cd "$repo" || return
  case $1 in
    good) GITHUB_SHA=$sha bash -eo pipefail "$tmp/run.sh" ;;
    unset) env -u GITHUB_SHA bash -eo pipefail "$tmp/run.sh" ;;
    wrong) GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 bash -eo pipefail "$tmp/run.sh" ;;
    *) echo "run_guard: unknown SHA_MODE '$1'" >&2 && return 2 ;;
  esac
}

# guard_case NAME WANT_CODE WANT_TEXT SHA_MODE SETUP [ARGS...]
# SETUP runs with ARGS in a new repo before the guard. WANT_CODE and WANT_TEXT
# are as in check_case.
guard_case() {
  local name=$1 want_code=$2 want_text=$3 sha_mode=$4
  shift 4
  new_repo || fail "$name: new_repo failed"
  run_setup "$name" in_dir "$repo" "$@"
  check_case "$name" "$want_code" "$want_text" run_guard "$sha_mode"
}

p=.github/scripts/verify-and-publish.sh
o=.github/scripts/other.sh

# edit FILE [CMD [ARGS...]] adds a line to FILE, then runs CMD.
edit() {
  echo '# edit' >>"$1" || return
  shift
  [ "$#" -eq 0 ] || "$@"
}

# add_new adds an untracked file to .github/scripts.
add_new() { echo x >.github/scripts/new.sh; }

# ignore_new adds a file to .github/scripts that .git/info/exclude ignores.
ignore_new() { echo new.sh >>.git/info/exclude && add_new; }

# replace_commit edits the publish script, makes a commit object with the
# edited tree and writes a replace ref from the tagged commit to it. Then git
# shows the edited script as the content of the tagged commit.
replace_commit() {
  edit "$p" git add "$p" &&
    git replace "$sha" "$(git commit-tree "$(git write-tree)" -m evil)"
}

# hide_by_filter edits the publish script and adds a clean filter that gives
# git the tagged content, so git diff and git hash-object see no change.
hide_by_filter() {
  edit "$p" &&
    git config filter.fake.clean "cat >/dev/null; git cat-file blob $sha:$p" &&
    echo "$p filter=fake" >>.git/info/attributes
}

guard_case "clean tree" 0 "" good true
guard_case "publish script edited" 1 "The build changed .github/scripts" good edit "$p"
guard_case "publish script edited and staged" 1 "The build changed .github/scripts" good edit "$p" git add "$p"
guard_case "publish script edited, assume-unchanged" 1 "The build changed $p" good edit "$p" git update-index --assume-unchanged "$p"
guard_case "publish script edited, skip-worktree" 1 "The build changed $p" good edit "$p" git update-index --skip-worktree "$p"
guard_case "other script edited, assume-unchanged" 1 "as hidden" good edit "$o" git update-index --assume-unchanged "$o"
guard_case "other script edited, skip-worktree" 1 "as hidden" good edit "$o" git update-index --skip-worktree "$o"
guard_case "new untracked file" 1 "added a file" good add_new
guard_case "new ignored file" 1 "added a file" good ignore_new
guard_case "mode change on the other script" 1 "The build changed .github/scripts" good chmod -x "$o"
guard_case "file outside .github/scripts edited" 0 "" good edit README.md
guard_case "the build committed a change" 1 "The build changed .github/scripts" good edit "$p" git commit -q -am build
guard_case "publish script edited, replace ref" 1 "The build changed .github/scripts" good replace_commit
guard_case "publish script edited, clean filter" 1 "The build changed $p" good hide_by_filter
guard_case "GITHUB_SHA unset" nonzero "GITHUB_SHA: unbound variable" unset true
guard_case "GITHUB_SHA wrong" nonzero "The build changed .github/scripts" wrong true

harness_footer release-guard-test
