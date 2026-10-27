#!/usr/bin/env bash
# Tests verify-and-publish.sh with a fake gh. The release-check job in ci.yml
# runs it. Maintainers can also run it on their machine, from any directory:
# see CONTRIBUTING.md, Checks. It needs no network and no token.
#
# Each case builds a temp tree with a copy of the script, a small dist/ and a
# fake gh at the front of PATH. The fake keeps a draft or published release in
# files, answers every gh call that the script makes, and exits 99 on any other
# call. A case changes the state of the fake, runs the script, and wants an
# exit code, a release state (draft or published) and a text in the output.
#
# VERIFY_SCRIPT (an absolute path) selects another copy of the script to test.
set -euo pipefail

CDPATH='' cd -- "$(dirname -- "$0")/../.."
src=$PWD
script=${VERIFY_SCRIPT:-$src/.github/scripts/verify-and-publish.sh}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

S=$tmp/state # the state of the fake gh
sha=0123456789abcdef0123456789abcdef01234567
other_sha=fedcba9876543210fedcba9876543210fedcba98
failed=0
total=0

# fail reports a failed case. It uses the GitHub error syntax in Actions.
fail() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error::$*" >&2
  else
    echo "FAIL: $*" >&2
  fi
  failed=$((failed + 1))
}

# The fake gh. The quoted delimiter keeps every $ for the fake to expand.
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'FAKE'
#!/usr/bin/env bash
# Fake gh for verify-and-publish-test.sh. State is in files in $FAKE_GH_STATE.
set -euo pipefail
S=${FAKE_GH_STATE:?}
die() {
  echo "fake gh: $*" >&2
  exit 99
}
[ "${GH_TOKEN:-}" = fake ] || die "GH_TOKEN is not 'fake'"
args="$*"
echo "$args" >>"$S/calls"
tag=$GITHUB_REF_NAME
repo=$GITHUB_REPOSITORY
state=$(cat "$S/state")

if [ "$args" = "release view $tag -R $repo --json assets -q .assets[].name" ]; then
  ls "$S/assets"
elif [[ $args == "release download $tag -R $repo --pattern *.tar.gz --pattern checksums.txt -D "* ]] && [ $# -eq 11 ]; then
  dir=${!#}
  mkdir -p "$dir"
  for f in "$S"/assets/*; do
    [ -e "$f" ] || continue
    case ${f##*/} in
    *.tar.gz | checksums.txt) cp "$f" "$dir/" ;;
    esac
  done
elif [ "$args" = "api repos/$repo/releases/tags/$tag -q .immutable" ]; then
  # A draft has no tag page: the real API answers 404.
  [ "$state" = published ] || {
    echo "fake gh: HTTP 404, the release is a draft" >&2
    exit 1
  }
  cat "$S/immutable"
elif [ "$args" = "api repos/$repo/commits/refs/tags/$tag -q .sha" ]; then
  cat "$S/tag_sha"
elif [[ $args == "attestation verify draft/"* ]]; then
  file=$3
  want="attestation verify $file -R $repo"
  want="$want --cert-identity $GITHUB_SERVER_URL/$repo/.github/workflows/release.yml@$GITHUB_REF"
  want="$want --source-ref $GITHUB_REF --source-digest $GITHUB_SHA --deny-self-hosted-runners"
  [ "$args" = "$want" ] || die "attestation verify with unexpected arguments: $args"
  [ -f "$file" ] || die "attestation verify on a missing file: $file"
  if [ "${file##*/}" = "$(cat "$S/attest_fail")" ]; then
    echo "fake gh: attestation verify failed for $file" >&2
    exit 1
  fi
elif [ "$args" = "release edit $tag -R $repo --draft=false" ]; then
  [ "$state" = draft ] || die "release edit on a release that is not a draft"
  echo published >"$S/state"
  first=$(cd "$S/assets" && ls -- *.tar.gz | head -n 1)
  case $(cat "$S/after") in
  swap_asset) echo swapped >"$S/assets/$first" ;;
  add_asset) echo extra >"$S/assets/extra.zip" ;;
  move_tag) echo fedcba9876543210fedcba9876543210fedcba98 >"$S/tag_sha" ;;
  esac
else
  die "unknown call: $args"
fi
FAKE
chmod +x "$tmp/bin/gh"

# new_tree builds the temp tree for one case: the script, a dist/ with two
# archives, checksums.txt and files that the script must ignore, and a fake
# release that holds the same assets as a draft.
new_tree() {
  rm -rf "${tmp:?}/w" "${tmp:?}/state"
  mkdir -p "$tmp/w/.github/scripts" "$tmp/w/dist/sub" "$S/assets" "$tmp/home"
  cp "$script" "$tmp/w/.github/scripts/verify-and-publish.sh"
  printf 'linux archive\n' >"$tmp/w/dist/mcpmoat_9.9.9_linux_amd64.tar.gz"
  printf 'darwin archive\n' >"$tmp/w/dist/mcpmoat_9.9.9_darwin_arm64.tar.gz"
  printf 'abc  mcpmoat_9.9.9_linux_amd64.tar.gz\n' >"$tmp/w/dist/checksums.txt"
  printf '{}\n' >"$tmp/w/dist/artifacts.json"
  printf 'nested\n' >"$tmp/w/dist/sub/nested.tar.gz"
  cp "$tmp"/w/dist/*.tar.gz "$tmp/w/dist/checksums.txt" "$S/assets/"
  echo draft >"$S/state"
  echo "$sha" >"$S/tag_sha"
  echo true >"$S/immutable"
  : >"$S/attest_fail"
  : >"$S/after"
}

# Changes to the fake release. A case runs one of them.
good() { :; }
extra_on_draft() { echo extra >"$S/assets/extra.zip"; }
missing_on_draft() { rm "$S/assets/checksums.txt"; }
changed_draft() { echo changed >"$S/assets/mcpmoat_9.9.9_darwin_arm64.tar.gz"; }
tag_moved() { echo "$other_sha" >"$S/tag_sha"; }
tag_moves_after() { echo move_tag >"$S/after"; }
asset_swapped_after() { echo swap_asset >"$S/after"; }
asset_added_after() { echo add_asset >"$S/after"; }
not_immutable() { echo false >"$S/immutable"; }
attest_fails_last() { echo mcpmoat_9.9.9_linux_amd64.tar.gz >"$S/attest_fail"; }

# check_case builds a tree, runs the change $5 (with its arguments), runs the
# script and checks three things: the exit code, the state of the release
# (draft or published) and that the output contains the text $4. The state
# shows whether the script stopped before or after the publish.
check_case() {
  local name=$1 want=$2 want_state=$3 msg=$4 got=0 out state
  shift 4
  total=$((total + 1))
  new_tree
  "$@"
  out=$(env -i PATH="$tmp/bin:$PATH" HOME="$tmp/home" FAKE_GH_STATE="$S" \
    GH_TOKEN=fake GITHUB_REF_NAME=v9.9.9 GITHUB_REPOSITORY=owner/repo \
    GITHUB_SHA="$sha" GITHUB_REF=refs/tags/v9.9.9 GITHUB_SERVER_URL=https://github.com \
    "$tmp/w/.github/scripts/verify-and-publish.sh" 2>&1) || got=$?
  state=$(cat "$S/state")
  if [ "$got" != "$want" ]; then
    fail "$name: exit $got, want $want: $out"
  elif [ "$state" != "$want_state" ]; then
    fail "$name: the release is $state, want $want_state: $out"
  elif [[ $out != *"$msg"* ]]; then
    fail "$name: the output lacks '$msg': $out"
  fi
}

check_case "good release" 0 published "" good

check_case "extra asset on the draft" 1 draft "::error::The release assets do not match dist/" extra_on_draft
check_case "missing asset on the draft" 1 draft "::error::The release assets do not match dist/" missing_on_draft
check_case "draft differs from dist/" 1 draft "differ" changed_draft
check_case "tag moved before the publish" 1 draft "::error::The tag v9.9.9 points at $other_sha" tag_moved
check_case "attestation verify fails" 1 draft "attestation verify failed" attest_fails_last

check_case "tag moved after the publish" 1 published "::error::The tag v9.9.9 points at $other_sha" tag_moves_after
check_case "asset swapped after the publish" 1 published "differ" asset_swapped_after
check_case "asset added after the publish" 1 published "::error::The release assets do not match dist/" asset_added_after
check_case "release is not immutable" 1 published "::error::The release is not immutable" not_immutable
check_case "after-publish failure says to check the release" 1 published "::error::The release is public, but it is not locked" tag_moves_after

if [ "$failed" -ne 0 ]; then
  echo "verify-and-publish-test: $failed of $total cases failed" >&2
  exit 1
fi
echo "verify-and-publish-test: all $total cases pass"
