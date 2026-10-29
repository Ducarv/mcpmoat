#!/usr/bin/env bash
# Verifies the draft release, publishes it, and checks it after the publish.
# The release workflow (.github/workflows/release.yml) runs it, in the step
# "Verify and publish the release", after GoReleaser built the draft release
# and the workflow attested the assets.
#
# Contract:
#   - The built assets are in dist/ in the repo root (the *.tar.gz archives and
#     checksums.txt). The script runs from the repo root and writes the
#     downloaded assets to draft/ and published/ there.
#   - The gh CLI is on the PATH.
#   - These variables are set. GitHub Actions sets all of them except GH_TOKEN.
#       GH_TOKEN           token for gh (the workflow sets it to github.token)
#       GITHUB_REF_NAME    the release tag
#       GITHUB_REPOSITORY  owner/repo
#       GITHUB_SHA         the commit that this run built
#       GITHUB_REF         the tag ref, for the attestation check
#       GITHUB_SERVER_URL  for the signer identity of the attestation

set -euo pipefail

# CDPATH is empty, so that cd neither prints a path nor goes to another place.
CDPATH='' cd -- "$(dirname -- "$0")/../.."

# check_assets downloads the release assets to $1 and checks that they are
# exactly the files in dist/, no more and no less. Each command has its own
# "|| return 1", because set -e is off inside a function that runs as an if
# condition.
check_assets() {
  local want got f
  want=$(cd dist && find . -maxdepth 1 -type f \
    \( -name '*.tar.gz' -o -name checksums.txt \) | sed 's|^\./||' | sort) || return 1
  got=$(gh release view "$GITHUB_REF_NAME" -R "$GITHUB_REPOSITORY" \
    --json assets -q '.assets[].name' | sort) || return 1
  if [ "$got" != "$want" ]; then
    echo "::error::The release assets do not match dist/:"
    diff <(echo "$want") <(echo "$got") || true
    return 1
  fi
  gh release download "$GITHUB_REF_NAME" -R "$GITHUB_REPOSITORY" \
    --pattern '*.tar.gz' --pattern checksums.txt -D "$1" || return 1
  while read -r f; do
    cmp "dist/$f" "$1/$f" || return 1
  done <<<"$want"
}

# check_immutable fails unless GitHub locked the published release.
# That needs "Immutable releases" on (docs/releasing.md, One-time setup, step 5).
check_immutable() {
  local immutable
  immutable=$(gh api "repos/$GITHUB_REPOSITORY/releases/tags/$GITHUB_REF_NAME" -q .immutable) || return 1
  if [ "$immutable" != true ]; then
    echo "::error::The release is not immutable. Turn on Immutable releases (docs/releasing.md, One-time setup, step 5)."
    return 1
  fi
}

# check_tag fails unless the tag still points at the commit that this run
# built. The commits API resolves an annotated tag to its commit.
check_tag() {
  local tag_sha
  tag_sha=$(gh api "repos/$GITHUB_REPOSITORY/commits/refs/tags/$GITHUB_REF_NAME" -q .sha) || return 1
  if [ "$tag_sha" != "$GITHUB_SHA" ]; then
    echo "::error::The tag $GITHUB_REF_NAME points at $tag_sha, not at $GITHUB_SHA."
    return 1
  fi
}

check_assets draft
# --cert-identity is an exact match on the signing workflow and its ref. Some
# gh versions match --signer-workflow as a prefix only.
for f in draft/*; do
  gh attestation verify "$f" -R "$GITHUB_REPOSITORY" \
    --cert-identity "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/.github/workflows/release.yml@$GITHUB_REF" \
    --source-ref "$GITHUB_REF" \
    --source-digest "$GITHUB_SHA" \
    --deny-self-hosted-runners
done

# A moved tag would lock the published release on another commit.
check_tag

gh release edit "$GITHUB_REF_NAME" -R "$GITHUB_REPOSITORY" --draft=false

# An immutable release locks its tag and assets at publish, so these checks
# are final.
if ! check_immutable || ! check_tag || ! check_assets published; then
  echo "::error::The release is public, but it is not locked, or its tag or assets changed after the checks. Check it, and delete it if it is wrong."
  exit 1
fi
