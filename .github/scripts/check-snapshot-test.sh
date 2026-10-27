#!/usr/bin/env bash
# Tests check-snapshot.sh on changed copies of dist/. The release-check job in
# ci.yml runs it after the "Build a snapshot" step. Maintainers can also run
# it on their machine, from any directory, after
# "goreleaser release --snapshot --clean": see CONTRIBUTING.md, Checks.
# It needs go, jq and file, and sha256sum or shasum, because check-snapshot.sh
# needs them, and it runs go env itself.
set -euo pipefail

src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)

# fail prints an error to stderr and stops the script. In GitHub Actions it
# also makes an annotation.
fail() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error::$*" >&2
  else
    echo "$*" >&2
  fi
  exit 1
}

[ -f "$src/dist/checksums.txt" ] || fail "dist/ is missing: run goreleaser release --snapshot --clean first"

# The host of check-snapshot.sh: go env GOOS and GOARCH. The cases use it to
# name the binary that check-snapshot.sh looks up for this host.
host_os=$(go env GOOS)
host_arch=$(go env GOARCH)

# The Linux binary that the static-link case changes: not the binary of this
# host, so that no host-run check can fail first.
static_arch=amd64
if [ "$host_os" = linux ] && [ "$host_arch" = amd64 ]; then
  static_arch=arm64
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failed=0
total=0

# archive prints the name of the archive for a target in the copy of dist/.
archive() {
  find dist -maxdepth 1 -name "mcpmoat_*_$1.tar.gz" -exec basename {} \;
}

# drop_archive removes the archive for a target ($1) from the copy.
drop_archive() {
  rm "dist/$(archive "$1")"
}

# extra_archive adds an archive that .goreleaser.yaml does not build.
extra_archive() {
  cp "dist/$(archive linux_amd64)" dist/mcpmoat_0.0.0_windows_amd64.tar.gz
}

# change_archive changes the bytes of an archive and keeps its name.
change_archive() {
  printf 'x' >>"dist/$(archive linux_amd64)"
}

# drop_checksum_line removes the first line of checksums.txt.
drop_checksum_line() {
  sed '1d' dist/checksums.txt >dist/checksums.new && mv dist/checksums.new dist/checksums.txt
}

# drop_host_binary removes the Binary entry of this host from artifacts.json.
# It uses the same host as check-snapshot.sh.
drop_host_binary() {
  jq --arg os "$host_os" --arg arch "$host_arch" \
    'map(select(.type == "Binary" and .goos == $os and .goarch == $arch | not))' \
    dist/artifacts.json >dist/artifacts.new && mv dist/artifacts.new dist/artifacts.json
}

# binary_path prints the path of the binary for an OS ($1) and an arch ($2)
# in the copy, from dist/artifacts.json.
binary_path() {
  jq -r --arg os "$1" --arg arch "$2" \
    '.[] | select(.type == "Binary" and .goos == $os and .goarch == $arch) | .path' \
    dist/artifacts.json
}

# dynamic_linux_binary replaces a Linux binary that is not the host binary
# with a text file, which file does not report as statically linked.
dynamic_linux_binary() {
  printf 'not a static binary\n' >"$(binary_path linux "$static_arch")"
}

# delete_host_binary deletes the binary file of this host. Its entry stays in
# artifacts.json.
delete_host_binary() {
  rm "$(binary_path "$host_os" "$host_arch")"
}

# change_version sets another version in metadata.json, so that the binary
# does not print it.
change_version() {
  jq '.version = "9.9.9"' dist/metadata.json >dist/metadata.new && mv dist/metadata.new dist/metadata.json
}

# check_case copies check-snapshot.sh and dist/ to a new tree, changes the
# copy with the command after the message, and runs the script in the tree.
# check-snapshot.sh goes to the directory of its own path in the tree, because
# it uses "cd ../.." from there. The case passes when the exit code is the
# wanted one. A case that wants exit 1 also needs the message to contain the
# text of $3, so that it fails for the reason in its name.
check_case() {
  local name=$1 want=$2 msg=$3 got=0 out
  shift 3
  total=$((total + 1))
  rm -rf "${tmp:?}/w"
  mkdir -p "$tmp/w/.github/scripts"
  cp "$src/.github/scripts/check-snapshot.sh" "$tmp/w/.github/scripts/"
  cp -R "$src/dist" "$tmp/w/dist"
  if ! (cd "$tmp/w" && "$@"); then
    echo "FAIL: $name: the change to the copy failed" >&2
    failed=$((failed + 1))
    return
  fi
  out=$("$tmp/w/.github/scripts/check-snapshot.sh" 2>&1) || got=$?
  if [ "$got" != "$want" ]; then
    echo "FAIL: $name: exit $got, want $want: $out" >&2
    failed=$((failed + 1))
  elif [ "$want" = 1 ] && [[ $out != *"$msg"* ]]; then
    echo "FAIL: $name: the message lacks '$msg': $out" >&2
    failed=$((failed + 1))
  fi
}

# The real snapshot must pass.
check_case "real snapshot" 0 "" true

# The archives.
check_case "extra archive" 1 "expected only the archives for" extra_archive
check_case "missing archive" 1 "expected 1 archive for linux_arm64 in dist/, found 0" drop_archive linux_arm64
check_case "changed archive" 1 "dist/checksums.txt does not match the archives" change_archive

# checksums.txt.
check_case "missing line in checksums.txt" 1 "lines in dist/checksums.txt, found $(($(wc -l <"$src/dist/checksums.txt") - 1))" drop_checksum_line

# The binaries.
check_case "Linux binary is not statically linked" 1 "is not statically linked" dynamic_linux_binary

# artifacts.json and metadata.json. On every host, the first lookup that fails
# is the one for the host binary. check-snapshot.sh looks up linux amd64, then
# linux arm64, then the host. On a linux/amd64 host the first lookup is the host
# binary. On a linux/arm64 host the second is. On macOS the third is. So the
# first message names the host in all cases.
check_case "missing Binary entry for this host" 1 "no $host_os $host_arch binary found in dist/artifacts.json (got '')" drop_host_binary
check_case "Binary file of this host is missing on disk" 1 "no $host_os $host_arch binary found in dist/artifacts.json (got 'dist/" delete_host_binary
check_case "missing artifacts.json" 1 "dist/artifacts.json is missing" rm dist/artifacts.json
check_case "missing checksums.txt" 1 "dist/checksums.txt is missing" rm dist/checksums.txt
check_case "missing metadata.json" 1 "dist/metadata.json is missing" rm dist/metadata.json
check_case "version in metadata.json differs from the binary" 1 "version output does not start with" change_version

if [ "$failed" -ne 0 ]; then
  echo "check-snapshot-test: $failed of $total cases failed" >&2
  exit 1
fi
echo "check-snapshot-test: all $total cases pass"
