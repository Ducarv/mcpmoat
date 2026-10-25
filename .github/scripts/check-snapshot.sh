#!/usr/bin/env bash
# Checks the archives that "goreleaser release --snapshot --clean" writes to
# dist/. The release-check job in ci.yml runs it. It also runs on macOS: see
# CONTRIBUTING.md, Checks.
set -euo pipefail

cd "$(dirname "$0")/../.."

# binary prints the path of the binary for an OS and an arch, from
# dist/artifacts.json.
binary() {
  local path
  path=$(jq -r --arg os "$1" --arg arch "$2" \
    '.[] | select(.type == "Binary" and .goos == $os and .goarch == $arch) | .path' \
    dist/artifacts.json)
  if [ -z "$path" ] || [ ! -f "$path" ]; then
    echo "no $1 $2 binary found in dist/artifacts.json (got '$path')" >&2
    return 1
  fi
  echo "$path"
}

# The goos x goarch list in .goreleaser.yaml: one archive each, no others.
targets=(darwin_amd64 darwin_arm64 linux_amd64 linux_arm64)
for t in "${targets[@]}"; do
  n=$(find dist -maxdepth 1 -name "mcpmoat_*_$t.tar.gz" | wc -l | tr -d ' ')
  if [ "$n" -ne 1 ]; then
    echo "expected 1 archive for $t in dist/, found $n:"
    ls -l dist
    exit 1
  fi
done
want_count=${#targets[@]}
count=$(find dist -maxdepth 1 -name '*.tar.gz' | wc -l | tr -d ' ')
if [ "$count" -ne "$want_count" ]; then
  echo "expected only the archives for ${targets[*]} in dist/, found $count:"
  ls -l dist
  exit 1
fi

# checksums.txt must have one line for each archive, and each line must match.
lines=$(wc -l <dist/checksums.txt | tr -d ' ')
if [ "$lines" -ne "$want_count" ]; then
  echo "expected $want_count lines in dist/checksums.txt, found $lines"
  exit 1
fi
if command -v sha256sum >/dev/null; then
  sha256=(sha256sum)
else
  sha256=(shasum -a 256) # macOS
fi
if ! (cd dist && "${sha256[@]}" -c checksums.txt); then
  echo "dist/checksums.txt does not match the archives"
  exit 1
fi

# The Linux binaries must be static. file reads them on any host.
for arch in amd64 arm64; do
  bin=$(binary linux "$arch")
  info=$(file "$bin")
  echo "$info"
  case "$info" in
    *"statically linked"*) ;;
    *)
      echo "$bin is not statically linked"
      exit 1
      ;;
  esac
done

# Run the binary for this host and check the version that the ldflags set.
bin=$(binary "$(go env GOOS)" "$(go env GOARCH)")
want_prefix="mcpmoat v$(jq -r .version dist/metadata.json) "
out=$("$bin" version)
echo "$out"
case "$out" in
  "$want_prefix"*) ;;
  *)
    echo "version output does not start with '$want_prefix'"
    exit 1
    ;;
esac
