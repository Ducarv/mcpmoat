#!/usr/bin/env bash
# Runs the TestE2E tests, the network tests of cmd/mcpmoat/e2e_network_test.go
# included, in a Linux network namespace that has only loopback (NFR-01). The
# offline job in ci.yml runs it. It takes no arguments and runs on Linux only:
# see CONTRIBUTING.md, Checks.
#
# The tests run as the calling user, not as root, with GOPROXY=off. So the
# module cache must be warm: this script builds everything first, while the
# network is still there.
set -euo pipefail

cd "$(dirname "$0")/../.."

# The tests that must pass. A test that skips or does not run fails the script.
required=(TestE2ENoNetworkWithoutLLM TestE2ELLMMissingKey TestE2ELLMFindings TestE2ELLMProviderFailure)

# fail prints an error to stderr and stops the script with exit code 1.
fail() {
  echo "run-offline: $*" >&2
  exit 1
}

# setup_error is fail for a host that cannot run the script: exit code 2.
setup_error() {
  echo "run-offline: $*" >&2
  exit 2
}

if [ "$(uname -s)" != Linux ]; then
  setup_error "needs Linux (a network namespace), this system is $(uname -s)"
fi
for tool in go sudo unshare setpriv ip getent timeout; do
  command -v "$tool" >/dev/null || setup_error "needs $tool, which is not on PATH"
done

# The E2E tests refuse a temp dir below a directory that its group or others
# can write, such as /tmp (see requirePrivateChain in cmd/mcpmoat/e2e_test.go).
base=${TMPDIR:-/tmp}
p=$(cd "$base" && pwd -P)
while :; do
  mode=$(stat -c %a "$p")
  if ((8#$mode & 8#022)); then
    setup_error "$p is writable by its group or by others: set TMPDIR to a private directory"
  fi
  [ "$p" = / ] && break
  p=$(dirname "$p")
done
work=$(mktemp -d "$base/mcpmoat-offline.XXXXXX") # mode 0700
trap 'rm -rf "$work"' EXIT
log=$work/go-test.log

echo "run-offline: build the tests, the binary and the fixture servers"
go test -count=1 -run '^$' ./cmd/mcpmoat/
go build -o /dev/null ./cmd/mcpmoat
go build ./testdata/servers/...

# Take the user and the Go paths now: sudo resets the environment, and
# SUDO_UID is not always set. GOROOT is the toolchain that ran the builds
# above, also when go.mod made the go command switch to another one.
uid=$(id -u)
gid=$(id -g)
home=${HOME:?HOME is not set}
goroot=$(go env GOROOT)
gocache=$(go env GOCACHE)
gomodcache=$(go env GOMODCACHE)

# inner runs as root in the new network namespace. It gets its values as
# arguments, not as environment variables.
# shellcheck disable=SC2016 # the variables expand in the inner shell
inner='
set -euo pipefail
export LC_ALL=C
root=$1 uid=$2 gid=$3 home=$4 goroot=$5 gocache=$6 gomodcache=$7 work=$8
cd "$root"

ip link set lo up

# The namespace must be closed, or this job proves nothing.
if getent ahosts github.com >/dev/null 2>&1; then
  echo "run-offline: a DNS lookup works in the namespace, so it is not closed" >&2
  exit 1
fi
if timeout 3 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null; then
  echo "run-offline: a TCP connection to 1.1.1.1:443 works in the namespace, so it is not closed" >&2
  exit 1
fi
# Nothing listens in the new namespace. With loopback up, a connection is
# refused; without it, the network is unreachable.
if lo_err=$(timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/9" 2>&1); then
  echo "run-offline: something listens on 127.0.0.1:9 in the new namespace" >&2
  exit 1
fi
case $lo_err in
  *"Connection refused"*) ;;
  *)
    echo "run-offline: loopback does not work in the namespace: $lo_err" >&2
    exit 1
    ;;
esac
echo "run-offline: the namespace has loopback only; run the E2E tests as uid $uid"

# The job proves that no IP traffic leaves the namespace. Unix sockets on the
# filesystem are out of its scope, but --clear-groups drops the supplementary
# groups of the user (on GitHub runners: docker, which can open the Docker
# socket). The user keeps its own uid and gid, so it can still read its Go
# caches and the private TMPDIR, which it owns.
exec setpriv --reuid="$uid" --regid="$gid" --clear-groups -- \
  env -i \
  HOME="$home" \
  PATH="$goroot/bin:/usr/bin:/bin" \
  GOCACHE="$gocache" \
  GOMODCACHE="$gomodcache" \
  GOPROXY=off \
  GOTOOLCHAIN=local \
  GOFLAGS=-mod=readonly \
  TMPDIR="$work" \
  CI=true \
  go test -count=1 -v -run "^TestE2E" ./cmd/mcpmoat/
'

echo "run-offline: enter the network namespace (sudo unshare --net)"
if ! sudo unshare --net -- bash -c "$inner" bash \
  "$PWD" "$uid" "$gid" "$home" "$goroot" "$gocache" "$gomodcache" "$work" 2>&1 | tee "$log"; then
  fail "the tests or the namespace checks failed (see the output above)"
fi

for t in "${required[@]}"; do
  grep -qE "^--- PASS: $t \(" "$log" || fail "$t did not pass: it failed, skipped or did not run"
done
echo "run-offline: all required tests passed with loopback only"
