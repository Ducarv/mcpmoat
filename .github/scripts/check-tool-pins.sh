#!/usr/bin/env bash
# Checks that the GoReleaser and govulncheck pins agree in the workflows and in
# CONTRIBUTING.md, and that each step uses its pin. The rules and their limits
# live in the Go program internal/pincheck; this script only runs it. The
# ci-scripts job in ci.yml runs it. You can also run it on your machine, from
# any directory: see CONTRIBUTING.md, Checks. check-tool-pins-test.sh tests it.
#
# Extra arguments go to the program, for example -root DIR. The program runs
# in the repository root, so give DIR as an absolute path.
set -euo pipefail

# CDPATH is empty, so that cd neither prints a path nor goes to another place.
CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

exec go run ./internal/pincheck "$@"
