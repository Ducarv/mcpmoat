#!/usr/bin/env bash
# Checks that the tool version pins agree. The release-check job in ci.yml
# runs it. To run it on your machine, run it from any directory. See
# CONTRIBUTING.md, Checks.
set -euo pipefail

cd "$(dirname "$0")/../.."

ci=.github/workflows/ci.yml
files=(ci release govulncheck)
ver_re='v[0-9][0-9A-Za-z.+-]*[0-9A-Za-z]'

# fail prints an error for GitHub Actions and stops the script.
fail() {
  echo "::error::$*"
  exit 1
}

# pins prints the version of every "  NAME: vX.Y.Z" line of a file, once each.
pins() {
  sed -nE 's/^ *'"$1"': *"?('"$ver_re"')"? *(#.*)?$/\1/p' "$2" | sort -u
}

# --- GoReleaser: ci.yml is the reference. release.yml and CONTRIBUTING.md
# must name the same version.
want=$(pins GORELEASER_VERSION "$ci")
rel=$(pins GORELEASER_VERSION .github/workflows/release.yml)
# CONTRIBUTING.md names the version only in goreleaser/v<major>@<version>.
doc=$(grep -oE 'goreleaser(/v[0-9]+)?@'"$ver_re" CONTRIBUTING.md | sed 's/.*@//' | sort -u || true)
if [ -z "$want" ] || [ "$rel" != "$want" ] || [ "$doc" != "$want" ]; then
  fail "The GoReleaser pins differ. ci.yml: $want. release.yml: $rel. CONTRIBUTING.md: $doc."
fi

# --- govulncheck: ci.yml is the reference. Each file must have one pin with
# the same version, and must run govulncheck only through that pin. This is a
# text check, not a YAML parser. Review is the real control.
# The $ stays literal: the workflows hold this text.
# shellcheck disable=SC2016
call='"golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"'
want=$(pins GOVULNCHECK_VERSION "$ci")
for f in "${files[@]}"; do
  file=.github/workflows/$f.yml
  [ -f "$file" ] || fail "$file is missing."

  got=$(pins GOVULNCHECK_VERSION "$file")
  if [ -z "$got" ]; then
    fail "$f.yml has no GOVULNCHECK_VERSION pin."
  fi
  if [ "$got" != "$want" ]; then
    fail "The govulncheck pin of $f.yml is $(paste -sd ' ' - <<<"$got"), expected $want (the pin in ci.yml)."
  fi

  code=$(grep -v '^ *#' "$file" || true)
  if ! grep -qF "$call" <<<"$code"; then
    fail "$f.yml has no govulncheck call that uses \$GOVULNCHECK_VERSION."
  fi
  # Remove the pinned call, the pin lines and the names. Any other line that
  # mentions govulncheck can pick a version in another way.
  other=$(grep -iE 'govulncheck' <<<"${code//"$call"/}" \
    | grep -vE '^ *GOVULNCHECK_VERSION: *"?'"$ver_re"'"? *(#.*)?$' \
    | grep -vE '^ *(name: )?govulncheck:?$' || true)
  if [ -n "$other" ]; then
    fail "$f.yml has a govulncheck line that is not the pin or the pinned call: $other"
  fi
done
