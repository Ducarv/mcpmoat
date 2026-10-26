#!/usr/bin/env bash
# Checks that the tool version pins agree. The release-check job in ci.yml
# runs it. You can also run it on your machine, from any directory: see
# CONTRIBUTING.md, Checks. check-tool-pins-test.sh tests it.
set -euo pipefail

cd "$(dirname "$0")/../.."

wf=.github/workflows
workflows=(ci release govulncheck)
ver_re='v[0-9][0-9A-Za-z.+-]*[0-9A-Za-z]'

# fail prints an error and stops the script.
fail() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error::$*"
  else
    echo "check-tool-pins: $*" >&2
  fi
  exit 1
}

# join puts the lines of stdin on one line, so that an error stays on one line.
join() {
  paste -sd ' ' -
}

# pin_re prints the regex of a "  NAME: vX.Y.Z" line. The version is group 1.
pin_re() {
  printf '^ *%s: *"?(%s)"? *(#.*)?$' "$1" "$ver_re"
}

# pins prints the sorted, unique versions of the NAME lines of a file.
pins() {
  sed -nE "s/$(pin_re "$1")/\\1/p" "$2" | sort -u
}

for f in "${workflows[@]}"; do
  [ -f "$wf/$f.yml" ] || fail "$wf/$f.yml is missing."
done
[ -f CONTRIBUTING.md ] || fail "CONTRIBUTING.md is missing."

# GoReleaser: ci.yml is the reference. release.yml and CONTRIBUTING.md must
# name the same version.
goreleaser_want=$(pins GORELEASER_VERSION "$wf/ci.yml")
case $goreleaser_want in
  '' | *$'\n'*) fail "ci.yml must have exactly one GORELEASER_VERSION pin. Found: $(join <<<"$goreleaser_want")" ;;
esac
rel=$(pins GORELEASER_VERSION "$wf/release.yml")
# CONTRIBUTING.md names the version only in goreleaser/v<major>@<version>.
doc=$(grep -oE "goreleaser(/v[0-9]+)?@$ver_re" CONTRIBUTING.md | sed 's/.*@//' | sort -u || true)
if [ "$rel" != "$goreleaser_want" ] || [ "$doc" != "$goreleaser_want" ]; then
  fail "The GoReleaser pins differ. ci.yml: $goreleaser_want. release.yml: $(join <<<"$rel"). CONTRIBUTING.md: $(join <<<"$doc")."
fi

# govulncheck: ci.yml is the reference. Each file must have one pin with the
# same version and one call line that uses it. No other line outside a comment
# may mention govulncheck. This is a text check, not a YAML parser. It catches
# drift by accident. Review is the real control.
vuln_want=$(pins GOVULNCHECK_VERSION "$wf/ci.yml")
case $vuln_want in
  '' | *$'\n'*) fail "ci.yml must have exactly one GOVULNCHECK_VERSION pin. Found: $(join <<<"$vuln_want")" ;;
esac
# shellcheck disable=SC2016 # the $ is regex text, not a variable
run_re='^ *run: go run "golang\.org/x/vuln/cmd/govulncheck@\$GOVULNCHECK_VERSION" \./\.\.\.$'
for f in "${workflows[@]}"; do
  file=$wf/$f.yml
  got=$(pins GOVULNCHECK_VERSION "$file")
  [ -n "$got" ] || fail "$f.yml has no GOVULNCHECK_VERSION pin."
  [ "$got" = "$vuln_want" ] || fail "The govulncheck pin of $f.yml is $(join <<<"$got"), expected $vuln_want (the pin in ci.yml)."

  code=$(grep -v '^ *#' "$file" || true)
  grep -qE "$run_re" <<<"$code" || fail "$f.yml has no call line that uses \$GOVULNCHECK_VERSION."
  other=$(grep -iE 'govulncheck' <<<"$code" |
    grep -vE "$run_re" |
    grep -vE "$(pin_re GOVULNCHECK_VERSION)" |
    grep -vE '^name: govulncheck$|^  govulncheck:$' || true)
  [ -z "$other" ] || fail "$f.yml has a govulncheck line that is not the pin, the call line or a name: $(join <<<"$other")"
done
