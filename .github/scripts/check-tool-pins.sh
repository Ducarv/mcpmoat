#!/usr/bin/env bash
# Checks that the GoReleaser and govulncheck pins agree, and that each workflow
# runs govulncheck only through the pinned call line. The release-check job in
# ci.yml runs it. You can also run it on your machine, from any directory: see
# CONTRIBUTING.md, Checks. check-tool-pins-test.sh tests it.
set -euo pipefail

# CDPATH is empty, so that cd neither prints a path nor goes to another place.
CDPATH='' cd -- "$(dirname -- "$0")/../.."

wf=.github/workflows
workflows=(ci release govulncheck)
# A full version only. A short one such as v1.9 is a query, and Go picks the
# newest version that matches it.
ver_re='v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?'

# fail prints an error and stops the script. In GitHub Actions the error is an
# annotation. On your machine it is plain text on stderr.
fail() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error::$*"
  else
    echo "check-tool-pins: $*" >&2
  fi
  exit 1
}

# one_line puts the lines of stdin on one line, so that an error stays on one
# line.
one_line() {
  paste -sd ' ' -
}

# pin_re prints the regex of a "  NAME: vX.Y.Z" line. The version is group 1.
pin_re() {
  printf '^ *%s: *"?(%s)"? *(#.*)?$' "$1" "$ver_re"
}

# code_of prints the lines of a file that are not comments.
code_of() {
  grep -v '^ *#' "$1" || true
}

# pins prints the sorted, unique versions of the NAME lines of the file $2.
# $1 is NAME.
pins() {
  sed -nE "s/$(pin_re "$1")/\\1/p" "$2" | sort -u
}

# need_one_in_ci stops the script unless ci.yml pins exactly one version of a
# tool. $1 is the tool, $2 is the output of pins for ci.yml.
need_one_in_ci() {
  case $2 in
    '' | *$'\n'*) fail "ci.yml must pin one version of $1. Found: $(one_line <<<"$2")" ;;
  esac
}

for f in "${workflows[@]}"; do
  [ -f "$wf/$f.yml" ] || fail "$f.yml is missing."
done
[ -f CONTRIBUTING.md ] || fail "CONTRIBUTING.md is missing."

# GoReleaser: ci.yml is the reference. release.yml and CONTRIBUTING.md must
# name the same version.
goreleaser_want=$(pins GORELEASER_VERSION "$wf/ci.yml")
need_one_in_ci GoReleaser "$goreleaser_want"
# A GORELEASER_VERSION line that is not a full version could override the pin.
for f in ci release; do
  other=$(code_of "$wf/$f.yml" | grep -E '^ *GORELEASER_VERSION:' | grep -vE "$(pin_re GORELEASER_VERSION)" || true)
  [ -z "$other" ] || fail "$f.yml has a GORELEASER_VERSION line that is not a full version: $(one_line <<<"$other")"
done
goreleaser_rel=$(pins GORELEASER_VERSION "$wf/release.yml")
# CONTRIBUTING.md names the version after goreleaser/v<major>@. Every such
# text counts, so a short version or @latest in one command makes the set differ.
goreleaser_doc=$(grep -oE 'goreleaser(/v[0-9]+)?@[^[:space:]`"]+' CONTRIBUTING.md | sed 's/.*@//' | sort -u || true)
if [ "$goreleaser_rel" != "$goreleaser_want" ] || [ "$goreleaser_doc" != "$goreleaser_want" ]; then
  fail "The GoReleaser pins differ. ci.yml: $goreleaser_want. release.yml: $(one_line <<<"$goreleaser_rel"). CONTRIBUTING.md: $(one_line <<<"$goreleaser_doc")."
fi

# govulncheck: ci.yml is the reference. Each file must have pins with the
# same version and at least one call line that uses them. No other line
# outside a comment may mention govulncheck, no line may continue the call
# line, and no file may use continue-on-error. This is a text check, not a YAML
# parser. It catches drift by accident. Other step keys, such as if: or shell:,
# and Go variables, such as GOPROXY or GOSUMDB, are not checked. Review is the
# real control.
vuln_want=$(pins GOVULNCHECK_VERSION "$wf/ci.yml")
need_one_in_ci govulncheck "$vuln_want"
# shellcheck disable=SC2016 # the $ is regex text, not a variable
run_re='^ *run: go run "golang\.org/x/vuln/cmd/govulncheck@\$GOVULNCHECK_VERSION" \./\.\.\.$'

# listed succeeds when $1 is the name of a workflow in the list.
listed() {
  local w
  for w in "${workflows[@]}"; do
    if [ "$w" = "$1" ]; then return 0; fi
  done
  return 1
}

# A workflow that is not in the list must not mention govulncheck outside a
# comment. It could use another version. GitHub runs .yaml files too.
for file in "$wf"/*.yml "$wf"/*.yaml; do
  [ -e "$file" ] || continue
  ext=${file##*.}
  name=$(basename "$file" ".$ext")
  if [ "$ext" = yml ] && listed "$name"; then continue; fi
  if grep -qi govulncheck <<<"$(code_of "$file")"; then
    fail "$name.$ext mentions govulncheck. Only ci.yml, release.yml and govulncheck.yml may. To add a .yml workflow, add its name to the workflows list of check-tool-pins.sh."
  fi
done

for f in "${workflows[@]}"; do
  file=$wf/$f.yml
  got=$(pins GOVULNCHECK_VERSION "$file")
  [ -n "$got" ] || fail "$f.yml has no GOVULNCHECK_VERSION pin."
  [ "$got" = "$vuln_want" ] || fail "The govulncheck pin of $f.yml is $(one_line <<<"$got"), expected $vuln_want (the pin in ci.yml)."

  code=$(code_of "$file")
  grep -qE "$run_re" <<<"$code" || fail "$f.yml has no call line that uses \$GOVULNCHECK_VERSION."
  # The call line and the pin lines are the only lines that may mention
  # govulncheck. In govulncheck.yml the workflow name and the job ID may too.
  names='^$' # matches no line that mentions govulncheck
  if [ "$f" = govulncheck ]; then names='^name: govulncheck$|^  govulncheck:$'; fi
  other=$(grep -iE 'govulncheck' <<<"$code" |
    grep -vE "$run_re" |
    grep -vE "$(pin_re GOVULNCHECK_VERSION)" |
    grep -vE "$names" || true)
  [ -z "$other" ] || fail "$f.yml has a govulncheck line that is not the pin, the call line or a name: $(one_line <<<"$other")"

  # YAML continues a value on a line that is indented deeper. Such a line after
  # the call line could add "|| true" or arguments.
  call_indent=-1
  while IFS= read -r line; do
    [ -n "${line//[[:space:]]/}" ] || continue
    indent=${line%%[! ]*}
    if [ "$call_indent" -ge 0 ] && [ "${#indent}" -gt "$call_indent" ]; then
      fail "$f.yml has a line that continues the call line: $line"
    fi
    call_indent=-1
    if [[ $line =~ $run_re ]]; then call_indent=${#indent}; fi
  done <<<"$code"

  if grep -qE '^ *(- )?continue-on-error:' <<<"$code"; then
    fail "$f.yml uses continue-on-error. A step that cannot fail would hide a vulnerability."
  fi
done
