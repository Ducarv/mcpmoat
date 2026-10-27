#!/usr/bin/env bash
# Checks that the GoReleaser and govulncheck pins agree, that each GoReleaser
# step reads its version from the pin, and that each workflow runs govulncheck
# only through the pinned call line.
#
# This is a best-effort text check, not a YAML parser. It reads block style
# only, and anything it cannot read fails closed. So write the workflows in
# block style. For GoReleaser it checks these things:
# - Each goreleaser-action step has version: ${{ env.GORELEASER_VERSION }} in
#   its with: block.
# - Every line in a workflow that names GORELEASER_VERSION is that version
#   input or the pin line in the env: of a job. Any other form fails, for
#   example a second definition, a different case or a write to $GITHUB_ENV.
# - A job with a goreleaser-action step has the pin in its own env:.
# - A file under .github/actions that names goreleaser-action fails. Extend
#   this check before you add such a file.
# - A workflow line with a YAML anchor, alias or merge key fails, because an
#   alias line can repeat a step without naming it.
# Not covered: other ways to install GoReleaser or govulncheck, such as
# docker://goreleaser/goreleaser, a remote reusable workflow, brew install, go
# install, a composite action outside .github/actions, or a $GITHUB_ENV write
# that builds the name from pieces. Review is the control for these. A later
# issue can widen the check.
# The tool-pins job in ci.yml runs it. You can also run it on your machine,
# from any directory: see CONTRIBUTING.md, Checks. check-tool-pins-test.sh
# tests it.
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
  printf '^ *%s: *"?(%s)"?( +#.*)? *$' "$1" "$ver_re"
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

# wf_files is the list of the workflow files. GitHub runs .yaml files too.
wf_files=()
for file in "$wf"/*.yml "$wf"/*.yaml; do
  if [ -e "$file" ]; then wf_files+=("$file"); fi
done

# yaml_refs prints the lines of a file that use a YAML anchor (&name), an alias
# (*name) or a merge key (<<:). An alias can hide a goreleaser-action step in a
# line that names nothing. The rule is narrow, to avoid false alarms in shell
# text. A line matches when, outside quotes and comments, a token &name or
# *name stands after "- ", after ": ", or after [ { or a comma, and ends at a
# space, a comma, a bracket or the end of the line. The line "<<:" matches too.
# The body of a block scalar (a key with | or >, such as run: |) is skipped.
# Known limit: an unquoted apostrophe in a plain value can hide text after it.
yaml_refs() {
  code_of "$1" | awk '
    BEGIN {
      q = "\047"
      ref_re = "(^(- +)+|: +|[[{,] *)[&*][A-Za-z0-9_-]+([],} ]|$)"
      block_re = "^[|>][-+0-9]* *$"
    }
    /^[[:space:]]*$/ { next }
    {
      match($0, /^ */)
      indent = RLENGTH
      if (inblock) {
        if (indent > blockind) next
        inblock = 0
      }
      line = $0; sub(/^ */, "", line)
      shown = line
      gsub(/"[^"]*"/, "\"\"", line)
      gsub(q "[^" q "]*" q, "\"\"", line)
      sub(/ +#.*$/, "", line)
      rest = line; dashes = 0
      while (rest ~ /^- +/) { match(rest, /^- +/); dashes += RLENGTH; sub(/^- +/, "", rest) }
      if (rest ~ /^<<:/ || line ~ ref_re) print shown
      # A block scalar starts when the line ends with : | or - | and so on.
      # Its body is indented deeper than the key (or the dash, for - |).
      val = rest; sub(/^.*: +/, "", val)
      if (val ~ block_re || rest ~ block_re) {
        inblock = 1
        blockind = (rest ~ block_re) ? indent : indent + dashes
      }
    }
  '
}

# An anchor, an alias or a merge key can hide a step from the checks below.
for file in "${wf_files[@]}"; do
  refs=$(yaml_refs "$file")
  [ -z "$refs" ] ||
    fail "$(basename "$file"): line uses a YAML anchor, alias or merge key: \"${refs%%$'\n'*}\". Write the workflows without them."
done

# GoReleaser: ci.yml is the reference. release.yml and CONTRIBUTING.md must
# name the same version.
goreleaser_want=$(pins GORELEASER_VERSION "$wf/ci.yml")
need_one_in_ci GoReleaser "$goreleaser_want"
# A GORELEASER_VERSION line that is not a full version could override the pin.
# Any workflow file can hold one, so check them all.
for file in "${wf_files[@]}"; do
  other=$(code_of "$file" | grep -E '^ *GORELEASER_VERSION:' | grep -vE "$(pin_re GORELEASER_VERSION)" || true)
  [ -z "$other" ] || fail "$(basename "$file") has a GORELEASER_VERSION line that is not a full version: $(one_line <<<"$other")"
done
goreleaser_rel=$(pins GORELEASER_VERSION "$wf/release.yml")
# CONTRIBUTING.md names the version after goreleaser/v<major>@. Every such
# text counts, so a short version or @latest in one command makes the set differ.
goreleaser_doc=$(grep -oE 'goreleaser(/v[0-9]+)?@[^[:space:]`"]+' CONTRIBUTING.md | sed 's/.*@//' | sort -u || true)
if [ "$goreleaser_rel" != "$goreleaser_want" ] || [ "$goreleaser_doc" != "$goreleaser_want" ]; then
  fail "The GoReleaser pins differ. ci.yml: $goreleaser_want. release.yml: $(one_line <<<"$goreleaser_rel"). CONTRIBUTING.md: $(one_line <<<"$goreleaser_doc")."
fi

# A composite action can hold a goreleaser-action step, and this check does not
# read it. So a file under .github/actions that names the action fails. find
# lists the matching files. The ; form makes find succeed when none matches.
if [ -d .github/actions ]; then
  action_files=$(find -H .github/actions ! -type d -exec grep -liF 'goreleaser/goreleaser-action' {} \; | one_line)
  [ -z "$action_files" ] ||
    fail "$action_files names goreleaser/goreleaser-action. This check does not read .github/actions. Extend the check before you add such a file."
fi

# Each goreleaser/goreleaser-action step must have a version input with the
# value ${{ env.GORELEASER_VERSION }} inside its with: block. Without it, with
# another value such as latest, or with the key in another place such as env:,
# the action installs another GoReleaser than the pinned one. A step starts at
# a "- " line and ends at the next line that has the same indent or less. So a
# version input of another step does not count.
# The same function also checks every line that names GORELEASER_VERSION, in
# any case. Such a line must be the version input or the pin line: exact case,
# no space before the colon, at indent 6 in the env: of a job. Any other line
# could change the version at run time. Examples are a second definition, a
# flow style env, or a run: step that writes to $GITHUB_ENV. A job with a
# goreleaser-action step must have the pin line in its own env:.
# This is a best-effort text check, not a YAML parser. It reads block style
# only. It counts the lines that name goreleaser/goreleaser-action and the
# steps that it could read. When a line names the action in a style that it
# cannot read (flow style, an anchor, a split line), it fails. So write each
# step in block style. The govulncheck check below is a text check too.
#
# The awk program reads the file one line at a time and keeps this state in
# variables. A variable that was never set is 0 or empty.
#   indent    the number of spaces at the start of the line.
#   top       the last key at indent 0, such as jobs.
#   job       the last key at indent 2 under jobs: the job ID.
#   jobkey    the last key at indent 4 in that job, such as env or steps.
#   has_step  the jobs that have a goreleaser-action step.
#   has_pin   the jobs that have the pin line in their env:.
#   instep    1 while the program is inside a step (a "- " list item).
#   start     the indent of the "- " line that began the step.
#   first     the text of that line. The messages show it.
#   keyind    the column where the first key of the step starts, after "- ".
#   kpos      the column where the key of the line starts. A key of the step
#             itself has kpos equal to keyind. A key of a child has more.
#   inwith    1 while the program is inside the with: block of the step.
#   childind  the indent of the keys inside with:. The first line sets it.
#   uses      1 when the step runs goreleaser-action.
#   seen      1 when with: has a version input.
#   bad       1 when a version input is not ${{ env.GORELEASER_VERSION }}.
#   mentions  the lines that name goreleaser/goreleaser-action in any style.
#   recognised  the lines among them that are a readable "uses:" line.
# end_step prints the errors of a step and clears the state of that step.
goreleaser_steps() {
  code_of "$1" | PIN_RE=$(pin_re GORELEASER_VERSION) awk '
    BEGIN {
      q = "\047"
      uses_re = "^uses: *[\"" q "]?goreleaser/goreleaser-action([\"" q " @]|$)"
      version_re = "^[\"" q "]?version[\"" q "]? *:"
      pin_re = ENVIRON["PIN_RE"]
    }
    # is_version_line succeeds when the line is the allowed version input.
    # A # starts a comment only after a space.
    function is_version_line(s,   val) {
      if (tolower(s) !~ version_re) return 0
      val = s; sub(/^[^:]*: */, "", val)
      return val ~ /^("\$\{\{ env\.GORELEASER_VERSION \}\}"|\$\{\{ env\.GORELEASER_VERSION \}\})( +#.*)? *$/
    }
    function end_step() {
      if (uses && !seen) print "the step \"" first "\" has no version input in its with: block."
      if (uses && bad) print "the step \"" first "\" has a version input that is not ${{ env.GORELEASER_VERSION }}."
      uses = seen = bad = inwith = 0
    }
    tolower($0) ~ /goreleaser\/goreleaser-action/ {
      mentions++
      if (!(job in has_step)) { has_step[job] = 1; order[++njobs] = job }
    }
    /^[[:space:]]*$/ { next }
    {
      match($0, /^ */)
      indent = RLENGTH
      trimmed = $0; sub(/^ */, "", trimmed)
      key = trimmed; sub(/:.*/, "", key)
      if (indent == 0) { top = key; job = ""; jobkey = "" }
      else if (top == "jobs" && indent == 2) { job = key; jobkey = "" }
      else if (top == "jobs" && indent == 4) jobkey = key
      if (tolower($0) ~ /goreleaser_version/) {
        if (top == "jobs" && job != "" && indent == 6 && jobkey == "env" && trimmed ~ pin_re) has_pin[job] = 1
        else if (!is_version_line(trimmed)) print "the line \"" trimmed "\" mentions GORELEASER_VERSION in a form this check does not allow. Allowed: the pin line in the env: of a job and the version input of a goreleaser-action step."
      }
      if (instep && indent <= start) { end_step(); instep = 0 }
      body = $0
      kpos = indent
      if (!instep && $0 ~ /^ *- /) {
        instep = 1; start = indent; first = $0; sub(/^ */, "", first)
        match($0, /^ *- +/)
        keyind = RLENGTH; kpos = keyind
        sub(/^ *- +/, "", body)
      } else {
        sub(/^ */, "", body)
      }
      if (!instep) next
      lc = tolower(body)
      if (lc ~ uses_re) { uses = 1; recognised++ }
      if (inwith && indent <= keyind) inwith = 0
      if (kpos == keyind && lc ~ /^with:/) {
        inwith = 1; childind = -1
      } else if (inwith) {
        if (childind < 0) childind = indent
        if (indent == childind && lc ~ version_re) {
          seen = 1
          if (!is_version_line(body)) bad = 1
        }
      }
    }
    END {
      if (instep) end_step()
      if (mentions > recognised) print "a line names goreleaser-action in a style this check cannot read. Write the step in block style."
      for (i = 1; i <= njobs; i++)
        if (!(order[i] in has_pin)) print "the job \"" order[i] "\" has a goreleaser-action step but its env: does not define GORELEASER_VERSION."
    }
  '
}
for file in "${wf_files[@]}"; do
  base=$(basename "$file")
  # A file with another GORELEASER_VERSION than ci.yml has would break the pin.
  # A file with a step but no definition would use the default of the action.
  got=$(pins GORELEASER_VERSION "$file")
  [ -z "$got" ] || [ "$got" = "$goreleaser_want" ] ||
    fail "$base has GORELEASER_VERSION $(one_line <<<"$got"), expected $goreleaser_want (the pin in ci.yml)."
  if [ -z "$got" ] && grep -qi 'goreleaser/goreleaser-action' <<<"$(code_of "$file")"; then
    fail "$base has a goreleaser-action step but does not define GORELEASER_VERSION. The step would use the default of the action."
  fi
  bad_steps=$(goreleaser_steps "$file")
  [ -z "$bad_steps" ] || fail "$base: $(one_line <<<"$bad_steps")"
done

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
# comment. It could use another version.
for file in "${wf_files[@]}"; do
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
  # govulncheck. In govulncheck.yml the workflow name, the job ID and
  # the line "    needs: govulncheck" may too.
  names='^$' # matches no line that mentions govulncheck
  if [ "$f" = govulncheck ]; then names='^name: govulncheck$|^  govulncheck:$|^    needs: govulncheck$'; fi
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
