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
# - A workflow line with a YAML form that this check cannot read fails: an
#   anchor, alias or merge key (an alias line can repeat a step without naming
#   it), a tag, a tab, a line with only a dash, a backslash inside double
#   quotes (an escape can spell goreleaser-action without its plain text), a
#   line that continues the plain value before it, and a quote that does not
#   close on its line. See yaml_refs for the exact rules.
# Not covered: other ways to install GoReleaser or govulncheck, such as
# docker://goreleaser/goreleaser, a remote reusable workflow, brew install, go
# install, a composite action outside .github/actions, or a $GITHUB_ENV write
# that builds the name from pieces. Review is the control for these. A later
# issue can widen the check.
# The ci-scripts job in ci.yml runs it. You can also run it on your machine,
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

# wf_files is the list of the workflow files. GitHub runs .yaml files too. The
# dot patterns find a name that starts with a dot, which a plain * skips.
wf_files=()
for file in "$wf"/*.yml "$wf"/*.yaml "$wf"/.*.yml "$wf"/.*.yaml; do
  if [ -e "$file" ]; then wf_files+=("$file"); fi
done

# yaml_refs prints the lines of a file that use a YAML form that the checks
# below cannot read. These forms can hide a goreleaser-action step, because the
# checks read one line at a time and look for the plain text of the action:
# - an anchor (&name), an alias (*name) or a merge key (<<:). A name is any text
#   up to a space or a flow indicator (, [ ] { }), as YAML allows. The token
#   stands at the start of the line, after "- ", after ": ", or after [ { or a
#   comma. The line "<<:" matches too, with spaces before the colon.
# - a tag (! or !!str) at the start of a value.
# - a tab, which YAML reads as a space in some places and not in others.
# - a backslash inside a double-quoted text, because "\x6e" can spell a letter.
# - a quote at the start of a value that does not close on the line (a text
#   that goes on in the next line can hold a line that looks like a pin). A
#   doubled single quote inside single quotes is an escape and does not close.
# - a line with a dash and nothing else (or a comment). YAML then starts the
#   keys of the item on the next line, at a column that the checks do not know.
# - a line that is indented deeper than the key of the line before it, when
#   that line has a plain value. YAML joins the two lines into one text, so a
#   line that looks like a version input or a pin can be part of another value.
# Quoted texts and comments are not searched, and the body of a block scalar (a
# key with | or >, such as run: |) is skipped. A plain value that has ", *" or
# "{*" in it matches the first rule, so put such a value in quotes.
# Known limit: an unquoted apostrophe in a plain value can hide text after it.
yaml_refs() {
  code_of "$1" | awk '
    BEGIN {
      q = "\047"
      start = "(^|- +|: +|[[{,] *)"
      ref_re = "(^(- +)*|: +|[[{,] *)[&*][^],[{} ]+"
      tag_re = start "!"
      open_re = start "[\"" q "]"
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
      # A double-quoted text without a backslash is fine. A backslash in one
      # that is left after that is an escape.
      esc = shown
      gsub(/"[^"\\]*"/, "Q", esc)
      escaped = esc ~ /"[^"]*\\/
      gsub(/"[^"]*"/, "Q", line)
      gsub(q q, "", line)
      gsub(q "[^" q "]*" q, "Q", line)
      sub(/ +#.*$/, "", line)
      rest = line; dashes = 0
      while (rest ~ /^- +/) { match(rest, /^- +/); dashes += RLENGTH; sub(/^- +/, "", rest) }
      bare = line ~ /^(- *)+$/
      joined = prev_value && indent > prev_col
      if (escaped || bare || joined || rest ~ /^<< *:/ || line ~ ref_re || line ~ tag_re || line ~ open_re || line ~ /\t/) print shown
      # A block scalar starts when the line ends with : | or - | and so on.
      # Its body is indented deeper than the key (or the dash, for - |).
      val = rest; sub(/^.*: +/, "", val)
      if (val ~ block_re || rest ~ block_re) {
        inblock = 1
        blockind = (rest ~ block_re) ? indent : indent + dashes
      }
      # A key with a plain value, or a plain list item. A key without a value
      # (key:) has children, so a deeper line is normal after it.
      prev_value = (rest ~ /: +[^ ]/ || (dashes > 0 && rest != "" && rest !~ /:( |$)/)) && !inblock
      prev_col = (rest ~ /: +[^ ]/) ? indent + dashes : indent
    }
  '
}

# These forms can hide a step from the checks below.
for file in "${wf_files[@]}"; do
  refs=$(yaml_refs "$file")
  [ -z "$refs" ] ||
    fail "$(basename "$file"): line uses a YAML form this check cannot read: \"${refs%%$'\n'*}\". Write the workflows without anchors, aliases, merge keys, tags, tabs, a backslash in double quotes, and a quote that does not close on its line. Put a plain value that has a comma and a star, or a brace and a star, in quotes."
done

# GoReleaser: ci.yml is the reference. release.yml and CONTRIBUTING.md must
# name the same version.
goreleaser_want=$(pins GORELEASER_VERSION "$wf/ci.yml")
need_one_in_ci GoReleaser "$goreleaser_want"
# A GORELEASER_VERSION line that is not a full version could override the pin.
# Any workflow file can hold one, so check them all. goreleaser_steps below
# rejects such a line too. This check is first on purpose, for a clearer
# message.
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
# find -L follows a symlink to a directory, as GitHub does.
if [ -d .github/actions ]; then
  action_files=$(find -L .github/actions -type f -exec grep -liF 'goreleaser/goreleaser-action' {} \; | one_line)
  [ -z "$action_files" ] ||
    fail "$action_files names goreleaser/goreleaser-action. This check does not read .github/actions. Extend the check before you add such a file."
fi

# goreleaser_steps applies the GoReleaser rules of the header, to one file.
# A step starts at a "- " line and ends at the next line that has the same
# indent or less. So a version input of another step does not count. The pin
# line must be exact: case, no space before the colon, at indent 6 in the env:
# of a job. It counts the lines that name goreleaser/goreleaser-action and the
# steps that it could read. When a line names the action in a style that it
# cannot read (flow style, a split line), it fails.
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
#   order     the jobs that have a goreleaser-action step, in file order.
#   njobs     how many jobs are in order.
#   body      the line without its indent and the "- " of a step.
#   lc        body in lower case.
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
  # The END rule of goreleaser_steps finds the second case per job. This check
  # is per file, and it is first on purpose, for a clearer message.
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
run_re='^ {8}run: go run "golang\.org/x/vuln/cmd/govulncheck@\$GOVULNCHECK_VERSION" \./\.\.\.$'

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
  # govulncheck. In govulncheck.yml the workflow name, the job ID, the line
  # "    needs: govulncheck" and the if: line of the failure job may too.
  names='^$' # matches no line that mentions govulncheck
  if [ "$f" = govulncheck ]; then
    names="^name: govulncheck\$|^  govulncheck:\$|^    needs: govulncheck\$|^    if: failure\(\) \|\| needs\.govulncheck\.result == 'cancelled'\$"
  fi
  other=$(grep -iE 'govulncheck' <<<"$code" |
    grep -vE "$run_re" |
    grep -vE "$(pin_re GOVULNCHECK_VERSION)" |
    grep -vE "$names" || true)
  [ -z "$other" ] || fail "$f.yml has a govulncheck line that is not the pin, the call line or a name: $(one_line <<<"$other")"

  # A line that is indented deeper than the call line would continue its value,
  # for example with "|| true". yaml_refs fails on such a line.

  if grep -qE '^ *(- )?continue-on-error:' <<<"$code"; then
    fail "$f.yml uses continue-on-error. A step that cannot fail would hide a vulnerability."
  fi
done
