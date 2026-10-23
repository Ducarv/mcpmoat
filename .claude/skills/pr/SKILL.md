---
name: pr
description: Create a pull request with a Summary, Testing and Release Notes description that follows the project's conventions (base branch, template, release-note audience and app names).
allowed-tools: [Bash, Read, Glob, Grep]
---

# Pull Request

Create a pull request with a clear description and release notes that a non-technical reader
can understand.

## Project profile

Read `.agents/project.md` at the repo root first, if it exists. These sections drive this skill:

- **Git and pull requests**: base branch, branch flow, issue link, PR template, CI trigger,
  and what (if anything) may follow the Release Notes section.
- **Release notes**: whether they are required, who reads them, the language rules, and the
  app identifier table.

If the file is missing, use the repo's default branch, use the PR template
(`.github/pull_request_template.md` or `.github/PULL_REQUEST_TEMPLATE.md`) if it exists, and write release notes for a general product audience.

## Steps

### 1. Choose the base branch

```bash
git branch --show-current
git remote show origin | sed -n 's/.*HEAD branch: //p'   # repo default branch
```

- If the profile names a default PR base branch, use it.
- Otherwise use the repo default branch.
- If the current branch was cut from another feature branch, or from a release or production
  branch (a likely hotfix), ask the user to confirm the base.
- Never guess when it is unclear. Ask.

### 2. Check the branch state

```bash
git status
git log origin/<base>..HEAD --oneline
```

- Warn about uncommitted changes.
- Confirm there are commits that are not on the base branch.
- Push the branch if it has no upstream: `git push -u origin <branch>`.

### 3. Gather context

```bash
git diff origin/<base>...HEAD --stat
git log origin/<base>..HEAD --pretty=format:"%s%n%b"
git diff origin/<base>...HEAD
cat .github/pull_request_template.md .github/PULL_REQUEST_TEMPLATE.md 2>/dev/null || true
git diff --name-only --diff-filter=AMRD origin/<base>...HEAD | grep -E '\.md$|^docs/|^\.github/ISSUE_TEMPLATE/' || true   # changed doc files
```

If a PR template exists, keep its structure and fill it in. Otherwise use the format below.

### 4. Write the description

**Summary**: what changed and why, for reviewers. Bullet points for multiple changes.

**Testing**: how to verify the change, as a checklist: commands to run, manual steps, edge
cases to check. Tick only what you actually ran.

**Release Notes**: what changed, written for a non-technical reader.

**Docs**: put the changed doc files from step 3 in the template `## Docs` section, one path per
line, and write `none` only when the list is empty. A behaviour change, and what makes a "No doc
change needed" reason real, are defined in
[CONTRIBUTING.md Pull requests](../../../CONTRIBUTING.md#pull-requests). The owner doc is the one
in the "Topic to owner" table of `docs/README.md`.

- In the template `## Checklist`, tick `Docs updated (list the files)` only when the list has at
  least one file, and the diff does not have a behaviour change with no owner doc in the list
  (see the last point below). When both boxes qualify, tick `Docs updated`.
- Tick `No doc change needed because: ...` only with a real reason. Take it from the first source
  that has one: (a) the reason the caller passed in (a reason from the user), (b) the user, (c) the
  issue. Write the reason on the line.
- If the diff clearly has no behaviour change (for example a refactor or tests only), or the owner
  doc already states the new behaviour (read it), check the diff, then write
  `No doc change needed because: <one line from the diff>` and tick that box. Do this only when
  you are sure. If you are unsure, follow the next point.
- If the diff has a behaviour change, the owner doc is not in the list, and no source gives a
  real reason, do not tick either box:
  - Interactive run: **stop and ask** the user to update the owner doc, or to give the reason.
    Do not create the PR until they answer.
  - Non-interactive or `--auto` run (the caller says so, or no user can answer): do not wait and
    do not create the PR. Return a short failure message that names the missing owner doc, and let
    the caller fix it.

If the work closes an issue, add the issue link line from the profile (default `Closes #<n>`).

### 5. Release-note rules

1. **No jargon.** Not "refactored", "optimised a query" or "fixed a race condition". Say what
   the user experiences.
2. **Describe the user's experience.** What can they do now that they could not do before?
3. **Be specific about where.** Which app, page, screen or button. Use the app identifiers
   from the profile.
4. **Explain before and after.** What used to happen, and what happens now.
5. **For bug fixes, give the symptom.** What would a customer have said?
6. **Internal changes still get a note**, prefixed with `Internal:`.

Questions every release note should answer: which app, which page or screen, what changed,
the old behaviour, the new behaviour, and (for fixes) what a customer would have reported.

Good:

> **Customer Dashboard (web)**: Added an "Export CSV" button to the Transactions page, above
> the table on the right. It downloads every transaction that matches the current filters as a
> file that opens in Excel or Google Sheets.

> **Customer Dashboard (web)**: Fixed recent transactions not showing for some accounts. Users
> may have reported "my sales aren't showing up". Transactions now show correctly in every
> time zone.

> Internal: Updated the database driver. No user-facing change.

Bad, and why:

| Bad | Problem | Better |
|---|---|---|
| "Fixed bug" | Which bug? Who saw it? | "Fixed users being unable to log in after a password change" |
| "UI improvements" | What, and where? | "Made the Pay button larger and green on the checkout page" |
| "Updated API endpoint" | Jargon, no user impact | "Users can now filter transactions by payment method" |
| Empty | Never acceptable | "Internal: code clean-up, no user impact" |

### 6. Create the PR

```bash
gh pr create --base <base> --title "<title>" --body "$(cat <<'EOF'
## Summary
- <change>

## Testing
- [ ] <step>

## Checklist
<!-- Tick one. -->
- [ ] Docs updated (list the files)
- [ ] No doc change needed because: <reason>

## Docs
- <doc file or "none">

## Release Notes
<note>
EOF
)"
```

Title: under 70 characters, imperative mood, specific ("Fix payment timeout on slow
connections", not "Fix bug"). Follow the profile's commit style for the title if it has one.

Add nothing after the Release Notes section unless the profile allows it.

### 7. Verify and hand off

```bash
gh pr view --json url,title,baseRefName -q '.url'
```

Report the PR URL. If the profile defines a CI trigger (for example a label), tell the user,
but apply it only if the profile or the user says to.
