---
name: polish-pr
description: >-
  Polish your own branch or PR with a local review loop: run the review-pr panel,
  verify and address every finding to a high-polish bar, record each decision in a
  local ledger, commit additively, run the project gates, and repeat until the
  review approves with only optional nits left. No review bot or labels needed.
  Does not merge.
argument-hint: "[pr-number] [--max-rounds N] [--lite-followups] [--no-post] [--fresh]"
allowed-tools: [Bash, Read, Edit, Write, Glob, Grep, Agent, Skill]
---

# Polish PR (local loop)

Drive the **author side** of a review loop on your own machine. Each round runs the
`review-pr` panel against the whole branch, you fix or answer every finding, and the next
round checks the result with fresh reviewers. You stop when the review approves and only
optional nits are left. **This skill never merges.** Merging is a human decision.

## How it relates to `review-pr`

- **`review-pr`** runs one review (three specialist agents) and prints a report. It does not
  change code.
- **`polish-pr`** (this skill) calls `review-pr` in a loop and does the author's work between
  rounds: triage, fixes, commits, gates and a written record of every decision.

The reviewers in each round are fresh sub-agents that never see your reasoning, so the round
after a fix is an independent check of that fix.

## Arguments

From the arguments, in any order:
- a PR number (optional). Without it, use the PR for the current branch if one exists, else
  review the branch against its base with no PR.
- `--max-rounds N`: round cap (default: the profile value, else 5).
- `--lite-followups`: run rounds 2 and later with `--lite` (cheaper, less deep).
- `--no-post`: do not post review comments on the PR. By default, when a PR exists, every round
  posts its review report and its resolution summary as PR comments (Step 5b), and the loop
  ends with a final summary comment. The PR then keeps the review context for later sessions
  and human reviewers. The profile's **Post a disposition comment on the PR** value overrides
  the default.
- `--post`: accepted as a no-op alias. Posting is already the default.
- `--fresh`: start a new ledger instead of resuming the existing one.

## Tool notes

This skill works in any agent tool that reads `SKILL.md` files. Where the tools differ:

- **Invocation and arguments.** Claude Code: `/polish-pr <args>`. Codex: `$polish-pr <args>`. As a plugin, both tools
  also accept the `workflow:` prefix (`/workflow:polish-pr`, `$workflow:polish-pr`). Use the text the user gave after the skill name.
- **Spawning agents.** Claude Code: the Agent tool with the agent name (add the `workflow:`
  prefix when the toolkit is installed as a plugin). Codex: ask to spawn the custom agent by
  name. Codex agent names use underscores, so `review-security` is `review_security`.
- **Model tiers.** Agents run on a tier: **deep**, **standard** or **fast**. Claude Code maps
  them to opus, sonnet and haiku. Codex maps them to reasoning effort high, medium and low
  (or to the models set in the Codex adapter). Pass the tier's model or effort when you spawn.
- **No sub-agents?** If the tool cannot spawn agents, do each agent's job yourself, one at a
  time. First read the agent's definition (`.claude/agents/<name>.md` or
  `.codex/agents/<name>.toml`). Start each role with a fresh read of the code, and do not
  reuse conclusions from an earlier role. Say in your report that the roles ran in sequence.
- **Task tracking.** Use the tool's tracker if it has one (Claude Code: `TaskCreate` and
  `TaskUpdate`; Codex: the plan tool). Otherwise keep the task table in your messages.

## Project profile

Read `.agents/project.md` at the repo root first, if it exists. You use **Commands** (gates),
**Git and pull requests** (base branch, commit style, attribution), **Code style** (for fixes)
and **Local review loop** (max rounds, push and post defaults). If it is missing, use the Go
defaults: `gofmt -l .`, `go vet ./...`, `golangci-lint run`, `go test ./...`.

## Step 1: Set up

```bash
BRANCH=$(git branch --show-current)
N=$(gh pr view --json number -q .number 2>/dev/null)          # empty if there is no PR
BASE_BRANCH=<profile base, else the PR base, else: git remote show origin | sed -n 's/.*HEAD branch: //p'>
LEDGER_DIR="$(git rev-parse --git-common-dir)/polish-pr"
LEDGER="$LEDGER_DIR/$(printf '%s' "$BRANCH" | tr '/' '-').md"
mkdir -p "$LEDGER_DIR"
git status --porcelain
```

Stop and ask if:
- you are on the base branch (polish works on feature branches only),
- the working tree has uncommitted changes (ask whether to commit them first or stop),
- there are no commits ahead of `origin/$BASE_BRANCH`.

The ledger lives inside `.git/`, so it is never committed. If it exists and `--fresh` was not
given, **resume**: the next round number is the last recorded round + 1. Tell the user you are
resuming, and from which round.

Ledger format (create it on the first round):

```markdown
# polish-pr ledger: <branch>
Base: origin/<base>. PR: #<n> or none. Started: <UTC date>.

## Round 1 - <short head sha> - Tier: standard - Verdict: REQUEST CHANGES
Panelled files: internal/discover/list.go, internal/pins/hash.go

| # | Tags | Severity | Finding | File:line | Disposition | Reason or commit |
|---|---|---|---|---|---|---|
| 1 | [S/L] | Should-Fix | Env values from config reach stdout | internal/discover/list.go:42 | fixed | 3f2a9c1 |
| 2 | [Q] | Nit | Inline comment repeats the code | internal/pins/hash.go:10 | declined | Comment explains why keys are sorted, not the code |
```

## Step 2: The loop

```
round = last ledger round + 1
loop:
  HEAD = git rev-parse HEAD
  run the review-pr skill: [<N>] --ledger $LEDGER [--lite if round > 1 and --lite-followups]
  run the docs check (Step 3.6) and add its finding, if any, to the round's findings
  append the round to the ledger: head sha, method/tier, verdict, panelled files, findings
  post the review report as a PR comment (Step 5b)
  if verdict is COMMENT (review incomplete):
      run the round again once; if it is incomplete again, stop and escalate
  if verdict is APPROVE and every remaining finding (the docs finding too) is Minor/Nit with a disposition:
      post the resolution summary for the remaining findings (Step 5b), then stop (Step 6)
  triage every finding (Step 3) and write each disposition to the ledger
  apply the fixes (Step 4), run the gates (Step 5), commit
  push, then post the resolution summary as a PR comment (Step 5b)
  if round == max rounds: stop and report (Step 6)
  round += 1
```

Rules for the loop:
- **Every round reviews the whole branch against the base**, not only the latest commit.
  `review-pr` handles this. It may choose a delta-verify on a follow-up round when the rules
  allow it.
- **Any new commit after a review needs a new round.** This includes a comment-only change or
  a typo fix. Never call a delta "too small to review".
- **Do not set a cron, loop or timer** to wait for the review agents. They wake you when they
  finish.
- **Cost.** Each panel round runs up to three deep-tier agents. Tell the user the round count as you
  go. Suggest `--lite-followups` when the rounds are mostly about nits.

## Step 3: Triage rules

### 3.1 Verify before you act

Treat every finding as a **lead to confirm, not a fact**. Open the cited file and line and
check it before you fix **or** decline. Reviewers write confident findings that are sometimes
wrong: a misread comment, a symbol that is in fact imported, a line number in the wrong file.
A quick read is cheap compared with acting on a phantom.

### 3.2 One disposition per finding

Every finding gets exactly one of:
- **fixed** (the default): it is real and in scope for this branch. Record the commit.
- **already-done**: point to where.
- **non-issue**: explain concretely why it is wrong.
- **declined**: it is real but does not belong here. Give a *technical* reason and track it
  (open an issue or note it for the user).

Never put minors and nits together in one "declined by design" bucket. Give a reason per item.

### 3.3 No lazy deferrals

If a fix is small, testable and in scope, do it in **this** branch, even in a shared file.
"Do it in a follow-up" is acceptable only with a real technical reason (large, risky, needs its
own design or review). Never defer for diff tidiness or comfort. The bar is a highly polished
PR, not "no critical issues".

### 3.4 Write the reason where the reviewer reads it

Write every disposition and reason to the ledger **before** the next round. `review-pr` reads
the ledger to filter findings that were already handled, so a clear reason stops the same
point coming back. An unexplained decline comes back next round and wastes a cycle. A decline
holds only while its reason is true. If the code changes so the reason no longer applies, the
finding can return, and that is correct.

Be honest in the ledger. Mark a finding `fixed` only after the code has changed and the gates
pass. Never edit an earlier round's entries to make a finding go away.

### 3.5 Check the premise against the real environment

Some findings rest on a false premise. Example: a reviewer suggests `permissions: {}` on a CI
workflow because "it never uses the token", but `actions/checkout` needs `contents: read` on a
private repo, so `{}` would break the build. Declining with that checked reason is correct.
State the premise you disproved.

### 3.6 Docs check (every round)

Run `git diff --name-only origin/<base>...HEAD`. If the diff has a behaviour change, as defined in
[CONTRIBUTING.md Pull requests](../../../CONTRIBUTING.md#pull-requests), find the owner doc in the
"Topic to owner" table of `docs/README.md`. Add a finding if the owner doc is not in the diff and
the PR has no "No doc change needed because" line with a real reason. To check the PR, read the body
with `gh pr view <n> --json body -q .body`. If there is no PR (`N` is empty in Step 1), read the
ledger instead: a "No doc change needed because" reason that an earlier round recorded there
counts, and without one the finding stands when the owner doc is not in the diff. The finding is `[Q]`, Should-Fix,
"PR does not update the owner doc". Treat it like any other finding. There are two fixes. Update
the owner doc in an additive commit. Or, if the doc needs no change, record the "No doc change
needed because ..." reason in the ledger and, once a PR exists, add that line to the PR body with
`gh pr edit`. You can also decline it with a technical reason. Write the disposition to the ledger.

## Step 4: Apply fixes

- Small, local fixes: make them yourself with Read and Edit, following the profile's code style.
- Multi-file or larger fixes: delegate to the dev agents (`go-dev`, `cli-dev`, `datastore`,
  `unit-test`, `cli-test`, `e2e-test`) with a precise task, or invoke the `coordinate` skill.
- When a reviewer asks you to reorder or refactor load-bearing control flow (not just an
  additive fix), re-derive the invariants it touches yourself before you commit.
- Add or update tests for behaviour you fix, where the project has tests for that area.

## Step 5: Gates and commits

- **Gates on every round with changes**, from the profile: lint/format fix, typecheck, and the
  tests for the touched packages or files. Do not truncate gate output or ignore exit codes.
  A red gate means you are not done with the round.
- **Worktrees may skip git hooks.** If you work in a git worktree, run the lint and typecheck
  gates by hand, and run `git status -sb` after you commit to check HEAD is not detached.
- **Additive commits only.** Never amend, rebase or force-push a branch that is on the remote.
  Fix forward with new commits. Force-push only if the user asks.
- Commit messages follow the profile's commit style and describe the real fixes (for example
  `fix(pins): sort schema keys before hashing`). Do not use "address review" as the whole
  message.
- **Push:** follow the profile. Default: push once at the end, and only if the branch already
  tracks a remote. Exception: when Step 5b posts a resolution summary, push the round's
  commits first, so the commit SHAs in the comment resolve on the PR. If a PR exists but the
  local branch has no upstream, set it first: `git push -u origin HEAD:<head>`, where `<head>` is
  the PR's head branch (`gh pr view --json headRefName -q .headRefName`). If that push is not
  possible, post the resolution summary without commit links, and say in it that the commits
  are not on the PR.

## Step 5b: Post the round to the PR

Skip this step when there is no PR, or with `--no-post`. Each round posts **two** comments:

1. **The review report**, right after the review: the `review-pr` report as printed, with the
   heading `Code Review: PR #<n>, polish round <r>`, the reviewed commit SHA, the method and
   tier, every finding with its tags, file and line, and the verdict line. Add one line at the
   end that says a resolution summary follows.
2. **The resolution summary**, after the round's fixes are committed, the gates are green and
   the commits are pushed (or Step 5 applies when they cannot be pushed). Heading:
   `Resolution: PR #<n>, polish round <r>`. Content:
   - the fix commits (SHA and subject),
   - a table with one row per finding: number, tags, severity, short finding, disposition
     (`fixed`, `already-done`, `non-issue`, `declined`), and the commit or the reason,
   - for every `non-issue` and `declined` row, the full technical reason (the same text as in
     the ledger),
   - the gate results for the round (commands, pass counts, exit codes),
   - one line on what comes next (the next round, or the stop condition that was met).

Write both comments for a human reviewer who did not see this session. Refer to findings as
"finding 3", never `#3`, because `#<n>` links to GitHub issues and PRs. Follow any user rules
for published text (for example a cleaning step) before you post. Use
`gh pr comment <n> --body-file <file>`, and keep the file outside the repo.

Never edit or delete an earlier round's comments. If a later round changes a disposition,
say so in that round's resolution summary.

### A REQUEST CHANGES in the middle of the loop is real

A round can go from APPROVE back to REQUEST CHANGES. There are two real reasons, and neither is
noise:
- **Your last change had a consequence.** A fix can add a new defect that the next full pass
  catches.
- **Reviews are not deterministic.** The same diff reviewed twice gives different findings. A
  real issue missed in round 1 can show up in round 3, even in code you did not touch. Check
  it on its merits. Do not dismiss it because "earlier rounds were fine with it".

## Step 6: Stop and report

Stop when the latest round on the current HEAD is **APPROVE** and every remaining finding is an
optional Minor or Nit with a disposition. A full re-read will almost always find *some* new
optional nit, so "zero findings" is not the target. "Only optional nits remain" is. Do not chase
optional nits forever. When you decline them, give the reason (often the "fix" makes the code
harder to read).

A **COMMENT** verdict is not a stop point. It means the review was incomplete. Run the round
again, and escalate if it is incomplete twice.

Also stop when you reach the round cap, or when the same finding keeps coming back after two
honest attempts. Escalate it to the user with both positions.

Report to the user:
- the final verdict and the HEAD sha it applies to,
- the round history (round, tier or method, verdict, findings fixed and declined),
- the remaining optional nits, with your recommendation for each,
- the final `git diff --stat origin/<base>...HEAD`,
- the ledger path,
- whether you pushed.

Unless `--no-post` was given (or the profile turns posting off), and a PR exists, post one final
PR comment: the round history (round, method and tier, verdict, findings fixed and declined),
every declined finding with its reason, the final verdict with its HEAD SHA, and the remaining
optional nits. Write it for a human reviewer.

## Step 7: Hand off. Never merge.

- Do not merge, and do not approve your own PR. Report that the branch is polished and hand it
  over.
- A local APPROVE is not a GitHub approval. Branch protection still needs a human reviewer and
  CI. If the profile defines a CI trigger (for example a label), tell the user. Apply it only if
  the profile or the user says to.
- If the diff adds a new environment variable, flag it. Do not suggest the PR is ready to merge
  until the user confirms the variable exists in every deployed environment.

## The rules to keep in mind every round

- Verify every finding against the live file before you fix or decline it.
- One disposition per finding, with a reason, written to the ledger before the next round.
- Small, in-scope fixes go in this branch. No lazy deferrals.
- Every round reviews the whole branch. Any new commit needs a new round.
- Gates green before each round ends. Additive commits only.
- With a PR, post each round's review report and resolution summary as PR comments.
- A mid-loop REQUEST CHANGES is real.
- Stop at "only optional nits". COMMENT means incomplete, not passed.
- No cron or timer to wait for agents.
- Never merge.
