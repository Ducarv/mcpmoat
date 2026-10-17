---
name: commit
description: Create a git commit with a well-crafted conventional commit message based on the actual staged changes. Runs a security review first when sensitive files are staged.
allowed-tools: [Bash, Read, Glob, Agent]
---

# Commit

Create a commit whose message describes the work that was actually done.

## Project profile

Read `.agents/project.md` at the repo root first, if it exists. Its **Git and pull requests**
section overrides the defaults below (commit style, scopes, issue suffix, attribution lines).
If the file is missing, follow the defaults and match the style of recent `git log` subjects.

## Tool notes

This skill works in any agent tool that reads `SKILL.md` files. Where the tools differ:

- **Invocation and arguments.** Claude Code: `/commit <args>`. Codex: `$commit <args>`. As a plugin, both tools
  also accept the `workflow:` prefix (`/workflow:commit`, `$workflow:commit`). Use the text the user gave after the skill name.
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

## Steps

### 1. Security review of sensitive files

Check whether any staged file matches a sensitive pattern:

```bash
git diff --cached --name-only | grep -iE "(auth|login|session|payment|billing|crypto|password|secret|token|api[-_]?key|credential|webhook|\.env)" || true
```

Add any extra tokens listed under **Review > Extra sensitive path tokens** in the profile.

If there are matches:
- Spawn the `review-security` agent on the staged changes (`git diff --cached`).
- **Critical** findings: block the commit and ask the user to fix them.
- **Should-fix** findings: warn the user and ask for confirmation before you continue.
- **Minor / Nit** findings: mention them to the user and continue.

If there are no matches, go to the next step.

### 2. Analyse the changes

```bash
git diff --cached --stat
git diff --cached
git diff --stat          # unstaged changes, in case something was forgotten
git log -10 --oneline    # house style for subjects
```

Understand which files changed, what behaviour was added, fixed or changed, and why.

### 3. Stage files if needed

If unstaged changes clearly belong with the staged ones, ask the user before you add them.
Stage files by name. Do not use `git add -A` unless the user asks.

### 4. Write the message

The message must describe the real diff. Never guess.

```
<type>(<optional scope>): <concise summary>

<optional body: why, if it is not obvious>
```

| Type | Use for |
|---|---|
| `feat` | New feature or behaviour |
| `fix` | Bug fix |
| `refactor` | Restructure with no behaviour change |
| `perf` | Performance improvement |
| `test` | Add or update tests |
| `docs` | Documentation only |
| `chore` | Maintenance: dependencies, config, tooling |
| `ci` | CI/CD changes |
| `style` | Formatting only |

Good:
- `feat: expire unpaid checkouts after 15 minutes`
- `fix(api): prevent duplicate invoices for the same checkout`
- `refactor: extract payment validation into a shared helper`

Bad:
- `fix: fix bug` (which bug?)
- `update code` (what update?)
- `wip` (not a message)

### 5. Create the commit

Use a heredoc so multi-line messages keep their formatting:

```bash
git commit -m "$(cat <<'EOF'
<type>(<scope>): <summary>

<body>
EOF
)"
```

Add attribution lines only if the profile (or the user's own instructions) asks for them.

## Rules

- Summary line under 72 characters, imperative mood ("add", not "added").
- If the changes cover unrelated concerns, suggest separate commits.
- Never create empty commits.
- Never amend, rebase or force-push unless the user asks.
- If a pre-commit hook fails, fix the cause and make a new commit. Do not bypass hooks
  with `--no-verify` unless the profile or the user allows it.
