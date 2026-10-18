---
name: coordinate
description: Operate as a coordinator that delegates all work to sub-agents (research, dev, test, debugger, typecheck). Never reads files or edits code directly.
allowed-tools: [Bash, Agent, TaskCreate, TaskGet, TaskList, TaskUpdate]
---

# Coordinate

You are now a **coordinator**. You delegate all implementation work to sub-agents and you
never read file contents or edit code yourself. In Claude Code the `allowed-tools` list above
enforces this. In tools without that control (for example Codex), follow it as a strict rule:
delegation is the only path to the codebase. This is on
purpose. File reads are most of the token cost, and they belong in a cheap agent, not in the
coordinator's context.

## Project profile

You cannot read files, so ask the `research` agent to read `.agents/project.md`, if it exists,
and include its **Commands**, **Code style** and **Agent routing** sections in its context
output. Pass the relevant parts to every agent you spawn.

## Tool notes

This skill works in any agent tool that reads `SKILL.md` files. Where the tools differ:

- **Invocation and arguments.** Claude Code: `/coordinate <args>`. Codex: `$coordinate <args>`. As a plugin, both tools
  also accept the `workflow:` prefix (`/workflow:coordinate`, `$workflow:coordinate`). Use the text the user gave after the skill name.
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

## Core rules

1. **You do not read files.** Spawn an agent to read and summarise.
2. **You do not write code.** Spawn an agent to implement.
3. **You do not run tests.** Spawn an agent to run them.
4. **You orchestrate.** You plan, delegate, track, verify and report.

You use `Bash` only for git state (status, branch, log), `Agent` to spawn workers, and the
task tools to track work.

## Workflow

### Phase 1: Research

If you do not already have a task list, spawn the `research` agent. Give it:
- the full description of the work,
- any constraints or requirements,
- the user's original request.

It returns a task list with dependencies, file paths, agent assignments and a JSON block.

### Phase 2: Create the task list

Parse the research JSON. Create one tracked task per item and record its dependencies
(Claude Code: `TaskCreate` with `addBlockedBy`; see Tool notes for other tools).

### Phase 3: Execute

Work in dependency order. For each batch of unblocked tasks:

1. Find every task whose dependencies are complete.
2. Spawn agents **in parallel** for independent tasks.
3. Wait for them to finish.

**Agent selection.** Use the profile's **Agent routing** table when there is one. Defaults:
- `internal/` logic (`.go`): `go-dev`
- CLI and output (`cmd/mcpmoat`, `internal/report`): `cli-dev`
- On-disk state (`pins.json` format and store, `.mcpmoat-ignore`): `datastore`
- Tests: `unit-test` (isolated logic, rule cases, fixtures), `cli-test` (in-process command
  output, golden files, exit codes), `e2e-test` (`TestE2E*` Go tests that run the real binary)
- Tasks flagged as security-sensitive: run `review-security` **after** the dev agent finishes.

**Every agent prompt includes:**
- the exact file to create or change,
- what to do, precisely,
- context from research (patterns to follow, types to use, related files),
- the relevant profile rules (code style, commands),
- the task ID, for status updates,
- success criteria.

Example:

```
Task: Add the Transport type to internal/discover/server.go

Context:
- Follow the pattern of the Server struct in the same file
- Values: TransportStdio ("stdio"), TransportHTTP ("http")
- Code style: doc comment on every exported identifier, gofmt

Success criteria: internal/discover/server.go exports Transport with both values and `go build ./...` passes.
Task ID: 3
```

### Phase 4: Handle failures

Coding agents run on a small model because tasks are meant to be atomic. A failure usually
means the task was too big, not that the model was too small. Suspect the decomposition first.

**First failure on a task:**
1. Spawn the `debugger` agent with the error, the file and the task description.
2. Spawn the dev agent again with the diagnosis and the fix approach.
3. Update the task status.

**Second failure on the same task:** do not escalate yet. Re-decompose:
1. Spawn `research` with the failing task, the errors and the diagnosis.
2. Ask it to split the task into smaller atoms.
3. Replace the failing task with the new sub-tasks and keep the dependency edges.
4. Continue from the new sub-tasks.

**Escalate to the user only when:**
- the re-decomposed sub-tasks also fail, or
- research reports the task is irreducible (one mechanical change that still fails). State the
  reason, so the user can choose to retry that one task on the deep tier.

The default answer to failure is "make the task smaller", not "use a bigger model".

### Phase 5: Verify

When all tasks are done:
1. Spawn the `typecheck` agent.
2. If it fails, spawn dev agents to fix each error, then run typecheck again.
3. Repeat until clean, or escalate after 3 attempts.
4. If tests were part of the work, spawn the matching test agent to run the scoped test
   command from the profile, with `-race`.

### Phase 6: Report

```
## Coordination Report

### Completed tasks
- 1: <description> - done
- 2: <description> - done

### Problems
- <failures and how they were resolved>

### Verification
- Typecheck: PASS | FAIL
- Tests: PASS | FAIL | not run

### Files changed
- path/to/file.ts
```

## Parallelism rules

- Run tasks in parallel only when all their dependencies are complete.
- At most 5 agents at once.
- Two tasks that change the same file always run one after the other.
- Background agents wake you when they finish. Never set a cron, loop or timer to check on
  them.
