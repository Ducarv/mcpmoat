# CLAUDE.md

Guidance for Claude Code sessions in this repository.

## Project summary

mcpmoat is an offline Go CLI that protects the individual developer against malicious or tampered
MCP servers. Phase 1 is a scanner (`mcpmoat scan`): it discovers MCP servers configured for Claude
Code, Cursor and Codex, connects to them, reads their tools, prompts and resources, applies YAML rules
and native heuristics (threats T1 to T5), and detects rug pulls with per-tool hashes (pins).

The source of truth is **[docs/PRD.md](docs/PRD.md)**. Issues cite its IDs: FR-01 to FR-17,
NFR-01 to NFR-07, threats T1 to T5, milestones M1 to M8. Read the cited section before you start an
issue.

## Package layout

```
cmd/mcpmoat/          CLI entry (standard library: flag)
internal/discover/    config readers: claudecode, cursor, codex
internal/inspect/     connects to servers, extracts tools, prompts, resources
internal/rules/       loads YAML, applies regex and heuristics
internal/pins/        hashes, diff and pins.json
internal/report/      terminal and JSON output
internal/termsafe/    escapes untrusted text for the terminal (used by discover and report)
rules/                built-in rules (go:embed)
testdata/servers/     malicious example MCP servers, for tests and demo
docs/                 PRD and other documentation
```

## Commands

```sh
gofmt -l .                                             # must print nothing
go mod tidy && git diff --exit-code -- go.mod go.sum   # module files are tidy
go build ./...
go vet ./...
golangci-lint run ./...
go test -race -shuffle=on ./...
govulncheck ./...
```

## Conventions

- **CLI:** Go standard library `flag`. No cobra (may change later, see PRD section 14).
- **MCP:** the official `github.com/modelcontextprotocol/go-sdk`, kept behind an interface in
  `internal/inspect` so spec changes stay local (NFR-06).
- **Dependencies:** minimal and pinned. Ask before you add a module.
- **No telemetry.** No network calls except to configured MCP servers and, only with the opt-in
  `--llm` flag, the LLM provider (NFR-01).
- **Secrets:** never print, log or store env or header values from client configs. Keys only.
- **Running servers:** stdio servers run with exactly the configured command and a scrubbed
  environment (NFR-04).
- **Rules:** every rule needs positive (`should_match`) and negative (`should_not_match`) tests
  (NFR-05). A rule is one YAML file plus its tests.
- **Tests:** table-driven, `t.TempDir()`, `t.Setenv()`; never touch the real `$HOME`.
- **Exit codes:** 0 no findings, 1 findings at or above `--fail-on`, 2 execution error (FR-16).
- **Language:** English for code, comments, docs, issues and commits. Conventional Commits.
- The repo owner is learning Go. Prefer clear, idiomatic standard-library code over clever code,
  and explain non-obvious Go idioms in PR descriptions.

## Issue labels and how to pick up work

Every work issue has exactly one `model:*` label and `effort:high`:

| Label | Meaning |
|---|---|
| `model:haiku` | Basic, repetitive or boilerplate task. Run with Claude Haiku. |
| `model:sonnet` | Feature or non-trivial work. Run with Claude Sonnet. |
| `model:opus` | Bug, security-critical or core-design work. Run with Claude Opus. |
| `effort:high` | Run with high reasoning effort. |

Pick up an issue by its `model:*` label: run the session (or the agents) on that model with high
effort. The `issue2pr` skill applies this automatically.

Other labels:

| Label | Meaning |
|---|---|
| `epic` | Tracks a milestone; has sub-issues. Not a work item (no `model:*` label). |
| `type:feature`, `type:chore`, `type:rule`, `type:test`, `type:docs` | Kind of work |
| `bug` | Something broken |
| `security` | Affects mcpmoat's own security |
| `area:cli`, `area:discover`, `area:inspect`, `area:rules`, `area:pins`, `area:report`, `area:release` | Package or area |
| `phase:1` to `phase:4` | Roadmap phase |
| `good first issue`, `help wanted`, `documentation` | Community |

GitHub milestones match PRD milestones: `M1 Skeleton` to `M8 Optional LLM`, plus `Phase 2+ Backlog`.

## Claude Code setup

The agents and skills in `.claude/` came from
[Nodeglade/platform](https://github.com/Nodeglade/platform/tree/main/.claude). The full set was
ported to Go: same roles, Go content. The Go practices come from
[samber/cc-skills-golang](https://github.com/samber/cc-skills-golang) and
[eduardo-sl/go-agent-skills](https://github.com/eduardo-sl/go-agent-skills) (both MIT), Effective Go,
Go Code Review Comments and the Google Go style guide. They read the project profile in
[`.agents/project.md`](.agents/project.md) (commands, code style, agent routing, git conventions).

Agents (`.claude/agents/`), with the Nodeglade agent each one replaces:

- `research`: explores the code and splits a task into atomic, one-file tasks with dependencies.
- `go-dev` (was `typescript-dev`): one atomic task on one `.go` file in `internal/`.
- `cli-dev` (was `react-dev`): the user-facing layer: `flag` subcommands, `run()` pattern, exit
  codes, stdout/stderr, colour and TTY, escaping untrusted text.
- `datastore` (was `database`): `pins.json` format, versions and migrations, atomic writes,
  permissions, XDG paths, `.mcpmoat-ignore`.
- `unit-test`: table-driven Go tests, `t.Parallel` rules, fuzz targets, benchmarks, rule cases.
- `cli-test` (was `component-test`): in-process CLI output tests with golden files and exit-code
  tables.
- `e2e-test` (was Playwright `e2e-test`): `testscript` (`.txtar`) journeys against the real binary
  and fixture MCP servers.
- `debugger`: finds the root cause of a failure with the Go toolbox (`-race`, delve, pprof);
  does not fix code.
- `typecheck`: runs the Go gates (`go mod tidy` check, build, vet, golangci-lint, govulncheck).
- `review-security`: security review of a diff (gosec, govulncheck, exec, paths, secrets, NFR-01).
- `review-logic`: correctness review of a diff (races, goroutine leaks, errors, context, nil).
- `review-quality`: maintainability review against Go idioms and the PRD layout.

Skills (`.claude/skills/`):

- `issue2pr`: full pipeline from a GitHub issue to a PR; honours the `model:*` label.
- `coordinate`: orchestrates the agents above; never edits code itself.
- `review-pr`: three parallel review agents (security, logic, quality) with risk tiers.
- `polish-pr`: local review loop until only optional nits remain; never merges.
- `commit`: conventional commit from the staged diff; security review for sensitive files.
- `pr`: opens a PR with Summary, Testing and Release Notes.
- `deai-writer`: rewrites AI-sounding prose (README, posts, launch drafts).

All skills route work to the Go agents above and run the Go gates from the profile.
