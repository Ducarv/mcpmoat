# CLAUDE.md

Guidance for Claude Code sessions in this repository.

## Project summary

mcpmoat is an offline Go CLI that scans MCP servers for malicious or tampered tools (`mcpmoat scan`).
The source of truth is **[docs/PRD.md](docs/PRD.md)**. Issues cite its IDs: FR-01 to FR-17, NFR-01 to
NFR-07, threats T1 to T5, milestones M1 to M8. Read the cited section before you start an issue.

## Where to find things

- [docs/README.md](docs/README.md): index of all docs. Start here.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): package layout and data flow.
- [CONTRIBUTING.md](CONTRIBUTING.md#checks): commands and gates to run before a PR.
- [.agents/project.md](.agents/project.md): conventions, agent routing and review criteria.
- [docs/PRD.md](docs/PRD.md): requirements and threat model.
- [SECURITY.md](SECURITY.md): how to report a vulnerability.

Conventions are in the [Code style](.agents/project.md#code-style) section of `.agents/project.md`.
The repo owner is learning Go, so prefer clear, idiomatic standard-library code. Never forget:
secrets (print keys only), no telemetry, ask before you add a module.
Every PR updates the docs. The rule is in [CONTRIBUTING.md](CONTRIBUTING.md#pull-requests).

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
[Nodeglade/platform](https://github.com/Nodeglade/platform/tree/main/.claude) and were ported to Go.
The Go practices come from [samber/cc-skills-golang](https://github.com/samber/cc-skills-golang) and
[eduardo-sl/go-agent-skills](https://github.com/eduardo-sl/go-agent-skills) (both MIT),
[Effective Go](https://go.dev/doc/effective_go),
[Go Code Review Comments](https://go.dev/wiki/CodeReviewComments) and the
[Google Go style guide](https://google.github.io/styleguide/go/).

Agent definitions are in `.claude/agents/` and skill definitions in `.claude/skills/`. They read the
project profile in [`.agents/project.md`](.agents/project.md).
