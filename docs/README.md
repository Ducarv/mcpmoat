# mcpmoat documentation index

This page is the index. Each topic has one owner doc. Update the owner doc. Do not copy its text.

## Topic to owner

| Topic | Owner |
|---|---|
| Product pitch, install and usage | [README.md](../README.md) |
| Requirements, milestones and FR/NFR IDs | [docs/PRD.md](PRD.md) |
| Threat model | [docs/PRD.md](PRD.md#53-threats) |
| Package layout and data flow (docs/PRD.md section 8 is the target design) | [docs/ARCHITECTURE.md](ARCHITECTURE.md) |
| JSON output schema and versioning (it links the schema file) | [docs/ARCHITECTURE.md](ARCHITECTURE.md#json-output) |
| Commands (gates) | [CONTRIBUTING.md](../CONTRIBUTING.md#checks) |
| Rule authoring | [CONTRIBUTING.md](../CONTRIBUTING.md#contributing-a-rule) |
| PR docs rule | [CONTRIBUTING.md](../CONTRIBUTING.md#pull-requests) |
| Conventions (code style, git, language, agent routing, review, release notes) | [.agents/project.md](../.agents/project.md) |
| Security reporting | [SECURITY.md](../SECURITY.md) |
| How stdio servers start | [docs/stdio-servers.md](stdio-servers.md) |
| Competitor study | [docs/competitors.md](competitors.md) |
| Claude Code entry point and issue labels | [CLAUDE.md](../CLAUDE.md) |
| Test fixtures (servers) | [testdata/servers/README.md](../testdata/servers/README.md) |
| Test fixtures (T4 and T5 configs) | [dangerous](../testdata/configs/dangerous/README.md) and [typosquat](../testdata/configs/typosquat/README.md) |

## Other files

- [bug_report.md](../.github/ISSUE_TEMPLATE/bug_report.md) and [new_rule.md](../.github/ISSUE_TEMPLATE/new_rule.md): issue forms.
- [.github/pull_request_template.md](../.github/pull_request_template.md): the PR description form.
- [.claude/agents/](../.claude/agents/) and [.claude/skills/](../.claude/skills/): agent and skill definitions.
  They own no other topic.
