# Project profile: mcpmoat

The agents and skills in `.claude/` read this file, and `CLAUDE.md` imports it. It is also the
conventions page for contributors. Its sections override the generic defaults of the agents.

This file owns conventions, agent routing, release notes and review criteria. It links to
[CONTRIBUTING.md](../CONTRIBUTING.md#checks) for the gates and to [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for the layout.

## Stack

- Language: Go (version pinned in `go.mod`).
- CLI: standard library `flag`. No cobra.
- MCP: `github.com/modelcontextprotocol/go-sdk`, isolated behind an interface in `internal/inspect` (NFR-06).
- Package layout and data flow: [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md).
- Rules: YAML files in `rules/`, embedded with `go:embed`.
- No database, no frontend, no Node.js tooling.

## Commands

| Purpose | Command |
|---|---|
| Gates (the local checks that CI also runs) | run the block in [CONTRIBUTING.md](../CONTRIBUTING.md#checks) |
| Format fix | `gofmt -w .` (or `golangci-lint fmt`) |
| Typecheck | `go build ./... && go vet ./...` |
| Tests (scoped) | `go test -race ./internal/<pkg>/ -run '<TestName>' -v` |
| E2E scenario | `go test ./cmd/mcpmoat/ -run 'TestE2E<Name>' -v` |
| Update golden files | `go test ./<pkg>/ -update` (review the diff afterwards) |
| Fuzz a parser | `go test -fuzz=FuzzX -fuzztime=30s ./<pkg>/` |

## Code style

- `gofmt` output. Doc comments on every exported identifier.
- Return and wrap errors with `%w`; never panic on bad input.
- `context.Context` first for anything that does I/O or can block.
- Small interfaces defined by the consumer; no global mutable state.
- Table-driven tests; `t.Parallel()` where safe (never with `t.Setenv`); `t.TempDir()`,
  `t.Context()`; fixtures under `testdata/`; no `time.Sleep` for synchronisation. Tests never touch
  the real `$HOME` or real client configs: use `t.TempDir()` and `t.Setenv()`.
- `os.Exit` only in `main`; stdout for data, stderr for logs and warnings.
- `//nolint` only with the linter name and a reason.
- Never print, log or store env or header values from client configs, whether or not they look
  secret. Print keys only.
- No telemetry. No network calls except configured servers and, behind `--llm`, the LLM provider.
- Minimal, pinned dependencies. Ask before adding one.
- stdio servers run with exactly the configured command and a scrubbed environment (NFR-04).
- Exit codes: 0 no findings, 1 findings at or above `--fail-on`, 2 execution error (FR-16).
- Every rule is one YAML file plus tests with `should_match` and `should_not_match` cases (NFR-05).
- The repo owner is learning Go. Prefer clear, idiomatic standard-library code over clever code.
  Explain non-obvious Go idioms in PR descriptions.

## Agent routing

| Work | Agent |
|---|---|
| `internal/` logic (`.go`) | `go-dev` |
| `cmd/mcpmoat`, `internal/report` (flags, output, exit codes) | `cli-dev` |
| `pins.json` format and store, `.mcpmoat-ignore` | `datastore` |
| Unit `_test.go`, `rules/*.yaml` cases, `testdata/` fixtures | `unit-test` |
| In-process CLI output, golden files, exit-code tables | `cli-test` |
| `TestE2E*` tests in `cmd/mcpmoat/e2e_test.go` against the real binary | `e2e-test` |
| Root-cause diagnosis | `debugger` |
| Final compile and vet check | `typecheck` |
| Security-flagged tasks after the dev agent | `review-security` |
| Docs: `*.md`, `docs/`, `.github/` templates, `.claude/` agent and skill text | `general-purpose` (no dedicated docs agent; follow the owner docs in [docs/README.md](../docs/README.md)). A task that edits `.claude/agents/review-*.md`, a review step of a skill, `.agents/project.md` or `CLAUDE.md` is security-flagged: run `review-security` after it. |

## Git and pull requests

- Default PR base branch: `main`.
- Branch names: `feat/<issue>-<slug>`, `fix/<issue>-<slug>`, `chore/<issue>-<slug>`, `docs/<issue>-<slug>`.
- Commit style: Conventional Commits. Scopes: `cli`, `discover`, `inspect`, `rules`, `pins`,
  `report`, `release`, `ci`, `docs`.
- Issue link: `Closes #<n>`.
- PR template: `.github/pull_request_template.md`. Add a `## Release Notes` section after it.
- CI trigger: none (CI runs on every pull request).
- Every PR updates its owner doc, or says why no doc change is needed: see
  [CONTRIBUTING.md](../CONTRIBUTING.md#pull-requests).

## Release notes

- Required for every PR.
- Audience: developers who run the `mcpmoat` CLI.
- Name the command, flag or rule ID that changed. Internal changes start with `Internal:`.

## Review

- Extra sensitive path tokens: `inspect`, `exec`, `env`, `pins`, `hash`, `release`, `goreleaser`,
  `workflows`, `.agents`.
- Path tokens to ignore: none.
- Project review criteria:
  - Code follows the Code style rules on rule tests (NFR-05), the scrubbed stdio environment
    (NFR-04) and the exit-code contract (FR-16).
  - Code sits in the package that [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) assigns. PRD
    section 8 (`docs/PRD.md`) is the target design.
  - The PR updates the owner doc (see [docs/README.md](../docs/README.md)) or states why not
    ([CONTRIBUTING.md](../CONTRIBUTING.md#pull-requests)).

## Local review loop

- Max rounds: 5.
- Push: at the end, only if the branch tracks a remote.
- Post a disposition comment on the PR: yes.

## Writing

- English for code, docs, issues, commits.
- Plain words, short sentences. Avoid em dashes.
