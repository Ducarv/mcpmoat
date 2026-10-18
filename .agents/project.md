# Project profile: mcpmoat

The agents and skills in `.claude/` read this file. Its sections override their generic defaults.

## Stack

- Language: Go (version pinned in `go.mod`).
- CLI: standard library `flag`. No cobra.
- MCP: `github.com/modelcontextprotocol/go-sdk`, isolated behind an interface in `internal/inspect`.
- Rules: YAML files in `rules/`, embedded with `go:embed`.
- No database, no frontend, no Node.js tooling.

## Commands

| Purpose | Command |
|---|---|
| Format check | `gofmt -l .` (must print nothing) |
| Format fix | `gofmt -w .` (or `golangci-lint fmt`) |
| Module check | `go mod tidy && git diff --exit-code -- go.mod go.sum` |
| Typecheck | `go build ./... && go vet ./...` |
| Lint | `golangci-lint run ./...` (v2 config in `.golangci.yml`) |
| Vulnerabilities | `govulncheck ./...` |
| Tests (all) | `go test -race -shuffle=on ./...` |
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
  `t.Context()`; fixtures under `testdata/`; no `time.Sleep` for synchronisation.
- `os.Exit` only in `main`; stdout for data, stderr for logs and warnings.
- `//nolint` only with the linter name and a reason.
- Never print, log or store secret values from client configs. Print keys only.
- No telemetry. No network calls except configured servers and, behind `--llm`, the LLM provider.
- Minimal, pinned dependencies. Ask before adding one.

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

## Git and pull requests

- Default PR base branch: `main`.
- Branch names: `feat/<issue>-<slug>`, `fix/<issue>-<slug>`, `chore/<issue>-<slug>`, `docs/<issue>-<slug>`.
- Commit style: Conventional Commits. Scopes: `cli`, `discover`, `inspect`, `rules`, `pins`,
  `report`, `release`, `ci`, `docs`.
- Issue link: `Closes #<n>`.
- PR template: `.github/pull_request_template.md`. Add a `## Release Notes` section after it.
- CI trigger: none (CI runs on every pull request).

## Release notes

- Required for every PR.
- Audience: developers who run the `mcpmoat` CLI.
- Name the command, flag or rule ID that changed. Internal changes start with `Internal:`.

## Review

- Extra sensitive path tokens: `inspect`, `exec`, `env`, `pins`, `hash`, `release`, `goreleaser`,
  `workflows`.
- Path tokens to ignore: none.
- Project review criteria:
  - Every rule has `should_match` and `should_not_match` cases (NFR-05).
  - stdio servers run with a scrubbed environment and the exact configured command (NFR-04).
  - Exit-code contract: 0 / 1 / 2 (FR-16).
  - Code sits in the package the PRD architecture assigns (`docs/PRD.md`, section 8).

## Local review loop

- Max rounds: 5.
- Push: at the end, only if the branch tracks a remote.
- Post a disposition comment on the PR: yes.

## Writing

- English for code, docs, issues, commits.
- Plain words, short sentences. Avoid em dashes.
