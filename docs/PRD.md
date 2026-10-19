# mcpmoat: Product Requirements Document

| Field | Value |
|---|---|
| Spec version | 0.2 |
| Date | 2026-10-17 |
| Status | All decisions closed. Phase 1 in progress. |
| Scope of this document | Phase 1 (scanner) in detail; phases 2 to 4 as roadmap only |

Requirement IDs in this document are stable. Issues, pull requests and commit messages refer to them
(`FR-07`, `NFR-04`, `T2`, `M5`). Do not renumber them.

---

## 1. Overview

### 1.1 One-line vision

A Go command-line tool that protects **the individual developer** against malicious or tampered MCP
servers. It starts as a **scanner** and evolves, in phases, into a **local firewall**, a **trust
score** and **data-flow control**. Everything runs 100% offline, with no account and no telemetry.

### 1.2 Problem

AI coding clients (Claude Code, Cursor, Codex) load MCP servers from configuration files on the
developer's machine. Each server exposes tools whose names, descriptions and input schemas go
straight into the model's context. A malicious or compromised server can:

- hide instructions for the model inside a tool description or schema (tool poisoning),
- change its tools after the developer has approved them (rug pull),
- try to redefine the behaviour of tools from other, trusted servers (shadowing),
- be configured in an unsafe way (plain `http://`, plaintext secrets, unpinned packages),
- impersonate a popular server with a near-identical name (typosquatting).

Existing tools focus on enterprises or require an account or a cloud service. The individual
developer has no simple, offline, open tool to check what their clients will load.

### 1.3 Target user

An individual developer who uses one or more AI coding clients with MCP servers on their own
macOS or Linux machine, and who wants a quick, local, scriptable check that fits into a shell, a git
hook or CI.

---

## 2. Goals and non-goals

### 2.1 Goals (phase 1)

- G1. Discover every MCP server configured for Claude Code, Cursor and Codex on the machine, with no
  arguments (`mcpmoat scan`).
- G2. Read the tools, prompts and resources each server exposes, through the official MCP Go SDK.
- G3. Detect the five phase 1 attacks T1 to T5 with transparent, testable YAML rules and native
  heuristics.
- G4. Detect rug pulls by pinning a hash of every tool and reporting changes with a diff.
- G5. Give clear output for humans (coloured terminal) and machines (versioned JSON, exit codes).
- G6. Ship as a single static binary through GitHub Releases, Homebrew and `go install`.
- G7. Stay offline, account-free and telemetry-free.

### 2.2 Non-goals (phase 1)

- Enterprise features: SSO, RBAC, central dashboard.
- Windows support.
- Clients other than Claude Code, Cursor and Codex.
- SARIF output.
- Docker or npm distribution.
- Any GUI or cloud service.
- Analysis of server source code.
- Protection against prompt injection carried by **content** (planned for phase 4).

See section 12 for the full out-of-scope list.

---

## 3. Decisions log

| Topic | Decision | Rationale / accepted trade-off |
|---|---|---|
| Audience | Individual developer, on their own machine | The audience competitors left aside. Gives up enterprise features (SSO, RBAC). |
| Long-term scope | 4 pillars: scanner, firewall, trust score, data flow | Broad vision, delivered in phases that stand on their own. |
| Order | Scanner, then firewall, then score, then flow | Simplest to hardest. The scanner becomes the engine for later phases. |
| Phase 1 threat | Malicious or tampered server (tool poisoning, rug pull) | Detectable with rules and hashes. Prompt injection is phase 4. |
| Firewall behaviour | Quarantine new or changed servers; only warn otherwise | Protects without blocking daily use. |
| LLM use | Optional, off by default | Project stays offline and predictable. |
| Language | Go | Single binary and security ecosystem. Cost: learning curve (author comes from JavaScript). |
| Distribution | GitHub Releases, Homebrew, `go install` | No Docker or npm at first. |
| Supported clients | Claude Code, Cursor, Codex | VS Code, Claude Desktop, Windsurf later. |
| OS | macOS and Linux (amd64, arm64) | Windows later. |
| Output | Coloured terminal text and JSON | SARIF later. |
| Telemetry | None | Trust over metrics. |
| License | Apache-2.0 | Same as competitors; patent protection. |
| Language of artefacts | English (code, README, issues) | Reach. |
| Outreach | Short progress posts, a few per month, plus a strong launch at end of phase 1 | Visibility without stealing coding time. |
| Success | Learning and portfolio: phase 1 published and working | Does not depend on adoption. |
| Time | Under 5 h per week | Hence small phases; each milestone stands alone. |
| Name | `mcpmoat` | Checked: nothing with this name on GitHub. |
| Connect by default | Yes. `scan` connects to servers; `--no-connect` does static analysis only | Full value by default; opt-out for cautious users and CI. |
| CLI library | Go standard library `flag` | Simpler to learn. Can migrate to `cobra` if subcommands grow. |

---

## 4. Roadmap: the four phases

| Phase | Deliverable | Command |
|---|---|---|
| 1. Scanner (MVP) | Discover configured MCP servers, read their tools, apply rules, detect changes (rug pull) | `mcpmoat scan` |
| 2. Local firewall | Proxy between client and servers, with quarantine, tool allowlist and local log | `mcpmoat proxy`, `mcpmoat approve` |
| 3. Trust score | Before install, assess an MCP package: author, age, recent changes, install scripts, scanner result | `mcpmoat vet <package>` |
| 4. Data flow | In the proxy, tag data origin (public or private) and block dangerous combinations (the "lethal trifecta") | Proxy policies |

Only phase 1 is detailed in this document. Phases 2 to 4 get their own spec later. Phases 2 to 4
reuse `discover`, `inspect`, `rules` and `pins`. The phase 2 proxy calls the same rule engine on every
`tools/list`.

---

## 5. Phase 1 threat model

### 5.1 Assets

Credentials and data reachable by the AI agent on the developer's machine: tokens, email,
repositories, files.

### 5.2 Adversary

The author of an MCP server (or someone who compromised their package) who wants the model to run
hidden instructions or leak data.

### 5.3 Threats

| ID | Attack | Detection |
|---|---|---|
| T1 | Tool poisoning: hidden instruction in a tool's description or schema | Pattern rules: imperative phrases aimed at the model, mentions of other tools, "don't tell the user", invisible characters, very long text, base64 |
| T2 | Rug pull: the description, schema or annotations of a tool change after the pin | Per-tool hash stored in a pins file; differences raise an alert |
| T3 | Shadowing: a tool that tries to redefine another tool's behaviour ("when using send_email, always...") | Rule: description cites the name of a tool from another server |
| T4 | Dangerous config: remote server over `http://` without TLS, plaintext secret in config, unpinned package (`npx package@latest`) | Static config analysis |
| T5 | Basic typosquatting: name very close to a known server | Compare with a short list of popular servers (edit distance) |

### 5.4 Out of scope for phase 1

- Prompt injection coming from **content** (for example a GitHub issue the agent reads).
- Malware in server code (no source analysis).
- Unauthenticated servers on the network.
- Attacks on the AI client itself.

### 5.5 Stated limitation (must appear in the README)

The scanner reduces risk but does not guarantee safety. Rule-based detection has false positives and
false negatives.

A remote server can show the scanner a different tool list than it shows the real clients
(cloaking). mcpmoat does not name itself in its requests (generic User-Agent and MCP client name),
but a server can still tell clients apart in other ways, and the pins only cover what the scanner
sees.

---

## 6. Functional requirements (phase 1)

Each requirement has acceptance criteria written as testable statements. "Fixture" means a file or
fake server under `testdata/`.

### 6.1 Discovery

**FR-01: Auto-discover MCP configs.** Read Claude Code `~/.claude.json` and project `.mcp.json`;
Cursor `~/.cursor/mcp.json` and `.cursor/mcp.json`; Codex `~/.codex/config.toml`, `[mcp_servers]`
section.

- Given a home directory fixture with all five files, discovery returns every server from every file.
- Global and per-project entries in `~/.claude.json` are both returned, each tagged with its scope.
- A missing config file is skipped without an error.
- A malformed config file produces a per-file error in the output and does not stop discovery of
  other files.
- Each discovered server records its source file path and client (`claude-code`, `cursor`, `codex`).
- Tests use a temporary `HOME` and working directory, never the real ones.

**FR-02: `--config <file>`.** Analyse one specific file.

- `mcpmoat scan --config path/to/file` reads only that file and skips auto-discovery.
- The format (Claude Code JSON, Cursor JSON, Codex TOML) is detected from the content and file name.
- An unknown format exits with code 2 and a clear message naming the file.

**FR-03: List servers.** Show discovered servers with origin, type (stdio or http) and command.

- For each server the output shows: name, client, source file, transport (`stdio` or `http`), and the
  command plus arguments (stdio) or URL (http).
- Values of environment variables and headers are never printed; only their keys (masked values).

### 6.2 Inspection

**FR-04: Connect and list.** Connect to each server via MCP and list tools (with their
annotations), prompts, resources and resource templates (name, description, schema).

- Against the benign fixture server, inspection returns its exact tools, prompts, resources and
  resource templates with names, descriptions, input schemas and tool annotations.
- Both stdio and HTTP (streamable HTTP and SSE) transports work against fixture servers.
- Inspection uses `github.com/modelcontextprotocol/go-sdk`.

**FR-05: `--no-connect`.** Static config analysis only; executes no server.

- With `--no-connect`, no child process is started and no network connection is opened (asserted by
  a test).
- Config rules (target `config`) still run and report findings.

**FR-06: Per-server timeout and isolated failure.** Default timeout 10 s; one broken server does
not break the scan.

- `--timeout` accepts a Go duration; the default is `10s`.
- A fixture server that hangs is reported as timed out after the timeout, and the scan continues.
- A fixture server that crashes on start is reported as failed, and other servers are still scanned.
- A failed or timed-out server contributes an error entry to the report, not a crash.

### 6.3 Rules

**FR-07: YAML rules, embedded and external.** Rules live in YAML files, embedded in the binary and
loadable from a directory (`--rules <dir>`).

- The built-in rules in `rules/` are embedded with `go:embed` and load with no flags.
- `--rules <dir>` loads every `*.yaml`/`*.yml` file in the directory in addition to the built-ins.
- An invalid rule file fails with exit code 2 and names the file and field.
- Two rules with the same `id` are rejected.

**FR-08: Rule schema.** Each rule has `id`, `title`, `severity` (low, medium, high, critical),
`target` (description, schema, config), `match` (regex, word list or native heuristic) and
`references`.

- A rule missing a required field is rejected with a message that names the field.
- `severity` and `target` accept only the listed values.
- `match` supports at least `any_regex`, `all_regex`, `keywords` and named native heuristics.
- Regexes are compiled once at load time with Go's RE2 engine (linear time, no backtracking), and
  matched text has a size cap.

Example rule:

```yaml
id: MOAT-T1-003
title: Tool description tells the model to hide actions from the user
severity: high
target: description
match:
  any_regex:
    - '(?i)do not (tell|inform|mention).{0,30}user'
    - '(?i)without (telling|notifying) the user'
references:
  - https://invariantlabs.ai/blog/whatsapp-mcp-exploited
```

**FR-09: Initial rule set.** At least 15 rules covering T1 to T5.

- The embedded rule set has at least 15 rules.
- Every threat T1 to T5 has at least one rule or native check.
- Every rule has at least one `should_match` and one `should_not_match` test case (see NFR-05).

**FR-10: Ignore findings.** Ignore a specific finding via `.mcpmoat-ignore` or `--ignore <id>`.

- `--ignore MOAT-T1-003` suppresses all findings of that rule; the flag can repeat.
- `.mcpmoat-ignore` in the working directory supports one entry per line, comments with `#`, and
  entries scoped to a rule ID, optionally limited to a server and tool.
- Ignored findings do not affect the exit code and are counted as "ignored" in the summary.

### 6.4 Pins (rug-pull detection)

**FR-11: Store pins.** On first run, store the SHA-256 of each tool's name, description, schema and
annotations in `~/.config/mcpmoat/pins.json`. The annotations are the title and the four hints
`readOnlyHint`, `destructiveHint`, `idempotentHint` and `openWorldHint`. An absent hint is different
from a set hint.

- The hash input is a canonical serialisation: the same tool with JSON keys in a different order
  gives the same hash.
- A change of one character in name, description or schema gives a different hash.
- A change of one annotation hint gives a different hash.
- The pins file has a format version field and is written atomically (temp file plus rename).
- `XDG_CONFIG_HOME` is honoured when set.

Known limit: the Go SDK decodes `readOnlyHint` and `idempotentHint` as a plain `bool`. So for these
two hints, "absent" and "false" are the same. A change to `true` is always visible.

**FR-12: Detect changes.** On later runs, warn about new, removed or changed tools, showing the
text diff.

- Using the rug-pull fixture, the second run reports the changed tool with a unified text diff of the
  description and/or schema.
- New and removed tools are reported as separate change kinds.
- A changed tool is a finding with severity `high` (T2).

**FR-13: Accept changes.** `mcpmoat pin --accept <server>` accepts the new version.

- After `pin --accept <server>`, the next scan reports no pin changes for that server.
- Pins for other servers are not changed.
- Accepting an unknown server name exits with code 2.

### 6.5 Output

**FR-14: Terminal report.** Per-server summary, findings grouped by severity, colours (disable
with `--no-color`).

- Each finding shows rule ID, severity, server, tool (if any), a one-sentence risk and what to do.
- Findings are grouped and ordered by severity (critical first).
- `--no-color` and the `NO_COLOR` environment variable disable ANSI codes; output to a non-terminal
  has no colour.

**FR-15: `--json`.** Output with a stable, versioned schema.

- JSON output includes a `schema_version` field.
- A JSON Schema file for the output is published in `docs/`, and a test validates sample output
  against it.
- Field names do not change without a schema version bump.

**FR-16: Exit codes.** 0 no findings, 1 findings at or above `--fail-on` (default `high`),
2 execution error.

- No findings at or above the threshold: exit 0.
- At least one non-ignored finding at or above `--fail-on`: exit 1.
- Invalid flags, invalid rules, unreadable `--config`: exit 2.
- A per-server connection failure alone does not cause exit 2 (it is reported; see FR-06).
- Tests cover every branch, including `--fail-on low|medium|high|critical`.

### 6.6 Optional LLM

**FR-17: `--llm`.** Sends each tool description to a model and asks for a risk classification.
Off by default; key from an environment variable; README warns that this option **sends data off
the machine**.

- Without `--llm`, no LLM code path runs and no request is made (see NFR-01).
- With `--llm` and no API key in the environment, the command exits with code 2 and names the
  variable.
- With `--llm`, a warning that data leaves the machine is printed before any request.
- LLM output appears as findings with a distinct source marker and never removes rule findings.

---

## 7. Non-functional requirements

**NFR-01: Privacy.** No telemetry. No network connections besides configured servers and, only
with `--llm`, the LLM provider. A proxy that the user sets in `HTTP_PROXY` or `HTTPS_PROXY` is part
of the route to a configured server, so mcpmoat honours it (and `NO_PROXY`).

- A test runs a full scan with network access denied for anything other than fixture servers, and
  asserts no other connection is attempted. The test clears the proxy variables.

**NFR-02: Distribution.** Single static binary for macOS and Linux (amd64, arm64), published with
GoReleaser, Homebrew formula in an own tap, checksums and GitHub attestation.

- Release artefacts exist for darwin/amd64, darwin/arm64, linux/amd64, linux/arm64.
- Binaries are built with `CGO_ENABLED=0`.
- A `checksums.txt` file and GitHub artifact attestations are published with each release.
- `brew install <login>/tap/mcpmoat` installs the latest release.

**NFR-03: Performance.** A typical scan (up to 10 servers) finishes in under 15 s, mostly waiting
for servers to start. Analysis itself under 1 s.

- Benchmark: rule analysis of 10 servers with 20 tools each runs in under 1 s.
- Integration: scanning 10 fixture servers concurrently finishes in under 15 s.

**NFR-04: Project's own security.** stdio servers run without inheriting extra secrets and with
the same command the client would use. Minimal, pinned dependencies. `SECURITY.md` with a reporting
channel.

- A stdio server's environment contains only the variables declared in its client config plus a
  minimal safe base (for example `PATH`, `HOME`), asserted by a test.
- The executed command and arguments are exactly those in the client config.
- `go.mod` lists only needed dependencies; CI actions are pinned to commit SHAs.

**NFR-05: Quality.** Tests for every rule, with cases that must and must not fire. Fake MCP servers
(fixtures) reproducing T1 to T5. CI with `go test`, `go vet`, `golangci-lint`.

- `go test ./...` fails if any rule lacks a positive or a negative case.
- Fixture servers for T1 to T5 exist under `testdata/servers/`.
- CI runs `go test`, `go vet` and `golangci-lint` on macOS and Linux for every pull request.

**NFR-06: Compatibility.** Support the MCP spec versions in use (including 2026-07-28) via the
official Go SDK (`github.com/modelcontextprotocol/go-sdk`).

- Protocol details are isolated behind an interface in `internal/inspect`.
- Fixture servers cover the protocol versions the SDK negotiates.

**NFR-07: Usability.** `mcpmoat scan` with no arguments just works. Every finding explains the risk
in one sentence and says what to do.

- `mcpmoat scan` with no flags discovers, inspects and reports.
- Every rule has a non-empty one-sentence risk text and a remediation text (enforced by a test).

---

## 8. Architecture (phase 1)

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
```

| Package | Responsibility | Main requirements |
|---|---|---|
| `cmd/mcpmoat` | Parse flags with `flag`, dispatch `scan`, `pin`, `version`, `help`; map results to exit codes | FR-02, FR-05, FR-13, FR-16 |
| `internal/discover` | Read client config files into a common `Server` model | FR-01 to FR-03 |
| `internal/inspect` | Start or connect to servers with the Go SDK; list tools, prompts, resources; timeouts; scrubbed environment | FR-04, FR-06, NFR-04, NFR-06 |
| `internal/rules` | Load and validate YAML rules; run matchers and native heuristics; ignore list | FR-07 to FR-10 |
| `internal/pins` | Canonical hashing, `pins.json` store, change detection and diff | FR-11 to FR-13 |
| `internal/report` | Terminal and JSON rendering; JSON schema | FR-14, FR-15, NFR-07 |
| `internal/termsafe` | Escape untrusted text for the terminal (used by `discover` and `report`) | FR-14 |
| `rules/` | Built-in YAML rules and their test cases | FR-09, NFR-05 |
| `testdata/servers/` | Benign and malicious fixture servers | NFR-05 |

Data flow for `mcpmoat scan`:

1. `discover` returns a list of `Server` values.
2. Config rules run on each `Server` (always, also with `--no-connect`).
3. Unless `--no-connect`, `inspect` connects to each server concurrently with a bounded pool and a
   per-server timeout, and returns tools, prompts and resources.
4. `rules` runs description and schema rules, plus cross-server checks (T3).
5. `pins` compares tool hashes with `pins.json` (T2) and stores pins on first run.
6. `report` renders terminal or JSON output; `cmd/mcpmoat` sets the exit code.

Phases 2 to 4 reuse `discover`, `inspect`, `rules` and `pins`. The phase 2 proxy calls the same rule
engine on every `tools/list`.

---

## 9. Milestones (phase 1)

Each milestone can be published on its own.

| ID | Name | Covers | Exit criteria |
|---|---|---|---|
| M1 | Skeleton | Repo, license, short README, CI, `mcpmoat version` | `go.mod` exists; `mcpmoat version` prints the injected version; CI runs `go test`, `go vet`, `golangci-lint` on macOS and Linux and is green. |
| M2 | Discovery | FR-01 to FR-03 | `mcpmoat scan --no-connect` lists servers from Claude Code, Cursor and Codex configs with origin, type and command; secrets are masked; fixtures and tests for each format; release `v0.1.0` published. |
| M3 | Inspection | FR-04 to FR-06 | `mcpmoat scan` connects to stdio and HTTP fixture servers and lists tools, prompts and resources; timeouts and isolated failures tested; scrubbed environment tested (NFR-04). |
| M4 | Rules | FR-07 to FR-10 | YAML engine with embedded and external rules; at least 15 rules with positive and negative tests; malicious fixture servers for T1, T3, T4, T5; ignore list works. |
| M5 | Pins | FR-11 to FR-13 | Pins stored on first run; rug-pull fixture detected with a diff on second run; `pin --accept` clears it. |
| M6 | Output & distribution | FR-14 to FR-16, NFR-02 | Terminal and JSON output with JSON Schema; exit-code contract tested; GoReleaser builds static binaries with checksums and attestation; Homebrew tap works. |
| M7 | Launch | Release `v1.0.0` of phase 1 | End-to-end test detects T1 to T5; README with demo GIF, install, limitations and credits; launch post, Show HN and Reddit drafts; `v1.0.0` published. |
| M8 | Optional LLM | FR-17 | `--llm` works behind an explicit opt-in with a warning; a test proves no network calls happen without it. |

---

## 10. Community and visibility plan

- The English README opens with a GIF of the scan detecting an attack, then a one-line install, then
  an honest "What this does not do" section.
- `CONTRIBUTING.md` focuses on **contributing rules**, the easiest entry point: a rule is a YAML file
  plus a test.
- Issues labelled `good first issue` for new rules and config readers for other clients.
- Progress posts a few times a month (what was learned, one attack explained). Strong launch at M7.
- Cite and link prior work (Invariant Labs, OWASP MCP Top 10) for credibility and to avoid looking
  like a copy.

---

## 11. Success criteria

**Primary:** phase 1 published (`v1.0.0`), installable via Homebrew, detecting the five attacks T1 to
T5 in tests, with clear documentation.

**Secondary** (good signals, not goals):

- first issue opened by a stranger,
- first rule contributed by someone else,
- launch post published.

---

## 12. Out of scope (for now)

- Windows.
- VS Code, Claude Desktop, Windsurf.
- SARIF.
- Docker, npm.
- GUI.
- Enterprise features (SSO, RBAC, central dashboard).
- Analysis of server source code.
- Protection against content-borne prompt injection (phase 4).
- Any cloud service.

---

## 13. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Strong competitors (Snyk Agent Scan, mcpproxy-go, Docker, `alexar76/warden`, `mcp-lock`) | Differentiator: offline, open to contributions, individual-dev focus, path to firewall and data flow. Study them before M4. |
| False positives annoy users into quitting | Severities, `--ignore` and negative tests for every rule. |
| Running servers to inspect them is itself a risk | Same command the client already runs, `--no-connect` option, README warning. |
| Little weekly time and Go is new | Small milestones; start with file-reading-only work (M2). |
| MCP spec changes | Use the official SDK and isolate the protocol in `internal/inspect`. |

---

## 14. Final decisions

1. **Name:** `mcpmoat` (checked: nothing with this name on GitHub).
2. **Connect by default:** yes. `scan` connects to servers by default; `--no-connect` does static
   analysis only.
3. **CLI library:** Go standard library `flag` (simpler to learn); can migrate to `cobra` if
   subcommands grow.

---

## References

- Invariant Labs, MCP tool poisoning and the WhatsApp MCP exploit:
  https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks and
  https://invariantlabs.ai/blog/whatsapp-mcp-exploited
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- Model Context Protocol specification: https://modelcontextprotocol.io/specification
- Official MCP Go SDK: https://github.com/modelcontextprotocol/go-sdk
