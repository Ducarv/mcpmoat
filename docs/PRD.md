# mcpmoat: Product Requirements Document

| Field | Value |
|---|---|
| Spec version | 0.2 |
| Date | 2026-10-18 |
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
| Server state (#87) | Each discovered server is `enabled`, `disabled`, `unapproved` or `project-approved`, read from the client config. Inspection does not start or connect to a server that is not enabled without an explicit opt-in, separate from the untrusted opt-in | A turned-off server is not run by the scan. A repository cannot approve its own servers: an approval only from its own settings files gives `project-approved`, which needs the opt-in. Cursor keeps its toggle in SQLite, which mcpmoat does not read, so Cursor servers always show `enabled`. |
| Placeholder expansion (#88) | Inspection expands `${...}` placeholders like the client: Claude Code and Cursor syntax, none for Codex. A missing variable is a fixed error that names at most the variable. A server from an untrusted project file reads only the base variables (stdio) or no variable and no workspace folder (remote) | The scan runs what the client runs. Expanded values can be secrets, so they stay masked. Fails closed where Cursor probably uses an empty value. A repository cannot use the untrusted opt-in to get secrets or the user's name. Cost: an untrusted server that needs a secret variable is refused. |
| Client identity and lists (#97) | Send the MCP client name of the client that owns the config. Always send every list request, and warn when an undeclared capability returns items | Makes cloaking harder. Residuals: version, capabilities, timing and User-Agent can still tell mcpmoat apart. A server that never answers an unknown method times out. |
| Work directory and `npx` (#104) | Trusted project servers run in their project directory, like the client. The child environment always gets `npm_config_yes=false` | Same behaviour as the client, and `npx` does not install a missing package without a prompt. Configured `-y`, `--yes` or `npm_config_yes` still win. Other launchers are not covered. |
| DNS answers and proxies (#106) | For a configured DNS name, refuse loopback, unspecified, link-local and multicast answers. Behind a proxy, warn with `dns-pin-unavailable` | Stops a DNS name from pointing the scan at the local machine or a metadata service. Private addresses stay allowed for company servers. A proxy resolves names itself, so the guard cannot apply there. |

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
| T1 | Tool poisoning: hidden instruction in a tool's description or schema | Pattern rules: imperative phrases aimed at the model, mentions of other tools, "don't tell the user", invisible characters, very long text, base64, mixed-script words |
| T2 | Rug pull: the description, schema or annotations of a tool change after the pin | Per-tool hash stored in a pins file; differences raise an alert |
| T3 | Shadowing: a tool that tries to redefine another tool's behaviour ("when using send_email, always...") | Rule: tool text (description, title, annotations title, or the description and title strings of the input and output schema) cites the name of a tool from another server |
| T4 | Dangerous config: remote server over `http://` without TLS, plaintext secret in config, unpinned package (`npx package@latest`) | Static config analysis |
| T5 | Basic typosquatting: name very close to a known server | Compare with a short list of popular servers (edit distance: one edit. Two edits when the shorter name has more than 8 characters and either the edits only add or drop characters at the end of the popular name, or the part after the last separator the two names share has 5 or more characters. With no shared separator, that part is the whole shorter name) |

### 5.4 Out of scope for phase 1

- Prompt injection coming from **content** (for example a GitHub issue the agent reads).
- Malware in server code (no source analysis).
- Unauthenticated servers on the network.
- Attacks on the AI client itself.

### 5.5 Stated limitation (must appear in the README)

The scanner reduces risk but does not guarantee safety. Rule-based detection has false positives and
false negatives.

A server can show the scanner a different tool list than it shows the real clients (cloaking).
mcpmoat does not name itself in its requests, to make this harder:

- In the MCP `initialize` request, mcpmoat sends the client name of the client that owns the config:
  `claude-code` for Claude Code, `cursor-vscode` for Cursor and `codex-mcp-client` for Codex. For a
  config of any other kind, it sends a neutral name. The HTTP User-Agent is generic.
- mcpmoat always sends the list requests for tools, prompts, resources and resource templates, also
  when the server does not declare that capability. A server can leave a capability out of the
  handshake and still answer the real client. When an undeclared list returns items, mcpmoat
  reports the items and adds an `undeclared-capability` warning.

A server can still tell clients apart in other ways:

- the client version, which is a fixed value and can differ from the installed release;
- the client capabilities, which are not the same as those of the real client;
- the timing and the order of the requests;
- the HTTP User-Agent, which is generic and not the one of the real client.

The pins only cover what the scanner sees.

A benign server that never answers an unknown method makes the inspection of that server time out.
mcpmoat reports it as timed out (FR-06).

### 5.6 DNS answers and proxies

A remote server is configured with a URL. When the host in that URL is a DNS name, the DNS answer
decides where mcpmoat connects. A hostile DNS answer can point the scan at the user's own machine
or at a cloud metadata service. mcpmoat resolves the name once and keeps (pins) the address of the
first connection for the whole inspection. It also applies these rules:

- For a configured DNS name that is not a localhost name (`localhost`, `localhost.` or a name
  under `.localhost`), mcpmoat refuses these resolved addresses: loopback, unspecified (all of
  `0.0.0.0/8`, and `::`), link-local, multicast, the cloud host services `100.100.100.200`
  (Alibaba Cloud), `fd00:ec2::254` (AWS) and `168.63.129.16` (Azure WireServer), `192.0.0.0/24`,
  `fec0::/10`, and the NAT64 (`64:ff9b::/96`), IPv4-compatible, IPv4-translated and 6to4 forms of
  a refused IPv4 address.
- When the answer also holds allowed addresses, mcpmoat uses only those.
- When no allowed address remains, mcpmoat does not connect. The error is fixed text, labelled
  `network`, and holds no address.
- Private addresses (RFC 1918 and IPv6 ULA) stay allowed, because company servers use them.
- An IP literal in the URL is the user's own choice, so it stays allowed. A localhost name
  connects to loopback only.

Behind `HTTP_PROXY` or `HTTPS_PROXY`, the proxy resolves the name, not mcpmoat. The pin and the
address guard do not apply then. mcpmoat adds a `dns-pin-unavailable` warning to tell the user. The
warning does not hold the proxy URL, because that URL can hold credentials.

Known limits:

- An IPv4 address embedded with another NAT64 prefix (for example `64:ff9b:1::/48`) or in a Teredo
  address is not refused.
- An IP literal or a localhost name in the URL is not checked, also for an untrusted server.
- Names that end in `.local` (mDNS) and resolve to link-local addresses are refused, also when the
  user wants them (false positive).
- Other ULA addresses than `fd00:ec2::254` stay allowed.
- `100.64.0.0/10` (shared address space, RFC 6598) stays allowed, because Tailscale uses it for
  real servers. Only `100.100.100.200` in that range is refused.

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

**FR-03: List servers.** Show discovered servers with origin, type (stdio or http), state and
command.

- For each server the output shows: name, client, source file, transport (`stdio` or `http`), state,
  and the command plus arguments (stdio) or URL (http).
- Values of environment variables and headers are never printed; only their keys (masked values).

*Enabled and approval state.* Each discovered server has a state: `enabled`, `disabled`,
`unapproved` or `project-approved`. The state comes from the client config:

- Codex: `enabled = false` in the server's `[mcp_servers.<name>]` table gives `disabled`.
- Claude Code: the keys `enabledMcpjsonServers`, `disabledMcpjsonServers`, `disabledMcpServers` and
  `enableAllProjectMcpServers`. mcpmoat reads them from `projects.<path>` in `~/.claude.json`, from
  the user file `~/.claude/settings.json`, and from the project files `.claude/settings.json` and
  `.claude/settings.local.json`.
  - The user file `~/.claude/settings.json` and `projects.<path>` in `~/.claude.json` are trusted.
    The project files `.claude/settings.json` and `.claude/settings.local.json` are untrusted: a
    cloned repository can ship them.
  - A `.mcp.json` server named in `disabledMcpjsonServers` is `disabled`. Else, a server named in
    `enabledMcpjsonServers`, or any server when `enableAllProjectMcpServers` is true, is approved.
    An approval from a trusted file gives `enabled`. An approval only from the untrusted project
    files gives `project-approved`. Else the server is `unapproved`.
  - For `enableAllProjectMcpServers`, the first value found wins, in this order:
    `settings.local.json`, the project `settings.json`, the user `settings.json`, `~/.claude.json`.
    When the first value is `true`, the approval is trusted if a trusted file also has `true`.
  - A server named in `disabledMcpServers` is `disabled`, also when it is approved. For a global
    server, only `projects.<path>.disabledMcpServers` of the current project applies. When the
    current project has two keys (see below), the lists of both keys apply to the servers of both.
  - The current project is the working directory as given, or with its symlinks resolved: Claude
    Code writes the key with the real path. When `~/.claude.json` has both keys, the disabled lists
    of both apply. The approval (`enabledMcpjsonServers` and `enableAllProjectMcpServers`) comes
    from one key only, the working directory as given if it has a key, so a second key never adds
    an approval. Another form of the same path, such as another letter case on a case-insensitive
    file system, does not match (known limit).

  For a `.mcp.json` server that no disabled list names:

  | Name in a trusted `enabledMcpjsonServers` | Name in an untrusted `enabledMcpjsonServers` | First `enableAllProjectMcpServers` | State |
  |---|---|---|---|
  | yes | any | any | `enabled` |
  | no | any | `true`, in a trusted file | `enabled` |
  | no | any | `true`, in an untrusted file | `project-approved` |
  | no | yes | absent or `false` | `project-approved` |
  | no | no | absent or `false` | `unapproved` |

  The state fails closed when mcpmoat cannot read a source:

  - A settings file that has an error: no `.mcp.json` server keeps an approval. An `enabled` or
    `project-approved` server becomes `unapproved`; `disabled` stays.
  - `~/.claude.json` exists, but mcpmoat cannot read its `projects.<path>` state for the current
    project: the file is refused as a whole (also for a bad value in another project), the
    `projects` value is not an object, or the object of the current project, or its state, has an
    error. Then no `.mcp.json` server keeps an approval, as above, and every global server of
    `~/.claude.json` that would be `enabled` is `unapproved`: mcpmoat cannot confirm that the
    project does not turn it off.
  - A missing file is not an error, and a `~/.claude.json` with no key for the current project is
    not a failure.
  - Each failure gives a per-file error, so the scan fails and the result does not look clean.
- Cursor: not read. Cursor keeps its on and off toggle in its SQLite state, which mcpmoat does not
  read, so every Cursor server shows `enabled` (known limit).
- With `--config`, mcpmoat reads one file only and has no approval data. A server from a Claude Code
  project `.mcp.json` is `unapproved` (fails closed). A server from another file is `enabled` unless
  the file itself turns it off (known limit).

Acceptance criteria:

- A Codex fixture with `enabled = false` gives a `disabled` server.
- A Claude Code fixture gives `enabled`, `disabled`, `unapproved` and `project-approved` servers
  from the rule above.
- A state key with a wrong type gives a per-file error that holds no value.
- Inspection never starts or connects to a server that is not `enabled` (also `project-approved`),
  unless the user opts in explicitly. This opt-in is separate from the opt-in for untrusted project
  configs. A server that is both disabled and untrusted needs both.

A project repository can ship its own `.claude/settings.json` that approves its own `.mcp.json`
servers. Such an approval gives only `project-approved`, never `enabled`, so inspection still needs
the state opt-in. It never changes trust: inspection of an untrusted project config still needs the
untrusted opt-in too.

*Variable placeholders.* Discovery keeps `${...}` placeholders as written, and the list shows them
as written. Inspection expands them as the client does, just before it starts or connects to the
server:

- Claude Code: `${VAR}` and `${VAR:-default}`. A variable that is set but empty gives an empty
  value, not the default.
- Cursor: `${env:NAME}` and the workspace variables `${userHome}`, `${workspaceFolder}`,
  `${workspaceFolderBasename}`, `${pathSeparator}` and `${/}`. A workspace variable on a server
  with no project is an error.
- Codex: no expansion.

Rules:

- Values come from the user's environment, the one that mcpmoat runs in.
- mcpmoat expands the command, the arguments, the URL, and the values of environment variables and
  headers. It does not expand names (keys).
- A missing variable with no default gives a fixed config error. The error names the variable only
  when it is a plain variable name (ASCII letters, digits and `_`, not a digit first, at most 64
  bytes). Else it says "variable with an invalid name". mcpmoat does not start or connect to that
  server. Cursor probably uses an empty value here; mcpmoat fails closed.
- An expanded text can be at most 64 KiB, and the expanded texts of one server together at most
  1 MiB. Over a limit, mcpmoat refuses the server with a fixed config error and does not start or
  connect to it.
- Expanded values stay masked. They are never printed, logged or stored, and the report shows the
  server as configured.

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
- A failed, timed-out or refused server is only a warning, and it does not change the exit code.
  One exception: when the server is already pinned, it is also a `MOAT-T2-004` finding (medium) with
  the reason `pinned server could not be inspected` (see FR-12). A hostile server must not avoid the
  rug-pull check by failing on purpose.
- Ctrl-C, `SIGTERM` or `SIGHUP` cancels the run. mcpmoat stops the stdio servers that it started,
  because they run in their own session and the terminal does not signal them. `scan` prints
  `interrupted; no pins were saved`, saves nothing and exits with code 2. `pin --accept` does the
  same.

### 6.3 Rules

**FR-07: YAML rules, embedded and external.** Rules live in YAML files, embedded in the binary and
loadable from a directory (`--rules <dir>`).

- The built-in rules in `rules/` are embedded with `go:embed` and load with no flags.
- `--rules <dir>` loads every `*.yaml`/`*.yml` file in the directory in addition to the built-ins.
- An invalid rule file fails with exit code 2 and names the file and field.
- Two rules with the same `id` are rejected.

**FR-08: Rule schema.** Each built-in rule has `id`, `title`, `severity` (low, medium, high,
critical), `target` (description, schema, config), `match` (regex, word list or native heuristic) and
`references`.

- A rule missing a required field is rejected with a message that names the field.
- The loader requires only `id`, `title`, `severity`, `target` and `match`. `references`, `risk`,
  `remediation` and the test cases are required for built-in rules only (NFR-05, NFR-07).
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
- `.mcpmoat-ignore` cannot ignore the pin rules (`MOAT-T2-001` to `MOAT-T2-004`). The file can come
  from a cloned repository, and it must not silence the rug-pull alarm. Only `--ignore` on the
  command line ignores a pin rule. `scan` prints a warning when the file has such an entry.

### 6.4 Pins (rug-pull detection)

**FR-11: Store pins.** On first run, store the SHA-256 of each tool's name, title, description,
input schema, output schema and annotations in `~/.config/mcpmoat/pins.json`. The annotations are
the title and the four hints `readOnlyHint`, `destructiveHint`, `idempotentHint` and
`openWorldHint`. An absent hint is different from a set hint.

- The hash input is a canonical serialisation: the same tool with JSON keys in a different order
  gives the same hash.
- A change of one character in the name, title, description or a schema gives a different hash,
  except a number change within the float64 limit below.
- A change of one annotation hint gives a different hash.
- Each hash starts with its version (`sha256-v1:`). When a stored hash has another version, mcpmoat
  shows the tool as not verified. It never accepts the tool silently.
- A tool or hash that cannot be verified is reported as not verified (`MOAT-T2-004`). Examples are a
  duplicate or empty tool name, a stored text that does not match its hash, and a server that
  cannot be pinned. Only `pin --accept` pins such a server again, never `scan`.
- `pins.json` also stores the canonical text of each tool, next to its hash, so that a later run
  can show the diff. It never stores env, header, args or URL values from the configs.
- The pins file has a format version field and is written atomically (temp file plus rename).
- `XDG_CONFIG_HOME` is honoured when set.

Known limits: the Go SDK decodes `readOnlyHint` and `idempotentHint` as a plain `bool`. So for
these two hints, "absent" and "false" are the same. A change to `true` is always visible. The SDK
decode and the canonical serialisation pass every schema number through `float64`. So a number that
a `float64` cannot hold exactly is rounded (an integer above 2^53, a long decimal, or a value that
underflows to zero), and a change only in such digits does not change the hash. The hash does not
cover a tool's `_meta` and `icons`, because `inspect` drops them. So a change only in `_meta` or
`icons` does not change the hash. This is an accepted limit. Issue #153 will keep them in `inspect`
and hash them before v1.0.0.

**FR-12: Detect changes.** On later runs, warn about new, removed or changed tools, showing the
text diff.

- Using the rug-pull fixture, the second run reports the changed tool with a unified text diff of the
  description and/or schema.
- New and removed tools are reported as separate change kinds.
- A changed tool is a finding with severity `high` (T2). The rule IDs and severities are:
  `MOAT-T2-001` changed tool (`high`), `MOAT-T2-002` new tool (`medium`), `MOAT-T2-003` removed tool
  (`low`) and `MOAT-T2-004` tool not verified (`high` when the tool name is pinned, else `medium`).
- A tool that is pinned but cannot be verified (a duplicate name, invalid tool data, another hash
  version or a corrupt pin) can hide a rug pull. A hostile server can return a pinned name twice to
  avoid the `MOAT-T2-001` check. So that finding is `high`. An unverified tool whose name is not
  pinned is `medium`.
- A pinned server that cannot be inspected (it failed, timed out or was refused) is a `MOAT-T2-004`
  finding (`medium`) with the reason `pinned server could not be inspected`. A server that is not
  pinned stays a warning only (FR-06).
- The default threshold of `--fail-on` is `high`. So the default does not fail on `MOAT-T2-002`
  (new tool), `MOAT-T2-003` (removed tool) or a `medium` `MOAT-T2-004`. It does fail on
  `MOAT-T2-001` and on a `high` `MOAT-T2-004`.
- `scan` and `pin --accept` read `pins.json` before they start any server. A bad `pins.json` exits
  with code 2 before a server starts. The `pinned N tools for <server>` lines appear only after the
  pins are saved.

**FR-13: Accept changes.** `mcpmoat pin --accept <server>` accepts the new version.

- After `pin --accept <server>`, the next scan reports no pin changes for that server.
- Pins for other servers are not changed.
- Accepting an unknown server name exits with code 2.
- A name that more than one server has exits with code 2 and lists the matches. `--config` narrows
  the search.
- Any config file problem exits with code 2, because a broken file can hide a second server with
  the same name. `pin` prints each problem and `fix the config file or choose one with --config
  <file>`, and it does not inspect or write anything.
- `pin --accept` prints the diff of each changed tool before the `accepted ...` line, so you see
  what the accept changes.
- `pin --accept <server> --expect <digest>` saves the pins only if the tools that the server
  returns now give the same digest. A hostile server picks the tools that it shows, so it could
  show harmless tools to `scan` and harmful tools to `pin --accept`. The digest closes this gap.
  If the digests differ, `pin` prints the diff and `the tools of <server> differ from what scan
  showed ...; nothing was saved`, saves nothing and exits with code 2. An invalid or empty
  `--expect` exits with code 2 before any server starts. Without `--expect`, `pin --accept` works as
  before and prints a note on stderr that it trusts the tools that the server returns now.
- After the diffs, `scan` prints one line for each pinned server that has a pin finding that is not
  ignored: `To accept <server>: mcpmoat pin --accept <server> --expect pd1:<32 hex>`. The server
  name in the command is quoted for a POSIX shell when needed. A name with a character that is not
  safe to paste gets no command, only the digest. On Windows (`cmd.exe` or PowerShell) the user may
  need to change the quotes. There is no line for a server pinned for the first time, a server that
  could not be inspected, an ignored finding, or tools that cannot be pinned.
- The digest (`pins.Digest`, version `pd1`) is the first 128 bits of SHA-256 over the sorted tool
  names and their hashes. 128 bits, because the server picks both tool sets, so a collision costs
  about 2^64 work (the birthday bound).

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
  minimal safe base (for example `PATH`, `HOME`) and `npm_config_yes=false`, asserted by a test.
- The executed command and arguments are exactly those in the client config, after the same
  placeholder expansion as the client (FR-03).
- A trusted project server (for example a `projects.<path>` entry in `~/.claude.json`) runs in its
  project directory, as the client runs it. A server from an untrusted project file does not get
  this default.
- `go.mod` lists only needed dependencies; CI actions are pinned to commit SHAs.

`npm_config_yes=false` makes `npx` (npm 7 or later) stop with an error when the package is not
installed, so the scan does not install a package that the user did not install. A configured `-y`
or `--yes` argument, or a configured `npm_config_yes` variable, still wins, because the user chose
it. Known limits: `pnpm dlx`, `bunx`, `uvx` and the standalone `npx` from before npm 7 ignore this
variable.

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
internal/termsafe/    escapes untrusted text for the terminal (used by discover, report and rules)
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
| `internal/termsafe` | Escape untrusted text for the terminal (used by `discover`, `report` and `rules`) | FR-14 |
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
