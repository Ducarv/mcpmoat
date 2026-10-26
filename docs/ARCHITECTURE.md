# Architecture

> **Status:** this page describes the code as it is today and marks what is still planned. Today
> `mcpmoat scan --no-connect` reads configs, loads rules, lists servers and applies the config rules
> (T4 and T5) and the ignore list. `mcpmoat scan` without `--no-connect` also connects to the
> servers, pins their tools on the first run, and reports new, removed and changed tools on later
> runs (T2). It prints a diff for each new and each changed tool. `mcpmoat pin --accept <server>
> --expect <digest>` accepts the changes. The YAML rules are not
> applied to tools yet (#143). `mcpmoat scan --json` writes the same report as one JSON document
> (FR-15, see [JSON output](#json-output)). `mcpmoat scan --llm` also asks a language model to rate
> the name and description of each inspected tool, and adds advisory findings (FR-17, see
> [The `--llm` classifier](#the---llm-classifier)).

This page is the one place for the package layout, the import direction, the data flow, the
`internal/inspect` interface and the rules for untrusted text. The [PRD](PRD.md) holds the product
requirements. Section 8 of the PRD is the target architecture.

## Package layout

```
cmd/mcpmoat/            CLI entry (standard library flag); runWithContext() returns the exit code
internal/
  termsafe/             escapes untrusted text for the terminal
  safefile/             hardened bounded read of untrusted files
  discover/             config readers: Claude Code, Cursor, Codex
    discovertest/       test helpers for discover
  inspect/              connects to servers, reads tools, prompts and resources
    inspecttest/        test helpers for inspect, including Fake
  rules/                loads YAML rules, applies regex and heuristics
  pins/                 tool hash, pins.json store, change detection and diff
  report/               terminal and JSON output
    reporttest/         test helpers for report: schema loader, unsafe-byte check
  llm/                  optional --llm classifier (Anthropic or OpenAI-compatible API)
rules/                  built-in rules (go:embed)
testdata/               fixtures for tests and the demo
  configs/              example client configs
  servers/              example MCP servers (benign, poisoned, mailer, shadowing, rugpull)
docs/                   PRD and other documentation
```

- `cmd/mcpmoat`: parses flags, runs the command, returns the exit code. `os.Exit` is only in `main`.
  `configs.go` holds the config loader that `scan` and `pin` share (`loadConfigs`), so both commands
  apply the same trust rules to a config file. `pins_shared.go` holds the helpers of the pin step
  that both commands use (`serverIdentity`, `readPins`, `pinnable`, `appendDiff`). `scan_pins.go`
  holds the pin step of `scan` (`pinner`), and `accept_hint.go` the "To accept" line. `scan_llm.go`
  holds the `--llm` step: it maps each `inspect.Tool` to an `llm.Input` and calls a
  `toolClassifier`, a small interface that `*llm.Client` implements. The `cli.newClassifier`
  factory builds it, and tests replace the factory with a fake.
- `internal/termsafe`: escapes untrusted text for the terminal. See
  [Where untrusted text is escaped](#where-untrusted-text-is-escaped).
- `internal/safefile`: the one shared hardened file read. It confines the open to a directory with
  `os.Root`, refuses non-regular files, does not block on a FIFO (as the file or as the directory) and
  caps the size. `discover` and `rules` use it.
- `internal/discover`: finds the MCP servers that the client configs declare. It does not start them.
- `internal/inspect`: starts or calls each server and reads what it offers. It is the only product
  package that imports the MCP SDK (see [The `internal/inspect` interface](#the-internalinspect-interface)).
- `internal/rules`: loads and checks the YAML rules, runs the config heuristics and the shadowing
  check, and reads `.mcpmoat-ignore`.
- `internal/pins`: computes the canonical hash of each tool (`Canonical`, `Hash`), makes the pins of
  a server (`Snapshot`), keeps the versioned `pins.json` store (`Load`, `Get`, `Set`, `Save` and
  `DefaultPath`), compares the pins with the current tools (`Compare`), and makes the digest of a
  tool set (`Digest`, `ValidDigest`). `Compare` finds changed, new, removed and not verified tools.
  It makes the unified diff of a changed or new tool, and shows the whole current text of a pinned
  tool whose pin cannot be checked. See [Tool hash](#tool-hash), [Tool set digest](#tool-set-digest)
  and [The `pins.json` store](#the-pinsjson-store).
- `internal/report`: writes the terminal output: the servers (`WriteServers`), a summary with one
  line for each server (`WriteSummary`), the findings grouped by severity (`WriteFindings`) and the
  diffs of changed, new and not verified tools (`WriteDiffs`). `Style` (`style.go`) decides the
  colour. See [Terminal report](#terminal-report). It also renders the JSON report of
  `scan --json` (`WriteJSON`). See [JSON output](#json-output).
- `internal/llm`: the optional `--llm` client (FR-17). It sends the name and description of one tool
  to an Anthropic or OpenAI-compatible API and accepts only a fixed verdict. It uses the standard
  library only. See [The `--llm` classifier](#the---llm-classifier).
- `rules/`: the built-in rule files (`rules/*.yaml`) and `data/popular-servers.txt`. The Go file
  `rules/embed.go` embeds both with `go:embed`. It holds data only. `internal/rules` parses it.
- `testdata/`: fixtures. `testdata/servers` holds malicious example servers. `testdata/configs`
  holds example client configs. Other folders hold fixtures for single packages.
- `internal/discover/discovertest`, `internal/inspect/inspecttest` and
  `internal/report/reporttest`: helpers for tests in other packages. `inspecttest.Fake` is an
  `Inspector` that returns canned results. A test that uses `Fake` never starts a real server.
  `inspecttest.Fixture` builds one fixture server under `testdata/servers/` and returns the path of
  its binary. The test starts it. `reporttest` loads the JSON Schema of the current
  `schema_version` and checks output for raw bytes that can act on a terminal.

## Import direction

Imports go one way. A package in the table imports only the packages in its row. The table lists
the product packages and non-test imports. Tests also import `inspecttest`, `discovertest` and
`reporttest`. `inspecttest` imports `discover` and `inspect`. `discovertest` imports no module
package. `reporttest` imports `report`, `termsafe` and the external module
`github.com/google/jsonschema-go`. A depguard rule in `.golangci.yml` allows each of the three
only in `_test.go` files, so none of them reaches the binary.

| Package | Imports (module packages only) |
|---|---|
| `internal/termsafe` | none |
| `internal/safefile` | none |
| `internal/discover` | `safefile`, `termsafe` |
| `internal/inspect` | `discover` |
| `internal/rules` | `discover`, `inspect`, `safefile`, `termsafe`, `rules` (the embedded data) |
| `internal/report` | `discover`, `inspect`, `termsafe` |
| `internal/pins` | `inspect`, `safefile`, and the module `github.com/aymanbagabas/go-udiff` |
| `internal/llm` | `discover` |
| `cmd/mcpmoat` | `discover`, `inspect`, `llm`, `pins`, `report`, `rules`, `termsafe` |

`internal/inspect` does not import `termsafe`. The report layer escapes what `inspect` returns.
`internal/llm` does not import `inspect`: `cmd/mcpmoat` gives it only the tool name and description.

You can check this table with:

```sh
go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./...
```

Depguard rules in `.golangci.yml` also fence the network and the processes. They check non-test
files only:

- `net-http-only-in-inspect-and-llm`: only `internal/inspect` and `internal/llm` may import
  `net/http` or a package below it, such as `net/http/httptrace`.
- `net-only-in-inspect-and-llm`: only `internal/inspect` and `internal/llm` may import the bare
  `net` package. The rule matches `net` exactly, so `net/url` and `net/netip` are not covered.
- `net-dial-only-in-inspect-and-llm`: only `internal/inspect` and `internal/llm` may import
  `net/smtp`, `net/rpc` (also `net/rpc/jsonrpc`) or `crypto/tls`.
- `os-exec-only-in-inspect`: only `internal/inspect` and its test helper
  `internal/inspect/inspecttest`, which builds the fixture servers, may import `os/exec`.
- `llm-only-in-cmd`: only `cmd/mcpmoat` may import `internal/llm`.

So a non-test file in another package that imports `net`, `net/http`, `net/smtp`, `net/rpc`,
`crypto/tls` or `os/exec` fails the lint gate (NFR-01, NFR-04). The fence is defence in depth, not
a proof. It does not cover `os.StartProcess`, `syscall` (`cmd/mcpmoat` and `internal/safefile`
import it) or the imports of third-party packages. The network tests in `cmd/mcpmoat` and the
offline CI job are the proof.

## Data flow

### Implemented

`mcpmoat scan` does these steps today:

1. `cmd/mcpmoat` parses the flags and checks `--timeout`, `--concurrency` and `--fail-on`. A bad
   value is a usage error with exit code 2. Then `setupLLM` checks the `--llm` flags and the API
   key. With `--llm`, it also prints the warning that data leaves the machine and builds the
   classifier. This all happens before the rules load (see
   [The `--llm` classifier](#the---llm-classifier)).
2. It loads the rules with `rules.Builtin` and, with `--rules`, `rules.LoadDir`. Then
   `rules.NewSet` checks for duplicate rule IDs and for clashes with built-in IDs. This only loads
   and checks the rules. A bad rule file or an ID problem gives exit code 2.
3. It reads `.mcpmoat-ignore` with `rules.ReadIgnoreFile` and adds the `--ignore` rule IDs. It keeps
   two lists (`scanIgnores` in `cmd/mcpmoat/scan_pins.go`): one for the config rules, with the file
   and the flags, and one for the pin rules and the LLM rules, with the flags only. The file can come
   from a cloned repository, so it cannot ignore a pin rule or an LLM rule. The guard is
   `fileCannotIgnore`: it is true for a pin rule (`pins.IsPinRuleID`: the rule ID starts with
   `MOAT-T2-`, the unexported `ruleIDPrefix`) and for `llm.RuleID` and `llm.RuleIDInvalid`
   (`MOAT-LLM-001` and `MOAT-LLM-002`). When a file entry for such a rule matches a finding, `scan`
   keeps the finding, prints one warning for each such rule ID (`warnFileCannotIgnore`), and tells
   the user to use `--ignore`.
4. It finds the servers with `loadConfigs` in `cmd/mcpmoat/configs.go`. That function runs
   `discover.Discover`, or reads one file with `discover.ReadConfig` when `--config` is set. `pin`
   uses the same function, so both commands read the configs with the same trust rules.
5. It runs the built-in config rules on every server it found, also a disabled one, as `discover`
   gives it. `rules.CheckConfig` gives the T4 findings (MOAT-T4-001 to 004). The typosquat check
   from `rules.NewBuiltinTyposquat` gives the T5 finding (MOAT-T5-001). The ignore list drops
   some findings. The rule set gives the severity of each one that is left.
6. `writeScanReport` prints the report on stdout (see [Terminal report](#terminal-report)):
   `report.WriteServers` prints the server table, `report.WriteSummary` prints the summary, and
   `report.WriteFindings` prints the findings, only when findings are left. It never prints a
   value. Last, `reportScan` prints the ignored count for each rule ID on stderr (only rule IDs and
   counts, no server names).
   With `--json`, step 6 is different: `buildScanReport` (`cmd/mcpmoat/scan_json.go`) makes one
   `report.ScanReport` from the same servers, findings and diffs, and `report.WriteJSON` writes it
   on stdout instead of the terminal report. See [JSON output](#json-output).

Steps 1 and 2 always run. Steps 3 to 6 run in both modes. Without `--no-connect`, `scan` adds
the connect and pin steps between step 5 and step 6:

- 5a. `scan` first reads `pins.json` (`pins.Load`). A bad file exits with code 2 before any server
  starts. Then `inspect.Run` inspects the servers with the `--timeout` and `--concurrency` values.
  The inspector is `inspect.New` with the zero `SDKOptions`. So a server from an untrusted project
  file, and a server that the client config turns off or leaves unapproved, is refused. `scan` has
  no flag that allows them. A stdio server runs with a scrubbed environment (NFR-04). A server that
  fails, times out or is refused shows its status in the summary on stdout (`failed`, `timeout` or
  `not inspected`). It does not change the exit code (FR-06), unless the server is pinned and failed
  or timed out: then it is also a high finding (see 5b). The inspection warnings
  (`Result.Warnings`, and `ConnectError.Warnings` of a failed server) go to the summary of that
  server too (`outcomeSummary` in `cmd/mcpmoat/scan_pins.go`). `pin` still prints them on stderr
  (`warnInspection` in `cmd/mcpmoat/pins_shared.go`).
- Signals: `main` passes a context that ends on Ctrl-C, `SIGTERM` or `SIGHUP`. The stdio servers run
  in their own session, so the terminal does not signal them. When the context ends, `inspect.Run`
  stops them. `scan` then prints `mcpmoat scan: interrupted; no pins were saved`, saves nothing,
  prints no report and exits with code 2. A second signal ends mcpmoat at once.
- 5b. For each server, `cmd/mcpmoat` checks the tools against the store that it read in 5a.
  - A server that is not in the store is pinned on its first run. If the tools cannot be pinned (see
    `pinnable`), the server gets a high MOAT-T2-004 finding: it is never pinned, so its tools are
    never checked for changes, and it must fail the default threshold. A server whose config path is
    not absolute (the working directory is not known) gets the same finding with the reason
    `the config path is not absolute`, because its identity would not match the store.
    `scan` prints `mcpmoat scan: pinned N tools for <server>` on stderr only after the save worked.
  - A pinned server that failed or timed out gets a MOAT-T2-004 finding (high, exit 1) with the
    reason `pinned server could not be inspected` (`pinner.notInspected`). A hostile server must not
    avoid the check by failing on purpose. A pinned server that a gate refused (`inspect.Refused`:
    the client config turns it off or does not approve it) shows its status `not inspected` and its
    reason in the summary, with no pin finding: the config of the user sets that state, not the
    server. A server that is not pinned shows its status and reason too, with no pin finding
    (FR-06).
  - A second entry with the same identity gets a MOAT-T2-004 finding with the reason `the server is
    listed twice`, so that its tools are not skipped. It is high when the identity is pinned, else
    medium (`pinner.unverifiedSeverity`).
  - A server that is in the store goes through `pins.Compare` (`pinner.compare`). The findings are
    MOAT-T2-001 (changed tool, high), MOAT-T2-002 (new tool, medium), MOAT-T2-003 (removed tool,
    low) and MOAT-T2-004 (not verified). The severity of MOAT-T2-004 is high when the tool name is
    pinned, because a duplicate, invalid or unverifiable copy of a pinned tool can hide a rug pull,
    and medium otherwise (`Change.Severity` in `internal/pins/compare.go`). A tool is not verified
    when its name is empty or used twice, when it has no canonical form, when it is pinned with
    another hash version, or when its pinned text does not match its hash. These are native rule
    IDs: there is no YAML file for them, because pins handle T2. A MOAT-T2-004 finding shows a fixed
    reason text in brackets after the tool name on the `Tool` line, or on a `Reason` line when the
    finding has no tool name (it is about the whole server, or the tool name is empty):
    `duplicate tool name`, `empty tool name`, `invalid tool data`, `pinned with another hash
    version` or `pinned text does not match its hash`. The reason
    never holds server text. For the last two reasons the pin cannot be trusted, so the change also
    has a diff of the whole current tool (`Change.Diff`). The `--ignore` flag drops them by rule ID,
    server and tool name. The `.mcpmoat-ignore` file does not (see step 3). `scan` never re-pins a
    server that is in the store. When the tools of a pinned server no longer fit the size limit of
    pins.json (`pins.ValidateServer`), `pins.Compare` has no reason for it, so `pinner.compare`
    adds the high MOAT-T2-004 finding `the tools cannot be pinned` that a first run gives.
- 5c. For a pinned server with at least one pin finding that is not ignored, `pinOutcomes` also keeps
  the `pins.Digest` of the tools that `scan` saw (`acceptHint` in `cmd/mcpmoat/accept_hint.go`). A
  server whose tools cannot be pinned (`pinnable`: `pins.Snapshot` and `pins.ValidateServer`, the
  rules of `Store.Set`) has no hint, because `pin --accept` would refuse them. A first-run server, a
  server that was not inspected and an ignored finding give no hint. A hint keeps `truncated` when a
  diff of that server was cut, `ignored` when `--ignore` dropped a pin finding of that server, and
  `noText` when a kept diff is only a fixed note (`pins.Change.DiffIsNote`). `setSelectors` checks
  which server `pin --accept <name>` would select among all servers of the scan (`selectServers`,
  the same function that `pin` uses). It sets `project` when `pin` needs `--project` to select the
  server, and `ambiguous` when the name cannot select it.
- 5d. Only with `--llm` (FR-17), `classifyTools` in `cmd/mcpmoat/scan_llm.go` runs after the pin
  step. It sends the name and description of each tool of each server with status `StatusOK` to the
  classifier, and adds one advisory row for each tool that the model rates as risky, for each tool
  with an unusable answer, and for each cut tool (see the verdict rules in
  [The `--llm` classifier](#the---llm-classifier)). It only adds rows: it never changes or drops a
  rule finding, and it never touches pins, diffs or hints. Only `--ignore` drops LLM rows, as for
  the pin rows. The `.mcpmoat-ignore` file does not (see step 3).
  The ignored count includes the dropped LLM rows.
- The pin findings join the config findings in one report. A changed tool and a new tool also get a
  diff, so the user can review the content of a new tool before they accept it. A new tool has the
  header `New tool <tool> on server <server>:` and only added lines. A not verified tool with a diff
  (see 5b) has the header `Not verified tool <tool> on server <server> (current text):` and only
  added lines. A finding that the user ignored gets no diff. `report.WriteDiffs` prints the diffs
  after the findings. When a diff was cut at
  the size limit (`Change.Truncated`), `scan` prints a warning on stderr that names the tool and the
  server: `the diff of tool <tool> on server <server> was cut at the size limit; review the full tool
  before you accept it`. Then `writeAcceptHints` prints one line for each hint on stdout:
  `To accept <server>: mcpmoat pin --accept <server> --expect pd1:<64 hex>`. After
  `scan --config <file>`, the command holds `--config <file>` too, so `pin` reads the same file, and
  `--project <path>` when the hint has a project. When a diff of that server was cut, the line ends
  with ` (the diff was cut: review the full tool first)`. When `--ignore` dropped a pin finding of
  that server, it ends with ` (--ignore hid some changes: run scan without it to review them
  first)`. When a kept diff is only a fixed note, it ends with
  ` (a change has no diff text: review the tool first)`.
  The command holds the server name, the project and the config path only when each one is a bare
  shell word
  (`isBareShellWord`: the ASCII characters `[A-Za-z0-9._@/:+=-]`, starting with a letter, `_` or
  `/`, and not too long). POSIX shells, `cmd.exe` and PowerShell all read such a word as plain text.
  No quoting is safe in all of them, so any other name or path gives a line with no command
  (`acceptCommand`). The line has no command either when the user did not see every change (a cut
  diff, a change that `--ignore` hid, or a diff that is only a note), when the name cannot select
  the server (`acceptHint.ambiguous`), or when a config file has a problem. `pin` refuses the last
  two without a `--config` that narrows it, and refuses a config problem until the file is fixed
  (`acceptSteps`).
- `scan` saves the new pins after it prints the report, so a save error never hides the report
  (`savePinned` in `cmd/mcpmoat/scan.go`). `savePinned` reads `pins.json` again, sets only the
  first-run servers that the file does not hold yet (another run may have pinned them meanwhile),
  and saves. The `pinned N tools` lines come after the save, only for the servers it set. When the
  file holds a server that this scan wanted to pin, with other tools, `scan` prints a warning: this
  scan did not compare its tools with the pins of the other run.

`--no-connect` starts no process and reads and writes no `pins.json`.

In `reportScan`, a signal during the inspection or the LLM step, or a report write error, returns 2
at once.
Otherwise `reportScan` prints the report and then gets the exit code from `scanExitCode` in
`cmd/mcpmoat/scan_findings.go`. An execution error gives 2, and 2 wins over 1. Otherwise
`hasFailingFinding` gives 1 when a row (the ignored findings are already dropped) has a severity at
or above `--fail-on`. It compares `rules.Severity` `Rank()` values, and a severity with rank 0
(unknown) always counts. The user contract, with the list of execution errors, is in
[README.md](../README.md#exit-codes). `--json` does not change the exit codes.

`mcpmoat pin --accept <server> [--project <path>] [--expect <digest>]` (FR-13) does these steps:

1. It finds the server by exact name, in `--config <file>` or by auto-discovery, like `scan`
   (`selectServers`). With `--project <path>`, it keeps only the server of that project. Without it,
   when the name is in more than one place and exactly one of them is outside any project, it keeps
   that one. An unknown name exits with 2. A name that still matches more than one server exits with
   2 and lists the matches; `--config` or `--project` narrows them. `pin` fails closed on any config
   file problem, because a broken file can hide a second server with the same name. It prints each
   problem, then `mcpmoat pin: fix the config file or choose one with --config <file>`, and exits
   with 2. It inspects nothing and writes nothing.
2. It reads `pins.json` (`pins.Load`). A bad file exits with 2 before any server starts. It reads
   the file again just before step 6.
3. It inspects that one server with `--timeout`, with the same inspector as `scan`. A server that
   fails, times out or is refused exits with 2, and nothing is written. The inspection warnings go
   to stderr, like in `scan`.
4. It makes the pins of the tools (`pins.Snapshot`) and counts the differences with `pins.Compare`.
   It prints the diff of each changed tool and of each new tool on stdout (`report.WriteDiffs`).
   A server that is not pinned yet has no pins, so `pin` shows every tool as a new tool, with only
   added lines. A diff that was cut at the size limit gives the same stderr warning as in `scan`.
5. With `--expect`, it computes `pins.Digest` of the snapshot and compares it with the flag value
   before `Store.Set` and `Save`. If they differ, it prints
   `mcpmoat pin: the tools of <server> differ from what scan showed (digest ..., expected ...);
   nothing was saved. Run scan again and review the diff.` on stderr and exits with 2. The server
   picks the tools that it shows to each run, so without this check a hostile server could show
   harmless tools to `scan` and harmful tools to `pin`. `pin` checks the flag with
   `pins.ValidDigest` right after it parses the flags, so an invalid or empty `--expect` exits with 2
   before it reads any file or starts any server.
6. It sets the pins of this server only (`Store.Set`) on the store that it read again, and saves
   the file. Other servers keep their pins, and so do entries that another run wrote since step 2.
   A `pins.json` problem exits with 2.
7. It prints `accepted <server>: N new, N changed, N removed` on stdout, with `, N not verified`
   added only when N is above 0. Without `--expect`, it also prints a note on stderr that it trusts
   the tools that the server returns now. The note comes before the save (step 6).

A signal during step 3 (Ctrl-C, `SIGTERM` or `SIGHUP`, see Signals above) stops the server. `pin`
saves nothing, prints `mcpmoat pin: interrupted; no pins were saved` and exits with 2.

The code below is built and tested, but `scan` does not call it yet: `rules.CheckShadowing`. The
tool rules (descriptions and schemas) do not run
yet (#143). `scan` loads the rules from `--rules` and checks them, but does not apply them. It
prints a notice on stderr that says so.

Known gaps: the store has no lock (#150), only a read just before the save.

Known limit: a renamed or moved server (a new name, config file or project path) has a new identity.
`scan` pins it again as a new server, and it does not report the old pin. A follow-up issue will
track this.

### Planned (PRD section 8)

The target flow is `discover -> inspect -> rules -> pins -> report`. The `discover`, `inspect`,
`pins` and `report` steps run today, and the `rules` step is not applied to tools yet:

- `discover` lists the servers.
- `inspect` connects and reads the tools, prompts and resources.
- `rules` applies the rules and the heuristics to what `inspect` read.
- `pins` hashes each tool and reports new, removed and changed tools (rug pulls). This part is
  built (see above).
- `report` prints the findings, as a table and as JSON. Both are built (see above).
- The exit code is 1 when a finding is at or above `--fail-on`.

## Tool hash

`pins.Hash` gives the pin hash of one `inspect.Tool` (FR-11, threat T2).

- Input: the eight `inspect.Tool` fields (name, title, description, annotations, inputSchema,
  outputSchema, `_meta` and icons), in a canonical form that uses RFC 8785 (JCS), through the
  standard library `encoding/json/jsontext`.
- Output: `sha256-v1:<hex>`. The prefix is `HashVersion`.
- The store keeps the canonical text next to the hash. A later run shows a diff of that text.
  `Compare` trusts the hash for its verdict. It uses the stored text only for the diff, and only
  after it checks that the text matches the stored hash.
- Golden hashes: `testdata/pins/hash/golden.txt`, for the fixtures in
  `testdata/pins/hash/tools.json`.

The diff of a changed tool (`unifiedDiff` in `internal/pins/diff.go`, with `go-udiff`) and the diff
of a new tool (`newToolDiff`, a diff from empty text, so every content line is an added line) work
on a rendered form of the tool: one item for each line (name, title, description, annotations,
`_meta`, icons, inputSchema, outputSchema, the last five as indented JSON). The annotations,
`_meta` and icons come before the schemas, so a large unchanged schema cannot push a change in them
out of a cut diff. A large `_meta` change, or a large `_meta` or icons value in a new tool, can
still push the schemas out (#162). A line of more than about 200 runes is wrapped, so a change in a
long line still shows. The diff trims the lines that both texts share at the start and at the end,
keeps 3 lines of context, and only then cuts the rest to 64 KiB and 2000 lines. When the cut
applies, the diff ends with a marker line and `Change.Truncated` is true, so `scan` and `pin` can
warn the user. The labels are `pinned` and `current`. A changed or new tool always has diff text, or
a fixed note when the diff cannot be made or the change is not visible in the rendered text. Server
text is raw in the diff. The report layer escapes it (see [Where untrusted text is
escaped](#where-untrusted-text-is-escaped)).

The doc comments own the rules. `Canonical` owns the shape, null handling, errors, no normalisation
and the known limits. `HashVersion` owns when the version changes and what the store does with a
stored hash of another version. Read them with `go doc ./internal/pins Canonical` and
`go doc ./internal/pins HashVersion`. The known limits, also those of `_meta` and `icons`, are
requirements in [PRD FR-11](PRD.md#64-pins-rug-pull-detection). Logs and errors never print a
`_meta` value.

## Tool set digest

`pins.Digest` gives a short fingerprint of the tool set of one server (FR-13, threat T2). It binds
a `scan` to the later `pin --accept --expect`.

- Output: `pd1:<32 lowercase hex>`. The prefix is `DigestVersion`. Change the version whenever the
  encoding changes, so a digest from an old mcpmoat never matches a new one. `ValidDigest` checks
  the format only.
- Input of SHA-256: the tools sorted by name, in byte order. For each tool, the name and then the
  `Pin.Hash`, each as an unsigned varint (`encoding/binary`) with the length in bytes, followed by
  the bytes. A tool name comes from the server and can hold any byte, so plain separators could give
  the same input for two different sets. The length prefix makes the encoding unambiguous. The map
  order does not matter. An empty set has a defined digest: SHA-256 of no bytes.
- The digest keeps the whole SHA-256 sum (64 hex characters). The server picks both tool sets (the
  one that it shows to `scan` and the one that it shows to `pin`), so it can search for a collision.
  That costs about 2^(n/2) work for an n-bit digest (the birthday bound). 128 bits would give about
  2^64, which a funded attacker can pay. 256 bits give about 2^128.
- Only `Pin.Hash` goes in. The hash already covers the whole tool.

## The `internal/inspect` interface

`internal/inspect` hides the MCP protocol behind a small interface, so that a change in the MCP spec
stays in this one package (NFR-06):

```go
type Inspector interface {
	Inspect(ctx context.Context, s discover.Server) (Result, error)
}

func Run(ctx context.Context, servers []discover.Server, opts Options, insp Inspector) ([]Outcome, error)
```

- `Run` inspects many servers with a bounded pool of workers. It returns one `Outcome` for each
  server, in a stable order. One broken or hung server does not stop the others.
- `Options` has `Timeout` and `Concurrency`. For the defaults, see `DefaultOptions` in
  `internal/inspect/inspect.go`.
- `Outcome` has `Server`, `Index`, `Status`, `Result` and `Err`. `Index` is the position of the
  server in the slice given to `Run`, so a caller can match the sorted outcomes to its own order.
  `Status` is `StatusOK`, `StatusTimeout` or `StatusFailed`.
- `Result` holds the server identity, the instructions text and the lists of `Tool`, `Prompt`,
  `Resource` and `ResourceTemplate`, plus `Warning` values.
- `SDKInspector` is the real `Inspector`. Make one with
  `New(SDKOptions{AllowUntrusted, AllowDisabled})`. It starts stdio servers itself and gives remote
  servers to `Remote(ctx, srv, RemoteOptions)`.
- `SDKOptions.HiddenEnv` hides variables from every placeholder. `scan` passes the LLM key
  variable. See [Placeholders](stdio-servers.md#placeholders).
- `SDKOptions.Dial` is a test hook for NFR-01. It is nil in production, and nil uses a
  `net.Dialer`. When it is set, every connection to a remote server goes through it. It sees only
  the addresses that pass the DNS pin and the address guard, so the guard still applies. With a
  proxy, it sees the address of the proxy. It has no effect on stdio servers.
  `cmd/mcpmoat/network_test.go` uses it to prove that `scan` dials only the configured fixture
  hosts.

Among the product packages, only `internal/inspect` imports the MCP SDK (the fixture servers under
`testdata/` also use it). The depguard rule `mcp-sdk-only-in-inspect` in `.golangci.yml` enforces
this (NFR-06). `golangci-lint` skips `testdata/`.

Before `Inspect` starts anything, it checks the state gate and the untrusted gate. A gate that
fails starts nothing. A stdio server runs with no shell, with the exact configured command and with
a scrubbed environment (NFR-04). The details are in `internal/inspect/doc.go`. The page for users
is [How mcpmoat starts stdio servers](stdio-servers.md).

## The `pins.json` store

`internal/pins` keeps the pins of each server in one file, `pins.json`, so that a later run can see
a changed tool (a rug pull). `scan` writes the pins of a server on its first run. Only
`pin --accept` writes them again.

- Path: `DefaultPath` returns `$XDG_CONFIG_HOME/mcpmoat/pins.json` when `XDG_CONFIG_HOME` is set to
  an absolute path, and `~/.config/mcpmoat/pins.json` otherwise. It does not use `os.UserConfigDir`,
  so macOS also uses `~/.config`. The caller passes `getenv` and `homeDir`, as the `cli` in
  `cmd/mcpmoat` does for `discover`, so the package reads no process state.
- Format, version 1:

  ```json
  {
    "version": 1,
    "servers": [
      {
        "client": "claude-code",
        "source": "/home/me/.claude.json",
        "project_path": "",
        "name": "files",
        "tools": {
          "read_file": { "hash": "sha256-v1:<hex>", "canonical": "<JCS text of the tool>" }
        }
      }
    ]
  }
  ```

- Identity: a server is `client`, `source`, `project_path` and `name`. `project_path` is empty for a
  global server. Claude Code project servers in `~/.claude.json` share the same `source` and can share
  a `name`, so `project_path` tells them apart. Two entries with the same identity are an error.
  Every key is required, also an empty `project_path`, and a key must not be `null`.
- Pins: each tool has a `hash` and a `canonical` text. Both are opaque non-empty strings for the
  store. The hashing code owns their format. The format changed in place before the first release,
  so version 1 is the one shape that a release will know.
- Tool names: the server chose them, and they can hold control characters. Code that prints a name
  from the store escapes it with `internal/termsafe`, as it does for a name from a live server.
- Content: the file holds the identity, the tool names, the hashes and the canonical texts. It
  never holds args, a URL, env, headers or a command from your configs.
- Echo residual risk: a server can echo an env value that you configured into a tool description.
  That text then lands in the canonical text in `pins.json`. mcpmoat cannot tell such a value from
  other text. The same is true for a URL from the server, such as a signed icon `src` with a token
  in it. The file and the pin diff can hold it. The file has mode `0600`, so treat it as private.
- Read, change and write: `Load` reads the file through `safefile` and fails closed. A bad file is
  an error and never an empty store, because an empty store would hide a rug pull. `Set` checks one
  server and refuses it on its own, with a size cap of 2 MiB for each server (compact JSON), so the
  caller can still save the others. The server chose the data that `Set` refuses, so the caller must
  report a refused server, never skip it silently: a server that is never pinned looks new on each
  run, and its changes are never reported. `Save` writes atomically (temp file, mode `0600`, sync,
  rename). A new directory gets mode `0700`. The rules, the caps and the error texts are in the doc
  comments of `Load`, `Set` and `Save` in `internal/pins/store.go`.

Known limits:

- There is no file lock. `scan` and `pin --accept` read the file again just before they save, and
  they change only their own entries (`scan` adds only first-run servers that the file does not
  hold). This narrows the window for a lost update, but two runs that read and save at the same
  moment can still undo each other, and the last writer wins. A run can then drop the first pins
  that a parallel run saved, and the next run sees that server as new, with no alert. Issue #150
  tracks the full lock and the missing-file limit below.
- An existing config directory keeps its mode. mcpmoat creates a new directory with `0700`, but it
  does not check or tighten one that exists, and `Load` does not check the mode or the owner of an
  existing `pins.json`. If other users can write to the directory or the file, they can replace the
  pins. Issue #154 tracks this.
- A crash (for example SIGKILL or a power loss) can leave a `.pins-*.tmp` file in the directory. It
  holds only names and hashes and has mode `0600`. mcpmoat does not remove old temp files, because
  one can belong to a parallel run that is still writing.
- A missing `pins.json` looks like a first run, so a deleted file resets the pins without an alert.
  A symlink whose target is missing (`pins.json`, its directory or a parent of the directory), and a
  directory path that is not a directory, are errors, not a first run.
- `Load` follows a relative `pins.json` symlink that stays inside the directory. It refuses an
  absolute symlink, even one that points back inside, and one that leaves the directory
  (`safefile.ErrOutsideRoot`). `Save` replaces a symlink with a regular file.
- On Windows the mode bits are mostly ignored and the directory sync is skipped.
- The cap for each server (2 MiB) keeps one server from filling the file alone. The cap for the
  whole file is 32 MiB. So about 16 servers at full size can make the file larger than 32 MiB, and
  then `Save` fails for all servers. One project config can declare that many servers, but a server
  from an untrusted project file starts only with `AllowUntrusted`, and `scan` has no flag for it.
  The store cannot tell a hostile server from a real one. `scan` and `pin --accept` report the
  `Save` error and exit with 2, and no server is pinned. This is a known ceiling, not a silent loss.
  The policy for a full file (which servers to keep) is not decided yet.
- `Save` writes indented JSON, and the 32 MiB cap applies to that form. A compact file near the cap,
  for example from a hand edit, loads but cannot be saved.

## Terminal report

`scan` prints the report on stdout in this order (`writeScanReport` in `cmd/mcpmoat/scan.go`):

1. The server table (`report.WriteServers`).
2. `SUMMARY` (`report.WriteSummary`): one line for each server, in config order. The line has the
   name with the client and the scope, the status, the tool count (status `ok` only) and the
   finding count. The status is `ok`, `timeout`, `failed` or `not inspected`. A server that
   `--no-connect` skipped, or that `scan` refused to start, is `not inspected`. A server that is
   not `ok` and has a reason shows it last, after the counts: the reason can hold server text, so
   it must not be able to fake a count or push the real one off the line. The inspection warnings
   (`cleartext-secrets`, `undeclared-capability`, `dns-pin-unavailable`) are indented under the
   server. They hold header keys, never values.
3. `FINDINGS` (`report.WriteFindings`): groups by severity, the worst first, only the groups that
   have findings. Each finding has the rule ID and title, the server as `name (client, scope)`
   (so two servers with the same name in two configs differ), a `Where` line (field and key), a
   `Tool` line (a pin finding about one tool) or a `Reason` line (a pin finding about the whole
   server), a `Risk` line and a `Fix` line. An LLM finding (`--llm`) has ` [LLM]` after its title
   and a `Source: LLM classification (advisory)` line after the server line, for example
   `MOAT-LLM-001  Language model rates this tool as risky [LLM]`.
4. The diffs (`report.WriteDiffs`) and the `To accept` lines.

The `Risk` and `Fix` text of a built-in rule comes from its YAML file (the `risk` and
`remediation` fields). The pin rules MOAT-T2-001 to 004 have fixed texts in `internal/pins`
(`ChangeKind.Risk` and `ChangeKind.Remediation`). These remediations name the `To accept` command.
`scan` prints no such line for a server whose tools cannot be pinned, so it gives every pin finding
of that server a fixed text of its own (`fixNotPinnable` in `cmd/mcpmoat/scan_pins.go`). The
MOAT-T2-004 findings that `scan` makes itself get their own fixed texts too. The LLM findings
MOAT-LLM-001 and MOAT-LLM-002 have fixed titles, risk texts and remediations in `internal/llm`
(`Title`, `Category.Text`, `Remediation`, `InvalidTitle`, `InvalidText`, `InvalidRemediation`). No
text from the model reaches them.

The summary and the findings are the report. They are not logs, so they stay on stdout. Warnings
do not change the exit code, which counts findings only (FR-16).

The failure reason of a server in the summary can hold error text from the server. `scan` prints it
on stdout, and `pin` prints it on stderr. So the known gap of `internal/inspect` (an expanded
variable value shorter than 8 bytes is not scrubbed from error text, see "Secrets" in
`internal/inspect/doc.go`) applies to stdout too. `termsafe` makes the text safe for a terminal,
but it does not remove a secret.

Colour (FR-14, NFR-07) is decoration. Every severity and status also shows as a word, so the plain
output is complete. `report.Style` holds one switch, `Color`. `cmd/mcpmoat` sets it in `runScan`
and `internal/report` does not read the environment. `Color` is true only when stdout is a
terminal (`isTerminal` in `cmd/mcpmoat/cli.go` checks `os.ModeCharDevice` on the stdout writer when
it is an `*os.File`, with no dependency; any other writer, such as a buffer, is never a terminal),
`--no-color` is not set (before or after `scan`), and `NO_COLOR` is empty. Only the headings, the severity
group lines and the status words get colour (ANSI SGR codes in `internal/report/style.go`, the
only place that writes the ESC byte). All config, server and rule text goes through `termsafe`
first, so an escape sequence in that text never reaches the terminal as one.

## JSON output

`mcpmoat scan --json` (FR-15) writes the report as one JSON document on stdout. The schema is
[docs/schema/scan-output.v2.json](schema/scan-output.v2.json). The version 1 schema file,
[docs/schema/scan-output.v1.json](schema/scan-output.v1.json), stays unchanged. The Go
types are in
`internal/report/json.go`. `cmd/mcpmoat/scan_json.go` fills them from the same data as the
terminal report, in the same order. The one difference: `findings` keeps the order of the rows,
and the terminal report groups them by severity. The report types hold plain strings, bools and ints, never a
`discover` type, so a secret cannot reach the output by accident.

Shape (`schema_version` 2):

- Top level: `schema_version`, `tool` (`name`, `version`), `mode` (`no-connect` or `connect`),
  `complete`, `servers`, `findings`, `diffs` and `errors`. An empty list is `[]`, never `null`.
- `complete` is `false` when the report can miss results: a config file has a problem (see
  `errors`), or the inspection or the pin step failed as a whole (for example, `pins.json` cannot
  be read), or the LLM step of a `--llm` scan did not classify every tool: a provider failure, an
  internal error of the LLM step, or more tools than the `--llm` cap. The exit code is then 2, and
  the reason is on stderr only. A failed save of new pins comes after the document is written, so it
  does not change `complete`: the findings are whole, and the exit code is 2.
- A server has `name`, `client`, `scope`, `project_path`, `untrusted`, `state`, `transport`,
  `source`, `inspection.status` (`not_run`, `ok`, `timeout`, `failed` or `refused`) and either
  `argv` (stdio) or `url` (http and sse). Both are redacted like in the terminal report.
  `not_run` means that mcpmoat did not connect. This is the case in `no-connect` mode. It also
  happens in `connect` mode when the inspection or the pin step fails as a whole (for example,
  `pins.json` cannot be read). Then `mode` is `connect`, every server is `not_run`, `complete` is
  `false`, the exit code is 2 and the reason is on stderr. Two servers with the same identity
  (client, source, project path and name) share one status: `ok` when one of them was inspected,
  because `checkOutcome` then checks the tools of the first one that was inspected. The duplicate
  gives a `MOAT-T2-004` finding when both copies were inspected, or when the identity is pinned
  and a copy failed. An identity that is not pinned, with one copy `ok` and one that failed, gives
  only the warning on stderr.
- A finding has `rule_id`, `severity`, `server`, `field`, `key`, `related` and `source`. `related`
  is a second name (a key or a server), a fixed reason text or, for `MOAT-LLM-001`, the category
  of the verdict. It is never a value. `source` is required: `rule` for a rule finding and `llm` for
  an advisory finding of `--llm`. It is the only finding field that is never empty.
- A diff has `server`, `tool`, `kind` (`changed`, `new` or `unverified`), `diff`,
  `diff_truncated` and `diff_is_note`. When `diff_is_note` is true, `diff` is a fixed note of
  mcpmoat, not a unified diff: the diff could not be made, or the change does not show in the
  rendered text.
- Every enum in the schema lists all the values that mcpmoat writes. The Go `String` methods have
  an `unknown` fallback for an invalid value. That value is a bug, and the schema rejects it.
- A file problem in `errors` has `path`, `project_path`, `server`, `line`, `col`, `reason` and
  `untrusted`. `reason` is fixed text.

What stays on stderr: the warnings, the notices and the errors. They are byte-identical to a run
without `--json`, with one addition: there is no summary, so `scan` writes on stderr the lines that
the summary shows without `--json` (a server that was not inspected, and the warnings of an
inspection, see `warnNotInspected` in `cmd/mcpmoat/scan.go`). With `--no-connect` there are no
such lines. With `--json`, stdout holds no table, no "No MCP servers found." line and no
`To accept` line. The exit codes do not change. When `scan` stops before the report (for
example, `--config` cannot be loaded, or an interrupt), stdout is empty and the exit code is 2.
If `WriteJSON` fails, `scan` exits with 2, like a failed table write.

Redaction: the document never holds env or header values, the working directory of a server, or
error text from a server or from the OS. A server entry holds no env or header data. A finding
names the key it is about in `key` (and `related`): the key name only, never its value, as in the
terminal table. `ScanReport` has no field for the rest. The `argv` and the `url` are redacted when
the JSON types are built.

Escaping: names, paths and diffs come from untrusted servers and configs. Valid UTF-8 text stays
exact, so a JSON parser gets the original back. `encoding/json` writes invalid UTF-8 as U+FFFD.
`WriteJSON` writes every control, invisible or bidi character as a `\uXXXX` escape (DEL, `0x7f`,
too), so it is safe to print the raw output in a terminal. A program that decodes the JSON (for
example `jq -r`) gets the raw text, which can hold terminal control sequences. It must escape that
text before it prints it. This is the JSON form of the rule in
[Where untrusted text is escaped](#where-untrusted-text-is-escaped). `termsafe` quotes text for the
terminal. JSON escaping does the same job here.

Version policy: a rename, a removal, an added field (every object in the schema sets
`additionalProperties: false`, so the old schema rejects it), or a change of the type or the
meaning of a field bumps `SchemaVersion` and adds `docs/schema/scan-output.v<N>.json`.
`internal/report/reporttest` loads the schema file of the current version for the tests in
`internal/report` and `cmd/mcpmoat`. A test in `internal/report` compares the struct tags of the
Go types with the schema file of the current version, and fails when they differ. A second test
validates sample output against the schema. The limit: the tests cannot stop someone from editing
an old schema file in place. The reviewer must catch that. An old schema file is kept as it was
released.

History: version 1 is the first format. Version 2 adds the required finding field `source` (for
`--llm`, FR-17), and `complete` is also `false` when the LLM step did not classify every tool. The
other fields keep their names and types.

Not in version 2: accept hints (#169), ignored counts (#175), a summary, `pin --json` and
`--fail-on` (#65).

## The `--llm` classifier

`mcpmoat scan --llm` (FR-17) asks a language model to rate the name and description of each
inspected tool. It is off by default. Without `--llm`, `runScan` reads no API key and never calls
`cli.newClassifier`, so no LLM code sends anything (NFR-01).

This section holds the code structure and the design reasons. Other files own the rest:

- The user contract (flags, warning, what is sent, limits, findings, exit codes and security notes)
  is in [README.md](../README.md#optional-llm-classification-sends-data-off-your-machine).
- The requirements are in FR-17 of [PRD](PRD.md).
- The threat model is in [PRD section 5.3](PRD.md#53-threats), which owns it. The package doc
  comment in `internal/llm/doc.go` holds the code-level notes of the threat model.

Setup:

- `setupLLM` in `cmd/mcpmoat/scan_llm.go` runs in step 1 of the data flow. It calls
  `checkLLMFlags`, which checks the flags, the base URL and the key and returns the LLM config. A
  problem is a usage error (exit 2) before `scan` reads a config file. The error texts are fixed
  and never hold the key, the model name or the URL.
- Then `setupLLM` prints the warning on stderr with `scanWarnf`. The host in it goes through
  `termsafe.Quote`. Only after that, `buildClassifier` calls `cli.newClassifier`. It is the only
  call of that function, and it never runs without `--llm`.
- The provider, model and base URL come only from flags. The API key comes only from the
  environment (`llm.KeyEnv`), because an argument would show in `ps` and in the shell history.
  The key is a `discover.Secret`, so it prints as a mask in `fmt` and `slog` output.
- The base URL must be `https`, or `http` for a loopback host. The reason: the key must never
  cross a network in clear text.

The dial hook: `llm.Config.Dial` is a test hook. It is nil in production, and nil uses a
`net.Dialer`. For an `http` base URL, `loopbackDial` wraps it. It resolves the host at connect
time, requires that every address is a loopback address, and dials only those addresses. The check
at connect time is needed because a name such as `localhost` is loopback only by its text: the
system resolver can map it to another address. An address that does not answer gets a short
timeout, so the next address is tried soon (for example when a firewall drops packets to `::1`).
The client has its own `http.Transport` with TLS 1.2 or later. It follows no redirect, because a
redirect would carry the key to another location. It never uses a proxy for an `http` base URL, so
the key never goes to a proxy in clear text. For `https` it honours `HTTPS_PROXY` and `NO_PROXY`,
like the server connections. Go ignores a proxy value that it cannot parse and then connects
directly. The limits of a scan (tool count, workers, timeout, body size) are in the
[README](../README.md#optional-llm-classification-sends-data-off-your-machine). They live in
`cmd/mcpmoat` (`maxLLMTools`, `llmWorkers`) and `internal/llm`.

What is sent: `internal/llm` builds one request for each tool from the fixed system prompt
(`llm.SystemPrompt`), the fixed verdict schema and one user message. The message is a JSON object
with `tool_name`, `tool_description` and `truncated`. The description goes into it as a JSON string
value, never into the system prompt, so it cannot change the instructions of the model.
`cmd/mcpmoat` gives `internal/llm` only the name and the description (see
[Import direction](#import-direction)). The cuts are made at a rune boundary: `llm.MaxToolNameBytes`,
`llm.MaxDescriptionBytes` and, for the whole message, `llm.MaxToolMessageBytes`. `Classify` sets
`Verdict.Truncated` when it cut the name or the description. The flag never comes from the model
output. A cut name or description is a sign of risk, because the part that is not shown can hold
the payload. The system prompt tells the model to rate it at least `medium`, but the code does not
trust the model for this (see the verdict below).

The verdict: `parseVerdict` reads the model answer strictly: exactly one JSON object with the keys
`risk` and `category`, exact keys and case, no duplicate key, no other key, nothing after the
object. The values come from fixed lists. `classifyTools` turns a verdict into rows:

- A risk of `low`, `medium` or `high` gives one `MOAT-LLM-001` finding with that severity. The
  category goes in `related`. `none` gives no finding. The severity is never `critical`.
- `llmRow` builds the row. For a tool with `Verdict.Truncated` set, it returns `truncatedRow` when
  `belowMedium` is true for the risk or the answer is unusable. That row has the fixed text
  `llm.TruncatedText`. The code enforces the rule, not only the system prompt, because a prompt
  injection in the part before the cut could ask the model for `none`. The README owns the rule
  that the user sees: see
  [`--llm`](../README.md#optional-llm-classification-sends-data-off-your-machine).
- An answer that cannot be used for a tool that was not cut gives `MOAT-LLM-002` (medium). That is
  an invalid answer, a refusal or an answer cut at the token limit. Only `llm.ErrInvalidOutput`
  gives this finding.
- The finding texts are fixed in `internal/llm`, so no text from the model reaches the terminal or
  the JSON output.

`sortAnswer` sorts every error of `Classify` and fails closed. `llm.ErrInvalidOutput` gives
`MOAT-LLM-002`, the end of the context is a stop, and `llm.ErrProvider` is a provider failure. Any
other error is an internal error. Both failures stop the step. The first failure stops the running
requests, starts no new one and decides the stderr line. So a new error path can never make a
failed step look like a complete scan. The README lists the provider failures and the texts of the
exit-code-2 cases (see [`--llm`](../README.md#optional-llm-classification-sends-data-off-your-machine)
and [Exit codes](../README.md#exit-codes)). Every error of `internal/llm` has fixed text. It never
holds the key, a URL, a header, a response body or model output.

`classifyTools` only adds rows. It never changes or drops a rule finding, a pin, a diff or a
`To accept` line. The LLM rules share the exception of the pin rules: only `--ignore` drops LLM
rows, and the file cannot ignore them (step 3).

The proof that nothing is sent without `--llm` is the network tests in `cmd/mcpmoat` and the
offline CI job. The depguard fence (see [Import direction](#import-direction)) only keeps the
network code in `internal/inspect` and `internal/llm`.

## Where untrusted text is escaped

Config files and server output are untrusted. A cloned repository can ship a config, and a server
can send any text. Raw control characters in such text can rewrite your terminal.

`internal/termsafe` is the one place with the rule for this text:

- `Quote(s)` returns `s` unchanged when it is safe, and a quoted, escaped form when it is not.
- `QuoteIf(s, force)` also quotes a safe `s` when `force` is true.
- `QuoteCut(s, n)` cuts to `n` runes, quotes the result, and adds `CutMarker` when it cut.
- `Cut(s, n)` cuts to `n` runes at a rune boundary, adds no marker, and reports whether it cut.
- `IsInvisible(r)` tells if a rune shows as nothing.

The layers that import it are `cmd/mcpmoat`, `internal/discover`, `internal/report` and
`internal/rules`. `internal/pins` does not import it. It returns raw server text, and the report
layer escapes that text. To list the files, run:

```sh
git grep -l '"github.com/Ducarv/mcpmoat/internal/termsafe"' -- '*.go' ':!*_test.go'
```

The rule: untrusted text goes through `termsafe` before it reaches a terminal. This covers server
names, paths, argv and errors that carry server output. `Outcome.Err` can carry server output, so
the report layer must escape it. `discover.FileError.Error` already escapes.

The diff of a changed or new tool is the first place where a tool description reaches the terminal.
`internal/pins` keeps the raw text in `Change.Diff`. `report.WriteDiffs` splits each diff line into
the unified prefix (`@@`, `---`, `+++`, `+`, `-` or a space) and the rest. It writes the prefix as it
is and sends the rest through `termsafe.QuoteCut`, with a cap of 2000 runes for each line. A control
character, an escape sequence, a bidi override or invalid UTF-8 shows as a visible escape. The
tool and server names in the diff header are escaped too. The summary of `scan` and the stderr
lines of `scan` and `pin` that name a server or carry server output (the pinned notice, the
warnings and the errors) are escaped and cut in the same way.

An LLM finding row holds the tool name and the server name, which are escaped like the names of
any other finding. Its title, risk text, remediation and category are fixed text from
`internal/llm`. The model output never reaches the row. The `--llm` warning escapes the host of the
base URL, and the provider failure line holds only fixed text and numbers.

For secrets in output, see [Code style](../.agents/project.md#code-style).

## How to add a rule

A rule is one file, `rules/<ID>.yaml`, plus its test cases. The steps and the required cases are
in [Contributing a rule](../CONTRIBUTING.md#contributing-a-rule).

## See also

- [PRD](PRD.md), section 8: the target architecture.
- [How mcpmoat starts stdio servers](stdio-servers.md).
- [Documentation index](README.md).
- [CONTRIBUTING.md](../CONTRIBUTING.md).
