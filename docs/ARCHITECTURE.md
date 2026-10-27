# Architecture

> **Status:** this page describes the code as it is today and marks what is still planned. Today
> `mcpmoat scan --no-connect` reads configs, loads rules, lists servers and applies the config rules
> (T4 and T5) and the ignore list. `mcpmoat scan` without `--no-connect` also connects to the
> servers, pins their tools on the first run, and reports new, removed and changed tools on later
> runs (T2). It prints a diff for each new and each changed tool. It also applies the description
> and schema rules (T1 and T3, built-in and from `--rules`) to the tools, with a time limit for
> all servers and a share of it for each server. `mcpmoat pin --accept <server> --expect <digest>`
> accepts the changes. The shadowing check is not applied yet (#200). `mcpmoat scan --json` writes
> the same report as one JSON document (FR-15, see [JSON output](#json-output)). `mcpmoat scan
> --llm` also asks a language model to rate the name and description of each inspected tool, and
> adds advisory findings (FR-17, see
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
  discover/             config readers (Claude Code, Cursor, Codex), secret and credential checks
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
  that both commands use (`serverIdentity`, `readPins`, `readPinsLocked`, `printNewPinsFile`,
  `pinnable`, `appendDiff`). `scan_pins.go`
  holds the pin step of `scan` (`pinner`), and `accept_hint.go` the "To accept" line and its one
  decision function (`acceptAdvice`). `argscrub.go` hides the `--llm-base-url` values and the URL
  user info in the text of argument errors (`argHider`, `newBaseURLHider`, `hideUserinfo`).
  `scan.go` holds the parts of `scan`: `runScan` calls
  `parseScanArgs` (the flags, in a `scanArgs`), `buildScanSetup` (the notices and the `scanSetup`)
  and `scanConfigs`. `reportScan` then calls `runScanSteps` (the steps, in a `scanStepsResult`) and
  `writeScanOutput` (the terminal report or the JSON). `scan_json.go` builds the JSON report
  (`buildScanReport`). `scan_rules.go` loads the rules and builds the `rules.Analyzer`
  (`loadRules`), and `scan_tools.go` holds the tool rule step (`toolRulesStep`). Four files hold the
  `--llm` step.
  `scan_llm_flags.go` holds the flags, `checkLLMFlags` and the setup warning. `scan_llm_plan.go`
  builds the jobs (`llmPlan`, `planLLMJobs`, `fairShare`, `llmServerJobs`, `maxLLMTools`): it maps
  each `inspect.Tool` and the `inspect.Result.Credentials` of its server to an `llm.Input`, and
  gives each job a `*discover.TextRedactor` of the wide `inspect.Result.Secrets`
  (`llmJob.redactor`) for the row key.
  `scan_llm.go` runs the step (`llmStep`, `classifyPlan`, `runLLMJobs`, `sortAnswer`,
  `rejectedFailure` and the failure lines), and `scan_llm_rows.go` turns the answers into rows
  (`llmRow`, `invalidRow`, `llmSeverity`). The step calls a `toolClassifier`, a small interface
  that `*llm.Client` implements. The `cli.newClassifier` factory builds it, and tests replace the
  factory with a fake.
- `internal/termsafe`: escapes untrusted text for the terminal. See
  [Where untrusted text is escaped](#where-untrusted-text-is-escaped).
- `internal/safefile`: the one shared hardened file read. It confines the open to a directory with
  `os.Root`, refuses non-regular files, does not block on a FIFO (as the file or as the directory) and
  caps the size. `discover` and `rules` use it. A caller that must check the directory on its open
  handle first opens it with `OpenRoot`, checks it, and then opens the file with
  `OpenIfExistsInRoot` in the same root, so the checked directory is the one that it reads from.
  `pins.Load` and `pins.LoadLocked` do this.
- `internal/discover`: finds the MCP servers that the client configs declare. It does not start them.
  It also holds the shared redaction of tool text (`redact_text.go`: `TextRedactor`,
  `SecretTextValues`, `RedactTextPrefix`) and the credential checks (`ArgCredentials`, `TokenLike`,
  `IsAuthScheme`) that `inspect`, `llm` and `cmd/mcpmoat` use.
- `internal/inspect`: starts or calls each server and reads what it offers. It is the only product
  package that imports the MCP SDK (see [The `internal/inspect` interface](#the-internalinspect-interface)).
- `internal/rules`: loads and checks the YAML rules, applies the description and schema rules to
  one tool at a time (`Analyzer`), runs the config heuristics, and reads `.mcpmoat-ignore` (`scan`
  asks for that only with `--use-ignore-file`). It also holds the shadowing check
  (`CheckShadowing`), which `scan` does not call yet (#200).
- `internal/pins`: computes the canonical hash of each tool (`Canonical`, `Hash`), makes the pins of
  a server (`Snapshot`), keeps the versioned `pins.json` store (`Load`, `LoadLocked`, `Get`, `Set`,
  `Clone`, `Save` and `DefaultPath`), compares the pins with the current tools (`Compare`), and
  makes the digest of a tool set (`Digest`, `ValidDigest`). `Compare` finds changed, new, removed
  and not verified tools. It makes the unified diff of a changed or new tool, and shows the whole
  current text of a pinned tool whose pin cannot be checked. See [Tool hash](#tool-hash),
  [Tool set digest](#tool-set-digest) and [The `pins.json` store](#the-pinsjson-store).
- `internal/report`: writes the terminal output: the servers (`WriteServers`), a summary with one
  line for each server (`WriteSummary`), the findings grouped by severity (`WriteFindings`) and the
  diffs of changed, new and not verified tools (`WriteDiffs`). `Style` (`style.go`) decides the
  colour. See [Terminal report](#terminal-report). It also renders the JSON report of
  `scan --json` (`WriteJSON`), with caps on the text fields. See [JSON output](#json-output).
- `internal/llm`: the optional `--llm` client (FR-17). It sends the name and description of one tool
  to an Anthropic or OpenAI-compatible API and accepts only a fixed verdict. It uses the standard
  library, the module `github.com/cenkalti/backoff/v7` for the waits between retries and, from this
  module, only `discover` (see [Import direction](#import-direction)). See
  [The `--llm` classifier](#the---llm-classifier).
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
| `internal/llm` | `discover`, and the module `github.com/cenkalti/backoff/v7` |
| `cmd/mcpmoat` | `discover`, `inspect`, `llm`, `pins`, `report`, `rules`, `termsafe` |

`internal/inspect` does not import `termsafe`. The report layer escapes what `inspect` returns.
`internal/rules` imports `inspect` for the `inspect.Tool` type that `Analyzer.CheckTool` reads.
This direction is allowed: `inspect` does not import `rules`, so there is no cycle.
`internal/llm` does not import `inspect`: `cmd/mcpmoat` gives it only the tool name, the
description and the credential values of the server (`llm.Input`). `internal/llm` imports
`discover` for the `discover.Secret` type of these values and of the API key, for the text
redaction (`discover.SecretTextValues`, `discover.RedactTextPrefix`), for `discover.Mask` and for
`discover.IsLoopbackHost`. It imports `github.com/cenkalti/backoff/v7` (v7.0.1, MIT licence, no
dependencies of its own) only for the backoff of its retries. No error text of that module leaves
`internal/llm`.

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
a proof. It does not cover `os.StartProcess`, `syscall` (`cmd/mcpmoat`, `internal/inspect`,
`internal/pins` and `internal/safefile` import it) or the imports of third-party packages. The
network tests in `cmd/mcpmoat` and the offline CI job are the proof.

## Data flow

### Implemented

`mcpmoat scan` does these steps today:

1. `cmd/mcpmoat` parses the flags and checks `--timeout`, `--concurrency` and `--fail-on`. A bad
   value is a usage error with exit code 2. Then `setupLLM` checks the `--llm` flags and the API
   key. With `--llm`, it also prints the warning that data leaves the machine and builds the
   classifier. This all happens before the rules load (see
   [The `--llm` classifier](#the---llm-classifier)).
2. It loads the rules with `rules.Builtin` and, with `--rules`, `rules.LoadDir`. Then
   `rules.NewSet` checks for duplicate rule IDs, for clashes with built-in IDs and for reserved
   native IDs (`rules.ReservedRuleID`): a rule from `--rules` must not use `MOAT-T1-023`,
   `MOAT-T1-024`, `MOAT-T4-005` or an ID that starts with `MOAT-T2-` or `MOAT-LLM-`, in any case.
   Last, `rules.NewAnalyzer` compiles the match block of each rule once. It compiles a config rule
   only to check it and drops its matcher, and it keeps the description and schema rules. A rule
   whose regex does not compile gives a load error with the file, the field `match` and the reason.
   A bad rule file, an ID problem or a bad regex gives exit code 2, also with `--no-connect`
   (`loadRules` in `cmd/mcpmoat/scan_rules.go`). Then `scan` prints a fixed notice on stderr for
   the rules from `--rules` that it does not apply: `configRulesNotice` when a rule has the target
   `config` (`scan` runs only its built-in config checks), and `toolRulesNoConnectNotice` when a
   rule has the target `description` or `schema` and `--no-connect` is set.
3. `scan` does this step after step 4, because it needs the working directory that `loadConfigs`
   returns. Only with `--use-ignore-file`, it reads `.mcpmoat-ignore` with `rules.ReadIgnoreFile`
   (`loadIgnore`). Without the flag, `scan` only checks that the file exists (`os.Lstat` in
   `noteIgnoreFile`, which never opens the file) and prints the note `ignoreFileNote` on stderr.
   Then it adds the `--ignore` rule IDs. It keeps two lists (`scanIgnores` in
   `cmd/mcpmoat/scan_pins.go`): one for the config rules and the tool rules, with the file and the
   flags, and one for the pin rules, the LLM rules, `MOAT-T1-023`, `MOAT-T1-024` and `MOAT-T4-005`,
   with the flags only. The file can come from a cloned repository, so it cannot ignore a pin rule,
   an LLM rule, the budget rule or a cap rule. The guard is `fileCannotIgnore`: it is true for a
   pin rule (`pins.IsPinRuleID`: the rule ID starts with `MOAT-T2-`, the unexported
   `ruleIDPrefix`), for `llm.RuleID` and `llm.RuleIDInvalid` (`MOAT-LLM-001` and `MOAT-LLM-002`),
   for `rules.RuleAnalysisBudget` (`MOAT-T1-023`), for `rules.RuleToolFindingCap` (`MOAT-T1-024`)
   and for `rules.RuleConfigFindingCap` (`MOAT-T4-005`). When a file entry for such a rule matches
   a finding, `scan` keeps the finding, prints one warning for each such rule ID
   (`warnFileCannotIgnore`), and tells the user to use `--ignore`. `scanIgnores.fileEntries` holds
   the number of entries that `scan` read from the file (the N in the stderr line
   `using N entries`, set in `loadIgnore`). Some of them can be entries that the file cannot apply
   (see above) or that match no finding. The count goes to the JSON `ignored.file_entries`. It is 0
   without `--use-ignore-file`.
4. It finds the servers with `loadConfigs` in `cmd/mcpmoat/configs.go`. That function runs
   `discover.Discover`, or reads one file with `discover.ReadConfig` when `--config` is set. `pin`
   uses the same function, so both commands read the configs with the same trust rules.
5. It runs the built-in config rules on every server it found, also a disabled one, as `discover`
   gives it. `rules.CheckConfig` gives the T4 findings (MOAT-T4-001 to 004). The typosquat check
   from `rules.NewBuiltinTyposquat` gives the T5 finding (MOAT-T5-001). The ignore list drops
   some findings. The rule set gives the severity of each one that is left. `configStep` runs this
   step with `configChecks.findings` (both in `cmd/mcpmoat/scan_findings.go`), and it caps the rows
   (#213):
   - The caps count the rows after the ignore list. First a server keeps at most 100 rows
     (`configRowsPerServer`). Then, when more than 10,000 rows are left over all the servers, the
     scan keeps 10,000 (`configRowsTotal`). Each cut keeps the most severe rows (`cutConfigHits`, a
     stable sort): severity first, then trusted servers before untrusted ones (`configHit.untrusted`,
     so a project file cannot push out the finding of a server that the user set up), then server
     order, then finding order. A severity that is not valid counts as critical (`capRank`). The kept rows of a server stay in their first order.
   - A server that lost rows in one or both cuts gets one `MOAT-T4-005` row
     (`rules.RuleConfigFindingCap`, a native rule with no YAML file, see `configCapRow`). Its
     related text is `N more config findings are not listed; limit M` (`configCapText`). M is 100,
     or 10000 when the scan cut rows of that server. Its severity is the highest severity of the
     rows it left out, but never lower than high (`configCapSeverity`), so the row fails closed.
     It does not count toward the caps. So the step gives at most 10,000 config rows plus one cap
     row for each cut server.
   - Only `--ignore MOAT-T4-005` drops the cap row, not the file (`fileCannotIgnore`), so a hostile
     config and ignore file cannot hide that rows were cut. `configStep` prints one line on stderr
     when a server lost rows, also when `--ignore` drops the cap rows (`configCapWarningText`):
     `mcpmoat scan: warning: config findings were left out for N servers; see MOAT-T4-005` (or
     `for 1 server`). The text does not say that each server has a row, because `--ignore` can
     drop the rows. The JSON `complete` stays `true`, and the exit code follows `--fail-on`.
   - The caps bound the rows, not the work before the cut: `rules.CheckConfig` still makes one
     finding for each key (see [Size bound](#size-bound)).
6. `writeScanOutput` writes the report on stdout. Without `--json` it calls `writeScanReport` (see
   [Terminal report](#terminal-report)): `report.WriteServers` prints the server table,
   `report.WriteSummary` prints the summary, and `report.WriteFindings` prints the findings, only
   when findings are left. It never prints a value. Last, `reportScan` prints the ignored count for
   each rule ID on stderr (`printIgnored`: only rule IDs and counts, no server names). With
   `--json`, step 6 is different: `buildScanReport` (`cmd/mcpmoat/scan_json.go`) makes one
   `report.ScanReport` from the same servers, findings and diffs, and `report.WriteJSON` writes it
   on stdout instead of the terminal report. The `ignored` map that `printIgnored` prints, and
   `scanIgnores.fileEntries`, also go into the document (`jsonIgnored`): they become the `ignored`
   object, so a CI job can read the counts without the stderr line. See
   [JSON output](#json-output).

Steps 1 and 2 always run. Steps 3 to 6 run in both modes. In the code, `runScan` does steps 1 and 2
(`parseScanArgs`, `setupLLM`, `loadRules` and `buildScanSetup`). `scanConfigs` does steps 3 and 4.
`reportScan` does the rest: `runScanSteps` runs step 5 and the steps below, and `writeScanOutput`
does step 6. Without `--no-connect`, `scan` adds the connect, pin, tool rule and LLM steps between
step 5 and step 6:

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
  prints no report and exits with code 2. A signal during the tool rule step (5d) or the LLM step
  (5e) gives the same result. A second signal ends mcpmoat at once.
- 5b. For each server, `cmd/mcpmoat` checks the tools against the store that it read in 5a.
  - A server that is not in the store is pinned on its first run. If the tools cannot be pinned (see
    `pinnable`), the server gets a high MOAT-T2-004 finding: it is never pinned, so its tools are
    never checked for changes, and it must fail the default threshold. A server whose config path is
    not absolute (the working directory is not known) gets the same finding with the reason
    `the config path is not absolute`, because its identity would not match the store.
    `pins.json` has a size limit of 32 MiB, and `Store.Set` refuses a server that would make the
    file larger (`pins.ErrStoreFull`). The report comes before the save, so `pinOutcomes` adds each
    first-run server to a copy of the store (`pinner.budget`, made with `Store.Clone`) in the order
    of the save. A server that does not fit is not pinned and gets the same high MOAT-T2-004
    finding with the fixed reason `reasonStoreFull` and the fix `fixStoreFull` (the texts are in
    [Pins and rug pulls](pins.md)). The reason stays at 80 runes or less, so the terminal report
    does not cut it. The risk (`riskServerUnverified`) tells that the tools of the server are not
    checked against pins. The servers that fit are still pinned.
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
  - A server that is in the store goes through `pins.CompareMasked` (`pinner.compare`, see Masked
    diffs in [Tool hash](#tool-hash)). The findings are MOAT-T2-001 (changed tool, high),
    MOAT-T2-002 (new tool, medium), MOAT-T2-003 (removed tool, low) and MOAT-T2-004 (not
    verified). The severity of MOAT-T2-004 is high when the tool name is pinned, because a
    duplicate, invalid or unverifiable copy of a pinned tool can hide a rug pull, and medium
    otherwise (`Change.Severity` in `internal/pins/compare.go`). A tool is not verified when its
    name is empty or used twice, when it has no canonical form, when it is pinned with another
    hash version, or when its pinned text does not match its hash. These are native rule IDs:
    there is no YAML file for them, because pins handle T2. A MOAT-T2-004 finding shows a fixed
    reason text in brackets after the tool name on the `Tool` line, or on a `Reason` line when the
    finding has no tool name (it is about the whole server, or the tool name is empty):
    `duplicate tool name`, `empty tool name`, `invalid tool data`, `pinned with another hash
    version` or `pinned text does not match its hash`. The reason never holds server text. For
    the last two reasons the pin cannot be trusted, so the change also has a diff of the whole
    current tool (`Change.Diff`). The `--ignore` flag drops them by rule ID, server and real tool
    name (`Change.RawTool`, not the masked `key`). The `.mcpmoat-ignore` file does not, also with
    `--use-ignore-file` (see step 3). `scan` never re-pins a server that is in the store. When the
    tools of a pinned server no longer fit the size limit of pins.json (`pins.ValidateServer`),
    `pins.Compare` has no reason
    for it, so `pinner.compare` adds the high MOAT-T2-004 finding `the tools cannot be pinned` that
    a first run gives.
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
  - The JSON `accept` object (`scan --json`, schema version 3) comes from the same hint and the same
    decision as the terminal line. `acceptAdvice` (`cmd/mcpmoat/accept_hint.go`) returns the text
    of the line and `isCommand`, which is true only when the text is the `pin --accept` command
    (`acceptCommand`) and false when it is the prose steps (`acceptSteps`). The terminal prints
    `text`. The JSON gets `digest` (the digest of the hint) and, only when `isCommand` is true,
    `command` (the same `text`). It never gets the prose, so a program cannot run a line that the
    terminal shows as steps. `acceptOf` (`cmd/mcpmoat/scan_json.go`) finds the hint of a server by
    its identity (`serverIdentity`); a server with no hint has no `accept` key. When two servers
    have the same identity (the same client, source, project path and name), the pin step compares
    only the first one, so `scan` has one hint and prints one "To accept" line. `acceptOf` matches
    by identity, so the JSON gives both servers the same `accept` object, with the same digest.
    `WriteJSON` never cuts `digest` or `command`.
- 5d. The tool rule step (`toolRulesStep` in `cmd/mcpmoat/scan_tools.go`) runs after the pin step
  and before the LLM step, on each server with status `StatusOK`, in config order. It does not run
  when the pin step failed as a whole. For each tool, `rules.Analyzer.CheckTool` runs the
  description rules on `Tool.Description` and the schema rules on the text of `Tool.InputSchema`.
  It reads no other field: not the output schema, the title or the annotations, and not the
  prompts or the resources. It checks one tool at a time and keeps nothing after the call, so the
  memory stays low.
  - Shared forms: the rules of one text share one prepared text, so the match forms of the text
    (at most 21 for a regex, `maxRegexForms`) are built once for all the rules. The schema rules of
    a tool also share the decoded schema strings, the seams and the raw text pass. The
    `match_window` heuristic reads the shared result of the window cut. The findings come in a fixed
    order: the description rules, then the schema rules, each in rule ID order.
  - Rows: one row for each rule with a hit. The row has the field `tool`, the tool name as the key
    and `description` or `schema` as the related name. It never holds tool text or pattern text.
    The key is cut to 512 runes and then ends with `...` (`toolKey`, `maxToolKeyRunes`), so a long
    tool name cannot fill the report.
    The rule set gives the severity, the title, the risk and the remediation. The ignore list drops
    rows like the config rows (see step 3), but the `MOAT-T1-023` and `MOAT-T1-024` rows only with
    `--ignore`.
  - Row cap: a server keeps at most 1000 tool rows (`maxToolRowsPerServer` in
    `cmd/mcpmoat/scan_tools.go`). `addTool` holds the rows after the ignore list, in tool order: a
    row that the list drops does not count. At the end of the server, `flushTools` keeps the most
    severe rows (a stable sort, so among rows of the same severity it keeps the ones of the first
    tools) and leaves them in tool order. A hostile server cannot push a severe finding out of the
    report with weak findings that come first. A row over the limit is not kept, but it is counted.
    The pending rows of one server are bounded by its tools (at most 10,000) times the rules. Then
    `addCapRow` adds one `MOAT-T1-024` row (`rules.RuleToolFindingCap`, a native rule with no YAML file: its title, risk
    and fix are fixed texts in `scan_tools.go`, `capTitle`, `capRisk` and `capRemediation`) and
    prints one warning on stderr. Its related text is `N more tool findings are not listed; limit M`
    (`capText`). The `MOAT-T1-023` row and the cap row do not count toward the limit. The cap row
    has the severity of `failClosedSeverity`, the same as the budget row, so the row fails closed (high
    with the built-in rules): a server that floods the report still fails the gate. Only
    `--ignore MOAT-T1-024` drops it, not the file (`fileCannotIgnore`), so a cloned repository
    cannot hide that findings were left out. The warning prints also when `--ignore` drops the row.
    This is a finding, not an execution error: the exit code follows `--fail-on`, and the JSON
    `complete` stays `true`. The cap keeps a hostile server from filling the report. It does not cap
    the other rows (see [Size bound](#size-bound)).
  - Budget (#210): the whole step has a wall-clock limit of 30 seconds (`toolRulesStepBudget`), a
    context deadline on the step context that `checkTools` makes. Each server gets its own context,
    made from the step context, with a fair share of the time that is left: the time until the
    step limit divided by the servers still to check, but never more than 5 seconds
    (`toolRulesBudget`, see `serverShare`). A server that ends early leaves its time to the servers
    after it. Before #210 each server had its own 5 seconds, one after the other, so 20 servers
    could take about 100 seconds. The analyzer checks the context before each regex on each form,
    and between the schema strings and the seams. So it stops at most about one regex on one form
    after the deadline, plus one build of the forms of one text, which cannot be stopped (#146).
    The worst known case of that build is a fill of CSIs (see the cost comment in
    `internal/rules/match.go` and `maxStrictOSCStarts`). [Limits](limits.md) has the measured size
    of the overshoot, and the comment of `TestAnalyzerCheckToolHostileBudget` in
    `internal/rules/analyze_test.go` explains it. So the step takes at most 30 s plus one
    overshoot. The overshoot comes out of the shared limit, so servers early in the order can use
    up the time of later servers: those servers get `MOAT-T1-023`, never a silent pass. A server
    that uses up its share keeps the rows found so far and gets one finding `MOAT-T1-023`
    (`rules.RuleAnalysisBudget`, a native rule with no YAML file). Its severity is the highest
    severity of the description and schema rules that `scan` applies, but never lower than high
    (`failClosedSeverity`, `rules.Analyzer.MaxSeverity`). So it is high with the built-in rules,
    and critical when a description or schema rule from `--rules` is critical. This severity
    counts every applied description or schema rule, also one that `--ignore` drops, on purpose:
    the rules that did not run could have given a finding (fail closed). Its related text is
    `rule analysis time budget used up; N of M tools not fully checked`. `checkServer`
    also prints one warning on stderr for that server, with the share that it got, rounded to
    milliseconds. A server that the step reaches after the step limit, or with a fair share under
    1 ms (`minServerShare`, the rounding unit of that warning), is not analysed, and the servers
    after it are not analysed either (`checkTools`). So the late servers are always the last ones.
    `addLateServer` gives each late server the same row for all its tools, with no warning of its
    own. At the end, the step prints one line for all such servers (`lateServersText`):
    `mcpmoat scan: warning: the 30s time limit of the rule analysis left too little time; N
    servers were not checked`. This is a finding, not an execution error: the exit code follows `--fail-on` (1
    with the default), and the JSON `complete` stays `true` (see [JSON output](#json-output)). The
    end of the step limit is not an interrupt: `interrupted` checks the parent context, which
    ends only on a signal.
  - Errors: a signal during the step prints the interrupted line, prints no report and gives exit
    code 2 (see Signals above). An internal error of the step (a guard: `CheckTool` fails only when
    its context ends) prints `mcpmoat scan: server <name>: the rule analysis failed (internal
    error)`, prints no report and gives exit code 2.
- 5e. Only with `--llm` (FR-17), `llmStep` in `cmd/mcpmoat/scan_llm.go` runs after the tool rule
  step: `planLLMJobs` builds the jobs, and `classifyPlan` runs them. It sends the name and
  description of each tool of each server with status `StatusOK` to the classifier, with the
  credential values of that server (`inspect.Result.Credentials` goes to `llm.Input.Secrets`, and
  `internal/llm` replaces them before the request). For a stdio server, these values include the
  credentials in its expanded argv. The wide `inspect.Result.Secrets` stays for the local report:
  it masks the `key` of each LLM row (see Secret values in [The `--llm`
  classifier](#the---llm-classifier)). It adds one advisory row for each tool that the model rates
  as risky, for each tool with an unusable answer or a refusal of the provider, and for each cut
  tool (see the verdict rules in [The `--llm` classifier](#the---llm-classifier)). It only adds
  rows: it never changes or drops a rule finding, and it never touches pins, diffs or hints. Only
  `--ignore` drops LLM rows, as for the pin rows. The `.mcpmoat-ignore` file does not, also with
  `--use-ignore-file` (see step 3). The ignored count includes the dropped LLM rows.
- The pin findings and the tool rule findings join the config findings in one report. A changed
  tool and a new tool also get a diff, so the user can review the content of a new tool before
  they accept it. A new tool has the header `New tool <tool> on server <server>:` and only added
  lines. A not verified tool with a diff (see 5b) has the header
  `Not verified tool <tool> on server <server> (current text):` and only added lines. A finding
  that the user ignored gets no diff. `report.WriteDiffs` prints the diffs after the findings.
  When a diff was cut at the size limit (`Change.Truncated`), `scan` prints a warning on stderr
  that names the tool and the server: `the diff of tool <tool> on server <server> was cut at the
  size limit; review the full tool before you accept it`. Then `writeAcceptHints` prints one line
  for each hint on stdout:
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
  (`savePinned` in `cmd/mcpmoat/scan.go`). `savePinned` reads `pins.json` again with the lock on
  the pins directory (`readPinsLocked`, see [The `pins.json` store](#the-pinsjson-store)), sets
  only the first-run servers that the file does not hold yet (another run may have pinned them
  meanwhile), saves, and then releases the lock. It releases the lock right after the save, before
  it prints any line, so a blocked stdout or stderr never holds the lock. The `pinned N tools`
  lines come after the save, only for the servers it set. When the save created a new pins file
  (`Store.Existed` is false), `printNewPinsFile` prints one line before them. When the first read
  found `pins.json` but the locked read does not, the file was removed while `scan` ran: a save
  would drop every older pin, so `savePinned` saves nothing, prints `pinsRemovedText` and `scan`
  exits with 2 (`pinsRemovedWhileRunning`). When the file holds a server that this scan wanted to
  pin, with other tools, `scan` prints a warning: this scan did not compare its tools with the pins
  of the other run. Another run can make the file larger after the report, so a server that fitted
  in 5b can get `pins.ErrStoreFull` here. That server is not pinned and gets a warning on stderr,
  the other servers are still saved, and `scan` exits with 2. The message texts are in [Pins and
  rug pulls](pins.md).

`--no-connect` starts no process and reads and writes no `pins.json`.

In `reportScan`, a signal during the inspection, the tool rule step or the LLM step, or an internal
error of the tool rule step, makes `runScanSteps` stop (its `ok` is false), and `reportScan` returns
2 at once. A report write error in `writeScanOutput` returns 2 at once too. Otherwise `reportScan`
writes the report and then gets the exit code from `scanExitCode` in `cmd/mcpmoat/scan_findings.go`.
An execution error gives 2, and 2 wins over 1. Otherwise `hasFailingFinding` gives 1 when a row (the
ignored findings are already dropped) has a severity at or above `--fail-on`. It compares
`rules.Severity` `Rank()` values, and a severity with rank 0 (unknown) always counts. The user
contract, with the list of execution errors, is in [Exit codes](exit-codes.md). `--json` does not
change the exit codes.

`mcpmoat pin --accept <server> [--project <path>] [--expect <digest>]` (FR-13) does these steps:

1. It finds the server by exact name, in `--config <file>` or by auto-discovery, like `scan`
   (`selectServers`). With `--project <path>`, it keeps only the server of that project. Without it,
   when the name is in more than one place and exactly one of them is outside any project, it keeps
   that one. An unknown name exits with 2. A name that still matches more than one server exits with
   2 and lists the matches; `--config` or `--project` narrows them. `pin` fails closed on any config
   file problem, because a broken file can hide a second server with the same name. It prints each
   problem, then `mcpmoat pin: fix the config file or choose one with --config <file>`, and exits
   with 2. It inspects nothing and writes nothing.
2. It reads `pins.json` (`pins.Load`). This is the first read of the command. A bad file exits with
   2 before any server starts. It reads the file again, with no lock, before step 4, and a third
   time, with the lock, in step 6. When the pins file existed at the first read of the command
   and a later read does not find it, `pin` saves nothing (steps 4 and 6).
3. It inspects that one server with `--timeout`, with the same inspector as `scan`. A server that
   fails, times out or is refused exits with 2, and nothing is written. The inspection warnings go
   to stderr, like in `scan`.
4. It makes the pins of the tools (`pins.Snapshot`) and compares them with the pins of the read
   without the lock (`pins.CompareMasked` with the mask of the server). It prints the diff of each
   changed tool and of each new tool on stdout (`report.WriteDiffs`). When the pins file existed at
   the first read of the command but this read does not find it, the file was removed while the
   server ran. Then `pin` prints no diff (every tool would look new), saves nothing, prints
   `pinsRemovedText` and exits with 2 (`pinsRemovedWhileRunning`). A server that is not pinned yet
   has no pins, so `pin` shows every tool as a new tool, with only added lines. A diff that was cut
   at the size limit gives the same stderr warning as in `scan`.
5. With `--expect`, it computes `pins.Digest` of the snapshot and compares it with the flag value
   before `Store.Set` and `Save`. If they differ, it prints
   `mcpmoat pin: the tools of <server> differ from what scan showed (digest ..., expected ...);
   nothing was saved. Run scan again and review the diff.` on stderr and exits with 2. The server
   picks the tools that it shows to each run, so without this check a hostile server could show
   harmless tools to `scan` and harmful tools to `pin`. `pin` checks the flag with
   `pins.ValidDigest` right after it parses the flags, so an invalid or empty `--expect` exits with 2
   before it reads any file or starts any server.
6. It reads `pins.json` again with the lock on the pins directory (`readPinsLocked`), sets the
   pins of this server only (`Store.Set`) on that store, saves the file, and then releases the
   lock. It releases the lock right after the save, before it prints any line, so a blocked stdout
   or stderr never holds the lock. The diffs of step 4 come from the read without the lock, so a
   slow reader of stdout (a pager) never holds the lock. When the file existed at the first read
   of the command (or at the read for the diffs) but not at the locked read, it was removed while
   `pin` ran: `pin` saves nothing, prints `pinsRemovedText` and exits with 2
   (`pinsRemovedWhileRunning`). When the entry of this server changed between the two reads, `pin`
   warns that the diff is against the older pins. The counts
   of step 7 come from the locked store. Other servers keep their pins, and so do entries that
   another run wrote. A `pins.json` problem exits with 2. When `Set` refuses the server with
   `pins.ErrStoreFull`, `pin` prints a message that the pins file is full (see [Pins and rug
   pulls](pins.md)), saves nothing and exits with 2. When the save created a new pins file,
   `printNewPinsFile` prints one line on stderr before step 7.
7. It prints `accepted <server>: N new, N changed, N removed` on stdout, with `, N not verified`
   added only when N is above 0. Without `--expect`, it also prints a note on stderr that it trusts
   the tools that the server returns now. The note comes before the save (step 6).

A signal during step 3 (Ctrl-C, `SIGTERM` or `SIGHUP`, see Signals above) stops the server. `pin`
saves nothing, prints `mcpmoat pin: interrupted; no pins were saved` and exits with 2.

The code below is built and tested, but `scan` does not call it yet: `rules.CheckShadowing`
(#200).

Known limit: a renamed or moved server (a new name, config file or project path) has a new identity.
`scan` pins it again as a new server, and it does not report the old pin. A follow-up issue will
track this.

### Planned (PRD section 8)

The target flow is `discover -> inspect -> rules -> pins -> report`. All five steps run today.
`scan` runs the tool rules after the pin step, not before it. The order does not change the
findings, because neither step reads the result of the other. The open parts are in the `rules`
step:

- `discover` lists the servers.
- `inspect` connects and reads the tools, prompts and resources.
- `rules` applies the rules and the heuristics to what `inspect` read. Today the tool rules read
  only the description and the input schema of each tool (see 5d), not the prompts or the
  resources. The shadowing check is not applied yet (#200).
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
text is raw in the diff, apart from the mask below. The report layer escapes it (see [Where
untrusted text is escaped](#where-untrusted-text-is-escaped)).

Masked diffs: `scan` and `pin` call `pins.CompareMasked(stored, current, mask)`. `pins.Compare` is
the same call with a nil mask. The mask comes from `cmd/mcpmoat` (`compareMask` in
`pins_shared.go`, over one `discover.TextRedactor` for each server, built from
`inspect.Result.Secrets`), so `internal/pins` needs no list of secrets. `discover.NewTextRedactor`
reads the values and builds the border table of the search for each value once, and every string of
a pin diff reuses them. The search still runs once for each configured value, so a hostile config
with very many values makes a large diff slower. A multi-pattern search would fix that (a
follow-up). `render` applies the mask to the decoded text of both sides before the 200-rune wrap,
the trim and the 64 KiB cut: to the name, the title, the description, and every JSON string value,
key and number of the annotations, `_meta`, icons and schemas (`maskJSON`). So a wrap or a cut
cannot leave a part of a value, and a JSON escape in the server text (`\"`, `\u0041`) cannot hide
one. This holds for how the server writes the value, not for the value itself: the mask compares the
decoded bytes, so a configured value that holds a backslash sequence (the Windows path
`C:\tools\new_dir` holds `\t` and `\n`) is not found when the server sends a real tab and newline
there, and the escaped output then shows the value again. `CompareMasked` also masks `Change.Tool`
and keeps the real name in `Change.RawTool`, which only the ignore lookup reads and which is never
printed. The verdicts, the hashes, the digest and `pins.json` use the raw text. When the hashes
differ but the masked texts are equal, the diff is the fixed note `the tool changed only in text
that holds a secret value from the config, so the diff is hidden`. For the limits of this mask, see
Known limits in [The `pins.json` store](#the-pinsjson-store).

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
  hosts. Its type is `inspect.DialFunc`, which has the signature of `net.Dialer.DialContext`.

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
  other text in the file. The same is true for a URL from the server, such as a signed icon `src`
  with a token in it. The file has mode `0600`, so treat it as private. The pin diff masks the
  configured values of the server (`pins.CompareMasked`, see Masked diffs in [Tool
  hash](#tool-hash)), but not a URL token that the server made itself. For a value that is no
  longer configured, see Known limits below.
- Read, change and write: `Load` reads the file through `safefile` and fails closed. A bad file is
  an error and never an empty store, because an empty store would hide a rug pull. `Set` checks one
  server and refuses it on its own, with a size cap of 2 MiB for each server (compact JSON), so the
  caller can still save the others. The server chose the data that `Set` refuses, so the caller must
  report a refused server, never skip it silently: a server that is never pinned looks new on each
  run, and its changes are never reported. `Save` writes atomically (temp file, mode `0600`, sync,
  rename). A new directory gets mode `0700`. The rules, the caps and the other error texts are in
  the doc comments of `Load`, `LoadLocked`, `Set` and `Save` in `internal/pins/store.go`.
- Size budget: the whole file has a limit of 32 MiB, as the indented JSON that `Save` writes. The
  `Store` knows the size of that file without an encode, so `Set` also refuses a server whose entry
  would make the file larger than the limit, with an error that wraps `ErrStoreFull`. The store
  does not change, so the servers that fit are still saved and only the refused server is not
  pinned. `Set` refuses only growth: a change that does not make the file larger, such as a smaller
  replacement of a server, is always accepted. `Clone` returns a copy of the store, so `scan` can
  call `Set` on the copy to learn whether a server fits before it prints the report (see 5b),
  without a change to the real store. The size check in `Save` stays as a backstop. The format of
  `pins.json` did not change, so its version stays 1.
- Owner and mode check: `Load` and `LoadLocked` refuse an unsafe pins directory or `pins.json`, and
  `Save` refuses an unsafe pins directory. Unsafe means that another user owns the path, that group
  or others can write it (mode bits `0o022`), or (macOS only) that its ACL lets a user or group
  write it. The error wraps `ErrInsecurePermissions` and names the path, the mode and a fix (the
  texts are in [docs/pins.md](pins.md)). mcpmoat never changes a mode itself, so the user must fix
  an unsafe path. `scan` and `pin --accept` exit with 2 (FR-16). The first read runs before any
  server starts. Both commands read the file again just before they save, and then they save. That
  second read and the save can refuse after the servers ran, because a mode can change while `scan`
  inspects them. Modes such as `0755` for a directory and `0644` for a file pass: pins are not
  secret, so this is an integrity check. The code is in `internal/pins` (`perm.go`, `perm_unix.go`,
  `perm_other.go`, `acl_darwin.go`, `acl_other.go`).
- Checks on the open handles: `Load` opens the pins directory once, as an `os.Root`
  (`safefile.OpenRoot`), and checks the owner, the mode and the ACL on the open directory handle
  (`checkDirHandle`). It opens `pins.json` through that root (`safefile.OpenIfExistsInRoot`) and
  checks the open file (`checkFileHandle`) before the type and size checks and before the read
  (`readChecked`). So the checked directory and file are the ones that `Load` reads, with no path
  race between the check and the read. An unsafe file that is also larger than 32 MiB reports the
  permission problem, not the size. A pins directory or a `pins.json` that the user may not open
  (for example a root-owned path with mode `0700` or `0600`) gets the owner check by path
  (`dirOpenError`, `checkFilePermByPath`), so the owner problem shows with its hint and not only as
  "permission denied".
- Symlinks: a `pins.json` that is a symlink is refused with an error that wraps
  `ErrInsecurePermissions`, also when its target is in the pins directory. `readChecked` compares
  the open file with the directory entry (`os.SameFile`), so an entry that another file replaced
  after the open is refused too. The fix is to replace the symlink with the file. A symlink that is
  absolute or that leaves the directory is refused before that (`safefile.ErrOutsideRoot`). A
  pins directory that is a symlink (for example a config directory on another volume), and a
  symlink in a parent, are followed: the checks see the target. A symlink on the path, the pins
  directory included, must belong to the current user or root (`checkSymlinkOwner`). This holds for
  every symlink that the walk meets, also a symlink that is reached only through the target of
  another symlink (see the next item). The check reads each entry with `os.Lstat`, because
  `os.Stat` shows only the target. The sticky bit of a parent such as `/tmp` does not stop another
  user from creating a symlink there and pointing it to another directory later.
- Parent directories: `Load` and `LoadLocked` first check each parent directory of the pins
  directory, up to `/` (`checkParents`). `checkParentsAs` resolves the path one part at a time, as
  the kernel does, and does not use `filepath.EvalSymlinks`. It starts at `/`. For a symlink it
  checks the owner, reads the target with `os.Readlink` and goes on inside the target (from `/` for
  an absolute target, from the directory that holds the link for a relative one). A `..` goes up
  from the directory that the walk has reached, not from the written path. It stops with an error
  after 40 symlinks, which also ends a loop. So when `~/.config` is a symlink to `/data/cfg`,
  `/data` is checked too, and so is a link that `/data/cfg` is itself. Every directory above the
  pins directory that the walk passes, also one that holds a symlink or lies inside a link target,
  gets the owner and mode check once. A parent is refused when a user that is neither the current
  user nor root owns it, or when group or others can write it, unless the sticky bit is set (as on
  `/tmp`), and a symlink that such a user owns is refused (see the symlink rule above). When more
  than one entry is unsafe, the error names the last one that the walk found, which is the one
  nearest to the pins directory. The error names the real path, so on macOS it can say
  `/private/var/...` for a path that you wrote as `/var/...`. A refusal has no `read <path>:`
  prefix. The fix hint is `chmod go-w -- '<path>'`, or a private `XDG_CONFIG_HOME`. A missing
  parent (a first run) stops the walk, so the nearest existing parent, in which the pins directory
  is made, and every directory above it are still checked. Without this check, a user who can
  write a parent could swap, rename or remove the whole `mcpmoat/` directory, and the next run
  would pin the current tools as a first run. The check is by path, by design: when no other user
  can write a parent, nobody but root can swap a part of the path between the check and the open.
- ACL (macOS only): on macOS an ACL is separate from the mode bits, so `chmod +a` can let another
  user write a path that passes the mode check. `checkACL` reads the ACL of the open pins directory
  and of the open `pins.json` with the `fgetattrlist(2)` system call, as a raw syscall without cgo.
  It refuses any allow entry that holds a write-class right, for any principal. The fix hint is
  `chmod -N -- '<path>'`, which removes the whole ACL. A deny entry passes, for example the
  `everyone deny delete` entry that macOS puts on home directories. The check fails closed: an ACL
  that it cannot read or parse is refused. On Linux, POSIX ACL entries show in the group bits of
  the mode, so the mode check already catches them. Other systems are out of scope.
- First run: a missing `pins.json` or a missing pins directory is a first run. The store is empty
  and `Store.Existed` returns false. `checkFirstRunWith` walks up to the nearest part of the path
  that exists. That part must be a directory or a symlink to one. A part that is a file, or a
  symlink with a missing target, gives the error `<part> is not a directory, or it is a symlink
  with a missing target`. The text is the same when the pins directory itself is a file and when a
  parent of it is a file. A path where no part exists gives the error `no directory on the path
  exists`, not a first run: a real first run always has an existing parent, such as the home
  directory. A `pins.json` symlink with a missing target is an error too.
- New pins file notice: a deleted `pins.json` looks like a first run to `Load`. So after a save that
  created a new file (`Store.Existed` is false), `scan` and `pin --accept` print one line on stderr
  (`printNewPinsFile`, the text is in [Pins and rug pulls](pins.md)). On a first run the line is
  expected. On a later run it tells the user that every server was pinned again with no alert.
  When the pins file existed at the first read of the command but a later read does not find it
  (the locked read, or for `pin --accept` also the read for the diffs), the file was removed while
  the run went on. Then the run saves nothing and exits with 2 (`pinsRemovedWhileRunning`),
  because a save would drop every older pin. A real first run is not changed by this.
- Lock: `scan` and `pin --accept` read `pins.json` again just before they save with `LoadLocked`
  (`readPinsLocked` in `cmd/mcpmoat/pins_shared.go`), and hold the lock through `Set` and `Save`.
  So two parallel runs keep each other's changes. The lock is an exclusive advisory `flock(2)` on
  the open handle of the pins directory, not on a lock file: that needs no extra file, has no
  symlink or FIFO risk at a lock path, and works on a read-only directory. To lock the same
  directory on every run, `LoadLocked` creates a missing pins directory (mode `0700`) first. The
  first read, before any server starts, and the read for the diffs of `pin --accept` take no lock,
  so a slow server or a slow reader of stdout never holds it. While another run holds the lock, the
  run tries again for up to 10 seconds (`defaultPinsLockWait` in `cmd/mcpmoat/cli.go`). Then it
  prints the read error (which wraps `ErrLocked`) and `pinsLockedText`, and exits with 2. A signal
  during the wait gives the interrupted line. When the system or the file system cannot lock the
  directory (for example some network mounts), `LoadLocked` goes on without the lock
  (`Store.RanWithoutLock`), and the run prints one warning. The texts of both lines are in
  [Pins and rug pulls](pins.md). `scan` and `pin --accept` release the lock right after the save,
  before they print. The code is in `internal/pins` (`lock.go`, `lock_unix.go`, `lock_other.go`).

Known limits:

- The mask of the pin diffs and of the tool names (`pins.CompareMasked`) uses the values that are
  configured now. A value that is no longer configured (for example a rotated token) and that is
  still in an old pin can show on the pinned side of a diff. A value that a server splits over two
  JSON strings, or over the tool name and the description, is not found. `pins.json` keeps the raw
  text (see Echo residual risk above).
- `Save` checks the pins directory by path (`checkDirPerm`), not on an open handle as `Load` does,
  and it does not read the ACL. It checks after it created a missing directory
  (`atomicWriter.writeFile`), so a directory that another user made in the meantime is refused
  too. A swap of the path between this check and the write is not detected. Only root, or a user
  who can write a parent (which the parent check refuses), can make that swap. `Save` does not
  check the old `pins.json`, because the rename replaces it.
- The parent check is by path, by design (see above). It trusts root.
- The parent check refuses a parent that the group can write, also when the group holds only you.
  For example, a `~/.config` made with umask 002 (mode `0775`) is refused until
  `chmod go-w ~/.config`.
- ACLs on the parent directories are not checked, also on macOS. Only the pins directory and
  `pins.json` get the ACL check. So an allow ACL entry for another user on `~/.config` or `~` (for
  example `delete_child`) is not detected, and that user could remove or replace the `mcpmoat`
  directory.
- The ACL check cannot map the principal of an entry to a user or a group without cgo. So it
  refuses an allow entry with a write right also when the entry is for your own account (fail
  closed). `chmod -N` removes it.
- The lock is advisory, so it stops only runs that lock too. mcpmoat v0.1.0 takes no lock, so a
  v0.1.0 run in parallel with a newer run can still lose an update (the last writer wins).
- Any local process that can open the pins directory can hold the lock, also a process of another
  user when the directory has mode `0755` (that mode passes the check). Such a process blocks
  pinning: `scan` and `pin --accept` wait 10 seconds and exit with 2 (fail closed).
- A file system that cannot lock (some network mounts) runs without the lock after one warning, and
  a parallel run can still lose an update. On systems that are not Unix, such as Windows, there is
  no lock at all: the run prints the same warning. Windows is a non-goal (PRD section 2.2).
- A locked run creates a missing pins directory before it takes the lock. When the run then saves
  nothing, an empty directory with mode `0700` remains.
- On systems that are not Unix, such as Windows, the owner, mode and parent checks and the
  directory sync are skipped, because the mode bits are mostly ignored there.
- Some file systems report fixed mode bits that `chmod` cannot change (for example FAT, some
  network mounts and WSL `/mnt/c`). The check can then refuse the pins directory at once, also a new
  one. Set `XDG_CONFIG_HOME` to a path on another volume.
- A directory that root owns, for example one made with `sudo`, is refused for a user who is not
  root. The reverse is refused too. `sudo mcpmoat scan` with the HOME or `XDG_CONFIG_HOME` of the
  user, and a root container with a bind-mounted config that a host uid owns, fail because the
  owner is not the current user.
- A crash (for example SIGKILL or a power loss) can leave a `.pins-*.tmp` file in the directory. It
  holds only names and hashes and has mode `0600`. mcpmoat does not remove old temp files, because
  one can belong to a parallel run that is still writing.
- The cap for each server (2 MiB) keeps one server from filling the file alone, but about 16
  servers at full size fill the 32 MiB file. Then the servers that are already in the file stay,
  and each new server that does not fit is not pinned (a high MOAT-T2-004 finding) until the user
  removes old entries. mcpmoat never removes a server from the file itself.
- The 32 MiB budget is first come, first served, and nothing prunes old entries. So the servers of
  a hostile project config can fill the file, and later servers are then not pinned. Each refused
  server is reported, never skipped silently. The user removes servers from `pins.json` by hand.
- At report time, the budget check (`pinner.budget`) covers only servers that are pinned for the
  first time. A pinned server whose tools grew still gets the "To accept" line, and
  `pin --accept` can then refuse it with exit 2 because the file is full.
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
MOAT-T2-004 findings that `scan` makes itself get their own fixed texts too. The budget finding
MOAT-T1-023 has no YAML file, so its title, risk and fix are fixed texts in
`cmd/mcpmoat/scan_tools.go` (`budgetTitle`, `budgetRisk`, `budgetRemediation`). The cap finding
MOAT-T1-024 has fixed texts there too (`capTitle`, `capRisk`, `capRemediation`). The config cap
finding MOAT-T4-005 has fixed texts in `cmd/mcpmoat/scan_findings.go` (`configCapTitle`,
`configCapRisk`, `configCapRemediation`). The LLM findings
MOAT-LLM-001 and MOAT-LLM-002 have fixed titles, risk texts and remediations in `internal/llm`
(`Title`, `Category.Text`, `Remediation`, `InvalidTitle`, `InvalidText`, `InvalidRemediation`). No
text from the model reaches them.

The summary and the findings are the report. They are not logs, so they stay on stdout. Warnings
do not change the exit code, which counts findings only (FR-16).

The failure reason of a server in the summary can hold error text from the server. `scan` prints it
on stdout, and `pin` prints it on stderr. So the known gap of `internal/inspect` applies to stdout
too: a configured value shorter than 8 bytes is removed from error text only where it stands as a
whole word (see `replaceWords` in `internal/inspect/scrub_words.go` and "Known limits" in
`internal/inspect/doc.go`), so a hostile server that glues a letter to the value can still show
it. `termsafe` makes the text safe for a terminal, but it does not remove a secret.

Colour (FR-14, NFR-07) is decoration. Every severity and status also shows as a word, so the plain
output is complete. `report.Style` holds one switch, `Color`. `cmd/mcpmoat` sets it in
`buildScanSetup` and `internal/report` does not read the environment. `Color` is true only when
stdout is a terminal (`isTerminal` in `cmd/mcpmoat/cli.go` checks `os.ModeCharDevice` on the stdout
writer when it is an `*os.File`, with no dependency; any other writer, such as a buffer, is never a
terminal), `--no-color` is not set (before or after `scan`), and `NO_COLOR` is empty. Only the
headings, the severity group lines and the status words get colour (ANSI SGR codes in
`internal/report/style.go`, the only place that writes the ESC byte). All config, server and rule
text goes through `termsafe` first, so an escape sequence in that text never reaches the terminal as
one.

## JSON output

`mcpmoat scan --json` (FR-15) writes the report as one JSON document on stdout. The schema is
[docs/schema/scan-output.v3.json](schema/scan-output.v3.json). The schema files of the older
versions, [version 1](schema/scan-output.v1.json) and [version 2](schema/scan-output.v2.json), stay
unchanged. The Go types are in `internal/report/json.go`. `cmd/mcpmoat/scan_json.go` fills them from
the same data as the terminal report, in the same order. The one difference: `findings` keeps the
order of the rows, and the terminal report groups them by severity. The report types hold plain
strings, bools and ints, never a `discover` type, so a secret cannot reach the output by accident.

Shape (`schema_version` 3):

- Top level: `schema_version`, `tool` (`name`, `version`), `mode` (`no-connect` or `connect`),
  `complete`, `fields_truncated`, `servers`, `findings`, `diffs`, `errors` and `ignored`. An empty
  list is `[]`, never `null`.
- `fields_truncated` is `true` when `WriteJSON` cut at least one long text field (see
  [Size bound](#size-bound)).
- `ignored` is always there. It has `total` (the number of findings that an ignore entry dropped:
  the number in the `N findings ignored` line on stderr), `rules` (the count for each rule ID; `{}`
  when nothing was ignored; the keys are rule IDs, never text from the ignore file) and
  `file_entries` (the number of entries that `scan` read from `.mcpmoat-ignore`; 0 without
  `--use-ignore-file`). The dropped
  findings are not in `findings`, so a CI job reads these counts to see what the ignore list hid.
- `complete` is `false` when the report can miss results: a config file has a problem (see
  `errors`), or the inspection or the pin step failed as a whole (for example, `pins.json` cannot
  be read), or the LLM step of a `--llm` scan did not classify every tool: a provider failure, a
  provider refusal of every answered tool, an internal error of the LLM step, or tools over the
  share of their server of the `--llm` cap. The exit code is then 2, and the reason is on stderr
  only. A refusal of one tool alone does not change `complete`: it is a `MOAT-LLM-002` row. A
  failed save of new pins comes after the document is written, so it does not change `complete`:
  the findings are whole, and the exit code is 2. A server that used up its share of the rule
  analysis time, or that the step did not analyse at all, does not change `complete`
  either: it is a `MOAT-T1-023` finding (see 5d). This is a decision (#210): the `MOAT-T1-023`
  row of each such server is the marker for an incomplete rule analysis. `complete` `false` would
  force exit code 2, so hostile input could turn a finding into an execution error, against the
  meaning of FR-16. There is no new field and no schema change. A CI job must check the findings
  for `MOAT-T1-023`, not only `complete`. A server that has more tool findings than the row cap,
  or more config findings than a config cap, does not change `complete` either: it is a
  `MOAT-T1-024` or a `MOAT-T4-005` finding.
- A server has `name`, `client`, `scope`, `project_path`, `untrusted`, `state`, `transport`,
  `source`, `inspection.status` (`not_run`, `ok`, `timeout`, `failed` or `refused`) and either
  `argv` (stdio) or `url` (http and sse). Both are redacted like in the terminal report. A server
  that has changes to accept also has `accept`, with `digest` (the pin digest of the terminal hint)
  and, only when the terminal hint shows a command, `command` (see 5c). A server with nothing to
  accept has no `accept` key.
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
the JSON types are built. A tool name in `key` (tool rule, pin and LLM findings) and the `tool` and
`diff` of each `diffs` entry show each value of `inspect.Result.Secrets` (8 bytes or more) that the
server echoes as `********`. `cmd/mcpmoat` masks them before it builds the rows (`maskedToolKey`
in `scan_tools.go`, and `pins.CompareMasked` with `compareMask` for the pin rows and diffs), so the
terminal and the JSON output get the same text. No field says that a value was masked. A shorter
value is not masked. The ignore lookup uses the real tool name.

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

Version 3 is one bump for three changes (#175, #169 and #170), because each of them adds a field.

History: version 1 is the first format. Version 2 adds the required finding field `source` (for
`--llm`, FR-17), and `complete` is also `false` when the LLM step did not classify every tool. The
other fields keep their names and types. Version 3 adds the top-level `ignored` object (the
counts of the findings that the ignore list dropped, so a CI job can read them: #175), the optional
server field `accept` (the digest and the command of the "To accept" hint, so a CI job can read
them: #169) and the top-level `fields_truncated` flag with the length caps of the text fields
(#170, see [Size bound](#size-bound)). The other fields keep their names and types. The schema
files of version 1 and version 2 stay as they were released.

Not in version 3: a summary, `pin --json` and `--fail-on` (#65).

### Size bound

`scan --json` bounds the text of each field, the number of tool findings for each server, the
number of config findings and the memory of the writer, also for a hostile config. A project
`.mcp.json` can hold a server name of megabytes, and every finding row of that server repeats it.
The bound has three parts. The pin findings and the LLM findings have no row cap of their own, but
other limits bound them (see part 2).

1. Per-field caps (`boundReport` in `internal/report/json_bound.go`). `WriteJSON` cuts each
   untrusted text field to a number of characters (runes) and adds `...` (`termsafe.CutMarker`)
   after a cut value. It never changes the report of the caller (it works on a copy).
   - Names, keys, related texts and server fields: 512 characters (`jsonMaxNameRunes`). That is the
     server `name`, the finding fields `server`, `key` and `related`, the diff fields `server` and
     `tool`, and the config problem field `server`. A cut value has at most 515 characters.
   - Paths: 4096 characters (`jsonMaxPathRunes`). That is the server fields `source` and
     `project_path`, and the config problem fields `path` and `project_path`. A cut value has at
     most 4099 characters.
   - Never cut: the diff text (it has its own cut, `diff_truncated`), `argv`, `url`, the accept
     `command` and the accept `digest`. A cut command line, URL or command would mislead, and a cut
     digest would not work. The rule ID, the severity and every fixed or enum field are short.
   - `fields_truncated` is `true` when `WriteJSON` cut any field. A caller can also set it to
     `true`, and `WriteJSON` never sets it back to `false`. Each cut field has a `maxLength`
     (515 or 4099) in the schema.
   - Limit: two names that differ only after the cut look equal in the output (issue #223 tracks a
     fix). The cut happens only when `WriteJSON` writes. The ignore list and the pins use the real
     names.
2. Per-server row cap (see 5d). A server keeps at most 1000 tool rule rows, then one `MOAT-T1-024`
   row. The cap counts the rows after the ignore list. The `MOAT-T1-023` row and the cap row do not
   count. The cap bounds the part that grows with the number of tools times the number of rules. It
   does not bound the other rows of a server. The rows of one server are:
   - up to 1000 tool rows, plus 1 cap row, plus 1 budget row (bounded by the row cap);
   - plus the pin rows: at most one for each current tool (a new, changed or unverified tool) and
     one for each removed tool, plus at most one row for the server itself. A server lists at most
     10,000 tools (`maxItems` in `internal/inspect`), and `pins.json` holds the tools of an earlier
     scan, so also at most 10,000;
   - plus the LLM rows: the scan sends at most 500 tools in all (`maxLLMTools`), and the LLM step
     adds at most one row for each tool;
   - plus the config rows (T4 and T5), at most 100 (`configRowsPerServer`), plus one `MOAT-T4-005`
     row (see step 5). `secretFinding` in `internal/rules/config.go` makes one row for each env key
     and each header key that looks like a secret, so before the cap the number of config rows is
     limited only by the size of the config file: 4 MiB for a project file and a `--config` file
     (`maxProjectConfigSize`), and 32 MiB for a global file such as `~/.claude.json`
     (`maxConfigSize`).

   The pin rows and the LLM rows are not capped by a row cap. A config file can hold at most 10,000
   servers (`maxServersPerFile` in `internal/discover`), so the number of servers multiplies their
   bound. The config rows have a cap for the whole scan too: at most 10,000 (`configRowsTotal`),
   plus one `MOAT-T4-005` row for each server that lost rows. That last part is bounded by the
   number of servers, as the server list is. The field caps still cut the text of every row, and
   each row repeats the server name (up to 515 characters). [Limits](limits.md) has the row counts
   and output sizes that were measured with and without the config caps (#213).
3. Streaming writer. `WriteJSON` writes the document one list element at a time, through a
   buffered writer (`jsonStream`). It encodes each server, finding, diff and error on its own, so
   the memory follows the largest element and not the whole document. The output bytes are the
   same as when one `json.Encoder` with `SetIndent` encodes the whole document. When a write fails
   in the middle, `w` may already hold the first part of the document. `WriteJSON` returns the
   error, and `scan` reports it and exits with 2.

The tests prove the bound of the writer, of the tool rows and of the config rows. The exact measured
numbers are in the comments of the tests, so they stay with the code. For the config rows, they are
in [docs/limits.md](limits.md) and in the comments of `TestScanJSONConfigBound`. The limits have
headroom of about 2 times, so a change that makes the output or the allocations grow with the size
of a name fails them.

- `TestWriteJSONBoundsOutputAndMemory` (`internal/report/json_bound_test.go`) tests the writer
  alone. The hostile report has a server name of 1 MiB and 10,000 findings. In each finding, the
  `Server`, the `Key` and the `Related` field hold that name, so without the cut the output would
  be about 31 GB. The output is about 17 MB. `WriteJSON` allocates a small multiple of the output
  (under 4 times, also with `-race`). The old whole-document encoder allocated 16 to 19 times. The
  test limits are: output at most 32 MiB, and allocation at most 8 times the output.
- `TestScanJSONBound` (`cmd/mcpmoat/scan_json_bound_test.go`) tests the whole in-process
  `scan --json`. The hostile config has a server name of 1 MiB, 3000 tools and 25 rules that match
  every description. The output is under 1 MiB, with about 1000 rows. In a tool row the
  name is in the `server` field only: `key` is the tool name and `related` is `description`. For
  comparison, the same rows with the version 2 encoder (no cut) would hold the name about 1000
  times, about 1 GB, more than 1,000 times the bounded output. The test checks, in both modes
  (with and without `-race`), the output size (at most 1.5 MiB), the number of rows, the
  `fields_truncated` flag, the `MOAT-T1-024` row and the schema. The allocation check runs only
  without `-race`: the scan allocates a few tens of MiB, and the limit is 128 MiB plus 8 times the
  output (`maxScanAllocBytes` and `maxJSONAllocFactor`). Under `-race` the race detector makes `regexp`
  allocate far more, so the check could not catch a regression there. The test skips the check and
  uses fewer tools in that mode.
- `TestScanJSONConfigBound` (`cmd/mcpmoat/scan_json_bound_test.go`) runs `scan --no-connect` on
  hostile 4 MiB project files (1 MiB under `-race`), with server names of 600 characters. It checks
  the row count, the output size (at most 256 KiB for one server, 16 MiB for many servers), the
  `MOAT-T4-005` rows and, only without `-race`, an allocation bound of 384 MiB plus a multiple of
  the output. The caps bound the rows and the output, not the memory before the cut: discovery
  decodes the whole file, and `rules.CheckConfig` makes one finding for each key first. So the
  scan gives at most 10,000 config rows plus one `MOAT-T4-005` row for each cut server. The JSON
  and terminal output of a 4 MiB file stay under about 10 MB, and the scan still allocates about
  200 to 250 MiB. The measured numbers are in [docs/limits.md](limits.md).

## The `--llm` classifier

`mcpmoat scan --llm` (FR-17) asks a language model to rate the name and description of each
inspected tool. It is off by default. Without `--llm`, `runScan` reads no API key and never calls
`cli.newClassifier`, so no LLM code sends anything (NFR-01).

This section holds the code structure and the design reasons. Other files own the rest:

- The user contract (flags, warning, what is sent, limits, findings, exit codes and security notes)
  is in [docs/llm.md](llm.md).
- The requirements are in FR-17 of [PRD](PRD.md).
- The threat model is in [PRD section 5.3](PRD.md#53-threats), which owns it. The package doc
  comment in `internal/llm/doc.go` holds the code-level notes of the threat model.

Setup:

- `setupLLM` in `cmd/mcpmoat/scan_llm_flags.go` runs in step 1 of the data flow. It calls
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

The dial hook: `llm.Config.Dial` is a test hook of type `llm.DialFunc`. It is nil in production,
and nil uses a `net.Dialer`. For an `http` base URL, `loopbackDial` wraps it. It resolves the host
at connect time, requires that every address is a loopback address, and dials only those
addresses. The check at connect time is needed because a name such as `localhost` is loopback
only by its text: the system resolver can map it to another address. An address that does not
answer gets a short timeout, so the next address is tried soon (for example when a firewall drops
packets to `::1`).
The client has its own `http.Transport` with TLS 1.2 or later. It follows no redirect, because a
redirect would carry the key to another location. It never uses a proxy for an `http` base URL, so
the key never goes to a proxy in clear text. For `https` it honours `HTTPS_PROXY` and `NO_PROXY`,
like the server connections. Go ignores a proxy value that it cannot parse and then connects
directly. The limits of a scan (tool count, workers, timeouts, retries, body size, output tokens)
are in the [docs/llm.md](llm.md). They live in
`cmd/mcpmoat` (`maxLLMTools`, `llmWorkers`, `defaultLLMStepTimeout`) and `internal/llm`.

Retries: `Classify` calls `sendWithRetry` in `internal/llm/retry.go`, which calls `send` again for
each try, so each try builds a new request with a new body. `retryPolicy` holds the numbers: 3
tries in total for each tool (`llm.RetryMaxTries`), a backoff that starts at 1 s and doubles with
a max wait of 8 s, a jitter of 0.5 to 1.5 times, and a cap of 30 s on a `Retry-After` wait
(`llm.RetryAfterCap`). With 3 tries there are only 2 waits: about 1 s, then about 2 s, with
jitter, so the max wait of 8 s is not reached. The two constants are exported only so that the
usage text of `scan` takes its numbers from them.
`retryableStatus` lists the codes that get a retry: 429, 502, 503, 504 and 529. Every other code
(also 400, 413 and 422), a request timeout (`requestTimeout`, 30 s for each try) and every other
transport error stop at once. `parseRetryAfter` reads the header (seconds or an HTTP date); a
value that is not valid or in the past gives the normal backoff, and a value over the cap means no
retry. `sendWithRetry` also refuses a `Retry-After` wait that is longer than the time left before
the deadline of its context (the step deadline, see below): it returns the error of the provider
at once, with `backoff.Permanent`, so the tool fails with the status of the provider and the scan
exits with 2. `send` reads only this one response header of a non-2xx answer, never its body. The module
`github.com/cenkalti/backoff/v7` runs the waits. `retryError` unwraps its errors: after the last
try, the caller gets the error of that try as without retries, and when the context ends during a
wait it gets the same error as when the context ends during a request. The reason: the error text
of the module holds the text of the last error, and every error of `internal/llm` must have fixed
text.

Output cap: `anthropicAPI` sets `max_tokens` to 200. `newOpenAIAPI` sets `max_completion_tokens`
to 2048 only for the default OpenAI base URL, because reasoning models bill hidden tokens that the
response cap does not limit. Any other base URL gets no field, because many OpenAI-compatible
servers know only `max_tokens` and refuse the field with 400, which would refuse every tool. A cut
answer is `llm.ErrInvalidOutput`.

The step deadline: `runLLMJobs` in `cmd/mcpmoat/scan_llm.go` runs all the jobs (`runLLMJob` for
each job) under one context with the time limit `defaultLLMStepTimeout` (10 minutes, no flag) and the
cause `errLLMStepDeadline` (`context.WithTimeoutCause`). The reason: each request has a limit,
but with retries and `Retry-After` waits one tool can take about 150 s, and 500 tools with 4
workers could take hours. When the cause is `errLLMStepDeadline` and the context of the caller has
not ended (`endedByDeadline`), a request that the deadline stopped is `answerDeadline`, not
`answerStopped`, and the failure of the step is `answerDeadline` when at least one job has no
answer. It is a provider failure: exit 2, `complete` false, the report prints, the rows of the
tools that got an answer stay, and stderr names the time limit (`durationText`). A signal wins,
also when the deadline is reached at the same time, because `endedByDeadline` and `classifyPlan`
check `ctx.Err()`, the context of the caller: the cause of the step context does not decide it.
A failure that came first cancelled the context first, so it stays the failure. One race is left:
a provider failure that a worker got just before the deadline but recorded just after it can show
as the deadline. Only the stderr reason changes: the exit code is 2 and `complete` is `false` in
both cases. A test sets `cli.llmStepTimeout` to a short value.

The plan: `planLLMJobs` in `cmd/mcpmoat/scan_llm_plan.go` builds the jobs before the first request.
`llmServerJobs` gives one job for each tool of each server with status `StatusOK`, in the order of
the servers. `fairShare` splits `maxLLMTools` between the servers with a max-min fair share
("water-filling"): a server with fewer tools than an equal part keeps all of them, the part that
it does not use goes to the larger servers, and the remainder goes to the servers that come first,
so the result is always the same. Each server sends its first tools up to its share. The reason: a
hostile server that lists thousands of tools must not take the whole cap from the other servers.
It can still make the step incomplete (exit 2) by listing more tools than its share. Then
`llmStep` prints the notice `mcpmoat scan: sending N tools (about K KiB of text) to the LLM
provider` (`llmPlan.sendingNotice`, numbers only) when the plan has at least one job, and
`classifyPlan` runs the jobs. There is no byte budget for the whole scan: the cap and the caps of
each request bound it.

What is sent: `internal/llm` builds one request for each tool from the fixed system prompt
(`llm.SystemPrompt`), the fixed verdict schema and one user message. The message is a JSON object
with `tool_name`, `tool_description`, `truncated` and, only after a replacement, `redacted`. The
description goes into it as a JSON string value, never into the system prompt, so it cannot change
the instructions of the model.
`cmd/mcpmoat` gives `internal/llm` only the name, the description and the credential values of
the server (see [Import direction](#import-direction)).

Secret values: a server gets the env values, the header values, the URL secrets and the expanded
placeholder values from its config, and a stdio server also gets its expanded argv. It can echo
all of them in its tool text. `inspect` gives two lists: the wide `Result.Secrets` for the local
report, and its subset `Result.Credentials` for the request. So the path is:

1. On success, `inspect` puts these values in `inspect.Result.Secrets` (`resultSecrets` in
   `internal/inspect/secrets.go`). For a stdio server, `argSecrets` adds the secrets in the
   expanded command and args: the text that `discover.RedactArgs` masks, from
   `discover.ArgSecrets`, which runs the same code, and the smaller parts of it that a server can
   echo alone. For the env values, the expanded values and the header values, `valueCredentials`
   (in `secrets.go`) adds the credential pieces that `discover.ArgCredentials` finds inside each
   value. `cookieSecrets` (in `remote.go`) adds the cookie pieces, and `urlCredentials` the URL
   credentials. A piece under 8 bytes goes only to the whole-word scrub list of the failure text.
   Each value has at least 8 bytes and is in the list one time, longest first. The values are
   `discover.Secret`, so they print and encode only as the mask. The doc comment of
   `inspect.Result.Secrets` lists every value and piece, and the doc comment of `RedactArgs` holds
   its limits (such as `--db mypassword` or a positional value).
2. `inspect` also puts the values of `Result.Secrets` that look like a credential in
   `inspect.Result.Credentials` (`resultCredentials` in `internal/inspect/secrets.go`), in the
   same order. `isCredential`, `holdsCredential`, `headerCredentials` and `urlCredentials` decide,
   with `discover.IsSecretName`, `discover.TokenLike`, `discover.IsAuthScheme` and
   `discover.ArgCredentials`. The doc comment of `inspect.Result.Credentials` holds the rule for the
   code, and [What is sent](llm.md) holds it for users. Plain words such as `NODE_ENV=production`
   are not credentials, and the check fails closed.
3. `llmServerJobs` in `cmd/mcpmoat/scan_llm_plan.go` copies the `Result.Credentials` slice of
   each server into `llm.Input.Secrets` of each tool of that server. So a value of one server is
   removed only from the tools of that server, and a plain config value that the server echoes
   reaches the provider (issues #229 and #235). Each job also gets a `discover.TextRedactor` of
   the wide `Result.Secrets` of its server (`llmJob.redactor`), for the `key` of its row.
4. `toolMessage` in `internal/llm` replaces each value of at least 8 bytes
   (`discover.MinSecretBytes`) with `discover.Mask` (`********`) in the name and the description,
   before the cut, so a cut cannot leave a part of a secret. The code is in
   `internal/discover/redact_text.go`, so that the local report (`maskedToolKey` and `compareMask`
   in `cmd/mcpmoat`) uses the same code without a dependency on the LLM package, and
   `internal/report` and `internal/pins` cannot import `internal/llm` (the `llm-only-in-cmd` rule of
   depguard). `internal/llm` and `cmd/mcpmoat` already import `internal/discover`, and
   `internal/pins` gets only a mask function, so the import table does not change.
   `discover.SecretTextValues` adds, for a value that is not valid UTF-8, the form that the JSON
   decoder of the SDK gives (one U+FFFD for each invalid byte), because a server that echoes the
   value sends that form. `redactWindow` marks every byte of every match first, also of matches that
   overlap, then writes one mask for each run of marked bytes. The search for each value is a
   Knuth-Morris-Pratt search, linear in the length of the text and of the value, also for a periodic
   value (issue #231). To bound the work, `discover.RedactTextPrefix` redacts only a window of the
   first limit+1 bytes (the limit is `llm.MaxToolNameBytes` or `llm.MaxDescriptionBytes`) and
   doubles it while the masks make the result too short. Its result is always a prefix of the full
   redaction, so the text and the cut are the same. The message has `redacted: true` when a mask
   starts in the first limit+1 bytes of the redacted name or description, also when the cut then
   removes it. The field is omitted otherwise. A secret that starts or ends with `*`, or holds a
   whole mask, can show again across a mask (a documented limit). The system prompt tells the model
   that the mask is removed text, not an instruction.

The report and the JSON output mask the wide `Result.Secrets` in the tool names and the pin diffs
(see Redaction in [JSON output](#json-output)). The `key` of an LLM row also uses that mask
(`llmJob.redactor`), because the request hides fewer values than the report must. docs/llm.md
lists the limits of the replacement.

The cuts are made at a rune boundary: `llm.MaxToolNameBytes`, `llm.MaxDescriptionBytes` and, for
the whole message, `llm.MaxToolMessageBytes`. `Classify` sets
`Verdict.Truncated` when it cut the name or the description, and `Verdict.Redacted` when
`toolMessage` removed a credential (the `redacted` field of the message). The flags never
come from the model output. A cut name or description is a sign of risk, because the part that is not shown can hold
the payload. The system prompt tells the model to rate it at least `medium`, but the code does not
trust the model for this (see the verdict below).

The verdict: `parseVerdict` reads the model answer strictly: exactly one JSON object with the keys
`risk` and `category`, exact keys and case, no duplicate key, no other key, nothing after the
object. The values come from fixed lists. `classifyPlan` turns a verdict into rows with the row
builders in `cmd/mcpmoat/scan_llm_rows.go`:

- A risk of `low`, `medium` or `high` gives one `MOAT-LLM-001` finding with that severity. The
  category goes in `related`. `none` gives no finding. The severity is never `critical`.
  `llmSeverity` is the one place that maps an `llm.Risk` to a
  `rules.Severity`.
- `llmRow` builds the row. `unrated` is true for a tool with `Verdict.Truncated` or
  `Verdict.Redacted` set: part of its text was not rated. For such a tool, `llmRow` returns
  `floorRow` when `belowMedium` is true for the risk or the answer is unusable. That row is
  `MOAT-LLM-001`, `medium`, category `other`, with the fixed text `llm.TruncatedText` for a cut
  text and `llm.RedactedText` when only a credential was removed. A cut text wins when both
  are true. A rating of `medium` or `high` stays. The code enforces the rule, not only the system
  prompt, because a prompt injection in the part before the cut could ask the model for `none`,
  and a hostile config can choose which text mcpmoat removes (through a value under a secret-like
  key; a phrase under a plain key is not removed, so the model reads it). docs/llm.md owns the
  rule that the user sees: see [`--llm`](llm.md).
- An answer that cannot be used for a tool that was not cut and had no credential removed gives
  `MOAT-LLM-002` (medium). That is an invalid answer, a refusal of the model or an answer cut at the
  token limit (`llm.ErrInvalidOutput`, risk text `llm.InvalidText`). A tool that the provider
  refused (`llm.ErrRejected`, HTTP 400, 413 or 422) gives the same row with the risk text
  `llm.RejectedText` (`rejectedRow`). Both go through `invalidRow`, so an unrated tool (cut or
  redacted) gets the floor row in both cases. Only these two errors give this finding. So a hostile
  server that makes the provider refuse its own tool description, or makes the answer unusable,
  keeps the LLM rating of that tool at `medium`, below the default `--fail-on high`. The rule
  findings still apply.
- The finding texts are fixed in `internal/llm`, so no text from the model reaches the terminal or
  the JSON output.

`sortAnswer` sorts every error of `Classify` into an `answerKind` and fails closed.
`llm.ErrInvalidOutput` gives `answerUnusable`, the end of the context is a stop (`runLLMJob`
turns it into `answerDeadline` after the step deadline, see above),
`llm.ErrRejected` gives `answerRejected`, and any other `llm.ErrProvider` is a provider failure.
`llm.ErrRejected` wraps `llm.ErrProvider`, so its case comes first. Any other error is an internal
error. A provider failure and an internal error stop the step. The first of them stops the running
requests, starts no new one and decides the stderr line. A refusal stops nothing. So a new error
path can never make a failed step look like a complete scan. The table of status codes is
`statusClassOf` in `internal/llm`: 400, 413 and 422 are per tool, and 401, 403, 3xx and every
other code are global. Transport errors are global too.

The guard: after all the requests, when there is no global failure and no signal,
`rejectedFailure` checks the refusals. When at least one answered tool was refused and none got a
2xx answer (`answerKind.got2xx`: a verdict or an unusable answer), the step is a provider failure
of kind `answerRejected`, with the reason of the refused tool with the lowest job index
(`rejectedReason`, for example `HTTP 400, the provider refused every tool`). No tool gets an LLM
row then. The reason: a wrong model name or API shape that gives 400 for every tool must exit
with 2 and `complete` false, not look like a complete scan with one medium row for each tool. A
global failure or a signal wins over the guard. docs/llm.md and docs/exit-codes.md list the
provider failures and the texts of the exit-code-2 cases (see [`--llm`](llm.md) and
[Exit codes](exit-codes.md)). Every error of `internal/llm` has fixed text. It never holds the
key, a URL, a header, a response body or model output.
For a provider failure, `llmFailureText` in `cmd/mcpmoat` quotes `llm.Reason(err)`, the fixed
reason text, for example `HTTP 401 (the API key was refused)`.

The LLM step only adds rows. It never changes or drops a rule finding, a pin, a diff or a
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
in [Contributing a rule](writing-rules.md).

## See also

- [PRD](PRD.md), section 8: the target architecture.
- [How mcpmoat starts stdio servers](stdio-servers.md).
- [Documentation index](README.md).
- [CONTRIBUTING.md](../CONTRIBUTING.md).
