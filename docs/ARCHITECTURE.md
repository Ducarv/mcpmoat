# Architecture

> **Status:** this page describes the code as it is today and marks what is still planned. Today
> `mcpmoat scan --no-connect` reads configs, loads rules, lists servers and applies the config rules
> (T4 and T5) and the ignore list. `mcpmoat scan` without `--no-connect` also connects to the
> servers, pins their tools on the first run, and reports new, removed and changed tools on later
> runs (T2). It prints a diff for each new and each changed tool. `mcpmoat pin --accept <server>
> --expect <digest>` accepts the changes. The YAML rules are not
> applied to tools yet (#143).

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
  report/               terminal output
rules/                  built-in rules (go:embed)
testdata/               fixtures for tests and the demo
  configs/              example client configs
  servers/              example MCP servers (benign, poisoned, mailer, shadowing)
docs/                   PRD and other documentation
```

- `cmd/mcpmoat`: parses flags, runs the command, returns the exit code. `os.Exit` is only in `main`.
  `configs.go` holds the config loader that `scan` and `pin` share (`loadConfigs`), so both commands
  apply the same trust rules to a config file. `pins_shared.go` holds the helpers of the pin step
  that both commands use (`serverIdentity`, `readPins`, `pinnable`, `appendDiff`). `scan_pins.go`
  holds the pin step of `scan` (`pinner`), and `accept_hint.go` the "To accept" line.
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
- `internal/report`: writes the terminal output: the servers (`WriteServers`), the findings
  (`WriteFindings`) and the diffs of changed, new and not verified tools (`WriteDiffs`).
- `rules/`: the built-in rule files (`rules/*.yaml`) and `data/popular-servers.txt`. The Go file
  `rules/embed.go` embeds both with `go:embed`. It holds data only. `internal/rules` parses it.
- `testdata/`: fixtures. `testdata/servers` holds malicious example servers. `testdata/configs`
  holds example client configs. Other folders hold fixtures for single packages.
- `internal/discover/discovertest` and `internal/inspect/inspecttest`: helpers for tests in other
  packages. `inspecttest.Fake` is an `Inspector` that returns canned results. A test that uses
  `Fake` never starts a real server. `inspecttest.Fixture` builds one fixture server
  under `testdata/servers/` and returns the path of its binary. The test starts it.

## Import direction

Imports go one way. A package in the table imports only the packages in its row. The table lists
the product packages and non-test imports. Tests also import `inspecttest` and `discovertest`.
`inspecttest` imports `discover` and `inspect`. `discovertest` imports no module package.

| Package | Imports (module packages only) |
|---|---|
| `internal/termsafe` | none |
| `internal/safefile` | none |
| `internal/discover` | `safefile`, `termsafe` |
| `internal/inspect` | `discover` |
| `internal/rules` | `discover`, `inspect`, `safefile`, `termsafe`, `rules` (the embedded data) |
| `internal/report` | `discover`, `termsafe` |
| `internal/pins` | `inspect`, `safefile`, and the module `github.com/aymanbagabas/go-udiff` |
| `cmd/mcpmoat` | `discover`, `inspect`, `pins`, `report`, `rules`, `termsafe` |

`internal/inspect` does not import `termsafe`. The report layer escapes what `inspect` returns.
You can check this table with:

```sh
go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./...
```

## Data flow

### Implemented

`mcpmoat scan` does these steps today:

1. `cmd/mcpmoat` parses the flags and checks `--timeout` and `--concurrency`. A bad value is a
   usage error with exit code 2.
2. It loads the rules with `rules.Builtin` and, with `--rules`, `rules.LoadDir`. Then
   `rules.NewSet` checks for duplicate rule IDs and for clashes with built-in IDs. This only loads
   and checks the rules. A bad rule file or an ID problem gives exit code 2.
3. It reads `.mcpmoat-ignore` with `rules.ReadIgnoreFile` and adds the `--ignore` rule IDs. It keeps
   two lists (`scanIgnores` in `cmd/mcpmoat/scan_pins.go`): one for the config rules, with the file
   and the flags, and one for the pin rules, with the flags only. The file can come from a cloned
   repository, so it cannot ignore a pin rule. The guard is `pins.IsPinRuleID`: a rule ID is a pin
   rule when it starts with `MOAT-T2-` (the unexported `ruleIDPrefix`). `scan` prints a warning for
   each such rule ID, and tells the user to use `--ignore`.
4. It finds the servers with `loadConfigs` in `cmd/mcpmoat/configs.go`. That function runs
   `discover.Discover`, or reads one file with `discover.ReadConfig` when `--config` is set. `pin`
   uses the same function, so both commands read the configs with the same trust rules.
5. It runs the built-in config rules on every server it found, also a disabled one, as `discover`
   gives it. `rules.CheckConfig` gives the T4 findings (MOAT-T4-001 to 004). The typosquat check
   from `rules.NewBuiltinTyposquat` gives the T5 finding (MOAT-T5-001). The ignore list drops
   some findings. The rule set gives the severity of each one that is left.
6. `report.WriteServers` prints the servers. Then, only when findings are left,
   `report.WriteFindings` prints a blank line and a table of them. The table holds the rule ID, the
   severity, the server, the field and the key or related name. It never holds a value. Last,
   `reportScan` prints the ignored count for each rule ID on stderr (only rule IDs and counts, no
   server names).

Steps 1 and 2 always run. Steps 3 to 6 run in both modes. Without `--no-connect`, `scan` adds
the connect and pin steps between step 5 and step 6:

- 5a. `scan` first reads `pins.json` (`pins.Load`). A bad file exits with code 2 before any server
  starts. Then `inspect.Run` inspects the servers with the `--timeout` and `--concurrency` values.
  The inspector is `inspect.New` with the zero `SDKOptions`. So a server from an untrusted project
  file, and a server that the client config turns off or leaves unapproved, is refused. `scan` has
  no flag that allows them. A stdio server runs with a scrubbed environment (NFR-04). A server that
  fails, times out or is refused gives a warning on stderr. It does not change the exit code
  (FR-06), unless the server is pinned and failed or timed out: then it is also a high finding (see
  5b). The inspection warnings (`Result.Warnings`, and `ConnectError.Warnings` of a failed server)
  go to stderr too, one line each (`warnInspection` in `cmd/mcpmoat/pins_shared.go`).
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
    the client config turns it off or does not approve it) stays a warning: the config of the user
    sets that state, not the server. A server that is not pinned stays a warning only (FR-06).
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
    reason text in the KEY/RELATED column: `duplicate tool name`, `empty tool name`, `invalid tool
    data`, `pinned with another hash version` or `pinned text does not match its hash`. The reason
    never holds server text. For the last two reasons the pin cannot be trusted, so the change also
    has a diff of the whole current tool (`Change.Diff`). The `--ignore` flag drops them by rule ID,
    server and tool name. The `.mcpmoat-ignore` file does not (see step 3). `scan` never re-pins a
    server that is in the store.
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
- The pin findings join the config findings in one table. A changed tool and a new tool also get a
  diff, so the user can review the content of a new tool before they accept it. A new tool has the
  header `New tool <tool> on server <server>:` and only added lines. A not verified tool with a diff
  (see 5b) has the header `Not verified tool <tool> on server <server> (current text):` and only
  added lines. A finding that the user ignored gets no diff. `report.WriteDiffs` prints the diffs
  after the findings table. When a diff was cut at
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

The exit codes (`cmd/mcpmoat/cli.go`) are: 0 when no finding has severity high or above; 1 when a
finding that is not ignored has severity high or above (the PRD default of `--fail-on`, which is not
a flag yet). A changed tool is high, so it gives exit code 1. So does a high MOAT-T2-004 finding: a
pinned tool name that cannot be verified, a pinned server that fails or times out, a server whose
tools cannot be pinned, or a pinned server that is listed twice. A new tool, or a not verified
tool with a new name, next to a removed tool of the same server (a likely rename) is high too. The default does not fail on MOAT-T2-002 (a new
tool alone), MOAT-T2-003 (removed tool) or a medium MOAT-T2-004 (an unpinned tool name, or an
unpinned server that is listed twice). The code is 2 for an execution error, and that includes a
`pins.json` that `scan` cannot read or save, and a signal. `scan` prints the report first.
Exit code 2 wins over 1. `internal/report` has no JSON output.

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

Known gaps: the store has no lock (#150), only a read just before the save. `--fail-on` (#65) and
the JSON output (#64) are not implemented.

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
- `report` prints the findings, as a table and as JSON.
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
out of a cut diff. A large `_meta` change can still push a schema change out (#162). A line of more than about 200 runes is
wrapped, so a change in a long line still shows. The diff trims the lines that both texts share at
the start and at the end, keeps 3 lines of context, and only then cuts the rest to 64 KiB and 2000
lines. When the cut applies, the diff ends with a marker line and `Change.Truncated` is true, so
`scan` and `pin` can warn the user. The labels are `pinned` and `current`. A changed or new tool
always has diff text, or a fixed note when the diff cannot be made or the change is not visible in
the rendered text. Server text is raw in the diff. The report layer escapes it (see [Where untrusted
text is escaped](#where-untrusted-text-is-escaped)).

The doc comments own the rules. `Canonical` owns the shape, null handling, errors, no normalisation
and the known limits. `HashVersion` owns when the version changes and what the store does with a
stored hash of another version. Read them with `go doc ./internal/pins Canonical` and
`go doc ./internal/pins HashVersion`. The known limits are requirements in
[PRD FR-11](PRD.md#64-pins-rug-pull-detection). They include the `_meta` and `icons` limits: a
changing value in `_meta` raises `MOAT-T2-001` on every scan, and an unknown key inside an icon is
not covered. `HashVersion` stays `sha256-v1`. The form got `_meta` and `icons` in place before the
first release, as the [`pins.json` store](#the-pinsjson-store) section says.
The pin diff shows `_meta` and icons values, escaped by `termsafe` like all server text. Logs and
errors never print a `_meta` value.

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
- `Outcome` has `Server`, `Status`, `Result` and `Err`. `Status` is `StatusOK`, `StatusTimeout` or
  `StatusFailed`.
- `Result` holds the server identity, the instructions text and the lists of `Tool`, `Prompt`,
  `Resource` and `ResourceTemplate`, plus `Warning` values.
- `SDKInspector` is the real `Inspector`. Make one with `New(SDKOptions{AllowUntrusted, AllowDisabled})`.
  It starts stdio servers itself and gives remote servers to `Remote(ctx, srv, RemoteOptions)`.

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
  other text. The file has mode `0600`, so treat it as private.
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
tool and server names in the diff header are escaped too. The stderr lines of `scan` and `pin`
that name a server or carry server output (the pinned notice, the warnings and the errors) are
escaped and cut in the same way.

For secrets in output, see [Code style](../.agents/project.md#code-style).

## How to add a rule

A rule is one file, `rules/<ID>.yaml`, plus its test cases. The steps and the required cases are
in [Contributing a rule](../CONTRIBUTING.md#contributing-a-rule).

## See also

- [PRD](PRD.md), section 8: the target architecture.
- [How mcpmoat starts stdio servers](stdio-servers.md).
- [Documentation index](README.md).
- [CONTRIBUTING.md](../CONTRIBUTING.md).
