# Architecture

> **Status:** this page describes the code as it is today and marks what is still planned. Today
> `mcpmoat scan --no-connect` reads configs, loads rules, lists servers and applies the config rules
> (T4 and T5) and the ignore list. It does not connect to servers yet.

This page is the one place for the package layout, the import direction, the data flow, the
`internal/inspect` interface and the rules for untrusted text. The [PRD](PRD.md) holds the product
requirements. Section 8 of the PRD is the target architecture.

## Package layout

```
cmd/mcpmoat/            CLI entry (standard library flag); run() returns the exit code
internal/
  termsafe/             escapes untrusted text for the terminal
  safefile/             hardened bounded read of untrusted files
  discover/             config readers: Claude Code, Cursor, Codex
    discovertest/       test helpers for discover
  inspect/              connects to servers, reads tools, prompts and resources
    inspecttest/        test helpers for inspect, including Fake
  rules/                loads YAML rules, applies regex and heuristics
  pins/                 tool hash (pins.json store still to come)
  report/               terminal output
rules/                  built-in rules (go:embed)
testdata/               fixtures for tests and the demo
  configs/              example client configs
  servers/              example MCP servers (benign, poisoned, mailer, shadowing)
docs/                   PRD and other documentation
```

- `cmd/mcpmoat`: parses flags, runs the command, returns the exit code. `os.Exit` is only in `main`.
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
- `internal/pins`: computes the canonical hash of each tool (`Canonical`, `Hash`). See
  [Tool hash](#tool-hash). The `pins.json` store is still to come.
- `internal/report`: writes the terminal tables: the servers (`WriteServers`) and the config findings
  (`WriteFindings`).
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
| `internal/pins` | `inspect` |
| `cmd/mcpmoat` | `discover`, `inspect`, `report`, `rules`, `termsafe` |

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
3. It reads `.mcpmoat-ignore` with `rules.ReadIgnoreFile` and adds the `--ignore` rule IDs.
4. It finds the servers with `discover.Discover`, or reads one file with `discover.ReadConfig`.
5. It runs the built-in config rules on every server it found, also a disabled one, as `discover`
   gives it. `rules.CheckConfig` gives the T4 findings (MOAT-T4-001 to 004). The typosquat check
   from `rules.NewBuiltinTyposquat` gives the T5 finding (MOAT-T5-001). The ignore list drops
   some findings. The rule set gives the severity of each one that is left.
6. `report.WriteServers` prints the servers. Then, only when findings are left,
   `report.WriteFindings` prints a blank line and a table of them. The table holds the rule ID, the
   severity, the server, the field and the key or related name. It never holds a value. Last,
   `reportScan` prints the ignored count for each rule ID on stderr (only rule IDs and counts, no
   server names).

Steps 1 and 2 always run. Steps 3 to 6 run only with `--no-connect`. Without `--no-connect`,
`scan` prints "not implemented yet" after step 2 and exits with 2. The exit codes
(`cmd/mcpmoat/cli.go`) are: 0 when no finding has severity high or above; 1 when a finding that is
not ignored has severity high or above (the PRD default of `--fail-on`, which is not a flag yet);
2 for an execution error. Exit code 2 wins over 1. `mcpmoat pin` is a stub. `internal/report` has
no JSON output.

The code below is built and tested, but `scan` does not call it yet: `inspect.Run`, `inspect.New`
(`SDKInspector`), `inspect.Remote` and `rules.CheckShadowing`. The tool rules (descriptions and
schemas) do not run yet. `scan` loads the rules from `--rules` and checks them, but does not apply
them. It prints a notice on stderr that says so.

### Planned (PRD section 8)

The target flow is `discover -> inspect -> rules -> pins -> report`:

- `discover` lists the servers.
- `inspect` connects and reads the tools, prompts and resources.
- `rules` applies the rules and the heuristics to what `inspect` read.
- `pins` hashes each tool and reports new, removed and changed tools (rug pulls).
- `report` prints the findings, as a table and as JSON.
- The exit code is 1 when a finding is at or above `--fail-on`.

## Tool hash

`pins.Hash` gives the pin hash of one `inspect.Tool` (FR-11, threat T2). The full contract is in
`internal/pins/canonical.go` and `internal/pins/hash.go`.

- Input: all six `inspect.Tool` fields: name, title, description, input schema, output schema and
  annotations (title and the four hints). `inspect` drops `_meta` and `icons`, so they are not
  hashed.
- Canonical form: one JSON object with a fixed shape. Every key is always present: an absent hint
  or schema is `null`, and nil annotations give the same bytes as empty annotations. RFC 8785 (JCS)
  makes it canonical, through `Value.Canonicalize` in the standard library `encoding/json/jsontext`.
- No Unicode normalisation: invisible, bidi and tag characters, and NFC against NFD, all change the
  hash.
- Invalid UTF-8, invalid schema JSON and duplicate keys give an error that wraps `ErrInvalidTool`.
- Output: `sha256-v1:` (`HashVersion`) and the lowercase hex SHA-256 of the canonical form. A change
  to the fields, the shape or the canonicalisation needs a new version. A stored hash with another
  prefix means "pin again", not a rug pull.
- Known limits: the MCP SDK decodes schema numbers as `float64`, so a change only in an integer
  above 2^53 does not change the hash. JCS makes `1`, `1.0` and `1e0` equal. At decode time, the SDK
  keeps the last value of a duplicate key and turns invalid UTF-8 and lone surrogates into U+FFFD.
  For `readOnlyHint` and `idempotentHint`, `false` and absent are the same.
- Golden hashes: `testdata/pins/hash/golden.txt`, for the fixtures in
  `testdata/pins/hash/tools.json`.

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
`internal/rules`. To list the files, run:

```sh
git grep -l '"github.com/Ducarv/mcpmoat/internal/termsafe"' -- '*.go' ':!*_test.go'
```

The rule: untrusted text goes through `termsafe` before it reaches a terminal. This covers server
names, paths, argv and errors that carry server output. `Outcome.Err` can carry server output, so
the report layer must escape it. `discover.FileError.Error` already escapes.

For secrets in output, see [Code style](../.agents/project.md#code-style).

## How to add a rule

A rule is one file, `rules/<ID>.yaml`, plus its test cases. The steps and the required cases are
in [Contributing a rule](../CONTRIBUTING.md#contributing-a-rule).

## See also

- [PRD](PRD.md), section 8: the target architecture.
- [How mcpmoat starts stdio servers](stdio-servers.md).
- [Documentation index](README.md).
- [CONTRIBUTING.md](../CONTRIBUTING.md).
