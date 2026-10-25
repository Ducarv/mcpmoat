# mcpmoat

An offline scanner for malicious or tampered MCP servers, built for the individual developer.

**Status: pre-alpha, Phase 1 in progress.** Nothing is released yet.

mcpmoat finds the MCP servers that Claude Code, Cursor and Codex load on your machine, reads the tools
they expose, and checks them for tool poisoning, rug pulls, shadowing, dangerous config and
typosquatting. It runs locally, needs no account and sends no telemetry.

## Install

This works today:

```sh
go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@latest
```

It builds the latest commit on `main`. It needs Go 1.27 or later (see [go.mod](go.mod)).

These methods come with the first release:

- Homebrew: `brew install Ducarv/tap/mcpmoat`
- GitHub Releases: download a static binary for macOS or Linux (amd64, arm64) from the
  [releases page](https://github.com/Ducarv/mcpmoat/releases).

## Usage

```sh
mcpmoat scan                  # discover, connect, pin or compare the tools, and report
mcpmoat scan --no-connect     # static config analysis only; runs no server, reads no pins
mcpmoat scan --fail-on medium # exit 1 also for a medium finding (default high)
mcpmoat pin --accept <name> --expect <digest>  # accept the tools of a server, only if they match the digest from scan
mcpmoat version               # print the version, commit and build date
```

## Pins and rug pulls

`mcpmoat scan` connects to each server and lists its tools. A stdio server is started. See
[How mcpmoat starts stdio servers](docs/stdio-servers.md).

- **First run:** mcpmoat pins the tools of each server in `pins.json`. After it saves the file, it
  prints `mcpmoat scan: pinned N tools for <server>` on stderr. The file is
  `$XDG_CONFIG_HOME/mcpmoat/pins.json`, or `~/.config/mcpmoat/pins.json` when `XDG_CONFIG_HOME` is
  not set. The file has mode `0600`. It stores each tool's hash and text. It never stores env,
  header, args or URL values from your configs.
- **Later runs:** `scan` compares the tools with the pins. It reports `MOAT-T2-001` (changed tool,
  high), `MOAT-T2-002` (new tool, medium), `MOAT-T2-003` (removed tool, low) and `MOAT-T2-004` (tool
  not verified). A new tool is medium. Read the report, not only the exit code (see [Exit
  codes](#exit-codes)). A new tool, or a not verified tool with
  a new name, is high when the same server also lost a tool in that scan, because a server can
  rename a tool to avoid the changed-tool check. A server whose tools cannot be pinned (a duplicate
  or empty tool name, invalid tool data, or more than 2 MiB) is a high `MOAT-T2-004`, because
  mcpmoat can never check its tools for changes. `MOAT-T2-004` is high when the tool name is pinned,
  because a duplicate, invalid or unverifiable copy of a pinned tool can hide a rug pull. Else it is
  medium. For each changed tool, `scan` prints a unified diff of the pinned and the current text
  after the findings table. For each new tool, it prints the full text of the tool as added lines,
  under the header `New tool <tool> on server <server>:`, so you can review it before you accept it.
  A pinned tool whose pin cannot be checked (another hash version, or a pinned text that does not
  match its hash) gets its full current text too, under `Not verified tool <tool> on server <server>
  (current text):`. An ignored finding gets no diff. If a diff is longer than 64 KiB or 2000 lines,
  `scan` cuts it and prints a warning on stderr with the tool and the server name. Review the full
  tool before you accept it. You can ignore these IDs with `--ignore` only (see [Ignore
  findings](#ignore-findings)).
- **Accept:** `scan` never changes the pins of a pinned server. Read the diff. If you trust the
  change, run `mcpmoat pin --accept <server> --expect <digest>`. The name must match one server
  exactly. If two clients use it, narrow it with `--config <file>`. If one file uses it in several
  places (`~/.claude.json` has a global section and project sections), `pin` takes the server
  outside any project, if there is exactly one. Add `--project <path>` to take the server of one
  project. If a config file has
  any problem, `pin --accept` prints it and exits with code 2, because a broken file can hide a
  second server with the same name. `pin --accept` connects to that one server and stores new pins
  for it only. It prints the diff of each changed, new and not verified tool, then
  `accepted <server>: N new, N changed, N removed`. If the server is not pinned yet, every tool is
  new, so `pin --accept` shows every tool. It prints the same warning when it cuts a diff.
- **Recommended flow:** run `mcpmoat scan` and review the diff. After the diffs, `scan` prints one
  line for each pinned server that has a pin finding:
  `To accept <server>: mcpmoat pin --accept <server> --expect pd1:<64 hex>`. After
  `scan --config <file>`, the command holds `--config <file>` too. Copy that line and run it. The
  digest (version `pd1`, the full SHA-256) covers the tools that `scan` showed you. `pin --accept --expect`
  saves the pins only if the tools that the server returns now give the same digest. Else it prints
  the diff and `the tools of <server> differ from what scan showed ...; nothing was saved`, saves
  nothing and exits with code 2. Run `scan` again and review the new diff. A hostile server can
  show harmless tools to `scan` and harmful tools to `pin --accept`. The digest stops that attack.
  An invalid or empty `--expect` exits with code 2 before any server starts.
- Without `--expect`, `pin --accept` works as before, but it trusts the tools that the server
  returns now. It prints a note on stderr, before it saves, to say so. Use `--expect` unless you have a reason not to.
- `scan` prints no `To accept` line for a server that is pinned for the first time, for a server
  that it could not inspect, for a finding that you ignored, or for tools that cannot be pinned. The
  command holds `--project <path>` when `pin` needs it to select the server. The line holds a
  command only when the server name (and the `--project` and `--config` paths) uses only the
  characters `A-Z a-z 0-9 . _ @ / : + = -` and starts with a letter, `_` or `/`. Every shell, also
  `cmd.exe` and PowerShell, reads such a word as plain text. Else the line says what to run and
  gives the digest, but no command. The line has no command either when you did not see every
  change (a cut diff, a change that `--ignore` hid, or a diff that is only a note), when the name
  cannot select the server, or when a config file has a problem. Then you must review the tool
  first, or `pin` needs `--config`. The line ends with a note for each change that you did not see:
  `(the diff was cut: review the full tool first)`, `(--ignore hid some changes: run scan without
  it to review them first)` or `(a change has no diff text: review the tool first)`. The digest
  covers those changes too.
- A server that fails, times out or is refused (an untrusted or turned-off server) is a warning on
  stderr. If the server is not pinned, it is only a warning. If the server is already pinned and
  fails or times out, it is also a high `MOAT-T2-004` finding (see [Exit codes](#exit-codes)) with
  the reason `pinned server could not be inspected`, because a
  hostile server must not avoid the rug-pull check by failing on purpose. A pinned server that is
  refused stays a warning: your client config turns it off or does not approve it, and the server
  cannot choose that.
- `scan` and `pin --accept` print the warnings of the inspection on stderr: secrets that go over
  plain http (`cleartext-secrets`), lists that the server answered but did not declare
  (`undeclared-capability`), and a proxy that skips the DNS pin (`dns-pin-unavailable`). The lines
  hold keys and fixed names only, never values. A server that is listed twice is a `MOAT-T2-004` finding too: high
  when it is pinned, else medium.
- `scan` and `pin --accept` read `pins.json` before they start any server. A `pins.json` that
  cannot be read exits with code 2 before a server starts. They read it again just before they
  save. `scan` pins only the first-run servers that the file does not hold yet, and prints
  `pinned` only for those. `pin --accept` changes only the entry of its server and keeps entries
  that another run wrote meanwhile. A parallel run can still lose an update until the lock (#150)
  exists.
- Press Ctrl-C (or send `SIGTERM` or `SIGHUP`) to stop a run. mcpmoat stops the stdio servers that
  it started. A signal during the inspection, or after it but before new pins are saved, makes
  `scan` and `pin --accept` print `interrupted; no pins were saved`, save nothing and exit with
  code 2. [Exit codes](#exit-codes) tells what `scan` does at other times.
- [Exit codes](#exit-codes) tells which of these findings give exit code 1 at each `--fail-on`
  value.

## Ignore findings

`mcpmoat scan` applies the built-in config rules (dangerous config, T4, and typosquatting, T5) to
every server it finds. The ignore list below drops findings of these rules. The pin findings
(`MOAT-T2-001` to `MOAT-T2-004`) are different: only `--ignore` drops them (see below). The YAML tool rules (descriptions and schemas) are not applied to
tools yet, so they do not run.
[Exit codes](#exit-codes) tells how the findings set the exit code.

`--ignore <rule-id>` ignores all findings of one rule. You can use the flag more than one time.

A `.mcpmoat-ignore` file in the working directory also ignores findings of the config rules. It
cannot ignore the pin rules `MOAT-T2-001` to `MOAT-T2-004`, because the file can come from a cloned
repository and must not silence the rug-pull alarm. Use `--ignore` on the command line for them.
When the file has such an entry, `scan` prints a warning. Write one entry on each
line: `RULE-ID [server[/tool]]`. A line that starts with `#` is a comment. After the rule ID, a
`#` as a separate word starts a comment to the end of the line. A server name cannot start with `#`.

```text
# All findings of this rule, on all servers
MOAT-T1-003
# All findings of this rule on the server "github"
MOAT-T1-003 github
# Only the tool "create_issue" of the server "github"
MOAT-T3-001 github/create_issue
# A comment after the entry
MOAT-T1-003 github # reviewed, the server is ours
# A server name that contains '/': end it with '/'
MOAT-T1-003 my/server/
```

Server and tool names must match exactly, and they are case-sensitive. mcpmoat splits each line on
spaces and tabs, so you cannot write a name that contains a space or a tab. A line, comments
included, must not hold control characters (other than tab), invisible characters or other white
space, because they can hide text in a terminal. mcpmoat skips a malformed line and prints a
warning with its line number.

**Security note:** mcpmoat reads `.mcpmoat-ignore` from the directory you run it in, also in a
repository that you cloned. A repository can use this file to hide findings for any server, also
for your global servers: an entry without a server, such as `MOAT-T1-003`, applies to every server.
When the file gives entries, mcpmoat prints `using N entries from .mcpmoat-ignore` (or
`using 1 entry from .mcpmoat-ignore`) on stderr. If you see this line, read the file before you
trust a clean result.

When the ignore list drops findings, `scan` also prints one line on stderr after the findings
table. It gives the count for each rule ID, for example
`mcpmoat scan: 2 findings ignored: MOAT-T4-002 (2)`. It shows only rule IDs and counts. A
`.mcpmoat-ignore` in a repository that you did not write can hide findings, so check this line and
the file. Ignored findings do not count for the exit code, so the file can turn exit code 1 into 0.

## Exit codes

This section is the exit-code contract of `mcpmoat scan`. Other docs give a short form and link
here.

| Code | Meaning |
|---|---|
| 0 | No execution error, and no finding that is not ignored has severity at or above `--fail-on`. |
| 1 | No execution error, and at least one finding that is not ignored has severity at or above `--fail-on`. |
| 2 | Execution or usage error. Exit code 2 wins over 1. |

- `--fail-on low|medium|high|critical` sets the lowest severity that gives exit code 1. The default
  is `high`. Only these exact lowercase words work. Another value, an empty value or a second
  `--fail-on` is a usage error (exit code 2). It is a `scan` flag only. `pin` never exits with
  code 1.
- Ignored findings (`.mcpmoat-ignore` or `--ignore`) never give exit code 1.
- mcpmoat fails closed. A finding with a severity that mcpmoat does not know always counts, at
  every `--fail-on` value. A finding whose rule ID is not in the rule set counts as critical.
- No built-in rule is critical yet, so `--fail-on critical` passes every built-in finding, also a
  rug pull (`MOAT-T2-001` is high). It fails only in the two fail-closed cases above. `scan` says
  so on stderr: `mcpmoat scan: note: no built-in rule is critical yet, so with --fail-on critical
  no built-in finding gives exit code 1`.
- An unpinned server that fails or times out is a warning on stderr only. It does not change the
  exit code. A pinned server that fails or times out is a high `MOAT-T2-004` finding.

Exit code 2 comes, for example, from a usage error (invalid flags), invalid rules, an unreadable
`--config` file, a problem in a config file, a `pins.json` that cannot be read or saved, a report
that cannot be written (a closed stdout), an unknown home or working directory in auto-discovery,
or an internal error. Some of these errors still print the report on stdout first, so you can read
the findings:

| Execution error | Report |
|---|---|
| A problem in a config file | Printed, then the problems. A `--config` file with a problem and no server prints only the problem. |
| A `pins.json` that cannot be read or saved | Printed |
| An internal error of the inspection (`inspect.Run`) | Printed |
| A signal before the save of new pins | Printed |
| A usage error, invalid rules, or an unknown home or working directory | Not printed |
| A signal during the inspection | Not printed |
| A report that cannot be written | Not printed |

A signal is Ctrl-C, `SIGTERM` or `SIGHUP`. It gives exit code 2 at these times:

- While `scan` reads the configs. The read stops, and the file it did not read is a config file
  problem with the reason `canceled`. If `scan` found a server and you did not use `--no-connect`,
  it then stops at the inspection, as in the next item: it prints the line below and no report.
  A `pins.json` that cannot be read is the exception: `scan` reads it before the inspection, so
  it prints the report and the `pins.json` error, without the line below.
- During the inspection. `scan` stops the stdio servers that it started, prints
  `mcpmoat scan: interrupted; no pins were saved`, saves nothing and prints no report.
- After the report, before the save of new pins. `scan` prints the same line and saves nothing.
  This applies only when the scan has new servers to pin.

At other times the scan ends with exit code 0 or 1, as if no signal came. A second signal ends
mcpmoat at once.

To use the exit code in CI or in a git hook, see [docs/ci.md](docs/ci.md).

## Build from source

```sh
go build -o mcpmoat ./cmd/mcpmoat
./mcpmoat version
```

[CONTRIBUTING.md](CONTRIBUTING.md#build-the-binary) explains how to set the version.

## What this does not do

- **It does not guarantee safety.** Rule-based scanning reduces risk. It has false positives (it can
  flag a safe tool) and false negatives (it can miss a malicious one).
- It does not analyse server source code, so it does not find malware inside a server.
- It does not protect against prompt injection that arrives in content the agent reads (for example
  a GitHub issue). That is planned for a later phase.
- `mcpmoat scan` starts each configured stdio server, with the same command your client already
  runs. mcpmoat uses no shell. The server gets only the env from its config plus a small allowlist
  of safe variables, such as `PATH` and `HOME`. This env scrub is not a sandbox: the server runs as
  you and can read your files and use the network. A server can also echo a configured env value
  into a tool description, and then that text is stored in `pins.json`. mcpmoat does not start a
  server from an untrusted project file or a turned-off server, and no flag allows it yet. The YAML
  tool rules do not run yet, so exit code 0 does not mean that the tools are safe.
- Not done yet: a lock for `pins.json` (#150) and JSON output (#64).
- `scan --rules <dir>` loads and checks extra rule files, but `scan` does not apply them yet. It
  prints `mcpmoat scan: rules from --rules are loaded and checked, but not applied yet` on stderr.

## Documentation

- [docs/README.md](docs/README.md): the index of all docs and which file owns each topic.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to add a rule, build the binary and open a PR.
- [docs/ci.md](docs/ci.md): how to run mcpmoat in CI and in git hooks.
- [SECURITY.md](SECURITY.md): how to report a vulnerability in mcpmoat.

## Credits

The threat model builds on public research by [Invariant Labs](https://invariantlabs.ai/) and the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

## License

[Apache-2.0](LICENSE)
