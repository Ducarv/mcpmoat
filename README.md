# mcpmoat

An offline scanner for malicious or tampered MCP servers, built for the individual developer.

**Status: pre-alpha, Phase 1 in progress.** Nothing is released yet.

mcpmoat finds the MCP servers that Claude Code, Cursor and Codex load on your machine, reads the tools
they expose, and checks them for tool poisoning, rug pulls, shadowing, dangerous config and
typosquatting. It runs locally, needs no account and sends no telemetry.

## Install (planned)

These methods will work from the first release:

- Homebrew (macOS and Linux): `brew install --cask Ducarv/tap/mcpmoat`. The tap gets stable
  releases only, not prereleases. The macOS binaries are not notarized yet: see
  [Verify a download](#verify-a-download).
- Go: `go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@latest`
- GitHub Releases: download the archive for your system from the
  [releases page](https://github.com/Ducarv/mcpmoat/releases). The archives are
  `mcpmoat_<version>_<os>_<arch>.tar.gz` for `darwin` or `linux` and `amd64` or `arm64`.
  `<version>` is the release number without the `v`, for example `0.1.0`. Each archive holds the
  `mcpmoat` binary, `LICENSE` and `README.md`. The Linux binary is static. The macOS binary links
  only macOS system libraries, like every Go binary on macOS. Extract the binary and put it on your
  `PATH`.

Run `mcpmoat version` to check the install. A release binary prints
`mcpmoat v<version> (commit <c>, built <d>)`. The `go install` build above prints `commit none, built
unknown`, because `go install` builds from the Go module cache, which has no git data.

### Verify a download

Each release has a `checksums.txt` file. Download it to the same folder as the archive, then check
the archive. This step only catches a broken download. It does not prove where the archive came
from.

```sh
shasum -a 256 --ignore-missing -c checksums.txt   # macOS
sha256sum --ignore-missing -c checksums.txt       # Linux
```

The real check is the build provenance attestation of the archive. Check it with the
[GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify mcpmoat_<version>_<os>_<arch>.tar.gz -R Ducarv/mcpmoat \
  --cert-identity https://github.com/Ducarv/mcpmoat/.github/workflows/release.yml@refs/tags/v<version> \
  --source-ref refs/tags/v<version> --deny-self-hosted-runners
```

The check proves which repo, workflow and tag built the archive. It does not prove that the code
was reviewed. Use `--cert-identity` as above, not `--signer-workflow`: some `gh` versions match
`--signer-workflow` as a prefix only, so `release.yml` would also match another workflow file
whose name starts with `release.yml`.

Homebrew does not check the attestation. `brew install` checks only the sha256 values in the cask
from the tap. A cask is Ruby code that Homebrew runs on install, so matching sha256 values alone do
not prove that the cask is safe. To check the cask, first verify `checksums.txt` with the command
above, with the same flags. Then open `Casks/mcpmoat.rb` in the
[tap](https://github.com/Ducarv/homebrew-tap) and check these points:

- The `version` line is the release number without the `v`, for example `"0.1.0"`.
- Every `url` starts with `https://github.com/Ducarv/mcpmoat/releases/download/v#{version}/`.
  Homebrew fills in `#{version}` from the `version` line.
- Each `sha256` is the hash on the `checksums.txt` line for the archive that the `url` in the same
  block names.
- The only block that runs a command is `postflight_steps`. It holds one `on_macos` block with one
  `xattr` line that removes the quarantine flag from `mcpmoat`.
- There is no other code. The cask holds only these parts: `version`; `on_macos` and `on_linux`,
  each with `on_arm` and `on_intel` blocks that hold `url` and `sha256`; `name`, `desc` and
  `homepage`; `livecheck` with one `skip` line; `binary`; and `postflight_steps`.

The macOS binaries are not notarized yet. The Homebrew cask removes the quarantine flag on install,
so Gatekeeper does not check the binary. Verify the archive if that matters to you.

## Usage

```sh
mcpmoat scan                 # discover, connect, pin or compare the tools, and report
mcpmoat scan --no-connect    # static config analysis only; runs no server, reads no pins
mcpmoat pin --accept <name> --expect <digest>  # accept the tools of a server, only if they match the digest from scan
mcpmoat version              # print the version, commit and build date
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
  high), `MOAT-T2-002` (new tool, medium), `MOAT-T2-003` (removed tool, low) and `MOAT-T2-004`
  (tool not verified). A new tool is medium, so alone it does not give exit code 1: read the
  report, not only the exit code. A new tool, or a not verified tool with a new name, is high when
  the same server also lost a tool in that scan, because a server can rename a tool to avoid the
  changed-tool check. A server whose tools cannot be pinned (a duplicate or empty tool
  name, invalid tool data, or more than 2 MiB) is a high `MOAT-T2-004`, because mcpmoat can never
  check its tools for changes. `MOAT-T2-004` is high when the tool name is pinned, because a duplicate,
  invalid or unverifiable copy of a pinned tool can hide a rug pull. Else it is medium. For each
  changed tool, `scan` prints a unified diff of the pinned and the current text after the findings
  table. For each new tool, it prints the full text of the tool as added lines, under the header
  `New tool <tool> on server <server>:`, so you can review it before you accept it. A pinned tool
  whose pin cannot be checked (another hash version, or a pinned text that does not match its hash)
  gets its full current text too, under `Not verified tool <tool> on server <server> (current
  text):`. An ignored finding gets no diff. If a diff is longer than 64 KiB or 2000 lines, `scan` cuts it and prints a
  warning on stderr with the tool and the server name. Review the full tool before you accept it.
  You can ignore these IDs with `--ignore` only (see [Ignore findings](#ignore-findings)).
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
  stderr. If the server is not pinned, it does not change the exit code. If the server is already
  pinned and fails or times out, it is also a `MOAT-T2-004` finding (high, exit code 1) with the
  reason `pinned server could not be inspected`, because a hostile server must not avoid the
  rug-pull check by failing on purpose. A pinned server that is refused stays a warning: your
  client config turns it off or does not approve it, and the server cannot choose that.
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
  it started. `scan` and `pin --accept` print `interrupted; no pins were saved`, save nothing and
  exit with code 2.
- A changed tool gives exit code 1. So does a high `MOAT-T2-004` (a pinned tool name that cannot be
  verified, a pinned server that fails or times out, or a server whose tools cannot be pinned), and
  a new tool next to a removed one. The default threshold is high, so a new tool (`MOAT-T2-002`)
  alone, a removed tool (`MOAT-T2-003`) and a medium `MOAT-T2-004` (an unpinned tool name) do not
  give exit code 1. A `pins.json`
  that `scan` cannot read or save gives exit code 2.

## Ignore findings

`mcpmoat scan` applies the built-in config rules (dangerous config, T4, and typosquatting, T5) to
every server it finds. The ignore list below drops findings of these rules. The pin findings
(`MOAT-T2-001` to `MOAT-T2-004`) are different: only `--ignore` drops them (see below). The YAML tool rules (descriptions and schemas) are not applied to
tools yet, so they do not run.
`scan` exits with code 1 when a finding that is not ignored has severity high or above.

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
- Not done yet: a lock for `pins.json` (#150), `--fail-on` (#65) and JSON output (#64).
- `scan --rules <dir>` loads and checks extra rule files, but `scan` does not apply them yet. It
  prints `mcpmoat scan: rules from --rules are loaded and checked, but not applied yet` on stderr.

## Documentation

- [docs/README.md](docs/README.md): the index of all docs and which file owns each topic.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to add a rule, build the binary and open a PR.
- [SECURITY.md](SECURITY.md): how to report a vulnerability in mcpmoat.

## Credits

The threat model builds on public research by [Invariant Labs](https://invariantlabs.ai/) and the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

## License

[Apache-2.0](LICENSE)
