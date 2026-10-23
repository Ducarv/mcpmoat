# mcpmoat

An offline scanner for malicious or tampered MCP servers, built for the individual developer.

**Status: pre-alpha, Phase 1 in progress.** Nothing is released yet.

mcpmoat finds the MCP servers that Claude Code, Cursor and Codex load on your machine, reads the tools
they expose, and checks them for tool poisoning, rug pulls, shadowing, dangerous config and
typosquatting. It runs locally, needs no account and sends no telemetry.

## Install (planned)

These methods will work from the first release:

- Homebrew: `brew install Ducarv/tap/mcpmoat`
- Go: `go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@latest`
- GitHub Releases: download a static binary for macOS or Linux (amd64, arm64) from the
  [releases page](https://github.com/Ducarv/mcpmoat/releases).

## Planned usage

```sh
mcpmoat scan                 # discover, connect, check and report
mcpmoat scan --no-connect    # static config analysis only; runs no server
mcpmoat pin --accept <name>  # accept a changed server after you review it
mcpmoat version              # print the version, commit and build date
```

## Ignore findings

mcpmoat has built-in rules, and `scan` loads and checks them. `scan` does not apply them to
server data yet, so it has no findings to ignore. It reads the ignore list and reports problems in it.

`--ignore <rule-id>` ignores all findings of one rule. You can use the flag more than one time.

A `.mcpmoat-ignore` file in the working directory also ignores findings. Write one entry on each
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
- `mcpmoat scan` cannot connect to servers yet. Until then, `scan` needs `--no-connect`. Without
  it, `scan` prints an error and exits with code 2. When connecting is wired in, `mcpmoat scan`
  will by default start each configured stdio server, with the same command your client already
  runs. mcpmoat will use no shell. The server will get only the env from its config plus a small
  allowlist of safe variables, such as `PATH` and `HOME`. This env scrub is not a sandbox: the
  server runs as you and can read your files and use the network.

## Documentation

- [docs/README.md](docs/README.md): the index of all docs and which file owns each topic.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to add a rule, build the binary and open a PR.
- [SECURITY.md](SECURITY.md): how to report a vulnerability in mcpmoat.

## Credits

The threat model builds on public research by [Invariant Labs](https://invariantlabs.ai/) and the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

## License

[Apache-2.0](LICENSE)
