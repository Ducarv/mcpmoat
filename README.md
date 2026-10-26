# mcpmoat

An offline scanner for malicious or tampered MCP servers, built for the individual developer. It
stays offline unless you use `--llm`.

**Status: early release, [v0.1.0](https://github.com/Ducarv/mcpmoat/releases/tag/v0.1.0).** Phase 1
is in progress. The YAML tool rules (tool poisoning and shadowing) do not run yet: see
[What this does not do](#what-this-does-not-do).

mcpmoat finds the MCP servers that Claude Code, Cursor and Codex load on your machine, reads the tools
they expose, and checks them for tool poisoning, rug pulls, shadowing, dangerous config and
typosquatting. It runs locally, needs no account and sends no telemetry. It connects only to the
servers you configured, and to an LLM provider only when you opt in with `scan --llm` (see
[Optional LLM classification](docs/llm.md)).

## Install

```sh
brew install --cask Ducarv/tap/mcpmoat                      # macOS and Linux
go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@v0.1.0    # needs Go 1.27 or later
```

You can also download an archive from the [releases page](https://github.com/Ducarv/mcpmoat/releases).
Run `mcpmoat version` to check the install. [docs/install.md](docs/install.md) has all methods and
the version output. [Verify a download](https://github.com/Ducarv/mcpmoat/blob/HEAD/docs/install.md#verify-a-download)
shows how to check an archive and the Homebrew cask. The macOS binaries are not notarized yet. The
Homebrew tap gets stable releases only.

## Usage

```sh
mcpmoat scan                  # discover, connect, pin or compare the tools, and report
mcpmoat scan --no-connect     # static config analysis only; runs no server, reads no pins
mcpmoat scan --fail-on medium # exit 1 also for a medium finding (default high)
mcpmoat scan --json           # the same report as one JSON document on stdout
mcpmoat scan --llm            # also ask an LLM to rate each tool; sends data off your machine
mcpmoat pin --accept <name> --expect <digest>  # accept the tools of a server, only if they match the digest from scan
mcpmoat version               # print the version, the commit and its date
```

`scan` prints the server table, a summary and the findings grouped by severity. With `--json` it
prints one JSON document instead. [docs/scan-output.md](docs/scan-output.md) has a sample, the colour
rules and the JSON format.

## Pins and rug pulls

A `mcpmoat scan` pins the tools of each new server in `pins.json`. Later runs report a changed, new,
removed or not verified tool, and show a diff for each changed and new tool. `scan` never changes a pin. To accept a change, review the diff
and run `mcpmoat pin --accept <server> --expect <digest>`. See [docs/pins.md](docs/pins.md).

## Ignore findings

`--ignore <rule-id>` and a `.mcpmoat-ignore` file drop findings of a rule. A repository that you
cloned can hide findings with its `.mcpmoat-ignore`, so read the file before you trust a clean result.
The file cannot drop the pin findings or the LLM findings. Only `--ignore` can. See [docs/ignore.md](docs/ignore.md).

## Optional LLM classification (sends data off your machine)

**Warning: `scan --llm` sends the name and description of every inspected tool to an LLM provider.
This data leaves your machine.** The option is off by default. See [docs/llm.md](docs/llm.md).

## Exit codes

`mcpmoat scan` exits with 0 when no finding that is not ignored is at or above `--fail-on`, with 1 when
one is, and with 2 on an execution or usage error. Exit code 2 wins over 1. See [docs/exit-codes.md](docs/exit-codes.md) for the contract.

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
- `--llm` does not make a scan complete or reliable. A model can miss a malicious tool, and a
  hostile description can try to influence the model. Its findings are advisory, and with `--llm`
  your tool names and descriptions leave your machine.
- Not done yet: a lock for `pins.json` (#150).
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
