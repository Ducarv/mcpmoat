# mcpmoat

[![CI](https://github.com/Ducarv/mcpmoat/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Ducarv/mcpmoat/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Ducarv/mcpmoat)](https://github.com/Ducarv/mcpmoat/releases)
[![Go version](https://img.shields.io/github/go-mod/go-version/Ducarv/mcpmoat)](go.mod)
[![License](https://img.shields.io/github/license/Ducarv/mcpmoat)](LICENSE)

An offline scanner for malicious or tampered MCP servers, built for the individual developer.

mcpmoat finds the MCP servers that Claude Code, Cursor and Codex load on your machine, reads the tools
they expose, and checks them for tool poisoning, shadowing, rug pulls, dangerous config and
typosquatting.

**Status: early release, [v0.1.0](https://github.com/Ducarv/mcpmoat/releases/tag/v0.1.0).** v0.1.0
runs the config checks and the rug-pull check. From the next release (build from `dev` to try it),
`scan` also applies the tool poisoning and shadowing rules to the description and the input schema
of each tool when it connects to the servers. A clean scan (exit code 0) does not mean that the
tools are safe. See [what this does not do](#what-this-does-not-do).

## Features

- **Offline.** No account and no telemetry. It connects only to the servers you configured, and to an
  LLM provider only if you use `--llm`.
- **Checks the config.** It flags plaintext secrets, unpinned packages, insecure URLs, auto-install
  flags and look-alike package names.
- **Checks the tools** (next release, not in v0.1.0). It flags hidden instructions, invisible
  characters, exfiltration and shadowing in the description and the input schema of each tool.
- **Catches rug pulls.** It pins every tool and reports a tool that changes, appears or goes away.
- **Built for CI.** Exit code 0, 1 or 2, a `--fail-on` threshold, and one JSON document with `--json`.
- **Optional LLM rating** (next release, not in v0.1.0). Off by default. With `--llm`, tool names and
  descriptions leave your machine.

## Install

```sh
brew install --cask Ducarv/tap/mcpmoat                      # macOS and Linux
go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@v0.1.0    # needs Go 1.27 or later
```

You can also download an archive from the [releases page](https://github.com/Ducarv/mcpmoat/releases).
[docs/install.md](docs/install.md) has all methods. The macOS binaries are not notarized yet, and the
Homebrew tap gets stable releases only. Run `mcpmoat version` to check the install. Here is [how to
verify a download](https://github.com/Ducarv/mcpmoat/blob/HEAD/docs/install.md#verify-a-download).

## Quick start

```sh
mcpmoat scan
```

`scan` starts each stdio server in your configs, with the command your client already runs. To read the
configs only, run `mcpmoat scan --no-connect` first. `scan` prints a server table, a summary and the
findings, worst first. A shortened sample:

```text
SUMMARY
  github (claude-code, global): ok, 12 tools, 0 findings
  files (cursor, global): ok, 4 tools, 1 finding

FINDINGS
HIGH (1)
  MOAT-T4-002  Plaintext secret in config
    Server: files (cursor, global)
    Where: env GITHUB_TOKEN
    Fix: Move the secret out of the config: use an environment variable reference ...
```

More about the output: [docs/scan-output.md](docs/scan-output.md).

## Usage

**Scan the config only.** This starts no server and reads no pins.

```sh
mcpmoat scan --no-connect
```

**Fail a build on findings.** Exit code 1 means a finding that is not ignored is at or above
`--fail-on` (default `high`). Exit code 2 means an error, and it wins over 1. See
[docs/exit-codes.md](docs/exit-codes.md) and [docs/ci.md](docs/ci.md).

```sh
mcpmoat scan --fail-on medium
```

**Read the report as JSON.**

```sh
mcpmoat scan --json | jq '.findings[] | {rule_id, server}'
```

**Check for a rug pull.** A `scan` pins the tools of each new server. Later runs show a diff when they
change. Review the diff, then accept it with the digest that `scan` prints. An accept does not make
the new text safe: from the next release, a tool poisoning finding on the new text stays after the
accept. See [docs/pins.md](docs/pins.md).

```sh
mcpmoat pin --accept <server> --expect <digest>
```

**Ignore a finding.** Use `--ignore` or a `.mcpmoat-ignore` file. A cloned repository can hide findings
with its own `.mcpmoat-ignore`, so read it first. The file cannot drop pin findings or, from the
next release, LLM findings. Only `--ignore` can. See [docs/ignore.md](docs/ignore.md).

```sh
mcpmoat scan --ignore MOAT-T4-003
```

**Rate tools with an LLM** (next release; build from `dev` to try it). This sends tool names and
descriptions to the provider. Set `MCPMOAT_LLM_API_KEY` first. See [docs/llm.md](docs/llm.md).

```sh
mcpmoat scan --llm
```

## What this does not do

- **It does not guarantee safety.** It has false positives and false negatives.
- It does not analyse server source code, so it does not find malware inside a server.
- It does not protect against prompt injection in content the agent reads.
- `scan` starts your configured stdio servers. It passes them only a few env variables, but this is not
  a sandbox: a server runs as you and can read your files and use the network. It never starts a
  server from an untrusted project file.
- A clean scan (exit code 0) does not mean that the tools are safe. The tool rules find only known
  patterns, and v0.1.0 does not apply them (the next release does). They do not run with
  `--no-connect`. The check that compares the tools of two servers for shadowing does not run yet.

The full list is in [docs/limits.md](https://github.com/Ducarv/mcpmoat/blob/HEAD/docs/limits.md).

## Documentation

[docs/README.md](docs/README.md) is the index. Start with [Install](docs/install.md),
[Scan output](docs/scan-output.md), [Pins and rug pulls](docs/pins.md), [Exit codes](docs/exit-codes.md)
and [Use mcpmoat in CI](docs/ci.md). For the design, read [Architecture](docs/ARCHITECTURE.md) and the
[requirements](docs/PRD.md).

## Contributing

Clone the repo, branch from `dev` and open your pull request against `dev`. `main` holds released
code. [CONTRIBUTING.md](CONTRIBUTING.md) explains the checks, and
[docs/writing-rules.md](docs/writing-rules.md) shows how to add a rule. Build with
`go build -o mcpmoat ./cmd/mcpmoat`. To report a vulnerability, read
[SECURITY.md](https://github.com/Ducarv/mcpmoat/blob/HEAD/SECURITY.md).

## Credits

The threat model builds on public research by [Invariant Labs](https://invariantlabs.ai/) and the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

Built by [Ducarv](https://github.com/Ducarv). See the
[contributors](https://github.com/Ducarv/mcpmoat/graphs/contributors).

## License

[Apache-2.0](LICENSE)
