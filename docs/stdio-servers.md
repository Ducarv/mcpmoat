# How mcpmoat starts stdio servers

> **Status:** this page describes how mcpmoat will start stdio servers when `mcpmoat scan` connects
> to servers (issue #25). Today `mcpmoat scan` does not start servers.

A stdio server is a local program that your MCP client starts. To read its tools, mcpmoat starts
the same program. This page tells you what the program gets from mcpmoat.

## Why

A server must not get the secrets in your shell (NFR-04 in the [PRD](PRD.md)). Your shell often
holds tokens, cloud keys and access to your SSH agent. A malicious server could read them. So a
server gets only the variables that its client config declares, plus a small base set.

The scrub covers environment variables only. It is not a sandbox. A started server runs as you.
It can read any file that you can read, for example `~/.aws/credentials` or `~/.ssh`, and it can
use the network. Use `--no-connect` for servers that you do not trust.

## No shell

mcpmoat runs the `command` and `args` from the client config exactly as written, byte for byte.
It does not use a shell. Nothing expands globs, variables, quotes or `~`. The program sees the
same `argv` that your client gives it, with the command as written in `argv[0]`.

## The base environment

A server gets these variables from your environment. mcpmoat passes a variable only when it is
set in your environment. The list is based on the default lists of the official MCP SDKs and
Codex, plus `LC_CTYPE`.

| Variable | Why it is passed |
|---|---|
| `PATH` | The server finds its own tools, for example `npx` starts `node`. |
| `HOME` | Runtimes find their caches and config, such as `~/.npm` and `~/.cache/uv`. |
| `USER` | User identity that some tools read. It is not secret. |
| `LOGNAME` | User identity that some tools read. It is not secret. |
| `SHELL` | npm and some other tools read it. It is in the MCP SDK default list. |
| `TERM` | It is in the MCP SDK and Codex default lists. Low risk. |
| `LANG` | Text encoding of stdio for Python and Node. |
| `LC_ALL` | Text encoding of stdio for Python and Node. |
| `LC_CTYPE` | Text encoding of stdio for Python and Node. |
| `TMPDIR` | The per-user temporary directory on macOS. Without it, tools use the shared `/tmp`. |
| `TZ` | Time zone. It is in the Codex default list. |
| `__CF_USER_TEXT_ENCODING` | macOS text encoding. It is in the Codex list. It is not set on Linux. |

Names are case-sensitive. `Path` is not `PATH`.

## What is not passed

All other variables stay out. Some examples:

- `SSH_AUTH_SOCK`, `GPG_AGENT_INFO`: they give access to your SSH agent or your keyring.
- `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`: a proxy URL can hold a user name and a
  password.
- `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`: they change which TLS certificates the server trusts.
- `NPM_CONFIG_*`, `AWS_*`, `GITHUB_*`, `*_TOKEN`: they often hold tokens and keys.
- `LD_*`, `DYLD_*`: they load other code into the program.
- `NODE_OPTIONS`, `PYTHONPATH`: they load other code into Node or Python.
- `PWD`, `XDG_*`: they point to directories that the server does not need.

To give a server one of these variables, declare it in the `env` of that server in your client
config. mcpmoat passes it exactly as you declare it. For Claude Code and Cursor
(`mcpServers.<name>.env`):

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "<your value>" }
    }
  }
}
```

For Codex (`[mcp_servers.<name>.env]` in `config.toml`):

```toml
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]

[mcp_servers.github.env]
GITHUB_PERSONAL_ACCESS_TOKEN = "<your value>"
```

## Rules for the config env

- A variable in the config env wins over the same variable in the base set. For example, a
  `PATH` in the config replaces your `PATH`.
- mcpmoat does not expand `${VAR}` placeholders yet (issue #88). It passes them as written. So a
  server that needs the expanded value can fail to authenticate.
- An empty name, a name with `=` or a NUL byte, or a value with a NUL byte is not valid. Then
  mcpmoat does not start the server. The error message never shows the name or the value, because
  either one can hold a secret.

## Work directory

- When the config sets an absolute `cwd` (Codex only), the server runs in that directory, as
  written. Files in that directory can change what runs, the same as in your client.
- Else the server runs in a private, empty directory that mcpmoat makes for it.

When the config sets no absolute `cwd`, mcpmoat does not use your current directory, your home
directory, `/tmp` or the project directory as the work directory. It makes the private directory
in your user cache directory (`~/.cache/mcpmoat` on Linux, `~/Library/Caches/mcpmoat` on macOS).
On Linux, `$XDG_CACHE_HOME` can move the cache directory.

The reason is that npm and uv also look in the parent directories of the work directory for
`node_modules`, `.npmrc`, `package.json`, `pyproject.toml` and `uv.toml`, and these files can
change which program runs. So mcpmoat checks each directory from the private directory up to `/`.
Each one must be owned by you or by root, and only that owner can write to it. A shared directory
such as `/tmp` fails this check. When the check fails, mcpmoat does not start the server.

Your home directory is one of these parent directories. So npm and uv can still find
`~/node_modules`, `~/package.json` or `~/pyproject.toml`. This is accepted: you own your home
directory, and your client sees the same files.

A relative command with a `/`, such as `./server`, needs an absolute `cwd` in the config. Without
one, mcpmoat does not guess a directory and does not start the server.

Limit: your client can run a project server in the project root. mcpmoat does not do that, so a
server that reads files from its work directory can act differently in mcpmoat.

Note: the server runs in an empty private directory with a small environment. So a malicious server
could notice that mcpmoat started it, not your client, and act differently. Pins and rules see
only what the server shows to mcpmoat.

## Terminal

The server starts in a new session with no controlling terminal, in its own process group. This is
defence in depth, not a guarantee:

- The server cannot open `/dev/tty`.
- Ctrl-C and other signals from your terminal do not go to the server. mcpmoat stops it.
- The server cannot push fake input into your terminal with `TIOCSTI`.

But you own your terminal device (`/dev/pts/N` on Linux, `/dev/ttysNNN` on macOS). The server runs
as you, so it can find that device and open it by its path. Then it can write escape sequences to
your terminal or read your keystrokes. mcpmoat does not connect the output of the server to your
terminal. It escapes all text from the server before it shows it.

mcpmoat can stop the process group of the server. That includes the child processes that stay in
the group. A process that leaves the group on purpose is not stopped. This is not a sandbox.

## How mcpmoat finds the command

An absolute command is used as written. For a bare command such as `npx`, mcpmoat searches the
`PATH` of the server, like the clients do. That is the `PATH` from the config env when it is set,
else your `PATH`. Empty and relative entries (such as `.` or `bin`) are skipped. When no entry is
usable, the command is not found. mcpmoat does not use a default `PATH`. When the command is a bare
name and the environment of the server has no `PATH`, mcpmoat does not start the server. So mcpmoat finds the same file as
your client only when the environment of the server has a `PATH`, and only when that `PATH` is the
same as the `PATH` of your client (see the risks below).

Risks:

- A directory early in your `PATH` that others can write to is a risk. It is the same risk as in
  your client.
- Your shell `PATH` can be different from the `PATH` of a GUI client. On macOS, an app that starts
  from the Dock does not read your shell profile. So mcpmoat can find a different `npx` than
  Cursor does. If this is important to you, use an absolute command in the config.

## Project servers

A server from a project file (`.mcp.json`, `.cursor/mcp.json` or a project `.codex/config.toml`)
is untrusted, because a cloned repository can ship that file. mcpmoat does not start such a server
without an explicit opt-in from you. The opt-in flag comes in a later release.

## Platforms

mcpmoat starts stdio servers on macOS and Linux. Windows is not supported (PRD section 2.2,
non-goals).
