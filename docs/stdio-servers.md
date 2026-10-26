# How mcpmoat starts stdio servers

> **Status:** this page describes how the `internal/inspect` code starts stdio servers.
> `mcpmoat scan` (without `--no-connect`) and `mcpmoat pin --accept <server>` call that code. See
> [ARCHITECTURE.md](ARCHITECTURE.md#data-flow) for what is wired today.

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

mcpmoat runs the `command` and `args` from the client config exactly as written, byte for byte,
after it expands the `${...}` placeholders the same way as your client (see
[Placeholders](#placeholders)). It does not use a shell. Nothing else expands globs, quotes or `~`.
The program sees the same `argv` that your client gives it, with the command in `argv[0]`.

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

mcpmoat also adds one variable of its own: `npm_config_yes=false` (see
[npx and package installs](#npx-and-package-installs)).

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
- mcpmoat expands the `${...}` placeholders in the values before it starts the server (see
  [Placeholders](#placeholders)). It does not expand the names.
- An empty name, a name with `=` or a NUL byte, or a value with a NUL byte is not valid. Then
  mcpmoat does not start the server. The error message never shows the name or the value, because
  either one can hold a secret.

## Placeholders

A client config can hold `${...}` placeholders, for example `"GITHUB_TOKEN": "${GITHUB_TOKEN}"`.
Your client replaces them with values from your environment before it starts the server. mcpmoat
does the same, with the syntax of the client that owns the config:

- Claude Code: `${VAR}` and `${VAR:-default}`. A variable that is set but empty gives an empty
  value, not the default.
- Cursor: `${env:NAME}`, `${userHome}`, `${workspaceFolder}`, `${workspaceFolderBasename}`,
  `${pathSeparator}` and `${/}`.
- Codex: no placeholders. mcpmoat passes the text as written.

Rules:

- The values come from your environment, the one that you start mcpmoat in. A placeholder can
  read any variable, not only the base set. So a config can pass a variable such as
  `GITHUB_TOKEN` to the server, the same as in your client.
- Exception for hidden variables: some variables are hidden from every placeholder. `scan` hides
  `MCPMOAT_LLM_API_KEY`. A placeholder for a hidden variable fails for every server, trusted or
  not, stdio or remote, with a config error that says the variable is hidden from placeholders.
  The code is `SDKOptions.HiddenEnv` in `internal/inspect`.
- Exception: a server from a project file that a repository can ship (see
  [Project servers](#project-servers)) runs only when you opt in, and it reads less. A stdio
  server reads only the base set, which it gets anyway. A remote server reads no variable at all,
  and no Cursor `${workspaceFolder}` or `${workspaceFolderBasename}`, because even `USER`, `HOME`
  or the project path tell the host who you are. Any other variable counts as not set:
  a default applies, and without a default mcpmoat does not start the server or connect. So a
  config from a cloned repository cannot send a secret variable to a server address that it
  chose. This applies also when your client runs the server: mcpmoat cannot see the Cursor
  approval, and a Claude Code approval by name covers every repository with a server of that
  name. A project server that needs a secret variable, such as `${GITHUB_TOKEN}`, is not started.
  A server from your own config reads your whole environment, also when it is turned off and you
  opt in to inspect it.
- mcpmoat expands the command, the arguments, the URL, and the values of `env` and `headers`. It
  does not expand the names.
- When a variable is not set and the placeholder has no default, mcpmoat does not start the
  server. The error names the variable, never a value. Cursor probably uses an empty value in
  this case. mcpmoat stops instead.
- The error shows the name only when it is a plain variable name: ASCII letters, digits and `_`,
  not a digit first, at most 64 bytes. Otherwise it says "variable with an invalid name". A
  secret value can hold `${` by chance, so the text inside `${...}` can be part of the secret.
- An expanded text can be at most 64 KiB long, and the expanded texts of one server together at
  most 1 MiB. Over a limit, mcpmoat does not start the server.
- A Cursor workspace placeholder (`${workspaceFolder}` or `${workspaceFolderBasename}`) in a
  global Cursor server gives an error, because that server has no project.
- The server list shows the config as written, not the expanded values. mcpmoat removes the
  expanded values of 8 bytes or more from its error messages. A shorter value is not removed, so it
  can show in an error message that the server sends back.

## npx and package installs

When its input is not a terminal, `npx` does not ask before it installs a package. A server gets a
pipe as input, not your terminal. So `npx some-tool` installs `some-tool` from the public npm
registry and runs it when it is not installed on your machine. Anyone can publish a package with
that name.

So mcpmoat always adds `npm_config_yes=false` to the environment of the server. Then `npx` (npm 7
or later) stops with an error and installs nothing.

Your config still wins:

- With `-y` or `--yes` in the `args`, `npx` installs the package, the same as in your client.
- With `npm_config_yes` in the `env` of the server (in any letter case), mcpmoat does not add its
  own value.

Limits:

- `pnpm dlx`, `bunx`, `uvx` and the standalone `npx` from before npm 7 ignore this variable. They
  can still install a package that is not on your machine.
- The variable also goes to every `npm` command that the server starts itself. This is a small
  difference from your client.

## Work directory

- When the config sets an absolute `cwd` (Codex only), the server runs in that directory, as
  written. Files in that directory can change what runs, the same as in your client.
- Else, a trusted project server runs in its project directory, the same as in your client. An
  example is a server in the `projects` section of `~/.claude.json`. The project directory must
  exist. Files in the project, such as `node_modules/.bin` and `.npmrc`, can change what runs, the
  same as in your client. One scan reads the servers of every project in `~/.claude.json`, so it
  runs these servers in all of those projects at once. Your client runs them only when you open
  the project.
- Else the server runs in a private, empty directory that mcpmoat makes for it.

A server from a project file that a repository can ship (see [Project servers](#project-servers))
never runs in its project directory, also when you opt in to start it.

When neither of the first two cases applies, mcpmoat does not use your current directory, your
home directory, `/tmp` or the project directory as the work directory. It makes the private
directory in your user cache directory (`~/.cache/mcpmoat` on Linux, `~/Library/Caches/mcpmoat` on
macOS). On Linux, `$XDG_CACHE_HOME` can move the cache directory.

The reason is that npm and uv also look in the parent directories of the work directory for
`node_modules`, `.npmrc`, `package.json`, `pyproject.toml` and `uv.toml`, and these files can
change which program runs. So mcpmoat checks each directory from the private directory up to `/`.
Each one must be owned by you or by root, and only that owner can write to it. A shared directory
such as `/tmp` fails this check. When the check fails, mcpmoat does not start the server.

Your home directory is one of these parent directories. So npm and uv can still find
`~/node_modules`, `~/package.json` or `~/pyproject.toml`. This is accepted: you own your home
directory, and your client sees the same files.

A relative command with a `/`, such as `./server`, needs an absolute `cwd` in the config or a
project directory. Without one, mcpmoat does not guess a directory and does not start the server.

Limit: your client can run a global server in the directory where you started the client, and a
server from a repository project file in the project root. mcpmoat runs these servers in the
private directory, so a server that reads files from its work directory can act differently in
mcpmoat.

Note: a server can run in an empty private directory with a small environment. So a malicious
server could notice that mcpmoat started it, not your client, and act differently. Pins and rules
see only what the server shows to mcpmoat.

## Terminal

The server starts in a new session with no controlling terminal, in its own process group. This is
defence in depth, not a guarantee:

- The server cannot open `/dev/tty`.
- Ctrl-C and other signals from your terminal do not go to the server. When mcpmoat gets Ctrl-C,
  `SIGTERM` or `SIGHUP`, it stops the server and exits with code 2. It saves no pins.
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
name and the environment of the server has no `PATH`, mcpmoat does not start the server. So
mcpmoat finds the same file as your client only when the environment of the server has a `PATH`,
and only when that `PATH` is the same as the `PATH` of your client (see the risks below).

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

## Disabled and unapproved servers

Your client can turn a server off, and Claude Code asks you to approve each server in `.mcp.json`.
`mcpmoat scan --no-connect` shows this in the `STATE` column: `enabled`, `disabled`,
`unapproved` or `project-approved`. A `project-approved` server is approved only by files from the
repository, not by you. A cloned repository can approve its own servers, so mcpmoat does not count
that approval.

mcpmoat does not start a `disabled`, `unapproved` or `project-approved` server without an explicit
opt-in from you. This opt-in is separate from the opt-in for project servers. A server that is both
untrusted and disabled, unapproved or project-approved needs both opt-ins.

mcpmoat checks the state first, then whether the server is untrusted. When both checks refuse a
server, the error tells about the state.

No command-line flag exists for these opt-ins yet. So `mcpmoat scan` and `mcpmoat pin --accept` do
not start such a server. They print a warning (scan) or an error with exit code 2 (pin) instead.

## Platforms

mcpmoat starts stdio servers on macOS and Linux. Windows is not supported (PRD section 2.2,
non-goals).
