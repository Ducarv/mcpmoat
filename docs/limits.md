# What mcpmoat does not do

This page lists what mcpmoat does not do, so you know how far to trust a clean scan.

- **It does not guarantee safety.** Rule-based scanning reduces risk. It has false positives (it can
  flag a safe tool) and false negatives (it can miss a malicious one). Exit code 0 does not mean
  that the tools are safe.
- It does not analyse server source code, so it does not find malware inside a server.
- It does not protect against prompt injection that arrives in content the agent reads (for example
  a GitHub issue). That is planned for a later phase.
- `mcpmoat scan` starts each configured stdio server, with the same command your client already
  runs. mcpmoat uses no shell. The server gets only the env from its config plus a small allowlist
  of safe variables, such as `PATH` and `HOME`. This env scrub is not a sandbox: the server runs as
  you and can read your files and use the network.
- A server can also echo a configured env value into a tool description, and then that text is
  stored in `pins.json`.
- mcpmoat does not start a server from an untrusted project file or a turned-off server, and no flag
  allows it yet.
- The description and schema rules read only the description and the input schema of each tool.
  They do not read the output schema, the title or the annotations of a tool, and they do not read
  prompts or resources.
- The shadowing check (tool text that names a tool of another server, to change how the model uses
  that tool) is not applied yet (#200).
- `scan --no-connect` gets no tools, so it applies no description or schema rule. When `--rules`
  has such a rule, `scan` prints `mcpmoat scan: rules from --rules with target description or
  schema are not applied with --no-connect; these rules need a connection to each server to get
  its tools` on stderr.
- `scan` does not apply a rule from `--rules` with the target `config`. It runs only its built-in
  config checks, and prints `mcpmoat scan: rules from --rules with target config are not applied;
  scan applies only the built-in config checks` on stderr.
- The rule analysis has a time limit of 30 seconds for all servers together. Each server gets a
  fair share of the time that is left, but never more than 5 seconds. A server that uses up its
  share, or that `scan` does not analyse, gets a `MOAT-T1-023` finding (see
  [Exit codes](exit-codes.md)), and its tools that were not fully checked can hide a malicious
  text. `scan` does not analyse a server that it reaches after the limit or with a share under
  1 ms, or any server after it. Before this limit, each server
  had its own 5 seconds, one after the other, so 20 servers could take about 100 seconds.
- The rule analysis step takes at most 30 seconds plus one overshoot. The overshoot is the part of
  an analysis that cannot stop at its deadline: one build of the match forms of one text (#146)
  and one regex on one form (the Go `regexp` package has no context). It is up to about 1 second
  on an idle Apple M1 Pro, about 10 seconds with the race detector, and more on a loaded machine.
  The overshoot uses the shared limit too, so servers early in the order can use up the time of
  later servers. Those later servers get `MOAT-T1-023`, never a silent pass.
- `scan` keeps at most 1000 tool rule findings for each server. The limit counts the findings
  after the ignore list. `scan` keeps the most severe findings, and among findings of the same
  severity the ones of the first tools, so a server cannot push a severe finding out of the report
  with many weak ones. It counts the rest but does not list them, and adds one `MOAT-T1-024`
  finding that says how many it left out. Its severity is the highest severity of the applied rules,
  and never below high. A `.mcpmoat-ignore` file cannot drop it, and only `--ignore MOAT-T1-024`
  can (see [Ignore findings](ignore.md)). The scan stays complete, and the exit code follows
  `--fail-on`. The config findings, the pin findings and the LLM findings are not part of this
  limit. The number of tools for each server (at most 10,000) bounds the pin findings (at most one
  for each current tool and one for each removed tool, plus one for the server; the pinned tools
  come from an earlier scan, so they are at most 10,000 too), and the LLM tool cap of 500 bounds
  the LLM findings. The number of servers multiplies these bounds.
- `scan` keeps at most 100 config findings (`MOAT-T4-*` and `MOAT-T5-*`) for each server and
  10,000 for the whole scan. The config checks make one finding for each env key and each header
  key that looks like a secret, so without the caps a hostile project `.mcp.json` with many short
  keys could make a huge report. The caps count the findings after the ignore list. `scan` first
  keeps the 100 most severe findings of each server. When more than 10,000 are left, it keeps the
  10,000 most severe of the whole scan: severity first, then the order of the servers, then the
  order of the findings. A severity that mcpmoat does not know counts as critical. A server that
  lost findings gets one `MOAT-T4-005` finding: `N more config findings are not listed; limit M`
  (M is 100, or 10000 when the limit of the whole scan cut that server). It is high, or higher
  when a finding that it left out is higher. It does not count toward the caps, so the report has
  at most 10,000 config findings plus one `MOAT-T4-005` finding for each server that lost
  findings. A `.mcpmoat-ignore` file cannot drop it, so a hostile config cannot hide that findings
  were cut. Only `--ignore MOAT-T4-005` can. The scan stays complete, and the exit code follows
  `--fail-on`.
- The config caps bound the rows and the output. They do not bound the memory that `scan` uses
  before the cut: it first turns every key into a finding. A 4 MiB project file still costs about
  200 to 250 MiB of allocations. Measured on an Apple M1 Pro (go1.27.3, no race detector) with a
  4 MiB project file:

  | Config | Rows | `--json` output | Allocations |
  |---|---|---|---|
  | One server, 111,622 env keys | 101 | 71,690 bytes | 210.9 MiB |
  | One server, 103,453 header keys | 101 | 72,104 bytes | 202.4 MiB |
  | 921 servers, 110 env keys each | 10,921 | 8,576,786 bytes | 225.8 MiB |
  | One server, env keys, without the caps | 111,622 | 77.6 MB | 828.9 MiB |
  | 921 servers, without the caps | 101,310 | 71.2 MB | 762 MiB |

  The terminal output is about 87.6 KB for one server and 9,765,244 bytes for 921 servers (211.5
  and 251.2 MiB of allocations). Without the caps it was about 86 to 96 MB, with about 1.0 to
  1.1 GiB of allocations.
- The size of a config file has a limit: 4 MiB for a project file (`.mcp.json`,
  `.cursor/mcp.json`) and for a `--config` file, 256 KiB for a Codex TOML file, and 32 MiB for a
  global JSON file such as `~/.claude.json`, which holds chat history.
- In `scan --json`, a name that is longer than 512 characters and a path that is longer than 4096
  characters are cut, and each cut ends with `...`. The top-level field `fields_truncated` is true
  when any field was cut. Two names that differ only after the cut look equal in the JSON (a fix is
  planned as issue #223). Diffs, commands, URLs and argv are never cut.
- The time limit cannot stop the build of the match forms of one text. For a very hostile text
  (for example 128 KiB of one run of invisible characters), this build can take about a second, so
  the analysis of a server can end that much after its share (#146).
- `--llm` does not make a scan complete or reliable. A model can miss a malicious tool, and a
  hostile description can try to influence the model. Its findings are advisory, and with `--llm`
  your tool names and descriptions leave your machine.
- `--llm` classifies at most 500 tools in one scan, shared fairly between the servers (see
  [Optional LLM classification](llm.md)). The tools of a server over its share are not
  classified, and the scan exits with 2. So a hostile server can make a `--llm` scan exit with 2 on
  purpose, but it cannot use up the share of the other servers.
- The LLM step of a `--llm` scan stops after 10 minutes, and no flag changes this. A slow or busy
  provider can use up this time: the tools that are not classified by then give exit code 2.
- With `--llm-provider openai` and a base URL that is not the default OpenAI API (an
  OpenAI-compatible server), mcpmoat sets no cap on the output tokens of the model (see
  [Output cap](llm.md)).
- A tool that the provider refuses (HTTP 400, 413 or 422) is not classified. It gets a `medium`
  finding, not a rating. That is below the default `--fail-on high`, so a hostile server that makes
  the provider refuse its tool descriptions can keep their LLM rating from reaching `high`. When
  the provider refuses every tool that it answers, the LLM step fails and the scan exits with 2.
- `--llm` replaces the secret values of a server with `********` in the tool text that it sends,
  also the secrets in the args of a stdio server, but not all of them (see
  [What is sent](llm.md)):
  - A value shorter than 8 bytes is not removed.
  - An encoded form of a value (for example base64, URL-encoded or split with spaces) is not
    removed.
  - A secret in an arg that mcpmoat does not recognise is not removed, for example
    `--db mypassword`, a positional `hunter2`, a short path segment or `-phunter2`.
  - A secret that starts or ends with `*`, or holds a whole `********`, can show again across a
    `********`.
  - A header value of 8 bytes or more is replaced also when it is not secret, for example
    `application/json`. Arg text that the report masks is replaced also when it is not secret, for
    example a long random-looking path segment, a nix hash, a UUID or a name with spaces.
  - A tool whose text had a configured value removed gets a `medium` finding at least, also when
    the removed text is an ordinary word of your config (for example the env value `production`).
    A config that you do not control can choose which text is removed, for example an env value
    that equals an injection phrase in a tool description. The finding is `medium`, not `high`,
    so the default `--fail-on high` does not fail on it. The rule findings still read the full
    text.
- The report on the terminal and the `--json` output show the tool names as the server sent them.
  mcpmoat does not remove secret values from them, so a server that puts a secret in a tool name
  can make it show on stdout. Only the rows of the `--llm` step hide such a value (as
  `********`). Issue #228 tracks the other rows.
- When you give a wrong argument, every command hides the user info of each URL in the error text
  (`https://user:pass@host` shows as `https://(hidden)@host`), and it hides the value of
  `--llm-base-url`, also one with no scheme such as `user:pass@host`. This covers the flag errors
  of `mcpmoat`, `scan` and `pin`, an unknown command name, the `unexpected arguments` error of
  every command and the `pin --accept <name>` messages. The limits:
  - `pin` has no `--llm-base-url` flag. When an `--accept`, `--config` or `--project` value holds a
    `--llm-base-url` value (`--accept --llm-base-url=user:pass@host`), `pin` stops with exit code 2
    and a fixed message that does not print the value. A very short `--llm-base-url` value that
    also shows inside one of these values stops `pin` too, also when no secret is in it.
  - A raw `/`, `?` or `#` in a password ends the user info early, so the password can show. RFC
    3986 says that a URL must percent-encode these characters in the user info. The value of
    `--llm-base-url` is still hidden whole.
  - A value with no scheme is not hidden when it is the value of another flag and no dash comes
    before the flag name, for example `--timeout=llm-base-url=user:PASS@host`.
  - The errors about the `--config` and `--project` paths are not scrubbed, because these values
    are paths, not URLs.
- The lock on the pins directory is advisory. mcpmoat v0.1.0 does not lock, so a v0.1.0 run in
  parallel with a newer run can lose an update. A file system that cannot lock (some network
  mounts) and Windows run without the lock, after one warning.
- The owner and mode check covers the pins directory, `pins.json` and each parent directory of the
  pins directory. On macOS it also checks the ACL of the pins directory and `pins.json`, but not the
  ACL of a parent, so an allow entry for another user on `~/.config` or `~` (for example
  `delete_child`) is not detected. On Windows the owner, mode and parent checks are skipped.
- The check for a removed `pins.json` looks only at whether the file exists, so it can miss a file
  that another run removes and creates again (see **New pins file** in [Pins and rug
  pulls](pins.md)).
- Another local user can hold the advisory lock on a pins directory with mode `0755`. Then `scan`
  and `pin --accept` cannot pin and exit with code 2 after 10 seconds.
- `pins.json` has a limit of 32 MiB, first come, first served, and mcpmoat never prunes old entries.
  A hostile project config can fill the file. A server that does not fit is reported and not
  pinned (see **Full pins file** in [Pins and rug pulls](pins.md)).
- For the detail, see [Pins and rug pulls](pins.md) and [Known
  limits](ARCHITECTURE.md#the-pinsjson-store).

## See also

- [How mcpmoat starts stdio servers](stdio-servers.md)
- [Optional LLM classification](llm.md)
- [Pins and rug pulls](pins.md)
- [Exit codes](exit-codes.md)
- [Threat model and non-goals](PRD.md#2-goals-and-non-goals)
