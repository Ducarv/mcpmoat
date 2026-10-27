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
  stored in `pins.json` as the server sent it. The report masks the value (see below), but
  `pins.json` (mode `0600`) keeps the raw text.
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
- The rule analysis of each server has a time budget. A server that uses it up gets a
  `MOAT-T1-023` finding (see [Exit codes](exit-codes.md)), and its tools that were not fully
  checked can hide a malicious text.
- The budget cannot stop the build of the match forms of one text. This build takes under about
  0.2 s in the worst case that we measured, so the analysis of a server can end that much after
  its budget.
- A text with more than 256 U+009D (C1 OSC controls) always gets `MOAT-T1-017` or `MOAT-T1-018`
  (high), also a benign text in the wrong encoding. The reason and the example are in
  [Contributing a rule](writing-rules.md#2-write-the-rule). With a custom rule at critical
  severity and `--fail-on critical`, a text with more than 256 U+009D can hide the payload from
  that rule and only `MOAT-T1-017` or `MOAT-T1-018` (high) fires.
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
  the LLM findings. Nothing bounds the config findings except the size of the config file (32 MiB
  for a global file, 4 MiB for a project file), and the number of servers multiplies all these
  bounds. A cap for the config findings is planned as a follow-up (issue #213).
- In `scan --json`, a name that is longer than 512 characters and a path that is longer than 4096
  characters are cut, and each cut ends with `...`. The top-level field `fields_truncated` is true
  when any field was cut. Two names that differ only after the cut look equal in the JSON (a fix is
  planned as issue #223). Diffs, commands, URLs and argv are never cut. These caps and the cap of
  1000 tool findings do not bound the size of the whole JSON document: a hostile config file with a
  very large number of config findings can give a very large document.
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
- The report on the terminal and the `--json` output show each configured value that a server
  echoes in its tool text as `********`: the env values, the header values, the expanded
  placeholder values, the secrets in the args and the secret URL parts, and the credential pieces
  inside them, such as one cookie (see [Scan output](scan-output.md), and
  [What is sent](llm.md) for the pieces). This mask has limits:
  - A value shorter than 8 bytes is not masked.
  - An encoded form of a value (for example base64, URL-encoded or split with spaces) is not
    masked.
  - The mask compares the text after the JSON decode. A configured value that holds characters
    that the output escapes (a backslash sequence such as the `\t` and `\n` of the Windows path
    `C:\tools\new_dir`, a quote, a control character, or a `\uXXXX` written as plain characters)
    is not found when the server sends the real characters (a tab, a newline). The pin diff or the
    quoted tool name then shows those characters as escapes, so the value can show again.
  - A value that a server splits over two JSON strings (for example a key and its value) or over
    the tool name and the description is not found.
  - The password of the Oracle form `scott/pw@orcl` in an env value, an expanded value or a header
    value is not masked alone. Only the whole value is.
  - The decoded text `name:password` of a `Basic` header value is not masked as a whole. Only the
    password (8 bytes or more) and the base64 forms are, so the name can show.
  - The mask uses the values that are configured now. A value that is no longer configured (for
    example a rotated token) can still show on the pinned side of a pin diff.
  - A secret that starts or ends with `*`, or holds a whole `********`, can show again across a
    `********`.
  - A server can write `********` in its text itself, so the marker does not prove that mcpmoat
    masked a value.
- `--llm` replaces with `********` only the configured values that look like a credential in the
  tool text that it sends (see [What is sent](llm.md)). The limits of the report mask above apply
  here too. Also:
  - A plain config value that a server echoes reaches the provider, for example the env value
    `production` of `NODE_ENV`, or a password under a key that does not look secret.
  - A secret in an arg that mcpmoat does not recognise is not removed, for example
    `--db mypassword`, a positional `hunter2`, a short path segment or `-phunter2`. The password
    of a positional `admin:pw` or `scott/pw@orcl` is removed only when the whole value looks like
    a token.
  - The check fails closed, so some text that is not secret is removed too: a word of 32 bytes or
    more (also a readable path segment), a UUID, or a header value that starts with an auth scheme
    word, such as `Token count`.
  - A tool whose text had a credential removed gets a `medium` finding at least. A config that you
    do not control can choose which text is removed, for example an env value under a secret-like
    key that equals an injection phrase in a tool description. The finding is `medium`, not
    `high`, so the default `--fail-on high` does not fail on it. A phrase under a key that does
    not look secret is not removed, so the model reads it. The rule findings still read the full
    text.
- When a server fails, mcpmoat removes the configured values and their credential pieces from the
  failure text. A value or piece shorter than 8 bytes is removed only where it stands as a whole
  word (see [Placeholders](stdio-servers.md#placeholders)). The limits:
  - A hostile server can glue a letter to a short value (`1234x`) or split it (`1_2_3_4`), and
    then the value shows.
  - A common word that is also a short configured value is masked too (with the value `1`,
    `exit status 1` shows as `exit status ********`).
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
