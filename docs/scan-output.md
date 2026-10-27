# Scan output

This page tells what `mcpmoat scan` prints in the terminal and with `--json`.

## What `scan` prints

`scan` prints the server table, then a summary with one line for each server, then the findings
grouped by severity (the worst first). This is a short sample (the table is left out, and the long
risk and fix texts are shortened):

```text
SUMMARY
  github (claude-code, global): ok, 12 tools, 0 findings
  files (cursor, global): ok, 4 tools, 2 findings
    warning: cleartext-secrets: secrets go over plain http to a host that is not loopback: header X-Api-Key
  search (codex, global): timeout, 0 findings (...)

FINDINGS
HIGH (1)
  MOAT-T4-002  Plaintext secret in config
    Server: files (cursor, global)
    Where: env GITHUB_TOKEN
    Risk: A secret is written in clear text in the client config ...
    Fix: Move the secret out of the config: use an environment variable reference ...
MEDIUM (1)
  MOAT-T4-003  Package runner uses an unpinned package
    Server: files (cursor, global)
    Where: args @example~corp/files~mcp
    Risk: The server starts from a package that is not fixed ...
    Fix: Pin an exact version, for example npx @scope/server@1.4.2 ...
```

- **Summary:** the status of a server is `ok`, `timeout`, `failed` or `not inspected`. A server
  that `--no-connect` skipped, or that `scan` refused to start (an untrusted or turned-off server),
  is `not inspected`. A server that failed, timed out or was refused shows its reason in brackets
  at the end of its line (shortened as `(...)` above), and so does every server when `scan` cannot
  read pins.json. A server with status `ok` also shows its tool count. The connection warnings of
  a server show under its line. They hold header keys only, never values.
- **Findings:** each finding has the rule ID and title, the server with its client and scope (so two
  servers with the same name in two configs differ), where it matched (the field and key, or the
  tool), and a `Risk` and a `Fix` line.
- **Tool rule findings:** when `scan` connects to the servers, it applies the description and
  schema rules (T1 and T3, built-in and from `--rules`) to every tool. A finding of these rules has
  a `Tool:` line in place of `Where:`: the tool name, then `(description)` or `(schema)`, the part
  of the tool that matched. A tool name longer than 80 characters (runes) is cut to 80 and ends
  with `...`. The finding never shows the tool text or the pattern.
- **Time budget:** a server that uses up its rule time budget keeps the findings found so far, and
  gets one `MOAT-T1-023` finding with a `Reason:` line in place of `Tool:`. `scan` also prints one
  warning on stderr. Its severity and exit code are in [Exit codes](exit-codes.md).
- **Finding cap:** a server with more than 1000 tool findings gets one `MOAT-T1-024` summary
  finding. `scan` lists the 1000 most severe findings (the ones of the first tools among findings of
  the same severity) and counts the rest. The scan stays complete, and the
  exit code follows `--fail-on`. The severity is the highest severity among the applied rules and
  never lower than high, so the finding fails closed. Only `--ignore` drops it. A `.mcpmoat-ignore`
  file cannot.
- **Counts:** the tool rule findings, `MOAT-T1-023` and `MOAT-T1-024` count in the findings of
  their server in the summary.

A short sample of these two kinds of finding:

```text
HIGH (2)
  MOAT-T1-003  Tool description tells the model to hide actions from the user
    Server: notes (claude-code, global)
    Tool: daily_quote (description)
    Risk: ...
    Fix: ...
  MOAT-T1-023  Rule analysis stopped at the time budget
    Server: slow (claude-code, global)
    Reason: "rule analysis time budget used up; 3 of 8 tools not fully checked"
    Risk: mcpmoat did not check all the tools of this server ...
    Fix: Do not use this server until you have read its tool descriptions and schemas yourself ...
```

The other notes on the terminal output:

- **Colour:** colour is on only when stdout is a terminal. `--no-color` (before or after the command, as in
  `mcpmoat scan --no-color`) or a non-empty `NO_COLOR` environment variable turns it off. Colour
  marks the headings, the severity lines and the status words only. The words carry the meaning, so
  the output is the same without colour. `scan` escapes every config, server and rule text first,
  so terminal escape sequences in a config or from a server do not reach your terminal.
- **Exit code:** warnings and statuses do not change it. Only findings do (see
  [Exit codes](exit-codes.md)).

## JSON output

`mcpmoat scan --json` prints the report as one JSON document. It works with `--no-connect` too.
List the rule ID and the server of each finding:

```sh
mcpmoat scan --json | jq -r '.findings[] | "\(.rule_id) \(.server)"'
```

- **stdout** holds exactly one JSON document. It has no table, no `To accept` line and no other
  text. If `scan` makes no report (for example, `--config` cannot be loaded), stdout is empty.
- **stderr** gets the warnings, the notices and the errors. They are the same as in a run without
  `--json`, plus the lines that the summary shows without `--json`: a server that was not
  inspected, and the warnings of an inspection.
- **Exit codes** do not change: 0, 1 or 2 (see [Exit codes](exit-codes.md)).
- **`complete`** is `false` when the report can miss results, for example when a config file has a
  problem, `pins.json` cannot be read, or the LLM step of a `--llm` scan did not classify every
  tool: a provider failure, a provider refusal of every tool, the 10-minute time limit of the LLM
  step, an internal error of the LLM step, or tools over the 500-tool cap (see
  [Optional LLM classification](llm.md)). The exit code is then 2, and the reason is on stderr. A
  tool that the provider refused (HTTP 400, 413 or 422) alone does not make `complete` `false`: it
  is a `MOAT-LLM-002` finding (or `MOAT-LLM-001` when its text was cut or had a configured value removed).
  `complete` can be `true` with exit code 2 when the save of new pins fails after the report, so
  always check the exit code too. A failed write to stdout (for example a closed pipe) can leave
  only the first part of the document. It is not valid JSON, and the exit code is 2. A server that
  uses up its rule time budget does not make `complete` `false`: the `MOAT-T1-023` finding tells you
  about it.
- **`ignored`** is a required field. It holds `total` (the number of findings that an ignore entry
  dropped, the same number as in the stderr line `N findings ignored: ...`), `rules` (the rule ID
  and the count of dropped findings for each rule, `{}` when none) and `file_entries` (the number of
  `.mcpmoat-ignore` entries that `scan` read, the same number as in the stderr line
  `using N entries`; some of them may not apply to any finding). It holds rule IDs only, never text
  of the ignore file.
- **`accept`** is an optional field of a server. A pinned server that has a `To accept` hint in the
  terminal has `accept` with `digest` (`pd1:` and 64 hex characters, the same digest as in the
  terminal hint) and, only when the terminal hint prints a command, `command`. It never holds the
  prose steps of a hint without a command. The `To accept` line itself is not in the JSON. When two
  servers have the same identity (the same client, source, project path and name), `scan` prints one
  `To accept` line, and the JSON gives both servers the same `accept` object, with the same digest.
- **`fields_truncated`** is a required boolean. It is `true` when at least one text field was cut at
  its length cap. `scan` cuts names to 512 characters and paths to 4096 characters, and each cut
  ends with `...`. It never cuts diffs, commands, URLs or argv. Two server names that differ only
  after the cut are equal in the JSON, so use `server_index` (see below) to tell such servers apart.
- **Match a finding or diff to its server:** each finding and each diff has a required integer
  `server_index` (0 or more). It is the position of its server in the `servers` array. Use it to
  find the server object. Do not match by the `server` text, because a cut name can be equal for
  two servers. The `errors` entries have no `server_index`, because a file error has no server
  object. Do not match `errors[].server` to `servers[].name`: a cut name can be equal for two
  servers, and a file error has no server object. Use `path`, `project_path`, `line` and `col` to
  tell the errors apart. For example, print each finding with the client of its server:

  ```sh
  mcpmoat scan --json | jq -r '.servers as $s | .findings[] | "\(.rule_id) \($s[.server_index].client)"'
  ```
- **The size has limits, but the whole document is not bounded:** the field caps and the cap of 1000
  tool findings for each server bound the rows and the text of the tool findings. A server with more
  tool findings gets one `MOAT-T1-024` finding, with `"field": "tool"` and an empty `key` like
  `MOAT-T1-023`. The config findings, the pin findings and the LLM findings are not part of that
  cap. The number of config findings is limited only by the size of the config file, so a hostile
  config can give a very large document. See [Limits](limits.md) for the bounds of each kind of
  finding, and [Size bound](ARCHITECTURE.md#size-bound) for the tests.
- A tool rule finding has `"field": "tool"`, the tool name in `key`, and `description` or `schema`
  in `related`. An LLM finding (`MOAT-LLM-001`, `MOAT-LLM-002`) also has `"field": "tool"` and
  the tool name in `key`. In a tool rule finding and in an LLM finding, a tool name longer than
  512 characters (runes) is cut to 512 in `key` and ends with `...`. A pin finding
  (`MOAT-T2-001` to `MOAT-T2-003`) is not cut yet: its `key` holds the full tool name. The
  `MOAT-T1-023` finding has `"field": "tool"`, an empty `key`, and the reason
  (`rule analysis time budget used up; N of M tools not fully checked`) in `related`.
- The document never holds env or header values. A finding names the key it is about, for example
  `GITHUB_TOKEN`, never its value. See [JSON output](ARCHITECTURE.md#json-output) for the full
  redaction and escaping rules.
- Decoded values are raw server text. A tool such as `jq -r` can print terminal control sequences,
  so do not print decoded values (names, diffs) to a terminal without escaping them. Use `jq`
  without `-r` to keep the escapes.
- Each finding has a `source`: `rule` for a rule finding, `llm` for an advisory finding of
  `--llm`.
- The format has a `schema_version` (now `4`; version 2 added `source`, version 3 added `ignored`,
  `accept` and `fields_truncated`, version 4 added `server_index` to each finding and each diff).
  The schema is [schema/scan-output.v4.json](schema/scan-output.v4.json). Files of version 1, 2 and
  3 stay as they are. See [JSON output](ARCHITECTURE.md#json-output) for the shape and the version policy.

## See also

- [Exit codes](exit-codes.md)
- [Pins and rug pulls](pins.md)
- [JSON output: shape and version policy](ARCHITECTURE.md#json-output)
