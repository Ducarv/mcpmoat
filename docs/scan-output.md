# Scan output

## What `scan` prints

`scan` prints the server table, then a summary with one line for each server, then the findings
grouped by severity (the worst first). This is a short sample (the table is left out, and the long
risk and fix texts are shortened):

```text
SUMMARY
  github (claude-code, global): ok, 12 tools, 0 findings
  files (cursor, project:/work/app (untrusted)): ok, 4 tools, 2 findings
    warning: cleartext-secrets: secrets go over plain http to a host that is not loopback: header X-Api-Key
  search (codex, global): timeout, 0 findings (...)

FINDINGS
HIGH (1)
  MOAT-T4-002  Plaintext secret in config
    Server: files (cursor, project:/work/app (untrusted))
    Where: env GITHUB_TOKEN
    Risk: A secret is written in clear text in the client config ...
    Fix: Move the secret out of the config: use an environment variable reference ...
MEDIUM (1)
  MOAT-T4-003  Package runner uses an unpinned package
    Server: files (cursor, project:/work/app (untrusted))
    Where: args @example-corp/files-mcp
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
- **Colour:** colour is on only when stdout is a terminal. `--no-color` (before or after the command, as in
  `mcpmoat scan --no-color`) or a non-empty `NO_COLOR` environment variable turns it off. Colour
  marks the headings, the severity lines and the status words only. The words carry the meaning, so
  the output is the same without colour. `scan` escapes every config, server and rule text first,
  so terminal escape sequences in a config or from a server do not reach your terminal.
- **Exit code:** warnings and statuses do not change it. Only findings do (see
  [Exit codes](exit-codes.md#exit-codes)).

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
- **Exit codes** do not change: 0, 1 or 2 (see [Pins and rug pulls](pins.md#pins-and-rug-pulls)).
- **`complete`** is `false` when the report can miss results, for example when a config file has a
  problem, `pins.json` cannot be read, or the LLM step of a `--llm` scan did not classify every
  tool: a provider failure, an internal error of the LLM step, or more than 500 tools. The exit
  code is then 2, and the reason is on stderr.
  `complete` can be `true` with exit code 2 when the save of new pins fails after the report, so
  always check the exit code too.
- The document never holds env or header values. A finding names the key it is about, for example
  `GITHUB_TOKEN`, never its value. See [JSON output](ARCHITECTURE.md#json-output) for the full
  redaction and escaping rules.
- Decoded values are raw server text. A tool such as `jq -r` can print terminal control sequences,
  so do not print decoded values (names, diffs) to a terminal without escaping them. Use `jq`
  without `-r` to keep the escapes.
- Each finding has a `source`: `rule` for a rule finding, `llm` for an advisory finding of
  `--llm`.
- The format has a `schema_version` (now `2`; version 2 added `source`). The schema is
  [docs/schema/scan-output.v2.json](schema/scan-output.v2.json). See
  [JSON output](ARCHITECTURE.md#json-output) for the shape and the version policy.

## See also

- [Exit codes](exit-codes.md)
- [Pins and rug pulls](pins.md)
- [JSON output: shape and version policy](ARCHITECTURE.md#json-output)
