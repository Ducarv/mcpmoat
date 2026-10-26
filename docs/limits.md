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
- The rule analysis of each server has a time budget. A server that uses it up gets a
  `MOAT-T1-023` finding (see [Exit codes](exit-codes.md)), and its tools that were not fully
  checked can hide a malicious text.
- The budget cannot stop the build of the match forms of one text. For a very hostile text (for
  example 128 KiB of one run of invisible characters), this build can take about a second, so the
  analysis of a server can end that much after its budget (#146).
- `--llm` does not make a scan complete or reliable. A model can miss a malicious tool, and a
  hostile description can try to influence the model. Its findings are advisory, and with `--llm`
  your tool names and descriptions leave your machine.
- Not done yet: a lock for `pins.json` (#150).

## See also

- [How mcpmoat starts stdio servers](stdio-servers.md)
- [Optional LLM classification](llm.md)
- [Pins and rug pulls](pins.md)
- [Exit codes](exit-codes.md)
- [Threat model and non-goals](PRD.md#2-goals-and-non-goals)
