# What mcpmoat does not do

This page lists what mcpmoat does not do, so you know how far to trust a clean scan.

- **It does not guarantee safety.** Rule-based scanning reduces risk. It has false positives (it can
  flag a safe tool) and false negatives (it can miss a malicious one).
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
- **The YAML tool rules do not run yet, so exit code 0 does not mean that the tools are safe.**
- `--llm` does not make a scan complete or reliable. A model can miss a malicious tool, and a
  hostile description can try to influence the model. Its findings are advisory, and with `--llm`
  your tool names and descriptions leave your machine.
- Not done yet: a lock for `pins.json` (#150).
- The owner and mode check of the pins directory and `pins.json` has limits: it skips parent
  directories, ACLs, Windows and some symlink targets. A directory that root owns is refused for you,
  and the reverse. `scan` then exits with code 2. See [Known
  limits](ARCHITECTURE.md#the-pinsjson-store).
- `scan --rules <dir>` loads and checks extra rule files, but `scan` does not apply them yet. It
  prints `mcpmoat scan: rules from --rules are loaded and checked, but not applied yet` on stderr.

## See also

- [How mcpmoat starts stdio servers](stdio-servers.md)
- [Optional LLM classification](llm.md)
- [Pins and rug pulls](pins.md)
- [Threat model and non-goals](PRD.md#2-goals-and-non-goals)
