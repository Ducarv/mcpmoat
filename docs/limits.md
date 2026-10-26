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
- The owner and mode check of the pins directory and `pins.json` does not cover parent directories
  such as `~/.config`. It reads the owner and the mode bits only, not ACLs, and it is skipped on
  Windows.
- The owner check compares the owner with the current user. A directory that root owns is refused
  for a user who is not root. The reverse is refused too: `sudo mcpmoat scan` with the HOME or
  `XDG_CONFIG_HOME` of the user, and a root container with a bind-mounted config that a host uid
  owns, fail with exit code 2.
- A relative `pins.json` symlink that stays inside the pins directory is followed. The check covers
  the pins directory and the target file, but not a subdirectory that holds the target. If others
  can write that subdirectory, an attacker can swap the target. This needs an unusual setup. It is
  an accepted limit.
- A parent of the pins directory that is a regular file skips the check. `Load` reports it with the
  same error as before.
- `scan --rules <dir>` loads and checks extra rule files, but `scan` does not apply them yet. It
  prints `mcpmoat scan: rules from --rules are loaded and checked, but not applied yet` on stderr.

## See also

- [How mcpmoat starts stdio servers](stdio-servers.md)
- [Optional LLM classification](llm.md)
- [Pins and rug pulls](pins.md)
- [Threat model and non-goals](PRD.md#2-goals-and-non-goals)
