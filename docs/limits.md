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
- The budget cannot stop the build of the match forms of one text. For the most hostile texts that
  we measured, this build takes under about 0.2 s (Apple M1 Pro). The current worst case is a CSI
  fill (ESC [ A that builds all seven forms, or 256 U+009D and then C1 CSIs), at about 0.17 s.
  128 KiB of U+009D takes about 54 ms, and 128 KiB of U+009D "a" pairs about 90 ms (0.55 s to
  0.8 s before #146). So the analysis of a server can end that much after its budget.
- A text with more than 256 U+009D (C1 OSC controls) always gets `MOAT-T1-017` or `MOAT-T1-018`
  (high), also a benign text in the wrong encoding. The reason and the example are in
  [Contributing a rule](writing-rules.md#2-write-the-rule). With a custom rule at critical
  severity and `--fail-on critical`, a text with more than 256 U+009D can hide the payload from
  that rule and only `MOAT-T1-017` (high) fires.
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
