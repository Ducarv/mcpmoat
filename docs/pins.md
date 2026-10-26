# Pins and rug pulls

`mcpmoat scan` connects to each server and lists its tools. A stdio server is started. See
[How mcpmoat starts stdio servers](stdio-servers.md).

- **First run:** mcpmoat pins the tools of each server in `pins.json`. After it saves the file, it
  prints `mcpmoat scan: pinned N tools for <server>` on stderr. The file is
  `$XDG_CONFIG_HOME/mcpmoat/pins.json`, or `~/.config/mcpmoat/pins.json` when `XDG_CONFIG_HOME` is
  not set. The file has mode `0600`. It stores each tool's hash and text. It never stores env,
  header, args or URL values from your configs.
- **Owner and mode:** mcpmoat refuses a pins directory or a `pins.json` that another user owns or
  that group or others can write to. `scan` and `pin --accept` then exit with code 2. The error
  names the path and the mode, and gives a hint. For a mode problem, run `chmod go-w -- '<path>'`.
  For an owner problem, the hint is `ask the owner or root to run chown, or remove the path`. When
  both problems exist, only the owner or root can run `chmod`, so the hint starts with `chown`. A
  directory made with umask 002 (mode `0775`) or a file with mode `0664` is refused until you run
  `chmod go-w`. A directory of `0755` and a file of `0644` pass. For the limits, see [The
  `pins.json` store](ARCHITECTURE.md#the-pinsjson-store).
- **Later runs:** `scan` compares the tools with the pins. It reports `MOAT-T2-001` (changed tool,
  high), `MOAT-T2-002` (new tool, medium), `MOAT-T2-003` (removed tool, low) and `MOAT-T2-004` (tool
  not verified). A new tool is medium. Read the report, not only the exit code (see [Exit
  codes](exit-codes.md)). A new tool, or a not verified tool with
  a new name, is high when the same server also lost a tool in that scan, because a server can
  rename a tool to avoid the changed-tool check. A server whose tools cannot be pinned (a duplicate
  or empty tool name, invalid tool data, or more than 2 MiB) is a high `MOAT-T2-004`, because
  mcpmoat can never check its tools for changes. `MOAT-T2-004` is high when the tool name is pinned,
  because a duplicate, invalid or unverifiable copy of a pinned tool can hide a rug pull. Else it is
  medium. For each changed tool, `scan` prints a unified diff of the pinned and the current text
  after the findings. For each new tool, it prints the full text of the tool as added lines,
  under the header `New tool <tool> on server <server>:`, so you can review it before you accept it.
  A pinned tool whose pin cannot be checked (another hash version, or a pinned text that does not
  match its hash) gets its full current text too, under `Not verified tool <tool> on server <server>
  (current text):`. An ignored finding gets no diff. If a diff is longer than 64 KiB or 2000 lines,
  `scan` cuts it and prints a warning on stderr with the tool and the server name. Review the full
  tool before you accept it. You can ignore these IDs with `--ignore` only (see [Ignore
  findings](ignore.md)).
- **Accept:** `scan` never changes the pins of a pinned server. Read the diff. If you trust the
  change, run `mcpmoat pin --accept <server> --expect <digest>`. The name must match one server
  exactly. If two clients use it, narrow it with `--config <file>`. If one file uses it in several
  places (`~/.claude.json` has a global section and project sections), `pin` takes the server
  outside any project, if there is exactly one. Add `--project <path>` to take the server of one
  project. If a config file has
  any problem, `pin --accept` prints it and exits with code 2, because a broken file can hide a
  second server with the same name. `pin --accept` connects to that one server and stores new pins
  for it only. It prints the diff of each changed, new and not verified tool, then
  `accepted <server>: N new, N changed, N removed`. If the server is not pinned yet, every tool is
  new, so `pin --accept` shows every tool. It prints the same warning when it cuts a diff.
- **Recommended flow:** run `mcpmoat scan` and review the diff. After the diffs, `scan` prints one
  line for each pinned server that has a pin finding:
  `To accept <server>: mcpmoat pin --accept <server> --expect pd1:<64 hex>`. After
  `scan --config <file>`, the command holds `--config <file>` too. Copy that line and run it. The
  digest (version `pd1`, the full SHA-256) covers the tools that `scan` showed you. `pin --accept --expect`
  saves the pins only if the tools that the server returns now give the same digest. Else it prints
  the diff and `the tools of <server> differ from what scan showed ...; nothing was saved`, saves
  nothing and exits with code 2. Run `scan` again and review the new diff. A hostile server can
  show harmless tools to `scan` and harmful tools to `pin --accept`. The digest stops that attack.
  An invalid or empty `--expect` exits with code 2 before any server starts.
- Without `--expect`, `pin --accept` works as before, but it trusts the tools that the server
  returns now. It prints a note on stderr, before it saves, to say so. Use `--expect` unless you have a reason not to.
- `scan` prints no `To accept` line for a server that is pinned for the first time, for a server
  that it could not inspect, for a finding that you ignored, or for tools that cannot be pinned. The
  command holds `--project <path>` when `pin` needs it to select the server. The line holds a
  command only when the server name (and the `--project` and `--config` paths) uses only the
  characters `A-Z a-z 0-9 . _ @ / : + = -` and starts with a letter, `_` or `/`. Every shell, also
  `cmd.exe` and PowerShell, reads such a word as plain text. Else the line says what to run and
  gives the digest, but no command. The line has no command either when you did not see every
  change (a cut diff, a change that `--ignore` hid, or a diff that is only a note), when the name
  cannot select the server, or when a config file has a problem. Then you must review the tool
  first, or `pin` needs `--config`. The line ends with a note for each change that you did not see:
  `(the diff was cut: review the full tool first)`, `(--ignore hid some changes: run scan without
  it to review them first)` or `(a change has no diff text: review the tool first)`. The digest
  covers those changes too.
- A server that fails, times out or is refused (an untrusted or turned-off server) shows its status
  in the summary on stdout. If the server is not pinned, it does not change the exit code. If the
  server is already pinned and fails or times out, it is also a high `MOAT-T2-004` finding (see
  [Exit codes](exit-codes.md)) with the reason `pinned server could not be inspected`, because a hostile server must not
  avoid the rug-pull check by failing on purpose. A pinned server that is refused shows its status
  `not inspected` and its reason in the summary, with no pin finding: your client config turns it
  off or does not approve it, and the server cannot choose that.
- `scan` shows the warnings of the inspection in the summary on stdout (on stderr with `--json`).
  `pin --accept` prints them on stderr. They are: secrets that go over plain http (`cleartext-secrets`), lists that the server
  answered but did not declare (`undeclared-capability`), and a proxy that skips the DNS pin (`dns-pin-unavailable`). The lines
  hold keys and fixed names only, never values. A server that is listed twice is a `MOAT-T2-004` finding too: high
  when it is pinned, else medium.
- `scan` and `pin --accept` read `pins.json` before they start any server. A `pins.json` that
  cannot be read exits with code 2 before a server starts. They read it again just before they
  save. `scan` pins only the first-run servers that the file does not hold yet, and prints
  `pinned` only for those. `pin --accept` changes only the entry of its server and keeps entries
  that another run wrote meanwhile. A parallel run can still lose an update until the lock (#150)
  exists.
- Press Ctrl-C (or send `SIGTERM` or `SIGHUP`) to stop a run. mcpmoat stops the stdio servers that
  it started. A signal during the inspection, or after it but before new pins are saved (for
  `scan`, only when there are new pins), makes `scan` and `pin --accept` print `interrupted; no
  pins were saved`, save nothing and exit with code 2. [Exit codes](exit-codes.md) tells what `scan` does at other times.
- [Exit codes](exit-codes.md) tells which of these findings give exit code 1 at each `--fail-on`
  value.

## See also

- [How mcpmoat starts stdio servers](stdio-servers.md)
- [Ignore findings](ignore.md)
- [Exit codes](exit-codes.md)
- [The `pins.json` store](ARCHITECTURE.md#the-pinsjson-store)
