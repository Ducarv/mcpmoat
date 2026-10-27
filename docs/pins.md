# Pins and rug pulls

`mcpmoat scan` connects to each server and lists its tools. A stdio server is started. See
[How mcpmoat starts stdio servers](stdio-servers.md).

- **First run:** mcpmoat pins the tools of each server in `pins.json`. After it saves the file, it
  prints `mcpmoat scan: pinned N tools for <server>` on stderr. The file is
  `$XDG_CONFIG_HOME/mcpmoat/pins.json`, or `~/.config/mcpmoat/pins.json` when `XDG_CONFIG_HOME` is
  not set. The file has mode `0600`. It stores each tool's hash and text. It never stores env,
  header, args or URL values from your configs. But a server can echo such a value in its tool
  text, and `pins.json` keeps that text as the server sent it.
- **New pins file:** when `scan` or `pin --accept` creates a new `pins.json`, it prints one line on
  stderr after the save: `mcpmoat <cmd>: no pins file was found, so a new one was created at
  <path>; if this is not your first run, the old file was removed or moved`. On your first run
  this is expected. On a later run it means that the old file is gone, so every server was pinned
  again with no alert. Find out who removed the file before you trust the new pins. If the pins
  file existed at the first read of the command, before any server starts (or, for `pin --accept`,
  at the read before it shows the diff), but a later read does not find it, the run saves nothing,
  prints `mcpmoat <cmd>: the pins file was removed while this command ran, so no pins were saved;
  run the command again` and exits with code 2. When
  `pin --accept` finds this before it shows the diff, it shows no diff. A real first run does not
  get this line. This check looks only at whether the file exists. If another run deletes the file
  and a second run creates a new one while this run is still working, this run does not notice,
  but the second run prints the new pins file line.
- **Owner and mode:** mcpmoat refuses a pins directory or a `pins.json` that another user owns or
  that group or others can write to. `scan` and `pin --accept` then exit with code 2. The error
  names the path and the mode, and gives a hint. For a mode problem, run `chmod go-w -- '<path>'`.
  For an owner problem, the hint is `ask the owner or root to run chown, or to remove the path`.
  When both problems exist, only the owner or root can run `chmod`, so the hint first asks the
  owner or root to run `chown`, and then gives the `chmod go-w` command. A
  directory made with umask 002 (mode `0775`) or a file with mode `0664` is refused until you run
  `chmod go-w`. A directory of `0755` and a file of `0644` pass. For the limits, see [The
  `pins.json` store](ARCHITECTURE.md#the-pinsjson-store).
- **Parent directories:** mcpmoat also checks each directory above the pins directory, up to `/`
  (for example `~/.config` and your home directory). It refuses a parent that a user other than you
  or root owns, or that group or others can write, unless the sticky bit is set (as on `/tmp`).
  A user who can write a parent could remove or replace the whole `mcpmoat` directory, and the next
  run would pin the current tools with no alert. The hint is `chmod go-w -- '<path>'`, or a private
  `XDG_CONFIG_HOME`. A common case: a `~/.config` made with umask 002 has mode `0775`, and mcpmoat
  refuses it until you run `chmod go-w ~/.config`. Another case is a container job where `HOME` is
  a mount that a different user owns (for example a root job with a `HOME` that belongs to uid
  1001). Then every `scan` that connects exits with code 2 before it inspects anything. Set a
  private `XDG_CONFIG_HOME` that you own for that job.
- **ACL (macOS):** on macOS, an ACL can let another user write a path that has a safe mode. mcpmoat
  refuses a pins directory or a `pins.json` whose ACL has an allow entry that gives a write right,
  for any user or group, also for your own account. The hint is `chmod -N -- '<path>'`. It removes
  the whole ACL of that path, also its deny entries. On Linux, ACL entries show in the group bits of
  the mode, so the mode check catches them. mcpmoat does not read the ACL of a parent directory.
  An allow entry for another user on `~/.config` or `~` (for example `delete_child`) is not
  detected, so check those ACLs yourself with `ls -led`.
- **Symlinks:** mcpmoat refuses a `pins.json` that is a symlink, also when it points to a file in
  the same directory. The hint is to replace the symlink with the file. A pins directory that is a
  symlink, for example `~/.config` on another disk, is fine when you or root own the symlink:
  mcpmoat checks its target. A symlink that another user owns is refused, on the pins directory
  and on every parent. This includes a symlink that is only reached through the target of another
  symlink: mcpmoat follows each link, one part of the path at a time, and checks every symlink and
  every directory on the way. In a sticky directory such as `/tmp`, any user can create a symlink,
  and that user can point it to another directory later, so the next run would see a first run. The
  hint is to ask the owner or root to remove or replace the symlink, or to use a private
  `XDG_CONFIG_HOME`. The error names the real path (on macOS `/private/var/...` for `/var/...`) and
  shows the unsafe entry that is nearest to the pins directory.
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
- **Secret values in diffs:** a diff shows each configured value of the server (the env, header and
  expanded values, the secrets in the args and the URL, and the credential pieces inside them, of 8
  bytes or more) as `********`, on the pinned side and on the current side. So does the tool name
  of the diff and of the finding. mcpmoat masks the decoded text before it wraps and cuts the
  diff, so a wrap or a cut never leaves a part of a value. When a tool changed only in text that
  holds such a value, the diff is the fixed note `the tool changed only in text that holds a
  secret value from the config, so the diff is hidden`. Like any diff that is only a note, it
  gives a `To accept` line with no command. The hashes, `pins.json` and the digest of `--expect`
  use the raw text, so an echoed secret still changes the hash and gives a `MOAT-T2-001` finding.
  The mask uses the values that are configured now. See [What mcpmoat does not do](limits.md) for
  its limits, such as a rotated token.
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
  new, so `pin --accept` shows every tool. It prints the same warning when it cuts a diff. If the
  new pins do not fit, see **Full pins file** below.
  `pin --accept` records the new text as the baseline. It does not clear tool poisoning findings:
  the T1 and T3 rules still apply to the accepted text, so the next `scan` can still exit with
  code 1.
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
- `scan --json` gives the same digest in the field `accept` of a pinned server that has a pin
  finding with a `To accept` hint: `{ "digest": "pd1:<64 hex>", "command": "mcpmoat pin --accept ...
  --expect <digest>" }`. `command` is there only when the terminal hint prints a command. When the
  terminal prints steps (a cut diff, a change that `--ignore` hid, a diff that is only a note, a
  server name that more than one server uses, a config file problem, or a name or path that is not a
  plain shell word), the JSON has the digest and no command. The JSON never holds the steps. Do not
  let a CI job accept a change from this field: a person must review the diff first.
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
  that another run wrote meanwhile.
- **Lock:** for that last read and the save, `scan` and `pin --accept` lock the pins directory, so
  two runs at the same time keep each other's changes. `pin --accept` shows the diff before it
  takes the lock, and reads the file again under the lock. If another run changed the pins of the
  server in that time, it prints a warning that the diff is against the older pins. A run waits up
  to 10 seconds for another process that holds the lock. Then it prints the read error and
  `mcpmoat <cmd>: another process is using the pins file; run the command again in a moment`, and
  exits with code 2. The holder is normally another mcpmoat run, but any local process that can
  open the pins directory can hold the advisory lock. With a pins directory of mode `0755`, that
  includes another user, who can then block pinning. Use mode `0700` to stop that. The run releases
  the lock right after the save, before it prints. A run that takes the lock creates a missing pins
  directory (mode `0700`), so an empty directory can stay when the run saves nothing. Some file
  systems, for example some network mounts, cannot lock. Then the run goes on without the lock and
  prints one warning: `mcpmoat <cmd>: warning: the file system of the pins directory <dir> does
  not support file locks, so a parallel run can overwrite these pins`. Windows has no lock, and the
  run prints the same warning. mcpmoat v0.1.0 does not lock, so do not run it at the same time as a
  newer version.
- **Full pins file:** the whole `pins.json` has a limit of 32 MiB. A first-run server that would
  make the file larger is not pinned, and the other servers still are. It gets a high
  `MOAT-T2-004` with the reason `the pins file is full (32 MiB), so this server is not pinned` and
  the fix `Remove servers you no longer use from pins.json, or remove this server from the client
  config, then run mcpmoat scan again.` A later change to the tools of that server is not
  detected. If another run made the file larger after the report, `scan` prints
  `mcpmoat scan: warning: server <server> not pinned: the pins file is full (32 MiB)` instead and
  exits with code 2. If the new pins of `pin --accept` do not fit, it prints `mcpmoat pin: cannot
  pin <server>: the pins file is full (32 MiB); remove servers you no longer use from
  pins.json`, saves nothing and exits with code 2. `scan` checks the limit only for servers that
  it pins for the first time. A pinned server whose tools grew still gets a `To accept` line, and
  `pin --accept` can then refuse it. The limit is first come, first served, and mcpmoat never
  removes old entries, so the servers of a hostile project config can fill the file. A refused
  server is always reported. To make room, remove servers from `pins.json` by hand.
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
