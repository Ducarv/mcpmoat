# Ignore findings

`mcpmoat scan` applies the built-in config rules (dangerous config, T4, and typosquatting, T5) to
every server it finds. When it connects to the servers, it also applies the description and schema
rules (tool poisoning, T1, and shadowing, T3) to their tools. You can drop findings of these rules in
two ways: `--ignore` on the command line, or a `.mcpmoat-ignore` file that `scan` reads only with
`--use-ignore-file`. Some findings are different: only `--ignore` drops them (see
[What the file cannot ignore](#what-the-file-cannot-ignore)). [Exit codes](exit-codes.md) tells how
the findings set the exit code.

## --ignore

`--ignore <rule-id>` ignores all findings of one rule, on every server. You can use the flag more
than one time. It works with or without `--use-ignore-file`.

## The .mcpmoat-ignore file

`scan` reads `.mcpmoat-ignore` from the working directory only when you add `--use-ignore-file`.
The flag is off by default. Without it, `scan` never opens the file. When the file is there, `scan`
prints this note on stderr and goes on:

```text
mcpmoat scan: note: .mcpmoat-ignore is not read; add --use-ignore-file to apply it
```

The default protects you. The working directory can be a repository that you cloned or the checkout
of a pull request, and you did not write its `.mcpmoat-ignore`. Older versions of mcpmoat always
read the file. A hostile file could then turn exit code 1 into 0, for example for a plaintext token
in `.mcp.json`. It could also hide a poisoned tool, and it could hide config findings in CI. So use
`--use-ignore-file` only with a file that you trust. In CI, guard the file, for example with
`CODEOWNERS` (see [Using mcpmoat in CI](ci.md#security-notes)).

With `--use-ignore-file`, the file ignores findings of the config rules and of the description and
schema rules. Write one entry on each line: `RULE-ID [server[/tool]]`. A line that starts with `#`
is a comment. After the rule ID, a `#` as a separate word starts a comment to the end of the line. A
server name cannot start with `#`.

```text
# All findings of this rule, on all servers
MOAT-T1-003
# All findings of this rule on the server "github"
MOAT-T1-003 github
# Only the tool "create_issue" of the server "github"
MOAT-T3-001 github/create_issue
# A comment after the entry
MOAT-T1-003 github # reviewed, the server is ours
# A server name that contains '/': end it with '/'
MOAT-T1-003 my/server/
```

Server and tool names must match exactly, and they are case-sensitive. mcpmoat splits each line on
spaces and tabs, so you cannot write a name that contains a space or a tab. A line, comments
included, must not hold control characters (other than tab), invisible characters or other white
space, because they can hide text in a terminal. mcpmoat skips a malformed line and prints a
warning with its line number.

A `server/tool` entry is the only way to ignore a rule for one tool: `--ignore` cannot do it. Five
built-in rules (`MOAT-T1-004`, `MOAT-T1-007`, `MOAT-T1-010`, `MOAT-T1-011` and `MOAT-T1-012`) tell
you in their remediation to add such an entry and to run `scan` with `--use-ignore-file`.

## What the file cannot ignore

Also with `--use-ignore-file`, the file cannot ignore these findings:

- the pin rules `MOAT-T2-001` to `MOAT-T2-004`, so that a project cannot silence the rug-pull alarm
  for your own servers (see [Pins and rug pulls](pins.md));
- the LLM rules `MOAT-LLM-001` and `MOAT-LLM-002`, so that it cannot silence the LLM classifier for
  every server of a user who runs `scan --llm` there;
- `MOAT-T1-023`, the finding that the rule analysis of a server stopped early, so that the tools
  after the stop do not look clean;
- `MOAT-T1-024`, the finding that `scan` left tool findings out of the list of a server;
- `MOAT-T4-005`, the finding that `scan` left config findings out of the list (see
  [Limits](limits.md)).

Use `--ignore` on the command line for these rules. `MOAT-T1-023`, `MOAT-T1-024` and `MOAT-T4-005`
are not about one tool, so `--ignore` drops them for every server. When a file entry for one of
these rules matches a finding, `scan` keeps the finding and prints a warning on stderr:
`mcpmoat scan: warning: .mcpmoat-ignore cannot ignore MOAT-LLM-001; use --ignore on the command line`.

So a hostile file cannot hide a poisoned tool without a sign. Without `--use-ignore-file`, it drops
nothing. With the flag, it can drop description and schema findings, but `scan` shows that it did
(see below), and it cannot drop the findings above.

## See what was ignored

When the file gives entries, `scan` prints `mcpmoat scan: using N entries from .mcpmoat-ignore` (or
`using 1 entry from .mcpmoat-ignore`) on stderr. An entry without a server, such as `MOAT-T1-003`,
applies to every server, also to your global servers. If you see this line, read the file before you
trust a clean result.

When the ignore list drops findings, `scan` also prints one line on stderr after the report. It
gives the count for each rule ID, for example
`mcpmoat scan: 2 findings ignored: MOAT-T4-002 (2)`. It shows only rule IDs and counts. Ignored
findings do not count for the exit code, so an ignore entry can turn exit code 1 into 0. Check this
line, and check the file when you use `--use-ignore-file`.

`scan --json` shows the same counts in the top-level field `ignored`:
`{ "total": N, "rules": { "<rule ID>": count }, "file_entries": M }`. `rules` gives the number of
dropped findings for each rule ID. `total` is the sum, and it is the same number as `N findings
ignored` in the stderr line. `file_entries` is the number of entries that `scan` read from
`.mcpmoat-ignore`, the same number as in `using N entries from .mcpmoat-ignore`. It is 0 without
`--use-ignore-file`. The JSON holds rule IDs and counts only, never text from the ignore file. A CI
job that reads only stdout can see that findings were dropped.

## See also

- [Pins and rug pulls](pins.md)
- [Exit codes](exit-codes.md)
- [Using mcpmoat in CI](ci.md)
