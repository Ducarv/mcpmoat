# Ignore findings

`mcpmoat scan` applies the built-in config rules (dangerous config, T4, and typosquatting, T5) to
every server it finds. The ignore list below drops findings of these rules. The pin findings
(`MOAT-T2-001` to `MOAT-T2-004`) and, with `--llm`, the LLM findings (`MOAT-LLM-001` and
`MOAT-LLM-002`) are different: only `--ignore` drops them (see below). The YAML tool rules
(descriptions and schemas) are not applied to tools yet, so they do not run.
[Exit codes](exit-codes.md#exit-codes) tells how the findings set the exit code.

`--ignore <rule-id>` ignores all findings of one rule. You can use the flag more than one time.

A `.mcpmoat-ignore` file in the working directory also ignores findings of the config rules. It
cannot ignore the pin rules `MOAT-T2-001` to `MOAT-T2-004` or the LLM rules `MOAT-LLM-001` and
`MOAT-LLM-002`, because the file can come from a cloned repository. It must not silence the
rug-pull alarm, or the LLM classifier for every server of a user who runs `scan --llm` there. Use
`--ignore` on the command line for these rules. When a file entry for one of these rules matches a
finding, `scan` keeps the finding and prints a warning on stderr:
`mcpmoat scan: warning: .mcpmoat-ignore cannot ignore MOAT-LLM-001; use --ignore on the command line`.
Write one entry on each
line: `RULE-ID [server[/tool]]`. A line that starts with `#` is a comment. After the rule ID, a
`#` as a separate word starts a comment to the end of the line. A server name cannot start with `#`.

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

**Security note:** mcpmoat reads `.mcpmoat-ignore` from the directory you run it in, also in a
repository that you cloned. A repository can use this file to hide config findings for any server,
also for your global servers: an entry without a server, such as `MOAT-T1-003`, applies to every
server. It cannot hide the pin findings or the LLM findings (see above). When the file gives
entries, mcpmoat prints `using N entries from .mcpmoat-ignore` (or
`using 1 entry from .mcpmoat-ignore`) on stderr. If you see this line, read the file before you
trust a clean result.

When the ignore list drops findings, `scan` also prints one line on stderr after the report. It
gives the count for each rule ID, for example
`mcpmoat scan: 2 findings ignored: MOAT-T4-002 (2)`. It shows only rule IDs and counts. A
`.mcpmoat-ignore` in a repository that you did not write can hide findings, so check this line and
the file. Ignored findings do not count for the exit code, so the file can turn exit code 1 into 0.

## See also

- [Pins and rug pulls](pins.md)
- [Exit codes](exit-codes.md)
