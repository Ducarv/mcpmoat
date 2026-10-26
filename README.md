# mcpmoat

An offline scanner for malicious or tampered MCP servers, built for the individual developer. It
stays offline unless you use `--llm`.

**Status: pre-alpha, Phase 1 in progress.** Nothing is released yet.

mcpmoat finds the MCP servers that Claude Code, Cursor and Codex load on your machine, reads the tools
they expose, and checks them for tool poisoning, rug pulls, shadowing, dangerous config and
typosquatting. It runs locally, needs no account and sends no telemetry. It connects only to the
servers you configured, and to an LLM provider only when you opt in with `scan --llm` (see
[Optional LLM classification](#optional-llm-classification-sends-data-off-your-machine)).

## Install

This works today:

```sh
go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@latest
```

It builds the latest commit on `main`. It needs Go 1.27 or later (see [go.mod](go.mod)). For a
repeatable install, as in CI, pin one commit instead of `@latest`: see
[docs/ci.md](docs/ci.md#github-actions).

These methods come with the first release:

- Homebrew (macOS and Linux): `brew install --cask Ducarv/tap/mcpmoat`. The tap gets stable
  releases only, not prereleases. The macOS binaries are not notarized yet: see
  [Verify a download](#verify-a-download).
- GitHub Releases: download the archive for your system from the
  [releases page](https://github.com/Ducarv/mcpmoat/releases). The archives are
  `mcpmoat_<version>_<os>_<arch>.tar.gz` for `darwin` or `linux` and `amd64` or `arm64`.
  `<version>` is the release number without the `v`, for example `0.1.0`. Each archive holds the
  `mcpmoat` binary, `LICENSE` and `README.md`. The Linux binary is static. The macOS binary links
  only macOS system libraries, like every Go binary on macOS. Extract the binary and put it on your
  `PATH`.

Run `mcpmoat version` to check the install. A release binary prints
`mcpmoat v<version> (commit <c>, built <d>)`. `<d>` is the commit date, not the build time, so the
same commit always gives the same binary. The `go install` build above prints `commit none, built
unknown`, because `go install` builds from the Go module cache, which has no git data.

### Verify a download

Each release has a `checksums.txt` file. Download it to the same folder as the archive, then check
the archive. This step only catches a broken download. It does not prove where the archive came
from.

```sh
shasum -a 256 --ignore-missing -c checksums.txt   # macOS
sha256sum --ignore-missing -c checksums.txt       # Linux
```

The real check is the build provenance attestation of the archive. Check it with the
[GitHub CLI](https://cli.github.com/). The first command gets the commit that the tag points at:

```sh
sha=$(gh api repos/Ducarv/mcpmoat/commits/refs/tags/v<version> -q .sha)
gh attestation verify mcpmoat_<version>_<os>_<arch>.tar.gz -R Ducarv/mcpmoat \
  --cert-identity https://github.com/Ducarv/mcpmoat/.github/workflows/release.yml@refs/tags/v<version> \
  --source-ref refs/tags/v<version> --source-digest "$sha" --deny-self-hosted-runners
```

The check proves which repo, workflow, tag and commit built the archive. It does not prove that the
code was reviewed. Use `--cert-identity` as above, not `--signer-workflow`: some `gh` versions match
`--signer-workflow` as a prefix only, so `release.yml` would also match another workflow file
whose name starts with `release.yml`.

Homebrew does not check the attestation. `brew install` checks only the sha256 values in the cask
from the tap. A cask is Ruby code that Homebrew runs on install, so matching sha256 values alone do
not prove that the cask is safe. To check the cask, first verify `checksums.txt`:

```sh
gh attestation verify checksums.txt -R Ducarv/mcpmoat \
  --cert-identity https://github.com/Ducarv/mcpmoat/.github/workflows/release.yml@refs/tags/v<version> \
  --source-ref refs/tags/v<version> --source-digest "$sha" --deny-self-hosted-runners
```

Then open `Casks/mcpmoat.rb` in the [tap](https://github.com/Ducarv/homebrew-tap) and check these
points:

- The `version` line is the release number without the `v`, for example `"0.1.0"`.
- Each `url` is exactly
  `https://github.com/Ducarv/mcpmoat/releases/download/v#{version}/mcpmoat_#{version}_<os>_<arch>.tar.gz`.
  `<os>` is `darwin` in the `on_macos` block and `linux` in the `on_linux` block. `<arch>` is
  `arm64` in the `on_arm` block and `amd64` in the `on_intel` block. Homebrew fills in `#{version}`
  from the `version` line.
- `#{version}` is the only `#{` in the file. In Ruby, any other `#{...}` in a string runs code when
  Homebrew loads the cask.
- Each `sha256` is a literal hex string of 64 characters. It is the hash on the `checksums.txt` line
  for the archive that the `url` in the same block names.
- The only block that runs a command is `postflight_steps`. It holds one `on_macos` block with one
  `xattr` line that removes the quarantine flag from `mcpmoat`.
- There is no other code. The cask holds only these parts:
  - `version`
  - `on_macos` and `on_linux`, each with an `on_arm` and an `on_intel` block that holds `url` and
    `sha256`
  - `name`, `desc` and `homepage`
  - `livecheck`, with one `skip` line
  - `binary`
  - `postflight_steps`

The macOS binaries are not notarized yet. The Homebrew cask removes the quarantine flag on install,
so Gatekeeper does not check the binary. Verify the archive if that matters to you.

## Usage

```sh
mcpmoat scan                  # discover, connect, pin or compare the tools, and report
mcpmoat scan --no-connect     # static config analysis only; runs no server, reads no pins
mcpmoat scan --fail-on medium # exit 1 also for a medium finding (default high)
mcpmoat scan --json           # the same report as one JSON document on stdout
mcpmoat scan --llm            # also ask an LLM to rate each tool; sends data off your machine
mcpmoat pin --accept <name> --expect <digest>  # accept the tools of a server, only if they match the digest from scan
mcpmoat version               # print the version, the commit and its date
```

### What `scan` prints

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
  [Exit codes](#exit-codes)).

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
- **Exit codes** do not change: 0, 1 or 2 (see [Pins and rug pulls](#pins-and-rug-pulls)).
- **`complete`** is `false` when the report can miss results, for example when a config file has a
  problem, `pins.json` cannot be read, or the LLM step of a `--llm` scan is incomplete (a provider
  failure, or more than 500 tools). The exit code is then 2, and the reason is on stderr.
  `complete` can be `true` with exit code 2 when the save of new pins fails after the report, so
  always check the exit code too.
- The document never holds env or header values. A finding names the key it is about, for example
  `GITHUB_TOKEN`, never its value. See [JSON output](docs/ARCHITECTURE.md#json-output) for the full
  redaction and escaping rules.
- Decoded values are raw server text. A tool such as `jq -r` can print terminal control sequences,
  so do not print decoded values (names, diffs) to a terminal without escaping them. Use `jq`
  without `-r` to keep the escapes.
- Each finding has a `source`: `rule` for a rule finding, `llm` for an advisory finding of
  `--llm`.
- The format has a `schema_version` (now `2`; version 2 added `source`). The schema is
  [docs/schema/scan-output.v2.json](docs/schema/scan-output.v2.json). See
  [JSON output](docs/ARCHITECTURE.md#json-output) for the shape and the version policy.

## Pins and rug pulls

`mcpmoat scan` connects to each server and lists its tools. A stdio server is started. See
[How mcpmoat starts stdio servers](docs/stdio-servers.md).

- **First run:** mcpmoat pins the tools of each server in `pins.json`. After it saves the file, it
  prints `mcpmoat scan: pinned N tools for <server>` on stderr. The file is
  `$XDG_CONFIG_HOME/mcpmoat/pins.json`, or `~/.config/mcpmoat/pins.json` when `XDG_CONFIG_HOME` is
  not set. The file has mode `0600`. It stores each tool's hash and text. It never stores env,
  header, args or URL values from your configs.
- **Later runs:** `scan` compares the tools with the pins. It reports `MOAT-T2-001` (changed tool,
  high), `MOAT-T2-002` (new tool, medium), `MOAT-T2-003` (removed tool, low) and `MOAT-T2-004` (tool
  not verified). A new tool is medium. Read the report, not only the exit code (see [Exit
  codes](#exit-codes)). A new tool, or a not verified tool with
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
  findings](#ignore-findings)).
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
  [Exit codes](#exit-codes)) with the reason `pinned server could not be inspected`, because a hostile server must not
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
  pins were saved`, save nothing and exit with code 2. [Exit codes](#exit-codes) tells what `scan` does at other times.
- [Exit codes](#exit-codes) tells which of these findings give exit code 1 at each `--fail-on`
  value.

## Ignore findings

`mcpmoat scan` applies the built-in config rules (dangerous config, T4, and typosquatting, T5) to
every server it finds. The ignore list below drops findings of these rules, and of the LLM rules
`MOAT-LLM-001` and `MOAT-LLM-002` with `--llm`. The pin findings
(`MOAT-T2-001` to `MOAT-T2-004`) are different: only `--ignore` drops them (see below). The YAML tool rules (descriptions and schemas) are not applied to
tools yet, so they do not run.
[Exit codes](#exit-codes) tells how the findings set the exit code.

`--ignore <rule-id>` ignores all findings of one rule. You can use the flag more than one time.

A `.mcpmoat-ignore` file in the working directory also ignores findings of the config rules. It
cannot ignore the pin rules `MOAT-T2-001` to `MOAT-T2-004`, because the file can come from a cloned
repository and must not silence the rug-pull alarm. Use `--ignore` on the command line for them.
When the file has such an entry, `scan` prints a warning. Write one entry on each
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
repository that you cloned. A repository can use this file to hide findings for any server, also
for your global servers: an entry without a server, such as `MOAT-T1-003`, applies to every server.
When the file gives entries, mcpmoat prints `using N entries from .mcpmoat-ignore` (or
`using 1 entry from .mcpmoat-ignore`) on stderr. If you see this line, read the file before you
trust a clean result.

When the ignore list drops findings, `scan` also prints one line on stderr after the report. It
gives the count for each rule ID, for example
`mcpmoat scan: 2 findings ignored: MOAT-T4-002 (2)`. It shows only rule IDs and counts. A
`.mcpmoat-ignore` in a repository that you did not write can hide findings, so check this line and
the file. Ignored findings do not count for the exit code, so the file can turn exit code 1 into 0.

## Optional LLM classification (sends data off your machine)

**Warning: `scan --llm` sends the name and description of every inspected tool to an LLM provider.
This data leaves your machine.** The option is off by default. Without `--llm`, mcpmoat reads no
API key and sends nothing to an LLM provider.

```sh
mcpmoat scan --llm                                                # Anthropic API, default model
mcpmoat scan --llm --llm-provider openai --llm-model <model>      # OpenAI API
mcpmoat scan --llm --llm-provider openai --llm-model <model> \
  --llm-base-url http://127.0.0.1:8080/v1                         # a local OpenAI-compatible server
```

- **API key:** mcpmoat reads it only from the `MCPMOAT_LLM_API_KEY` environment variable. There is no
  flag for it, because command-line arguments show in `ps` and in your shell history. With `--llm`
  and no key, `scan` exits with code 2 and names the variable. A local server needs a key too: use
  any value that it accepts.
- **`--llm-provider anthropic|openai`:** the API. The default is `anthropic`. `openai` also works
  with a server that speaks the OpenAI Chat Completions API.
- **`--llm-model <name>`:** the model. It is required for `openai`. `mcpmoat scan -h` shows the
  default model for `anthropic`.
- **`--llm-base-url <url>`:** the base URL of the API. The default is the public API of the
  provider. It must use `https`, or `http` only for a loopback host such as `127.0.0.1` or
  `localhost`. With `http`, every address that the host name resolves to must be a loopback
  address. Otherwise `scan` refuses the URL and sends no request. A user name, a password, a query
  or a fragment in the URL is refused.
- Each `--llm-*` flag needs `--llm`. `--llm` does not work with `--no-connect`, because without a
  connection there are no tools to send. Both are usage errors (exit code 2).
- **Warning line:** before the first request, `scan` prints this line on stderr, also with `--json`:
  `mcpmoat scan: warning: --llm sends the name and description of every tool to the LLM provider
  <provider> at <host>. This data leaves your machine.`
- **What is sent:** one request for each tool of each server that `scan` inspected (status `ok`).
  The request holds the tool name (cut at 512 bytes) and the tool description (cut at 16 KiB, or
  less when the whole message would pass 24 KiB once it is JSON-escaped), with a flag that says
  that text was cut, and a fixed instruction text from mcpmoat. `--ignore` and
  `.mcpmoat-ignore` hide LLM findings from the report, but they do not stop a tool from being sent.
  To keep a server out of `--llm`, scan it with a separate config.
- **What mcpmoat never puts in a request:** your config files, env values, headers, args, URLs, the
  tool schemas and `pins.json`. The key goes only in the auth header of the provider.
- **The description goes as the server wrote it:** mcpmoat does not remove secret values from it.
  A server that got a token through its env or headers can put that token into a description, and
  `--llm` then sends it to the provider. Run `--llm` only if you accept that a tool description can
  leave your machine as the server wrote it.
- **Limits:** at most 500 tools in one scan and 4 requests at the same time. Each request has 30
  seconds. mcpmoat does not retry and does not follow redirects. The request and the response are
  each capped at 64 KiB. The cost of a scan grows with the number and the size of the tool
  descriptions. The LLM requests honour `HTTPS_PROXY` and `NO_PROXY`, like the connections to your
  servers, when the base URL is `https`. A base URL with `http` (a loopback host only) never uses a
  proxy.
- **Findings:** the model can answer only with a risk level and a category from a fixed list.
  mcpmoat shows no text from the model.
  - `MOAT-LLM-001`: the model rates the tool as risky. The severity is the risk level: `low`,
    `medium` or `high`, never `critical`. A risk level of `none` gives no finding.
  - `MOAT-LLM-002` (medium): the model refused, or its answer did not match the fixed format. A
    description written to confuse the model can cause this. Only an unusable model answer gives
    this finding. Any other error stops the LLM step (see **Exit codes** below).
  - A tool name or description that was cut before it was sent always gives at least one
    `MOAT-LLM-001` finding of severity `medium` with the category `other`, whatever the model
    answers, because the part that was not sent can hold the payload. The risk text says: "The
    tool description is too long to classify in full. The part after the cut was not rated and can
    hold hidden instructions for the AI agent." If the model rates a cut description `medium` or
    `high`, the finding keeps the severity and the category of the model.

  An LLM finding is marked `[LLM]` and has a `Source` line. In JSON its `source` is `llm`, and
  `related` holds the category. A short sample:

  ```text
  HIGH (1)
    MOAT-LLM-001  Language model rates this tool as risky [LLM]
      Server: files (cursor, global)
      Source: LLM classification (advisory)
      Tool: read_file (credential-access)
      Risk: An LLM classifier rated this tool description as likely to make the AI agent read ...
      Fix: Read the full tool description and check it by hand. ...
  ```

- **Advisory only:** a model can be wrong. No LLM finding does not mean that a tool is safe. A
  hostile tool description can try to talk the model into a low rating. LLM findings only add to
  the rule findings. They never remove or change a rule finding, and they never change the pins.
- **What `--llm` does not check:** mcpmoat sends no input schema, so `--llm` does not rate text
  that is hidden in a parameter description of a schema.
- **Your API key and the servers:** a config file that you trust can expand
  `${MCPMOAT_LLM_API_KEY}` into the env of a server, as the client would, and that server then gets
  the key.
- **Exit codes:** LLM findings count for `--fail-on` like any finding. A provider failure (a
  network, TLS or proxy error, a timeout, an HTTP error, a response that is too large) or more than
  500 tools gives exit code 2. The report still prints, `complete` is `false` in JSON, and stderr
  says how many tools were not classified, for example
  `mcpmoat scan: the LLM provider failed (HTTP 401); 12 tools were not classified`.
  An internal error of the LLM step also stops the step with exit code 2, and stderr then says
  `mcpmoat scan: the LLM step failed (internal error); 12 tools were not classified`. mcpmoat
  never prints the text of that error.
  A hostile server can cause this on purpose: it can list more than 500 tools, or write a
  description that makes the provider answer with an HTTP 4xx (a content filter or a context
  limit). The rule findings still print.
- **Ignore:** `--ignore` and `.mcpmoat-ignore` work for `MOAT-LLM-001` and `MOAT-LLM-002`. The
  ignored count on stderr includes them (see [Ignore findings](#ignore-findings)).
- **OpenAI temperature:** the OpenAI request does not set a temperature, so models with a fixed
  temperature work.

## Exit codes

This section is the exit-code contract of `mcpmoat scan`. Other docs give a short form and link
here.

| Code | Meaning |
|---|---|
| 0 | No execution error, and no finding that is not ignored has severity at or above `--fail-on`. |
| 1 | No execution error, and at least one finding that is not ignored has severity at or above `--fail-on`. |
| 2 | Execution or usage error. Exit code 2 wins over 1. |

- `--fail-on low|medium|high|critical` sets the lowest severity that gives exit code 1. The default
  is `high`. Only these exact lowercase words work. Another value, an empty value or a second
  `--fail-on` is a usage error (exit code 2). It is a `scan` flag only. `pin` never exits with
  code 1.
- Ignored findings (`.mcpmoat-ignore` or `--ignore`) never give exit code 1.
- With `--llm`, the LLM findings (`MOAT-LLM-001`, `MOAT-LLM-002`) count like any other finding.
  They are `high` at most.
- mcpmoat fails closed. A finding with a severity that mcpmoat does not know always counts, at
  every `--fail-on` value. A finding whose rule ID is not in the rule set counts as critical.
- No built-in rule is critical yet, so `--fail-on critical` passes every built-in finding, also a
  rug pull (`MOAT-T2-001` is high). It fails only in the two fail-closed cases above. `scan` says
  so on stderr: `mcpmoat scan: note: no built-in rule is critical yet, so with --fail-on critical
  no built-in finding gives exit code 1`.
- An unpinned server that fails or times out is a warning only (in the summary, or on stderr with
  `--json`). It does not change the exit code. A pinned server that fails or times out is a high `MOAT-T2-004` finding.

Exit code 2 comes, for example, from a usage error (invalid flags), invalid rules, an unreadable
`--config` file, a problem in a config file, a `pins.json` that cannot be read or saved, a report
that cannot be written (a closed stdout), an unknown home or working directory in auto-discovery,
an `--llm` problem (a missing or invalid `MCPMOAT_LLM_API_KEY`, a provider failure, an internal
error of the LLM step, or more than 500 tools), or an internal error. Some of these errors still
print the report on stdout first, so you can read the findings:

| Execution error | Report |
|---|---|
| A problem in a config file | Printed, then the problems. A `--config` file with a problem and no server prints only the problem. |
| A `pins.json` that cannot be read or saved | Printed |
| An internal error of the inspection (`inspect.Run`) | Printed |
| An LLM provider failure, an internal error of the LLM step, or more than 500 tools with `--llm` | Printed |
| A signal before the save of new pins | Printed |
| A usage error (also a bad `--llm-*` flag or a missing API key), invalid rules, or an unknown home or working directory | Not printed |
| A signal during the inspection or the LLM step | Not printed |
| A report that cannot be written | Not printed |

A signal is Ctrl-C, `SIGTERM` or `SIGHUP`. It gives exit code 2 at these times:

- While `scan` reads the configs. The read stops, and the file it did not read is a config file
  problem with the reason `canceled`. If `scan` found a server and you did not use `--no-connect`,
  it then stops at the inspection, as in the next item: it prints the line below and no report.
  A `pins.json` that cannot be read is the exception: `scan` reads it before the inspection, so
  it prints the report and the `pins.json` error, without the line below.
- During the inspection. `scan` stops the stdio servers that it started, prints
  `mcpmoat scan: interrupted; no pins were saved`, saves nothing and prints no report.
- During the LLM step of a `--llm` scan. `scan` stops the requests and then does the same: it
  prints the same line, saves nothing and prints no report.
- After the report, before the save of new pins. `scan` prints the same line and saves nothing.
  This applies only when the scan has new servers to pin.

At other times the scan ends with exit code 0 or 1, as if no signal came. A second signal ends
mcpmoat at once.

To use the exit code in CI or in a git hook, see [docs/ci.md](docs/ci.md).

## Build from source

```sh
go build -o mcpmoat ./cmd/mcpmoat
./mcpmoat version
```

[CONTRIBUTING.md](CONTRIBUTING.md#build-the-binary) explains how to set the version.

## What this does not do

- **It does not guarantee safety.** Rule-based scanning reduces risk. It has false positives (it can
  flag a safe tool) and false negatives (it can miss a malicious one).
- It does not analyse server source code, so it does not find malware inside a server.
- It does not protect against prompt injection that arrives in content the agent reads (for example
  a GitHub issue). That is planned for a later phase.
- `mcpmoat scan` starts each configured stdio server, with the same command your client already
  runs. mcpmoat uses no shell. The server gets only the env from its config plus a small allowlist
  of safe variables, such as `PATH` and `HOME`. This env scrub is not a sandbox: the server runs as
  you and can read your files and use the network. A server can also echo a configured env value
  into a tool description, and then that text is stored in `pins.json`. mcpmoat does not start a
  server from an untrusted project file or a turned-off server, and no flag allows it yet. The YAML
  tool rules do not run yet, so exit code 0 does not mean that the tools are safe.
- `--llm` does not make a scan complete or reliable. A model can miss a malicious tool, and a
  hostile description can try to influence the model. Its findings are advisory, and with `--llm`
  your tool names and descriptions leave your machine.
- Not done yet: a lock for `pins.json` (#150).
- `scan --rules <dir>` loads and checks extra rule files, but `scan` does not apply them yet. It
  prints `mcpmoat scan: rules from --rules are loaded and checked, but not applied yet` on stderr.

## Documentation

- [docs/README.md](docs/README.md): the index of all docs and which file owns each topic.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to add a rule, build the binary and open a PR.
- [docs/ci.md](docs/ci.md): how to run mcpmoat in CI and in git hooks.
- [SECURITY.md](SECURITY.md): how to report a vulnerability in mcpmoat.

## Credits

The threat model builds on public research by [Invariant Labs](https://invariantlabs.ai/) and the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

## License

[Apache-2.0](LICENSE)
