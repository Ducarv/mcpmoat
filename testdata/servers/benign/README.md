# benign (TEST FIXTURE)

This is a **test fixture** for mcpmoat. It is not a product. Do not install it in a real client.

It is a clean fake MCP server and the negative baseline (NFR-05). No rule may report a finding on
it. All names and descriptions are short, plain ASCII text with no instructions, no URLs and no
hidden characters. The tools return fixed or computed harmless text. The server makes no network
call.

Build and run (MCP over stdio): `go build -o benign ./testdata/servers/benign`.

## What it offers

The page size is 1, so a client must follow `nextCursor` to read all tools.

| Kind | Name | Notes |
|---|---|---|
| Tool | `add` | Adds `a` and `b`. Read-only, idempotent, not open-world. |
| Tool | `echo` | Returns `text` unchanged. Same annotations as `add`. |
| Prompt | `greeting` | One required argument, `name`. |
| Resource | `mcpmoat://benign/readme` | A short plain text. |
| Resource template | `mcpmoat://benign/notes/{name}` | Name is `note`. |

## Test-only flags

The inspect tests use these flags. The default run needs none of them. Some of them write a file or
start a process, so this fixture is not fully passive when you set them.

| Flag | Effect |
|---|---|
| `-mode ok` | Serve MCP on stdio until stdin closes. This is the default. |
| `-mode crash` | Exit with code 3 before the handshake. |
| `-mode hang-init` | Never read stdin and never reply. |
| `-mode hang-list` | Finish the handshake, then block every `tools/list` request. |
| `-mode flood-list` | Answer the list requests with empty lists. On the last one, send 20000 `ping` requests, then stop reading stdin. |
| `-mode echo-env -echovar NAME` | **Not benign.** Serve one tool, `fetch_<value>`, where `<value>` is the value of the environment variable `NAME`. The tool description and the description of its input property `text` also hold the value. This is a hostile server that echoes a configured secret (#228, #234). |
| `-mode fail-echo -echovar NAME` | **Not benign.** Answer `initialize` with a JSON-RPC error whose message holds the value of `NAME`, then exit with code 1 (#180). The echo is on stdout, because mcpmoat sends the child's stderr to `/dev/null`. |
| `-echovar NAME` | The environment variable that `echo-env` and `fail-echo` read. These modes need it, and `NAME` must be set (an empty value is allowed). Other modes ignore it. |
| `-pidfile path` | **Writes a file.** Write the process ID to `path`. |
| `-envfile path` | **Writes a file.** Write the sorted environment to `path`, to check the scrubbed environment (NFR-04). |
| `-spawn path` | **Starts a process and writes a file.** Start a copy of the fixture in `hang-init` mode and write its process ID to `path`, to check that mcpmoat stops the whole process group. |

Bad flags, an unknown mode, a missing `-echovar` (or an unset variable) or a file write error exit
with code 2.

Use only fake values with `echo-env` and `fail-echo`, for example
`MCPMOAT_FAKE_TOKEN=FAKE-TOKEN-0123456789` or the short value `123456`. Use letters, digits and `-`
only, so that a client accepts the tool name.

## Notes

- `TestFixtureBuiltinT1` and `TestFixtureBuiltinT3` in `internal/rules/fixtures_test.go` assert that
  the built-in T1 and T3 rules find nothing in its tools.
- `TestFixtureBenign` in the same file asserts that `CheckShadowing(benign, mailer)`,
  `CheckConfig` and the typosquat check find nothing.
- See [testdata/servers/README.md](../README.md) for the other fixtures.
