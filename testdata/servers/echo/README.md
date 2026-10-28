# echo (TEST FIXTURE)

This is a **test fixture** for mcpmoat. It is not a product. Do not install it in a real client.

It is a hostile fake MCP server that echoes a configured secret. A client gives a stdio server its
configured env values, so a hostile server can send such a value back in its MCP output. This
fixture reads the value of one environment variable and puts it in a tool name, a tool
description and a schema, or in the error message of its `initialize` reply. mcpmoat must show the
value as a mask in its report (#228, #234, #180). The server makes no network call, starts no
process, and reads or writes no file. It reads exactly one environment variable.

Build and run (MCP over stdio): `go build -o <dir>/echo ./testdata/servers/echo`.

## Flags

| Flag | Effect |
|---|---|
| `-mode echo-env` | Serve one tool, `fetch_<value>`, where `<value>` is the value of the environment variable that `-echovar` names. The tool description and the description of its input property `text` also hold the value. This is the default. |
| `-mode fail-echo` | Answer `initialize` with a JSON-RPC error whose message is `cannot start: bad token <value>`, then exit with code 1. The echo is on stdout, because mcpmoat sends the child's stderr to `/dev/null`. |
| `-echovar NAME` | The environment variable to echo. It is required, and `NAME` must be set (an empty value is allowed). |

A bad flag, `-h`, an unknown mode, an extra argument or a missing `-echovar` (or an unset variable)
exits with code 2. Error messages on stderr name the variable, never its value.

Use only fake values, for example `MCPMOAT_FAKE_TOKEN=FAKE-TOKEN-0123456789` or the short value
`123456`. Use letters, digits and `-` only, so that a client accepts the tool name.

## Notes

- `TestE2EScanEchoedSecret` and `TestE2EScanShortValueInFailure` in
  `cmd/mcpmoat/e2e_echo_test.go` run the real binary with this fixture.
- See [testdata/servers/README.md](../README.md) for the other fixtures.
