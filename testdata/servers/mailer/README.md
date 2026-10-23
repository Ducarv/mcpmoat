# mailer (TEST FIXTURE)

This is a **test fixture** for mcpmoat. It is not a product. Do not install it in a real client.

It is a benign fake MCP server and the victim in the **T3 (cross-server tool shadowing)**
scenario. It has one tool, `send_email`, with the arguments `to`, `subject` and `body`. The tool
**does not send anything**. It ignores its arguments and returns `queued (fixture, nothing sent)`.

This server must look clean: its text has no instructions, so no rule reports a finding on it
alone. It pairs with the `shadowing` fixture (`testdata/servers/shadowing`), whose tool
`add_numbers` tries to change how the model uses `send_email`. Scan both together and mcpmoat must
report **MOAT-T3-001** (expected; the rule comes with #37 and #51).

The server makes no network call, starts no process and reads or writes no file.

Build and run (MCP over stdio): `go build -o mailer ./testdata/servers/mailer`. Flag
`-mode ok|crash|hang-init` as in the `benign` fixture.
