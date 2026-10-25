# Test fixture: CI example repo

**This is a TEST FIXTURE. Do not use it as a real config.**

It is a Claude Code project config (`repo/.mcp.json`) for a small example
repo. The CI and hook examples in [docs/ci.md](../../docs/ci.md) scan it, and
the `TestE2EScanFailOn` test uses it to check the exit codes of `--fail-on`
and `--ignore`. It has no secrets, no `env` and no `headers`. The servers do
not exist.

Use this config only with `--no-connect`. As a second guard, the remote URL
points at the reserved `.invalid` top-level domain (RFC 2606), which never
resolves. So a scan that connects by mistake fetches nothing.

| Server | Expected rule IDs |
|---|---|
| `notes` | none (pinned package `@example-corp/notes-mcp@1.2.3`, no `-y`) |
| `files` | `MOAT-T4-003` medium (`@latest` package); `MOAT-T4-004` low (npx `-y` before the package spec) |
| `remote` | `MOAT-T4-001` high (`http://` remote on `mcp.example.invalid`) |

No other rule must fire. In particular, the package names do not match
`MOAT-T5-001` (typosquat).

In the `repo` folder, `mcpmoat scan --no-connect --config .mcp.json` exits
with 1, because `MOAT-T4-001` is high and the default is `--fail-on high`.
With `--fail-on critical`, it exits with 0. `TestE2EScanFailOn` in
`cmd/mcpmoat/e2e_test.go` holds the expected exit code for each `--fail-on`
and `--ignore` value.
