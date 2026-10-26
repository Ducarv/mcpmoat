# Test fixture: typosquat config (T5)

**This is a TEST FIXTURE. Do not use it as a real config.**

It is a Cursor config (`home/.cursor/mcp.json`) with names that are close to
popular MCP servers. It checks rule `MOAT-T5-001`. The servers are not run,
and the fixture makes no network calls. All packages are pinned and the remote
URL uses https, so no T4-001, T4-002 or T4-003 rule fires. The npx entries use
`-y`, so MOAT-T4-004 fires on them.

Scan this home only with `--no-connect`. The one exception is `TestE2EAcceptance`: it
scans a copy of its `mcpServers` in an untrusted project `.cursor/mcp.json` without
`--no-connect`, but the untrusted-project gate refuses every server there, so nothing
starts. As a second guard, the npx entries pass `--registry https://registry.invalid/` and
the remote host is `mcp.example.invalid`: the reserved `.invalid` domain (RFC 2606) never
resolves, so a scan that connects by mistake fetches nothing.

| Server | What it is | Expected rule IDs |
|---|---|---|
| `filesystem` | package `@modelcontextprotocol/server-filesytem` is a typo of `server-filesystem` | `MOAT-T4-004` (npx `-y` before the package spec); `MOAT-T5-001` (package) |
| `mcp-server-fecth` | server name is a typo of `mcp-server-fetch`; it is a remote server, so only its name can be compared | `MOAT-T5-001` (name) |
| `memory` | package `@modelcontextprotocol/server-memory` is an exact popular name | `MOAT-T4-004` (npx `-y` before the package spec) |

Layout is the same as `testdata/discover/cursor/*/home`, so
`discovertest.CopyFixture` and `discover.ReadCursor` can read it.
