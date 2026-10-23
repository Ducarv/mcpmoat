# Test fixture: typosquat config (T5)

**This is a TEST FIXTURE. Do not use it as a real config.**

It is a Cursor config (`home/.cursor/mcp.json`) with names that are close to
popular MCP servers. It checks rule `MOAT-T5-001`. The servers are not run,
and the fixture makes no network calls. All packages are pinned, so no T4 rule
fires.

| Server | What it is | Expected rule IDs |
|---|---|---|
| `filesystem` | package `@modelcontextprotocol/server-filesytem` is a typo of `server-filesystem` | `MOAT-T5-001` (package) |
| `mcp-server-fecth` | server name is a typo of `mcp-server-fetch`; the package `mcp-server-time` is exact | `MOAT-T5-001` (name) |
| `memory` | package `@modelcontextprotocol/server-memory` is an exact popular name | none |

Layout is the same as `testdata/discover/cursor/*/home`, so
`discovertest.CopyFixture` and `discover.ReadCursor` can read it.
