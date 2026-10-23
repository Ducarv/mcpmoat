# Test fixtures: MCP servers

Every folder here is a **test fixture** for mcpmoat. These are fake servers for tests and the demo.
They are not products. They make no network call, start no process and read or write no file. The
malicious text in them is inert data. Do not install them in a real client.

Each fixture is one self-contained `main` package, on purpose: a reader can audit one malicious
fixture alone, without a shared helper that could hide behaviour. So the small `run()` and exit-code
block is repeated in each folder.

| Folder | Threat | Expected rule IDs |
|---|---|---|
| `benign/` | none (negative baseline) | none |
| `poisoned/` | T1 tool poisoning | MOAT-T1-001 to MOAT-T1-009 (pending #36 and #42 to #50); see its README for the marker of each ID |
| `shadowing/` + `mailer/` | T3 cross-server shadowing | MOAT-T3-001 (scan both servers together) |
| (none yet) | T2 rug pull | Fixtures come with the M5 Pins milestone |

T4 (dangerous config) and T5 (typosquat) are config fixtures, not servers. They are in
[`../configs/`](../configs/):

| Folder | Threat | Expected rule IDs |
|---|---|---|
| `configs/dangerous/` | T4 | MOAT-T4-001, MOAT-T4-002, MOAT-T4-003, MOAT-T4-004 |
| `configs/typosquat/` | T5 | MOAT-T4-004, MOAT-T5-001 |
