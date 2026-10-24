# Test fixtures: MCP servers

Every folder here is a **test fixture** for mcpmoat. These are fake servers for tests and the demo.
They are not products. No fixture makes a network call. The malicious fixtures (`poisoned/`,
`shadowing/` and `mailer/`) start no process and write no file. Their malicious text is inert data.
`benign/` has test-only flags that can write a file or start a copy of itself. See its
[README](benign/README.md). `TestFixtureImports` in `internal/rules/fixtures_imports_test.go`
checks the imports of every fixture. Do not install any fixture in a real client.

Each fixture is one self-contained `main` package, on purpose: a reader can audit one malicious
fixture alone, without a shared helper that could hide behaviour. So the small `run()` and exit-code
block is repeated in each folder.

| Folder | Threat | Expected rule IDs |
|---|---|---|
| `benign/` | none (negative baseline) | none; see its [README](benign/README.md) for the test-only flags |
| `poisoned/` | T1 tool poisoning | MOAT-T1-002, MOAT-T1-003, MOAT-T1-004, MOAT-T1-005, MOAT-T1-006, MOAT-T1-007, MOAT-T1-008, MOAT-T1-009, MOAT-T1-012, MOAT-T1-017, MOAT-T1-019, MOAT-T1-020 (MOAT-T1-007 and MOAT-T1-017 on the `padded_notes` tool); see its README for the marker of each ID |
| `shadowing/` + `mailer/` | T3 cross-server shadowing | MOAT-T1-003 and MOAT-T1-005 (`shadowing/` alone); MOAT-T3-001 (two sources, see the note below) |
| (none yet) | T2 rug pull | Fixtures come with the M5 Pins milestone |

MOAT-T3-001 comes from two checks. Only tests run them. For what `scan` runs today, see
[Data flow](../../docs/ARCHITECTURE.md#data-flow).

- The YAML rule `rules/MOAT-T3-001.yaml` fires on the description of `shadowing/add_numbers` alone.
  `TestFixtureBuiltinT3` checks this on each fixture alone. It expects a hit only on that tool.
- `rules.CheckShadowing` finds `shadowing/add_numbers` against `mailer/send_email` when it gets
  both servers. `TestFixtureShadowing` checks this.

`TestFixtureBuiltinT1` also checks MOAT-T1-003 and MOAT-T1-005 on `shadowing/add_numbers`. All three
tests are in `internal/rules/fixtures_test.go`.

T4 (dangerous config) and T5 (typosquat) are config fixtures, not servers. They are in
[`../configs/`](../configs/):

| Folder | Threat | Expected rule IDs |
|---|---|---|
| `configs/dangerous/` | T4 | MOAT-T4-001, MOAT-T4-002, MOAT-T4-003, MOAT-T4-004 |
| `configs/typosquat/` | T5 | MOAT-T4-004, MOAT-T5-001 |
