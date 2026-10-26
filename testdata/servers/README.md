# Test fixtures: MCP servers

Every folder here is a **test fixture** for mcpmoat. These are fake servers for tests and the demo.
They are not products. No fixture makes a network call. The malicious fixtures (`poisoned/`,
`shadowing/`, `mailer/` and `rugpull/`) start no process and write no file. Their malicious text
is inert data. `benign/` has test-only flags that can write a file or start a copy of itself. See
its [README](benign/README.md). `TestFixtureImports` in
`internal/rules/fixtures_imports_test.go` checks the imports of every fixture. Do not install any
fixture in a real client.

Each fixture is one self-contained `main` package, on purpose: a reader can audit one malicious
fixture alone, without a shared helper that could hide behaviour. So the small `run()` and exit-code
block is repeated in each folder.

| Folder | Threat | Expected rule IDs |
|---|---|---|
| `benign/` | none (negative baseline) | none; see its [README](benign/README.md) for the test-only flags |
| `poisoned/` | T1 tool poisoning | MOAT-T1-002, MOAT-T1-003, MOAT-T1-004, MOAT-T1-005, MOAT-T1-006, MOAT-T1-007, MOAT-T1-008, MOAT-T1-009, MOAT-T1-012, MOAT-T1-017, MOAT-T1-019, MOAT-T1-020 (MOAT-T1-007 and MOAT-T1-017 on the `padded_notes` tool); see its README for the marker of each ID |
| `shadowing/` + `mailer/` | T3 cross-server shadowing | MOAT-T1-003 and MOAT-T1-005 (`shadowing/` alone); MOAT-T3-001 (two sources, see the note below) |
| `rugpull/` | T2 rug pull | MOAT-T2-001 on `get_time` with `-variant injected` (high); no YAML rule; see its [README](rugpull/README.md) |

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

## End-to-end acceptance test

`TestE2EAcceptance` in `cmd/mcpmoat/e2e_acceptance_test.go` runs the real binary on all these
fixtures together. The trusted global config runs the five stdio servers: `benign`, `poisoned`,
`shadowing`, `mailer` and `rugpull` (clean). An untrusted Cursor project file holds the servers of
the T4 and T5 config fixtures. The untrusted-project gate refuses every project server, so none
of them starts, but the config rules still check them. The test also checks that no process
starts and no connection to a remote project server happens.

1. Scan 1 pins the five stdio servers.
2. The config switches `rugpull` to `-variant injected`.
3. Scan 2 runs as text, then again with `--json`.

Every scan exits with code 1, because the T4 findings are high.

The test checks the exact rule IDs and severities of each server:

| Server | Threat | Rule IDs the test asserts |
|---|---|---|
| `benign` | none | none |
| `rugpull` | T2 | `MOAT-T2-001` (high) on `get_time`, in scan 2 only; none in scan 1 |
| `dangerous` config servers | T4 | the IDs of each server in [its README](../configs/dangerous/README.md): MOAT-T4-001, MOAT-T4-002, MOAT-T4-003, MOAT-T4-004; none on `remote-local` |
| `typosquat` config servers | T5 | the IDs of each server in [its README](../configs/typosquat/README.md): MOAT-T4-004, MOAT-T5-001 |
| `poisoned`, `shadowing`, `mailer` | T1, T3 | none, for now (see below) |

`scan` does not apply the T1 and T3 description and schema rules yet (issue #143). So the test
asserts an empty set for `poisoned`, `shadowing` and `mailer`, and only `MOAT-T2-001` for the
injected `rugpull`. When #143 lands, the expected sets for `poisoned`, `shadowing` and `mailer`
get the IDs that `scan` then reports (the first table of this file lists the IDs that the rule
tests expect today), and the injected `rugpull` gets the T1 IDs of its `get_time`. The
[rugpull README](rugpull/README.md) names the T1 markers of that text, but not their rule IDs.
