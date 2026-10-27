# Exit codes

This page is the exit-code contract of `mcpmoat scan`. Other docs give a short form and link
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
  rug pull (`MOAT-T2-001` is high). `scan` says so on stderr: `mcpmoat scan: note: no built-in
  rule is critical yet, so with --fail-on critical no built-in finding gives exit code 1`. It fails
  only in the two fail-closed cases above, or when a description or schema rule from `--rules` is
  critical: then a finding of that rule and a `MOAT-T1-023` budget finding (see below) give exit
  code 1.
- An unpinned server that fails or times out is a warning only (in the summary, or on stderr with
  `--json`). It does not change the exit code. A pinned server that fails or times out is a high
  `MOAT-T2-004` finding.
- A server whose rule analysis uses up its time budget (5 seconds for each server) is a
  `MOAT-T1-023` finding. Its severity is the highest severity of the description and schema rules
  that `scan` applies, but never lower than high. So it is high with the built-in rules, and
  critical when a description or schema rule from `--rules` is critical (see the
  `--fail-on critical` item above). It is not an execution error: it gives exit code 1 with the
  default `--fail-on`, and the JSON `complete` stays `true`. `scan` also prints a warning on
  stderr, and the other servers still get their own budget.

Exit code 2 comes, for example, from a usage error (invalid flags), invalid rules (also a regex in
a `--rules` file that does not compile, with or without `--no-connect`), an unreadable
`--config` file, a problem in a config file, a `pins.json` that cannot be read or saved, a report
that cannot be written (a closed stdout), an unknown home or working directory in auto-discovery,
an `--llm` problem (a missing or invalid `MCPMOAT_LLM_API_KEY`, a provider failure, a provider
refusal of every tool, the 10-minute time limit of the LLM step, an internal error of the LLM
step, or tools over the 500-tool cap), an internal error of the tool rule step, or another
internal error. One tool that the provider refuses (HTTP 400, 413 or 422) is not an execution
error: it is a `medium` finding, and the scan goes on (see [Optional LLM classification](llm.md)).
That is below the default `--fail-on high`, so a hostile server that makes the provider refuse its
tool descriptions can keep their LLM rating from reaching `high`. Some of these errors still print
the report on stdout first, so you can read the findings:

| Execution error | Report |
|---|---|
| A problem in a config file | Printed, then the problems. A `--config` file with a problem and no server prints only the problem. |
| A `pins.json` that cannot be read or saved | Printed |
| An internal error of the inspection (`inspect.Run`) | Printed |
| An LLM provider failure, a provider refusal of every tool, the 10-minute time limit of the LLM step, an internal error of the LLM step, or tools over the 500-tool cap with `--llm` | Printed |
| A signal before the save of new pins | Printed |
| A usage error (also a bad `--llm-*` flag or a missing API key), invalid rules, or an unknown home or working directory | Not printed |
| A signal during the inspection, the tool rule step or the LLM step | Not printed |
| An internal error of the tool rule step. `scan` prints `mcpmoat scan: server <name>: the rule analysis failed (internal error)` | Not printed |
| A report that cannot be written | Not printed |

A signal is Ctrl-C, `SIGTERM` or `SIGHUP`. It gives exit code 2 at these times:

- While `scan` reads the configs. The read stops, and the file it did not read is a config file
  problem with the reason `canceled`. If `scan` found a server and you did not use `--no-connect`,
  it then stops at the inspection, as in the next item: it prints the line below and no report.
  A `pins.json` that cannot be read is the exception: `scan` reads it before the inspection, so
  it prints the report and the `pins.json` error, without the line below.
- During the inspection. `scan` stops the stdio servers that it started, prints
  `mcpmoat scan: interrupted; no pins were saved`, saves nothing and prints no report.
- During the tool rule step, which applies the description and schema rules to the tools after
  the inspection. `scan` stops the rule analysis, prints the same line, saves nothing and prints no
  report.
- During the LLM step of a `--llm` scan. `scan` stops the requests and then does the same: it
  prints the same line, saves nothing and prints no report. The 10-minute time limit of the LLM
  step is not a signal: it prints the report (see the table above).
- After the report, before the save of new pins. `scan` prints the same line and saves nothing.
  This applies only when the scan has new servers to pin.

At other times the scan ends with exit code 0 or 1, as if no signal came. A second signal ends
mcpmoat at once.

To use the exit code in CI or in a git hook, see [Using mcpmoat in CI and git hooks](ci.md).

## See also

- [Using mcpmoat in CI and git hooks](ci.md)
- [Pins and rug pulls](pins.md)
- [Scan output](scan-output.md)
