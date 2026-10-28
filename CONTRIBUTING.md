# Contributing to mcpmoat

Thank you for helping. The easiest and most useful way to contribute is a **detection rule**.

## Contributing a rule

A rule is one YAML file that holds its own test cases. [docs/writing-rules.md](docs/writing-rules.md) has the five steps: pick a threat, write the rule, add
test cases, run the tests and try an external rule. Open your PR against `dev`.

## Building and testing

### Requirements

You need Go 1.27.3 or later. The `go` line in `go.mod` sets the minimum language version
(`go 1.27.0`). The `toolchain` line sets the toolchain that builds the project and runs in CI
(`toolchain go1.27.3`). With Go 1.21 or later and the default `GOTOOLCHAIN=auto`, the `go` command
downloads go1.27.3 for you.

`go.mod` is the source of truth. When the versions in `go.mod` change, change this section too.

The project uses [golangci-lint](https://golangci-lint.run/) v2. The config is in `.golangci.yml`.
CI pins v2.15.0. Install the same version:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
```

You can also use `brew install golangci-lint`, or follow the
[install guide](https://golangci-lint.run/welcome/install/).

You need [GoReleaser](https://goreleaser.com/) only when you change `.goreleaser.yaml`. CI and the
release workflow pin one version. `go run github.com/goreleaser/goreleaser/v2@v2.19.0 <cmd>` runs that
version and needs no install. `brew install goreleaser` also works, but it can give another version.
To bump the version, change `GORELEASER_VERSION` in `ci.yml` and `release.yml` and every
`goreleaser/v2@` command in this file. The `ci-scripts` CI job fails if they differ. Then build a
snapshot and check that `dist/homebrew/Casks/mcpmoat.rb` still has the parts in the cask list in
[docs/install.md](docs/install.md#verify-a-download). In a snapshot, the `version` line is the snapshot version
and the urls hold the literal snapshot tag (for example `v0.0.0`) in place of `v#{version}`. Only a
real tag gives the exact urls.

### Checks

Run these checks before you open a pull request:

```sh
gofmt -l .                                             # must print nothing
go mod tidy && git diff --exit-code -- go.mod go.sum   # module files are tidy
go build ./...
go vet ./...
golangci-lint config verify                            # .golangci.yml is valid
golangci-lint run ./...
go test -race -shuffle=on ./...
govulncheck ./...
```

On Linux, `TMPDIR` is usually `/tmp`, which other users can write to. Some E2E tests then skip,
because mcpmoat refuses to make its run directory below such a directory. To run them, set `TMPDIR`
to a private directory, for example `TMPDIR=$(mktemp -d ~/.cache/mcpmoat-test.XXXXXX)`. CI does this.

If you change a workflow, a tool pin or a script in `.github/scripts/`, also run these checks. They
need [ShellCheck](https://www.shellcheck.net/) and no token. The two pin check scripts also need Go,
because the pin check is a Go program. Go builds it with the modules in your module cache. The first
run can download the toolchain that `go.mod` names and the modules, so it can need the network. The
other scripts need no network. Run the `shellcheck` line from the repository root. The scripts find
the root themselves, so you can run them from any directory.

```sh
shellcheck .github/scripts/*.sh                # lint the scripts
.github/scripts/test-harness-test.sh           # test the shared test harness
.github/scripts/check-tool-pins-test.sh        # test the pin check
.github/scripts/check-tool-pins.sh             # check the tool version pins
.github/scripts/notify-failure-test.sh         # test the failure issue job (needs jq)
.github/scripts/release-guard-test.sh          # test the release guard step (needs git)
.github/scripts/verify-and-publish-test.sh     # test the publish script (standard tools only)
```

If you change `.goreleaser.yaml`, also run these checks. A snapshot build needs no token and
publishes nothing. It writes the archives to `dist/`. The two scripts after the build,
`check-snapshot-test.sh` and `check-snapshot.sh`, read `dist/`. Both need `jq`, `file`, `go` and
`sha256sum` or `shasum`. They run on Linux and macOS.

```sh
go run github.com/goreleaser/goreleaser/v2@v2.19.0 check                       # config is valid
go run github.com/goreleaser/goreleaser/v2@v2.19.0 release --snapshot --clean  # build all archives
.github/scripts/check-snapshot-test.sh                                         # test the archive check
.github/scripts/check-snapshot.sh                                              # check the archives
```

Agent-oriented variants (scoped tests, E2E scenario, golden files, fuzz) are in the Commands table of
[.agents/project.md](.agents/project.md#commands).

`go.mod` lists the dependencies. Do not change it unless your change needs a new module.

CI (`.github/workflows/ci.yml`) runs on every pull request. On Linux and macOS it runs build, vet, race
tests, golangci-lint and the version smoke test. On Linux only it also runs the gofmt check, the
`go mod tidy` check and govulncheck.

The `ci-scripts` job also runs on every pull request. It runs these scripts:

- `shellcheck .github/scripts/*.sh` lints the scripts.
- `.github/scripts/test-harness-test.sh` tests the shared test harness. It runs first, because the
  other test scripts use the harness.
- `.github/scripts/check-tool-pins-test.sh` tests the pin check.
- `.github/scripts/check-tool-pins.sh` runs the pin check.
- `.github/scripts/notify-failure-test.sh` uses a fake `gh`. It runs the real `run:` block of the
  `notify-failure` job of `govulncheck.yml` and checks the job keys by text. The job details are in
  [docs/releasing.md](docs/releasing.md#weekly-vulnerability-check).
- `.github/scripts/release-guard-test.sh` runs the real `run:` block of the guard step of
  `release.yml` ("Check that the build left the scripts unchanged") in scratch git repos.
- `.github/scripts/verify-and-publish-test.sh` runs the script of the "Verify and publish the
  release" step of `release.yml` with a fake `gh`.

None of them needs a token. Only the two pin check scripts need Go, and on the first run they can
need the network (see above).

Every `*-test.sh` script sources `.github/scripts/test-harness.sh`. To add a script test, source it
and use its case runner (`check_case`). Do not write a new harness. The header of
`test-harness.sh` has a usage example. The script tests must pass with bash 5 and with bash 3.2
(`/bin/bash` on macOS). So do not use:

- `mapfile` or `readarray`
- associative arrays (`declare -A`)
- `((x++))` under `set -e` (it fails when `x` is 0)
- an empty array expansion such as `"${list[@]}"` under `set -u` (bash 3.2 stops there)

A new guard needs a test case that fails when you remove the guard.

The pin check is the Go program in `internal/pincheck` (package `main`). It is a CI tool only.
GoReleaser builds only `./cmd/mcpmoat`, so the pin check is not part of the mcpmoat binary.
`.github/scripts/check-tool-pins.sh` runs it. You can also run it with
`go run ./internal/pincheck -root .`. Through `go run`, any failure is exit 1 (the program itself
exits 2 on a bad flag or a root it cannot open), and stderr gets an extra `exit status N` line.
Its tests are in `internal/pincheck/*_test.go` (`go test ./...` runs them) and in
`.github/scripts/check-tool-pins-test.sh`. It only reads the files. It changes nothing. It prints
at most 50 problems, then one line `and N more problems`. Each message cuts a key, a value or a
name from a workflow to 80 bytes.

It reads each `.github/workflows/*.yml` and `*.yaml` file (in any case, also a name that starts
with a dot) with a YAML parser (`go.yaml.in/yaml/v3`). The rules read the values as the parser
decodes them, so flow style, quotes and escapes cannot hide a value. Comments are not read. A
workflow fails closed when it has one of these forms, because they can hide a step or make two
YAML readers disagree:

- no YAML document, or more than one document
- an alias (`*name`), an anchor (`&name`), a merge key (`<<`) or an explicit tag (such as `!!str`)
- two keys in one mapping that are the same when case is ignored
- a mapping key that is not a scalar, or a key with a non-ASCII character
- more than 1 MiB, or nesting deeper than 64 levels
- a top level that is not a mapping, or YAML that does not parse
- an `env:` key (in any case, at the workflow, job or step level, or deeper) whose value is not a
  mapping, for example an expression, a block scalar or an empty value

The `env:` rule is there because GitHub evaluates a step `env:` over the job `env:`, so an
expression such as `env: ${{ fromJSON(...) }}` could set `GORELEASER_VERSION` or
`GOVULNCHECK_VERSION` to a value the check cannot see.

A workflow that is a symlink, or that is not a regular file, also fails. `ci.yml`, `release.yml`,
`govulncheck.yml` and `CONTRIBUTING.md` must exist and be regular files.

The GoReleaser rules:

- `ci.yml` pins one full version (`vMAJOR.MINOR.PATCH`) as `GORELEASER_VERSION` in the `env:` of a
  job. It can repeat the same pin in more jobs. `release.yml` has at least one such pin. Every pin in
  every workflow has the version of `ci.yml`.
- Each `goreleaser/goreleaser-action` step has `version: ${{ env.GORELEASER_VERSION }}` in its
  `with:` mapping, and its job has the pin in its own `env:`.
- A `with:` of a goreleaser-action step that is not a mapping fails, for example an expression. The
  list above covers every `env:`.
- Any other key or value in a workflow that names `goreleaser/goreleaser-action` or
  `GORELEASER_VERSION` (in any case) fails, for example a write to `$GITHUB_ENV` or a key in another
  case.
- `CONTRIBUTING.md` names at least one GoReleaser version (such as a `goreleaser/v2@` command).
  Each `goreleaser@` or `goreleaser/vN@` version in it is the pin of `ci.yml`.
- A file under `.github/actions` that names the action (in any case) fails, so that a new local
  action cannot skip the rules. A symlink there fails too, and so does any other entry that is not
  a regular file or a directory. The name `.github/actions` matches in any case, for example
  `.github/Actions`.

The govulncheck rules:

- `ci.yml` pins one full version as `GOVULNCHECK_VERSION`. `release.yml` and `govulncheck.yml` each
  have at least one pin, and each pin has the version of `ci.yml`. A pin can be in any mapping of
  the file.
- Each of the three files has a step whose `run:` value is exactly
  `go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...`.
- In the three files, a job that has that step has no job-level `if:` key and no job-level
  `needs:` key. GitHub skips such a job when its `if:` is false. It also skips a job that waits
  (`needs:`) for a skipped job. Then the scan would not run.
- In the three files, any other key or value that names `govulncheck` (in any case) fails.
  `govulncheck.yml` may also have these, with this exact case and text: `name: govulncheck` at the
  top level, `govulncheck` as a job ID, and, in any job that does not run the call,
  `needs: govulncheck` and `if: failure() || needs.govulncheck.result == 'cancelled'`.
- The three files have no `continue-on-error` key.
- No other workflow names `govulncheck`.

Not covered:

- GitHub reads the workflows with its own YAML reader, which can differ from yaml.v3. The check
  fails on the forms where readers often differ (see the list above), but it cannot prove that
  GitHub reads the same values.
- Other ways to install GoReleaser, such as `docker://goreleaser/goreleaser`, a remote reusable
  workflow, `brew install` or `go install`, and a composite action outside `.github/actions`.
- A name that a step builds from pieces, for example in a `$GITHUB_ENV` write.
- Where a `GOVULNCHECK_VERSION` pin is. It can be in any mapping, not only an `env:`.
- The other keys of the step with the govulncheck call, such as `if:`, `shell:` and
  `working-directory:`. The check reads the job-level `if:` and `needs:` of the job with the call,
  but not the `if:` of its step. For example, `shell: "true {0}"` stops the call, and the step still
  passes.
- The `release` job of `release.yml` waits (`needs: test`) for the job with the call. The check
  does not read that job's `needs:` or `if:` keys, so a change there is not caught.
- A GoReleaser step that uses a renamed or forked action, or
  `go run github.com/goreleaser/goreleaser/...@version` instead of goreleaser-action. The check
  does not require that `release.yml` has at least one goreleaser-action step.
- The `ci-scripts` job of `ci.yml` runs this check (the step `run: .github/scripts/check-tool-pins.sh`)
  and the test of the check (the step `run: .github/scripts/check-tool-pins-test.sh`). The check does
  not read those steps, so a change that removes them is not caught.
- A job-level `if:` on the `ci-scripts` job itself. GitHub skips a job whose `if:` is false, and a
  skipped required check counts as passing. The check does not read that key.
- `defaults.run.shell` of the workflow or the job, `strategy`, `runs-on` and the trigger filters
  under `on:`.
- `defaults.run.working-directory` of the workflow or the job. The call can then scan another
  directory.
- Go variables in any `env:`, such as `GOPROXY`, `GOSUMDB`, `GONOSUMDB`, `GOPRIVATE`, `GOINSECURE`,
  `GOFLAGS` and `GOTOOLCHAIN`. A fake proxy can make an old govulncheck look clean.
- The keys `BASH_ENV`, `ENV` and `PATH` in a plain `env:` mapping. They can change what runs.
- Other ways to install or run govulncheck, such as
  `go install golang.org/x/vuln/cmd/...@latest`, or a tool name that a step builds from pieces. The
  name rule sees only the text `govulncheck` in one piece.
- A job-level `container:` whose image has its own `go`. The call then runs with the Go of that
  image.
- An earlier step in the job that changes `$GITHUB_PATH`, edits `go.mod` or `go.sum`, or checks out
  another ref. The check also does not read the `ref:` of a checkout step. A `$GITHUB_PATH` write can
  put another `go` first on the path.

Review must catch those. A follow-up issue tracks a stricter check.

The `release-check` job runs `goreleaser check` and a snapshot build. Then it runs one test and a
check: `.github/scripts/check-snapshot-test.sh` (positive and negative cases for the archive check)
and `.github/scripts/check-snapshot.sh`. Both read `dist/`.

The weekly `govulncheck` workflow (`.github/workflows/govulncheck.yml`) checks `main` every Monday.
A failed scheduled or manual run makes its `notify-failure` job open one issue, "Weekly vulnerability
check failed" (label `security`), or add a comment to it if it is already open. Only that job has
`issues: write`. A maintainer finds how to run the check by hand and what to do after a failed run in
[docs/releasing.md](docs/releasing.md#weekly-vulnerability-check).

The `offline` job proves that a scan makes no network call that it should not make (NFR-01). It
runs the `TestE2E` tests, the network tests of `cmd/mcpmoat/e2e_network_test.go` included, through
`.github/scripts/run-offline.sh`, in a Linux network namespace (`sudo unshare --net`) that has only
loopback. The script first checks that DNS and outside TCP connections fail and that loopback
works, then runs the tests as the normal user (`setpriv`) with `GOPROXY=off`. To run it on Linux,
run `.github/scripts/run-offline.sh` from the repository root. It needs `go`, `sudo`, `unshare`,
`setpriv`, `ip`, `getent` and `timeout`. It also needs a private `TMPDIR`: no directory in the
`TMPDIR` path may be writable by its group or by others. With the default `/tmp`, or on a system
that is not Linux, the script stops with exit code 2. On macOS there is no network namespace:
`go test ./cmd/mcpmoat/` runs the in-process network tests (`cmd/mcpmoat/network_test.go`) and the
E2E tests as usual, without the kernel check.

### Rebuild the look-alike tables

Two tables in `internal/rules` come from Unicode data: `skeletonTable` in `confusables.go` and
`edgeLookalikes` in `mixedscript.go`. Rebuild them when `TestScriptTablesVersion` fails after a Go
Unicode update, or when the project moves to a new Unicode TR39 version. The constants
`confusablesVersion` and `scriptTablesVersion` in `internal/rules/confusables.go` record the
versions in use.

1. Download `confusables.txt` for that version by hand from
   `https://www.unicode.org/Public/security/<version>/confusables.txt`. Keep it outside the
   repository and do not commit it. The test reads only this local file and makes no network
   call. The build and CI never download it.
2. Update the two version constants first. The test fails when the `# Version:` line of the file
   is not `confusablesVersion`, or when the Unicode version of Go or of `golang.org/x/text` is not
   `scriptTablesVersion`.
3. Compare the committed tables with the file. The test fails with a diff when they differ:

   ```sh
   go test ./internal/rules/ -run TestGenTables -args -confusables=/path/to/confusables.txt
   ```

   Without `-confusables`, the test skips.
4. Add `-update` after `-confusables=...` to rewrite `skeletonTable` and `edgeLookalikes`.
5. Review `git diff`. Update `skeletonTableSize` and `edgeLookalikesSize` when the counts change,
   and the version numbers in the comments (for example in `internal/rules/doc.go`). Then run
   `go test -race ./internal/rules/`.

The generator is test code in package `rules` (`internal/rules/gentables_test.go`). It needs no
extra tool and no extra dependency.

### Build the binary

```sh
go build -ldflags "-X main.version=v1.2.3 -X main.commit=abc123 -X main.date=2026-01-01T00:00:00Z" -o mcpmoat ./cmd/mcpmoat
./mcpmoat version
```

Without `-ldflags`, mcpmoat reads the version, commit and date that Go stores in the binary. A plain
`go build` in a git checkout prints a pseudo-version such as `v0.0.0-20261017181905-4091e6ff2614+dirty`.
A build with `go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@<version>` prints that module version.
The version is `dev` only when Go has no data to store, for example with `-buildvcs=false` or outside
a git checkout. With a version set by `-X main.version`, mcpmoat uses only the values that you link
(`main.commit` and `main.date`), and prints `none` and `unknown` for the ones that you leave out. The
output of the command above is `mcpmoat v1.2.3 (commit abc123, built 2026-01-01T00:00:00Z)`.

CI builds with `-ldflags "-X main.version=ci-smoke"` and checks that `mcpmoat version` prints that value.

Release builds set these values through GoReleaser (`.goreleaser.yaml`): `main.version` is the tag
with its `v`, `main.commit` is the first 12 characters of the commit (the same as a `go build` in a
git checkout) and `main.date` is the commit date.

## Branches and releases

```text
feature branch --PR--> dev --release PR (merge commit)--> main --tag vX.Y.Z--> release
```

- `dev` is the default branch. Clone it, branch from it and open your PR against it.
- `main` is the release branch. Only the maintainer merges `dev` into `main`, with a PR and a
  merge commit (not a squash, so the two histories stay joined).
- Release tags go on `main` only. The release workflow fails for a tag that is not on the
  first-parent history of `main`.
- Hotfix: branch from `main`, open the PR against `main`, then open a PR from `main` into `dev` and
  merge it with a merge commit (not a squash, or the histories stop joining).
- Both branches need a PR, the checks `test (ubuntu-latest)` and `test (macos-latest)`, and allow no
  force push and no delete. `main` also needs the checks `offline` and `release-check`, and allows
  merge commits only. `dev` allows merge commits too, for the hotfix merge-back.
- Dependabot and the dependency graph watch the default branch, so a security update lands on `dev`.
  After you merge one, cut a release soon, so that the released code on `main` gets the fix. The
  weekly `govulncheck` workflow also checks the released code on `main`, so a new advisory shows up
  before the next release.

## Pull requests

- One change per pull request. A new rule is a good size.
- Reference the issue and the PRD IDs (for example `FR-09`, `T1`) in the description.
- Code style, dependencies, telemetry, commits and branch names: see the Code style and Git and pull
  requests sections of [.agents/project.md](.agents/project.md).
- Every PR either updates its owner doc (listed in [docs/README.md](docs/README.md)) or says "No doc
  change needed because ..." in the PR.
- A behaviour change is a change to flags, output, exit codes, rules, package layout, CLI commands,
  the gate commands in Checks or security-relevant behaviour. A PR with a behaviour change and neither a doc update nor that sentence
  is not ready.
- A "No doc change needed because ..." reason is real when the diff has no behaviour change, or when
  the owner doc already states the new behaviour. A reason from an issue or a PR body is a claim:
  check it against the diff. A change to security-relevant behaviour always needs an owner-doc
  update, whatever the reason says, and even when the owner doc already states the behaviour. In that
  case, update at least its status line or its wording.

## Releasing

This section is for maintainers. [docs/releasing.md](docs/releasing.md) has the one-time setup, the
steps to cut a release and the checks after it. The branch rules are in
[Branches and releases](#branches-and-releases).

## Security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[Apache-2.0 License](LICENSE).
