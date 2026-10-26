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
`goreleaser/v2@` command in this file. The `release-check` CI job fails if they differ. Then build a
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

If you change `.goreleaser.yaml`, also run these checks. A snapshot build needs no token and
publishes nothing. It writes the archives to `dist/`. The last script needs `jq`, and it runs on
Linux and macOS.

```sh
go run github.com/goreleaser/goreleaser/v2@v2.19.0 check                       # config is valid
go run github.com/goreleaser/goreleaser/v2@v2.19.0 release --snapshot --clean  # build all archives
.github/scripts/check-snapshot.sh                                              # check the archives
```

Agent-oriented variants (scoped tests, E2E scenario, golden files, fuzz) are in the Commands table of
[.agents/project.md](.agents/project.md#commands).

`go.mod` lists the dependencies. Do not change it unless your change needs a new module.

CI (`.github/workflows/ci.yml`) runs on every pull request. On Linux and macOS it runs build, vet, race
tests, golangci-lint and the version smoke test. On Linux only it also runs the gofmt check, the
`go mod tidy` check and govulncheck. The `release-check` job runs `.github/scripts/check-tool-pins.sh`.
The script checks that the GoReleaser pins match. It also checks that the govulncheck pins in
`ci.yml`, `release.yml` and `govulncheck.yml` match, and that each file runs govulncheck only
through `$GOVULNCHECK_VERSION`. Then the job runs `goreleaser check`, a snapshot build and
`.github/scripts/check-snapshot.sh`. To run the pin check on your machine, call
`.github/scripts/check-tool-pins.sh`. The test of the script is `.github/scripts/check-tool-pins-test.sh`.

The weekly `govulncheck` workflow (`.github/workflows/govulncheck.yml`) checks `main` every Monday.
A maintainer finds how to run it by hand and what to do after a failed run in
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
