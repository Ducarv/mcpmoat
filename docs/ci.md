# Using mcpmoat in CI and git hooks

Run `mcpmoat scan --no-connect` on the MCP config of a repository, so that a dangerous change to
`.mcp.json` fails a pull request or a commit. With `--no-connect`, mcpmoat checks the config only.
It starts no server, opens no connection and reads no `pins.json`, so the job needs no saved state.
It also does not read `.mcpmoat-ignore` unless you add `--use-ignore-file`, so a pull request cannot
hide a finding with that file (see [Security notes](#security-notes)).

The examples scan a Claude Code project config, `.mcp.json`, in the root of the repository. The
GitHub Actions workflow also scans a Cursor project config, `.cursor/mcp.json`. For another file,
change the `--config` value.

## GitHub Actions

Save this as `.github/workflows/mcpmoat.yml`:

```yaml
name: mcpmoat

on:
  pull_request:
    paths:
      - '.mcp.json'
      - '.cursor/mcp.json'
      - '.mcpmoat-ignore'

permissions:
  contents: read

jobs:
  mcpmoat-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Set up Go
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version: '1.27'
          # A repository without go.sum has nothing to cache.
          cache: false

      - name: Install mcpmoat
        # This pins a release tag, and the Go checksum database checks it.
        run: go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@v0.2.0

      # The install runs before the checkout, so it never runs in the tree of
      # the pull request.
      - name: Check out the code
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Scan .mcp.json
        # A pull request that deletes .mcp.json has nothing to scan.
        if: hashFiles('.mcp.json') != ''
        run: mcpmoat scan --no-connect --config .mcp.json

      - name: Scan .cursor/mcp.json
        # Keep this step also when your repository has no .cursor/mcp.json:
        # a pull request can add one, and Cursor loads it. !cancelled() runs
        # it also when the step above failed, so you see both reports.
        if: ${{ !cancelled() && hashFiles('.cursor/mcp.json') != '' }}
        run: mcpmoat scan --no-connect --config .cursor/mcp.json
```

`setup-go` adds `$(go env GOPATH)/bin` to `PATH`, so the `mcpmoat` command works in the next step.
The `paths` filter runs the job only when a pull request changes `.mcp.json`, `.cursor/mcp.json`
or `.mcpmoat-ignore`. The job reads `.mcpmoat-ignore` only when you add `--use-ignore-file` to
`mcpmoat scan`. If you make the job a required check, remove the filter: GitHub keeps a required
check that did not run in the pending state.

`--config` reads a file in a folder named `.cursor` as a Cursor config, and the repository root
is its project.

## A plain git hook

Run this in the root of your repository. It saves the hook and makes it executable. If a
pre-commit hook (or a symlink with that name) already exists, it changes nothing and prints a
message:

```sh
hook=$(git rev-parse --git-path hooks)/pre-commit
if [ -e "$hook" ] || [ -L "$hook" ]; then
  echo "$hook exists; add the mcpmoat line to it" >&2
else
  cat > "$hook" <<'EOF'
#!/bin/sh
# Scan the MCP config with mcpmoat before each commit.
if [ ! -f .mcp.json ]; then
  exit 0
fi
exec mcpmoat scan --no-connect --config .mcp.json
EOF
  chmod +x "$hook"
fi
```

If you already have a pre-commit hook, add this line to it, after the first line (`#!/bin/sh`):

```sh
if [ -f .mcp.json ]; then mcpmoat scan --no-connect --config .mcp.json || exit $?; fi
```

`git rev-parse --git-path hooks` finds the hooks folder also in a linked worktree or a submodule.
When `core.hooksPath` is set, it gives that folder, and the folder must exist.

The hook needs `mcpmoat` on `PATH`. It exits with code 0 when there is no `.mcp.json`. Else it
exits with the exit code of mcpmoat, so a code that is not 0 stops the commit. To change the
threshold, add `--fail-on` to the last line of the hook. For example, `--fail-on medium` also
stops a commit for a medium finding:

```sh
exec mcpmoat scan --no-connect --config .mcp.json --fail-on medium
```

Do not use `--fail-on critical`: no built-in rule is critical yet, so it passes every built-in
finding (see [Exit codes](exit-codes.md)).

`git commit --no-verify` skips the hook. So the hook helps you, but it does not replace the CI job.

## pre-commit framework

For the [pre-commit](https://pre-commit.com/) framework, add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: mcpmoat
        name: mcpmoat scan
        # A commit that changes only .mcpmoat-ignore can run the hook when
        # there is no .mcp.json. Then there is nothing to scan.
        entry: sh -c '[ ! -f .mcp.json ] || exec mcpmoat scan --no-connect --config .mcp.json "$@"' --
        language: system
        pass_filenames: false
        files: ^(\.mcp\.json|\.mcpmoat-ignore)$
```

Run `pre-commit install` once in the repository, so that the hook runs on each `git commit`. To
test the hook now, run `pre-commit run --all-files`.

`language: system` runs the `mcpmoat` command from your `PATH`, so install mcpmoat first. The hook
runs only when the commit changes `.mcp.json` or `.mcpmoat-ignore`. To change the threshold, add
`args: [--fail-on, medium]` to the hook. The `"$@"` and the trailing `--` in `entry` pass the
`args` to `mcpmoat scan`. Keep both. Without the trailing `--`, the first arg becomes `$0` of the
shell and is lost, so `args: [--fail-on, medium]` would run `mcpmoat scan ... medium`.

pre-commit shows the output of a hook only when the hook fails. To see the findings each time, add
`verbose: true` to the hook.

To skip the install step, use the remote hook instead:

```yaml
repos:
  - repo: https://github.com/Ducarv/mcpmoat
    rev: <tag>   # v0.2.0 or a newer release tag, or the full commit SHA of such a tag
    hooks:
      - id: mcpmoat
```

v0.2.0 is the first release tag with the hook file (`.pre-commit-hooks.yaml`). v0.1.0 does not
have it. The remote hook builds the `mcpmoat` binary with Go (`language: golang`). You do not need
Go on the `PATH`. When pre-commit finds no `go` command, it downloads the latest stable Go
toolchain into its own cache, so the first run needs network access and takes longer. If you want
a fixed toolchain, put a Go that you chose on `PATH`. The remote hook has the same `entry` and
`files` as the local hook. It runs only when the commit changes `.mcp.json` or `.mcpmoat-ignore`.
It skips when `.mcp.json` is missing. It blocks at the default `--fail-on high`. It takes `args` in
the same way as the local hook. Do not put `--no-connect=false` in `args`: the hook would then start
the stdio servers that `.mcp.json` lists. Use the local hook when you manage the `mcpmoat` binary
yourself.

A tag in `rev` can move, and pre-commit has no checksum database for it. The hook builds and runs
the code of that `rev` on each developer machine. To pin it, use a full commit SHA in `rev`
instead of a tag. The command `pre-commit autoupdate --freeze` does this.

Both pre-commit hooks scan only the `.mcp.json` file in the root of the repository. They do not scan other
client configs such as `.cursor/mcp.json`, and they do not scan a `.mcp.json` in a subfolder. To
scan those files, use the CI job.

## Exit codes and --fail-on

`mcpmoat scan` exits with 0, 1 or 2, and `--fail-on` sets the lowest severity that gives 1. The
contract is in [Exit codes](exit-codes.md). In CI, treat every code that is not 0 as a
failure. Never allow exit code 2: it means that the scan did not finish, so a clean result is not
known.

## Security notes

- Keep `--no-connect` in CI. `scan` reads the `--config` file as an untrusted project file, and the
  file comes from the pull request. With `--no-connect`, no server process starts from that
  content.
- `scan` does not read `.mcpmoat-ignore` by default. So a pull request cannot add or change that
  file to hide findings and turn exit code 1 into 0. If you add `--use-ignore-file` to the job, the
  file applies, and a pull request can change it. Use the flag only with a file that you guard. A
  pull request can also edit the workflow file: with `pull_request`, the run uses the workflow of
  the pull request, so it can add `--fail-on critical`, `--use-ignore-file` or `|| true`. Review
  changes to these files like code, and let GitHub enforce it. Add a `CODEOWNERS` entry for them,
  turn on "Require review from Code Owners" in the branch protection rule, and make the job a
  required check:

  ```text
  # .github/CODEOWNERS
  /.mcp.json           @example-org/security
  /.cursor/mcp.json    @example-org/security
  /.mcpmoat-ignore     @example-org/security
  /.github/            @example-org/security
  ```

  The entry covers the whole `.github/` folder: `CODEOWNERS`, the workflows and local actions such
  as `.github/actions/`. A pull request can also add a new workflow with a job of the same name
  that always passes. When you add the required check `mcpmoat-scan`, choose GitHub Actions as its
  source, so that another app cannot report a check with the same name.

- Without `--use-ignore-file`, `scan` prints
  `mcpmoat scan: note: .mcpmoat-ignore is not read; it can hide findings. Add --use-ignore-file only if you trust it` on stderr
  when the file is there. With the flag, when the file gives entries, `scan` prints
  `mcpmoat scan: using N entries from .mcpmoat-ignore` (or `using 1 entry`) on stderr. Look for
  these lines in the job log.
- The plain git hook scans the file in the working tree, not the staged version. If you stage only
  a part of your changes, the hook can check other text than the commit holds. The pre-commit
  framework hides the changes that are not staged while the hooks run, so it checks the staged
  version. Untracked files still apply. For example, when you add `--use-ignore-file` to the hook, a
  local `.mcpmoat-ignore` that you did not stage still applies.

## Try it

The fixture in [testdata/ci/](../testdata/ci/README.md) is a small example repository. Scan it
only with `--no-connect`. Never open its folder in an MCP client, and never approve its servers.
From the root of the mcpmoat repository, copy it to a temporary folder and scan it:

```sh
dir=$(mktemp -d)
cp testdata/ci/repo/.mcp.json "$dir/"
cd "$dir"
mcpmoat scan --no-connect --config .mcp.json
echo "exit code: $?"
```

The exit code is 1. [testdata/ci/README.md](../testdata/ci/README.md) lists the findings of each
server. To try the plain git hook, run `git init` in the same folder, run the block from
[A plain git hook](#a-plain-git-hook), then run `"$hook"`.
