# Using mcpmoat in CI and git hooks

Run `mcpmoat scan --no-connect` on the MCP config of a repository, so that a dangerous change to
`.mcp.json` fails a pull request or a commit. With `--no-connect`, mcpmoat checks the config only.
It starts no server, opens no connection and reads no `pins.json`, so the job needs no saved state.

The examples scan a Claude Code project config, `.mcp.json`, in the root of the repository. For
another file, change the `--config` value.

## GitHub Actions

Save this as `.github/workflows/mcpmoat.yml`:

```yaml
name: mcpmoat

on:
  pull_request:
    paths:
      - '.mcp.json'
      - '.mcpmoat-ignore'

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Check out the code
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Set up Go
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version: '1.27'
          # A repository without go.sum has nothing to cache.
          cache: false

      - name: Install mcpmoat
        # There is no tagged release yet. For a reproducible build, replace
        # @latest with a commit SHA of github.com/Ducarv/mcpmoat.
        run: go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@latest

      - name: Scan .mcp.json
        # A pull request that deletes .mcp.json has nothing to scan.
        if: hashFiles('.mcp.json') != ''
        run: mcpmoat scan --no-connect --config .mcp.json
```

`setup-go` adds `$(go env GOPATH)/bin` to `PATH`, so the `mcpmoat` command works in the next step.
The `paths` filter runs the job only when a pull request changes `.mcp.json` or `.mcpmoat-ignore`.
If you make the job a required check, remove the filter: GitHub keeps a required check that did
not run in the pending state.

## A plain git hook

Run this in the root of your repository. It saves the hook and makes it executable:

```sh
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/sh
# Scan the MCP config with mcpmoat before each commit.
if [ ! -f .mcp.json ]; then
  exit 0
fi
exec mcpmoat scan --no-connect --config .mcp.json
EOF
chmod +x .git/hooks/pre-commit
```

The hook needs `mcpmoat` on `PATH`. It exits with code 0 when there is no `.mcp.json`. Else it
exits with the exit code of mcpmoat, so a code that is not 0 stops the commit. To change the
threshold, add `--fail-on` to the last line of the hook:

```sh
exec mcpmoat scan --no-connect --config .mcp.json --fail-on critical
```

No built-in rule is critical today, so with `--fail-on critical` this git hook shows the findings
but never stops a commit for them.

`git commit --no-verify` skips the hook. So the hook helps you, but it does not replace the CI job.

## pre-commit framework

For the [pre-commit](https://pre-commit.com/) framework, add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: mcpmoat
        name: mcpmoat scan
        entry: mcpmoat scan --no-connect --config .mcp.json
        language: system
        pass_filenames: false
        files: ^(\.mcp\.json|\.mcpmoat-ignore)$
```

Run `pre-commit install` once in the repository, so that the hook runs on each `git commit`. To
test the hook now, run `pre-commit run --all-files`.

`language: system` runs the `mcpmoat` command from your `PATH`, so install mcpmoat first. The hook
runs only when the commit changes `.mcp.json` or `.mcpmoat-ignore`. To change the threshold, add
`--fail-on` to `entry`. pre-commit shows the output of a hook only when the hook fails. To see the
findings each time, add `verbose: true` to the hook. A remote hook (`repo: https://github.com/Ducarv/mcpmoat`)
comes after the first tagged release.

## Exit codes and --fail-on

`mcpmoat scan` exits with 0, 1 or 2, and `--fail-on` sets the lowest severity that gives 1. The
contract is in [README.md](../README.md#exit-codes). In CI, treat every code that is not 0 as a
failure. Never allow exit code 2: it means that the scan did not finish, so a clean result is not
known.

## Security notes

- Keep `--no-connect` in CI. `scan` reads the `--config` file as an untrusted project file, and the
  file comes from the pull request. With `--no-connect`, no server process starts from that
  content.
- A pull request can add or change `.mcpmoat-ignore` to hide config findings and turn exit code 1
  into 0. Review changes to that file like code. When the file gives entries, `scan` prints
  `mcpmoat scan: using N entries from .mcpmoat-ignore` (or `using 1 entry`) on stderr. Look for
  this line in the job log.
- The plain git hook scans the file in the working tree, not the staged version. If you stage only
  a part of your changes, the hook can check other text than the commit holds. The pre-commit
  framework hides the changes that are not staged while the hooks run, so it checks the staged
  version.
- `--fail-on critical` never fails today, because no built-in rule is critical. Not even a rug pull
  fails with it (`MOAT-T2-001` is high).

## Try it

The fixture in [testdata/ci/](../testdata/ci/README.md) is a small example repository. From the root
of the mcpmoat repository, copy it to a temporary folder and scan it:

```sh
dir=$(mktemp -d)
cp testdata/ci/repo/.mcp.json "$dir/"
cd "$dir"
mcpmoat scan --no-connect --config .mcp.json
echo "exit code: $?"
```

[testdata/ci/README.md](../testdata/ci/README.md) lists the findings and the exit code for each
`--fail-on` and `--ignore` value. To try the plain git hook, run `git init` in the same folder, then
run the commands from [A plain git hook](#a-plain-git-hook) and `.git/hooks/pre-commit`.
