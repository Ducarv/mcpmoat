# Demo GIF

`demo.gif` is a terminal recording of `mcpmoat scan`. [vhs](https://github.com/charmbracelet/vhs)
makes it from `demo.tape`. `setup.sh` builds the binaries and writes a fake home for the recording.

## What the demo shows

The demo config has four stdio servers. Each one is a test fixture:

| Server | Fixture |
|---|---|
| `notes` | `poisoned` |
| `math` | `shadowing` |
| `mailer` | `mailer` |
| `clock` | `rugpull` |

Scene 1 is the first scan. It finds T1 tool poisoning on `notes` and T3 shadowing on `math`, for
example `MOAT-T3-001`. The `pinned N tools` lines show that the first scan pins the tools of each
server. `mailer` shows no finding. It is the target of the cross-server shadowing check, and `scan`
does not run that check yet (#200). For the rule IDs of each fixture, see
[testdata/servers/README.md](../../testdata/servers/README.md).

Scene 2 is the rug pull. `demo_flip` makes `clock` serve a changed `get_time` tool. The second scan
reports `MOAT-T2-001` (rug pull) on `clock`/`get_time` and shows the old and new description.

## Safety

- The servers are inert test fixtures. Their malicious text is data only. See
  [testdata/servers/README.md](../../testdata/servers/README.md).
- `setup.sh` sets `HOME`, `XDG_CONFIG_HOME` and `XDG_CACHE_HOME` to a fake home in a new folder
  `~/.cache/mcpmoat-demo.*` (or `$XDG_CACHE_HOME/mcpmoat-demo.*` when `XDG_CACHE_HOME` is an
  absolute path). The demo does not touch your real home or your real client configs.
- The cache folder must be private. If other users can write to it, the demo is not safe.
  `setup.sh` refuses a cache folder that group or others can write to. It does not check the owner
  or the parent folders. That follow-up is not done yet.
- Only the `mcpmoat` binary goes on `PATH`, in `$MCPMOAT_DEMO_DIR/bin`. The config starts the
  fixtures by absolute path.
- The scans make no network call. The first `go build` in `setup.sh` can download Go modules or a
  Go toolchain.

## Requirements

- Go, at the version in `go.mod`.
- vhs 0.12 or later, with `ttyd` and `ffmpeg`. On macOS, `brew install vhs` installs all three.
- Record on a single-user machine. vhs runs ttyd, a local terminal server, for the recording.

## Regenerate the GIF

Regenerate the GIF before a release, or when the GIF no longer matches the scan output. Each new
GIF adds about 260 KB to the git history.

From the repo root, on macOS or Linux:

```sh
vhs docs/demo/demo.tape
```

Use the repo root because `mcpmoat scan` also reads project configs in the current folder
(`.mcp.json`, `.cursor/mcp.json`, `.claude/settings*.json`). The repo root has none.

vhs writes `docs/demo/demo.gif`. The first run builds mcpmoat and the fixture servers. With a cold Go
build cache this takes some time. The tape waits up to 120 s for it. The tape ends with a hidden
`demo_cleanup`.

If the build fails, or you press Ctrl-C during the build, `setup.sh` removes the demo folder and
leaves your shell and environment as they were.

If the vhs run fails, for example on a `Wait` timeout, a `mcpmoat-demo.*` folder can stay in the
cache folder. Make sure that no demo is active in a shell, then remove it:

```sh
rm -rf ~/.cache/mcpmoat-demo.*   # or "$XDG_CACHE_HOME"/mcpmoat-demo.*
```

When you source `setup.sh` by hand, it prints the folder path in its `mcpmoat demo folder:` line.

Keep the GIF short: under 30 s and a few hundred KB. Check the size and the length before you
commit it.

## Shell functions

You must source `setup.sh`, not run it: `source docs/demo/setup.sh`. It works in bash and zsh. It
defines two shell functions for the tape:

- `demo_flip` starts `clock` as `rugpull -variant injected`.
- `demo_cleanup` removes the demo folder and restores `HOME`, `PATH` and the `XDG_*` variables.

## Why the demo folder is not in /tmp

mcpmoat refuses to make its run folder below a folder that other users can write to, such as
`/tmp`. So `setup.sh` puts the demo folder below your private user cache. The E2E tests have the
same need. See [CONTRIBUTING.md](../../CONTRIBUTING.md#checks).
