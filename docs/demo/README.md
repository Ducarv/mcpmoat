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

Scene 1 is the first scan. `mcpmoat scan` finds T1 tool poisoning on `notes`. On `math` it finds
MOAT-T1-003, MOAT-T1-005 and MOAT-T3-001 (T3 shadowing). The `pinned N tools` lines show that the
first scan pins the tools of each server.

Scene 2 is the rug pull. `demo_flip` makes `clock` serve a changed `get_time` tool. The second scan
reports MOAT-T2-001 (rug pull) on `clock`/`get_time` and shows the old and new description.

## Safety

- The servers are inert test fixtures. Their malicious text is data only. See
  [testdata/servers/README.md](../../testdata/servers/README.md).
- `setup.sh` sets `HOME`, `XDG_CONFIG_HOME` and `XDG_CACHE_HOME` to a fake home in a new folder
  `~/.cache/mcpmoat-demo.*` (or `$XDG_CACHE_HOME/mcpmoat-demo.*` when `XDG_CACHE_HOME` is an
  absolute path). The demo does not touch your real home or your real client configs.
- Only the `mcpmoat` binary goes on `PATH`, in `$DEMO_DIR/bin`. The config starts the fixtures by
  absolute path.
- The demo makes no network call.

## Requirements

- Go, at the version in `go.mod`.
- vhs 0.12 or later, with `ttyd` and `ffmpeg`. On macOS, `brew install vhs` installs all three.

## Regenerate the GIF

From the repo root, on macOS or Linux:

```sh
vhs docs/demo/demo.tape
```

Use the repo root because `mcpmoat scan` also reads project configs in the current folder
(`.mcp.json`, `.cursor/mcp.json`, `.claude/settings*.json`). The repo root has none.

vhs writes `docs/demo/demo.gif`. The first run builds mcpmoat and the fixture servers. With a cold Go
build cache this takes some time. The tape waits up to 120 s for it. The tape ends with a hidden
`demo_cleanup`.

If the build fails, `setup.sh` removes the demo folder and leaves your shell and environment as they
were. If you press Ctrl-C during the build, a `mcpmoat-demo.*` folder can stay in the cache folder.
Remove it by hand.

Keep the GIF short: under 30 s and a few hundred KB. Check the size and the length before you
commit it.

Regenerate the GIF when the output of `scan` changes, or when a fixture gets a different rule ID.

## Shell functions

`setup.sh` defines two shell functions. The tape calls them.

- `demo_flip` writes the config again, with `clock` started as `rugpull -variant injected`. The
  next scan then sees a changed `get_time` tool.
- `demo_cleanup` removes the demo folder and restores `HOME`, `PATH`, `XDG_CONFIG_HOME` and
  `XDG_CACHE_HOME`. It removes only a direct child `mcpmoat-demo.*` of the cache folder, and
  refuses any other path.

Both functions refuse to run when no demo is active. While a demo is active, `setup.sh` refuses a
second `source`. Run `demo_cleanup` first.

## Why the demo folder is not in /tmp

mcpmoat refuses to make its run folder below a folder that other users can write to, such as
`/tmp`. So `setup.sh` puts the demo folder below your private user cache. The E2E tests have the
same need. See [CONTRIBUTING.md](../../CONTRIBUTING.md#checks).

`setup.sh` refuses the cache folder in these cases:

- Group or others can write to it. Fix it with `chmod go-w <folder>`.
- Its path has characters outside `[A-Za-z0-9/._ -]`. Set `XDG_CACHE_HOME` to a plain path.

A relative `XDG_CACHE_HOME` is ignored. `setup.sh` then uses `~/.cache`.
