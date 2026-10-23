# Test fixture: dangerous config (T4)

**This is a TEST FIXTURE. Do not use it as a real config.**

It is a Cursor config (`home/.cursor/mcp.json`) with unsafe settings. It
checks the static config rules of threat T4. All secrets in it are synthetic
canaries. They are not real credentials. The servers do not exist, and the
tests only read the config, so they make no network calls.

Use this home only with `--no-connect`. The package and image names
(`@example-corp/*`, `example/mcp-server`) are names that anyone can register,
so a scan that connects would fetch and run them, and would send the canary
header to `mcp.example.com`.

| Server | Expected rule IDs |
|---|---|
| `remote-plain` | `MOAT-T4-001` (`http://` remote); `MOAT-T4-002` (header `X-Api-Key` holds a plaintext secret) |
| `remote-local` | none (loopback `http://` is allowed) |
| `env-secret` | `MOAT-T4-002` (env `GITHUB_TOKEN` holds a plaintext token) |
| `latest-pkg` | `MOAT-T4-003` (`@latest` package) |
| `docker-untagged` | `MOAT-T4-003` (docker image without a tag) |

No other rule must fire. In particular:

- `remote-plain` header `Authorization` is a `${env:API_TOKEN}` reference, not a secret.
- `env-secret` env `API_KEY` is a `${env:API_KEY}` reference, and `LOG_LEVEL` is not a secret.
- `env-secret` runs a pinned package (`@example-corp/notes-mcp@1.2.3`).

Layout is the same as `testdata/discover/cursor/*/home`, so
`discovertest.CopyFixture` and `discover.ReadCursor` can read it.
