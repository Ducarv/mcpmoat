# Test fixture: dangerous config (T4)

**This is a TEST FIXTURE. Do not use it as a real config.**

It is a Cursor config (`home/.cursor/mcp.json`) with unsafe settings. It
checks the static config rules of threat T4. All secrets in it are synthetic
canaries. They are not real credentials. The servers do not exist, and the
tests only read the config, so they make no network calls.

Use this home only with `--no-connect`. As a second guard, every name in it
points at the reserved `.invalid` top-level domain (RFC 2606), which never
resolves: the remote URL host is `mcp.example.invalid`, the npx entries pass
`--registry https://registry.invalid/`, and the docker image is
`registry.invalid/example/mcp-server`. The pinned docker image is
`registry.invalid/example/server@sha256:...` and the `remote-url-secret` host
is `mcp.example.invalid`. So a scan that connects by mistake fetches nothing
and sends the canary header nowhere.

The two npx git specs use `git+https://git.invalid/example/example-server.git`.
The host `git.invalid` never resolves. So every host in this fixture is
`.invalid` or `example.invalid`, with no exception. No network call happens,
because the fixture is read with `--no-connect` and nothing fetches the package.

| Server | Expected rule IDs |
|---|---|
| `remote-plain` | `MOAT-T4-001` (`http://` remote); `MOAT-T4-002` (header `X-Api-Key` holds a plaintext secret) |
| `remote-local` | none (loopback `http://` is allowed) |
| `env-secret` | `MOAT-T4-002` (env `GITHUB_TOKEN` holds a plaintext token); `MOAT-T4-004` (npx `-y` before the package spec) |
| `latest-pkg` | `MOAT-T4-003` (`@latest` package); `MOAT-T4-004` (npx `-y` before the package spec) |
| `docker-untagged` | `MOAT-T4-003` (docker image without a tag) |
| `docker-arg-secret` | `MOAT-T4-002` (field `args`: the arg `-e SOME_API_TOKEN=...` holds a literal secret, a synthetic value) |
| `remote-url-secret` | `MOAT-T4-002` (field `url`: the query `api_key` holds a literal secret, a synthetic value) |
| `npx-git-unpinned` | `MOAT-T4-003` (git spec with no commit pin); `MOAT-T4-004` (`npx -y`) |
| `npx-git-pinned` | `MOAT-T4-004` (`npx -y`) |

No other rule must fire. In particular:

- `remote-plain` header `Authorization` is a `${env:API_TOKEN}` reference, not a secret.
- `env-secret` env `API_KEY` is a `${env:API_KEY}` reference, and `LOG_LEVEL` is not a secret.
- `env-secret` runs a pinned package (`@example-corp/notes-mcp@1.2.3`).
- `docker-arg-secret` pins its image by digest, so there is no `MOAT-T4-003`.
- `remote-url-secret` uses `https://`, so there is no `MOAT-T4-001`.
- `npx-git-pinned` pins a full 40-hex commit, so there is no `MOAT-T4-003`.

Layout is the same as `testdata/discover/cursor/*/home`, so
`discovertest.CopyFixture` and `discover.ReadCursor` can read it.
