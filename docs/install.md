# Install

This page lists the ways to install mcpmoat, how to check the version and how to verify a release
download.

- Homebrew (macOS and Linux): `brew install --cask Ducarv/tap/mcpmoat`. The tap gets stable
  releases only, not prereleases. The macOS binaries are not notarized yet: see
  [Verify a download](#verify-a-download).
- GitHub Releases: download the archive for your system from the
  [releases page](https://github.com/Ducarv/mcpmoat/releases). The archives are
  `mcpmoat_<version>_<os>_<arch>.tar.gz` for `darwin` or `linux` and `amd64` or `arm64`.
  `<version>` is the release number without the `v`, for example `1.0.0`. Each archive holds the
  `mcpmoat` binary, `LICENSE` and `README.md`. The Linux binary is static. The macOS binary links
  only macOS system libraries, like every Go binary on macOS. Extract the binary and put it on your
  `PATH`.
- Go: `go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@v1.0.0`. It needs Go 1.27 or later (see
  [go.mod](../go.mod)).

`@latest` builds the latest tagged release, and `@main` builds the latest commit on `main`. A tag
or one commit gives a repeatable install, as in CI: see [Using mcpmoat in CI](ci.md#github-actions).

Run `mcpmoat version` to check the install. A release binary prints
`mcpmoat v<version> (commit <c>, built <d>)`. `<d>` is the commit date, not the build time, so the
same commit always gives the same binary. A `go install` build, whatever the `@version`, prints
`commit none, built unknown`, because `go install` builds from the Go module cache, which has no git
data.

## Verify a download

Each release has a `checksums.txt` file. Download it to the same folder as the archive, then check
the archive. This step only catches a broken download. It does not prove where the archive came
from.

```sh
shasum -a 256 --ignore-missing -c checksums.txt   # macOS
sha256sum --ignore-missing -c checksums.txt       # Linux
```

The real check is the build provenance attestation of the archive. Check it with the
[GitHub CLI](https://cli.github.com/). The first command gets the commit that the tag points at:

```sh
sha=$(gh api repos/Ducarv/mcpmoat/commits/refs/tags/v<version> -q .sha)
gh attestation verify mcpmoat_<version>_<os>_<arch>.tar.gz -R Ducarv/mcpmoat \
  --cert-identity https://github.com/Ducarv/mcpmoat/.github/workflows/release.yml@refs/tags/v<version> \
  --source-ref refs/tags/v<version> --source-digest "$sha" --deny-self-hosted-runners
```

The check proves which repo, workflow, tag and commit built the archive. It does not prove that the
code was reviewed. Use `--cert-identity` as above, not `--signer-workflow`: some `gh` versions match
`--signer-workflow` as a prefix only, so `release.yml` would also match another workflow file
whose name starts with `release.yml`.

Homebrew does not check the attestation. `brew install` checks only the sha256 values in the cask
from the tap. A cask is Ruby code that Homebrew runs on install, so matching sha256 values alone do
not prove that the cask is safe. To check the cask, first verify `checksums.txt`:

```sh
gh attestation verify checksums.txt -R Ducarv/mcpmoat \
  --cert-identity https://github.com/Ducarv/mcpmoat/.github/workflows/release.yml@refs/tags/v<version> \
  --source-ref refs/tags/v<version> --source-digest "$sha" --deny-self-hosted-runners
```

Then open `Casks/mcpmoat.rb` in the [tap](https://github.com/Ducarv/homebrew-tap) and check these
points:

- The `version` line is the release number without the `v`, for example `"1.0.0"`.
- Each `url` is exactly
  `https://github.com/Ducarv/mcpmoat/releases/download/v#{version}/mcpmoat_#{version}_<os>_<arch>.tar.gz`.
  `<os>` is `darwin` in the `on_macos` block and `linux` in the `on_linux` block. `<arch>` is
  `arm64` in the `on_arm` block and `amd64` in the `on_intel` block. Homebrew fills in `#{version}`
  from the `version` line.
- `#{version}` is the only `#{` in the file. In Ruby, any other `#{...}` in a string runs code when
  Homebrew loads the cask.
- Each `sha256` is a literal hex string of 64 characters. It is the hash on the `checksums.txt` line
  for the archive that the `url` in the same block names.
- The only block that runs a command is `postflight_steps`. It holds one `on_macos` block with one
  `xattr` line that removes the quarantine flag from `mcpmoat`.
- There is no other code. The cask holds only these parts:
  - `version`
  - `on_macos` and `on_linux`, each with an `on_arm` and an `on_intel` block that holds `url` and
    `sha256`
  - `name`, `desc` and `homepage`
  - `livecheck`, with one `skip` line
  - `binary`
  - `postflight_steps`

The macOS binaries are not notarized yet. The Homebrew cask removes the quarantine flag on install,
so Gatekeeper does not check the binary. Verify the archive if that matters to you.

## See also

- [Using mcpmoat in CI and git hooks](ci.md)
- [Releasing](releasing.md) (for maintainers)
