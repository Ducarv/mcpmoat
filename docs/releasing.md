# Releasing

This page is for maintainers. The release workflow is `.github/workflows/release.yml`. The
GoReleaser config is `.goreleaser.yaml`.

## One-time setup

Do all of these steps before you push the first release tag. Step 3 says why.

1. Create the public repo `Ducarv/homebrew-tap`. GoReleaser writes the cask to its `Casks/` folder.
   Protect its default branch so that only the maintainer, who owns the token below, can push.
2. Create a fine-grained personal access token. Give it access to only `Ducarv/homebrew-tap`, with
   the Contents permission set to read and write. Give it an expiry of 90 days or less. Before it
   expires, make a new token and replace the secret in step 3.
3. In `Ducarv/mcpmoat`, create the GitHub environment `release`. Limit its deployment branches and
   tags to tags that match `v[0-9]*`. Add the maintainer as a required reviewer, so each release
   waits for approval. Add the token to it as the environment secret `HOMEBREW_TAP_GITHUB_TOKEN`. Do
   not make it a repository or organization secret: only jobs in the `release` environment can read
   an environment secret. If the environment does not exist, GitHub creates it on the first run,
   with no reviewer and no tag limit. The release job then stops before GoReleaser runs, because the
   secret is missing. A repository or organization secret with the same name hides a missing
   environment from that check.
4. Add a tag ruleset for `v[0-9]*` that restricts creations, updates and deletes. Let only the
   maintainer bypass it. Then only the maintainer can push, move or delete a release tag. After a
   release is published, Immutable releases (step 5) lock its tag for everyone.
5. In the settings of `Ducarv/mcpmoat`, turn on "Immutable releases". The workflow publishes a
   draft, so the assets lock when the release is published, after the attestations verify. The
   release job can check this only after the publish, because `GITHUB_TOKEN` cannot read the
   setting. So before each tag, check that `gh api repos/Ducarv/mcpmoat/immutable-releases` prints
   `"enabled":true`.
6. Protect the maintainer account: use 2FA or passkeys, keep no classic PATs with `repo` scope and
   no fine-grained tokens with Deployments or Administration write access on `Ducarv/mcpmoat`.

## Cut a release

Open a PR from `dev` to `main` and merge it with a merge commit, not a squash. Then tag that merge
commit on `main` and push the tag. A clone checks out `dev` and a local `main` can be old, so name
the commit and check it before you push:

```sh
git fetch origin
git tag v0.1.0 origin/main
git rev-list --first-parent origin/main | grep -Fx "$(git rev-parse 'v0.1.0^{commit}')"
git push origin v0.1.0
```

The `grep` prints the commit if it is on the first-parent history of `main`. If it prints nothing,
delete the local tag (`git tag -d v0.1.0`) and do not push it. A tag on the wrong commit that
reaches the Go module proxy stays there, and you lose that version number.

The tag starts the release workflow. The `test` job runs vet, the race tests and govulncheck. Then
the `release` job waits for the maintainer to approve it in the `release` environment. It fails if
the tagged commit is not on the first-parent history of `main`, or if the environment has no tap
secret. It builds the archives with GoReleaser, creates a draft GitHub release and pushes the cask
to the tap. Only the GoReleaser step gets the tap token. Then it attests the build provenance of
`dist/*.tar.gz` and `dist/checksums.txt`.

The next step checks that the build left `.github/scripts` unchanged, because the step after it runs
a script from the checkout with write permission. The step compares the folder with the tagged
commit, not with the index. It fails on any new file there, on a changed `verify-and-publish.sh`
(the check compares its bytes with the tagged commit, and ignores git replace refs and attribute
filters), and on a file that is marked assume-unchanged or skip-worktree. This is hardening, not a
boundary. The script `.github/scripts/release-guard-test.sh` tests this step in the `ci-scripts`
job. The step does not catch a build that does one of these things:

- It writes a git config: the repository config, the global config or the system config.
- It writes the index or the git object store (the files under `.git`).
- It writes `$GITHUB_PATH` or `$GITHUB_ENV`.
- It leaves a background process.
- It replaces a system program (`git`, `gh`, `bash`, `cmp`) or a tool config (the `gh` config, the
  sigstore cache). The runner user has passwordless `sudo` and a writable `$HOME`.

A separate publish job with a fresh checkout is the real fix, and issue #174 tracks it.

The next step, "Verify and publish the release", runs `.github/scripts/verify-and-publish.sh`. It
checks that the draft release holds exactly the files in `dist/*.tar.gz` and `dist/checksums.txt`.
It downloads them and checks that they match `dist/`. It verifies each attestation with
`gh attestation verify`. It checks that the tag still points at the commit that it built. Then it
publishes the release. Last, it checks that the release is immutable, and checks the tag and the
published files once more. The script `.github/scripts/verify-and-publish-test.sh` tests it with a
fake `gh`, with no network and no token. It runs in the `ci-scripts` job.

Try a prerelease tag first, for example `v0.1.0-rc.1`. GoReleaser marks it as a prerelease and does
not update the tap.

The workflow runs one release at a time. Push one tag, and push the next only after its run ends:
GitHub cancels a waiting run when a newer one queues behind it. Do not release an older version
after a newer one, for example a fix for an old minor line. Its run would point the tap at the older
version and mark it as the latest release.

After a stable release is published and verified (see [Verify a release](#verify-a-release)), open
a PR to `dev` that changes the version pins to the new tag:

- the `go install github.com/Ducarv/mcpmoat/cmd/mcpmoat@vX.Y.Z` lines in `README.md`,
  `docs/install.md` and `docs/ci.md`;
- the release link in the status line of `README.md`;
- the version examples in `docs/install.md`: the archive name and the cask `version` line.

Do not change them for a prerelease tag. Keep v0.2.0 in the pre-commit `rev` comment of
`docs/ci.md`: it names the first tag with the hook, not the latest one.

## Verify a release

Verify an archive and the tap cask with the steps in
[Verify a download](install.md#verify-a-download). Then check the install. For a stable tag, install from the
tap:

```sh
brew install --cask Ducarv/tap/mcpmoat
mcpmoat version
```

A prerelease tag does not update the tap. For an rc, extract the binary from the archive and run
`./mcpmoat version`.

Known limit: GoReleaser pushes the cask before the attest step runs. If a step before the publish
fails, the release stays a draft, so it is not public. But the cask is already in the tap, and its
URLs return 404 until the release is published. What to do depends on the cause:

- An external or transient cause, such as the tap token or the network: fix it and re-run the
  workflow. The re-run replaces the draft. Do not publish the draft by hand: only the workflow
  verifies the attestations before it publishes, and a published release cannot change.
- A cause in the code or config of the tagged commit: a re-run builds the same commit and fails
  again. Delete the draft, revert the tap commit, fix the cause on `dev`, merge `dev` into `main` and
  cut a new patch or rc tag.

If a check after the publish fails, the release is already public. Do not re-run the workflow: on a
release that is not immutable, a re-run uploads the assets again with no check. Check the release
with the steps in [Verify a download](install.md#verify-a-download). If it is wrong, delete it, revert the tap
commit and cut a new patch tag.

After any re-run of part of the workflow, check the tap's `Casks/mcpmoat.rb` with the cask steps in
[Verify a download](install.md#verify-a-download). Its sha256 values must match the draft's `checksums.txt`.

## Weekly vulnerability check

The `govulncheck` workflow (`.github/workflows/govulncheck.yml`) scans `main` every Monday at
06:17 UTC. It finds a new advisory against the released code between two releases. GitHub reads the
schedule only from the file on `dev`.

- To run it by hand, open the Actions tab and run it from `dev`. GitHub uses the workflow file of the
  branch that you pick. A run that you start by hand notifies you.
- A failed run, scheduled or started by hand, runs the job `notify-failure`. A timeout of the scan
  counts as a failure, and a timeout can end the scan as cancelled, so the job also runs when the
  scan job is cancelled. A run that you cancel by hand can also run it. The job cannot tell a
  timeout from a cancel by hand, so the issue body and the comment always say "failed or was
  cancelled".
- The job opens the issue "Weekly vulnerability check failed" with the `security` label. If an open
  issue with that exact title exists, the job adds a comment with the link to the run. So a check
  that fails every week adds comments to one issue. It does not open a new issue each week. One
  series of failures makes one issue.
- The job looks for the open issue by title and by the `security` label, so a stranger cannot hide
  the alert with an issue of the same title. This holds while only maintainers can add the label:
  do not let an issue form add `security` by itself, and do not label an issue from a stranger. The
  job does not check the author. It reads the newest 200 open issues with that label.
  If a maintainer removes the label from the open issue, the next failure opens a new issue. If the
  `security` label is deleted from the repo, the job fails and opens no issue: the red run is then
  the only signal.
- The job has the permission `issues: write` only, and it uses the `gh` CLI. The scan job keeps
  `contents: read`.
- The job uses one fixed concurrency group and does not cancel a run. GitHub keeps only one pending
  job in a group, so when three runs fail close together, the middle notice can be lost. The red
  runs still show.
- The script `.github/scripts/notify-failure-test.sh` tests this job in the `ci-scripts` job. See
  [Checks](../CONTRIBUTING.md#checks).
- GitHub sends the notice of a failed scheduled run only to the maintainer who last edited the cron
  line, or who enabled the workflow again. Keep GitHub Actions notifications on for that account.
  The issue makes the failure visible to everyone.
- After the fix, close the issue. The next failure opens a new issue.
- GitHub disables a schedule after 60 days with no repository activity. When you cut a release, open
  the `govulncheck` workflow in the Actions tab. If GitHub shows it as disabled, click Enable
  workflow. Then the failure notices go to you. A disabled schedule runs nothing, so no issue
  reports it. If it is enabled but the last run is more than 8 days old (one week plus one day), run
  it by hand and look for the reason.
- After a failed run, fix the cause on `dev`, merge `dev` into `main` and cut a release (see
  [Cut a release](#cut-a-release)).

## See also

- [Branches and releases](../CONTRIBUTING.md#branches-and-releases)
- [Verify a download](install.md#verify-a-download)
