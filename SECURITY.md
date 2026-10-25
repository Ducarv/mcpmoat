# Security policy

## Reporting a vulnerability

Please report security vulnerabilities in mcpmoat **privately** through GitHub Security Advisories:

1. Go to the [Security tab](https://github.com/Ducarv/mcpmoat/security) of this repository.
2. Click **Report a vulnerability**.
3. Describe the issue, the affected version or commit, and the steps to reproduce it.

**Do not open a public issue for a security bug.**

You can expect an acknowledgement within 7 days. We will keep you informed while we work on a fix
and credit you in the advisory unless you ask us not to.

## What counts as a vulnerability in mcpmoat

Examples of issues we want to hear about privately:

- mcpmoat leaks a secret from a client config (for example in output, logs or the pins file).
- mcpmoat passes secrets from your shell environment to a server it starts.
- mcpmoat runs a different command than the one in the client config.
- A crafted tool description or config makes mcpmoat hang, crash or run code.
- mcpmoat makes a network connection that is not to a configured server or (with `--llm`) the LLM
  provider.
- A problem in the release supply chain (checksums, attestations, the Homebrew cask in the tap).
  Release archives and `checksums.txt` carry GitHub artifact attestations. Verify an archive with
  `gh attestation verify <archive> -R Ducarv/mcpmoat --signer-workflow
  Ducarv/mcpmoat/.github/workflows/release.yml`. The macOS binaries are not notarized yet, and the
  cask removes the quarantine flag on install, so Gatekeeper does not check the binary. Verify the
  archive if that matters to you.

## What is not a vulnerability

A malicious MCP server that mcpmoat does **not** detect is a false negative, not a vulnerability in
mcpmoat. Please open a normal issue or, better, contribute a rule (see
[CONTRIBUTING.md](CONTRIBUTING.md)). If the detection gap itself is sensitive, use a private report.

## Supported versions

Before `v1.0.0`, only the latest release gets security fixes.
