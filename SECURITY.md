# Security policy

sovr-harvest signs txs with validator key material. Report security
problems privately. Do not open a public issue.

## How to report

1. Go to the [Security tab](https://github.com/sovrn-tech/sovr-harvest/security)
   of the repository.
2. Click **Report a vulnerability**. This opens a private advisory. Only
   you and the maintainers can see it.
3. Write these items in the report:
   - The version or the commit hash.
   - How you run the claimer: NixOS module, Docker image, or binary.
   - The steps to cause the problem, and the result.
   - What an attacker can do with the problem.

Do not put a real mnemonic, private key, or 1Password token in the report.
If the problem needs key material, use a test key.

## Supported versions

We fix security problems only in the latest release and on `main`.

## Scope

These problems are in scope:

- The claimer signs a tx other than a reward withdrawal, a restake to the
  configured validator, or the `MsgExec` that holds them.
- Key material goes to disk, to the logs, to the metrics, or out of the
  process.
- A gRPC node makes the claimer sign a tx that the node changed, or makes
  the program panic.
- The claimer uses an authz grant that is wider than the README permits.
- The NixOS module or the Docker image gives the process more access than
  the README says.

These problems are out of scope:

- An attacker who controls the host, the service user, or the 1Password
  service account token.
- Fees that a false node can cause. The README describes this limit in
  [Node trust](README.md#node-trust).
- Problems in the SOVR chain, the Cosmos SDK, or the 1Password SDK. Report
  these to their maintainers.

## After you report

We examine the report and tell you if we accept it. If we accept it, we
make a fix and a release. Then we publish the advisory. We name you in the
advisory, unless you tell us not to.
