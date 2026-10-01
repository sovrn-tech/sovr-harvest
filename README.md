# sovr-harvest

sovr-harvest withdraws x/distribution rewards for SOVR (`sovr-1`) validators
at regular intervals. It also exports Prometheus metrics. The signing
mnemonic can be in 1Password or in a local secrets file. The claimer gets
the mnemonic only when it signs a claim tx. It does not write the mnemonic
to disk, and it does not keep the mnemonic between claims.

Each claim is one tx with these messages:

- `MsgWithdrawValidatorCommission`: the validator commission.
- `MsgWithdrawDelegatorReward`: the rewards on the self-delegation of the
  operator.

We recommend that you sign with a separate **authz grantee** key. This key
can only withdraw rewards, and the operator key does not go on the host.
Refer to [Authz grantee](#authz-grantee-recommended). If you do not set
`grantee_address`, the operator key signs.

The claimed rewards go to the withdraw address of the operator. If you set
`restake`, the claimer also delegates the operator balance to the validator
at regular intervals. It keeps a small reserve for fees. Refer to
[Restake](#restake).

## How a poll works

At each `poll_interval` (default 5m), the claimer does these steps for each
validator:

1. Get the latest block, the validator, the operator account, and the
   account balance. Also get the outstanding rewards, the commission, and the
   self-delegation rewards. Update the metrics. If the chain ID of the node is
   not `chain_id`, stop.
2. If the validator is not due, stop. A validator is due when
   `claim_interval` plus a random jitter has passed since the last claim by
   this process.
3. If the pending commission plus the self-delegation rewards is less than
   `min_claim`, stop. **Up to this step, the claimer does not use key
   material.**
4. If a grantee is set, make sure that the operator gave the grantee an
   authz grant for each withdraw message. Make sure that the grants did not
   expire. Put the messages in one `MsgExec`. The grantee is then the signer.
5. Simulate the tx with the on-chain pubkey of the signer. This step does
   not need the private key. Calculate the fee.
   An account that did not sign a tx before has no pubkey on chain. For that
   account, the simulation uses an empty secp256k1 placeholder, as the Cosmos
   SDK client does.
   Stop if the fee is more than `max_fee`. Also stop if the fee is equal to or
   more than the claim, or more than the spendable balance of the account.
6. Get the mnemonic from 1Password and derive the key. **Make sure that the
   key derives the address and the on-chain pubkey of the signer.** Sign the
   tx. Then write zeros over the key and mnemonic buffers.
7. Broadcast the tx in sync mode, and wait until it is in a block. Get the
   claimed amounts from the tx events, and record them.
   If the tx is not in a block within `tx_timeout`, the next polls continue
   to look for it for one hour. During that time, the claimer sends no new
   claim for that validator, because a new claim would use the same
   sequence. If the tx gets into a block, the claimer records a successful
   claim. If not, the claimer records one failure and tries the claim again
   after the backoff.

After a failure, the claimer waits before it tries again. This backoff starts
at 5m and doubles after each failure, up to 6h.

`min_claim` is the real limit on how frequently the claimer claims after a
restart. After a claim, the pending rewards go down to approximately 0. A
process that restarts cannot claim again until the pending rewards are at
`min_claim` again.

## Restake

If you set `restake = true` on a validator, the claimer also sends a
`MsgDelegate` from the operator account to that validator. The restake has
its own schedule (`restake_interval`, default 24h, plus the same jitter as
the claims), backoff, and metrics.

The claimer sends one tx or less for each validator in each poll. If a claim
and a restake are both due, the claimer sends the claim first. The restake
then goes in the next poll, with a new snapshot. With `once`, the claimer
restakes only if it sends no claim. Thus, to claim and restake now, run
`once` two times.

A restake does these steps:

1. Make sure that the withdraw address of the operator is the operator
   account. If not, stop with an error: the rewards do not go to the
   operator account, and a restake would delegate other funds.
2. If the validator is not bonded, or is jailed, stop.
3. If a grantee is set, make sure that the operator gave the grantee a
   delegate grant (`StakeAuthorization`) that allows only this validator,
   and that does not expire before `tx_timeout`. The claimer does not use a
   generic grant for `MsgDelegate`, or a grant for more validators. Refer
   to [Key handling](#key-handling).
4. Calculate the amount: the spendable balance of the operator, minus
   `restake_reserve` (default 1 SOVR). If the operator signs, the operator
   also pays the fee. Thus, the amount is also less by the fee. If the
   grant has a `max_tokens` limit, the amount is not more than that limit.
   If the amount is less than `min_restake` (default 1 SOVR), stop. If only
   the `max_tokens` limit makes the amount less than `min_restake`, stop with
   the `grant_limit` error. Give a new delegate grant.
5. Continue as a claim does from step 5 of [How a poll
   works](#how-a-poll-works): simulate, check the fee, get the key, sign,
   broadcast, and confirm.

The claimer delegates all of the operator balance above the reserve, not
only the claimed rewards. Do not keep other funds in the operator account
that you do not want to stake.

Without a grantee, the operator pays the claim fees from the reserve. Thus,
`restake_reserve` must be equal to or more than `max_fee`. With a grantee,
the grantee pays the fees. The reserve then stays in the operator account for
other txs, for example unjail or grant renewal.

## Key handling

- With a grantee, the mnemonic in 1Password is the mnemonic of the grantee.
  An attacker who gets this mnemonic can do only two things. The attacker can
  withdraw your rewards early, into the withdraw address of the operator. The
  attacker can also spend the small fee balance of the grantee. With
  restake, the attacker can also delegate all of the operator balance
  to your validator. The funds stay in the operator account, but they are
  bonded, and it takes 21 days to unbond them. To stop the attacker, use the
  operator key to revoke the grants.
- For this reason, the claimer uses a delegate grant only if it allows only
  your validator. A generic `MsgDelegate` grant would let an attacker
  delegate the operator funds to a validator of the attacker. The attacker
  could then make that validator get slashed, and your funds would be
  burned.
- With 1Password, the only secret on the host is the **service account
  token**. Give the token read-only access to a vault that holds only the
  signing mnemonics. A person with the token can read that vault. Thus, keep
  the token as safe as the key. With a secrets file, the mnemonics
  themselves are on the host. Give that file the same care as the
  mnemonics.
- The claimer reads the token file (or secrets file) each time it gets a
  secret, not at startup. The NixOS module gives the token to the service
  through systemd `LoadCredential`. Thus, the service user cannot read the
  source file.
- The process calls `mlockall`, which keeps memory out of swap. It also
  clears `PR_SET_DUMPABLE`, which stops core dumps and ptrace from the same
  user. If `mlockall` fails, the process does not start. To start without
  these protections, use `-no-harden`.
- Limits: Go strings are immutable. The 1Password SDK and go-bip39 take or
  return strings. Thus, the claimer cannot write zeros over some copies of
  the mnemonic. The key derivation in the SDK also keeps two values in memory
  that it does not clear: the 64-byte BIP39 seed and the BIP32 master key.
  The seed is as sensitive as the mnemonic, because it derives every account.
  The sign operation copies the private scalar in the same way. After the
  claimer signs the tx, the program has no reference to these copies, and the
  Go garbage collector frees them. The claimer writes zeros over the byte
  slices that it owns. While the copies are in memory, `mlockall` and
  `PR_SET_DUMPABLE` keep them out of swap and core dumps.

## Node trust

The claimer does not trust the gRPC node with important data. The claimer
makes the messages, the memo, and the fee locally. It makes sure that the
chain ID of the node is correct. The signature covers the chain ID, the
account number, and the sequence. Thus, a node cannot make the claimer sign
a tx other than a reward withdrawal to the operator.

A node that gives false data can still make the claimer pay fees. For
example, the node can report each claim as failed and the pending rewards as
high. Then each backoff retry sends one more real tx, and each tx costs up to
`max_fee`. This is approximately 10 txs in the first day. After the backoff
gets to 6h, it is 4 txs each day. If possible, use your own node, through
loopback or TLS. If `grpc_insecure` points to a remote host, the claimer
logs a warning.

With restake, the claimer calculates the amount from the balance that the
node reports. A node that reports a balance that is too high can make the
claimer delegate some of the reserve. The chain does not delegate more than
the real balance, and the funds go only to your validator.

## Several validators, one grantee

Validators can use the same `grantee_address`. The claimer claims for them
one after the other. Before it claims for the next validator, it waits until
the tx of the current validator is in a block. Thus, the claims do not
compete for the sequence of the grantee.

Sometimes the confirmation of a claim times out while its tx is still in the
mempool. If this occurs, the claim for the next validator in that poll fails
with a sequence mismatch. The claimer tries that claim again after the
backoff.

## Usage

```sh
sovr-harvest once -dry-run -config config.toml   # query and simulate only, do not get keys
sovr-harvest check-secret -config config.toml    # get the mnemonic, make sure it matches, exit
sovr-harvest once -config config.toml            # claim now if the rewards are at min_claim or more; if not, restake
sovr-harvest run -config config.toml             # run as a daemon
```

For local tests, give the token in `OP_SERVICE_ACCOUNT_TOKEN` or in
`[onepassword] token_file`. Or, as an alternative, use `[secrets_file] path`
(see [Secrets file](#secrets-file-alternative-to-1password)). If your
`ulimit -l` is low, add `-no-harden`.

Refer to `examples/config.toml` for all settings.

## Authz grantee (recommended)

We tested this on sovr-1. Authz is enabled, and a `MsgExec` withdrawal
simulates correctly after a grant. The commands below use `sovrd`. If your
SOVR CLI has a different name, use that name.

1. Make a new key for the grantee. This key holds only money for fees.
2. Send some SOVR to the grantee for fees. A claim uses approximately 150k
   gas.
3. Go to the computer that has the operator key. Do not use the claimer
   host. Give the grantee grants for the two withdraw messages. Set an
   expiry on the grants, and renew the grants before they expire.

   ```sh
   GRANTEE=sovr1...   # the address of the grantee; a key name does not work
   EXP=$(date -d '+1 year' +%s)
   sovrd tx authz grant $GRANTEE generic \
     --msg-type /cosmos.distribution.v1beta1.MsgWithdrawValidatorCommission \
     --expiration $EXP --from operator --chain-id sovr-1
   # Wait until this tx is in a block. Then send the next tx.
   # If you do not wait, the next tx fails with "account sequence mismatch".
   sovrd tx authz grant $GRANTEE generic \
     --msg-type /cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward \
     --expiration $EXP --from operator --chain-id sovr-1
   ```

   If you set `claim_commission` or `claim_self_delegation` to false, do not
   give the grant for that message.

   If you set `restake`, also give a delegate grant. The grant must allow
   only your validator. Do not use a `generic` grant for `MsgDelegate`: the
   claimer does not use it.

   ```sh
   VALOPER=sovrvaloper1...   # your validator
   sovrd tx authz grant $GRANTEE delegate --allowed-validators $VALOPER \
     --expiration $EXP --from operator --chain-id sovr-1
   ```

   Optional: add `--spend-limit <amount>usovr` to set a limit on the total
   that the grantee can delegate. When the grantee delegates the full limit,
   the grant stops, and you must give it again. If the remaining limit is
   less than `min_restake`, the claimer does not restake. It records a
   `grant_limit` failure, and `SovrHarvestRestakeFailing` fires. Give the
   grant again.
4. Optional: Send the rewards directly to cold storage:
   `sovrd tx distribution set-withdraw-addr <cold-addr> --from operator`.
   If you do this, do not set `restake`. The claimer does not restake when
   the withdraw address is not the operator account.
5. Set `grantee_address` on the validator. Set `mnemonic_ref` to the
   mnemonic of the grantee. Run `sovr-harvest check-secret` and
   `sovr-harvest once -dry-run`.
6. After the claimer makes a claim as the grantee, remove the operator
   mnemonic from the vault.

To revoke a grant: `sovrd tx authz revoke <grantee-addr> /cosmos.distribution.v1beta1.<Msg> --from operator`.

Monitor `sovr_harvest_authz_grant_expiry_timestamp_seconds`. Its value is 0
when a grant is missing. Thus, one alert covers missing grants and grants
that expire soon.

## 1Password setup

1. Make a vault, for example `vault`. Put the signing mnemonic (grantee or
   operator) in a field of an item. For example, use the item `validator`
   and the concealed field `mnemonic`.
2. Make a service account with **read** access to only that vault.
3. Set `mnemonic_ref = "op://vault/validator/mnemonic"`.
4. On the host, keep the service account token in sops or a similar tool.
5. Run `sovr-harvest check-secret` one time. Make sure that the reference,
   the derivation path, and the address are correct.

## Secrets file (alternative to 1Password)

For hosts that cannot reach 1Password, mnemonics can instead come from a
local TOML file:

1. Create a file of `key = "mnemonic words..."` pairs, one per signing
   account, for example `/run/secrets/sovr-harvest-mnemonics.toml`:
   ```toml
   validator1 = "word1 word2 ... word24"
   ```
2. `chmod 600` it. sovr-harvest refuses to read a secrets file that is
   readable by group or other.
3. Set `[secrets_file] path = "/run/secrets/sovr-harvest-mnemonics.toml"`
   and `mnemonic_ref = "file://validator1"`.
4. Run `sovr-harvest check-secret` once to confirm the reference, derivation
   path, and address all line up.

You can mix `op://` and `file://` references across validators in the same
config. Unlike the 1Password token, the secrets file holds the mnemonics
themselves. Give the file the same care as the mnemonics. Keep it off the
host except when it is in use. Or supply it the same way as the 1Password
token, for example through systemd `LoadCredential` or sops.

## NixOS

```nix
{
  inputs.sovr-harvest.url = "github:sovrn-tech/sovr-harvest";

  # In a host config:
  imports = [ inputs.sovr-harvest.nixosModules.default ];
  sops.secrets.op-service-account-token = { };
  services.sovr-harvest = {
    enable = true;
    tokenFile = config.sops.secrets.op-service-account-token.path;
    settings = {
      grpc_endpoint = "127.0.0.1:9090";
      grpc_insecure = true;
      validator = [{
        operator_address = "sovrvaloper1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpwmje0";
        mnemonic_ref = "op://vault/validator/mnemonic";
      }];
    };
  };
}
```

The unit runs as a `DynamicUser` in a strict sandbox. `MemoryDenyWriteExecute`
is off, because the 1Password SDK runs its core as JIT-compiled WebAssembly.
The service must have outbound HTTPS access to 1Password (`*.1password.com`)
and access to the gRPC endpoint.

For the secrets file, set `secretsFile` instead of `tokenFile`, and set
`settings.validator[].mnemonic_ref` to `file://<key>`. Do not set
`settings.secrets_file`: the module sets it for you. Set both `tokenFile` and
`secretsFile` to mix `op://` and `file://` references.

## Binary releases

Each `v*` git tag gives a GitHub release with a static binary for
`linux/amd64` and `linux/arm64`. CI builds each binary from the flake package
on a runner of the same architecture. A tag with `-` gives a prerelease.
Cosign signs `SHA256SUMS` without a key.
Before you use an archive, verify the signature and the checksum:

```sh
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/sovrn-tech/sovr-harvest/\.github/workflows/release\.yml@'
sha256sum --check --ignore-missing SHA256SUMS
```

The Nix Go toolchain reads `/etc/services` and `/etc/protocols` from the Nix
store. On a host without Nix, Go uses its built-in table. Thus, use numeric
ports in `grpc_endpoint` and `listen_address`.

## Docker

The flake builds an OCI image. The image holds only the static binary and
the CA certificates. The process runs as `nobody` (UID 65534).

```sh
nix build .#docker
docker load < result
```

CI publishes a multi-arch image (`amd64`, `arm64`) to
`ghcr.io/sovrn-tech/sovr-harvest`. Each push to `main` gives the tags
`main` and the short commit hash. Each `v*` git tag gives the version
without the `v` and `latest`. A tag with `-` (for example `v1.2.0-rc1`) is a
prerelease. It does not move `latest`. Cosign signs each image without a key.
Before you use an image, verify its signature:

```sh
cosign verify ghcr.io/sovrn-tech/sovr-harvest:<tag> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/sovrn-tech/sovr-harvest/\.github/workflows/image\.yml@'
```

The image reads `/etc/sovr-harvest/config.toml`. In that config, set these
values:

- `listen_address = "0.0.0.0:9657"`. The default address `127.0.0.1` is not
  available from outside the container.
- `[onepassword] token_file = "/run/secrets/op-service-account-token"`, or
  `[secrets_file] path = "/run/secrets/sovr-harvest-mnemonics.toml"`.

A secrets file must have mode `0600`, and UID 65534 must own it. If not, the
claimer does not read it.

```sh
docker run -d --name sovr-harvest \
  --ulimit memlock=-1 \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD/config.toml:/etc/sovr-harvest/config.toml:ro" \
  -v "$PWD/op-token:/run/secrets/op-service-account-token:ro" \
  -p 127.0.0.1:9657:9657 \
  sovr-harvest:<version>
```

`--ulimit memlock=-1` is necessary for `mlockall`. If you cannot set it, add
`run -no-harden -config /etc/sovr-harvest/config.toml` after the image name.
But then key material can go into swap. To run a different command, give it
after the image name, for example
`sovr-harvest:<version> once -dry-run -config /etc/sovr-harvest/config.toml`.

## Metrics

The claimer serves the metrics on `listen_address` (default
`127.0.0.1:9657`) at `/metrics`. It also serves `/healthz` for liveness
checks. `/healthz` returns 503 if no poll finished in two times
(`poll_interval` + the maximum duration of a poll). This means that the loop
is stuck. All amounts are in usovr.

| Metric | Labels | Meaning |
|---|---|---|
| `sovr_harvest_pending_usovr` | validator, source | Rewards that you can withdraw now (`commission`, `self_delegation`) |
| `sovr_harvest_claimable_usovr` | validator | Pending rewards from the sources that the validator claims. The claimer compares this value with `min_claim` |
| `sovr_harvest_min_claim_usovr` | validator | The `min_claim` value in the config |
| `sovr_harvest_validator_outstanding_usovr` | validator | All undistributed rewards for the validator |
| `sovr_harvest_validator_bonded` / `_jailed` | validator | Validator status |
| `sovr_harvest_validator_tokens_usovr` | validator | Total bonded tokens |
| `sovr_harvest_account_balance_usovr` | validator, address, role | `signer` pays the fees. The signer is the grantee, or the operator if there is no grantee. With a grantee, the metric also shows `operator` |
| `sovr_harvest_authz_grant_expiry_timestamp_seconds` | validator, msg_type | Grant expiry. `+Inf` means no expiry. `0` means no grant |
| `sovr_harvest_claimed_usovr_total` | validator, source | Rewards that this process claimed, from tx events |
| `sovr_harvest_fees_paid_usovr_total` | validator | Fees that this process paid |
| `sovr_harvest_claim_attempts_total` | validator, result | `success`, `failed` (a simulate, secret, sign, broadcast, or confirm error), `below_threshold`, `fee_too_high`, `insufficient_balance`, `no_grant`, `dry_run` |
| `sovr_harvest_claim_consecutive_failures` | validator | Number of failed claim attempts in a row. A success or a skip sets it to 0 |
| `sovr_harvest_last_claim_timestamp_seconds` | validator | Time of the last confirmed claim |
| `sovr_harvest_next_claim_timestamp_seconds` | validator | Earliest time for the next claim |
| `sovr_harvest_last_claim_gas_used` | validator | Gas that the last claim used |
| `sovr_harvest_restakeable_usovr` | validator | Amount that a restake can delegate now. It is the operator balance minus `restake_reserve`, and minus `max_fee` if the operator signs. It is 0 if the restake cannot run for a reason that is not the amount |
| `sovr_harvest_min_restake_usovr` | validator | The `min_restake` value in the config |
| `sovr_harvest_restake_interval_seconds` | validator | The `restake_interval` value in the config. The no-restake alert uses it |
| `sovr_harvest_restaked_usovr_total` | validator | Tokens that this process delegated |
| `sovr_harvest_restake_fees_paid_usovr_total` | validator | Fees for the restake txs that this process paid |
| `sovr_harvest_restake_attempts_total` | validator, result | The `claim_attempts_total` results, and `withdraw_address_mismatch`, `validator_not_bonded`, `grant_limit` |
| `sovr_harvest_restake_consecutive_failures` | validator | Number of failed restake attempts in a row |
| `sovr_harvest_last_restake_timestamp_seconds` | validator | Time of the last confirmed restake |
| `sovr_harvest_next_restake_timestamp_seconds` | validator | Earliest time for the next restake |
| `sovr_harvest_polls_total` | result | Poll cycles |
| `sovr_harvest_last_poll_timestamp_seconds`, `_last_successful_poll_timestamp_seconds` | | Poll liveness. A poll is successful if it returns no error. If a claim continues to fail, `claim_consecutive_failures` shows it, not these metrics |
| `sovr_harvest_errors_total` | validator, stage | `query`, `grant`, `withdraw_address`, `simulate`, `secret`, `sign`, `broadcast`, `confirm`. `withdraw_address` is a restake for which the withdraw address is not the operator account |
| `sovr_harvest_secret_fetch_total` | result | 1Password secret fetches |
| `sovr_harvest_secret_fetch_duration_seconds` | | 1Password latency |
| `sovr_harvest_chain_height` | | Latest block height that the claimer saw |
| `sovr_harvest_build_info` | version, chain_id | |

The restake metrics are only for validators with `restake = true`. With
restake, `authz_grant_expiry_timestamp_seconds` also shows the delegate
grant. `fees_paid_usovr_total` has only the claim fees. `errors_total` has
the errors of the claims and the restakes.

The counters go back to 0 when the process restarts. They start at 0 for
each label value, so `increase()` sees the first event. The example alert
rules are in `examples/alerts.yml`. Their promtool tests are in
`examples/alerts_test.yml`.

## Notes on SOVR

- SOVR does not use x/mint. Emissions come from the custom x/distro module.
  This module sends funds to x/distribution in batches. Thus, the pending
  rewards increase in steps, not at each block.
- SOVR also has custom claim messages: `x/distro MsgClaimOperatorRewards`,
  `x/settlement MsgClaimSettlementRewards`, and `x/lockup MsgClaimVested`.
  This tool does not send them. **Do not send `MsgClaimVested` before
  `VestingEnd`.** If you send it before `VestingEnd`, you lose the unvested
  remainder.
- `grpc.sovrchain.net` is behind Cloudflare. Cloudflare resets a gRPC
  stream if its content-type is not `application/grpc` or
  `application/grpc+proto`. For this reason, the client registers the SDK
  codec with the name `proto`.

## Development

Use the development shell for local builds and tests. Go keeps its build
and test cache between commands. To see the cache paths, run
`go env GOCACHE GOMODCACHE`.

```sh
nix develop            # go, gopls, grpcurl; CGO_ENABLED=0
go test ./...
go build ./cmd/...
```

Before each commit, run the full checks:

```sh
nix flake check        # Go tests, NixOS module check, and alert rule tests
```

To build the package with the Git revision as its version, run `nix build`.
This build also runs the Go tests.

The package check uses the Git revision as its version. Thus each new
commit causes Nix to build the package and run its tests again. The checks
and the OCI image use the same package, so CI builds it only one time.
Each Nix package build starts from a Go build cache for the vendored
dependencies (`nix build .#default.goCache`). Nix builds this cache again
only when go.mod, go.sum, or nixpkgs change. Thus a change to the project
code makes Go compile only the project packages. The Nix builds do not use
the cache from the development shell.

## Security

To report a security problem, refer to [SECURITY.md](SECURITY.md). Do not
open a public issue.

## License

MIT. Refer to [LICENSE](LICENSE).
