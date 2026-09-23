# Nostr identity exchange

`POST /sts/exchange/nostr` exchanges a signed Nostr HTTP assertion for a
GitHub installation token scoped to exactly one repository. The route is disabled
by default. No Nostr relays, profiles, GitHub PATs or account association are used.

## Policy and request

In the owner's `.github` repository, create
`.github/chainguard/agent.nostr.yaml`:

```yaml
version: 1
nostr_npubs: ["<operator-approved lowercase npub>"]
repositories: [my-repo]
permissions:
  contents: read
```

Replace the placeholder with the client's public npub; never upload its nsec.
The App needs access to `.github` and the target repository. Policies are fetched
fresh on every request. Up to eight keys support rotation: add the new key,
switch clients, then remove the old key. Removal blocks new tokens; previously
issued tokens remain valid until expiry or explicit revocation.

V1 accepts `read`/`write` for contents, issues, pull_requests, actions, checks,
statuses, deployments, discussions, packages and pages; metadata accepts only
`read`. Unknown fields, duplicate permissions, wildcards and empty grants fail
closed. Repositories are explicit names within this policy owner's account.

Send `Content-Type: application/json`, no query string or content encoding, and
this exact body (maximum 4096 bytes):

```json
{"scope":"owner/my-repo","identity":"agent"}
```

Set `Authorization: Nostr <standard-base64-event-json>`. Sign a NIP-01 event with
kind 27235, empty content, current Unix `created_at`, and exactly four tags:

```text
["u", "https://your-sts.example/sts/exchange/nostr"]
["method", "POST"]
["payload", "<lowercase SHA256 of the exact transmitted body bytes>"]
["octo-sts-nonce", "<32 random bytes encoded as 64 lowercase hex characters>"]
```

`octo-sts-nonce` is this service's required extension, not NIP-13 proof of work.
The configured URL must match exactly. Events older than 60 seconds or more than
5 seconds in the future are rejected. The event ID and BIP-340 signature are both
verified. Headers are limited to 8192 bytes. Do not send private keys to STS.

A successful response contains `access_token`, `token_type: Bearer`, and
`expires_in`. Responses carry `Cache-Control: no-store`. A nonce is consumed
before the caller's token is created, even if GitHub subsequently fails. Retrying
requires a newly signed assertion and fresh nonce. The existing GitHub adapter
uses an internal contents-read token for `.github` to retrieve the policy before
nonce consumption; that credential is never returned to the caller.

## Deployment prerequisites

Set `NOSTR_EXCHANGE_ENABLED=true`, `NOSTR_EXCHANGE_URL` to the exact canonical
HTTPS endpoint, and `NOSTR_RATE_PER_MINUTE` to 1–100 (recommended 10).
The limit is a fixed UTC minute counter per audience/public key, across policies
and scopes. It limits issuance attempts after policy authorization. It is not a
substitute for an edge request/IP limit: rejected requests still consume CPU and
valid assertions can cause GitHub policy reads before issuance limiting.
Configure an edge limit before enabling the public endpoint.

Cloudflare's checked-in Wrangler config supplies the private `NOSTR_REPLAY`
SQLite Durable Object binding and migration in both environments. Deploying the
new migration requires an account/plan that supports SQLite Durable Objects.
Keep the binding private. Synchronous SQL read/transition/write does not yield;
storage output gates commit the consumed nonce before releasing a response.
Expired entries are pruned on requests and alarms. Do not delete/reset this
storage while the endpoint is enabled.

GCP requires a Firestore Native database `(default)` in `GCP_PROJECT` and the
runtime service account's Firestore read/write transaction permissions (for
example `roles/datastore.user`). Enable TTL on `expires_at` in collection group
`nostr_replay` to clean up inactive principals. Correctness does not depend on
prompt TTL deletion: each transaction prunes expired nonces before checking.
Metadata credentials are obtained using the runtime service account. Requests
must arrive through the canonical HTTPS ingress with the original Host preserved;
do not expose the HTTP container directly or trust caller-supplied forwarded
headers. Conflicts retry up to three transactions; outages and uncertain commits
return 503 and never issue a caller token.

Replay records last until event creation +180 seconds. Maintain healthy clocks
within ±5 seconds. Independent Cloudflare and GCP stores **must use distinct
public audiences**. For failover at the same URL, disable issuance on all old
instances, wait at least 180 seconds, then enable the replacement. Backups,
rollbacks and replay-store restoration require the same blackout; never run old
and new independent stores concurrently behind one audience.

Enable only after the operator supplies the first client's real public npub and
intended repository grants. The committed fixture key is public test material.
Disable with `NOSTR_EXCHANGE_ENABLED=false` (404); retain replay storage during
rollback. Production enabling and real GitHub issuance are operator rollout work.

## Verification

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo check -p octo-sts-cloudflare --target wasm32-unknown-unknown --locked
(cd cloudflare && npx --yes wrangler@4.136.3 deploy --env="" --dry-run)
npm install --prefix /tmp/nostr-runtime --no-audit --no-fund miniflare@4.20260730.0
NODE_PATH=/tmp/nostr-runtime/node_modules node cloudflare/tests/nostr.cjs
```

The runtime fixture signs independently with secp256k1, executes the release
WASM in workerd, mocks all GitHub traffic, races eight identical assertions,
and restarts the runtime against retained SQLite data. Exactly one caller token
must be issued. It also checks payload tampering and the disabled route.
GCP tests exercise the REST transaction protocol against a local mock server;
a real Firestore deployment/IAM check remains necessary before GCP rollout.
Wall time from the local fixture is diagnostic, not a production CPU benchmark.

Protocol references: [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md),
[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md),
[Firestore beginTransaction](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/beginTransaction)
and [transaction commit](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/commit).
