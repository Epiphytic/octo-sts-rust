# Nostr identity exchange (btq-u5p)

Status: proposed; operator design approval required before implementation.

## Decision

Add `POST /sts/exchange/nostr` using a strict NIP-98 HTTP authentication
profile. Authorize the verified public key through an explicit GitHub-hosted
policy, then issue a GitHub App installation token for one requested repository.
No PAT, OIDC provider, relay, profile lookup, or GitHub account association is
required. A key proves possession, not membership in a GitHub organization.

Use the `nostr` protocol crate with minimal features for event parsing,
canonical event-ID verification, and Schnorr verification. Do not add the full
`nostr-sdk` networking stack. Add an atomic replay-store interface separate from
`Cache`. Cloudflare uses Durable Objects; GCP uses Firestore. Deployments with
independent stores must have distinct, configured public audiences.

These are proposed product and security decisions, not evidence of a working
implementation. The hermes-agent public key and desired grants must be supplied
and reviewed by the operator before onboarding.

## Existing seams and compatibility

The actual workspace has platform-neutral logic in `core/` and adapters in
`cloudflare/` and `gcp/`; older architecture examples using top-level `src/` do
not describe the current layout. This design builds on
[the architecture](../architecture/README.md) and
[the original design](2026-02-03-octo-sts-rust-design.md).

`core/src/platform.rs` provides `Clock`, `HttpClient`, `JwtSigner`, and a `Cache`
with separate get/put operations. Neither that contract nor the current
Workers KV/native memory caches provides atomic distributed consumption.
`core/src/sts/exchange_pat.rs` demonstrates installation lookup, policy loading,
and the token response. Reuse GitHub functions from `core/src/github/auth.rs`
and `api.rs`, and identity-path validation from `core/src/policy/mod.rs`.
Do not reuse PAT membership checks or its empty-repository-list semantics.

Add a dedicated core Nostr verifier, policy type/loader, and exchange handler;
route them from `cloudflare/src/lib.rs` and `gcp/src/main.rs`. Extend policy
validation tooling/webhook coverage for the new suffix. Keep existing OIDC/PAT
parsers, routes, and policy behavior unchanged. No private Nostr keys enter STS.

## Wire contract

```http
POST /sts/exchange/nostr HTTP/1.1
Host: sts.epiphytic.org
Content-Type: application/json
Authorization: Nostr <standard-base64-encoded-signed-event-json>

{"scope":"Epiphytic/example-repo","identity":"hermes-agent"}
```

The body has exactly `scope` and `identity`. Scope is exactly `owner/repository`,
with validated GitHub name components; identity uses existing path-safe
validation. Reject queries, trailing-slash aliases, encoded path aliases,
duplicate JSON fields, unknown fields, and multiple authorization headers.
Require uncompressed UTF-8 JSON: cap raw body at 4 KiB and authorization value
at 8 KiB before decoding. Adapters preserve the raw body bytes for hashing and
must not reserialize them first. Reject oversized input with 413.

[NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) defines HTTP
authentication using kind 27235 and URL/method tags. This STS profile additionally
requires an empty content string, a payload hash, and a service-specific random
nonce tag. Example event shape (placeholders are not a valid signature):

```json
{
  "id": "<64 lowercase hex characters>",
  "pubkey": "<64 lowercase hex characters>",
  "created_at": 1790100000,
  "kind": 27235,
  "tags": [
    ["u", "https://sts.epiphytic.org/sts/exchange/nostr"],
    ["method", "POST"],
    ["payload", "<sha256 of exact body bytes as lowercase hex>"],
    ["octo-sts-nonce", "<32 random bytes as 64 lowercase hex characters>"]
  ],
  "content": "",
  "sig": "<128 lowercase hex characters>"
}
```

Require exactly these four tags, each with two string elements, in any order;
reject duplicates and additional tags. The custom tag intentionally avoids the
NIP-13 proof-of-work `nonce` tag. Clients generate a fresh cryptographically
random nonce for every attempt. Generic NIP-98 signers need this STS profile;
a normal signed note is not accepted and the event should not be relay-published.

Verify both the event ID and signature. [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
defines the ID over the canonical event tuple, and BIP-340 Schnorr verification
against the event public key. Verifying only a signature over an untrusted
supplied ID would leave request fields unbound. Reject malformed lengths,
noncanonical hex, invalid curve keys, duplicate event fields, and non-integer
or out-of-range timestamps before cryptographic work.

The `u` tag must equal a configured `NOSTR_EXCHANGE_URL`, including HTTPS origin
and the exact path above. Compare exact strings; do not derive authority from
Host or forwarded headers. Only serve the route on its configured public
origin; preview URLs and alternate hostnames must reject it. Reverse proxies
must enforce that origin rather than rewriting arbitrary hosts into it.

Accept `now - 60 <= created_at <= now + 5` seconds using checked arithmetic.
Recheck freshness immediately before replay consumption and token issuance,
so slow GitHub/policy operations cannot extend the acceptance window.

Success uses the existing response fields `access_token`, `token_type`, and
`expires_in`, calculated from GitHub's actual expiry. Send `Cache-Control:
no-store`. Malformed requests return 400, invalid/expired/replayed assertions
401, unauthorized key/resource 403, rate limiting 429, and replay-store failure
503. Missing policy is a generic authorization failure. Internal policy errors
are logged without credentials; do not silently fall back to PAT/OIDC.

## Policy and authorization

Propose a dedicated file in the owner's `.github` repository:
`.github/chainguard/hermes-agent.nostr.yaml`. This deliberately refines the bead's
suggestion of extending `.pat.yaml`/`.sts.yaml`: a separate schema avoids
ambiguous OR/AND behavior with `required_org` and prevents existing policies
from accidentally opting into a new authentication method.

```yaml
version: 1
nostr_npubs:
  - "<operator-verified hermes-agent npub>"
permissions:
  contents: read
repositories:
  - example-repo
```

This is a template; the placeholder must never pass validation. Require a
nonempty list of at most eight distinct public keys, a nonempty repository
allowlist, and a nonempty permission map. Reject unknown fields (including
`required_org`, OIDC issuer/subject fields, and alternate hex-key fields),
duplicate YAML keys, wildcards, path separators in repository names, and
unknown permission names/levels. Reuse existing permission validation where
available; otherwise introduce a shared validator without relaxing old flows.

[NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md) defines npub as
Bech32-encoded public-key bytes. Require canonical lowercase npub, correct
checksum/prefix, and exactly 32 decoded bytes; reject nsec, nprofile, Bech32m,
whitespace, and mixed case. Decode once and compare the resulting key bytes
with the verified event's hex public key. Do not compare display strings or
resolve NIP-05 names. Hex remains the protocol representation; accepting hex
in policy can be a later, explicitly versioned convenience.

The scope owner determines both the policy repository and App installation;
request body cannot select an unrelated policy owner or installation ID. Match
the requested repository against the allowlist using GitHub's case-insensitive
ASCII naming semantics, without trimming or Unicode normalization. Pass only
that single repository to token creation, never the whole allowlist. Permissions
come solely from the policy; clients cannot request overrides. GitHub's App and
installation grants remain the upper bound, and errors must never retry with
broader scope. The `.github` repository itself is an ordinary resource requiring
an explicit grant. Multi-repository issuance is deferred.

Anyone who can change this policy on the policy repository's default branch
can grant access. Protect that branch and review policy changes as authorization
changes. Fetch Nostr policy fresh for each exchange in v1, with no positive or
negative policy cache and no stale-on-error fallback. Installation-ID caching
may continue. This avoids importing the PAT policy cache's five-minute
revocation delay; changes still cannot undo an already-authorized in-flight
request or a previously issued GitHub token.

## Replay and failure semantics

Introduce a platform trait with an asynchronous operation equivalent to:

```text
consume(key, expires_at) -> Consumed | AlreadyConsumed | storage error
```

The operation must be linearizable across instances, persist through restarts,
and atomically insert only if absent or expired. The key is SHA-256 over a
length-delimited tuple of protocol version, configured audience, verified
public-key bytes, and nonce bytes. Do not include signature, identity, scope,
or event ID: changing any of those must not allow reuse of the same nonce.
Store only replay metadata, never the assertion, token, or private key.

Order: bounded parse, event verification, request binding and freshness,
policy authorization, installation resolution, freshness recheck, atomic
consume, token mint. No GitHub token request occurs before consumption succeeds.
A timeout with unknown consumption outcome fails closed. GitHub failure or
response loss burns the nonce; retry requires a newly signed event and nonce.
This provides at-most-one issuance attempt per nonce, not exactly-once delivery
or one token per public key. Never return a cached token for a repeated event.

Keep entries until at least `created_at + 180` seconds. All serving clocks
must stay within five seconds of real time; alert and disable issuance if this
cannot be assured. Retention has margin beyond the acceptance window and skew.
Cleanup timing is not authorization: compare expiry inside the atomic operation.
Do not delete replay state during rollback or restore a stale snapshot while
recent assertions remain valid. After replay-state loss, disable the endpoint
for at least 180 seconds before reopening with healthy clocks.

| Platform | Proposed adapter | Operational requirement |
| --- | --- | --- |
| Cloudflare | SQLite-backed Durable Object, deterministic object ID from audience and public key; atomic insert/check within storage transaction | New binding and migration; durable namespace retained across deployments; alarm cleanup; no KV fallback |
| GCP | Firestore transaction on replay-key document, with expiry checked inside the transaction | Dedicated collection, service-account IAM, bounded retries; TTL only for cleanup; no local-memory fallback |

[Durable Object storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)
is transactional and strongly consistent. [Firestore transactions](https://docs.cloud.google.com/firestore/native/docs/manage-data/transactions)
atomically commit writes and may rerun on contention. Keep GitHub calls outside
transactions so retries cannot mint additional tokens.

Independent Cloudflare and GCP stores are safe only with distinct audience
URLs. For active-active service or platform migration under the same public
URL, first provide one shared replay authority; alternatively stop the old
service, wait out the retention window, and then enable the new one. DNS
failover alone is not sufficient. This restriction is a deployment gate.

TLS and redaction remain essential: an attacker who steals a fresh assertion
can race its legitimate sender. Replay protection cannot decide which copy is
legitimate. Nor does it prevent a trusted key from creating many fresh events.
Apply edge/IP limits before verification and authenticated per-key issuance
limits before GitHub calls; configure thresholds before enablement. Track
counts, latency, replay rejection, and store failures without logging
Authorization, full assertions, or access tokens. Nostr identities are public
but logs should still minimize correlatable identity data.

## Cryptography and portability decision

Prefer `nostr` over hand-written canonicalization using bare `secp256k1` plus
Bech32 utilities. Its [Event verification API](https://docs.rs/nostr/latest/nostr/event/struct.Event.html)
provides verification of both ID and signature. Use an explicit verification
context and retain strict STS parsing/tag checks around the library. Bare
`secp256k1` remains a fallback if the protocol crate cannot meet WASM or size
requirements, but would require independently tested serialization and decoding.
Web Crypto's existing JWT signer is not a substitute for BIP-340 verification.

The [feature listing](https://docs.rs/crate/nostr/0.44.2/features) shows why
feature selection matters: `std` enables secp256k1 random/global-context
features, while `alloc` offers a smaller starting point. Documentation currently
resolves to different versions across pages; do not copy an unverified manifest
or assume `latest` is a compatible pin. During the approved implementation
spike, select and lock one reviewed release with defaults disabled, test the
minimal feature set, and inspect the resolved feature tree. Do not enable
relay, signing, NIP-04/44 encryption, or SDK features just to verify events.

Portability is **not yet demonstrated**. The acceptance gate is a native build,
`wasm32-unknown-unknown` build, packaged Wrangler dry run, and an actual Workers
runtime verification fixture. Check native C toolchain requirements of
secp256k1 dependencies, random-source initialization, WASM imports, compressed
bundle growth, and verification CPU against the account's configured limits.
Both adapters must pass the same vectors. No dependency or production binding
is introduced by this proposal.

## Rotation, tests, and delivery

Rotate by adding the operator-verified new npub, deploying the client key, then
removing the old npub through the protected policy workflow. The overlap is
explicit and bounded operationally. A key cannot authorize its own replacement.
For compromise, remove the old key immediately, disable Nostr issuance if
needed, and revoke known issued GitHub tokens using the existing revocation
path. Policy removal does not revoke existing tokens; otherwise their actual
GitHub expiry bounds exposure. Never request or store an nsec for onboarding.

| Test group | Required evidence before enabling |
| --- | --- |
| Cryptography | Known NIP-01/BIP-340 vectors; bad signature/key/ID; modified body, timestamp, tags, and content; canonical escaping; cross-client signing fixture |
| Parsing/binding | Size/depth limits; duplicate JSON/YAML keys and tags; malformed base64/hex/npub; wrong kind/method/URL/payload; host spoofing; query/path aliases; timestamp boundary and overflow cases |
| Policy/scoping | Key match/miss; rotation overlap/removal; no implicit organization membership; wrong owner, repository, installation; empty/wildcard grants rejected; exact one-repository GitHub request and permission map |
| Replay | Sequential and concurrent duplicates across separate instances; same nonce in different signed events; expiry boundaries; restart persistence; store timeout/outage; GitHub failure and response-loss retries |
| Platforms | Identical core vectors on native and Workers runtime; concurrent real-adapter tests; same-audience deployment guard; recovery blackout and clock-skew behavior |
| Regression | Existing OIDC/PAT suites; disabled feature route behavior; policy validator coverage; response shape and redaction |

After operator approval, sequence implementation as: portability/vector spike;
strict policy and verifier; atomic store adapters and concurrency tests; routes
and client fixture; disabled-by-default deployment; staging exchange against a
throwaway repository; controlled hermes-agent onboarding. Run the full workspace
suite and WASM checks with locked dependencies and retain logs. Live acceptance
must prove allowed access, denied cross-repository access, replay rejection,
and token revocation without retaining credentials in evidence.

A `NOSTR_EXCHANGE_ENABLED` flag defaults false on both platforms. Enabling
requires the configured audience, healthy atomic store, validated policy, and
operator deployment approval. Rollback disables only this route and preserves
replay records; existing OIDC/PAT operations continue.

## Operator decision requested

Approve or revise the strict NIP-98 profile, separate `.nostr.yaml` schema,
one-repository issuance, and new durable replay infrastructure. Confirm whether
Cloudflare and GCP will use distinct audiences or require shared replay state.
Supply the hermes-agent **public** npub through the normal trusted operator
channel and specify its initial owner/repository/permission grants. No actual
identity grant is embedded here. Implementation remains gated on that review.
