# PR #9: PAT owner federation review

Reviewed original head `aeab41c3fe996cccd0d6ac0eca1e04e166f5fac6` against
`ae40343f584b128c04345395499a6907601dfcc6`. No merge or deployment performed.

## Findings addressed

- **P2: Owner authentication unnecessarily depends on organization-list access.**
  `check_org_membership` originally called and parsed `/user/orgs` before testing
  the authenticated login. A classic PAT can authenticate with `/user` yet lack
  the `user`/`read:org` scopes that the org-list API requires. Its 403 prevented
  owner federation. The owner comparison now returns before the org-list request;
  `/user` authentication still occurs first in `handle`.
- **P2: The three new helper tests did not cover the failure above or identity
  boundaries.** Added coverage for owner authentication without org-list access,
  mixed ASCII case, whitespace, Unicode lookalikes, prefix mismatches, empty
  requirements, non-owner API errors/malformed responses, and handler-level PAT
  validation and repository denial. Denial checks assert error categories.
- **P3: Missing public documentation.** README now documents account-name trust,
  collaborator rejection, PAT permission implications, rename risk, the OIDC
  distinction, and the production deployment environment. Architecture overview
  updated to describe the owner branch.

## Security assessment

The comparison uses `user.login` returned by the fixed GitHub `/user` endpoint,
not a request-supplied username, policy subject, display name, or repository
collaborator relation. The policy is loaded from the target owner's `.github`
repository. A caller cannot select another login through the request. Choosing
another scope still selects that owner's policy and installation.

ASCII case-insensitive equality is suitable for GitHub login matching. It does
not trim strings, perform substring matching, or equate Cyrillic/Unicode
lookalikes with ASCII. Tests include a Cyrillic `а`. This is deliberately
name-based trust, not immutable numeric-account-ID trust: policies must be
reviewed after account renames/deletion, particularly for cross-owner policies.

A successful owner match authorizes the policy's installation permissions even
when the source PAT has fewer repository permissions. That is identity federation,
not a permission intersection. Repository and permission checks remain downstream;
no collaborator fallback was introduced. Both Cloudflare and GCP use this core.

OIDC should remain unchanged. It validates issuer, subject, audience and custom
claims from `.sts.yaml`; it has neither a GitHub-authenticated `/user` login nor
`required_org`. Equating an arbitrary issuer's subject or actor with a GitHub
login would introduce a new and unsafe trust shortcut.

## Pre-existing limitations requiring separate follow-up

- **P2: PAT `owner/.github` scoping differs from the documented contract.**
  `handle` passes `.github` to `check_repository_access`, so a nonempty target
  list such as `[repo-a]` rejects it. An empty list instead produces a token for
  `.github` alone. Repository scopes also issue the full policy list, unlike
  OIDC's single requested repository. These behaviors precede this PR. Use an
  explicit allowed `owner/repo` for owner-federation verification; do not promise
  PAT org-level scope parity until it is separately corrected and tested.
- Organization listing only reads the first 100 memberships. Membership beyond
  that page is falsely denied. Fine-grained tokens receive an empty list from
  this endpoint and cannot establish organization membership. Neither behavior
  is introduced by the owner branch.
- The two workflow edits only rename `gear` to `plugin-marketplace` in existing
  OIDC smoke tests. They do not exercise PAT federation or deploy the PR code.
  Their green result is not a PAT regression test or proof of a production rollout.

## Validation

- Original PR: `cargo test -p octo-sts-core --locked`: 66 passed.
- Updated implementation: same command: 69 passed, including handler denials.
- Regression proof: substituted the original membership function while keeping
  the new owner test; it failed because `/user/orgs` was called. Restored the fix.
- `git diff --check`: passed.
- Cloudflare WASM check attempted with
  `cargo check -p octo-sts-cloudflare --target wasm32-unknown-unknown --locked`;
  blocked downloading `worker-sys` because `static.crates.io` DNS was unavailable.
- ripwire review mapped the shared core change to both platform adapters. Its
  test gate reports platform routes as untested and does not recognize these
  inline Tokio tests. Its quality heuristic flags repeated test setup, churn,
  and similarity to existing HTTP/parsing code; these are recorded limitations,
  not a clean static-analysis verdict. No claim of complete adapter coverage.
- No live PAT exchange or production deployment was performed. Existing core
  compiler warnings are outside this change.

## Deployment after merge

From the merged checkout, run `wrangler deploy --env production` inside
`cloudflare/`. Plain `wrangler deploy` selects development. Production requires
Cloudflare credentials with deployment access, the configured KV namespace and
routing for `sts.epiphytic.org`, and production secrets `GITHUB_APP_ID`,
`GITHUB_APP_PRIVATE_KEY`, and `GITHUB_WEBHOOK_SECRET`. Secrets are environment
specific; use `wrangler secret put <NAME> --env production` if provisioning them.
The GitHub App must be installed on the account and cover the policy repositories
and requested permissions. Verify an owner PAT against an allowed explicit repo,
a non-owner denial, and output-token permission/repository boundaries after rollout.
Do not log PATs or returned installation tokens during verification.

## References

- [PR #9](https://github.com/Epiphytic/octo-sts-rust/pull/9)
- [GitHub org-list API: scope and fine-grained-token behavior](https://docs.github.com/en/rest/orgs/orgs#list-organizations-for-the-authenticated-user)
