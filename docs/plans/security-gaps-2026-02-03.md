# Security Review: octo-sts-rust

**Date:** 2026-02-03
**Status:** Completed
**Reviewer:** Gemini CLI Agent

## Executive Summary

A security review of the `octo-sts-rust` repository was performed. While the core architecture is sound and follows many best practices (such as constant-time signature verification and thorough issuer URL validation), several security gaps and vulnerabilities were identified. The most critical issues involve path traversal in policy loading and the failure to enforce repository restrictions defined in trust policies.

## Vulnerabilities

### 1. Path Traversal in Policy Loading
The `identity` parameter in both the `/sts/exchange` and `/sts/exchange/pat` endpoints is used directly in constructing file paths without sanitization.

**Location:** `src/policy/mod.rs` and `src/sts/exchange_pat.rs`
**Detail:** 
```rust
let path = format!(".github/chainguard/{}.sts.yaml", identity);
```
An attacker can provide an `identity` like `../../some/other/file` to attempt to load a YAML file from outside the `.github/chainguard/` directory. While the `.sts.yaml` or `.pat.yaml` suffix provides some protection, this allows escaping the intended policy directory.

**Recommendation:** Validate that the `identity` contains only safe characters (e.g., alphanumeric, hyphens, underscores) and does not contain path traversal sequences like `..`.

### 2. Repository Restriction Bypass (PAT Exchange)
The `PatTrustPolicy` includes a `repositories` field intended to limit which repositories a user can access, but this field is ignored during the token exchange process.

**Location:** `src/sts/exchange_pat.rs`
**Detail:** The `handle` function parses the `repositories` list from the policy but never verifies if the requested `scope` (repo) is included in that list. As a result, any member of the organization can get a token for *any* repository in that organization using any valid PAT identity.

**Recommendation:** Enforce that `params.scope` (the repository) is present in `policy.repositories` if the list is not empty.

### 3. Repository Restriction Bypass (Org Policies)
Similar to the PAT exchange, organization-level trust policies in the OIDC exchange flow fail to enforce the `repositories` restriction.

**Location:** `src/policy/check.rs` and `src/policy/compile.rs`
**Detail:** `OrgTrustPolicy` contains a `repositories` list that is compiled but never used in `check_token`. 

**Recommendation:** Add a check in `policy::check_token` to verify that the target repository is allowed by the organization policy.

### 4. Limited SSRF and Resource Exhaustion in OIDC Validation
The service performs OIDC discovery and fetches JWKS for any issuer provided in an unverified token's header before performing any policy checks.

**Location:** `src/oidc/validate.rs`
**Detail:** `validate_token` calls `fetch_discovery` and `fetch_jwks` based on the issuer claim in the unverified token. An attacker can trigger octo-sts to make outbound HTTPS requests to arbitrary servers.

**Recommendation:** Load the trust policy *before* OIDC validation and only perform discovery/JWKS fetching if the token's issuer matches one of the allowed issuers in the policy.

## Security Gaps

### 5. Incomplete OIDC Claim Validation
The manual OIDC validation implementation is missing checks for several standard security claims.

**Location:** `src/oidc/validate.rs`
**Detail:** Only the `exp` (expiration) claim is manually checked. The `nbf` (not before) and `iat` (issued at - for future checks) claims are ignored, as the `jsonwebtoken` library's automatic validation is disabled for WASM compatibility.

**Recommendation:** Add manual checks for `nbf` and `iat` claims using `js_sys::Date`.

### 6. Missing Webhook Security Feedback (TODOs)
The webhook handler contains several `TODO` items for critical event types.

**Location:** `src/github/webhook.rs`
**Detail:** `handle_pull_request_event` and `handle_check_suite_event` are not implemented. This means policy changes in Pull Requests are not validated via Check Runs, allowing invalid or malicious policies to be merged without automated feedback.

**Recommendation:** Implement the missing webhook handlers to provide validation for all policy changes before they are merged.

### 7. Lack of Rate Limiting
The service does not implement any rate limiting for the exchange endpoints.

**Location:** `src/lib.rs` (Router)
**Detail:** High-frequency requests can be used to attempt to exhaust the GitHub API rate limits for the App, leading to a Denial of Service for all users.

**Recommendation:** Implement rate limiting using Cloudflare Workers KV or Durable Objects, potentially scoped per organization or per source IP.

### 8. Potential for Regular Expression DoS (ReDoS)
Trust policies allow users to define regex patterns for issuers, subjects, and custom claims.

**Location:** `src/policy/compile.rs`
**Detail:** Regex patterns are compiled and executed without complexity limits or execution timeouts. A malicious policy could include a "catastrophic backtracking" regex that causes the Worker to exceed CPU limits.

**Recommendation:** Consider using a more restricted regex engine or implementing a timeout for regex matching.

### 9. Hardcoded Test Private Key
A valid-looking RSA private key is hardcoded in the source code.

**Location:** `src/github/auth.rs`
**Detail:** `TEST_PRIVATE_KEY` is included in the file for unit tests. While it is inside a `#[cfg(test)]` block, it is generally better to load test keys from environment variables or separate files to prevent accidental leakage into production code or confusion.

## Functional Gaps with Security Implications

### 10. Missing Org-Wide Policy Support
The implementation does not currently support using a policy stored in the org's `.github` repository for actions in other repositories, despite this being a documented feature.

**Detail:** `policy::load` only looks in the repository specified in the `scope`. If a user wants to use an org-wide policy for `myorg/myrepo`, they currently cannot do so unless they specify `scope=myorg/.github`, which would result in a token with the wrong scope.

**Recommendation:** Update `policy::load` to fall back to the `.github` repository if the policy is not found in the target repository.
