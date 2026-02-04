# octo-sts-rust Design Document

**Date:** 2026-02-03
**Status:** Draft
**Original:** [octo-sts/app](https://github.com/octo-sts/app)

## Overview

octo-sts-rust is a Rust port of octo-sts, a GitHub App that functions as a Security Token Service (STS). It enables workloads that produce OIDC tokens to exchange them for short-lived, scoped GitHub API tokens—eliminating the need for Personal Access Tokens (PATs).

This implementation targets Cloudflare Workers for deployment, using Workers KV for caching and Web Crypto API for cryptographic operations.

## Architecture

```
┌─────────────────┐     OIDC Token      ┌──────────────────────┐
│   Workload      │────────────────────▶│   octo-sts-rust      │
│ (GitHub Actions,│                     │  (Cloudflare Worker) │
│  GCP, etc.)     │◀────────────────────│                      │
└─────────────────┘   GitHub Token      └──────────┬───────────┘
                                                   │
                      ┌────────────────────────────┼────────────────────────────┐
                      │                            │                            │
                      ▼                            ▼                            ▼
              ┌──────────────┐           ┌─────────────────┐          ┌─────────────┐
              │  Workers KV  │           │   GitHub API    │          │ OIDC Issuers│
              │  (caching)   │           │ (tokens, policy │          │ (validation)│
              └──────────────┘           │  fetch, webhooks)│          └─────────────┘
                                         └─────────────────┘
```

### Key Characteristics

- **Stateless:** All state lives in KV or is fetched fresh from GitHub/OIDC providers
- **Fast cold starts:** Rust compiled to WASM provides sub-millisecond startup
- **Global edge deployment:** Runs on Cloudflare's network close to callers
- **Secure secrets:** GitHub App private key stored in Workers Secrets

## API Endpoints

### Token Exchange

The core endpoint that exchanges OIDC tokens for GitHub tokens.

```
POST /sts/exchange?scope={owner/repo}&identity={policy-name}
Authorization: Bearer <oidc-token>

Response 200:
{
  "access_token": "ghs_xxxx",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### Token Revocation

Invalidates a previously issued GitHub token.

```
POST /sts/revoke
Authorization: Bearer <github-token-to-revoke>

Response 204: No Content
```

### Health/Info

```
GET /

Response 200:
{
  "name": "octo-sts",
  "documentation": "https://github.com/octo-sts/app"
}
```

### Webhook Handler

Receives GitHub App webhook events for trust policy validation.

```
POST /webhook
X-GitHub-Event: push | pull_request | check_suite
X-Hub-Signature-256: sha256=...

Response 200: { "ok": true }
```

### Error Responses

All errors follow a consistent format:

```json
{
  "error": "permission_denied",
  "message": "token does not match trust policy"
}
```

## Token Exchange Flow

```
1. Parse Request
   ├── Extract scope (owner/repo) and identity (policy name) from query params
   └── Extract OIDC bearer token from Authorization header

2. Validate OIDC Token
   ├── Decode JWT header to get issuer (without verifying yet)
   ├── Validate issuer URL format (HTTPS, no query/fragment, safe chars)
   ├── Fetch OIDC discovery document: {issuer}/.well-known/openid-configuration
   ├── Fetch JWKS from discovery document's jwks_uri
   └── Verify JWT signature against JWKS

3. Load Trust Policy
   ├── Check KV cache for policy (key: {owner}/{repo}/{identity})
   ├── If miss: fetch .github/chainguard/{identity}.sts.yaml from repo
   ├── Parse YAML and compile regex patterns
   └── Cache in KV with 5-minute TTL

4. Check Token Against Policy
   ├── Match issuer (exact or regex)
   ├── Match subject (exact or regex)
   ├── Match audience (exact, regex, or default to service domain)
   └── Match any custom claim patterns

5. Generate GitHub Token
   ├── Get installation ID (cached in KV or fetch from GitHub API)
   ├── Generate JWT signed with GitHub App private key
   ├── Request installation token with scoped permissions from policy
   └── Return token to caller
```

## Trust Policy System

Trust policies are YAML files stored in repositories at `.github/chainguard/{name}.sts.yaml`.

### Repository Trust Policy

For individual repositories:

```yaml
issuer: https://token.actions.githubusercontent.com
# OR issuer_pattern: https://token\.actions\.githubusercontent\.com

subject: repo:myorg/myrepo:ref:refs/heads/main
# OR subject_pattern: repo:myorg/myrepo:.*

# Optional
audience: https://octo-sts.example.com
# OR audience_pattern: ...

# Optional custom claim matching
claim_patterns:
  job_workflow_ref: myorg/workflows/.github/workflows/deploy.yaml@.*

# Permissions granted to the issued token
permissions:
  contents: read
  issues: write
```

### Organization Trust Policy

Stored in the `.github` repository, can scope to specific repos:

```yaml
issuer: https://accounts.google.com
subject_pattern: "^\\d+$"  # Google numeric subject
permissions:
  contents: read
# Optional: limit which repos this policy applies to
repositories:
  - repo-a
  - repo-b
```

### Validation Rules

- Exactly one of `issuer` or `issuer_pattern` (same for subject/audience)
- Regex patterns are anchored with `^...$` automatically
- Permissions must be valid GitHub App permission keys
- Custom claims are matched as strings (booleans become "true"/"false")

## GitHub App Authentication

### Stage 1: Generate App JWT

Create a short-lived JWT signed with the App's private key:

```
Header: { "alg": "RS256", "typ": "JWT" }
Payload: {
  "iat": <now - 60>,        // Clock skew buffer
  "exp": <now + 600>,       // 10 minute expiry
  "iss": <app-id>           // GitHub App ID
}
```

Signing uses Web Crypto API with the RSA private key stored in Workers Secrets. The key is in PKCS#8 PEM format.

### Stage 2: Request Installation Token

Using the App JWT:

```
POST /app/installations/{installation_id}/access_tokens
Authorization: Bearer <app-jwt>
Body: {
  "repositories": ["repo-name"],  // Optional scoping
  "permissions": { "contents": "read" }
}
```

GitHub returns a token valid for 1 hour with only the requested permissions.

### Required Secrets

| Secret | Description |
|--------|-------------|
| `GITHUB_APP_ID` | The App's numeric ID |
| `GITHUB_APP_PRIVATE_KEY` | RSA private key in PEM format |
| `GITHUB_WEBHOOK_SECRET` | For validating webhook signatures |

## Workers KV Schema

Single KV namespace with prefixed keys.

### Installation ID Cache

```
Key:    install:{owner}
Value:  {"id": 12345678, "cached_at": 1706900000}
TTL:    1 hour
```

### Trust Policy Cache

```
Key:    policy:{owner}/{repo}/{identity}
Value:  {
          "raw": "<yaml string>",
          "compiled": {
            "issuer": "https://...",
            "issuer_pattern": null,
            "subject_pattern_compiled": "^repo:.*$",
            "permissions": {"contents": "read"},
            ...
          },
          "cached_at": 1706900000
        }
TTL:    5 minutes
```

**KV Binding:** `OCTO_STS_KV`

## Webhook Handling

Validates trust policy files when created or modified, providing feedback via GitHub Check Runs.

### Supported Events

- `push` - Commits pushed to any branch
- `pull_request` - PR opened, synchronized, or reopened
- `check_suite` - Check suite requested

### Flow

```
1. Verify Signature
   ├── Compute HMAC-SHA256 of raw body using webhook secret
   └── Compare against X-Hub-Signature-256 header (constant-time)

2. Parse Event
   ├── Identify event type from X-GitHub-Event header
   └── Extract repository, commits, and changed files

3. Find Policy Changes
   ├── Filter for files matching .github/chainguard/*.sts.yaml
   └── Skip deleted files

4. Validate Each Policy
   ├── Fetch file content at the commit SHA
   ├── Parse YAML
   ├── Determine schema (OrgTrustPolicy if repo is ".github", else TrustPolicy)
   └── Validate structure and compile regex patterns

5. Report Results
   ├── Create Check Run via GitHub API
   ├── Status: success or failure
   └── Include error details if invalid
```

## Error Handling

### Client Errors (4xx)

| Code | Error Key | Cause |
|------|-----------|-------|
| 400 | `invalid_request` | Missing scope/identity, malformed query params |
| 400 | `invalid_token` | JWT parsing failed, malformed OIDC token |
| 401 | `token_verification_failed` | OIDC signature invalid, issuer mismatch |
| 403 | `permission_denied` | Token doesn't match trust policy |
| 404 | `policy_not_found` | No .sts.yaml file for given identity |
| 404 | `installation_not_found` | GitHub App not installed on repo/org |

### Server Errors (5xx)

| Code | Error Key | Cause |
|------|-----------|-------|
| 500 | `internal_error` | KV failure, unexpected panic |
| 502 | `upstream_error` | GitHub API returned error |
| 504 | `upstream_timeout` | GitHub API or OIDC provider timeout |

### Logging

- All requests logged with: timestamp, path, status, duration
- Errors include: error key, sanitized message (no tokens/secrets)
- Sensitive data (OIDC tokens, GitHub tokens) never logged; only SHA-256 hashes if identification needed

## Project Structure

```
octo-sts-rust/
├── src/
│   ├── lib.rs              # Worker entry point, request router
│   ├── config.rs           # Environment/secrets configuration
│   ├── error.rs            # Error types and HTTP response mapping
│   │
│   ├── sts/
│   │   ├── mod.rs
│   │   ├── exchange.rs     # Token exchange endpoint handler
│   │   └── revoke.rs       # Token revocation endpoint
│   │
│   ├── policy/
│   │   ├── mod.rs
│   │   ├── types.rs        # TrustPolicy, OrgTrustPolicy structs
│   │   ├── compile.rs      # Regex compilation, validation
│   │   └── check.rs        # Token-to-policy matching logic
│   │
│   ├── github/
│   │   ├── mod.rs
│   │   ├── auth.rs         # App JWT generation, installation tokens
│   │   ├── api.rs          # GitHub API client
│   │   └── webhook.rs      # Webhook signature verification
│   │
│   ├── oidc/
│   │   ├── mod.rs
│   │   ├── discovery.rs    # OIDC discovery document fetching
│   │   ├── jwks.rs         # JWKS fetching and caching
│   │   └── validate.rs     # Token validation
│   │
│   └── kv/
│       ├── mod.rs
│       └── cache.rs        # KV get/put with TTL helpers
│
├── Cargo.toml              # Dependencies
├── wrangler.toml           # Cloudflare Worker configuration
└── README.md
```

## Dependencies

```toml
[dependencies]
worker = "0.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
jsonwebtoken = "9"
regex = "1"
thiserror = "1"
base64 = "0.21"
```

**Notes:**
- Use `worker::Fetch` for HTTP requests (avoids reqwest WASM complexity)
- Verify `jsonwebtoken` WASM compatibility for RS256 signing
- May need `getrandom` with `js` feature for WASM random number generation

## Configuration

### wrangler.toml

```toml
name = "octo-sts"
main = "build/worker/shim.mjs"
compatibility_date = "2024-01-01"

[build]
command = "cargo install -q worker-build && worker-build --release"

[vars]
DOMAIN = "octo-sts.example.com"

[[kv_namespaces]]
binding = "OCTO_STS_KV"
id = "<kv-namespace-id>"
```

### Secrets (via `wrangler secret put`)

- `GITHUB_APP_ID`
- `GITHUB_APP_PRIVATE_KEY`
- `GITHUB_WEBHOOK_SECRET`

## Future Considerations

Not in scope for initial implementation, but worth noting:

- **Metrics export:** Could add Workers Analytics Engine integration
- **Rate limiting:** Could use Workers KV or Durable Objects for per-org limits
- **Allowlist:** Optional org allowlist for webhook processing (environment variable)
- **Multi-region KV:** Consider KV replication settings for global latency
