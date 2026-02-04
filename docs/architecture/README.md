# octo-sts-rust Architecture

This document describes the architecture of octo-sts-rust, a Cloudflare Workers implementation of the [octo-sts](https://github.com/octo-sts/app) Security Token Service.

## System Overview

octo-sts-rust is a Security Token Service (STS) that exchanges OIDC tokens for short-lived GitHub API tokens. It enables workloads (GitHub Actions, GCP services, etc.) to access GitHub APIs without storing long-lived Personal Access Tokens.

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
              │  (caching)   │           │                 │          │ (validation)│
              └──────────────┘           └─────────────────┘          └─────────────┘
```

## Core Components

### Request Router (`src/lib.rs`)

The Worker entry point. Routes incoming HTTP requests to the appropriate handler:

| Path | Method | Handler |
|------|--------|---------|
| `/` | GET | Health/info endpoint |
| `/sts/exchange` | POST | Token exchange |
| `/sts/revoke` | POST | Token revocation |
| `/webhook` | POST | GitHub webhook handler |

### STS Module (`src/sts/`)

Implements the core token exchange and revocation logic.

**exchange.rs** - The main token exchange flow:
1. Parse and validate the incoming OIDC token
2. Load and match against trust policies
3. Generate a scoped GitHub installation token

**revoke.rs** - Proxies revocation requests to GitHub's API.

### Policy Module (`src/policy/`)

Handles trust policy parsing, compilation, and matching.

**types.rs** - Defines `TrustPolicy` and `OrgTrustPolicy` structs matching the YAML schema.

**compile.rs** - Compiles regex patterns and validates policy structure.

**check.rs** - Matches OIDC token claims against compiled policies.

### GitHub Module (`src/github/`)

All GitHub API interactions.

**auth.rs** - Generates GitHub App JWTs and requests installation tokens.

**api.rs** - Client for GitHub API (fetching policies, installation IDs).

**webhook.rs** - Verifies webhook signatures and handles events.

### OIDC Module (`src/oidc/`)

OIDC token validation per RFC 8414 and OpenID Connect Core 1.0.

**discovery.rs** - Fetches `.well-known/openid-configuration` documents.

**jwks.rs** - Fetches and caches JSON Web Key Sets.

**validate.rs** - Validates issuer URLs, subjects, and audiences.

### KV Module (`src/kv/`)

Workers KV caching layer.

**cache.rs** - Type-safe get/put operations with TTL management.

## Data Flow: Token Exchange

```
                                    ┌─────────────────────────────────────┐
                                    │         Token Exchange Flow         │
                                    └─────────────────────────────────────┘

┌──────────┐    POST /sts/exchange    ┌──────────────┐
│  Client  │ ────────────────────────▶│   Router     │
└──────────┘    + OIDC Bearer Token   └──────┬───────┘
                                             │
                                             ▼
                                    ┌──────────────────┐
                                    │  Parse Request   │
                                    │  - scope         │
                                    │  - identity      │
                                    │  - bearer token  │
                                    └────────┬─────────┘
                                             │
              ┌──────────────────────────────┼──────────────────────────────┐
              │                              │                              │
              ▼                              ▼                              ▼
     ┌─────────────────┐          ┌──────────────────┐           ┌─────────────────┐
     │ Validate OIDC   │          │  Load Trust      │           │ Get Installation│
     │ - fetch JWKS    │          │  Policy          │           │ ID              │
     │ - verify sig    │          │  - check KV      │           │ - check KV      │
     │ - check claims  │          │  - fetch from GH │           │ - fetch from GH │
     └────────┬────────┘          └────────┬─────────┘           └────────┬────────┘
              │                            │                              │
              └──────────────────────────────┼──────────────────────────────┘
                                             │
                                             ▼
                                    ┌──────────────────┐
                                    │  Match Policy    │
                                    │  - issuer        │
                                    │  - subject       │
                                    │  - audience      │
                                    │  - custom claims │
                                    └────────┬─────────┘
                                             │
                                             ▼
                                    ┌──────────────────┐
                                    │ Generate GitHub  │
                                    │ Token            │
                                    │ - sign App JWT   │
                                    │ - request token  │
                                    │ - scope perms    │
                                    └────────┬─────────┘
                                             │
                                             ▼
┌──────────┐     GitHub Token       ┌──────────────────┐
│  Client  │ ◀──────────────────────│   Response       │
└──────────┘                        └──────────────────┘
```

## Trust Policy System

Trust policies define which OIDC tokens can be exchanged for GitHub tokens with what permissions.

### Policy Location

Policies are stored in repositories at `.github/chainguard/{name}.sts.yaml`.

### Policy Types

**Repository Policy** - Applies to a single repository:
```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:org/repo:ref:refs/heads/main
permissions:
  contents: read
```

**Organization Policy** - Stored in `.github` repo, can scope to multiple repos:
```yaml
issuer: https://accounts.google.com
subject_pattern: "^\\d+$"
permissions:
  contents: read
repositories:
  - repo-a
  - repo-b
```

### Matching Rules

- `issuer` or `issuer_pattern` (exactly one required)
- `subject` or `subject_pattern` (exactly one required)
- `audience` or `audience_pattern` (optional, defaults to service domain)
- `claim_patterns` (optional custom claim matching)
- Regex patterns are auto-anchored with `^...$`

## Caching Strategy

Workers KV caches two types of data to reduce GitHub API calls:

| Data | Key Pattern | TTL | Rationale |
|------|-------------|-----|-----------|
| Installation IDs | `install:{owner}` | 1 hour | Rarely change |
| Trust Policies | `policy:{owner}/{repo}/{identity}` | 5 minutes | May be updated during development |

## Security Model

### Secrets Management

| Secret | Purpose |
|--------|---------|
| `GITHUB_APP_ID` | Identifies the GitHub App |
| `GITHUB_APP_PRIVATE_KEY` | Signs App JWTs (RSA PKCS#8 PEM) |
| `GITHUB_WEBHOOK_SECRET` | Validates webhook signatures |

### Token Security

- OIDC tokens are validated cryptographically against issuer JWKS
- GitHub tokens are scoped to only the permissions specified in the trust policy
- Tokens are never logged; only SHA-256 hashes for identification
- All sensitive operations use constant-time comparison

### Webhook Security

- Signatures verified using HMAC-SHA256
- Constant-time comparison prevents timing attacks
- Only processes events from installed repositories

## Error Handling

Errors are categorized for appropriate client feedback:

| Category | HTTP Status | Logged |
|----------|-------------|--------|
| Client errors (bad input) | 4xx | Minimal |
| Policy violations | 403 | Yes, without tokens |
| Server errors | 5xx | Full details |

## Deployment

### Cloudflare Workers Configuration

```toml
# wrangler.toml
name = "octo-sts"
main = "build/worker/shim.mjs"

[[kv_namespaces]]
binding = "OCTO_STS_KV"
id = "<namespace-id>"

[vars]
DOMAIN = "octo-sts.example.com"
```

### Required Setup

1. Create a GitHub App with appropriate permissions
2. Create a Workers KV namespace
3. Configure secrets via `wrangler secret put`
4. Deploy with `wrangler deploy`

## Related Documents

- [Design Document](../plans/2026-02-03-octo-sts-rust-design.md) - Original design decisions and rationale
- [Original octo-sts](https://github.com/octo-sts/app) - The Go implementation this ports
