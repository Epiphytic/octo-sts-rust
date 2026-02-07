# octo-sts-rust Architecture

This document describes the architecture of octo-sts-rust, a multi-platform implementation of the [octo-sts](https://github.com/octo-sts/app) Security Token Service.

## System Overview

octo-sts-rust is a Security Token Service (STS) that exchanges OIDC tokens (and GitHub PATs) for short-lived GitHub API tokens. It enables workloads (GitHub Actions, GCP services, etc.) to access GitHub APIs without storing long-lived credentials.

The project is a Cargo workspace with three crates:

```
┌──────────────────┐     ┌──────────────────┐
│  cloudflare/     │     │  gcp/            │
│  (WASM cdylib)   │     │  (native binary) │
│                  │     │                  │
│  Workers KV      │     │  Moka cache      │
│  Fetch API       │     │  reqwest HTTP    │
│  JS clock        │     │  System clock    │
│  PEM signing     │     │  PEM or KMS sign │
└────────┬─────────┘     └────────┬─────────┘
         │                        │
         └──────────┬─────────────┘
                    │
           ┌────────▼─────────┐
           │  core/           │
           │  (platform-      │
           │   agnostic lib)  │
           │                  │
           │  OIDC validation │
           │  Policy matching │
           │  GitHub API      │
           │  Token exchange  │
           │  PAT exchange    │
           └──────────────────┘
```

## Platform Abstraction

All core logic depends on traits defined in `core/src/platform.rs`:

| Trait | Purpose | Cloudflare impl | GCP impl |
|-------|---------|----------------|----------|
| `Cache` | Key-value storage with TTL | Workers KV | Moka (in-memory) |
| `HttpClient` | Outbound HTTP requests | Fetch API | reqwest |
| `Clock` | Current timestamp | `Date.now()` via js-sys | `SystemTime` |
| `Environment` | Env vars and secrets | Worker env bindings | `std::env` |
| `JwtSigner` | GitHub App JWT signing | `PemJwtSigner` | `PemJwtSigner` or `KmsJwtSigner` |

All async traits use `#[async_trait(?Send)]` for WASM compatibility (Cloudflare Workers are single-threaded).

## Core Components

### STS Module (`core/src/sts/`)

**exchange.rs** — OIDC token exchange:
1. Validate the incoming OIDC token (signature, claims, audience)
2. Load and match against trust policies from `.github/chainguard/{name}.sts.yaml`
3. Detect org-level vs repo-level scope
4. Generate a scoped GitHub installation token

**exchange_pat.rs** — PAT exchange:
1. Validate the PAT against GitHub's `/user` API
2. Load PAT trust policy from `.github/chainguard/{name}.pat.yaml`
3. Check org membership using the PAT
4. Generate a scoped GitHub installation token

**revoke.rs** — Proxies revocation requests to GitHub's API.

### Policy Module (`core/src/policy/`)

**types.rs** — `TrustPolicy` and `OrgTrustPolicy` structs matching the YAML schema.

**compile.rs** — Compiles regex patterns, validates policy structure, produces `CompiledPolicy`.

**check.rs** — Matches OIDC token claims against compiled policies.

**mod.rs** — Policy loading with caching. Fetches policies from GitHub using the App's own installation token.

### GitHub Module (`core/src/github/`)

**auth.rs** — GitHub App authentication:
- `PemJwtSigner` — Signs App JWTs locally using an RSA PEM private key
- `get_installation_id()` — Finds the App's installation for an org
- `create_installation_token()` — Requests a scoped installation token from GitHub

**api.rs** — GitHub REST API client (fetching policy files, creating check runs).

**webhook.rs** — Webhook signature verification (HMAC-SHA256) and push event handling for policy validation.

### OIDC Module (`core/src/oidc/`)

**discovery.rs** — Fetches `.well-known/openid-configuration` documents per RFC 8414.

**jwks.rs** — Fetches and caches JSON Web Key Sets.

**validate.rs** — Validates OIDC token signatures, issuers, subjects, and audiences.

### GCP KMS Module (`gcp/src/kms.rs`)

**KmsJwtSigner** — Signs GitHub App JWTs using GCP Cloud KMS:
1. Constructs JWT header and claims locally
2. Computes SHA-256 digest of the signing input
3. Sends digest to KMS `asymmetricSign` API
4. Assembles the final JWT from KMS signature

The private key never leaves the Cloud KMS HSM. GCP access tokens are fetched from the metadata server and cached (~55 min TTL).

## Data Flow: OIDC Token Exchange

```
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
     │ - verify sig    │          │  - check cache   │           │ - check cache   │
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
                                    │   (PEM or KMS)   │
                                    │ - request token  │
                                    │ - scope perms    │
                                    └────────┬─────────┘
                                             │
                                             ▼
┌──────────┐     GitHub Token       ┌──────────────────┐
│  Client  │ ◀──────────────────────│   Response       │
└──────────┘                        └──────────────────┘
```

## Data Flow: PAT Exchange

```
┌──────────┐    POST /sts/exchange/pat    ┌──────────────┐
│  Client  │ ────────────────────────────▶│   Router     │
└──────────┘    + PAT Bearer Token        └──────┬───────┘
                                                 │
                                                 ▼
                                        ┌──────────────────┐
                                        │ Validate PAT     │
                                        │ GET /user         │
                                        └────────┬─────────┘
                                                 │
                                  ┌──────────────┼───────────────┐
                                  │              │               │
                                  ▼              ▼               ▼
                         ┌──────────────┐ ┌────────────┐ ┌────────────────┐
                         │ Load PAT     │ │ Check Org  │ │ Check Repo     │
                         │ Policy       │ │ Membership │ │ Access         │
                         │ (.pat.yaml)  │ │ GET /orgs  │ │ (policy list)  │
                         └──────┬───────┘ └─────┬──────┘ └───────┬────────┘
                                │               │                │
                                └───────────────┼────────────────┘
                                                │
                                                ▼
                                       ┌──────────────────┐
                                       │ Generate GitHub  │
                                       │ Token            │
                                       │ (same as OIDC)   │
                                       └──────────────────┘
```

## Trust Policy System

### Policy Location

Policies are stored in repositories at `.github/chainguard/{name}.sts.yaml` (OIDC) or `.github/chainguard/{name}.pat.yaml` (PAT).

### Policy Types

**Repository OIDC Policy** — Stored in a repo, applies to that repo:
```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:org/repo:ref:refs/heads/main
permissions:
  contents: read
```

**Organization OIDC Policy** — Stored in `.github` repo, scopes to multiple repos:
```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "^repo:myorg/.*:ref:refs/heads/main$"
permissions:
  contents: read
  pull_requests: write
repositories:
  - repo-a
  - repo-b
```

**PAT Policy** — Stored in `.github` repo:
```yaml
required_org: myorg
permissions:
  contents: write
repositories:
  - repo-a
  - repo-b
```

### OIDC Matching Rules

- `issuer` or `issuer_pattern` (exactly one required)
- `subject` or `subject_pattern` (exactly one required)
- `audience` or `audience_pattern` (optional, defaults to service domain)
- `claim_patterns` (optional custom claim matching)
- Regex patterns are auto-anchored with `^...$`

### Org-level vs Repo-level Scoping

When scope is `owner/.github` (org-level):
- Policy is loaded from the `.github` repo
- Repository access check is skipped
- Installation token is scoped to the policy's `repositories` list

When scope is `owner/repo` (repo-level):
- Policy is loaded from the target repo (or `.github` repo)
- Repository is validated against the policy's `repositories` list
- Installation token is scoped to the requested repo

## Caching Strategy

Both platforms cache to reduce GitHub API calls:

| Data | Key Pattern | TTL | Rationale |
|------|-------------|-----|-----------|
| Installation IDs | `install:{owner}` | 1 hour | Rarely change |
| OIDC Trust Policies | `policy:{owner}/{repo}/{identity}` | 5 minutes | May be updated during development |
| PAT Trust Policies | `pat-policy:{scope}:{identity}` | 5 minutes | May be updated during development |

## Security Model

### Secrets Management

| Secret | Purpose | Cloudflare | GCP |
|--------|---------|-----------|-----|
| `GITHUB_APP_ID` | Identifies the GitHub App | Worker secret | Env var |
| `GITHUB_APP_PRIVATE_KEY` | Signs App JWTs (PEM mode) | Worker secret | Env var |
| `KMS_KEY_NAME` | KMS key reference (KMS mode) | N/A | Env var |
| `GITHUB_WEBHOOK_SECRET` | Validates webhook signatures | Worker secret | Env var |

### JWT Signing Modes

**PEM mode** (both platforms): The RSA private key is stored as an environment variable/secret. `PemJwtSigner` in `core/src/github/auth.rs` uses `surrealdb-jsonwebtoken` to sign JWTs.

**KMS mode** (GCP only): The RSA private key is stored in Cloud KMS. `KmsJwtSigner` in `gcp/src/kms.rs` constructs the JWT locally, computes a SHA-256 digest, and sends it to KMS for signing. The private key never leaves the HSM.

### Token Security

- OIDC tokens are validated cryptographically against issuer JWKS
- PATs are validated by calling GitHub's `/user` API
- GitHub installation tokens are scoped to only the permissions specified in the trust policy
- Tokens are never logged; only SHA-256 hashes for identification
- Webhook signatures use HMAC-SHA256 with constant-time comparison

## API Endpoints

| Path | Method | Handler |
|------|--------|---------|
| `/` | GET | Health/info |
| `/sts/exchange` | POST | OIDC token exchange |
| `/sts/exchange/pat` | POST | PAT exchange |
| `/sts/revoke` | POST | Token revocation |
| `/webhook` | POST | GitHub webhook handler |

## Error Handling

| Category | HTTP Status | Logged |
|----------|-------------|--------|
| Client errors (bad input) | 4xx | Minimal |
| Policy violations | 403 | Yes, without tokens |
| Server errors | 5xx | Full details |

## Related Documents

- [Design Document](../plans/2026-02-03-octo-sts-rust-design.md) - Original design decisions
- [Multi-Platform Design](../plans/2026-02-04-multi-platform-design.md) - Workspace architecture
- [Original octo-sts](https://github.com/octo-sts/app) - The Go implementation this ports
