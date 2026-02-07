# octo-sts-rust

A Rust implementation of [octo-sts](https://github.com/octo-sts/app) — a GitHub Security Token Service.

## What is this?

octo-sts-rust is a drop-in replacement for [octo-sts](https://github.com/octo-sts/app) that exchanges OIDC tokens for short-lived GitHub API tokens. It eliminates the need for long-lived Personal Access Tokens (PATs) by enabling workloads to federate their identity with GitHub.

**Example use case:** A GitHub Actions workflow in repo A needs to access repo B. Instead of storing a PAT, the workflow exchanges its OIDC token for a scoped GitHub token that only has the permissions defined in a trust policy.

### Added features beyond octo-sts

- **PAT exchange** — Exchange a GitHub PAT or OAuth token for a scoped GitHub App installation token, restricted by org membership and policy
- **Multi-platform** — Runs on both Cloudflare Workers (WASM) and GCP Cloud Run (native binary)
- **GCP KMS signing** — Optionally sign GitHub App JWTs using GCP Cloud KMS asymmetric keys so the private key never leaves the HSM

## Quick Start

### OIDC token exchange

```bash
curl -X POST "https://your-sts.example.com/sts/exchange?scope=org/repo&identity=deploy" \
  -H "Authorization: Bearer $OIDC_TOKEN"
```

### PAT exchange

```bash
curl -X POST "https://your-sts.example.com/sts/exchange/pat?scope=org/.github&identity=my-pat-policy" \
  -H "Authorization: Bearer $GITHUB_PAT"
```

Response (both endpoints):
```json
{
  "access_token": "ghs_xxxx",
  "token_type": "bearer",
  "expires_in": 3600
}
```

## Architecture

```
octo-sts-rust/
├── core/           # Platform-agnostic business logic (Cargo lib crate)
├── cloudflare/     # Cloudflare Workers adapter (WASM)
├── gcp/            # GCP Cloud Run adapter (native binary)
└── terraform/      # Infrastructure-as-code for Cloudflare
```

The project is a Cargo workspace. All business logic lives in `core/` and depends only on abstract platform traits (`Cache`, `HttpClient`, `Clock`, `Environment`, `JwtSigner`). The `cloudflare/` and `gcp/` crates provide platform-specific implementations.

```
┌──────────────────┐     ┌──────────────────┐
│  cloudflare/     │     │  gcp/            │
│  Workers KV      │     │  Moka cache      │
│  Fetch API       │     │  reqwest HTTP    │
│  Web Crypto      │     │  KMS or PEM sign │
└────────┬─────────┘     └────────┬─────────┘
         │                        │
         └──────────┬─────────────┘
                    │
           ┌────────▼─────────┐
           │  core/           │
           │  OIDC validation │
           │  Policy matching │
           │  GitHub API      │
           │  Token exchange  │
           └──────────────────┘
```

## Trust Policies

Trust policies define who can get what permissions. They are YAML files stored in your org's `.github` repo (or individual repos) at `.github/chainguard/{name}.sts.yaml`.

### OIDC trust policy

```yaml
# .github/chainguard/deploy.sts.yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
permissions:
  contents: read
```

### Organization-level policy

Stored in the `.github` repo, scoped to multiple repositories:

```yaml
# .github/chainguard/ci-deploy.sts.yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: "^repo:myorg/.*:ref:refs/heads/main$"
permissions:
  contents: read
  pull_requests: write
repositories:
  - repo-a
  - repo-b
```

### PAT trust policy

```yaml
# .github/chainguard/dev-access.pat.yaml
required_org: myorg
permissions:
  contents: write
  pull_requests: write
repositories:
  - repo-a
  - repo-b
```

### Matching rules

- `issuer` or `issuer_pattern` (exactly one required)
- `subject` or `subject_pattern` (exactly one required)
- `audience` or `audience_pattern` (optional, defaults to service domain)
- `claim_patterns` (optional, custom OIDC claim matching)
- Regex patterns are auto-anchored with `^...$`

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Health check |
| `POST` | `/sts/exchange?scope={owner/repo}&identity={name}` | Exchange OIDC token for GitHub token |
| `POST` | `/sts/exchange/pat?scope={owner/repo}&identity={name}` | Exchange PAT for scoped GitHub token |
| `POST` | `/sts/revoke` | Revoke a GitHub token |
| `POST` | `/webhook` | GitHub webhook handler (policy validation) |

All exchange endpoints require `Authorization: Bearer <token>` header.

**Scope formats:**
- `owner/repo` — repo-level policy, token scoped to that repo
- `owner/.github` — org-level policy, token scoped to repositories listed in the policy

## Deployment

### Option 1: Cloudflare Workers

**Prerequisites:** Cloudflare account, Wrangler CLI, GitHub App

```bash
cd cloudflare

# Create KV namespace
wrangler kv namespace create OCTO_STS_KV
# Update wrangler.toml with the returned ID

# Set secrets
wrangler secret put GITHUB_APP_ID
wrangler secret put GITHUB_APP_PRIVATE_KEY
wrangler secret put GITHUB_WEBHOOK_SECRET

# Deploy
wrangler deploy
```

### Option 2: GCP Cloud Run

**Prerequisites:** GCP project, Docker, GitHub App

```bash
cd gcp

# Build
cargo build -p octo-sts-gcp --release

# Required environment variables
export GITHUB_APP_ID=12345
export GITHUB_WEBHOOK_SECRET=your-webhook-secret
export DOMAIN=https://sts.example.com

# Choose ONE signing mode:

# Option A: PEM key (private key in environment variable)
export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."

# Option B: KMS signing (private key stays in Cloud KMS HSM)
export KMS_KEY_NAME="projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1"

# Run
./target/release/octo-sts-gcp
```

The GCP adapter auto-detects the signing mode: if `KMS_KEY_NAME` is set, it uses Cloud KMS; otherwise it uses the PEM key from `GITHUB_APP_PRIVATE_KEY`.

### GitHub App configuration

Create a GitHub App with:
- **Webhook URL:** `https://your-sts.example.com/webhook`
- **Webhook secret:** (generate and save as `GITHUB_WEBHOOK_SECRET`)
- **Permissions:** Must include at least the permissions you want to grant via policies
- **Events:** `push` (for policy validation via Check Runs)

## GCP KMS signing

When deployed on GCP with `KMS_KEY_NAME` set, the service signs GitHub App JWTs using Cloud KMS `asymmetricSign`. The private key never leaves the HSM.

**Setup:**
1. Create an RSA key in Cloud KMS (`RSA_SIGN_PKCS1_2048_SHA256` or `RSA_SIGN_PKCS1_4096_SHA256`)
2. Export the public key and upload it to the GitHub App settings
3. Grant the Cloud Run service account `roles/cloudkms.signerVerifier` on the key
4. Set `KMS_KEY_NAME` to the full key version resource name

## Differences from original octo-sts

### What's the same

- **API compatibility** — Same HTTP endpoints and request/response format
- **Trust policy format** — Same YAML schema in `.github/chainguard/*.sts.yaml`
- **Core functionality** — OIDC validation, policy matching, token generation
- **Webhook validation** — Check Runs for policy file validation

### What's new

| Feature | Original (Go) | This (Rust) |
|---------|---------------|-------------|
| **PAT exchange** | Not supported | `POST /sts/exchange/pat` |
| **Platforms** | GCP only | Cloudflare Workers + GCP |
| **KMS signing** | GCP KMS | GCP KMS (GCP adapter) |
| **PEM signing** | PEM key | PEM key (both adapters) |

### Platform comparison

| Aspect | Cloudflare Workers | GCP Cloud Run |
|--------|-------------------|---------------|
| **Caching** | Workers KV (global, eventually consistent) | Moka in-memory (local) |
| **HTTP client** | Fetch API | reqwest |
| **Signing** | PEM only | PEM or KMS |
| **Cold start** | <1ms | ~100ms |
| **Protocol** | HTTP only | HTTP only |

## Build and test

```bash
# Run core unit tests (59 tests)
cargo test -p octo-sts-core

# Check Cloudflare WASM build
cargo check -p octo-sts-cloudflare --target wasm32-unknown-unknown

# Build GCP binary
cargo build -p octo-sts-gcp --release
```

## License

Apache-2.0 (same as original octo-sts)

## Acknowledgments

This project is a port of [octo-sts/app](https://github.com/octo-sts/app) by Chainguard, Inc.
