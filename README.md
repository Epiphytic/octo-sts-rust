# octo-sts-rust

A Rust implementation of [octo-sts](https://github.com/octo-sts/app) for Cloudflare Workers.

## What is this?

octo-sts-rust is a Security Token Service (STS) that exchanges OIDC tokens for short-lived GitHub API tokens. It eliminates the need for Personal Access Tokens (PATs) by enabling workloads to federate their identity with GitHub.

**Example use case:** A GitHub Actions workflow in repo A needs to access repo B. Instead of storing a PAT, the workflow exchanges its OIDC token for a scoped GitHub token that only has the permissions defined in a trust policy.

## Quick Start

```bash
# Exchange an OIDC token for a GitHub token
curl -X POST "https://your-worker.workers.dev/sts/exchange?scope=org/repo&identity=deploy" \
  -H "Authorization: Bearer $OIDC_TOKEN"
```

Response:
```json
{
  "access_token": "ghs_xxxx",
  "token_type": "bearer",
  "expires_in": 3600
}
```

## Trust Policies

Define who can get what permissions by creating `.github/chainguard/{name}.sts.yaml` in your repository:

```yaml
# Allow GitHub Actions from main branch to read contents
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
permissions:
  contents: read
```

See the [architecture documentation](docs/architecture/README.md) for the full policy schema.

## Differences from Original octo-sts

This is a Rust port of the original Go implementation, designed for Cloudflare Workers deployment.

### What's the Same

- **API compatibility** - Same HTTP endpoints and request/response format
- **Trust policy format** - Same YAML schema in `.github/chainguard/*.sts.yaml`
- **Core functionality** - OIDC validation, policy matching, token generation
- **Webhook validation** - Check Runs for policy file validation

### What's Different

| Aspect | Original (Go) | This Port (Rust) |
|--------|---------------|------------------|
| **Runtime** | Cloud Run / GKE | Cloudflare Workers |
| **Protocol** | gRPC + HTTP | HTTP only |
| **Caching** | In-memory LRU | Workers KV |
| **Crypto** | GCP KMS | Web Crypto API |
| **Cold start** | ~100ms | <1ms |

### Tradeoffs

**No gRPC support** - The original serves both gRPC and HTTP. Cloudflare Workers only supports HTTP natively, so this implementation is HTTP-only. If you have gRPC clients, they'll need to use the HTTP endpoint instead. The HTTP API is identical to the original's HTTP gateway.

**No GCP KMS** - The original can use GCP KMS for key management. This implementation stores the GitHub App private key in Workers Secrets and uses Web Crypto API for signing. This is simpler but means the private key is directly accessible to the Worker code.

**Different caching semantics** - Workers KV is eventually consistent with global replication, while the original uses local in-memory caches. Policy changes may take slightly longer to propagate (typically <60 seconds globally).

## Deployment

### Prerequisites

- Cloudflare account with Workers enabled
- GitHub App with appropriate permissions
- Wrangler CLI installed

### Setup

1. Clone and configure:
   ```bash
   git clone https://github.com/your-org/octo-sts-rust
   cd octo-sts-rust
   ```

2. Create KV namespace:
   ```bash
   wrangler kv namespace create OCTO_STS_KV
   # Update wrangler.toml with the returned ID
   ```

3. Set secrets:
   ```bash
   wrangler secret put GITHUB_APP_ID
   wrangler secret put GITHUB_APP_PRIVATE_KEY
   wrangler secret put GITHUB_WEBHOOK_SECRET
   ```

4. Deploy:
   ```bash
   wrangler deploy
   ```

### GitHub App Configuration

Create a GitHub App with these settings:

- **Webhook URL:** `https://your-worker.workers.dev/webhook`
- **Webhook secret:** (generate and save for `GITHUB_WEBHOOK_SECRET`)
- **Permissions:** Match the permissions you want to grant via policies
- **Events:** `push`, `pull_request`, `check_suite`

## API Reference

### Token Exchange

```
POST /sts/exchange?scope={owner/repo}&identity={policy-name}
Authorization: Bearer <oidc-token>
```

### Token Revocation

```
POST /sts/revoke
Authorization: Bearer <github-token>
```

### Health Check

```
GET /
```

## Documentation

- [Architecture](docs/architecture/README.md) - System design and components
- [Design Document](docs/plans/2026-02-03-octo-sts-rust-design.md) - Original design decisions

## License

Apache-2.0 (same as original octo-sts)

## Acknowledgments

This project is a port of [octo-sts/app](https://github.com/octo-sts/app) by Chainguard, Inc.
