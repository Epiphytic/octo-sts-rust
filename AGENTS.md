# AGENTS.md - AI Agent Instructions

Instructions for AI agents working on this codebase.

## Project Summary

**octo-sts-rust** is a Cloudflare Workers application (Rust/WASM) that exchanges OIDC tokens for GitHub API tokens. It's a port of [octo-sts/app](https://github.com/octo-sts/app) from Go.

## Architecture Documents

Read these before making changes:

| Document | Location | Purpose |
|----------|----------|---------|
| Architecture | `docs/architecture/README.md` | System design, components, data flow diagrams |
| Design | `docs/plans/2026-02-03-octo-sts-rust-design.md` | Original design decisions and API spec |

## Module Map

| Module | Path | Responsibility |
|--------|------|----------------|
| Router | `src/lib.rs` | HTTP request routing |
| Config | `src/config.rs` | Environment and secrets |
| Errors | `src/error.rs` | Error types, HTTP mapping |
| STS | `src/sts/` | Token exchange, revocation |
| Policy | `src/policy/` | Trust policy parsing, matching |
| GitHub | `src/github/` | API client, App auth, webhooks |
| OIDC | `src/oidc/` | Token validation, JWKS |
| KV | `src/kv/` | Workers KV caching |

## API Endpoints

```
GET  /                 → Health check
POST /sts/exchange     → OIDC → GitHub token
POST /sts/revoke       → Revoke GitHub token
POST /webhook          → GitHub webhook handler
```

## Key Types

- `TrustPolicy` - Repository-level trust policy
- `OrgTrustPolicy` - Organization-level trust policy (extends TrustPolicy)
- `ExchangeRequest` - Token exchange request parameters
- `ExchangeResponse` - Token exchange response with access_token

## External Dependencies

- **GitHub API** - Token generation, policy fetching, webhooks
- **OIDC Providers** - Token validation (GitHub Actions, Google, etc.)
- **Workers KV** - Caching (binding: `OCTO_STS_KV`)

## Secrets

- `GITHUB_APP_ID` - GitHub App numeric ID
- `GITHUB_APP_PRIVATE_KEY` - RSA private key (PEM)
- `GITHUB_WEBHOOK_SECRET` - Webhook HMAC secret

## Testing Guidance

1. Policy matching is security-critical - test thoroughly
2. OIDC validation must reject malformed tokens
3. GitHub token scoping must match policy permissions exactly
4. Webhook signatures must use constant-time comparison

## Common Pitfalls

- **WASM compatibility** - Not all crates work in Workers; prefer `worker::Fetch` over `reqwest`
- **Async** - Workers uses `wasm-bindgen-futures`; all async must be compatible
- **Crypto** - Use Web Crypto API via `worker` crate; avoid native crypto crates
- **KV consistency** - Workers KV is eventually consistent; cache TTLs account for this
