# CLAUDE.md - Project Context for Claude

This file provides context for Claude Code when working on this project.

## Project Overview

octo-sts-rust is a Rust port of [octo-sts](https://github.com/octo-sts/app), a GitHub Security Token Service. It exchanges OIDC tokens for short-lived GitHub API tokens, deployed on Cloudflare Workers.

## Key Documentation

- **Architecture:** `docs/architecture/README.md` - System design, components, data flow
- **Design decisions:** `docs/plans/2026-02-03-octo-sts-rust-design.md` - Original design rationale

## Project Structure

```
src/
├── lib.rs           # Worker entry point, request router
├── config.rs        # Environment/secrets configuration
├── error.rs         # Error types and HTTP response mapping
├── sts/             # Token exchange and revocation
├── policy/          # Trust policy parsing and matching
├── github/          # GitHub API client and auth
├── oidc/            # OIDC token validation
└── kv/              # Workers KV caching
```

## Key Concepts

**Trust Policies:** YAML files at `.github/chainguard/{name}.sts.yaml` that define which OIDC tokens can be exchanged for GitHub tokens with what permissions.

**Token Exchange Flow:** OIDC token → validate signature → match policy → generate GitHub installation token with scoped permissions.

## Build and Deploy

```bash
# Development
wrangler dev

# Deploy
wrangler deploy

# Set secrets
wrangler secret put GITHUB_APP_ID
wrangler secret put GITHUB_APP_PRIVATE_KEY
wrangler secret put GITHUB_WEBHOOK_SECRET
```

## Dependencies

- `worker` - Cloudflare Workers SDK
- `jsonwebtoken` - JWT handling
- `serde_yaml` - Trust policy parsing
- `regex` - Pattern matching

## Testing

Tests should cover:
- Policy parsing and compilation
- OIDC claim validation
- Policy matching logic
- Error handling paths

## Common Tasks

When modifying trust policy logic, check `src/policy/`.
When modifying GitHub API interactions, check `src/github/`.
When modifying OIDC validation, check `src/oidc/`.
When modifying caching behavior, check `src/kv/`.
