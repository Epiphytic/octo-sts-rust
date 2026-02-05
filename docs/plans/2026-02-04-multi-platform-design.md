# Multi-Platform Support: Cloudflare Workers + GCP Cloud Functions

**Date:** 2026-02-04
**Status:** Proposed

## Goal

Enable users to deploy octo-sts-rust to either Cloudflare Workers or GCP Cloud Functions from the same codebase. Users build from source and select their target platform. Full feature parity is required: OIDC token exchange, PAT token exchange, token revocation, webhook handling, and caching must work identically on both platforms.

## Architecture Overview

The codebase splits into three layers:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Platform Entrypoints                        │
│  ┌─────────────────────┐         ┌─────────────────────┐       │
│  │  cloudflare/        │         │  gcp/               │       │
│  │  - lib.rs (Worker)  │         │  - main.rs (HTTP)   │       │
│  │  - cache.rs (KV)    │         │  - cache.rs (FS)    │       │
│  │  - http.rs (Fetch)  │         │  - http.rs (reqwest)│       │
│  │  - env.rs           │         │  - env.rs           │       │
│  └──────────┬──────────┘         └──────────┬──────────┘       │
└─────────────┼───────────────────────────────┼───────────────────┘
              │                               │
              ▼                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Platform Traits                            │
│  Cache, HttpClient, Clock, Environment                          │
└─────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Core Logic                              │
│  policy/, oidc/, github/, sts/, error.rs, config.rs            │
│  (100% platform-agnostic, uses traits only)                    │
└─────────────────────────────────────────────────────────────────┘
```

**Build targets:**
- Cloudflare: `wasm32-unknown-unknown` deployed via `wrangler`
- GCP: `x86_64-unknown-linux-gnu` containerized as a Cloud Function

**Key principle:** Core logic never imports `worker::*` or GCP-specific crates. It depends only on the trait abstractions and standard async Rust.

## Platform Traits

Four traits abstract platform-specific functionality. Core logic depends only on these.

```rust
// core/src/platform.rs

/// Key-value cache with TTL support
#[async_trait]
pub trait Cache: Send + Sync {
    async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>>;
    async fn put<T: Serialize>(&self, key: &str, value: &T, ttl_secs: u64) -> Result<()>;
}

/// HTTP client for outbound requests (GitHub API, OIDC discovery)
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse>;
    async fn post(&self, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<HttpResponse>;
}

pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Clock for current time (enables testing)
pub trait Clock: Send + Sync {
    fn now_secs(&self) -> u64;
}

/// Environment/secrets access
pub trait Environment: Send + Sync {
    fn get_var(&self, name: &str) -> Result<String>;
    fn get_secret(&self, name: &str) -> Result<String>;
}
```

**Why these four:**
- `Cache` replaces direct Workers KV calls
- `HttpClient` replaces `worker::Fetch` / platform-specific HTTP
- `Clock` replaces `js_sys::Date::now()`, also makes testing deterministic
- `Environment` replaces `worker::Env` bindings

## Core Module Refactoring

Existing modules become platform-agnostic by accepting trait objects instead of `worker::Env`.

**Before (current code):**
```rust
// src/sts/exchange.rs
pub async fn handle(req: Request, env: &Env) -> Result<ExchangeResponse> {
    let config = Config::from_env(env)?;
    let installation_id = kv::cache::get_or_fetch_installation(owner, env, &config).await?;
    // ...
}
```

**After (refactored):**
```rust
// core/src/sts/exchange.rs
pub async fn handle<C, H, E>(
    request: ExchangeRequest,
    cache: &C,
    http: &H,
    env: &E,
    clock: &dyn Clock,
) -> Result<ExchangeResponse>
where
    C: Cache,
    H: HttpClient,
    E: Environment,
{
    let config = Config::from_env(env)?;
    let installation_id = get_or_fetch_installation(owner, cache, http, &config).await?;
    // ...
}
```

**What moves to `core/`:**
- `policy/` -- unchanged (already platform-agnostic except regex)
- `oidc/` -- swap `worker::Fetch` for `HttpClient` trait
- `github/` -- swap `worker::Fetch` for `HttpClient` trait
- `sts/` -- accept traits, parse platform-neutral request structs
- `error.rs` -- remove `into_response()`, return plain errors
- `config.rs` -- use `Environment` trait

**What stays platform-specific:**
- HTTP request/response parsing (each platform has its own types)
- The actual `Cache`, `HttpClient`, `Clock`, `Environment` implementations

## Cloudflare Adapter

Reorganization of existing code behind trait interfaces.

```rust
// cloudflare/src/lib.rs
use worker::*;

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let cache = CloudflareCache::new(&env)?;
    let http = CloudflareHttp::new();
    let environment = CloudflareEnv::new(&env);
    let clock = CloudflareClock;

    let router = Router::new();
    router
        .post_async("/sts/exchange", |req, _| {
            handle_exchange(req, &cache, &http, &environment, &clock)
        })
        // ... other routes
        .run(req, env)
        .await
}
```

| Trait | Implementation |
|-------|----------------|
| `Cache` | Workers KV via `env.kv()` |
| `HttpClient` | `worker::Fetch::Request` |
| `Clock` | `js_sys::Date::now()` |
| `Environment` | `env.var()` / `env.secret()` |

## GCP Cloud Functions Adapter

New code using GCP-native services.

```rust
// gcp/src/main.rs
use hyper::{Body, Request, Response, Server};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap();

    let cache = FirestoreCache::new().await.unwrap();
    let http = ReqwestHttp::new();
    let environment = GcpEnv::new();
    let clock = SystemClock;

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    // ... hyper server setup with routing
}
```

| Trait | Implementation | Crate |
|-------|----------------|-------|
| `Cache` | Firestore with TTL policy | `firestore` |
| `HttpClient` | reqwest (native TLS) | `reqwest` |
| `Clock` | `std::time::SystemTime` | std |
| `Environment` | `std::env::var()` + Secret Manager | `gcp_secret_manager` |

**Firestore schema:**
```
octo-sts-cache/
├── installations/
│   └── {owner} -> { id: u64, expires_at: Timestamp }
└── policies/
    └── {owner}_{repo}_{identity} -> { policy: JSON, expires_at: Timestamp }
```

Firestore's TTL feature auto-deletes expired documents (configure via a TTL policy on the `expires_at` field).

## Project Structure

Cargo workspace with three crates:

```
octo-sts-rust/
├── Cargo.toml              # Workspace root
├── core/
│   ├── Cargo.toml          # Platform-agnostic logic
│   └── src/
│       ├── lib.rs
│       ├── platform.rs     # Trait definitions
│       ├── config.rs
│       ├── error.rs
│       ├── policy/
│       ├── oidc/
│       ├── github/
│       └── sts/
├── cloudflare/
│   ├── Cargo.toml          # depends on core, worker crate
│   ├── wrangler.toml
│   └── src/
│       ├── lib.rs          # #[event(fetch)] entrypoint
│       ├── cache.rs        # Workers KV impl
│       ├── http.rs         # Fetch impl
│       └── env.rs          # Env impl
├── gcp/
│   ├── Cargo.toml          # depends on core, hyper, firestore
│   ├── Dockerfile
│   └── src/
│       ├── main.rs         # HTTP server entrypoint
│       ├── cache.rs        # Firestore impl
│       ├── http.rs         # reqwest impl
│       └── env.rs          # std::env + Secret Manager impl
├── terraform/              # Existing CF config + new GCP module
└── docs/
```

**Shared dependencies** (in `core/Cargo.toml`): `serde`, `serde_json`, `serde_yaml`, `regex`, `thiserror`, `base64`, `url`, `hex`, `async-trait`.

**Build commands:**
```bash
# Cloudflare
cd cloudflare && wrangler deploy

# GCP
cd gcp && cargo build --release
docker build -t octo-sts-gcp .
gcloud functions deploy octo-sts --gen2 --runtime=docker ...
```

## Testing Strategy

Three tiers of tests:

### Tier 1: Core unit tests

The 56 existing tests for policy parsing, OIDC validation, and claim matching move to `core/` unchanged. Functions that now require traits use mock implementations:

```rust
// core/src/test_support.rs
pub struct MockCache(HashMap<String, Vec<u8>>);
pub struct MockHttp(Vec<(String, HttpResponse)>);  // url -> response
pub struct MockClock(pub u64);                      // fixed timestamp
pub struct MockEnv(HashMap<String, String>);
```

### Tier 2: Platform adapter tests

Each adapter crate has integration tests verifying trait implementations against real services:
- **Cloudflare:** Use `wrangler dev` with a test KV namespace
- **GCP:** Use the Firestore emulator (`gcloud emulators firestore start`)

### Tier 3: End-to-end tests

A shared test suite in `core/tests/e2e/` defines platform-neutral scenarios (happy path exchange, invalid token, policy mismatch). Each platform crate runs these against its deployed endpoint.

**What changes for existing tests:**
- Tests that construct `OidcClaims` or `CompiledPolicy` directly: no changes
- Tests that call `handle()` functions: add mock trait args
- No tests are deleted, just adapted to the new signatures

## Migration Path

Four sequential phases, each leaving the project in a deployable state:

### Phase 1: Extract core
- Create workspace structure
- Move business logic into `core/` crate
- Define the four traits in `core/src/platform.rs`
- Refactor functions to accept trait generics instead of `worker::Env`
- Create mock trait implementations for tests
- All 56 tests pass against core

### Phase 2: Cloudflare adapter
- Move Workers-specific code into `cloudflare/` crate
- Implement traits using existing Workers KV, Fetch, etc.
- Wire up the `#[event(fetch)]` entrypoint
- Verify `wrangler dev` works identically to today

### Phase 3: GCP adapter
- Build `gcp/` crate with hyper server
- Implement Firestore cache adapter
- Implement reqwest HTTP client adapter
- Implement `std::env` + Secret Manager environment
- Test against Firestore emulator locally

### Phase 4: GCP deployment
- Dockerfile for Cloud Functions
- Terraform module for GCP (Cloud Function, Firestore database, Secret Manager secrets, IAM)
- Deployment documentation

**Risk mitigation:** Phase 2 is the checkpoint. If the existing Cloudflare deployment works identically after the refactor, the abstraction layer is validated before writing any GCP code.
