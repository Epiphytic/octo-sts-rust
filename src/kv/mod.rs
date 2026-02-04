//! Workers KV caching module
//!
//! Provides caching for installation IDs and trust policies.

mod cache;

pub use cache::{cache_policy, get_cached_policy, get_or_fetch_installation};
