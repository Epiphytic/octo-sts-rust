use super::replay::Claim;
use crate::error::{ApiError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use nostr::event::Event;
use secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_BODY: usize = 4096;
pub const MAX_AUTH: usize = 8192;
pub const PATH: &str = "/sts/exchange/nostr";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRequest {
    pub scope: String,
    pub identity: String,
}

// Separate strict envelope rejects duplicate/unknown fields before library parsing.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

pub struct Assertion {
    pub(super) request: ExchangeRequest,
    pub(super) public_key: [u8; 32],
    created_at: u64,
    principal: String,
    nonce_key: String,
}

impl Assertion {
    pub fn check_time(&self, now: u64) -> Result<()> {
        check_time(self.created_at, now)
    }
    pub fn replay_claim(&self) -> Claim {
        Claim {
            principal: self.principal.clone(),
            key: self.nonce_key.clone(),
            expires_at: self.created_at + 180,
        }
    }
}

fn unauthorized() -> ApiError {
    ApiError::token_verification_failed("invalid Nostr assertion")
}

fn check_time(created: u64, now: u64) -> Result<()> {
    if created > now.saturating_add(5)
        || now > created.saturating_add(60)
        || created.checked_add(180).is_none()
    {
        return Err(unauthorized());
    }
    Ok(())
}

pub(super) fn is_hex(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn repo_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn parse_body(body: &[u8]) -> Result<ExchangeRequest> {
    let request: ExchangeRequest = serde_json::from_slice(body)
        .map_err(|_| ApiError::invalid_request("invalid Nostr request body"))?;
    crate::policy::validate_identity(&request.identity)?;
    let (owner, repo) = request
        .scope
        .split_once('/')
        .ok_or_else(|| ApiError::invalid_request("scope must be owner/repository"))?;
    if owner.is_empty()
        || owner.len() > 39
        || owner.starts_with('-')
        || owner.ends_with('-')
        || !owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || !repo_name(repo)
    {
        return Err(ApiError::invalid_request("invalid scope"));
    }
    Ok(request)
}

/// Adapters supply the single raw Authorization value and bounded, unchanged bytes.
pub fn verify(auth: &str, body: &[u8], audience: &str, now: u64) -> Result<Assertion> {
    if auth.len() > MAX_AUTH || body.len() > MAX_BODY {
        return Err(ApiError::PayloadTooLarge);
    }
    super::validate_audience(audience)?;
    let request = parse_body(body)?;
    let encoded = auth.strip_prefix("Nostr ").ok_or_else(unauthorized)?;
    let raw = STANDARD.decode(encoded).map_err(|_| unauthorized())?;
    let envelope: Envelope = serde_json::from_slice(&raw).map_err(|_| unauthorized())?;
    if !is_hex(&envelope.id, 32)
        || !is_hex(&envelope.pubkey, 32)
        || !is_hex(&envelope.sig, 64)
        || envelope.kind != 27235
        || !envelope.content.is_empty()
        || envelope.tags.len() != 4
    {
        return Err(unauthorized());
    }
    check_time(envelope.created_at, now)?;
    let mut tags = std::collections::HashMap::new();
    for tag in &envelope.tags {
        if tag.len() != 2 || tags.insert(tag[0].as_str(), tag[1].as_str()).is_some() {
            return Err(unauthorized());
        }
    }
    let payload = hex::encode(Sha256::digest(body));
    let nonce = tags.get("octo-sts-nonce").ok_or_else(unauthorized)?;
    if tags.get("u") != Some(&audience)
        || tags.get("method") != Some(&"POST")
        || tags.get("payload") != Some(&payload.as_str())
        || !is_hex(nonce, 32)
    {
        return Err(unauthorized());
    }
    let event: Event = serde_json::from_slice(&raw).map_err(|_| unauthorized())?;
    event
        .verify_with_ctx(&Secp256k1::verification_only())
        .map_err(|_| unauthorized())?;
    let public_key: [u8; 32] = hex::decode(&envelope.pubkey)
        .map_err(|_| unauthorized())?
        .try_into()
        .map_err(|_| unauthorized())?;
    let principal = digest_tuple(&[b"octo-sts-nostr-v1", audience.as_bytes(), &public_key]);
    let nonce_bytes = hex::decode(nonce).map_err(|_| unauthorized())?;
    let nonce_key = digest_tuple(&[
        b"octo-sts-nostr-v1",
        audience.as_bytes(),
        &public_key,
        &nonce_bytes,
    ]);
    Ok(Assertion {
        request,
        public_key,
        created_at: envelope.created_at,
        principal,
        nonce_key,
    })
}

fn digest_tuple(parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hex::encode(hash.finalize())
}
