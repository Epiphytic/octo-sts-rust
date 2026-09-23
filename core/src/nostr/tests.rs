use super::replay::{Claim, ReplayState, ReplayStore};
use super::*;
use crate::platform::{HttpClient, HttpResponse, JwtSigner};
use crate::test_support::MockClock;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::cell::RefCell;

#[path = "../../tests/support/nostr_fixture.rs"]
mod fixture;
use fixture::*;
fn assertion(nonce: u8) -> Assertion {
    verify(&header(&event(BODY, NOW, nonce)), BODY, AUD, NOW).unwrap()
}
#[test]
fn signature_and_time_boundaries() {
    for time in [NOW - 60, NOW, NOW + 5] {
        assert!(verify(&header(&event(BODY, time, 1)), BODY, AUD, NOW).is_ok());
    }
    for time in [NOW - 61, NOW + 6, u64::MAX] {
        assert!(verify(&header(&event(BODY, time, 1)), BODY, AUD, NOW).is_err());
    }
    let valid = event(BODY, NOW, 1);
    for field in ["id", "sig", "pubkey"] {
        let mut bad = valid.clone();
        bad[field] = json!("00".repeat(if field == "sig" { 64 } else { 32 }));
        assert!(verify(&header(&bad), BODY, AUD, NOW).is_err(), "{field}");
    }
    let mut bad = valid.clone();
    bad["content"] = json!("signed note");
    assert!(verify(&header(&bad), BODY, AUD, NOW).is_err());
    assert!(verify(
        &header(&valid),
        BODY,
        "https://other.example/sts/exchange/nostr",
        NOW
    )
    .is_err());
    assert!(verify(
        &header(&valid),
        br#"{"scope":"owner/two","identity":"agent"}"#,
        AUD,
        NOW
    )
    .is_err());
}

#[test]
fn duplicate_and_malformed_inputs() {
    let good = event(BODY, NOW, 1);
    for index in 0..4 {
        let mut bad = good.clone();
        bad["tags"][index][1] = json!("wrong");
        assert!(verify(&header(&bad), BODY, AUD, NOW).is_err());
    }
    let mut bad = good.clone();
    bad["tags"][3] = bad["tags"][0].clone();
    assert!(verify(&header(&bad), BODY, AUD, NOW).is_err());
    let raw = serde_json::to_string(&good).unwrap();
    let duplicate = format!("{{\"kind\":27235,{}", &raw[1..]);
    assert!(verify(
        &format!("Nostr {}", STANDARD.encode(duplicate)),
        BODY,
        AUD,
        NOW
    )
    .is_err());
    for body in [
        br#"{"scope":"owner/one","scope":"evil/two","identity":"agent"}"#.as_slice(),
        br#"{"scope":"owner/one","identity":"../agent"}"#,
        br#"{"scope":"owner/../one","identity":"agent"}"#,
        br#"{"scope":"owner/one","identity":"agent","permissions":{}}"#,
    ] {
        assert!(verify(&header(&event(body, NOW, 1)), body, AUD, NOW).is_err());
    }
    assert_eq!(
        verify(&"x".repeat(MAX_AUTH + 1), BODY, AUD, NOW)
            .err()
            .unwrap()
            .status_code(),
        413
    );
    assert_eq!(
        verify(&header(&good), &vec![0; MAX_BODY + 1], AUD, NOW)
            .err()
            .unwrap()
            .status_code(),
        413
    );
}

#[test]
fn policy_is_explicit_and_rotation_is_operator_controlled() {
    let policy = Policy::parse(&yaml()).unwrap();
    assert!(policy.authorize(&assertion(1).public_key, "ONE").is_ok());
    assert!(policy.authorize(&[0; 32], "one").is_err());
    assert!(policy.authorize(&assertion(1).public_key, "three").is_err());
    for invalid in [
        yaml().replace("version: 1", "version: 2"),
        yaml() + "required_org: owner\n",
        yaml().replace("[one, two]", "[]"),
        yaml().replace("[one, two]", "['*']"),
        yaml().replace("contents: read", "contents: read, contents: write"),
        yaml().replace("contents: read", "unknown_permission: write"),
        yaml() + "version: 1\n",
        yaml().replace(&npub(), &npub().to_uppercase()),
        yaml().replace("npub1", "nsec1"),
    ] {
        assert!(Policy::parse(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn replay_survives_serialization_and_nonce_changes_cannot_bypass() {
    let mut state = ReplayState::default();
    let claim = assertion(1).replay_claim();
    state.consume(&claim, NOW, 2).unwrap();
    let mut restored: ReplayState =
        serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
    assert_eq!(
        restored
            .consume(&claim, NOW + 1, 2)
            .unwrap_err()
            .status_code(),
        401
    );
    let other_body = br#"{"scope":"owner/two","identity":"agent"}"#;
    let other = verify(
        &header(&event(other_body, NOW + 1, 1)),
        other_body,
        AUD,
        NOW,
    )
    .unwrap()
    .replay_claim();
    assert_eq!(claim.key, other.key);
    restored
        .consume(&assertion(2).replay_claim(), NOW, 2)
        .unwrap();
    assert_eq!(
        restored
            .consume(&assertion(3).replay_claim(), NOW, 2)
            .unwrap_err()
            .status_code(),
        429
    );
    restored.prune(NOW + 180);
    let fresh = verify(&header(&event(BODY, NOW + 180, 1)), BODY, AUD, NOW + 180).unwrap();
    restored
        .consume(&fresh.replay_claim(), NOW + 180, 2)
        .unwrap();
}

struct Signer;
#[async_trait::async_trait(?Send)]
impl JwtSigner for Signer {
    async fn sign_app_jwt(&self, _: i64) -> Result<String> {
        Ok("app-jwt".into())
    }
}
struct Store {
    state: RefCell<ReplayState>,
    fail: bool,
}
#[async_trait::async_trait(?Send)]
impl ReplayStore for Store {
    async fn consume(&self, claim: &Claim) -> Result<()> {
        if self.fail {
            return Err(ApiError::ServiceUnavailable);
        }
        self.state.borrow_mut().consume(claim, NOW, 10)
    }
}
struct GitHub {
    requests: RefCell<Vec<Value>>,
    fail: bool,
}
#[async_trait::async_trait(?Send)]
impl HttpClient for GitHub {
    async fn get(&self, url: &str, _: &[(&str, &str)]) -> Result<HttpResponse> {
        let body = if url.ends_with("/installation") {
            br#"{"id":42}"#.to_vec()
        } else {
            assert!(
                url.contains("/repos/owner/.github/contents/.github/chainguard/agent.nostr.yaml")
            );
            yaml().into_bytes()
        };
        Ok(HttpResponse { status: 200, body })
    }
    async fn post(&self, _: &str, _: &[(&str, &str)], body: &[u8]) -> Result<HttpResponse> {
        let request: Value = serde_json::from_slice(body).unwrap();
        self.requests.borrow_mut().push(request.clone());
        if self.fail && request["repositories"] == json!(["one"]) {
            return Err(ApiError::ServiceUnavailable);
        }
        Ok(HttpResponse {
            status: 201,
            body: br#"{"token":"test-only-token","expires_at":"2030-01-01T00:00:00Z"}"#.to_vec(),
        })
    }
    async fn delete(&self, _: &str, _: &[(&str, &str)]) -> Result<HttpResponse> {
        unreachable!()
    }
}

#[tokio::test]
async fn exchange_scopes_token_and_burns_nonce_even_after_upstream_failure() {
    let store = Store {
        state: RefCell::new(ReplayState::default()),
        fail: false,
    };
    let http = GitHub {
        requests: RefCell::new(vec![]),
        fail: false,
    };
    exchange(assertion(1), &store, &http, &Signer, &MockClock(NOW))
        .await
        .unwrap();
    assert_eq!(
        http.requests.borrow().last().unwrap(),
        &json!({"repositories":["one"],"permissions":{"contents":"read"}})
    );
    assert_eq!(
        exchange(assertion(1), &store, &http, &Signer, &MockClock(NOW))
            .await
            .err()
            .unwrap()
            .status_code(),
        401
    );
    let failing = GitHub {
        requests: RefCell::new(vec![]),
        fail: true,
    };
    assert!(
        exchange(assertion(2), &store, &failing, &Signer, &MockClock(NOW))
            .await
            .is_err()
    );
    assert_eq!(
        exchange(assertion(2), &store, &http, &Signer, &MockClock(NOW))
            .await
            .err()
            .unwrap()
            .status_code(),
        401
    );
    let outage = Store {
        state: RefCell::new(ReplayState::default()),
        fail: true,
    };
    let clean = GitHub {
        requests: RefCell::new(vec![]),
        fail: false,
    };
    assert_eq!(
        exchange(assertion(3), &outage, &clean, &Signer, &MockClock(NOW))
            .await
            .err()
            .unwrap()
            .status_code(),
        503
    );
    // Policy loading uses an internal contents-read token, but the caller's token
    // must never be minted while replay persistence is unavailable.
    assert!(clean
        .requests
        .borrow()
        .iter()
        .all(|r| r["repositories"] == json!([".github"])));
}

#[test]
fn policy_rejects_valid_non_npub_encodings() {
    // Valid checksums: nsec test key, NIP-19 profile TLV, and the same
    // authorized public key encoded using Bech32m instead of Bech32.
    for encoded in [
        "nsec1qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qursl6edet",
        "nprofile1qqsf38qtwm94vwt3lhymauc7cpkr2c8nyjwka609mq79wcj4jms97mcv0c4mt",
        "npub1nzwqkakt2cuhrlwfhme3asrvx4s0xfyadm57tkpu2a39t9hqtahst4qlz8",
    ] {
        assert!(Policy::parse(&yaml().replace(&npub(), encoded)).is_err());
    }
}
