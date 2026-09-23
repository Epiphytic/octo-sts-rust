use crate::{platform::SystemClock, AppState, HyperResponse};
use core::replay::{Claim, ReplayState, ReplayStore};
use http_body_util::{BodyExt, Limited};
use hyper::{body::Incoming, Request, StatusCode};
use octo_sts_core::{error::ApiError, nostr as core, platform::Clock};

pub async fn handle(req: Request<Incoming>, state: &AppState) -> HyperResponse {
    if std::env::var("NOSTR_EXCHANGE_ENABLED").as_deref() != Ok("true") {
        return crate::json_response(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error":"not_found"}),
        );
    }
    let result = run(req, state).await;
    let mut response = match result {
        Ok(value) => crate::json_response(StatusCode::OK, &value),
        Err(e) => crate::error_response(&e),
    };
    response.headers_mut().insert(
        "cache-control",
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response
}

async fn run(
    req: Request<Incoming>,
    state: &AppState,
) -> Result<octo_sts_core::sts::exchange_pat::ExchangeResponse, ApiError> {
    let audience = std::env::var("NOSTR_EXCHANGE_URL").map_err(|_| ApiError::ServiceUnavailable)?;
    let url = core::validate_audience(&audience)?;
    let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let headers = req.headers();
    if headers.get_all("host").iter().count() != 1
        || headers.get("host").and_then(|v| v.to_str().ok()) != Some(authority)
        || *req.uri() != core::PATH
        || headers.get_all("content-type").iter().count() != 1
        || headers.get("content-type").and_then(|v| v.to_str().ok()) != Some("application/json")
        || headers.contains_key("content-encoding")
        || headers.get_all("authorization").iter().count() != 1
    {
        return Err(ApiError::invalid_request(
            "invalid Nostr request headers or URL",
        ));
    }
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::token_verification_failed("missing Nostr assertion"))?
        .to_owned();
    if auth.len() > core::MAX_AUTH {
        return Err(ApiError::PayloadTooLarge);
    }
    let body = Limited::new(req.into_body(), core::MAX_BODY)
        .collect()
        .await
        .map_err(|_| ApiError::PayloadTooLarge)?
        .to_bytes();
    let assertion = core::verify(&auth, &body, &audience, state.clock.now_secs())?;
    let store = FirestoreReplay::from_env()?;
    core::exchange(
        assertion,
        &store,
        &state.http,
        state.signer.as_ref(),
        &state.clock,
    )
    .await
}

struct FirestoreReplay {
    client: reqwest::Client,
    database: String,
    limit: u32,
    endpoint: String,
}

impl FirestoreReplay {
    fn from_env() -> Result<Self, ApiError> {
        let project = std::env::var("GCP_PROJECT").map_err(|_| ApiError::ServiceUnavailable)?;
        if project.is_empty()
            || !project
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ApiError::ServiceUnavailable);
        }
        let limit = std::env::var("NOSTR_RATE_PER_MINUTE")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|n| (1..=100).contains(n))
            .ok_or(ApiError::ServiceUnavailable)?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ApiError::ServiceUnavailable)?;
        Ok(Self {
            client,
            database: format!("projects/{project}/databases/(default)"),
            limit,
            endpoint: "https://firestore.googleapis.com/v1".into(),
        })
    }

    async fn access_token(&self) -> Result<String, ApiError> {
        #[derive(serde::Deserialize)]
        struct Token {
            access_token: String,
        }
        self.client.get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google").send().await
            .map_err(|_| ApiError::ServiceUnavailable)?.error_for_status()
            .map_err(|_| ApiError::ServiceUnavailable)?.json::<Token>().await
            .map(|t| t.access_token).map_err(|_| ApiError::ServiceUnavailable)
    }

    async fn rollback(&self, token: &str, transaction: &str) {
        let _ = self
            .client
            .post(format!(
                "{}/{}/documents:rollback",
                self.endpoint, self.database
            ))
            .bearer_auth(token)
            .json(&serde_json::json!({"transaction":transaction}))
            .send()
            .await;
    }

    async fn attempt(&self, claim: &Claim, token: &str) -> Result<bool, ApiError> {
        let base = format!("{}/{}/documents", self.endpoint, self.database);
        let response = self
            .client
            .post(format!("{base}:beginTransaction"))
            .bearer_auth(token)
            .json(&serde_json::json!({"options":{"readWrite":{}}}))
            .send()
            .await
            .map_err(|_| ApiError::ServiceUnavailable)?
            .error_for_status()
            .map_err(|_| ApiError::ServiceUnavailable)?;
        #[derive(serde::Deserialize)]
        struct Transaction {
            transaction: String,
        }
        let transaction = response
            .json::<Transaction>()
            .await
            .map_err(|_| ApiError::ServiceUnavailable)?
            .transaction;
        let result = self.transition(claim, token, &base, &transaction).await;
        if !matches!(result, Ok(true)) {
            self.rollback(token, &transaction).await;
        }
        result
    }

    async fn transition(
        &self,
        claim: &Claim,
        token: &str,
        base: &str,
        transaction: &str,
    ) -> Result<bool, ApiError> {
        let document = format!(
            "{}/documents/nostr_replay/{}",
            self.database, claim.principal
        );
        let response = self
            .client
            .get(format!("{}/{document}", self.endpoint))
            .query(&[("transaction", transaction)])
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| ApiError::ServiceUnavailable)?;
        let mut state = if response.status() == StatusCode::NOT_FOUND {
            ReplayState::default()
        } else {
            let value: serde_json::Value = response
                .error_for_status()
                .map_err(|_| ApiError::ServiceUnavailable)?
                .json()
                .await
                .map_err(|_| ApiError::ServiceUnavailable)?;
            let raw = value["fields"]["state"]["stringValue"]
                .as_str()
                .ok_or(ApiError::ServiceUnavailable)?;
            serde_json::from_str(raw).map_err(|_| ApiError::ServiceUnavailable)?
        };
        state.consume(claim, SystemClock.now_secs(), self.limit)?;
        // A later transaction must not shorten TTL for earlier retained nonces.
        let expiry = state.expires_at()?;
        let body = serde_json::json!({"transaction":transaction,"writes":[{"update":{
            "name":document,"fields":{
                "state":{"stringValue":serde_json::to_string(&state).map_err(|_| ApiError::ServiceUnavailable)?},
                "expires_at":{"timestampValue":expiry}
            }
        }}]});
        let response = self
            .client
            .post(format!("{base}:commit"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|_| ApiError::ServiceUnavailable)?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(false);
        }
        response
            .error_for_status()
            .map_err(|_| ApiError::ServiceUnavailable)?;
        Ok(true)
    }
}

#[async_trait::async_trait(?Send)]
impl ReplayStore for FirestoreReplay {
    async fn consume(&self, claim: &Claim) -> Result<(), ApiError> {
        let token = self.access_token().await?;
        for _ in 0..3 {
            if self.attempt(claim, &token).await? {
                return Ok(());
            }
        }
        Err(ApiError::ServiceUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    // Exercise the actual REST adapter, including transaction binding, serialized
    // state and rollback. Production endpoints are fixed, never caller-controlled.
    fn server(
        steps: Vec<(&'static str, u16, serde_json::Value)>,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            for (expected, status, body) in steps {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let (header_end, length) = loop {
                    let mut chunk = [0; 4096];
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                        let length = headers
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .map(|v| v.parse::<usize>().unwrap())
                            .unwrap_or(0);
                        break (end + 4, length);
                    }
                };
                while bytes.len() < header_end + length {
                    let mut chunk = [0; 4096];
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                }
                let request = String::from_utf8(bytes).unwrap();
                assert!(
                    request.lines().next().unwrap().contains(expected),
                    "{request}"
                );
                if expected.ends_with(":commit") || expected.ends_with(":rollback") {
                    let value: serde_json::Value =
                        serde_json::from_str(&request[header_end..]).unwrap();
                    assert_eq!(value["transaction"], "dHg=");
                    if expected.ends_with(":commit") {
                        let doc = &value["writes"][0]["update"];
                        assert!(doc["name"].as_str().unwrap().ends_with(&"a".repeat(64)));
                        let state: ReplayState = serde_json::from_str(
                            doc["fields"]["state"]["stringValue"].as_str().unwrap(),
                        )
                        .unwrap();
                        assert_eq!(
                            doc["fields"]["expires_at"]["timestampValue"],
                            state.expires_at().unwrap()
                        );
                    }
                }
                let body = body.to_string();
                write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (endpoint, thread)
    }

    #[tokio::test]
    async fn firestore_transaction_success_conflict_replay_and_outage() {
        let claim = Claim {
            principal: "a".repeat(64),
            key: "b".repeat(64),
            expires_at: SystemClock.now_secs() + 180,
        };
        let begin = (
            ":beginTransaction",
            200,
            serde_json::json!({"transaction":"dHg="}),
        );
        let absent = ("?transaction=dHg%3D", 404, serde_json::json!({}));
        let rollback = (":rollback", 200, serde_json::json!({}));
        let mut state = ReplayState::default();
        state.consume(&claim, SystemClock.now_secs(), 10).unwrap();
        let existing = (
            "?transaction=dHg%3D",
            200,
            serde_json::json!({"fields":{"state":{"stringValue":serde_json::to_string(&state).unwrap()}}}),
        );
        let (endpoint, thread) = server(vec![
            begin.clone(),
            absent.clone(),
            (":commit", 200, serde_json::json!({})),
            begin.clone(),
            absent.clone(),
            (":commit", 409, serde_json::json!({})),
            rollback.clone(),
            begin.clone(),
            existing,
            rollback.clone(),
            begin,
            absent,
            (":commit", 503, serde_json::json!({})),
            rollback,
        ]);
        let store = FirestoreReplay {
            client: reqwest::Client::new(),
            database: "projects/test/databases/(default)".into(),
            limit: 10,
            endpoint,
        };
        assert!(store.attempt(&claim, "fixture-token").await.unwrap());
        assert!(!store.attempt(&claim, "fixture-token").await.unwrap());
        assert_eq!(
            store
                .attempt(&claim, "fixture-token")
                .await
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(
            store
                .attempt(&claim, "fixture-token")
                .await
                .unwrap_err()
                .status_code(),
            503
        );
        thread.join().unwrap();
    }
}
