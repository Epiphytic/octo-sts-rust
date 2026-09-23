use crate::platform::{JsClock, WorkersFetchClient};
use core::replay::{Claim, ReplayState, ReplayStore};
use futures::StreamExt;
use octo_sts_core::{error::ApiError, nostr as core, platform::Clock};
use worker::*;

pub async fn handle(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    if ctx
        .env
        .var("NOSTR_EXCHANGE_ENABLED")
        .map(|v| v.to_string())
        .ok()
        .as_deref()
        != Some("true")
    {
        return Response::empty().map(|r| r.with_status(404));
    }
    let result = run(&mut req, &ctx.env).await;
    let mut response = match result {
        Ok(value) => Response::from_json(&value)?,
        Err(e) => crate::error_response(&e)?,
    };
    response.headers_mut().set("Cache-Control", "no-store")?;
    Ok(response)
}

async fn run(
    req: &mut Request,
    env: &Env,
) -> std::result::Result<octo_sts_core::sts::exchange_pat::ExchangeResponse, ApiError> {
    let unavailable = |_| ApiError::ServiceUnavailable;
    let audience = env
        .var("NOSTR_EXCHANGE_URL")
        .map_err(unavailable)?
        .to_string();
    core::validate_audience(&audience)?;
    if req.url().map_err(unavailable)?.as_str() != audience
        || req
            .headers()
            .get("Content-Type")
            .map_err(unavailable)?
            .as_deref()
            != Some("application/json")
        || req
            .headers()
            .get("Content-Encoding")
            .map_err(unavailable)?
            .is_some()
    {
        return Err(ApiError::invalid_request(
            "invalid Nostr request URL or content type",
        ));
    }
    let auth = req
        .headers()
        .get("Authorization")
        .map_err(unavailable)?
        .ok_or_else(|| ApiError::token_verification_failed("missing Nostr assertion"))?;
    // Fetch Headers joins duplicate Authorization values with commas; base64 parsing rejects them.
    if auth.len() > core::MAX_AUTH {
        return Err(ApiError::PayloadTooLarge);
    }
    let mut stream = req.stream().map_err(unavailable)?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(unavailable)?;
        if body.len() + chunk.len() > core::MAX_BODY {
            return Err(ApiError::PayloadTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let assertion = core::verify(&auth, &body, &audience, JsClock.now_secs())?;
    let store = WorkersReplay {
        namespace: env.durable_object("NOSTR_REPLAY").map_err(unavailable)?,
    };
    let signer = crate::make_signer(env)?;
    core::exchange(assertion, &store, &WorkersFetchClient, &signer, &JsClock).await
}

struct WorkersReplay {
    namespace: ObjectNamespace,
}

#[async_trait::async_trait(?Send)]
impl ReplayStore for WorkersReplay {
    async fn consume(&self, claim: &Claim) -> std::result::Result<(), ApiError> {
        let result: Result<u16> = async {
            let stub = self.namespace.id_from_name(&claim.principal)?.get_stub()?;
            let body = serde_json::to_string(claim)?;
            let mut init = RequestInit::new();
            init.with_method(Method::Post).with_body(Some(body.into()));
            let request = Request::new_with_init("https://replay.internal/consume", &init)?;
            Ok(stub.fetch_with_request(request).await?.status_code())
        }
        .await;
        match result {
            Ok(204) => Ok(()),
            Ok(401) => Err(ApiError::token_verification_failed(
                "replayed Nostr assertion",
            )),
            Ok(429) => Err(ApiError::RateLimited),
            _ => Err(ApiError::ServiceUnavailable),
        }
    }
}

/// Private binding only: never route a public URL to this object. Synchronous SQL
/// read/transition/write contains no await, hence no interleaving within an object.
/// Workers storage output gates persist the write before releasing the response.
#[durable_object]
pub struct NostrReplay {
    state: State,
    env: Env,
}

impl DurableObject for NostrReplay {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let claim: Claim = req.json().await?;
        let limit = self
            .env
            .var("NOSTR_RATE_PER_MINUTE")?
            .to_string()
            .parse::<u32>()
            .map_err(|_| Error::RustError("invalid Nostr limit".into()))?;
        let sql = self.state.storage().sql();
        sql.exec(
            "CREATE TABLE IF NOT EXISTS replay (id INTEGER PRIMARY KEY, value TEXT NOT NULL)",
            None,
        )?;
        #[derive(serde::Deserialize)]
        struct Row {
            value: String,
        }
        let rows: Vec<Row> = sql
            .exec("SELECT value FROM replay WHERE id = 1", None)?
            .to_array()?;
        let mut state: ReplayState = match rows.first() {
            Some(row) => serde_json::from_str(&row.value)?,
            None => ReplayState::default(),
        };
        if let Err(e) = state.consume(&claim, JsClock.now_secs(), limit) {
            return Response::empty().map(|r| r.with_status(e.status_code()));
        }
        sql.exec(
            "INSERT OR REPLACE INTO replay (id, value) VALUES (1, ?)",
            vec![serde_json::to_string(&state)?.into()],
        )?;
        self.state
            .storage()
            .set_alarm(std::time::Duration::from_secs(240))
            .await?;
        Response::empty().map(|r| r.with_status(204))
    }

    async fn alarm(&self) -> Result<Response> {
        // Alarm delivery may race a newer fetch. Prune by actual expiry instead
        // of dropping the table or removing unexpired entries.
        let sql = self.state.storage().sql();
        #[derive(serde::Deserialize)]
        struct Row {
            value: String,
        }
        let rows: Vec<Row> = sql
            .exec("SELECT value FROM replay WHERE id = 1", None)?
            .to_array()?;
        if let Some(row) = rows.first() {
            let mut state: ReplayState = serde_json::from_str(&row.value)?;
            state.prune(JsClock.now_secs());
            sql.exec(
                "UPDATE replay SET value = ? WHERE id = 1",
                vec![serde_json::to_string(&state)?.into()],
            )?;
        }
        Response::empty()
    }
}
