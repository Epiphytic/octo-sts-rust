// Local integration fixture only; never use its public test key in production.
#[path = "../tests/support/nostr_fixture.rs"]
mod fixture;
use fixture::*;
use serde_json::json;
fn main() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!(
        "{}",
        json!({"url":AUD,"body":String::from_utf8(BODY.to_vec()).unwrap(),"authorization":header(&event(BODY,now,1)),"policy":yaml()})
    );
}
