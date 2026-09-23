// Public test key only. Never authorize this key in a deployed policy.
use base64::{engine::general_purpose::STANDARD, Engine};
use nostr::{key::PublicKey, nips::nip19::ToBech32};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
pub const AUD: &str = "https://sts.example.com/sts/exchange/nostr";
pub const NOW: u64 = 1_800_000_000;
pub const BODY: &[u8] = br#"{"scope":"owner/one","identity":"agent"}"#;

pub fn event(body: &[u8], timestamp: u64, nonce: u8) -> Value {
    let secp = Secp256k1::new();
    let keys = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7; 32]).unwrap());
    let pubkey = keys.x_only_public_key().0.to_string();
    let tags = json!([
        ["u", AUD],
        ["method", "POST"],
        ["payload", hex::encode(Sha256::digest(body))],
        ["octo-sts-nonce", hex::encode([nonce; 32])]
    ]);
    let bytes = serde_json::to_vec(&json!([0, pubkey, timestamp, 27235, tags, ""])).unwrap();
    let id = Sha256::digest(bytes);
    let sig = secp.sign_schnorr_no_aux_rand(&id, &keys).to_string();
    json!({"id":hex::encode(id),"pubkey":pubkey,"created_at":timestamp,"kind":27235,"tags":tags,"content":"","sig":sig})
}
pub fn header(event: &Value) -> String {
    format!(
        "Nostr {}",
        STANDARD.encode(serde_json::to_vec(event).unwrap())
    )
}
pub fn npub() -> String {
    PublicKey::from_hex(event(BODY, NOW, 1)["pubkey"].as_str().unwrap())
        .unwrap()
        .to_bech32()
        .unwrap()
}
pub fn yaml() -> String {
    format!("version: 1\nnostr_npubs: ['{}']\npermissions: {{contents: read}}\nrepositories: [one, two]\n",npub())
}
