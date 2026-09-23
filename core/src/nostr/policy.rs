use crate::error::{ApiError, Result};
use nostr::{
    key::PublicKey,
    nips::nip19::{FromBech32, ToBech32},
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    version: u8,
    nostr_npubs: Vec<String>,
    #[serde(deserialize_with = "unique_permissions")]
    pub permissions: HashMap<String, String>,
    repositories: Vec<String>,
    #[serde(skip)]
    keys: Vec<[u8; 32]>,
}

fn unique_permissions<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<HashMap<String, String>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = HashMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("unique permission map")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut result = HashMap::new();
            while let Some((k, v)) = map.next_entry::<String, String>()? {
                if result.insert(k, v).is_some() {
                    return Err(serde::de::Error::custom("duplicate permission"));
                }
            }
            Ok(result)
        }
    }
    d.deserialize_map(Visitor)
}

impl Policy {
    pub fn parse(yaml: &str) -> Result<Self> {
        let invalid = || ApiError::permission_denied("invalid Nostr policy");
        if yaml.len() > 65536 {
            return Err(invalid());
        }
        let mut policy: Self = serde_yaml::from_str(yaml).map_err(|_| invalid())?;
        if policy.version != 1
            || policy.nostr_npubs.is_empty()
            || policy.nostr_npubs.len() > 8
            || policy.repositories.is_empty()
            || policy.repositories.len() > 100
            || policy.permissions.is_empty()
        {
            return Err(invalid());
        }
        let mut repos = HashSet::new();
        for repo in &policy.repositories {
            if !super::assertion::repo_name(repo) || !repos.insert(repo.to_ascii_lowercase()) {
                return Err(invalid());
            }
        }
        for npub in &policy.nostr_npubs {
            if !npub.starts_with("npub1") {
                return Err(invalid());
            }
            let key = PublicKey::from_bech32(npub).map_err(|_| invalid())?;
            if key.to_bech32().map_err(|_| invalid())? != *npub {
                return Err(invalid());
            }
            let bytes = key.to_bytes();
            secp256k1::XOnlyPublicKey::from_slice(&bytes).map_err(|_| invalid())?;
            if policy.keys.contains(&bytes) {
                return Err(invalid());
            }
            policy.keys.push(bytes);
        }
        // Deliberately limited v1 repository permissions. No organization/account grants.
        for (name, level) in &policy.permissions {
            let writable = matches!(
                name.as_str(),
                "contents"
                    | "issues"
                    | "pull_requests"
                    | "actions"
                    | "checks"
                    | "statuses"
                    | "deployments"
                    | "discussions"
                    | "packages"
                    | "pages"
            );
            if !(writable && matches!(level.as_str(), "read" | "write")
                || name == "metadata" && level == "read")
            {
                return Err(invalid());
            }
        }
        Ok(policy)
    }

    pub fn authorize(&self, key: &[u8; 32], repo: &str) -> Result<()> {
        if !self.keys.contains(key)
            || !self
                .repositories
                .iter()
                .any(|r| r.eq_ignore_ascii_case(repo))
        {
            return Err(ApiError::permission_denied(
                "Nostr identity or repository not permitted",
            ));
        }
        Ok(())
    }
}
