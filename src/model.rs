use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
#[derive(Clone, Serialize, Deserialize)]
pub struct Application {
    pub id: Uuid,
    pub owner: String,
    pub name: String,
    pub keys: Vec<Key>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Key {
    pub id: Uuid,
    pub name: String,
    pub digest: String,
    pub created_at: u64,
    pub revoked: bool,
}
#[derive(Clone)]
pub struct Versioned {
    pub app: Application,
    pub version: u64,
}
pub fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
pub fn constant_eq(a: &str, b: &str) -> bool {
    bool::from(digest(a).as_bytes().ct_eq(digest(b).as_bytes()))
}
pub fn issue(app: Uuid, name: String) -> (Key, String) {
    let id = Uuid::new_v4();
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let token = format!(
        "kgt_{}_{}_{}",
        app.simple(),
        id.simple(),
        hex::encode(secret)
    );
    let key = Key {
        id,
        name,
        digest: digest(&token),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        revoked: false,
    };
    (key, token)
}
pub fn parse_token(token: &str) -> Option<(Uuid, Uuid)> {
    if token.len() != 134 {
        return None;
    }
    let p: Vec<_> = token.split('_').collect();
    if p.len() != 4
        || p[0] != "kgt"
        || p[1].len() != 32
        || p[2].len() != 32
        || p[3].len() != 64
        || !p[1..].iter().all(|s| {
            s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    {
        return None;
    }
    Some((Uuid::parse_str(p[1]).ok()?, Uuid::parse_str(p[2]).ok()?))
}
pub fn validates(app: &Application, id: Uuid, token: &str) -> bool {
    let supplied = digest(token);
    app.keys.iter().any(|k| {
        k.id == id && !k.revoked && bool::from(k.digest.as_bytes().ct_eq(supplied.as_bytes()))
    })
}
