use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{Rng, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

const KEY_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
// 46 independently sampled letters provide log2(52^46) > 256 bits of entropy.
const KEY_SECRET_LEN: usize = 46;

#[derive(Clone, Serialize, Deserialize)]
pub struct Application {
    pub id: Uuid,
    pub name: String,
    pub keys: Vec<Key>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Key {
    pub owner: String,
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
/// Stable, header-safe identifier for the configured identity provider's subject.
pub fn user_id(subject: &str) -> String {
    format!("usr_{}", digest(subject))
}
pub fn constant_eq(a: &str, b: &str) -> bool {
    bool::from(digest(a).as_bytes().ct_eq(digest(b).as_bytes()))
}
pub fn issue(owner: String, name: String) -> (Key, String) {
    let id = Uuid::new_v4();
    let mut rng = OsRng;
    let secret: String = (0..KEY_SECRET_LEN)
        .map(|_| KEY_ALPHABET[rng.gen_range(0..KEY_ALPHABET.len())] as char)
        .collect();
    let token = format!("kg-{secret}");
    let key = Key {
        owner,
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
/// New keys contain only ASCII letters after the prefix; previously issued
/// canonical base64url keys remain usable against their existing stored digests.
pub fn valid_token(token: &str) -> bool {
    token
        .strip_prefix("kg-")
        .is_some_and(|secret| match secret.len() {
            KEY_SECRET_LEN => secret.bytes().all(|b| b.is_ascii_alphabetic()),
            43 => URL_SAFE_NO_PAD
                .decode(secret)
                .is_ok_and(|bytes| bytes.len() == 32),
            _ => false,
        })
}
pub fn authenticate<'a>(app: &'a Application, token: &str) -> Option<&'a Key> {
    let supplied = digest(token);
    app.keys.iter().find(|k| {
        !k.owner.is_empty()
            && !k.revoked
            && bool::from(k.digest.as_bytes().ct_eq(supplied.as_bytes()))
    })
}
