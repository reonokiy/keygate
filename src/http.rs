//! Bound responses from credential stores and identity providers before decoding them.
use serde::de::DeserializeOwned;
pub const MAX_JSON_BYTES: usize = 1024 * 1024;
pub async fn json<T: DeserializeOwned>(mut response: reqwest::Response) -> Result<T, ()> {
    if response
        .content_length()
        .is_some_and(|n| n > MAX_JSON_BYTES as u64)
    {
        return Err(());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if bytes.len().saturating_add(chunk.len()) > MAX_JSON_BYTES {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

#[cfg(test)]
#[path = "../tests/unit/http.rs"]
mod tests;
