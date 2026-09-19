//! Envoy owns the OAuth session. Verify the forwarded ID token as an additional trust check.
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{JwkSet, KeyOperations, PublicKeyUse},
};
use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
#[derive(Debug)]
pub enum IdentityError {
    Invalid,
    Unavailable,
}
pub struct Oidc {
    client: reqwest::Client,
    issuer: String,
    audience: String,
    jwks_url: String,
    cache: Mutex<Option<(Instant, Result<JwkSet, ()>)>>,
}
#[derive(Deserialize)]
struct Claims {
    sub: String,
    aud: serde_json::Value,
    azp: Option<String>,
}
impl Oidc {
    pub fn new(issuer: String, audience: String, jwks_url: String) -> anyhow::Result<Self> {
        for s in [&issuer, &jwks_url] {
            let url = reqwest::Url::parse(s)?;
            anyhow::ensure!(
                url.scheme() == "https"
                    || (url.scheme() == "http"
                        && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))),
                "OIDC endpoints require HTTPS except loopback tests"
            );
            anyhow::ensure!(
                url.username().is_empty()
                    && url.password().is_none()
                    && url.host_str().is_some()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "OIDC endpoint cannot contain credentials"
            );
        }
        anyhow::ensure!(!audience.is_empty(), "OIDC audience is required");
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            issuer,
            audience,
            jwks_url,
            cache: Mutex::new(None),
        })
    }
    pub async fn subject(&self, token: &str) -> Result<String, IdentityError> {
        if token.len() > 16384 {
            return Err(IdentityError::Invalid);
        }
        let header = decode_header(token).map_err(|_| IdentityError::Invalid)?;
        if !matches!(
            header.alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::ES256
                | Algorithm::ES384
                | Algorithm::EdDSA
        ) {
            return Err(IdentityError::Invalid);
        }
        let kid = header.kid.ok_or(IdentityError::Invalid)?;
        let mut cache = self.cache.lock().await;
        // Successful JWKS fetches live for 60s. Cache failures for 5s so an IdP
        // outage cannot turn every login request into a new outbound request.
        let fresh = cache.as_ref().is_some_and(|(at, result)| {
            at.elapsed() < Duration::from_secs(if result.is_ok() { 60 } else { 5 })
        });
        if !fresh {
            let started = Instant::now();
            let result = match self.client.get(&self.jwks_url).send().await {
                Ok(response) if response.status().is_success() => crate::http::json(response).await,
                _ => Err(()),
            };
            *cache = Some((started, result));
        }
        let keys = cache
            .as_ref()
            .unwrap()
            .1
            .as_ref()
            .map_err(|_| IdentityError::Unavailable)?;
        let mut matching = keys
            .keys
            .iter()
            .filter(|jwk| jwk.common.key_id.as_deref() == Some(&kid));
        let jwk = matching.next().ok_or(IdentityError::Invalid)?;
        if matching.next().is_some()
            || jwk
                .common
                .public_key_use
                .as_ref()
                .is_some_and(|usage| *usage != PublicKeyUse::Signature)
            || jwk
                .common
                .key_operations
                .as_ref()
                .is_some_and(|ops| !ops.contains(&KeyOperations::Verify))
            || jwk
                .common
                .key_algorithm
                .is_some_and(|alg| alg.to_string() != format!("{:?}", header.alg))
        {
            return Err(IdentityError::Invalid);
        }
        let key = DecodingKey::from_jwk(jwk).map_err(|_| IdentityError::Invalid)?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = 30;
        validation.validate_nbf = true;
        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|_| IdentityError::Invalid)?
            .claims;
        let multiple_audiences = claims.aud.as_array().is_some_and(|aud| aud.len() > 1);
        if (multiple_audiences && claims.azp.is_none())
            || claims.azp.as_ref().is_some_and(|azp| azp != &self.audience)
            || claims.sub.is_empty()
            || claims.sub.len() > 512
        {
            return Err(IdentityError::Invalid);
        }
        Ok(claims.sub)
    }
}

#[cfg(test)]
#[path = "../tests/unit/identity.rs"]
mod tests;
