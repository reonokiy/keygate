//! Envoy owns the OAuth session. Verify the forwarded ID token as an additional trust check.
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
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
    cache: Mutex<Option<(Instant, JwkSet)>>,
}
#[derive(Deserialize)]
struct Claims {
    sub: String,
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
                url.username().is_empty() && url.password().is_none(),
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
        // Refresh at most once a minute, including unknown key IDs, to bound IdP load.
        if cache
            .as_ref()
            .is_none_or(|(time, _)| time.elapsed() >= Duration::from_secs(60))
        {
            let started = Instant::now();
            let response = self
                .client
                .get(&self.jwks_url)
                .send()
                .await
                .map_err(|_| IdentityError::Unavailable)?;
            if !response.status().is_success() {
                return Err(IdentityError::Unavailable);
            }
            let keys: JwkSet = response
                .json()
                .await
                .map_err(|_| IdentityError::Unavailable)?;
            *cache = Some((started, keys));
        }
        let jwk = cache
            .as_ref()
            .unwrap()
            .1
            .find(&kid)
            .ok_or(IdentityError::Invalid)?;
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
        if claims.sub.is_empty() || claims.sub.len() > 512 {
            return Err(IdentityError::Invalid);
        }
        Ok(claims.sub)
    }
}
