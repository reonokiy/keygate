mod common;
use axum::{Router, http::StatusCode, routing::get};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use keygate::identity::{IdentityError, Oidc};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::RwLock;
struct Provider {
    url: String,
    document: Arc<RwLock<(StatusCode, String)>>,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
    key: EncodingKey,
    jwk: Value,
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Provider {
    async fn new() -> Self {
        let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
        let jwk = json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"fixture","x":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())});
        let document = Arc::new(RwLock::new((
            StatusCode::OK,
            json!({"keys":[jwk]}).to_string(),
        )));
        let requests = Arc::new(AtomicUsize::new(0));
        let (d, r) = (document.clone(), requests.clone());
        let router = Router::new().route(
            "/jwks",
            get(move || {
                let (d, r) = (d.clone(), r.clone());
                async move {
                    r.fetch_add(1, Ordering::SeqCst);
                    let current = d.read().await;
                    (current.0, current.1.clone())
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            url,
            document,
            requests,
            task,
            key: EncodingKey::from_ed_der(der.as_ref()),
            jwk,
        }
    }
    fn oidc(&self) -> Oidc {
        Oidc::new(
            self.url.clone(),
            "keygate".into(),
            format!("{}/jwks", self.url),
        )
        .unwrap()
    }
    fn claims(&self) -> Value {
        json!({"iss":self.url,"aud":"keygate","sub":"alice","exp":now()+300})
    }
    fn token(&self, claims: &Value, kid: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = kid.map(Into::into);
        encode(&header, claims, &self.key).unwrap()
    }
    async fn keys(&self, keys: Value) {
        *self.document.write().await = (StatusCode::OK, json!({"keys":keys}).to_string());
    }
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
#[tokio::test]
async fn jwt_claims_and_header_attack_matrix() {
    let p = Provider::new().await;
    let verifier = p.oidc();
    for field in ["exp", "iss", "aud", "sub"] {
        let mut claims = p.claims();
        claims.as_object_mut().unwrap().remove(field);
        assert!(
            matches!(
                verifier.subject(&p.token(&claims, Some("fixture"))).await,
                Err(IdentityError::Invalid)
            ),
            "missing {field}"
        );
    }
    for (field, value) in [
        ("exp", json!(now() - 120)),
        ("exp", json!("tomorrow")),
        ("iss", json!("https://attacker.invalid")),
        ("aud", json!(["other"])),
        ("sub", json!("")),
        ("sub", json!("x".repeat(513))),
        ("sub", json!(1)),
        ("nbf", json!(now() + 3600)),
    ] {
        let mut claims = p.claims();
        claims[field] = value;
        assert!(
            matches!(
                verifier.subject(&p.token(&claims, Some("fixture"))).await,
                Err(IdentityError::Invalid)
            ),
            "bad {field}"
        );
    }
    for token in [
        "".into(),
        "malformed".into(),
        "x".repeat(16385),
        p.token(&p.claims(), None),
        p.token(&p.claims(), Some("unknown")),
    ] {
        assert!(matches!(
            verifier.subject(&token).await,
            Err(IdentityError::Invalid)
        ));
    }
    let mut claims = p.claims();
    claims["aud"] = json!(["keygate", "another"]);
    assert!(matches!(
        verifier.subject(&p.token(&claims, Some("fixture"))).await,
        Err(IdentityError::Invalid)
    ));
    claims["azp"] = json!("keygate");
    assert_eq!(
        verifier
            .subject(&p.token(&claims, Some("fixture")))
            .await
            .unwrap(),
        "alice"
    );
    assert_eq!(
        p.requests.load(Ordering::SeqCst),
        1,
        "bad kid must not force a JWKS refetch"
    );
}
#[tokio::test]
async fn signing_key_purpose_algorithm_and_ambiguity_are_enforced() {
    let p = Provider::new().await;
    for (field, value) in [
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
        ("key_ops", json!([])),
        ("alg", json!("RS256")),
    ] {
        let mut key = p.jwk.clone();
        key[field] = value;
        p.keys(json!([key])).await;
        assert!(
            matches!(
                p.oidc()
                    .subject(&p.token(&p.claims(), Some("fixture")))
                    .await,
                Err(IdentityError::Invalid)
            ),
            "must reject JWK {field}"
        );
    }
    p.keys(json!([p.jwk, p.jwk])).await;
    assert!(
        matches!(
            p.oidc()
                .subject(&p.token(&p.claims(), Some("fixture")))
                .await,
            Err(IdentityError::Invalid)
        ),
        "duplicate kid is ambiguous"
    );
    let mut key = p.jwk.clone();
    key["key_ops"] = json!(["verify"]);
    p.keys(json!([key])).await;
    assert_eq!(
        p.oidc()
            .subject(&p.token(&p.claims(), Some("fixture")))
            .await
            .unwrap(),
        "alice"
    );
}
#[tokio::test]
async fn jwks_faults_fail_closed_without_leaking_upstream_body() {
    let p = Provider::new().await;
    for (status, body) in [
        (StatusCode::FORBIDDEN, "upstream-secret"),
        (StatusCode::FOUND, "redirect"),
        (StatusCode::OK, "not JSON"),
        (StatusCode::OK, "{}"),
    ] {
        *p.document.write().await = (status, body.into());
        assert!(matches!(
            p.oidc()
                .subject(&p.token(&p.claims(), Some("fixture")))
                .await,
            Err(IdentityError::Unavailable)
        ));
    }
    let mut bad = p.jwk.clone();
    bad["x"] = json!("bad%%%base64");
    p.keys(json!([bad])).await;
    assert!(matches!(
        p.oidc()
            .subject(&p.token(&p.claims(), Some("fixture")))
            .await,
        Err(IdentityError::Invalid)
    ));
    p.task.abort();
    assert!(matches!(
        p.oidc()
            .subject(&p.token(&p.claims(), Some("fixture")))
            .await,
        Err(IdentityError::Unavailable)
    ));
}
#[test]
fn oidc_endpoint_configuration_rejects_unsafe_urls() {
    for url in [
        "not a url",
        "http://id.example.com",
        "https://user:password@id.example.com",
        "https://id.example.com/#fragment",
        "https://id.example.com/?query=yes",
    ] {
        assert!(
            Oidc::new(
                url.into(),
                "app".into(),
                "https://id.example.com/jwks".into()
            )
            .is_err(),
            "issuer {url}"
        );
    }
    assert!(
        Oidc::new(
            "https://id.example.com".into(),
            "".into(),
            "https://id.example.com/jwks".into()
        )
        .is_err()
    );
}

#[tokio::test]
async fn manager_returns_401_for_invalid_login_and_503_for_provider_failure() {
    use axum::{body::Body, http::Request};
    use keygate::{Manager, manager_router};
    use tower::ServiceExt;
    let p = Provider::new().await;
    let store = Arc::new(common::Memory::default());
    let secret = "test-proxy-secret-at-least-32-bytes-long";
    for unavailable in [false, true] {
        *p.document.write().await = (
            if unavailable {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            },
            json!({"keys":[p.jwk]}).to_string(),
        );
        let manager = manager_router(
            Manager::new(store.clone(), secret.into(), "http://localhost:8080".into())
                .unwrap()
                .with_oidc(p.oidc()),
        );
        let mut claims = p.claims();
        if !unavailable {
            claims["aud"] = json!("wrong-audience");
        }
        let response = manager
            .oneshot(
                Request::builder()
                    .uri("/api/me")
                    .header("x-keygate-proxy-secret", secret)
                    .header("x-keygate-id-token", p.token(&claims, Some("fixture")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if unavailable {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
    }
}
