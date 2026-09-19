mod common;
use axum::{
    Json, Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use keygate::{Manager, identity::Oidc, manager_router};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
#[tokio::test]
async fn verifies_forwarded_id_token_and_rejects_forged_subject() {
    let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap();
    let x = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    let jwks = json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"test","x":x}]});
    let server = Router::new().route("/jwks", get(move || async move { Json(jwks) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });
    let verifier = Oidc::new(issuer.clone(), "keygate".into(), format!("{issuer}/jwks")).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("test".into());
    let key = EncodingKey::from_ed_der(bytes.as_ref());
    let claims = json!({"sub":"alice","iss":issuer,"aud":"keygate","exp":now+300});
    let token = encode(&header, &claims, &key).unwrap();
    assert_eq!(verifier.subject(&token).await.unwrap(), "alice");
    for (field, value) in [
        ("aud", json!("another-app")),
        ("iss", json!("https://evil.example")),
        ("exp", json!(now - 60)),
        ("sub", json!("")),
    ] {
        let mut bad = claims.clone();
        bad[field] = value;
        assert!(
            verifier
                .subject(&encode(&header, &bad, &key).unwrap())
                .await
                .is_err()
        );
    }
    let foreign = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    assert!(
        verifier
            .subject(
                &encode(
                    &header,
                    &claims,
                    &EncodingKey::from_ed_der(foreign.as_ref())
                )
                .unwrap()
            )
            .await
            .is_err()
    );
    let hmac = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"fake"),
    )
    .unwrap();
    assert!(verifier.subject(&hmac).await.is_err());
    let store = Arc::new(common::Memory::default());
    let secret = "test-proxy-secret-at-least-32-bytes-long";
    let app = manager_router(
        Manager::new(store, secret.into(), "http://localhost:8080".into())
            .unwrap()
            .with_oidc(verifier),
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header("x-keygate-proxy-secret", secret)
                .header("x-keygate-subject", "forged-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header("x-keygate-proxy-secret", secret)
                .header("x-keygate-id-token", token)
                .header("x-keygate-subject", "forged-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    use http_body_util::BodyExt;
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        json!({"subject":"alice","user_id":keygate::model::user_id("alice")})
    );
    task.abort();
}
