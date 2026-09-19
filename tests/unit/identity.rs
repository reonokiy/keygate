use super::*;
use axum::{Router, http::StatusCode, routing::get};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
#[tokio::test]
async fn jwks_failure_backoff_and_refresh_expiry() {
    let requests = Arc::new(AtomicUsize::new(0));
    let hits = requests.clone();
    let server = Router::new().route(
        "/jwks",
        get(move || {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                StatusCode::SERVICE_UNAVAILABLE
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });
    let verifier = Oidc::new(url.clone(), "app".into(), format!("{url}/jwks")).unwrap();
    let token = format!(
        "{}.{}.x",
        URL_SAFE_NO_PAD.encode(json!({"alg":"EdDSA","kid":"test"}).to_string()),
        URL_SAFE_NO_PAD.encode("{}")
    );
    for _ in 0..10 {
        assert!(matches!(
            verifier.subject(&token).await,
            Err(IdentityError::Unavailable)
        ));
    }
    assert_eq!(
        requests.load(Ordering::SeqCst),
        1,
        "failed fetches must be rate limited"
    );
    *verifier.cache.lock().await = Some((Instant::now() - Duration::from_secs(6), Err(())));
    assert!(matches!(
        verifier.subject(&token).await,
        Err(IdentityError::Unavailable)
    ));
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    *verifier.cache.lock().await = Some((
        Instant::now() - Duration::from_secs(61),
        Ok(JwkSet { keys: vec![] }),
    ));
    assert!(matches!(
        verifier.subject(&token).await,
        Err(IdentityError::Unavailable)
    ));
    assert_eq!(
        requests.load(Ordering::SeqCst),
        3,
        "expired successful cache must not mask an outage"
    );
    task.abort();
}
