mod common;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use keygate::{
    Authorizer, Manager, authz_router, manager_router,
    model::{Application, Versioned},
    store::{Store, StoreError},
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;
const SECRET: &str = "test-proxy-secret-at-least-32-bytes-long";
fn request(method: &str, path: &str, owner: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("x-keygate-proxy-secret", SECRET)
        .header("x-keygate-subject", owner)
        .header("origin", "http://localhost:8080")
        .header("x-keygate-csrf", "1")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}
async fn json_response(app: &Router, req: Request<Body>, expected: StatusCode) -> Value {
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), expected);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    }
}
async fn setup() -> (Arc<dyn Store>, Router) {
    let store: Arc<dyn Store> = Arc::new(common::Memory::default());
    let manager = manager_router(
        Manager::new(
            store.clone(),
            common::config(),
            SECRET.into(),
            "http://localhost:8080".into(),
        )
        .unwrap(),
    );
    (store, manager)
}
async fn create(manager: &Router) -> (Uuid, Uuid, String) {
    issue_for(manager, common::APP_ID).await
}
async fn issue_for(manager: &Router, id: Uuid) -> (Uuid, Uuid, String) {
    let key = json_response(
        manager,
        request(
            "POST",
            &format!("/api/apps/{id}/keys"),
            "alice",
            json!({"name":"script"}),
        ),
        StatusCode::CREATED,
    )
    .await;
    (
        id,
        Uuid::parse_str(key["id"].as_str().unwrap()).unwrap(),
        key["key"].as_str().unwrap().into(),
    )
}
async fn check(auth: &Router, app: Uuid, token: &str) -> StatusCode {
    auth.clone()
        .oneshot(
            Request::builder()
                .uri(format!("/check/{app}/v1/models"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}
#[tokio::test]
async fn applications_are_configured_by_admin_and_created_in_storage_only_for_keys() {
    let store: Arc<dyn Store> = Arc::new(common::Memory::default());
    let second = Uuid::new_v4();
    let config = common::config_for(&[(common::APP_ID, "Codex"), (second, "Custom API")]);
    let manager = manager_router(
        Manager::new(
            store.clone(),
            config,
            SECRET.into(),
            "http://localhost:8080".into(),
        )
        .unwrap(),
    );
    for owner in ["alice", "bob"] {
        let apps = json_response(
            &manager,
            request("GET", "/api/apps", owner, Value::Null),
            StatusCode::OK,
        )
        .await;
        assert_eq!(
            apps,
            json!([
                {"id": common::APP_ID, "name": "Codex", "keys": []},
                {"id": second, "name": "Custom API", "keys": []}
            ])
        );
    }
    assert!(store.list().await.unwrap().is_empty());
    json_response(
        &manager,
        request(
            "POST",
            "/api/apps",
            "alice",
            json!({"name": "User-created app"}),
        ),
        StatusCode::METHOD_NOT_ALLOWED,
    )
    .await;
    for path in ["/", "/app.js"] {
        let response = manager
            .clone()
            .oneshot(request("GET", path, "alice", Value::Null))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let content = std::str::from_utf8(&body).unwrap();
        assert!(!content.contains("create-app"));
        assert!(!content.contains("app-name"));
    }
    json_response(
        &manager,
        request(
            "POST",
            &format!("/api/apps/{}/keys", common::APP_ID),
            "alice",
            json!({"name": "\n"}),
        ),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert!(store.list().await.unwrap().is_empty());
    let (app, key, _) = create(&manager).await;
    let stored = store.get(app).await.unwrap().unwrap();
    assert_eq!(stored.app.name, "Codex");
    assert_eq!(stored.app.keys.len(), 1);
    assert_eq!(stored.app.keys[0].id, key);
}

#[tokio::test]
async fn catalog_names_override_storage_and_unconfigured_apps_are_inaccessible() {
    let (store, manager) = setup().await;
    let (app, _, token) = create(&manager).await;
    let mut stored = store.get(app).await.unwrap().unwrap();
    stored.app.name = "Old database name".into();
    store.put(&stored.app, stored.version).await.unwrap();
    let (orphan_key, orphan_token) = keygate::model::issue("alice".into(), "orphan key".into());
    let orphan = Application {
        id: Uuid::new_v4(),
        name: "Unconfigured database app".into(),
        keys: vec![orphan_key.clone()],
    };
    store.put(&orphan, 0).await.unwrap();
    let apps = json_response(
        &manager,
        request("GET", "/api/apps", "alice", Value::Null),
        StatusCode::OK,
    )
    .await;
    assert_eq!(apps.as_array().unwrap().len(), 1);
    assert_eq!(apps[0]["id"], app.to_string());
    assert_eq!(apps[0]["name"], "Codex");
    assert_eq!(apps[0]["keys"].as_array().unwrap().len(), 1);
    for (method, path, body) in [
        (
            "POST",
            format!("/api/apps/{}/keys", orphan.id),
            json!({"name": "new"}),
        ),
        (
            "DELETE",
            format!("/api/apps/{}/keys/{}", orphan.id, orphan_key.id),
            Value::Null,
        ),
    ] {
        json_response(
            &manager,
            request(method, &path, "alice", body),
            StatusCode::NOT_FOUND,
        )
        .await;
    }
    let auth = authz_router(Authorizer::new(
        store.clone(),
        common::config(),
        Duration::ZERO,
        16,
    ));
    assert_eq!(check(&auth, app, &token).await, StatusCode::OK);
    assert_eq!(
        check(&auth, orphan.id, &orphan_token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(store.get(orphan.id).await.unwrap().unwrap().version, 1);
}

#[tokio::test]
async fn config_rename_preserves_existing_keys_after_restart() {
    let (store, manager) = setup().await;
    let (app, key, token) = create(&manager).await;
    let config = common::config_for(&[(app, "Renamed by admin")]);
    let manager = manager_router(
        Manager::new(
            store.clone(),
            config.clone(),
            SECRET.into(),
            "http://localhost:8080".into(),
        )
        .unwrap(),
    );
    let auth = authz_router(Authorizer::new(store.clone(), config, Duration::ZERO, 16));
    let apps = json_response(
        &manager,
        request("GET", "/api/apps", "alice", Value::Null),
        StatusCode::OK,
    )
    .await;
    assert_eq!(apps[0]["id"], app.to_string());
    assert_eq!(apps[0]["name"], "Renamed by admin");
    assert_eq!(apps[0]["keys"][0]["id"], key.to_string());
    assert_eq!(store.get(app).await.unwrap().unwrap().version, 1);
    assert_eq!(check(&auth, app, &token).await, StatusCode::OK);
    json_response(
        &manager,
        request(
            "DELETE",
            &format!("/api/apps/{app}/keys/{key}"),
            "alice",
            Value::Null,
        ),
        StatusCode::NO_CONTENT,
    )
    .await;
    assert_eq!(check(&auth, app, &token).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn removed_application_blocks_persisted_keys_after_config_reload() {
    let (store, manager) = setup().await;
    let (app, key, token) = create(&manager).await;
    let config = common::config_for(&[]);
    let manager = manager_router(
        Manager::new(
            store.clone(),
            config.clone(),
            SECRET.into(),
            "http://localhost:8080".into(),
        )
        .unwrap(),
    );
    let auth = authz_router(Authorizer::new(
        store.clone(),
        config,
        Duration::from_secs(30),
        16,
    ));
    let apps = json_response(
        &manager,
        request("GET", "/api/apps", "alice", Value::Null),
        StatusCode::OK,
    )
    .await;
    assert_eq!(apps, json!([]));
    for (method, path, body) in [
        (
            "POST",
            format!("/api/apps/{app}/keys"),
            json!({"name": "new"}),
        ),
        ("DELETE", format!("/api/apps/{app}/keys/{key}"), Value::Null),
    ] {
        json_response(
            &manager,
            request(method, &path, "alice", body),
            StatusCode::NOT_FOUND,
        )
        .await;
    }
    assert_eq!(check(&auth, app, &token).await, StatusCode::UNAUTHORIZED);
    let stored = store.get(app).await.unwrap().unwrap();
    assert_eq!(stored.version, 1);
    assert_eq!(stored.app.keys.len(), 1);
    assert!(!stored.app.keys[0].revoked);
}

#[tokio::test]
async fn manager_rejects_mismatched_storage_records_before_mutating_keys() {
    struct Corrupt(Versioned);
    #[async_trait::async_trait]
    impl Store for Corrupt {
        async fn get(&self, _: Uuid) -> Result<Option<Versioned>, StoreError> {
            Ok(Some(self.0.clone()))
        }
        async fn list(&self) -> Result<Vec<Versioned>, StoreError> {
            Ok(vec![self.0.clone()])
        }
        async fn put(&self, _: &Application, _: u64) -> Result<(), StoreError> {
            panic!("invalid storage records must never be written")
        }
    }
    let (key, _) = keygate::model::issue("alice".into(), "existing".into());
    let key_id = key.id;
    let store = Arc::new(Corrupt(Versioned {
        app: Application {
            id: Uuid::new_v4(),
            name: "Mismatched".into(),
            keys: vec![key],
        },
        version: 1,
    }));
    let manager = manager_router(
        Manager::new(
            store,
            common::config(),
            SECRET.into(),
            "http://localhost:8080".into(),
        )
        .unwrap(),
    );
    for (method, path, body) in [
        (
            "POST",
            format!("/api/apps/{}/keys", common::APP_ID),
            json!({"name": "new"}),
        ),
        (
            "DELETE",
            format!("/api/apps/{}/keys/{key_id}", common::APP_ID),
            Value::Null,
        ),
    ] {
        let error = json_response(
            &manager,
            request(method, &path, "alice", body),
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .await;
        assert_eq!(error, json!({"error": "invalid storage record"}));
    }
}

#[tokio::test]
async fn issue_use_isolate_and_revoke() {
    let (store, manager) = setup().await;
    let (app, key, token) = create(&manager).await;
    let auth = authz_router(Authorizer::new(
        store.clone(),
        common::config(),
        Duration::ZERO,
        16,
    ));
    assert_eq!(check(&auth, app, &token).await, StatusCode::OK);
    assert_eq!(
        check(&auth, Uuid::new_v4(), &token).await,
        StatusCode::UNAUTHORIZED
    );
    let mut bad = token.clone();
    bad.pop();
    bad.push(if token.ends_with('0') { '1' } else { '0' });
    assert_eq!(check(&auth, app, &bad).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        check(&auth, app, "malformed").await,
        StatusCode::UNAUTHORIZED
    );
    let list = json_response(
        &manager,
        request("GET", "/api/apps", "alice", Value::Null),
        StatusCode::OK,
    )
    .await;
    assert!(!list.to_string().contains(&token));
    assert!(!list.to_string().contains("digest"));
    let persisted = serde_json::to_string(&store.get(app).await.unwrap().unwrap().app).unwrap();
    assert!(!persisted.contains(&token));
    assert!(persisted.contains("digest"));
    let bob = json_response(
        &manager,
        request("GET", "/api/apps", "bob", Value::Null),
        StatusCode::OK,
    )
    .await;
    assert_eq!(bob[0]["keys"], json!([]));
    json_response(
        &manager,
        request(
            "POST",
            &format!("/api/apps/{app}/keys"),
            "bob",
            json!({"name":"own"}),
        ),
        StatusCode::CREATED,
    )
    .await;
    json_response(
        &manager,
        request(
            "DELETE",
            &format!("/api/apps/{app}/keys/{key}"),
            "bob",
            Value::Null,
        ),
        StatusCode::NOT_FOUND,
    )
    .await;
    json_response(
        &manager,
        request(
            "DELETE",
            &format!("/api/apps/{app}/keys/{key}"),
            "alice",
            Value::Null,
        ),
        StatusCode::NO_CONTENT,
    )
    .await;
    assert_eq!(check(&auth, app, &token).await, StatusCode::UNAUTHORIZED);
    json_response(
        &manager,
        request(
            "DELETE",
            &format!("/api/apps/{app}/keys/{key}"),
            "alice",
            Value::Null,
        ),
        StatusCode::NO_CONTENT,
    )
    .await;
}

#[tokio::test]
async fn previously_issued_base64url_keys_still_authorize_and_can_be_revoked() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let (store, manager) = setup().await;
    let app = common::APP_ID;
    let token = format!("kg-{}", URL_SAFE_NO_PAD.encode([0xfb; 32]));
    assert_eq!(token.len(), 46);
    assert!(token[3..].contains('-'));
    assert!(token.contains('_'));
    let (mut key, _) = keygate::model::issue("alice".into(), "legacy script".into());
    key.digest = keygate::model::digest(&token);
    let key_id = key.id;
    store
        .put(
            &Application {
                id: app,
                name: "Codex".into(),
                keys: vec![key],
            },
            0,
        )
        .await
        .unwrap();
    let auth = authz_router(Authorizer::new(store, common::config(), Duration::ZERO, 16));
    assert_eq!(check(&auth, app, &token).await, StatusCode::OK);
    let (_, _, fresh) = create(&manager).await;
    assert_eq!(fresh.len(), 49);
    assert!(
        fresh
            .strip_prefix("kg-")
            .unwrap()
            .bytes()
            .all(|b| b.is_ascii_alphabetic())
    );
    assert_eq!(check(&auth, app, &fresh).await, StatusCode::OK);
    json_response(
        &manager,
        request(
            "DELETE",
            &format!("/api/apps/{app}/keys/{key_id}"),
            "alice",
            Value::Null,
        ),
        StatusCode::NO_CONTENT,
    )
    .await;
    assert_eq!(check(&auth, app, &token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(check(&auth, app, &fresh).await, StatusCode::OK);
}

#[tokio::test]
async fn nonalphabetic_new_length_tokens_cannot_authorize_even_with_stored_digests() {
    let (store, _) = setup().await;
    let tokens: Vec<_> = ['0', '-', '_']
        .into_iter()
        .map(|invalid| format!("kg-{}{invalid}", "A".repeat(45)))
        .collect();
    let keys = tokens
        .iter()
        .map(|token| {
            let (mut key, _) = keygate::model::issue("alice".into(), "invalid stored key".into());
            key.digest = keygate::model::digest(token);
            key
        })
        .collect();
    let app = common::APP_ID;
    store
        .put(
            &Application {
                id: app,
                name: "Codex".into(),
                keys,
            },
            0,
        )
        .await
        .unwrap();
    let auth = authz_router(Authorizer::new(store, common::config(), Duration::ZERO, 16));
    for token in tokens {
        assert_eq!(token.len(), 49);
        assert_eq!(check(&auth, app, &token).await, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn rejects_untrusted_identity_and_csrf() {
    let (_, manager) = setup().await;
    for name in ["x-keygate-subject", "x-keygate-proxy-secret"] {
        let mut req = request("GET", "/api/apps", "alice", Value::Null);
        req.headers_mut().remove(name);
        json_response(&manager, req, StatusCode::UNAUTHORIZED).await;
    }
    let mut req = request(
        "POST",
        &format!("/api/apps/{}/keys", common::APP_ID),
        "alice",
        json!({"name":"bad"}),
    );
    req.headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    json_response(&manager, req, StatusCode::FORBIDDEN).await;
    let mut req = request(
        "POST",
        &format!("/api/apps/{}/keys", common::APP_ID),
        "alice",
        json!({"name":"bad"}),
    );
    req.headers_mut().remove("x-keygate-csrf");
    json_response(&manager, req, StatusCode::FORBIDDEN).await;
    let mut req = request("GET", "/api/apps", "alice", Value::Null);
    req.headers_mut()
        .append("x-keygate-subject", "bob".parse().unwrap());
    json_response(&manager, req, StatusCode::UNAUTHORIZED).await;
}
#[tokio::test]
async fn separate_nodes_observe_revocation_after_absolute_cache_expiry() {
    let (store, manager) = setup().await;
    let (app, key, token) = create(&manager).await;
    let a = authz_router(Authorizer::new(
        store.clone(),
        common::config(),
        Duration::from_millis(150),
        16,
    ));
    let b = authz_router(Authorizer::new(
        store,
        common::config(),
        Duration::from_millis(150),
        16,
    ));
    assert_eq!(check(&a, app, &token).await, StatusCode::OK);
    assert_eq!(check(&b, app, &token).await, StatusCode::OK);
    json_response(
        &manager,
        request(
            "DELETE",
            &format!("/api/apps/{app}/keys/{key}"),
            "alice",
            Value::Null,
        ),
        StatusCode::NO_CONTENT,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(check(&a, app, &token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(check(&b, app, &token).await, StatusCode::UNAUTHORIZED);
}
struct Failing {
    inner: Arc<dyn Store>,
    fail: AtomicBool,
}
#[async_trait::async_trait]
impl Store for Failing {
    async fn get(&self, id: Uuid) -> Result<Option<Versioned>, StoreError> {
        if self.fail.load(Ordering::SeqCst) {
            Err(StoreError::Unavailable)
        } else {
            self.inner.get(id).await
        }
    }
    async fn list(&self) -> Result<Vec<Versioned>, StoreError> {
        self.inner.list().await
    }
    async fn put(&self, app: &Application, version: u64) -> Result<(), StoreError> {
        self.inner.put(app, version).await
    }
}
#[tokio::test]
async fn storage_outage_does_not_extend_cached_authorization() {
    let (store, manager) = setup().await;
    let (app, _, token) = create(&manager).await;
    let store = Arc::new(Failing {
        inner: store,
        fail: AtomicBool::new(false),
    });
    let auth = authz_router(Authorizer::new(
        store.clone(),
        common::config(),
        Duration::from_millis(150),
        16,
    ));
    assert_eq!(check(&auth, app, &token).await, StatusCode::OK);
    store.fail.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        check(&auth, app, &token).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}
#[tokio::test]
#[ignore = "requires Linux Docker host networking and envoyproxy/envoy:v1.38.4"]
async fn real_envoy_authorization_and_streaming() {
    use std::process::Command;
    struct Container(String);
    impl Drop for Container {
        fn drop(&mut self) {
            let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
        }
    }
    let (store, manager) = setup().await;
    let (app, key, token) = create(&manager).await;
    let authz = authz_router(Authorizer::new(store, common::config(), Duration::ZERO, 16));
    let auth_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_port = auth_listener.local_addr().unwrap().port();
    let auth_task = tokio::spawn(async move { axum::serve(auth_listener, authz).await.unwrap() });
    let upstream = Router::new().fallback(|headers: axum::http::HeaderMap| async move {
        (
            [
                ("content-type", "text/event-stream".to_owned()),
                (
                    "x-observed-auth-user",
                    headers
                        .get("x-auth-request-user")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                ),
                (
                    "x-observed-user",
                    headers
                        .get("x-keygate-user-id")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                ),
                (
                    "x-observed-app",
                    headers
                        .get("x-keygate-app")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                ),
                (
                    "x-observed-key",
                    headers
                        .get("x-keygate-key-id")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                ),
            ],
            "data: ready\n\ndata: [DONE]\n\n",
        )
    });
    let up_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = up_listener.local_addr().unwrap().port();
    let up_task = tokio::spawn(async move { axum::serve(up_listener, upstream).await.unwrap() });
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let cluster = |name: &str, port: u16| json!({"name":name,"type":"STATIC","connect_timeout":"1s","load_assignment":{"cluster_name":name,"endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"127.0.0.1","port_value":port}}}}]}]}});
    let mut config = json!({"static_resources":{"listeners":[{"name":"ingress","address":{"socket_address":{"address":"127.0.0.1","port_value":port}},"filter_chains":[{"filters":[{"name":"envoy.filters.network.http_connection_manager","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager","stat_prefix":"test","route_config":{"name":"route","virtual_hosts":[{"name":"all","domains":["*"],"routes":[{"match":{"prefix":"/"},"route":{"cluster":"upstream","timeout":"0s"}}]}]},"http_filters":[{"name":"envoy.filters.http.ext_authz","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz","failure_mode_allow":false,"http_service":{"server_uri":{"uri":"http://authz","cluster":"authz","timeout":"6s"},"path_prefix":format!("/check/{app}"),"authorization_request":{"allowed_headers":{"patterns":[{"exact":"authorization"}]}}}}},{"name":"envoy.filters.http.router","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]}}]}]}],"clusters":[cluster("authz",auth_port),cluster("upstream",up_port)]}});
    let temp = tempfile::tempdir().unwrap();
    config["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        ["http_filters"][0]["typed_config"]["http_service"]["authorization_response"] = json!({"allowed_upstream_headers":{"patterns":[{"exact":"x-auth-request-user"},{"exact":"x-keygate-user-id"},{"exact":"x-keygate-app"},{"exact":"x-keygate-key-id"}]}});
    let file = temp.path().join("envoy.json");
    std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
    let name = format!("keygate-envoy-test-{}", Uuid::new_v4());
    let _guard = Container(name.clone());
    let result = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &name,
            "--network",
            "host",
            "-v",
            &format!("{}:/etc/envoy/envoy.json:ro", file.display()),
            "envoyproxy/envoy:v1.38.4",
            "-c",
            "/etc/envoy/envoy.json",
            "--concurrency",
            "1",
            "--log-level",
            "error",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "could not start test Envoy: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{port}/v1/responses");
    let mut ready = false;
    for _ in 0..100 {
        if client.get(&url).send().await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !ready {
        let logs = Command::new("docker")
            .args(["logs", &name])
            .output()
            .unwrap();
        panic!("Envoy failed: {}", String::from_utf8_lossy(&logs.stderr));
    }
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let response = client
        .post(&url)
        .bearer_auth(&token)
        .header("x-auth-request-user", "forged-auth-user")
        .header("x-keygate-user-id", "forged-user")
        .header("x-keygate-app", "forged-app")
        .header("x-keygate-key-id", "forged-key")
        .json(&json!({"stream":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    assert_eq!(
        response.headers()["x-observed-user"],
        keygate::model::user_id("alice")
    );
    assert_eq!(
        response.headers()["x-observed-auth-user"],
        response.headers()["x-observed-user"]
    );
    assert_eq!(response.headers()["x-observed-app"], app.to_string());
    assert_eq!(response.headers()["x-observed-key"], key.to_string());
    assert!(response.text().await.unwrap().contains("data: [DONE]"));
    json_response(
        &manager,
        request(
            "DELETE",
            &format!("/api/apps/{app}/keys/{key}"),
            "alice",
            Value::Null,
        ),
        StatusCode::NO_CONTENT,
    )
    .await;
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    auth_task.abort();
    up_task.abort();
}

#[tokio::test]
async fn all_routes_security_headers_and_input_boundaries() {
    let (store, manager) = setup().await;
    let (app, _, token) = create(&manager).await;
    for path in ["/", "/app.js", "/style.css", "/api/me", "/healthz"] {
        let response = manager
            .clone()
            .oneshot(request("GET", path, "alice", Value::Null))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
    }
    for path in [
        "/healthz".to_owned(),
        format!("/check/{app}"),
        format!("/check/{app}/"),
    ] {
        let router = authz_router(Authorizer::new(
            store.clone(),
            common::config(),
            Duration::ZERO,
            16,
        ));
        let response = router
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    for bad in [
        "".to_owned(),
        " ".into(),
        "x".repeat(129),
        "new\napp".into(),
    ] {
        json_response(
            &manager,
            request(
                "POST",
                &format!("/api/apps/{app}/keys"),
                "alice",
                json!({"name":bad}),
            ),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    let mut req = request(
        "POST",
        &format!("/api/apps/{app}/keys"),
        "alice",
        json!({"name":"x".repeat(16384)}),
    );
    assert_eq!(
        manager.clone().oneshot(req).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    req = request("GET", "/api/apps", "alice", Value::Null);
    req.headers_mut().insert(
        "x-keygate-proxy-secret",
        axum::http::HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
    json_response(&manager, req, StatusCode::UNAUTHORIZED).await;
    for sub in ["".to_owned(), "a".repeat(513)] {
        json_response(
            &manager,
            request("GET", "/api/apps", &sub, Value::Null),
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }
    json_response(
        &manager,
        request(
            "DELETE",
            &format!("/api/apps/{app}/keys/{}", Uuid::new_v4()),
            "alice",
            Value::Null,
        ),
        StatusCode::NOT_FOUND,
    )
    .await;
    let mut entry = store.get(app).await.unwrap().unwrap();
    entry.app.keys = vec![entry.app.keys[0].clone(); 1000];
    store.put(&entry.app, entry.version).await.unwrap();
    json_response(
        &manager,
        request(
            "POST",
            &format!("/api/apps/{app}/keys"),
            "alice",
            json!({"name":"excess"}),
        ),
        StatusCode::CONFLICT,
    )
    .await;
    // Alice's quota must not consume Bob's quota on the same shared application.
    json_response(
        &manager,
        request(
            "POST",
            &format!("/api/apps/{app}/keys"),
            "bob",
            json!({"name":"own quota"}),
        ),
        StatusCode::CREATED,
    )
    .await;
    json_response(
        &manager,
        request(
            "POST",
            &format!("/api/apps/{}/keys", Uuid::new_v4()),
            "bob",
            json!({"name":"missing"}),
        ),
        StatusCode::NOT_FOUND,
    )
    .await;
    assert!(
        Manager::new(
            store.clone(),
            common::config(),
            "short".into(),
            "http://localhost".into()
        )
        .is_err()
    );
    for origin in [
        "not a URL",
        "https://example.com/path",
        "https://example.com/",
        "ftp://example.com",
    ] {
        assert!(
            Manager::new(
                store.clone(),
                common::config(),
                SECRET.into(),
                origin.into()
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn malformed_and_duplicate_credentials_never_authorize() {
    let (store, manager) = setup().await;
    let (app, _, token) = create(&manager).await;
    let auth = authz_router(Authorizer::new(store, common::config(), Duration::ZERO, 16));
    for value in [
        None,
        Some("Basic abc"),
        Some("Bearer "),
        Some("Bearer invalid"),
    ] {
        let mut request = Request::builder().uri(format!("/check/{app}"));
        if let Some(v) = value {
            request = request.header("authorization", v);
        }
        assert_eq!(
            auth.clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let request = Request::builder()
        .uri(format!("/check/{app}"))
        .header("authorization", format!("Bearer {token}"))
        .header("authorization", "Bearer other")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        auth.clone().oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let missing = Uuid::new_v4();
    let (_, token) = keygate::model::issue("alice".into(), "unknown".into());
    assert_eq!(
        check(&auth, missing, &token).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn manager_storage_errors_are_sanitized_and_do_not_issue_keys() {
    struct Broken {
        inner: Arc<dyn Store>,
        conflict: bool,
    }
    #[async_trait::async_trait]
    impl Store for Broken {
        async fn get(&self, id: Uuid) -> Result<Option<Versioned>, StoreError> {
            self.inner.get(id).await
        }
        async fn list(&self) -> Result<Vec<Versioned>, StoreError> {
            Err(StoreError::Unavailable)
        }
        async fn put(&self, _: &Application, _: u64) -> Result<(), StoreError> {
            Err(if self.conflict {
                StoreError::Conflict
            } else {
                StoreError::Unavailable
            })
        }
    }
    let (store, manager) = setup().await;
    let (app, key, _) = create(&manager).await;
    for conflict in [false, true] {
        let manager = manager_router(
            Manager::new(
                Arc::new(Broken {
                    inner: store.clone(),
                    conflict,
                }),
                common::config(),
                SECRET.into(),
                "http://localhost:8080".into(),
            )
            .unwrap(),
        );
        let code = if conflict {
            StatusCode::CONFLICT
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        for (method, path, body) in [
            (
                "POST",
                format!("/api/apps/{app}/keys"),
                json!({"name":"new"}),
            ),
            ("DELETE", format!("/api/apps/{app}/keys/{key}"), Value::Null),
        ] {
            let result = json_response(&manager, request(method, &path, "alice", body), code).await;
            assert!(result.get("key").is_none());
        }
        json_response(
            &manager,
            request("GET", "/api/apps", "alice", Value::Null),
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .await;
    }
}

#[tokio::test]
async fn authenticated_user_identity_comes_from_storage_not_client_headers() {
    let (store, manager) = setup().await;
    shared_users(store, manager).await;
}
async fn shared_users(store: Arc<dyn Store>, manager: Router) {
    let auth = authz_router(Authorizer::new(store, common::config(), Duration::ZERO, 16));
    let app = common::APP_ID.to_string();
    let id = app.as_str();
    let mut keys = Vec::new();
    for owner in ["alice", "bob"] {
        let issued = json_response(
            &manager,
            request(
                "POST",
                &format!("/api/apps/{id}/keys"),
                owner,
                json!({"name":"script","owner":"attacker"}),
            ),
            StatusCode::CREATED,
        )
        .await;
        keys.push((owner, issued.clone()));
        let response = auth
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/check/{id}"))
                    .header(
                        "authorization",
                        format!("Bearer {}", issued["key"].as_str().unwrap()),
                    )
                    .header("x-auth-request-user", "attacker")
                    .header("x-keygate-user-id", "attacker")
                    .header("x-keygate-subject", "attacker")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-keygate-user-id"],
            keygate::model::user_id(owner)
        );
        assert_eq!(
            response.headers()["x-auth-request-user"],
            response.headers()["x-keygate-user-id"]
        );
        assert_eq!(response.headers()["x-keygate-app"], id);
        assert_eq!(
            response.headers()["x-keygate-key-id"],
            issued["id"].as_str().unwrap()
        );
        let me = json_response(
            &manager,
            request("GET", "/api/me", owner, Value::Null),
            StatusCode::OK,
        )
        .await;
        assert_eq!(me["user_id"], keygate::model::user_id(owner));
    }
    for (owner, issued) in &keys {
        let other = if *owner == "alice" { "bob" } else { "alice" };
        let list = json_response(
            &manager,
            request("GET", "/api/apps", owner, Value::Null),
            StatusCode::OK,
        )
        .await;
        assert_eq!(list[0]["keys"].as_array().unwrap().len(), 1);
        assert_eq!(list[0]["keys"][0]["id"], issued["id"]);
        let path = format!("/api/apps/{id}/keys/{}", issued["id"].as_str().unwrap());
        json_response(
            &manager,
            request("DELETE", &path, other, Value::Null),
            StatusCode::NOT_FOUND,
        )
        .await;
        assert_eq!(
            check(
                &auth,
                Uuid::parse_str(id).unwrap(),
                issued["key"].as_str().unwrap()
            )
            .await,
            StatusCode::OK
        );
        json_response(
            &manager,
            request("DELETE", &path, owner, Value::Null),
            StatusCode::NO_CONTENT,
        )
        .await;
        assert_eq!(
            check(
                &auth,
                Uuid::parse_str(id).unwrap(),
                issued["key"].as_str().unwrap()
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn failed_ownership_lookup_and_invalid_key_name_cannot_mutate_storage() {
    let (store, manager) = setup().await;
    let (app, key, _) = create(&manager).await;
    json_response(
        &manager,
        request(
            "POST",
            &format!("/api/apps/{app}/keys"),
            "alice",
            json!({"name":"\n"}),
        ),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(store.get(app).await.unwrap().unwrap().app.keys.len(), 1);
    let manager = manager_router(
        Manager::new(
            Arc::new(Failing {
                inner: store,
                fail: AtomicBool::new(true),
            }),
            common::config(),
            SECRET.into(),
            "http://localhost:8080".into(),
        )
        .unwrap(),
    );
    json_response(
        &manager,
        request(
            "POST",
            &format!("/api/apps/{app}/keys"),
            "alice",
            json!({"name":"new"}),
        ),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    json_response(
        &manager,
        request(
            "DELETE",
            &format!("/api/apps/{app}/keys/{key}"),
            "alice",
            Value::Null,
        ),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn postgres_shared_user_management_and_authorization() {
    let db = common::Database::start();
    let pg = keygate::store::PostgresStore::open(&db.url).await.unwrap();
    pg.initialize().await.unwrap();
    let store: Arc<dyn Store> = Arc::new(pg);
    let manager = manager_router(
        Manager::new(
            store.clone(),
            common::config(),
            SECRET.into(),
            "http://localhost:8080".into(),
        )
        .unwrap(),
    );
    shared_users(store, manager).await;
}

#[tokio::test]
async fn opaque_key_cannot_cross_application_scope() {
    let first_id = Uuid::new_v4();
    let second_id = Uuid::new_v4();
    let config = common::config_for(&[(first_id, "First"), (second_id, "Second")]);
    let store: Arc<dyn Store> = Arc::new(common::Memory::default());
    let manager = manager_router(
        Manager::new(
            store.clone(),
            config.clone(),
            SECRET.into(),
            "http://localhost:8080".into(),
        )
        .unwrap(),
    );
    let (first, _, first_token) = issue_for(&manager, first_id).await;
    let (second, _, second_token) = issue_for(&manager, second_id).await;
    let auth = authz_router(Authorizer::new(store, config, Duration::ZERO, 16));
    assert_eq!(check(&auth, first, &first_token).await, StatusCode::OK);
    assert_eq!(check(&auth, second, &second_token).await, StatusCode::OK);
    assert_eq!(
        check(&auth, first, &second_token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        check(&auth, second, &first_token).await,
        StatusCode::UNAUTHORIZED
    );
}
