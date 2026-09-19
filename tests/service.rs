use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use keygate::{
    Authorizer, Manager, authz_router, manager_router,
    model::{Application, Versioned},
    store::{OpenBaoStore, SqliteStore, Store, StoreError},
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
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open("sqlite::memory:").await.unwrap());
    let manager = manager_router(
        Manager::new(store.clone(), SECRET.into(), "http://localhost:8080".into()).unwrap(),
    );
    (store, manager)
}
async fn create(manager: &Router) -> (Uuid, Uuid, String) {
    let app = json_response(
        manager,
        request("POST", "/api/apps", "alice", json!({"name":"Codex"})),
        StatusCode::CREATED,
    )
    .await;
    let id = Uuid::parse_str(app["id"].as_str().unwrap()).unwrap();
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
async fn issue_use_isolate_and_revoke() {
    let (store, manager) = setup().await;
    let (app, key, token) = create(&manager).await;
    let auth = authz_router(Authorizer::new(store.clone(), Duration::ZERO, 16));
    assert_eq!(check(&auth, app, &token).await, StatusCode::OK);
    assert_eq!(
        check(&auth, Uuid::new_v4(), &token).await,
        StatusCode::FORBIDDEN
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
    assert_eq!(bob, json!([]));
    json_response(
        &manager,
        request(
            "POST",
            &format!("/api/apps/{app}/keys"),
            "bob",
            json!({"name":"stolen"}),
        ),
        StatusCode::NOT_FOUND,
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
async fn rejects_untrusted_identity_and_csrf() {
    let (_, manager) = setup().await;
    for name in ["x-keygate-subject", "x-keygate-proxy-secret"] {
        let mut req = request("GET", "/api/apps", "alice", Value::Null);
        req.headers_mut().remove(name);
        json_response(&manager, req, StatusCode::UNAUTHORIZED).await;
    }
    let mut req = request("POST", "/api/apps", "alice", json!({"name":"bad"}));
    req.headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    json_response(&manager, req, StatusCode::FORBIDDEN).await;
    let mut req = request("POST", "/api/apps", "alice", json!({"name":"bad"}));
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
        Duration::from_millis(150),
        16,
    ));
    let b = authz_router(Authorizer::new(store, Duration::from_millis(150), 16));
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
async fn cas_contract(store: Arc<dyn Store>) {
    let mut app = Application {
        id: Uuid::new_v4(),
        owner: "alice".into(),
        name: "test".into(),
        keys: vec![],
    };
    store.put(&app, 0).await.unwrap();
    assert!(matches!(
        store.put(&app, 0).await,
        Err(StoreError::Conflict)
    ));
    let first = store.get(app.id).await.unwrap().unwrap();
    let (mut key, _) = keygate::model::issue(app.id, "key".into());
    key.revoked = true;
    app.keys.push(key);
    store.put(&app, first.version).await.unwrap();
    assert!(matches!(
        store.put(&first.app, first.version).await,
        Err(StoreError::Conflict)
    ));
    assert!(store.get(app.id).await.unwrap().unwrap().app.keys[0].revoked);
    assert_eq!(store.list().await.unwrap().len(), 1);
}
#[tokio::test]
async fn sqlite_cas_and_restart_persistence() {
    let temp = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", temp.path().join("keys.db").display());
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&url).await.unwrap());
    cas_contract(store).await;
    let reopened = SqliteStore::open(&url).await.unwrap();
    assert_eq!(reopened.list().await.unwrap().len(), 1);
}

// Wire-level KV v2 contract double. This is not a real OpenBao daemon.
#[tokio::test]
async fn openbao_http_contract_cas_token_reload_and_fail_closed() {
    use axum::{
        extract::{Path, State},
        http::HeaderMap,
        routing::get,
    };
    use std::collections::HashMap;
    type Data = Arc<tokio::sync::Mutex<HashMap<Uuid, (u64, Value)>>>;
    async fn read(
        State(data): State<Data>,
        Path(id): Path<Uuid>,
        headers: HeaderMap,
    ) -> (StatusCode, axum::Json<Value>) {
        if headers
            .get("x-vault-token")
            .is_none_or(|v| v != "test-token")
        {
            return (StatusCode::FORBIDDEN, axum::Json(json!({})));
        }
        match data.lock().await.get(&id) {
            Some((v, d)) => (
                StatusCode::OK,
                axum::Json(json!({"data":{"data":d,"metadata":{"version":v}}})),
            ),
            None => (StatusCode::NOT_FOUND, axum::Json(json!({}))),
        }
    }
    async fn write(
        State(data): State<Data>,
        Path(id): Path<Uuid>,
        headers: HeaderMap,
        axum::Json(body): axum::Json<Value>,
    ) -> StatusCode {
        if headers
            .get("x-vault-token")
            .is_none_or(|v| v != "test-token")
        {
            return StatusCode::FORBIDDEN;
        }
        let mut data = data.lock().await;
        let version = data.get(&id).map_or(0, |(v, _)| *v);
        if body["options"]["cas"].as_u64() != Some(version) {
            return StatusCode::BAD_REQUEST;
        }
        data.insert(id, (version + 1, body["data"].clone()));
        StatusCode::OK
    }
    async fn list(State(data): State<Data>, headers: HeaderMap) -> (StatusCode, axum::Json<Value>) {
        if headers
            .get("x-vault-token")
            .is_none_or(|v| v != "test-token")
        {
            return (StatusCode::FORBIDDEN, axum::Json(json!({})));
        }
        (
            StatusCode::OK,
            axum::Json(
                json!({"data":{"keys":data.lock().await.keys().map(ToString::to_string).collect::<Vec<_>>()}}),
            ),
        )
    }
    let app = Router::new()
        .route("/v1/kv/data/keygate/apps/{id}", get(read).post(write))
        .route("/v1/kv/metadata/keygate/apps", get(list))
        .with_state(Data::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let temp = tempfile::tempdir().unwrap();
    let token_file = temp.path().join("token");
    tokio::fs::write(&token_file, "test-token\n").await.unwrap();
    let store: Arc<dyn Store> = Arc::new(
        OpenBaoStore::new(
            &format!("http://{addr}"),
            "kv",
            "keygate",
            token_file.clone(),
        )
        .unwrap(),
    );
    cas_contract(store.clone()).await;
    tokio::fs::write(&token_file, "revoked").await.unwrap();
    assert!(matches!(store.list().await, Err(StoreError::Unavailable)));
    tokio::fs::write(&token_file, "test-token").await.unwrap();
    assert_eq!(store.list().await.unwrap().len(), 1);
    task.abort();
    assert!(matches!(
        store.get(Uuid::new_v4()).await,
        Err(StoreError::Unavailable)
    ));
}

/// Real local OpenBao, isolated from cluster credentials. Run with cargo test-all.
#[tokio::test]
#[ignore = "requires Docker and quay.io/openbao/openbao:2.6.1"]
async fn real_openbao_lifecycle() {
    use std::process::Command;
    struct Container(String);
    impl Drop for Container {
        fn drop(&mut self) {
            let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
        }
    }
    let name = format!("keygate-test-{}", Uuid::new_v4());
    let _guard = Container(name.clone());
    let result = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &name,
            "-p",
            "127.0.0.1::8200",
            "-e",
            "BAO_DEV_ROOT_TOKEN_ID=keygate-isolated-test-only",
            "quay.io/openbao/openbao:2.6.1",
            "server",
            "-dev",
            "-dev-listen-address=0.0.0.0:8200",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "Docker failed to start isolated OpenBao"
    );
    let output = Command::new("docker")
        .args(["port", &name, "8200/tcp"])
        .output()
        .unwrap();
    let base = format!(
        "http://{}",
        String::from_utf8(output.stdout).unwrap().trim()
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let mut ready = false;
    for _ in 0..100 {
        if client
            .get(format!("{base}/v1/sys/health"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "isolated OpenBao never became ready");
    let response = client
        .post(format!("{base}/v1/sys/mounts/keygate-test"))
        .header("x-vault-token", "keygate-isolated-test-only")
        .json(&json!({"type":"kv","options":{"version":"2"}}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("token");
    tokio::fs::write(&file, "keygate-isolated-test-only")
        .await
        .unwrap();
    let store: Arc<dyn Store> =
        Arc::new(OpenBaoStore::new(&base, "keygate-test", "test", file).unwrap());
    cas_contract(store.clone()).await;
    let manager = manager_router(
        Manager::new(store.clone(), SECRET.into(), "http://localhost:8080".into()).unwrap(),
    );
    let (app, key, token) = create(&manager).await;
    let node_a = authz_router(Authorizer::new(
        store.clone(),
        Duration::from_millis(100),
        16,
    ));
    let node_b = authz_router(Authorizer::new(
        store.clone(),
        Duration::from_millis(100),
        16,
    ));
    assert_eq!(check(&node_a, app, &token).await, StatusCode::OK);
    assert_eq!(check(&node_b, app, &token).await, StatusCode::OK);
    let persisted = client
        .get(format!("{base}/v1/keygate-test/data/test/apps/{app}"))
        .header("x-vault-token", "keygate-isolated-test-only")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!persisted.contains(&token));
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
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(check(&node_a, app, &token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(check(&node_b, app, &token).await, StatusCode::UNAUTHORIZED);
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
    let authz = authz_router(Authorizer::new(store, Duration::ZERO, 16));
    let auth_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_port = auth_listener.local_addr().unwrap().port();
    let auth_task = tokio::spawn(async move { axum::serve(auth_listener, authz).await.unwrap() });
    let upstream = Router::new().fallback(|| async {
        (
            [("content-type", "text/event-stream")],
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
    let config = json!({"static_resources":{"listeners":[{"name":"ingress","address":{"socket_address":{"address":"127.0.0.1","port_value":port}},"filter_chains":[{"filters":[{"name":"envoy.filters.network.http_connection_manager","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager","stat_prefix":"test","route_config":{"name":"route","virtual_hosts":[{"name":"all","domains":["*"],"routes":[{"match":{"prefix":"/"},"route":{"cluster":"upstream","timeout":"0s"}}]}]},"http_filters":[{"name":"envoy.filters.http.ext_authz","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz","failure_mode_allow":false,"http_service":{"server_uri":{"uri":"http://authz","cluster":"authz","timeout":"6s"},"path_prefix":format!("/check/{app}"),"authorization_request":{"allowed_headers":{"patterns":[{"exact":"authorization"}]}}}}},{"name":"envoy.filters.http.router","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]}}]}]}],"clusters":[cluster("authz",auth_port),cluster("upstream",up_port)]}});
    let temp = tempfile::tempdir().unwrap();
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
        .json(&json!({"stream":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
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
