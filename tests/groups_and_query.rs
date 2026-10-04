mod common;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use keygate::{
    Authorizer, Manager, authz_router,
    config::Config,
    manager_router,
    scim::{self, Scim},
    store::{PostgresStore, Store},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;
const SECRET: &str = "test-proxy-secret-at-least-32-bytes-long";
async fn call(
    router: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let response = router
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn directory(store: &dyn Store) {
    let user = Uuid::from_u128(10).to_string();
    store
        .directory_put(
            "Users",
            &user,
            &json!({"id":user,"externalId":"alice","active":true}),
        )
        .await
        .unwrap();
    let group = Uuid::from_u128(11).to_string();
    store.directory_put("Groups",&group,&json!({"id":group,"externalId":"app-group","displayName":"test-group","members":[{"value":user}]})).await.unwrap();
}
#[tokio::test]
async fn oidc_app_groups_and_synced_membership_control_issuance_and_existing_keys() {
    let store = Arc::new(common::Memory::default());
    directory(store.as_ref()).await;
    let config=Arc::new(Config::parse(&json!({"applications":[{"id":common::APP_ID,"name":"First","group":"test-group"},{"id":Uuid::from_u128(2),"name":"Second","group":"other-group"}]}).to_string()).unwrap());
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
    let headers = [
        ("x-keygate-proxy-secret", SECRET),
        ("x-keygate-subject", "alice"),
        ("x-keygate-groups", "[\"test-group\"]"),
        ("origin", "http://localhost:8080"),
        ("x-keygate-csrf", "1"),
    ];
    let (status, apps) = call(&manager, "GET", "/api/apps", &headers, Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(apps.as_array().unwrap().len(), 1);
    let (status, _) = call(
        &manager,
        "POST",
        &format!("/api/apps/{}/keys", Uuid::from_u128(2)),
        &headers,
        json!({"name":"denied"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let endpoint = format!("/api/apps/{}/keys", common::APP_ID);
    let (status, key) = call(
        &manager,
        "POST",
        &endpoint,
        &headers,
        json!({"name":"allowed"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let token = key["key"].as_str().unwrap();
    let path = format!("/check/{}/config?api_key={token}", common::APP_ID);
    assert_eq!(
        call(&auth, "GET", &path, &[], Value::Null).await.0,
        StatusCode::OK
    );
    // Group removal must override an already populated application/key cache.
    store.directory_put("Groups",&Uuid::from_u128(11).to_string(),&json!({"id":Uuid::from_u128(11),"externalId":"app-group","displayName":"test-group","members":[]})).await.unwrap();
    assert_eq!(
        call(&auth, "GET", &path, &[], Value::Null).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &manager,
            "POST",
            &endpoint,
            &headers,
            json!({"name":"stale-token"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // Owners can still revoke a key after losing their group.
    assert_eq!(
        call(
            &manager,
            "DELETE",
            &format!("{endpoint}/{}", key["id"].as_str().unwrap()),
            &headers,
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
}
#[tokio::test]
async fn query_auth_is_unambiguous_and_has_the_same_app_and_revocation_checks() {
    let store = Arc::new(common::Memory::default());
    let (key, token) = keygate::model::issue("alice".into(), "probe".into());
    let app = keygate::model::Application {
        id: common::APP_ID,
        name: "test".into(),
        keys: vec![key.clone()],
    };
    store.put(&app, 0).await.unwrap();
    let auth = authz_router(Authorizer::new(
        store.clone(),
        common::config(),
        Duration::ZERO,
        16,
    ));
    let base = format!("/check/{}", common::APP_ID);
    let bearer = format!("Bearer {token}");
    for uri in [
        format!("{base}?api_key={token}"),
        format!("{base}/?apikey={token}"),
        format!("{base}/nested/path?foo=bar&api_key={token}"),
        format!("{base}?api%5Fkey={token}"),
    ] {
        assert_eq!(
            call(&auth, "GET", &uri, &[], Value::Null).await.0,
            StatusCode::OK
        );
    }
    assert_eq!(
        call(
            &auth,
            "GET",
            &format!("{base}?api_key={token}"),
            &[("authorization", &bearer)],
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    for (uri, header) in [
        (format!("{base}?api_key={token}&api_key={token}"), None),
        (format!("{base}?api_key={token}&apikey={token}"), None),
        (format!("{base}?api_key="), None),
        (format!("{base}?api_key=%ZZ"), None),
        (format!("{base}?api_key={token}"), Some("Bearer wrong")),
        (format!("{base}?api_key={token}"), Some("Basic invalid")),
        (base.clone(), None),
    ] {
        let headers = header
            .map(|h| vec![("authorization", h)])
            .unwrap_or_default();
        assert_eq!(
            call(&auth, "GET", &uri, &headers, Value::Null).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let wrong = format!("/check/{}?api_key={token}", Uuid::from_u128(2));
    assert_eq!(
        call(&auth, "GET", &wrong, &[], Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
    let mut app = app;
    app.keys[0].revoked = true;
    store.put(&app, 1).await.unwrap();
    assert_eq!(
        call(
            &auth,
            "GET",
            &format!("{base}?api_key={token}"),
            &[],
            Value::Null
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn scim_requires_its_own_token_and_controls_user_and_group_lifecycle() {
    let store = Arc::new(common::Memory::default());
    assert!(Scim::new(store.clone(), "short".into()).is_err());
    let router = scim::router(Scim::new(store.clone(), SECRET.into()).unwrap());
    let bearer = format!("Bearer {SECRET}");
    let headers = [("authorization", bearer.as_str())];
    assert_eq!(
        call(&router, "GET", "/Users", &[], Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&router, "GET", "/Unknown", &headers, Value::Null)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    for (path, data) in [
        ("/Users", json!({"externalId":"alice"})),
        (
            "/Groups",
            json!({"externalId":"g","displayName":"test-group","members":[{"value":"invalid"}]}),
        ),
        ("/Groups", json!({"externalId":"","members":[]})),
        (
            "/Groups",
            json!({"externalId":"g","displayName":"","members":[]}),
        ),
    ] {
        assert_eq!(
            call(&router, "POST", path, &headers, data).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let (status, user) = call(
        &router,
        "POST",
        "/Users",
        &headers,
        json!({"externalId":"alice","active":true}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let user_id = user["id"].as_str().unwrap();
    assert_eq!(
        call(
            &router,
            "POST",
            "/Users",
            &headers,
            json!({"externalId":"alice","active":true})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (status, group) = call(
        &router,
        "POST",
        "/Groups",
        &headers,
        json!({"externalId":"g","displayName":"test-group","members":[{"value":user_id}]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(store.allowed("alice", "test-group").await.unwrap());
    let users = call(
        &router,
        "GET",
        "/Users?count=1000&startIndex=1",
        &headers,
        Value::Null,
    )
    .await
    .1;
    assert_eq!(users["totalResults"], 1);
    assert_eq!(
        call(
            &router,
            "GET",
            &format!("/Users/{user_id}"),
            &headers,
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &router,
            "PUT",
            &format!("/Users/{user_id}"),
            &headers,
            json!({"externalId":"alice","active":false})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(!store.allowed("alice", "test-group").await.unwrap());
    assert_eq!(
        call(
            &router,
            "DELETE",
            &format!("/Groups/{}", group["id"].as_str().unwrap()),
            &headers,
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(
            &router,
            "GET",
            &format!("/Groups/{}", group["id"].as_str().unwrap()),
            &headers,
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &router,
            "DELETE",
            &format!("/Users/{user_id}"),
            &headers,
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
}
#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn postgres_directory_survives_restart_and_revokes_existing_key_access() {
    let db = common::Database::start();
    let store = PostgresStore::open(&db.url).await.unwrap();
    store.initialize().await.unwrap();
    directory(&store).await;
    assert!(store.allowed("alice", "test-group").await.unwrap());
    assert!(!store.allowed("bob", "test-group").await.unwrap());
    assert_eq!(store.directory_list("Users").await.unwrap().len(), 1);
    let reopened = PostgresStore::open(&db.url).await.unwrap();
    assert!(reopened.allowed("alice", "test-group").await.unwrap());
    reopened
        .directory_delete("Users", &Uuid::from_u128(10).to_string())
        .await
        .unwrap();
    assert!(!reopened.allowed("alice", "test-group").await.unwrap());
    reopened
        .directory_delete("Groups", &Uuid::from_u128(11).to_string())
        .await
        .unwrap();
}

#[tokio::test]
async fn custom_stores_without_directory_support_fail_closed() {
    struct Unsupported;
    #[async_trait::async_trait]
    impl Store for Unsupported {
        async fn get(
            &self,
            _: Uuid,
        ) -> Result<Option<keygate::model::Versioned>, keygate::store::StoreError> {
            unreachable!()
        }
        async fn list(&self) -> Result<Vec<keygate::model::Versioned>, keygate::store::StoreError> {
            unreachable!()
        }
        async fn put(
            &self,
            _: &keygate::model::Application,
            _: u64,
        ) -> Result<(), keygate::store::StoreError> {
            unreachable!()
        }
    }
    let store = Unsupported;
    assert!(store.allowed("alice", "test-group").await.is_err());
    assert!(store.directory_list("Users").await.is_err());
    assert!(
        store
            .directory_put("Users", "id", &json!({}))
            .await
            .is_err()
    );
    assert!(store.directory_delete("Users", "id").await.is_err());
}
