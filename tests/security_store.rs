mod common;
use keygate::{
    model::{Application, issue},
    store::{PostgresStore, Store, StoreError},
};
use uuid::Uuid;
fn app() -> Application {
    Application {
        id: Uuid::new_v4(),
        name: "shared".into(),
        keys: vec![],
    }
}
#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn postgres_cas_persistence_concurrency_and_read_only_authorizer() {
    let db = common::Database::start();
    let store = PostgresStore::open(&db.url).await.unwrap();
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
    assert!(store.list().await.unwrap().is_empty());
    let mut app = app();
    assert!(store.get(app.id).await.unwrap().is_none());
    let (key, token) = issue(
        "alice".into(),
        "'; DROP TABLE keygate_applications;--".into(),
    );
    app.keys.push(key);
    store.put(&app, 0).await.unwrap();
    assert!(matches!(
        store.put(&app, 0).await,
        Err(StoreError::Conflict)
    ));
    let old = store.get(app.id).await.unwrap().unwrap();
    let mut a = old.app.clone();
    a.keys.push(issue("bob".into(), "bob".into()).0);
    let mut b = old.app.clone();
    b.keys.push(issue("carol".into(), "carol".into()).0);
    let (left, right) = tokio::join!(store.put(&a, old.version), store.put(&b, old.version));
    assert_ne!(left.is_ok(), right.is_ok());
    assert!(matches!(
        left.err().or(right.err()).unwrap(),
        StoreError::Conflict
    ));
    let reopened = PostgresStore::open(&db.url).await.unwrap();
    let entry = reopened.get(app.id).await.unwrap().unwrap();
    assert_eq!(entry.app.keys.len(), 2);
    assert_eq!(entry.version, 2);
    assert_eq!(reopened.list().await.unwrap().len(), 1);
    let pool = sqlx::PgPool::connect(&db.url).await.unwrap();
    let document: String = sqlx::query_scalar("SELECT document::text FROM keygate_applications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!document.contains(&token));
    assert!(document.contains(&keygate::model::digest(&token)));
    sqlx::raw_sql("CREATE ROLE authz LOGIN PASSWORD 'read-only-test'; GRANT CONNECT ON DATABASE postgres TO authz; GRANT USAGE ON SCHEMA public TO authz; GRANT SELECT ON keygate_applications TO authz;").execute(&pool).await.unwrap();
    let readonly = PostgresStore::open(
        &db.url
            .replace("postgres:isolated-test-only@", "authz:read-only-test@"),
    )
    .await
    .unwrap();
    assert!(readonly.get(app.id).await.unwrap().is_some());
    assert!(readonly.initialize().await.is_err());
    assert!(matches!(
        readonly.put(&app, 2).await,
        Err(StoreError::Unavailable)
    ));
    let router = keygate::authz_router(keygate::Authorizer::new(
        std::sync::Arc::new(readonly),
        std::time::Duration::ZERO,
        16,
    ));
    use tower::ServiceExt;
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(format!("/check/{}", app.id))
                .header("authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.headers()["x-auth-request-user"],
        keygate::model::user_id("alice")
    );
}
#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn postgres_corruption_missing_schema_and_overflow_fail_closed() {
    let db = common::Database::start();
    assert!(PostgresStore::open("not a database URL").await.is_err());
    let store = PostgresStore::open(&db.url).await.unwrap();
    let app = app();
    assert!(store.get(app.id).await.is_err());
    assert!(store.list().await.is_err());
    assert!(store.put(&app, 0).await.is_err());
    store.initialize().await.unwrap();
    for expected in [i64::MAX as u64, u64::MAX] {
        assert!(matches!(
            store.put(&app, expected).await,
            Err(StoreError::Unavailable)
        ));
    }
    store.put(&app, 0).await.unwrap();
    let pool = sqlx::PgPool::connect(&db.url).await.unwrap();
    // Privileged corruption must never become an authenticated identity.
    sqlx::query(
        "ALTER TABLE keygate_applications DROP CONSTRAINT keygate_applications_version_check",
    )
    .execute(&pool)
    .await
    .unwrap();
    for version in [-1i64, 0] {
        sqlx::query("UPDATE keygate_applications SET version = $1")
            .bind(version)
            .execute(&pool)
            .await
            .unwrap();
        assert!(store.get(app.id).await.is_err());
        assert!(store.list().await.is_err());
    }
    sqlx::query("UPDATE keygate_applications SET version = 1, document = '{}'::jsonb")
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.get(app.id).await.is_err());
    assert!(store.list().await.is_err());
    let wrong = Application {
        id: Uuid::new_v4(),
        name: "wrong".into(),
        keys: vec![],
    };
    sqlx::query("UPDATE keygate_applications SET document = $1::jsonb")
        .bind(serde_json::to_string(&wrong).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.get(app.id).await.is_err());
    sqlx::query("DROP TABLE keygate_applications")
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.put(&wrong, 0).await.is_err());
}
