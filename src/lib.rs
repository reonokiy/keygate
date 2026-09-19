mod http;
pub mod identity;
pub mod model;
pub mod store;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{any, delete, get, post},
};
use model::{Application, Versioned};
use moka::future::Cache;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::{Store, StoreError};
use tokio::sync::Semaphore;
use uuid::Uuid;

#[derive(Clone)]
pub struct Manager {
    store: Arc<dyn Store>,
    proxy_secret: Arc<str>,
    origin: Arc<str>,
    oidc: Option<Arc<identity::Oidc>>,
}
impl Manager {
    pub fn with_oidc(mut self, oidc: identity::Oidc) -> Self {
        self.oidc = Some(Arc::new(oidc));
        self
    }
    pub fn new(
        store: Arc<dyn Store>,
        proxy_secret: String,
        origin: String,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            proxy_secret.len() >= 32,
            "proxy secret must contain at least 32 bytes"
        );
        let url = reqwest::Url::parse(&origin)?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https")
                && url.origin().ascii_serialization() == origin,
            "public origin must be an exact HTTP(S) origin without trailing slash"
        );
        Ok(Self {
            store,
            proxy_secret: proxy_secret.into(),
            origin: origin.into(),
            oidc: None,
        })
    }
}
#[derive(Clone)]
struct Identity(String);
#[derive(Debug)]
struct Error(StatusCode, &'static str);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
impl From<StoreError> for Error {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Conflict => {
                Self(StatusCode::CONFLICT, "concurrent update; reload and retry")
            }
            StoreError::Unavailable => Self(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
        }
    }
}
fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    if h.get_all(name).iter().count() != 1 {
        return None;
    }
    h.get(name)?.to_str().ok()
}
async fn secure_response(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("content-security-policy", HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"));
    response
}
async fn manager_auth(State(s): State<Manager>, mut req: Request, next: Next) -> Response {
    let h = req.headers();
    let trusted =
        header(h, "x-keygate-proxy-secret").is_some_and(|v| model::constant_eq(v, &s.proxy_secret));
    if !trusted {
        return Error(StatusCode::UNAUTHORIZED, "trusted login required").into_response();
    }
    let subject = if let Some(oidc) = &s.oidc {
        match header(h, "x-keygate-id-token") {
            Some(token) => match oidc.subject(token).await {
                Ok(sub) => sub,
                Err(identity::IdentityError::Invalid) => {
                    return Error(StatusCode::UNAUTHORIZED, "invalid login token").into_response();
                }
                Err(identity::IdentityError::Unavailable) => {
                    return Error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "identity provider unavailable",
                    )
                    .into_response();
                }
            },
            None => return Error(StatusCode::UNAUTHORIZED, "login token required").into_response(),
        }
    } else {
        match header(h, "x-keygate-subject").filter(|v| !v.is_empty() && v.len() <= 512) {
            Some(sub) => sub.to_owned(),
            None => {
                return Error(StatusCode::UNAUTHORIZED, "trusted login required").into_response();
            }
        }
    };
    if !matches!(*req.method(), Method::GET | Method::HEAD)
        && (header(h, "origin") != Some(&s.origin) || header(h, "x-keygate-csrf") != Some("1"))
    {
        return Error(StatusCode::FORBIDDEN, "invalid request origin").into_response();
    }
    let identity = Identity(subject);
    req.extensions_mut().insert(identity);
    next.run(req).await
}
pub fn manager_router(s: Manager) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../web/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../web/style.css"),
                )
            }),
        )
        .route(
            "/api/me",
            get(
                |axum::Extension(id): axum::Extension<Identity>| async move {
                    Json(json!({"subject":id.0,"user_id":model::user_id(&id.0)}))
                },
            ),
        )
        .route("/api/apps", get(list_apps).post(create_app))
        .route("/api/apps/{app}/keys", post(create_key))
        .route("/api/apps/{app}/keys/{key}", delete(revoke_key))
        .layer(middleware::from_fn_with_state(s.clone(), manager_auth))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn(secure_response))
        .with_state(s)
}
fn public_app(app: &Application, owner: &str) -> Value {
    json!({"id":app.id,"name":app.name,"keys":app.keys.iter().filter(|k| k.owner == owner).map(|k| json!({"id":k.id,"name":k.name,"created_at":k.created_at,"revoked":k.revoked})).collect::<Vec<_>>()})
}
#[derive(Deserialize)]
struct Named {
    name: String,
}
fn name(value: String) -> Result<String, Error> {
    let v = value.trim();
    if v.is_empty() || v.len() > 128 || v.chars().any(char::is_control) {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "name must contain 1–128 bytes without control characters",
        ));
    }
    Ok(v.into())
}
async fn list_apps(
    State(s): State<Manager>,
    axum::Extension(id): axum::Extension<Identity>,
) -> Result<Json<Value>, Error> {
    let apps = s.store.list().await?;
    Ok(Json(json!(
        apps.iter()
            .map(|a| public_app(&a.app, &id.0))
            .collect::<Vec<_>>()
    )))
}
async fn create_app(
    State(s): State<Manager>,
    axum::Extension(id): axum::Extension<Identity>,
    Json(body): Json<Named>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let app = Application {
        id: Uuid::new_v4(),
        name: name(body.name)?,
        keys: vec![],
    };
    s.store.put(&app, 0).await?;
    Ok((StatusCode::CREATED, Json(public_app(&app, &id.0))))
}
async fn application(s: &Manager, app: Uuid) -> Result<Versioned, Error> {
    s.store
        .get(app)
        .await?
        .filter(|a| a.app.id == app)
        .ok_or(Error(StatusCode::NOT_FOUND, "application not found"))
}
async fn create_key(
    State(s): State<Manager>,
    axum::Extension(id): axum::Extension<Identity>,
    Path(app): Path<Uuid>,
    Json(body): Json<Named>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let mut entry = application(&s, app).await?;
    if entry.app.keys.iter().filter(|k| k.owner == id.0).count() >= 1000 {
        return Err(Error(StatusCode::CONFLICT, "user key limit reached"));
    }
    let (key, token) = model::issue(id.0, name(body.name)?);
    let key_id = key.id;
    entry.app.keys.push(key);
    s.store.put(&entry.app, entry.version).await?;
    Ok((StatusCode::CREATED, Json(json!({"id":key_id,"key":token}))))
}
async fn revoke_key(
    State(s): State<Manager>,
    axum::Extension(id): axum::Extension<Identity>,
    Path((app, key)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, Error> {
    let mut entry = application(&s, app).await?;
    let key = entry
        .app
        .keys
        .iter_mut()
        .find(|k| k.id == key && k.owner == id.0)
        .ok_or(Error(StatusCode::NOT_FOUND, "key not found"))?;
    if !key.revoked {
        key.revoked = true;
        s.store.put(&entry.app, entry.version).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Clone)]
struct Cached {
    app: Arc<Application>,
    fetched_at: Instant,
}
#[derive(Clone)]
pub struct Authorizer {
    store: Arc<dyn Store>,
    cache: Cache<Uuid, Cached>,
    ttl: Duration,
    inflight: Arc<Semaphore>,
}
impl Authorizer {
    pub fn new(store: Arc<dyn Store>, ttl: Duration, capacity: u64) -> Self {
        Self {
            store,
            cache: Cache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl.max(Duration::from_millis(1)))
                .build(),
            ttl,
            inflight: Arc::new(Semaphore::new(32)),
        }
    }
    async fn app(&self, id: Uuid) -> Result<Option<Arc<Application>>, Error> {
        if let Some(c) = self.cache.get(&id).await
            && c.fetched_at.elapsed() < self.ttl
        {
            return Ok(Some(c.app));
        }
        let _permit = tokio::time::timeout(Duration::from_millis(250), self.inflight.acquire())
            .await
            .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "authenticator busy"))?
            .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "authenticator unavailable"))?;
        // Recheck after acquiring a permit; cache age is measured before fetching, never sliding.
        if let Some(c) = self.cache.get(&id).await
            && c.fetched_at.elapsed() < self.ttl
        {
            return Ok(Some(c.app));
        }
        let fetched_at = Instant::now();
        let item = tokio::time::timeout(Duration::from_secs(5), self.store.get(id))
            .await
            .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "storage timeout"))??;
        let Some(item) = item else {
            return Ok(None);
        };
        if item.app.id != id || item.version == 0 {
            return Err(Error(
                StatusCode::SERVICE_UNAVAILABLE,
                "invalid storage record",
            ));
        }
        let app = Arc::new(item.app);
        if !self.ttl.is_zero() {
            self.cache
                .insert(
                    id,
                    Cached {
                        app: app.clone(),
                        fetched_at,
                    },
                )
                .await;
        }
        Ok(Some(app))
    }
}
pub fn authz_router(s: Authorizer) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/check/{app}", any(check))
        .route("/check/{app}/", any(check))
        .route("/check/{app}/{*rest}", any(check_nested))
        .layer(DefaultBodyLimit::max(0))
        .layer(middleware::from_fn(secure_response))
        .with_state(s)
}
async fn check_nested(
    State(s): State<Authorizer>,
    Path((app, _)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    authorize(s, app, headers).await
}
async fn check(
    State(s): State<Authorizer>,
    Path(app): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    authorize(s, app, headers).await
}
async fn authorize(s: Authorizer, expected: Uuid, headers: HeaderMap) -> Result<Response, Error> {
    let token = header(&headers, "authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Error(StatusCode::UNAUTHORIZED, "API key required"))?;
    if !model::valid_token(token) {
        return Err(Error(StatusCode::UNAUTHORIZED, "invalid API key"));
    }
    let app = s
        .app(expected)
        .await?
        .ok_or(Error(StatusCode::UNAUTHORIZED, "invalid API key"))?;
    let authenticated = model::authenticate(&app, token)
        .ok_or(Error(StatusCode::UNAUTHORIZED, "invalid API key"))?;
    Ok((
        StatusCode::OK,
        [
            ("x-auth-request-user", model::user_id(&authenticated.owner)),
            ("x-keygate-user-id", model::user_id(&authenticated.owner)),
            ("x-keygate-app", app.id.to_string()),
            ("x-keygate-key-id", authenticated.id.to_string()),
        ],
    )
        .into_response())
}

#[cfg(test)]
#[path = "../tests/unit/cache.rs"]
mod cache_tests;
