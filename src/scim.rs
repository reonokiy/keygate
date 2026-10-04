//! Pocket ID provisioning, separate from human OIDC login and application keys.
use crate::{Error, header, model, store::Store};
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct Scim {
    store: Arc<dyn Store>,
    token: Arc<str>,
}
impl Scim {
    pub fn new(store: Arc<dyn Store>, token: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            token.len() >= 32,
            "SCIM token must contain at least 32 bytes"
        );
        Ok(Self {
            store,
            token: token.into(),
        })
    }
}
async fn auth(State(s): State<Scim>, req: Request, next: Next) -> Response {
    if !header(req.headers(), "authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|v| model::constant_eq(v, &s.token))
    {
        return Error(StatusCode::UNAUTHORIZED, "SCIM authentication required").into_response();
    }
    next.run(req).await
}
pub fn router(s: Scim) -> Router {
    Router::new()
        .route("/{kind}", get(list).post(create))
        .route("/{kind}/{id}", get(read).put(replace).delete(remove))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(s.clone(), auth))
        .layer(middleware::from_fn(crate::secure_response))
        .with_state(s)
}
fn kind(kind: &str) -> Result<(), Error> {
    if matches!(kind, "Users" | "Groups") {
        Ok(())
    } else {
        Err(Error(StatusCode::NOT_FOUND, "resource not found"))
    }
}
async fn list(State(s): State<Scim>, Path(k): Path<String>) -> Result<Json<Value>, Error> {
    kind(&k)?;
    let resources = s.store.directory_list(&k).await?;
    Ok(Json(
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":resources.len(),"startIndex":1,"itemsPerPage":resources.len(),"Resources":resources}),
    ))
}
async fn read(
    State(s): State<Scim>,
    Path((k, id)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    kind(&k)?;
    let document = s
        .store
        .directory_list(&k)
        .await?
        .into_iter()
        .find(|d| d["id"] == id)
        .ok_or(Error(StatusCode::NOT_FOUND, "resource not found"))?;
    Ok(Json(document))
}
fn validate(k: &str, id: &str, mut document: Value) -> Result<Value, Error> {
    kind(k)?;
    let external = document["externalId"]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 512);
    let valid = external.is_some()
        && document.is_object()
        && if k == "Users" {
            document["active"].as_bool().is_some()
        } else {
            document["displayName"]
                .as_str()
                .is_some_and(|v| !v.is_empty() && v.len() <= 128)
                && document["members"].as_array().is_some_and(|members| {
                    members.iter().all(|m| {
                        m["value"]
                            .as_str()
                            .is_some_and(|v| Uuid::parse_str(v).is_ok())
                    })
                })
        };
    if !valid {
        return Err(Error(StatusCode::BAD_REQUEST, "invalid SCIM resource"));
    }
    document["id"] = json!(id);
    document["meta"] = json!({
        "resourceType": if k == "Users" { "User" } else { "Group" },
        "lastModified": time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)
            .expect("UTC timestamp is RFC3339"),
    });
    Ok(document)
}
async fn create(
    State(s): State<Scim>,
    Path(k): Path<String>,
    Json(document): Json<Value>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let id = Uuid::new_v4().to_string();
    let document = validate(&k, &id, document)?;
    if s.store
        .directory_list(&k)
        .await?
        .iter()
        .any(|existing| existing["externalId"] == document["externalId"])
    {
        return Err(Error(StatusCode::CONFLICT, "resource already exists"));
    }
    s.store.directory_put(&k, &id, &document).await?;
    Ok((StatusCode::CREATED, Json(document)))
}
async fn replace(
    State(s): State<Scim>,
    Path((k, id)): Path<(String, Uuid)>,
    Json(document): Json<Value>,
) -> Result<Json<Value>, Error> {
    let document = validate(&k, &id.to_string(), document)?;
    s.store
        .directory_put(&k, &id.to_string(), &document)
        .await?;
    Ok(Json(document))
}
async fn remove(
    State(s): State<Scim>,
    Path((k, id)): Path<(String, Uuid)>,
) -> Result<StatusCode, Error> {
    kind(&k)?;
    s.store.directory_delete(&k, &id.to_string()).await?;
    Ok(StatusCode::NO_CONTENT)
}
