//! Backends implement atomic compare-and-swap; services use only Store.
use crate::model::{Application, Versioned};
use async_trait::async_trait;
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{path::PathBuf, str::FromStr, time::Duration};
use uuid::Uuid;
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("concurrent update; reload and retry")]
    Conflict,
    #[error("storage unavailable")]
    Unavailable,
}
#[async_trait]
pub trait Store: Send + Sync {
    async fn get(&self, id: Uuid) -> Result<Option<Versioned>, StoreError>;
    async fn list(&self) -> Result<Vec<Versioned>, StoreError>;
    /// expected == 0 means create only. Updates must match the current version.
    async fn put(&self, app: &Application, expected: u64) -> Result<(), StoreError>;
}
pub struct SqliteStore {
    pool: SqlitePool,
}
impl SqliteStore {
    pub async fn open(url: &str) -> anyhow::Result<Self> {
        let options = SqliteConnectOptions::from_str(url)?
            .create_if_missing(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS applications (id TEXT PRIMARY KEY, version INTEGER NOT NULL, document TEXT NOT NULL)").execute(&pool).await?;
        Ok(Self { pool })
    }
}
fn decode(row: sqlx::sqlite::SqliteRow) -> Result<Versioned, StoreError> {
    Ok(Versioned {
        version: row
            .try_get::<i64, _>("version")
            .map_err(|_| StoreError::Unavailable)? as u64,
        app: serde_json::from_str(
            &row.try_get::<String, _>("document")
                .map_err(|_| StoreError::Unavailable)?,
        )
        .map_err(|_| StoreError::Unavailable)?,
    })
}
#[async_trait]
impl Store for SqliteStore {
    async fn get(&self, id: Uuid) -> Result<Option<Versioned>, StoreError> {
        sqlx::query("SELECT version, document FROM applications WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| StoreError::Unavailable)?
            .map(decode)
            .transpose()
    }
    async fn list(&self) -> Result<Vec<Versioned>, StoreError> {
        sqlx::query("SELECT version, document FROM applications ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .map_err(|_| StoreError::Unavailable)?
            .into_iter()
            .map(decode)
            .collect()
    }
    async fn put(&self, app: &Application, expected: u64) -> Result<(), StoreError> {
        let document = serde_json::to_string(app).map_err(|_| StoreError::Unavailable)?;
        let result = if expected == 0 {
            sqlx::query("INSERT OR IGNORE INTO applications (id, version, document) VALUES (?, 1, ?)").bind(app.id.to_string()).bind(document).execute(&self.pool).await
        } else {
            sqlx::query("UPDATE applications SET version = version + 1, document = ? WHERE id = ? AND version = ?").bind(document).bind(app.id.to_string()).bind(expected as i64).execute(&self.pool).await
        }.map_err(|_| StoreError::Unavailable)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
}
/// Agent-managed token file is reread for every request, supporting renewal/relogin.
pub struct OpenBaoStore {
    client: reqwest::Client,
    base: String,
    mount: String,
    prefix: String,
    token_file: PathBuf,
}
impl OpenBaoStore {
    pub fn new(base: &str, mount: &str, prefix: &str, token_file: PathBuf) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(base)?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid OpenBao URL"
        );
        for value in [mount, prefix] {
            anyhow::ensure!(
                !value.is_empty()
                    && value.split('/').all(|s| !s.is_empty()
                        && s != "."
                        && s != ".."
                        && s.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))),
                "invalid KV mount or prefix"
            );
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            base: base.trim_end_matches('/').into(),
            mount: mount.into(),
            prefix: prefix.into(),
            token_file,
        })
    }
    async fn request(
        &self,
        method: reqwest::Method,
        kind: &str,
        suffix: &str,
    ) -> Result<reqwest::RequestBuilder, StoreError> {
        let token = tokio::fs::read_to_string(&self.token_file)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        if token.trim().is_empty() {
            return Err(StoreError::Unavailable);
        }
        Ok(self
            .client
            .request(
                method,
                format!(
                    "{}/v1/{}/{}/{}/apps{}",
                    self.base, self.mount, kind, self.prefix, suffix
                ),
            )
            .header("X-Vault-Token", token.trim()))
    }
}
#[async_trait]
impl Store for OpenBaoStore {
    async fn get(&self, id: Uuid) -> Result<Option<Versioned>, StoreError> {
        let r = self
            .request(reqwest::Method::GET, "data", &format!("/{id}"))
            .await?
            .send()
            .await
            .map_err(|_| StoreError::Unavailable)?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !r.status().is_success() {
            return Err(StoreError::Unavailable);
        }
        let v: serde_json::Value = r.json().await.map_err(|_| StoreError::Unavailable)?;
        let app: Application = serde_json::from_value(v["data"]["data"].clone())
            .map_err(|_| StoreError::Unavailable)?;
        if app.id != id {
            return Err(StoreError::Unavailable);
        }
        Ok(Some(Versioned {
            app,
            version: v["data"]["metadata"]["version"]
                .as_u64()
                .filter(|v| *v > 0)
                .ok_or(StoreError::Unavailable)?,
        }))
    }
    async fn list(&self) -> Result<Vec<Versioned>, StoreError> {
        let r = self
            .request(reqwest::Method::GET, "metadata", "")
            .await?
            .query(&[("list", "true")])
            .send()
            .await
            .map_err(|_| StoreError::Unavailable)?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(vec![]);
        }
        if !r.status().is_success() {
            return Err(StoreError::Unavailable);
        }
        let v: serde_json::Value = r.json().await.map_err(|_| StoreError::Unavailable)?;
        let ids = v["data"]["keys"]
            .as_array()
            .ok_or(StoreError::Unavailable)?;
        let mut result = Vec::new();
        for id in ids {
            let id = Uuid::parse_str(id.as_str().ok_or(StoreError::Unavailable)?)
                .map_err(|_| StoreError::Unavailable)?;
            if let Some(app) = self.get(id).await? {
                result.push(app);
            }
        }
        Ok(result)
    }
    async fn put(&self, app: &Application, expected: u64) -> Result<(), StoreError> {
        let r = self
            .request(reqwest::Method::POST, "data", &format!("/{}", app.id))
            .await?
            .json(&serde_json::json!({"options": {"cas": expected}, "data": app}))
            .send()
            .await
            .map_err(|_| StoreError::Unavailable)?;
        match r.status() {
            s if s.is_success() => Ok(()),
            reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::CONFLICT => {
                Err(StoreError::Conflict)
            }
            _ => Err(StoreError::Unavailable),
        }
    }
}
