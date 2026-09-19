//! Backends implement atomic compare-and-swap; services use only Store.
use crate::model::{Application, Versioned};
use async_trait::async_trait;
use sqlx::{
    PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{str::FromStr, time::Duration};
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
pub struct PostgresStore {
    pool: PgPool,
}
impl PostgresStore {
    pub async fn open(url: &str) -> anyhow::Result<Self> {
        let options = PgConnectOptions::from_str(url)?;
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }
    /// Run with the manager's write role before starting replicas. Authz needs SELECT only.
    pub async fn initialize(&self) -> anyhow::Result<()> {
        sqlx::query("CREATE TABLE IF NOT EXISTS keygate_applications (id TEXT PRIMARY KEY, version BIGINT NOT NULL CHECK (version > 0), document JSONB NOT NULL)")
            .execute(&self.pool).await?;
        Ok(())
    }
}

fn decode(row: sqlx::postgres::PgRow) -> Result<Versioned, StoreError> {
    Ok(Versioned {
        version: u64::try_from(
            row.try_get::<i64, _>("version")
                .map_err(|_| StoreError::Unavailable)?,
        )
        .ok()
        .filter(|v| *v > 0)
        .ok_or(StoreError::Unavailable)?,
        app: serde_json::from_str(
            &row.try_get::<String, _>("document")
                .map_err(|_| StoreError::Unavailable)?,
        )
        .map_err(|_| StoreError::Unavailable)?,
    })
}
#[async_trait]
impl Store for PostgresStore {
    async fn get(&self, id: Uuid) -> Result<Option<Versioned>, StoreError> {
        sqlx::query(
            "SELECT version, document::text AS document FROM keygate_applications WHERE id = $1",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| StoreError::Unavailable)?
        .map(decode)
        .transpose()?
        .map(|entry| {
            if entry.app.id == id {
                Ok(entry)
            } else {
                Err(StoreError::Unavailable)
            }
        })
        .transpose()
    }
    async fn list(&self) -> Result<Vec<Versioned>, StoreError> {
        sqlx::query(
            "SELECT version, document::text AS document FROM keygate_applications ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| StoreError::Unavailable)?
        .into_iter()
        .map(decode)
        .collect()
    }
    async fn put(&self, app: &Application, expected: u64) -> Result<(), StoreError> {
        if expected >= i64::MAX as u64 {
            return Err(StoreError::Unavailable);
        }
        let document = serde_json::to_string(app).map_err(|_| StoreError::Unavailable)?;
        let result = if expected == 0 {
            sqlx::query("INSERT INTO keygate_applications (id, version, document) VALUES ($1, 1, $2::jsonb) ON CONFLICT (id) DO NOTHING").bind(app.id.to_string()).bind(document).execute(&self.pool).await
        } else {
            sqlx::query("UPDATE keygate_applications SET version = version + 1, document = $1::jsonb WHERE id = $2 AND version = $3").bind(document).bind(app.id.to_string()).bind(expected as i64).execute(&self.pool).await
        }.map_err(|_| StoreError::Unavailable)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }
}
