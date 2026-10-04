#![allow(dead_code)]
use keygate::{
    config::Config,
    model::{Application, Versioned},
    store::{Store, StoreError},
};
use std::{
    collections::BTreeMap,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;
pub const APP_ID: Uuid = Uuid::from_u128(1);
pub fn config() -> Arc<Config> {
    config_for(&[(APP_ID, "Codex")])
}
pub fn config_for(applications: &[(Uuid, &str)]) -> Arc<Config> {
    let applications: Vec<_> = applications
        .iter()
        .map(|(id, name)| serde_json::json!({"id": id, "name": name, "group": "test-group"}))
        .collect();
    Arc::new(Config::parse(&serde_json::json!({"applications": applications}).to_string()).unwrap())
}
#[derive(Default)]
pub struct Memory(
    Mutex<BTreeMap<Uuid, Versioned>>,
    Mutex<BTreeMap<(String, String), serde_json::Value>>,
);
#[async_trait::async_trait]
impl Store for Memory {
    async fn allowed(&self, owner: &str, group: &str) -> Result<bool, StoreError> {
        let resources = self.1.lock().unwrap();
        if resources.is_empty() {
            return Ok(group == "test-group");
        }
        Ok(resources.iter().any(|((kind, id), user)| {
            kind == "Users"
                && user["externalId"] == owner
                && user["active"] == true
                && resources.iter().any(|((kind, _), g)| {
                    kind == "Groups"
                        && g["displayName"] == group
                        && g["members"]
                            .as_array()
                            .is_some_and(|m| m.iter().any(|v| v["value"] == *id))
                })
        }))
    }
    async fn directory_list(&self, kind: &str) -> Result<Vec<serde_json::Value>, StoreError> {
        Ok(self
            .1
            .lock()
            .unwrap()
            .iter()
            .filter(|((k, _), _)| k == kind)
            .map(|(_, v)| v.clone())
            .collect())
    }
    async fn directory_put(
        &self,
        kind: &str,
        id: &str,
        document: &serde_json::Value,
    ) -> Result<(), StoreError> {
        self.1
            .lock()
            .unwrap()
            .insert((kind.into(), id.into()), document.clone());
        Ok(())
    }
    async fn directory_delete(&self, kind: &str, id: &str) -> Result<(), StoreError> {
        self.1.lock().unwrap().remove(&(kind.into(), id.into()));
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Versioned>, StoreError> {
        Ok(self.0.lock().unwrap().get(&id).cloned())
    }
    async fn list(&self) -> Result<Vec<Versioned>, StoreError> {
        Ok(self.0.lock().unwrap().values().cloned().collect())
    }
    async fn put(&self, app: &Application, expected: u64) -> Result<(), StoreError> {
        let mut entries = self.0.lock().unwrap();
        if entries.get(&app.id).map_or(0, |v| v.version) != expected {
            return Err(StoreError::Conflict);
        }
        entries.insert(
            app.id,
            Versioned {
                app: app.clone(),
                version: expected + 1,
            },
        );
        Ok(())
    }
}
pub struct Database {
    name: String,
    pub url: String,
}
impl Database {
    pub fn start() -> Self {
        let name = format!("keygate-pg-test-{}", Uuid::new_v4());
        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &name,
                "-e",
                "POSTGRES_PASSWORD=isolated-test-only",
                "-p",
                "127.0.0.1::5432",
                "postgres:17-alpine",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Docker PostgreSQL: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut db = Self {
            name,
            url: String::new(),
        };
        let output = Command::new("docker")
            .args(["port", &db.name, "5432/tcp"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let address = String::from_utf8(output.stdout).unwrap();
        db.url = format!(
            "postgres://postgres:isolated-test-only@{}/postgres?sslmode=disable",
            address.trim()
        );
        for _ in 0..100 {
            let result = Command::new("docker")
                .args([
                    "exec",
                    &db.name,
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    "postgres",
                ])
                .output()
                .unwrap();
            if result.status.success() {
                return db;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("isolated PostgreSQL did not start");
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

pub async fn seed_directory(store: &dyn Store, group: &str, owners: &[&str]) {
    let mut members = Vec::new();
    for (index, owner) in owners.iter().enumerate() {
        let id = Uuid::from_u128(100 + index as u128).to_string();
        store
            .directory_put(
                "Users",
                &id,
                &serde_json::json!({"id":id,"externalId":owner,"active":true}),
            )
            .await
            .unwrap();
        members.push(serde_json::json!({"value":id}));
    }
    let id = Uuid::from_u128(99).to_string();
    store.directory_put("Groups", &id, &serde_json::json!({"id":id,"externalId":"test-group-id","displayName":group,"members":members})).await.unwrap();
}
