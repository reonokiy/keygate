//! The administrator's application catalog, loaded once at startup.
use serde::Deserialize;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredApplication {
    pub id: Uuid,
    pub name: String,
    pub group: String,
}

pub struct Config {
    applications: Vec<ConfiguredApplication>,
    ids: HashSet<Uuid>,
}

impl Config {
    pub fn parse(document: &str) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Document {
            applications: Vec<ConfiguredApplication>,
        }
        let mut document: Document = serde_json::from_str(document)
            .map_err(|_| anyhow::anyhow!("invalid application configuration"))?;
        let mut ids = HashSet::new();
        for app in &mut document.applications {
            anyhow::ensure!(
                !app.id.is_nil() && ids.insert(app.id),
                "application configuration requires unique, non-nil UUIDs"
            );
            app.group = app.group.trim().to_owned();
            anyhow::ensure!(
                !app.group.is_empty()
                    && app.group.len() <= 128
                    && !app.group.chars().any(char::is_control),
                "each application requires a explicit, nonempty OIDC group"
            );
            app.name = app.name.trim().to_owned();
            anyhow::ensure!(
                !app.name.is_empty()
                    && app.name.len() <= 128
                    && !app.name.chars().any(char::is_control),
                "application configuration names must contain 1–128 bytes without control characters"
            );
        }
        Ok(Self {
            applications: document.applications,
            ids,
        })
    }

    pub fn applications(&self) -> &[ConfiguredApplication] {
        &self.applications
    }

    pub fn application(&self, id: Uuid) -> Option<&ConfiguredApplication> {
        self.applications.iter().find(|app| app.id == id)
    }

    pub fn contains(&self, id: Uuid) -> bool {
        self.ids.contains(&id)
    }
}
