use clap::{Parser, ValueEnum};
use keygate::{
    Authorizer, Manager, authz_router, manager_router,
    store::{OpenBaoStore, SqliteStore, Store},
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
#[derive(Clone, ValueEnum)]
enum Mode {
    Manager,
    Authz,
    All,
}
#[derive(Clone, ValueEnum)]
enum Backend {
    Sqlite,
    Openbao,
}
#[derive(Parser)]
#[command(version, about = "API key management and Envoy external authorization")]
struct Args {
    #[arg(long, env = "KEYGATE_MODE", default_value = "all")]
    mode: Mode,
    #[arg(long, env = "KEYGATE_BACKEND", default_value = "sqlite")]
    backend: Backend,
    #[arg(
        long,
        env = "KEYGATE_SQLITE_URL",
        default_value = "sqlite://keygate.db"
    )]
    sqlite_url: String,
    #[arg(
        long,
        env = "KEYGATE_BAO_ADDR",
        default_value = "http://127.0.0.1:8200"
    )]
    bao_addr: String,
    #[arg(long, env = "KEYGATE_BAO_MOUNT", default_value = "kv")]
    bao_mount: String,
    #[arg(long, env = "KEYGATE_BAO_PREFIX", default_value = "keygate")]
    bao_prefix: String,
    #[arg(long, env = "KEYGATE_BAO_TOKEN_FILE")]
    bao_token_file: Option<PathBuf>,
    #[arg(long, env = "KEYGATE_OIDC_ISSUER")]
    oidc_issuer: Option<String>,
    #[arg(long, env = "KEYGATE_OIDC_AUDIENCE")]
    oidc_audience: Option<String>,
    #[arg(long, env = "KEYGATE_OIDC_JWKS_URL")]
    oidc_jwks_url: Option<String>,
    /// Only for proxies that securely overwrite the subject header after validating identity.
    #[arg(long, env = "KEYGATE_TRUST_SUBJECT_HEADER", default_value = "false")]
    trust_subject_header: bool,
    #[arg(long, env = "KEYGATE_PROXY_SECRET_FILE")]
    proxy_secret_file: Option<PathBuf>,
    #[arg(
        long,
        env = "KEYGATE_PUBLIC_ORIGIN",
        default_value = "http://localhost:8080"
    )]
    public_origin: String,
    #[arg(long, env = "KEYGATE_MANAGER_LISTEN", default_value = "127.0.0.1:8080")]
    manager_listen: SocketAddr,
    #[arg(long, env = "KEYGATE_AUTHZ_LISTEN", default_value = "127.0.0.1:8081")]
    authz_listen: SocketAddr,
    #[arg(long, env = "KEYGATE_CACHE_TTL_SECONDS", default_value = "30")]
    cache_ttl_seconds: u64,
    #[arg(long, env = "KEYGATE_CACHE_CAPACITY", default_value = "1024")]
    cache_capacity: u64,
}
async fn shutdown() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("signal handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
async fn serve(address: SocketAddr, app: axum::Router) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keygate=info".into()),
        )
        .init();
    let args = Args::parse();
    anyhow::ensure!(
        args.cache_ttl_seconds <= 300 && args.cache_capacity > 0,
        "cache TTL must be <= 300 seconds and capacity must be positive"
    );
    let store: Arc<dyn Store> = match args.backend {
        Backend::Sqlite => Arc::new(SqliteStore::open(&args.sqlite_url).await?),
        Backend::Openbao => Arc::new(OpenBaoStore::new(
            &args.bao_addr,
            &args.bao_mount,
            &args.bao_prefix,
            args.bao_token_file
                .ok_or_else(|| anyhow::anyhow!("--bao-token-file is required"))?,
        )?),
    };
    let authz = authz_router(Authorizer::new(
        store.clone(),
        Duration::from_secs(args.cache_ttl_seconds),
        args.cache_capacity,
    ));
    if matches!(args.mode, Mode::Authz) {
        return serve(args.authz_listen, authz).await;
    }
    let secret = tokio::fs::read_to_string(
        args.proxy_secret_file
            .ok_or_else(|| anyhow::anyhow!("--proxy-secret-file is required for manager"))?,
    )
    .await?;
    let mut manager = Manager::new(store, secret.trim().into(), args.public_origin)?;
    if !args.trust_subject_header {
        manager = manager.with_oidc(keygate::identity::Oidc::new(
            args.oidc_issuer
                .ok_or_else(|| anyhow::anyhow!("--oidc-issuer is required"))?,
            args.oidc_audience
                .ok_or_else(|| anyhow::anyhow!("--oidc-audience is required"))?,
            args.oidc_jwks_url
                .ok_or_else(|| anyhow::anyhow!("--oidc-jwks-url is required"))?,
        )?);
    }
    let manager = manager_router(manager);
    match args.mode {
        Mode::Manager => serve(args.manager_listen, manager).await,
        Mode::All => {
            tokio::try_join!(
                serve(args.manager_listen, manager),
                serve(args.authz_listen, authz)
            )?;
            Ok(())
        }
        Mode::Authz => unreachable!(),
    }
}
