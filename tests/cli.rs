#![cfg(unix)]
mod common;
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status();
        let _ = self.0.wait();
    }
}
fn command(url: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keygate"));
    // Do not inherit operator configuration or credentials; retain LLVM_PROFILE_FILE.
    for (k, _) in std::env::vars().filter(|(k, _)| k.starts_with("KEYGATE_")) {
        cmd.env_remove(k);
    }
    cmd.env_remove("RUST_LOG");
    cmd.args(["--database-url", url]);
    cmd
}
fn address() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}
#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn cli_modes_and_graceful_shutdown() {
    let db = common::Database::start();
    keygate::store::PostgresStore::open(&db.url)
        .await
        .unwrap()
        .initialize()
        .await
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let secret = temp.path().join("proxy");
    std::fs::write(&secret, "test-proxy-secret-at-least-32-bytes-long").unwrap();
    for (mode, trusted, signal) in [
        ("authz", false, "-INT"),
        ("manager", true, "-TERM"),
        ("all", false, "-TERM"),
    ] {
        let manager = address();
        let authz = address();
        let mut cmd = command(&db.url);
        cmd.args([
            "--mode",
            mode,
            "--manager-listen",
            &manager,
            "--authz-listen",
            &authz,
            "--proxy-secret-file",
            secret.to_str().unwrap(),
        ]);
        if trusted {
            cmd.arg("--trust-subject-header");
        } else {
            cmd.args([
                "--oidc-issuer",
                "https://id.example.com",
                "--oidc-audience",
                "keygate",
                "--oidc-jwks-url",
                "https://id.example.com/jwks",
            ]);
        }
        let mut child = Server(
            cmd.stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let addresses = match mode {
            "authz" => vec![authz],
            "manager" => vec![manager],
            _ => vec![manager, authz],
        };
        for addr in addresses {
            let mut ready = false;
            for _ in 0..100 {
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "server exited during startup"
                );
                if client
                    .get(format!("http://{addr}/healthz"))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
                {
                    ready = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert!(ready, "{mode} never became ready");
        }
        assert!(
            Command::new("kill")
                .args([signal, &child.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        assert!(child.0.wait().unwrap().success());
        // Drop must not signal a reaped/reused PID.
        std::mem::forget(child);
    }
}
#[test]
#[ignore = "requires Docker PostgreSQL"]
fn cli_configuration_errors_fail_closed_without_exposing_secrets() {
    let db = common::Database::start();
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("proxy");
    let sentinel = "never-log-this-test-proxy-secret-value";
    std::fs::write(&file, sentinel).unwrap();
    let common = ["--proxy-secret-file", file.to_str().unwrap()];
    let cases = vec![
        vec!["--cache-ttl-seconds", "301"],
        vec!["--cache-capacity", "0"],
        vec![],
        vec!["--proxy-secret-file", "/does/not/exist"],
        common.to_vec(),
        [
            common.as_slice(),
            &[
                "--oidc-issuer",
                "http://unsafe.example.com",
                "--oidc-audience",
                "keygate",
                "--oidc-jwks-url",
                "https://id.example.com/jwks",
            ],
        ]
        .concat(),
        [
            common.as_slice(),
            &["--oidc-issuer", "https://id.example.com"],
        ]
        .concat(),
        [
            common.as_slice(),
            &[
                "--oidc-issuer",
                "https://id.example.com",
                "--oidc-audience",
                "keygate",
            ],
        ]
        .concat(),
        [
            common.as_slice(),
            &["--trust-subject-header", "--public-origin", "invalid"],
        ]
        .concat(),
    ];
    for args in cases {
        let output = command(&db.url).args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains(sentinel));
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let output = command(&db.url)
        .args([
            "--mode",
            "authz",
            "--authz-listen",
            &listener.local_addr().unwrap().to_string(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
#[ignore = "requires Docker PostgreSQL"]
fn all_mode_does_not_stay_running_when_one_listener_fails() {
    let db = common::Database::start();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("proxy");
    std::fs::write(&file, "test-proxy-secret-at-least-32-bytes-long").unwrap();
    let output = command(&db.url)
        .args([
            "--mode",
            "all",
            "--manager-listen",
            &address(),
            "--authz-listen",
            &listener.local_addr().unwrap().to_string(),
            "--proxy-secret-file",
            file.to_str().unwrap(),
            "--trust-subject-header",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[tokio::test]
#[ignore = "requires Docker PostgreSQL"]
async fn database_startup_errors_do_not_leak_credentials() {
    let db = common::Database::start();
    let sentinel = "never-log-this-database-password";
    let wrong_password = db.url.replace("isolated-test-only", sentinel);
    for url in [&wrong_password, "invalid database URL"] {
        let output = command(url).arg("--mode").arg("authz").output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("database connection failed"));
        assert!(!stderr.contains(sentinel));
        assert!(!stderr.contains(url));
    }
    let pool = sqlx::PgPool::connect(&db.url).await.unwrap();
    sqlx::raw_sql("CREATE ROLE restricted LOGIN PASSWORD 'never-log-this-database-password'; GRANT CONNECT ON DATABASE postgres TO restricted; GRANT USAGE ON SCHEMA public TO restricted;").execute(&pool).await.unwrap();
    let restricted = db.url.replace(
        "postgres:isolated-test-only@",
        &format!("restricted:{sentinel}@"),
    );
    let output = command(&restricted)
        .arg("--mode")
        .arg("manager")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("database initialization failed"));
    assert!(!stderr.contains(sentinel));
}
