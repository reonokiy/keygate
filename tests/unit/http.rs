use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
async fn response(bytes: Vec<u8>) -> reqwest::Response {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0);
        let _ = stream.write_all(&bytes).await;
    });
    reqwest::Client::new().get(url).send().await.unwrap()
}
#[tokio::test]
async fn bounded_json_rejects_declared_streamed_and_truncated_bodies() {
    let declared = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_JSON_BYTES + 1
    );
    assert!(
        json::<serde_json::Value>(response(declared.into_bytes()).await)
            .await
            .is_err()
    );
    let body = " ".repeat(MAX_JSON_BYTES + 1);
    let chunked = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        body.len(),
        body
    );
    assert!(
        json::<serde_json::Value>(response(chunked.into_bytes()).await)
            .await
            .is_err()
    );
    let truncated =
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}".to_vec();
    assert!(
        json::<serde_json::Value>(response(truncated).await)
            .await
            .is_err()
    );
    for (body, valid) in [("{}", true), ("not-json", false)] {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        assert_eq!(
            json::<serde_json::Value>(response(raw.into_bytes()).await)
                .await
                .is_ok(),
            valid
        );
    }
    let body = format!("\"{}\"", "x".repeat(MAX_JSON_BYTES - 2));
    let good = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    assert_eq!(
        json::<String>(response(good.into_bytes()).await)
            .await
            .unwrap()
            .len(),
        MAX_JSON_BYTES - 2
    );
}
