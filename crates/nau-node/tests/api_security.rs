//! The socket path, exercised over a real loopback TCP connection.
//!
//! `api::route` is a pure function and its tests prove the *decisions*. These
//! tests prove that the byte-framing loop around it enforces the same decisions on
//! the wire, which is where upstream's remaining defects live:
//!
//! * upstream grows the body buffer until `Content-Length` is satisfied, with no
//!   cap and no read timeout (`node.rs:984-1007`) — a `413` and a `408` are
//!   asserted here, along with the property that the buffer cannot grow past the
//!   cap (the oversized-body test would otherwise allocate the whole thing);
//! * upstream sends `Access-Control-Allow-Origin: *` and validates neither
//!   `Origin` nor `Host` (`node.rs:741-746`) — a hostile origin is asserted to be
//!   refused with **no** `Access-Control-Allow-Origin` header, and a rebinding
//!   `Host` too;
//! * upstream calls this router with no authentication at all
//!   (`node.rs:1107-1152`) — an unauthenticated mutation is asserted to be
//!   refused, and the deposit asserted not to have happened.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use nau_node::api::{self, RequestLimits};
use nau_node::{ApiPolicy, Authenticator, Node, NodeConfig, Scope};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A credential the tests configure, with every scope and no DID.
const TOKEN: &str = "integration-token";

/// Bind `127.0.0.1:0`, serve on it with `policy` and `limits`, and return the
/// port plus a shutdown handle.
async fn serve(
    policy: ApiPolicy,
    limits: RequestLimits,
) -> (u16, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();
    let node = Node::ephemeral(NodeConfig::default()).expect("ephemeral node");
    let shared = Arc::new(Mutex::new(node));
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        let _ = api::serve_on(listener, shared, policy, limits, shutdown).await;
    });
    (port, tx)
}

/// A policy with one unbound service caller holding every scope.
fn service_policy() -> ApiPolicy {
    ApiPolicy::deny_all().with_authenticator(
        Authenticator::deny_all()
            .with_token(
                TOKEN,
                "service",
                None,
                &[Scope::Read, Scope::Write, Scope::Admin],
            )
            .expect("configures"),
    )
}

/// One request over a fresh connection, returning the raw response text.
///
/// The reader runs concurrently with the writer because a server that refuses a
/// request *while the client is still sending* closes the socket with unread data
/// in its receive buffer, which makes the stack emit a reset; a reader that is
/// already draining the socket keeps the answer that arrived before the reset.
async fn exchange(port: u16, request: &str) -> String {
    exchange_chunks(port, &[request.as_bytes().to_vec()]).await
}

/// [`exchange`] with the request delivered in several writes.
async fn exchange_chunks(port: u16, chunks: &[Vec<u8>]) -> String {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let (mut reader, mut writer) = stream.into_split();
    let reading = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk).await {
                // EOF and a reset both end the response; whatever arrived is kept.
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        buf
    });
    for chunk in chunks {
        if writer.write_all(chunk).await.is_err() {
            break;
        }
    }
    let _ = writer.flush().await;
    // Keep the write half open: a server that bounds its read answers on its own.
    let response = tokio::time::timeout(Duration::from_secs(10), reading)
        .await
        .ok()
        .and_then(|joined| joined.ok())
        .unwrap_or_default();
    String::from_utf8_lossy(&response).into_owned()
}

/// A `POST` with a JSON body.
fn post(target: &str, body: &str, extra_headers: &str) -> String {
    format!(
        "POST {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n{extra_headers}\r\n{body}",
        body.len()
    )
}

fn status_of(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0)
}

fn body_of(response: &str) -> serde_json::Value {
    let body = match response.split_once("\r\n\r\n") {
        Some((_, body)) => body,
        None => return serde_json::Value::Null,
    };
    serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
}

fn header_of<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response
        .split("\r\n")
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
}

#[tokio::test]
async fn an_unauthenticated_mutation_is_refused_on_the_wire_and_changes_nothing() {
    let (port, shutdown) = serve(service_policy(), RequestLimits::default()).await;

    let response = exchange(
        port,
        &post("/accounts/alice/deposit", r#"{"amount":"1000"}"#, ""),
    )
    .await;
    assert_eq!(status_of(&response), 401, "{response}");
    assert_eq!(body_of(&response)["error"], "credential_required");

    // The same request with the credential lands, so the refusal is about the
    // credential and not about the request shape.
    let response = exchange(
        port,
        &post(
            "/accounts/alice/deposit",
            r#"{"amount":"1000"}"#,
            &format!("Authorization: Bearer {TOKEN}\r\n"),
        ),
    )
    .await;
    assert_eq!(status_of(&response), 200, "{response}");
    assert_eq!(body_of(&response)["balance_minor"], 1_000_000_000);

    // And a read needs no credential.
    let response = exchange(
        port,
        "GET /accounts/alice/balance HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    )
    .await;
    assert_eq!(status_of(&response), 200, "{response}");

    let _ = shutdown.send(());
}

#[tokio::test]
async fn a_hostile_origin_is_refused_and_never_echoed_on_the_wire() {
    let (port, shutdown) = serve(service_policy(), RequestLimits::default()).await;

    for origin in ["http://evil.example", "null"] {
        let response = exchange(
            port,
            &post(
                "/accounts/alice/deposit",
                r#"{"amount":"1"}"#,
                &format!("Origin: {origin}\r\nAuthorization: Bearer {TOKEN}\r\n"),
            ),
        )
        .await;
        assert_eq!(status_of(&response), 403, "for origin {origin}: {response}");
        assert_eq!(body_of(&response)["error"], "forbidden_origin");
        assert_eq!(
            header_of(&response, "access-control-allow-origin"),
            None,
            "a hostile origin must never be echoed: {response}"
        );
    }

    // A preflight for a hostile origin is refused with no CORS headers at all.
    let response = exchange(
        port,
        "OPTIONS /accounts/alice/deposit HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Origin: http://evil.example\r\nAccess-Control-Request-Method: POST\r\n\r\n",
    )
    .await;
    assert_eq!(status_of(&response), 403, "{response}");
    assert_eq!(header_of(&response, "access-control-allow-origin"), None);
    assert_eq!(header_of(&response, "vary"), None);

    // An allow-listed origin is echoed exactly, never as `*`.
    let policy = service_policy().allow_origin("http://127.0.0.1:1420");
    let (port, shutdown2) = serve(policy, RequestLimits::default()).await;
    let response = exchange(
        port,
        &post(
            "/accounts/alice/deposit",
            r#"{"amount":"1"}"#,
            "Origin: http://127.0.0.1:1420\r\n",
        ),
    )
    .await;
    assert_eq!(
        status_of(&response),
        401,
        "still needs a credential: {response}"
    );
    assert_eq!(
        header_of(&response, "access-control-allow-origin"),
        Some("http://127.0.0.1:1420")
    );
    assert_eq!(header_of(&response, "vary"), Some("Origin"));

    let response = exchange(
        port,
        &post(
            "/accounts/alice/deposit",
            r#"{"amount":"1"}"#,
            &format!("Origin: http://127.0.0.1:1420\r\nAuthorization: Bearer {TOKEN}\r\n"),
        ),
    )
    .await;
    assert_eq!(status_of(&response), 200, "{response}");
    assert_eq!(
        header_of(&response, "access-control-allow-origin"),
        Some("http://127.0.0.1:1420")
    );

    let _ = shutdown.send(());
    let _ = shutdown2.send(());
}

#[tokio::test]
async fn a_rebinding_host_is_refused_on_the_wire() {
    let (port, shutdown) = serve(service_policy(), RequestLimits::default()).await;
    let response = exchange(port, "GET /health HTTP/1.1\r\nHost: evil.example\r\n\r\n").await;
    assert_eq!(status_of(&response), 403, "{response}");
    assert_eq!(body_of(&response)["error"], "forbidden_host");
    let _ = shutdown.send(());
}

#[tokio::test]
async fn an_oversized_body_is_refused_with_a_typed_413_and_bounded_memory() {
    // A 64 KiB cap, and a declared body of 1 MiB. The server must refuse from the
    // *declared* length, before reading the body, so the test sends only the head:
    // if the loop tried to satisfy `Content-Length` first it would block here.
    let limits = RequestLimits::new(64 * 1024, Duration::from_secs(5));
    let (port, shutdown) = serve(service_policy(), limits).await;

    let declared = 1024 * 1024;
    let head = format!(
        "POST /accounts/alice/deposit HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Content-Type: application/json\r\nContent-Length: {declared}\r\n\
         Authorization: Bearer {TOKEN}\r\n\r\n"
    );
    let response = exchange(port, &head).await;
    assert_eq!(status_of(&response), 413, "{response}");
    assert!(
        body_of(&response)["message"]
            .as_str()
            .unwrap_or_default()
            .contains("exceeds"),
        "{response}"
    );
    let _ = shutdown.send(());
}

#[tokio::test]
async fn an_oversized_head_is_refused_with_a_typed_413() {
    let limits = RequestLimits::new(8 * 1024, Duration::from_secs(5));
    let (port, shutdown) = serve(service_policy(), limits).await;

    // A head that never terminates and passes the cap. It is sized to what the
    // server will actually consume (cap + one 4 KiB read), so the server closes
    // with everything drained and the client does not lose the answer to a reset.
    let mut head = String::from("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    while head.len() < 12 * 1024 {
        head.push_str("X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    let response = exchange(port, &head).await;
    assert_eq!(
        status_of(&response),
        413,
        "raw response ({} bytes): {response:?}",
        response.len()
    );
    let _ = shutdown.send(());
}

#[tokio::test]
async fn a_slow_drip_body_is_refused_with_a_typed_408() {
    // A 300 ms budget, a body that declares 64 bytes, and a client that sends one
    // byte and then stalls. Upstream had no read timeout at all, so this request
    // would hold a connection and a task forever.
    let limits = RequestLimits::new(64 * 1024, Duration::from_millis(300));
    let (port, shutdown) = serve(service_policy(), limits).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let head = format!(
        "POST /accounts/alice/deposit HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Content-Type: application/json\r\nContent-Length: 64\r\n\
         Authorization: Bearer {TOKEN}\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.expect("head");
    stream.write_all(b"{").await.expect("one byte of body");
    stream.flush().await.expect("flush");

    let mut response = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response)).await;
    assert!(read.is_ok(), "the server must answer rather than hang");
    let response = String::from_utf8_lossy(&response).into_owned();
    assert_eq!(status_of(&response), 408, "{response}");
    assert!(
        response.contains("request_timeout"),
        "the status is typed: {response}"
    );

    // The connection is closed, so the half-body never reached the market.
    let balance = exchange(
        port,
        "GET /accounts/alice/balance HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    )
    .await;
    assert_eq!(body_of(&balance)["balance_minor"], 0, "{balance}");
    let _ = shutdown.send(());
}

#[tokio::test]
async fn a_conflicting_or_chunked_body_declaration_is_refused_with_a_400() {
    let (port, shutdown) = serve(service_policy(), RequestLimits::default()).await;

    for head in [
        "POST /accounts/alice/deposit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\
         Content-Length: 3\r\n\r\n{}",
        "POST /accounts/alice/deposit HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: abc\r\n\r\n",
        "POST /accounts/alice/deposit HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
    ] {
        let response = exchange(port, head).await;
        assert_eq!(status_of(&response), 400, "for `{head}`: {response}");
        assert_eq!(body_of(&response)["error"], "bad_request");
    }
    let _ = shutdown.send(());
}

#[tokio::test]
async fn a_body_at_the_cap_is_served_and_a_declared_body_past_it_is_not() {
    // The boundary, on the wire: exactly at the cap the request is read and
    // answered; one byte past it is refused from the declared length.
    let limits = RequestLimits::new(4 * 1024, Duration::from_secs(5));
    let (port, shutdown) = serve(service_policy(), limits).await;

    // A valid JSON body padded with whitespace to exactly the cap.
    let mut body = String::from(r#"{"amount":"1"}"#);
    while body.len() < 4 * 1024 {
        body.push(' ');
    }
    assert_eq!(body.len(), 4 * 1024);
    let response = exchange(
        port,
        &post(
            "/accounts/alice/deposit",
            &body,
            &format!("Authorization: Bearer {TOKEN}\r\n"),
        ),
    )
    .await;
    assert_eq!(status_of(&response), 200, "{response}");
    assert_eq!(body_of(&response)["balance_minor"], 1_000_000);

    let head = format!(
        "POST /accounts/alice/deposit HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Authorization: Bearer {TOKEN}\r\n\r\n",
        4 * 1024 + 1
    );
    let response = exchange(port, &head).await;
    assert_eq!(status_of(&response), 413, "{response}");
    let _ = shutdown.send(());
}

#[tokio::test]
async fn serve_refuses_a_non_loopback_bind_without_a_configured_caller() {
    // The daemon must not offer a privileged, unauthenticated API to the network.
    let node = Arc::new(Mutex::new(
        Node::ephemeral(NodeConfig::default()).expect("ephemeral"),
    ));
    // `0.0.0.0:0` binds every interface; the guard must fire before the bind.
    let error = api::serve(node, "0.0.0.0:0", async {})
        .await
        .expect_err("must refuse");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        error.to_string().contains("NAU_API_TOKENS"),
        "the refusal must name the variable to configure: {error}"
    );
}
