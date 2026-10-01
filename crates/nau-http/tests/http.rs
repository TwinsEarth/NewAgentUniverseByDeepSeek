//! End-to-end tests for `nau-http` over **real loopback sockets**.
//!
//! There is no mock here: every test that exercises the transport starts a
//! `tokio::net::TcpListener` on `127.0.0.1:0`, runs a canned responder in a task,
//! and points the transport at the port the kernel actually assigned.
//!
//! upstream v2.5.6 fix set covered here:
//! * there was no HTTP client and no HTTP dependency at all, so no request ever
//!   reached a socket;
//! * a non-2xx response must be `Ok` with the status intact, because the provider
//!   layer — not the transport — decides what a status means;
//! * a truncated body, an oversized body and a stalled server must all be typed
//!   errors, never panics and never hangs.

use std::time::Duration;

use nau_http::{
    parse_url, Headers, HttpError, HttpRequest, HttpResponse, TcpTransport, Transport,
    DEFAULT_MAX_BODY,
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One request as the test server saw it.
struct SeenRequest {
    method: String,
    target: String,
    headers: Headers,
    body: Vec<u8>,
}

impl SeenRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }

    fn body_json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("request body is JSON")
    }
}

/// Start a server that answers each connection with `response` and records the
/// request it read.
///
/// The socket is a real one and the port is assigned by the kernel, so the test
/// exercises the same code path a provider would.
async fn spawn_server(
    response: impl Into<Vec<u8>> + Send + 'static,
) -> (u16, tokio::task::JoinHandle<SeenRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    let response = response.into();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let seen = read_request(&mut socket).await;
        socket.write_all(&response).await.expect("write response");
        socket.flush().await.expect("flush");
        // Close, so read-to-EOF framing terminates.
        let _ = socket.shutdown().await;
        seen
    });
    (port, handle)
}

/// Start a server that writes `response` and ignores whether the client reads it
/// all, for tests where the client is *expected* to stop early.
///
/// A client refusing an oversized body hangs up mid-write, so the responder must
/// tolerate a broken pipe rather than panic and reset the connection, which
/// would replace the error under test with a different one.
async fn spawn_write_only_server(response: impl Into<Vec<u8>> + Send + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    let response = response.into();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let _ = read_request(&mut socket).await;
            let _ = socket.write_all(&response).await;
            let _ = socket.flush().await;
            // Hold the socket open briefly so the data is not discarded by a
            // reset before the client has decided to stop reading.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    port
}

/// Start a server that accepts a connection and then never answers, to prove the
/// read timeout is real.
async fn spawn_silent_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        // Hold the connection open, saying nothing, for longer than the client's
        // read timeout, but not forever: the test must still finish.
        tokio::time::sleep(Duration::from_millis(750)).await;
        let _ = socket.shutdown().await;
    });
    (port, handle)
}

/// Read one HTTP/1.1 request from `socket`.
async fn read_request(socket: &mut TcpStream) -> SeenRequest {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let read = socket.read(&mut byte).await.expect("read head");
        if read == 0 {
            break;
        }
        head.push(byte[0]);
        assert!(head.len() < 64 * 1024, "request head is unbounded");
    }
    let text = String::from_utf8(head.clone()).expect("head is UTF-8");
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    let mut headers = Headers::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push(name.trim().to_string(), value.trim().to_string());
        }
    }
    let length: usize = headers
        .content_length()
        .unwrap_or(0)
        .try_into()
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if length > 0 {
        socket.read_exact(&mut body).await.expect("read body");
    }
    SeenRequest {
        method,
        target,
        headers,
        body,
    }
}

fn url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}

// ---------------------------------------------------------------------------
// Request framing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_get_request_is_framed_with_host_connection_and_user_agent() {
    let (port, server) =
        spawn_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok")
            .await;

    let transport = TcpTransport::new();
    let response = transport
        .execute(HttpRequest::get(&url(port, "/v1/models?x=1")))
        .await
        .expect("request succeeds");

    assert_eq!(response.status, 200);
    assert_eq!(response.headers.get("content-type"), Some("text/plain"));
    assert_eq!(response.text().expect("utf-8"), "ok");

    let seen = server.await.expect("server task");
    assert_eq!(seen.method, "GET");
    assert_eq!(
        seen.target, "/v1/models?x=1",
        "the query string is preserved"
    );
    assert_eq!(
        seen.header("host"),
        Some(format!("127.0.0.1:{port}").as_str()),
        "a non-default port must appear in Host"
    );
    assert_eq!(seen.header("connection"), Some("close"));
    assert!(
        seen.header("user-agent")
            .is_some_and(|agent| agent.starts_with("nau-http/")),
        "User-Agent must name this client, saw {:?}",
        seen.header("user-agent")
    );
    assert!(
        seen.header("content-length").is_none(),
        "a bodyless GET must not claim a Content-Length"
    );
    assert!(seen.body.is_empty());
}

#[tokio::test]
async fn headers_are_matched_case_insensitively() {
    let (port, _server) =
        spawn_server("HTTP/1.1 200 OK\r\ncOnTeNt-LeNgTh: 3\r\nX-Trace-ID: abc\r\n\r\nhey").await;

    let response = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect("request succeeds");

    assert_eq!(response.headers.get("Content-Length"), Some("3"));
    assert_eq!(response.headers.get("x-trace-id"), Some("abc"));
    assert!(response.headers.contains("X-TRACE-ID"));
    assert_eq!(response.body, b"hey");
}

#[tokio::test]
async fn a_post_json_request_declares_its_content_type_and_length() {
    let (port, server) =
        spawn_server("HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"ok\":\"yes....\"}").await;

    let payload = serde_json::json!({"model": "deepseek-flash", "stream": false});
    let request =
        HttpRequest::post_json(&url(port, "/chat/completions"), &payload).expect("body serializes");
    let expected_len = serde_json::to_vec(&payload).expect("serializes").len();

    let response = TcpTransport::new()
        .execute(request)
        .await
        .expect("request succeeds");
    assert_eq!(response.status, 200);

    let seen = server.await.expect("server task");
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.target, "/chat/completions");
    assert_eq!(seen.header("content-type"), Some("application/json"));
    assert_eq!(
        seen.header("content-length"),
        Some(expected_len.to_string().as_str()),
        "Content-Length must describe the body that was actually sent"
    );
    assert_eq!(seen.body_json(), payload);
}

#[tokio::test]
async fn a_caller_supplied_content_length_is_replaced_by_the_real_one() {
    let (port, server) = spawn_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;

    // upstream v2.5.6 fix: the outgoing length is derived from the body, so a
    // caller cannot desynchronise the connection by lying about it.
    let request = HttpRequest::post_json(&url(port, "/v1/messages"), &serde_json::json!({"a": 1}))
        .expect("body serializes")
        .header("Content-Length", "9999");

    let _ = TcpTransport::new()
        .execute(request)
        .await
        .expect("request succeeds");

    let seen = server.await.expect("server task");
    assert_eq!(seen.header("content-length"), Some("7"));
    assert_eq!(seen.body.len(), 7);
}

// ---------------------------------------------------------------------------
// Status handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_404_is_a_successful_exchange_not_a_transport_error() {
    let (port, _server) =
        spawn_server("HTTP/1.1 404 Not Found\r\nContent-Length: 19\r\n\r\n{\"error\":\"missing\"}")
            .await;

    let response = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/nope")))
        .await
        .expect("a 404 is not a transport fault");

    assert_eq!(response.status, 404);
    assert_eq!(
        response.json::<Value>().expect("json")["error"],
        Value::from("missing")
    );
}

#[tokio::test]
async fn a_500_is_returned_with_its_status_and_body_intact() {
    let (port, _server) =
        spawn_server("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 11\r\n\r\nboom in 500")
            .await;

    let response = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect("a 500 is not a transport fault");

    assert_eq!(response.status, 500);
    assert_eq!(response.text().expect("utf-8"), "boom in 500");
}

// ---------------------------------------------------------------------------
// JSON bodies
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, PartialEq, Debug)]
struct Completion {
    id: String,
    choices: Vec<Choice>,
}

#[derive(serde::Deserialize, PartialEq, Debug)]
struct Choice {
    text: String,
    index: u32,
}

#[tokio::test]
async fn a_json_body_deserialises_into_a_typed_value() {
    let body = r#"{"id":"cmpl-1","choices":[{"text":"hello","index":0}]}"#;
    let response_text = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (port, _server) = spawn_server(response_text).await;

    let response = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/v1/completions")))
        .await
        .expect("request succeeds");

    let decoded: Completion = response.json().expect("typed decode");
    assert_eq!(
        decoded,
        Completion {
            id: "cmpl-1".to_string(),
            choices: vec![Choice {
                text: "hello".to_string(),
                index: 0,
            }],
        }
    );
}

#[tokio::test]
async fn a_twice_read_body_still_parses() {
    let (port, _server) =
        spawn_server("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{\"n\":42}..").await;

    let response = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect("request succeeds");

    // `text()` and `json()` both borrow the stored bytes; neither consumes them.
    assert_eq!(response.text().expect("utf-8").len(), 9);
    assert!(
        response.json::<Value>().is_err(),
        "trailing bytes are not JSON"
    );
    assert_eq!(response.body_snippet(6), "{\"n\":4");
}

// ---------------------------------------------------------------------------
// Framing faults
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_truncated_content_length_body_is_a_typed_error_not_a_panic() {
    // Declares 50 bytes and delivers 10.
    let (port, _server) =
        spawn_server("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n0123456789").await;

    let error = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect_err("a short body is an error");

    match error {
        HttpError::TruncatedBody { expected, received } => {
            assert_eq!(expected, 50);
            assert_eq!(received, 10);
        }
        other => panic!("expected TruncatedBody, saw {other:?}"),
    }
}

#[tokio::test]
async fn an_empty_response_is_a_typed_error() {
    let (port, _server) = spawn_server(Vec::new()).await;

    let error = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect_err("no status line at all");

    assert!(
        matches!(error, HttpError::MalformedHead(_)),
        "expected MalformedHead, saw {error:?}"
    );
}

#[tokio::test]
async fn a_nonsense_status_line_is_a_typed_error() {
    let (port, _server) = spawn_server("NOT-HTTP 200 OK\r\nContent-Length: 0\r\n\r\n").await;

    let error = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect_err("a status line must start with an HTTP version");

    assert!(
        matches!(error, HttpError::MalformedHead(_)),
        "expected MalformedHead, saw {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Size limits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_oversized_declared_body_is_refused() {
    let body = "x".repeat(4096);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (port, _server) = spawn_server(response).await;

    let transport = TcpTransport::builder()
        .max_body(1024)
        .build()
        .expect("limits are valid");

    let error = transport
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect_err("4096 bytes must not pass a 1024-byte cap");

    assert!(
        matches!(error, HttpError::BodyTooLarge { limit } if limit == 1024),
        "expected BodyTooLarge, saw {error:?}"
    );
}

#[tokio::test]
async fn an_oversized_unframed_body_is_refused_rather_than_truncated() {
    // No Content-Length: the body is delimited by the close, so the cap is the
    // only bound. Refusing beats handing back a silently partial document.
    let body = "y".repeat(4096);
    let port = spawn_write_only_server(format!(
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}"
    ))
    .await;

    let transport = TcpTransport::builder()
        .max_body(1024)
        .build()
        .expect("limits are valid");

    let error = transport
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect_err("an unbounded body must hit the cap");

    assert!(
        matches!(error, HttpError::BodyTooLarge { limit } if limit == 1024),
        "expected BodyTooLarge, saw {error:?}"
    );
}

#[tokio::test]
async fn zero_limits_are_rejected_at_construction() {
    assert!(TcpTransport::builder().max_body(0).build().is_err());
    assert!(TcpTransport::builder().max_head(0).build().is_err());
    assert!(TcpTransport::builder()
        .read_timeout(Duration::ZERO)
        .build()
        .is_err());
    assert!(TcpTransport::builder()
        .connect_timeout(Duration::ZERO)
        .build()
        .is_err());
    assert!(TcpTransport::new()
        .with_read_timeout(Duration::ZERO)
        .is_err());
    assert!(TcpTransport::new().with_max_body(0).is_err());
    assert_eq!(TcpTransport::new().max_body(), DEFAULT_MAX_BODY);
}

// ---------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_server_that_never_answers_times_out_with_a_typed_error() {
    let (port, server) = spawn_silent_server().await;

    let transport = TcpTransport::builder()
        .read_timeout(Duration::from_millis(150))
        .build()
        .expect("limits are valid");

    let started = std::time::Instant::now();
    let error = transport
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect_err("a silent server must time out");
    let elapsed = started.elapsed();

    assert!(
        matches!(error, HttpError::ReadTimeout { .. }),
        "expected ReadTimeout, saw {error:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the timeout must fire promptly, took {elapsed:?}"
    );
    let _ = server.await;
}

#[tokio::test]
async fn a_connection_refused_is_a_typed_connect_error() {
    // Bind, learn the port, then drop the listener so nothing is listening.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    let error = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect_err("nothing is listening");

    assert!(
        matches!(error, HttpError::Connect { port: p, .. } if p == port),
        "expected Connect, saw {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Chunked transfer-coding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_chunked_response_is_decoded_not_rejected() {
    let (port, _server) = spawn_server(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
         5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .await;

    let response = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect("chunked responses are supported");

    assert_eq!(response.status, 200);
    assert_eq!(response.text().expect("utf-8"), "hello world");
}

#[tokio::test]
async fn chunk_extensions_are_ignored_and_trailers_are_consumed() {
    let (port, _server) = spawn_server(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
         4;name=value\r\nabcd\r\n0\r\nX-Trailer: 1\r\n\r\n",
    )
    .await;

    let response = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect("chunk extensions and trailers are legal");

    assert_eq!(response.body, b"abcd");
}

#[tokio::test]
async fn chunked_plus_content_length_is_refused() {
    // upstream v2.5.6 fix: two conflicting frames are a request-smuggling
    // vector; the client refuses to guess which one the peer meant.
    let (port, _server) = spawn_server(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
    )
    .await;

    let error = TcpTransport::new()
        .execute(HttpRequest::get(&url(port, "/")))
        .await
        .expect_err("ambiguous framing");

    assert!(
        matches!(error, HttpError::UnsupportedTransferCoding(_)),
        "expected UnsupportedTransferCoding, saw {error:?}"
    );
}

#[test]
fn the_chunked_decoder_handles_the_whole_grammar_offline() {
    assert_eq!(
        TcpTransport::decode_chunked(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n").expect("decodes"),
        b"Wikipedia"
    );
    assert_eq!(
        TcpTransport::decode_chunked(b"0\r\n\r\n").expect("decodes"),
        b""
    );
    assert!(
        TcpTransport::decode_chunked(b"zz\r\nabc\r\n0\r\n\r\n").is_err(),
        "a non-hex size is malformed"
    );
    assert!(
        TcpTransport::decode_chunked(b"10\r\nabcd").is_err(),
        "a short chunk is truncated, not silently accepted"
    );
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

#[test]
fn urls_are_split_into_scheme_host_port_path_and_tls_flag() {
    let parsed = parse_url("http://example.com/a/b?c=d").expect("parses");
    assert_eq!(parsed.scheme, "http");
    assert_eq!(parsed.host, "example.com");
    assert_eq!(parsed.port, 80);
    assert_eq!(parsed.path, "/a/b?c=d");
    assert!(!parsed.tls);
    assert_eq!(parsed.host_header(), "example.com");

    let parsed = parse_url("https://Example.COM:8443/x").expect("parses");
    assert_eq!(parsed.scheme, "https");
    assert_eq!(parsed.host, "Example.COM");
    assert_eq!(parsed.port, 8443);
    assert_eq!(parsed.path, "/x");
    assert!(parsed.tls);
    assert_eq!(parsed.host_header(), "Example.COM:8443");

    let bare = parse_url("http://example.com").expect("parses");
    assert_eq!(bare.path, "/", "an empty path becomes `/`");

    let query_only = parse_url("http://example.com?q=1").expect("parses");
    assert_eq!(query_only.path, "/?q=1");

    let fragment = parse_url("http://example.com/a#frag").expect("parses");
    assert_eq!(fragment.path, "/a", "a fragment is never sent");

    let ipv6 = parse_url("http://[::1]:8080/v1").expect("parses");
    assert_eq!(ipv6.host, "::1");
    assert_eq!(ipv6.port, 8080);
    assert_eq!(ipv6.host_header(), "[::1]:8080");
}

#[test]
fn a_missing_scheme_is_a_typed_error() {
    let error = parse_url("api.example.com/v1").expect_err("no scheme");
    assert!(
        matches!(error, HttpError::UnsupportedScheme { ref scheme } if scheme.is_empty()),
        "expected UnsupportedScheme, saw {error:?}"
    );
    assert!(parse_url("").is_err());
}

#[test]
fn a_non_http_scheme_is_a_typed_error() {
    for candidate in [
        "ftp://example.com/x",
        "file:///etc/passwd",
        "ws://example.com",
    ] {
        let error = parse_url(candidate).expect_err("unsupported scheme");
        assert!(
            matches!(error, HttpError::UnsupportedScheme { .. }),
            "{candidate} should be UnsupportedScheme, saw {error:?}"
        );
    }
}

#[test]
fn a_malformed_url_is_a_typed_error() {
    for candidate in [
        "http://",
        "http:///path-with-no-host",
        "http://host:not-a-number/",
        "http://host:0/",
        "http://host:70000/",
        "http://user:pass@host/",
        "http://[::1/v1",
    ] {
        let error = parse_url(candidate).expect_err("malformed");
        assert!(
            matches!(error, HttpError::MalformedUrl { .. }),
            "{candidate} should be MalformedUrl, saw {error:?}"
        );
    }
}

#[tokio::test]
async fn a_url_with_a_bad_scheme_never_opens_a_socket() {
    let error = TcpTransport::new()
        .execute(HttpRequest::get("ftp://127.0.0.1:1/x"))
        .await
        .expect_err("scheme is checked before connecting");
    assert!(
        matches!(error, HttpError::UnsupportedScheme { .. }),
        "expected UnsupportedScheme, saw {error:?}"
    );
}

#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn https_without_the_tls_feature_is_a_typed_error_not_a_downgrade() {
    // upstream v2.5.6 fix: an `https://` request must never travel in clear
    // text. Without the feature it fails before any socket is opened.
    let error = TcpTransport::new()
        .execute(HttpRequest::get("https://example.com/v1/models"))
        .await
        .expect_err("TLS is required");

    match error {
        HttpError::TlsDisabled { url } => assert_eq!(url, "https://example.com/v1/models"),
        other => panic!("expected TlsDisabled, saw {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

#[test]
fn a_non_utf8_body_is_reported_and_snippets_are_bounded() {
    let mut headers = Headers::new();
    headers.push("Content-Type", "application/octet-stream");
    let response = HttpResponse {
        status: 200,
        headers,
        body: vec![0xff, 0xfe, b'a', b'b'],
    };

    assert!(response.text().is_err());
    // Lossy only for diagnostics, and bounded by the byte limit: at most three
    // output bytes (one replacement character) per taken input byte.
    assert_eq!(response.body_snippet(2), "\u{fffd}\u{fffd}");
    assert_eq!(
        response.body_snippet(0),
        "",
        "a zero-width snippet copies nothing"
    );
    let huge = HttpResponse {
        status: 200,
        headers: Headers::new(),
        body: vec![b'z'; 1024 * 1024],
    };
    assert_eq!(
        huge.body_snippet(64).len(),
        64,
        "a megabyte of body must not end up in a log line"
    );
    assert_eq!(
        response.body_snippet(4096),
        "\u{fffd}\u{fffd}ab",
        "a limit past the end returns the whole body"
    );
}

#[test]
fn duplicate_headers_are_all_preserved() {
    let mut headers = Headers::new();
    headers.push("Set-Cookie", "a=1");
    headers.push("Set-Cookie", "b=2");

    assert_eq!(headers.get("set-cookie"), Some("a=1"), "first wins");
    assert_eq!(headers.values("set-cookie"), vec!["a=1", "b=2"]);
    assert_eq!(headers.len(), 2);
    assert!(!headers.is_empty());
    assert_eq!(headers.iter().count(), 2);
}

#[test]
fn transfer_encoding_is_chunked_only_when_chunked_is_last() {
    let mut headers = Headers::new();
    headers.push("Transfer-Encoding", "gzip, chunked");
    assert!(headers.is_chunked());

    let mut headers = Headers::new();
    headers.push("Transfer-Encoding", "chunked, gzip");
    assert!(!headers.is_chunked(), "chunked must be the final coding");

    let mut headers = Headers::new();
    headers.push("Transfer-Encoding", "CHUNKED");
    assert!(headers.is_chunked(), "matching is case-insensitive");
}
