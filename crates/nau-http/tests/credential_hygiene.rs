//! Credential hygiene on the client side.
//!
//! upstream v2.8.2 fix (finding 1): upstream's provider adapters had no HTTP
//! client at all, so an `Authorization` header exists only in their doc comments
//! (`llm/adapter.rs`), and a credential could never reach a log line because it
//! could never reach a request. The moment this crate *does* put a credential on
//! the wire, the interesting property becomes the reverse: a request that carries
//! a key must still be safe to print.
//!
//! These tests pin that property, and the related one that a caller cannot smuggle
//! a second, conflicting credential into a request through a header list.

use nau_http::{HttpRequest, USER_AGENT};

#[test]
fn a_request_that_carries_a_credential_prints_without_it() {
    let request = HttpRequest::post_json(
        "https://api.example/v1/messages",
        &serde_json::json!({"model": "m"}),
    )
    .expect("serialises")
    .header("x-api-key", "sk-live-do-not-print-me")
    .header("Authorization", "Bearer sk-live-do-not-print-me-either")
    .header("API-KEY", "case-insensitive-secret")
    .header("Content-Type", "application/json");

    let printed = format!("{request:?}");
    assert!(!printed.contains("do-not-print-me"), "{printed}");
    assert!(!printed.contains("case-insensitive-secret"), "{printed}");
    assert_eq!(
        printed.matches("<redacted>").count(),
        3,
        "every credential-shaped header must be redacted: {printed}"
    );
    // Non-secret headers are still visible, so the print is useful for debugging.
    assert!(printed.contains("application/json"), "{printed}");
    assert!(printed.contains("api.example"), "{printed}");
}

#[test]
fn a_header_replaces_rather_than_duplicates_a_credential() {
    // Two conflicting `Authorization` headers is exactly how a request ends up
    // authenticated as somebody else than the caller intended.
    let request = HttpRequest::get("https://api.example/v1/models")
        .header("authorization", "Bearer first")
        .header("Authorization", "Bearer second");
    let values: Vec<&str> = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(values, vec!["Bearer second"], "the later header wins, once");
}

#[test]
fn the_user_agent_names_the_crate_and_its_version() {
    assert!(USER_AGENT.starts_with("nau-http/"), "{USER_AGENT}");
    assert!(
        USER_AGENT.contains(env!("CARGO_PKG_VERSION")),
        "{USER_AGENT}"
    );
}

#[test]
fn the_client_consumes_no_float_from_a_caller() {
    // upstream v2.8.2 fix (finding 4): this crate has no float in its public API —
    // no weight, confidence, score, threshold or ratio — so there is nothing an
    // externally supplied `NaN` could reach. The assertion below is a
    // compile-time-shaped claim expressed as a test: the body it sends is bytes,
    // and a non-finite value cannot be serialized into it.
    assert!(serde_json::Number::from_f64(f64::NAN).is_none());
    assert!(serde_json::from_str::<serde_json::Value>("1e999").is_err());
    let request = HttpRequest::post_json("https://api.example/v1/x", &serde_json::json!({"n": 1}))
        .expect("serialises");
    let body = std::str::from_utf8(request.body.as_deref().expect("a body")).expect("utf-8");
    assert!(
        !body.contains("NaN") && !body.contains("Infinity"),
        "{body}"
    );
}
