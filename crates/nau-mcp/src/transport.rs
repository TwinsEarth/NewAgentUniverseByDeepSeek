//! Transports: newline-delimited JSON-RPC over any reader/writer pair, and the
//! SSE frame format for the HTTP transport.
//!
//! ## What changed from upstream v2.5.6
//!
//! Upstream's `run_stdio` was hard-wired to `tokio::io::stderr()`/`stdout()` and
//! to a market actor it spawned itself, so the transport could not be tested and
//! could not be reused. [`serve_stdio`] is generic over the reader and writer,
//! which makes it exercisable with an in-memory buffer, and it is the same code
//! path a real pipe uses.
//!
//! ## What changed from upstream v2.8.2
//!
//! upstream v2.8.2 fix (finding 5): upstream's two live transports
//! (`sse.rs:130-147` for HTTP, `stdio.rs:85-93` for stdio) call the tool bridges
//! **directly**, so `validate_arguments` — which exists and is tested — never
//! runs on the path a client actually uses. Both transports here are thin
//! wrappers over [`handle_line`] → [`McpServer::handle`] →
//! [`McpServer::dispatch`], which is the one function that authenticates,
//! validates and dispatches. A transport has no other door to a tool.
//!
//! upstream v2.8.2 fix (finding 6): both transports now have to say **who** is
//! calling. [`serve_stdio`] resolves a credential from the environment through
//! the [`Authenticator`] and falls back to the read-only
//! [`Principal::anonymous`]; [`handle_http_message`] takes the
//! `Authorization: Bearer` header a real HTTP front end would hand it. Neither
//! can produce a write-capable principal without a configured token, so
//! "nothing configured" means every mutating tool is refused.

use nau_core::Result;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::{Authenticator, Credential, Principal};
use crate::rpc::{error_code, RequestId, RpcResponse};
use crate::server::{encode_response, handle_line, McpServer, SessionState};

/// Serve newline-delimited JSON-RPC until EOF, as the process's own caller.
///
/// One request per line, one response per line. Empty lines are skipped. A
/// notification (a request with no `id`) produces no response. A line that is not
/// JSON produces a `-32700` parse-error response carrying `id: null`.
///
/// The caller's identity comes from the credential named by
/// [`Authenticator::token_env`] ([`crate::auth::DEFAULT_TOKEN_ENV`] by default).
/// When that variable is unset, blank, or does not match a configured token, the
/// session runs as [`Principal::anonymous`]: **reads still work and every
/// mutating tool is refused**. That is deliberate — a stdio peer that did not
/// configure a token must not inherit authority from the fact that it holds the
/// pipe.
///
/// Returns `Ok(())` at end of input, so a caller can treat a closed pipe as a
/// clean shutdown rather than an error.
pub async fn serve_stdio<R, W>(
    server: &McpServer,
    authenticator: &Authenticator,
    state: &mut SessionState,
    reader: R,
    writer: W,
) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let principal =
        authenticator.principal_or_anonymous(authenticator.credential_from_env().as_ref());
    serve_stdio_as(server, &principal, state, reader, writer).await
}

/// [`serve_stdio`] with an explicit [`Principal`], for embedding and tests.
///
/// A caller cannot use this to escalate: the only principals that exist are
/// [`Principal::anonymous`] (read-only) and the ones
/// [`Authenticator::authenticate`] produces from a configured token.
pub async fn serve_stdio_as<R, W>(
    server: &McpServer,
    principal: &Principal,
    state: &mut SessionState,
    reader: R,
    mut writer: W,
) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = reader.lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            // EOF: a clean shutdown.
            Ok(None) => return Ok(()),
            Err(error) => {
                // A broken pipe is also a clean shutdown: the peer went away.
                if error.kind() == std::io::ErrorKind::BrokenPipe {
                    return Ok(());
                }
                return Err(error.into());
            }
        };
        let Some(response) = handle_line(server, principal, state, &line) else {
            continue;
        };
        let encoded = encode_response(&response)?;
        writer.write_all(encoded.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }
}

/// Answer one MCP-over-HTTP message, framed for Server-Sent Events.
///
/// `authorization` is the raw `Authorization` header, e.g.
/// `Bearer <token>`. The behaviour is deliberately asymmetric:
///
/// * **no** header ⇒ the message is served as [`Principal::anonymous`], so a read
///   still works (which is what an unauthenticated discovery client needs) and a
///   mutating tool comes back as an `isError` tool result;
/// * a header that is present but does not authenticate anybody ⇒ the whole
///   message is refused with [`error_code::UNAUTHORIZED`], because a client that
///   *tried* to authenticate and failed must not be silently downgraded to
///   anonymous — that is how a revoked credential keeps working for reads and
///   how a misconfiguration goes unnoticed.
///
/// # Errors
///
/// Only serialization failures; every protocol-level outcome is a framed
/// response.
pub fn handle_http_message(
    server: &McpServer,
    authenticator: &Authenticator,
    authorization: Option<&str>,
    state: &mut SessionState,
    message: &str,
) -> Result<Option<String>> {
    let credential = authorization.and_then(Credential::from_authorization_header);
    // A header was sent but did not even parse as a bearer credential.
    if authorization.is_some() && credential.is_none() {
        return Ok(Some(sse_frame(&encode_response(&RpcResponse::err(
            RequestId::Null,
            error_code::UNAUTHORIZED,
            "the `Authorization` header must be `Bearer <token>`",
        ))?)));
    }
    if credential.is_some() {
        if let Err(error) = authenticator.authenticate(credential.as_ref()) {
            // Refuse the whole message: a presented credential that matches
            // nobody is an error, never a downgrade to anonymous.
            return Ok(Some(sse_frame(&encode_response(&RpcResponse::err(
                RequestId::Null,
                error_code::UNAUTHORIZED,
                error.to_string(),
            ))?)));
        }
    }
    let principal = authenticator.principal_or_anonymous(credential.as_ref());
    match handle_line(server, &principal, state, message) {
        Some(response) => Ok(Some(sse_frame(&encode_response(&response)?))),
        // A notification produces no response, so no SSE frame.
        None => Ok(None),
    }
}

/// Format a JSON-RPC payload as a Server-Sent Events frame.
///
/// The MCP HTTP transport sends each message as `event: message` followed by a
/// single `data:` line, terminated by a blank line. Newlines inside `payload`
/// would break the single-line rule, so they are escaped before framing.
pub fn sse_frame(payload: &str) -> String {
    let flattened = payload.replace('\r', "\\r").replace('\n', "\\n");
    format!("event: message\ndata: {flattened}\n\n")
}
