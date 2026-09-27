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

use nau_core::Result;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::server::{encode_response, handle_line, McpServer, SessionState};

/// Serve newline-delimited JSON-RPC until EOF.
///
/// One request per line, one response per line. Empty lines are skipped. A
/// notification (a request with no `id`) produces no response. A line that is not
/// JSON produces a `-32700` parse-error response carrying `id: null`.
///
/// Returns `Ok(())` at end of input, so a caller can treat a closed pipe as a
/// clean shutdown rather than an error.
pub async fn serve_stdio<R, W>(
    server: &McpServer,
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
        let Some(response) = handle_line(server, state, &line) else {
            continue;
        };
        let encoded = encode_response(&response)?;
        writer.write_all(encoded.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
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
