//! The host ABI frame: one length-prefixed JSON envelope in, one out.
//!
//! ```text
//! frame   := length-prefix || payload
//! length-prefix := 4 bytes, big-endian unsigned, the payload length
//! payload := UTF-8 JSON, one of [`Request`] or [`Response`], at most
//!            MAX_FRAME_BYTES bytes
//! ```
//!
//! # Why a length prefix rather than a newline
//!
//! A JSON envelope may legitimately contain a newline inside a string, so a
//! newline-delimited protocol needs an escaping rule, and an escaping rule is a
//! second parser that can disagree with the first. A 4-byte big-endian length is the
//! whole grammar, and it is the same framing `nau-sandbox` already uses for bounded
//! capture — so a host that has learned one has learned the other.
//!
//! # The two refusals that matter
//!
//! * an oversized frame is refused **from its prefix**, before a buffer for it is
//!   allocated: a plugin that announces four gigabytes must not be able to make the
//!   host ask for four gigabytes;
//! * a truncated frame is refused as truncated rather than accepted as a short one,
//!   because "the writer died halfway" and "the writer sent less" are different
//!   facts and only one of them is a protocol error.
//!
//! # Additive within a major
//!
//! The envelopes deliberately do **not** use `deny_unknown_fields`, unlike the
//! manifest schema. The kernel accepts an older ABI minor because the bus is
//! additive within a major ([`nau_plugin::ABI_MINOR`]); if the frame refused unknown
//! keys, adding an optional field would break every deployed plugin and the
//! additive promise would be false. The `abi` field is what governs compatibility,
//! and it is checked explicitly rather than inferred from the keys present.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use nau_plugin::{PluginError, Result};

/// Largest accepted frame payload, in bytes (1 MiB).
pub const MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Width of the length prefix, in bytes.
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// The plugin name the `nau-plugin-echo` binary reports.
pub const ECHO_PLUGIN: &str = "io.example.echo";

/// Error code: the declared length is zero.
pub const CODE_EMPTY: &str = "abi_payload_empty";
/// Error code: the declared length exceeds [`MAX_FRAME_BYTES`].
pub const CODE_TOO_LARGE: &str = "abi_frame_too_large";
/// Error code: the stream ended inside a frame.
pub const CODE_TRUNCATED: &str = "abi_frame_truncated";
/// Error code: the payload is not UTF-8 JSON of the expected envelope.
pub const CODE_NOT_JSON: &str = "abi_payload_not_json";
/// Error code: the request declares an ABI this build does not speak.
pub const CODE_ABI_MISMATCH: &str = "abi_version_mismatch";

/// The ABI version string this build speaks, `major.minor`.
#[must_use]
pub fn abi_version() -> String {
    format!("{}.{}", nau_plugin::ABI_MAJOR, nau_plugin::ABI_MINOR)
}

/// One call into a process plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// The ABI the caller speaks, `major.minor`.
    pub abi: String,
    /// A caller-chosen correlation id, echoed in the response. Not required to be a
    /// UUID: a host may use any string it can match up.
    #[serde(default)]
    pub id: String,
    /// The operation.
    pub op: String,
    /// The operation's arguments. `null` when the operation takes none.
    #[serde(default)]
    pub payload: Value,
}

impl Request {
    /// Whether this request declares an ABI this build can serve.
    ///
    /// The rule is the kernel's: the same major, and a minor no newer than this
    /// build's. A newer minor is refused because an older plugin cannot know what it
    /// added.
    #[must_use]
    pub fn abi_is_compatible(&self) -> bool {
        let expected = abi_version();
        if self.abi == expected {
            return true;
        }
        match (parse_abi(&self.abi), parse_abi(&expected)) {
            (Some((major, minor)), Some((host_major, host_minor))) => {
                major == host_major && minor <= host_minor
            }
            _ => false,
        }
    }
}

/// One answer from a process plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// The ABI the plugin speaks.
    pub abi: String,
    /// The id of the request this answers.
    #[serde(default)]
    pub id: String,
    /// The plugin that answered.
    pub plugin: String,
    /// The plugin's own version.
    pub version: String,
    /// Whether the call succeeded.
    pub ok: bool,
    /// The answer, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// The machine-readable refusal code, when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// The refusal in prose, when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Response {
    /// A successful answer.
    #[must_use]
    pub fn ok(request: &Request, plugin: &str, version: &str, payload: Value) -> Self {
        Self {
            abi: abi_version(),
            id: request.id.clone(),
            plugin: plugin.to_string(),
            version: version.to_string(),
            ok: true,
            payload: Some(payload),
            code: None,
            message: None,
        }
    }

    /// A refusal: `ok: false` with a code, never an empty success.
    #[must_use]
    pub fn refused(id: &str, plugin: &str, version: &str, code: &str, message: &str) -> Self {
        Self {
            abi: abi_version(),
            id: id.to_string(),
            plugin: plugin.to_string(),
            version: version.to_string(),
            ok: false,
            payload: None,
            code: Some(code.to_string()),
            message: Some(message.to_string()),
        }
    }
}

/// Encode one frame: a big-endian length prefix followed by the payload.
///
/// # Errors
///
/// [`CODE_EMPTY`] for an empty payload (a frame that carries nothing is a bug on the
/// writer's side, not an empty message), [`CODE_TOO_LARGE`] beyond
/// [`MAX_FRAME_BYTES`].
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() {
        return Err(crate::payload::protocol(
            CODE_EMPTY,
            "a frame must carry a payload",
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|_| {
        crate::payload::protocol(
            CODE_TOO_LARGE,
            format!(
                "a payload of {} bytes cannot be framed; the maximum is {MAX_FRAME_BYTES}",
                payload.len()
            ),
        )
    })?;
    if length > MAX_FRAME_BYTES {
        return Err(crate::payload::protocol(
            CODE_TOO_LARGE,
            format!("{length} bytes exceeds the {MAX_FRAME_BYTES}-byte cap"),
        ));
    }
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(payload);
    Ok(framed)
}

/// Write one frame and flush it.
///
/// # Errors
///
/// As [`encode_frame`], plus [`PluginError::Io`] when the write fails. The flush is
/// inside this function on purpose: a plugin that forgets to flush and exits looks
/// exactly like a plugin that crashed.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let framed = encode_frame(payload)?;
    writer.write_all(&framed)?;
    writer.flush()?;
    Ok(())
}

/// Read one frame.
///
/// Returns `Ok(None)` when the stream ended cleanly before the first byte of a
/// length prefix — "there is no next request", which is not an error.
///
/// # Errors
///
/// [`CODE_TRUNCATED`] when the stream ends inside a frame, [`CODE_EMPTY`] for a
/// zero-length frame, [`CODE_TOO_LARGE`] when the declared length exceeds
/// [`MAX_FRAME_BYTES`] (refused from the prefix, before the buffer is allocated),
/// and [`PluginError::Io`] for a read failure.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
    if !read_prefix(reader, &mut prefix)? {
        return Ok(None);
    }
    let length = u32::from_be_bytes(prefix);
    if length == 0 {
        return Err(crate::payload::protocol(
            CODE_EMPTY,
            "a zero-length frame carries no payload",
        ));
    }
    if length > MAX_FRAME_BYTES {
        return Err(crate::payload::protocol(
            CODE_TOO_LARGE,
            format!(
                "the frame declares {length} bytes, more than the {MAX_FRAME_BYTES}-byte cap; \
                 refused from its length prefix, before any buffer was allocated for it"
            ),
        ));
    }
    let mut payload = vec![0u8; usize::try_from(length).unwrap_or(0)];
    reader.read_exact(&mut payload).map_err(|e| {
        crate::payload::protocol(
            CODE_TRUNCATED,
            format!("the frame declared {length} bytes but the stream ended early: {e}"),
        )
    })?;
    Ok(Some(payload))
}

/// Parse a JSON payload into a [`Request`].
///
/// # Errors
///
/// [`CODE_NOT_JSON`] when the bytes are not a JSON [`Request`].
pub fn decode_request(payload: &[u8]) -> Result<Request> {
    serde_json::from_slice(payload)
        .map_err(|e| crate::payload::protocol(CODE_NOT_JSON, format!("this is not a request: {e}")))
}

/// Parse a JSON payload into a [`Response`].
///
/// # Errors
///
/// [`CODE_NOT_JSON`] when the bytes are not a JSON [`Response`].
pub fn decode_response(payload: &[u8]) -> Result<Response> {
    serde_json::from_slice(payload).map_err(|e| {
        crate::payload::protocol(CODE_NOT_JSON, format!("this is not a response: {e}"))
    })
}

/// Fill `prefix`, returning `false` when the stream ended before its first byte.
fn read_prefix<R: Read>(reader: &mut R, prefix: &mut [u8; LENGTH_PREFIX_BYTES]) -> Result<bool> {
    let mut filled = 0usize;
    while filled < prefix.len() {
        match reader.read(&mut prefix[filled..]) {
            // A clean EOF at the frame boundary; anything else is truncation.
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => {
                return Err(crate::payload::protocol(
                    CODE_TRUNCATED,
                    format!(
                        "the stream ended {filled} bytes into a {LENGTH_PREFIX_BYTES}-byte length \
                         prefix"
                    ),
                ))
            }
            Ok(read) => filled += read,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(PluginError::Io(e)),
        }
    }
    Ok(true)
}

/// Parse `major.minor`.
fn parse_abi(text: &str) -> Option<(u32, u32)> {
    let (major, minor) = text.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> Request {
        Request {
            abi: abi_version(),
            id: "req-1".into(),
            op: "echo".into(),
            payload: json!({ "hello": "world" }),
        }
    }

    #[test]
    fn a_frame_round_trips_through_a_stream() {
        let payload = serde_json::to_vec(&request()).expect("encodes");
        let mut wire = Vec::new();
        write_frame(&mut wire, &payload).expect("writes");
        assert_eq!(&wire[..4], &(payload.len() as u32).to_be_bytes());

        let mut reader = wire.as_slice();
        let read = read_frame(&mut reader).expect("reads").expect("one frame");
        assert_eq!(read, payload);
        assert!(
            read_frame(&mut reader).expect("clean eof").is_none(),
            "the second read is a clean EOF, not an error"
        );
    }

    #[test]
    fn an_oversized_frame_is_refused_from_its_prefix() {
        // Ten mebibytes announced, four bytes supplied: the refusal must come from
        // the prefix, which is why the error is `too_large` and not `truncated`.
        let mut reader: &[u8] = &[0x00, 0xA0, 0x00, 0x00];
        let err = read_frame(&mut reader).expect_err("must be refused");
        assert!(err.to_string().contains(CODE_TOO_LARGE), "{err}");
    }

    #[test]
    fn a_truncated_frame_is_refused_rather_than_shortened() {
        let mut wire = encode_frame(b"{\"a\":1}").expect("encodes");
        wire.truncate(wire.len() - 2);
        let err = read_frame(&mut wire.as_slice()).expect_err("must be refused");
        assert!(err.to_string().contains(CODE_TRUNCATED), "{err}");

        // A stream that ends inside the length prefix is truncated too.
        let err = read_frame(&mut &[0u8, 0, 0][..]).expect_err("must be refused");
        assert!(err.to_string().contains(CODE_TRUNCATED), "{err}");
    }

    #[test]
    fn an_empty_payload_is_refused_in_both_directions() {
        assert!(encode_frame(b"").is_err());
        let err = read_frame(&mut &[0u8, 0, 0, 0][..]).expect_err("must be refused");
        assert!(err.to_string().contains(CODE_EMPTY), "{err}");
    }

    #[test]
    fn an_empty_stream_is_not_an_error() {
        assert!(read_frame(&mut &[][..]).expect("clean eof").is_none());
    }

    #[test]
    fn the_abi_rule_is_the_kernels() {
        let mut r = request();
        assert!(r.abi_is_compatible());
        r.abi = "2.0".into();
        assert!(r.abi_is_compatible(), "an older minor is accepted");
        r.abi = "2.9".into();
        assert!(!r.abi_is_compatible(), "a newer minor is refused");
        r.abi = "3.0".into();
        assert!(!r.abi_is_compatible(), "a different major is refused");
        r.abi = "two.two".into();
        assert!(!r.abi_is_compatible());
    }

    #[test]
    fn a_refusal_response_carries_a_code_and_no_payload() {
        let response = Response::refused("req-1", ECHO_PLUGIN, "1.2.3", CODE_NOT_JSON, "nope");
        assert!(!response.ok);
        assert_eq!(response.code.as_deref(), Some(CODE_NOT_JSON));
        assert!(response.payload.is_none());
        let text = serde_json::to_string(&response).expect("encodes");
        assert!(text.contains(CODE_NOT_JSON), "{text}");
    }

    #[test]
    fn a_well_formed_response_round_trips_and_a_bad_one_is_refused() {
        let response = Response::ok(&request(), ECHO_PLUGIN, "1.2.3", json!({ "echoed": true }));
        let bytes = serde_json::to_vec(&response).expect("encodes");
        assert_eq!(decode_response(&bytes).expect("decodes"), response);
        let err = decode_response(b"{\"not\":\"a response\"}").expect_err("must be refused");
        assert!(err.to_string().contains(CODE_NOT_JSON), "{err}");
        assert!(decode_request(b"[]").is_err());
    }

    #[test]
    fn the_echo_plugin_name_is_a_third_party_name() {
        // It must classify as T3, because that is the tier the process runtime
        // accepts and the end-to-end test starts it at.
        assert_eq!(
            nau_plugin::Tier::from_name(ECHO_PLUGIN).expect("classifies"),
            nau_plugin::Tier::ThirdParty
        );
    }
}
