//! `nau-plugin-echo` — a real process plugin, so the process runtime has something
//! real to point at.
//!
//! It reads one [length-prefixed frame](nau_plugins::frame) from stdin, answers with
//! one on stdout, and exits. That is the whole plugin: it exists to make the host ABI
//! concrete — a file on disk that `nau_plugin::runtime::ProcessRuntime` can be
//! started against, and that an end-to-end test can talk to — rather than to be
//! useful.
//!
//! # Protocol
//!
//! ```text
//! stdin:  u32_be(len) || {"abi":"2.2","id":"req-1","op":"echo","payload":{…}}
//! stdout: u32_be(len) || {"abi":"2.2","id":"req-1","plugin":"io.example.echo",
//!                         "version":"1.2.3","ok":true,"payload":{…}}
//! ```
//!
//! Operations: `echo` answers with the request payload unchanged; `ping` answers with
//! `{"pong": true}`. An unknown operation, an incompatible `abi` or a payload that is
//! not a request is answered with `ok: false` and a machine-readable code — never
//! with an empty success.
//!
//! Exit codes: `0` answered, `1` answered with `ok: false`, `2` the frame itself could
//! not be read or written. The distinction matters to a host: `2` means the plugin is
//! not speaking this ABI at all, which is a different repair from "the plugin refused
//! the call".
//!
//! stderr is the plugin's own log and is not part of the protocol. Everything this
//! binary writes to stdout is a frame, so a host may parse the stream without
//! filtering it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::io::{Read, Write};
use std::process::ExitCode;

use nau_plugins::frame::{self, Response};
use serde_json::json;

/// Exit code: the call was answered and succeeded.
const EXIT_OK: u8 = 0;
/// Exit code: the call was answered with a refusal.
const EXIT_REFUSED: u8 = 1;
/// Exit code: no frame could be read or written.
const EXIT_IO: u8 = 2;

fn main() -> ExitCode {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    ExitCode::from(run(&mut input, &mut output))
}

/// Read one request, answer it, and report the exit code.
fn run<R: Read, W: Write>(input: &mut R, output: &mut W) -> u8 {
    let payload = match frame::read_frame(input) {
        Ok(Some(payload)) => payload,
        Ok(None) => {
            // A clean EOF before any frame: nothing was asked, so nothing is refused.
            eprintln!("nau-plugin-echo: no request on stdin");
            return EXIT_IO;
        }
        Err(err) => {
            eprintln!("nau-plugin-echo: {err}");
            return EXIT_IO;
        }
    };

    let request = match frame::decode_request(&payload) {
        Ok(request) => request,
        Err(err) => {
            // The frame was readable but not a request: answer with the refusal, so a
            // host sees a typed code rather than a dead process.
            let response = Response::refused(
                "",
                frame::ECHO_PLUGIN,
                env!("CARGO_PKG_VERSION"),
                frame::CODE_NOT_JSON,
                &err.to_string(),
            );
            return report(output, &response, EXIT_REFUSED);
        }
    };

    if !request.abi_is_compatible() {
        let response = Response::refused(
            &request.id,
            frame::ECHO_PLUGIN,
            env!("CARGO_PKG_VERSION"),
            frame::CODE_ABI_MISMATCH,
            &format!(
                "this plugin speaks {} and was asked for {}",
                frame::abi_version(),
                request.abi
            ),
        );
        return report(output, &response, EXIT_REFUSED);
    }

    let response = match request.op.as_str() {
        "echo" => Response::ok(
            &request,
            frame::ECHO_PLUGIN,
            env!("CARGO_PKG_VERSION"),
            request.payload.clone(),
        ),
        "ping" => Response::ok(
            &request,
            frame::ECHO_PLUGIN,
            env!("CARGO_PKG_VERSION"),
            json!({ "pong": true }),
        ),
        other => Response::refused(
            &request.id,
            frame::ECHO_PLUGIN,
            env!("CARGO_PKG_VERSION"),
            nau_plugins::payload::CODE_UNKNOWN_OPERATION,
            &format!(
                "`{}` implements echo and ping, not `{other}`",
                frame::ECHO_PLUGIN
            ),
        ),
    };
    let code = if response.ok { EXIT_OK } else { EXIT_REFUSED };
    report(output, &response, code)
}

/// Write the response frame and return `fallback` unless the write failed.
fn report<W: Write>(output: &mut W, response: &Response, fallback: u8) -> u8 {
    let encoded = match serde_json::to_vec(response) {
        Ok(encoded) => encoded,
        Err(err) => {
            eprintln!("nau-plugin-echo: cannot encode the response: {err}");
            return EXIT_IO;
        }
    };
    match frame::write_frame(output, &encoded) {
        Ok(()) => fallback,
        Err(err) => {
            eprintln!("nau-plugin-echo: cannot write the response frame: {err}");
            EXIT_IO
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_plugins::frame::{decode_response, Request};

    fn request_bytes(op: &str, abi: &str) -> Vec<u8> {
        let mut wire = Vec::new();
        let request = Request {
            abi: abi.to_string(),
            id: "req-1".into(),
            op: op.to_string(),
            payload: json!({ "hello": "world" }),
        };
        frame::write_frame(&mut wire, &serde_json::to_vec(&request).expect("encodes"))
            .expect("writes");
        wire
    }

    /// Run one call and return the exit code with the decoded response.
    fn call(op: &str, abi: &str) -> (u8, Response) {
        let bytes = request_bytes(op, abi);
        let mut input = bytes.as_slice();
        let mut output = Vec::new();
        let code = run(&mut input, &mut output);
        let payload = frame::read_frame(&mut output.as_slice())
            .expect("reads")
            .expect("one frame");
        (code, decode_response(&payload).expect("decodes"))
    }

    #[test]
    fn echo_returns_the_payload_and_the_version() {
        let (code, response) = call("echo", &frame::abi_version());
        assert_eq!(code, EXIT_OK);
        assert!(response.ok);
        assert_eq!(response.plugin, frame::ECHO_PLUGIN);
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(response.id, "req-1");
        assert_eq!(response.payload.expect("payload")["hello"], json!("world"));
    }

    #[test]
    fn ping_answers_pong() {
        let (code, response) = call("ping", &frame::abi_version());
        assert_eq!(code, EXIT_OK);
        assert_eq!(response.payload.expect("payload")["pong"], json!(true));
    }

    #[test]
    fn an_unknown_operation_is_refused_with_a_code() {
        let (code, response) = call("sing", &frame::abi_version());
        assert_eq!(code, EXIT_REFUSED);
        assert!(!response.ok);
        assert_eq!(
            response.code.as_deref(),
            Some(nau_plugins::payload::CODE_UNKNOWN_OPERATION)
        );
    }

    #[test]
    fn an_incompatible_abi_is_refused_rather_than_guessed() {
        let (code, response) = call("echo", "9.0");
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(frame::CODE_ABI_MISMATCH));
        assert!(response.message.expect("message").contains("9.0"));
    }

    #[test]
    fn a_payload_that_is_not_a_request_is_refused_and_a_clean_eof_is_not_a_refusal() {
        // A well-framed payload that is not a request: the plugin answers with a
        // typed code instead of dying.
        let mut wire = Vec::new();
        frame::write_frame(&mut wire, b"not json at all").expect("writes");
        let mut output = Vec::new();
        let code = run(&mut wire.as_slice(), &mut output);
        assert_eq!(code, EXIT_REFUSED);
        let payload = frame::read_frame(&mut output.as_slice())
            .expect("reads")
            .expect("one frame");
        assert_eq!(
            decode_response(&payload).expect("decodes").code.as_deref(),
            Some(frame::CODE_NOT_JSON)
        );

        let mut output = Vec::new();
        assert_eq!(run(&mut &[][..], &mut output), EXIT_IO);
        assert!(
            output.is_empty(),
            "nothing is written when nothing was asked"
        );
    }

    #[test]
    fn a_frame_that_cannot_be_read_leaves_the_stdout_stream_untouched() {
        let mut output = Vec::new();
        let code = run(&mut &[0x00, 0xA0, 0x00, 0x00][..], &mut output);
        assert_eq!(code, EXIT_IO);
        assert!(output.is_empty());
    }
}
