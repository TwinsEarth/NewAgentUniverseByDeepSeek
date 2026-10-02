//! `com.twinsearth.sys.http` — one GET, through `nau-http`.
//!
//! # The bridge, stated rather than hidden
//!
//! `nau-http`'s transport port is **asynchronous**: `Transport::execute` is an
//! `async fn` over `tokio::net::TcpStream`, `tokio::time::timeout` and `mpsc`, and the
//! crate's own docs say the runtime is the caller's business ("No runtime is started
//! here"). This framework is the opposite: [`SystemPlugin::handle`] is synchronous
//! and [`crate::host`] states there is no async runtime in it.
//!
//! So this plugin owns the bridge, and owns it explicitly:
//!
//! * a **current-thread `tokio` runtime is built per call, on a worker thread**, and
//!   the boxed request future is driven there with `Runtime::block_on`;
//! * the worker thread exists because `Runtime::block_on` from inside another
//!   runtime's context panics, and a T0 plugin is called from wherever the host
//!   happens to be. A panic cannot escape this door: the thread's `join` is matched,
//!   and a worker that died becomes a typed [`CODE_TRANSPORT_PANICKED`] refusal
//!   instead of taking the host's stack with it;
//! * a no-op-waker poll (the pattern `nau-mcp` uses for an in-process dispatcher) is
//!   deliberately **not** used here: a future waiting on a socket never becomes ready
//!   without a reactor, so polling once would turn every real request into a
//!   random-looking refusal.
//!
//! The cost is one thread and one runtime per request, and it is a real cost — stated
//! here because it is the price of a synchronous plugin using an asynchronous client.
//!
//! # Bounded, because a plugin must not be able to hang the host
//!
//! | Bound | Value | Where it comes from |
//! |---|---|---|
//! | connect timeout | [`CONNECT_TIMEOUT`] (2 s) | `nau_http::TcpTransportBuilder::connect_timeout` |
//! | read timeout | [`READ_TIMEOUT`] (5 s) | `nau_http::TcpTransportBuilder::read_timeout` |
//! | response body | [`MAX_RESPONSE_BODY`] (1 MiB) | `nau_http::TcpTransportBuilder::max_body` |
//!
//! The response head keeps `nau-http`'s own 64 KiB cap by default. A body over the
//! cap is `HttpError::BodyTooLarge`, a refusal, never a silent truncation.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `get` | `url` | `url`, `scheme`, `host`, `port`, `tls`, `status`, `body_len`, `content_type`, `exchange` |
//! | `precheck` | `url` | `url`, `scheme`, `host`, `port`, `path`, `tls`, `host_header`, `connect_attempted` |
//!
//! `get` requires the request to declare `net:gossip:publish`, and `precheck` requires
//! `plugin:message:send`. **The `net:gossip:publish` declaration is a placeholder, and
//! saying so is part of the design**: this capability model has no `net:egress`, so
//! the choice is between naming a network capability that this plugin does not
//! literally exercise and opening an arbitrary-URL fetch to every holder of the basic
//! set. `net:gossip:publish` is the system tier's outbound-network declaration
//! (`Capability::decision` grants it to `Tier::System` and refuses it to the
//! third-party tier), and it gates the door on the *caller's* token — the bus checks
//! it before delivery and [`PluginGrant::require_operation`] checks it again here.
//! A caller reading `net:gossip:publish` on this plugin should read it as "outbound
//! network, system tier", which is what it is being used for.
//!
//! A non-2xx status is **not** a refusal: the exchange completed and the status is the
//! caller's business, which is `nau-http`'s documented rule. Only a transport or
//! protocol fault is an `Err` — and a `https://` URL in a build without nau-http's
//! `tls` feature is refused by name (`HttpError::TlsDisabled`), never downgraded to
//! plain TCP.

use std::io;
use std::time::Duration;

use nau_http::{HttpError, HttpRequest, HttpResponse, ParsedUrl, TcpTransport, Transport};
use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginError, PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: the transport or the protocol refused the exchange.
pub const CODE_HTTP: &str = "http_refused";
/// Error code: the URL is one `nau-http` cannot speak, refused before any socket.
pub const CODE_URL_INVALID: &str = "http_url_invalid";
/// Error code: the plugin's runtime could not be built.
pub const CODE_NO_EXECUTOR: &str = "http_executor_unavailable";
/// Error code: the transport panicked on its worker thread.
pub const CODE_TRANSPORT_PANICKED: &str = "http_transport_panicked";

/// The operations this plugin implements, for the unknown-operation refusal.
pub const OPERATIONS: &[&str] = &["get", "precheck"];

/// Longest a connection attempt may take before it is refused by name.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Longest a single read may make no progress before it is refused by name.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest response body this door will accept (1 MiB).
///
/// Smaller than `nau_http::DEFAULT_MAX_BODY` (8 MiB) on purpose: the answer reports a
/// length, not a payload, so a megabyte is already far more than the answer needs, and
/// a plugin should not be able to make the host hold eight.
pub const MAX_RESPONSE_BODY: usize = 1 << 20;

/// The HTTP system plugin.
pub struct HttpPlugin {
    id: PluginId,
    grant: PluginGrant,
    transport: Box<dyn Transport>,
}

impl HttpPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.http";

    /// The capabilities the plugin declares: the basic set, plus
    /// `net:gossip:publish` as the outbound-network declaration the `get` operation
    /// requires of its callers. See the module documentation for why that
    /// capability, and what it does and does not mean here.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::GossipPublish,
    ];

    /// Build the plugin with `nau-http`'s real TCP transport, bounded by
    /// [`CONNECT_TIMEOUT`], [`READ_TIMEOUT`] and [`MAX_RESPONSE_BODY`].
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] if [`HttpPlugin::ID`] is not a valid plugin name, and
    /// [`PluginError::Runtime`] if the bounded transport cannot be built (a zero
    /// timeout or a zero body cap), which cannot happen for these constants.
    pub fn new() -> Result<Self> {
        // `nau_http::TcpTransportBuilder`: `connect_timeout`/`read_timeout`/`max_body`
        // are the crate's own knobs, applied here and validated together by `build`.
        let transport = TcpTransport::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .max_body(MAX_RESPONSE_BODY)
            .build()
            .map_err(|error| http_error(CODE_HTTP, error))?;
        Self::with_transport(Box::new(transport))
    }

    /// Build the plugin over a caller-supplied transport.
    ///
    /// This is the seam a host uses to compile in a different execution path, and the
    /// seam this crate's tests use to answer without opening a socket.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] if [`HttpPlugin::ID`] is not a valid plugin name.
    pub fn with_transport(transport: Box<dyn Transport>) -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            transport,
        })
    }
}

impl SystemPlugin for HttpPlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        ctx.log(
            LogLevel::Info,
            &format!(
                "http ready: GET through nau-http (connect {}s, read {}s, body {} bytes), driven \
                 synchronously by a per-call runtime; https needs nau-http's `tls` feature",
                CONNECT_TIMEOUT.as_secs(),
                READ_TIMEOUT.as_secs(),
                MAX_RESPONSE_BODY
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        // 1. The message's declared capability must be one this plugin holds. The bus
        //    checks this too, and it is repeated here because a T0 plugin is
        //    in-process: the refusal must not depend on which door was used.
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            // 2. Egress is the operation that asks the caller for the network
            //    capability; a pure URL parse does not.
            "get" => {
                self.grant
                    .require_operation(declared, Capability::GossipPublish)?;
                self.get(&msg.payload)
            }
            "precheck" => {
                self.grant
                    .require_operation(declared, Capability::MessageSend)?;
                self.precheck(&msg.payload)
            }
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        // Nothing to release: the transport holds no connection between calls (one
        // connection per request, always `Connection: close`), and giving up the grant
        // is what makes a call after shutdown a typed refusal rather than one that
        // still has authority behind it.
        self.grant.release();
        Ok(())
    }
}

impl HttpPlugin {
    /// `get`: one GET, answered with the status and the body length.
    ///
    /// # Errors
    ///
    /// [`CODE_URL_INVALID`] for a URL `nau-http` cannot speak, then whatever the
    /// transport reports under [`CODE_HTTP`]. A non-2xx status is an answer.
    fn get(&self, request: &Value) -> Result<Value> {
        let url = payload::string_field(request, "url")?;
        // `parse_url` first, so a URL this client cannot speak is refused before a
        // socket exists — and it is nau-http's own rule, not a second copy of it.
        let parsed =
            nau_http::parse_url(url).map_err(|error| http_error(CODE_URL_INVALID, error))?;
        let response = self.execute(HttpRequest::get(url))?;
        Ok(payload::answer(
            Self::ID,
            "get",
            json!({
                "url": url,
                "scheme": &parsed.scheme,
                "host": &parsed.host,
                "port": parsed.port,
                "tls": parsed.tls,
                "status": response.status,
                "body_len": response.body.len(),
                "content_type": response.headers.get("content-type"),
                "exchange": "completed",
            }),
        ))
    }

    /// `precheck`: validate a URL with `nau-http`'s parser, and dial nothing.
    ///
    /// # Errors
    ///
    /// [`CODE_URL_INVALID`] naming the parse failure.
    fn precheck(&self, request: &Value) -> Result<Value> {
        let url = payload::string_field(request, "url")?;
        let parsed: ParsedUrl =
            nau_http::parse_url(url).map_err(|error| http_error(CODE_URL_INVALID, error))?;
        // Computed before the fields are read, so the borrow of `parsed` is whole.
        let host_header = parsed.host_header();
        Ok(payload::answer(
            Self::ID,
            "precheck",
            json!({
                "url": url,
                "scheme": &parsed.scheme,
                "host": &parsed.host,
                "port": parsed.port,
                "path": &parsed.path,
                "tls": parsed.tls,
                "host_header": host_header,
                "connect_attempted": false,
            }),
        ))
    }

    /// Drive one request to completion on a runtime this plugin owns.
    fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
        let transport: &dyn Transport = self.transport.as_ref();
        // Built here and moved to the worker: a `Runtime` is `Send`, and creating one
        // is legal anywhere — it is `block_on` *inside* another runtime's context that
        // panics, which is why the drive happens on a thread of this plugin's own. The
        // failure to build is this plugin's, not the transport's, so it is named
        // separately from a transport refusal.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                refused(
                    CODE_NO_EXECUTOR,
                    format!("the plugin's runtime could not be built: {error}"),
                )
            })?;
        let outcome = std::thread::scope(|scope| {
            let worker = scope.spawn(move || runtime.block_on(transport.execute(request)));
            worker.join()
        });
        match outcome {
            Ok(result) => result.map_err(|error| http_error(CODE_HTTP, error)),
            Err(_panicked) => Err(refused(
                CODE_TRANSPORT_PANICKED,
                "the transport panicked on the plugin's worker thread; the host's stack was not \
                 taken with it",
            )),
        }
    }
}

/// Map a transport failure onto the kernel's error taxonomy.
///
/// A connect or I/O failure keeps [`PluginError::Io`], so a caller can see that it is
/// retryable (`PluginError::is_retryable`); a protocol fault is a
/// [`PluginError::Runtime`]. Either way the message begins with the code, so a caller
/// can branch on it without matching prose.
fn http_error(code: &str, error: HttpError) -> PluginError {
    let detail = format!("{code}: {error}");
    match error {
        HttpError::Io(source) | HttpError::Connect { source, .. } => {
            PluginError::Io(io::Error::new(source.kind(), detail))
        }
        _ => PluginError::Runtime(detail),
    }
}

/// Build a named refusal from anything that reports a failure.
fn refused(code: &str, detail: impl std::fmt::Display) -> PluginError {
    PluginError::Runtime(format!("{code}: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostLimits, SystemPluginHost};
    use nau_http::CannedTransport;
    use nau_plugin::bus::{PmbKind, Target};
    use nau_plugin::lifecycle::PluginState;
    use nau_plugin::{CapabilityToken, Tier};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NOW: u64 = 1_750_000_000;
    /// The host's own T0 publisher key seed, as `tests/common/mod.rs` documents it.
    const HOST_SEED: u8 = 3;
    /// The trusted vendor key seed that counter-signs a system manifest.
    const VENDOR_SEED: u8 = 9;

    fn token(caps: &[Capability]) -> CapabilityToken {
        CapabilityToken::issue(HttpPlugin::ID, Tier::System, caps, DIGEST, NOW).expect("issuable")
    }

    /// The plugin, initialised through the framework with `caps`.
    fn plugin(caps: &[Capability]) -> HttpPlugin {
        let mut plugin = HttpPlugin::new().expect("valid id");
        let mut ctx = HostContext::new(token(caps), HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    /// The plugin over a transport that answers without a socket.
    fn canned(status: u16, body: &[u8]) -> HttpPlugin {
        let transport = CannedTransport::new(status, Vec::new(), body.to_vec());
        let mut plugin = HttpPlugin::with_transport(Box::new(transport)).expect("valid id");
        let mut ctx =
            HostContext::new(token(HttpPlugin::CAPABILITIES), HostLimits::default()).expect("ctx");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.sys.policy").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(HttpPlugin::ID.to_string()),
            Capability::parse(capability).expect("known capability"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    #[test]
    fn the_plugin_registers_reaches_running_and_preflights_a_url_without_dialling() {
        let verified = crate::sign::verified_system(
            HttpPlugin::ID,
            HttpPlugin::CAPABILITIES,
            &crate::sign::fixture_key(HOST_SEED),
            &crate::sign::fixture_key(VENDOR_SEED),
        )
        .expect("a system manifest verifies");
        let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
        host.register(
            Box::new(HttpPlugin::new().expect("valid id")),
            &verified,
            NOW,
        )
        .expect("registers");
        host.init(HttpPlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(HttpPlugin::ID), Some(PluginState::Running));

        let answer = host
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "precheck", "url": "http://127.0.0.1:1/a?b=c#frag" }),
            ))
            .expect("answers");
        assert_eq!(answer["scheme"], json!("http"));
        assert_eq!(answer["host"], json!("127.0.0.1"));
        assert_eq!(answer["port"], json!(1));
        assert_eq!(answer["path"], json!("/a?b=c"));
        assert_eq!(answer["host_header"], json!("127.0.0.1:1"));
        assert_eq!(answer["connect_attempted"], json!(false));
    }

    #[test]
    fn a_request_out_of_capability_is_refused_by_name() {
        let mut plugin = plugin(HttpPlugin::CAPABILITIES);
        let err = plugin
            .handle(&request(
                "net:dht:write",
                json!({ "op": "get", "url": "http://127.0.0.1:1/" }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains("net:dht:write"), "{err}");

        // Held, but declared for the operation that is not its door: `get` names the
        // outbound-network placeholder it needs.
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "get", "url": "http://127.0.0.1:1/" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("net:gossip:publish"), "{text}");
    }

    #[test]
    fn a_get_to_an_unreachable_address_returns_the_clients_typed_refusal() {
        let mut plugin = plugin(HttpPlugin::CAPABILITIES);
        // `127.0.0.1:1` is loopback and cannot be connected to in CI: the assertion is
        // on the *typed refusal*, never on a successful fetch, so nothing here depends
        // on outbound connectivity. A host transport that answered would be a protocol
        // error, which is also this code — the assertion does not depend on which.
        let err = plugin
            .handle(&request(
                "net:gossip:publish",
                json!({ "op": "get", "url": "http://127.0.0.1:1/" }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains(CODE_HTTP), "{err}");
    }

    #[test]
    fn a_wired_transport_is_executed_and_its_status_and_body_length_are_reported() {
        let mut plugin = canned(200, b"hello world");
        let answer = plugin
            .handle(&request(
                "net:gossip:publish",
                json!({ "op": "get", "url": "http://agents.example.invalid/card" }),
            ))
            .expect("answers");
        assert_eq!(answer["status"], json!(200));
        assert_eq!(answer["body_len"], json!(11));
        assert_eq!(answer["exchange"], json!("completed"));

        // A non-2xx status is a completed exchange, not a refusal.
        let mut plugin = canned(404, b"");
        let answer = plugin
            .handle(&request(
                "net:gossip:publish",
                json!({ "op": "get", "url": "http://agents.example.invalid/missing" }),
            ))
            .expect("answers");
        assert_eq!(answer["status"], json!(404));
        assert_eq!(answer["body_len"], json!(0));
    }

    #[test]
    fn a_url_this_client_cannot_speak_is_refused_before_any_socket() {
        let mut plugin = plugin(HttpPlugin::CAPABILITIES);
        for url in ["ftp://example.invalid/x", "not-a-url", "http://user@host/x"] {
            let err = plugin
                .handle(&request(
                    "plugin:message:send",
                    json!({ "op": "precheck", "url": url }),
                ))
                .expect_err("must be refused");
            assert!(err.to_string().contains(CODE_URL_INVALID), "{err}");

            // The same refusal on `get`: the URL is parsed before the transport runs,
            // so no socket is opened for a URL this client cannot speak.
            let err = plugin
                .handle(&request(
                    "net:gossip:publish",
                    json!({ "op": "get", "url": url }),
                ))
                .expect_err("must be refused");
            assert!(err.to_string().contains(CODE_URL_INVALID), "{err}");
        }

        // ...and a URL that parses is answered, still without a socket.
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "precheck", "url": "https://agents.example.invalid:8443/x" }),
            ))
            .expect("answers");
        assert_eq!(answer["tls"], json!(true));
        assert_eq!(answer["port"], json!(8443));
    }

    /// A transport that panics, to prove the worker-thread boundary holds.
    ///
    /// Implemented by hand rather than with `async_trait`, which is not a dependency
    /// of this crate: the desugared signature is what the trait declares.
    struct PanickingTransport;

    impl Transport for PanickingTransport {
        // The desugared `#[async_trait]` signature, verbatim: this crate does not
        // depend on `async-trait`, so the lifetime bounds are spelled out here.
        fn execute<'lifecycle, 'async_trait>(
            &'lifecycle self,
            _request: HttpRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = nau_http::Result<HttpResponse>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'lifecycle: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { panic!("this transport panics on purpose") })
        }
    }

    #[test]
    fn a_panicking_transport_becomes_a_typed_refusal_rather_than_a_host_panic() {
        let mut plugin =
            HttpPlugin::with_transport(Box::new(PanickingTransport)).expect("valid id");
        let mut ctx =
            HostContext::new(token(HttpPlugin::CAPABILITIES), HostLimits::default()).expect("ctx");
        plugin.init(&mut ctx).expect("inits");
        let err = plugin
            .handle(&request(
                "net:gossip:publish",
                json!({ "op": "get", "url": "http://agents.example.invalid/" }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains(CODE_TRANSPORT_PANICKED), "{err}");
    }

    #[test]
    fn the_bridge_holds_when_the_host_dispatches_from_inside_a_runtime() {
        // The case the worker thread exists for: a host that calls `handle` from
        // inside its own tokio runtime. A `block_on` on the caller's thread would
        // panic there; the plugin's own thread does not.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let mut plugin = canned(200, b"ok");
        let answer = runtime
            .block_on(async {
                plugin.handle(&request(
                    "net:gossip:publish",
                    json!({ "op": "get", "url": "http://agents.example.invalid/" }),
                ))
            })
            .expect("answers");
        assert_eq!(answer["status"], json!(200));
        assert_eq!(answer["body_len"], json!(2));
    }
}
