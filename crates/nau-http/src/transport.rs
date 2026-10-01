//! The transport port, plus a deterministic test double.
//!
//! The port exists so that the provider layer can be tested without a network
//! while the production path is a real socket. Upstream v2.5.6 had neither: it
//! had no HTTP client, and its six providers were `Mock*Client`s returning fixed
//! strings, so nothing above them could be tested against a real wire shape and
//! nothing in production ever reached a provider.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;

use crate::error::{HttpError, Result};
use crate::message::{HttpRequest, HttpResponse};

/// Something that can execute an [`HttpRequest`].
///
/// Implementations are `Send + Sync` because a provider holds one and is itself
/// shared behind `&self`.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send `request` and read the response.
    ///
    /// A non-2xx status is **not** an error: the exchange succeeded, so the
    /// response is returned inside `Ok`. Only connection, timeout, framing and
    /// TLS faults are `Err`.
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse>;
}

/// A deterministic transport that answers with pre-loaded responses and records
/// every request it was handed.
///
/// This is the only test double in the crate, and its name says so: it is not a
/// vendor adapter, it opens no socket, and it never invents a response. Tests
/// assert on the recorded requests, so a provider's headers and body are checked
/// byte for byte.
#[derive(Debug, Default)]
pub struct RecordingTransport {
    inner: Mutex<Inner>,
}

/// Mutable state of a [`RecordingTransport`].
#[derive(Debug, Default)]
struct Inner {
    responses: VecDeque<HttpResponse>,
    requests: Vec<HttpRequest>,
}

impl RecordingTransport {
    /// A transport with no queued responses.
    pub fn new() -> Self {
        Self::default()
    }

    /// A transport that answers, in order, with `responses`.
    pub fn with_responses(responses: Vec<HttpResponse>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                responses: responses.into_iter().collect(),
                requests: Vec::new(),
            }),
        }
    }

    /// Queue one more response.
    pub fn push_response(&self, response: HttpResponse) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.responses.push_back(response);
        }
    }

    /// Every request seen so far, in call order.
    ///
    /// A poisoned mutex yields whatever was recorded before the panic rather
    /// than panicking again: a test double must not be the thing that fails.
    pub fn requests(&self) -> Vec<HttpRequest> {
        lock(&self.inner).requests.clone()
    }

    /// The `n`-th request seen, counted from zero.
    pub fn request(&self, n: usize) -> Option<HttpRequest> {
        lock(&self.inner).requests.get(n).cloned()
    }

    /// How many requests have been executed.
    pub fn call_count(&self) -> usize {
        lock(&self.inner).requests.len()
    }

    /// How many responses are still queued.
    pub fn remaining(&self) -> usize {
        lock(&self.inner).responses.len()
    }
}

/// Lock `mutex`, recovering the payload from a poisoned guard.
///
/// Recovering is deliberate: this crate forbids panics outside `#[cfg(test)]`,
/// and a mutex poisoned by an unrelated panic must not turn into a second one.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[async_trait]
impl Transport for RecordingTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
        let mut inner = lock(&self.inner);
        inner.requests.push(request);
        inner.responses.pop_front().ok_or(HttpError::MalformedHead(
            "RecordingTransport has no queued response left".to_string(),
        ))
    }
}

/// A transport that answers everything with the same byte string, for tests that
/// care about the raw wire form.
#[derive(Debug, Clone)]
pub struct CannedTransport {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
}

impl CannedTransport {
    /// A transport answering `status` with `headers` and `body`.
    pub fn new(status: u16, headers: Vec<(String, String)>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers,
            body: body.into(),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Every request this transport has answered.
    pub fn requests(&self) -> Vec<HttpRequest> {
        lock(&self.requests).clone()
    }
}

#[async_trait]
impl Transport for CannedTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
        lock(&self.requests).push(request);
        let mut headers = crate::message::Headers::new();
        for (name, value) in &self.headers {
            headers.push(name.clone(), value.clone());
        }
        Ok(HttpResponse {
            status: self.status,
            headers,
            body: self.body.clone(),
        })
    }
}
