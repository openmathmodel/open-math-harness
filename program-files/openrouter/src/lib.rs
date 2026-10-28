//! OpenRouter adapter: a provider of the `model` interface
//! (`nucleus-model-interface`) backed by OpenRouter's chat completions API.
//!
//! ## Authority and checks
//!
//! Which models this adapter will call is the resource of the capability its
//! caller holds, and nothing else. The model id *is* the resource path, so the
//! kernel has already authorized this exact model against this exact caller
//! before the adapter sees the dispatch.
//!
//! ## Privileges and compromise
//!
//! This program is started with host network access and a read-only bind of
//! the directory holding the API key file. The key is read for every HTTP
//! attempt (the platform may replace it at any connect), sent only as the
//! `Authorization` header to the configured base URL, never written to replies
//! or stderr, and scrubbed from any error text. A request that names the
//! project it is made for also carries `X-Proxy-Tags: project=<name>`, which
//! the proxy records to keep a project that does not take part in training
//! out of its export; nothing else of a request goes in a header, and the tag
//! is logged nowhere here. Redirects are not followed and no proxy is taken
//! from the environment, so the key
//! and request content are never sent to a host chosen by a response or by
//! inherited state. A compromised adapter can spend the key's credit,
//! disclose the key and every prompt it sees to any host, and lie to its
//! callers. It cannot use its callers' capabilities or reach files outside
//! its binds.
//!
//! ## Concurrency: provider slots
//!
//! At most `--max-inflight` HTTP attempts (default 16) are open to the
//! provider at once, `complete` and `start` alike ([`slots`]). A call takes a
//! slot, first come first served, when it is about to send, holds it until its
//! transport is released, and gives it back before a retry's backoff. A stream
//! waiting for a slot tells its puller so with a queue lease
//! ([`nucleus_model_interface::QueueStatus`], renewed every 10 s while it
//! waits); a lease never extends the stream's deadline.
//!
//! A `complete` dispatch is checked in the dispatch loop (model id, request
//! validation; a refusal is answered at once) and then served on a thread of
//! its own, which waits for a slot. The kernel's `max_inflight_per_endpoint`
//! bounds how many dispatches can be here, so nothing grows without bound. A
//! dispatch waiting here has already been authorized and charged by the kernel,
//! whose dispatch-time re-authorization does not reach it: a revocation while
//! it waits is not observed (its deadline and its caller's exit are, through
//! `CancelDispatch`). An operator who wants revocation to hold until the call
//! starts sets `max_inflight_per_endpoint` equal to `--max-inflight`, so the
//! wait happens in the kernel's queue instead. The provider gets the time the
//! caller has left when the call gets its slot, not when it arrives; a dispatch
//! whose wait ate that time is answered `service_error` ("waited … for a
//! provider slot") and not sent — its own deadline was fine when it arrived,
//! and the congestion is this adapter's.
//!
//! `CancelDispatch` for a `complete` stops it within 50 ms wherever it is:
//! waiting for a slot (nothing was sent), in backoff, or in the middle of an
//! attempt, whose connection is then closed. A request already sent cannot be
//! taken back from the provider, so the provider may still finish and charge
//! for it; nobody is left to tell. The thread answers the kernel (which needs
//! the reply to free its in-flight entry) as soon as it has let go of the
//! transport, and its slot passes on.
//!
//! Worker and reader threads talk only to the provider and to internal
//! channels and tables; the dispatch loop remains the only thread that talks
//! to the kernel, and it never waits on a provider or a stream. A worker that
//! dies without an outcome (a panic in the HTTP or JSON layers, or a thread
//! the host would not start) is reported to the kernel as `service_error`;
//! nothing is leaked and the loop does not go down with it.
//!
//! `Terminate` arrives after the kernel has already detached this provider
//! and answered every caller still waiting `unavailable` (the retryable code
//! for an observation). The adapter tells its streams and workers to stop and
//! exits; calls in flight end with the process, and whether the provider
//! completed them is unknown to their callers, as for any lost reply.
//!
//! ## Streaming
//!
//! `start`, `next` and `cancel` are ordinary calls (see the interface crate).
//! Each stream has a reader thread that talks only to the provider and to a
//! bounded buffer ([`streams`]). A stream is tied to the process that started
//! it, ends half a second after the `start` caller's own deadline (capped by
//! `--max-timeout-ms`), and is abandoned if nobody pulls it. Streams count
//! against the provider slots while they are sent, and against their own
//! per-caller bound ([`streams::MAX_STREAMS_PER_CALLER`]) until their reader
//! has ended.
//!
//! `next` and `cancel` are parked off the dispatch loop and answered as soon
//! as there is something to say ([`controls`]). `cancel` stops the reader at
//! once — the reader looks at least every 50 ms, in network waits, retry
//! backoff and buffer backpressure alike — and answers `released: true` when
//! the reader and its connection are gone, or `released: false` after two
//! seconds (less if the caller's deadline is nearer). Released says the
//! transport is done, not that the provider did no work or charged nothing.
//!
//! ## Limits
//!
//! Every provider attempt is bounded by the caller's remaining deadline,
//! capped by `--max-timeout-ms`, and resolving plus connecting by 10 s
//! ([`transport::CONNECT_TIMEOUT`]). A `next` waits at most two seconds, a
//! `cancel` at most two, both inside the caller's own deadline.
//!
//! ## Retries
//!
//! A call retries a *transient* failure up to `--retries` times (default 3),
//! all inside its deadline: a retry that could not finish in time is not made.
//! What failed decides how long the first wait is, because two retryable
//! failures can want opposite waits:
//!
//! - **The provider answered** with a passing condition — 408, 425, 429,
//!   every 5xx, or a 200 whose body is an error object. It is up and asking
//!   for room, so the wait is `--retry-backoff-ms` (default 20 s), doubling.
//! - **The provider could not be reached**, or the connection died having
//!   delivered nothing. The wait starts at 2 s and doubles — at the default
//!   three retries, attempts at 0, 2, 6 and 14 s. That nothing came back does
//!   not prove nothing was done: a request that reached the provider before
//!   the connection died may have been served and charged, and the retry may
//!   be charged again.
//!
//! The second case is sized against the puller's patience rather than the
//! provider's: a `start` whose stream produces nothing for 90 s is cancelled
//! by the prover, and a first wait of 20 s would fit only three attempts
//! inside that window. A 4xx that says the request itself is wrong is not
//! retried, and neither is a refusal of the account
//! (401, 403, and a want of credit, whether it comes as an HTTP 402 or as an
//! error object with that code inside a 200 body or an event of the stream):
//! the person must top up or fix the key, so they are told at once with the
//! provider's message. Each attempt is a fresh HTTP request with the same
//! body; a final error says how many retries it took. There is no request
//! journal: an outcome lost with this process is unknown to its caller, and
//! nothing is replayed.
//!
//! A `start` retries on the same rule, but only while **nothing has reached
//! the consumer**: before the first byte of text or reasoning, a repeated
//! attempt hands the puller nothing twice. Once a byte has been pushed, the
//! attempt is not repeatable and the failure is final. Retries here are
//! bounded in practice by the consumer's own patience: a puller that gives up
//! cancels the stream, which ends the backoff at once.
//!
mod controls;
mod slots;
mod streams;
mod transport;
mod wire;

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use nucleus_model_interface::{
    ACTION_CANCEL, ACTION_COMPLETE, ACTION_NEXT, ACTION_START, CompletionRequest, CompletionResponse,
    MAX_QUEUE_LEASE_MS, StartResponse,
};

use controls::Controls;
use nucleus_protocol::{
    ACTION_PROVIDE, DispatchId, EndpointName, Error, ErrorCode, KERNEL_ENDPOINT, Payload, ProcessId,
};
use nucleus_sdk::{Connection, Dispatch, Event};
pub use slots::{Slot, Slots};
pub use streams::{Feed, Streams};

const DEFAULT_MAX_TIMEOUT_MS: u64 = 120_000;
/// Retries of a transient provider failure unless `--retries` says otherwise.
pub const DEFAULT_RETRIES: u32 = 3;
/// First backoff before a retry; doubles each time.
pub const DEFAULT_RETRY_BACKOFF_MS: u64 = 20_000;
/// HTTP attempts open at once unless `--max-inflight` says otherwise.
pub const DEFAULT_MAX_INFLIGHT: usize = 16;
/// How often the dispatch loop looks for finished calls and answerable
/// parked ones while any exists. Bounds the added latency of a reply.
const REPLY_POLL: Duration = Duration::from_millis(20);
/// Calls with less time left than this are refused rather than started.
const MIN_TIMEOUT_MS: u64 = 1_000;
/// Time kept back from the caller's deadline for the reply to travel.
const REPLY_MARGIN_MS: u64 = 500;
/// How often a stream waiting for a slot renews its queue lease, well inside
/// the lease's own [`MAX_QUEUE_LEASE_MS`].
const LEASE_RENEWAL: Duration = Duration::from_secs(10);
const MAX_KEY_BYTES: u64 = 4096;
/// Whether a failure is worth another attempt, and how soon.
///
/// Two failures that both deserve a retry can want opposite waits. A provider
/// that answered 429 is alive and asking for room, so the wait is long. A
/// provider that could not be reached at all is retried soon, so the retries
/// fit inside the puller's patience (module doc, "Retries").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Again {
    /// Not worth repeating.
    No,
    /// The provider could not be reached, or the connection died with nothing
    /// delivered to the consumer. Repeat quickly. The provider may still have
    /// received, served and charged for the request.
    Soon,
    /// The provider answered with a passing condition of its own. It is up;
    /// give it room.
    Later,
}

impl Again {
    /// The wait before the *first* repeat; it doubles from there.
    fn first_backoff(self, configured: Duration) -> Duration {
        match self {
            Again::Later => configured,
            // At the default three retries, every attempt starts inside the
            // puller's 90 s patience.
            Again::Soon | Again::No => Duration::from_millis(RECONNECT_BACKOFF_MS),
        }
    }
}

/// First wait before reconnecting to a provider that was not reachable; it
/// doubles from there (2, 4, 8 s at the default three retries: attempts at 0,
/// 2, 6 and 14 s). Sized against the puller's own patience, not against a
/// provider.
const RECONNECT_BACKOFF_MS: u64 = 2_000;

/// Whether a failed response with this status is worth a retry: a passing
/// condition of the provider (see the module doc, "Retries").
fn transient_status(status: u16) -> Again {
    if matches!(status, 200 | 408 | 425 | 429) || status >= 500 {
        // The provider answered, so it is up: give it room.
        Again::Later
    } else {
        Again::No
    }
}

/// What an error the provider reported is worth: a want of credit is final
/// whatever envelope it came in; anything else is worth what `otherwise` says.
fn retry_for(error: &Error, otherwise: Again) -> Again {
    if wire::is_credit_refusal(error) { Again::No } else { otherwise }
}

/// An API key. Deliberately has no way to print itself.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// Reads and trims a key file. Refuses empty or implausibly large files.
    pub fn read(path: &std::path::Path) -> Result<Self, String> {
        let size = std::fs::metadata(path).map_err(|e| format!("key file: {e}"))?.len();
        if size > MAX_KEY_BYTES {
            return Err("key file is too large to be an API key".to_owned());
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("key file: {e}"))?;
        let key = text.trim();
        if key.is_empty() || key.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("key file must contain exactly one token".to_owned());
        }
        Ok(Self(key.to_owned()))
    }

    fn scrub(&self, text: &str) -> String {
        text.replace(&self.0, "[redacted]")
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

/// Where each attempt's key comes from. The key file is re-read per attempt so
/// a key the platform replaces takes effect without restarting Nucleus; until
/// the platform has delivered one, model calls fail and the service stays up.
enum KeySource {
    #[cfg(test)]
    Fixed(Secret),
    File(PathBuf),
}

const NO_KEY: &str =
    "no model key: the platform writes the team's key into the VM when it prepares the runtime";

impl KeySource {
    fn current(&self) -> Result<Secret, Error> {
        match self {
            #[cfg(test)]
            Self::Fixed(key) => Ok(key.clone()),
            Self::File(path) => match std::fs::metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Err(Error::new(ErrorCode::Unavailable, NO_KEY))
                }
                Ok(meta) if meta.len() == 0 => Err(Error::new(ErrorCode::Unavailable, NO_KEY)),
                _ => Secret::read(path).map_err(|e| Error::new(ErrorCode::Unavailable, e)),
            },
        }
    }
}

/// Startup options, from the command line. Operator configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub key_file: PathBuf,
    /// One base URL per adapter: a gateway that cannot be reached fails the
    /// call after its retries, and the adapter tries no other URL or key.
    pub base_url: String,
    pub endpoint: EndpointName,
    pub max_timeout_ms: u64,
    /// HTTP attempts open at once, `complete` and `start` together; further
    /// ones wait for a slot in arrival order.
    pub max_inflight: usize,
    /// Retries of a transient failure per call (module doc).
    pub retries: u32,
    pub retry_backoff_ms: u64,
}

impl Options {
    /// Parses `--key-file <file> --base-url <url>
    /// [--endpoint <name>] [--max-timeout-ms <n>]
    /// [--max-inflight <n>] [--retries <n>]
    /// [--retry-backoff-ms <n>]`.
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut key_file = None;
        let mut base_url = None;
        let mut endpoint = nucleus_model_interface::ENDPOINT.to_owned();
        let mut max_timeout_ms = DEFAULT_MAX_TIMEOUT_MS;
        let mut max_inflight = DEFAULT_MAX_INFLIGHT;
        let mut retries = DEFAULT_RETRIES;
        let mut retry_backoff_ms = DEFAULT_RETRY_BACKOFF_MS;
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
            match flag.as_str() {
                "--key-file" => key_file = Some(PathBuf::from(value)),
                "--base-url" => base_url = Some(value.trim_end_matches('/').to_owned()),
                "--endpoint" => endpoint = value,
                "--max-timeout-ms" => {
                    max_timeout_ms = value.parse().map_err(|_| "--max-timeout-ms must be a number")?;
                }
                "--max-inflight" => {
                    max_inflight = value.parse().map_err(|_| "--max-inflight must be a number")?;
                }
                "--retries" => retries = value.parse().map_err(|_| "--retries must be a number")?,
                "--retry-backoff-ms" => {
                    retry_backoff_ms = value.parse().map_err(|_| "--retry-backoff-ms must be a number")?;
                }
                _ => return Err(format!("unknown option {flag}")),
            }
        }
        if max_inflight < 1 {
            return Err("--max-inflight must be at least 1".to_owned());
        }
        if max_timeout_ms < MIN_TIMEOUT_MS {
            return Err(format!("--max-timeout-ms must be at least {MIN_TIMEOUT_MS}"));
        }
        let base_url = base_url.ok_or("--base-url is required")?;
        check_base_url(&base_url)?;
        Ok(Self {
            key_file: key_file.ok_or("--key-file is required")?,
            base_url,
            endpoint: EndpointName::new(endpoint).map_err(|e| e.to_string())?,
            max_timeout_ms,
            max_inflight,
            retries,
            retry_backoff_ms,
        })
    }
}

/// The key must travel over TLS. Plain HTTP is accepted only to a loopback
/// address, which is what tests and local gateways use.
fn check_base_url(url: &str) -> Result<(), String> {
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"].iter().any(|prefix| {
        url.strip_prefix(prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
    });
    if url.starts_with("https://") || loopback {
        Ok(())
    } else {
        Err("--base-url must be https, or http to a loopback address".to_owned())
    }
}

/// The adapter's whole ability to reach the provider.
pub struct Adapter {
    key: KeySource,
    url: String,
    max_timeout_ms: u64,
    retries: u32,
    retry_backoff: Duration,
    slots: Slots,
}

impl Adapter {
    #[cfg(test)]
    pub fn new(options: &Options, key: Secret) -> Self {
        Self::with_key(options, KeySource::Fixed(key))
    }

    /// Reads the key from `options.key_file` for every attempt.
    pub fn from_key_file(options: &Options) -> Self {
        Self::with_key(options, KeySource::File(options.key_file.clone()))
    }

    fn with_key(options: &Options, key: KeySource) -> Self {
        Self {
            key,
            url: format!("{}/chat/completions", options.base_url),
            max_timeout_ms: options.max_timeout_ms,
            retries: options.retries,
            retry_backoff: Duration::from_millis(options.retry_backoff_ms),
            slots: Slots::new(options.max_inflight),
        }
    }

    /// What to call an attempt that ended without an answer from the
    /// provider. `again` is what a failure of the connection is worth.
    fn failed(&self, key: &Secret, failure: transport::Failure, again: Again) -> (Error, Again) {
        use transport::Failure;
        match failure {
            Failure::Deadline => (
                Error::new(ErrorCode::Timeout, "the provider did not finish before the call's deadline"),
                again,
            ),
            Failure::Stopped => (
                Error::new(
                    ErrorCode::Cancelled,
                    "stopped because the caller gave up; whether the provider finished or charged for the \
                     call is unknown",
                ),
                Again::No,
            ),
            Failure::Send { unreachable, detail } => {
                // A provider that could not be reached is named as such, with where it was sought.
                let what = if unreachable {
                    format!("model provider unreachable at {}", self.url)
                } else {
                    "request to provider failed".to_owned()
                };
                (Error::new(ErrorCode::ServiceError, key.scrub(&format!("{what}: {detail}"))), Again::Soon)
            }
            Failure::Limit(detail) => (Error::new(ErrorCode::ServiceError, detail), Again::No),
            Failure::Read(detail) => (
                Error::new(
                    ErrorCode::ServiceError,
                    key.scrub(&format!("reading the provider's response failed: {detail}")),
                ),
                again,
            ),
        }
    }

    /// Time to allow the provider, or an error if the caller left too little.
    pub fn timeout_for(&self, remaining_ms: u64) -> Result<Duration, Error> {
        let budget = remaining_ms.saturating_sub(REPLY_MARGIN_MS).min(self.max_timeout_ms);
        if budget < MIN_TIMEOUT_MS {
            return Err(Error::new(ErrorCode::InvalidInput, "deadline is too short for a model call"));
        }
        Ok(Duration::from_millis(budget))
    }

    /// Sends one request, retrying a transient failure (module doc,
    /// "Retries") within `timeout`, the caller's remaining time.
    #[cfg(test)]
    pub fn complete(
        &self,
        model: &str,
        request: &CompletionRequest,
        timeout: Duration,
    ) -> Result<CompletionResponse, Error> {
        self.complete_from(None, model, request, Instant::now() + timeout, &AtomicBool::new(false))
    }

    /// Sends one request, retrying a transient failure (module doc, "Retries")
    /// until `deadline`, for a caller that may already hold its first slot and
    /// may be cancelled.
    fn complete_from(
        &self,
        mut held: Option<Slot>,
        model: &str,
        request: &CompletionRequest,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<CompletionResponse, Error> {
        let alive = || !cancelled.load(Ordering::Acquire);
        let mut retries = 0;
        // The first wait comes from what failed; later ones double it.
        let mut grown = Duration::ZERO;
        loop {
            let slot = match held.take() {
                Some(slot) => slot,
                None => self.slots.acquire(|| waiting_for_slot(deadline, cancelled))?,
            };
            let attempt = deadline.min(Instant::now() + Duration::from_millis(self.max_timeout_ms));
            let result = self.complete_inner(model, request, attempt, &alive);
            drop(slot);
            let (error, again) = match result {
                Ok(response) => return Ok(response),
                Err(failure) => failure,
            };
            let backoff = if retries == 0 { again.first_backoff(self.retry_backoff) } else { grown };
            let left = deadline.saturating_duration_since(Instant::now());
            let room = backoff + Duration::from_millis(MIN_TIMEOUT_MS);
            if again == Again::No || retries >= self.retries || left < room {
                return Err(after_retries(error, retries));
            }
            pause(backoff, cancelled)?;
            grown = backoff.saturating_mul(2);
            retries += 1;
        }
    }

    /// One attempt, asked for as a stream and assembled here, so that every
    /// `reasoning_details` block a later request must hand back verbatim is
    /// kept, complete and in order ([`wire::StreamAssembler`]).
    ///
    /// A provider that answers a streaming request with an ordinary JSON body
    /// is accepted as it comes (the scripted servers of the tests do this).
    /// The error carries whether it is transient (worth a retry).
    fn complete_inner(
        &self,
        model: &str,
        request: &CompletionRequest,
        deadline: Instant,
        alive: &dyn Fn() -> bool,
    ) -> Result<CompletionResponse, (Error, Again)> {
        let key = self.key.current().map_err(|e| (e, Again::No))?;
        let body = wire::request_body(model, request).to_string();
        let mut exchange =
            transport::post(&self.url, &key, request.project.as_deref(), body, deadline, alive)
                .map_err(|failure| self.failed(&key, failure, Again::Soon))?;
        let status = exchange.status();
        if (300..400).contains(&status) {
            return Err((
                Error::new(ErrorCode::ServiceError, "provider answered with a redirect; not followed"),
                Again::No,
            ));
        }
        // The provider and any explicit output budget govern generation. The
        // caller's deadline bounds the wait; the reply must fit one IPC frame.
        let text = exchange.text(alive).map_err(|failure| self.failed(&key, failure, Again::Soon))?;
        drop(exchange);
        let refused = |e: Error| {
            let again = retry_for(&e, transient_status(status));
            (Error::new(e.code, key.scrub(&e.message)), again)
        };
        if !(200..300).contains(&status) || !text.trim_start().starts_with(['d', ':', 'e']) {
            // An error body, or a provider that ignored `stream` and answered
            // with one JSON object.
            return wire::parse_response(status, &text, model).map_err(refused);
        }
        let mut assembler = wire::StreamAssembler::default();
        for line in text.lines() {
            assembler.feed(line).map_err(refused)?;
        }
        // A stream cut short is a transport failure, which a retry may fix.
        assembler.finish(model).map_err(|e| (Error::new(e.code, key.scrub(&e.message)), Again::Soon))
    }

    /// Serves one stream into its feed until the completion, a failure, its
    /// deadline, or the consumer letting go. Each attempt waits for a slot
    /// first, telling the puller with a queue lease while it waits.
    ///
    /// Retries a transient failure that delivered nothing (module doc,
    /// "Retries").
    pub fn stream(
        &self,
        model: &str,
        request: &CompletionRequest,
        deadline: Instant,
        feed: &Feed,
    ) -> Result<CompletionResponse, Error> {
        let mut retries = 0;
        let mut grown = Duration::ZERO;
        loop {
            if !feed.alive() {
                return Err(stream_over(deadline, "before the next attempt"));
            }
            let mut renew = Instant::now();
            let slot = self.slots.acquire(|| {
                let now = Instant::now();
                if !feed.alive() {
                    return Err(stream_over(deadline, "while it waited for a provider slot"));
                }
                if now >= renew {
                    feed.set_queue(Some(MAX_QUEUE_LEASE_MS));
                    renew = now + LEASE_RENEWAL;
                }
                Ok(())
            })?;
            // Dispatched: whatever lease was given ends here.
            feed.set_queue(None);
            let result = self.stream_inner(model, request, deadline, feed);
            drop(slot);
            let (error, again) = match result {
                Ok(response) => return Ok(response),
                Err(failure) => failure,
            };
            let backoff = if retries == 0 { again.first_backoff(self.retry_backoff) } else { grown };
            let left = deadline.saturating_duration_since(Instant::now());
            let room = backoff + Duration::from_millis(MIN_TIMEOUT_MS);
            if again == Again::No || retries >= self.retries || left < room {
                return Err(after_retries(error, retries));
            }
            if !feed.wait_for_retry(backoff) {
                return Err(stream_over(deadline, "during retry backoff"));
            }
            grown = backoff.saturating_mul(2);
            retries += 1;
        }
    }

    fn stream_inner(
        &self,
        model: &str,
        request: &CompletionRequest,
        deadline: Instant,
        feed: &Feed,
    ) -> Result<CompletionResponse, (Error, Again)> {
        // True once a byte has reached the consumer. From that moment the
        // attempt cannot be repeated: the puller already holds text a second
        // attempt would send again.
        let mut delivered = false;
        let alive = || feed.alive();
        let key = self.key.current().map_err(|e| (e, Again::No))?;
        let body = wire::request_body(model, request).to_string();
        let mut exchange =
            transport::post(&self.url, &key, request.project.as_deref(), body, deadline, &alive)
                .map_err(|failure| self.failed(&key, failure, Again::Soon))?;
        let status = exchange.status();
        if (300..400).contains(&status) {
            return Err((
                Error::new(ErrorCode::ServiceError, "provider answered with a redirect; not followed"),
                Again::No,
            ));
        }
        if !(200..300).contains(&status) {
            // Preserve the HTTP status retry policy if reading the error
            // body fails. A local size-limit failure remains final as well.
            let text = exchange
                .text(&alive)
                .map_err(|failure| self.failed(&key, failure, transient_status(status)))?;
            return wire::parse_response(status, &text, model).map_err(|e| {
                let again = retry_for(&e, transient_status(status));
                (Error::new(e.code, key.scrub(&e.message)), again)
            });
        }
        let mut assembler = wire::StreamAssembler::default();
        // The transport bounds unconsumed provider bytes. The assembler stores
        // reply fragments separately; the requested token budget is enforced
        // by the provider, not a local bound on assembler memory.
        let (mut thought, mut called) = (0, 0);
        while let Some(line) =
            exchange.line(&alive).map_err(|failure| self.failed(&key, failure, again(delivered)))?
        {
            let added = assembler.feed(&line).map_err(|e| {
                let again = retry_for(&e, again(delivered));
                (Error::new(e.code, key.scrub(&e.message)), again)
            })?;
            // Only explicitly readable reasoning is displayed. It also moves
            // the progress counter, even before any answer arrives. Tool
            // calls reach the consumer only whole, but their fragments are
            // output too: counted, or a long tool call looks like a stall.
            let (now, bytes) = (assembler.reasoning_text().len(), assembler.tool_call_bytes());
            if now > thought || bytes > called {
                let alive = feed.push_reasoning(&assembler.reasoning_text()[thought..], bytes - called);
                delivered |= now > thought;
                (thought, called) = (now, bytes);
                if !alive {
                    return Err(ended(deadline));
                }
            }
            if let Some(text) = added {
                delivered = true;
                if !feed.push(&text) {
                    return Err(ended(deadline));
                }
            }
        }
        assembler.finish(model).map_err(|e| (e, again(delivered)))
    }
}

/// The checks `complete` and `start` share: model id and request validation.
/// Nothing is sent here.
fn check(dispatch: &Dispatch) -> Result<(String, CompletionRequest), Error> {
    // The model is the resource the kernel already authorized this caller for:
    // a capability on `["deepseek"]` is what makes `deepseek/...` callable and
    // anything else `permission_denied`, before this code runs.
    let model = nucleus_model_interface::model_id(&dispatch.resource)?;
    let request: CompletionRequest = dispatch.payload.decode()?;
    request.validate()?;
    Ok((model, request))
}

/// A `complete` dispatch that passed its checks. Carries the caller's
/// absolute deadline so the provider gets the time actually left when the
/// call gets its slot, not when the dispatch arrived.
pub struct Job {
    caller: ProcessId,
    model: String,
    request: CompletionRequest,
    deadline: Instant,
    /// When the dispatch arrived, so a wait for a slot can be named for what it was.
    offered: Instant,
    /// Set by the dispatch loop when the kernel withdraws the dispatch.
    cancelled: Arc<AtomicBool>,
}

impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The request holds the prompt, which does not belong in a log.
        write!(f, "Job(caller {}, model {})", self.caller, self.model)
    }
}

impl Job {
    /// Checks a `complete` dispatch. A refusal here is answered at once.
    pub fn prepare(adapter: &Adapter, dispatch: &Dispatch) -> Result<Self, Error> {
        // Refuse a hopeless deadline now rather than after a wait; it is checked again at start.
        adapter.timeout_for(dispatch.remaining_ms)?;
        let (model, request) = check(dispatch)?;
        let now = Instant::now();
        Ok(Self {
            caller: dispatch.caller,
            model,
            request,
            deadline: now + Duration::from_millis(dispatch.remaining_ms),
            offered: now,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Waits for a slot and makes the call. Runs on a worker thread; touches
    /// the provider and nothing else.
    pub fn run(self, adapter: &Adapter) -> Result<Payload, Error> {
        let slot = adapter.slots.acquire(|| waiting_for_slot(self.deadline, &self.cancelled))?;
        let now = Instant::now();
        let remaining_ms = millis(self.deadline.saturating_duration_since(now));
        // The deadline was acceptable when the dispatch arrived (`prepare`); if it is not now, the
        // wait for a slot here is what consumed it, and that is this adapter's failure, not bad input.
        let timeout = adapter.timeout_for(remaining_ms).map_err(|_| {
            Error::new(
                ErrorCode::ServiceError,
                format!(
                    "waited {} ms for a provider slot; {remaining_ms} ms left is too little for a model call",
                    millis(now.saturating_duration_since(self.offered))
                ),
            )
        })?;
        let response =
            adapter.complete_from(Some(slot), &self.model, &self.request, now + timeout, &self.cancelled)?;
        Payload::encode(&response)
    }
}

/// The check a `complete` runs while it waits for a slot. The caller's
/// deadline ends the wait through the kernel, which answers the caller
/// `timeout` and withdraws the dispatch; the adapter's own look at it, a
/// reply margin later, only keeps a withdrawal that never came from
/// stranding the thread.
fn waiting_for_slot(deadline: Instant, cancelled: &AtomicBool) -> Result<(), Error> {
    if cancelled.load(Ordering::Acquire) {
        Err(cancelled_before_start())
    } else if Instant::now() >= deadline + Duration::from_millis(REPLY_MARGIN_MS) {
        Err(Error::new(
            ErrorCode::ServiceError,
            "the deadline passed while the call waited for a provider slot",
        ))
    } else {
        Ok(())
    }
}

/// A retry's backoff for a `complete`, ended early by cancellation.
fn pause(backoff: Duration, cancelled: &AtomicBool) -> Result<(), Error> {
    let until = Instant::now() + backoff;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(Error::new(ErrorCode::Cancelled, "cancelled during retry backoff"));
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(());
        }
        std::thread::sleep(left.min(slots::POLL));
    }
}

/// A final error that says how many retries came before it.
fn after_retries(error: Error, retries: u32) -> Error {
    if retries == 0 {
        error
    } else {
        Error::new(error.code, format!("{} (after {retries} retries)", error.message))
    }
}

/// Whether a stream that failed may be attempted again: only while nothing
/// has reached the consumer, because a second attempt would resend it.
fn again(delivered: bool) -> Again {
    if delivered { Again::No } else { Again::Soon }
}

/// Why a stream is no longer wanted, when its feed says so.
fn stream_over(deadline: Instant, when: &str) -> Error {
    if Instant::now() >= deadline {
        Error::new(ErrorCode::Timeout, format!("the model stream reached its deadline {when}"))
    } else {
        Error::new(ErrorCode::Cancelled, format!("the stream was cancelled or abandoned {when}"))
    }
}

/// The consumer let go, or the deadline passed, while the stream was running.
/// Not repeatable: there is no one left to hand a second attempt to.
fn ended(deadline: Instant) -> (Error, Again) {
    if Instant::now() >= deadline {
        (Error::new(ErrorCode::Timeout, "the model stream reached its deadline"), Again::No)
    } else {
        (Error::new(ErrorCode::ServiceError, "stream abandoned by its consumer"), Again::No)
    }
}

fn cancelled_before_start() -> Error {
    Error::new(ErrorCode::Cancelled, "cancelled before the provider was contacted")
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Handles `start` (and refuses unknown actions) on the dispatch loop. It
/// only registers the stream and starts its reader; nothing here waits.
pub fn serve(adapter: &Arc<Adapter>, streams: &Streams, dispatch: &Dispatch) -> Result<Payload, Error> {
    if dispatch.action.as_str() != ACTION_START {
        return Err(Error::new(ErrorCode::InvalidInput, "unknown action"));
    }
    // The puller keeps its own deadline and cancels when it passes; the
    // stream's own, a reply margin later, only ends a stream nobody cancels.
    let lifetime = dispatch.remaining_ms.saturating_add(REPLY_MARGIN_MS).min(adapter.max_timeout_ms);
    let deadline = Instant::now() + Duration::from_millis(lifetime);
    // Reserve the stream first: a request that cannot be served is not sent.
    let (stream, feed) = streams.open(dispatch.caller, deadline)?;
    let (model, request) = match check(dispatch) {
        Ok(checked) => checked,
        Err(e) => {
            drop(feed);
            streams.cancel(dispatch.caller, &stream);
            return Err(e);
        }
    };
    let reader = Arc::clone(adapter);
    let spawned = std::thread::Builder::new().name("model-stream".to_owned()).spawn(move || {
        let result = reader.stream(&model, &request, deadline, &feed);
        feed.finish(result);
    });
    if let Err(e) = spawned {
        // The closure, and the feed with it, was dropped unrun: nothing sent.
        streams.cancel(dispatch.caller, &stream);
        return Err(Error::new(ErrorCode::ServiceError, format!("could not start a stream reader: {e}")));
    }
    Payload::encode(&StartResponse { stream })
}

/// What a worker thread hands back: the dispatch it served and its outcome.
type Finished = (DispatchId, Result<Payload, Error>);

/// A worker's obligation to report, honoured even when the worker does not
/// get to the end: dropped without [`Report::done`] (a panic on the way), it
/// reports a `service_error`, so the kernel is answered.
pub struct Report {
    dispatch: DispatchId,
    to: Sender<Finished>,
    sent: bool,
}

impl Report {
    pub fn new(dispatch: DispatchId, to: Sender<Finished>) -> Self {
        Self { dispatch, to, sent: false }
    }

    /// The normal path: the outcome the worker produced.
    pub fn done(mut self, result: Result<Payload, Error>) {
        self.sent = true;
        // A closed channel means the loop is gone; there is nobody to tell.
        let _ = self.to.send((self.dispatch, result));
    }
}

impl Drop for Report {
    fn drop(&mut self) {
        if !self.sent {
            let failed = Error::new(ErrorCode::ServiceError, "worker failed before producing an outcome");
            let _ = self.to.send((self.dispatch, Err(failed)));
        }
    }
}

/// The `complete` workers, as the loop sees them: one thread per dispatch,
/// each with the flag that withdraws it.
struct Workers {
    adapter: Arc<Adapter>,
    running: BTreeMap<DispatchId, Arc<AtomicBool>>,
    report: Sender<Finished>,
    finished: Receiver<Finished>,
}

impl Workers {
    fn new(adapter: Arc<Adapter>) -> Self {
        let (report, finished) = mpsc::channel();
        Self { adapter, running: BTreeMap::new(), report, finished }
    }

    /// Runs `job` on a thread of its own. However the worker ends — outcome,
    /// panic, or a thread the host refused to start — exactly one report for
    /// `dispatch` reaches the loop's channel.
    fn submit(&mut self, dispatch: DispatchId, job: Job) -> Result<(), Error> {
        if self.running.contains_key(&dispatch) {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "a dispatch with this id is already being served",
            ));
        }
        self.running.insert(dispatch, Arc::clone(&job.cancelled));
        let (adapter, report) = (Arc::clone(&self.adapter), self.report.clone());
        let spawned = std::thread::Builder::new().name("complete".to_owned()).spawn(move || {
            // First thing, before anything that can panic.
            let report = Report::new(dispatch, report);
            report.done(job.run(&adapter));
        });
        if let Err(e) = spawned {
            // The closure, and the job with it, was dropped unrun: nothing sent.
            let failed = Error::new(ErrorCode::ServiceError, format!("could not start a worker thread: {e}"));
            let _ = self.report.send((dispatch, Err(failed)));
        }
        Ok(())
    }

    /// The kernel withdrew `dispatch`: its worker stops within 50 ms and
    /// reports. Unknown and finished ids change nothing.
    fn withdraw(&self, dispatch: DispatchId) {
        if let Some(cancelled) = self.running.get(&dispatch) {
            cancelled.store(true, Ordering::Release);
        }
    }

    fn stop_all(&self) {
        for cancelled in self.running.values() {
            cancelled.store(true, Ordering::Release);
        }
    }
}

type Kernel = Connection<std::io::Stdin, std::io::Stdout>;

/// Answers every finished or answerable call the loop has not yet answered.
fn answer_ready(kernel: &mut Kernel, workers: &mut Workers, controls: &mut Controls) -> Result<(), String> {
    for (dispatch, result) in controls.ready() {
        kernel.reply(dispatch, result).map_err(|e| e.to_string())?;
    }
    while let Ok((dispatch, result)) = workers.finished.try_recv() {
        kernel.reply(dispatch, result).map_err(|e| e.to_string())?;
        workers.running.remove(&dispatch);
    }
    Ok(())
}

/// Provides the endpoint and serves dispatches until told to terminate.
pub fn run(options: &Options) -> Result<(), String> {
    let adapter = Arc::new(Adapter::from_key_file(options));
    let streams = Streams::default();
    let mut controls = Controls::new(streams.clone());
    let mut workers = Workers::new(Arc::clone(&adapter));
    let mut kernel = Connection::from_stdio().map_err(|e| e.to_string())?;
    let authority = kernel
        .find_handle(KERNEL_ENDPOINT, ACTION_PROVIDE)
        .ok_or("started without authority to provide an endpoint")?;
    let interface =
        nucleus_model_interface::interface(options.endpoint.clone()).map_err(|e| e.to_string())?;
    kernel.provide(authority, interface).map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;

    loop {
        answer_ready(&mut kernel, &mut workers, &mut controls)?;
        // With nothing in flight or parked nothing can become answerable, so wait for the kernel alone.
        let event = if workers.running.is_empty() && controls.is_empty() {
            kernel.next_event().map_err(|e| e.to_string())?
        } else {
            match kernel.next_event_within(REPLY_POLL).map_err(|e| e.to_string())? {
                Some(event) => event,
                None => continue,
            }
        };
        match event {
            Event::Dispatch(dispatch) if dispatch.action.as_str() == ACTION_COMPLETE => {
                if let Err(e) =
                    Job::prepare(&adapter, &dispatch).and_then(|job| workers.submit(dispatch.id, job))
                {
                    kernel.reply(dispatch.id, Err(e)).map_err(|e| e.to_string())?;
                }
            }
            Event::Dispatch(dispatch) if matches!(dispatch.action.as_str(), ACTION_NEXT | ACTION_CANCEL) => {
                if let Err(e) = controls.park(&dispatch, REPLY_MARGIN_MS) {
                    kernel.reply(dispatch.id, Err(e)).map_err(|e| e.to_string())?;
                }
            }
            Event::Dispatch(dispatch) => {
                let result = serve(&adapter, &streams, &dispatch);
                kernel.reply(dispatch.id, result).map_err(|e| e.to_string())?;
            }
            Event::CancelDispatch(dispatch) => {
                // A parked call is answered here; a `complete` answers from its worker once it stopped.
                if controls.withdraw(dispatch) {
                    let withdrawn = Error::new(ErrorCode::Cancelled, "the caller withdrew the call");
                    kernel.reply(dispatch, Err(withdrawn)).map_err(|e| e.to_string())?;
                } else {
                    workers.withdraw(dispatch);
                }
            }
            Event::ChildExited(_) | Event::ChildReaped { .. } => {}
            // The kernel detached this provider and answered every caller
            // before `Terminate`. Nothing waiting was sent; calls in flight
            // end with the process.
            Event::Terminate => {
                streams.stop_all();
                workers.stop_all();
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests;
