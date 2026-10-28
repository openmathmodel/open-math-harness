//! One HTTP exchange with the provider, as blocking calls over an owned
//! current-thread Tokio runtime.
//!
//! Every attempt builds its own client and runtime and drops both when it
//! ends, so an attempt that is given up leaves no connection, task or pooled
//! socket behind: when [`Exchange`] is dropped the transport is released. The
//! one exception is a name lookup that has not returned: it is abandoned, not
//! waited for ([`Runtime`]).
//! The client speaks HTTP/1 only, follows no redirect (a redirect would send
//! the key and the prompt wherever the response points), uses no proxy from
//! the environment for the same reason, keeps no idle connection, and bounds
//! resolving and connecting (TLS included) by [`CONNECT_TIMEOUT`].
//!
//! Every wait — resolving, connecting, headers, each read of the body — is
//! also bounded by the attempt's absolute deadline and by the caller's `alive`
//! check, both looked at every [`CHECK_EVERY`]. The runtime only runs inside
//! those waits; between them the connection is not read, which is the
//! backpressure a slow consumer puts on the provider.

use std::collections::VecDeque;
use std::future::Future;
use std::time::{Duration, Instant};

use crate::Secret;

/// Bound on resolving the provider's name and opening the connection to it
/// (TLS handshake included), so that a provider whose packets vanish fails
/// all four attempts of a call (the default three retries) inside the 90 s a
/// puller waits.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a wait looks at its deadline and its caller's `alive` check.
pub const CHECK_EVERY: Duration = Duration::from_millis(50);
/// Maximum unconsumed provider bytes held across queued response lines.
const MAX_PENDING_BYTES: usize = 8 << 20;
/// Maximum body bytes collected for a non-streaming completion or error.
const MAX_TEXT_BYTES: usize = 16 << 20;

/// Why an exchange stopped without an answer from the provider.
#[derive(Debug)]
pub enum Failure {
    /// The attempt's deadline passed first.
    Deadline,
    /// The caller's `alive` check said stop.
    Stopped,
    /// The request could not be sent. `unreachable` is set when the provider
    /// could not be reached at all (name, route, refusal, connect bound).
    Send { unreachable: bool, detail: String },
    /// The response broke off while it was being read.
    Read(String),
    /// A provider response exceeded a local memory-safety limit; do not retry.
    Limit(&'static str),
}

/// A request that reached the provider and got a status line back. Dropping
/// it closes the connection and stops the runtime.
pub struct Exchange {
    // Field order is drop order: the response (and its connection) before
    // the runtime that drives it.
    response: reqwest::Response,
    runtime: Runtime,
    deadline: Instant,
    /// Body bytes read but not yet handed out as a line.
    pending: VecDeque<u8>,
    /// Bytes of the current unterminated line already searched for '\n'.
    scanned: usize,
    ended: bool,
}

/// Sends one `POST` of `body` with the key as a bearer token, and the
/// project the call is made for as `X-Proxy-Tags: project=<name>` when it
/// names one, and waits for the status line.
pub fn post(
    url: &str,
    key: &Secret,
    project: Option<&str>,
    body: String,
    deadline: Instant,
    alive: &dyn Fn() -> bool,
) -> Result<Exchange, Failure> {
    let client =
        client().build().map_err(|e| unsent(format!("cannot build the transport: {}", chain(&e))))?;
    send(&client, url, key, project, body, deadline, alive)
}

/// The client of every attempt (module doc).
fn client() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .http1_only()
        .pool_max_idle_per_host(0)
        .connect_timeout(CONNECT_TIMEOUT)
}

fn unsent(detail: String) -> Failure {
    Failure::Send { unreachable: false, detail }
}

/// [`post`] through `client`.
fn send(
    client: &reqwest::Client,
    url: &str,
    key: &Secret,
    project: Option<&str>,
    body: String,
    deadline: Instant,
    alive: &dyn Fn() -> bool,
) -> Result<Exchange, Failure> {
    let runtime = Runtime::new().map_err(|e| unsent(format!("cannot start the transport: {e}")))?;
    let mut request = client
        .post(url)
        .header("Authorization", format!("Bearer {}", key.0))
        .header("Content-Type", "application/json")
        .header("Accept", "text/event-stream");
    if let Some(project) = project {
        request = request.header("X-Proxy-Tags", format!("project={project}"));
    }
    let request = request.body(body).send();
    let response = runtime.drive(request, deadline, alive)?.map_err(|e| Failure::Send {
        // Name resolution, routing, refusal and the connect bound all
        // surface as connect errors.
        unreachable: e.is_connect() || e.is_timeout(),
        detail: chain(&e),
    })?;
    Ok(Exchange { response, runtime, deadline, pending: VecDeque::new(), scanned: 0, ended: false })
}

impl Exchange {
    pub fn status(&self) -> u16 {
        self.response.status().as_u16()
    }

    /// The next line of the body without its line ending, or `None` at the
    /// end. A last line without a line ending is still a line. At most
    /// MAX_PENDING_BYTES unconsumed response bytes are retained. A deque
    /// avoids shifting the rest of a large chunk for every short SSE line.
    pub fn line(&mut self, alive: &dyn Fn() -> bool) -> Result<Option<String>, Failure> {
        loop {
            if let Some(line) = next_line(&mut self.pending, &mut self.scanned) {
                return text(&line).map(Some);
            }
            if self.ended {
                if self.pending.is_empty() {
                    return Ok(None);
                }
                let line: Vec<u8> = self.pending.drain(..).collect();
                self.scanned = 0;
                return text(&line).map(Some);
            }
            match self.runtime.drive(self.response.chunk(), self.deadline, alive)? {
                Ok(Some(chunk)) => append_pending(&mut self.pending, &chunk)?,
                Ok(None) => self.ended = true,
                Err(e) => return Err(Failure::Read(chain(&e))),
            }
        }
    }

    /// The rest of the body as text, for error bodies and one-object answers.
    pub fn text(&mut self, alive: &dyn Fn() -> bool) -> Result<String, Failure> {
        let mut all = String::new();
        while let Some(line) = self.line(alive)? {
            append_text_line(&mut all, &line)?;
        }
        Ok(all)
    }
}

fn text(line: &[u8]) -> Result<String, Failure> {
    let line = std::str::from_utf8(line)
        .map_err(|_| Failure::Read("the provider sent a line that is not UTF-8".to_owned()))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_owned())
}

/// Drain a complete response line, searching only bytes added since the last
/// unsuccessful search. This makes a long line arriving one byte per chunk
/// linear in its length instead of repeatedly scanning its prefix.
fn next_line(pending: &mut VecDeque<u8>, scanned: &mut usize) -> Option<Vec<u8>> {
    debug_assert!(*scanned <= pending.len());
    match pending.range(*scanned..).position(|byte| *byte == b'\n') {
        Some(relative) => {
            let end = *scanned + relative + 1;
            *scanned = 0;
            Some(pending.drain(..end).collect())
        }
        None => {
            *scanned = pending.len();
            None
        }
    }
}

/// Refuse to retain more response bytes than the buffer holds. Reqwest has
/// already allocated each chunk; this bounds the adapter's pending deque,
/// not all process memory.
fn append_pending(pending: &mut VecDeque<u8>, chunk: &[u8]) -> Result<(), Failure> {
    if chunk.len() > MAX_PENDING_BYTES.saturating_sub(pending.len()) {
        return Err(Failure::Limit("provider response buffer exceeds 8 MiB"));
    }
    pending.extend(chunk.iter().copied());
    Ok(())
}

/// Apply a separate total limit when the whole response is collected.
fn append_text_line(all: &mut String, line: &str) -> Result<(), Failure> {
    if line.len().saturating_add(1) > MAX_TEXT_BYTES.saturating_sub(all.len()) {
        return Err(Failure::Limit("provider response body exceeds 16 MiB"));
    }
    all.push_str(line);
    all.push('\n');
    Ok(())
}

/// An attempt's runtime, shut down without waiting when it is dropped.
///
/// A runtime dropped the ordinary way waits, without a bound, for its
/// blocking pool, and that is where the resolver runs the system's name
/// lookup (`getaddrinfo`). An attempt given up while a lookup hangs would
/// then end when the system resolver gives up, tens of seconds later, holding
/// its caller, its provider slot and the release a `cancel` reports. Instead
/// the lookup is abandoned: it ends on its own thread, and its answer goes
/// unused. Nothing had been sent.
struct Runtime(Option<tokio::runtime::Runtime>);

impl Runtime {
    fn new() -> std::io::Result<Self> {
        Ok(Self(Some(tokio::runtime::Builder::new_current_thread().enable_all().build()?)))
    }

    /// Runs `work` until it finishes, the deadline passes or `alive` says
    /// stop, whichever is first; looks at the last two every [`CHECK_EVERY`].
    fn drive<F: Future>(
        &self,
        work: F,
        deadline: Instant,
        alive: &dyn Fn() -> bool,
    ) -> Result<F::Output, Failure> {
        // Only a runtime that is being dropped has none.
        let Some(runtime) = &self.0 else { return Err(Failure::Stopped) };
        runtime.block_on(async {
            let mut work = std::pin::pin!(work);
            loop {
                let now = Instant::now();
                if now >= deadline {
                    return Err(Failure::Deadline);
                }
                if !alive() {
                    return Err(Failure::Stopped);
                }
                let slice = CHECK_EVERY.min(deadline - now);
                if let Ok(done) = tokio::time::timeout(slice, work.as_mut()).await {
                    return Ok(done);
                }
            }
        })
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

/// An error with its causes, which is where reqwest says what actually failed.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};

    use super::*;

    /// An unterminated provider line or excessive pending network data must
    /// never grow the adapter-owned byte buffer past its limit.
    #[test]
    fn pending_provider_bytes_have_an_exact_bound() {
        let mut pending = VecDeque::from(vec![b'x'; MAX_PENDING_BYTES - 1]);
        append_pending(&mut pending, b"y").unwrap();
        assert_eq!(pending.len(), MAX_PENDING_BYTES);
        assert!(matches!(append_pending(&mut pending, b"z"), Err(Failure::Limit(_))));
        assert_eq!(pending.len(), MAX_PENDING_BYTES);

        let mut empty = VecDeque::new();
        let oversized = vec![b'x'; MAX_PENDING_BYTES + 1];
        assert!(matches!(append_pending(&mut empty, &oversized), Err(Failure::Limit(_))));
        assert!(empty.is_empty());
        append_pending(&mut empty, b"one\ntwo\n").unwrap();
        assert_eq!(empty.into_iter().collect::<Vec<_>>(), b"one\ntwo\n".to_vec());
    }

    /// Scanning a long line split into tiny chunks must avoid repeatedly
    /// searching its existing prefix. Short lines in one chunk remain ordered.
    #[test]
    fn searches_each_provider_byte_only_once_across_chunks() {
        let mut pending = VecDeque::new();
        let mut scanned = 0;
        for n in 1..=16_384 {
            append_pending(&mut pending, b"x").unwrap();
            assert!(next_line(&mut pending, &mut scanned).is_none());
            assert_eq!(scanned, n);
        }
        append_pending(&mut pending, b"\nsecond\n").unwrap();
        let first = next_line(&mut pending, &mut scanned).unwrap();
        assert_eq!(first.len(), 16_385);
        assert_eq!(first.last(), Some(&b'\n'));
        assert_eq!(next_line(&mut pending, &mut scanned).unwrap(), b"second\n".to_vec());
        assert!(next_line(&mut pending, &mut scanned).is_none());
        assert_eq!(scanned, 0);
    }

    /// Every network-chunk split must preserve response lines, including
    /// empty lines, CRLF and multibyte UTF-8 split across chunks.
    #[test]
    fn response_line_parser_preserves_all_two_chunk_fragmentations() {
        let input = "α\n\nβ\r\nfinal";
        for split in 0..=input.len() {
            let mut pending = VecDeque::new();
            let mut scanned = 0;
            let mut lines: Vec<Vec<u8>> = Vec::new();
            for chunk in [&input.as_bytes()[..split], &input.as_bytes()[split..]] {
                append_pending(&mut pending, chunk).unwrap();
                while let Some(line) = next_line(&mut pending, &mut scanned) {
                    lines.push(line);
                }
            }
            if !pending.is_empty() {
                lines.push(pending.drain(..).collect());
            }
            let decoded: Vec<String> = lines.iter().map(|line| text(line).unwrap()).collect();
            assert_eq!(
                decoded,
                vec!["α".to_owned(), "".to_owned(), "β".to_owned(), "final".to_owned()],
                "split: {split}"
            );
        }
    }

    /// Several valid lines must respect the total response bound. Rejection
    /// must leave the already collected response unchanged.
    #[test]
    fn collected_provider_body_has_an_exact_bound() {
        let mut all = String::new();
        let quarter = "x".repeat(MAX_TEXT_BYTES / 4 - 1);
        for _ in 0..4 {
            append_text_line(&mut all, &quarter).unwrap();
        }
        assert_eq!(all.len(), MAX_TEXT_BYTES);
        assert!(matches!(append_text_line(&mut all, "y"), Err(Failure::Limit(_))));
        assert_eq!(all.len(), MAX_TEXT_BYTES);

        let mut short = String::new();
        append_text_line(&mut short, "one").unwrap();
        append_text_line(&mut short, "two").unwrap();
        assert_eq!(short, "one\ntwo\n");
    }

    /// Looks a name up the way the system resolver does (hyper-util's
    /// `GaiResolver`): a blocking call on the runtime's blocking pool. The
    /// lookup is under way once `looking` is set and answers only when the
    /// test lets go of the other end of `answer`.
    struct Unanswered {
        looking: Arc<AtomicBool>,
        answer: Arc<Mutex<mpsc::Receiver<()>>>,
    }

    impl reqwest::dns::Resolve for Unanswered {
        fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
            let (looking, answer) = (Arc::clone(&self.looking), Arc::clone(&self.answer));
            Box::pin(async move {
                let lookup = tokio::task::spawn_blocking(move || {
                    looking.store(true, Ordering::Release);
                    let _ = answer.lock().unwrap().recv();
                });
                let _ = lookup.await;
                Err::<reqwest::dns::Addrs, _>("the lookup found nothing".into())
            })
        }
    }

    /// An attempt stopped by its caller, or past its deadline, while its
    /// name lookup does not answer ends at its next check, without waiting
    /// for the lookup.
    #[test]
    fn an_attempt_given_up_during_a_name_lookup_does_not_wait_for_it() {
        for stopped in [true, false] {
            let (answer, unanswered) = mpsc::channel::<()>();
            let looking = Arc::new(AtomicBool::new(false));
            let resolver =
                Unanswered { looking: Arc::clone(&looking), answer: Arc::new(Mutex::new(unanswered)) };
            let client = client().dns_resolver(Arc::new(resolver)).build().unwrap();
            // Stopped as soon as the lookup is under way, or expired during it.
            let deadline = Instant::now() + Duration::from_millis(if stopped { 60_000 } else { 500 });
            let during = Arc::clone(&looking);
            let (ended, end) = mpsc::channel();
            std::thread::spawn(move || {
                let alive = || !(stopped && during.load(Ordering::Acquire));
                let url = "http://provider.invalid/v1/chat/completions";
                let result = send(&client, url, &Secret("k".into()), None, String::new(), deadline, &alive);
                let _ = ended.send(result.err());
            });
            let Ok(failure) = end.recv_timeout(Duration::from_secs(3)) else {
                panic!("the attempt waited for its name lookup (stopped: {stopped})");
            };
            assert!(looking.load(Ordering::Acquire), "the attempt ended before its lookup began");
            match (stopped, failure) {
                (true, Some(Failure::Stopped)) | (false, Some(Failure::Deadline)) => {}
                (_, other) => panic!("stopped: {stopped}, ended with {other:?}"),
            }
            // The abandoned lookup may end now.
            drop(answer);
        }
    }
}
