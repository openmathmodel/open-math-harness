#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

use nucleus_model_interface::{CancelResponse, NextResponse};
use nucleus_protocol::{ActionName, ResourcePath};
use serde_json::json;

use super::*;

fn request() -> CompletionRequest {
    CompletionRequest {
        messages: vec![nucleus_model_interface::Message::text(nucleus_model_interface::Role::User, "hi")],
        tools: Vec::new(),
        max_output_tokens: 1,
        temperature: None,
        reasoning_effort: None,
        tool_choice: None,
        project: None,
    }
}

fn options(extra: &[&str]) -> Result<Options, String> {
    let mut args = ["--key-file", "/secrets/key", "--base-url", "https://api.openmathmodel.org/v1"]
        .map(str::to_owned)
        .to_vec();
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    Options::parse(args)
}

/// Local response-size failures do not trigger another provider request.
#[test]
fn oversized_response_is_non_retryable() {
    let key = Secret("k".into());
    let adapter = Adapter::new(&options(&[]).unwrap(), key.clone());
    let (error, retry) = adapter.failed(&key, transport::Failure::Limit("response too large"), Again::Soon);
    assert_eq!(retry, Again::No);
    assert_eq!(error.code, ErrorCode::ServiceError);
    assert_eq!(error.message, "response too large");
}

/// Exercise the complete HTTP path: a provider sends a large unterminated
/// streaming line. The adapter rejects it locally, and makes no second call.
#[test]
fn oversized_provider_response_fails_without_retrying() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let body = vec![b'x'; (8 << 20) + 1];
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        read_request(&socket);
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(headers.as_bytes()).unwrap();
        // The adapter may close the socket immediately upon reaching its cap.
        let _ = socket.write_all(&body);
        listener.set_nonblocking(true).unwrap();
        // Again::Soon waits RECONNECT_BACKOFF_MS (2 s) before retrying.
        // A shorter observation window would miss an unintended second call.
        let until = Instant::now() + Duration::from_millis(RECONNECT_BACKOFF_MS + 1_000);
        while Instant::now() < until {
            match listener.accept() {
                Ok(_) => return Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(false)
    });
    let adapter = Adapter::new(
        &options(&["--base-url", &base, "--retries", "3", "--retry-backoff-ms", "10"]).unwrap(),
        Secret("k".into()),
    );
    let failure = adapter.complete("deepseek/x", &request(), Duration::from_secs(15)).unwrap_err();
    assert_eq!(failure.code, ErrorCode::ServiceError);
    assert!(failure.message.contains("8 MiB"), "{}", failure.message);
    assert!(!server.join().unwrap().unwrap(), "unexpected retry request");
}

/// A non-successful streaming response must preserve a local size-limit
/// failure. An empty fallback body would instead permit retries for 503.
#[test]
fn oversized_error_body_in_stream_is_not_retried() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        read_request(&socket);
        let body = vec![b'x'; (8 << 20) + 1];
        let headers = format!(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(headers.as_bytes()).unwrap();
        // The client is allowed to close as soon as the local limit is hit.
        let _ = socket.write_all(&body);
        listener.set_nonblocking(true).unwrap();
        let until = Instant::now() + Duration::from_millis(RECONNECT_BACKOFF_MS + 1_000);
        while Instant::now() < until {
            match listener.accept() {
                Ok(_) => return Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(false)
    });
    let adapter = Arc::new(Adapter::new(
        &options(&["--base-url", &base, "--retries", "3", "--retry-backoff-ms", "10"]).unwrap(),
        Secret("k".into()),
    ));
    let streams = Streams::default();
    let id = start(&adapter, &streams, 15_000);
    let error = loop {
        match pull(&streams, &id) {
            Ok(next) => assert!(next.delta.is_empty() && next.done.is_none()),
            Err(error) => break error,
        }
    };
    assert_eq!(error.code, ErrorCode::ServiceError, "{}", error.message);
    assert!(error.message.contains("8 MiB"), "{}", error.message);
    assert!(!server.join().unwrap().unwrap(), "unexpected retry request");
}

/// The HTTP status still determines retryability if the provider's error
/// body cannot be decoded. Credential/credit refusals must stay final.
#[test]
fn malformed_provider_error_body_preserves_status_retry_policy() {
    for (status, expected) in [(402, Again::No), (403, Again::No), (503, Again::Later)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_request(&socket);
            let reply = format!("HTTP/1.1 {status} X\r\nContent-Length: 1\r\nConnection: close\r\n\r\n");
            socket.write_all(reply.as_bytes()).unwrap();
            socket.write_all(&[0xff]).unwrap();
        });
        let adapter = Adapter::new(&options(&["--base-url", &base]).unwrap(), Secret("k".into()));
        let streams = Streams::default();
        let (_, feed) = streams.open(ProcessId(1), Instant::now() + Duration::from_secs(10)).unwrap();
        let (error, retry) = adapter
            .stream_inner("deepseek/x", &request(), Instant::now() + Duration::from_secs(10), &feed)
            .unwrap_err();
        server.join().unwrap();
        assert_eq!(retry, expected, "status {status}: {}", error.message);
        assert_eq!(error.code, ErrorCode::ServiceError);
        assert!(error.message.contains("UTF-8"), "status {status}: {}", error.message);
    }
}

/// Reads one HTTP request from `socket`, headers and body, and returns the body.
fn read_request(socket: &TcpStream) -> Vec<u8> {
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reader = BufReader::new(socket);
    let mut length = 0;
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0, "the request ended early");
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    body
}

/// A provider that reads one request, answers `prefix` and then holds the
/// connection until the adapter closes it, which it reports.
struct Held {
    url: String,
    sent: mpsc::Receiver<()>,
    closed: mpsc::Receiver<()>,
}

impl Held {
    fn start(prefix: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sent, sent_rx) = mpsc::channel();
        let (closed, closed_rx) = mpsc::channel();
        let prefix = prefix.to_owned();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_request(&socket);
            socket.write_all(prefix.as_bytes()).unwrap();
            sent.send(()).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            let mut byte = [0];
            let result = socket.read(&mut byte);
            if matches!(result, Ok(0))
                || result.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
            {
                closed.send(()).unwrap();
            }
        });
        Self { url, sent: sent_rx, closed: closed_rx }
    }

    fn adapter(&self) -> Arc<Adapter> {
        Arc::new(Adapter::new(&options(&["--base-url", &self.url]).unwrap(), Secret("k".into())))
    }
}

fn start(adapter: &Arc<Adapter>, streams: &Streams, remaining_ms: u64) -> String {
    let dispatch = Dispatch {
        id: DispatchId(1),
        endpoint: nucleus_protocol::EndpointName::new("model").unwrap(),
        caller: ProcessId(1),
        action: ActionName::new(ACTION_START).unwrap(),
        resource: ResourcePath::new(["deepseek", "x"]).unwrap(),
        payload: Payload::encode(&json!({"messages":[{"role":"user","content":"hi"}],"max_output_tokens":8}))
            .unwrap(),
        remaining_ms,
    };
    serve(adapter, streams, &dispatch).unwrap().decode::<StartResponse>().unwrap().stream
}

fn pull(streams: &Streams, id: &str) -> Result<NextResponse, Error> {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(reply) = streams.poll_next(ProcessId(1), id, Instant::now() >= until) {
            return reply;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A provider that answered gets the operator's backoff; one that could not
/// be reached gets a short one.
#[test]
fn a_failure_the_provider_answered_waits_longer_than_one_it_could_not() {
    let configured = Duration::from_secs(20);
    assert_eq!(Again::Later.first_backoff(configured), configured);
    assert!(Again::Soon.first_backoff(configured) < configured);

    assert_eq!(transient_status(429), Again::Later, "alive, asking for room");
    assert_eq!(transient_status(503), Again::Later);
    assert_eq!(transient_status(400), Again::No, "the request itself is wrong");
}

/// An account refusal is final, in whatever envelope it comes: one request,
/// and the person reads the provider's reason in seconds instead of after
/// minutes of backoff. An upstream failure in the same envelope is retried.
#[test]
fn no_credit_is_reported_at_once_and_not_retried() {
    let refusal =
        |code: serde_json::Value| json!({"error": {"code": code, "message": "credit is exhausted"}});
    let sse = |event: serde_json::Value| format!("data: {{\"choices\":[]}}\n\ndata: {event}\n\n");
    for (status, content_type, body, requests) in [
        (402, "application/json", refusal(json!("insufficient_credits")).to_string(), 1),
        (200, "application/json", refusal(json!("insufficient_credits")).to_string(), 1),
        (200, "text/event-stream", sse(refusal(json!(402))), 1),
        (200, "text/event-stream", sse(refusal(json!(502))), 4),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let reply = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        // Serves the expected requests and stops; a further one is left in the backlog.
        let server = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let (mut served, until) = (0, Instant::now() + Duration::from_secs(10));
            while served < requests && Instant::now() < until {
                let Ok((mut socket, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                socket.set_nonblocking(false).unwrap();
                read_request(&socket);
                socket.write_all(reply.as_bytes()).unwrap();
                served += 1;
            }
            (served, listener)
        });
        let adapter = Adapter::new(
            &options(&["--base-url", &base, "--retries", "3", "--retry-backoff-ms", "10"]).unwrap(),
            Secret("k".into()),
        );
        let error = adapter.complete("deepseek/x", &request(), Duration::from_secs(10)).unwrap_err();
        let (served, listener) = server.join().unwrap();
        let more = listener.accept().is_ok();
        assert_eq!((served, more), (requests, false), "{status} {body}: {}", error.message);
        if requests == 1 {
            assert!(error.message.contains("credit is exhausted"), "{}", error.message);
        }
    }
}

/// A stream ends at its caller's deadline, not at `--max-timeout-ms`, so a
/// silent provider does not hold the reader, the connection or the stream bound.
#[test]
fn the_start_deadline_closes_a_silent_stream_without_a_cancel() {
    let server = Held::start("");
    let (adapter, streams) = (server.adapter(), Streams::default());
    let id = start(&adapter, &streams, 1_000);
    server.sent.recv_timeout(Duration::from_secs(2)).unwrap();
    let error = loop {
        match pull(&streams, &id) {
            Ok(next) => assert!(next.delta.is_empty() && next.done.is_none()),
            Err(error) => break error,
        }
    };
    assert_eq!(error.code, ErrorCode::Timeout, "{}", error.message);
    assert!(server.closed.recv_timeout(Duration::from_secs(2)).is_ok(), "the connection was not closed");
}

/// `released: true` means the reader has closed the connection.
#[test]
fn a_cancel_is_released_once_the_connection_is_closed() {
    let partial = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n\
                   data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n";
    let server = Held::start(partial);
    let (adapter, streams) = (server.adapter(), Streams::default());
    let id = start(&adapter, &streams, 60_000);
    assert_eq!(pull(&streams, &id).unwrap().delta, "partial");
    let mut controls = Controls::new(streams.clone());
    let cancel = Dispatch {
        id: DispatchId(2),
        endpoint: nucleus_protocol::EndpointName::new("model").unwrap(),
        caller: ProcessId(1),
        action: ActionName::new(ACTION_CANCEL).unwrap(),
        resource: ResourcePath::new(["deepseek", "x"]).unwrap(),
        payload: Payload::encode(&json!({"stream": id})).unwrap(),
        remaining_ms: 10_000,
    };
    controls.park(&cancel, REPLY_MARGIN_MS).unwrap();
    let answer = loop {
        if let Some((_, answer)) = controls.ready().pop() {
            break answer;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(answer.unwrap().decode::<CancelResponse>().unwrap().released);
    assert!(server.closed.recv_timeout(Duration::from_secs(1)).is_ok(), "the connection was not closed");
}

#[test]
fn the_key_must_travel_over_tls_or_loopback() {
    assert!(Options::parse(["--key-file", "/secrets/key"].map(str::to_owned)).is_err(), "no --base-url");
    assert!(options(&["--base-url", "http://127.0.0.1:8080/v1"]).is_ok());
    assert!(options(&["--base-url", "http://localhost:1"]).is_ok());
    for bad in ["http://openrouter.ai/api/v1", "http://127.0.0.1.evil.example/v1", "ftp://x", "openrouter.ai"]
    {
        assert!(options(&["--base-url", bad]).is_err(), "{bad}");
    }
}

/// What the operator may set, and what is refused before startup.
#[test]
fn operator_options_are_validated_at_startup() {
    for (args, accepted) in [
        (&["--max-inflight", "3"][..], true),
        (&["--max-inflight", "0"], false),
        (&["--max-inflight", "many"], false),
        (&["--max-inflight"], false),
    ] {
        assert_eq!(options(args).is_ok(), accepted, "{args:?}");
    }
    assert_eq!(options(&["--max-inflight", "3"]).unwrap().max_inflight, 3);
}

#[test]
fn deadlines_bound_the_provider_call() {
    let adapter = Adapter::new(&options(&["--max-timeout-ms", "5000"]).unwrap(), Secret("k".into()));
    assert_eq!(adapter.timeout_for(60_000).unwrap(), Duration::from_millis(5_000));
    assert_eq!(adapter.timeout_for(3_000).unwrap(), Duration::from_millis(2_500));
    assert_eq!(adapter.timeout_for(1_200).unwrap_err().code, ErrorCode::InvalidInput);
}

#[test]
fn a_worker_that_never_reports_is_still_answered_once() {
    // A panic inside a worker unwinds through its `Report`; this drives the guard the same way.
    let (to, finished) = mpsc::channel();
    drop(Report::new(DispatchId(1), to.clone()));
    let (dispatch, result) = finished.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(dispatch, DispatchId(1));
    let error = result.unwrap_err();
    assert_eq!(error.code, ErrorCode::ServiceError);

    // The normal path reports once: the guard does not add a second, contradictory report.
    Report::new(DispatchId(2), to).done(Ok(Payload::encode(&serde_json::json!({})).unwrap()));
    let (dispatch, result) = finished.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(dispatch == DispatchId(2) && result.is_ok());
    assert!(finished.try_recv().is_err(), "exactly one report per worker");
}

#[test]
fn a_dispatch_whose_wait_ate_its_deadline_is_a_service_error_and_is_not_sent() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let adapter = Adapter::new(&options(&["--base-url", &base]).unwrap(), Secret("k".into()));
    let now = Instant::now();
    let job = Job {
        caller: ProcessId(3),
        model: "deepseek/x".into(),
        request: request(),
        deadline: now + Duration::from_millis(700),
        offered: now - Duration::from_millis(1_800),
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let error = job.run(&adapter).unwrap_err();
    assert_eq!(error.code, ErrorCode::ServiceError, "{}", error.message);
    assert!(listener.accept().is_err(), "nothing was sent");
    assert_eq!(adapter.slots.counts(), (0, 0), "the slot went back");
}

#[test]
fn key_files_are_validated_and_secrets_do_not_print() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    std::fs::write(&path, "  sk-or-test-123\n").unwrap();
    let key = Secret::read(&path).unwrap();
    assert_eq!(format!("{key:?}"), "Secret([redacted])");
    assert_eq!(key.scrub("bad header Bearer sk-or-test-123!"), "bad header Bearer [redacted]!");
    std::fs::write(&path, "\n").unwrap();
    assert!(Secret::read(&path).is_err());
    std::fs::write(&path, "two tokens").unwrap();
    assert!(Secret::read(&path).is_err());
    assert!(Secret::read(&dir.path().join("missing")).is_err());
}

/// A provider that refuses `requests` requests and answers, for each, its
/// header line `<name>: ...` in lower case, or "" when it had none.
fn refusing(requests: usize, name: &'static str) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..n]);
            }
            let text = String::from_utf8_lossy(&request).to_lowercase();
            seen.push(text.lines().find(|l| l.starts_with(&format!("{name}:"))).unwrap_or("").to_owned());
            let body = r#"{"error":{"message":"refused by the fixture"}}"#;
            write!(
                stream,
                "HTTP/1.1 400 X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
        seen
    });
    (base, server)
}

/// The project a request is made for reaches the proxy as its tag, and a
/// request made for none carries no tag.
#[test]
fn a_project_is_sent_as_a_proxy_tag_exactly_when_the_request_names_one() {
    let (base, server) = refusing(2, "x-proxy-tags");
    let adapter =
        Adapter::new(&options(&["--base-url", &base, "--retries", "0"]).unwrap(), Secret("k".into()));
    for project in [Some("alpha-1"), None] {
        let request = CompletionRequest { project: project.map(str::to_owned), ..request() };
        adapter.complete("deepseek/x", &request, Duration::from_secs(5)).unwrap_err();
    }
    assert_eq!(server.join().unwrap(), ["x-proxy-tags: project=alpha-1", ""]);
}

#[test]
fn each_request_reads_the_current_key_file_and_a_missing_key_is_a_clear_error() {
    let (base, server) = refusing(2, "authorization");
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("model-key");
    let mut options = options(&["--base-url", &base, "--retries", "0"]).unwrap();
    options.key_file = key.clone();
    let adapter = Adapter::from_key_file(&options);
    let call = || adapter.complete("deepseek/x", &request(), Duration::from_secs(5)).unwrap_err();
    let missing = call();
    assert_eq!((missing.code, missing.message.as_str()), (ErrorCode::Unavailable, NO_KEY));
    for token in ["sk-one", "sk-two"] {
        std::fs::write(&key, token).unwrap();
        assert!(!call().message.contains(token), "the key is scrubbed from errors");
    }
    assert_eq!(server.join().unwrap(), ["authorization: bearer sk-one", "authorization: bearer sk-two"]);
}
