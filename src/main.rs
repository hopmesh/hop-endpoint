//! # hop-endpoint — a `hops://` origin endpoint (DESIGN.md §30)
//!
//! An operator runs this on their own infrastructure to make their service reachable over
//! Hop. It's a **listening** Hop node (clients dial it directly, so the operator bears the
//! cost of their own traffic — our relay fleet is never a conduit for domain traffic) plus
//! an HTTP translator **bound to one origin**: a `hops://` request carries only a path, and
//! the endpoint executes it against its *own* configured backend. It is never an open proxy.
//!
//! The operator publishes `_hopaddress.<domain>  TXT  <printed-address>` (HNS) and fronts
//! `--listen` with TLS (the LB terminates `wss://<domain>:9444/` → plain `ws` here), exactly
//! like the relay fleet.
//!
//! Usage:
//!   hop-endpoint --listen 0.0.0.0:9444 --domain example.hopme.sh \
//!                --origin http://localhost:8080 [--identity-file PATH] [--max-resp BYTES]
//!
//! ## Protocol-level domain binding
//!
//! Every `hops://` request carries a signed `host` field. The endpoint is configured with
//! exactly one `--domain` and **rejects any request whose `host` is not that domain** (403)
//! before it ever touches the backend. The URL it fetches is built *solely* from the
//! configured `--origin` plus the request path — the request's own bytes never choose a host.
//! Redirects are disabled, so the backend cannot bounce the endpoint off-origin either. There
//! is no code path by which this process fetches anything other than `<origin><path>`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hop_core::prelude::*;
use tungstenite::Message;

static NEXT_LINK: AtomicU64 = AtomicU64::new(1);

/// F-19: cap on concurrent inbound connections, so the one-thread-per-connection accept loop can't
/// exhaust threads/memory on the single always-on instance. Generous for legitimate traffic.
const MAX_CONNS: usize = 256;
static ACTIVE_CONNS: AtomicUsize = AtomicUsize::new(0);

/// Decrements the active-connection count when a connection handler thread finishes (including on a
/// panic unwind, since it runs in Drop). Paired with the `fetch_add` in the accept loop.
struct ConnGuard;
impl Drop for ConnGuard {
    fn drop(&mut self) {
        ACTIVE_CONNS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// services-10: cap concurrent hops:// backend fetches. Each inbound mesh request spawned a thread
/// with no bound, so a burst of mesh requests (which never pass the TCP-side IP limiter) could
/// exhaust threads/memory on the single instance. Over the cap we shed the request with a 503.
const MAX_INFLIGHT_FETCHES: usize = 128;
static INFLIGHT_FETCHES: AtomicUsize = AtomicUsize::new(0);

/// Decrements the in-flight fetch count when a fetch worker finishes (incl. panic unwind).
struct FetchGuard;
impl Drop for FetchGuard {
    fn drop(&mut self) {
        INFLIGHT_FETCHES.fetch_sub(1, Ordering::SeqCst);
    }
}

/// F-19: per-source fixed-window rate limit. One noisy client can otherwise monopolize the
/// connection cap and the single instance; this bounds requests per source IP per window.
const RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_REQ_PER_WINDOW: u32 = 100;
/// Above this many tracked sources we sweep expired windows so the map can't grow without bound.
const RATE_MAP_SWEEP_AT: usize = 10_000;

fn rate_state() -> &'static Mutex<HashMap<IpAddr, (Instant, u32)>> {
    static RATE: OnceLock<Mutex<HashMap<IpAddr, (Instant, u32)>>> = OnceLock::new();
    RATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// True if `ip` is under its per-window budget (and records this request). False ⇒ shed it.
fn allow_source(ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut map = rate_state().lock().unwrap();
    if map.len() > RATE_MAP_SWEEP_AT {
        map.retain(|_, (start, _)| now.duration_since(*start) < RATE_WINDOW);
    }
    let (start, count) = map.entry(ip).or_insert((now, 0));
    if now.duration_since(*start) >= RATE_WINDOW {
        *start = now;
        *count = 0;
    }
    *count += 1;
    *count <= MAX_REQ_PER_WINDOW
}

/// Driver events: bearer lifecycle + a completed backend fetch handed back from a worker.
enum Ev {
    Up(u64, Role, Sender<Vec<u8>>),
    Data(u64, Vec<u8>),
    Down(u64),
    /// A finished HTTP fetch: reply (to, for_request_id, status, content_type, body).
    Fetched(PubKeyBytes, BundleId, u16, String, Vec<u8>),
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// services-r3-03: the relay-degrade precedence now lives in ONE place, `hop_gateway::resolve_relay`,
// so the gateway and endpoint binaries share a single tested implementation and cannot drift. The
// endpoint imports it directly (see the `use hop_gateway::resolve_relay;` below).
use hop_gateway::resolve_relay;

/// services-r2-03: pick the per-source rate-limit key from an `X-Forwarded-For` header value.
///
/// XFF is `client, proxy1, proxy2, ...`, appended left-to-right as it traverses proxies. The LAST
/// entry is the one appended by the closest trusted hop (our LB), so it is the only entry not fully
/// client-controllable. Keying on the FIRST entry let a client rotate a spoofed leading value to
/// dodge the per-source window; taking the LAST entry keys on the LB-appended hop instead. This is
/// still only as trustworthy as the deployment's LB stripping/appending XFF. services-r3-02: behind
/// a trusted LB the accept-loop `peer_addr` limiter is SKIPPED (see `accept_peer_limited`), because
/// all LB traffic shares one peer IP and would otherwise be one global window; the count cap
/// (`MAX_CONNS`) bounds resource use, and THIS XFF-keyed limiter is the per-client control.
fn client_ip_from_xff(raw: &str) -> Option<String> {
    raw.split(',')
        .map(|s| s.trim())
        .rfind(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// services-r3-02: how the accept loop treats the raw TCP `peer_addr` for rate limiting.
///
/// Behind Cloud Run / a shared LB every client arrives from the SAME front-end IP, so the
/// accept-loop `allow_source(peer.ip())` bucket lumps ALL users into one 100-req/10s window — a
/// global availability cap that also sheds health probes (they share the LB IP) under load. The
/// per-CLIENT control is the XFF-keyed limiter inside `serve_http_proxy`. When we know a trusted LB
/// fronts us, the accept-loop peer bucket must be SKIPPED so it can't globally throttle; the count
/// cap ([`MAX_CONNS`]) still bounds resource exhaustion, and per-client fairness is enforced on the
/// real client IP downstream. When NOT behind a trusted proxy (direct exposure), the peer bucket
/// stays on as the only per-source backstop.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TrustedProxy {
    /// No trusted proxy configured: apply the accept-loop peer-IP limiter (direct exposure).
    None,
    /// Any inbound peer is a trusted LB front-end: skip the accept-loop peer-IP limiter entirely.
    Any,
    /// A specific trusted LB IP: skip the peer limiter only for that peer; limit everyone else.
    Ip(IpAddr),
}

/// Resolve the trusted-proxy policy from `HOP_TRUSTED_PROXY`. `any` (or `1`/`true`/`yes`) ⇒ every
/// peer is the LB (the Cloud Run / shared-LB deployment). A parseable IP ⇒ trust only that peer.
/// Unset/empty/unparseable ⇒ `None` (direct exposure; keep the peer-IP limiter).
fn resolve_trusted_proxy(env: Option<&str>) -> TrustedProxy {
    match env.map(|s| s.trim()) {
        Some("any") | Some("1") | Some("true") | Some("yes") => TrustedProxy::Any,
        Some(s) if !s.is_empty() => match s.parse::<IpAddr>() {
            Ok(ip) => TrustedProxy::Ip(ip),
            Err(_) => TrustedProxy::None,
        },
        _ => TrustedProxy::None,
    }
}

/// True ⇒ the accept loop should apply its per-`peer_addr` rate bucket to this peer. False ⇒ this
/// peer is a trusted LB front-end, so skip the accept-loop bucket (the XFF limiter handles the real
/// client). This is what prevents one global bucket from throttling all LB-fronted traffic.
fn accept_peer_limited(peer_ip: IpAddr, trusted: TrustedProxy) -> bool {
    match trusted {
        TrustedProxy::None => true,          // direct exposure: limit every peer
        TrustedProxy::Any => false,          // all peers are the LB: never limit at accept
        TrustedProxy::Ip(t) => peer_ip != t, // limit everyone EXCEPT the trusted LB
    }
}

fn main() {
    let mut listen = "0.0.0.0:9444".to_string();
    let mut origin: Option<String> = None;
    let mut domain: Option<String> = None;
    let mut identity_file: Option<String> = None;
    let mut max_resp: u32 = 8 * 1024 * 1024; // 8 MiB cap on a translated response
    let mut print_address = false;
    // Dial a relay so the endpoint is reachable by its address on the mesh (can send/receive
    // messages), as a leaf that never carries others' traffic (DESIGN.md §30). Default on.
    let mut relay: Option<String> = Some("wss://relay.hopme.sh/".to_string());
    // services-11: whether a --relay/--no-relay was given on the CLI, so env only fills the default.
    let mut relay_cli_set = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => listen = args.next().unwrap_or(listen),
            "--origin" => origin = args.next(),
            "--domain" => domain = args.next(),
            "--identity-file" => identity_file = args.next(),
            "--max-resp" => max_resp = args.next().and_then(|s| s.parse().ok()).unwrap_or(max_resp),
            "--relay" => {
                relay = args.next();
                relay_cli_set = true;
            }
            "--no-relay" => {
                relay = None; // run isolated (listening only), e.g. for local tests
                relay_cli_set = true;
            }
            // Load the identity, print its base58 address, and exit. Used to fill in the
            // `_hopaddress.<domain>` TXT record before the endpoint ever serves traffic.
            "--print-address" => print_address = true,
            other => eprintln!("ignoring unknown arg: {other}"),
        }
    }

    // services-11: graceful degrade when the relay fleet is off (relays_enabled=false). Infra can
    // set HOP_NO_RELAY=1 (or HOP_RELAY to a specific URL) so the always-on example instance doesn't
    // spin dialing a dead relay - it just serves its origin over plain HTTP. A CLI --relay/--no-relay
    // still wins; env only fills the default so the container needs no arg change to degrade.
    relay = resolve_relay(
        relay,
        relay_cli_set,
        std::env::var("HOP_NO_RELAY").ok().as_deref(),
        std::env::var("HOP_RELAY").ok().as_deref(),
    );
    if relay.is_none() {
        println!("hop-endpoint: no relay configured; serving origin only (not mesh-routable)");
    }

    // services-r3-02: when fronted by a trusted LB (Cloud Run / shared LB), skip the accept-loop
    // per-peer rate bucket so all clients aren't lumped into one global window; per-client fairness
    // is enforced on the real X-Forwarded-For IP downstream. Default None = direct exposure.
    let trusted_proxy = resolve_trusted_proxy(std::env::var("HOP_TRUSTED_PROXY").ok().as_deref());
    if trusted_proxy != TrustedProxy::None {
        println!(
            "hop-endpoint: trusted proxy = {trusted_proxy:?}; accept-loop peer rate limit skipped \
             for the LB (per-client limit keyed on X-Forwarded-For)"
        );
    }

    if print_address {
        let identity = load_identity(&identity_file);
        println!("{}", bs58::encode(identity.address()).into_string());
        return;
    }
    let origin = origin.unwrap_or_else(|| {
        eprintln!(
            "--origin http://your-backend is required (the ONLY backend this endpoint serves)"
        );
        std::process::exit(2);
    });
    let domain = domain.unwrap_or_else(|| {
        eprintln!(
            "--domain example.com is required (the ONLY hops:// host this endpoint answers for)"
        );
        std::process::exit(2);
    });
    // Bind to a single origin: scheme://host[:port], no trailing slash. Requests only ever
    // get this prefix + their path — never an arbitrary host (no open proxy).
    let origin = origin.trim_end_matches('/').to_string();
    // The single authorized domain, normalized (case-insensitive, no trailing dot).
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();

    let identity = load_identity(&identity_file);
    let addr = identity.address();
    let mut node = Node::new(identity);
    // Answer hop.identify as the domain we back (DESIGN.md §29/§30), so a peer that resolves
    // or traces this address sees `example.hopme.sh`, not a bare short address.
    node.set_kind(NodeKind::Endpoint);
    node.set_name(Some(domain.clone()));
    // A leaf: routable by address, but it never relays other nodes' bundles (§30) — domain
    // traffic and the backbone don't flow *through* an endpoint.
    node.set_max_relayed(0);
    println!("hop-endpoint: address {}", bs58::encode(addr).into_string());
    println!("hop-endpoint: authorized domain {domain}  (rejects any other host)");
    println!("hop-endpoint: serving origin {origin}");
    println!(
        "hop-endpoint: publish DNS →  _hopaddress.{domain}  TXT  \"{}\"",
        bs58::encode(addr).into_string()
    );
    println!(
        "hop-endpoint: listening on {listen} (ws = hops:// bearer, http = reverse-proxy to origin)"
    );

    // Redirects are disabled: the backend can never bounce us to a different host.
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");

    let (tx, rx) = mpsc::channel::<Ev>();
    // A cheap clone (Arc inside) for the accept threads' plain-HTTP reverse proxy; the
    // original `http` is owned by the driver for hops:// fetches.
    let http_accept = http.clone();

    // Accept inbound connections (one thread per connection). A connection is either a
    // WebSocket (the hops:// Hop bearer) or a plain HTTP request, which we reverse-proxy to
    // our own origin so https://<domain>/ serves the same content as hops://<domain>/.
    {
        let tx = tx.clone();
        let listener = TcpListener::bind(&listen).expect("bind --listen address");
        let origin = origin.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                // F-19: bound concurrent connections so the one-thread-per-connection accept loop
                // can't be driven to thread/memory exhaustion on the single 512Mi instance. Over the
                // cap we shed load (drop the socket) rather than spawn unboundedly.
                // F-19 / services-r3-02: shed a source over its per-window budget before spending a
                // slot — but ONLY when the peer is NOT a trusted LB. Behind an LB every client shares
                // the LB's IP, so this bucket would be a global availability cap (and shed health
                // probes); there, per-client fairness is enforced on X-Forwarded-For in the proxy.
                if let Ok(peer) = stream.peer_addr() {
                    if accept_peer_limited(peer.ip(), trusted_proxy) && !allow_source(peer.ip()) {
                        drop(stream);
                        continue;
                    }
                }
                if ACTIVE_CONNS.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
                    ACTIVE_CONNS.fetch_sub(1, Ordering::SeqCst);
                    drop(stream);
                    continue;
                }
                let (tx, origin, http) = (tx.clone(), origin.clone(), http_accept.clone());
                std::thread::spawn(move || {
                    let _guard = ConnGuard; // decrements ACTIVE_CONNS on drop (incl. panic unwind)
                                            // F-19: isolate a per-connection panic so a malformed request can't tear down
                                            // the accept loop / process (the driver still runs on the main thread).
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        serve_conn(stream, &tx, &origin, &http, max_resp)
                    }));
                });
            }
        });
    }

    // Dial the relay (if configured) so the endpoint joins the mesh as a routable leaf —
    // reachable by its address for messages, reconnecting forever (DESIGN.md §30).
    if let Some(relay_url) = relay {
        let tx = tx.clone();
        println!("hop-endpoint: joining mesh via relay {relay_url} (routable leaf)");
        std::thread::spawn(move || dial_relay(relay_url, tx));
    }

    run(node, domain, origin, http, max_resp, tx, rx);
}

/// services-11: reconnect backoff bounds. When the relay fleet is off (relays_enabled=false) the
/// dead relay is unreachable indefinitely; a flat 5s retry then spams a reconnect attempt + log line
/// every 5s forever, burning the always-on instance's CPU and filling logs. Back off exponentially
/// from a short base up to a cap so a dead relay is probed rarely (once a minute), while a real relay
/// blip still reconnects fast.
const RECONNECT_BASE: Duration = Duration::from_secs(5);
const RECONNECT_MAX: Duration = Duration::from_secs(60);

/// The backoff after `failures` consecutive failed dials: `BASE * 2^(failures-1)`, capped at MAX.
/// `failures == 0` (a fresh success) resets to BASE. Pure + total so it is unit-testable (services-11).
fn reconnect_backoff(failures: u32) -> Duration {
    if failures == 0 {
        return RECONNECT_BASE;
    }
    let base = RECONNECT_BASE.as_secs();
    // Saturating shift: 2^(failures-1) without overflow, then cap at MAX.
    let mult = 1u64.checked_shl(failures - 1).unwrap_or(u64::MAX);
    let secs = base.saturating_mul(mult).min(RECONNECT_MAX.as_secs());
    Duration::from_secs(secs)
}

/// Dial a relay over `wss://` and bridge it as a Hop bearer link (we're the Initiator), so
/// this endpoint is reachable by its address through the mesh. Reconnects with exponential backoff
/// (services-11) so a dead relay isn't hammered every 5s. Same read-timeout interleave as the
/// inbound bearer, but as a TLS WebSocket client.
fn dial_relay(url: String, ev_tx: Sender<Ev>) {
    use tungstenite::stream::MaybeTlsStream;
    // services-11: consecutive-failure count drives the backoff; a successful connect resets it, so a
    // real relay blip reconnects fast while a permanently-dead relay is probed at most once a minute.
    let mut failures: u32 = 0;
    loop {
        match tungstenite::connect(&url) {
            Ok((mut ws, _resp)) => {
                failures = 0; // connected: reset the backoff
                eprintln!("hop-endpoint: connected to relay {url}");
                // Non-blocking socket: a read MUST NOT block, or the loop never gets back to
                // send our outgoing Noise handshake msg1 (it's produced by the driver right
                // after Ev::Up) — that deadlock leaves the WS open but the handshake unstarted,
                // so the relay never registers us as a peer. (A read timeout on a TLS stream
                // didn't reliably surface as WouldBlock; non-blocking does.)
                match ws.get_ref() {
                    MaybeTlsStream::Plain(s) => {
                        let _ = s.set_nonblocking(true);
                    }
                    MaybeTlsStream::Rustls(t) => {
                        let _ = t.get_ref().set_nonblocking(true);
                    }
                    _ => {}
                }
                let link = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
                let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>();
                if ev_tx.send(Ev::Up(link, Role::Initiator, out_tx)).is_err() {
                    return;
                }
                let mut hello = false;
                'conn: loop {
                    // Flush any queued outgoing (handshake + bundles), retrying WouldBlock.
                    let mut wrote = false;
                    loop {
                        match out_rx.try_recv() {
                            Ok(bytes) => {
                                wrote = true;
                                match ws.write(Message::Binary(bytes)) {
                                    Ok(()) => {}
                                    Err(tungstenite::Error::Io(e))
                                        if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                    Err(_) => break 'conn,
                                }
                            }
                            Err(mpsc::TryRecvError::Empty) => break,
                            Err(mpsc::TryRecvError::Disconnected) => break 'conn,
                        }
                    }
                    match ws.flush() {
                        Ok(()) => {
                            if wrote && !hello {
                                hello = true;
                                eprintln!("hop-endpoint: sent handshake to relay");
                            }
                        }
                        Err(tungstenite::Error::Io(e))
                            if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => break,
                    }
                    match ws.read() {
                        Ok(Message::Binary(b)) => {
                            if ev_tx.send(Ev::Data(link, b.to_vec())).is_err() {
                                return;
                            }
                        }
                        Ok(Message::Close(_)) => break,
                        Ok(_) => {}
                        Err(tungstenite::Error::Io(e))
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
                let _ = ev_tx.send(Ev::Down(link));
                // A clean disconnect after a good connection: treat the NEXT dial as a fresh attempt
                // (failures already reset to 0 on connect), so a transient drop reconnects at BASE.
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                let wait = reconnect_backoff(failures);
                // services-11: report the degraded state and back off, instead of spamming a dial +
                // log every 5s at a dead relay (e.g. while relays_enabled=false). The endpoint keeps
                // serving its origin over plain HTTP the whole time; only mesh reachability is down.
                eprintln!(
                    "hop-endpoint: relay {url} unreachable ({e}); mesh-unreachable, \
                     retry #{failures} in {}s",
                    wait.as_secs()
                );
                std::thread::sleep(wait);
                continue;
            }
        }
        // A connection that came up and later dropped: brief pause, then reconnect promptly.
        std::thread::sleep(RECONNECT_BASE);
    }
}

/// The driver: sole owner of the node. Routes outgoing bytes to per-link writers, and on a
/// `hops` request spawns a worker to fetch the origin, replying when it returns.
fn run(
    mut node: Node,
    domain: String,
    origin: String,
    http: reqwest::blocking::Client,
    max_resp: u32,
    tx: Sender<Ev>,
    rx: mpsc::Receiver<Ev>,
) {
    let mut writers: HashMap<u64, Sender<Vec<u8>>> = HashMap::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(1000)) {
            Ok(Ev::Up(link, role, out)) => {
                writers.insert(link, out);
                node.handle(BearerEvent::Connected(link, role));
            }
            Ok(Ev::Data(link, bytes)) => node.handle(BearerEvent::Data(link, bytes)),
            Ok(Ev::Down(link)) => {
                writers.remove(&link);
                node.handle(BearerEvent::Disconnected(link));
            }
            Ok(Ev::Fetched(to, for_id, status, content_type, body)) => {
                // Carry the origin's content-type back so a hops:// client (e.g. a WebView)
                // renders each resource correctly (HTML/CSS/JS/image).
                let _ = node.send_http_response(
                    to,
                    for_id,
                    status,
                    vec![("content-type".to_string(), content_type)],
                    body,
                );
            }
            Err(RecvTimeoutError::Timeout) => node.tick(now_ms()),
            Err(RecvTimeoutError::Disconnected) => break,
        }

        // Translate any inbound hops requests against our OWN origin (path only).
        for r in node.take_http_requests() {
            // Protocol-level domain binding: refuse anything not addressed to our domain
            // BEFORE spawning a fetch. The signed `host` must equal our single --domain.
            let req_host = r.host.trim_end_matches('.').to_ascii_lowercase();
            if req_host != domain {
                eprintln!(
                    "hop-endpoint: refusing host {:?} (authorized: {domain})",
                    r.host
                );
                let body = format!("hop-endpoint: this endpoint only serves {domain}").into_bytes();
                let ct = "text/plain; charset=utf-8".to_string();
                let _ = tx.send(Ev::Fetched(r.from, r.id, 403, ct, body));
                continue;
            }
            // services-10: bound concurrent fetch workers. Mesh requests bypass the TCP IP limiter,
            // so without this a burst spawns unbounded threads on the single instance. Over the cap
            // reply 503 immediately rather than spawn.
            if INFLIGHT_FETCHES.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT_FETCHES {
                INFLIGHT_FETCHES.fetch_sub(1, Ordering::SeqCst);
                let ct = "text/plain; charset=utf-8".to_string();
                let body = b"hop-endpoint: busy, try again".to_vec();
                let _ = tx.send(Ev::Fetched(r.from, r.id, 503, ct, body));
                continue;
            }
            let (origin, http, tx) = (origin.clone(), http.clone(), tx.clone());
            std::thread::spawn(move || {
                let _guard = FetchGuard; // decrements INFLIGHT_FETCHES on drop (incl. panic unwind)
                let (status, ctype, body) = fetch(&http, &origin, &r, max_resp);
                let _ = tx.send(Ev::Fetched(r.from, r.id, status, ctype, body));
            });
        }

        for (link, bytes) in node.drain_outgoing() {
            if let Some(out) = writers.get(&link) {
                if out.send(bytes).is_err() {
                    writers.remove(&link);
                }
            }
        }
    }
}

/// Execute one request against our origin. The request's `url` is treated as a **path** and
/// appended to the fixed origin — the endpoint never fetches any other host. v1 is GET-only.
fn fetch(
    http: &reqwest::blocking::Client,
    origin: &str,
    r: &hop_core::node::HttpReqItem,
    max_resp: u32,
) -> (u16, String, Vec<u8>) {
    let plain = "text/plain; charset=utf-8".to_string();
    if !r.method.eq_ignore_ascii_case("GET") {
        return (405, plain, b"hop-endpoint: only GET in v1".to_vec());
    }
    let path = path_of(&r.url);
    let url = format!("{origin}{path}");
    // Tell the origin this request arrived over the mesh, so it can word itself accordingly.
    match http.get(&url).header("x-hop-scheme", "hops").send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let ctype = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let mut body = resp.bytes().map(|b| b.to_vec()).unwrap_or_default();
            if body.len() > max_resp as usize {
                body.truncate(max_resp as usize);
            }
            (status, ctype, body)
        }
        Err(_) => (502, plain, b"hop-endpoint: backend unreachable".to_vec()),
    }
}

/// Reduce a request target to a path+query, discarding any scheme/host a client may have
/// sent — so a request can only ever hit our own origin (no open proxy).
fn path_of(url: &str) -> String {
    let after = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("hops://"))
        .map(|rest| {
            rest.split_once('/')
                .map(|(_, p)| format!("/{p}"))
                .unwrap_or_else(|| "/".to_string())
        })
        .unwrap_or_else(|| url.to_string());
    if after.starts_with('/') {
        after
    } else {
        format!("/{after}")
    }
}

/// Serve a plain HTTP request by reverse-proxying it to our OWN origin (path only) — the
/// standard-HTTPS sibling of the hops:// path. The LB terminates TLS, so we speak plain HTTP
/// here. Like the hops:// path it can never reach any host but our configured origin, so
/// there's no open-proxy surface. v1 is GET/HEAD.
fn serve_http_proxy(
    mut stream: TcpStream,
    origin: &str,
    http: &reqwest::blocking::Client,
    max_resp: u32,
) {
    // Read the request line + headers (up to the blank line); we only need method + path.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_path = parts.next().unwrap_or("/").to_string();
    // Drain the rest of the headers so the client's send completes cleanly, capturing the
    // real client IP from `X-Forwarded-For` (services-06).
    let mut xff: Option<String> = None;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line == "\r\n" || line == "\n" => break,
            Ok(_) => {
                if let Some(v) = line
                    .split_once(':')
                    .filter(|(k, _)| k.trim().eq_ignore_ascii_case("x-forwarded-for"))
                    .map(|(_, v)| v)
                {
                    xff = client_ip_from_xff(v);
                }
            }
            Err(_) => break,
        }
    }

    // services-08: a cheap liveness endpoint that never touches the origin, so the LB / uptime
    // checks can confirm the driver process is up (the sibling of relayd's F-17 /healthz).
    let path_only = path_of(&raw_path);
    if method.eq_ignore_ascii_case("GET") && path_only == "/healthz" {
        let body = b"ok";
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
        return;
    }

    // services-06: behind Cloud Run / the shared LB the TCP peer is Google's front-end, not the
    // end user, so the accept-loop peer_addr limiter buckets everyone together. Re-key the limit on
    // the real client IP from X-Forwarded-For when present; shed a client over its window budget.
    if let Some(ip_str) = &xff {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            if !allow_source(ip) {
                let body = b"hop-endpoint: rate limited";
                let header = format!(
                    "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
                return;
            }
        }
    }

    let head_only = method.eq_ignore_ascii_case("HEAD");
    let (status, ctype, body) = if !method.eq_ignore_ascii_case("GET") && !head_only {
        (
            405u16,
            "text/plain; charset=utf-8".to_string(),
            b"hop-endpoint: only GET/HEAD over plain HTTP".to_vec(),
        )
    } else {
        let url = format!("{origin}{path_only}");
        // The LB terminated TLS for us; tell the origin this came over standard https.
        match http.get(&url).header("x-hop-scheme", "https").send() {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let ctype = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let mut body = resp.bytes().map(|b| b.to_vec()).unwrap_or_default();
                if body.len() > max_resp as usize {
                    body.truncate(max_resp as usize);
                }
                (status, ctype, body)
            }
            Err(_) => (
                502,
                "text/plain; charset=utf-8".to_string(),
                b"hop-endpoint: backend unreachable".to_vec(),
            ),
        }
    };

    let reason = if status == 200 { "OK" } else { "" };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    if !head_only {
        let _ = stream.write_all(&body);
    }
    let _ = stream.flush();
}

/// Handle one inbound connection: a WebSocket becomes a Hop link (hops:// bearer); anything
/// else is a plain HTTP request we reverse-proxy to our own origin, so `https://<domain>/`
/// serves the same content as `hops://<domain>/`. We peek (non-consuming) to decide, leaving
/// the bytes intact for whichever handler takes over (the relay's WS bearer does the same).
fn serve_conn(
    stream: TcpStream,
    ev_tx: &Sender<Ev>,
    origin: &str,
    http: &reqwest::blocking::Client,
    max_resp: u32,
) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut head = [0u8; 1024];
    match stream.peek(&mut head) {
        Ok(n) if n > 0 => {
            let req = String::from_utf8_lossy(&head[..n]).to_ascii_lowercase();
            if !req.contains("upgrade: websocket") {
                serve_http_proxy(stream, origin, http, max_resp);
                return;
            }
        }
        _ => return, // no data (e.g. a bare TCP probe) — nothing to serve
    }
    let _ = stream.set_read_timeout(None); // hand a clean blocking socket to tungstenite

    let mut ws = match tungstenite::accept(stream) {
        Ok(w) => w,
        Err(_) => return,
    };
    let _ = ws
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(100)));

    let link = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>();
    if ev_tx.send(Ev::Up(link, Role::Responder, out_tx)).is_err() {
        return;
    }
    'conn: loop {
        loop {
            match out_rx.try_recv() {
                Ok(bytes) => {
                    if ws.write(Message::Binary(bytes)).is_err() {
                        break 'conn;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break 'conn,
            }
        }
        if ws.flush().is_err() {
            break;
        }
        match ws.read() {
            Ok(Message::Binary(b)) => {
                if ev_tx.send(Ev::Data(link, b.to_vec())).is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    let _ = ev_tx.send(Ev::Down(link));
}

/// Load a stable identity from a 32-byte file (so the endpoint's address — published in DNS
/// — survives restarts), generating and persisting one on first run.
fn load_identity(path: &Option<String>) -> Identity {
    if let Some(path) = path {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Identity::from_secret_bytes(&seed);
            }
        }
        let id = Identity::generate();
        // services-13: a 32-byte long-term secret written 0600 (owner-only), never world-readable,
        // with a loud warning on failure (a silent drop means the DNS-published address goes stale).
        if let Err(e) = write_secret_600(path, &id.to_secret_bytes()) {
            eprintln!(
                "warning: could not persist identity to {path}: {e}; address will change on restart"
            );
        }
        return id;
    }
    eprintln!("warning: no --identity-file; address will change on restart (DNS would go stale)");
    Identity::generate()
}

/// Write `bytes` to `path` with owner-only (0600) permissions (services-13). On Unix the mode is
/// applied at create time so the secret is never briefly world-readable; non-Unix falls back to a
/// plain write (the endpoint only ships on Unix).
fn write_secret_600(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        // Re-assert 0600 in case the file pre-existed with looser perms (mode only applies on create).
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    /// A throwaway one-shot HTTP/1.1 origin: it serves `n` sequential requests, each with a fixed
    /// status/content-type/body, and records the request line + `x-hop-scheme` header it saw so a
    /// test can assert the endpoint fetched `<origin><path>` (path only, no host) and stamped the
    /// scheme. Returns the bound `http://127.0.0.1:PORT` origin and a receiver of `(request_line,
    /// x_hop_scheme)` observations. Deliberately minimal (no keep-alive; `Connection: close`).
    fn stub_origin(
        n: usize,
        status_line: &'static str,
        content_type: &'static str,
        body: Vec<u8>,
    ) -> (String, std::sync::mpsc::Receiver<(String, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel::<(String, String)>();
        std::thread::spawn(move || {
            for _ in 0..n {
                let (mut sock, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(_) => return,
                };
                sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut reader = BufReader::new(sock.try_clone().unwrap());
                let mut req_line = String::new();
                reader.read_line(&mut req_line).ok();
                let mut scheme = String::new();
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) if line == "\r\n" || line == "\n" => break,
                        Ok(_) => {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("x-hop-scheme") {
                                    scheme = v.trim().to_string();
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = tx.send((req_line.trim_end().to_string(), scheme));
                let resp = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes());
                let _ = sock.write_all(&body);
                let _ = sock.flush();
            }
        });
        (origin, rx)
    }

    fn test_client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    fn req_item(method: &str, url: &str) -> hop_core::node::HttpReqItem {
        hop_core::node::HttpReqItem {
            from: [0u8; 32],
            id: [1u8; 32],
            host: "example.hopme.sh".into(),
            method: method.into(),
            url: url.into(),
            headers: vec![],
            body: vec![],
            max_resp: 8 * 1024 * 1024,
        }
    }

    #[test]
    fn fetch_rejects_non_get_without_touching_the_backend() {
        // v1 is GET-only: a POST (or any non-GET) is refused with 405 BEFORE any network call, so
        // an unreachable/garbage origin is never even dialed. Point at a dead port to prove no fetch.
        let http = test_client();
        let (status, ctype, body) = fetch(
            &http,
            "http://127.0.0.1:1", // would 502 if actually dialed
            &req_item("POST", "/x"),
            8 * 1024 * 1024,
        );
        assert_eq!(status, 405, "non-GET is rejected");
        assert!(ctype.starts_with("text/plain"));
        assert!(String::from_utf8_lossy(&body).contains("only GET"));
        // Method match is case-insensitive but still GET-only: lowercase get is allowed through
        // (would try to dial), delete is not.
        let (s2, _, _) = fetch(&http, "http://127.0.0.1:1", &req_item("DELETE", "/x"), 1024);
        assert_eq!(s2, 405, "DELETE is also rejected");
    }

    #[test]
    fn fetch_hits_origin_plus_path_only_and_passes_status_ctype_body() {
        // The endpoint must fetch <origin><path> — never the client-supplied host — and pass the
        // origin's status, content-type, and body straight back. The client sends a full URL with a
        // DIFFERENT host; the endpoint must strip it to the path and hit its OWN origin.
        let (origin, rx) = stub_origin(
            1,
            "201 Created",
            "text/html; charset=utf-8",
            b"<h1>hi</h1>".to_vec(),
        );
        let http = test_client();
        let (status, ctype, body) = fetch(
            &http,
            &origin,
            &req_item("GET", "https://evil.example/page?q=1"),
            8 * 1024 * 1024,
        );
        assert_eq!(status, 201, "origin status is passed through");
        assert_eq!(ctype, "text/html; charset=utf-8", "content-type preserved");
        assert_eq!(body, b"<h1>hi</h1>");
        // The origin saw the PATH only (host stripped) and the hops scheme stamp.
        let (req_line, scheme) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            req_line, "GET /page?q=1 HTTP/1.1",
            "fetched the path only, never the client's host"
        );
        assert_eq!(scheme, "hops", "the mesh scheme is stamped for the origin");
    }

    #[test]
    fn fetch_truncates_a_body_over_max_resp() {
        // max_resp is a hard cap on the translated body so a huge origin response can't blow memory
        // on the single instance; the body is truncated to exactly the cap.
        let (origin, _rx) = stub_origin(1, "200 OK", "application/octet-stream", vec![7u8; 5000]);
        let http = test_client();
        let (status, _ctype, body) = fetch(&http, &origin, &req_item("GET", "/big"), 100);
        assert_eq!(status, 200);
        assert_eq!(body.len(), 100, "body truncated to the max_resp cap");
        assert!(body.iter().all(|&b| b == 7));
    }

    #[test]
    fn fetch_returns_502_when_the_backend_is_unreachable() {
        // A refused/dead origin must surface as 502 (backend unreachable), not a panic or a hang.
        let http = test_client();
        let (status, ctype, body) = fetch(&http, "http://127.0.0.1:1", &req_item("GET", "/"), 1024);
        assert_eq!(status, 502, "unreachable backend => 502");
        assert!(ctype.starts_with("text/plain"));
        assert!(String::from_utf8_lossy(&body).contains("unreachable"));
    }

    /// Drive `serve_http_proxy` over a real loopback TCP socket with the given raw request bytes and
    /// return the full raw HTTP response the handler wrote back. `origin` is the backend it proxies
    /// to (use a `stub_origin`, or a dead port for the 502 path).
    fn drive_proxy(request: &[u8], origin: &str, max_resp: u32) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = origin.to_string();
        let http = test_client();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            serve_http_proxy(sock, &origin, &http, max_resp);
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(request).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut resp = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        server.join().unwrap();
        String::from_utf8_lossy(&resp).into_owned()
    }

    #[test]
    fn http_proxy_healthz_never_touches_the_origin() {
        // services-08: /healthz is a cheap liveness endpoint that must answer 200 "ok" WITHOUT
        // dialing the origin (so it stays up even if the backend is down). Point at a dead port and
        // still get a healthy 200.
        let resp = drive_proxy(
            b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n",
            "http://127.0.0.1:1",
            1024,
        );
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "healthz => 200: {resp}"
        );
        assert!(
            resp.trim_end().ends_with("ok"),
            "healthz body is ok: {resp}"
        );
    }

    #[test]
    fn http_proxy_rejects_non_get_head_with_405() {
        // Over plain HTTP the reverse proxy is GET/HEAD only; a POST is 405 and never hits the origin.
        let resp = drive_proxy(
            b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
            "http://127.0.0.1:1",
            1024,
        );
        assert!(
            resp.starts_with("HTTP/1.1 405"),
            "POST over plain HTTP => 405: {resp}"
        );
        assert!(resp.contains("only GET/HEAD"));
    }

    #[test]
    fn http_proxy_get_proxies_origin_body_and_head_omits_it() {
        // A GET proxies the origin's status/content-type/body back. A HEAD to the SAME resource
        // returns the same status line but NO body (the standard HEAD contract).
        let (origin, _rx) = stub_origin(2, "200 OK", "text/plain; charset=utf-8", b"BODY".to_vec());
        let get = drive_proxy(b"GET /r HTTP/1.1\r\nHost: x\r\n\r\n", &origin, 1024);
        assert!(get.starts_with("HTTP/1.1 200 OK"));
        assert!(get.contains("Content-Type: text/plain"));
        assert!(
            get.trim_end().ends_with("BODY"),
            "GET returns the body: {get}"
        );

        let head = drive_proxy(b"HEAD /r HTTP/1.1\r\nHost: x\r\n\r\n", &origin, 1024);
        assert!(head.starts_with("HTTP/1.1 200 OK"), "HEAD status: {head}");
        assert!(
            head.contains("Content-Length: 4"),
            "HEAD still advertises the length: {head}"
        );
        assert!(
            !head.trim_end().ends_with("BODY"),
            "HEAD must not send the body: {head}"
        );
    }

    #[test]
    fn http_proxy_502s_when_origin_unreachable() {
        // A GET to a dead origin surfaces 502 to the plain-HTTP client, not a hang.
        let resp = drive_proxy(
            b"GET /r HTTP/1.1\r\nHost: x\r\n\r\n",
            "http://127.0.0.1:1",
            1024,
        );
        assert!(
            resp.starts_with("HTTP/1.1 502"),
            "dead origin => 502: {resp}"
        );
    }

    #[test]
    fn http_proxy_rate_limits_on_the_real_client_ip_from_xff() {
        // services-06: behind an LB the TCP peer is Google's front-end, so the per-client limit is
        // re-keyed on the real client IP from X-Forwarded-For. Exhaust that IP's window directly, then
        // a request carrying it in XFF must be shed with 429 (proving the proxy keys on XFF, not the
        // loopback peer). Uses a unique IP so the shared static rate map isn't cross-contaminated.
        let ip: IpAddr = "198.51.100.42".parse().unwrap();
        for _ in 0..MAX_REQ_PER_WINDOW {
            assert!(allow_source(ip));
        }
        // This IP is now over budget. A proxied request presenting it in XFF is rate-limited.
        let req = b"GET /r HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 198.51.100.42\r\n\r\n";
        let resp = drive_proxy(req, "http://127.0.0.1:1", 1024);
        assert!(
            resp.starts_with("HTTP/1.1 429"),
            "an over-budget XFF client is rate-limited before the origin: {resp}"
        );
        assert!(resp.contains("rate limited"));
    }

    #[test]
    fn path_of_reduces_to_path_and_never_leaks_a_host() {
        // The endpoint must only ever fetch <origin><path>; a client-supplied scheme/host is dropped.
        assert_eq!(path_of("https://evil.com/a/b?q=1"), "/a/b?q=1");
        assert_eq!(path_of("hops://example.com/"), "/");
        assert_eq!(path_of("/already/a/path"), "/already/a/path");
        assert_eq!(path_of("no-leading-slash"), "/no-leading-slash");
        assert_eq!(path_of("http://host"), "/");
        assert_eq!(path_of("/healthz"), "/healthz");
    }

    #[test]
    fn resolve_relay_precedence_cli_wins_then_env_degrade() {
        // services-r2-02: the graceful-degrade precedence is the control that keeps the always-on
        // example instance from spinning against a dead relay when the fleet is off. Assert it as a
        // pure function so a regression fails a test, not CI.
        let default = || Some("wss://relay.hopme.sh/".to_string());

        // 1. No CLI, no env -> the default relay stands (normal operation).
        assert_eq!(resolve_relay(default(), false, None, None), default());

        // 2. HOP_NO_RELAY=1/true/yes forces degrade (no relay) -> serve origin only when fleet off.
        for v in ["1", "true", "yes"] {
            assert_eq!(
                resolve_relay(default(), false, Some(v), None),
                None,
                "HOP_NO_RELAY={v} degrades to no relay"
            );
        }
        // A non-degrade value leaves the default in place.
        assert_eq!(resolve_relay(default(), false, Some("0"), None), default());

        // 3. HOP_RELAY overrides the default URL (when not degrading).
        assert_eq!(
            resolve_relay(default(), false, None, Some("wss://eu.relay/")),
            Some("wss://eu.relay/".to_string())
        );
        // An empty HOP_RELAY is ignored (default stands).
        assert_eq!(resolve_relay(default(), false, None, Some("")), default());
        // HOP_NO_RELAY takes precedence over HOP_RELAY.
        assert_eq!(
            resolve_relay(default(), false, Some("1"), Some("wss://eu.relay/")),
            None,
            "degrade wins over an explicit HOP_RELAY"
        );

        // 4. A CLI --relay/--no-relay (cli_set=true) ALWAYS wins; env is ignored entirely.
        assert_eq!(
            resolve_relay(
                Some("wss://cli/".into()),
                true,
                Some("1"),
                Some("wss://env/")
            ),
            Some("wss://cli/".to_string()),
            "explicit --relay overrides even HOP_NO_RELAY"
        );
        assert_eq!(
            resolve_relay(None, true, None, Some("wss://env/")),
            None,
            "explicit --no-relay overrides HOP_RELAY"
        );
    }

    #[test]
    fn client_ip_from_xff_takes_the_trusted_last_hop() {
        // services-r2-03: key the per-source limit on the LAST XFF entry (the LB-appended hop), not
        // the FIRST (client-controllable) one, so a client can't rotate a spoofed leading value to
        // dodge its window.
        assert_eq!(
            client_ip_from_xff("1.1.1.1, 2.2.2.2, 3.3.3.3").as_deref(),
            Some("3.3.3.3"),
            "last (LB-appended) hop, not the first client-supplied one"
        );
        assert_eq!(
            client_ip_from_xff("9.9.9.9").as_deref(),
            Some("9.9.9.9"),
            "single entry is that entry"
        );
        // Whitespace + trailing-comma noise is trimmed; empties are ignored.
        assert_eq!(
            client_ip_from_xff("  1.1.1.1 ,  4.4.4.4 , ").as_deref(),
            Some("4.4.4.4")
        );
        assert_eq!(client_ip_from_xff("").as_deref(), None);
        assert_eq!(client_ip_from_xff(" , ").as_deref(), None);
    }

    #[test]
    fn per_source_rate_limit_sheds_over_budget() {
        // services-06: the fixed-window limiter admits up to the budget then sheds. Uses a unique IP
        // per test run so the shared static map doesn't cross-contaminate.
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        for _ in 0..MAX_REQ_PER_WINDOW {
            assert!(allow_source(ip), "under budget is admitted");
        }
        assert!(
            !allow_source(ip),
            "the request past the window budget is shed"
        );
    }

    #[test]
    fn resolve_trusted_proxy_maps_env_to_policy() {
        // services-r3-02: `any`/truthy => trust every peer (Cloud Run / shared LB); a bare IP =>
        // trust only that peer; unset/empty/garbage => None (direct exposure, keep the limiter).
        assert_eq!(resolve_trusted_proxy(Some("any")), TrustedProxy::Any);
        assert_eq!(resolve_trusted_proxy(Some("1")), TrustedProxy::Any);
        assert_eq!(resolve_trusted_proxy(Some("true")), TrustedProxy::Any);
        assert_eq!(resolve_trusted_proxy(Some(" yes ")), TrustedProxy::Any);
        assert_eq!(
            resolve_trusted_proxy(Some("10.0.0.1")),
            TrustedProxy::Ip("10.0.0.1".parse().unwrap())
        );
        assert_eq!(resolve_trusted_proxy(None), TrustedProxy::None);
        assert_eq!(resolve_trusted_proxy(Some("")), TrustedProxy::None);
        assert_eq!(
            resolve_trusted_proxy(Some("not-an-ip")),
            TrustedProxy::None,
            "unparseable => direct exposure (fail closed to the safe limiter)"
        );
    }

    #[test]
    fn accept_loop_does_not_globally_rate_limit_behind_a_trusted_lb() {
        // services-r3-02 (the core proof): behind a trusted LB every client shares ONE peer IP. The
        // accept-loop peer bucket must be SKIPPED there, or ~100 req / 10s across ALL users combined
        // would shed real traffic (and health probes) — a global availability cap. With the LB
        // trusted, the accept loop never applies the peer limiter, so an unbounded number of LB-
        // fronted requests pass the accept gate (per-client fairness is enforced on XFF downstream).
        let lb_ip: IpAddr = "35.191.0.5".parse().unwrap(); // stand-in for the shared LB front-end

        // Trust ANY peer (Cloud Run): the accept-loop bucket is never applied to the LB IP, so far
        // MORE than MAX_REQ_PER_WINDOW connections from that one peer IP are admitted at the gate.
        for _ in 0..(MAX_REQ_PER_WINDOW * 5) {
            assert!(
                !accept_peer_limited(lb_ip, TrustedProxy::Any),
                "a trusted-any LB peer is never peer-rate-limited at accept"
            );
        }

        // Trust only a specific LB IP: that peer is exempt; everyone else is still limited.
        assert!(
            !accept_peer_limited(lb_ip, TrustedProxy::Ip(lb_ip)),
            "the configured trusted LB IP is exempt from the accept-loop bucket"
        );
        let other: IpAddr = "203.0.113.99".parse().unwrap();
        assert!(
            accept_peer_limited(other, TrustedProxy::Ip(lb_ip)),
            "a non-trusted peer is still limited even when a specific LB IP is trusted"
        );

        // Direct exposure (no trusted proxy): the peer limiter still applies (the safe default).
        assert!(
            accept_peer_limited(lb_ip, TrustedProxy::None),
            "with no trusted proxy the accept-loop peer limiter stays on as the backstop"
        );
    }

    #[test]
    fn reconnect_backoff_grows_then_caps() {
        // services-11: a dead relay must not be dialed every 5s forever. Backoff starts at BASE,
        // doubles per consecutive failure, and caps at MAX so a permanently-down relay is probed
        // rarely (once a minute) rather than hammered.
        assert_eq!(
            reconnect_backoff(0),
            RECONNECT_BASE,
            "no failures resets to base"
        );
        assert_eq!(
            reconnect_backoff(1),
            Duration::from_secs(5),
            "first failure = base"
        );
        assert_eq!(reconnect_backoff(2), Duration::from_secs(10));
        assert_eq!(reconnect_backoff(3), Duration::from_secs(20));
        assert_eq!(reconnect_backoff(4), Duration::from_secs(40));
        assert_eq!(
            reconnect_backoff(5),
            RECONNECT_MAX,
            "caps at max (would be 80s)"
        );
        assert_eq!(
            reconnect_backoff(100),
            RECONNECT_MAX,
            "stays capped, no overflow"
        );
        // The whole point: a dead relay is probed at most once per MAX, not every 5s.
        assert!(
            reconnect_backoff(20) <= RECONNECT_MAX,
            "a long-dead relay is never dialed faster than the cap"
        );
    }

    #[cfg(unix)]
    #[test]
    fn identity_secret_is_written_owner_only() {
        // services-13: the persisted identity seed must be 0600 (owner-only), never world-readable.
        use std::os::unix::fs::PermissionsExt;
        let path = format!(
            "{}/hop-endpoint-secret-{}.key",
            std::env::temp_dir().display(),
            std::process::id()
        );
        let _ = std::fs::remove_file(&path);
        write_secret_600(&path, &[7u8; 32]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "identity seed must be owner-only, got {mode:o}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), vec![7u8; 32]);
        // A pre-existing loose file is tightened on rewrite.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_secret_600(&path, &[8u8; 32]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rewrite must tighten perms, got {mode:o}");
        let _ = std::fs::remove_file(&path);
    }
}
