//! # hop-endpoint - a `hops://` origin endpoint (DESIGN.md §30)
//!
//! An operator runs this on their own infrastructure to make their service reachable over
//! Hop. It's a **listening** Hop node (clients dial it directly, so the operator bears the
//! cost of their own traffic - our relay fleet is never a conduit for domain traffic) plus
//! an HTTP translator **bound to one origin**: a `hops://` request carries only a path, and
//! the endpoint executes it against its *own* configured backend. It is never an open proxy.
//!
//! The endpoint publishes its own HNS binding: it serves a signed reach record at
//! `https://<domain>/.well-known/hop` (§30), so a client resolves the domain by fetching that (the
//! TLS cert proves the domain; the record self-certifies the address). The operator just fronts
//! `--listen` with TLS (the LB terminates `wss://<domain>:9444/` to plain `ws` here, and routes the
//! well-known GET to this same HTTP server), exactly like the relay fleet.
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
//! configured `--origin` plus the request path - the request's own bytes never choose a host.
//! Redirects are disabled, so the backend cannot bounce the endpoint off-origin either. There
//! is no code path by which this process fetches anything other than `<origin><path>`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use hop_core::prelude::*;
use hop_endpoint_core::Endpoint;

/// This origin endpoint runs on an in-memory node, wrapped as an [`Endpoint`] so multiple replicas
/// (same identity, no shared datastore) can cluster and each proxy a given request once. Clustering
/// is off unless `HOP_CLUSTER_SECRET` is set; every replica must set the same value.
type Ep = Endpoint<hop_core::store::MemoryStore>;
use tungstenite::Message;

static NEXT_LINK: AtomicU64 = AtomicU64::new(1);

/// HNS reach-record TTL (DESIGN.md §30): how long a client caches this endpoint's `domain -> address`
/// binding after fetching `/.well-known/hop`. We RE-sign well within it ([`WELL_KNOWN_RESIGN`]) so the
/// served record is always fresh even under a long-lived process.
const WELL_KNOWN_TTL_SECS: u32 = 7200; // 2h
/// How often the driver loop re-signs the well-known body, comfortably under [`WELL_KNOWN_TTL_SECS`].
const WELL_KNOWN_RESIGN: Duration = Duration::from_secs(3600); // 1h

/// The pre-signed `/.well-known/hop` body (JSON `{address, endpoint, reach}`, the same shape every
/// endpoint SDK serves). Process-global because an endpoint is bound to exactly one domain/identity, so
/// there is one record. Empty until the driver first signs it (a probe before then just 404s); the
/// driver refreshes it under a Mutex so a long-lived process never serves an expired record.
fn well_known_body() -> &'static Mutex<Vec<u8>> {
    static WK: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
    WK.get_or_init(|| Mutex::new(Vec::new()))
}

/// Sign this endpoint's reach record for `public_url` and render the `/.well-known/hop` JSON body.
/// The `reach` field is the base64-std postcard record (drivers decode exactly this); `address` +
/// `endpoint` are informational, matching the SDK discovery format. All three values are base58 /
/// base64 / a bare wss URL, so the JSON is safe to build by hand (no embedded quotes to escape).
fn sign_well_known(node: &Ep, public_url: &str) -> Vec<u8> {
    let rec = node.sign_reach_record(public_url.to_string(), WELL_KNOWN_TTL_SECS);
    let reach = base64::engine::general_purpose::STANDARD.encode(rec.to_bytes());
    let address = bs58::encode(node.address()).into_string();
    format!("{{\"address\":\"{address}\",\"endpoint\":\"{public_url}\",\"reach\":\"{reach}\"}}")
        .into_bytes()
}

/// The direct-dial URL a client reaches this endpoint at (the reach record's `endpoint` field), the
/// LB-fronted `wss://<domain>/` that `serve_conn` upgrades to a Hop bearer link.
fn public_url_for(domain: &str) -> String {
    format!("wss://{domain}/")
}

/// services-r7-02: cap on a single inbound WS bearer message/frame, mirroring relayd's services-05
/// `MAX_FRAME_BYTES`. The hops:// WS bearer accepts frames from ANY mesh peer that dials this public
/// endpoint, so it must bound them at the mesh frame cap rather than tungstenite's 64 MiB default -
/// otherwise one peer could push a 64 MiB frame the single always-on instance has to buffer. A frame
/// over this cap drops the connection, exactly as the relay's raw-TCP/WS bearer paths reject one.
const MAX_FRAME_BYTES: usize = 1 << 20; // 1 MiB

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

/// services-r3-03: hard cap on the TOTAL bytes of a plain-HTTP request line plus all headers. The
/// proxy reads these into growable `String`s with `read_line`; without a cap a hostile client can
/// stream an endless request line / header block and grow the buffer until the 512Mi instance OOMs.
/// 64 KiB is far above any legitimate request head (paths + a normal header set), so a real client
/// is never truncated; anything past it is a resource-exhaustion attempt and the connection is shed.
const MAX_REQ_HEAD_BYTES: u64 = 64 * 1024;

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
#[derive(Debug)]
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
/// accept-loop `allow_source(peer.ip())` bucket lumps ALL users into one 100-req/10s window - a
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

/// The parsed CLI configuration. Split out of `main` so the arg-parsing decision table is a pure,
/// unit-testable function (it reads no globals and does no I/O), leaving `main` as orchestration.
struct CliConfig {
    listen: String,
    origin: Option<String>,
    domain: Option<String>,
    identity_file: Option<String>,
    max_resp: u32,
    print_address: bool,
    /// Dial a relay so the endpoint is reachable by its address on the mesh (can send/receive
    /// messages), as a leaf that never carries others' traffic (DESIGN.md §30). Default on.
    relay: Option<String>,
    /// services-11: whether a --relay/--no-relay was given on the CLI, so env only fills the default.
    relay_cli_set: bool,
}

/// Parse the endpoint's CLI flags into a [`CliConfig`]. Pure over its `args` iterator (no env, no
/// I/O), so every flag/default path is unit-testable. Unknown flags are logged and ignored, matching
/// the original lenient behavior.
fn parse_args(args: impl Iterator<Item = String>) -> CliConfig {
    let mut listen = "0.0.0.0:9444".to_string();
    let mut origin: Option<String> = None;
    let mut domain: Option<String> = None;
    let mut identity_file: Option<String> = None;
    let mut max_resp: u32 = 8 * 1024 * 1024; // 8 MiB cap on a translated response
    let mut print_address = false;
    let mut relay: Option<String> = Some("wss://relay.hopme.sh/".to_string());
    let mut relay_cli_set = false;
    let mut args = args;
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
            // Load the identity, print its base58 address, and exit. Useful for pinning the
            // endpoint's published address in config/docs (the endpoint serves it itself via
            // /.well-known/hop, so no DNS record needs it).
            "--print-address" => print_address = true,
            other => eprintln!("ignoring unknown arg: {other}"),
        }
    }
    CliConfig {
        listen,
        origin,
        domain,
        identity_file,
        max_resp,
        print_address,
        relay,
        relay_cli_set,
    }
}

fn main() {
    let CliConfig {
        listen,
        origin,
        domain,
        identity_file,
        max_resp,
        print_address,
        mut relay,
        relay_cli_set,
    } = parse_args(std::env::args().skip(1));

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
    let identity = load_identity(&identity_file);
    // Normalize origin/domain and configure the leaf endpoint node bound to that domain (extracted
    // so the normalization + node setup is unit-testable; main keeps the socket/thread orchestration).
    let (mut node, origin, domain) = build_endpoint(origin, domain, identity, &listen);

    // Publish this endpoint's HNS reach record at /.well-known/hop (§30): a client resolves the domain
    // by fetching it (its TLS cert proves the domain; the signed record self-certifies the address).
    // Sign the initial body BEFORE the accept loop starts so a well-known GET never races an empty
    // body; the driver loop refreshes it (WELL_KNOWN_RESIGN) so it never expires.
    // PRIME THE NODE CLOCK FIRST: sign_reach_record stamps issued_at from node.now_ms, which is 0 until
    // the first tick. Signing pre-tick would mint a record with issued_at=0 that is already expired
    // (issued_at + ttl << now), so every fresh resolution in the first WELL_KNOWN_RESIGN window would
    // fail verification. One tick sets the clock to real wall time.
    node.tick(now_ms());
    *well_known_body().lock().expect("well-known lock") =
        sign_well_known(&node, &public_url_for(&domain));

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
                // slot - but ONLY when the peer is NOT a trusted LB. Behind an LB every client shares
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

    // Dial the relay (if configured) so the endpoint joins the mesh as a routable leaf -
    // reachable by its address for messages, reconnecting forever (DESIGN.md §30).
    if let Some(relay_url) = relay {
        let tx = tx.clone();
        println!("hop-endpoint: joining mesh via relay {relay_url} (routable leaf)");
        std::thread::spawn(move || dial_relay(relay_url, tx));
    }

    run(node, domain, origin, http, max_resp, tx, rx);
}

/// Normalize the operator's `origin`/`domain`, build the leaf endpoint node bound to that domain,
/// and log the operator-facing startup banner. Returns `(node, normalized_origin, normalized_domain)`.
/// Split out of `main` so the normalization rules (strip a trailing `/` on the origin; lowercase and
/// strip a trailing `.` on the domain) and the node configuration (Endpoint kind, name = domain, a
/// leaf that relays nothing) are unit-testable without standing up sockets or the driver loop.
fn build_endpoint(
    origin: String,
    domain: String,
    identity: Identity,
    listen: &str,
) -> (Ep, String, String) {
    // Bind to a single origin: scheme://host[:port], no trailing slash. Requests only ever get this
    // prefix + their path - never an arbitrary host (no open proxy).
    let origin = origin.trim_end_matches('/').to_string();
    // The single authorized domain, normalized (case-insensitive, no trailing dot).
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();

    let addr = identity.address();
    let mut node = Endpoint::new(Node::new(identity));
    // Answer hop.identify as the domain we back (DESIGN.md §29/§30), so a peer that resolves or
    // traces this address sees `example.hopme.sh`, not a bare short address.
    node.set_kind(NodeKind::Endpoint);
    node.set_name(Some(domain.clone()));
    // A leaf: routable by address, but it never relays other nodes' bundles (§30) - domain traffic
    // and the backbone don't flow *through* an endpoint.
    node.set_max_relayed(0);
    println!("hop-endpoint: address {}", bs58::encode(addr).into_string());
    println!("hop-endpoint: authorized domain {domain}  (rejects any other host)");
    println!("hop-endpoint: serving origin {origin}");
    println!(
        "hop-endpoint: HNS reach record served at https://{domain}/.well-known/hop  (address {})",
        bs58::encode(addr).into_string()
    );
    println!(
        "hop-endpoint: listening on {listen} (ws = hops:// bearer, http = reverse-proxy to origin + /.well-known/hop)"
    );
    // Cluster with sibling replicas if configured: every replica set to the same HOP_CLUSTER_SECRET
    // joins the same cluster and each proxies a given request once (DESIGN.md §40).
    if let Ok(pass) = std::env::var("HOP_CLUSTER_SECRET") {
        if !pass.is_empty() {
            node.cluster_join_passphrase(pass.as_bytes());
            println!(
                "hop-endpoint: clustering ON (HOP_CLUSTER_SECRET set); replicas dedup shared work over the mesh"
            );
        }
    }
    (node, origin, domain)
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
                // after Ev::Up) - that deadlock leaves the WS open but the handshake unstarted,
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
                                match ws.write(Message::Binary(bytes.into())) {
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
    mut node: Ep,
    domain: String,
    origin: String,
    http: reqwest::blocking::Client,
    max_resp: u32,
    tx: Sender<Ev>,
    rx: mpsc::Receiver<Ev>,
) {
    let mut writers: HashMap<u64, Sender<Vec<u8>>> = HashMap::new();
    // Refresh the /.well-known/hop reach record before it expires (§30). Signed once in `main` before
    // the accept loop starts; re-signed here every WELL_KNOWN_RESIGN so a long-lived process never
    // serves an expired record.
    let public_url = public_url_for(&domain);
    let mut last_wk = Instant::now();
    loop {
        // services-r3-04: the accept threads wrap serve_conn in catch_unwind so one malformed request
        // can't tear down the process, but the driver's own parse/handle ran unguarded on this thread.
        // A core panic while parsing a malformed/hostile bundle (BearerEvent::Data) would then kill
        // the whole endpoint. Mirror the accept path: run every node.* call that touches attacker-
        // controlled bytes under catch_unwind, so a core panic becomes a logged skip, not process
        // death. node is `&mut`, so AssertUnwindSafe (same as serve_conn's wrapper); on a caught
        // panic the node keeps running and the next event is processed.
        match rx.recv_timeout(Duration::from_millis(1000)) {
            Ok(Ev::Up(link, role, out)) => {
                writers.insert(link, out);
                guard_core("bearer-connected", || {
                    node.handle(BearerEvent::Connected(link, role))
                });
            }
            Ok(Ev::Data(link, bytes)) => {
                // The malformed-bundle path: bytes are attacker-controlled, so guard the parse/handle.
                guard_core("bearer-data", || {
                    node.handle(BearerEvent::Data(link, bytes))
                });
            }
            Ok(Ev::Down(link)) => {
                writers.remove(&link);
                guard_core("bearer-disconnected", || {
                    node.handle(BearerEvent::Disconnected(link))
                });
            }
            Ok(Ev::Fetched(to, for_id, status, content_type, body)) => {
                // Carry the origin's content-type back so a hops:// client (e.g. a WebView)
                // renders each resource correctly (HTML/CSS/JS/image).
                guard_core("http-response", || {
                    let _ = node.send_http_response(
                        to,
                        for_id,
                        status,
                        vec![("content-type".to_string(), content_type)],
                        body,
                    );
                });
            }
            Err(RecvTimeoutError::Timeout) => {
                guard_core("tick", || node.tick(now_ms()));
                // Re-sign the well-known reach record so its expiry always stays in the future.
                if last_wk.elapsed() >= WELL_KNOWN_RESIGN {
                    if let Ok(mut wk) = well_known_body().lock() {
                        *wk = sign_well_known(&node, &public_url);
                    }
                    last_wk = Instant::now();
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }

        // Translate any inbound hops requests against our OWN origin (path only). take_http_requests
        // parses attacker-controlled bundle contents, so guard it too; on a panic, skip this cycle.
        let requests =
            guard_core("take-http-requests", || node.take_http_requests()).unwrap_or_default();
        handle_http_requests(requests, &domain, &origin, &http, max_resp, &tx);

        let outgoing = guard_core("drain-outgoing", || node.drain_outgoing()).unwrap_or_default();
        for (link, bytes) in outgoing {
            if let Some(out) = writers.get(&link) {
                if out.send(bytes).is_err() {
                    writers.remove(&link);
                }
            }
        }
    }
}

/// Handle the batch of inbound `hops://` requests the node surfaced this cycle: enforce the
/// protocol-level domain binding (reject a non-matching `host` with 403 before any backend touch),
/// shed over the in-flight fetch cap with 503, and otherwise spawn a bounded worker to fetch the
/// origin and reply. Split out of `run` so the security-critical routing decisions (domain binding,
/// the busy cap) are unit-testable without wiring up the whole driver loop. Replies are sent as
/// [`Ev::Fetched`] on `tx`, exactly as the inline loop did (behavior-preserving).
fn handle_http_requests(
    requests: Vec<hop_core::node::HttpReqItem>,
    domain: &str,
    origin: &str,
    http: &reqwest::blocking::Client,
    max_resp: u32,
    tx: &Sender<Ev>,
) {
    for r in requests {
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
        let (origin, http, tx) = (origin.to_string(), http.clone(), tx.clone());
        std::thread::spawn(move || {
            let _guard = FetchGuard; // decrements INFLIGHT_FETCHES on drop (incl. panic unwind)
            let (status, ctype, body) = fetch(&http, &origin, &r, max_resp);
            let _ = tx.send(Ev::Fetched(r.from, r.id, status, ctype, body));
        });
    }
}

/// services-r3-04: run a node call that touches attacker-controlled bytes under catch_unwind, so a
/// core panic (e.g. on a malformed bundle) becomes a logged skip instead of tearing down the whole
/// endpoint process. Mirrors how the accept threads wrap serve_conn. `node` is `&mut`, so the closure
/// is `AssertUnwindSafe` (same as serve_conn's wrapper). Returns `None` if the call panicked.
///
/// F-18d (pass-18 audit): this wraps a WHOLE core call, not the individual `self.*` mutations
/// inside one `on_bundle` match arm. That is deliberate: `Node`'s state is plain safe-Rust
/// `HashMap`/`Vec` (memory-safe regardless of where a panic lands). See the longer
/// note on `hop-relayd`'s `guard_core` (`services/hop-relayd/src/main.rs`) for the full
/// audit trail: no reachable mid-arm panic was found beyond one already-fixed case, and the
/// riskiest arm (`Payload::HpsRekey`) was reordered to fail-safe (install-then-remove) and is
/// enforced by `hop_core::node::tests::hps_rekey_install_before_remove_survives_a_mid_arm_panic`.
fn guard_core<T>(what: &str, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(_) => {
            // services-03: don't log the offending bytes (attacker-controlled + potentially sensitive
            // per-message metadata); just note which stage panicked so the endpoint stays up.
            eprintln!("hop-endpoint: core panic in {what}; skipped (endpoint stays up)");
            None
        }
    }
}

/// Execute one request against our origin. The request's `url` is treated as a **path** and
/// appended to the fixed origin - the endpoint never fetches any other host. v1 is GET-only.
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
/// sent - so a request can only ever hit our own origin (no open proxy).
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

/// The parts of a plain-HTTP request head the proxy needs: the method, the raw request-target, and
/// the real client IP parsed from `X-Forwarded-For` (if any).
struct RequestHead {
    method: String,
    raw_path: String,
    xff: Option<String>,
}

/// services-r3-03: read the request line + headers from a reader that is ALREADY byte-capped (the
/// caller wraps the socket in `.take(MAX_REQ_HEAD_BYTES)`), so this cannot grow its buffers without
/// bound. Returns `None` when there's nothing to serve (empty read) OR when the head is truncated by
/// the cap before the blank-line terminator (a header block larger than the cap = a hostile client;
/// the caller sheds it). Also captures `X-Forwarded-For` for the per-client rate limit (services-06).
fn read_request_head<R: BufRead>(reader: &mut R) -> Option<RequestHead> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return None; // no data (a bare TCP probe) - nothing to serve
    }
    // The request line itself must be complete (end in a newline). If the byte cap truncated it, the
    // line has no trailing '\n' and we reject rather than parse a partial target.
    if !request_line.ends_with('\n') {
        return None; // request line exceeded the head-size cap
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_path = parts.next().unwrap_or("/").to_string();
    // Drain the rest of the headers so the client's send completes cleanly, capturing the real
    // client IP from `X-Forwarded-For`. The `.take()` cap bounds the total bytes read here.
    let mut xff: Option<String> = None;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            // EOF at a line boundary: either a clean close after complete headers or the `.take`
            // cap landing exactly on a boundary. We got only complete lines, so serve what we have
            // (matches the original lenient behavior; the cap already bounds memory).
            Ok(0) => break,
            Ok(_) if line == "\r\n" || line == "\n" => break, // end of the header block
            Ok(_) if !line.ends_with('\n') => {
                // A header line with no terminator means the byte cap truncated it mid-line: this is
                // an oversized (hostile) head, so shed it rather than parse a partial header.
                return None;
            }
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
    Some(RequestHead {
        method,
        raw_path,
        xff,
    })
}

/// Serve a plain HTTP request by reverse-proxying it to our OWN origin (path only) - the
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
    // services-r3-03: cap the total request-line + header bytes so a hostile client can't grow the
    // read buffers until OOM. `.take(MAX_REQ_HEAD_BYTES)` bounds every read_line below; if the head
    // exceeds the cap the reject is a shed connection, not process death.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let cloned = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(cloned.take(MAX_REQ_HEAD_BYTES));
    let Some(head) = read_request_head(&mut reader) else {
        // Over the head-size cap (or an empty/failed read): shed without touching the origin.
        let body = b"hop-endpoint: request head too large";
        let header = format!(
            "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
        return;
    };
    let RequestHead {
        method,
        raw_path,
        xff,
    } = head;

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

    // HNS discovery (DESIGN.md §30): serve this endpoint's signed reach record so a client can resolve
    // the domain -> Hop address. The TLS cert on this fetch proves the domain; the record self-certifies
    // the address. Never proxied to the origin. Empty body = not signed yet (startup race) -> 404.
    if method.eq_ignore_ascii_case("GET") && path_only == "/.well-known/hop" {
        let body = well_known_body()
            .lock()
            .map(|b| b.clone())
            .unwrap_or_default();
        let (code, ctype, payload): (&str, &str, Vec<u8>) = if body.is_empty() {
            (
                "404 Not Found",
                "text/plain",
                b"hop-endpoint: reach record not ready".to_vec(),
            )
        } else {
            ("200 OK", "application/json", body)
        };
        let header = format!(
            "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            payload.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&payload);
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

/// What a peeked connection is: a WebSocket upgrade (a hops:// bearer link), a plain HTTP request
/// (reverse-proxied to our origin), or nothing to serve (no bytes / a bare TCP probe).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PeekKind {
    WsUpgrade,
    HttpProxy,
    Empty,
}

/// services-r3-05: decide from the peeked head bytes whether we can classify yet, and how. Returns
/// `Some(kind)` once the decision is final: `WsUpgrade` if the `upgrade: websocket` token is present,
/// `HttpProxy` once the whole header block has arrived (end-of-headers marker seen) with no upgrade
/// token. Returns `None` while the head is still incomplete (no terminator yet AND no upgrade token),
/// so the caller peeks again for the rest of a segmented handshake. Pure, so it is unit-testable.
fn classify_head(head: &[u8]) -> Option<PeekKind> {
    let req = String::from_utf8_lossy(head).to_ascii_lowercase();
    if req.contains("upgrade: websocket") {
        return Some(PeekKind::WsUpgrade);
    }
    // The header block is terminated by a blank line (CRLFCRLF, or bare-LF LFLF from lenient clients).
    // Once we've seen it with no upgrade token, this is definitely a plain HTTP request.
    if req.contains("\r\n\r\n") || req.contains("\n\n") {
        return Some(PeekKind::HttpProxy);
    }
    None // head still incomplete: an upgrade header could yet arrive in a later segment
}

/// services-r3-05: classify an inbound connection from a NON-consuming peek, robust to a handshake
/// split across TCP segments. Retries the peek (bounded by attempts and the read timeout) until the
/// head is complete enough to decide (classify_head returns Some) or the buffer fills / we time out.
/// On timeout / a full buffer with no decision, it falls back to the best guess from what arrived
/// (so a slow client is never hung forever). The peek never consumes, so the handler re-reads.
fn peek_kind(stream: &TcpStream) -> PeekKind {
    let mut head = [0u8; 2048];
    let mut last_n = 0usize;
    // A handful of retries with a short sleep covers a segmented handshake without adding latency to
    // the common single-segment case (the first peek already has the whole head). The socket's 5s
    // read timeout is the hard ceiling; these attempts just re-peek as more segments land.
    for attempt in 0..8 {
        match stream.peek(&mut head) {
            Ok(0) => return PeekKind::Empty, // clean EOF with nothing sent
            Ok(n) => {
                last_n = n;
                if let Some(kind) = classify_head(&head[..n]) {
                    return kind;
                }
                if n == head.len() {
                    break; // buffer full and still undecided: stop peeking, guess below
                }
            }
            // No data yet (non-blocking would-block) but the peer hasn't closed: wait briefly for the
            // next segment, unless this is the very first attempt with nothing at all (a bare probe).
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if attempt == 0 && last_n == 0 {
                    return PeekKind::Empty;
                }
            }
            Err(_) => break,
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // Undecided after the retries (no terminator, no upgrade token). If we saw ANY bytes, treat it as
    // plain HTTP (the safe default: the proxy path re-reads and handles a partial/odd request); if we
    // saw nothing, there's nothing to serve.
    if last_n > 0 {
        PeekKind::HttpProxy
    } else {
        PeekKind::Empty
    }
}

/// services-r7-02: the WebSocket config the inbound hops:// bearer accepts with. It caps a single
/// message AND a single frame at [`MAX_FRAME_BYTES`], instead of tungstenite's 64 MiB default, so a
/// mesh peer that dials this public endpoint cannot push a giant frame the single always-on instance
/// must buffer (the relay enforces the identical cap on its WS bearer, services-05). Extracted so the
/// cap is unit-testable and can't silently drift back to the default (`ws_bearer_config_rejects_...`).
fn bearer_ws_config() -> tungstenite::protocol::WebSocketConfig {
    tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES))
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
    // services-r3-05: classify WS-upgrade vs plain HTTP from a NON-consuming peek. A single peek can
    // return only the first TCP segment, so a handshake split across segments (the `Upgrade:
    // websocket` header arriving in a later packet than the request line) would misroute to the HTTP
    // proxy. peek_kind retries the peek briefly until the head is complete enough to decide (it has
    // seen the end-of-headers marker, or the upgrade token, or a bound), so a segmented handshake is
    // classified correctly. The bytes stay in the socket buffer for whichever handler takes over.
    match peek_kind(&stream) {
        PeekKind::HttpProxy => {
            serve_http_proxy(stream, origin, http, max_resp);
            return;
        }
        PeekKind::WsUpgrade => {}  // fall through to the WS handshake below
        PeekKind::Empty => return, // no data (e.g. a bare TCP probe) - nothing to serve
    }
    let _ = stream.set_read_timeout(None); // hand a clean blocking socket to tungstenite

    // services-r7-02: accept with the bearer frame cap (bearer_ws_config) instead of tungstenite's
    // 64 MiB default, so an oversized frame from any mesh peer is rejected rather than buffered.
    let mut ws = match tungstenite::accept_with_config(stream, Some(bearer_ws_config())) {
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
                    if ws.write(Message::Binary(bytes.into())).is_err() {
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

/// Load a stable identity from a 32-byte file (so the endpoint's address - published in DNS
/// - survives restarts), generating and persisting one on first run.
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
        // The endpoint must fetch <origin><path> - never the client-supplied host - and pass the
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
    fn http_proxy_serves_the_signed_well_known_reach_record() {
        // §30: GET /.well-known/hop returns THIS endpoint's signed reach record as JSON, without ever
        // touching the origin (point at a dead port). The served `reach` field must verify in core as a
        // self-certifying binding of the endpoint's own address, proving a client can resolve it.
        use base64::Engine as _;
        let mut node = Endpoint::new(Node::new(Identity::generate()));
        // Prime the node clock exactly as main() does: sign_reach_record stamps issued_at from now_ms,
        // so an un-ticked node would mint issued_at=0 and the record would be born expired. Ticking here
        // (and verifying WITH the expiry check below) is what makes this test catch that regression.
        node.tick(now_ms());
        let addr = node.address();
        *well_known_body().lock().unwrap() = sign_well_known(&node, "wss://example.hopme.sh/");

        let resp = drive_proxy(
            b"GET /.well-known/hop HTTP/1.1\r\nHost: x\r\n\r\n",
            "http://127.0.0.1:1",
            4096,
        );
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "well-known => 200: {resp}"
        );
        assert!(
            resp.contains("Content-Type: application/json"),
            "served as JSON: {resp}"
        );

        // Pull the JSON body, extract the base64 `reach` field, and verify the record in core.
        let json = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        let reach_b64 = json
            .split("\"reach\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("reach field present");
        let record = base64::engine::general_purpose::STANDARD
            .decode(reach_b64)
            .expect("reach is base64");
        // Verify WITH the expiry check (Some(now)), not None: a record signed by an un-ticked node has
        // issued_at=0 and is already expired, so this is the assertion that catches the born-expired bug.
        let now = now_ms() / 1000;
        let rec = hop_core::reach::ReachRecord::verify(&record, Some(now))
            .expect("the served reach record verifies AND is unexpired");
        assert_eq!(
            rec.claim.address, addr,
            "the record certifies THIS endpoint's address"
        );
        assert_eq!(rec.claim.endpoint, "wss://example.hopme.sh/");
        assert!(
            rec.claim.issued_at > 0,
            "issued_at must be real wall time, not 0"
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
        // would shed real traffic (and health probes) - a global availability cap. With the LB
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

    #[test]
    fn read_request_head_rejects_an_oversized_header_block_instead_of_growing_unbounded() {
        // services-r3-03: a hostile client that streams an endless request line / header block must be
        // shed, not allowed to grow the read buffer until OOM. The reader is wrapped in
        // `.take(MAX_REQ_HEAD_BYTES)`, so read_request_head can allocate at most that many bytes and
        // returns None when the head is truncated by the cap. Before the fix, read_line had no cap and
        // this input would grow a String without bound. We model the socket with a Cursor so the test
        // is deterministic (no real OOM needed): the SAME `.take` cap the proxy uses bounds the read.
        use std::io::Cursor;

        // A single header line far larger than the cap, with NO terminator: the classic OOM attempt.
        let hostile_len = (MAX_REQ_HEAD_BYTES as usize) * 4;
        let mut hostile = Vec::with_capacity(hostile_len + 32);
        hostile.extend_from_slice(b"GET / HTTP/1.1\r\nX-Bloat: ");
        hostile.resize(hostile.len() + hostile_len, b'A'); // no CRLF, no blank line: never terminates
        let mut reader = BufReader::new(Cursor::new(hostile).take(MAX_REQ_HEAD_BYTES));
        assert!(
            read_request_head(&mut reader).is_none(),
            "an oversized header block is rejected (shed), not read unbounded into memory"
        );

        // A giant request LINE with no newline is likewise rejected (truncated by the cap).
        let mut giant_line = Vec::new();
        giant_line.extend_from_slice(b"GET /");
        giant_line.resize(giant_line.len() + hostile_len, b'a'); // no '\n' anywhere
        let mut reader = BufReader::new(Cursor::new(giant_line).take(MAX_REQ_HEAD_BYTES));
        assert!(
            read_request_head(&mut reader).is_none(),
            "an oversized request line is rejected, not grown without bound"
        );

        // A normal, well-formed head under the cap still parses cleanly (no false rejection).
        let ok = b"GET /path HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n".to_vec();
        let mut reader = BufReader::new(Cursor::new(ok).take(MAX_REQ_HEAD_BYTES));
        let head = read_request_head(&mut reader).expect("a normal head parses");
        assert!(head.method.eq_ignore_ascii_case("GET"));
        assert_eq!(head.raw_path, "/path");
        assert_eq!(head.xff.as_deref(), Some("9.9.9.9"), "XFF still captured");
    }

    #[test]
    fn serve_http_proxy_rejects_an_oversized_header_head_with_431_not_oom() {
        // End-to-end over a real socket: a hostile oversized header head gets a 431 and the origin is
        // NEVER touched (point the proxy at a dead port to prove no fetch happened). Before the fix,
        // the header read would grow without bound toward OOM instead of a bounded 431 shed.
        use std::net::TcpStream;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let http = test_client();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            // Dead origin port: if the proxy ever fetched, it would 502, not 431.
            serve_http_proxy(sock, "http://127.0.0.1:1", &http, 8 * 1024 * 1024);
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // Send the request line + a header that never terminates: stream well past the cap.
        client.write_all(b"GET / HTTP/1.1\r\nX-Bloat: ").unwrap();
        let chunk = vec![b'A'; 8 * 1024];
        // Write ~1 MiB of header with no CRLF; the proxy caps its read at 64 KiB and sheds.
        for _ in 0..128 {
            if client.write_all(&chunk).is_err() {
                break; // the server may close (shed) mid-stream, which is exactly the point
            }
        }
        let _ = client.flush();

        let mut resp = String::new();
        let _ = client.read_to_string(&mut resp);
        assert!(
            resp.contains("431"),
            "oversized head is shed with 431, not read into OOM; got: {:?}",
            resp.chars().take(80).collect::<String>()
        );
        assert!(
            !resp.contains("502"),
            "the origin must NOT be dialed for an oversized head (no fetch happened)"
        );
        server.join().unwrap();
    }

    #[test]
    fn guard_core_converts_a_core_panic_into_a_logged_skip_not_a_process_death() {
        // services-r3-04: the driver runs node.handle(...) on the main thread. A core panic on a
        // malformed bundle used to kill the whole endpoint (the accept threads DID catch_unwind, the
        // driver did not). guard_core wraps those calls so a panic becomes a caught None and the loop
        // continues. Revert the catch_unwind and this test's panicking closure unwinds the test.
        let ok = guard_core("unit", || 41 + 1);
        assert_eq!(ok, Some(42), "a non-panicking call returns its value");

        let caught = guard_core::<()>("malformed-bundle", || {
            panic!("simulated core panic on a hostile/malformed bundle");
        });
        assert!(
            caught.is_none(),
            "a core panic is caught and reported as a skip (endpoint stays up), not propagated"
        );

        // The endpoint is still usable after a caught panic: the next guarded call runs normally.
        let after = guard_core("post-panic", || "still-alive");
        assert_eq!(
            after,
            Some("still-alive"),
            "the driver keeps processing events after a caught core panic"
        );
    }

    #[test]
    fn classify_head_handles_a_ws_handshake_split_across_tcp_segments() {
        // services-r3-05: a single peek can return only the first TCP segment. If the request line
        // arrives in one segment and `Upgrade: websocket` in the next, a one-shot classify would
        // misroute the WS handshake to the HTTP proxy. classify_head returns None while the head is
        // still incomplete (so peek_kind peeks again), Some(WsUpgrade) once the token arrives, and
        // Some(HttpProxy) only once the whole header block is in with no upgrade token.

        // Segment 1: just the request line - NOT decidable yet (could still be an upgrade).
        assert_eq!(
            classify_head(b"GET / HTTP/1.1\r\nHost: x\r\n"),
            None,
            "an incomplete head with no terminator and no token is undecided (peek again)"
        );
        // Segment 1 + 2 accumulated: the upgrade header has now arrived => WS upgrade.
        assert_eq!(
            classify_head(
                b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            ),
            Some(PeekKind::WsUpgrade),
            "once Upgrade: websocket is seen the split handshake is classified as WS"
        );
        // A COMPLETE plain-HTTP head (blank line seen) with no upgrade token => proxy.
        assert_eq!(
            classify_head(b"GET /page HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(PeekKind::HttpProxy),
            "a complete header block with no upgrade token is a plain HTTP request"
        );
        // Case-insensitive token match (the peek lowercases): an upper-case Upgrade header still wins.
        assert_eq!(
            classify_head(b"GET / HTTP/1.1\r\nUPGRADE: WEBSOCKET\r\n\r\n"),
            Some(PeekKind::WsUpgrade),
            "the upgrade token is matched case-insensitively"
        );
    }

    #[test]
    fn peek_kind_classifies_a_segmented_ws_upgrade_over_a_real_socket() {
        // The end-to-end proof of the split-handshake fix: send the request line, pause, THEN send the
        // Upgrade header in a separate write (a distinct TCP segment). peek_kind must retry the peek
        // and still classify WsUpgrade. A one-shot peek (the old code) would have seen only the first
        // segment and misrouted to the HTTP proxy.
        use std::net::TcpStream;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
            peek_kind(&sock)
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.set_nodelay(true).unwrap();
        // Segment 1: the request line only (no upgrade token yet).
        client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").unwrap();
        client.flush().unwrap();
        std::thread::sleep(Duration::from_millis(60)); // force a segment boundary
                                                       // Segment 2: the upgrade header block.
        client
            .write_all(b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            .unwrap();
        client.flush().unwrap();

        let kind = server.join().unwrap();
        assert_eq!(
            kind,
            PeekKind::WsUpgrade,
            "a WS handshake split across TCP segments is still classified as an upgrade (not misrouted)"
        );
    }

    // ---- parse_args: the CLI decision table (pure over its arg iterator) ------------------------

    fn args_of(a: &[&str]) -> std::vec::IntoIter<String> {
        a.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn parse_args_applies_the_documented_defaults_with_no_flags() {
        // With no CLI flags the endpoint takes its documented defaults: bind 9444, 8 MiB response
        // cap, dial the default relay, and require --origin/--domain later (so they're None here).
        let c = parse_args(std::iter::empty::<String>());
        assert_eq!(c.listen, "0.0.0.0:9444");
        assert!(c.origin.is_none(), "origin defaults unset (required later)");
        assert!(c.domain.is_none(), "domain defaults unset (required later)");
        assert!(c.identity_file.is_none());
        assert_eq!(c.max_resp, 8 * 1024 * 1024);
        assert!(!c.print_address);
        assert_eq!(
            c.relay.as_deref(),
            Some("wss://relay.hopme.sh/"),
            "the default relay is dialed unless overridden"
        );
        assert!(!c.relay_cli_set, "no --relay/--no-relay was given");
    }

    #[test]
    fn parse_args_reads_every_flag_and_ignores_unknowns() {
        // Each flag maps to its field; an unrecognized flag is logged and skipped (lenient), not fatal.
        let c = parse_args(args_of(&[
            "--listen",
            "1.2.3.4:80",
            "--origin",
            "http://backend:8080/",
            "--domain",
            "Example.HopMe.sh.",
            "--identity-file",
            "/etc/hop/id.key",
            "--max-resp",
            "4096",
            "--relay",
            "wss://eu.relay/",
            "--print-address",
            "--totally-unknown-flag",
        ]));
        assert_eq!(c.listen, "1.2.3.4:80");
        assert_eq!(c.origin.as_deref(), Some("http://backend:8080/"));
        // parse_args keeps the raw values; normalization (trim slash / lowercase) happens in main.
        assert_eq!(c.domain.as_deref(), Some("Example.HopMe.sh."));
        assert_eq!(c.identity_file.as_deref(), Some("/etc/hop/id.key"));
        assert_eq!(c.max_resp, 4096);
        assert!(c.print_address);
        assert_eq!(c.relay.as_deref(), Some("wss://eu.relay/"));
        assert!(c.relay_cli_set, "an explicit --relay marks the CLI as set");
    }

    #[test]
    fn parse_args_no_relay_clears_the_relay_and_marks_cli_set() {
        // --no-relay runs the endpoint isolated (listening only); it must clear the default relay AND
        // record that the CLI decided, so env (HOP_RELAY/HOP_NO_RELAY) can't override the operator.
        let c = parse_args(args_of(&["--no-relay"]));
        assert!(c.relay.is_none(), "--no-relay clears the relay");
        assert!(
            c.relay_cli_set,
            "--no-relay marks the CLI as set (env won't override)"
        );
    }

    #[test]
    fn parse_args_bad_max_resp_falls_back_to_the_default() {
        // A non-numeric --max-resp is ignored rather than aborting startup: keep the safe default cap.
        let c = parse_args(args_of(&["--max-resp", "not-a-number"]));
        assert_eq!(
            c.max_resp,
            8 * 1024 * 1024,
            "garbage --max-resp keeps the default"
        );
        // A --listen with no following value keeps the previous (default) listen rather than panicking.
        let c = parse_args(args_of(&["--listen"]));
        assert_eq!(
            c.listen, "0.0.0.0:9444",
            "a dangling --listen keeps the default"
        );
    }

    #[test]
    fn now_ms_returns_a_plausible_unix_millis() {
        // now_ms is the driver's clock source for node.tick; just prove it returns a sane, advancing
        // unix-millis value (well past 2020, and non-decreasing across two reads).
        let a = now_ms();
        let b = now_ms();
        assert!(
            a >= 1_600_000_000_000,
            "now_ms is unix millis (past 2020): {a}"
        );
        assert!(
            b >= a,
            "the wall clock does not go backwards across two reads"
        );
    }

    // ---- handle_http_requests: domain binding + the busy cap + the fetch happy path -------------

    fn req_item_host(method: &str, url: &str, host: &str) -> hop_core::node::HttpReqItem {
        let mut r = req_item(method, url);
        r.host = host.into();
        r
    }

    fn recv_fetched(rx: &mpsc::Receiver<Ev>) -> (u16, String, Vec<u8>) {
        match rx
            .recv_timeout(Duration::from_secs(4))
            .expect("a reply was produced")
        {
            Ev::Fetched(_to, _id, status, ctype, body) => (status, ctype, body),
            other => panic!("expected Ev::Fetched, got a different event: {other:?}"),
        }
    }

    #[test]
    fn handle_http_requests_enforces_domain_binding_serves_matches_and_sheds_when_busy() {
        // The security-critical routing block, tested directly (it was inline in `run`). Three paths:
        //   1. a host that isn't our --domain is refused 403 WITHOUT touching the backend,
        //   2. a request for our domain is fetched from the origin and the reply passed back,
        //   3. over the in-flight fetch cap the request is shed with 503 (no worker spawned).
        let http = test_client();
        let (tx, rx) = mpsc::channel::<Ev>();
        let domain = "example.hopme.sh";

        // 1. Wrong host -> 403, and the dead origin proves no backend fetch happened (no 502 hang).
        handle_http_requests(
            vec![req_item_host("GET", "/x", "evil.example")],
            domain,
            "http://127.0.0.1:1",
            &http,
            1024,
            &tx,
        );
        let (status, ctype, body) = recv_fetched(&rx);
        assert_eq!(status, 403, "a non-authorized host is refused");
        assert!(ctype.starts_with("text/plain"));
        assert!(String::from_utf8_lossy(&body).contains("only serves example.hopme.sh"));

        // A trailing dot / different case on the request host still matches (normalized like --domain).
        let (origin, _o) = stub_origin(1, "200 OK", "text/plain; charset=utf-8", b"ok".to_vec());
        handle_http_requests(
            vec![req_item_host("GET", "/y", "Example.HopMe.sh.")],
            domain,
            &origin,
            &http,
            1024,
            &tx,
        );
        let (status, _ct, body) = recv_fetched(&rx);
        assert_eq!(
            status, 200,
            "a matching host (case/dot-insensitive) is served"
        );
        assert_eq!(body, b"ok", "the origin body is passed back");
        // Let the worker's FetchGuard drop so INFLIGHT_FETCHES settles back to 0 before the cap test.
        std::thread::sleep(Duration::from_millis(50));

        // 3. Over the in-flight cap: shed with 503 before spawning any worker. Simulate saturation by
        // pinning the counter at the cap, then restore it so the shared global isn't left dirty.
        INFLIGHT_FETCHES.fetch_add(MAX_INFLIGHT_FETCHES, Ordering::SeqCst);
        handle_http_requests(
            vec![req_item("GET", "/z")], // host defaults to example.hopme.sh (matches)
            domain,
            "http://127.0.0.1:1", // dead: if a worker DID spawn this would be 502, not 503
            &http,
            1024,
            &tx,
        );
        INFLIGHT_FETCHES.fetch_sub(MAX_INFLIGHT_FETCHES, Ordering::SeqCst);
        let (status, _ct, body) = recv_fetched(&rx);
        assert_eq!(
            status, 503,
            "over the fetch cap the request is shed, not queued"
        );
        assert!(String::from_utf8_lossy(&body).contains("busy"));
    }

    // ---- load_identity: stable-from-file, generate-and-persist, ephemeral ------------------------

    #[test]
    fn load_identity_is_stable_from_a_seed_file_and_persists_a_fresh_one() {
        // The DNS-published address must survive restarts: loading the same seed file yields the same
        // address, and a first run with a missing path GENERATES and PERSISTS a seed so the next load
        // is stable too. A None path is ephemeral (address changes each run).
        let dir = std::env::temp_dir();
        let pid = std::process::id();

        // Case A: an existing 32-byte seed file -> the same address on every load.
        let seed_path = format!("{}/hop-endpoint-seed-A-{pid}.key", dir.display());
        std::fs::write(&seed_path, [7u8; 32]).unwrap();
        let a1 = load_identity(&Some(seed_path.clone()));
        let a2 = load_identity(&Some(seed_path.clone()));
        assert_eq!(
            a1.address(),
            a2.address(),
            "a fixed seed file yields a stable address"
        );
        let _ = std::fs::remove_file(&seed_path);

        // Case B: a missing path -> generate + persist, and the persisted seed reloads to the SAME
        // address (so the published DNS record stays valid across restarts).
        let gen_path = format!("{}/hop-endpoint-seed-B-{pid}.key", dir.display());
        let _ = std::fs::remove_file(&gen_path);
        let b1 = load_identity(&Some(gen_path.clone()));
        assert!(
            std::path::Path::new(&gen_path).exists(),
            "a fresh identity is persisted"
        );
        let b2 = load_identity(&Some(gen_path.clone()));
        assert_eq!(
            b1.address(),
            b2.address(),
            "the persisted seed reloads to the same address"
        );
        let _ = std::fs::remove_file(&gen_path);

        // Case C: no path -> an ephemeral identity (just a well-formed 32-byte address).
        let c = load_identity(&None);
        assert_eq!(
            c.address().len(),
            32,
            "an ephemeral identity still has a 32-byte address"
        );
    }

    // ---- serve_conn: the WebSocket (hops:// bearer) path, end to end over a real socket ---------

    #[test]
    fn serve_conn_bridges_a_websocket_as_a_hop_link_both_directions() {
        // A real WS client drives serve_conn's bearer path: the connection surfaces as Ev::Up(Responder)
        // with a writer; a client Binary frame becomes Ev::Data; bytes pushed to the writer are written
        // back to the client (out_rx -> ws.write); and a client close becomes Ev::Down. This exercises
        // the whole per-connection loop that the driver relies on.
        use tungstenite::connect;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ev_tx, ev_rx) = mpsc::channel::<Ev>();
        let http = test_client();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            serve_conn(sock, &ev_tx, "http://127.0.0.1:1", &http, 1024);
        });

        let url = format!("ws://{addr}/");
        let (mut ws, _resp) = connect(&url).expect("client WS handshake completes");

        // The connection came up as a responder-side Hop link with a writer we can push bytes into.
        let out = match ev_rx.recv_timeout(Duration::from_secs(3)).unwrap() {
            Ev::Up(_link, role, out) => {
                assert_eq!(
                    role,
                    Role::Responder,
                    "an accepted WS is the Responder side"
                );
                out
            }
            other => panic!("expected Ev::Up first, got {other:?}"),
        };

        // Client -> endpoint: a Binary frame surfaces as Ev::Data with the exact bytes.
        ws.send(Message::Binary(vec![1, 2, 3, 4].into())).unwrap();
        ws.flush().unwrap();
        match ev_rx.recv_timeout(Duration::from_secs(3)).unwrap() {
            Ev::Data(_link, bytes) => {
                assert_eq!(bytes, vec![1, 2, 3, 4], "the frame bytes pass through")
            }
            other => panic!("expected Ev::Data, got {other:?}"),
        }

        // Endpoint -> client: bytes pushed to the link writer are written back over the socket.
        out.send(vec![9, 8, 7]).unwrap();
        let got = loop {
            match ws.read().unwrap() {
                Message::Binary(b) => break b,
                _ => continue, // skip any ping/pong control frames
            }
        };
        assert_eq!(
            got,
            vec![9, 8, 7],
            "writer bytes are delivered to the client"
        );

        // Client close -> Ev::Down (the link is torn down).
        ws.close(None).unwrap();
        let _ = ws.flush();
        // Drain the client so tungstenite completes the close handshake.
        while ws.read().is_ok() {}
        match ev_rx.recv_timeout(Duration::from_secs(3)).unwrap() {
            Ev::Down(_link) => {}
            other => panic!("expected Ev::Down on close, got {other:?}"),
        }
        server.join().unwrap();
    }

    #[test]
    fn ws_bearer_config_rejects_an_oversized_frame_at_the_cap() {
        // services-r7-02: the inbound hops:// WS bearer accepts with bearer_ws_config(), which caps a
        // single message/frame at MAX_FRAME_BYTES (the mesh frame cap relayd enforces via services-05)
        // rather than tungstenite's 64 MiB default. Without it, a mesh peer that dials this public
        // endpoint could push a giant frame the single always-on instance must buffer. Drive the REAL
        // bearer_ws_config() serve_conn uses through accept_with_config over a socket with BLOCKING
        // reads (so frame reassembly can't race a read timeout - this isolates the CAP): an under-cap
        // frame reads Ok, an over-cap frame reads Err (rejected). Revert-proof: widening the cap back
        // to tungstenite's default makes the over-cap frame below read Ok instead, failing the test.
        use tungstenite::connect;

        // The config carries exactly the mesh frame cap on BOTH the message and the frame size.
        let cfg = bearer_ws_config();
        assert_eq!(cfg.max_message_size, Some(MAX_FRAME_BYTES));
        assert_eq!(cfg.max_frame_size, Some(MAX_FRAME_BYTES));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || -> (bool, bool) {
            let (sock, _) = listener.accept().unwrap();
            // Accept with the SAME config serve_conn uses; blocking reads (no per-loop timeout).
            let mut ws = tungstenite::accept_with_config(sock, Some(bearer_ws_config())).unwrap();
            // An under-cap frame is delivered; the following over-cap frame is rejected as a read error.
            let small_ok = matches!(ws.read(), Ok(Message::Binary(b)) if b.len() == 4);
            let big_rejected = ws.read().is_err();
            (small_ok, big_rejected)
        });

        let url = format!("ws://{addr}/");
        let (mut ws, _resp) = connect(&url).expect("client WS handshake completes");
        ws.send(Message::Binary(vec![1, 2, 3, 4].into())).unwrap();
        ws.flush().unwrap();
        // Over the cap by one byte: the client (default config) sends it; the capped server rejects it.
        let _ = ws.send(Message::Binary(vec![0xABu8; MAX_FRAME_BYTES + 1].into()));
        let _ = ws.flush();
        let _ = ws.close(None);

        let (small_ok, big_rejected) = server.join().unwrap();
        assert!(small_ok, "an under-cap frame is delivered");
        assert!(
            big_rejected,
            "an over-cap frame is rejected by the bearer frame cap, not buffered (pre-fix 64 MiB default)"
        );
    }

    // ---- peek_kind: the empty (bare probe) and byte-but-undecided fallbacks ---------------------

    #[test]
    fn peek_kind_reports_empty_on_a_bare_tcp_probe() {
        // A connection that opens and closes without sending a byte (a bare TCP probe / health check
        // at the socket layer) classifies as Empty, so serve_conn serves nothing rather than hanging.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
            peek_kind(&sock)
        });
        let client = TcpStream::connect(addr).unwrap();
        drop(client); // send nothing, close immediately -> clean EOF
        assert_eq!(
            server.join().unwrap(),
            PeekKind::Empty,
            "a bare probe is Empty"
        );
    }

    #[test]
    fn peek_kind_falls_back_to_http_proxy_for_bytes_without_a_terminator() {
        // A client that sends a partial head (bytes, but no end-of-headers marker and no upgrade token)
        // must NOT hang forever: after the bounded peek retries, peek_kind falls back to HttpProxy (the
        // safe default) so the proxy path re-reads and handles the odd/partial request.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
            peek_kind(&sock)
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.set_nodelay(true).unwrap();
        // A request line with no blank-line terminator and no upgrade token: undecidable, so peek_kind
        // exhausts its retries and guesses HttpProxy. Keep the socket open through the retry window.
        client
            .write_all(b"GET /partial HTTP/1.1\r\nHost: x\r\n")
            .unwrap();
        client.flush().unwrap();
        let kind = server.join().unwrap();
        assert_eq!(
            kind,
            PeekKind::HttpProxy,
            "bytes with no terminator fall back to the HTTP proxy, not a hang"
        );
        drop(client);
    }

    // ---- run: the driver event loop dispatches Up/Data/Down/Fetched and routes outgoing ---------

    #[test]
    fn run_driver_dispatches_events_and_routes_outgoing_to_the_link_writer() {
        // Drive the real driver loop: an Ev::Up(Initiator) registers a writer AND makes the node emit
        // its Noise handshake msg1, which the driver must route back to that link's writer (out_rx).
        // Then Ev::Data (garbage, guarded), Ev::Fetched (guarded send_http_response), and Ev::Down all
        // dispatch without tearing the loop down. The loop owns a tx clone so it never sees Disconnect;
        // we assert the observable msg1 routing, then let the daemon thread go (it can't be stopped from
        // outside by design, mirroring the always-on production loop).
        let node = Endpoint::new(Node::new(Identity::generate()));
        let (tx, rx) = mpsc::channel::<Ev>();
        let driver_tx = tx.clone();
        let http = test_client();
        std::thread::spawn(move || {
            run(
                node,
                "example.hopme.sh".to_string(),
                "http://127.0.0.1:1".to_string(),
                http,
                1024,
                driver_tx,
                rx,
            );
        });

        // Ev::Up as the Initiator: the node produces handshake msg1, which the driver routes to out_rx.
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>();
        tx.send(Ev::Up(1, Role::Initiator, out_tx)).unwrap();
        let msg1 = out_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("the driver routed the node's handshake msg1 to the link writer");
        assert!(!msg1.is_empty(), "the routed handshake frame is non-empty");

        // Feed the remaining event arms; each must dispatch under guard_core without panicking the loop.
        tx.send(Ev::Data(1, vec![0xde, 0xad, 0xbe, 0xef])).unwrap(); // garbage bundle: guarded parse
        tx.send(Ev::Fetched(
            [0u8; 32],
            [1u8; 32],
            200,
            "text/plain; charset=utf-8".to_string(),
            b"body".to_vec(),
        ))
        .unwrap();
        tx.send(Ev::Down(1)).unwrap();
        // Give the loop time to process those arms and fire at least one recv_timeout tick.
        std::thread::sleep(Duration::from_millis(1200));
        // The loop is still alive (owns its tx); the test's observable proof was the routed msg1 above.
        drop(tx);
    }

    // ---- dial_relay: the connected bridge path and the unreachable-relay backoff path -----------

    #[test]
    fn dial_relay_bridges_a_relay_ws_as_an_initiator_link_and_reports_down_on_close() {
        // Point dial_relay at a local WS server standing in for a relay: it must connect, surface
        // Ev::Up(Initiator) with a writer, relay a server Binary frame as Ev::Data, and report Ev::Down
        // when the relay closes. This covers the connected read/write bridge (the reconnect backoff on
        // the pure side is already covered by reconnect_backoff's test).
        //
        // Determinism note: the relay-side server keeps the connection OPEN and actively re-sends the
        // data frame until the test flips `stop`. If instead it sent one frame and closed, a heavily
        // slowed (e.g. coverage-instrumented) endpoint thread could be scheduled only AFTER the socket
        // was already closed, so its first `ws.read()` would return ConnectionClosed and it would report
        // Down having never drained the buffered data. Holding the connection open (and only closing
        // once the test has observed the data) makes "data before close" a guarantee, not a race.
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = stop.clone();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_nodelay(true).ok(); // no Nagle batching: frames ship immediately
            let mut ws = tungstenite::accept(sock).expect("relay-side WS handshake");
            // Keep an open, actively-flowing connection so the endpoint can never observe a closed
            // socket before it has drained a data frame. Re-send until the test says stop.
            while !stop_srv.load(Ordering::Relaxed) {
                if ws.send(Message::Binary(vec![5, 6, 7].into())).is_err() {
                    break;
                }
                if ws.flush().is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            let _ = ws.close(None); // now close so the endpoint reports Ev::Down
            while ws.read().is_ok() {}
        });

        let url = format!("ws://{addr}/");
        let (ev_tx, ev_rx) = mpsc::channel::<Ev>();
        // dial_relay reconnects forever; run it detached and just observe the first connection's events.
        std::thread::spawn(move || dial_relay(url, ev_tx));

        // Hold the link writer alive for the WHOLE test. If it were dropped (e.g. bound as `_out` in a
        // match arm, which drops at the arm's end), dial_relay's out_rx would see Disconnected and tear
        // the link down (Ev::Down) before it ever read the relay's data frame - an intermittent
        // "Down with no Data" race. Keeping it alive removes the race entirely.
        let out = match ev_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Ev::Up(_link, role, out) => {
                assert_eq!(role, Role::Initiator, "the dialer is the Initiator");
                out
            }
            other => panic!("expected Ev::Up(Initiator) first, got {other:?}"),
        };
        // The relay's data frame is surfaced as Ev::Data with the exact bytes (the connection is still
        // open and flowing, so this is guaranteed to arrive before any close).
        match ev_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Ev::Data(_l, b) => assert_eq!(b, vec![5, 6, 7], "the relay frame bytes pass through"),
            other => panic!("expected Ev::Data while the relay is still open, got {other:?}"),
        }
        // Endpoint -> relay: bytes pushed to the link writer are written out over the WS (dial_relay's
        // out_rx -> ws.write path, incl. the one-shot "sent handshake" log). The relay drains them when
        // it closes below.
        out.send(vec![1, 2, 3]).unwrap();
        // Now let the relay close and confirm the endpoint reports the link Down (draining any extra
        // buffered data frames first).
        stop.store(true, Ordering::Relaxed);
        loop {
            match ev_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
                Ev::Down(_l) => break,        // clean close reported
                Ev::Data(_l, _b) => continue, // drain frames buffered before the close
                other => panic!("expected Ev::Down after the relay closes, got {other:?}"),
            }
        }
        drop(out); // release the writer only after the link teardown was observed
        server.join().unwrap();
    }

    #[test]
    fn dial_relay_reports_the_degraded_state_when_the_relay_is_unreachable() {
        // A dead relay (connection refused) must NOT surface a link: dial_relay takes the error/backoff
        // branch (log + reconnect_backoff sleep) and no Ev::Up ever arrives. We observe the absence of a
        // link within a short window; the dialer then sleeps in backoff (detached, mirroring production
        // where the endpoint keeps serving its origin while mesh reachability is down).
        let (ev_tx, ev_rx) = mpsc::channel::<Ev>();
        std::thread::spawn(move || dial_relay("ws://127.0.0.1:1/".to_string(), ev_tx));
        // Nothing should come up: the relay is refused, so the error branch runs and backs off.
        assert!(
            matches!(
                ev_rx.recv_timeout(Duration::from_millis(500)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "an unreachable relay never surfaces a link (it degrades and backs off)"
        );
    }

    // ---- build_endpoint: origin/domain normalization + leaf-node configuration ------------------

    #[test]
    fn build_endpoint_normalizes_origin_and_domain_and_builds_a_leaf_node() {
        // The operator's --origin/--domain are normalized before use: the origin loses a trailing '/'
        // (so requests are exactly `<origin><path>`), and the domain is lowercased with any trailing
        // dot stripped (so the case-insensitive host binding compares cleanly). The node is built as an
        // Endpoint leaf (it never relays others' bundles) named for the domain.
        let identity = Identity::generate();
        let expected_addr = identity.address();
        let (node, origin, domain) = build_endpoint(
            "http://backend:8080/".to_string(),
            "Example.HopMe.SH.".to_string(),
            identity,
            "0.0.0.0:9444",
        );
        assert_eq!(
            origin, "http://backend:8080",
            "a trailing slash is stripped"
        );
        assert_eq!(
            domain, "example.hopme.sh",
            "the domain is lowercased with the trailing dot removed"
        );
        assert_eq!(
            node.address(),
            expected_addr,
            "the node keeps the supplied identity's address (published in DNS)"
        );
    }

    // ---- read_request_head: the empty/EOF/read-error edges -------------------------------------

    #[test]
    fn read_request_head_returns_none_on_an_empty_reader() {
        // No bytes at all (a bare TCP probe that sends nothing) => None, so the proxy serves nothing.
        use std::io::Cursor;
        let mut reader = BufReader::new(Cursor::new(Vec::<u8>::new()).take(MAX_REQ_HEAD_BYTES));
        assert!(
            read_request_head(&mut reader).is_none(),
            "an empty read yields no request head"
        );
    }

    #[test]
    fn read_request_head_serves_complete_lines_then_eof_without_a_blank_line() {
        // A client that sends a complete request line + header then closes (EOF at a line boundary, no
        // terminating blank line) is served leniently from the complete lines already read. A non-XFF
        // header is skipped; the method/path are parsed.
        use std::io::Cursor;
        let raw = b"GET /page HTTP/1.1\r\nHost: example\r\n".to_vec(); // no trailing blank line
        let mut reader = BufReader::new(Cursor::new(raw).take(MAX_REQ_HEAD_BYTES));
        let head = read_request_head(&mut reader).expect("complete lines are served on EOF");
        assert!(head.method.eq_ignore_ascii_case("GET"));
        assert_eq!(head.raw_path, "/page");
        assert!(head.xff.is_none(), "no X-Forwarded-For present");
    }

    /// A reader that emits its buffered bytes once, then fails every subsequent read. Wrapped in a
    /// BufReader it lets `read_request_head` parse the request line, then errors while draining
    /// headers, exercising the read-error branch of the header loop.
    struct FailingReader {
        data: std::io::Cursor<Vec<u8>>,
    }
    impl std::io::Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = std::io::Read::read(&mut self.data, buf)?;
            if n == 0 {
                return Err(std::io::Error::other("boom"));
            }
            Ok(n)
        }
    }

    #[test]
    fn read_request_head_stops_gracefully_on_a_header_read_error() {
        // A read error while draining headers must not panic: we stop and serve what we parsed (the
        // request line). Models a socket that faults after delivering the request line.
        let reader = FailingReader {
            data: std::io::Cursor::new(b"GET /x HTTP/1.1\r\n".to_vec()),
        };
        let mut reader = BufReader::new(reader);
        let head = read_request_head(&mut reader).expect("the request line still parses");
        assert!(head.method.eq_ignore_ascii_case("GET"));
        assert_eq!(head.raw_path, "/x");
    }

    // ---- serve_http_proxy: the max_resp truncation on the plain-HTTP path -----------------------

    #[test]
    fn http_proxy_truncates_a_body_over_max_resp() {
        // The plain-HTTP reverse proxy applies the same hard body cap as the hops:// path, so a huge
        // origin response can't blow memory. Point it at a stub returning 5000 bytes with max_resp=100.
        let (origin, _rx) = stub_origin(1, "200 OK", "application/octet-stream", vec![9u8; 5000]);
        let resp = drive_proxy(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n", &origin, 100);
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "status passes through: {resp}"
        );
        assert!(
            resp.contains("Content-Length: 100"),
            "the body is truncated to the max_resp cap: {resp}"
        );
    }

    // ---- allow_source: the map sweep once the tracked-source set grows large --------------------

    #[test]
    fn allow_source_sweeps_the_map_once_it_grows_past_the_threshold() {
        // The per-source map is swept of expired windows once it exceeds RATE_MAP_SWEEP_AT so it can't
        // grow without bound. Insert more than the threshold of distinct sources to trip the sweep; all
        // are fresh (< the window) so every source is retained and still admitted.
        use std::net::Ipv4Addr;
        // Distinct, high addresses that won't collide with the small fixed IPs other tests use.
        let n = (RATE_MAP_SWEEP_AT as u32) + 2;
        let mut admitted = true;
        for i in 0..n {
            let ip = IpAddr::V4(Ipv4Addr::from(0xB000_0000u32 + i));
            admitted &= allow_source(ip);
        }
        assert!(
            admitted,
            "fresh distinct sources are all admitted (and the sweep retains them)"
        );
    }

    // ---- load_identity: the persist-failure warning path ---------------------------------------

    #[test]
    fn load_identity_still_returns_an_identity_when_persistence_fails() {
        // If the seed can't be persisted (e.g. an unwritable path), load_identity logs a warning and
        // still returns a usable (ephemeral) identity rather than aborting startup.
        let bad = format!(
            "{}/hop-endpoint-nodir-{}/id.key", // parent dir does not exist -> create fails
            std::env::temp_dir().display(),
            std::process::id()
        );
        let id = load_identity(&Some(bad));
        assert_eq!(
            id.address().len(),
            32,
            "an identity is returned even when the seed cannot be persisted"
        );
    }

    // ---- serve_conn: the plain-HTTP route, empty/invalid handshakes, writer teardown ------------

    fn spawn_serve_conn(
        origin: &'static str,
        max_resp: u32,
    ) -> (
        std::net::SocketAddr,
        mpsc::Receiver<Ev>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ev_tx, ev_rx) = mpsc::channel::<Ev>();
        let http = test_client();
        let h = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            serve_conn(sock, &ev_tx, origin, &http, max_resp);
        });
        (addr, ev_rx, h)
    }

    #[test]
    fn serve_conn_routes_a_plain_http_request_to_the_reverse_proxy() {
        // serve_conn peeks, sees no WS upgrade, and hands a plain HTTP request to the reverse proxy.
        // /healthz answers 200 without touching the (dead) origin, proving the proxy branch ran.
        let (addr, ev_rx, h) = spawn_serve_conn("http://127.0.0.1:1", 1024);
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        let _ = client.read_to_string(&mut resp);
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "proxied healthz: {resp}"
        );
        // The proxy path never surfaces a bearer link.
        assert!(
            ev_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "a plain HTTP request produces no bearer Ev::Up"
        );
        h.join().unwrap();
    }

    #[test]
    fn serve_conn_returns_on_a_bare_probe_without_serving() {
        // A connection that opens and closes with no bytes classifies Empty; serve_conn returns without
        // surfacing a link or hanging.
        let (addr, ev_rx, h) = spawn_serve_conn("http://127.0.0.1:1", 1024);
        let client = TcpStream::connect(addr).unwrap();
        drop(client); // send nothing, close
        assert!(
            ev_rx.recv_timeout(Duration::from_millis(500)).is_err(),
            "a bare probe surfaces no events"
        );
        h.join().unwrap();
    }

    #[test]
    fn serve_conn_returns_when_the_websocket_handshake_is_invalid() {
        // A request whose head carries the upgrade token but is not a valid WS handshake (no
        // Sec-WebSocket-Key) is classified WsUpgrade, then tungstenite::accept rejects it and serve_conn
        // returns without ever surfacing Ev::Up.
        let (addr, ev_rx, h) = spawn_serve_conn("http://127.0.0.1:1", 1024);
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            )
            .unwrap();
        // The handshake is rejected; the server closes without surfacing a link.
        let mut resp = Vec::new();
        let mut buf = [0u8; 512];
        while let Ok(n) = client.read(&mut buf) {
            if n == 0 {
                break;
            }
            resp.extend_from_slice(&buf[..n]);
        }
        assert!(
            ev_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "an invalid WS handshake surfaces no Ev::Up"
        );
        h.join().unwrap();
    }

    #[test]
    fn serve_conn_tears_down_the_link_when_its_writer_is_dropped() {
        // Dropping the link's writer (out_tx, carried on Ev::Up) makes serve_conn's out_rx see a
        // Disconnected on the next loop and break the connection, reporting Ev::Down. This is the path
        // the driver uses to close a link (it drops the writer when the link goes away).
        use tungstenite::connect;
        let (addr, ev_rx, h) = spawn_serve_conn("http://127.0.0.1:1", 1024);
        let (mut ws, _resp) = connect(format!("ws://{addr}/")).expect("WS handshake");
        let out = match ev_rx.recv_timeout(Duration::from_secs(3)).unwrap() {
            Ev::Up(_l, _role, out) => out,
            other => panic!("expected Ev::Up, got {other:?}"),
        };
        drop(out); // the driver dropped this link's writer
        match ev_rx.recv_timeout(Duration::from_secs(3)).unwrap() {
            Ev::Down(_l) => {}
            other => panic!("expected Ev::Down after the writer is dropped, got {other:?}"),
        }
        let _ = ws.close(None);
        while ws.read().is_ok() {}
        h.join().unwrap();
    }

    #[test]
    fn serve_conn_ignores_non_binary_control_and_text_frames() {
        // Only Binary frames carry Hop link packets; a Text (or control) frame is ignored (no Ev::Data)
        // and the link stays up until close. Proves the Ok(_) arm of the read loop.
        use tungstenite::connect;
        let (addr, ev_rx, h) = spawn_serve_conn("http://127.0.0.1:1", 1024);
        let (mut ws, _resp) = connect(format!("ws://{addr}/")).expect("WS handshake");
        // Hold the writer alive so serve_conn tears down via the Close frame (reading + ignoring the
        // Text frame first), not via an early out_rx Disconnected from a dropped writer.
        let out = match ev_rx.recv_timeout(Duration::from_secs(3)).unwrap() {
            Ev::Up(_l, _r, out) => out,
            other => panic!("expected Ev::Up, got {other:?}"),
        };
        ws.send(Message::Text("not a hop packet".into())).unwrap();
        ws.flush().unwrap();
        // A Text frame yields no Ev::Data; the next event we expect is Down after we close.
        ws.close(None).unwrap();
        let _ = ws.flush();
        while ws.read().is_ok() {}
        match ev_rx.recv_timeout(Duration::from_secs(3)).unwrap() {
            Ev::Down(_l) => {}
            Ev::Data(_l, _b) => panic!("a non-binary frame must not surface Ev::Data"),
            other => panic!("unexpected event: {other:?}"),
        }
        drop(out);
        h.join().unwrap();
    }

    // ---- peek_kind: the buffer-full guess and the stalled-peer timeout --------------------------

    #[test]
    fn peek_kind_guesses_http_proxy_when_the_peek_buffer_fills_undecided() {
        // A client that streams more than the 2 KiB peek buffer with no end-of-headers marker and no
        // upgrade token fills the buffer while still undecided; peek_kind stops peeking and falls back
        // to HttpProxy (the proxy re-reads and handles/sheds it).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
            peek_kind(&sock)
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.set_nodelay(true).unwrap();
        // > 2048 bytes, no CRLFCRLF, no upgrade token: undecidable, buffer fills.
        let mut blob = Vec::new();
        blob.extend_from_slice(b"GET /");
        blob.resize(4096, b'a');
        client.write_all(&blob).unwrap();
        client.flush().unwrap();
        assert_eq!(
            server.join().unwrap(),
            PeekKind::HttpProxy,
            "a full buffer with no decision falls back to HttpProxy"
        );
        drop(client);
    }

    #[test]
    fn peek_kind_reports_empty_when_the_peer_connects_but_stalls() {
        // A peer that connects and holds the socket open without sending anything must not hang the
        // handler: the peek times out on the first attempt with no bytes and classifies Empty.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            // A short read timeout so the first peek returns TimedOut quickly (no data sent).
            sock.set_read_timeout(Some(Duration::from_millis(80))).ok();
            peek_kind(&sock)
        });
        let client = TcpStream::connect(addr).unwrap();
        // Hold the connection open (send nothing) long enough for the peek to time out, then close.
        let kind = server.join().unwrap();
        drop(client);
        assert_eq!(
            kind,
            PeekKind::Empty,
            "a connected-but-silent peer times out to Empty rather than hanging"
        );
    }

    // ---- ConnGuard / FetchGuard: the counters decrement on drop (incl. panic unwind) ------------

    #[test]
    fn conn_guard_decrements_active_conns_on_drop() {
        // The accept loop bumps ACTIVE_CONNS and relies on ConnGuard::drop to release the slot when the
        // handler thread finishes (or unwinds). Prove the Drop decrements. Uses the global counter,
        // which no other test mutates, and restores it to its starting value.
        let before = ACTIVE_CONNS.load(Ordering::SeqCst);
        ACTIVE_CONNS.fetch_add(1, Ordering::SeqCst);
        {
            let _g = ConnGuard; // dropped at the end of this scope -> fetch_sub(1)
        }
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            before,
            "ConnGuard::drop released the connection slot"
        );
    }

    #[test]
    fn fetch_guard_decrements_inflight_fetches_on_drop() {
        // The fetch worker bumps INFLIGHT_FETCHES and relies on FetchGuard::drop to release the slot.
        let before = INFLIGHT_FETCHES.load(Ordering::SeqCst);
        INFLIGHT_FETCHES.fetch_add(1, Ordering::SeqCst);
        {
            let _g = FetchGuard; // dropped here -> fetch_sub(1)
        }
        assert_eq!(
            INFLIGHT_FETCHES.load(Ordering::SeqCst),
            before,
            "FetchGuard::drop released the in-flight fetch slot"
        );
    }

    // ---- read_request_head: request-line and truncated-header-line edges ------------------------

    #[test]
    fn read_request_head_rejects_a_request_line_with_no_newline() {
        // A request line that arrives without a terminating newline (the byte cap truncated it) is
        // rejected rather than parsed as a partial target.
        use std::io::Cursor;
        let mut reader = BufReader::new(Cursor::new(b"GET /no-newline".to_vec()).take(64));
        assert!(
            read_request_head(&mut reader).is_none(),
            "a request line with no newline is shed"
        );
    }

    #[test]
    fn read_request_head_rejects_a_truncated_header_line() {
        // A header line with no terminator (the cap landed mid-header) is an oversized/hostile head and
        // is shed, not parsed as a partial header.
        use std::io::Cursor;
        // Complete request line, then a header that never terminates within the cap.
        let mut raw = b"GET / HTTP/1.1\r\nX-Long: ".to_vec();
        raw.resize(raw.len() + 200, b'z'); // no CRLF
        let mut reader = BufReader::new(Cursor::new(raw).take(64));
        assert!(
            read_request_head(&mut reader).is_none(),
            "a header line truncated by the cap is shed"
        );
    }

    #[test]
    fn read_request_head_captures_x_forwarded_for() {
        // The X-Forwarded-For header is captured (keyed on the trusted last hop) for the per-client
        // rate limit; other headers are drained and ignored.
        use std::io::Cursor;
        let raw =
            b"GET /p HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 1.1.1.1, 2.2.2.2\r\nAccept: */*\r\n\r\n"
                .to_vec();
        let mut reader = BufReader::new(Cursor::new(raw).take(MAX_REQ_HEAD_BYTES));
        let head = read_request_head(&mut reader).expect("a well-formed head parses");
        assert_eq!(head.raw_path, "/p");
        assert_eq!(
            head.xff.as_deref(),
            Some("2.2.2.2"),
            "the last (trusted) XFF hop is captured"
        );
    }
}
