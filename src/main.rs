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
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hop_core::prelude::*;
use tungstenite::Message;

static NEXT_LINK: AtomicU64 = AtomicU64::new(1);

/// Driver events: bearer lifecycle + a completed backend fetch handed back from a worker.
enum Ev {
    Up(u64, Role, Sender<Vec<u8>>),
    Data(u64, Vec<u8>),
    Down(u64),
    /// A finished HTTP fetch: reply (to, for_request_id, status, content_type, body).
    Fetched(PubKeyBytes, BundleId, u16, String, Vec<u8>),
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
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
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => listen = args.next().unwrap_or(listen),
            "--origin" => origin = args.next(),
            "--domain" => domain = args.next(),
            "--identity-file" => identity_file = args.next(),
            "--max-resp" => max_resp = args.next().and_then(|s| s.parse().ok()).unwrap_or(max_resp),
            "--relay" => relay = args.next(),
            "--no-relay" => relay = None, // run isolated (listening only), e.g. for local tests
            // Load the identity, print its base58 address, and exit. Used to fill in the
            // `_hopaddress.<domain>` TXT record before the endpoint ever serves traffic.
            "--print-address" => print_address = true,
            other => eprintln!("ignoring unknown arg: {other}"),
        }
    }

    if print_address {
        let identity = load_identity(&identity_file);
        println!("{}", bs58::encode(identity.address()).into_string());
        return;
    }
    let origin = origin.unwrap_or_else(|| {
        eprintln!("--origin http://your-backend is required (the ONLY backend this endpoint serves)");
        std::process::exit(2);
    });
    let domain = domain.unwrap_or_else(|| {
        eprintln!("--domain example.com is required (the ONLY hops:// host this endpoint answers for)");
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
    println!("hop-endpoint: publish DNS →  _hopaddress.{domain}  TXT  \"{}\"", bs58::encode(addr).into_string());
    println!("hop-endpoint: listening on {listen} (ws = hops:// bearer, http = reverse-proxy to origin)");

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
                let (tx, origin, http) = (tx.clone(), origin.clone(), http_accept.clone());
                std::thread::spawn(move || serve_conn(stream, &tx, &origin, &http, max_resp));
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

/// Dial a relay over `wss://` and bridge it as a Hop bearer link (we're the Initiator), so
/// this endpoint is reachable by its address through the mesh. Reconnects forever. Same
/// read-timeout interleave as the inbound bearer, but as a TLS WebSocket client.
fn dial_relay(url: String, ev_tx: Sender<Ev>) {
    use tungstenite::stream::MaybeTlsStream;
    loop {
        match tungstenite::connect(&url) {
            Ok((mut ws, _resp)) => {
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
                        Err(tungstenite::Error::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
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
            }
            Err(e) => eprintln!("hop-endpoint: relay {url} unreachable ({e}); retrying"),
        }
        std::thread::sleep(Duration::from_secs(5));
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
                eprintln!("hop-endpoint: refusing host {:?} (authorized: {domain})", r.host);
                let body = format!("hop-endpoint: this endpoint only serves {domain}").into_bytes();
                let ct = "text/plain; charset=utf-8".to_string();
                let _ = tx.send(Ev::Fetched(r.from, r.id, 403, ct, body));
                continue;
            }
            let (origin, http, tx) = (origin.clone(), http.clone(), tx.clone());
            std::thread::spawn(move || {
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
        .map(|rest| rest.split_once('/').map(|(_, p)| format!("/{p}")).unwrap_or_else(|| "/".to_string()))
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
    // Drain the rest of the headers so the client's send completes cleanly.
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line == "\r\n" || line == "\n" => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    let head_only = method.eq_ignore_ascii_case("HEAD");
    let (status, ctype, body) = if !method.eq_ignore_ascii_case("GET") && !head_only {
        (405u16, "text/plain; charset=utf-8".to_string(), b"hop-endpoint: only GET/HEAD over plain HTTP".to_vec())
    } else {
        let url = format!("{origin}{}", path_of(&raw_path));
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
            Err(_) => (502, "text/plain; charset=utf-8".to_string(), b"hop-endpoint: backend unreachable".to_vec()),
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
    let _ = ws.get_ref().set_read_timeout(Some(Duration::from_millis(100)));

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
        if std::fs::write(path, id.to_secret_bytes()).is_err() {
            eprintln!("warning: could not persist identity to {path}; address will change on restart");
        }
        return id;
    }
    eprintln!("warning: no --identity-file; address will change on restart (DNS would go stale)");
    Identity::generate()
}
