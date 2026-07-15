<p align="center">
  <img alt="Hop" src="https://hopme.sh/hop-mark.svg" width="200">
</p>

<h1 align="center">hop-endpoint</h1>

<p align="center">
  <b>A <code>hops://</code> origin endpoint: your HTTP backend, reachable over the Hop mesh and bound to one domain.</b><br>
  HTTP over the mesh, terminated by you, for exactly your domain.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-stable-CE422B" alt="Rust">
  <img src="https://img.shields.io/badge/deploy-Cloud%20Run%20%C2%B7%20Docker-1f6feb" alt="Cloud Run · Docker">
  <img src="https://img.shields.io/badge/license-Apache--2.0-3ddc84" alt="license Apache-2.0">
</p>

---

Hop is a **delay-tolerant, end-to-end-encrypted mesh**: messages hop device to device over BLE, Wi-Fi,
and the internet until they reach the person or service you meant. Held, never dropped.

**hop-endpoint is a `hops://` origin.** It's a listening Hop node that terminates `hops://` for exactly
one domain and translates each request to your own HTTP backend, so a mesh client can reach your
service the way a browser reaches an origin. It is never an open proxy: it rejects any request whose
signed `host` isn't its configured `--domain`, and the URL it fetches is built solely from `--origin`
plus the request path, so the request's own bytes never choose a host.

## Run it

```sh
hop-endpoint \
  --listen 0.0.0.0:9444 \
  --domain example.hopme.sh \
  --origin http://localhost:8080 \
  --identity-file /etc/hop/identity
```

Full flags:

```
hop-endpoint --listen 0.0.0.0:9444 --domain example.hopme.sh \
             --origin http://localhost:8080 [--identity-file PATH] [--max-resp BYTES]
```

Clients dial the endpoint directly, so you bear the cost of your own traffic; the relay fleet is never
a conduit for domain traffic. Front `--listen` with TLS exactly like a web origin (the LB terminates
`wss://<domain>:9444/` to the plain `ws` this speaks).

## Reachable by name

The endpoint publishes its own binding: it serves a signed reach record at
`https://<domain>/.well-known/hop`, and a client resolves the domain by fetching that one URL. The
domain's TLS cert proves the domain, the served record self-certifies the address, and the Noise
handshake confirms it. Spoof the DNS or MITM the lookup and the attacker still can't forge the cert or
complete the handshake as the address. Route the well-known GET to this same HTTP server; the endpoint
re-signs the record well within its TTL, so a long-lived process never serves a stale binding.

## Bound to one origin

Domain binding is enforced at the protocol layer, before the backend is ever touched:

- Every `hops://` request carries a signed `host`. The endpoint is configured with exactly one
  `--domain` and returns 403 for any other host.
- The fetched URL is `<origin><path>`, built only from `--origin`; the request's bytes never pick a host.
- Redirects are disabled, so the backend can't bounce the endpoint off-origin either.

There is no code path by which this process fetches anything other than your configured origin. If you
want general, allowlisted egress instead of a single origin, that's a [gateway](https://github.com/hopmesh/hop-gateway).

## Configure

| Env / flag          | Purpose                                                          |
| ------------------- | ---------------------------------------------------------------- |
| `PORT`              | Cloud Run's serving port; the WebSocket bearer binds here        |
| `HOP_DOMAIN`        | the single domain this endpoint is authorized to serve           |
| `HOP_IDENTITY_FILE` | path to the 32-byte identity seed, for a stable published address |
| `--origin`          | your backend base URL; the endpoint fetches only `<origin><path>` |
| `--max-resp BYTES`  | cap on the backend response size streamed back to the mesh       |
| `HOP_CLUSTER_SECRET`| optional: run multiple replicas that gossip handled messages     |

## Status

Prototype. The listening node, the domain-binding guard, the well-known reach-record publish and
re-sign, and the backend translation are built and unit-tested. Optional replica clustering (same
identity, membership plus handled-message gossip) is off unless `HOP_CLUSTER_SECRET` is set.

## The Hop family

Hop is one protocol with many faces. The endpoint SDKs, same surface in your language:
[node](https://github.com/hopmesh/hop-sdk-node) ·
[python](https://github.com/hopmesh/hop-sdk-python) ·
[go](https://github.com/hopmesh/hop-sdk-go) ·
[ruby](https://github.com/hopmesh/hop-sdk-ruby) ·
[crystal](https://github.com/hopmesh/hop-sdk-crystal) ·
[elixir](https://github.com/hopmesh/hop-sdk-elixir) ·
[apple](https://github.com/hopmesh/hop-sdk-apple) ·
[android](https://github.com/hopmesh/hop-sdk-android).
The protocol core is [hop-core](https://github.com/hopmesh/hop-core) / [libhop](https://github.com/hopmesh/libhop).

## License

[Apache-2.0](./LICENSE.md), use it freely. Only the protocol core (`hop-core`) is FSL-1.1-ALv2,
source-available and converting to Apache-2.0 after two years.
