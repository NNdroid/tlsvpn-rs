# tlsvpn-rs

**tlsvpn-rs** is the Rust implementation of [tlsvpn](https://github.com/NNdroid/tlsvpn) — a high-performance, high-stealth Layer 2 VPN tunnel that transmits Ethernet frames over standard TCP TLS. The Go and Rust binaries are **fully interoperable and interchangeable**: either client works against either server, enforced byte-for-byte by shared protocol golden vectors and cross-implementation end-to-end tests.

Beyond parity, the Rust build adds its own focus: an event-driven I/O core (mio + Waker), multi-worker server sharding, and a protocol-path benchmark of **~3.7 GB/s** (frame scan + inner crypto, single core).

## 🌟 Core Features

* **🛡️ Camouflage**: Standard TLS with ALPN (h2/http1.1) and randomized payload padding. Non-VPN or invalid-PSK connections get an nginx-styled 403 page or a slow-loris tarpit; probe traffic (printable first byte) is detected inside the TLS stream as well.
* **🔐 Inner Encryption (Optional)**: `--encrypt` adds AES-256-GCM **inside** the TLS tunnel with per-session random salts (one per direction, nonce = seq‖salt, AAD covers wireLen‖seq) — integrity protection, and immunity to keystream reuse across sessions/directions/clients. Older peers transparently fall back to legacy AES-CTR.
* **⚡ TCP Brutal**: Optional TCP Brutal congestion control (Linux `tcp_brutal` module) holding a fixed rate under loss.
* **🔗 Multipath**: Parallel TCP connections with MinRTT load balancing, or XOR-parity FEC — every K data frames carry one parity frame (overhead ≈ 1/K) so any single lost frame is transparently reconstructed. Legacy packet-duplication FEC remains as the automatic fallback.
* **🌐 Multi-IP Failover**: Comma-separated server addresses, round-robin per connection, exponential backoff with jitter and 30s-stable reset.
* **📦 Layer 2 Tunneling**: TAP device (ARP/DHCP/IPv6 pass-through), MAC learning switch with flooding, session survivorship (120s grace with seamless resume across reconnects/restarts).
* **📊 Web Dashboard**: Same UI as the Go build — live throughput chart, FEC/loss stats, per-connection details, MAC table, ban/kick management, live log tail & level switching, Prometheus `/metrics`.
* **🚀 Server Sharding**: `--workers N` spawns N event-loop workers (independent pollers, session tables) behind a shared acceptor — line-rate beyond a single core.
* **📦 Zero-Copy Data Path**: Frames travel as `Arc`-shared buffers end to end — broadcast/flood/multi-backend dispatch is reference-count only, with AVX2-accelerated FEC parity math and O(1) reorder-gap resolution.

---

## 🚀 Quick Start

### 1. Build

```bash
git clone https://github.com/NNdroid/tlsvpn-rs.git
cd tlsvpn-rs
cargo build --release
# binary: target/release/tlsvpn
```

### 2. Server (Linux, root)

```bash
# generate a TLS pair once (any method, e.g.):
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 3650 -nodes -subj "/CN=tlsvpn"

sudo ./target/release/tlsvpn --mode server --psk "your_secret_key" --addr ":4000" \
  --cert server.crt --key server.key --encrypt --web ":8080" --web-auth "admin:change-me"
```

### 3. Client

```bash
sudo ./target/release/tlsvpn --mode client --psk "your_secret_key" \
  --addr "203.0.113.10:4000,[2001:db8::10]:4000" \
  --conns 4 --fec --encrypt --brutal
```

Windows/macOS clients work with `--tap mem` (no kernel TAP); interface addressing and policy routing are Linux features.

### 4. JSON Config File

`-c config.json` makes the file the **single source of truth** — all other flags are ignored, unknown fields are rejected, and the format is **identical to the Go build** (you can swap binaries without touching the config).

```bash
# Print the full template from the binary itself
./tlsvpn --print-config > config.json
```

```json
{
  "mode": "client",
  "psk": "change-me-please",
  "addr": "203.0.113.10:4000,[2001:db8::10]:4000",
  "encrypt": true,
  "brutal": true, "brutal_up": 100, "brutal_down": 500,
  "workers": 4,
  "web": { "addr": ":8080", "auth": "admin:change-me" },
  "client": { "conns": 4, "fec": true, "fec_group": 4 }
}
```

Server mode uses `"mode": "server"` with a `server` section (`v4_cidr`, `v6_cidr`, `cert`, `key`) instead of `client`. Field-by-field reference below.

> Unlike the Go server, the Rust server requires an explicit `--cert`/`--key` (no self-signed generation). Generate a pair once, pin it on clients via `cert_sha256`, and it survives restarts the same way.

---

## 🛠️ Configuration Reference (JSON)

Values and defaults match the Go implementation 1:1; the only Rust-specific field is `workers`.

### 🟢 Global

| Field | Default | Description |
| --- | --- | --- |
| `mode` | (Required) | `server` or `client` |
| `psk` | `quic_secret` ⚠️ | Pre-shared key. The default is accepted only with a loud warning — always set your own |
| `addr` | server `0.0.0.0:4000` / client (Required) | **Server**: listen address (`:4000` binds all interfaces). **Client**: comma-separated target list for multi-IP round-robin |
| `tap` | `tap0` | TAP device name. `"mem"` uses an in-memory backend (CI/e2e, no kernel device) |
| `mac` | (Empty) | Manually specify the TAP interface MAC (part of the client identity) |
| `log_level` | `info` | `debug` / `info` / `warn` / `error` (switchable live from the dashboard) |
| `encrypt` | `false` | Inner AES-256-GCM payload encryption with per-session salts (legacy CTR fallback for old peers) |
| `brutal` / `brutal_up` / `brutal_down` | `false` / `100` / `500` | TCP Brutal congestion control and rates (Mbps) |
| `socks5` | (Empty) | Client: route ALL outbound sockets through a SOCKS5 proxy (`host:port`, `user:pass@host:port`, `socks5h://…`) |
| `workers` | `0` | **Rust server only**: worker event-loop threads (0 = auto, one per CPU up to 8) |
| `mtu` | `1500` | TAP device MTU. Larger values (e.g. 8000–16000) mean fewer frames, TLS records and syscalls per byte — set it on **both** ends (sender's frame size, receiver accepts up to 128 KB by protocol) |

### 🌐 web (Optional — dashboard is off unless `web.addr` is set)

| Field | Default | Description |
| --- | --- | --- |
| `addr` | (Empty) | Dashboard listen address (e.g. `:8080`) |
| `auth` | (Empty) | Basic Auth as `user:pass`. Strongly recommended when binding a non-loopback address |

### 🔵 server (Server mode only)

| Field | Default | Description |
| --- | --- | --- |
| `v4_cidr` | `10.0.0.0/24` | IPv4 address pool for clients (gateway = first host) |
| `v6_cidr` | `fd00::/64` | IPv6 address pool for clients |
| `cert` / `key` | (Required in Rust) | TLS certificate pair (PEM) |

### 🟡 client (Client mode only)

| Field | Default | Description |
| --- | --- | --- |
| `conns` | `1` | Parallel TCP connections (multi-IP round-robin, MinRTT/FEC multipath) |
| `fec` | `false` | FEC over multipath (XOR parity when the server supports it, else duplication) |
| `fec_group` | `4` | XOR FEC group size K (2–64); parity overhead is 1/K |
| `sni` | `www.cloudflare.com` | SNI domain used during the TLS handshake for camouflage |
| `insecure` | `false` | Skip server TLS verification (prefer `cert_sha256`) |
| `cert_sha256` | (Empty) | Pin the server certificate by SHA-256 fingerprint (hex, colon-tolerant) |
| `req_v4` / `req_v6` | (Empty) | Request a specific internal IPv4/IPv6 address |
| `fwmark` | `0` | Policy routing fwmark (transparent proxies / traffic splitting, Linux) |

---

## 📈 Web Dashboard (Optional)

Off by default; enable with `web.addr` for **both** server and client. Throughput chart (120s), FEC recovered/lost counters, per-connection RTT/bytes/retries, MAC learning table, IP-pool usage, ban/kick/kick-all with immediate effect, in-panel log tail (500 lines) with live level switching, and Prometheus `/metrics`.

Security: `web.auth` (Basic Auth, constant-time compare) and a CSRF header guard (`X-Requested-With`) on every control action.

## ⚠️ Important Notes

1. **Kernel Module**: Brutal mode requires the `tcp_brutal` congestion-control module (Linux only; other platforms log a warning and continue without it).
2. **Permissions**: `/dev/net/tun` access, typically root.
3. **Client identity**: the ClientID is derived from the TAP MAC + PSK. If the real MAC cannot be determined (e.g. `--tap mem`), a warning is logged and an all-zero MAC is used — set `mac` explicitly when running many such clients, or they will share one identity/IP.
4. **Interoperability**: handshake fields `fec_group`, `enc_algo`, `enc_salt`, `enc_salt2` are additive; older peers (Go or Rust) interoperate in fallback mode (duplication FEC / legacy CTR).

---

## 🧪 Protocol Interop & Benchmarks

The protocol contract is locked by **golden vectors** (`tlsvpn/testdata/protocol_golden.json`, generated by the Go repo) covering key derivation, CTR keystream, frame headers, and handshake field names — `cargo test --test protocol_conformance` fails on any drift.

Cross-implementation e2e probes (self-contained protocol stacks, no shared code) verify real interop:

```bash
# Rust probe -> any server (Go or Rust)
cargo run --release --example interop_client -- --addr 127.0.0.1:4000 --psk secret --encrypt --fec 4

# Go probe -> any server
go build -C interop -o probe.exe . && ./interop/probe.exe --addr <server> --psk secret --encrypt --fec --fec-group 4
```

Protocol-path benchmark (frame scan + legacy inner crypto, 1M iterations, single core):

```bash
cargo test --release bench_protocol_throughput -- --ignored --nocapture
# Protocol Throughput: ~3200 MB/s
```

Same-machine deployments can squeeze out further CPU headroom with a PGO + native-CPU build (instrument → run local traffic → recompile):

```bash
rustup component add llvm-tools-preview
./scripts/build_pgo.sh   # requires the e2e cert pair in the repo root; see script
```

---

## 📎 Appendix: Command-Line Flags

All flags still work for quick one-liners; `-c config.json` overrides everything. Flag names map 1:1 to the JSON fields (`--brutal-up` ↔ `brutal_up`, etc.).

```bash
# Server one-liner
sudo ./tlsvpn --mode server --psk "your_secret_key" --addr ":4000" --cert server.crt --key server.key \
  --encrypt --brutal --workers 4 --web ":8080" --web-auth "admin:pass"

# Client one-liner
sudo ./tlsvpn --mode client --addr "1.1.1.1:4000,[::1]:4000" --psk "your_secret_key" \
  --conns 4 --fec --fec-group 4 --encrypt --brutal --brutal-down 500

# Shared   : --psk --tap --mac --loglevel --encrypt --brutal --brutal-up --brutal-down --web --web-auth
# Server   : --v4cidr --v6cidr --cert --key --workers
# Client   : --conns --fec --fec-group --req-v4 --req-v6 --sni --insecure --cert-sha256 --fwmark --socks5
# Utility  : --print-config
```

---

*Disclaimer: This project is for educational and authorized network testing purposes only.*
