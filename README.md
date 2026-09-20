# tlsvpn-rs

**tlsvpn-rs** is the Rust implementation of [tlsvpn](https://github.com/NNdroid/tlsvpn) — a high-performance, high-stealth Layer 2 VPN that carries Ethernet frames over standard TCP TLS.

The Rust and Go binaries are **fully interchangeable**: any client works against any server, locked byte-for-byte by shared protocol golden vectors and cross-implementation e2e tests. Beyond parity, the Rust build adds an event-driven I/O core (mio + Waker), multi-worker server sharding, and a protocol-path benchmark of **~3.7 GB/s** (frame scan + inner crypto, single core).

## Features

- **Camouflage** — real TLS with ALPN (`h2`/`http1.1`) and randomized payload padding. Invalid-PSK connections get an nginx-styled 403 page or a slow-loris tarpit; probes (printable first byte) are detected inside the TLS stream as well.
- **Inner encryption (optional)** — AES-256-GCM *inside* TLS, with random per-direction salts, separate data/FEC keys, `nonce = seq‖salt`, and AAD over `wireLen‖seq`. Protocol v2 only.
- **Multipath & FEC** — parallel TCP connections with MinRTT load balancing, or XOR-parity FEC: one parity frame per K data frames (≈1/K overhead) so any single lost frame is reconstructed transparently. Duplication FEC remains the automatic fallback.
- **Resilience** — comma-separated server addresses with round-robin per connection, exponential backoff with jitter, 30s-stable reset.
- **Layer 2** — TAP device (ARP/DHCP/IPv6 pass-through), MAC-learning switch with flooding, and session survivorship: 120s grace with seamless resume across reconnects and restarts.
- **Zero-copy data path** — frames stay `Arc`-shared end to end, so broadcast/flood/multi-backend dispatch is reference-count only, with AVX2-accelerated FEC parity math and O(1) reorder-gap resolution.
- **Server sharding** — `workers: N` runs N event-loop workers (independent pollers and session tables) behind a shared acceptor; line-rate beyond a single core.
- **Dashboard** — live throughput chart, FEC/loss stats, per-connection details, MAC table, ban/kick management, log tail with live level switching, Prometheus `/metrics`.
- **TCP Brutal** — optional `tcp_brutal` congestion control that holds a fixed rate under loss (Linux only).

## Quick Start

**Server** (Linux, root):

```bash
git clone https://github.com/NNdroid/tlsvpn-rs.git && cd tlsvpn-rs
cargo build --release

# generate a TLS pair once, then pin it on clients via cert_sha256
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
            -days 3650 -nodes -subj "/CN=tlsvpn"

sudo ./target/release/tlsvpn -c server.json
```

```json
{
  "mode": "server",
  "psk": "GENERATE-A-UNIQUE-RANDOM-SECRET",
  "addr": ":4000",
  "encrypt": true,
  "web": { "addr": ":8080", "auth": "admin:GENERATE-A-UNIQUE-PASSWORD", "bind": "tunnel" },
  "server": { "cert": "server.crt", "key": "server.key" }
}
```

**Client**:

```json
{
  "mode": "client",
  "psk": "GENERATE-A-UNIQUE-RANDOM-SECRET",
  "addr": "203.0.113.10:4000,[2001:db8::10]:4000",
  "encrypt": true,
  "brutal": true, "brutal_up": 100, "brutal_down": 500,
  "client": { "conns": 4, "fec": true, "fec_group": 4 }
}
```

```bash
sudo ./target/release/tlsvpn -c client.json
```

Windows and macOS clients work with `"tap": "mem"` (no kernel TAP); interface addressing and policy routing are Linux features.

Fuller ready-made examples are checked in at the repo root — `config.server.json` and `config.client.json` (same `psk`, so they pair up). They're validated by the test suite, so they never drift from the binary. They deliberately omit the two Rust-only keys (`workers`, `mtu`) so the Go binary can read them too: Go decodes with `DisallowUnknownFields` and refuses the whole file over an unknown key.

## Configuration

`-c config.json` is the **only** configuration surface — there are no other flags, and the format is identical to the Go build, so binaries can be swapped without touching a config. Unknown fields are rejected. Start from the built-in template:

```bash
./tlsvpn --print-config > config.json
```

<details><summary>Full template (matches <code>--print-config</code>)</summary>

```json
{
  "mode": "client",
  "psk": "REPLACE-WITH-A-RANDOM-SECRET",
  "addr": "203.0.113.10:4000,[2001:db8::10]:4000",
  "log_level": "info",
  "encrypt": true,
  "min_enc": "gcm",
  "pad_mode": "bucket",
  "brutal": true,
  "brutal_up": 100,
  "brutal_down": 500,
  "workers": 4,
  "mtu": 1500,
  "socks5": "",
  "tap": "tap0",
  "mac": "",
  "web": { "addr": ":8080", "auth": "admin:REPLACE-WITH-A-RANDOM-PASSWORD", "bind": "tunnel", "cert": "", "key": "" },
  "client": { "conns": 4, "fec": true, "fec_group": 4, "sni": "www.cloudflare.com",
              "insecure": false, "cert_sha256": "", "req_v4": "", "req_v6": "", "fwmark": 0 },
  "server": { "v4_cidr": "10.0.0.0/24", "v6_cidr": "fd00::/64", "cert": "", "key": "",
              "session_token": true, "max_sessions": 1024 }
}
```

</details>

All defaults match the Go implementation 1:1. Two fields are Rust extensions (`workers`, `mtu`) — Go has no such keys and refuses a config file containing them, so they only belong in Rust-only files.

| Field | Default | Where | Description |
| --- | --- | --- | --- |
| `mode` | (required) | — | `server` or `client` |
| `psk` | (required) | — | High-entropy pre-shared key. Empty and known placeholder values are rejected |
| `addr` | server `0.0.0.0:4000` | — | **Server**: listen address (`:4000` binds all interfaces). **Client**: comma-separated targets for multi-IP round-robin |
| `encrypt` | `true` when omitted in JSON | — | Inner AES-256-GCM with per-session salts and separate data/FEC key domains |
| `min_enc` | `""` | — | Strength floor: `gcm` refuses peers that cannot negotiate GCM, `""`/`any` sets no floor. Requires `encrypt: true`; connections below the floor are refused |
| `pad_mode` | `bucket` | — | Full-record padding: `bucket` maps every record to a fixed size with positive padding; only `off` permits zero padding |
| `brutal` | `false` | — | TCP Brutal congestion control (Linux `tcp_brutal` module) |
| `brutal_up` / `brutal_down` | `100` / `500` | — | Brutal rates in Mbps |
| `workers` | `0` | — | **Rust-only extension** — Go rejects this key. Worker event-loop threads (0 = auto, one per CPU up to 8) |
| `mtu` | `1500` | — | **Rust-only extension** — Go rejects this key. TAP MTU; higher values (8000–16000) mean fewer frames, TLS records and syscalls per byte — set it on **both** ends (receiver accepts up to 128 KB) |
| `tap` | `tap0` | — | TAP device name. `"mem"` is an in-memory backend (CI/e2e, no kernel device) |
| `mac` | (empty) | — | Explicit non-zero unicast TAP MAC. If empty, both real and `mem` clients generate and persist one; the server derives ClientID from canonical MAC + PSK |
| `socks5` | (empty) | — | Route **all** outbound sockets through a SOCKS5 proxy (`host:port`, `user:pass@host:port`, `socks5h://…`) |
| `log_level` | `info` | — | `trace` / `debug` / `info` / `warn` / `error` — validated at startup, anything else is refused (switchable live from the dashboard) |
| `web.addr` | (empty) | — | Dashboard listen address; off unless set |
| `web.auth` | (required when enabled) | — | Basic Auth as `user:pass`, compared as fixed-length SHA-256 digests. Known example credentials are rejected |
| `web.bind` | `all` | — | `all` = every interface; `tunnel` = tunnel IPs only (server: pool gateway v4+v6, client: assigned IP; rebinds within 2s as IPs appear). Binds are **per address**: if the v6 gateway is tentative or disabled it retries on its own while the v4 listener keeps serving. On Linux the tunnel addresses are brought `up` first and the v6 address gets `nodad` — without it a v6 address that has no RA to answer for stays tentative forever, and `[fd00::1]:8080` never binds |
| `web.cert` / `web.key` | (empty) | — | Dashboard HTTPS pair. Required when `web.bind=all` exposes a non-loopback listener |
| `server.v4_cidr` | `10.0.0.0/24` | server | IPv4 pool for clients (gateway = first host). Bare IPs are accepted; garbage is refused rather than silently downgrading to the default pool |
| `server.v6_cidr` | `fd00::/64` | server | IPv6 pool for clients |
| `server.cert` / `server.key` | (required) | server | TLS certificate pair (PEM). A missing file or a cert/key that don't match is reported as `Invalid configuration: server.cert …` and exits 1 — it must not be a panic |
| `server.session_token` | `false` | server | Compatibility field only — the Rust server always issues a random 256-bit resume token and rotates the key epoch on reconnect, whatever this value is. Retained so a Go config file stays readable (`deny_unknown_fields` would otherwise refuse it) |
| `server.max_sessions` | `1024` | server | Maximum concurrent sessions |
| `client.conns` | `1` | client | Parallel TCP connections (multi-IP round-robin, MinRTT/FEC multipath) |
| `client.fec` | `false` | client | FEC over multipath — XOR parity when the server supports it, else duplication |
| `client.fec_group` | `4` | client | XOR FEC group size K (2–64); parity overhead is 1/K |
| `client.sni` | `www.cloudflare.com` | client | SNI domain for handshake camouflage |
| `client.insecure` | `false` | client | Skip server TLS verification (prefer `cert_sha256`) |
| `client.cert_sha256` | (empty) | client | Pin the server cert by SHA-256 fingerprint (hex, colon-tolerant) |
| `client.req_v4` / `req_v6` | (empty) | client | Request a specific internal IPv4/IPv6 address |
| `client.fwmark` | `0` | client | Policy-routing fwmark for traffic splitting (Linux) |

Keys that belong to the other mode are accepted but have no effect (a server ignores `client.*`, a client ignores `server.*`). Every non-default one is called out on startup — `ignored (mode=server has no effect on them): server.v4_cidr, server.v6_cidr, server.cert` — so a value pasted into the wrong block can't fail silently. Defaults are not listed, since they just mean the key wasn't written.

> Unlike the Go server, the Rust server requires explicit `server.cert`/`server.key` — no self-signed generation. Generate a pair once and it survives restarts the same way.

## Dashboard

Off by default; set `web.addr` on **both** sides to enable it. Served over HTTPS whenever `web.cert`/`web.key` are set, plain HTTP otherwise. Throughput chart (120s), FEC recovered/lost counters, per-connection RTT/bytes/retries, MAC table, IP-pool usage, ban/kick/kick-all with immediate effect, in-panel log tail (500 lines) with live level switching, and Prometheus `/metrics`. Every control action requires a CSRF header (`X-Requested-With`).

## Notes

1. **Kernel module** — Brutal mode needs the Linux `tcp_brutal` module; elsewhere a warning is logged and it continues without it.
2. **Permissions** — TAP requires `/dev/net/tun` access, typically root.
3. **Client identity** — the ClientID derives from canonical TAP MAC + PSK. If no MAC is configured or readable, including `"tap": "mem"`, the client generates and persists a random non-zero unicast MAC together with its token and epoch.
4. **Interoperability** — current Go and Rust builds share strict protocol v2 and byte-for-byte golden vectors, including data/FEC GCM domains. Upgrade both ends together; there is no pre-v2 compatibility mode, so an old binary is refused rather than downgraded.

## Development

**Interop is locked by golden vectors.** `tlsvpn/testdata/protocol_golden.json` (generated by the Go repo) covers key derivation, CTR keystream, frame headers and handshake field names; `cargo test --test protocol_conformance` fails on any drift.

**Cross-implementation e2e** — `scripts/e2e_test.sh` drives the four suites below against a real Rust build and a real Go build over the in-memory TAP, so it needs no `CAP_NET_ADMIN` and runs for real on hosted CI:

```bash
./scripts/build.sh native                      # Rust server/client
cargo build --examples                          # Rust probe
(cd ../tlsvpn && ./scripts/build.sh)            # Go server/client
go build -C interop -o interop/probe .          # Go probe
./scripts/e2e_test.sh                           # all suites
./scripts/e2e_test.sh accept tok                # selected suites
```

| Suite | Cases | Covers |
| --- | ---: | --- |
| `accept` | 21 | Feature matrix: all on, all off (fallback), both-ends-upgraded, plus 5 pre-v2-rejection cases that need old binaries |
| `tok` | 6 | Resume-token hijack via two same-MAC clients — 4 cross-language rejects + 2 `session_token=false` still-rejected controls |
| `pad` | 12 | `pad_mode` off / bucket / bogus × rs,go server × rs,go client |
| `minenc` | 19 | `min_enc` floors × declared `enc_algo`, including an unknown algo ID, plus 3 Go-probe crossings |
| `cfg` | 38 | 6 config dimensions × 4 rs/go combinations (CIDR pools, `client.conns`, `web.auth`, panel HTTPS, `web.bind=tunnel`, `log_level`) + 7 startup-rejection cases × 2 implementations |

Each suite is also standalone with its own env knobs (`SRV`, `CLI`, `PAD`, `PORT`, …), and ports are offset per case from a `PORT_BASE_*` var so concurrent runs don't collide. The 5 pre-v2-rejection cases in `accept` are the only ones that need an old binary — they print a skip count instead of failing when `E2E_RS_OLD_BIN`, `E2E_RS_OLD_PROBE` and `E2E_GO_OLD_BIN` aren't set. `e2e_cert.pem`/`e2e_key.pem` are gitignored and generated on demand; shared helpers are in `scripts/e2e_lib.sh`.

**Standalone probes** verify real interop against either server:

```bash
cargo run --release --example interop_client -- \
  --addr 127.0.0.1:4000 --psk secret --encrypt --fec 4
```

**Benchmark & build options**

```bash
cargo test --release bench_protocol_throughput -- --ignored --nocapture
# Protocol Throughput: ~3200 MB/s

./scripts/build_pgo.sh   # PGO + native-CPU; needs rustup llvm-tools-preview
```

`scripts/build.sh` takes `native` (default, host build), `musl` (the three static release targets, via `cross`), `gnu` (x86_64+aarch64 cross) or `all`; artifacts land in `dist/` as `tlsvpn-<target-triple>`.

Real-network tests (ping v4/v6, traceroute, iperf3, optional librespeed) live in `scripts/net_perf_test.sh` and run as the `net-perf` CI job. Hosted runners lack `CAP_NET_ADMIN`, so the job self-skips there — run `sudo bash scripts/net_perf_test.sh` on a Linux box or a privileged self-hosted runner for real results.

## CLI

Two verbs, nothing else:

```bash
./tlsvpn -c config.json   # run server or client, per the config's "mode"
./tlsvpn --print-config   # print the template and exit
```

`-c` also accepts `--config path` and `--config=path`. Running without `-c` prints this usage and exits.

---

*Disclaimer: This project is for educational and authorized network testing purposes only.*
