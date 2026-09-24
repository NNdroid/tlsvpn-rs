# tlsvpn-rs

**tlsvpn-rs** is the Rust implementation of [tlsvpn](https://github.com/NNdroid/tlsvpn) — a high-performance, high-stealth Layer 2 VPN that carries Ethernet frames over standard TCP TLS.

The Rust and Go binaries are **fully interchangeable**: any client works against any server, locked byte-for-byte by shared protocol golden vectors and cross-implementation e2e tests. Beyond parity, the Rust build adds an event-driven I/O core (mio + Waker), multi-worker server sharding, and a protocol-path benchmark of **~3.7 GB/s** (frame scan + inner crypto, single core).

## Features

- **Camouflage** — real TLS with ALPN (`h2`/`http1.1`) and randomized payload padding. Invalid-PSK connections get an nginx-styled 403 page or a slow-loris tarpit; probes (printable first byte) are detected inside the TLS stream as well.
- **Inner encryption (optional)** — AES-256-GCM *inside* TLS, with random per-direction salts, separate data/FEC keys, `nonce = seq‖salt`, and AAD over `wireLen‖seq`. Protocol v2 only.
- **Server-observed TLS diagnostics** — a successful application handshake can return an optional `tls` object with the negotiated version/cipher/ALPN/SNI and the ordered ClientHello cipher, signature, group and ALPN features actually seen by the server. The client Web UI displays the `tls-clienthello-v1` SHA-256. It filters GREASE and is intentionally **not called JA3/JA4**, because rustls/Go do not expose the full raw extension order. The digest is for diagnostics, not authentication; randoms, tickets, certificate bodies and key material are never returned.
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
  "up": "",
  "down": "",
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
  "server": { "v4_cidr": "10.0.0.0/24", "v6_cidr": "fd00::/64", "cert": "", "key": "", "max_sessions": 1024 }
}
```

</details>

All defaults match the Go implementation 1:1. Two fields are Rust extensions (`workers`, `mtu`) — Go has no such keys and refuses a config file containing them, so they only belong in Rust-only files.

| Field | Default | Where | Description |
| --- | --- | --- | --- |
| `mode` | (required) | — | `server` or `client` |
| `psk` | (required) | — | High-entropy pre-shared key. Empty and known placeholder values are rejected |
| `addr` | server `0.0.0.0:4000` | — | **Server**: listen address (`:4000` binds all interfaces). **Client**: comma-separated targets for multi-IP round-robin |
| `up` / `down` | (empty) | — | Absolute executable paths for process-level tunnel lifecycle hooks |
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
Session resume tokens are a mandatory protocol-v2 property and are always enabled. There is no `server.session_token` switch. Legacy configs containing that key are still accepted during upgrade, but its value is ignored.

| `server.v4_cidr` | `10.0.0.0/24` | server | IPv4 pool for clients (gateway = first host). Bare IPs are accepted; garbage is refused rather than silently downgrading to the default pool |
| `server.v6_cidr` | `fd00::/64` | server | IPv6 pool for clients |
| `server.cert` / `server.key` | (required) | server | TLS certificate pair (PEM). A missing file or a cert/key that don't match is reported as `Invalid configuration: server.cert …` and exits 1 — it must not be a panic |
| `server.max_sessions` | `1024` | server | Maximum concurrent sessions |
| `server.fec_group_min` | `2` | server | Lower bound on a peer's FEC group size K; an FEC handshake below it is refused |
| `server.fec_group_max` | `64` | server | Upper bound on a peer's FEC group size K; an FEC handshake above it is refused. Neither end is clamped, and defaults are the protocol limits so nothing is limited unless configured. The parity is broadcast to all N backends, so the redundancy ratio is N/K: a `min` floor bounds bandwidth, a `max` ceiling bounds pending-frame buffering and recovery latency |
| `client.conns` | `1` | client | Parallel TCP connections (multi-IP round-robin, MinRTT/FEC multipath) |
| `client.fec` | `false` | client | XOR-parity FEC over multipath; the parity is broadcast to all N backends, so the redundancy ratio is N/K |
| `client.fec_group` | `4` | client | XOR FEC group size K (2–64), clamped into range before it goes on the wire; the server may refuse an out-of-policy K |
| `client.sni` | `www.cloudflare.com` | client | SNI domain for handshake camouflage |
| `client.insecure` | `false` | client | Skip server TLS verification (prefer `cert_sha256`) |
| `client.cert_sha256` | (empty) | client | Pin the server cert by SHA-256 fingerprint (hex, colon-tolerant) |
| `client.req_v4` / `req_v6` | (empty) | client | Request a specific internal IPv4/IPv6 address |
| `client.fwmark` | `0` | client | Policy-routing fwmark for traffic splitting (Linux). `0` disables the fwmark rule only; a non-empty `client.source_rules` still enables policy routing |
| `client.fwmark_priority` | `0` | client | `ip rule` priority, a uint32. `0` = let the kernel assign one. Use it on machines that already run policy routing to make this client's rule win or lose |
| `client.extra_routes` | `[]` | client | Extra routes into the fwmark table, in iproute2 serialization form — one prefix plus an optional `dev`, e.g. `"fd99:10:5:8::/64 dev tap0"`. The address family is inferred from the prefix, so no `-4`/`-6`; with no `dev` the tunnel TAP is used. Validated at config load, not after the tunnel handshake |
| `client.source_rules` | `[]` | client | Policy-routing rules matched on the packet's **source prefix** instead of `SO_MARK`. Each entry installs `ip rule from <from> table <table>` plus that table's default routes (from the gateways the server sends) and any `routes` you list. Use it for traffic that has no socket to mark — e.g. packets an NPT gateway forwards, whose return flow must be pinned to the tunnel TAP. `from` may be a bare address (completed to a host route); `table` is mandatory and must be in `[1, 65535]`, excluding the kernel-reserved `253`/`254`/`255`; `priority` is a uint32, `0` = kernel-assigned. Validated at config load |

**Policy routing is owned by the process, not by systemd.** With a non-zero `fwmark` — or a non-empty `client.source_rules` — the client installs the `ip rule` entries and the routes itself, and it removes whatever it installed on exit. For the fwmark rule the table number is always equal to the fwmark value — a `fwmark` of `0x100` means table `256`, so don't reach for a different table number; `source_rules` tables are whatever you configured, and nothing derives them for you. It waits up to 30 s for the TAP to exist and be up before touching routing, so a network manager that creates the device later doesn't need a separate ordering unit. Do **not** also keep an external drop-in doing the same work: two rules for one fwmark compete by priority, the kernel serves whichever wins, and each of them believes it owns the table. The dashboard's *Status → Configuration* page lists the fwmark, priority, table number, extra routes and source rules, and *Status → Negotiation* shows whether policy routing actually took effect or the exact `ip` error it hit.

### `up` / `down` lifecycle hooks

```json
{ "up": "/etc/openvpn/up.sh", "down": "/etc/openvpn/down.sh" }
```

The Go and Rust builds use the same semantics. Hooks are executed directly, not through `sh -c`, so the file needs a shebang and executable permission (`chmod 0755`); paths must be absolute. Each hook has a 30-second timeout and uses the configuration directory as its working directory. `up` runs once after the TAP addresses and built-in policy routing are ready. Parallel connections and short reconnects do not run it again. `down` runs once while the TAP still exists on graceful shutdown, and is also attempted after a partially successful `up`. A failing `up` aborts startup; a failing `down` returns a failing process status. Hooks run with the same UID/capabilities as tlsvpn and are **not a sandbox**: only point them at administrator-controlled files. The inherited environment is reduced to a safe PATH/locale (plus required Windows system variables), so service credentials are not forwarded. The timeout terminates the immediate hook process, not an arbitrary descendant tree; scripts must supervise and clean up any children they create. The first SIGINT/SIGTERM begins this graceful path, while a second signal forces exit. `SIGKILL`, a kernel panic, or power loss cannot run cleanup code.

Scripts receive OpenVPN-style variables `script_type`, `dev`, `dev_type=tap`, `config`, `ifconfig_local`, `ifconfig_ipv6_local`, `route_vpn_gateway`, and `route_ipv6_gateway`, plus `TLSVPN_SCRIPT_TYPE`, `TLSVPN_MODE`, `TLSVPN_DEV`, `TLSVPN_CONFIG`, `TLSVPN_IPV4`, `TLSVPN_IPV6`, `TLSVPN_GATEWAY_V4`, and `TLSVPN_GATEWAY_V6`. The PSK is deliberately never exported.

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
(cd ../tlsvpn && go build -C interop -o interop/probe .)  # Go probe
./scripts/e2e_test.sh                           # all suites
./scripts/e2e_test.sh accept tok                # selected suites
```

| Suite | Cases | Covers |
| --- | ---: | --- |
| `accept` | 21 | Feature matrix: all on, all off (fallback), both-ends-upgraded, plus 5 pre-v2-rejection cases that need old binaries |
| `tok` | 4 | Resume-token hijack via two same-MAC clients — all four Rust/Go server-client combinations must reject a new process that lacks the current token |
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
