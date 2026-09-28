# tlsvpn-rs

**tlsvpn-rs** is the Rust implementation of [tlsvpn](https://github.com/NNdroid/tlsvpn) — a high-performance, high-stealth Layer 2 VPN that carries Ethernet frames over standard TCP TLS.

The Rust and Go binaries are **wire-compatible**: any current Rust/Go client-server pairing speaks the same strict protocol v2, locked byte-for-byte by shared protocol golden vectors and cross-implementation e2e tests. Runtime configuration and WebUI backend capabilities are intentionally documented separately below because they are not currently identical. Beyond wire parity, the Rust build adds an event-driven I/O core (mio + Waker) and multi-worker server sharding.

## Features

- **Camouflage** — real TLS with ALPN (`h2`/`http1.1`) and randomized payload padding. Invalid-PSK connections get an nginx-styled 403 page or a slow-loris tarpit; probes (printable first byte) are detected inside the TLS stream as well.
- **Inner encryption (optional)** — authenticated AEAD *inside* TLS: AES-256-GCM (`gcm256`, default), AES-128-GCM (`gcm128`), ChaCha20-Poly1305 (`chacha20`) or XChaCha20-Poly1305 (`xchacha20`). Data/FEC use separate keys and per-direction session salts. AES-GCM/ChaCha20 use `seq(4BE) || salt(8B)` nonces; XChaCha20 uses a derived 20-byte prefix plus `seq(4BE)`. AAD is `dataLen(4BE) || seq(4BE)`, and every current algorithm uses a 16-byte tag. Both peers must match exactly.
- **Server-observed TLS diagnostics** — a successful application handshake can return an optional `tls` object with the negotiated version/cipher/ALPN/SNI and the ordered ClientHello cipher, signature, group and ALPN features actually seen by the server. The client Web UI displays the `tls-clienthello-v1` SHA-256. It filters GREASE and is intentionally **not called JA3/JA4**, because rustls/Go do not expose the full raw extension order. The digest is for diagnostics, not authentication; randoms, tickets, certificate bodies and key material are never returned.
- **Multipath & FEC** — parallel TCP connections with MinRTT load balancing and XOR-parity FEC: one parity frame per K data frames (≈1/K overhead) so any single lost frame is reconstructed transparently. The old duplication-FEC fallback has been removed from the current wire protocol.
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
  "enc_algo": "gcm256",
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
  "enc_algo": "gcm256",
  "brutal": true, "brutal_up": 100, "brutal_down": 500,
  "client": { "conns": 4, "fec": true, "fec_group": 4 }
}
```

```bash
sudo ./target/release/tlsvpn -c client.json
```

`"tap": "mem"` is a CI/e2e backend only: it has no real subnet behind it, drops writes, and does not provide a usable host VPN interface. Real interface addressing and policy routing are currently Linux-oriented.

Fuller ready-made examples are checked in at the repo root — `config.server.json` and `config.client.json` (same `psk`, so they pair up). They're validated by the test suite and deliberately stay inside the Go/Rust shared config subset. Rust-only `workers`/`mtu` are omitted so Go can read them. Persistent traffic-accounting keys (`traffic_days`, `traffic_file`) are supported by both implementations.

## Configuration

`-c config.json` is the **only** runtime configuration surface. `--print-config` prints a template and `-version`/`--version` prints the build version; neither adds runtime tuning flags. The shared protocol/network fields intentionally track Go, but the complete config schemas are **not identical**: Rust adds `workers`/`mtu`, Rust currently supports only `client.interface_manager=self`, and Rust server mode requires an explicit certificate/key pair. `traffic_days`/`traffic_file` are shared by both implementations. Unknown fields are rejected. Start from the built-in shared-subset template:

```bash
./tlsvpn --print-config > config.json
./tlsvpn -version
```

<details><summary>Representative shared-subset template (use <code>--print-config</code> for the canonical current output)</summary>

```json
{
  "mode": "client",
  "psk": "REPLACE-WITH-A-RANDOM-SECRET",
  "addr": "203.0.113.10:4000,[2001:db8::10]:4000",
  "log_level": "info",
  "up": "",
  "down": "",
  "encrypt": true,
  "enc_algo": "gcm256",
  "min_enc": "gcm",
  "pad_mode": "bucket",
  "brutal": true,
  "brutal_up": 100,
  "brutal_down": 500,
  "traffic_days": 30,
  "traffic_file": "tlsvpn-traffic.json",
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

The wire-facing defaults are kept aligned with Go, but the full config surfaces differ. Rust-only `workers` and `mtu` belong only in Rust-specific files; `traffic_days` and `traffic_file` are shared with Go and drive the same persistent daily-traffic dashboard view. `client.interface_manager=netifd` is a Go/OpenWrt integration and is currently rejected by Rust (use `self`). Rust server mode also requires explicit `server.cert`/`server.key`, whereas Go can generate and persist a self-signed pair.

Session resume tokens are a mandatory protocol-v2 property and are always enabled. There is no `server.session_token` switch. Legacy configs containing that key are still accepted during upgrade, but its value is ignored.

| Field | Default | Where | Description |
| --- | --- | --- | --- |
| `mode` | (required) | — | `server` or `client` |
| `psk` | (required) | — | High-entropy pre-shared key. Empty and known placeholder values are rejected |
| `addr` | server `0.0.0.0:4000` | — | **Server**: listen address (`:4000` binds all interfaces). **Client**: comma-separated targets for multi-IP round-robin |
| `up` / `down` | (empty) | — | Absolute executable paths for process-level tunnel lifecycle hooks |
| `encrypt` | `true` when omitted in JSON | — | Enable inner authenticated AEAD |
| `enc_algo` | `gcm256` | — | `gcm256` (AES-256-GCM), `gcm128` (AES-128-GCM), `chacha20` (ChaCha20-Poly1305), or `xchacha20` (XChaCha20-Poly1305). Both peers must match exactly |
| `min_enc` | `gcm` when `encrypt=true` | — | Minimum inner-encryption policy. Omitted/empty normalizes to `gcm`; the legacy name means require a supported authenticated inner AEAD. Explicit `any` removes the floor. Requires `encrypt=true` |
| `pad_mode` | `bucket` | — | Full-record padding: `bucket` maps every record to a fixed size with positive padding; only `off` permits zero padding |
| `brutal` | `false` | — | TCP Brutal congestion control (Linux `tcp_brutal` module) |
| `brutal_up` / `brutal_down` | `100` / `500` | — | Brutal rates in Mbps |
| `traffic_days` | `30` | — | Daily traffic retention in local-calendar days (`1`–`3650`), hot-applicable from the dashboard |
| `traffic_file` | `tlsvpn-traffic.json` beside the config | — | Persistent aggregate traffic store; per-client history uses the sibling `-clients.json` file |
| `workers` | `0` | — | **Rust-only extension** — Go rejects this key. Worker event-loop threads (0 = auto, one per CPU up to 8) |
| `mtu` | `1500` | — | **Rust-only extension** — Go rejects this key. TAP MTU, validated in the `576`–`9000` range. Use the same intended L2 MTU on both tunnel endpoints |
| `tap` | `tap0` | — | TAP device name. `"mem"` is an in-memory backend (CI/e2e, no kernel device) |
| `mac` | (empty) | — | Explicit non-zero unicast TAP MAC. If empty, both real and `mem` clients generate and persist one; the server derives ClientID from canonical MAC + PSK |
| `socks5` | (empty) | — | Route **all** outbound sockets through a SOCKS5 proxy (`host:port`, `user:pass@host:port`, `socks5h://…`) |
| `log_level` | `info` | — | `trace` / `debug` / `info` / `warn` / `error` — validated at startup, anything else is refused (switchable live from the dashboard) |
| `web.addr` | (empty) | — | Dashboard listen address; off unless set |
| `web.auth` | (required when enabled) | — | Credential source as `user:pass`. Browser login exchanges it for an HttpOnly SameSite session cookie; explicit Basic Auth remains accepted for scripts. Known example credentials are rejected |
| `web.bind` | `all` | — | `all` = every interface; `tunnel` = tunnel IPs only (server: pool gateway v4+v6, client: assigned IP; rebinds within 2s as IPs appear). Binds are **per address**: if the v6 gateway is tentative or disabled it retries on its own while the v4 listener keeps serving. On Linux the tunnel addresses are brought `up` first and the v6 address gets `nodad` — without it a v6 address that has no RA to answer for stays tentative forever, and `[fd00::1]:8080` never binds |
| `web.cert` / `web.key` | (empty) | — | Dashboard HTTPS pair. Required when `web.bind=all` exposes a non-loopback listener |
| `server.v4_cidr` | `10.0.0.0/24` | server | IPv4 pool for clients (gateway = first host). Bare IPs are accepted; garbage is refused rather than silently downgrading to the default pool |
| `server.v6_cidr` | `fd00::/64` | server | IPv6 pool for clients |
| `server.cert` / `server.key` | (required) | server | TLS certificate pair (PEM). A missing file or a cert/key that don't match is reported as `Invalid configuration: server.cert …` and exits 1 — it must not be a panic |
| `server.max_sessions` | `1024` | server | Maximum concurrent sessions |
| `server.fec_group_min` | `2` | server | Lower bound on a peer's FEC group size K; an FEC handshake below it is refused |
| `server.fec_group_max` | `64` | server | Upper bound on a peer's FEC group size K; an FEC handshake above it is refused. Neither end is clamped, and defaults are the protocol limits so nothing is limited unless configured. One parity copy is rotated across healthy backends, so the redundancy ratio is ≈1/K: a `min` floor bounds bandwidth, while a `max` ceiling bounds pending-frame buffering and recovery latency |
| `client.interface_manager` | `self` | client | Rust currently supports only `self`. The Go/OpenWrt `netifd` mode is intentionally rejected by tlsvpn-rs |
| `client.conns` | `1` | client | Parallel TCP connections (multi-IP round-robin, MinRTT/FEC multipath) |
| `client.fec` | `false` | client | XOR-parity FEC over multipath; one parity copy is rotated across healthy backends, so the redundancy ratio is ≈1/K |
| `client.fec_group` | `4` | client | XOR FEC group size K (2–64). Out-of-range configuration is rejected locally; the server may also refuse a K outside its configured policy |
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

Off by default; set `web.addr` to enable it. Rust embeds the same static WebUI asset set as Go (including zh-CN/zh-TW/en/de/fr/ja, local OS/arch icons, the current frame-format visualizer and favicon), while retaining the Rust backend/auth model. Served over HTTPS whenever `web.cert`/`web.key` are set, plain HTTP otherwise. Stats, per-connection details, FEC counters, MAC/IP-pool state, ban/kick controls, log tail with live level switching and Prometheus `/metrics` are backed by Rust APIs. Browser access uses the same HttpOnly session-cookie login flow as Go; Basic Auth from `web.auth` remains accepted for scripts, and mutating control calls require `X-Requested-With: tlsvpn`.

The dashboard backend follows the Go contract as well: browser login uses the same HttpOnly session-cookie flow (Basic Auth remains available to scripts), `/api/trend` keeps background 2-minute/1-hour/24-hour rings, `/api/events` provides SSE plus polling recovery, `/api/stats` includes persistent aggregate and per-client daily traffic, and the settings editor reads/writes the source JSON with PSK/Web-auth/SOCKS credentials redacted and preserved. `save_apply` hot-applies log level and padding immediately and reports every other changed path in `needs_restart`. Rust accepts Go's `traffic_days`/`traffic_file` configuration keys in addition to its `workers`/`mtu` extensions.

## One-click installer

`scripts/install.sh` is an English-only interactive/CLI installer for Debian, Ubuntu, Rocky/RHEL-family and Alpine Linux. It supports `install`, `upgrade`, `uninstall`, `rollback`, `maintenance` and `status`, keeps rollback snapshots of TLSVPN-managed files, installs systemd or OpenRC services, and can create a daily maintenance timer. Run it without an action for the wizard; type `back` at wizard prompts to move to the previous step.

```bash
# Interactive
sudo bash scripts/install.sh

# ACME/lego with a normal DNS name
sudo bash scripts/install.sh install --mode server --psk 'REPLACE-ME' \
  --cert-mode lego --cert-name vpn.example.com --email admin@example.com

# ACME/lego with a public IP identifier (RFC 8738 / short-lived profile)
sudo bash scripts/install.sh install --mode server --psk 'REPLACE-ME' \
  --cert-mode lego --cert-name 203.0.113.10 --email admin@example.com

# Client plus optional tuning/components
sudo bash scripts/install.sh install --mode client --server vpn.example.com:4000 \
  --psk 'REPLACE-ME' --tcp-brutal yes --optimize-kernel yes

sudo bash scripts/install.sh upgrade
sudo bash scripts/install.sh rollback
sudo bash scripts/install.sh uninstall --purge
```

Certificates can use lego/ACME, self-signed, or an existing cert/key pair. Daily maintenance renews lego certificates and checks GitHub Releases for a newer TLSVPN binary. XanMod is intentionally automated only on Debian/Ubuntu x86_64; tcp-brutal is optional and skipped on Alpine, and the installer warns about known-risk newer XanMod combinations unless `--force-tcp-brutal` is explicitly supplied. XanMod packages are never automatically removed on uninstall because removing a running kernel is unsafe.

## Notes

1. **Kernel module** — Brutal mode needs the Linux `tcp_brutal` module; elsewhere a warning is logged and it continues without it.
2. **Permissions** — TAP requires `/dev/net/tun` access, typically root.
3. **Client identity** — the ClientID derives from canonical TAP MAC + PSK. If no MAC is configured or readable, including `"tap": "mem"`, the client generates and persists a random non-zero unicast MAC together with its token and epoch.
4. **Interoperability** — current Go and Rust builds share strict protocol v2 and byte-for-byte golden vectors, including frame headers and data/FEC AEAD-domain vectors. All four current inner AEAD algorithms are interoperable across implementations. Upgrade both ends together; there is no pre-v2 compatibility mode, so an old binary is refused rather than downgraded.

## Cortex-A55 / RK3568 optimized build

The generic ARM64 artifacts remain the compatibility default. For Cortex-A55
systems such as RK3568/R5S, build the tuned binary separately:

```bash
./scripts/build.sh a55
# dist/tlsvpn-aarch64-unknown-linux-gnu-cortex-a55
```

Tagged releases also publish
`tlsvpn-aarch64-unknown-linux-musl-cortex-a55` alongside the generic ARM64
artifact. The tuned binary uses `-C target-cpu=cortex-a55`; run it only on
compatible CPUs.

## Development

**Interop is locked by golden vectors.** `tlsvpn/testdata/protocol_golden.json` (generated by the Go repo) covers key derivation, CTR keystream, frame headers and handshake field names; `cargo test --test protocol_conformance` fails on any drift.

**Cross-implementation e2e** — `scripts/e2e_test.sh` drives the five suites below against a real Rust build and a real Go build over the in-memory TAP, so it needs no `CAP_NET_ADMIN` and runs for real on hosted CI:

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
# Prints the current runner's measured protocol-path throughput; avoid treating an old CI number as a fixed product guarantee

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
