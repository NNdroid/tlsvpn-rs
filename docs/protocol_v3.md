# TLSVPN Protocol v3

Status: normative protocol specification for the current implementation.

This document is the protocol source of truth. Code, tests and cross-language implementations MUST follow it. Protocol v3 intentionally does **not** preserve wire compatibility with v2.

## 1. Transport and connection model

TLSVPN runs over TCP protected by TLS. One logical VPN session may use multiple simultaneous physical TCP/TLS connections. Every physical connection performs the application handshake independently and then joins the same logical session epoch.

The application protocol version is exactly:

```text
protocol_version = 3
```

A peer advertising any other version MUST be rejected. There is no v2 fallback, downgrade path, legacy magic dispatch, or alternate interpretation of v3 bytes.

The implementation currently advertises ALPN `h2`; TLS is still used as a byte-stream transport, not as HTTP/2 framing.

### 1.1 Logical session versus physical connection

A logical session owns the global data sequence, inner-AEAD epoch, FEC encoder/decoder state, reorder state, tunnel addresses and session-token state.

A physical TCP/TLS connection is only one transport path belonging to that logical session. Losing or replacing one physical path does **not** by itself create a new logical session epoch.

A same-epoch replacement connection MUST authenticate with the same logical client/session identity and then joins the existing sequence/FEC/AEAD epoch. A connection from an older epoch MUST NOT inject traffic after a newer epoch has been established.

## 2. Stream frame format

Every application record inside the TLS byte stream has a fixed 10-byte header:

```text
0               4        6              10
+---------------+--------+---------------+
| data_len u32  | pad u16| seq u32       |
+---------------+--------+---------------+
| data_len bytes payload                  |
+-----------------------------------------+
| pad_len bytes cover padding             |
+-----------------------------------------+
```

All integers are big-endian.

- `data_len`: payload bytes on the wire, excluding the 10-byte header and padding. For encrypted data records this includes the inner-AEAD tag.
- `pad_len`: opaque cover-padding byte count.
- `seq`: global logical-session data sequence. `seq=0` is reserved for handshake/control traffic. VPN data uses `1..0xffffffff`.

Authenticated post-handshake maximum `data_len` is `131070` bytes. The pre-authentication handshake-frame limit is `16384` bytes.

Padding bytes are not interpreted by the receiver and are not included in inner-AEAD AAD.

## 3. Physical connection state machine

A physical connection has two application phases.

### 3.1 Pre-handshake phase

The first TLSVPN record uses `seq=0` and contains UTF-8 JSON `HandshakeReq`. The server replies with one `seq=0` JSON `HandshakeResp`.

During this phase `seq=0` payload is JSON, not a typed v3 control.

### 3.2 Post-handshake phase

After a successful handshake:

- `seq > 0`: VPN data record.
- `seq = 0`, `data_len = 0`: KEEPALIVE.
- `seq = 0`, `data_len > 0`: typed v3 control record; payload byte 0 is `control_kind`.

Unknown or malformed post-handshake controls are protocol errors and MUST NOT be silently ignored.

## 4. Handshake request

The client sends a JSON object with these fields:

| Field | Type | Meaning |
|---|---|---|
| `protocol_version` | integer | MUST equal `3`. |
| `client_instance` | string | Process-instance identity; a changed instance establishes a new session epoch. |
| `conn_id` | string | Diagnostic UUID identifying one physical connection. |
| `client_id` | string | Stable logical client UUID derived from authenticated identity inputs. |
| `psk` | string | Hex SHA-256 of the configured PSK. |
| `mac` | string | Client tunnel MAC address. |
| `ipv4` | string | Requested/remembered IPv4 address, if any. |
| `ipv6` | string | Requested/remembered IPv6 address, if any. |
| `padding` | string | Random handshake camouflage material. |
| `brutal_groups` | bool | Enables grouped/aggregate TCP Brutal semantics. |
| `brutal_total_tx` | integer | Requested aggregate client→server Mbps budget. |
| `brutal_total_rx` | integer | Requested aggregate server→client Mbps budget. |
| `brutal_conns` | integer | Declared configured physical connection count. |
| `brutal_conn_index` | integer | Zero-based physical connection index. |
| `fec` | bool | Requests XOR FEC. |
| `fec_group` | integer | XOR FEC group size K. Protocol range is 2..64; server policy may narrow it. |
| `encrypt` | bool | Whether inner AEAD is enabled. |
| `enc_algo` | integer | Exact inner-AEAD algorithm identifier. |
| `session_token` | string | Random existing-session possession token, encoded as 64 hex characters. |
| `peer_info` | object | Diagnostic peer metadata only. |

The server MUST require exact v3 and exact configured inner-encryption compatibility. An invalid FEC request is rejected rather than silently clamped to another wire value.

## 5. Handshake response

A successful response contains:

| Field | Type | Meaning |
|---|---|---|
| `protocol_version` | integer | MUST equal `3`. |
| `session_epoch` | integer | Logical key/sequence epoch. |
| `success` | bool | Handshake result. |
| `message` | string | Human-readable result. |
| `session_id` | string | Logical session UUID. |
| `client_id` | string | Accepted logical client identifier. |
| `ipv4` / `ipv6` | string | Assigned tunnel addresses. |
| `gw_v4` / `gw_v6` | string | Tunnel gateway addresses. |
| `padding` | string | Handshake camouflage material. |
| `brutal_groups` | bool | Negotiated grouped-rate semantics. |
| `brutal_total_tx` / `brutal_total_rx` | integer | Negotiated aggregate Mbps budgets. |
| `fec` | bool | Negotiated FEC enablement. |
| `fec_group` | integer | Negotiated XOR group size K. |
| `encrypt` | bool | Negotiated inner-AEAD enablement. |
| `enc_algo` | integer | Exact selected inner-AEAD algorithm. |
| `enc_salt` | string | 8-byte client→server inner-AEAD salt, hex encoded. |
| `enc_salt2` | string | 8-byte server→client inner-AEAD salt, hex encoded. |
| `session_token` | string | Current/pending reconnect possession token. |
| `tls` | object | Server-observed TLS diagnostics. |
| `peer_info` | object | Authenticated peer diagnostics. |

Fields using `omitempty`/`skip_serializing_if` may be absent only when their semantic value is empty. Absence never enables a v2 interpretation. `protocol_version=3` is mandatory on every request and successful response.

### 5.1 `peer_info`

`peer_info` is diagnostic only and MUST NOT participate in authorization. Its current string fields are:

```text
implementation
hostname
os
os_version
kernel
arch
version
git_commit
build_time
```

### 5.2 `tls`

The response may include:

```text
fingerprint_kind          string
fingerprint_sha256        string
version_id                uint16
version                   string
cipher_suite_id           uint16
cipher_suite              string
alpn                      string
sni                       string
offered_cipher_suites     []uint16
offered_signature_schemes []uint16
offered_groups            []uint16
offered_alpn              []string
```

The current fingerprint kind is `tls-clienthello-v1`. It is diagnostic and MUST NOT be used as application authentication input.

## 6. Session token and epoch rules

The PSK hash authenticates VPN membership. `session_token` proves possession of an existing logical session.

A session token is 32 random bytes encoded as 64 hex characters. The implementation uses current/pending rollover so loss of one handshake response does not permanently desynchronize reconnect state.

A changed `client_instance`, sequence exhaustion, or another explicit epoch-rotation event establishes a new session epoch. A new epoch MUST reset:

- data sequence allocation to 1;
- FEC-mode transition generation;
- every backend's remembered FEC fence generation;
- RX reorder state;
- RX FEC decoder state and retirement horizon;
- per-direction inner-AEAD salts/nonce domain.

A mere physical-path failure/rejoin within the same logical session MUST NOT reset the sequence, FEC generation, reorder state, session epoch, or AEAD salts.

Old physical connections belonging to a previous epoch MUST NOT continue injecting data into the new epoch.

## 7. Data sequencing

VPN data uses `seq=1..0xffffffff`, globally allocated by the logical sending port across all physical backends.

`seq=0` is never VPN data.

Sequence values MUST NOT be reused inside one inner-AEAD epoch. When the uint32 sequence space is exhausted, the implementation must establish a fresh epoch before sending new data.

The receiver maintains a global reorder buffer keyed by this sequence. A physical TCP path therefore does not own its own independent data sequence.

## 8. Post-handshake control plane

For every non-empty post-handshake frame with `seq=0`, payload byte 0 is `control_kind`.

Current v3 kinds:

```text
0x01  FEC_PARITY
0x02  FEC_MODE
```

No other kind is valid in protocol v3. Unknown kinds are protocol errors.

An empty `seq=0` payload is KEEPALIVE and has no `control_kind` byte.

## 9. FEC_PARITY (`control_kind = 0x01`)

XOR FEC groups data into fixed arithmetic groups of K data sequences. Group starts satisfy:

```text
group_start ≡ 1 (mod K)
```

Payload layout:

```text
0        1              5      6
+--------+--------------+------+
| kind=1 | start u32 BE | K u8 |
+--------+--------------+------+
| K × member_len u32 BE        |
+-------------------------------+
| XOR parity payload            |
+-------------------------------+
```

The parity body is the bytewise XOR of the K **plaintext** member payloads, zero-extended to the longest member.

When inner encryption is enabled, only the parity body is encrypted with the FEC AEAD domain. The descriptor (`kind/start/K/lengths`) remains visible inside TLS.

Parity AEAD uses:

- sequence input: `group_start`;
- wire-length input: encrypted parity-body length including tag;
- key domain: `fec`.

A parity record can recover exactly one missing member.

## 10. FEC_MODE (`control_kind = 0x02`)

Dynamic FEC mode control lets RX bypass decoder map/allocation/XOR work while sender topology makes parity useless.

Payload length is exactly 16 bytes:

```text
0        1        2              4               12             16
+--------+--------+--------------+----------------+--------------+
| kind=2 | op u8  | flags u16 BE | generation u64 | boundary u32 |
+--------+--------+--------------+----------------+--------------+
```

`flags` MUST be zero in v3.

Operations:

```text
1  SUSPEND
2  RESUME
```

`generation` starts at 1 for each session epoch and strictly increases for each real sender-side dynamic FEC transition. The receiver applies only a generation newer than the last accepted generation.

`boundary` MUST be a non-zero arithmetic FEC group start.

### 10.1 SUSPEND

`SUSPEND(boundary)` means the sender will not generate useful parity for groups whose start is at or beyond `boundary` until a later RESUME.

For a genuine `>=2 → 1` physical-backend transition, if the encoder has a partial group, the boundary rewinds to that partial group's start because the sender discards that partial XOR state.

The receiver may immediately discard decoder state inside the declared bypass interval. Groups before the boundary remain eligible for already-in-flight pre-collapse parity until reorder progress proves they can no longer affect ordered output.

### 10.2 RESUME

For a genuine `1 → >=2` transition after a SUSPEND, FEC resumes only at the next complete arithmetic group start. TX does not resume halfway through a group.

`RESUME(boundary)` closes the bypass interval at `boundary`; data with `seq >= boundary` follows normal decoder processing.

If no complete group boundary remains before uint32 exhaustion, TX MUST remain suppressed until a new epoch; the boundary MUST NOT wrap.

### 10.3 Startup semantics

Starting a session with one physical backend is not a dynamic `2→1` transition. No synthetic SUSPEND is emitted.

If an additional backend joins before any real SUSPEND has existed, no RESUME is emitted because RX never entered a dynamic bypass interval.

### 10.4 Ordering

FEC_MODE and the data it governs are ordered by sender authority, not by receiver-local connection count.

A backend MUST receive the current FEC_MODE generation before its first governed data record. Implementations may enqueue the control and governed data as one batch or as consecutive records in the same backend queue, provided no governed record can overtake the control on that physical stream.

The backend records the generation only after successful control enqueue. If preferred-path enqueue fails and data falls back to another backend, the backend that actually accepts the data MUST be synchronized first.

The boundary, not immediate byte adjacency, defines applicability. A control may legally appear before already queued data whose sequence lies before the boundary.

Independent TCP streams can reorder controls relative to each other. `generation` resolves that cross-stream ordering; a stale lower generation cannot regress a newer receiver state.

### 10.5 Physical path failure and rejoin

Physical path failure and rejoin are **same-session topology events**, not implicit epoch changes.

For one logical sender:

1. The actual registered/usable sender backend count is authoritative. Receiver-local `liveConns` MUST NOT be used to infer FEC mode.
2. A genuine sender transition from at least two physical backends to one opens a SUSPEND interval as specified above.
3. The surviving authenticated connection continues using the current global data sequence, session epoch and AEAD salts.
4. A replacement physical connection that authenticates into the same epoch joins the existing logical sequence/FEC state. It does not reset sequence numbers or cryptographic state.
5. A newly registered backend starts with no remembered FEC fence generation for that backend. Before it can carry data governed by an already-current FEC_MODE generation, that generation MUST be queued on the same backend ahead of the governed data.
6. When sender topology returns from one backend to at least two after a real SUSPEND, the sender emits RESUME at the next complete group boundary.
7. A path that belongs to an older session epoch is invalid and MUST NOT be treated as a same-epoch rejoin.

These rules guarantee that temporary path loss can trigger RX CPU bypass without sacrificing in-flight pre-collapse recovery or reusing AEAD nonces.

## 11. FEC decoder cleanup and reorder interaction

On SUSPEND, groups wholly inside the now-unrecoverable bypass interval may be released immediately without incrementing FEC-loss counters.

Groups before the SUSPEND boundary can remain useful to delayed old parity. They may be retired only after:

```text
reorder.expected_seq >= suspend_boundary
```

After retirement, late data/parity below the retired boundary MUST NOT recreate decoder state.

Cleanup is deliberately kept off the normal active-data hot path. Progress is checked on control/parity paths and sparsely during a long bypass interval.

Parity processing remains conservative during dynamic data bypass. This avoids requiring a RESUME arriving on one TCP stream to precede a parity record arriving on another stream. The higher-frequency per-data decoder work is what dynamic bypass removes.

## 12. Inner AEAD

Inner AEAD is optional because TLS already authenticates/encrypts transport. When enabled, both peers MUST use exactly the negotiated/configured `enc_algo`; there is no implicit downgrade.

Algorithm IDs:

```text
0  none
2  AES-256-GCM
4  AES-128-GCM
5  ChaCha20-Poly1305
6  XChaCha20-Poly1305
```

All supported AEADs use a 16-byte tag.

### 12.1 Key derivation

For configured plaintext `psk`:

```text
key_material = SHA256(psk || algorithm_label)
```

The digest is truncated to the algorithm key size where required. The FEC domain appends `_fec` to the algorithm label.

Labels:

```text
AES-256-GCM       _enc_key
AES-128-GCM       _enc_key128
ChaCha20          _enc_chacha20
XChaCha20         _enc_xchacha20
```

### 12.2 Nonce

AES-GCM and ChaCha20-Poly1305 use:

```text
seq_u32_be || salt_8B
```

XChaCha20-Poly1305 uses:

```text
SHA256("tlsvpn-xchacha20-nonce-v1" || salt_8B)[0:20] || seq_u32_be
```

### 12.3 AAD

For data and FEC AEAD domains:

```text
AAD = wire_len_u32_be || seq_u32_be
```

For normal data, `seq` is the data sequence. For parity-body encryption, `seq` is `group_start`.

Post-handshake typed-control descriptors are not inner-AEAD encrypted; TLS authenticates them. The optional FEC parity body remains independently authenticated by the FEC AEAD domain.

## 13. Padding

The frame header carries `pad_len`; the receiver skips those bytes after consuming `data_len` payload bytes.

Current modes:

- `off`: no cover padding.
- `bucket`: bounded cover padding toward configured record-size buckets.

Padding is not part of inner-AEAD AAD.

## 14. Multipath scheduling and ownership

Data is sent once on the selected physical backend; it is not copied to every path. Under load, the scheduler may stripe data across eligible paths.

FEC parity is generated once per complete group and assigned according to the FEC path policy.

After successful enqueue, a backend queue owns its frame descriptor/payload. FEC_MODE fencing follows the actual backend that accepted the governed data after scheduler fallback.

Sender backend registration/unregistration is the topology authority used by the dynamic FEC state machine.

## 15. Keepalive and failure detection

A post-handshake KEEPALIVE is:

```text
seq = 0
data_len = 0
```

It refreshes liveness/read deadlines and carries no typed-control byte.

A malformed non-empty `seq=0` payload is a protocol error, not a keepalive.

A single physical connection failure may cause the corresponding connection handler to terminate while the logical session remains alive on other paths. Same-epoch replacement follows Section 10.5.

## 16. Protocol errors

At minimum, these are protocol errors in v3:

- `protocol_version != 3`;
- unknown non-empty post-handshake `control_kind`;
- malformed FEC_MODE payload, non-zero reserved flags, zero generation or invalid boundary;
- malformed FEC_PARITY descriptor;
- FEC control traffic when FEC was not negotiated;
- impossible/invalid negotiated FEC group parameters;
- incompatible inner-encryption settings or algorithm;
- sequence/key epoch misuse that could permit nonce reuse;
- accepting traffic from a physical connection whose epoch no longer matches the logical session.

Protocol errors MUST terminate the affected physical connection rather than reinterpret its bytes using previous protocol semantics.

## 17. Cross-language conformance

`testdata/protocol_golden.json` in the Go repository is the machine-readable deterministic wire contract. It MUST carry `version: 3` and be regenerated whenever a deliberate v3 wire change is made.

Go and Rust implementations MUST validate the same golden vectors for:

- PSK hashing;
- frame-header layout;
- handshake JSON field names;
- inner-AEAD domains, nonces, AAD and ciphertext;
- TLS diagnostic normalization;
- FEC_PARITY and FEC_MODE control payloads.

An implementation is not v3-compatible until it implements this contract exactly. No v2 compatibility shim is part of v3.

Any future deliberate wire-incompatible semantic change MUST increment the application protocol version rather than adding ambiguous fallback behavior to v3.
