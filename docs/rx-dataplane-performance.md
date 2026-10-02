# Single-path receive optimization

The first throughput change targets static single-connection sessions without
negotiated FEC. After decrypt, a validated contiguous batch transfers directly
to the existing delivery vector. It skips the atomic dedup table and the reorder
ring/bitmap. Frames are moved, without additional Arc clones.

The entire batch is validated before progress changes. A gap, duplicate, typed
control, or existing pending reorder gap uses the original path. Sequence progress
is shared with that path, including reconnects and epoch resets. The server also
checks the actual active connection count. One session mutex per batch remains
necessary to serialize overlapping reconnects. Client TAP delivery stays on its
bounded worker queue so a slow TAP cannot block TLS reads.

Both receive endpoints reuse input batches between plaintext drains. The default
batch limit is 16. `TLSVPN_RX_BATCH_SIZE=16|32|64|128` selects a comparison size;
other values use 16. `TLSVPN_RX_BYPASS=0` disables the optimization for a same-binary
negative control. These process-local settings do not change the protocol or JSON
config. Flush still happens at the end of each plaintext drain, without waiting
for a full batch.

Run `cargo test --release bench_rx_direct_batch -- --ignored --nocapture` for
paired before/after RX-stage measurements at every size. The baseline executes
dedup plus the original reorder implementation under the same batch lock. The
optimized measurement executes the direct transfer. Both reuse the same payload,
input/output allocation pattern, and Arc ownership. Reported Mbps is payload-size
times frames/second, not tunnel throughput. This isolates dedup/reorder CPU cost;
it does not measure TLS, TAP, network latency, whole-process CPU, or allocations
for newly received payloads. Functional tests verify that scratch vectors keep
their storage and direct delivery does not clone frame Arcs.

For actual TAP tests on privileged Linux:

```sh
RS_BIN=/absolute/path/to/tlsvpn-rs GO_BIN=/absolute/path/to/tlsvpn-go \
  sudo -E bash scripts/rx_perf_matrix.sh
```

This runs rs/rs, rs/go, and go/rs at each batch size with bypass off/on. Existing
network tests record upload/download Mbps and ping RTT/loss through isolated
network namespaces. Each case uses one connection and no FEC. Results and host
metadata are written to `perf-results/rx-real-tap/`. A capability gate creates
`SKIP.txt` and stops the sweep; a skipped test is not performance evidence.
CI uploads both stage and real-TAP logs. Hardware CPU/perf and full allocator
profiles remain follow-up measurements on a privileged device.

TX already batches framed plaintext into rustls writes. The dataplane transport
is TCP/TLS, so UDP sendmmsg/recvmmsg and GRO/GSO do not apply here. ARM64 already
has a separate `scripts/build.sh a55` artifact and corresponding CI compile check;
generic release artifacts retain their existing compatibility settings.

## TAP payload return pool

Client RX allocates payloads on the TLS reader, but the TAP worker used to release
them into its own thread-local pool. Delivered standard-MTU buffers now return
through the existing batch pool; the RX owner releases them into its frame pool
when acquiring the next batch. No payload copy or extra channel is added.
The return queue holds at most eight batches of 32 buffers of capacity 2048
(512 KiB of payload storage). Jumbo buffers and overflow keep the old release
path. Shared FEC frames are reused only after unique ownership is available.
`TLSVPN_RX_RECYCLE=0` restores worker-side release as a negative control.

`scripts/tap_recycle_perf.sh` runs recycle off/on/on/off at batch 16 for rs/rs,
go/rs, and the unaffected go/go control. Each transfer lasts 10 seconds by default
(`IPERF_SECONDS=1..120` overrides it). The receive buffer return change is in
the Rust client, so rs/go is covered by the RX matrix but is not a recycling
target. The same CI artifact contains these logs.

Every iperf measurement now records `VPN_METRICS`: full VPN server/client process
CPU from /proc utime+stime, and separate logical TAP RX/TX packet rates. CPU is
percent of one core and may exceed 100 for a multithreaded process; it is not
iperf's CPU or a whole-host percentage. Monotonic elapsed time covers the transfer
and endpoint sampling overhead. CPU and packet counter resets fail the sample.
The TAP return microbenchmark includes producer/worker synchronization and memory
reuse, but does not model the kernel TAP or TLS crypto. Whole-allocator profiles
and physical ARM device measurements remain outstanding.

## Second optimization pass (experimental controls)

Static single-path owned RX is enabled by default; the other candidates remain
opt-in until real-TAP A/B results justify a default change:

* `TLSVPN_RX_OWNED=0` disables the default static single-connection/no-FEC client
  RX ownership path. It keeps unique
  payload Vecs through TAP delivery. A batch with a gap or replay converts to
  shared storage and uses the existing reorder path. Both delivery variants
  share one bounded FIFO; each return pool retains at most 512 KiB, or 1 MiB
  combined when both variants are present. The session batch mutex remains.
* `TLSVPN_TX_BATCH=1`: the client TAP reader drains already-readable packets
  without waiting. On Linux its fd is nonblocking and EAGAIN ends the batch;
  normal recv/send wait for readiness only on EAGAIN, preserving their blocking
  behavior without a per-packet poll syscall. A single-backend/no-FEC port assigns sequences and queues
  the batch under one queue lock, with one wake. FEC/multipath keeps the existing
  scheduler/fence path. Queue headroom and sequence exhaustion still drop safely.
* `TLSVPN_RX_COMPACT=1`: scanner tail compaction is deferred until storage is
  full or consumed. It reduces tail copies, not the payload extraction copy;
  this is not a zero-copy TLS decoder. Padding, length caps and fragmented reads
  retain their original behavior.
* `TLSVPN_SWITCH_BATCH=1`: server forwarding groups only consecutive known
  unicasts with the authenticated source MAC and same destination. It holds the
  MAC shard guard through enqueue, preserving port removal ordering. Unknown
  destinations, broadcast and spoofed frames use the scalar path.
* `TLSVPN_TX_BATCH_SIZE=8|16|32`: selects the maximum frame count for ownership
  batches and opportunistic TAP drains. The existing 8 KiB byte bound remains;
  default stays 8. Invalid values use 8. No timer waits for a full batch.

`scripts/dataplane_candidates.sh` tests each candidate separately, TX batch
limits, then a 10-second off/on/on/off combined sweep of rs/rs, rs/go, go/rs and
go/go. Logs include process CPU, TAP pps, throughput and `LOAD_LATENCY` ICMP
p50/p95/p99/loss under load. These are ICMP samples, not application latency.
Two repeats on a shared VM do not establish statistical significance.

The separate `alloc-profile` feature wraps the existing mimalloc allocator with
event counters. Set `TLSVPN_ALLOC_PROFILE=1` to log cumulative alloc/realloc calls
and requested bytes once per second. Requested bytes are allocation traffic,
not retained/live memory. Diagnostic builds also log TX batch-size buckets
(1, 2–4, 5–8, >8), batch queue residence buckets (<=10 us, <=100 us, <=1 ms,
<=10 ms, >10 ms), peak queued frame count, actual/attempted wakes and scanner
tail bytes moved. Batch residence timestamps start at the first frame, and
the histogram counts batches, not packets. Instrumentation is compiled out of
ordinary builds; diagnostic throughput must not be compared to release numbers.

CI rebuilds pre-candidate commit `aa6f6d1` separately and profiles that binary
plus current candidates off/on for allocation events. A separate build without
allocator instrumentation captures CPU stacks with candidates off/on. Software
CPU-clock sampling with frame pointers
produces raw perf data, text reports, stacks and SVG flame graphs. A missing perf
permission/tool creates explicit SKIP evidence rather than fabricated profiles.
Allocation counters do not identify allocation call sites or peak heap usage.
