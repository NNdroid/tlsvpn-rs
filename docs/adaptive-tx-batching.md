# Adaptive TX batching candidate

This candidate keeps the existing nonblocking TAP drain and TLS framing unchanged.
It changes only the maximum number of ownership-queue frames that may coalesce into
one backend batch when `TLSVPN_TX_ADAPTIVE_BATCH=1`.

The policy is zero-wait: no timer or sleep is introduced. The batch ceiling grows
geometrically from 1 to 2 to 4 to 8 frames based on the current queued-frame count
plus the incoming burst size. The existing configured static maximum and 8 KiB
byte cap remain hard limits. With the environment variable unset or set to `0`,
behavior is identical to the current static batching path.

The Real-TAP candidate matrix compares static and adaptive batching in B/A/A/B
order for rs/rs, rs/go, go/rs and the unaffected go/go control, plus an rs/rs
four-connection pressure case. Promotion should require repeatable throughput or
CPU-per-packet improvement without p95/p99 or loss regressions.
