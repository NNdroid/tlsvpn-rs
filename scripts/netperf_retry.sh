#!/usr/bin/env bash
# Re-run a netperf group when the adaptive scheduler utilization gate trips.
# The gate reads one cumulative /api/stats snapshot, and on a noisy shared
# runner the adaptive scheduler can legitimately concentrate the whole direction
# on the one healthy path for that sample (crypto_backend_ab.sh already treats
# this exact marker as a retryable rc=75 sample). Any other failure surfaces
# on the first attempt without a retry.
set -uo pipefail
log="$(mktemp)"
rc=0
for attempt in 1 2 3; do
  "$@" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  [[ $rc -eq 0 ]] && exit 0
  grep -Fq 'adaptive scheduler utilization gate failed' "$log" || break
  [[ $attempt -lt 3 ]] || break
  echo "[netperf-retry] invalid scheduler sample; retrying attempt=$attempt"
done
exit "$rc"
