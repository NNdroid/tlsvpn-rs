"""ICMP RTT under iperf load; report sample count and loss, not application RTT."""
import json
import math
import re
import sys
from pathlib import Path


def summarize(text, direction):
    values = sorted(float(n) for n in re.findall(r"time[=<]([\d.]+) ms", text))
    count = re.search(r"(\d+) packets transmitted, (\d+) received", text)
    if not count or not values:
        raise ValueError("missing ping loss summary or RTT samples")
    sent, received = map(int, count.groups())
    if sent <= 0 or received > sent:
        raise ValueError("invalid ping packet counters")
    def percentile(q):
        return values[max(0, math.ceil(q * len(values)) - 1)]
    return {"direction": direction, "samples": len(values), "sent": sent,
            "loss_pct": round(100 * (sent - received) / sent, 3),
            "p50_ms": percentile(.50), "p95_ms": percentile(.95), "p99_ms": percentile(.99)}


if __name__ == "__main__":
    print("LOAD_LATENCY " + json.dumps(summarize(Path(sys.argv[1]).read_text(), sys.argv[2])))
