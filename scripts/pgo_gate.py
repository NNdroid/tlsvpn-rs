#!/usr/bin/env python3
"""Evaluate Real-TAP B/A/A/B logs for an LLVM PGO candidate."""
from __future__ import annotations

import json
import math
import os
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

THROUGHPUT_RE = re.compile(
    r"iperf3\s+(upload|download)[^:]*:\s*([0-9]+(?:\.[0-9]+)?)\s+Mbps"
)
NAME_RE = re.compile(
    r"trial(\d+)-(baseline|pgo)-(rs-rs|rs-go|go-rs|go-go)-c(\d+)\.txt$"
)


def gmean(values: list[float]) -> float:
    if not values or any(v <= 0 for v in values):
        raise ValueError(f"invalid geomean input: {values}")
    return math.exp(sum(math.log(v) for v in values) / len(values))


def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError as exc:
        raise SystemExit(f"invalid {name}") from exc


def parse_log(path: Path) -> dict:
    text = path.read_text(errors="replace")
    throughput: dict[str, float] = {}
    metrics: dict[str, dict] = {}
    latency: dict[str, dict] = {}
    for line in text.splitlines():
        m = THROUGHPUT_RE.search(line)
        if m:
            throughput[m.group(1)] = float(m.group(2))
        if "VPN_METRICS " in line:
            payload = line.split("VPN_METRICS ", 1)[1].strip()
            obj = json.loads(payload)
            metrics[obj["direction"]] = obj
        if "LOAD_LATENCY " in line:
            payload = line.split("LOAD_LATENCY ", 1)[1].strip()
            obj = json.loads(payload)
            latency[obj["direction"]] = obj
    for direction in ("upload", "download"):
        if direction not in throughput:
            raise ValueError(f"{path}: missing {direction} throughput")
        if direction not in metrics:
            raise ValueError(f"{path}: missing {direction} VPN_METRICS")
        if direction not in latency:
            raise ValueError(f"{path}: missing {direction} LOAD_LATENCY")
    return {"throughput": throughput, "metrics": metrics, "latency": latency}


def cpu_per_mpps(metric: dict) -> float:
    cpu = float(metric["server_cpu_pct"]) + float(metric["client_cpu_pct"])
    pps = sum(
        float(metric[k])
        for k in ("server_rx_pps", "server_tx_pps", "client_rx_pps", "client_tx_pps")
    )
    if pps <= 0:
        raise ValueError("non-positive TAP pps")
    return cpu * 1_000_000.0 / pps


def aggregate(samples: list[dict], direction: str) -> dict:
    throughputs = [s["throughput"][direction] for s in samples]
    cpu_eff = [cpu_per_mpps(s["metrics"][direction]) for s in samples]
    p95 = [float(s["latency"][direction]["p95_ms"]) for s in samples]
    p99 = [float(s["latency"][direction]["p99_ms"]) for s in samples]
    loss = [float(s["latency"][direction]["loss_pct"]) for s in samples]
    return {
        "mbps_gmean": gmean(throughputs),
        "cpu_per_mpps_gmean": gmean(cpu_eff),
        "p95_ms_median": statistics.median(p95),
        "p99_ms_median": statistics.median(p99),
        "loss_pct_max": max(loss),
        "raw_mbps": throughputs,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: pgo_gate.py PERF_DIR", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    grouped: dict[tuple[str, int, str], list[dict]] = defaultdict(list)
    seen = 0
    for path in sorted(root.glob("trial*-*.txt")):
        m = NAME_RE.match(path.name)
        if not m:
            continue
        _trial, variant, pair, conns = m.groups()
        grouped[(variant, int(conns), pair)].append(parse_log(path))
        seen += 1
    if seen == 0:
        raise SystemExit(f"no ABBA logs found in {root}")

    min_geomean = env_float("PGO_MIN_GEOMEAN", 1.01)
    min_case_ratio = env_float("PGO_MIN_CASE_RATIO", 0.97)
    max_cpu_ratio = env_float("PGO_MAX_CPU_EFF_RATIO", 1.02)
    max_control_drift = env_float("PGO_MAX_CONTROL_DRIFT", 0.08)
    max_p95_ratio = env_float("PGO_MAX_P95_RATIO", 1.20)
    max_p99_ratio = env_float("PGO_MAX_P99_RATIO", 1.25)
    max_loss_delta = env_float("PGO_MAX_LOSS_DELTA", 0.5)
    max_loss_abs = env_float("PGO_MAX_LOSS_ABS", 1.0)

    failures: list[str] = []
    rows: list[dict] = []
    throughput_ratios: list[float] = []
    cpu_ratios: list[float] = []
    control_ratios: list[float] = []

    for conns in (1, 4):
        for pair in ("rs-rs", "rs-go", "go-rs", "go-go"):
            base_samples = grouped.get(("baseline", conns, pair), [])
            pgo_samples = grouped.get(("pgo", conns, pair), [])
            if len(base_samples) != 2 or len(pgo_samples) != 2:
                failures.append(
                    f"{pair}/c{conns}: expected two baseline and two PGO samples, "
                    f"got {len(base_samples)}/{len(pgo_samples)}"
                )
                continue
            for direction in ("upload", "download"):
                base = aggregate(base_samples, direction)
                pgo = aggregate(pgo_samples, direction)
                t_ratio = pgo["mbps_gmean"] / base["mbps_gmean"]
                cpu_ratio = pgo["cpu_per_mpps_gmean"] / base["cpu_per_mpps_gmean"]
                p95_limit = max(
                    base["p95_ms_median"] * max_p95_ratio,
                    base["p95_ms_median"] + 3.0,
                )
                p99_limit = max(
                    base["p99_ms_median"] * max_p99_ratio,
                    base["p99_ms_median"] + 5.0,
                )
                loss_limit = max(base["loss_pct_max"] + max_loss_delta, max_loss_abs)
                control = pair == "go-go"
                row = {
                    "pair": pair,
                    "conns": conns,
                    "direction": direction,
                    "control": control,
                    "baseline_mbps": round(base["mbps_gmean"], 3),
                    "pgo_mbps": round(pgo["mbps_gmean"], 3),
                    "throughput_ratio": round(t_ratio, 5),
                    "cpu_eff_ratio": round(cpu_ratio, 5),
                    "baseline_p95_ms": base["p95_ms_median"],
                    "pgo_p95_ms": pgo["p95_ms_median"],
                    "baseline_p99_ms": base["p99_ms_median"],
                    "pgo_p99_ms": pgo["p99_ms_median"],
                    "baseline_loss_pct": base["loss_pct_max"],
                    "pgo_loss_pct": pgo["loss_pct_max"],
                }
                rows.append(row)

                if control:
                    control_ratios.append(t_ratio)
                    if abs(t_ratio - 1.0) > max_control_drift:
                        failures.append(
                            f"noise control {pair}/c{conns}/{direction}: ratio {t_ratio:.3f} "
                            f"outside ±{max_control_drift:.1%}"
                        )
                    continue

                throughput_ratios.append(t_ratio)
                cpu_ratios.append(cpu_ratio)
                if t_ratio < min_case_ratio:
                    failures.append(
                        f"{pair}/c{conns}/{direction}: throughput ratio {t_ratio:.3f} < {min_case_ratio:.3f}"
                    )
                if pgo["p95_ms_median"] > p95_limit:
                    failures.append(
                        f"{pair}/c{conns}/{direction}: p95 {pgo['p95_ms_median']:.2f} ms > {p95_limit:.2f} ms"
                    )
                if pgo["p99_ms_median"] > p99_limit:
                    failures.append(
                        f"{pair}/c{conns}/{direction}: p99 {pgo['p99_ms_median']:.2f} ms > {p99_limit:.2f} ms"
                    )
                if pgo["loss_pct_max"] > loss_limit:
                    failures.append(
                        f"{pair}/c{conns}/{direction}: loss {pgo['loss_pct_max']:.3f}% > {loss_limit:.3f}%"
                    )

    if not throughput_ratios:
        failures.append("no Rust-involving candidate measurements")
        throughput_geomean = float("nan")
        cpu_geomean = float("nan")
    else:
        throughput_geomean = gmean(throughput_ratios)
        cpu_geomean = gmean(cpu_ratios)
        if throughput_geomean < min_geomean:
            failures.append(
                f"global throughput geomean ratio {throughput_geomean:.4f} < {min_geomean:.4f}"
            )
        if cpu_geomean > max_cpu_ratio:
            failures.append(
                f"global CPU/packet efficiency ratio {cpu_geomean:.4f} > {max_cpu_ratio:.4f}"
            )

    report = {
        "passed": not failures,
        "throughput_geomean_ratio": throughput_geomean,
        "cpu_per_packet_geomean_ratio": cpu_geomean,
        "go_go_control_ratios": control_ratios,
        "thresholds": {
            "min_geomean": min_geomean,
            "min_case_ratio": min_case_ratio,
            "max_cpu_eff_ratio": max_cpu_ratio,
            "max_control_drift": max_control_drift,
            "max_p95_ratio": max_p95_ratio,
            "max_p99_ratio": max_p99_ratio,
            "max_loss_delta": max_loss_delta,
            "max_loss_abs": max_loss_abs,
        },
        "failures": failures,
        "rows": rows,
    }
    (root / "pgo-gate.json").write_text(json.dumps(report, indent=2) + "\n")

    md = [
        "# LLVM PGO Real-TAP gate",
        "",
        f"- result: **{'PASS' if not failures else 'FAIL'}**",
        f"- throughput geomean ratio (PGO/baseline): **{throughput_geomean:.4f}**",
        f"- CPU/TAP-packet geomean ratio (PGO/baseline, lower is better): **{cpu_geomean:.4f}**",
        "",
        "| pair | conns | dir | base Mbps | PGO Mbps | ratio | CPU/packet | base p99 | PGO p99 | loss base→PGO |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        md.append(
            f"| {r['pair']}{' (control)' if r['control'] else ''} | {r['conns']} | {r['direction']} | "
            f"{r['baseline_mbps']:.2f} | {r['pgo_mbps']:.2f} | {r['throughput_ratio']:.3f} | "
            f"{r['cpu_eff_ratio']:.3f} | {r['baseline_p99_ms']:.2f} | {r['pgo_p99_ms']:.2f} | "
            f"{r['baseline_loss_pct']:.3f}%→{r['pgo_loss_pct']:.3f}% |"
        )
    if failures:
        md += ["", "## Gate failures", ""] + [f"- {f}" for f in failures]
    summary = "\n".join(md) + "\n"
    (root / "pgo-summary.md").write_text(summary)
    print(summary)

    enforce = os.environ.get("PGO_ENFORCE", "1") != "0"
    return 1 if failures and enforce else 0


if __name__ == "__main__":
    raise SystemExit(main())
