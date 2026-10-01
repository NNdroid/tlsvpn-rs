"""Whole VPN-process CPU and logical TAP packet rates, never iperf's CPU."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def cpu_ticks_from_stat(text):
    # comm can contain spaces/parentheses; field 3 begins after its final ') '.
    fields = text.rsplit(") ", 1)[1].split()
    return int(fields[11]) + int(fields[12])  # fields 14/15: utime + stime


def snapshot(server_pid, client_pid, server_ns, client_ns, server_tap, client_tap):
    result = {"ticks": {}, "packets": {}}
    for name, pid, ns, tap in (
        ("server", server_pid, server_ns, server_tap),
        ("client", client_pid, client_ns, client_tap),
    ):
        result["ticks"][name] = cpu_ticks_from_stat(Path(f"/proc/{int(pid)}/stat").read_text())
        link = json.loads(subprocess.check_output(
            ["ip", "netns", "exec", ns, "ip", "-j", "-s", "link", "show", "dev", tap],
            text=True,
        ))[0]
        stats = link.get("stats64", link.get("stats"))
        result["packets"][name] = {d: stats[d]["packets"] for d in ("rx", "tx")}
    result["at"] = time.monotonic()
    return result


def summarize(before, after, ticks_per_second, direction):
    elapsed = after["at"] - before["at"]
    if elapsed <= 0 or ticks_per_second <= 0:
        raise ValueError("invalid CPU measurement interval")
    out = {"direction": direction, "seconds": round(elapsed, 4)}
    for name in ("server", "client"):
        ticks = after["ticks"][name] - before["ticks"][name]
        if ticks < 0:
            raise ValueError("VPN process counters reset during measurement")
        out[f"{name}_cpu_pct"] = round(100 * ticks / ticks_per_second / elapsed, 2)
        for d in ("rx", "tx"):
            packets = after["packets"][name][d] - before["packets"][name][d]
            if packets < 0:
                raise ValueError("TAP counters reset during measurement")
            out[f"{name}_{d}_pps"] = round(packets / elapsed, 2)
    return out


if __name__ == "__main__":
    command, file, direction, *endpoints = sys.argv[1:]
    current = snapshot(*endpoints)
    if command == "start":
        Path(file).write_text(json.dumps(current))
    elif command == "finish":
        before = json.loads(Path(file).read_text())
        print("VPN_METRICS " + json.dumps(summarize(before, current, os.sysconf("SC_CLK_TCK"), direction)))
    else:
        raise ValueError("expected start or finish")
