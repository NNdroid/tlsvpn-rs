from pathlib import Path

# Keep this helper one-shot and scoped to the remaining audited README sentence.
p = Path("README.md")
s = p.read_text()
old = 'Windows and macOS clients work with `"tap": "mem"` (no kernel TAP); interface addressing and policy routing are Linux features.'
new = '`"tap": "mem"` is a CI/e2e backend only: it has no real subnet behind it, drops writes, and does not provide a usable host VPN interface. Real interface addressing and policy routing are currently Linux-oriented.'
if s.count(old) != 1:
    raise SystemExit(f"README.md: expected exactly one stale platform sentence, got {s.count(old)}")
p.write_text(s.replace(old, new, 1))
