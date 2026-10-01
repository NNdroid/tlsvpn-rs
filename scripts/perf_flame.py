"""Render perf script stacks without external dependencies; one weight per sample."""
from collections import Counter
from html import escape
from pathlib import Path
import re
import sys


def stacks(text):
    counts = Counter()
    frames = []
    for line in text.splitlines() + [""]:
        match = re.match(r"\s+[0-9a-fA-F]+\s+(.+)", line)
        if match:
            frames.append(match.group(1))
        elif not line.strip() and frames:
            counts[tuple(reversed(frames))] += 1
            frames = []
    return counts


def render(counts):
    if not counts:
        raise ValueError("perf produced no stack samples")
    tree = {"count": 0, "children": {}}
    for frames, n in counts.items():
        node = tree
        node["count"] += n
        for frame in frames:
            node = node["children"].setdefault(frame, {"count": 0, "children": {}})
            node["count"] += n
    depth = max(map(len, counts))
    height = 45 + depth * 20
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="{height}" viewBox="0 0 1200 {height}">',
           '<rect width="100%" height="100%" fill="white"/>',
           f'<text x="10" y="20">VPN CPU stacks: {tree["count"]} samples; width = sample count</text>']
    def visit(node, x, level):
        for label, child in sorted(node["children"].items()):
            width = 1180 * child["count"] / tree["count"]
            y = height - 20 * (level + 1)
            color = f'rgb(245,{100 + sum(label.encode()) % 100},80)'
            svg.append(f'<g><title>{escape(label)}: {child["count"]} samples</title><rect x="{x:.3f}" y="{y}" width="{width:.3f}" height="19" fill="{color}" stroke="white" stroke-width="0.3"/>')
            limit = int(width / 7)
            if limit > 4:
                svg.append(f'<text x="{x + 3:.3f}" y="{y + 14}" font-size="12">{escape(label[:limit - 1])}</text>')
            svg.append('</g>')
            visit(child, x, level + 1)
            x += width
    visit(tree, 10, 0)
    svg.append('</svg>')
    return "\n".join(svg)


if __name__ == "__main__":
    Path(sys.argv[2]).write_text(render(stacks(Path(sys.argv[1]).read_text())), encoding="utf-8")
