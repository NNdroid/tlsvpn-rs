#!/usr/bin/env bash
set -euo pipefail
GO_DIR="${1:-go-impl}"

echo "Syncing new shared WebUI modules from Go $(git -C "$GO_DIR" rev-parse --short HEAD)"
cp "$GO_DIR/webui/tcp.js" webui/tcp.js
cp "$GO_DIR/webui/diagnostics.js" webui/diagnostics.js
cp "$GO_DIR/scripts/webui_browser_smoke.mjs" scripts/webui_browser_smoke.mjs

python3 - <<'PY'
from pathlib import Path
p=Path('src/webui_assets.rs')
s=p.read_text()
needle='''        "/stream.js" => Some((\n            include_bytes!("../webui/stream.js"),\n            "application/javascript; charset=utf-8",\n        )),\n'''
insert=needle+'''        "/tcp.js" => Some((\n            include_bytes!("../webui/tcp.js"),\n            "application/javascript; charset=utf-8",\n        )),\n        "/diagnostics.js" => Some((\n            include_bytes!("../webui/diagnostics.js"),\n            "application/javascript; charset=utf-8",\n        )),\n'''
if needle not in s:
    raise SystemExit('webui_assets stream route marker missing')
s=s.replace(needle,insert,1)
p.write_text(s)
PY

cmp "$GO_DIR/webui/tcp.js" webui/tcp.js
cmp "$GO_DIR/webui/diagnostics.js" webui/diagnostics.js
cmp "$GO_DIR/scripts/webui_browser_smoke.mjs" scripts/webui_browser_smoke.mjs
node scripts/check_i18n.mjs
cargo test --test dashboard_script_test --test webui_sse_test --test webui_metrics_test

rm -rf go-impl
rm -f scripts/parity_webui_modules_temp.sh .github/workflows/parity-webui-modules-temp.yml
git add -A
git -c user.name='github-actions[bot]' \
    -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    commit -m 'webui: embed TCP and diagnostics modules from Go'
git push origin HEAD:parity/go-main-20261001
