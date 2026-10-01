#!/usr/bin/env bash
set -euo pipefail
GO_DIR="${1:-go-impl}"

echo "Resyncing shared WebUI from Go main $(git -C "$GO_DIR" rev-parse --short HEAD)"
shared=(
  webui/app.js
  webui/diagnostics.js
  webui/frameviz.js
  webui/i18n.js
  webui/index.html
  webui/login.html
  webui/metrics.js
  webui/stream.js
  webui/style.css
  webui/tcp.js
  scripts/check_i18n.mjs
  scripts/webui_browser_smoke.mjs
  scripts/webui_metrics_regression.mjs
)
for f in "${shared[@]}"; do
  cp "$GO_DIR/$f" "$f"
done
for f in "${shared[@]}"; do
  test "$(git hash-object "$f")" = "$(git hash-object "$GO_DIR/$f")" || {
    echo "blob mismatch after sync: $f" >&2
    exit 1
  }
done
cmp "$GO_DIR/webui/favicon.ico" webui/favicon.ico
while IFS= read -r -d '' f; do
  rel="${f#${GO_DIR}/}"
  cmp "$f" "$rel"
done < <(find "$GO_DIR/webui/icons" -type f -print0 | sort -z)

node scripts/check_i18n.mjs
node scripts/webui_metrics_regression.mjs
npm install --no-save --package-lock=false playwright@1.55.0
npx playwright install --with-deps chromium
node scripts/webui_browser_smoke.mjs

rm -rf go-impl node_modules
rm -f scripts/parity_resync_go_webui_temp.sh .github/workflows/parity-resync-go-webui-temp.yml
git add -A
git -c user.name='github-actions[bot]' \
    -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    commit -m 'webui: resync shared assets with current Go main'
git push origin HEAD:parity/go-main-20261001
