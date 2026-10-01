#!/usr/bin/env bash
set -euo pipefail

GO_DIR="${1:-go-impl}"
echo "Syncing shared parity from Go main at $(git -C "$GO_DIR" rev-parse --short HEAD)"

shared=(
  webui/app.js
  webui/i18n.js
  webui/index.html
  webui/metrics.js
  webui/stream.js
  webui/frameviz.js
  webui/style.css
  webui/login.html
  scripts/check_i18n.mjs
)

for f in "${shared[@]}"; do
  cp "$GO_DIR/$f" "$f"
done

cmp "$GO_DIR/webui/favicon.ico" webui/favicon.ico
while IFS= read -r -d '' f; do
  rel="${f#${GO_DIR}/}"
  cmp "$f" "$rel"
done < <(find "$GO_DIR/webui/icons" -type f -print0 | sort -z)

cp "$GO_DIR/config.client.json" config.client.json

for f in "${shared[@]}"; do
  test "$(git hash-object "$f")" = "$(git hash-object "$GO_DIR/$f")" || {
    echo "blob mismatch after sync: $f" >&2
    exit 1
  }
done

# Go's current compact topbar intentionally omits a dedicated zh-TW button;
# Traditional Chinese remains in the shared i18n dictionary and login selector.
# The old Rust parity test incorrectly required that obsolete topbar button.
sed -i '/assert!(index.contains("data-v=\\"zh-TW\\""));/d' tests/dashboard_script_test.rs

node scripts/check_i18n.mjs
cargo test --test dashboard_script_test --test webui_sse_test

rm -f scripts/parity_sync_temp.sh .github/workflows/parity-sync-temp.yml

git add -A
if git diff --cached --quiet; then
  echo "No parity changes to commit"
  exit 0
fi

git -c user.name='github-actions[bot]' \
    -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    commit -m 'webui: align shared assets with Go main'
git push origin HEAD:parity/go-main-20261001
