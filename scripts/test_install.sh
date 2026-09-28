#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

bash -n scripts/install.sh

grep -Fq 'REPO="NNdroid/tlsvpn-rs"' scripts/install.sh
grep -Fq 'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE' scripts/install.sh
grep -Fq 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE' scripts/install.sh
grep -Fq 'systemctl is-active --quiet tlsvpn.service' scripts/install.sh
grep -Fq 'journalctl -u tlsvpn.service -n 50 --no-pager' scripts/install.sh

echo "installer checks passed"
