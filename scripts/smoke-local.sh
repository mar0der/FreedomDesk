#!/usr/bin/env bash
# T1 smoke test: host + headless viewer on this machine over loopback.
# View-only (no input injected into your desktop), unattended via pinned viewer key.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DISPLAY:=:0}"; export DISPLAY
if [[ -z "${XAUTHORITY:-}" && -f /run/user/$(id -u)/gdm/Xauthority ]]; then
  export XAUTHORITY=/run/user/$(id -u)/gdm/Xauthority
fi
PROFILE=${PROFILE:-release}
FRAMES=${FRAMES:-150}
RUNS=${RUNS:-1}
PORT=${PORT:-47899}
cargo build --profile "$PROFILE" -p freedomdesk -q
BIN=target/$([[ $PROFILE == dev ]] && echo debug || echo "$PROFILE")/freedomdesk
TMP=$(mktemp -d)
trap 'kill $HOST_PID 2>/dev/null || true; rm -rf "$TMP"' EXIT
HOST_FP=$($BIN --config-dir "$TMP/host" id | awk '/fingerprint/{print $3}')
VIEW_FP=$($BIN --config-dir "$TMP/viewer" id | awk '/fingerprint/{print $3}')
RUST_LOG=${RUST_LOG:-warn} $BIN --config-dir "$TMP/host" host --bind 127.0.0.1 --port "$PORT" \
  --unattended-viewer "$VIEW_FP" --view-only &
HOST_PID=$!
sleep 1
for i in $(seq 1 "$RUNS"); do
  $BIN --config-dir "$TMP/viewer" view "127.0.0.1:$PORT" --headless --frames "$FRAMES" \
    --expect-fingerprint "$HOST_FP" 2>/dev/null
done
# Negative test: a viewer expecting the wrong host key must be refused.
if $BIN --config-dir "$TMP/viewer" view "127.0.0.1:$PORT" --headless --frames 1 \
     --expect-fingerprint AAAA-AAAA-AAAA-AAAA-AAAA-AAAA >/dev/null 2>&1; then
  echo "FAIL: wrong fingerprint accepted"; exit 1
fi
# Negative test: an unknown viewer (not in unattended list) gets the consent prompt;
# with no answer it must be denied. Skipped by default (pops a dialog on the desktop).
echo "PASS: smoke ($RUNS run(s), $FRAMES frames each); pin mismatch refused"
