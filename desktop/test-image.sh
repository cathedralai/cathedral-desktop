#!/bin/bash
# Disposable Docker-only smoke checks. No host desktop commands, published image or public tunnel.
set -euo pipefail
IMAGE="${1:-cathedral-desktop-ci}"
NAMES=()
TMP="$(mktemp -d)"
cleanup() {
  for name in "${NAMES[@]}"; do docker rm -f "$name" >/dev/null 2>&1 || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT
docker image inspect "$IMAGE" --format '{{json .Config.Cmd}}' | python3 -c \
  'import json,sys; assert json.load(sys.stdin)==["desktop-up","--tunnel","--foreground"]'

wait_ready() {
  local name="$1"
  for _ in {1..60}; do
    [ "$(docker inspect "$name" --format '{{.State.Running}}')" = true ] || return 1
    if docker exec "$name" sh -c 'test "$(cat /run/desktop/state 2>/dev/null)" = ready'; then return 0; fi
    sleep 1
  done
  return 1
}

# A real desktop becomes locally ready without a tunnel; killing a service ends it.
name="desktop-local-$RANDOM"
NAMES+=("$name")
docker run -d --network none --name "$name" "$IMAGE" desktop-up --foreground >/dev/null
wait_ready "$name"
docker exec "$name" pkill -x x11vnc
test "$(timeout 15 docker wait "$name")" = 1
docker cp "$name:/run/desktop/state" "$TMP/state"
test "$(cat "$TMP/state")" = failed

# The declared CMD must fail closed when no tunnel can be issued.
name="desktop-no-tunnel-$RANDOM"
NAMES+=("$name")
docker run -d --network none --name "$name" "$IMAGE" >/dev/null
test "$(timeout 90 docker wait "$name")" = 1
docker cp "$name:/run/desktop/state" "$TMP/state"
test "$(cat "$TMP/state")" = failed

# The current service overrides CMD and still starts the desktop through exec.
name="desktop-legacy-$RANDOM"
NAMES+=("$name")
docker run -d --network none --name "$name" "$IMAGE" sleep infinity >/dev/null
timeout 60 docker exec "$name" desktop-up >/dev/null
wait_ready "$name"
docker exec "$name" xdpyinfo >/dev/null
test "$(docker inspect "$name" --format '{{.State.Running}}')" = true
echo 'Desktop image smoke checks passed'
