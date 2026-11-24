#!/bin/bash
# Disposable Docker-only smoke checks. No host desktop commands, published image or public tunnel.
set -euo pipefail
# Usage: test-image.sh IMAGE [SERVER] [RUNTIME]. SERVER is tigervnc (the default display) or x11vnc; RUNTIME
# is runc (default) or runsc. x11vnc reaches the image CMD as DESKTOP_SERVER.
IMAGE="${1:-cathedral-desktop-ci}"
SERVER="${2:-tigervnc}"
RUNTIME="${3:-runc}"
case "$SERVER" in tigervnc) VNC_PROC=Xtigervnc ;; x11vnc) VNC_PROC=x11vnc ;; *) echo "server must be tigervnc or x11vnc" >&2; exit 2 ;; esac
# tigervnc runs with no DESKTOP_SERVER at all, so the check is on the default itself.
RUN=(docker run -d --runtime "$RUNTIME" --network none)
[ "$SERVER" = tigervnc ] || RUN+=(-e "DESKTOP_SERVER=$SERVER")
NAMES=()
TMP="$(mktemp -d)"
cleanup() {
  for name in "${NAMES[@]}"; do docker rm -f "$name" >/dev/null 2>&1 || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT
docker image inspect "$IMAGE" --format '{{json .Config.Cmd}}' | python3 -c \
  'import json,sys; assert json.load(sys.stdin)==["desktop-up","--tunnel","--foreground"]'

# A stopped desktop must report failed. Under gVisor the container's files are gone once it stops
# (docker cp finds nothing), so there the supervisor's own line in the log is the check.
assert_failed() {
  docker logs "$1" > "$TMP/log" 2>&1
  grep -q '^desktop-start: ' "$TMP/log"
  if [ "$RUNTIME" = runc ]; then
    docker cp "$1:/run/desktop/state" "$TMP/state"
    test "$(cat "$TMP/state")" = failed
  fi
}

wait_ready() {
  local name="$1"
  for _ in {1..60}; do
    [ "$(docker inspect "$name" --format '{{.State.Running}}')" = true ] || return 1
    if docker exec "$name" sh -c 'test "$(cat /run/desktop/state 2>/dev/null)" = ready'; then return 0; fi
    sleep 1
  done
  return 1
}

# A real desktop becomes locally ready without a tunnel; killing the VNC server ends it.
name="desktop-local-$RANDOM"
NAMES+=("$name")
"${RUN[@]}" --name "$name" "$IMAGE" desktop-up --foreground >/dev/null
wait_ready "$name"
docker exec "$name" pgrep -x "$VNC_PROC" >/dev/null
docker exec "$name" pkill -x "$VNC_PROC"
test "$(timeout 15 docker wait "$name")" = 1
assert_failed "$name"
echo 'Local startup and service-exit check passed'

# The declared CMD must fail closed when no tunnel can be issued.
name="desktop-no-tunnel-$RANDOM"
NAMES+=("$name")
"${RUN[@]}" --name "$name" "$IMAGE" >/dev/null
test "$(timeout 90 docker wait "$name")" = 1
assert_failed "$name"
echo 'Offline tunnel refusal check passed'

# The current service overrides CMD and still starts the desktop through exec.
name="desktop-legacy-$RANDOM"
NAMES+=("$name")
"${RUN[@]}" --name "$name" "$IMAGE" sleep infinity >/dev/null
timeout 60 docker exec "$name" desktop-up >/dev/null
wait_ready "$name"
docker exec "$name" xdpyinfo -display :1 >/dev/null
test "$(docker inspect "$name" --format '{{.State.Running}}')" = true
echo "Desktop image smoke checks passed ($SERVER under $RUNTIME)"
