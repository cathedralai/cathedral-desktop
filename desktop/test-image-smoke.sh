#!/bin/bash
# Smoke test of the built desktop image: start the desktop the way a room does (exec desktop-up),
# then check input, screenshot and the web port. Usage: test-image-smoke.sh IMAGE SERVER [RUNTIME]
#   SERVER   x11vnc | kasm      RUNTIME  runc (default) | runsc (gVisor, what sealed rooms run under)
# No tunnel is started, so the test needs no network after the image is built.
set -u
IMAGE="${1:?image}"; SERVER="${2:?x11vnc or kasm}"; RUNTIME="${3:-runc}"
fail=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
cid="$(docker run -d --runtime "$RUNTIME" "$IMAGE")" || { echo "FAIL container did not start under $RUNTIME"; exit 1; }
trap 'docker rm -f "$cid" >/dev/null 2>&1' EXIT
x() { docker exec "$cid" "$@"; }
t0=$(date +%s.%N)
if x desktop-up --server "$SERVER" --room smoke; then ok "desktop-up --server $SERVER"; else bad "desktop-up --server $SERVER exited non-zero"; fi
t1=$(date +%s.%N)
echo "info desktop-up took $(echo "$t1 - $t0" | bc) s under $RUNTIME"
x env DISPLAY=:1 xdpyinfo >/dev/null 2>&1 && ok "display :1 answers" || bad "display :1 does not answer"
[ "$(x cat /run/desktop/state 2>/dev/null)" = ready ] && ok "state ready" || bad "state is not ready"
x env DISPLAY=:1 xdotool mousemove 123 234 >/dev/null 2>&1
loc="$(x env DISPLAY=:1 xdotool getmouselocation 2>/dev/null)"
case "$loc" in *"x:123 y:234"*) ok "xdotool moves the pointer" ;; *) bad "pointer not at 123,234: $loc" ;; esac
x shot --b64 2>/dev/null | tr -d '\n' | base64 -d > /tmp/smoke-shot.png 2>/dev/null
size=$(stat -c %s /tmp/smoke-shot.png 2>/dev/null || echo 0)
magic="$(head -c 8 /tmp/smoke-shot.png | od -An -tx1 | tr -d ' \n')"
if [ "$magic" = 89504e470d0a1a0a ] && [ "$size" -gt 5000 ]; then ok "screenshot is a PNG of $size bytes"; else bad "screenshot magic=$magic size=$size"; fi
pw="$(x cat /work/vnc-password 2>/dev/null)"
[ ${#pw} -eq 12 ] && ok "room password generated" || bad "room password missing"
code() { x curl -s -o /dev/null -m 10 -w '%{http_code}' "$@" 2>/dev/null; }
if [ "$SERVER" = kasm ]; then
  c="$(code http://127.0.0.1:6080/)";                      [ "$c" = 401 ] && ok "web port refuses without the password (401)" || bad "web port without password answered $c, want 401"
  c="$(code -u "cathedral:wrong-$pw" http://127.0.0.1:6080/)"; [ "$c" = 401 ] && ok "web port refuses a wrong password (401)" || bad "web port with a wrong password answered $c, want 401"
  c="$(code -u "cathedral:$pw" http://127.0.0.1:6080/)";   [ "$c" = 200 ] && ok "web port serves the client with the password (200)" || bad "web port with the password answered $c, want 200"
  x pgrep -x x11vnc >/dev/null 2>&1 && bad "x11vnc is running in kasm mode" || ok "no x11vnc in kasm mode"
  x pgrep -x Xvfb   >/dev/null 2>&1 && bad "Xvfb is running in kasm mode"   || ok "no Xvfb in kasm mode"
else
  c="$(code http://127.0.0.1:6080/)"; [ "$c" = 200 ] && ok "web port serves the viewer page (200)" || bad "web port answered $c, want 200"
fi
# A second call must be a no-op, as the API's start exec may run twice.
x desktop-up --server "$SERVER" --room smoke >/dev/null 2>&1 && ok "second desktop-up is harmless" || bad "second desktop-up failed"
x env DISPLAY=:1 xdpyinfo >/dev/null 2>&1 && ok "display survives the second call" || bad "display gone after the second call"
if [ "$fail" != 0 ]; then
  echo "---- logs"; for f in kasmvnc xvfb x11vnc websockify openbox; do echo "## $f"; x sh -c "tail -n 40 /run/desktop/$f.log 2>/dev/null"; done
fi
exit "$fail"
