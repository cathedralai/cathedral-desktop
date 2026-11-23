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
# Screenshot options for agents (shot --jpeg / --scale / --region), and what one step of an agent loop costs
# inside the room. The times are information, not a pass mark: a shared CI runner is too noisy to gate on.
# They leave out the API hop a real customer call adds.
x shot >/dev/null 2>&1; png=$(x stat -c %s /work/screen.png 2>/dev/null || echo 0)
x shot --jpeg >/dev/null 2>&1; jpg=$(x stat -c %s /work/screen.jpg 2>/dev/null || echo 0)
jm="$(x sh -c 'head -c 2 /work/screen.jpg | od -An -tx1' 2>/dev/null | tr -d ' \n')"
if [ "$jm" = ffd8 ] && [ "$jpg" -gt 1000 ] && [ "$jpg" -lt "$png" ]; then ok "shot --jpeg is a JPEG of $jpg bytes, smaller than the PNG ($png)"; else bad "shot --jpeg magic=$jm size=$jpg png=$png"; fi
x shot --jpeg 60 --scale 50 >/dev/null 2>&1
dim="$(x magick identify -format '%wx%h' /work/screen.jpg 2>/dev/null)"; half=$(x stat -c %s /work/screen.jpg 2>/dev/null || echo 0)
[ "$dim" = 640x400 ] && ok "shot --scale 50 gives 640x400 ($half bytes)" || bad "shot --scale 50 gave '$dim', want 640x400"
x shot --region 100,100,300,200 >/dev/null 2>&1
dim="$(x magick identify -format '%wx%h' /work/screen.png 2>/dev/null)"
[ "$dim" = 300x200 ] && ok "shot --region captures the rectangle" || bad "shot --region gave '$dim', want 300x200"
x shot --scale 0 >/dev/null 2>&1 && bad "shot accepted --scale 0" || ok "shot refuses a bad --scale"
x shot --bogus >/dev/null 2>&1 && bad "shot accepted an unknown flag" || ok "shot refuses an unknown flag"
x shot --b64 2>/dev/null | tr -d '\n' | base64 -d > /tmp/smoke-shot2.png 2>/dev/null
[ "$(head -c 8 /tmp/smoke-shot2.png | od -An -tx1 | tr -d ' \n')" = 89504e470d0a1a0a ] && ok "plain shot --b64 is still a full PNG" || bad "plain shot --b64 changed"
med() { x bash -c 'for i in $(seq 15); do s=$(date +%s%N); "$@" >/dev/null 2>&1; e=$(date +%s%N); echo $(( (e-s)/1000000 )); done | sort -n | sed -n 8p' _ "$@"; }
echo "info median of 15, in the room, $SERVER under $RUNTIME: shot png $(med shot) ms ($png B); shot --jpeg $(med shot --jpeg) ms ($jpg B); shot --jpeg 60 --scale 50 $(med shot --jpeg 60 --scale 50) ms ($half B); one xdotool click $(med env DISPLAY=:1 xdotool mousemove 200 300 click 1) ms"
# A second call must be a no-op, as the API's start exec may run twice.
x desktop-up --server "$SERVER" --room smoke >/dev/null 2>&1 && ok "second desktop-up is harmless" || bad "second desktop-up failed"
x env DISPLAY=:1 xdpyinfo >/dev/null 2>&1 && ok "display survives the second call" || bad "display gone after the second call"
if [ "$fail" != 0 ]; then
  echo "---- logs"; for f in kasmvnc xvfb x11vnc websockify openbox; do echo "## $f"; x sh -c "tail -n 40 /run/desktop/$f.log 2>/dev/null"; done
fi
exit "$fail"
