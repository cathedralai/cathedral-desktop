#!/bin/bash
# Smoke test of the built desktop image: start the desktop the way a room does (exec desktop-up),
# then check input, screenshot and the web port. Usage: test-image-smoke.sh IMAGE SERVER [RUNTIME]
#   SERVER   x11vnc | tigervnc | kasm      RUNTIME  runc (default) | runsc (gVisor, what sealed rooms run under)
# The image CMD (supervised start, desktop-up --tunnel --foreground) is overridden with sleep infinity,
# as the sealed service does today; desktop/test-image.sh covers the CMD. No network: nothing is fetched
# at start and no tunnel is made.
set -u
IMAGE="${1:?image}"; SERVER="${2:?tigervnc, x11vnc or kasm}"; RUNTIME="${3:-runc}"
fail=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
cid="$(docker run -d --runtime "$RUNTIME" --network none "$IMAGE" sleep infinity)" || { echo "FAIL container did not start under $RUNTIME"; exit 1; }
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
if [ "$magic" = 89504e470d0a1a0a ] && [ "$size" -gt 500 ]; then ok "screenshot is a PNG of $size bytes"; else bad "screenshot magic=$magic size=$size"; fi
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
  # The VNC server behind the page: it must ask for the password (security type 2) and never offer "none" (1).
  rfb="$(x python3 -c '
import socket
s = socket.create_connection(("127.0.0.1", 5901), timeout=5)
banner = s.recv(12); s.sendall(banner)
n = s.recv(1)[0]; types = list(s.recv(n)) if n else []
print(banner.decode().strip(), "types", sorted(types))' 2>&1 | tail -1)"
  case "$rfb" in "RFB 003.008 types [2]") ok "VNC on 5901 offers password auth only ($rfb)" ;; *) bad "VNC on 5901 said: $rfb (want RFB 003.008 types [2])" ;; esac
  if [ "$SERVER" = tigervnc ]; then
    x pgrep -x x11vnc >/dev/null 2>&1 && bad "x11vnc is running in tigervnc mode" || ok "no x11vnc in tigervnc mode"
    x pgrep -x Xvfb   >/dev/null 2>&1 && bad "Xvfb is running in tigervnc mode"   || ok "no Xvfb in tigervnc mode"
    x pgrep -x Xtigervnc >/dev/null 2>&1 && ok "Xtigervnc is the display" || bad "Xtigervnc is not running"
  fi
fi
# Wallpaper choice (--wallpaper). bg prints "<unique colours> <colour>" for a 900x450 region of bare desktop
# (below the panel, away from the pointer). A solid background is exactly "1 RRGGBB". The first check is
# the control: the branded wallpaper must read as many colours there, or the probe proves nothing. (The
# first version of this test read one pixel that is the same dark colour in the branded picture, so it
# passed "neutral" while the branded picture was still up.)
bg() {
  x shot >/dev/null 2>&1
  x sh -c "magick /work/screen.png -crop 900x450+340+320 +repage -unique-colors -format '%w ' info:; magick /work/screen.png -format '%[hex:u.p{400,400}]' info:" 2>/dev/null \
    | tr a-f A-F | awk '{print $1, substr($2,1,6)}'
}
wp() { x desktop-up --server "$SERVER" --room smoke "$@" >/dev/null 2>&1; }
b="$(bg)"; [ "$b" = "1 0B0D11" ] && ok "a fresh desktop is neutral: one plain dark colour, no Cathedral picture" || bad "a fresh desktop reads '$b', want '1 0B0D11'"
x grep -q 'label="Desktop"' /root/.config/openbox/menu.xml && ok "a fresh desktop has the neutral menu title" || bad "a fresh desktop has the branded menu title"
if x test -e /work/desktop-wallpaper; then bad "a wallpaper choice was saved without being asked"; else ok "no wallpaper choice is saved until one is made"; fi
wp --wallpaper cathedral
b="$(bg)"; n="${b%% *}"
if [ "${n:-0}" -gt 50 ] 2>/dev/null; then ok "control: the branded wallpaper reads as $n colours"; else bad "control: the branded wallpaper reads as '$b', want many colours"; fi
x grep -q 'label="Cathedral"' /root/.config/openbox/menu.xml && ok "the branded wallpaper brings the branded menu title" || bad "menu title not branded with --wallpaper cathedral"
wp --wallpaper neutral
b="$(bg)"; [ "$b" = "1 0B0D11" ] && ok "neutral wallpaper is one plain dark colour" || bad "neutral wallpaper reads '$b', want '1 0B0D11'"
[ "$(x cat /work/desktop-wallpaper 2>/dev/null)" = neutral ] && ok "wallpaper choice is saved" || bad "wallpaper choice not saved"
x grep -q 'label="Desktop"' /root/.config/openbox/menu.xml && ok "menu title is Desktop when not branded" || bad "menu title still branded"
wp --wallpaper '#224466'
b="$(bg)"; [ "$b" = "1 224466" ] && ok "colour wallpaper applied" || bad "colour wallpaper reads '$b', want '1 224466'"
x magick -size 320x200 xc:'#AA3311' /work/own.png >/dev/null 2>&1
wp --wallpaper /work/own.png
b="$(bg)"; [ "$b" = "1 AA3311" ] && ok "customer picture applied" || bad "customer picture reads '$b', want '1 AA3311'"
wp
b="$(bg)"; [ "$b" = "1 AA3311" ] && ok "saved wallpaper survives a plain desktop-up" || bad "saved wallpaper lost: reads '$b'"
x sh -c 'echo not-a-picture > /work/bad.png'
wp --wallpaper /work/bad.png
b="$(bg)"; [ "$b" = "1 0B0D11" ] && ok "an unreadable picture falls back to the plain base" || bad "unreadable picture reads '$b', want '1 0B0D11'"
wp --wallpaper sideways
b="$(bg)"; [ "$b" = "1 0B0D11" ] && ok "an unknown value falls back to the plain base" || bad "unknown value reads '$b', want '1 0B0D11'"
wp --wallpaper cathedral
x grep -q 'label="Cathedral"' /root/.config/openbox/menu.xml && ok "cathedral wallpaper restores the branded menu title" || bad "menu title not restored"
b="$(bg)"; n="${b%% *}"
if [ "${n:-0}" -gt 50 ] 2>/dev/null; then ok "cathedral wallpaper is back ($n colours)"; else bad "cathedral wallpaper not back: reads '$b'"; fi
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
# shot's fast path needs scrot --thumb, PPM output and the <name>-thumb naming; say which path this image takes.
if x bash -c 'd=$(mktemp -d); DISPLAY=:1 scrot -o -t 50 "$d/f.ppm" >/dev/null 2>&1 && test -s "$d/f-thumb.ppm"'; then echo "info shot --scale uses scrot --thumb (PPM)"; else echo "info shot --scale falls back to magick on a full PNG"; fi
# --jpeg Q must hold on the scaled path: a lower quality gives a smaller file.
x shot --jpeg 30 --scale 50 >/dev/null 2>&1; lo=$(x stat -c %s /work/screen.jpg 2>/dev/null || echo 0)
x shot --jpeg 90 --scale 50 >/dev/null 2>&1; hi=$(x stat -c %s /work/screen.jpg 2>/dev/null || echo 0)
[ "$lo" -gt 0 ] && [ "$lo" -lt "$hi" ] && ok "shot --scale honours --jpeg quality ($lo B at 30, $hi B at 90)" || bad "shot --scale ignored --jpeg quality ($lo B at 30, $hi B at 90)"
x shot --region 100,100,300,200 >/dev/null 2>&1
dim="$(x magick identify -format '%wx%h' /work/screen.png 2>/dev/null)"
[ "$dim" = 300x200 ] && ok "shot --region captures the rectangle" || bad "shot --region gave '$dim', want 300x200"
x shot --scale 0 >/dev/null 2>&1 && bad "shot accepted --scale 0" || ok "shot refuses a bad --scale"
x shot --bogus >/dev/null 2>&1 && bad "shot accepted an unknown flag" || ok "shot refuses an unknown flag"
x shot --b64 2>/dev/null | tr -d '\n' | base64 -d > /tmp/smoke-shot2.png 2>/dev/null
[ "$(head -c 8 /tmp/smoke-shot2.png | od -An -tx1 | tr -d ' \n')" = 89504e470d0a1a0a ] && ok "plain shot --b64 is still a full PNG" || bad "plain shot --b64 changed"
med() { x bash -c 'for i in $(seq 15); do s=$(date +%s%N); "$@" >/dev/null 2>&1; e=$(date +%s%N); echo $(( (e-s)/1000000 )); done | sort -n | sed -n 8p' _ "$@"; }
echo "info median of 15, in the room, $SERVER under $RUNTIME: shot png $(med shot) ms ($png B); shot --jpeg $(med shot --jpeg) ms ($jpg B); shot --jpeg 60 --scale 50 $(med shot --jpeg 60 --scale 50) ms ($half B); one xdotool click $(med env DISPLAY=:1 xdotool mousemove 200 300 click 1) ms"
# Where a scaled shot spends its time: the capture, or the resize filter. Old filter vs the one shot uses.
x shot >/dev/null 2>&1
echo "info median of 15, in the room, $SERVER under $RUNTIME: magick 50% of the full PNG to JPEG, -resize $(med magick /work/screen.png -resize 50% -quality 60 /tmp/r.jpg) ms, -scale $(med magick /work/screen.png -scale 50% -quality 60 /tmp/s.jpg) ms"
# Where a click spends its time: starting xdotool and reading the keymap, or the input itself.
echo "info median of 15, in the room, $SERVER under $RUNTIME: xdotool getmouselocation (start only) $(med env DISPLAY=:1 xdotool getmouselocation) ms; mousemove $(med env DISPLAY=:1 xdotool mousemove 200 300) ms; click 1 $(med env DISPLAY=:1 xdotool click 1) ms; click --delay 0 1 (what a fused agent step sends) $(med env DISPLAY=:1 xdotool click --delay 0 1) ms"
# Where a shot spends its time under each runtime: process start, the capture itself, or the shot script around it.
echo "info median of 15, in the room, $SERVER under $RUNTIME: true $(med true) ms; bash -c true $(med bash -c true) ms; bare scrot jpeg to /tmp $(med env DISPLAY=:1 scrot -o -q 70 /tmp/bare.jpg) ms; bare scrot jpeg to /work $(med env DISPLAY=:1 scrot -o -q 70 /work/bare.jpg) ms; shot --jpeg $(med shot --jpeg) ms"
# step: the input and the screenshot in one call.
x step --settle 50 --jpeg 60 --scale 50 -- mousemove 321 222 2>/dev/null | tr -d '\n' | base64 -d > /tmp/smoke-step.jpg 2>/dev/null
sm="$(head -c 2 /tmp/smoke-step.jpg | od -An -tx1 | tr -d ' \n')"; ss=$(stat -c %s /tmp/smoke-step.jpg 2>/dev/null || echo 0)
loc="$(x env DISPLAY=:1 xdotool getmouselocation 2>/dev/null)"
case "$loc" in *"x:321 y:222"*) lok=1 ;; *) lok=0 ;; esac
if [ "$sm" = ffd8 ] && [ "$ss" -gt 1000 ] && [ "$lok" = 1 ]; then ok "step did the input and returned a JPEG ($ss bytes) in one call"; else bad "step: magic=$sm size=$ss pointer=$loc"; fi
out="$(x step -- no-such-xdotool-command 2>/dev/null)"; rc=$?
if [ "$rc" = 3 ] && [ -z "$out" ]; then ok "step prints no screenshot when the input fails (exit 3)"; else bad "step with a bad input: exit $rc, ${#out} bytes printed"; fi
x step --settle abc >/dev/null 2>&1; [ $? = 2 ] && ok "step refuses a bad --settle" || bad "step accepted a bad --settle"
two() { x bash -c 'for i in $(seq 15); do s=$(date +%s%N); env DISPLAY=:1 xdotool mousemove 200 300 click 1 >/dev/null 2>&1; shot --jpeg 60 --scale 50 >/dev/null 2>&1; e=$(date +%s%N); echo $(( (e-s)/1000000 )); done | sort -n | sed -n 8p'; }
echo "info median of 15, in the room, $SERVER under $RUNTIME: click then screenshot as two commands $(two) ms; step --settle 0 (one command) $(med step --settle 0 --jpeg 60 --scale 50 -- mousemove 200 300 click 1) ms. Through the API each command is also one exec round trip, which this does not measure"
# Asking for the other display server on a running desktop must refuse and leave everything as it was.
oth=kasm; [ "$SERVER" = kasm ] && oth=tigervnc
x desktop-up --server "$oth" --room smoke >/dev/null 2>&1; rc=$?
[ "$rc" = 2 ] && ok "switching to --server $oth on a running desktop is refused" || bad "switching to --server $oth exited $rc, want 2"
x desktop-up --server "$oth" --restart --room smoke >/dev/null 2>&1; rc=$?
[ "$rc" = 2 ] && ok "the same with --restart is refused" || bad "switching with --restart exited $rc, want 2"
[ "$(x cat /run/desktop/state 2>/dev/null)" = ready ] && ok "state is still ready after the refusals" || bad "state changed after a refused switch"
if [ "$SERVER" = kasm ]; then c="$(code -u "cathedral:$pw" http://127.0.0.1:6080/)"; else c="$(code http://127.0.0.1:6080/)"; fi
[ "$c" = 200 ] && ok "the viewer still answers after the refusals" || bad "the viewer answered $c after a refused switch"
# A second call must be a no-op, as the API's start exec may run twice.
x desktop-up --server "$SERVER" --room smoke >/dev/null 2>&1 && ok "second desktop-up is harmless" || bad "second desktop-up failed"
x env DISPLAY=:1 xdpyinfo >/dev/null 2>&1 && ok "display survives the second call" || bad "display gone after the second call"
if [ "$fail" != 0 ]; then
  echo "---- logs"; for f in kasmvnc tigervnc xvfb x11vnc websockify openbox; do echo "## $f"; x sh -c "tail -n 40 /run/desktop/$f.log 2>/dev/null"; done
fi
exit "$fail"
