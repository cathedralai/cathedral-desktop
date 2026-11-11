#!/bin/bash
# Render the Cathedral wallpaper with ImageMagick 7: near-black base, one soft coral glow, wordmark and caption.
# Usage: wallpaper.sh OUT.png [WxH]
set -eu
out="${1:?OUT.png}"; size="${2:-1280x800}"
w="${size%x*}"; h="${size#*x}"
bold="$(fc-match -f '%{file}' 'Inter:weight=700' 2>/dev/null || true)"
regular="$(fc-match -f '%{file}' 'Inter' 2>/dev/null || true)"
mono="$(fc-match -f '%{file}' 'JetBrains Mono' 2>/dev/null || true)"
[ -n "$bold" ] || bold=DejaVu-Sans-Bold
[ -n "$regular" ] || regular=DejaVu-Sans
[ -n "$mono" ] || mono=DejaVu-Sans-Mono
glow=$(( w * 9 / 10 ))
magick -size "${size}" xc:'#0B0D11' \
  \( -size "${glow}x${glow}" radial-gradient:'#F06E4A-#0B0D11' -alpha set -channel A -evaluate multiply 0.22 +channel \) \
  -gravity northwest -geometry "+$(( w - glow * 2 / 3 ))+$(( h - glow * 3 / 5 ))" -compose screen -composite \
  \( -size "${size}" xc:none -stroke '#FFFFFF' -strokewidth 1 -fill none \
     -draw "line 0,$(( h * 62 / 100 )) ${w},$(( h * 62 / 100 ))" -alpha set -channel A -evaluate multiply 0.06 +channel \) \
  -gravity northwest -geometry +0+0 -compose over -composite \
  -font "$bold" -pointsize $(( h / 11 )) -fill '#ECE9E1' -gravity northwest -annotate "+$(( w * 6 / 100 ))+$(( h * 66 / 100 ))" 'Cathedral' \
  -font "$regular" -pointsize $(( h / 44 )) -fill '#8E9AA6' -annotate "+$(( w * 6 / 100 + 4 ))+$(( h * 66 / 100 + h / 11 + h / 40 ))" 'Sealed desktop.  Every click, key and screenshot is a signed receipt.' \
  -font "$mono" -pointsize $(( h / 57 )) -fill '#F06E4A' -annotate "+$(( w * 6 / 100 + 4 ))+$(( h * 66 / 100 + h / 11 + h / 40 + h / 24 ))" 'AMD SEV-SNP  /  gVisor  /  cathedral.computer' \
  "$out"
echo "wallpaper $out ($size)"
