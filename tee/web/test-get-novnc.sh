#!/bin/bash
# bash tee/web/test-get-novnc.sh
# get-novnc.sh pins the noVNC download by sha256 from a table next to it. No network: the script and a TEST
# table are copied to a temp folder and a fake curl on PATH copies a local tarball.
set -u
SRC="$(cd "$(dirname "$0")" && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fail=0
check() { if [ "$2" = 0 ]; then echo "ok   $1"; else echo "FAIL $1"; fail=$((fail+1)); fi; }

mkdir -p "$W/tee/web" "$W/tee/fixtures" "$W/bin" "$W/src/noVNC-9.9.9/core" "$W/src/noVNC-9.9.9/vendor"
cp "$SRC/get-novnc.sh" "$W/tee/web/"
: > "$W/tee/fixtures/amd-genoa-ark.der"; : > "$W/tee/fixtures/amd-genoa-ask.der"
echo core > "$W/src/noVNC-9.9.9/core/rfb.js"; echo vendor > "$W/src/noVNC-9.9.9/vendor/pako.js"
tar czf "$W/novnc.tgz" -C "$W/src" noVNC-9.9.9
GOOD="$(shasum -a 256 "$W/novnc.tgz" | cut -d' ' -f1)"
ZERO="0000000000000000000000000000000000000000000000000000000000000000"
cat > "$W/bin/curl" <<'CURL'
#!/bin/bash
out=""; while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done
echo "curl called" >> "$FAKE_CURL_LOG"
cp "$FAKE_TARBALL" "$out"
CURL
chmod +x "$W/bin/curl"
export FAKE_TARBALL="$W/novnc.tgz" FAKE_CURL_LOG="$W/curl.log"

run() { : > "$FAKE_CURL_LOG"; PATH="$W/bin:$PATH" bash "$W/tee/web/get-novnc.sh" "$1" >"$W/out" 2>&1; }
empty() { [ ! -e "$W/tee/web/core" ] && [ ! -e "$W/tee/web/vendor" ] && [ ! -e "$W/tee/web/fixtures" ]; }

printf '# test table\n9.9.9 %s\n8.8.8 %s\n' "$GOOD" "$ZERO" > "$W/tee/web/novnc-sha256.txt"

run 8.8.8; rc=$?
[ "$rc" -ne 0 ]; check "a wrong hash exits non-zero" $?
empty; check "a wrong hash leaves no core, vendor or fixtures" $?
grep -q "sha256 mismatch" "$W/out"; check "a wrong hash says it is a sha256 mismatch" $?
ls "$W/tee/web" | grep -q '^tmp\|novnc.tgz' && rc=1 || rc=0; check "a wrong hash leaves no download in the folder" $rc

run 7.7.7; rc=$?
[ "$rc" -ne 0 ]; check "a version with no entry in the table exits non-zero" $?
[ ! -s "$FAKE_CURL_LOG" ]; check "a version with no entry is refused before any download" $?
empty; check "a version with no entry leaves nothing in place" $?

run 9.9.9; rc=$?
[ "$rc" -eq 0 ]; check "the right hash exits zero" $?
[ -f "$W/tee/web/core/rfb.js" ] && [ -f "$W/tee/web/vendor/pako.js" ] && [ -f "$W/tee/web/fixtures/amd-genoa-ark.der" ]; check "the right hash puts core, vendor and certificates in place" $?

# The production table pins the default version.
awk '$1 !~ /^#/ && $1 == "1.6.0" && $2 ~ /^[0-9a-f]{64}$/ { ok=1 } END { exit !ok }' "$SRC/novnc-sha256.txt"; check "the real table has a sha256 for the default version 1.6.0" $?
grep -q 'V="${1:-1.6.0}"' "$SRC/get-novnc.sh"; check "the default version is the pinned one" $?
! grep -q 'SHA256\b.*:-' "$SRC/get-novnc.sh"; check "the script has no environment override of the hash" $?

[ "$fail" -eq 0 ] && echo "all checks passed" || echo "$fail failure(s)"
exit "$fail"
