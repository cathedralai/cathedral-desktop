#!/bin/bash
# bash tee/web/test-get-novnc.sh
# get-novnc.sh pins the noVNC download by sha256 from a table next to it. No network: the script and a TEST
# table are copied to a temp folder and a fake curl on PATH copies a local tarball.
set -u
SRC="$(cd "$(dirname "$0")" && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fail=0
check() { if [ "$2" = 0 ]; then echo "ok   $1"; else echo "FAIL $1"; fail=$((fail+1)); fi; }

mkdir -p "$W/tee/web" "$W/tee/fixtures" "$W/bin" "$W/tmp" "$W/src/noVNC-9.9.9/core" "$W/src/noVNC-9.9.9/vendor"
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

# TMPDIR is inside $W so a temp folder the script leaves behind is visible.
run() { : > "$FAKE_CURL_LOG"; TMPDIR="$W/tmp" PATH="$W/bin:$PATH" bash "$W/tee/web/get-novnc.sh" "$1" >"$W/out" 2>&1; }
empty() { [ ! -e "$W/tee/web/core" ] && [ ! -e "$W/tee/web/vendor" ] && [ ! -e "$W/tee/web/fixtures" ]; }
no_install() { [ ! -e "$W/tee/web/core" ] && [ ! -e "$W/tee/web/vendor" ]; }
plant_old() { mkdir -p "$W/tee/web/core" "$W/tee/web/vendor"; echo old > "$W/tee/web/core/rfb.js"; echo old > "$W/tee/web/core/stray.js"; echo old > "$W/tee/web/vendor/stray.js"; }

printf '# test table\n9.9.9 %s\n8.8.8 %s\n' "$GOOD" "$ZERO" > "$W/tee/web/novnc-sha256.txt"

# A wrong hash: the mismatch message, no install, no temp folder left behind.
run 8.8.8; rc=$?
[ "$rc" -ne 0 ] && grep -q "sha256 mismatch for noVNC 8.8.8" "$W/out"; check "a wrong hash exits non-zero with the mismatch message" $?
[ -s "$FAKE_CURL_LOG" ]; check "a wrong hash got as far as the download (the failure is the hash, not a missing file)" $?
empty; check "a wrong hash leaves no core, vendor or fixtures" $?
[ -z "$(ls -A "$W/tmp")" ]; check "a wrong hash leaves no temp folder behind" $?

# A version with no entry: refused with its own message before any download.
run 7.7.7; rc=$?
[ "$rc" -ne 0 ] && grep -q "no sha256 for noVNC 7.7.7" "$W/out"; check "a version with no entry exits non-zero with the no-entry message" $?
[ ! -s "$FAKE_CURL_LOG" ]; check "a version with no entry is refused before any download (curl called 0 times)" $?
empty; check "a version with no entry leaves nothing in place" $?
[ -z "$(ls -A "$W/tmp")" ]; check "a version with no entry leaves no temp folder behind" $?

# An install from before the pin was never checked: a refusal must not leave it for the page to load.
plant_old; run 8.8.8
no_install; check "an old install plus a wrong hash leaves no core or vendor" $?
plant_old; run 7.7.7
no_install; check "an old install plus a version with no entry leaves no core or vendor" $?

# A good run replaces the old install completely.
plant_old; run 9.9.9; rc=$?
[ "$rc" -eq 0 ]; check "the right hash exits zero" $?
[ -f "$W/tee/web/core/rfb.js" ] && [ -f "$W/tee/web/vendor/pako.js" ] && [ -f "$W/tee/web/fixtures/amd-genoa-ark.der" ]; check "the right hash puts core, vendor and certificates in place" $?
[ "$(cat "$W/tee/web/core/rfb.js")" = core ]; check "the right hash replaces the old file" $?
[ ! -e "$W/tee/web/core/stray.js" ] && [ ! -e "$W/tee/web/vendor/stray.js" ]; check "the right hash removes a stray file from the old install" $?
[ -z "$(ls -A "$W/tmp")" ]; check "the right hash leaves no temp folder behind" $?

# Where the script is found must not decide what it deletes. A symlink in another folder, or the text piped
# into bash, must leave that folder's own core/ and vendor/ alone.
OTHER="$W/other"; mkdir -p "$OTHER/core" "$OTHER/vendor"
plant_other() { rm -rf "$OTHER/core" "$OTHER/vendor"; mkdir -p "$OTHER/core" "$OTHER/vendor"; echo keep > "$OTHER/core/keep.js"; echo keep > "$OTHER/vendor/keep.js"; }
other_intact() { [ "$(cat "$OTHER/core/keep.js" 2>/dev/null)" = keep ] && [ "$(cat "$OTHER/vendor/keep.js" 2>/dev/null)" = keep ]; }
cp "$W/tee/web/novnc-sha256.txt" "$OTHER/"
ln -sf "$W/tee/web/get-novnc.sh" "$OTHER/get-novnc.sh"

plant_other; rm -rf "$W/tee/web/core" "$W/tee/web/vendor"; : > "$FAKE_CURL_LOG"
(cd "$OTHER" && TMPDIR="$W/tmp" PATH="$W/bin:$PATH" bash ./get-novnc.sh 9.9.9 >"$W/out" 2>&1); rc=$?
other_intact; check "a symlink to the script in another folder deletes nothing there" $?
[ "$rc" -eq 0 ] && [ -f "$W/tee/web/core/rfb.js" ]; check "a symlink is followed to the script's own folder, which gets the install" $?

plant_other; : > "$FAKE_CURL_LOG"
(cd "$OTHER" && TMPDIR="$W/tmp" PATH="$W/bin:$PATH" bash -s 9.9.9 < "$W/tee/web/get-novnc.sh" >"$W/out" 2>&1); rc=$?
[ "$rc" -ne 0 ] && grep -q "not started as a file" "$W/out"; check "bash -s < get-novnc.sh is refused with the reason" $?
other_intact; check "bash -s < get-novnc.sh deletes nothing in the folder it ran in" $?
[ ! -s "$FAKE_CURL_LOG" ]; check "bash -s < get-novnc.sh downloads nothing" $?

# A script copied to a folder with no table refuses, and deletes nothing there.
NOTABLE="$W/notable"; mkdir -p "$NOTABLE/core" "$NOTABLE/vendor"; echo keep > "$NOTABLE/core/keep.js"; echo keep > "$NOTABLE/vendor/keep.js"
cp "$W/tee/web/get-novnc.sh" "$NOTABLE/"
(cd "$NOTABLE" && PATH="$W/bin:$PATH" bash ./get-novnc.sh 9.9.9 >"$W/out" 2>&1); rc=$?
[ "$rc" -ne 0 ] && grep -q "no novnc-sha256.txt" "$W/out" && [ -f "$NOTABLE/core/keep.js" ] && [ -f "$NOTABLE/vendor/keep.js" ]; check "a folder with no table is refused and nothing is deleted there" $?

# The viewer folder itself with its table gone refuses and removes the old, unchecked install.
VIEWER="$W/viewer"; mkdir -p "$VIEWER/core" "$VIEWER/vendor"; echo old > "$VIEWER/core/rfb.js"; echo old > "$VIEWER/vendor/pako.js"
cp "$W/tee/web/get-novnc.sh" "$VIEWER/"; : > "$VIEWER/index.html"; : > "$VIEWER/link.js"
(cd "$VIEWER" && PATH="$W/bin:$PATH" bash ./get-novnc.sh 9.9.9 >"$W/out" 2>&1); rc=$?
[ "$rc" -ne 0 ] && grep -q "no novnc-sha256.txt" "$W/out" && [ ! -e "$VIEWER/core" ] && [ ! -e "$VIEWER/vendor" ]; check "the viewer folder with no table is refused and its old install removed" $?

# The production table pins the default version.
awk '$1 !~ /^#/ && $1 == "1.6.0" && $2 ~ /^[0-9a-f]{64}$/ { ok=1 } END { exit !ok }' "$SRC/novnc-sha256.txt"; check "the real table has a sha256 for the default version 1.6.0" $?
grep -q 'V="${1:-1.6.0}"' "$SRC/get-novnc.sh"; check "the default version is the pinned one" $?

# The script reads no environment variable at all: every variable it uses it sets itself. This catches an
# override of the hash or of the table path (${NOVNC_TABLE:-...}) alike. Documented environment: none. BASH_SOURCE
# is a shell builtin that holds the script's own path, not environment.
assigned="$(grep -v '^[[:space:]]*#' "$SRC/get-novnc.sh" | grep -oE '(^|[;[:space:]{(])[A-Za-z_][A-Za-z0-9_]*=' | tr -d ' \t=;{(' | sort -u)"
used="$(grep -v '^[[:space:]]*#' "$SRC/get-novnc.sh" | grep -oE '\$\{?[A-Za-z_][A-Za-z0-9_]*|awk -v [A-Za-z_]+|\$\{![A-Za-z_]+' | sed -E 's/^\$\{?//; s/^awk -v //' | sort -u)"
foreign="$(comm -13 <(printf '%s\nBASH_SOURCE\n' "$assigned" | sort -u) <(echo "$used"))"
[ -z "$foreign" ]; check "the script reads no environment variable (found: ${foreign:-none})" $?
! grep -qE '\$\{[A-Za-z_]+:[-=?+]' "$SRC/get-novnc.sh"; check "the script has no \${NAME:-default} form that an environment variable could override" $?

[ "$fail" -eq 0 ] && echo "all checks passed" || echo "$fail failure(s)"
exit "$fail"
