#!/bin/bash
# Regenerate the Dockerfile's embedded scripts and pack the build context.
# Usage: ./build-context.sh OUT.tgz   (the sealed-pool builder takes FROM and RUN only)
set -euo pipefail
cd "$(dirname "$0")"
out="${1:?usage: build-context.sh OUT.tgz}"
python3 - <<'PY'
import base64,re
b=lambda p: base64.b64encode(open(p,"rb").read()).decode()
names=["desktop-up","shot","browser"]
install=" && ".join(f"echo {b('desktop/'+n)} | base64 -d > /usr/local/bin/{n}" for n in names)
s=open("Dockerfile").read()
s=re.sub(r"^RUN echo .*?chmod 755 [^\n]*$", f"RUN {install} && chmod 755 " + " ".join("/usr/local/bin/"+n for n in names), s, flags=re.S|re.M)
open("Dockerfile","w").write(s)
PY
tar czf "$out" Dockerfile desktop
echo "context: $out"
