#!/usr/bin/env bash
# Install the Greenhouse rehosting framework to Environ/Greenhouse.
#   - clones sefcom/greenhouse (main code + FirmAEreplacements + gh3fuzz +
#     ghqemu5 submodules)
#   - applies the FirmAgent reproduction patch: docker networks without IPAM
#     config (host/none) crash QemuRunner.setup_bridges
#   - keeps gh3fuzz/ghqemu5 (submodules) for the fuzzing harness
set -euo pipefail

HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO="$(cd -- "$HERE/.." && pwd)"
ENVIRON="${ENVIRON:-$REPO/Environ}"
DEST="$ENVIRON/Greenhouse"

if [ ! -d "$DEST/.git" ]; then
  git clone --recursive https://github.com/sefcom/greenhouse.git "$DEST" || \
    git clone https://github.com/sefcom/greenhouse.git "$DEST"
  ( cd "$DEST" && git submodule update --init --recursive 2>/dev/null || true )
fi

# --- patch: tolerate docker networks whose IPAM.Config is None ------------------
python3 - "$DEST/Greenhouse/backend/QemuRunner.py" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "configs = dnet.attrs['IPAM']['Config']"
new = "configs = dnet.attrs['IPAM'].get('Config') or []"
if old in s:
    s = s.replace(old, new, 1)
    open(p, "w").write(s)
    print("[greenhouse] patched setup_bridges IPAM None handling")
else:
    print("[greenhouse] QemuRunner.py already patched or pattern changed")
PY

echo "[+] Greenhouse installed to $DEST"
echo "    build runtime image with: Install/install_greenhouse_img.sh"
