#!/usr/bin/env bash
# Install FirmAE (with the Greenhouse modifications) to Environ/FirmAE.
#
# FirmAE's own install.sh needs root (apt + loop mounts), so the supported
# path is to build the `greenhouse-lite` image (which installs and patches
# FirmAE) and extract /work/FirmAE from it. This is the exact tree that was
# validated for full-system emulation in the FirmAgent reproduction.
#
# Usage:
#   Install/install_firmae.sh            # build image if missing, then extract
#   Install/install_firmae.sh --local    # only clone+download kernels, no image
set -euo pipefail

HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO="$(cd -- "$HERE/.." && pwd)"
ENVIRON="${ENVIRON:-$REPO/Environ}"
DEST="$ENVIRON/FirmAE"
IMAGE="greenhouse-lite:local"
MODE="${1:-}"

if [ "$MODE" = "--local" ]; then
  mkdir -p "$DEST"
  [ -d "$DEST/.git" ] || git clone --recursive https://github.com/pr0v3rbs/FirmAE "$DEST"
  # Greenhouse replacements (orchestrator scripts)
  GH="${GREENHOUSE_SRC:-$ENVIRON/Greenhouse}"
  if [ -d "$GH/FirmAEreplacements" ]; then
    cp "$GH/FirmAEreplacements/install.sh" "$DEST/install.sh"
    cp "$GH/FirmAEreplacements/v2.3.3.tar.gz" "$DEST/v2.3.3.tar.gz"
    cp "$GH/FirmAEreplacements/makeNetwork.py" "$DEST/scripts/makeNetwork.py"
    cp "$GH/FirmAEreplacements/delete.sh" "$DEST/scripts/delete.sh"
    cp "$GH/FirmAEreplacements/inferFile.sh" "$DEST/scripts/inferFile.sh"
    cp "$GH/FirmAEreplacements/test_emulation.sh" "$DEST/scripts/test_emulation.sh"
    cp "$GH/FirmAEreplacements/umount.sh" "$DEST/scripts/umount.sh"
    cp "$GH/FirmAEreplacements/extractor.py" "$DEST/sources/extractor/extractor.py"
    cp "$GH/FirmAEreplacements/firmae.config" "$DEST/firmae.config"
    cp "$GH/FirmAEreplacements/run.sh" "$DEST/run.sh"
    cp "$GH/FirmAEreplacements/initializer.py" "$DEST/analyses/initializer.py"
  fi
  ( cd "$DEST" && ./download.sh )
  echo "[firmae] source tree at $DEST; run ./install.sh as root to complete"
  exit 0
fi

# --- image-based install -------------------------------------------------------
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  bash "$HERE/install_greenhouse_img.sh"
fi
CID="$(docker create "$IMAGE")"
rm -rf "$DEST"
docker cp "$CID:/work/FirmAE" "$DEST"
docker rm -f "$CID" >/dev/null

# --- apply FirmAgent reproduction patches --------------------------------------
# 1) loop partition device nodes: containers have no udev, so /dev/loopXp1
#    never appears and makeImage.sh waits forever. Create it from sysfs.
python3 - "$DEST/firmae.config" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = '''            if [ "${IMAGE_PATH}" = "${1}" ]; then
                DEV_PATH=/host/`echo ${LINE} | awk '{print $1}'`p1
                if [ -e ${DEV_PATH} ]; then
                    FOUND=true
                fi
            fi'''
new = '''            if [ "${IMAGE_PATH}" = "${1}" ]; then
                DEV_PATH=/host/`echo ${LINE} | awk '{print $1}'`p1
                if [ ! -e ${DEV_PATH} ]; then
                    LPART=$(basename `echo ${LINE} | awk '{print $1}'`)p1
                    if [ -e /sys/class/block/${LPART}/dev ]; then
                        DEVNUM=$(cat /sys/class/block/${LPART}/dev)
                        MAJ=${DEVNUM%:*}
                        MIN=${DEVNUM#*:}
                        mknod -m660 ${DEV_PATH} b ${MAJ} ${MIN} 2>/dev/null
                        chown root.disk ${DEV_PATH} 2>/dev/null
                    fi
                fi
                if [ -e ${DEV_PATH} ]; then
                    FOUND=true
                fi
            fi'''
if old in s:
    s = s.replace(old, new, 1)
    open(p, "w").write(s)
    print("[firmae] patched loop partition wait in firmae.config")
else:
    print("[firmae] firmae.config already patched or pattern changed")
PY
# 2) USER may be unset in non-interactive containers
sed -i 's/chown -R "${USER}"/chown -R "${USER:-root}"/; s/chgrp -R "${USER}"/chgrp -R "${USER:-root}"/' "$DEST/run.sh" || true

echo "[+] FirmAE installed to $DEST"
echo "    kernels/binaries: $DEST/binaries, binwalk: $DEST/binwalk-2.3.3"
