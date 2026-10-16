#!/usr/bin/env bash
# Build the `greenhouse-lite:local` docker image: Ubuntu 20.04 + FirmAE
# (patched) + Greenhouse + Python venv (angr/keystone/r2pipe/pwntools/...) +
# Chrome 104/chromedriver + ghqemu5 assets.
#
# The image is used by:
#   - Install/install_firmae.sh          (extracts /work/FirmAE)
#   - the rehost batch (gh.py in a privileged container with docker.sock)
set -euo pipefail

HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO="$(cd -- "$HERE/.." && pwd)"
ENVIRON="${ENVIRON:-$REPO/Environ}"
GH="${GREENHOUSE_SRC:-$ENVIRON/Greenhouse}"

if [ ! -d "$GH/Greenhouse" ]; then
  echo "[-] Greenhouse source not found at $GH (run Install/install_greenhouse.sh)"; exit 1
fi
if [ ! -f "$GH/FirmAEreplacements/v2.3.3.tar.gz" ] || [ ! -f "$GH/chrome104.deb" ]; then
  echo "[!] Some image build inputs are missing from the greenhouse clone:"
  echo "    FirmAEreplacements/v2.3.3.tar.gz and chrome104.deb are expected."
  echo "    They are part of github.com/sefcom/greenhouse."
fi

# Build with USTC mirror + no proxy, host network (Docker config may inject
# a container-local 127.0.0.1 proxy that cannot work inside the build).
docker build --network host \
  --build-arg http_proxy= --build-arg https_proxy= \
  --build-arg HTTP_PROXY= --build-arg HTTPS_PROXY= \
  -f "$HERE/Dockerfile.greenhouse-lite" \
  -t greenhouse-lite:local "$GH"

echo "[+] built greenhouse-lite:local"
