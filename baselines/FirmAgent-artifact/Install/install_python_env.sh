#!/usr/bin/env bash
# Python environment for the FirmAgent LLM/angr pipeline -> Environ/Python.
# Pins are the combination verified with angr 9.2.1 on Python 3.10:
#   protobuf 3.20.3  (angr protobuf stubs are pre-3.19 generated code)
#   capstone 5.0.1   (6.x alpha removed CS_ARCH_ARM64 used by archinfo)
#   pycparser 2.21   (3.x removed the bundled ply used by angr's type parser)
set -euo pipefail

HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO="$(cd -- "$HERE/.." && pwd)"
ENVIRON="${ENVIRON:-$REPO/Environ}"
DEST="$ENVIRON/Python"

PY=python3.10
command -v "$PY" >/dev/null 2>&1 || PY=python3
"$PY" -m venv "$DEST"
"$DEST/bin/pip" install --upgrade pip >/dev/null
"$DEST/bin/pip" install \
  protobuf==3.20.3 capstone==5.0.1 pycparser==2.21 \
  angr==9.2.1 networkx==2.8.4 \
  r2pipe docker nclib requests python-nmap lxml ifaddr \
  pwntools==4.9.0 pyelftools==0.29 keystone-engine \
  coloredlogs python-magic

cat > "$DEST/env.sh" <<EOF
export FIRMAGENT_PYTHON="$DEST/bin/python"
export PATH="$DEST/bin:\$PATH"
EOF
chmod +x "$DEST/env.sh"

"$DEST/bin/python" -c "import angr, networkx, docker, keystone; print('[+] python env OK', angr.__version__)"
echo "[+] Python env installed to $DEST"
