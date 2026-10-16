#!/usr/bin/env bash
# FirmAgent reproduction toolchain overview.
#
# Everything installs under FirmAgent/Environ/<tool>/ (git-ignored).
#
#   install_all.sh          run every installer below (idempotent)
#   install_qemu.sh         instrumented QEMU (Fuzzing-SA): dynamic + static,
#                           TCG indirect-call plugin, Greenhouse ghqemu5 set,
#                           host qemu-system (mips/mipsel/arm/aarch64)
#   install_binwalk.sh      binwalk v3 + sasquatch + squashfs-tools + 7zz
#   install_firmae.sh       FirmAE (kernels, binwalk 2.3.3, patched scripts)
#                           extracted from the greenhouse-lite image
#   install_greenhouse.sh   sefcom/greenhouse + patches + gh3fuzz
#   install_python_env.sh   Python venv with pinned deps (angr 9.2.1, ...)
#   install_greenhouse_img.sh  build the `greenhouse-lite` docker image used
#                           by install_firmae.sh and by the rehost batch
#   accept_ida_eula.sh      headless IDA Pro EULA acceptance (Xvfb + xdotool)
#
# Manual prerequisites (cannot be scripted / licensed):
#   - IDA Pro 9.3 + Hex-Rays decompilers at /home/zym/IDAPro
#   - Docker (user in the docker group), nvidia-free host is fine
#   - DeepSeek (or OpenAI-compatible) API key for LLMATaint.py
#
# Toolchain required by the full FirmAgent pipeline:
#   firmware  : binwalk v3, sasquatch, squashfs-tools, unrar, 7zz
#   pre-fuzz  : IDA Pro 9.3 (+idat), Hex-Rays MIPS/ARM, networkx, IDA scripts
#               (Src/decompile? see Pre_Fuzzing/), Distance.py
#   rehost    : Greenhouse, FirmAE + kernels, Docker, PostgreSQL, radare2,
#               Chrome/chromedriver (GH HTTP checker), ghqemu5 QEMUs
#   fuzz/trace: instrumented QEMU (taint + dfilter + plugins), tshark-free
#               trace parsing in FuzzingRecord/
#   analysis  : angr 9.2.1, networkx 2.8.4, DeepSeek API client
#
# Usage:
#   Install/install_all.sh            # after `source Install/README` review
#   ENVIRON=/custom/path Install/install_qemu.sh
set -euo pipefail

HERE="$(cd -- "$(dirname -- "$0")" && pwd)"

bash "$HERE/install_binwalk.sh"
bash "$HERE/install_greenhouse.sh"
bash "$HERE/install_qemu.sh"
bash "$HERE/install_firmae.sh"
bash "$HERE/install_python_env.sh"

echo "[+] all toolchains installed under ${ENVIRON:-$HERE/../Environ}"
