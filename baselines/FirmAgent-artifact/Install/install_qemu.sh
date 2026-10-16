#!/usr/bin/env bash
# Install the QEMU toolchain used by FirmAgent to Environ/Qemu:
#   - instrumented Fuzzing-SA user-mode QEMU (taint TAINTTAG logging + dfilter
#     + Greenhouse hacks: -hackbind/-hackproc/-hacksysinfo/-hookhack), dynamic
#     build with TCG plugin support and static build without
#   - indirect-call resolver plugin (libibresolver.so, MIPS/ARM/x86-64)
#   - Greenhouse ghqemu5 prebuilt user-mode QEMUs (68 builds + intervention set)
#   - host qemu-system 6.2 (mips/mipsel/mips64/arm/aarch64) from apt debs
#
# Tested on Ubuntu 22.04 without sudo (uses apt-get download + dpkg -x).
set -euo pipefail

HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO="$(cd -- "$HERE/.." && pwd)"
ENVIRON="${ENVIRON:-$REPO/Environ}"
DEST="$ENVIRON/Qemu"
SRC="$DEST/src/Fuzzing-SA"
BUILD_ROOT="$DEST/build"
TARGETS="mips-linux-user,mipsel-linux-user,arm-linux-user,aarch64-linux-user"
mkdir -p "$DEST/bin" "$DEST/plugins" "$DEST/greenhouse" "$DEST/src"

have() { command -v "$1" >/dev/null 2>&1; }

# --- 1) source -----------------------------------------------------------------
if [ ! -d "$SRC/.git" ]; then
  git clone --depth 1 https://github.com/AxiaoJJ/Fuzzing-SA.git "$SRC"
fi

# --- 2) builds -----------------------------------------------------------------
build_variant() {
  local variant="$1" extra="$2" prefix="$DEST/$1"
  if ls "$prefix/bin"/qemu-* >/dev/null 2>&1; then
    echo "[qemu] $variant already built"; return 0
  fi
  local build="$BUILD_ROOT/$variant"
  mkdir -p "$build"; cd "$build"
  "$SRC/configure" --target-list="$TARGETS" --disable-system --disable-docs \
    --disable-werror --disable-gtk --disable-sdl --disable-vnc \
    $extra --prefix="$prefix"
  make -j"$(nproc)"
  make install
  cd - >/dev/null
}
build_variant dynamic "--enable-plugins"
build_variant static  "--static"

for b in "$DEST/dynamic/bin/"qemu-*; do
  [ -e "$b" ] || continue
  ln -sf "$b" "$DEST/bin/$(basename "$b")"
done
for b in "$DEST/static/bin/"qemu-*; do
  [ -e "$b" ] || continue
  ln -sf "$b" "$DEST/bin/$(basename "$b")-static"
done

# --- 3) indirect-call plugin (with MIPS jalr support) ---------------------------
PLUGIN_SRC="$SRC/indirect_call"
if [ -d "$PLUGIN_SRC" ]; then
  if ! grep -q "is_mips_jalr" "$PLUGIN_SRC/src/simple_backend.cpp" 2>/dev/null; then
    echo "[qemu] WARNING: Fuzzing-SA plugin lacks MIPS support; see Install/patches/"
  fi
  ( cd "$PLUGIN_SRC" && make clean >/dev/null 2>&1 || true; make BACKEND=simple CXX=clang++ ) || \
    echo "[qemu] plugin build skipped (clang++ missing?)"
  [ -f "$PLUGIN_SRC/libibresolver.so" ] && cp "$PLUGIN_SRC/libibresolver.so" "$DEST/plugins/"
  [ -f "$PLUGIN_SRC/libnvram-faker.so" ] && cp "$PLUGIN_SRC/libnvram-faker.so" "$DEST/plugins/" || true
fi

# --- 4) Greenhouse ghqemu5 prebuilts -------------------------------------------
GH_SRC="${GREENHOUSE_SRC:-$ENVIRON/Greenhouse}"
if [ -d "$GH_SRC/Greenhouse/qemu" ]; then
  cp -a "$GH_SRC/Greenhouse/qemu" "$DEST/greenhouse/qemu"
  mkdir -p "$DEST/greenhouse/external_qemu"
  cp -a "$GH_SRC/Greenhouse/greenhouse_files/external_qemu/." "$DEST/greenhouse/external_qemu/" 2>/dev/null || true
else
  echo "[qemu] NOTE: clone sefcom/greenhouse first (install_greenhouse.sh) for ghqemu5 prebuilts"
fi

# --- 5) host qemu-system (apt debs extracted, no sudo) -------------------------
if [ ! -x "$DEST/system/usr/bin/qemu-system-mips" ]; then
  TMP="$DEST/.debs"; mkdir -p "$TMP"; cd "$TMP"
  apt-get download qemu-system-mips qemu-system-arm qemu-system-common qemu-system-data \
      libslirp0 libfdt1 liburing2 libpmem1 libzstd1 2>/dev/null || true
  for d in *.deb; do dpkg -x "$d" "$DEST/system" 2>/dev/null || true; done
  cd - >/dev/null; rm -rf "$TMP"
  for b in "$DEST/system/usr/bin/qemu-system-"*; do
    [ -e "$b" ] || continue
    n="$(basename "$b")"
    cat > "$DEST/bin/$n" <<EOF
#!/bin/bash
export LD_LIBRARY_PATH=$DEST/system/usr/lib/x86_64-linux-gnu:\$LD_LIBRARY_PATH
exec "$b" "\$@"
EOF
    chmod +x "$DEST/bin/$n"
  done
fi

echo "[+] QEMU installed to $DEST"
echo "    source $DEST/../Qemu/env.sh   # PATH helper if present"
