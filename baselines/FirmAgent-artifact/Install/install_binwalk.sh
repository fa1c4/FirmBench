#!/usr/bin/env bash
# Install firmware-extraction tooling to Environ/Binwalk:
#   - sasquatch (patched squashfs 4.3, handles vendor squashfs/LZMA variants)
#   - binwalk v3 (Rust; needs recent toolchain for edition2024 crates)
#   - helpers: 7zz (p7zip), cpio, unsquashfs (squashfs-tools)
#
# No sudo required: missing apt packages are downloaded and unpacked locally.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO="$(cd -- "$HERE/.." && pwd)"
ENVIRON="${ENVIRON:-$REPO/Environ}"
DEST="$ENVIRON/Binwalk"
mkdir -p "$DEST/bin" "$DEST/src" "$DEST/tools"

have() { command -v "$1" >/dev/null 2>&1; }

# --- local sysroot for lzma/lzo headers (no sudo) ------------------------------
SYSROOT="$DEST/sysroot"; mkdir -p "$SYSROOT"
if [ ! -f "$SYSROOT/usr/include/lzma.h" ]; then
  TMP="$DEST/.debs"; mkdir -p "$TMP"; cd "$TMP"
  apt-get download liblzma-dev liblzo2-dev liblz4-dev zlib1g-dev 2>/dev/null || true
  for d in *.deb; do dpkg -x "$d" "$SYSROOT" 2>/dev/null || true; done
  cd - >/dev/null; rm -rf "$TMP"
fi

# --- sasquatch -----------------------------------------------------------------
SQ="$DEST/src/sasquatch"
if [ ! -x "$DEST/bin/sasquatch" ]; then
  [ -d "$SQ/.git" ] || git clone --depth 1 https://github.com/devttys0/sasquatch "$SQ"
  cd "$SQ"
  [ -f squashfs4.3.tar.gz ] || wget -q https://downloads.sourceforge.net/project/squashfs/squashfs/squashfs4.3/squashfs4.3.tar.gz
  tar xzf squashfs4.3.tar.gz
  cd squashfs4.3
  patch -p0 < ../patches/patch0.txt >/dev/null 2>&1 || true
  cd squashfs-tools
  make clean >/dev/null 2>&1 || true
  make -j"$(nproc)" \
    EXTRA_CFLAGS="-fcommon -I$SYSROOT/usr/include -Wno-error=misleading-indentation" \
    EXTRA_LDFLAGS="-L$SYSROOT/usr/lib/x86_64-linux-gnu"
  cp sasquatch "$DEST/bin/"
  cd - >/dev/null
fi

# --- rust toolchain + binwalk v3 ------------------------------------------------
if [ ! -x "$DEST/bin/binwalk" ]; then
  BW="$DEST/src/binwalk"
  [ -d "$BW/.git" ] || git clone --depth 1 https://github.com/ReFirmLabs/binwalk "$BW"
  RUSTUP_HOME="$DEST/.rustup" CARGO_HOME="$DEST/.cargo" \
    bash -c 'command -v rustup >/dev/null || curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable'
  ( cd "$BW" && RUSTUP_HOME="$DEST/.rustup" CARGO_HOME="$DEST/.cargo" \
      "$DEST/.cargo/bin/cargo" build --release --locked )
  cp "$BW/target/release/binwalk" "$DEST/bin/"
fi

# --- helpers -------------------------------------------------------------------
if [ ! -x "$DEST/tools/7zz" ]; then
  TMP="$DEST/.debs"; mkdir -p "$TMP"; cd "$TMP"
  apt-get download p7zip-full p7zip 2>/dev/null || true
  for d in *.deb; do dpkg -x "$d" "$DEST/tools" 2>/dev/null || true; done
  SEVENZ="$(find "$DEST/tools" -name 7z -type f | head -1)"
  [ -n "$SEVENZ" ] && ln -sf "$SEVENZ" "$DEST/tools/7zz"
  cd - >/dev/null; rm -rf "$TMP"
fi

cat > "$DEST/env.sh" <<EOF
export PATH="$DEST/bin:$DEST/tools/usr/bin:\$PATH"
# sasquatch/7zz are discovered by binwalk through PATH
EOF
chmod +x "$DEST/env.sh"
echo "[+] binwalk toolchain installed to $DEST"
