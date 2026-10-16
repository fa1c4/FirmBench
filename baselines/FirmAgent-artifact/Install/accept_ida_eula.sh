#!/usr/bin/env bash
# Headless acceptance of the IDA Pro EULA so that `idat -A` works in batch
# mode (IDA refuses batch mode until the EULA has been accepted via the GUI).
#
# Strategy (no root, no display):
#   1) unpack Xvfb/xdotool and their deps into a local prefix via apt-get download
#   2) the X server hardcodes /usr/bin/xkbcomp; interpose system()/execve() with
#      a tiny LD_PRELOAD shim that redirects it to the locally unpacked xkbcomp
#   3) start Xvfb :99, launch IDA GUI on a dummy file, click "I Agree"
#   4) verify ~/.idapro/ida.reg now contains the EULA record
#
# This was used successfully on Ubuntu 22.04 with IDA Pro 9.3. Coordinates for
# the dialog assume the default 1600x1200 Xvfb screen; adjust if needed.
set -euo pipefail

IDA_DIR="${IDA_DIR:-/home/zym/IDAPro}"
PREFIX="${PREFIX:-$HOME/.ida-eula-helpers}"
mkdir -p "$PREFIX/debs" "$PREFIX/root" "$PREFIX/tools"

cd "$PREFIX/debs"
apt-get download xvfb xserver-common x11-xkb-utils libxfont2 libxkbfile1 \
  xdotool libxdo3 libxcb-cursor0 libxcb-image0 libxcb-render-util0 libxcb-util1 \
  >/dev/null 2>&1 || true
for d in *.deb; do dpkg -x "$d" "$PREFIX/root" 2>/dev/null || true; done

export LD_LIBRARY_PATH="$PREFIX/root/usr/lib/x86_64-linux-gnu:$PREFIX/root/usr/lib/x86_64-linux-gnu"
XKB="$PREFIX/root/usr/bin/xkbcomp"
if [ ! -x "$XKB" ]; then echo "[-] xkbcomp not unpacked"; exit 1; fi

# --- LD_PRELOAD shim: redirect /usr/bin/xkbcomp --------------------------------
cat > "$PREFIX/tools/xkbshim.c" <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#define BAD  "/usr/bin/xkbcomp"
#define GOOD "/REPLACED/xkbcomp"
static char *fix(const char *s) {
    if (!s) return NULL;
    const char *p = strstr(s, BAD);
    if (!p) return (char *)s;
    char *b = malloc(strlen(s) + 256); if (!b) return (char *)s;
    size_t pre = (size_t)(p - s);
    memcpy(b, s, pre); sprintf(b + pre, "%s%s", GOOD, p + strlen(BAD));
    return b;
}
static int (*r_system)(const char *);
static int (*r_execve)(const char *, char *const[], char *const[]);
static int (*r_execv)(const char *, char *const[]);
int system(const char *c) { if (!r_system) r_system = dlsym(RTLD_NEXT, "system"); return r_system(fix(c)); }
int execve(const char *p, char *const a[], char *const e[]) { if (!r_execve) r_execve = dlsym(RTLD_NEXT, "execve"); return r_execve(fix(p), a, e); }
int execv(const char *p, char *const a[]) { if (!r_execv) r_execv = dlsym(RTLD_NEXT, "execv"); return r_execv(fix(p), a); }
EOF
sed -i "s|/REPLACED/xkbcomp|$XKB|" "$PREFIX/tools/xkbshim.c"
gcc -shared -fPIC -o "$PREFIX/tools/xkbshim.so" "$PREFIX/tools/xkbshim.c" -ldl

# --- start Xvfb with the shim ---------------------------------------------------
pkill -f "Xvfb :99" 2>/dev/null || true; rm -f /tmp/.X99-lock
LD_PRELOAD="$PREFIX/tools/xkbshim.so" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
  nohup "$PREFIX/root/usr/bin/Xvfb" :99 -screen 0 1600x1200x24 -nolisten tcp \
  >"$PREFIX/xvfb.log" 2>&1 &
sleep 3

# --- launch IDA GUI on a dummy binary and accept -------------------------------
DUMMY="$PREFIX/dummy"; cp /bin/ls "$DUMMY" 2>/dev/null || true
DISPLAY=:99 LD_LIBRARY_PATH="$PREFIX/root/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu" \
  "$IDA_DIR/ida" "$DUMMY" >"$PREFIX/ida_gui.log" 2>&1 &
sleep 25
DISPLAY=:99 LD_LIBRARY_PATH="$PREFIX/root/usr/lib/x86_64-linux-gnu" \
  "$PREFIX/root/usr/bin/xdotool" mousemove 737 824 click 1 || true
sleep 8
pkill -x ida 2>/dev/null || true

if strings "$HOME/.idapro/ida.reg" 2>/dev/null | grep -q "EULA"; then
  echo "[+] IDA EULA accepted; batch mode (idat -A) should work now"
else
  echo "[!] EULA record not found - open $IDA_DIR/ida manually and accept"
fi
