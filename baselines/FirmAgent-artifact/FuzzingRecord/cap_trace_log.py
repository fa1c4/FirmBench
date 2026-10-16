#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bound the size of a shared QEMU trace log.

The instrumented QEMU appends a trace line for every basic block it executes
inside QEMU_DFILTER. With a broad DFILTER and a service left running 24/7 the
log grows without bound (observed: ~20 GB/hour, one 878 GB file). This helper
caps the active log by truncating it in place when it exceeds --max-bytes.

Safety: run this only after the traced service has stopped. Truncating a live
log invalidates the fuzzer's byte windows and Source.json offsets. The
launchers can apply an optional file-size limit to the QEMU writer instead.

Truncate-in-place only keeps the writer small if it opened the log with
O_APPEND (writes land at end-of-file at write time). If the logger instead
writes at a previously computed offset, a live truncate can leave a sparse
file; in that case stop the writer, truncate, restart.

Usage:
  python3 FuzzingRecord/cap_trace_log.py <log> --max-bytes 536870912   # 512 MiB
  python3 FuzzingRecord/cap_trace_log.py <log> --action rotate          # keep last snapshot
  python3 FuzzingRecord/cap_trace_log.py <log> --reset                  # new session start
"""
import argparse
import os
import shutil
import time


def _human(n):
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return "{:.1f}{}".format(n, unit)
        n /= 1024.0
    return "{:.1f}P".format(n)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("log", help="path to the shared QEMU trace log")
    ap.add_argument("--max-bytes", type=int, default=512 * 1024 * 1024,
                    help="size cap in bytes (default 512 MiB)")
    ap.add_argument("--action", choices=("truncate", "rotate"), default="truncate",
                    help="truncate in place, or copy to a timestamped snapshot first")
    ap.add_argument("--reset", action="store_true",
                    help="zero the log regardless of size (start of a new session)")
    args = ap.parse_args()

    if not os.path.exists(args.log):
        print("[+] {}: does not exist, nothing to do".format(args.log))
        return 0

    size = os.path.getsize(args.log)
    print("[+] {}: {} bytes".format(args.log, _human(size)))
    if not (args.reset or size > args.max_bytes):
        print("[+] under cap ({}); left untouched".format(_human(args.max_bytes)))
        return 0

    if args.action == "rotate":
        snapshot = "{}.{}".format(args.log, time.strftime("%Y%m%d-%H%M%S"))
        with open(args.log, "rb") as src, open(snapshot, "wb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
        print("[+] snapshot -> {}".format(snapshot))
    with open(args.log, "r+b") as fh:
        fh.truncate(0)
    print("[+] truncated {} -> 0 bytes".format(args.log))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
