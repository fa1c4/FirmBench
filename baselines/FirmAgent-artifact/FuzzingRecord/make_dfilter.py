#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate a compact merged QEMU_DFILTER from any sink_scope_addr.txt.

QEMU_DFILTER is a comma-separated list of INCLUSIVE address ranges (see
Pre_Fuzzing/Get_SinkFunc.py: "QEMU dfilter ranges are inclusive on both ends").
Only basic blocks whose address falls inside a range emit a trace line, so a
broad range covering the whole text segment makes the trace log grow in
proportion to wall-clock execution (even while idle).

Legacy sink_scope_addr.txt files contain per-sink pairs
(0x<sink_func>..0x<reachable_end>) - hundreds of overlapping entries, some
inverted (start > end). This script normalizes inverted pairs, merges
overlapping/adjacent ranges, and prints ONE comma-separated string - the same
merge the current Get_SinkFunc.py performs, but host-side without IDA.

Keep the total under ~4 KB or QEMU may refuse to start (see start_rehost.sh).

Usage:
  python3 FuzzingRecord/make_dfilter.py <sink_scope_addr.txt>            # print
  python3 FuzzingRecord/make_dfilter.py <file> --out dfilter.txt         # also write
  python3 FuzzingRecord/make_dfilter.py <file> --max-chars 4096          # warn

Feed the result straight into the rehost launcher:
  ./FuzzingRecord/start_rehost.sh --container <name> \
      --dfilter "$(python3 FuzzingRecord/make_dfilter.py sink_scope_addr.txt)"
"""
import argparse
import re
import sys

_RANGE_RE = re.compile(r"0x([0-9a-fA-F]+)\s*\.\.\s*0x([0-9a-fA-F]+)")


def parse_ranges(path):
    """Extract (start, end) pairs from a file, normalizing inverted ones."""
    pairs = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            for m in _RANGE_RE.finditer(line):
                lo, hi = int(m.group(1), 16), int(m.group(2), 16)
                if lo > hi:
                    lo, hi = hi, lo  # legacy per-sink pair written inverted
                pairs.append((lo, hi))
    return pairs


def merge_ranges(pairs):
    """Sort and merge overlapping or adjacent intervals."""
    if not pairs:
        return []
    ordered = sorted(pairs)
    merged = [list(ordered[0])]
    for lo, hi in ordered[1:]:
        if lo <= merged[-1][1] + 1:  # overlap or adjacent
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, hi) for lo, hi in merged]


def to_dfilter(merged):
    return ",".join("0x{:X}..0x{:X}".format(lo, hi) for lo, hi in merged)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file", help="sink_scope_addr.txt (or any file with 0x..0x ranges)")
    ap.add_argument("--out", help="also write the dfilter string to this file")
    ap.add_argument("--max-chars", type=int, default=4096,
                    help="warn if the string exceeds this length (default 4096)")
    args = ap.parse_args()

    pairs = parse_ranges(args.file)
    merged = merge_ranges(pairs)
    dfilter = to_dfilter(merged)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(dfilter + "\n")

    print(dfilter)
    sys.stderr.write(
        "[+] {} raw ranges -> merged to {} ranges, {} chars\n".format(
            len(pairs), len(merged), len(dfilter)))
    if args.max_chars and len(dfilter) > args.max_chars:
        sys.stderr.write(
            "[!] dfilter > {} chars; QEMU may refuse to start. "
            "Narrow the sink scope.\n".format(args.max_chars))
    return 0


if __name__ == "__main__":
    sys.exit(main())