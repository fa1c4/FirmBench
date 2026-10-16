#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Convert the indirect-branch resolver plugin CSV into Indirect_call.json.

The QEMU plugin built from the firmware's instrumented QEMU fork
(``Fuzzing-SA/indirect_call``, ``libibresolver.so``) writes one line per taken
indirect branch:

    callsite offset,dest offset,callsite vaddr,dest vaddr,callsite ELF,dest ELF

``Taintanalysis.Augmented`` consumes a JSON structure of the form

    {"0x<caller_func>": {"0x<callsite>": ["0x<target>", ...]}}

so this script maps each callsite vaddr to its containing function (via
``sink_cfg.json`` when present, otherwise an angr CFG) and writes that JSON
next to the target binary as ``Indirect_call.json``.

Usage:
    python3 FuzzingRecord/indirect_csv_to_json.py \
        --csv output.csv --binary /path/to/httpd \
        [--sink-cfg /path/to/sink_cfg.json] [--output /path/to/Indirect_call.json]

``indirect_data.json`` is accepted as an alias by the taint pipeline, so the
output name can be changed freely.
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple


def _parse_int(token: str) -> Optional[int]:
    token = token.strip()
    if not token:
        return None
    try:
        return int(token, 16) if token.lower().startswith("0x") else int(token, 10)
    except ValueError:
        try:
            return int(token, 16)
        except ValueError:
            return None


def load_plugin_csv(csv_path: str, elf_filter: Optional[str] = None) -> List[Tuple[int, int]]:
    """Return unique (callsite_vaddr, dest_vaddr) pairs from the plugin CSV.

    Supports both the upstream column layout
        callsite offset,dest offset,callsite vaddr,dest vaddr,callsite ELF,dest ELF
    and the FirmAgent fork layout
        0x<callsite> -> 0x<dest>:  [ arg N is controllable.]
    """
    arrow_re = re.compile(r"(0x[0-9a-fA-F]+)\s*->\s*(0x[0-9a-fA-F]+)")
    pairs: List[Tuple[int, int]] = []
    seen = set()
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or line.lower().startswith("callsite"):
                continue
            if line.startswith("Indirect call"):
                continue
            match = arrow_re.search(line)
            if match:
                key = (int(match.group(1), 16), int(match.group(2), 16))
                if key not in seen:
                    seen.add(key)
                    pairs.append(key)
                continue
            cols = [c.strip() for c in line.split(",")]
            if len(cols) < 6:
                continue
            callsite = _parse_int(cols[2])
            target = _parse_int(cols[3])
            if callsite is None or target is None:
                continue
            if elf_filter and not os.path.basename(elf_filter) in (cols[4] + cols[5]):
                continue
            key = (callsite, target)
            if key in seen:
                continue
            seen.add(key)
            pairs.append(key)
    return pairs


def load_sink_cfg_ranges(path: Optional[str]):
    """Load [start, end) -> function_address from sink_cfg.json if available."""
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except Exception:
        return []
    ranges = []
    for node in cfg.get("nodes", []):
        try:
            start = int(node["address"])
            end = int(node.get("end_address", start + 1))
            func = int(node.get("function_address", 0))
        except (KeyError, TypeError, ValueError):
            continue
        ranges.append((start, end, func))
    ranges.sort()
    return ranges


def lookup_function_in_ranges(ranges, addr: int) -> Optional[int]:
    for start, end, func in ranges:
        if start <= addr < end:
            return func
    return None


def build_angr_function_map(binary: str):
    """Fallback: map any address to a function address with angr CFGFast."""
    try:
        import angr  # noqa: F401
    except Exception:
        return None, None
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
    except Exception as exc:
        print("[!] angr CFG failed: {}".format(exc), file=sys.stderr)
        return None, None

    def lookup(addr: int) -> Optional[int]:
        node = cfg.model.get_any_node(addr, anyaddr=True)
        if node is None:
            return None
        return node.function_address

    return lookup, proj.loader.main_object.mapped_base


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--csv", required=True, help="plugin output CSV (callsite,dest pairs)")
    ap.add_argument("--binary", required=True, help="target ELF the CSV was collected on")
    ap.add_argument("--sink-cfg", default=None,
                    help="sink_cfg.json for fast function lookup (default: next to binary)")
    ap.add_argument("--output", default=None,
                    help="output JSON (default: <binary_dir>/Indirect_call.json)")
    args = ap.parse_args()

    binary = os.path.abspath(args.binary)
    bin_dir = os.path.dirname(binary)
    sink_cfg = args.sink_cfg or os.path.join(bin_dir, "sink_cfg.json")
    output = args.output or os.path.join(bin_dir, "Indirect_call.json")

    pairs = load_plugin_csv(args.csv, elf_filter=binary)
    if not pairs:
        print("[!] no indirect branch pairs found in {}".format(args.csv))
        return 1

    ranges = load_sink_cfg_ranges(sink_cfg)
    angr_lookup = None
    mapped_base = 0
    if not ranges:
        print("[*] sink_cfg.json unavailable, falling back to angr CFG")
        angr_lookup, mapped_base = build_angr_function_map(binary)

    def find_func(addr: int) -> Optional[int]:
        func = lookup_function_in_ranges(ranges, addr) if ranges else None
        if func is None and angr_lookup is not None:
            func = angr_lookup(addr)
            if func is None and mapped_base:
                func = angr_lookup(addr - mapped_base)
        return func

    result: Dict[str, Dict[str, List[str]]] = {}
    skipped = 0
    for callsite, target in pairs:
        func = find_func(callsite)
        if func is None:
            skipped += 1
            continue
        func_key = hex(func)
        call_key = hex(callsite)
        tgt = hex(target)
        bucket = result.setdefault(func_key, {}).setdefault(call_key, [])
        if tgt not in bucket:
            bucket.append(tgt)

    if not result:
        print("[!] no callsites could be mapped to functions")
        return 1

    with open(output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    print("[+] indirect calls: {} callsites in {} functions ({} skipped) -> {}".format(
        sum(len(v) for v in result.values()), len(result), skipped, output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
