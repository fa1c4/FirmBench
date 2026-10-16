#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


PC_PATTERNS = [
    re.compile(r"\bPC:\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\b"),
    re.compile(r"\bpc=\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\b", re.IGNORECASE),
    # Greenhouse trace format: "Trace 0: 0x<host> [flags/pc/size]"
    re.compile(r"\bTrace\s+\d+:\s*0x[0-9a-fA-F]+\s*\[\s*[0-9a-fA-F]+/([0-9a-fA-F]+)/"),
]


def parse_address_token(token: str, prefer_hex: bool = False) -> Optional[int]:
    token = token.strip()
    if not token:
        return None
    try:
        if token.lower().startswith("0x"):
            return int(token, 16)
        if prefer_hex:
            return int(token, 16)
        if re.search(r"[a-fA-F]", token):
            return int(token, 16)
        return int(token, 10)
    except ValueError:
        return None


def parse_taint_pcs(log_path: str, tainted_only: bool = True) -> List[int]:
    addresses: List[int] = []
    seen = set()

    with open(log_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            if tainted_only and "TAINTED" not in line and "TAINTTAG" not in line:
                continue

            hit = None
            for pattern in PC_PATTERNS:
                matched = pattern.search(line)
                if matched:
                    hit = matched.group(1)
                    break

            if hit is None:
                continue

            addr = parse_address_token(hit, prefer_hex=True)
            if addr is None or addr in seen:
                continue

            seen.add(addr)
            addresses.append(addr)

    return addresses


def load_reachable_testcases(result_json_path: str, taint_tag: Optional[str] = None) -> List[Dict[str, Any]]:
    with open(result_json_path, "r", encoding="utf-8", errors="ignore") as file:
        data = json.load(file)

    if not isinstance(data, list):
        return []

    testcases: List[Dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        testcase = {
            "api_url": item.get("api_url"),
            "method": item.get("method"),
            "post_payload": item.get("post_payload"),
        }

        payload = testcase.get("post_payload")
        if taint_tag is not None:
            if not isinstance(payload, dict):
                continue
            if taint_tag not in [str(value) for value in payload.values()]:
                continue

        if testcase["api_url"] is None:
            continue

        testcases.append(testcase)

    return testcases


def to_hex_addresses(addresses: List[int]) -> List[str]:
    return [hex(addr) for addr in addresses]


def parse_taint_pcs_in_range(
    log_path: str,
    byte_start: int,
    byte_end: int,
    tainted_only: bool = True,
) -> Set[int]:
    """Parse PC addresses from a byte range [byte_start, byte_end) of the log file."""
    addresses: Set[int] = set()
    try:
        with open(log_path, "rb") as f:
            f.seek(byte_start)
            chunk = f.read(byte_end - byte_start)
    except (OSError, ValueError):
        return addresses

    try:
        text = chunk.decode("utf-8", errors="ignore")
    except Exception:
        text = chunk.decode("latin-1", errors="ignore")

    for line in text.splitlines():
        if tainted_only and "TAINTED" not in line and "TAINTTAG" not in line:
            continue
        for pattern in PC_PATTERNS:
            matched = pattern.search(line)
            if matched:
                addr = parse_address_token(matched.group(1), prefer_hex=True)
                if addr is not None:
                    addresses.add(addr)
                break
    return addresses


def load_trace_windows(windows_path: str) -> List[Dict[str, Any]]:
    """Load trace_windows.jsonl produced by taint_monitor.py."""
    windows: List[Dict[str, Any]] = []
    with open(windows_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                windows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return windows


def load_result_stream(stream_path: str) -> Dict[int, Dict[str, Any]]:
    """Load result_stream.ndjson into a dict keyed by request_id."""
    entries: Dict[int, Dict[str, Any]] = {}
    with open(stream_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid = obj.get("request_id")
            if rid is not None:
                entries[rid] = obj
    return entries


def build_exact_source_entries(
    qemu_log_path: str,
    windows: List[Dict[str, Any]],
    result_entries: Dict[int, Dict[str, Any]],
    tainted_only: bool = True,
) -> Dict[str, List[Dict[str, Any]]]:
    """Build source entries with exact join: addr → observing request(s).

    Only addresses observed within a request's byte window are included.
    Each entry gets:
      - reachable_testcase: the first observing request's testcase
      - observed_in_requests: list of all request_ids that observed this address
    """
    # addr → set of request_ids that observed it
    addr_to_requests: Dict[int, Set[int]] = {}
    addr_order: List[int] = []  # preserve discovery order

    for win in windows:
        rid = win.get("request_id")
        byte_start = win.get("byte_start")
        byte_end = win.get("byte_end")
        invalid = win.get("invalid", False)

        if invalid or byte_start is None or byte_end is None:
            continue
        if byte_start >= byte_end:
            continue

        addrs = parse_taint_pcs_in_range(qemu_log_path, byte_start, byte_end, tainted_only)
        for addr in addrs:
            if addr not in addr_to_requests:
                addr_to_requests[addr] = set()
                addr_order.append(addr)
            addr_to_requests[addr].add(rid)

    sources: List[Dict[str, Any]] = []
    for addr in addr_order:
        rids = addr_to_requests[addr]
        entry: Dict[str, Any] = {"address": hex(addr)}

        # reachable_testcase: first observing request's data
        first_rid = min(rids)
        first_req = result_entries.get(first_rid)
        if first_req:
            entry["reachable_testcase"] = {
                "api_url": first_req.get("api_url"),
                "method": first_req.get("method"),
                "post_payload": first_req.get("post_payload"),
            }

        # List of all observing request_ids
        entry["observed_in_requests"] = sorted(rids)
        sources.append(entry)

    return {"sources": sources}


def build_source_entries(
    addresses: List[int],
    testcases: Optional[List[Dict[str, Any]]] = None,
    testcase_strategy: str = "first",
) -> Dict[str, List[Dict[str, Any]]]:
    sources: List[Dict[str, Any]] = []
    testcases = testcases or []

    for idx, addr in enumerate(addresses):
        entry: Dict[str, Any] = {"address": hex(addr)}

        if testcases:
            if testcase_strategy == "first":
                entry["reachable_testcase"] = testcases[0]
            elif testcase_strategy == "round-robin":
                entry["reachable_testcase"] = testcases[idx % len(testcases)]

        sources.append(entry)

    return {"sources": sources}


def write_json(output_path: str, content: Any) -> None:
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(content, file, ensure_ascii=False, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert afl-qemu taint log into Source.json for LLMATaint.py",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--qemu-log", required=True, help="Path to qemu taint/debug log file")
    parser.add_argument(
        "--format",
        choices=["address-list", "sources"],
        default="sources",
        help="Output format: plain address list or {'sources': [...]} format",
    )
    parser.add_argument(
        "--result-json",
        default=None,
        help="Optional result.json from Fuzzer.py for attaching reachable testcase",
    )
    parser.add_argument(
        "--testcase-strategy",
        choices=["first", "round-robin"],
        default="first",
        help="How to attach testcase when --result-json is provided",
    )
    parser.add_argument(
        "--taint-tag",
        default=None,
        help="Optional taint tag filter for testcase payload values, e.g. TAINTTAG",
    )
    parser.add_argument(
        "--include-non-tainted-lines",
        action="store_true",
        help="Also parse lines without TAINTED/TAINTTAG markers",
    )
    parser.add_argument(
        "--windows",
        default=None,
        help="trace_windows.jsonl from taint_monitor.py — enables exact join mode",
    )
    parser.add_argument(
        "--result-stream",
        default=None,
        help="result_stream.ndjson from Fuzzer.py (default: <dir>/result_stream.ndjson)",
    )
    parser.add_argument("--output", default="Source.json", help="Output json path")
    args = parser.parse_args()

    # --- Exact join path: use taint_monitor-produced windows for precise attribution ---
    if args.windows:
        if not os.path.exists(args.windows):
            print(f"[!] Error: trace windows file not found: {args.windows}")
            sys.exit(1)

        stream_path = args.result_stream
        if not stream_path:
            stream_path = os.path.join(
                os.path.dirname(os.path.abspath(args.qemu_log)), "result_stream.ndjson"
            )

        if not os.path.exists(stream_path):
            print(f"[!] Error: result stream file not found: {stream_path}")
            print("    Provide --result-stream or ensure result_stream.ndjson exists")
            sys.exit(1)

        windows = load_trace_windows(args.windows)
        valid_windows = [w for w in windows if not w.get("invalid")]
        invalid_windows = [w for w in windows if w.get("invalid")]

        if not valid_windows:
            print(f"[!] Error: No valid trace windows found in {args.windows}")
            if invalid_windows:
                print(f"    ({len(invalid_windows)} invalid/corrupt windows skipped)")
            sys.exit(1)

        print(f"[*] Loaded {len(valid_windows)} valid trace windows ({len(invalid_windows)} invalid skipped)")

        result_entries = load_result_stream(stream_path)
        print(f"[*] Loaded {len(result_entries)} request entries from stream")

        tainted_only = not args.include_non_tainted_lines
        source_data = build_exact_source_entries(
            args.qemu_log, valid_windows, result_entries, tainted_only=tainted_only
        )

        write_json(args.output, source_data)
        num_sources = len(source_data.get("sources", []))
        print(f"[+] Parsed taint PCs (exact join): {num_sources}")
        print(f"[+] Wrote {args.output}")
        return

    # --- Legacy heuristic path ---
    addresses = parse_taint_pcs(args.qemu_log, tainted_only=not args.include_non_tainted_lines)

    if args.format == "address-list":
        output_obj: Any = to_hex_addresses(addresses)
    else:
        testcases = []
        if args.result_json:
            testcases = load_reachable_testcases(args.result_json, taint_tag=args.taint_tag)
        output_obj = build_source_entries(addresses, testcases, testcase_strategy=args.testcase_strategy)

    write_json(args.output, output_obj)
    print(f"[+] Parsed taint PCs: {len(addresses)}")
    print(f"[+] Wrote {args.output}")


if __name__ == "__main__":
    main()
