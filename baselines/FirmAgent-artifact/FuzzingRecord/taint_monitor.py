#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sidecar monitor: correlates Fuzzer.py requests with qemu taint log byte windows.

Usage (run alongside Fuzzer.py):
    python3 taint_monitor.py \
        --stream result_stream.ndjson \
        --qemu-log /scratch/qemu_trace.log \
        --out trace_windows.jsonl \
        --settle 0.5

Prerequisites:
    - Fuzzer.py must run with --tag-mode unique (or constant) and produce result_stream.ndjson
    - QEMU must log to --qemu-log via QEMU_LOG/QEMU_LOG_FILENAME
    - The log file must be accessible from the host (e.g. via shared volume / docker cp)

How it works:
    1. Tail the ndjson stream for new request entries
    2. On each new entry, record the current byte offset of the qemu log
    3. The window [prev_offset, current_offset) captures taint log entries
       generated between the previous request and this one
    4. Write {request_id, byte_start, byte_end, sent_at} to trace_windows.jsonl

Edge cases:
    - Log truncation/restart: detected via inode change or size < last_offset → mark window invalid
    - Settle delay: wait --settle seconds after seeing a request to let qemu flush
    - Half-line boundaries: byte_start/byte_end are raw offsets; downstream parser handles partial lines
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, Optional


def get_log_inode(path: str) -> Optional[int]:
    """Get inode number of a file, or None if not found."""
    try:
        return os.stat(path).st_ino
    except OSError:
        return None


def get_log_size(path: str) -> int:
    """Get current byte size of the log file."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def tail_ndjson(stream_path: str):
    """Generator: yield new JSON objects from an append-only ndjson file."""
    with open(stream_path, 'r', encoding='utf-8', errors='ignore') as f:
        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
            else:
                time.sleep(0.1)


def run_monitor(
    stream_path: str,
    qemu_log_path: str,
    out_path: str,
    settle: float = 0.5,
) -> None:
    """Main monitor loop: correlate requests with log byte windows."""
    # Wait for stream file to appear
    while not os.path.exists(stream_path):
        time.sleep(0.5)

    # Initialize log tracking
    last_log_inode = get_log_inode(qemu_log_path)
    last_log_offset = 0  # byte offset at the START of the current window

    # If log already exists, start from current end (skip historical data)
    if last_log_inode is not None:
        last_log_offset = get_log_size(qemu_log_path)

    # Open output file in append mode
    out_f = open(out_path, 'w', encoding='utf-8')

    request_count = 0
    print(f"[taint_monitor] Tailing {stream_path}, watching {qemu_log_path}", file=sys.stderr)
    print(f"[taint_monitor] Initial log offset: {last_log_offset}", file=sys.stderr)

    try:
        for entry in tail_ndjson(stream_path):
            request_id = entry.get('request_id')
            sent_at = entry.get('sent_at', '')
            if request_id is None:
                continue

            # Wait for qemu to flush log entries for this request
            time.sleep(settle)

            # Check for log truncation/restart
            current_inode = get_log_inode(qemu_log_path)
            current_size = get_log_size(qemu_log_path)

            if current_inode is None:
                # Log file disappeared → mark invalid
                window = {
                    'request_id': request_id,
                    'sent_at': sent_at,
                    'byte_start': None,
                    'byte_end': None,
                    'invalid': True,
                    'reason': 'log_file_missing',
                }
                out_f.write(json.dumps(window) + '\n')
                out_f.flush()
                request_count += 1
                last_log_offset = 0
                last_log_inode = None
                continue

            if current_inode != last_log_inode:
                # Log file was replaced (rotation/restart)
                window = {
                    'request_id': request_id,
                    'sent_at': sent_at,
                    'byte_start': 0,
                    'byte_end': current_size,
                    'invalid': True,
                    'reason': 'log_inode_changed',
                }
                out_f.write(json.dumps(window) + '\n')
                out_f.flush()
                request_count += 1
                last_log_offset = 0
                last_log_inode = current_inode
                continue

            if current_size < last_log_offset:
                # Log was truncated
                window = {
                    'request_id': request_id,
                    'sent_at': sent_at,
                    'byte_start': 0,
                    'byte_end': current_size,
                    'invalid': True,
                    'reason': 'log_truncated',
                }
                out_f.write(json.dumps(window) + '\n')
                out_f.flush()
                request_count += 1
                last_log_offset = 0
                continue

            # Normal case: window from last offset to current size
            window = {
                'request_id': request_id,
                'sent_at': sent_at,
                'byte_start': last_log_offset,
                'byte_end': current_size,
            }
            out_f.write(json.dumps(window) + '\n')
            out_f.flush()
            request_count += 1

            # Advance offset for next window
            last_log_offset = current_size

            if request_count % 10 == 0:
                print(f"[taint_monitor] Processed {request_count} requests", file=sys.stderr)

    except KeyboardInterrupt:
        print(f"\n[taint_monitor] Interrupted after {request_count} requests", file=sys.stderr)
    finally:
        out_f.close()
        print(f"[taint_monitor] Wrote {request_count} windows to {out_path}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sidecar: correlate Fuzzer.py requests with qemu taint log byte windows",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--stream", required=True, help="Path to result_stream.ndjson from Fuzzer.py")
    parser.add_argument("--qemu-log", required=True, help="Path to qemu taint log (QEMU_LOG_FILENAME)")
    parser.add_argument("--out", default="trace_windows.jsonl", help="Output trace windows file")
    parser.add_argument("--settle", type=float, default=0.5,
                        help="Seconds to wait after each request for qemu log flush")
    args = parser.parse_args()

    run_monitor(args.stream, args.qemu_log, args.out, settle=args.settle)


if __name__ == "__main__":
    main()
