#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

for _logger_name in (
    "angr.state_plugins.unicorn_engine",
    "angr.analyses.analysis",
    "angr.analyses.decompiler.clinic",
    "angr.analyses.decompiler.callsite_maker",
    "angr_platforms.X86_16.lift_86_16",
):
    logging.getLogger(_logger_name).setLevel(logging.CRITICAL)

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from angr_platforms.X86_16.corpus_scan import (
    FunctionScanResult,
    ScanTimeout,
    classify_failure,
    extract_cod_functions,
    scan_function,
    set_memory_limit,
    summarize_results,
)


def _timeout_result(cod_file: Path, proc_name: str, proc_kind: str, code: bytes, reason: str) -> FunctionScanResult:
    result = FunctionScanResult(
        cod_file=cod_file.name,
        proc_name=proc_name,
        proc_kind=proc_kind,
        byte_len=len(code),
        has_near_call_reloc=b"\xe8\x00\x00" in code,
        has_far_call_reloc=b"\x9a\x00\x00\x00\x00" in code,
        failure_class="timeout",
        reason=reason,
        fallback_kind="block_lift",
    )
    result.stage_reached = "decompile"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded staged corpus scan for .COD functions.")
    parser.add_argument("cod_dir", type=Path, help="Directory containing .COD files")
    parser.add_argument("--timeout-sec", type=int, default=5, help="Per-function timeout in seconds")
    parser.add_argument("--max-memory-mb", type=int, default=1024, help="Address-space cap for this process")
    parser.add_argument(
        "--max-decompile-bytes",
        type=int,
        default=384,
        help="In scan-safe mode, skip full decompilation for larger functions and stop at cfg/cleanup (0 = disable).",
    )
    parser.add_argument("--limit", type=int, default=0, help="Only scan the first N functions (0 = all)")
    parser.add_argument(
        "--stop-after-failures",
        type=int,
        default=0,
        help="Stop scanning after collecting this many failures (0 = scan all).",
    )
    parser.add_argument(
        "--mode",
        choices=("lift", "decompile-reloc-free", "scan-safe"),
        default="scan-safe",
        help="Either just lift, decompile reloc-free blobs, or run the full staged scan-safe lane.",
    )
    args = parser.parse_args()

    set_memory_limit(args.max_memory_mb)

    cod_files = sorted(args.cod_dir.rglob("*.COD"))
    results = []
    failures_seen = 0

    for cod_file in cod_files:
        for proc_name, proc_kind, code in extract_cod_functions(cod_file):
            try:
                result = scan_function(
                    cod_file,
                    proc_name,
                    proc_kind,
                    code,
                    args.timeout_sec,
                    args.mode,
                    max_decompile_bytes=args.max_decompile_bytes,
                )
            except ScanTimeout as exc:
                failure_class, reason = classify_failure("decompile", exc)
                result = _timeout_result(cod_file, proc_name, proc_kind, code, reason)
                result.failure_class = failure_class
            results.append(result)
            if not result.ok:
                failures_seen += 1
            if args.limit and len(results) >= args.limit:
                break
            if args.stop_after_failures and failures_seen >= args.stop_after_failures:
                break
        if args.limit and len(results) >= args.limit:
            break
        if args.stop_after_failures and failures_seen >= args.stop_after_failures:
            break

    summary = summarize_results(results, args.mode)
    print(json.dumps(summary, indent=2))
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
