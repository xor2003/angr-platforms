#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from angr_platforms.X86_16.corpus_scan import extract_cod_functions, scan_function, set_memory_limit, summarize_results


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded staged corpus scan for .COD functions.")
    parser.add_argument("cod_dir", type=Path, help="Directory containing .COD files")
    parser.add_argument("--timeout-sec", type=int, default=5, help="Per-function timeout in seconds")
    parser.add_argument("--max-memory-mb", type=int, default=1024, help="Address-space cap for this process")
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
            result = scan_function(cod_file, proc_name, proc_kind, code, args.timeout_sec, args.mode)
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
