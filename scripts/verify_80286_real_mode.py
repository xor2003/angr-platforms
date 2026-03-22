#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from angr_platforms.X86_16.verification_80286 import (
    DEFAULT_REVOCATION_LIST,
    DEFAULT_SUITE_DIR,
    discover_moo_files,
    load_revocation_hashes,
    summarize_results,
    summary_to_json,
    verify_moo_file,
)


def _default_jobs() -> int:
    cpu_count = os.cpu_count() or 1
    return max(1, cpu_count - 1)


def _verify_one_file(task: tuple[Path, int | None, bool, frozenset[str]]) -> dict:
    path, limit, execute_halt, revoked_hashes = task
    return verify_moo_file(path, limit=limit, execute_halt=execute_halt, revoked_hashes=set(revoked_hashes))


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify x86-16 real-mode execution against 80286 hardware dumps.")
    parser.add_argument(
        "suite",
        nargs="?",
        type=Path,
        default=DEFAULT_SUITE_DIR,
        help="A .MOO/.MOO.gz file or a directory containing them.",
    )
    parser.add_argument("--opcode", action="append", default=[], help="Restrict to one or more opcode filenames, e.g. 00 or 60.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of cases to verify per opcode file.")
    parser.add_argument(
        "--revocation-list",
        type=Path,
        default=DEFAULT_REVOCATION_LIST,
        help="Optional revocation-list file.",
    )
    parser.add_argument("--ignore-revoked", action="store_true", help="Do not skip revoked case hashes.")
    parser.add_argument(
        "--jobs",
        type=int,
        default=_default_jobs(),
        help="Worker processes to use across opcode files. Defaults to max(1, cpu_count - 1).",
    )
    parser.add_argument("--json-output", type=Path, default=None, help="Optional JSON summary output path.")
    args = parser.parse_args()
    if args.jobs < 1:
        raise SystemExit("--jobs must be at least 1")

    revoked = set() if args.ignore_revoked else load_revocation_hashes(args.revocation_list)
    files = discover_moo_files(args.suite, args.opcode)
    if not files:
        raise SystemExit("No matching .MOO files found.")

    tasks = [(path, args.limit, True, frozenset(revoked)) for path in files]
    worker_count = min(args.jobs, len(tasks))

    summaries = []
    if worker_count == 1:
        summaries = [
            verify_moo_file(path, limit=args.limit, execute_halt=True, revoked_hashes=revoked)
            for path in files
        ]
    else:
        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            summaries = list(executor.map(_verify_one_file, tasks))

    for summary in summaries:
        print(
            f"{summary['opcode']:>6}  passed={summary['passed']:>4}  failed={summary['failed']:>4}  "
            f"skipped={summary['skipped']:>4}  total={summary['total']:>4}  {summary['sample_name']}"
        )
        for result in summary["results"]:
            if result["passed"] or result["skipped"]:
                continue
            if result["error"]:
                print(f"         case {result['idx']:>4}: error: {result['error']}")
            elif result["mismatches"]:
                first = result["mismatches"][0]
                where = f" @ {first['address']:#x}" if first["address"] is not None else ""
                print(
                    f"         case {result['idx']:>4}: {first['kind']} {first['name']}{where}: "
                    f"expected {first['expected']:#x}, got {first['actual']:#x}"
                )

    suite_summary = summarize_results(summaries)
    print(
        f"\nTotal files={suite_summary['total_files']}  cases={suite_summary['total_cases']}  "
        f"passed={suite_summary['passed_cases']}  failed={suite_summary['failed_cases']}  "
        f"skipped={suite_summary['skipped_cases']}"
    )

    if args.json_output is not None:
        args.json_output.write_text(summary_to_json(suite_summary) + "\n")

    return 0 if suite_summary["failed_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
