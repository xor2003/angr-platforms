#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from datetime import date
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
from angr_platforms.X86_16.coverage_manifest import COMPARE_VERIFIED_MOO_OPCODES


def _default_jobs() -> int:
    cpu_count = os.cpu_count() or 1
    return max(1, cpu_count - 1)


def _verify_one_file(task: tuple[Path, int | None, bool, frozenset[str]]) -> dict:
    path, limit, execute_halt, revoked_hashes = task
    return verify_moo_file(path, limit=limit, execute_halt=execute_halt, revoked_hashes=set(revoked_hashes))


def _exclude_compare_covered(files: list[Path]) -> tuple[list[Path], list[Path]]:
    kept: list[Path] = []
    skipped: list[Path] = []
    for path in files:
        stem = path.name.removesuffix(".MOO.gz").removesuffix(".MOO")
        if stem in COMPARE_VERIFIED_MOO_OPCODES:
            skipped.append(path)
        else:
            kept.append(path)
    return kept, skipped


def _sample_compare_covered(
    files: list[Path], *, day_of_month: int
) -> tuple[list[Path], list[Path], list[Path]]:
    if not 1 <= day_of_month <= 31:
        raise ValueError("day_of_month must be in 1..31")

    kept: list[Path] = []
    sampled: list[Path] = []
    skipped: list[Path] = []
    sample_bucket = day_of_month - 1

    for path in files:
        stem = path.name.removesuffix(".MOO.gz").removesuffix(".MOO")
        if stem not in COMPARE_VERIFIED_MOO_OPCODES:
            kept.append(path)
            continue

        digest = hashlib.sha1(stem.encode("ascii")).digest()
        bucket = int.from_bytes(digest[:4], "big") % 31
        if bucket == sample_bucket:
            kept.append(path)
            sampled.append(path)
        else:
            skipped.append(path)

    return kept, sampled, skipped


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
        "--skip-compare-covered",
        action="store_true",
        help="Skip opcode files already covered by upstream-x86 compare semantics tests.",
    )
    parser.add_argument(
        "--sample-compare-covered",
        action="store_true",
        help="Keep only a deterministic day-of-month sample of compare-covered opcode files.",
    )
    parser.add_argument(
        "--sample-day",
        type=int,
        default=None,
        help="Override the day-of-month used for compare-covered sampling (1-31).",
    )
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
    if args.skip_compare_covered and args.sample_compare_covered:
        raise SystemExit("--skip-compare-covered and --sample-compare-covered are mutually exclusive")

    revoked = set() if args.ignore_revoked else load_revocation_hashes(args.revocation_list)
    files = discover_moo_files(args.suite, args.opcode)
    skipped_compare: list[Path] = []
    sampled_compare: list[Path] = []
    if args.skip_compare_covered:
        files, skipped_compare = _exclude_compare_covered(files)
    elif args.sample_compare_covered:
        day_of_month = args.sample_day or date.today().day
        files, sampled_compare, skipped_compare = _sample_compare_covered(files, day_of_month=day_of_month)
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
    if sampled_compare:
        print(f"Sampled compare-covered opcode files={len(sampled_compare)}")
    if skipped_compare:
        print(f"Skipped compare-covered opcode files={len(skipped_compare)}")

    if args.json_output is not None:
        args.json_output.write_text(summary_to_json(suite_summary) + "\n")

    return 0 if suite_summary["failed_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
