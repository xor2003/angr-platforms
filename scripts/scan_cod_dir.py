#!/usr/bin/env python3

from __future__ import annotations

import argparse
import io
import json
import re
import resource
import signal
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import angr


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401


ENTRY_RE = re.compile(r"\*\*\*\s+([0-9A-Fa-f]+)\s+((?:[0-9A-Fa-f]{2}\s+)+)(.*)$")
PROC_RE = re.compile(r"^([^\s]+)\tPROC (NEAR|FAR)$")


@dataclass
class FunctionScanResult:
    cod_file: str
    proc_name: str
    proc_kind: str
    byte_len: int
    has_near_call_reloc: bool
    has_far_call_reloc: bool
    lift_ok: bool
    decompile_ok: bool | None = None
    error: str | None = None


class ScanTimeout(Exception):
    pass


def _alarm_handler(_signum, _frame):
    raise ScanTimeout("timed out")


def _set_memory_limit(max_memory_mb: int) -> None:
    if max_memory_mb <= 0:
        return
    limit_bytes = max_memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def _extract_functions(cod_path: Path) -> list[tuple[str, str, bytes]]:
    lines = cod_path.read_text(errors="ignore").splitlines()
    out: list[tuple[str, str, bytes]] = []
    collect = False
    proc_name = ""
    proc_kind = ""
    chunks: list[bytes] = []

    for line in lines:
        proc_match = PROC_RE.match(line)
        if proc_match:
            collect = True
            proc_name, proc_kind = proc_match.groups()
            chunks = []
            continue

        if collect and f"{proc_name}\tENDP" in line:
            out.append((proc_name, proc_kind, b"".join(chunks)))
            collect = False
            proc_name = ""
            proc_kind = ""
            chunks = []
            continue

        if not collect:
            continue

        entry_match = ENTRY_RE.search(line)
        if entry_match:
            chunks.append(bytes.fromhex("".join(entry_match.group(2).split())))

    return out


def _project_from_bytes(code: bytes) -> angr.Project:
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )


def _scan_function(
    cod_file: Path,
    proc_name: str,
    proc_kind: str,
    code: bytes,
    timeout_sec: int,
    mode: str,
) -> FunctionScanResult:
    result = FunctionScanResult(
        cod_file=cod_file.name,
        proc_name=proc_name,
        proc_kind=proc_kind,
        byte_len=len(code),
        has_near_call_reloc=b"\xe8\x00\x00" in code,
        has_far_call_reloc=b"\x9a\x00\x00\x00\x00" in code,
        lift_ok=False,
    )

    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(timeout_sec)
    try:
        project = _project_from_bytes(code)
        project.factory.block(0x1000, len(code)).vex
        result.lift_ok = True

        if mode == "decompile-reloc-free":
            if result.has_near_call_reloc or result.has_far_call_reloc:
                result.decompile_ok = None
            else:
                cfg = project.analyses.CFGFast(normalize=True)
                dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
                result.decompile_ok = dec.codegen is not None and bool(dec.codegen.text)
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded sequential scan for .COD function lifting.")
    parser.add_argument("cod_dir", type=Path, help="Directory containing .COD files")
    parser.add_argument("--timeout-sec", type=int, default=5, help="Per-function timeout in seconds")
    parser.add_argument("--max-memory-mb", type=int, default=1024, help="Address-space cap for this process")
    parser.add_argument("--limit", type=int, default=0, help="Only scan the first N functions (0 = all)")
    parser.add_argument(
        "--mode",
        choices=("lift", "decompile-reloc-free"),
        default="lift",
        help="Either just lift each function, or also decompile functions without unresolved call relocations.",
    )
    args = parser.parse_args()

    _set_memory_limit(args.max_memory_mb)

    cod_files = sorted(args.cod_dir.rglob("*.COD"))
    results: list[FunctionScanResult] = []
    for cod_file in cod_files:
        for proc_name, proc_kind, code in _extract_functions(cod_file):
            results.append(_scan_function(cod_file, proc_name, proc_kind, code, args.timeout_sec, args.mode))
            if args.limit and len(results) >= args.limit:
                break
        if args.limit and len(results) >= args.limit:
            break

    failed = [
        item
        for item in results
        if not item.lift_ok or (args.mode == "decompile-reloc-free" and item.decompile_ok is False)
    ]
    print(json.dumps(
        {
            "mode": args.mode,
            "scanned": len(results),
            "failed": len(failed),
            "failures": [asdict(item) for item in failed],
        },
        indent=2,
    ))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
